"""
Network egress filtering, security profiles, domain whitelisting, and guest DNS monitoring for krunbox.
"""

import ipaddress
import json
import re
import shlex
import socket
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from .config import NETWORK_PROFILES
from .sandbox import NetworkPolicy

VALID_PROFILES = {"full", "ai-only", "dev-common", "offline", "custom"}
DOMAIN_REGEX = re.compile(r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
IPV4_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

DNS_MONITOR_SOURCE = '''#!/usr/bin/env python3
"""
In-guest DNS policy enforcer and real-time domain egress logger for krunbox.
Uses Python standard library only.
"""

import json
import os
import re
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time

DOMAIN_SAFE_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}$")
IPV4_SAFE_RE = re.compile(r"^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
MAX_LOG_BYTES = 2 * 1024 * 1024
BURST_DEDUP_SEC = 0.25


def _parse_qname(packet: bytes):
    if len(packet) < 12:
        return None, 0, 0
    _txid, flags, qdcount, _an, _ns, _ar = struct.unpack("!HHHHHH", packet[:12])
    if (flags & 0x8000) != 0 or qdcount < 1:
        return None, 0, 0

    labels = []
    idx = 12
    jumped = False
    end_idx = 12
    jumps = 0
    pkt_len = len(packet)

    while idx < pkt_len:
        length = packet[idx]
        if length == 0:
            if not jumped:
                end_idx = idx + 1
            break
        if (length & 0xC0) == 0xC0:
            if idx + 1 >= pkt_len:
                return None, 0, 0
            ptr = ((length & 0x3F) << 8) | packet[idx + 1]
            if not jumped:
                end_idx = idx + 2
                jumped = True
            idx = ptr
            jumps += 1
            if jumps > 16:
                return None, 0, 0
            continue
        if length > 63 or idx + 1 + length > pkt_len:
            return None, 0, 0
        raw_lbl = packet[idx + 1 : idx + 1 + length]
        try:
            labels.append(raw_lbl.decode("ascii").lower())
        except UnicodeDecodeError:
            return None, 0, 0
        idx += 1 + length
    else:
        return None, 0, 0

    if end_idx + 4 > pkt_len:
        return None, 0, 0
    qtype, _qclass = struct.unpack("!HH", packet[end_idx : end_idx + 4])
    qname = ".".join(labels).strip(".")
    return qname, qtype, end_idx + 4


def _extract_a_records(packet: bytes, qend: int):
    ips = []
    if len(packet) < max(12, qend):
        return ips
    _txid, _flags, _qd, ancount, _ns, _ar = struct.unpack("!HHHHHH", packet[:12])
    idx = qend
    pkt_len = len(packet)
    for _ in range(ancount):
        if idx >= pkt_len:
            break
        while idx < pkt_len:
            b = packet[idx]
            if b == 0:
                idx += 1
                break
            if (b & 0xC0) == 0xC0:
                idx += 2
                break
            idx += 1 + b
        if idx + 10 > pkt_len:
            break
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", packet[idx : idx + 10])
        idx += 10
        if idx + rdlen > pkt_len:
            break
        if rtype == 1 and rclass == 1 and rdlen == 4:
            ip = socket.inet_ntoa(packet[idx : idx + 4])
            if IPV4_SAFE_RE.match(ip) and ip not in ips:
                ips.append(ip)
        idx += rdlen
    return ips


def _build_refused(packet: bytes, qend: int) -> bytes:
    txid, req_flags = struct.unpack("!HH", packet[:4])
    rd_bit = req_flags & 0x0100
    resp_flags = 0x8085 | rd_bit  # QR=1, RA=1, RCODE=5 (REFUSED)
    header = struct.pack("!HHHHHH", txid, resp_flags, 1, 0, 0, 0)
    return header + packet[12:qend]


def _build_servfail(packet: bytes, qend: int) -> bytes:
    txid, req_flags = struct.unpack("!HH", packet[:4])
    rd_bit = req_flags & 0x0100
    resp_flags = 0x8082 | rd_bit  # QR=1, RA=1, RCODE=2 (SERVFAIL)
    header = struct.pack("!HHHHHH", txid, resp_flags, 1, 0, 0, 0)
    return header + packet[12:qend]


def _domain_matches(qname: str, pattern: str) -> bool:
    pat = pattern.strip().lower().rstrip(".")
    if not pat:
        return False
    if pat.startswith("*."):
        pat = pat[2:]
    return qname == pat or qname.endswith("." + pat)


def _is_ignorable_noise(qname: str) -> bool:
    if not qname:
        return True
    if qname in ("localhost", "local", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        return True
    if qname.endswith(".in-addr.arpa") or qname.endswith(".ip6.arpa") or qname in ("in-addr.arpa", "ip6.arpa"):
        return True
    return not bool(DOMAIN_SAFE_RE.match(qname))


class DnsMonitorDaemon:
    def __init__(self, bundle_dir: str):
        self.bundle_dir = bundle_dir
        self.policy_path = os.path.join(bundle_dir, "policy.json")
        self.traffic_path = os.path.join(bundle_dir, "traffic.jsonl")
        self.upstream_path = os.path.join(bundle_dir, "upstream_resolv.conf")
        self.policy_sig = None
        self.sandbox_name = "unknown"
        self.profile = "full"
        self.allowed_domains = []
        self.denied_domains = []
        self.recent_bursts = {}
        self.known_nft_ips = set()
        self._reload_policy()

    def _reload_policy(self):
        try:
            st = os.stat(self.policy_path)
            sig = (st.st_mtime_ns, st.st_size, st.st_ino)
            if sig == self.policy_sig:
                return
            with open(self.policy_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.sandbox_name = str(data.get("sandbox_name") or "unknown")
            self.profile = str(data.get("profile") or "full").strip().lower()
            self.allowed_domains = [str(d).strip().lower().rstrip(".") for d in data.get("allowed_domains", []) if d]
            self.denied_domains = [str(d).strip().lower().rstrip(".") for d in data.get("denied_domains", []) if d]
            self.policy_sig = sig
        except Exception:
            pass

    def _get_upstreams(self):
        upstreams = []
        try:
            if os.path.exists(self.upstream_path):
                with open(self.upstream_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                target = parts[1].strip()
                                if ":" in target and not target.startswith("["):
                                    host_p, port_s = target.rsplit(":", 1)
                                    if port_s.isdigit():
                                        upstreams.append((host_p, int(port_s)))
                                        continue
                                if target.startswith("127.") or target in ("::1", "0.0.0.0"):
                                    continue
                                upstreams.append((target, 53))
        except Exception:
            pass
        if not upstreams:
            upstreams = [("10.0.2.3", 53), ("1.1.1.1", 53), ("8.8.8.8", 53)]
        return upstreams

    def evaluate(self, qname: str):
        self._reload_policy()
        if self.profile == "offline":
            return "blocked", "Blocked by offline policy"
        for d in self.denied_domains:
            if _domain_matches(qname, d):
                return "blocked", "Matched denied domain blacklist"
        if self.profile in ("ai-only", "dev-common", "custom"):
            for d in self.allowed_domains:
                if _domain_matches(qname, d):
                    return "allowed", f"Allowed by {self.profile} whitelist"
            return "blocked", f"Not in {self.profile} whitelist"
        return "allowed", "Allowed by full policy"

    def log_event(self, qname: str, action: str, reason: str):
        if _is_ignorable_noise(qname):
            return
        now = time.time()
        key = (qname, action)
        last_ts = self.recent_bursts.get(key, 0.0)
        if now - last_ts < BURST_DEDUP_SEC:
            return
        self.recent_bursts[key] = now
        if len(self.recent_bursts) > 1024:
            cutoff = now - 5.0
            self.recent_bursts = {k: v for k, v in self.recent_bursts.items() if v >= cutoff}

        record = {
            "timestamp": now,
            "sandbox_name": self.sandbox_name,
            "domain": qname,
            "action": action,
            "protocol": "dns",
            "port": 53,
            "reason": reason,
        }
        try:
            if os.path.exists(self.traffic_path) and os.path.getsize(self.traffic_path) > MAX_LOG_BYTES:
                with open(self.traffic_path, "rb") as rf:
                    rf.seek(-MAX_LOG_BYTES // 2, os.SEEK_END)
                    tail = rf.read()
                nl = tail.find(b"\\n")
                if nl != -1:
                    tail = tail[nl + 1 :]
                with open(self.traffic_path, "wb") as wf:
                    wf.write(tail)
            with open(self.traffic_path, "a", encoding="utf-8") as af:
                af.write(json.dumps(record) + "\\n")
        except Exception:
            pass

    def _update_nft_whitelist(self, ips):
        new_ips = [ip for ip in ips if ip not in self.known_nft_ips and IPV4_SAFE_RE.match(ip)]
        if not new_ips or self.profile not in ("ai-only", "dev-common", "custom"):
            return
        try:
            elem = ", ".join(new_ips)
            subprocess.run(
                ["nft", f"add element inet krunbox_filter allowed_egress_v4 {{ {elem} }}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1.5,
                check=False,
            )
            self.known_nft_ips.update(new_ips)
        except Exception:
            pass

    def handle_packet(self, packet: bytes, use_tcp: bool = False) -> bytes:
        qname, _qtype, qend = _parse_qname(packet)
        if qname is None or qend == 0:
            return b""
        if qname in ("localhost", "localhost.localdomain"):
            action, reason = "allowed", "Local loopback"
        else:
            action, reason = self.evaluate(qname)
            self.log_event(qname, action, reason)

        if action == "blocked":
            return _build_refused(packet, qend)

        for host, port in self._get_upstreams():
            try:
                if use_tcp:
                    with socket.create_connection((host, port), timeout=2.5) as s:
                        s.sendall(struct.pack("!H", len(packet)) + packet)
                        hdr = s.recv(2)
                        if len(hdr) < 2:
                            continue
                        rlen = struct.unpack("!H", hdr)[0]
                        chunks = []
                        rem = rlen
                        while rem > 0:
                            chunk = s.recv(rem)
                            if not chunk:
                                break
                            chunks.append(chunk)
                            rem -= len(chunk)
                        resp = b"".join(chunks)
                else:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(2.5)
                        s.sendto(packet, (host, port))
                        resp, _ = s.recvfrom(4096)
                if resp:
                    ips = _extract_a_records(resp, qend)
                    if ips:
                        self._update_nft_whitelist(ips)
                    return resp
            except Exception:
                continue
        return _build_servfail(packet, qend)


def main():
    bundle_dir = os.environ.get("KRUNBOX_EGRESS_DIR", "/run/krunbox-egress")
    bind_host = os.environ.get("KRUNBOX_DNS_HOST", "127.0.0.1")
    primary_port = int(os.environ.get("KRUNBOX_DNS_PORT", "53"))
    alt_port = int(os.environ.get("KRUNBOX_DNS_ALT_PORT", "15353"))

    daemon = DnsMonitorDaemon(bundle_dir)
    sel = selectors.DefaultSelector()
    sockets = []
    bound_ports = []

    candidate_ports = []
    for p in (primary_port, alt_port):
        if p > 0 and p not in candidate_ports:
            candidate_ports.append(p)

    for port in candidate_ports:
        try:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp_sock.bind((bind_host, port))
            udp_sock.setblocking(False)
            actual_port = udp_sock.getsockname()[1]
            sel.register(udp_sock, selectors.EVENT_READ, ("udp", actual_port))
            sockets.append(udp_sock)
            bound_ports.append(actual_port)

            try:
                tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp_sock.bind((bind_host, actual_port))
                tcp_sock.listen(16)
                tcp_sock.setblocking(False)
                sel.register(tcp_sock, selectors.EVENT_READ, ("tcp", actual_port))
                sockets.append(tcp_sock)
            except Exception:
                pass
        except Exception:
            continue

    if not bound_ports:
        sys.exit(1)

    try:
        with open(os.path.join(bundle_dir, "dns_monitor.pid"), "w", encoding="utf-8") as pf:
            pf.write(str(os.getpid()))
        with open(os.path.join(bundle_dir, "dns_port"), "w", encoding="utf-8") as dpf:
            dpf.write(str(bound_ports[0]))
    except Exception:
        pass

    running = True

    def _stop(_sig, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    try:
        while running:
            events = sel.select(timeout=0.5)
            for key, _mask in events:
                proto, _p = key.data
                sock = key.fileobj
                if proto == "udp":
                    try:
                        data, addr = sock.recvfrom(4096)
                        resp = daemon.handle_packet(data, use_tcp=False)
                        if resp:
                            sock.sendto(resp, addr)
                    except Exception:
                        pass
                elif proto == "tcp":
                    try:
                        conn, _addr = sock.accept()
                        conn.settimeout(2.5)
                        with conn:
                            hdr = conn.recv(2)
                            if len(hdr) == 2:
                                qlen = struct.unpack("!H", hdr)[0]
                                pkt = conn.recv(qlen)
                                resp = daemon.handle_packet(pkt, use_tcp=True)
                                if resp:
                                    conn.sendall(struct.pack("!H", len(resp)) + resp)
                    except Exception:
                        pass
    finally:
        for s in sockets:
            try:
                sel.unregister(s)
                s.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
'''


def is_ipv4_address(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_ipv6_address(ip: str) -> bool:
    """Check if string is a valid IPv6 address."""
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False


def is_safe_domain_or_ip(value: str) -> bool:
    """Validate that a domain or IP does not contain shell or nftables metacharacters."""
    if not value or len(value) > 253:
        return False
    val = value.strip().lower().rstrip(".")
    if val in ("localhost", "local"):
        return True
    if IPV4_REGEX.match(val):
        parts = val.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    try:
        ipaddress.IPv6Address(val)
        return True
    except ValueError:
        pass
    return bool(DOMAIN_REGEX.match(val))


def get_profile_domains(profile_name: str, custom_domains: Optional[List[str]] = None) -> List[str]:
    """Retrieve the domain whitelist for a given profile."""
    prof = NETWORK_PROFILES.get(profile_name.lower(), NETWORK_PROFILES["full"])
    domains = [d for d in prof.get("domains", []) if is_safe_domain_or_ip(d)]
    if custom_domains:
        for d in custom_domains:
            clean = d.strip().lower().rstrip(".")
            if is_safe_domain_or_ip(clean) and clean not in domains:
                domains.append(clean)
    return domains


def get_denied_domains(custom_denied: Optional[List[str]] = None) -> List[str]:
    """Retrieve and sanitize the domain blacklist."""
    denied: List[str] = []
    if custom_denied:
        for d in custom_denied:
            clean = d.strip().lower().rstrip(".")
            if is_safe_domain_or_ip(clean) and clean not in denied:
                denied.append(clean)
    return denied


def resolve_domain_ips(domain: str) -> List[str]:
    """Resolve a domain name to IPv4 and IPv6 addresses."""
    ips = []
    clean_domain = domain.lstrip("*.").strip().lower().rstrip(".")
    if not is_safe_domain_or_ip(clean_domain):
        return ips
    try:
        results = socket.getaddrinfo(clean_domain, None, socket.AF_UNSPEC)
        for r in results:
            family = r[0]
            ip = r[4][0]
            if family == socket.AF_INET and IPV4_REGEX.match(ip):
                if ip not in ips:
                    ips.append(ip)
            elif family == socket.AF_INET6:
                clean_ip = ip.split("%")[0]
                try:
                    ipaddress.IPv6Address(clean_ip)
                    if clean_ip not in ips:
                        ips.append(clean_ip)
                except ValueError:
                    pass
    except Exception:
        pass
    return ips


def resolve_domain_all_ips(domain: str) -> Tuple[List[str], List[str]]:
    """Resolve a domain name to separate lists of (ipv4_addresses, ipv6_addresses)."""
    v4_ips = []
    v6_ips = []
    for ip in resolve_domain_ips(domain):
        if is_ipv4_address(ip):
            if ip not in v4_ips:
                v4_ips.append(ip)
        elif is_ipv6_address(ip):
            if ip not in v6_ips:
                v6_ips.append(ip)
    return v4_ips, v6_ips


def write_guest_egress_bundle(sandbox_name: str, policy: NetworkPolicy, bundle_dir: Path) -> None:
    """
    Write policy.json and dns_monitor.py into the host-mounted guest egress bundle directory
    (mounted at /run/krunbox-egress inside the sandbox).
    """
    bundle_dir.mkdir(parents=True, exist_ok=True)
    try:
        bundle_dir.chmod(0o700)
    except Exception:
        pass

    clean_profile = policy.profile.strip().lower()
    if clean_profile not in VALID_PROFILES:
        clean_profile = "custom"

    denied = get_denied_domains(policy.denied_domains)
    denied_set = set(denied)
    raw_allowed = get_profile_domains(clean_profile, policy.allowed_domains)
    allowed = [d for d in raw_allowed if d not in denied_set]

    policy_payload = {
        "sandbox_name": sandbox_name,
        "profile": clean_profile,
        "allowed_domains": allowed,
        "denied_domains": denied,
        "updated_at": time.time(),
    }

    policy_file = bundle_dir / "policy.json"
    policy_file.write_text(json.dumps(policy_payload, indent=2), encoding="utf-8")
    try:
        policy_file.chmod(0o644)
    except Exception:
        pass

    monitor_file = bundle_dir / "dns_monitor.py"
    monitor_file.write_text(DNS_MONITOR_SOURCE, encoding="utf-8")
    try:
        monitor_file.chmod(0o755)
    except Exception:
        pass


def _dns_monitor_shell_block() -> List[str]:
    """Shell snippet to start or refresh the in-guest DNS monitor daemon cleanly."""
    return [
        "",
        "# Start or refresh real-time DNS egress monitor if available",
        "if [ -f /run/krunbox-egress/dns_monitor.py ] && command -v python3 >/dev/null 2>&1; then",
        "    if [ ! -s /run/krunbox-egress/upstream_resolv.conf ] && [ -f /etc/resolv.conf ]; then",
        "        grep -E '^[[:space:]]*nameserver[[:space:]]+' /etc/resolv.conf | grep -v -E '127\\.[0-9]+\\.[0-9]+\\.[0-9]+' > /run/krunbox-egress/upstream_resolv.conf 2>/dev/null || true",
        "    fi",
        "    if [ -f /run/krunbox-egress/dns_monitor.pid ] && kill -0 \"$(cat /run/krunbox-egress/dns_monitor.pid 2>/dev/null)\" 2>/dev/null; then",
        "        true",
        "    else",
        "        rm -f /run/krunbox-egress/dns_port 2>/dev/null || true",
        "        python3 /run/krunbox-egress/dns_monitor.py >/dev/null 2>&1 &",
        "        for _krun_i in 1 2 3 4 5 6 7 8 9 10; do",
        "            [ -f /run/krunbox-egress/dns_port ] && break",
        "            sleep 0.05 2>/dev/null || true",
        "        done",
        "    fi",
        "    if [ \"$(cat /run/krunbox-egress/dns_port 2>/dev/null)\" = \"53\" ] && [ -s /run/krunbox-egress/upstream_resolv.conf ]; then",
        "        if ! grep -q '^nameserver 127\\.0\\.0\\.1$' /etc/resolv.conf 2>/dev/null; then",
        "            {",
        "                echo '# Managed by krunbox egress monitor'",
        "                echo 'nameserver 127.0.0.1'",
        "                grep -v -E '^[[:space:]]*nameserver[[:space:]]+' /etc/resolv.conf 2>/dev/null || true",
        "            } > /run/krunbox-egress/resolv.conf.tmp 2>/dev/null && cat /run/krunbox-egress/resolv.conf.tmp > /etc/resolv.conf 2>/dev/null || true",
        "        fi",
        "    fi",
        "fi",
    ]


def _mcp_config_shell_block() -> List[str]:
    """Shell snippet to auto-configure krunbox-gateway MCP server for agy, Claude, Cursor, and Gemini."""
    py_snippet = (
        "import json, os, sys\n"
        "cmd = sys.argv[1] if len(sys.argv) > 1 else '/run/krunbox/krunbox-mcp'\n"
        "cfg = {'command': cmd, 'args': []}\n"
        "paths = [\n"
        "    '/workspace/.agents/mcp_config.json',\n"
        "    '/workspace/.antigravity/mcp_config.json',\n"
        "    '/workspace/.gemini/mcp_config.json',\n"
        "]\n"
        "for h in ['/home/vscode', '/root']:\n"
        "    if os.path.isdir(h):\n"
        "        paths.extend([\n"
        "            os.path.join(h, '.gemini/config/mcp_config.json'),\n"
        "            os.path.join(h, '.gemini/antigravity-cli/mcp_config.json'),\n"
        "            os.path.join(h, '.config/antigravity/mcp_config.json'),\n"
        "            os.path.join(h, '.config/Claude/claude_desktop_config.json'),\n"
        "            os.path.join(h, '.cursor/mcp.json'),\n"
        "        ])\n"
        "for p in paths:\n"
        "    try:\n"
        "        os.makedirs(os.path.dirname(p), exist_ok=True)\n"
        "        d = {}\n"
        "        if os.path.exists(p) and os.path.getsize(p) > 0:\n"
        "            try:\n"
        "                with open(p, 'r', encoding='utf-8') as rf:\n"
        "                    loaded = json.load(rf)\n"
        "                    if isinstance(loaded, dict):\n"
        "                        d = loaded\n"
        "            except Exception:\n"
        "                d = {}\n"
        "        servers = d.setdefault('mcpServers', {})\n"
        "        if 'krunbox-gateway' not in servers or servers['krunbox-gateway'] != cfg:\n"
        "            servers['krunbox-gateway'] = cfg\n"
        "            with open(p, 'w', encoding='utf-8') as wf:\n"
        "                json.dump(d, wf, indent=2)\n"
        "        try:\n"
        "            os.chmod(p, 0o666)\n"
        "        except Exception:\n"
        "            pass\n"
        "    except Exception:\n"
        "        pass\n"
    )
    return [
        "",
        "# Auto-configure in-sandbox krunbox-gateway MCP server for agy, Claude, Cursor, and Gemini",
        "if [ -f /run/krunbox/krunbox-mcp ] || [ -f /usr/local/bin/krunbox-mcp ] || [ -d /run/krunbox ] || [ -f /etc/krunbox-egress.sh ]; then",
        "    _krun_mcp_cmd='/run/krunbox/krunbox-mcp'",
        "    if [ ! -f \"$_krun_mcp_cmd\" ] && [ -x /usr/local/bin/krunbox-mcp ]; then",
        "        _krun_mcp_cmd='/usr/local/bin/krunbox-mcp'",
        "    fi",
        "    if command -v python3 >/dev/null 2>&1; then",
        f"        python3 -c {shlex.quote(py_snippet)} \"$_krun_mcp_cmd\" 2>/dev/null || true",
        "    fi",
        "    _mcp_json='{\n  \"mcpServers\": {\n    \"krunbox-gateway\": {\n      \"command\": \"'\"${_krun_mcp_cmd}\"'\",\n      \"args\": []\n    }\n  }\n}'",
        "    for _target in \\",
        "        /home/vscode/.gemini/config/mcp_config.json \\",
        "        /home/vscode/.gemini/antigravity-cli/mcp_config.json \\",
        "        /home/vscode/.config/antigravity/mcp_config.json \\",
        "        /home/vscode/.config/Claude/claude_desktop_config.json \\",
        "        /home/vscode/.cursor/mcp.json \\",
        "        /workspace/.agents/mcp_config.json \\",
        "        /workspace/.antigravity/mcp_config.json \\",
        "        /workspace/.gemini/mcp_config.json \\",
        "        /root/.gemini/config/mcp_config.json; do",
        "        if [ ! -s \"$_target\" ]; then",
        "            mkdir -p \"$(dirname \"$_target\")\" 2>/dev/null || true",
        "            printf '%s\\n' \"$_mcp_json\" > \"$_target\" 2>/dev/null || true",
        "            chmod 0666 \"$_target\" 2>/dev/null || true",
        "        fi",
        "    done",
        "    if id -u vscode >/dev/null 2>&1; then",
        "        chown -R vscode:vscode /home/vscode/.gemini /home/vscode/.config /home/vscode/.cursor /workspace/.agents /workspace/.antigravity /workspace/.gemini 2>/dev/null || true",
        "    fi",
        "fi",
    ]


def generate_egress_firewall_script(policy: NetworkPolicy) -> str:
    """
    Generate an nftables egress firewall and DNS telemetry script for the container.
    Executed inside the microVM entrypoint and on live policy updates.
    Uses 'inet' table family supporting both IPv4 and IPv6.
    """
    clean_profile = policy.profile.strip().lower()
    if clean_profile not in VALID_PROFILES:
        clean_profile = "custom"

    denied_domains = get_denied_domains(policy.denied_domains)

    if clean_profile == "full" and not denied_domains:
        lines = [
            "#!/bin/bash",
            "# Policy: Full access - no egress firewall installed",
            "# Profile: full",
            "nft 'flush table inet krunbox_filter' 2>/dev/null || true",
            "nft 'delete table inet krunbox_filter' 2>/dev/null || true",
            "nft 'flush table ip krunbox_filter' 2>/dev/null || true",
            "nft 'delete table ip krunbox_filter' 2>/dev/null || true",
        ]
        lines.extend(_dns_monitor_shell_block())
        lines.extend(_mcp_config_shell_block())
        return "\n".join(lines) + "\n"

    # Offline Profile (Airgap mode): NO DNS port 53 allow rules, loopback & established only
    if clean_profile == "offline":
        lines = [
            "#!/bin/bash",
            "# krunbox egress security policy enforcement",
            "# Profile: offline",
            "set -e",
            "",
            "# Flush any existing custom egress chains",
            "nft add table inet krunbox_filter 2>/dev/null || true",
            "nft 'flush table inet krunbox_filter' 2>/dev/null || true",
            "nft 'flush table ip krunbox_filter' 2>/dev/null || true",
            "nft 'add chain inet krunbox_filter output { type filter hook output priority 0; policy accept; }' 2>/dev/null || true",
            "nft 'add chain inet krunbox_filter forward { type filter hook forward priority 0; policy accept; }' 2>/dev/null || true",
            "",
            "# 1. Always allow loopback",
            "nft 'add rule inet krunbox_filter output oif \"lo\" accept' 2>/dev/null || true",
            "",
            "# 2. Always allow established/related traffic",
            "nft 'add rule inet krunbox_filter output ct state established,related accept' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter forward ct state established,related accept' 2>/dev/null || true",
            "",
            "# Offline policy: Drop all other outbound network traffic (no DNS port 53 allowed)",
            "nft 'add rule inet krunbox_filter output drop' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter forward drop' 2>/dev/null || true",
            "",
            "echo '[krunbox-network] Enforced OFFLINE / airgapped network policy.'",
        ]
        lines.extend(_mcp_config_shell_block())
        lines.append("exit 0")
        return "\n".join(lines) + "\n"

    lines = [
        "#!/bin/bash",
        "# krunbox egress security policy enforcement",
        f"# Profile: {clean_profile}",
        "set -e",
        "",
        "# Flush any existing custom egress chains",
        "nft add table inet krunbox_filter 2>/dev/null || true",
        "nft 'flush table inet krunbox_filter' 2>/dev/null || true",
        "nft 'flush table ip krunbox_filter' 2>/dev/null || true",
        "nft 'add chain inet krunbox_filter output { type filter hook output priority 0; policy accept; }' 2>/dev/null || true",
        "nft 'add chain inet krunbox_filter forward { type filter hook forward priority 0; policy accept; }' 2>/dev/null || true",
        "",
        "# 1. Always allow loopback",
        "nft 'add rule inet krunbox_filter output oif \"lo\" accept' 2>/dev/null || true",
        "",
        "# 2. Always allow established/related traffic",
        "nft 'add rule inet krunbox_filter output ct state established,related accept' 2>/dev/null || true",
        "nft 'add rule inet krunbox_filter forward ct state established,related accept' 2>/dev/null || true",
    ]

    # DNS Handling
    if clean_profile in ("ai-only", "dev-common", "custom"):
        # DNS Egress Filter Bypass Guard:
        # Non-full profiles only allow DNS to 127.0.0.1 (in-guest daemon) and redirect external port 53
        lines.extend([
            "",
            "# 3. DNS Egress Filter: allow 127.0.0.1 for all, and allow dns_monitor daemon (skuid 0) to reach upstream",
            "nft 'add rule inet krunbox_filter output ip daddr 127.0.0.1 udp dport 53 accept' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter output ip daddr 127.0.0.1 tcp dport 53 accept' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter output meta skuid 0 udp dport 53 accept' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter output meta skuid 0 tcp dport 53 accept' 2>/dev/null || true",
            "# Redirect non-root external DNS traffic to local monitor to prevent bypass",
            "nft add table inet krunbox_nat 2>/dev/null || true",
            "nft 'flush table inet krunbox_nat' 2>/dev/null || true",
            "nft 'add chain inet krunbox_nat output { type nat hook output priority -100; policy accept; }' 2>/dev/null || true",
            "nft 'add rule inet krunbox_nat output meta skuid 0 accept' 2>/dev/null || true",
            "nft 'add rule inet krunbox_nat output ip daddr != 127.0.0.1 udp dport 53 redirect to :53' 2>/dev/null || true",
            "nft 'add rule inet krunbox_nat output ip daddr != 127.0.0.1 tcp dport 53 redirect to :53' 2>/dev/null || true",
        ])
    else:
        # Full profile with denied domains: allow general DNS lookups
        lines.extend([
            "",
            "# 3. Allow DNS lookups (UDP/TCP port 53)",
            "nft 'add rule inet krunbox_filter output udp dport 53 accept' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter output tcp dport 53 accept' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter forward udp dport 53 accept' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter forward tcp dport 53 accept' 2>/dev/null || true",
        ])

    # 4. Blacklisted / Denied Domains (evaluated FIRST with highest drop priority)
    denied_ips: Set[str] = set()
    for d in denied_domains:
        resolved = resolve_domain_ips(d)
        denied_ips.update(resolved)

    safe_denied_v4 = sorted(ip for ip in denied_ips if is_ipv4_address(ip))
    safe_denied_v6 = sorted(ip for ip in denied_ips if is_ipv6_address(ip))
    if denied_domains:
        lines.extend([
            "",
            f"# Blacklist: {len(denied_domains)} denied domains ({len(safe_denied_v4)} v4 IPs, {len(safe_denied_v6)} v6 IPs)",
            "nft 'add set inet krunbox_filter denied_egress_v4 { type ipv4_addr; flags interval; }' 2>/dev/null || true",
            "nft 'add set inet krunbox_filter denied_egress_v6 { type ipv6_addr; flags interval; }' 2>/dev/null || true",
        ])
        if safe_denied_v4:
            ip_list = ", ".join(safe_denied_v4)
            lines.append(f"nft 'add element inet krunbox_filter denied_egress_v4 {{ {ip_list} }}' 2>/dev/null || true")
        if safe_denied_v6:
            ip6_list = ", ".join(safe_denied_v6)
            lines.append(f"nft 'add element inet krunbox_filter denied_egress_v6 {{ {ip6_list} }}' 2>/dev/null || true")
        lines.extend([
            "# Immediately drop all traffic matching blacklisted IP destinations",
            "nft 'add rule inet krunbox_filter output ip daddr @denied_egress_v4 drop' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter forward ip daddr @denied_egress_v4 drop' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter output ip6 daddr @denied_egress_v6 drop' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter forward ip6 daddr @denied_egress_v6 drop' 2>/dev/null || true",
        ])

    # 5. Whitelist-based profiles (ai-only, dev-common, custom)
    if clean_profile != "full":
        raw_target_domains = get_profile_domains(clean_profile, policy.allowed_domains)
        denied_set = set(denied_domains)
        target_domains = [d for d in raw_target_domains if d not in denied_set]

        allowed_ips: Set[str] = set()
        for d in target_domains:
            resolved = resolve_domain_ips(d)
            for ip in resolved:
                if ip not in denied_ips:
                    allowed_ips.add(ip)

        safe_allowed_v4 = sorted(ip for ip in allowed_ips if is_ipv4_address(ip))
        safe_allowed_v6 = sorted(ip for ip in allowed_ips if is_ipv6_address(ip))
        lines.extend([
            "",
            f"# Whitelist: {len(target_domains)} allowed domains ({len(safe_allowed_v4)} v4 IPs, {len(safe_allowed_v6)} v6 IPs)",
            "nft 'add set inet krunbox_filter allowed_egress_v4 { type ipv4_addr; flags interval; }' 2>/dev/null || true",
            "nft 'add set inet krunbox_filter allowed_egress_v6 { type ipv6_addr; flags interval; }' 2>/dev/null || true",
        ])

        if safe_allowed_v4:
            ip_list = ", ".join(safe_allowed_v4)
            lines.append(f"nft 'add element inet krunbox_filter allowed_egress_v4 {{ {ip_list} }}' 2>/dev/null || true")
        if safe_allowed_v6:
            ip6_list = ", ".join(safe_allowed_v6)
            lines.append(f"nft 'add element inet krunbox_filter allowed_egress_v6 {{ {ip6_list} }}' 2>/dev/null || true")

        lines.extend([
            "# Allow traffic to whitelisted IPs on HTTP / HTTPS",
            "nft 'add rule inet krunbox_filter output ip daddr @allowed_egress_v4 tcp dport { 80, 443 } accept' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter forward ip daddr @allowed_egress_v4 tcp dport { 80, 443 } accept' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter output ip6 daddr @allowed_egress_v6 tcp dport { 80, 443 } accept' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter forward ip6 daddr @allowed_egress_v6 tcp dport { 80, 443 } accept' 2>/dev/null || true",
            "# Drop all other outbound web traffic",
            "nft 'add rule inet krunbox_filter output tcp dport { 80, 443 } drop' 2>/dev/null || true",
            "nft 'add rule inet krunbox_filter forward tcp dport { 80, 443 } drop' 2>/dev/null || true",
        ])

    lines.extend(_dns_monitor_shell_block())
    lines.extend(_mcp_config_shell_block())

    summary_msg = f"[krunbox-network] Enforced {clean_profile.upper()} policy"
    if policy.allowed_domains:
        summary_msg += f" with {len(policy.allowed_domains)} whitelisted"
    if policy.denied_domains:
        summary_msg += f" and {len(policy.denied_domains)} blacklisted"
    lines.append(f"echo {shlex.quote(summary_msg + '.')}")

    return "\n".join(lines) + "\n"
