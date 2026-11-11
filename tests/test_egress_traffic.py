"""
Unit and live integration tests for krunbox egress traffic monitoring, domain categorization,
sanitization, analytics, and the in-guest DNS monitor daemon.
"""

import csv
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
import pytest

from krunbox.core.sandbox import EgressEvent, NetworkPolicy
from krunbox.core.network import write_guest_egress_bundle
from krunbox.core.egress_traffic import (
    categorize_domain,
    sanitize_egress_domain,
    EgressTrafficManager,
)


def _encode_dns_query(domain: str, txid: int = 0x1234, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(lbl)]) + lbl.encode("ascii")
        for lbl in domain.strip(".").split(".")
    ) + b"\x00"
    question = qname + struct.pack("!HH", qtype, 1)
    return header + question


def _encode_dns_a_response(query: bytes, ip: str) -> bytes:
    txid = struct.unpack("!H", query[:2])[0]
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    idx = 12
    while idx < len(query) and query[idx] != 0:
        idx += 1 + query[idx]
    qend = idx + 5
    question = query[12:qend]
    # Pointer to offset 12 (0xC00C), TYPE A (1), CLASS IN (1), TTL 60, RDLENGTH 4
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip)
    return header + question + answer


def test_categorize_domain_all_categories():
    assert categorize_domain("api.openai.com") == "AI Provider"
    assert categorize_domain("api.anthropic.com") == "AI Provider"
    assert categorize_domain("claude.ai") == "AI Provider"
    assert categorize_domain("generativelanguage.googleapis.com") == "AI Provider"
    assert categorize_domain("huggingface.co") == "AI Provider"
    assert categorize_domain("cdn.hf.co") == "AI Provider"
    assert categorize_domain("openrouter.ai") == "AI Provider"
    assert categorize_domain("api.deepseek.com") == "AI Provider"
    assert categorize_domain("daily-cloudcode-pa.googleapis.com") == "AI Provider"
    assert categorize_domain("play.googleapis.com") == "AI Provider"
    assert categorize_domain("antigravity-cli-auto-updater-974169037036.us-central1.run.app") == "AI Provider"
    assert categorize_domain("lh3.googleusercontent.com") == "AI Provider"

    assert categorize_domain("registry.npmjs.org") == "Package Registry"
    assert categorize_domain("pypi.org") == "Package Registry"
    assert categorize_domain("files.pythonhosted.org") == "Package Registry"
    assert categorize_domain("static.crates.io") == "Package Registry"
    assert categorize_domain("proxy.golang.org") == "Package Registry"

    assert categorize_domain("github.com") == "Git & Source Control"
    assert categorize_domain("raw.githubusercontent.com") == "Git & Source Control"
    assert categorize_domain("gitlab.com") == "Git & Source Control"

    assert categorize_domain("registry-1.docker.io") == "Container Registry"
    assert categorize_domain("ghcr.io") == "Container Registry"
    assert categorize_domain("quay.io") == "Container Registry"

    assert categorize_domain("archive.ubuntu.com") == "OS & System Mirror"
    assert categorize_domain("deb.debian.org") == "OS & System Mirror"
    assert categorize_domain("dl.google.com") == "OS & System Mirror"

    assert categorize_domain("example.com") == "Web / External"
    assert categorize_domain("news.ycombinator.com") == "Web / External"


def test_sanitize_egress_domain():
    assert sanitize_egress_domain("  API.OpenAI.com. ") == "api.openai.com"
    assert sanitize_egress_domain("*.github.com") == "github.com"
    assert sanitize_egress_domain("8.8.8.8") == "8.8.8.8"

    # Internal PTR & loopback noise filtered
    assert sanitize_egress_domain("localhost") is None
    assert sanitize_egress_domain("127.0.0.1") is None
    assert sanitize_egress_domain("1.0.0.127.in-addr.arpa") is None
    assert sanitize_egress_domain("1.0.0.0.ip6.arpa") is None

    # Malicious inputs rejected
    assert sanitize_egress_domain("evil.com; rm -rf /") is None
    assert sanitize_egress_domain("<script>alert(1)</script>.com") is None
    assert sanitize_egress_domain("bad\ndomain.com") is None
    assert sanitize_egress_domain("../../etc/passwd") is None
    assert sanitize_egress_domain("") is None
    assert sanitize_egress_domain(None) is None


def test_egress_event_serialization():
    ev = EgressEvent(
        timestamp=1700000000.5,
        sandbox_name="krunbox-demo",
        domain="api.openai.com",
        action="allowed",
        protocol="https",
        port=443,
        category="AI Provider",
        reason="Allowed by policy",
        bytes_sent=512,
    )
    d = ev.to_dict()
    d["future_extra_field"] = "ignored"
    restored = EgressEvent.from_dict(d)
    assert restored.domain == "api.openai.com"
    assert restored.category == "AI Provider"
    assert restored.bytes_sent == 512


def test_egress_traffic_manager_stats_ranking_and_filtering(tmp_path):
    logs_dir = tmp_path / "egress_logs"
    mgr = EgressTrafficManager(logs_dir=logs_dir)

    assert (logs_dir.stat().st_mode & 0o777) == 0o700

    # Record host events for alpha and beta sandboxes
    mgr.record_event("krunbox-alpha", "api.openai.com", action="allowed", timestamp=100.0)
    mgr.record_event("krunbox-alpha", "api.openai.com", action="allowed", timestamp=110.0)
    mgr.record_event("krunbox-alpha", "evil-tracker.io", action="blocked", reason="Blacklisted", timestamp=120.0)
    mgr.record_event("krunbox-beta", "github.com", action="allowed", timestamp=130.0)

    # Also write guest-mounted traffic.jsonl events including corrupt & noise lines
    guest_dir = mgr.get_sandbox_bundle_dir("krunbox-alpha")
    guest_lines = [
        json.dumps({"timestamp": 115.0, "sandbox_name": "krunbox-alpha", "domain": "api.openai.com.", "action": "allowed", "protocol": "dns", "port": 53}),
        json.dumps({"timestamp": 125.0, "sandbox_name": "krunbox-alpha", "domain": "1.2.3.4.in-addr.arpa", "action": "allowed"}),
        json.dumps({"timestamp": 126.0, "sandbox_name": "krunbox-alpha", "domain": "bad;cmd.com", "action": "blocked"}),
        "{corrupted json line",
    ]
    (guest_dir / "traffic.jsonl").write_text("\n".join(guest_lines) + "\n", encoding="utf-8")

    # Ignored / malicious record_event calls return None
    assert mgr.record_event("krunbox-alpha", "localhost") is None
    assert mgr.record_event("krunbox-alpha", "bad$(whoami).com") is None

    # Global stats across all sandboxes
    global_stats = mgr.get_domain_stats()
    assert global_stats["total_requests"] == 5
    assert global_stats["unique_domains"] == 3
    assert global_stats["allowed_requests"] == 4
    assert global_stats["blocked_requests"] == 1
    assert global_stats["by_category"]["AI Provider"] == 3
    assert global_stats["by_category"]["Git & Source Control"] == 1
    assert global_stats["by_category"]["Web / External"] == 1

    # Ranked by (-total_count, -last_seen, domain)
    top_site = global_stats["sites"][0]
    assert top_site["domain"] == "api.openai.com"
    assert top_site["total_count"] == 3
    assert top_site["allowed_count"] == 3
    assert top_site["blocked_count"] == 0
    assert top_site["ports"] == [53, 443]
    assert top_site["sandboxes"] == ["krunbox-alpha"]

    # Per-sandbox stats (also works with unprefixed alias "alpha")
    alpha_stats = mgr.get_domain_stats(sandbox_name="alpha")
    assert alpha_stats["total_requests"] == 4
    assert alpha_stats["unique_domains"] == 2

    events = mgr.get_events(sandbox_name="krunbox-alpha", limit=2)
    assert len(events) == 2
    assert events[0].timestamp >= events[1].timestamp


def test_egress_traffic_rename_and_clear(tmp_path):
    mgr = EgressTrafficManager(logs_dir=tmp_path / "egress_logs")
    mgr.record_event("krunbox-old", "pypi.org", action="allowed", timestamp=200.0)
    bdir = mgr.get_sandbox_bundle_dir("krunbox-old")
    (bdir / "traffic.jsonl").write_text(
        json.dumps({"timestamp": 205.0, "sandbox_name": "krunbox-old", "domain": "crates.io", "action": "allowed", "protocol": "dns", "port": 53}) + "\n",
        encoding="utf-8",
    )

    mgr.rename_logs("krunbox-old", "krunbox-renamed")
    assert mgr.get_domain_stats("krunbox-old")["total_requests"] == 0
    renamed_stats = mgr.get_domain_stats("krunbox-renamed")
    assert renamed_stats["total_requests"] == 2
    for s in renamed_stats["sites"]:
        assert s["sandboxes"] == ["krunbox-renamed"]

    mgr.record_event("krunbox-other", "debian.org", action="allowed", timestamp=210.0)
    mgr.clear_logs("krunbox-renamed")
    assert mgr.get_domain_stats("krunbox-renamed")["total_requests"] == 0
    assert mgr.get_domain_stats("krunbox-other")["total_requests"] == 1

    mgr.clear_logs()
    assert mgr.get_domain_stats()["total_requests"] == 0


def test_live_dns_monitor_daemon_filtering_and_hot_reload(tmp_path):
    logs_dir = tmp_path / "egress_logs"
    mgr = EgressTrafficManager(logs_dir=logs_dir)
    bundle_dir = mgr.get_sandbox_bundle_dir("krunbox-live")

    # Start a mock upstream DNS server on an ephemeral localhost UDP port
    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.bind(("127.0.0.1", 0))
    upstream_port = upstream_sock.getsockname()[1]
    stop_upstream = threading.Event()

    def _upstream_worker():
        upstream_sock.settimeout(0.2)
        while not stop_upstream.is_set():
            try:
                data, addr = upstream_sock.recvfrom(4096)
                resp = _encode_dns_a_response(data, "93.184.216.34")
                upstream_sock.sendto(resp, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    up_thread = threading.Thread(target=_upstream_worker, daemon=True)
    up_thread.start()

    # Reserve a free UDP port for dns_monitor
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    monitor_port = probe.getsockname()[1]
    probe.close()

    (bundle_dir / "upstream_resolv.conf").write_text(f"nameserver 127.0.0.1:{upstream_port}\n", encoding="utf-8")
    initial_policy = NetworkPolicy(profile="ai-only", allowed_domains=["custom.corp.example"], denied_domains=[])
    write_guest_egress_bundle("krunbox-live", initial_policy, bundle_dir)

    env = dict(os.environ)
    env["KRUNBOX_EGRESS_DIR"] = str(bundle_dir)
    env["KRUNBOX_DNS_HOST"] = "127.0.0.1"
    env["KRUNBOX_DNS_PORT"] = str(monitor_port)
    env["KRUNBOX_DNS_ALT_PORT"] = "0"

    proc = subprocess.Popen(
        [sys.executable, str(bundle_dir / "dns_monitor.py")],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(40):
            if (bundle_dir / "dns_port").is_file():
                break
            time.sleep(0.05)
        assert (bundle_dir / "dns_port").read_text(encoding="utf-8").strip() == str(monitor_port)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2.0)

        # 1. Allowed AI domain -> RCODE 0
        client.sendto(_encode_dns_query("api.openai.com", txid=0x1111), ("127.0.0.1", monitor_port))
        resp_ok, _ = client.recvfrom(4096)
        flags_ok = struct.unpack("!HH", resp_ok[:4])[1]
        assert (flags_ok & 0x000F) == 0  # NOERROR

        # 2. Disallowed external domain under ai-only -> RCODE 5 (REFUSED)
        client.sendto(_encode_dns_query("news.ycombinator.com", txid=0x2222), ("127.0.0.1", monitor_port))
        resp_blk, _ = client.recvfrom(4096)
        flags_blk = struct.unpack("!HH", resp_blk[:4])[1]
        assert (flags_blk & 0x000F) == 5  # REFUSED

        # 3. Hot-reload policy to full with denied_domains=["malware.bad.org"]
        time.sleep(0.05)
        updated_policy = NetworkPolicy(profile="full", denied_domains=["malware.bad.org"])
        write_guest_egress_bundle("krunbox-live", updated_policy, bundle_dir)

        client.sendto(_encode_dns_query("news.ycombinator.com", txid=0x3333), ("127.0.0.1", monitor_port))
        resp_now_ok, _ = client.recvfrom(4096)
        assert (struct.unpack("!HH", resp_now_ok[:4])[1] & 0x000F) == 0

        client.sendto(_encode_dns_query("sub.malware.bad.org", txid=0x4444), ("127.0.0.1", monitor_port))
        resp_denied, _ = client.recvfrom(4096)
        assert (struct.unpack("!HH", resp_denied[:4])[1] & 0x000F) == 5

        client.close()

        stats = mgr.get_domain_stats("krunbox-live")
        assert stats["total_requests"] == 4
        assert stats["allowed_requests"] == 2
        assert stats["blocked_requests"] == 2
        domains_seen = {s["domain"] for s in stats["sites"]}
        assert domains_seen == {"api.openai.com", "news.ycombinator.com", "sub.malware.bad.org"}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        stop_upstream.set()
        upstream_sock.close()


def test_export_domain_stats_csv_json_and_edge_cases(tmp_path):
    logs_dir = tmp_path / "egress_logs"
    mgr = EgressTrafficManager(logs_dir=logs_dir)

    # 1. Test export when sites list is empty
    empty_csv = tmp_path / "empty.csv"
    ok, msg = mgr.export_domain_stats(empty_csv)
    assert ok is True
    assert empty_csv.is_file()
    with open(empty_csv, "r", encoding="utf-8") as f:
        reader = list(csv.reader(f))
        assert len(reader) == 1  # Only header row
        assert reader[0] == [
            "domain",
            "category",
            "total_count",
            "allowed_count",
            "blocked_count",
            "last_seen",
            "first_seen",
            "last_action",
            "ports",
            "sandboxes",
        ]

    empty_json = tmp_path / "empty.json"
    ok, msg = mgr.export_domain_stats(empty_json)
    assert ok is True
    assert empty_json.is_file()
    with open(empty_json, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["total_sites"] == 0
        assert data["sites"] == []
        assert "exported_at" in data
        assert data["sandbox"] == "all"

    # 2. Record events to populate domain stats
    mgr.record_event(
        "box-alpha",
        "api.openai.com",
        action="allowed",
        port=443,
        reason="ai-profile",
    )
    mgr.record_event(
        "box-beta",
        "api.openai.com",
        action="allowed",
        port=8443,
        reason="ai-profile",
    )
    mgr.record_event(
        "box-alpha",
        "malware.bad.org",
        action="blocked",
        port=80,
        reason="denied-domain",
    )

    # 3. Test export to CSV with autodetection and formatting checks
    csv_out = tmp_path / "exports" / "traffic.csv"
    ok, msg = mgr.export_domain_stats(csv_out)
    assert ok is True
    assert csv_out.is_file()
    with open(csv_out, "r", encoding="utf-8") as f:
        rows = list(csv.reader(f))
        assert len(rows) == 3  # Header + 2 unique domains
        header, row1, row2 = rows[0], rows[1], rows[2]
        assert header == [
            "domain",
            "category",
            "total_count",
            "allowed_count",
            "blocked_count",
            "last_seen",
            "first_seen",
            "last_action",
            "ports",
            "sandboxes",
        ]
        # api.openai.com has 2 calls, both allowed, ports 443;8443, sandboxes box-alpha;box-beta
        assert row1[0] == "api.openai.com"
        assert row1[1] == "AI Provider"
        assert row1[2] == "2"
        assert row1[3] == "2"
        assert row1[4] == "0"
        assert row1[7] == "allowed"
        assert "443" in row1[8] and "8443" in row1[8]
        assert ";" in row1[8]
        assert "box-alpha" in row1[9] and "box-beta" in row1[9]
        assert ";" in row1[9]
        # Check timestamp format: YYYY-MM-DD HH:MM:SS
        assert len(row1[5]) == 19
        assert row1[5][4] == "-" and row1[5][7] == "-" and row1[5][10] == " "

        # malware.bad.org row
        assert row2[0] == "malware.bad.org"
        assert row2[2] == "1"
        assert row2[3] == "0"
        assert row2[4] == "1"
        assert row2[7] == "blocked"
        assert row2[8] == "80"
        assert row2[9] == "box-alpha"

    # 4. Test export to JSON with autodetection
    json_out = tmp_path / "exports" / "traffic.json"
    ok, msg = mgr.export_domain_stats(json_out, sandbox_name="box-alpha")
    assert ok is True
    assert json_out.is_file()
    with open(json_out, "r", encoding="utf-8") as f:
        js = json.load(f)
        assert "exported_at" in js
        assert js["sandbox"] == "box-alpha"
        assert js["total_sites"] == 2
        domains = {s["domain"] for s in js["sites"]}
        assert domains == {"api.openai.com", "malware.bad.org"}

    # 5. Test parent directory creation if target directory doesn't exist
    deep_path = tmp_path / "very" / "deeply" / "nested" / "sub" / "dir" / "out.csv"
    assert not deep_path.parent.exists()
    ok, msg = mgr.export_domain_stats(deep_path)
    assert ok is True
    assert deep_path.is_file()

    # 6. Test explicit sites subset passed
    subset = [
        {
            "domain": "custom.example.com",
            "category": "Web / External",
            "total_count": 42,
            "allowed_count": 40,
            "blocked_count": 2,
            "last_seen": 1700000000.0,
            "first_seen": 1699990000.0,
            "last_action": "allowed",
            "ports": [443, 8080],
            "sandboxes": ["box-custom"],
        }
    ]
    explicit_out = tmp_path / "subset.csv"
    ok, msg = mgr.export_domain_stats(explicit_out, sites=subset, fmt="csv")
    assert ok is True
    with open(explicit_out, "r", encoding="utf-8") as f:
        rows = list(csv.reader(f))
        assert len(rows) == 2
        assert rows[1][0] == "custom.example.com"
        assert rows[1][2] == "42"
        assert rows[1][8] == "443;8080"
        assert rows[1][9] == "box-custom"

