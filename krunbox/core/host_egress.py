"""
Unalterable host-boundary network egress enforcement and fallback capability hardening for krunbox.
Applies nftables filtering in the outer rootless Podman network namespace outside the guest boundary,
configures pasta gateway isolation, and drops excessive container capabilities when KVM is absent.
"""

import os
import re
import shlex
import shutil
import subprocess
from typing import List, Optional, Set, Tuple

from .network import (
    VALID_PROFILES,
    IPV4_REGEX,
    get_profile_domains,
    get_denied_domains,
    resolve_domain_ips,
)
from .sandbox import NetworkPolicy

CONTAINER_NAME_RE = re.compile(r"^[a-zA-Z0-9_.-]+$")

LEAST_PRIVILEGE_CAPS = (
    "CHOWN,DAC_OVERRIDE,FOWNER,SETGID,SETUID,NET_BIND_SERVICE,SYS_CHROOT,KILL"
)


def build_host_lockdown_podman_args(
    policy: NetworkPolicy,
    host_lockdown: bool,
    has_krun: bool,
    persist_docker: bool = False,
    has_pasta: Optional[bool] = None,
) -> List[str]:
    """
    Build Podman CLI arguments for host-boundary egress enforcement and guest lockdown.
    """
    if not host_lockdown:
        return []

    args: List[str] = ["-e", "KRUNBOX_LOCK_EGRESS=1"]

    pasta_ok = (
        has_pasta
        if has_pasta is not None
        else (shutil.which("pasta") is not None or shutil.which("passt") is not None)
    )

    clean_profile = str(policy.profile or "full").strip().lower()
    if clean_profile not in VALID_PROFILES:
        clean_profile = "custom"

    if not has_krun and pasta_ok:
        if clean_profile == "offline":
            args.append("--network=pasta:--no-map-gw,--no-dhcp-dns")
        else:
            args.append("--network=pasta:--no-map-gw")

    return args


def get_fallback_capability_args(host_lockdown: bool) -> List[str]:
    """
    Return Podman capability flags when hardware microVM (krun) is unavailable.
    Replaces blanket --privileged with least-privilege capabilities when host_lockdown is enabled.
    """
    if not host_lockdown:
        return ["--privileged"]

    return [
        "--cap-drop=ALL",
        f"--cap-add={LEAST_PRIVILEGE_CAPS}",
    ]


def generate_host_netns_nft_script(
    policy: NetworkPolicy,
    guest_ssh_port: int = 2222,
) -> str:
    """
    Generate an idempotent nftables script creating `table ip krunbox_host_filter`
    (chains `output` and `forward` at priority -10) for execution inside the outer
    rootless Podman network namespace on the host, outside the guest boundary.
    """
    clean_profile = str(policy.profile or "full").strip().lower()
    if clean_profile not in VALID_PROFILES:
        clean_profile = "custom"

    try:
        safe_ssh_port = int(guest_ssh_port)
        if not (1 <= safe_ssh_port <= 65535):
            safe_ssh_port = 2222
    except (ValueError, TypeError):
        safe_ssh_port = 2222

    denied_domains = get_denied_domains(policy.denied_domains)

    if clean_profile == "full" and not denied_domains:
        lines = [
            "#!/bin/sh",
            "# Host-boundary netns policy: full access (no host filter required)",
            "# Profile: full",
            "nft 'flush table ip krunbox_host_filter' 2>/dev/null || true",
            "nft 'delete table ip krunbox_host_filter' 2>/dev/null || true",
            "exit 0",
        ]
        return "\n".join(lines) + "\n"

    lines = [
        "#!/bin/sh",
        "# Host-boundary outer Podman netns firewall enforcement",
        f"# Profile: {clean_profile}",
        "set -e",
        "",
        "# Recreate outer host filter table idempotently at priority -10",
        "nft 'flush table ip krunbox_host_filter' 2>/dev/null || true",
        "nft 'delete table ip krunbox_host_filter' 2>/dev/null || true",
        "nft add table ip krunbox_host_filter",
        "nft 'add chain ip krunbox_host_filter output { type filter hook output priority -10; policy accept; }'",
        "nft 'add chain ip krunbox_host_filter forward { type filter hook forward priority -10; policy accept; }'",
        "",
        "# 1. Always allow loopback traffic",
        "nft 'add rule ip krunbox_host_filter output oif \"lo\" accept'",
        "nft 'add rule ip krunbox_host_filter forward oif \"lo\" accept'",
        "",
        "# 2. Always allow established/related connections",
        "nft 'add rule ip krunbox_host_filter output ct state established,related accept'",
        "nft 'add rule ip krunbox_host_filter forward ct state established,related accept'",
        "",
        "# 3. Always allow replies from guest sshd",
        f"nft 'add rule ip krunbox_host_filter output tcp sport {safe_ssh_port} accept'",
        f"nft 'add rule ip krunbox_host_filter forward tcp sport {safe_ssh_port} accept'",
    ]

    if clean_profile == "offline":
        lines.extend([
            "",
            "# Offline policy: drop all other outbound and forwarded packets",
            "nft 'add rule ip krunbox_host_filter output drop'",
            "nft 'add rule ip krunbox_host_filter forward drop'",
            "exit 0",
        ])
        return "\n".join(lines) + "\n"

    # 4. Allow DNS queries (UDP/TCP port 53) for non-offline profiles
    lines.extend([
        "",
        "# 4. Allow DNS lookups (UDP/TCP port 53)",
        "nft 'add rule ip krunbox_host_filter output udp dport 53 accept'",
        "nft 'add rule ip krunbox_host_filter output tcp dport 53 accept'",
        "nft 'add rule ip krunbox_host_filter forward udp dport 53 accept'",
        "nft 'add rule ip krunbox_host_filter forward tcp dport 53 accept'",
    ])

    # 5. Drop blacklisted / denied domains first
    denied_ips: Set[str] = set()
    for domain in denied_domains:
        denied_ips.update(resolve_domain_ips(domain))

    safe_denied_ips = sorted(ip for ip in denied_ips if IPV4_REGEX.match(ip))
    if denied_domains:
        lines.extend([
            "",
            f"# Blacklist: {len(denied_domains)} denied domains ({len(safe_denied_ips)} resolved IPs)",
            "nft 'add set ip krunbox_host_filter denied_egress { type ipv4_addr; flags interval; }'",
        ])
        if safe_denied_ips:
            ip_list = ", ".join(safe_denied_ips)
            lines.append(
                f"nft 'add element ip krunbox_host_filter denied_egress {{ {ip_list} }}'"
            )
        lines.extend([
            "nft 'add rule ip krunbox_host_filter output ip daddr @denied_egress drop'",
            "nft 'add rule ip krunbox_host_filter forward ip daddr @denied_egress drop'",
        ])

    # 6. Whitelist-restricted profiles (ai-only, dev-common, custom)
    if clean_profile != "full":
        raw_target_domains = get_profile_domains(clean_profile, policy.allowed_domains)
        denied_set = set(denied_domains)
        target_domains = [d for d in raw_target_domains if d not in denied_set]

        allowed_ips: Set[str] = set()
        for domain in target_domains:
            for ip in resolve_domain_ips(domain):
                if ip not in denied_ips:
                    allowed_ips.add(ip)

        safe_allowed_ips = sorted(ip for ip in allowed_ips if IPV4_REGEX.match(ip))
        lines.extend([
            "",
            f"# Whitelist: {len(target_domains)} allowed domains ({len(safe_allowed_ips)} resolved IPs)",
            "nft 'add set ip krunbox_host_filter allowed_egress { type ipv4_addr; flags interval; }'",
        ])
        if safe_allowed_ips:
            ip_list = ", ".join(safe_allowed_ips)
            lines.append(
                f"nft 'add element ip krunbox_host_filter allowed_egress {{ {ip_list} }}'"
            )
        lines.extend([
            "# Allow HTTP/HTTPS to whitelisted destination IPs and drop all other outbound traffic",
            "nft 'add rule ip krunbox_host_filter output ip daddr @allowed_egress tcp dport { 80, 443 } accept'",
            "nft 'add rule ip krunbox_host_filter forward ip daddr @allowed_egress tcp dport { 80, 443 } accept'",
            "nft 'add rule ip krunbox_host_filter output drop'",
            "nft 'add rule ip krunbox_host_filter forward drop'",
        ])

    summary = f"[krunbox-host-egress] Applied {clean_profile} host-netns firewall."
    lines.append(f": {shlex.quote(summary)}")
    return "\n".join(lines) + "\n"


def apply_host_netns_lockdown(
    container_name: str,
    policy: NetworkPolicy,
    guest_ssh_port: int = 2222,
) -> Tuple[bool, str]:
    """
    Enter the outer rootless Podman network namespace for `container_name` from the host
    and apply `generate_host_netns_nft_script`. Never raises unhandled exceptions.
    """
    clean_cname = str(container_name or "").strip()
    if not clean_cname or not CONTAINER_NAME_RE.match(clean_cname):
        return False, f"Invalid container name: {container_name!r}"

    if os.environ.get("KRUNBOX_DISABLE_HOST_NETNS") == "1":
        return False, "Host netns enforcement disabled via environment"

    try:
        inspect_res = subprocess.run(
            ["podman", "inspect", "--format", "{{.State.Pid}}", clean_cname],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except Exception as exc:
        return False, f"Podman inspect unavailable: {exc}"

    if inspect_res.returncode != 0:
        err = (inspect_res.stderr or inspect_res.stdout or "inspect failed").strip()
        return False, f"Could not inspect container PID: {err}"

    raw_pid = (inspect_res.stdout or "").strip()
    try:
        pid = int(raw_pid)
    except (ValueError, TypeError):
        return False, f"Invalid container PID output: {raw_pid!r}"

    if pid <= 1:
        return False, f"Container PID must be > 1 (got {pid})"

    try:
        nft_script = generate_host_netns_nft_script(policy, guest_ssh_port=guest_ssh_port)
    except Exception as exc:
        return False, f"Failed to generate host nftables script: {exc}"

    primary_cmd = [
        "podman",
        "unshare",
        "nsenter",
        "-n",
        "-t",
        str(pid),
        "/bin/sh",
        "-c",
        nft_script,
    ]
    fallback_cmd = [
        "nsenter",
        "-U",
        "--preserve-credentials",
        "-n",
        "-t",
        str(pid),
        "/bin/sh",
        "-c",
        nft_script,
    ]

    last_err = "nsenter/nft unavailable"
    for cmd in (primary_cmd, fallback_cmd):
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if res.returncode == 0:
                return True, "Applied host-boundary netns firewall"
            err_msg = (res.stderr or res.stdout or f"exit code {res.returncode}").strip()
            if err_msg:
                last_err = err_msg
        except Exception as exc:
            last_err = str(exc)

    return False, f"Host-boundary netns firewall skipped: {last_err}"
