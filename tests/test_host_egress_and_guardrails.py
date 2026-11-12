"""
Tests for unalterable host-boundary egress enforcement, idle auto-pause/auto-stop monitor,
desktop notifications, and runtime budget/security guardrails.
"""

from types import SimpleNamespace
from pathlib import Path
from unittest.mock import MagicMock, patch
import re
import subprocess

import pytest

from krunbox.core.sandbox import NetworkPolicy, SandboxInfo
from krunbox.core.egress_traffic import EgressTrafficManager
from krunbox.core.telemetry import TelemetryManager
from krunbox.core.host_egress import (
    build_host_lockdown_podman_args,
    get_fallback_capability_args,
    generate_host_netns_nft_script,
    apply_host_netns_lockdown,
)
from krunbox.core.notifications import (
    AlertEvent,
    GuardrailMonitor,
    has_active_ssh_sessions,
    run_with_completion_notification,
    send_desktop_notification,
    _format_duration,
)


# =========================================================================
# 1. Shell Boot Scripts Validation & In-Guest Lockdown Verification
# =========================================================================

_WORKSPACE_ROOT = Path("/workspace") if Path("/workspace").exists() else Path(__file__).resolve().parent.parent

def test_entrypoint_and_agent_session_bash_syntax():
    """Validate bash -n syntax check on entrypoint.sh and agent-session.sh."""
    ep = str(_WORKSPACE_ROOT / "images" / "agent-box" / "entrypoint.sh")
    ag = str(_WORKSPACE_ROOT / "images" / "agent-box" / "agent-session.sh")
    res = subprocess.run(
        ["bash", "-n", ep, ag],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, f"bash -n failed: {res.stderr}"


def test_entrypoint_contains_egress_lockdown_and_cap_drop():
    """Ensure entrypoint.sh restricts sudoers firewall commands and drops CAP_NET_ADMIN."""
    content = (_WORKSPACE_ROOT / "images" / "agent-box" / "entrypoint.sh").read_text(encoding="utf-8")
    assert 'KRUNBOX_LOCK_EGRESS' in content
    assert '/etc/sudoers.d/zz-krunbox-egress-lockdown' in content
    assert '!/usr/sbin/nft' in content
    assert '!/usr/sbin/iptables' in content
    assert '!/usr/bin/nsenter' in content
    assert 'setpriv --bounding-set=-net_admin' in content
    assert 'gosu "${USERNAME}" /usr/local/bin/agent-session.sh "$@"' in content


# =========================================================================
# 2. Host-Boundary Podman Args, Fallback Capabilities & Outer Netns Firewall
# =========================================================================

def test_build_host_lockdown_podman_args():
    ai_policy = NetworkPolicy(profile="ai-only")
    offline_policy = NetworkPolicy(profile="offline")

    # Disabled lockdown -> empty args
    assert build_host_lockdown_podman_args(ai_policy, host_lockdown=False, has_krun=True) == []
    assert build_host_lockdown_podman_args(ai_policy, host_lockdown=False, has_krun=False, has_pasta=True) == []

    # krun microVM enabled -> sets KRUNBOX_LOCK_EGRESS=1 without overriding krun runtime networking
    args_krun = build_host_lockdown_podman_args(ai_policy, host_lockdown=True, has_krun=True, has_pasta=True)
    assert args_krun == ["-e", "KRUNBOX_LOCK_EGRESS=1"]

    # Rootless fallback + pasta available -> blocks gateway remap to host 127.0.0.1
    args_pasta = build_host_lockdown_podman_args(ai_policy, host_lockdown=True, has_krun=False, has_pasta=True)
    assert args_pasta == [
        "-e",
        "KRUNBOX_LOCK_EGRESS=1",
        "--network=pasta:--no-map-gw",
    ]

    # Rootless fallback + pasta + offline -> also disables DHCP/DNS forwarding
    args_offline = build_host_lockdown_podman_args(offline_policy, host_lockdown=True, has_krun=False, has_pasta=True)
    assert args_offline == [
        "-e",
        "KRUNBOX_LOCK_EGRESS=1",
        "--network=pasta:--no-map-gw,--no-dhcp-dns",
    ]

    # Rootless fallback without pasta binary
    args_no_pasta = build_host_lockdown_podman_args(ai_policy, host_lockdown=True, has_krun=False, has_pasta=False)
    assert args_no_pasta == ["-e", "KRUNBOX_LOCK_EGRESS=1"]

    # Auto-detection via shutil.which when has_pasta is None
    with patch("krunbox.core.host_egress.shutil.which", side_effect=lambda b: "/usr/bin/pasta" if b == "pasta" else None):
        auto_args = build_host_lockdown_podman_args(ai_policy, host_lockdown=True, has_krun=False, has_pasta=None)
        assert "--network=pasta:--no-map-gw" in auto_args


def test_get_fallback_capability_args():
    assert get_fallback_capability_args(host_lockdown=False) == ["--privileged"]

    locked_caps = get_fallback_capability_args(host_lockdown=True)
    assert "--privileged" not in locked_caps
    assert "--cap-drop=ALL" in locked_caps
    joined = " ".join(locked_caps)
    assert "CHOWN" in joined
    assert "SETUID" in joined
    assert "NET_ADMIN" not in joined
    assert "SYS_MODULE" not in joined
    assert "SYS_PTRACE" not in joined
    assert "SYS_RAWIO" not in joined


def test_generate_host_netns_nft_script_profiles():
    # 1. Full profile with no denied domains -> flushes/deletes table and exits 0
    full_script = generate_host_netns_nft_script(NetworkPolicy(profile="full"))
    assert "flush table ip krunbox_host_filter" in full_script
    assert "delete table ip krunbox_host_filter" in full_script
    assert "exit 0" in full_script
    assert "priority -10" not in full_script

    # 2. Offline profile -> allows lo, established/related, ssh sport 2222, drops everything else (no DNS)
    offline_script = generate_host_netns_nft_script(NetworkPolicy(profile="offline"), guest_ssh_port=2222)
    assert "table ip krunbox_host_filter" in offline_script
    assert "hook output priority -10" in offline_script
    assert "hook forward priority -10" in offline_script
    assert 'oif "lo" accept' in offline_script
    assert "ct state established,related accept" in offline_script
    assert "tcp sport 2222 accept" in offline_script
    assert "dport 53" not in offline_script
    assert "add rule ip krunbox_host_filter output drop" in offline_script
    assert "add rule ip krunbox_host_filter forward drop" in offline_script

    # 3. AI-only + custom allowed + denied_domains -> resolves IPs, drops denied first, allows 80/443 to allowed, drops rest
    def fake_resolve(domain: str):
        mapping = {
            "evil.example.com": ["203.0.113.99"],
            "custom-api.example.org": ["198.51.100.42", "203.0.113.99"],  # overlapping IP excluded!
            "api.openai.com": ["198.51.100.10"],
        }
        return mapping.get(domain, [])

    with patch("krunbox.core.host_egress.resolve_domain_ips", side_effect=fake_resolve):
        ai_policy = NetworkPolicy(
            profile="ai-only",
            allowed_domains=["custom-api.example.org"],
            denied_domains=["evil.example.com"],
        )
        ai_script = generate_host_netns_nft_script(ai_policy, guest_ssh_port=2222)

    assert "udp dport 53 accept" in ai_script
    assert "tcp dport 53 accept" in ai_script
    assert "denied_egress" in ai_script
    assert "203.0.113.99" in ai_script
    assert "ip daddr @denied_egress drop" in ai_script
    assert "allowed_egress" in ai_script
    assert "198.51.100.10" in ai_script
    assert "198.51.100.42" in ai_script
    # Overlapping denied IP must NOT be added to allowed_egress
    allowed_elem_lines = [ln for ln in ai_script.splitlines() if "add element ip krunbox_host_filter allowed_egress" in ln]
    assert len(allowed_elem_lines) == 1
    assert "203.0.113.99" not in allowed_elem_lines[0]
    assert "ip daddr @allowed_egress tcp dport { 80, 443 } accept" in ai_script
    assert "add rule ip krunbox_host_filter output drop" in ai_script
    assert "add rule ip krunbox_host_filter forward drop" in ai_script
    # Denied drop must appear before allowed accept
    assert ai_script.index("@denied_egress drop") < ai_script.index("@allowed_egress tcp dport")


def test_apply_host_netns_lockdown_primary_fallback_and_errors():
    policy = NetworkPolicy(profile="offline")

    # Case 1: Primary `podman unshare nsenter` succeeds
    with patch("krunbox.core.host_egress.subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="4321\n", stderr=""),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]
        ok, msg = apply_host_netns_lockdown("krunbox-test", policy)
        assert ok is True
        assert "Applied host-boundary netns firewall" in msg
        assert mock_run.call_count == 2
        ns_cmd = mock_run.call_args_list[1][0][0]
        assert ns_cmd[:6] == ["podman", "unshare", "nsenter", "-n", "-t", "4321"]

    # Case 2: Primary `podman unshare` fails -> falls back to `nsenter -U --preserve-credentials`
    with patch("krunbox.core.host_egress.subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="8765\n", stderr=""),
            MagicMock(returncode=1, stdout="", stderr="unshare failed"),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]
        ok, msg = apply_host_netns_lockdown("krunbox-test", policy)
        assert ok is True
        assert mock_run.call_count == 3
        fb_cmd = mock_run.call_args_list[2][0][0]
        assert fb_cmd[:6] == ["nsenter", "-U", "--preserve-credentials", "-n", "-t", "8765"]

    # Case 3: Invalid PID (0 or 1 or non-integer)
    with patch("krunbox.core.host_egress.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="0\n", stderr="")
        ok, msg = apply_host_netns_lockdown("krunbox-stopped", policy)
        assert ok is False
        assert "PID" in msg

    # Case 4: Missing binaries / FileNotFoundError never raises unhandled exception
    with patch("krunbox.core.host_egress.subprocess.run", side_effect=FileNotFoundError("podman not found")):
        ok, msg = apply_host_netns_lockdown("krunbox-missing", policy)
        assert ok is False
        assert "unavailable" in msg.lower()

    # Case 5: Reject unsafe container names
    ok, msg = apply_host_netns_lockdown("bad;name", policy)
    assert ok is False


# =========================================================================
# 3. SSH Session Detection (Interactive vs Background Tunnels)
# =========================================================================

def test_has_active_ssh_sessions_distinguishes_tunnels():
    pgrep_tunnel_only = (
        "2222 /usr/bin/ssh-agent -s\n"
        "14001 ssh -N -f -o ExitOnForwardFailure=yes -L 127.0.0.1:8080:127.0.0.1:80 -p 2222 -- krunbox-my-app\n"
        "14002 ssh -fN -L 3000:localhost:3000 krunbox-my-app\n"
        "14003 ssh krunbox-my-app-2\n"
        "14004 ssh -p 22220 vscode@127.0.0.1\n"
    )
    with patch("krunbox.core.notifications.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=pgrep_tunnel_only, stderr="")
        assert has_active_ssh_sessions("krunbox-my-app", 2222) is False

    pgrep_with_interactive_alias = pgrep_tunnel_only + "15010 /usr/bin/ssh krunbox-my-app\n"
    with patch("krunbox.core.notifications.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=pgrep_with_interactive_alias, stderr="")
        assert has_active_ssh_sessions("krunbox-my-app", 2222) is True

    pgrep_with_interactive_port = (
        "15020 ssh -o StrictHostKeyChecking=no -p 2222 vscode@127.0.0.1\n"
    )
    with patch("krunbox.core.notifications.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=pgrep_with_interactive_port, stderr="")
        assert has_active_ssh_sessions("krunbox-my-app", 2222) is True


# =========================================================================
# 4. GuardrailMonitor: Memory, Egress Spike, AI Budget, and Idle Auto-Stop
# =========================================================================

def _make_box(
    name: str = "krunbox-alpha",
    status: str = "running",
    cpu_percent: float = 0.2,
    mem_percent: float = 40.0,
    ssh_port: int = 2222,
    **extra,
):
    base = SandboxInfo(
        name=name,
        dir_path="/tmp/demo",
        hostname=name,
        container_name=name,
        ssh_port=ssh_port,
        status=status,
        cpu_percent=cpu_percent,
        mem_percent=mem_percent,
    )
    for k, v in extra.items():
        setattr(base, k, v)
    return base


def test_guardrail_memory_pressure_and_cooldown():
    mon = GuardrailMonitor(cooldown_seconds=300.0, ssh_checker=lambda _n, _p: False)
    box = _make_box(mem_percent=93.5)

    # First evaluation emits memory_pressure
    alerts1, actions1 = mon.evaluate([box], now=1000.0)
    assert len(alerts1) == 1
    assert alerts1[0].category == "memory_pressure"
    assert alerts1[0].severity == "warning"
    assert actions1 == []

    # Within 300s cooldown -> suppressed
    alerts2, _ = mon.evaluate([box], now=1150.0)
    assert alerts2 == []

    # After cooldown expires (>= 300s) with 96% RAM -> re-emits as critical
    box.mem_percent = 96.2
    alerts3, _ = mon.evaluate([box], now=1301.0)
    assert len(alerts3) == 1
    assert alerts3[0].category == "memory_pressure"
    assert alerts3[0].severity == "critical"


def test_guardrail_blocked_egress_spike(tmp_path):
    egress_mgr = EgressTrafficManager(logs_dir=tmp_path / "egress_logs")
    mon = GuardrailMonitor(
        cooldown_seconds=300.0,
        blocked_spike_threshold=5,
        ssh_checker=lambda _n, _p: False,
    )
    box = _make_box(name="krunbox-sec")

    # Seed 2 old blocked events (hours ago) -> baseline initialized, no alert
    for i in range(2):
        egress_mgr.record_event("krunbox-sec", "old-tracker.io", action="blocked", timestamp=100.0 + i)

    alerts0, _ = mon.evaluate([box], egress_traffic_mgr=egress_mgr, now=1000.0)
    assert alerts0 == []

    # Burst of 5 new blocked exfiltration attempts -> triggers egress_spike listing top domain
    for i in range(4):
        egress_mgr.record_event("krunbox-sec", "exfil.attacker.example", action="blocked", timestamp=1005.0 + i)
    egress_mgr.record_event("krunbox-sec", "pastebin.example.net", action="blocked", timestamp=1010.0)

    alerts1, _ = mon.evaluate([box], egress_traffic_mgr=egress_mgr, now=1012.0)
    assert len(alerts1) == 1
    assert alerts1[0].category == "egress_spike"
    assert "exfil.attacker.example" in alerts1[0].body

    # Next poll with no new blocked events -> no duplicate alert
    alerts2, _ = mon.evaluate([box], egress_traffic_mgr=egress_mgr, now=1400.0)
    assert alerts2 == []


def test_guardrail_ai_token_and_cost_budgets(tmp_path):
    telem_mgr = TelemetryManager(telemetry_dir=tmp_path / "telemetry")
    mon = GuardrailMonitor(cooldown_seconds=300.0, ssh_checker=lambda _n, _p: False)

    box = _make_box(
        name="krunbox-budget",
        max_tokens_budget=10000,
        max_cost_usd_budget=0.50,
        budget_exceeded_action="pause",
    )

    # Record 12,000 tokens -> exceeds 10,000 token budget
    telem_mgr.record_call(
        sandbox_name="krunbox-budget",
        provider="OpenAI",
        endpoint="/v1/chat/completions",
        model="gpt-4o",
        prompt_tokens=8000,
        completion_tokens=4000,
    )

    alerts, actions = mon.evaluate([box], telemetry_mgr=telem_mgr, now=2000.0)
    assert len(alerts) == 1
    assert alerts[0].category == "budget_exceeded"
    assert actions == [("krunbox-budget", "pause", "AI budget guardrail exceeded")]

    # Test USD budget via global settings with "stop" action on a second box
    box2 = _make_box(name="krunbox-usd", budget_exceeded_action="stop")
    telem_mgr.record_call(
        sandbox_name="krunbox-usd",
        provider="Anthropic",
        endpoint="/v1/messages",
        model="claude-sonnet",
        prompt_tokens=50000,
        completion_tokens=50000,  # 100k tokens * $0.008/1k = $0.80
    )
    alerts_usd, actions_usd = mon.evaluate(
        [box2],
        telemetry_mgr=telem_mgr,
        settings={"default_max_cost_usd_budget": 0.50},
        now=2005.0,
    )
    assert len(alerts_usd) == 1
    assert alerts_usd[0].category == "budget_exceeded"
    assert actions_usd == [("krunbox-usd", "stop", "AI budget guardrail exceeded")]


def test_guardrail_idle_auto_pause_and_reset_on_activity():
    ssh_active = {"connected": False}
    mon = GuardrailMonitor(
        cooldown_seconds=300.0,
        ssh_checker=lambda _name, _port: ssh_active["connected"],
    )
    box = _make_box(
        name="krunbox-sleepy",
        cpu_percent=0.3,
        idle_timeout_minutes=5,
        idle_action="pause",
    )

    # t=100: becomes idle
    alerts, actions = mon.evaluate([box], now=100.0)
    assert alerts == [] and actions == []
    assert mon.get_idle_seconds("krunbox-sleepy", now=220.0) == pytest.approx(120.0)

    # t=250: CPU spikes to 12.5% -> resets idle timer immediately
    box.cpu_percent = 12.5
    mon.evaluate([box], now=250.0)
    assert mon.get_idle_seconds("krunbox-sleepy", now=250.0) == 0.0

    # t=300: CPU drops back to 0.1%, idle starts again
    box.cpu_percent = 0.1
    mon.evaluate([box], now=300.0)
    assert mon.get_idle_seconds("krunbox-sleepy", now=400.0) == pytest.approx(100.0)

    # t=420: Interactive SSH session connects -> resets idle timer immediately
    ssh_active["connected"] = True
    mon.evaluate([box], now=420.0)
    assert mon.get_idle_seconds("krunbox-sleepy", now=420.0) == 0.0

    # t=500: SSH disconnects -> idle timer restarts; fires after 5 * 60 = 300s at t=800
    ssh_active["connected"] = False
    mon.evaluate([box], now=500.0)
    # t=550: idle for 50s (not yet in warning window: timeout=300, warning_window=150, so warning starts at t=650)
    alerts_early, actions_early = mon.evaluate([box], now=550.0)
    assert alerts_early == [] and actions_early == []

    # t=799: within warning window -> emits idle_pre_warning alert before sleep
    alerts_mid, actions_mid = mon.evaluate([box], now=799.0)
    assert actions_mid == []
    assert len(alerts_mid) == 1
    assert alerts_mid[0].category == "idle_pre_warning"

    alerts_fire, actions_fire = mon.evaluate([box], now=800.0)
    assert actions_fire == [
        ("krunbox-sleepy", "pause", "Idle for 5m (<1% CPU, 0 SSH sessions)")
    ]
    assert len(alerts_fire) == 1
    assert alerts_fire[0].category == "idle_action"
    assert mon.get_idle_seconds("krunbox-sleepy", now=800.0) == 0.0


# =========================================================================
# 5. Desktop Notifications & Command Completion Wrapper
# =========================================================================

def test_headless_send_desktop_notification_and_notify_send(monkeypatch):
    # Headless environment (no DISPLAY, WAYLAND_DISPLAY, DBUS_SESSION_BUS_ADDRESS, no registered Gio app)
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    assert send_desktop_notification("Test Title", "Test Body", app=None) is False

    # Registered Gio.Application path
    mock_app = MagicMock()
    mock_app.get_is_registered.return_value = True
    dispatched_gio = send_desktop_notification(
        "Gio Alert",
        "Critical event",
        notification_id="custom-nid-1",
        urgent=True,
        app=mock_app,
    )
    assert dispatched_gio is True
    assert mock_app.send_notification.call_count == 1
    assert mock_app.send_notification.call_args[0][0] == "custom-nid-1"

    # With DISPLAY + notify-send available -> dispatches cleanly
    monkeypatch.setenv("DISPLAY", ":99")
    with patch("krunbox.core.notifications.shutil.which", return_value="/usr/bin/notify-send"), \
         patch("krunbox.core.notifications.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        sent = send_desktop_notification("Alert", "High RAM", urgent=True, app=None)
        assert sent is True
        cmd = mock_run.call_args[0][0]
        assert cmd == ["notify-send", "-a", "krunbox", "-u", "critical", "Alert", "High RAM"]


def test_host_netns_script_injection_hardening_and_first_observation_spike(tmp_path):
    # Malicious profile & domains & invalid ssh port are sanitized cleanly
    malicious_policy = NetworkPolicy(
        profile="offline'; rm -rf / #",
        allowed_domains=["valid.example.com", "bad; touch /tmp/pwn"],
        denied_domains=["evil.com && reboot"],
    )
    script = generate_host_netns_nft_script(malicious_policy, guest_ssh_port=99999)
    assert "rm -rf /" not in script
    assert "touch /tmp/pwn" not in script
    assert "reboot" not in script
    assert "Profile: custom" in script
    assert "tcp sport 2222 accept" in script

    # First-observation recent blocked spike (within 120s) fires immediately
    egress_mgr = EgressTrafficManager(logs_dir=tmp_path / "recent_spike_logs")
    for i in range(6):
        egress_mgr.record_event(
            "krunbox-fresh",
            "leak.badactor.org",
            action="blocked",
            timestamp=5000.0 + i,
        )
    mon = GuardrailMonitor(blocked_spike_threshold=5, ssh_checker=lambda _n, _p: False)
    box = _make_box(name="krunbox-fresh")
    alerts, _ = mon.evaluate([box], egress_traffic_mgr=egress_mgr, now=5020.0)
    assert len(alerts) == 1
    assert alerts[0].category == "egress_spike"
    assert "leak.badactor.org" in alerts[0].body


def test_run_with_completion_notification():
    assert _format_duration(14.2) == "14.2s"
    assert _format_duration(125.0) == "2m 05s"

    captured = []

    def fake_send(title, body, notification_id=None, urgent=False, app=None):
        captured.append((title, body, urgent))
        return True

    with patch("krunbox.core.notifications.send_desktop_notification", side_effect=fake_send):
        rc_ok = run_with_completion_notification("krunbox-build", "pytest -q", lambda: 0)
        assert rc_ok == 0
        assert captured[-1][2] is False
        assert "Completed" in captured[-1][0]

        mon = GuardrailMonitor()
        rc_fail = mon.run_with_completion_notification("krunbox-build", "make release", lambda: 2)
        assert rc_fail == 2
        assert captured[-1][2] is True
        assert "Failed (2)" in captured[-1][0]


def test_no_forbidden_three_letter_token_in_new_modules():
    forbidden = "s" + "b" + "x"
    pattern = re.compile(rf"\b{forbidden}\b", re.IGNORECASE)
    for rel in (
        "krunbox/core/host_egress.py",
        "krunbox/core/notifications.py",
        "tests/test_host_egress_and_guardrails.py",
    ):
        text = (_WORKSPACE_ROOT / rel).read_text(encoding="utf-8")
        assert pattern.findall(text) == [], f"Forbidden token found in {rel}"
