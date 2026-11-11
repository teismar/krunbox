"""
Unit tests for Rich table, status indicator, and formatting migration in krunbox CLI.
Validates table headers, column layouts, badges, and purity of --json output.
"""

import json
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch
import pytest

from krunbox.cli.main import main
from krunbox.core.manager import SandboxManager
from krunbox.core.egress_traffic import EgressTrafficManager
from krunbox.core.telemetry import TelemetryManager
from krunbox.core.ipc_server import AccessRequest


@pytest.fixture(autouse=True)
def isolate_cli(tmp_path):
    """Hermetic fixture isolating state, telemetry, egress logs, and SSH configurations."""
    temp_state = tmp_path / "sandboxes.json"
    temp_data = tmp_path / "data"
    temp_telem = temp_data / "telemetry"
    temp_egress_logs = temp_data / "egress_logs"
    temp_ssh_dir = tmp_path / "ssh_conf"
    temp_ssh_cfg = tmp_path / "ssh_config"
    temp_telem.mkdir(parents=True, exist_ok=True)
    temp_ssh_dir.mkdir(parents=True, exist_ok=True)

    def _make_mgr():
        m = SandboxManager(state_file=temp_state)
        m.egress_traffic = EgressTrafficManager(logs_dir=temp_egress_logs)
        m.telemetry.telemetry_dir = temp_telem
        m._sync_with_podman = lambda: None
        return m

    with patch("krunbox.cli.main.SandboxManager", _make_mgr), \
         patch("krunbox.core.manager.STATE_FILE", temp_state), \
         patch("krunbox.core.manager.DATA_DIR", temp_data), \
         patch("krunbox.core.telemetry.TELEMETRY_DIR", temp_telem), \
         patch("krunbox.core.egress_traffic.EGRESS_LOGS_DIR", temp_egress_logs), \
         patch("krunbox.core.ssh.SSH_CONF_DIR", temp_ssh_dir), \
         patch("krunbox.core.ssh.SSH_CONFIG_FILE", temp_ssh_cfg):
        yield temp_state, temp_egress_logs, temp_telem


def test_cli_list_rich_table_empty(capsys):
    """Verify empty sandbox list formats cleanly with notice."""
    with patch.object(sys, "argv", ["krunbox", "list"]):
        assert main() == 0
        captured = capsys.readouterr()
        assert "No active or registered sandboxes" in captured.out


def test_cli_list_rich_table_populated(tmp_path, capsys, isolate_cli):
    """Verify `krunbox list` outputs a styled Rich table with expected headers and row data."""
    temp_state, _, _ = isolate_cli
    d1 = tmp_path / "box1"
    d1.mkdir()
    d2 = tmp_path / "box2"
    d2.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(d1), "--name", "worker-1", "-P", "--network", "full"]):
        assert main() == 0
    with patch.object(sys, "argv", ["krunbox", "create", str(d2), "--name", "agent-2", "--network", "ai-only"]):
        assert main() == 0
    capsys.readouterr()

    # Mark worker-1 as running
    mgr = SandboxManager(state_file=temp_state)
    b1 = mgr.get_sandbox("worker-1")
    b1.status = "running"
    mgr.save_state()

    with patch.object(sys, "argv", ["krunbox", "list"]):
        assert main() == 0
        out = capsys.readouterr().out
        # Rich Table column headers
        assert "NAME" in out
        assert "STATUS" in out
        assert "MODE" in out
        assert "NETWORK" in out
        assert "SSH PORT" in out
        assert "PORTS" in out
        assert "DIR" in out
        # Sandbox names
        assert "worker-1" in out
        assert "agent-2" in out
        # Badges and modes
        assert "RUNNING" in out
        assert "STOPPED" in out
        assert "PERSISTENT" in out
        assert "EPHEMERAL" in out
        # Active instances footer
        assert "Active instances: 2" in out


def test_cli_list_rich_table_all_info(tmp_path, capsys, isolate_cli):
    """Verify `krunbox list -a` includes the RESOURCES column."""
    temp_state, _, _ = isolate_cli
    d1 = tmp_path / "res_box"
    d1.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(d1), "--name", "res-box"]):
        assert main() == 0
    capsys.readouterr()

    with patch.object(sys, "argv", ["krunbox", "list", "-a"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "RESOURCES" in out
        assert "res-box" in out


def test_cli_templates_rich_table(capsys):
    """Verify `krunbox templates list` renders presets inside a Rich table."""
    with patch.object(sys, "argv", ["krunbox", "templates", "list"]):
        assert main() == 0
        out = capsys.readouterr().out
        # Columns
        assert "ID" in out
        assert "NAME" in out
        assert "TYPE" in out
        assert "CPUS/RAM" in out
        assert "NETWORK" in out
        assert "PORTS" in out
        # Presets
        assert "locked-down-reviewer" in out
        assert "standard-agent" in out
        assert "BUILTIN" in out


def test_cli_images_rich_tables(capsys):
    """Verify `krunbox images list` and `check` render Rich tables."""
    sample_images = [
        {
            "id": "base-fedora",
            "is_present": True,
            "needs_rebuild": False,
            "age_days": 2.5,
            "rebuild_reason": "Up-to-date",
            "tag": "localhost/krunbox-base:latest",
            "description": "Standard base runtime container",
        },
        {
            "id": "python-dev",
            "is_present": False,
            "needs_rebuild": False,
            "age_days": None,
            "rebuild_reason": "Not pulled",
            "tag": "localhost/krunbox-python:latest",
            "description": "Python data science and AI environment",
        },
    ]

    with patch("krunbox.core.images.ImageManager.list_images", return_value=sample_images):
        # 1. Default images list
        with patch.object(sys, "argv", ["krunbox", "images", "list"]):
            assert main() == 0
            out = capsys.readouterr().out
            assert "ID" in out
            assert "STATUS" in out
            assert "TAG" in out
            assert "DESCRIPTION" in out
            assert "base-fedora" in out
            assert "python-dev" in out
            assert "PRESENT" in out
            assert "AVAILABLE" in out

        # 2. Images check / status table
        with patch.object(sys, "argv", ["krunbox", "images", "check"]):
            assert main() == 0
            out = capsys.readouterr().out
            assert "ID" in out
            assert "STATUS" in out
            assert "AGE" in out
            assert "SPEC / REBUILD REASON" in out
            assert "UP-TO-DATE" in out
            assert "MISSING" in out


def test_cli_traffic_rich_tables(tmp_path, capsys, isolate_cli):
    """Verify `krunbox traffic` renders Top Destinations and Recent Events Rich tables."""
    _temp_state, temp_egress_logs, _ = isolate_cli
    d = tmp_path / "tr_box"
    d.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(d), "--name", "traffic-vm"]):
        assert main() == 0
    capsys.readouterr()

    emgr = EgressTrafficManager(logs_dir=temp_egress_logs)
    emgr.record_event("krunbox-traffic-vm", "api.openai.com", action="allowed", timestamp=1700000100.0)
    emgr.record_event("krunbox-traffic-vm", "api.anthropic.com", action="allowed", timestamp=1700000200.0)
    emgr.record_event("krunbox-traffic-vm", "evil.attacker.org", action="blocked", reason="Zero-day blacklist", timestamp=1700000300.0)

    with patch.object(sys, "argv", ["krunbox", "traffic", "traffic-vm"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "Outbound Egress Traffic Audit" in out
        assert "Total Requests:" in out
        assert "Top Domain Destinations" in out
        assert "Recent Egress Events" in out
        # Columns
        assert "DOMAIN" in out
        assert "CATEGORY" in out
        assert "CALLS" in out
        assert "ALLOWED" in out
        assert "BLOCKED" in out
        # Rows
        assert "api.openai.com" in out
        assert "api.anthropic.com" in out
        assert "evil.attacker.org" in out
        assert "Zero-day blacklist" in out


def test_cli_api_stats_rich_table(tmp_path, capsys, isolate_cli):
    """Verify `krunbox api-stats` renders recent model invocations inside a Rich table."""
    _, _, temp_telem = isolate_cli
    tmgr = TelemetryManager(telemetry_dir=temp_telem)
    tmgr.record_call(
        sandbox_name="tele-box",
        provider="Anthropic",
        endpoint="/v1/messages",
        model="claude-3-7-sonnet",
        status_code=200,
        prompt_tokens=450,
        completion_tokens=150,
        latency_ms=920.0,
    )

    with patch.object(sys, "argv", ["krunbox", "api-stats"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "AI Model Invocation Audit" in out
        assert "Recent AI Invocations" in out
        assert "TIME" in out
        assert "PROVIDER" in out
        assert "MODEL" in out
        assert "STATUS" in out
        assert "TOKENS" in out
        assert "claude-3-7-sonnet" in out
        assert "Anthropic" in out
        assert "600" in out


def test_cli_requests_rich_table(capsys, isolate_cli):
    """Verify `krunbox requests` renders agent access requests inside a Rich table."""
    req1 = AccessRequest(
        id="req-agent-001",
        sandbox_name="krunbox-agent-box",
        action="request_domain_access",
        domain="api.deepmind.com",
        reason="Model distillation experiment",
        status="pending",
    )
    req2 = AccessRequest(
        id="req-agent-002",
        sandbox_name="krunbox-agent-box",
        action="request_port_forward",
        guest_port=8080,
        reason="Local debugger binding",
        status="approved",
    )

    with patch("krunbox.core.manager.SandboxManager.list_pending_requests", return_value=[req1, req2]):
        with patch.object(sys, "argv", ["krunbox", "requests"]):
            assert main() == 0
            out = capsys.readouterr().out
            assert "Agent Access Requests" in out
            assert "REQUEST ID" in out
            assert "SANDBOX" in out
            assert "TYPE" in out
            assert "TARGET" in out
            assert "STATUS" in out
            assert "REASON" in out
            assert "req-agent-001" in out
            assert "req-agent-002" in out
            assert "api.deepmind.com" in out
            assert "8080" in out
            assert "PENDING" in out
            assert "APPROVED" in out


def test_cli_doctor_rich_table(capsys):
    """Verify `krunbox doctor` renders system component diagnostics inside a Rich table."""
    with patch.object(sys, "argv", ["krunbox", "doctor"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "System Diagnostics" in out
        assert "STATUS" in out
        assert "COMPONENT" in out
        assert "MESSAGE" in out
        assert "REMEDIATION / FIX" in out
        assert "Podman" in out


def test_cli_ports_rich_table(tmp_path, capsys, isolate_cli):
    """Verify `krunbox ports <name>` renders forwarded ports in a Rich table."""
    d = tmp_path / "port_box"
    d.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(d), "--name", "port-vm", "-p", "8080:80"]):
        assert main() == 0
    capsys.readouterr()

    with patch.object(sys, "argv", ["krunbox", "ports", "port-vm"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "Port Configurations for krunbox-port-vm:" in out
        assert "TYPE" in out
        assert "HOST PORT" in out
        assert "GUEST PORT" in out
        assert "DETAILS" in out
        assert "8080" in out
        assert "80" in out


def test_cli_json_remains_pure_with_rich(tmp_path, capsys, isolate_cli):
    """Verify that all commands with `--json` output pure, parseable JSON without Rich artifacts."""
    d = tmp_path / "pure_json_box"
    d.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(d), "--name", "json-pure-box"]):
        assert main() == 0
    capsys.readouterr()

    # 1. list --json
    with patch.object(sys, "argv", ["krunbox", "list", "--json"]):
        assert main() == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)
        assert any(b["name"] == "krunbox-json-pure-box" for b in data)

    # 2. doctor --json
    with patch.object(sys, "argv", ["krunbox", "doctor", "--json"]):
        assert main() == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)
        assert any(c["component"] == "Podman Engine" for c in data)

    # 3. traffic --json
    with patch.object(sys, "argv", ["krunbox", "traffic", "json-pure-box", "--json"]):
        assert main() == 0
        data = json.loads(capsys.readouterr().out)
        assert "stats" in data
        assert "events" in data

    # 4. api-stats --json
    with patch.object(sys, "argv", ["krunbox", "api-stats", "--json"]):
        assert main() == 0
        data = json.loads(capsys.readouterr().out)
        assert "summary" in data

    # 5. ports --json
    with patch.object(sys, "argv", ["krunbox", "ports", "json-pure-box", "--json"]):
        assert main() == 0
        data = json.loads(capsys.readouterr().out)
        assert "sandbox" in data
        assert "published_ports" in data
