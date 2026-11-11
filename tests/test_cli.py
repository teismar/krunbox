"""
Unit tests for krunbox CLI command suite including sandbox editing and egress traffic reporting.
"""

from unittest.mock import patch, MagicMock
import sys
import pytest

from krunbox.cli.main import main
from krunbox.core.manager import SandboxManager
from krunbox.core.egress_traffic import EgressTrafficManager


@pytest.fixture(autouse=True)
def isolate_state(tmp_path):
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
        return m

    with patch("krunbox.cli.main.SandboxManager", _make_mgr), \
         patch("krunbox.core.manager.STATE_FILE", temp_state), \
         patch("krunbox.core.manager.DATA_DIR", temp_data), \
         patch("krunbox.core.telemetry.TELEMETRY_DIR", temp_telem), \
         patch("krunbox.core.egress_traffic.EGRESS_LOGS_DIR", temp_egress_logs), \
         patch("krunbox.core.ssh.SSH_CONF_DIR", temp_ssh_dir), \
         patch("krunbox.core.ssh.SSH_CONFIG_FILE", temp_ssh_cfg):
        yield temp_state, temp_egress_logs


def test_cli_list(capsys):
    with patch.object(sys, "argv", ["krunbox", "list"]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        assert "NAME" in captured.out or "No active" in captured.out


def test_cli_create_default_sizing(tmp_path, capsys, isolate_state):
    temp_state, _ = isolate_state
    test_dir = tmp_path / "cli_test"
    test_dir.mkdir()

    with patch.object(sys, "argv", [
        "krunbox", "create", str(test_dir),
        "--name", "corporate-vm",
        "-P",
        "--network", "ai-only",
        "-p", "3000:3000"
    ]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        assert "Registered sandbox 'krunbox-corporate-vm'" in captured.out
        assert "Persistent" in captured.out

    mgr = SandboxManager(state_file=temp_state)
    box = mgr.get_sandbox("corporate-vm")
    assert box.cpus == 4
    assert box.ram_mib == 4096


def test_cli_edit_sandbox_hardware_rename_and_network(tmp_path, capsys, isolate_state):
    temp_state, _ = isolate_state
    test_dir = tmp_path / "edit_proj"
    test_dir.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(test_dir), "--name", "editable-vm"]):
        assert main() == 0
    capsys.readouterr()

    with patch("subprocess.run"):
        with patch.object(sys, "argv", [
            "krunbox", "edit", "editable-vm",
            "--rename", "edited-vm",
            "--cpus", "6",
            "--ram", "6144",
            "--network", "custom",
            "--allow", "api.openai.com",
            "--allow", "pypi.org",
            "--deny", "tracker.example.com",
        ]):
            assert main() == 0
            out = capsys.readouterr().out
            assert "krunbox-edited-vm" in out
            assert "6 vCPUs / 6144 MiB RAM" in out

        # Test --remove-allow and --clear-deny via update alias
        with patch.object(sys, "argv", [
            "krunbox", "update", "edited-vm",
            "--remove-allow", "pypi.org",
            "--clear-deny",
        ]):
            assert main() == 0
            capsys.readouterr()

    mgr = SandboxManager(state_file=temp_state)
    updated = mgr.get_sandbox("edited-vm")
    assert updated is not None
    assert updated.cpus == 6
    assert updated.ram_mib == 6144
    assert updated.network_policy.profile == "custom"
    assert updated.network_policy.allowed_domains == ["api.openai.com"]
    assert updated.network_policy.denied_domains == []


def test_cli_traffic_and_network_stats(tmp_path, capsys, isolate_state):
    _temp_state, temp_egress_logs = isolate_state
    test_dir = tmp_path / "traffic_proj"
    test_dir.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(test_dir), "--name", "net-vm"]):
        assert main() == 0
    capsys.readouterr()

    emgr = EgressTrafficManager(logs_dir=temp_egress_logs)
    emgr.record_event("krunbox-net-vm", "api.anthropic.com", action="allowed", timestamp=1700000100.0)
    emgr.record_event("krunbox-net-vm", "api.anthropic.com", action="allowed", timestamp=1700000200.0)
    emgr.record_event("krunbox-net-vm", "malware.example.org", action="blocked", reason="Blacklisted", timestamp=1700000300.0)

    with patch.object(sys, "argv", ["krunbox", "traffic", "net-vm"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "Outbound Egress Traffic Audit" in out
        assert "api.anthropic.com" in out
        assert "AI Provider" in out
        assert "malware.example.org" in out
        assert "Total Requests:" in out

    # Also test `krunbox network --traffic`
    with patch("subprocess.run"):
        with patch.object(sys, "argv", ["krunbox", "network", "net-vm", "--profile", "ai-only", "--traffic"]):
            assert main() == 0
            out = capsys.readouterr().out
            assert "AI-ONLY" in out
            assert "Outbound Egress Traffic Audit" in out

    # Test clearing traffic logs via CLI
    with patch.object(sys, "argv", ["krunbox", "traffic", "net-vm", "--clear"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "Cleared egress traffic logs" in out
    assert emgr.get_domain_stats("krunbox-net-vm")["total_requests"] == 0


def test_cli_doctor(capsys):
    with patch.object(sys, "argv", ["krunbox", "doctor"]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        assert "System Diagnostics" in captured.out
        assert "Podman" in captured.out


def test_cli_api_stats(capsys):
    with patch.object(sys, "argv", ["krunbox", "api-stats"]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        assert "AI Model Invocation Audit" in captured.out


def test_cli_connect_terminal(tmp_path, capsys):
    test_dir = tmp_path / "conn_test"
    test_dir.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(test_dir), "--name", "conn-box", "-P"]):
        assert main() == 0

    with patch("krunbox.core.ssh.launch_ssh_terminal", return_value=(True, "Launched ptyxis (PID 1234)")) as mock_term, \
         patch("krunbox.core.manager.SandboxManager.start_sandbox", return_value=(True, "started")):
        with patch.object(sys, "argv", ["krunbox", "connect", "conn-box", "--terminal"]):
            res = main()
            assert res == 0
            captured = capsys.readouterr()
            assert "Launched ptyxis" in captured.out
            mock_term.assert_called_once_with("krunbox-conn-box")


def test_cli_run_with_template(tmp_path, capsys, isolate_state):
    temp_state, _ = isolate_state
    test_dir = tmp_path / "tmpl_test"
    test_dir.mkdir()

    with patch("krunbox.core.manager.SandboxManager.start_sandbox", return_value=(True, "started")):
        with patch.object(sys, "argv", [
            "krunbox", "run", str(test_dir),
            "--name", "reviewer-vm",
            "--template", "locked-down-reviewer",
            "-d",
        ]):
            res = main()
            assert res == 0
            out = capsys.readouterr().out
            assert "locked-down-reviewer" in out or "reviewer-vm" in out

    mgr = SandboxManager(state_file=temp_state)
    box = mgr.get_sandbox("reviewer-vm")
    assert box is not None
    assert box.cpus == 2
    assert box.ram_mib == 2048
    assert box.network_policy.profile == "offline"
    assert box.protect_git_hooks is True
    assert box.protect_git_config is True
    assert box.host_egress_lockdown is True


def test_cli_pause_and_unpause(tmp_path, capsys, isolate_state):
    temp_state, _ = isolate_state
    test_dir = tmp_path / "pause_cli_test"
    test_dir.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(test_dir), "--name", "pbox"]):
        assert main() == 0
    capsys.readouterr()

    mgr = SandboxManager(state_file=temp_state)
    box = mgr.get_sandbox("pbox")
    box.status = "running"
    mgr.save_state()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with patch.object(sys, "argv", ["krunbox", "pause", "pbox"]):
            assert main() == 0
            out = capsys.readouterr().out
            assert "paused" in out.lower()

        with patch.object(sys, "argv", ["krunbox", "unpause", "pbox"]):
            assert main() == 0
            out = capsys.readouterr().out
            assert "resumed" in out.lower()


def test_cli_diff_rollback_and_snapshot(tmp_path, capsys, isolate_state):
    test_dir = tmp_path / "diff_test"
    test_dir.mkdir()
    f1 = test_dir / "app.py"
    f1.write_text("print('v1')\n")

    with patch.object(sys, "argv", ["krunbox", "create", str(test_dir), "--name", "diff-box"]):
        assert main() == 0
    capsys.readouterr()

    # Create baseline snapshot
    with patch.object(sys, "argv", ["krunbox", "snapshot", "diff-box"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "snapshot" in out.lower() or "✓" in out

    # Mutate file
    f1.write_text("print('v2 modified')\n")

    # Inspect diff
    with patch.object(sys, "argv", ["krunbox", "diff", "diff-box"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "app.py" in out

    # Rollback
    with patch.object(sys, "argv", ["krunbox", "rollback", "diff-box", "--file", "app.py"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "reverted" in out.lower()
    assert f1.read_text() == "print('v1')\n"


def test_cli_code_ide_launcher(tmp_path, capsys, isolate_state):
    test_dir = tmp_path / "code_test"
    test_dir.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(test_dir), "--name", "code-box"]):
        assert main() == 0
    capsys.readouterr()

    with patch("krunbox.core.manager.SandboxManager.start_sandbox", return_value=(True, "started")), \
         patch("krunbox.core.ide.launch_ide", return_value=(True, "Launched VS Code Remote-SSH")) as mock_launch:
        with patch.object(sys, "argv", ["krunbox", "code", "code-box", "--ide", "vscode"]):
            assert main() == 0
            out = capsys.readouterr().out
            assert "Launched VS Code" in out
            mock_launch.assert_called_once()


def test_cli_templates_crud(tmp_path, capsys, isolate_state):
    test_dir = tmp_path / "tmpl_save_test"
    test_dir.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(test_dir), "--name", "src-box", "--cpus", "6", "--ram", "6144"]):
        assert main() == 0
    capsys.readouterr()

    # List templates
    with patch.object(sys, "argv", ["krunbox", "templates", "list"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "standard-agent" in out
        assert "locked-down-reviewer" in out

    # Save custom template
    with patch.object(sys, "argv", ["krunbox", "templates", "save", "my-custom-preset", "--from-sandbox", "src-box"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "Saved custom template" in out

    # Delete custom template
    with patch.object(sys, "argv", ["krunbox", "templates", "delete", "my-custom-preset"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "Deleted custom template" in out


def test_cli_secret_vault_crud(tmp_path, capsys, isolate_state):
    test_dir = tmp_path / "sec_test"
    test_dir.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(test_dir), "--name", "sec-box"]):
        assert main() == 0
    capsys.readouterr()

    # Secret set
    with patch.object(sys, "argv", ["krunbox", "secret", "set", "sec-box", "ANTHROPIC_KEY", "sk-ant-test1234"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "Stored 'ANTHROPIC_KEY'" in out

    # Secret list
    with patch.object(sys, "argv", ["krunbox", "secret", "list", "sec-box"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "ANTHROPIC_KEY" in out

    # Secret rm
    with patch.object(sys, "argv", ["krunbox", "secret", "rm", "sec-box", "ANTHROPIC_KEY"]):
        assert main() == 0
        out = capsys.readouterr().out
        assert "Removed secret 'ANTHROPIC_KEY'" in out


def test_cli_exec_with_notify(tmp_path, capsys, isolate_state):
    temp_state, _ = isolate_state
    test_dir = tmp_path / "exec_test"
    test_dir.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(test_dir), "--name", "exec-box"]):
        assert main() == 0
    capsys.readouterr()

    mgr = SandboxManager(state_file=temp_state)
    box = mgr.get_sandbox("exec-box")
    assert box is not None
    box.status = "running"
    mgr.save_state()

    with patch("subprocess.run", return_value=MagicMock(returncode=0)), \
         patch("krunbox.cli.commands.run_with_completion_notification", return_value=0) as mock_notify:
        with patch.object(sys, "argv", ["krunbox", "exec", "-N", "exec-box", "echo", "done"]):
            res = main()
            assert res == 0
            mock_notify.assert_called_once()


def test_cli_idle_check(capsys):
    with patch("krunbox.core.manager.SandboxManager.evaluate_guardrails", return_value=([], [])):
        with patch.object(sys, "argv", ["krunbox", "idle-check"]):
            res = main()
            assert res == 0
            out = capsys.readouterr().out
            assert "nominal operating thresholds" in out


def test_cli_traffic_export_options(tmp_path, capsys, isolate_state):
    temp_state, temp_egress = isolate_state
    mgr = SandboxManager(state_file=temp_state)
    mgr.egress_traffic = EgressTrafficManager(logs_dir=temp_egress)

    # Populate sample egress traffic
    mgr.egress_traffic.record_event("test-box", "api.github.com", action="allowed", port=443, reason="dev")
    mgr.egress_traffic.record_event("test-box", "ads.example.com", action="blocked", port=80, reason="blocked")

    # 1. Test krunbox traffic --export <file.csv>
    csv_file = tmp_path / "traffic_export.csv"
    with patch.object(sys, "argv", ["krunbox", "traffic", "--export", str(csv_file)]):
        ret = main()
        assert ret == 0
        captured = capsys.readouterr()
        assert "Exported 2 domain records" in captured.out
        assert csv_file.is_file()
        content = csv_file.read_text(encoding="utf-8")
        assert "api.github.com" in content
        assert "ads.example.com" in content

    # 2. Test krunbox traffic -o <file.json>
    json_file = tmp_path / "traffic_export.json"
    with patch.object(sys, "argv", ["krunbox", "traffic", "-o", str(json_file)]):
        ret = main()
        assert ret == 0
        captured = capsys.readouterr()
        assert "Exported 2 domain records" in captured.out
        assert json_file.is_file()
        import json
        data = json.loads(json_file.read_text(encoding="utf-8"))
        assert data["total_sites"] == 2
        domains = {s["domain"] for s in data["sites"]}
        assert domains == {"api.github.com", "ads.example.com"}

    # 3. Test krunbox traffic --export with --json output flag
    json_flag_csv = tmp_path / "traffic_flag.csv"
    with patch.object(sys, "argv", ["krunbox", "traffic", "--export", str(json_flag_csv), "--json"]):
        ret = main()
        assert ret == 0
        captured = capsys.readouterr()
        import json
        parsed = json.loads(captured.out)
        assert parsed["status"] == "ok"
        assert json_flag_csv.is_file()


