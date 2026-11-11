"""
Advanced unit and integration tests for krunbox CLI command suite:
- JSON output formats (`list --json`, `stats --json`, `doctor --json`, `traffic --json`, `requests --json`, `ports --json`)
- Sandbox cloning (`krunbox clone <source> <new_name>`)
- Sandbox bundle export & import (`krunbox export <name> -o <archive.tar.gz>`, `krunbox import <archive> [--name <name>]`)
- Daemon execution (`krunbox daemon --once`)
- Shell completions (`krunbox completion bash|fish|zsh`)
"""

import json
import sys
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from krunbox.cli.main import main
from krunbox.core.manager import SandboxManager
from krunbox.core.egress_traffic import EgressTrafficManager
from krunbox.core.ipc_server import AccessRequest
from krunbox.core.notifications import AlertEvent


@pytest.fixture(autouse=True)
def isolate_cli(tmp_path):
    """
    Ensure hermetic state, telemetry, egress logs, and SSH configs for CLI tests.
    """
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
        yield temp_state, temp_egress_logs


# ============================================================================
# 1. JSON CLI Output Format Tests
# ============================================================================

def test_cli_list_json_empty(capsys, isolate_cli):
    """Verify `krunbox list --json` outputs valid empty JSON array when no sandboxes exist."""
    with patch.object(sys, "argv", ["krunbox", "list", "--json"]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data == [] or (isinstance(data, dict) and data.get("sandboxes") == [])


def test_cli_list_json_populated(tmp_path, capsys, isolate_cli):
    """Verify `krunbox list --json` formats active/registered sandboxes as valid structured JSON."""
    temp_state, _ = isolate_cli
    test_dir = tmp_path / "list_json_proj"
    test_dir.mkdir()

    with patch.object(sys, "argv", [
        "krunbox", "create", str(test_dir),
        "--name", "json-box",
        "--cpus", "4",
        "--ram", "4096",
        "--network", "ai-only",
    ]):
        assert main() == 0
    capsys.readouterr()

    with patch.object(sys, "argv", ["krunbox", "list", "--json"]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        boxes = data if isinstance(data, list) else data.get("sandboxes", [])
        assert len(boxes) >= 1
        box = next((b for b in boxes if "json-box" in b.get("name", "")), None)
        assert box is not None
        assert box.get("cpus") == 4
        assert box.get("ram_mib") == 4096
        assert box.get("status") in ("stopped", "running", "paused")


def test_cli_stats_json(capsys):
    """Verify `krunbox stats --json` outputs container telemetry in JSON format."""
    with patch.object(sys, "argv", ["krunbox", "stats", "--json"]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, dict)


def test_cli_doctor_json(capsys):
    """Verify `krunbox doctor --json` outputs diagnostic checks as structured JSON."""
    with patch.object(sys, "argv", ["krunbox", "doctor", "--json"]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        checks = data if isinstance(data, list) else data.get("checks", [])
        assert len(checks) > 0
        first = checks[0]
        assert "component" in first
        assert "status" in first
        assert first["status"] in ("ok", "warn", "fail")


def test_cli_traffic_json(tmp_path, capsys, isolate_cli):
    """Verify `krunbox traffic --json` returns network egress audit data in JSON format."""
    _temp_state, temp_egress_logs = isolate_cli
    emgr = EgressTrafficManager(logs_dir=temp_egress_logs)
    emgr.record_event("krunbox-analytics-box", "api.anthropic.com", action="allowed", timestamp=1700000100.0)
    emgr.record_event("krunbox-analytics-box", "malware.suspicious.io", action="blocked", reason="Malware domain", timestamp=1700000200.0)

    # Global egress audit in JSON
    with patch.object(sys, "argv", ["krunbox", "traffic", "--json"]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "stats" in data
        assert data["stats"]["total_requests"] >= 2
        assert data["stats"]["allowed_requests"] >= 1
        assert data["stats"]["blocked_requests"] >= 1
        assert "sites" in data["stats"]
        assert any(s["domain"] == "api.anthropic.com" for s in data["stats"]["sites"])

    # Filtered by sandbox name in JSON
    with patch.object(sys, "argv", ["krunbox", "traffic", "krunbox-analytics-box", "--json"]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["stats"]["total_requests"] >= 2
        assert "sites" in data["stats"]


def test_cli_requests_json(capsys, isolate_cli):
    """Verify `krunbox requests --json` outputs in-flight agent permission requests as JSON."""
    req = AccessRequest(
        id="req-test1234",
        sandbox_name="krunbox-agent-box",
        action="request_domain_access",
        domain="registry.npmjs.org",
        reason="Install npm packages",
    )
    with patch("krunbox.core.manager.SandboxManager.list_pending_requests", return_value=[req]):
        with patch.object(sys, "argv", ["krunbox", "requests", "--json"]):
            res = main()
            assert res == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            reqs = data if isinstance(data, list) else data.get("requests", [])
            assert len(reqs) >= 1
            item = next((r for r in reqs if r.get("id") == "req-test1234"), None)
            assert item is not None
            assert item.get("sandbox_name") == "krunbox-agent-box"
            assert item.get("status") == "pending"


# ============================================================================
# 2. Sandbox Clone Tests
# ============================================================================

def test_cli_clone_success(tmp_path, capsys, isolate_cli):
    """Verify `krunbox clone <source> <new_name>` duplicates configuration and registers the new sandbox."""
    temp_state, _ = isolate_cli
    src_dir = tmp_path / "clone_source_dir"
    src_dir.mkdir()

    with patch.object(sys, "argv", [
        "krunbox", "create", str(src_dir),
        "--name", "source-vm",
        "--cpus", "6",
        "--ram", "6144",
        "--network", "ai-only",
        "--allow", "api.openai.com",
        "-P",
    ]):
        assert main() == 0
    capsys.readouterr()

    with patch("subprocess.run"):
        with patch.object(sys, "argv", ["krunbox", "clone", "source-vm", "cloned-vm"]):
            res = main()
            assert res == 0
            captured = capsys.readouterr()
            assert "cloned-vm" in captured.out or "krunbox-cloned-vm" in captured.out

    mgr = SandboxManager(state_file=temp_state)
    src_box = mgr.get_sandbox("source-vm")
    cloned_box = mgr.get_sandbox("cloned-vm")

    assert src_box is not None
    assert cloned_box is not None
    assert "cloned-vm" in cloned_box.name
    assert cloned_box.cpus == 6
    assert cloned_box.ram_mib == 6144
    assert cloned_box.network_policy.profile == "ai-only"
    assert "api.openai.com" in cloned_box.network_policy.allowed_domains
    assert cloned_box.is_persistent is True
    assert cloned_box.ssh_port != src_box.ssh_port
    assert cloned_box.status == "stopped"


def test_cli_clone_nonexistent_source(capsys):
    """Verify `krunbox clone` fails cleanly when the source sandbox does not exist."""
    with patch.object(sys, "argv", ["krunbox", "clone", "nonexistent-vm", "new-vm"]):
        res = main()
        assert res != 0
        captured = capsys.readouterr()
        err_msg = captured.out + captured.err
        assert "not found" in err_msg.lower() or "error" in err_msg.lower()


def test_cli_clone_target_already_exists(tmp_path, capsys, isolate_cli):
    """Verify `krunbox clone` fails cleanly when target sandbox name is already registered."""
    src_dir = tmp_path / "clone_dup_dir"
    src_dir.mkdir()

    with patch.object(sys, "argv", ["krunbox", "create", str(src_dir), "--name", "first-vm"]):
        assert main() == 0
    with patch.object(sys, "argv", ["krunbox", "create", str(src_dir), "--name", "second-vm"]):
        assert main() == 0
    capsys.readouterr()

    with patch.object(sys, "argv", ["krunbox", "clone", "first-vm", "second-vm"]):
        res = main()
        assert res != 0
        captured = capsys.readouterr()
        err_msg = captured.out + captured.err
        assert "already exists" in err_msg.lower()


# ============================================================================
# 3. Sandbox Export & Import Tests
# ============================================================================

def test_cli_export_and_import_roundtrip(tmp_path, capsys, isolate_cli):
    """Verify exporting a sandbox creates a valid tar.gz archive, and importing restores it."""
    temp_state, _ = isolate_cli
    proj_dir = tmp_path / "export_proj"
    proj_dir.mkdir()
    (proj_dir / "index.js").write_text("console.log('hello from exported vm');\n")

    with patch.object(sys, "argv", [
        "krunbox", "create", str(proj_dir),
        "--name", "portable-vm",
        "--cpus", "4",
        "--ram", "4096",
        "--network", "dev-common",
    ]):
        assert main() == 0
    capsys.readouterr()

    archive_path = tmp_path / "portable-vm.tar.gz"

    # Export
    with patch.object(sys, "argv", ["krunbox", "export", "portable-vm", "-o", str(archive_path)]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        assert "exported" in captured.out.lower() or "✓" in captured.out
    assert archive_path.exists()
    assert archive_path.stat().st_size > 0
    assert tarfile.is_tarfile(archive_path)

    # Delete original sandbox
    with patch("subprocess.run"):
        with patch.object(sys, "argv", ["krunbox", "rm", "portable-vm"]):
            assert main() == 0
    capsys.readouterr()

    mgr = SandboxManager(state_file=temp_state)
    assert mgr.get_sandbox("portable-vm") is None

    # Import
    with patch.object(sys, "argv", ["krunbox", "import", str(archive_path)]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        assert "imported" in captured.out.lower() or "✓" in captured.out

    mgr = SandboxManager(state_file=temp_state)
    imported = mgr.get_sandbox("portable-vm")
    assert imported is not None
    assert imported.cpus == 4
    assert imported.ram_mib == 4096
    assert imported.network_policy.profile == "dev-common"


def test_cli_export_nonexistent_sandbox(tmp_path, capsys):
    """Verify `krunbox export` fails when target sandbox does not exist."""
    out_archive = tmp_path / "ghost.tar.gz"
    with patch.object(sys, "argv", ["krunbox", "export", "nonexistent-box", "-o", str(out_archive)]):
        res = main()
        assert res != 0
        captured = capsys.readouterr()
        err_msg = captured.out + captured.err
        assert "not found" in err_msg.lower() or "error" in err_msg.lower()
    assert not out_archive.exists()


def test_cli_import_with_custom_name(tmp_path, capsys, isolate_cli):
    """Verify importing with `--name <new_name>` overrides the archived identifier."""
    temp_state, _ = isolate_cli
    proj_dir = tmp_path / "import_rename_proj"
    proj_dir.mkdir()

    with patch.object(sys, "argv", [
        "krunbox", "create", str(proj_dir),
        "--name", "base-vm",
        "--cpus", "2",
        "--ram", "2048",
    ]):
        assert main() == 0
    capsys.readouterr()

    archive_path = tmp_path / "base-vm.tar.gz"
    with patch.object(sys, "argv", ["krunbox", "export", "base-vm", "-o", str(archive_path)]):
        assert main() == 0
    capsys.readouterr()

    # Import with override name
    with patch.object(sys, "argv", ["krunbox", "import", str(archive_path), "--name", "target-renamed-vm"]):
        res = main()
        assert res == 0
        captured = capsys.readouterr()
        assert "target-renamed-vm" in captured.out or "krunbox-target-renamed-vm" in captured.out

    mgr = SandboxManager(state_file=temp_state)
    renamed = mgr.get_sandbox("target-renamed-vm")
    assert renamed is not None
    assert renamed.cpus == 2
    assert renamed.ram_mib == 2048


def test_cli_import_invalid_archive(tmp_path, capsys):
    """Verify `krunbox import` fails gracefully when the archive file is corrupt or invalid."""
    corrupt_file = tmp_path / "corrupted.tar.gz"
    corrupt_file.write_text("this is completely invalid tar data")

    with patch.object(sys, "argv", ["krunbox", "import", str(corrupt_file)]):
        res = main()
        assert res != 0
        captured = capsys.readouterr()
        err_msg = captured.out + captured.err
        assert "error" in err_msg.lower() or "invalid" in err_msg.lower()


# ============================================================================
# 4. Daemon Execution Tests
# ============================================================================

def test_cli_daemon_once_success(capsys):
    """Verify `krunbox daemon --once` runs a single guardrail evaluation tick and exits 0."""
    with patch("krunbox.core.manager.SandboxManager.evaluate_guardrails", return_value=([], [])) as mock_eval:
        with patch.object(sys, "argv", ["krunbox", "daemon", "--once"]):
            res = main()
            assert res == 0
            captured = capsys.readouterr()
            out = captured.out.lower()
            assert "daemon" in out or "single pass" in out or "guardrail" in out
            mock_eval.assert_called_once()


# ============================================================================
# 5. Shell Completion Tests
# ============================================================================

def test_cli_completion_bash(capsys):
    """Verify `krunbox completion bash` generates bash completion script with subcommands."""
    with patch.object(sys, "argv", ["krunbox", "completion", "bash"]):
        res = main()
        assert res == 0
        out = capsys.readouterr().out
        assert "krunbox" in out
        assert "complete" in out or "_krunbox" in out or "COMPREPLY" in out


def test_cli_completion_fish(capsys):
    """Verify `krunbox completion fish` generates fish completion syntax."""
    with patch.object(sys, "argv", ["krunbox", "completion", "fish"]):
        res = main()
        assert res == 0
        out = capsys.readouterr().out
        assert "complete -c krunbox" in out or "krunbox" in out


def test_cli_completion_zsh(capsys):
    """Verify `krunbox completion zsh` generates zsh completion definitions."""
    with patch.object(sys, "argv", ["krunbox", "completion", "zsh"]):
        res = main()
        assert res == 0
        out = capsys.readouterr().out
        assert "#compdef krunbox" in out or "_krunbox" in out or "compdef" in out


def test_cli_completion_unsupported_shell(capsys):
    """Verify `krunbox completion <unsupported>` fails with non-zero exit or argparse error."""
    try:
        with patch.object(sys, "argv", ["krunbox", "completion", "unsupported_shell"]):
            res = main()
        assert res != 0
    except SystemExit as exc:
        assert exc.code != 0
