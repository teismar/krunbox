"""
Unit tests for uv CLI image container startup, keepalive command injection, and terminal fallback.
"""

from unittest.mock import MagicMock, patch
import pytest

from krunbox.core.manager import SandboxManager, is_uv_cli_image
from krunbox.core.config import BUILTIN_IMAGES
from krunbox.core.ssh import is_ssh_ready, launch_terminal_command, launch_sandbox_terminal
from krunbox.cli.commands import cmd_exec


@pytest.fixture(autouse=True)
def isolate_manager(tmp_path, monkeypatch):
    test_state = tmp_path / "sandboxes.json"
    temp_data = tmp_path / "data"
    temp_telem = temp_data / "telemetry"
    temp_egress = temp_data / "egress_logs"
    monkeypatch.setattr("krunbox.core.manager.STATE_FILE", test_state)
    monkeypatch.setattr("krunbox.core.manager.DATA_DIR", temp_data)
    monkeypatch.setattr("krunbox.core.telemetry.TELEMETRY_DIR", temp_telem)
    monkeypatch.setattr("krunbox.core.egress_traffic.EGRESS_LOGS_DIR", temp_egress)
    monkeypatch.setattr("krunbox.core.workspace_diff.DATA_DIR", temp_data)
    monkeypatch.setattr("krunbox.core.secrets.DATA_DIR", temp_data)
    return test_state


def test_is_uv_cli_image_detection():
    assert is_uv_cli_image("python-data") is True
    assert is_uv_cli_image("ghcr.io/astral-sh/uv:python3.12-bookworm-slim") is True
    assert is_uv_cli_image("ghcr.io/astral-sh/uv:latest") is True
    assert is_uv_cli_image("docker.io/astral-sh/uv:0.9") is True
    assert is_uv_cli_image("my-registry.io/custom/uv") is True

    # Standard non-uv images
    assert is_uv_cli_image("localhost/agent-box:latest") is False
    assert is_uv_cli_image("agent-box") is False
    assert is_uv_cli_image("docker.io/library/node:22-bookworm-slim") is False
    assert is_uv_cli_image("docker.io/library/debian:bookworm-slim") is False


def test_uv_image_startup_detached_adds_entrypoint_and_keepalive(tmp_path):
    ws = tmp_path / "ws_ml"
    ws.mkdir()
    manager = SandboxManager()

    box = manager.create_sandbox(
        dir_path=str(ws),
        name="ml-box",
        base_image="python-data",
        template_id="python-data-ml",
    )

    with patch.object(manager, "check_krun_available", return_value=False), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 TEST"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("subprocess.run") as mock_run:

        def fake_run(cmd, *args, **kwargs):
            if isinstance(cmd, list) and cmd[:3] == ["podman", "container", "exists"]:
                return MagicMock(returncode=1, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="c123456789012\n", stderr="")

        mock_run.side_effect = fake_run

        ok, msg = manager.start_sandbox(box.name, detach=True)
        assert ok is True
        assert box.status == "running"

        run_cmd = next(c[0][0] for c in mock_run.call_args_list if c[0][0][:2] == ["podman", "run"])

        # Entrypoint override must be present to clear bare 'uv'
        assert "--entrypoint" in run_cmd
        entry_idx = run_cmd.index("--entrypoint")
        assert run_cmd[entry_idx + 1] == ""

        # Image should be python-data
        assert "python-data" in run_cmd or BUILTIN_IMAGES["python-data"]["tag"] in run_cmd

        # Keepalive command and sshd provisioning must be present
        cmd_str = " ".join(run_cmd)
        assert "echo '[krunbox] Sandbox ready (Python 3.12, uv)'" in cmd_str
        assert "trap 'exit 0' TERM" in cmd_str
        assert "openssh-server" in cmd_str
        assert "/usr/sbin/sshd -p 2222" in cmd_str


def test_uv_image_startup_interactive_adds_entrypoint_and_bash(tmp_path):
    ws = tmp_path / "ws_ml_it"
    ws.mkdir()
    manager = SandboxManager()

    box = manager.create_sandbox(
        dir_path=str(ws),
        name="ml-box-it",
        base_image=BUILTIN_IMAGES["python-data"].get("fallback_tag", "ghcr.io/astral-sh/uv:python3.12-bookworm-slim"),
    )

    with patch.object(manager, "check_krun_available", return_value=False), \
         patch.object(manager.images, "ensure_image_ready", return_value=(True, "ready")), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 TEST"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("os.execvp") as mock_exec:

        manager.start_sandbox(box.name, detach=False)
        mock_exec.assert_called_once()
        run_cmd = mock_exec.call_args[0][1]
        assert "--entrypoint" in run_cmd
        assert run_cmd[-1] == "bash"


def test_uv_image_startup_with_extra_args(tmp_path):
    ws = tmp_path / "ws_ml_args"
    ws.mkdir()
    manager = SandboxManager()

    box = manager.create_sandbox(
        dir_path=str(ws),
        name="ml-box-args",
        base_image="python-data",
    )

    with patch.object(manager, "check_krun_available", return_value=False), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 TEST"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("subprocess.run") as mock_run:

        mock_run.return_value = MagicMock(returncode=0, stdout="c101\n", stderr="")

        ok, msg = manager.start_sandbox(box.name, detach=True, extra_args=["python3", "train.py"])
        assert ok is True

        run_cmd = next(c[0][0] for c in mock_run.call_args_list if c[0][0][:2] == ["podman", "run"])
        assert "--entrypoint" in run_cmd
        assert run_cmd[-2:] == ["python3", "train.py"]


def test_agent_box_startup_does_not_override_entrypoint(tmp_path):
    ws = tmp_path / "ws_agent"
    ws.mkdir()
    manager = SandboxManager()

    box = manager.create_sandbox(
        dir_path=str(ws),
        name="agent-box-test",
        base_image="localhost/agent-box:latest",
    )

    with patch.object(manager, "check_krun_available", return_value=False), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 TEST"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("subprocess.run") as mock_run:

        mock_run.return_value = MagicMock(returncode=0, stdout="c202\n", stderr="")

        ok, msg = manager.start_sandbox(box.name, detach=True)
        assert ok is True

        run_cmd = next(c[0][0] for c in mock_run.call_args_list if c[0][0][:2] == ["podman", "run"])
        # agent-box must NOT have --entrypoint override
        assert "--entrypoint" not in run_cmd
        assert run_cmd[-1] == "localhost/agent-box:latest"


def test_krunbox_python_image_startup_uses_baked_entrypoint(tmp_path):
    ws = tmp_path / "ws_kb_py"
    ws.mkdir()
    manager = SandboxManager()

    box = manager.create_sandbox(
        dir_path=str(ws),
        name="krunbox-py-test",
        base_image="localhost/krunbox-python:latest",
    )

    with patch.object(manager, "check_krun_available", return_value=False), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 TEST"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("subprocess.run") as mock_run:

        mock_run.return_value = MagicMock(returncode=0, stdout="c203\n", stderr="")

        ok, msg = manager.start_sandbox(box.name, detach=True)
        assert ok is True

        run_cmd = next(c[0][0] for c in mock_run.call_args_list if c[0][0][:2] == ["podman", "run"])
        # krunbox-python must NOT have --entrypoint override because entrypoint is baked in
        assert "--entrypoint" not in run_cmd
        assert run_cmd[-1] == "localhost/krunbox-python:latest"


def test_is_ssh_ready():
    with patch("socket.create_connection") as mock_conn:
        # Success case: returns SSH- banner
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_9.6"
        mock_conn.return_value.__enter__.return_value = mock_sock
        assert is_ssh_ready("127.0.0.1", 2222) is True

        # Failure case: connection refused / exception
        mock_conn.side_effect = ConnectionRefusedError()
        assert is_ssh_ready("127.0.0.1", 2222) is False

        # Non-SSH protocol banner
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK"
        mock_conn.side_effect = None
        assert is_ssh_ready("127.0.0.1", 2222) is False


def test_launch_sandbox_terminal_uses_ssh_without_podman_exec():
    with patch("krunbox.core.ssh.is_ssh_ready", return_value=True), \
         patch("krunbox.core.ssh.launch_ssh_terminal") as mock_ssh:
        mock_ssh.return_value = (True, "Launched ptyxis")
        ok, msg = launch_sandbox_terminal("ml-box", container_name="ml-box-container", ssh_port=2222)
        assert ok is True
        mock_ssh.assert_called_once_with("ml-box")


def test_cmd_exec_uses_ssh_connection(tmp_path):
    ws = tmp_path / "ws_exec"
    ws.mkdir()
    manager = SandboxManager()
    box = manager.create_sandbox(
        dir_path=str(ws),
        name="ml-exec",
        base_image="python-data",
    )
    box.status = "running"
    manager.save_state()

    with patch("krunbox.core.ssh.is_ssh_ready", return_value=True), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        rc = cmd_exec(manager, box.name, ["uv", "pip", "list"])
        assert rc == 0
        call_cmd = mock_run.call_args[0][0]
        assert call_cmd == ["ssh", box.name, "--", "uv", "pip", "list"]
