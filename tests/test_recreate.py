"""
Tests for sandbox recreation functionality in krunbox (backend manager, CLI, and UI).
"""

import sys
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

import krunbox.core.settings as core_settings
from krunbox.core.manager import SandboxManager
from krunbox.core.sandbox import SandboxInfo, PortMapping, NetworkPolicy
from krunbox.core.egress_traffic import EgressTrafficManager
from krunbox.ui.app import KrunboxApplication
from krunbox.ui.window import KrunboxWindow
from krunbox.ui.sandbox_row import SandboxCard
from krunbox.ui.worker import run_async
from krunbox.cli.main import main


@pytest.fixture
def manager(tmp_path):
    state_file = tmp_path / "sandboxes.json"
    data_dir = tmp_path / "data"
    egress_logs = data_dir / "egress_logs"
    telem_dir = data_dir / "telemetry"
    ssh_dir = tmp_path / "ssh_conf"
    ssh_cfg = tmp_path / "ssh_config"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    telem_dir.mkdir(parents=True, exist_ok=True)

    with patch("krunbox.core.manager.DATA_DIR", data_dir), \
         patch("krunbox.core.telemetry.TELEMETRY_DIR", telem_dir), \
         patch("krunbox.core.ssh.SSH_CONF_DIR", ssh_dir), \
         patch("krunbox.core.ssh.SSH_CONFIG_FILE", ssh_cfg):
        mgr = SandboxManager(state_file=state_file)
        mgr.egress_traffic = EgressTrafficManager(logs_dir=egress_logs)
        mgr.telemetry.telemetry_dir = telem_dir
        yield mgr


def pump_gtk(ticks: int = 15, sleep_sec: float = 0.01):
    ctx = GLib.MainContext.default()
    for _ in range(ticks):
        while ctx.pending():
            ctx.iteration(False)
        if sleep_sec > 0:
            import time
            time.sleep(sleep_sec)
        while ctx.pending():
            ctx.iteration(False)


# =====================================================================
# 1. Backend Manager Tests: SandboxManager.recreate_sandbox
# =====================================================================

def test_recreate_sandbox_not_found(manager):
    ok, msg = manager.recreate_sandbox("nonexistent")
    assert ok is False
    assert "not found" in msg


def test_recreate_sandbox_running_with_volumes_and_pull(manager, tmp_path):
    ws = tmp_path / "ws_recreate"
    ws.mkdir()
    box = manager.create_sandbox(str(ws), name="recreate-vm", is_persistent=True)
    box.status = "running"
    box.dynamic_tunnels.append(PortMapping(guest_port=8080, host_port=18080))
    manager.save_state()

    with patch("subprocess.run") as mock_run, \
         patch("krunbox.core.ssh.wait_for_ssh_ready", return_value=True), \
         patch.object(manager.images, "ensure_image_ready", return_value=(True, "Ready")) as mock_img, \
         patch.object(manager, "start_sandbox", return_value=(True, "Started")) as mock_start, \
         patch.object(manager, "forward_port") as mock_fwd, \
         patch("krunbox.core.manager.stop_ssh_tunnel") as mock_stop_tunnel:
        mock_run.return_value = MagicMock(returncode=0)

        ok, msg = manager.recreate_sandbox(box.name, pull_image=True, wipe_volumes=True, start_after=True)
        assert ok is True
        assert "Recreated and started sandbox" in msg

        mock_stop_tunnel.assert_called_once()
        mock_fwd.assert_called_once_with(box.name, 8080, 18080)

        podman_calls = [c[0][0] for c in mock_run.call_args_list]
        assert ["podman", "stop", box.container_name] in podman_calls
        assert ["podman", "rm", "-f", box.container_name] in podman_calls
        assert ["podman", "volume", "rm", "-f", f"{box.name}-gemini"] in podman_calls
        assert ["podman", "volume", "rm", "-f", f"{box.name}-vibe"] in podman_calls
        assert ["podman", "volume", "rm", "-f", f"{box.name}-docker"] in podman_calls

        mock_img.assert_called_once_with(box.base_image, force=True)
        mock_start.assert_called_once_with(box.name, detach=True)


def test_recreate_sandbox_stopped_no_pull_keep_volumes_no_start(manager, tmp_path):
    ws = tmp_path / "ws_recreate_stopped"
    ws.mkdir()
    box = manager.create_sandbox(str(ws), name="recreate-stopped-vm")
    box.status = "stopped"
    box.committed_image = "localhost/committed:1"
    manager.save_state()

    with patch("subprocess.run") as mock_run, \
         patch.object(manager.images, "ensure_image_ready") as mock_img, \
         patch.object(manager, "start_sandbox") as mock_start:
        mock_run.return_value = MagicMock(returncode=0)

        ok, msg = manager.recreate_sandbox(box.name, pull_image=False, wipe_volumes=False, start_after=False)
        assert ok is True
        assert "(stopped)" in msg

        podman_calls = [c[0][0] for c in mock_run.call_args_list]
        assert ["podman", "stop", box.container_name] not in podman_calls
        assert ["podman", "rm", "-f", box.container_name] in podman_calls
        assert ["podman", "rmi", "-f", "localhost/committed:1"] in podman_calls
        assert box.committed_image is None
        assert not any("volume" in c for c in podman_calls)
        mock_img.assert_not_called()
        mock_start.assert_not_called()
        assert box.status == "stopped"


def test_recreate_sandbox_paused_unpauses_first(manager, tmp_path):
    ws = tmp_path / "ws_paused"
    ws.mkdir()
    box = manager.create_sandbox(str(ws), name="paused-vm")
    box.status = "paused"
    manager.save_state()

    with patch("subprocess.run") as mock_run, \
         patch.object(manager.images, "ensure_image_ready", return_value=(True, "Ready")), \
         patch.object(manager, "start_sandbox", return_value=(True, "Started")):
        mock_run.return_value = MagicMock(returncode=0)
        ok, msg = manager.recreate_sandbox(box.name, pull_image=True, start_after=True)
        assert ok is True
        podman_calls = [c[0][0] for c in mock_run.call_args_list]
        assert ["podman", "unpause", box.container_name] in podman_calls
        assert ["podman", "stop", box.container_name] in podman_calls
        assert ["podman", "rm", "-f", box.container_name] in podman_calls


def test_recreate_sandbox_pull_failure_image_missing(manager, tmp_path):
    ws = tmp_path / "ws_pull_fail"
    ws.mkdir()
    box = manager.create_sandbox(str(ws), name="pull-fail-vm")

    with patch("subprocess.run") as mock_run, \
         patch.object(manager.images, "ensure_image_ready", return_value=(False, "Pull error")), \
         patch.object(manager.images, "is_image_present", return_value=False):
        mock_run.return_value = MagicMock(returncode=0)
        ok, msg = manager.recreate_sandbox(box.name, pull_image=True)
        assert ok is False
        assert "Failed to prepare container image" in msg


def test_recreate_sandbox_pull_failure_image_present_locally(manager, tmp_path):
    ws = tmp_path / "ws_pull_fallback"
    ws.mkdir()
    box = manager.create_sandbox(str(ws), name="pull-fallback-vm")

    with patch("subprocess.run") as mock_run, \
         patch.object(manager.images, "ensure_image_ready", return_value=(False, "Offline")), \
         patch.object(manager.images, "is_image_present", return_value=True), \
         patch.object(manager, "start_sandbox", return_value=(True, "Started")):
        mock_run.return_value = MagicMock(returncode=0)
        ok, msg = manager.recreate_sandbox(box.name, pull_image=True)
        assert ok is True
        assert "Recreated and started sandbox" in msg


# =====================================================================
# 2. CLI Tests: krunbox recreate
# =====================================================================

def test_cli_recreate_declined(tmp_path, capsys):
    state_file = tmp_path / "sandboxes.json"
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    test_dir = tmp_path / "recreate_cli_ws"
    test_dir.mkdir()

    with patch("krunbox.cli.main.SandboxManager", lambda: SandboxManager(state_file=state_file)), \
         patch("krunbox.core.manager.STATE_FILE", state_file), \
         patch("krunbox.core.manager.DATA_DIR", data_dir):
        with patch.object(sys, "argv", ["krunbox", "create", str(test_dir), "--name", "recreate-cli-vm"]):
            assert main() == 0
        capsys.readouterr()

        with patch("builtins.input", return_value="n"):
            with patch.object(sys, "argv", ["krunbox", "recreate", "recreate-cli-vm"]):
                ret = main()
                assert ret == 0
                out = capsys.readouterr().out
                assert "Recreation cancelled." in out


def test_cli_recreate_confirmed_yes_flag(tmp_path, capsys):
    state_file = tmp_path / "sandboxes.json"
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    test_dir = tmp_path / "recreate_cli_ws2"
    test_dir.mkdir()

    with patch("krunbox.cli.main.SandboxManager", lambda: SandboxManager(state_file=state_file)), \
         patch("krunbox.core.manager.STATE_FILE", state_file), \
         patch("krunbox.core.manager.DATA_DIR", data_dir):
        with patch.object(sys, "argv", ["krunbox", "create", str(test_dir), "--name", "recreate-cli-vm2"]):
            assert main() == 0
        capsys.readouterr()

        with patch("krunbox.core.manager.SandboxManager.recreate_sandbox", return_value=(True, "Recreated and started sandbox 'krunbox-recreate-cli-vm2'")) as mock_recreate:
            with patch.object(sys, "argv", ["krunbox", "recreate", "recreate-cli-vm2", "-y", "--no-pull", "--keep-volumes"]):
                ret = main()
                assert ret == 0
                out = capsys.readouterr().out
                assert "Recreated and started sandbox" in out
                mock_recreate.assert_called_once_with(
                    "recreate-cli-vm2",
                    pull_image=False,
                    wipe_volumes=False,
                    start_after=True,
                )


def test_cli_recreate_error(capsys):
    with patch("krunbox.core.manager.SandboxManager.recreate_sandbox", return_value=(False, "Sandbox 'notfound' not found.")):
        with patch.object(sys, "argv", ["krunbox", "recreate", "notfound", "-y"]):
            ret = main()
            assert ret == 1
            err = capsys.readouterr().err
            assert "Sandbox 'notfound' not found." in err


# =====================================================================
# 3. UI Tests: SandboxCard Recreate Button & Confirmation Dialog
# =====================================================================

def test_sandbox_card_recreate_button_and_dialog_flow(manager, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(core_settings, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", tmp_path / "settings.json")

    app = KrunboxApplication(application_id=f"io.krunbox.Test{uuid.uuid4().hex[:8]}")
    app.register(None)
    win = KrunboxWindow(app)
    win.present()
    pump_gtk(10)

    mgr = manager
    ws = tmp_path / "ws_ui_recreate"
    ws.mkdir()
    box = SandboxInfo(
        name="krunbox-recreate-ui-test",
        dir_path=str(ws),
        hostname="krunbox-recreate-ui-test",
        container_name="krunbox-recreate-ui-test",
        ssh_port=2222,
        status="running",
    )
    mgr._sandboxes[box.name] = box

    updated_called = []
    card = SandboxCard(win, mgr, box, on_updated=lambda: updated_called.append(True))
    pump_gtk(5)

    # 1. Verify recreate_btn exists on card with proper icon and tooltip
    assert card.recreate_btn is not None
    assert isinstance(card.recreate_btn, Gtk.Button)
    assert card.recreate_btn.get_icon_name() == "view-refresh-symbolic"
    assert "Recreate Sandbox" in card.recreate_btn.get_tooltip_text()

    # 2. Verify overflow action exists
    assert card._action_group.has_action("recreate")

    # 3. Clicking recreate button presents dialog
    card.recreate_btn.emit("clicked")
    pump_gtk(5)

    assert hasattr(card, "_recreate_dialog")
    dlg = card._recreate_dialog
    assert dlg is not None

    # Check response enabled behavior with extra confirmation checkbutton
    confirm_check = card._recreate_confirm_check
    assert confirm_check is not None
    assert confirm_check.get_active() is False

    if hasattr(dlg, "get_response_enabled"):
        # The destructive "recreate" response must be disabled initially
        assert dlg.get_response_enabled("recreate") is False

        # Toggling the confirmation checkbox enables the response
        confirm_check.set_active(True)
        pump_gtk(2)
        assert dlg.get_response_enabled("recreate") is True

    # 4. Confirming triggers manager.recreate_sandbox
    with patch.object(mgr, "recreate_sandbox", return_value=(True, "Recreated and started")) as mock_recreate:
        # Trigger response
        if hasattr(dlg, "response"):
            dlg.response("recreate")
        else:
            dlg.emit("response", "recreate")
        pump_gtk(15)

        mock_recreate.assert_called_once_with(
            box.name,
            pull_image=True,
            wipe_volumes=True,
            start_after=True,
        )
        assert len(updated_called) > 0

    card.cleanup()
    win.close()
    pump_gtk(5)


def test_sandbox_card_recreate_dialog_cancel(manager, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(core_settings, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", tmp_path / "settings.json")

    app = KrunboxApplication(application_id=f"io.krunbox.Test{uuid.uuid4().hex[:8]}")
    app.register(None)
    win = KrunboxWindow(app)
    win.present()
    pump_gtk(10)

    mgr = manager
    ws = tmp_path / "ws_ui_cancel"
    ws.mkdir()
    box = SandboxInfo(
        name="krunbox-recreate-cancel-test",
        dir_path=str(ws),
        hostname="krunbox-recreate-cancel-test",
        container_name="krunbox-recreate-cancel-test",
        ssh_port=2222,
        status="running",
    )
    mgr._sandboxes[box.name] = box

    card = SandboxCard(win, mgr, box, on_updated=lambda: None)
    pump_gtk(5)

    card.recreate_btn.emit("clicked")
    pump_gtk(5)

    dlg = card._recreate_dialog
    with patch.object(mgr, "recreate_sandbox") as mock_recreate:
        if hasattr(dlg, "response"):
            dlg.response("cancel")
        else:
            dlg.emit("response", "cancel")
        pump_gtk(10)
        mock_recreate.assert_not_called()

    card.cleanup()
    win.close()
    pump_gtk(5)


def test_sandbox_card_recreate_dialog_unconfirmed_blocks_call(manager, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(core_settings, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", tmp_path / "settings.json")

    app = KrunboxApplication(application_id=f"io.krunbox.Test{uuid.uuid4().hex[:8]}")
    app.register(None)
    win = KrunboxWindow(app)
    win.present()
    pump_gtk(10)

    mgr = manager
    ws = tmp_path / "ws_ui_unconfirmed"
    ws.mkdir()
    box = SandboxInfo(
        name="krunbox-recreate-unconfirmed-test",
        dir_path=str(ws),
        hostname="krunbox-recreate-unconfirmed-test",
        container_name="krunbox-recreate-unconfirmed-test",
        ssh_port=2222,
        status="running",
    )
    mgr._sandboxes[box.name] = box

    card = SandboxCard(win, mgr, box, on_updated=lambda: None)
    pump_gtk(5)

    card.recreate_btn.emit("clicked")
    pump_gtk(5)

    dlg = card._recreate_dialog
    confirm_check = card._recreate_confirm_check
    assert confirm_check.get_active() is False

    with patch.object(mgr, "recreate_sandbox") as mock_recreate:
        if hasattr(dlg, "response"):
            dlg.response("recreate")
        else:
            dlg.emit("response", "recreate")
        pump_gtk(10)
        mock_recreate.assert_not_called()

    card.cleanup()
    win.close()
    pump_gtk(5)


# =====================================================================
# 4. Worker run_async Error Callback Scope Test
# =====================================================================

def test_run_async_on_error_scoping_no_free_variable_error():
    loop = GLib.MainLoop()
    errors = []

    def failing_worker():
        raise RuntimeError("Worker intentional failure")

    def error_callback(err):
        errors.append(err)
        loop.quit()

    run_async(failing_worker, on_error=error_callback)
    GLib.timeout_add(1000, loop.quit)
    loop.run()

    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeError)
    assert str(errors[0]) == "Worker intentional failure"
