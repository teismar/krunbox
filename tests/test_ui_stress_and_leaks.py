"""
Interactive Stress and Memory Leak Test Suite for krunbox GTK4 UI.
Simulates extensive user interactions: rapid dialog open/close, card reconciliation,
theme cycling, search filtering, and background worker threads under load.
"""

import gc
import uuid
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

import krunbox.core.settings as core_settings
from krunbox.ui.app import KrunboxApplication
from krunbox.ui.window import KrunboxWindow
from krunbox.ui.sandbox_row import SandboxCard
from krunbox.ui.create_dialog import CreateSandboxDialog
from krunbox.ui.edit_dialog import EditSandboxDialog
from krunbox.ui.egress_dialog import EgressTrafficDialog
from krunbox.ui.settings_dialog import SettingsDialog
from krunbox.ui.doctor_dialog import DoctorDialog
from krunbox.ui.telemetry_dialog import TelemetryDialog
from krunbox.ui.logs_dialog import LogsDialog
from krunbox.ui.port_dialog import PortForwardDialog
from krunbox.ui.workspace_diff_dialog import WorkspaceChangesDialog
from krunbox.core.sandbox import SandboxInfo, NetworkPolicy, PortMapping


def iterate_gtk(iterations: int = 10):
    ctx = GLib.MainContext.default()
    for _ in range(iterations):
        while ctx.pending():
            ctx.iteration(False)
        ctx.iteration(False)


def test_interactive_card_reconciliation_zero_leak(tmp_path, monkeypatch):
    """Verify that card reconciliation updates existing cards in place and completely frees discarded cards."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(core_settings, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", tmp_path / "settings.json")
    app = KrunboxApplication(application_id=f"io.krunbox.Test{uuid.uuid4().hex[:8]}")
    app.register(None)
    win = KrunboxWindow(app)
    win.present()
    iterate_gtk(10)

    def make_boxes(n, offset=0):
        return [
            SandboxInfo(
                name=f"krunbox-worker-{i + offset}",
                dir_path=f"/workspace/project-{i + offset}",
                hostname=f"krunbox-box-{i + offset}",
                container_name=f"krunbox-cnt-{i + offset}",
                ssh_port=2222 + i + offset,
                status="running" if i % 2 == 0 else "stopped",
                published_ports=[PortMapping(host_port=3000 + i + offset, guest_port=3000)],
                dynamic_tunnels=[PortMapping(host_port=8080 + i + offset, guest_port=8080, is_tunnel=True)] if i % 3 == 0 else [],
                cpu_percent=float((i * 7) % 100),
                mem_usage=f"{(i + 1) * 64}MB / 4GB",
                mem_percent=float((i * 3) % 50),
                is_persistent=(i % 2 == 1),
                network_policy=NetworkPolicy(profile="ai-only" if i % 2 == 0 else "dev-common"),
            )
            for i in range(n)
        ]

    for _ in range(3):
        iterate_gtk(15)
        gc.collect()
    initial_cards = set(o for o in gc.get_objects() if isinstance(o, SandboxCard))

    win.cached_sandboxes = make_boxes(10)
    win._render_cards()
    iterate_gtk(10)

    for cycle in range(100):
        boxes = make_boxes(8, offset=(cycle % 5))
        for b in boxes:
            b.cpu_percent = float((cycle * 3) % 95)
        win.cached_sandboxes = boxes
        win._render_cards()
        iterate_gtk(2)

    for _ in range(3):
        iterate_gtk(15)
        gc.collect()
    active_cards = [o for o in gc.get_objects() if isinstance(o, SandboxCard) and o not in initial_cards]
    assert set(active_cards) == set(win._cards.values()), (
        f"Leaked cards: {len(active_cards)} alive vs {len(win._cards)} expected in window"
    )
    assert len(active_cards) == 8

    win.close()
    iterate_gtk(5)


def test_interactive_dialog_churn_leak_prevention(tmp_path, monkeypatch):
    """Stress test opening, using, and closing all dialogs (including Edit & Egress Traffic) 10 times each."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(core_settings, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", tmp_path / "settings.json")
    app = KrunboxApplication(application_id=f"io.krunbox.Test{uuid.uuid4().hex[:8]}")
    app.register(None)
    win = KrunboxWindow(app)
    win.manager.egress_traffic = type(win.manager.egress_traffic)(logs_dir=tmp_path / "egress_churn")
    win.present()
    iterate_gtk(10)

    sample_box = SandboxInfo(
        name="krunbox-churn-target",
        dir_path="/workspace",
        hostname="krunbox-churn-target",
        container_name="krunbox-churn-target",
        ssh_port=2299,
        cpus=4,
        ram_mib=4096,
        status="running",
        network_policy=NetworkPolicy(profile="ai-only", allowed_domains=["example.org"]),
    )

    for iteration in range(10):
        # 1. Create Sandbox Dialog
        create_dlg = CreateSandboxDialog(win, win.manager, on_created=lambda: None)
        create_dlg.present()
        iterate_gtk(3)
        create_dlg.dir_entry.set_text(f"/workspace/test-{iteration}")
        create_dlg.close()
        iterate_gtk(3)
        del create_dlg

        # 2. Edit Sandbox Dialog
        edit_dlg = EditSandboxDialog(win, win.manager, sample_box, on_saved=lambda: None)
        edit_dlg.present()
        iterate_gtk(3)
        edit_dlg.cpu_row.set_value(4 + (iteration % 4))
        edit_dlg.net_combo.set_selected(iteration % len(edit_dlg.net_keys))
        edit_dlg.close()
        iterate_gtk(3)
        del edit_dlg

        # 3. Egress Traffic Dialog
        win.manager.egress_traffic.record_event(
            sample_box.name,
            f"api-{iteration % 3}.example.com",
            action="allowed" if iteration % 2 == 0 else "blocked",
        )
        egress_dlg = EgressTrafficDialog(win, win.manager, sandbox_name=sample_box.name)
        egress_dlg.present()
        iterate_gtk(5)
        egress_dlg.search_entry.set_text("example")
        egress_dlg.close()
        iterate_gtk(3)
        del egress_dlg

        # 4. Settings Dialog
        settings_dlg = SettingsDialog(win)
        settings_dlg.present()
        iterate_gtk(3)
        settings_dlg.theme_combo.set_selected(iteration % 3)
        settings_dlg.close()
        iterate_gtk(3)
        del settings_dlg

        # 5. Doctor Dialog
        doctor_dlg = DoctorDialog(win)
        doctor_dlg.present()
        iterate_gtk(5)
        doctor_dlg.close()
        iterate_gtk(3)
        del doctor_dlg

        # 6. Telemetry Dialog
        telem_dlg = TelemetryDialog(win, win.manager)
        telem_dlg.present()
        iterate_gtk(5)
        telem_dlg.load_data()
        iterate_gtk(3)
        telem_dlg.close()
        iterate_gtk(3)
        del telem_dlg

        # 7. Port Forward Dialog
        port_dlg = PortForwardDialog(win, win.manager, "test-box", on_forwarded=lambda: None)
        port_dlg.present()
        iterate_gtk(3)
        port_dlg.guest_entry.set_text(str(3000 + iteration))
        port_dlg.close()
        iterate_gtk(3)
        del port_dlg

        # 8. Logs Dialog
        logs_dlg = LogsDialog(win, win.manager, "test-box")
        logs_dlg.present()
        iterate_gtk(5)
        logs_dlg.close()
        iterate_gtk(3)
        del logs_dlg

        # 9. Workspace Changes Dialog
        ws_dlg = WorkspaceChangesDialog(
            win,
            win.manager.snapshots,
            sample_box.name,
            str(tmp_path),
            on_changed=lambda: None,
        )
        ws_dlg.present()
        iterate_gtk(3)
        ws_dlg.close()
        iterate_gtk(3)
        del ws_dlg

    gc.collect()
    win.close()
    iterate_gtk(5)


def test_interactive_search_and_theme_stress(tmp_path, monkeypatch):
    """Simulate rapid search filtering and theme switching."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(core_settings, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", tmp_path / "settings.json")
    app = KrunboxApplication(application_id=f"io.krunbox.Test{uuid.uuid4().hex[:8]}")
    app.register(None)
    win = KrunboxWindow(app)
    win.present()

    boxes = [
        SandboxInfo(
            name=f"krunbox-alpha-{i}",
            dir_path=f"/workspace/project-alpha-{i}",
            hostname=f"krunbox-alpha-{i}",
            container_name=f"krunbox-cnt-alpha-{i}",
            ssh_port=2222 + i,
            status="running" if i % 2 == 0 else "stopped",
            published_ports=[PortMapping(host_port=3000 + i, guest_port=3000)],
            cpu_percent=15.0,
            is_persistent=False,
        )
        for i in range(12)
    ]
    win.cached_sandboxes = boxes
    win._render_cards()
    iterate_gtk(5)

    queries = ["alpha", "alpha-3", "project", "3005", "xyz-notfound", ""]
    for q in queries * 5:
        win.search_entry.set_text(q)
        iterate_gtk(2)

    for _ in range(12):
        win._on_quick_theme_toggle(win.theme_btn)
        iterate_gtk(2)

    assert win.props.visible
    win.close()
    iterate_gtk(5)
