"""
Headless GTK4 & Libadwaita UI tests for krunbox console.
Runs under xvfb-run.
"""

import time
from pathlib import Path
from unittest.mock import patch
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib
import pytest

import krunbox.core.settings as core_settings
from krunbox.core.manager import SandboxManager
from krunbox.core.sandbox import SandboxInfo, PortMapping, NetworkPolicy
from krunbox.core.notifications import AlertEvent
from krunbox.core.ipc_server import AccessRequest
from krunbox.ui.app import KrunboxApplication
from krunbox.ui.window import KrunboxWindow
from krunbox.ui.sandbox_row import SandboxCard
from krunbox.ui.create_dialog import CreateSandboxDialog
from krunbox.ui.edit_dialog import EditSandboxDialog
from krunbox.ui.egress_dialog import EgressTrafficDialog
from krunbox.ui.port_dialog import PortForwardDialog
from krunbox.ui.logs_dialog import LogsDialog
from krunbox.ui.telemetry_dialog import TelemetryDialog
from krunbox.ui.doctor_dialog import DoctorDialog
from krunbox.ui.settings_dialog import SettingsDialog


def pump_gtk(ticks: int = 15, sleep_sec: float = 0.01):
    ctx = GLib.MainContext.default()
    for _ in range(ticks):
        while ctx.pending():
            ctx.iteration(False)
        time.sleep(sleep_sec)
        while ctx.pending():
            ctx.iteration(False)


def make_isolated_manager(tmp_path: Path) -> SandboxManager:
    mgr = SandboxManager(state_file=tmp_path / "sandboxes.json")
    mgr.egress_traffic = type(mgr.egress_traffic)(logs_dir=tmp_path / "egress_logs")
    return mgr


@pytest.fixture(scope="session")
def app():
    application = KrunboxApplication()
    application.register()
    return application


def test_app_actions_and_accelerators(app):
    assert app.lookup_action("new-sandbox") is not None
    assert app.lookup_action("preferences") is not None
    assert app.lookup_action("refresh") is not None
    assert app.lookup_action("quit") is not None
    assert any("n" in a.lower() for a in app.get_accels_for_action("app.new-sandbox"))
    assert any("comma" in a.lower() for a in app.get_accels_for_action("app.preferences"))
    assert any("r" in a.lower() for a in app.get_accels_for_action("app.refresh"))
    assert any("q" in a.lower() for a in app.get_accels_for_action("app.quit"))


def test_window_creation_and_no_results_state(app):
    win = KrunboxWindow(app)
    assert win is not None
    assert "krunbox" in win.get_title()
    assert not win.stats_pill.has_css_class("pill")
    assert win.stats_pill.has_css_class("numeric")

    # Empty state when no sandboxes exist
    win.cached_sandboxes = []
    win._render_cards()
    assert win.stack.get_visible_child_name() == "empty"

    # Populated state vs no-results search filter state
    win.cached_sandboxes = [
        SandboxInfo(
            name="krunbox-demo-api",
            dir_path="/workspace/demo",
            hostname="krunbox-demo-api",
            container_name="krunbox-demo-api",
            ssh_port=2222,
            status="running",
        )
    ]
    win._render_cards()
    assert win.stack.get_visible_child_name() == "list"

    win.search_entry.set_text("nonexistent-filter-term")
    assert win.stack.get_visible_child_name() == "no-results"
    assert len(win._cards) == 0

    win.search_entry.set_text("")
    assert win.stack.get_visible_child_name() == "list"
    assert "krunbox-demo-api" in win._cards
    win.close()


def test_quick_theme_toggle(app, tmp_path, monkeypatch):
    monkeypatch.setattr(core_settings, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", tmp_path / "settings.json")
    win = KrunboxWindow(app)
    win._on_quick_theme_toggle(win.theme_btn)
    style_mgr = Adw.StyleManager.get_default()
    assert style_mgr.get_color_scheme() in (
        Adw.ColorScheme.FORCE_DARK,
        Adw.ColorScheme.FORCE_LIGHT,
        Adw.ColorScheme.DEFAULT,
    )
    win.close()


def test_sandbox_card_creation_and_live_updates(app, tmp_path):
    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)
    box = SandboxInfo(
        name="krunbox-ui-card-test",
        dir_path="/workspace",
        hostname="krunbox-ui-card-test",
        container_name="krunbox-ui-card-test",
        ssh_port=2222,
        cpus=4,
        ram_mib=4096,
        is_persistent=True,
        network_policy=NetworkPolicy(profile="ai-only"),
        published_ports=[PortMapping(host_port=3000, guest_port=3000)],
        status="running",
        cpu_percent=4.8,
        mem_usage="160MB / 4GB",
    )
    card = SandboxCard(win, mgr, box, on_updated=lambda: None)
    assert card is not None
    assert card.status_pill.get_text() == "RUNNING"
    assert not card.status_pill.has_css_class("pill")
    assert not card.mode_pill.has_css_class("pill")
    assert not card.net_pill.has_css_class("pill")
    assert "4 vCPUs · 4 GiB" in card.hw_pill.get_text()
    assert card.connect_btn is not None
    assert "Quick Connect" in card.connect_btn.get_tooltip_text()
    assert card.connect_dropdown_btn is not None
    assert card.connect_dropdown_btn.get_icon_name() in ("go-down-symbolic", "pan-down-symbolic")
    assert card.edit_btn is not None
    assert card.traffic_btn is not None
    assert card.recreate_btn is not None
    assert card.recreate_btn.get_icon_name() == "view-refresh-symbolic"
    assert "Recreate Sandbox" in card.recreate_btn.get_tooltip_text()
    assert card._action_group.has_action("recreate")

    # Test clicking quick connect triggers launch_ssh_terminal
    with patch("krunbox.core.ssh.launch_ssh_terminal", return_value=(True, "Launched xterm")) as mock_launch:
        card.connect_btn.emit("clicked")
        mock_launch.assert_called_once_with("krunbox-ui-card-test")

    # Verify update_data updates name, hardware, egress, and status without recreating connect_content
    orig_content = card.connect_content
    box.name = "krunbox-renamed-worker"
    box.cpus = 8
    box.ram_mib = 16384
    box.status = "stopped"
    box.network_policy = NetworkPolicy(profile="full", denied_domains=["bad.example.com"])
    card.update_data(box)

    assert card.name_label.get_text() == "krunbox-renamed-worker"
    assert card.status_pill.get_text() == "STOPPED"
    assert "8 vCPUs · 16 GiB" in card.hw_pill.get_text()
    assert "1 blocked" in card.net_pill.get_text()
    assert card.connect_btn.get_child() is orig_content

    card.cleanup()
    win.close()


def test_default_4_cpus_4_gib_and_settings_overrides(app, tmp_path, monkeypatch):
    monkeypatch.setattr(core_settings, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", tmp_path / "settings.json")

    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)

    # 1. Clean defaults: 4 vCPUs and 4 GiB RAM in both CreateSandboxDialog & SettingsDialog
    create_dlg = CreateSandboxDialog(win, mgr, on_created=lambda: None)
    assert create_dlg.get_title() == "New MicroVM Sandbox"
    assert int(create_dlg.cpu_row.get_value()) == 4
    assert int(create_dlg.ram_row.get_value()) == 4
    assert create_dlg.name_row.get_text().startswith("krunbox-")
    assert create_dlg.image_combo.get_selected() == 0
    assert create_dlg.persist_switch.get_active() is False
    assert create_dlg.browse_btn.get_icon_name() == "folder-open-symbolic"
    assert create_dlg.dir_banner is not None
    create_dlg.close()

    settings_dlg = SettingsDialog(win)
    assert settings_dlg.get_title() == "Preferences"
    assert int(settings_dlg.cpu_row.get_value()) == 4
    assert int(settings_dlg.ram_row.get_value()) == 4
    settings_dlg.close()

    # 2. Override settings.json and verify both dialogs honor user overrides
    core_settings.save_settings({
        "color_scheme": "dark",
        "default_cpus": 6,
        "default_ram_mib": 12288,
        "default_image": "python-data",
        "default_network": "ai-only",
        "default_persistent": True,
        "auto_refresh_seconds": 10,
    })

    settings_dlg2 = SettingsDialog(win)
    assert int(settings_dlg2.cpu_row.get_value()) == 6
    assert int(settings_dlg2.ram_row.get_value()) == 12
    assert int(settings_dlg2.refresh_row.get_value()) == 10
    assert settings_dlg2.persist_switch.get_active() is True
    settings_dlg2.close()

    create_dlg2 = CreateSandboxDialog(win, mgr, on_created=lambda: None)
    assert int(create_dlg2.cpu_row.get_value()) == 6
    assert int(create_dlg2.ram_row.get_value()) == 12
    assert create_dlg2.persist_switch.get_active() is True
    assert create_dlg2.image_keys[create_dlg2.image_combo.get_selected()] == "python-data"
    assert create_dlg2.net_keys[create_dlg2.net_combo.get_selected()] == "ai-only"

    # Inline domain validation check in CreateSandboxDialog
    create_dlg2.whitelist_entry.set_text("not a domain!!")
    assert create_dlg2.whitelist_warn_icon.get_visible() is True
    create_dlg2.whitelist_entry.set_text("api.openai.com")
    assert create_dlg2.whitelist_warn_icon.get_visible() is False
    create_dlg2.close()
    win.close()


def test_create_sandbox_workspace_picker_warning_and_create(app, tmp_path):
    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)
    dlg = CreateSandboxDialog(win, mgr, on_created=lambda: None)

    # 1. Existing directory -> no warning
    existing_dir = str(tmp_path / "existing_folder")
    Path(existing_dir).mkdir()
    dlg.dir_entry.set_text(existing_dir)
    assert dlg.dir_warn_icon.get_visible() is False
    assert dlg.dir_banner.get_revealed() is False

    # 2. Non-existent directory -> warning icon and banner shown
    missing_dir = str(tmp_path / "brand_new_subproject")
    dlg.dir_entry.set_text(missing_dir)
    assert dlg.dir_warn_icon.get_visible() is True
    assert dlg.dir_banner.get_revealed() is True
    assert "Directory does not exist" in dlg.dir_banner.get_title()
    assert dlg.dir_banner.get_button_label() == "Create Folder"

    # 3. Clicking "Create Folder" creates directory and clears warning
    assert not Path(missing_dir).exists()
    dlg._on_create_dir_clicked(dlg.dir_banner)
    assert Path(missing_dir).is_dir()
    assert dlg.dir_warn_icon.get_visible() is False
    assert dlg.dir_banner.get_revealed() is False

    # 4. Launching with missing dir triggers creation prompt
    another_missing = str(tmp_path / "prompt_launch_folder")
    dlg.dir_entry.set_text(another_missing)
    with patch.object(dlg, "_prompt_create_and_launch") as mock_prompt:
        dlg._on_launch_clicked(dlg.launch_btn)
        assert mock_prompt.called

    # 5. Test browse button click handler with fallback
    with patch.object(Gtk.FileDialog, "select_folder", side_effect=Exception("Portal unavailable")):
        with patch.object(dlg, "_browse_fallback") as mock_fallback:
            dlg.browse_btn.emit("clicked")
            assert mock_fallback.called

    dlg.close()
    win.close()


def test_edit_sandbox_dialog_restart_banner_validation_and_save(app, tmp_path):
    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)

    work_dir = tmp_path / "proj"
    work_dir.mkdir()
    running_box = SandboxInfo(
        name="krunbox-edit-running",
        dir_path=str(work_dir),
        hostname="krunbox-edit-running",
        container_name="krunbox-edit-running",
        ssh_port=2240,
        cpus=4,
        ram_mib=4096,
        is_persistent=True,
        network_policy=NetworkPolicy(
            profile="ai-only",
            allowed_domains=["custom.example.com"],
            denied_domains=["ads.example.net"],
        ),
        status="running",
    )
    mgr._sandboxes[running_box.name] = running_box
    mgr.save_state()

    saved_calls = []
    dlg = EditSandboxDialog(win, mgr, running_box, on_saved=lambda: saved_calls.append(True))
    assert dlg.get_title() == "Edit Sandbox - krunbox-edit-running"
    assert dlg.name_row.get_text() == "krunbox-edit-running"
    assert int(dlg.cpu_row.get_value()) == 4
    assert int(dlg.ram_row.get_value()) == 4
    assert dlg.restart_banner.get_revealed() is False
    assert dlg.net_keys[dlg.net_combo.get_selected()] == "ai-only"
    assert len(dlg._builtin_domain_rows) > 0

    # Changing CPU or RAM on a RUNNING sandbox reveals restart_banner; reverting hides it!
    dlg.cpu_row.set_value(8)
    assert dlg.restart_banner.get_revealed() is True
    dlg.cpu_row.set_value(4)
    assert dlg.restart_banner.get_revealed() is False

    dlg.ram_row.set_value(8)
    assert dlg.restart_banner.get_revealed() is True
    dlg.ram_row.set_value(4)
    assert dlg.restart_banner.get_revealed() is False

    # Domain validation warning & error banner on malformed entry
    dlg.blacklist_entry.set_text("bad domain spaces!!")
    assert dlg.blacklist_warn_icon.get_visible() is True
    dlg._on_save_clicked(dlg.save_btn)
    assert dlg.error_banner.get_revealed() is True
    assert "Invalid blocked domain" in dlg.error_banner.get_title()

    # Valid edit on stopped sandbox: rename + CPU/RAM + egress policy update
    dlg.close()

    stopped_box = SandboxInfo(
        name="krunbox-edit-stopped",
        dir_path=str(work_dir),
        hostname="krunbox-edit-stopped",
        container_name="krunbox-edit-stopped",
        ssh_port=2241,
        cpus=4,
        ram_mib=4096,
        is_persistent=False,
        network_policy=NetworkPolicy(profile="full"),
        status="stopped",
    )
    mgr._sandboxes[stopped_box.name] = stopped_box
    mgr.save_state()

    dlg2 = EditSandboxDialog(win, mgr, stopped_box, on_saved=lambda: saved_calls.append(True))
    # Stopped sandbox never shows restart_banner when CPU/RAM changes
    dlg2.cpu_row.set_value(6)
    dlg2.ram_row.set_value(8)
    assert dlg2.restart_banner.get_revealed() is False

    dlg2.name_row.set_text("renamed-agent")
    assert "krunbox-renamed-agent" in dlg2.sanitized_preview_label.get_text()
    dlg2.net_combo.set_selected(dlg2.net_keys.index("custom"))
    assert dlg2.builtin_expander.get_subtitle() == "Custom whitelist only"
    dlg2.whitelist_entry.set_text("api.anthropic.com, pypi.org")
    dlg2.blacklist_entry.set_text("telemetry.evil.org")
    assert dlg2.whitelist_warn_icon.get_visible() is False
    assert dlg2.blacklist_warn_icon.get_visible() is False

    import subprocess
    fake_proc = subprocess.CompletedProcess(args=["podman"], returncode=0, stdout="", stderr="")
    with (
        patch("krunbox.core.manager.subprocess.run", return_value=fake_proc),
        patch("krunbox.core.manager.remove_sandbox_ssh_config", create=True),
        patch("krunbox.core.manager.write_sandbox_ssh_config", create=True),
        patch("krunbox.core.ssh.remove_sandbox_ssh_config"),
        patch("krunbox.core.ssh.write_sandbox_ssh_config"),
    ):
        dlg2._on_save_clicked(dlg2.save_btn)
        pump_gtk(25)

    assert len(saved_calls) == 1
    updated = mgr.get_sandbox("krunbox-renamed-agent")
    assert updated is not None
    assert updated.cpus == 6
    assert updated.ram_mib == 8192
    assert updated.network_policy.profile == "custom"
    assert updated.network_policy.allowed_domains == ["api.anthropic.com", "pypi.org"]
    assert updated.network_policy.denied_domains == ["telemetry.evil.org"]
    win.close()


def test_egress_traffic_dialog_ranking_filters_stream_policy_and_clear(app, tmp_path):
    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)

    work_dir = tmp_path / "traffic_proj"
    work_dir.mkdir()
    box = SandboxInfo(
        name="krunbox-net-watch",
        dir_path=str(work_dir),
        hostname="krunbox-net-watch",
        container_name="krunbox-net-watch",
        ssh_port=2250,
        status="stopped",
        network_policy=NetworkPolicy(profile="full"),
    )
    mgr._sandboxes[box.name] = box
    mgr.save_state()

    # 1. Empty state check
    empty_dlg = EgressTrafficDialog(win, mgr, sandbox_name=box.name)
    pump_gtk(20)
    assert empty_dlg.sites_stack.get_visible_child_name() == "empty"
    assert empty_dlg.events_stack.get_visible_child_name() == "empty"
    empty_dlg.close()

    # 2. Record outbound site events with varied frequencies and actions
    et = mgr.egress_traffic
    for _ in range(5):
        et.record_event(box.name, "api.anthropic.com", action="allowed", port=443, reason="profile:ai-only")
    for _ in range(2):
        et.record_event(box.name, "exfil.attacker.example", action="blocked", port=443, reason="denied")
    et.record_event(box.name, "pypi.org", action="allowed", port=443, reason="profile:dev-common")

    policy_callbacks = []
    dlg = EgressTrafficDialog(
        win,
        mgr,
        sandbox_name=box.name,
        on_policy_updated=lambda: policy_callbacks.append(True),
    )
    pump_gtk(25)

    assert dlg.sites_stack.get_visible_child_name() == "populated"
    assert dlg.unique_sites_label.get_text() == "3"
    assert dlg.total_calls_label.get_text() == "8"
    assert dlg.allowed_calls_label.get_text() == "6"
    assert dlg.blocked_calls_label.get_text() == "2"

    # Ranked by total_count descending: api.anthropic.com (5), exfil.attacker.example (2), pypi.org (1)
    assert [r._domain for r in dlg._site_rows] == [
        "api.anthropic.com",
        "exfil.attacker.example",
        "pypi.org",
    ]

    # Activity Stream tab populated with all 8 events
    dlg.view_stack.set_visible_child_name("events")
    assert dlg.events_stack.get_visible_child_name() == "populated"
    assert len(dlg._event_rows) == 8
    dlg.view_stack.set_visible_child_name("sites")

    # Filter: Blocked only
    dlg.filter_blocked_btn.set_active(True)
    assert [r._domain for r in dlg._site_rows] == ["exfil.attacker.example"]

    # Filter: Allowed only
    dlg.filter_allowed_btn.set_active(True)
    assert [r._domain for r in dlg._site_rows] == ["api.anthropic.com", "pypi.org"]

    # Filter: All + Search query
    dlg.filter_all_btn.set_active(True)
    dlg.search_entry.set_text("pypi")
    assert [r._domain for r in dlg._site_rows] == ["pypi.org"]

    dlg.search_entry.set_text("no-such-domain-zzz")
    assert dlg.sites_stack.get_visible_child_name() == "no-match"

    dlg.search_entry.set_text("")
    assert len(dlg._site_rows) == 3

    # 1-click Block domain action on "pypi.org"
    pypi_row = [r for r in dlg._site_rows if r._domain == "pypi.org"][0]
    assert pypi_row._policy_action_btn is not None
    pypi_row._policy_action_btn.emit("clicked")
    pump_gtk(25)

    updated_box = mgr.get_sandbox(box.name)
    assert "pypi.org" in updated_box.network_policy.denied_domains
    assert len(policy_callbacks) >= 1

    # Now "pypi.org" is in denied_domains, so its 1-click action offers Allow!
    pypi_row_after = [r for r in dlg._site_rows if r._domain == "pypi.org"][0]
    pypi_row_after._policy_action_btn.emit("clicked")
    pump_gtk(25)
    assert "pypi.org" not in mgr.get_sandbox(box.name).network_policy.denied_domains

    # Clear History button resets sites and events back to empty status pages
    dlg.clear_btn.emit("clicked")
    pump_gtk(25)
    assert dlg.sites_stack.get_visible_child_name() == "empty"
    assert dlg.events_stack.get_visible_child_name() == "empty"

    dlg.close()
    win.close()


def test_port_forward_dialog(app, tmp_path):
    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)
    dlg = PortForwardDialog(win, mgr, "krunbox-ui-test", on_forwarded=lambda: None)
    assert dlg is not None
    assert dlg.get_title() == "Forward Port"
    assert dlg.guest_entry.get_text() == "3000"
    dlg.close()
    win.close()


def test_logs_dialog(app, tmp_path):
    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)
    dlg = LogsDialog(win, mgr, "krunbox-ui-test")
    assert dlg is not None
    assert "Logs: krunbox-ui-test" in dlg.get_title()
    assert dlg.copy_btn is not None
    dlg.close()
    win.close()


def test_telemetry_dialog(app, tmp_path):
    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)
    dlg = TelemetryDialog(win, mgr, "krunbox-ui-test")
    pump_gtk(15)
    assert dlg is not None
    assert "Telemetry" in dlg.get_title()
    assert hasattr(dlg, "banner")
    assert dlg.banner.get_revealed() is True
    assert "Coming Soon" in dlg.banner.get_title()
    assert dlg.content_stack.get_visible_child_name() == "empty"
    dlg.close()
    win.close()


def test_doctor_dialog(app):
    win = KrunboxWindow(app)
    dlg = DoctorDialog(win)
    pump_gtk(20)
    assert dlg is not None
    assert "System Diagnostics" in dlg.get_title()
    dlg.close()
    win.close()


def test_settings_dialog(app, tmp_path, monkeypatch):
    monkeypatch.setattr(core_settings, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", tmp_path / "settings.json")
    win = KrunboxWindow(app)
    dlg = SettingsDialog(win)
    assert dlg is not None
    assert dlg.get_title() == "Preferences"
    assert dlg.theme_combo is not None
    dlg.theme_combo.set_selected(1)  # Light theme
    dlg._on_theme_changed(dlg.theme_combo, None)
    style_mgr = Adw.StyleManager.get_default()
    assert style_mgr.get_color_scheme() == Adw.ColorScheme.FORCE_LIGHT
    dlg.close()
    win.close()


def test_sandbox_card_dual_level_bars_and_split_button_and_pause(app, tmp_path):
    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)
    box = SandboxInfo(
        name="krunbox-card-meters-test",
        dir_path=str(tmp_path),
        hostname="krunbox-card-meters-test",
        container_name="krunbox-card-meters-test",
        ssh_port=2222,
        cpus=4,
        ram_mib=4096,
        is_persistent=True,
        network_policy=NetworkPolicy(profile="ai-only"),
        status="running",
        cpu_percent=45.0,
        mem_percent=60.0,
        mem_usage="2.4 GiB / 4.0 GiB",
        protect_git_hooks=True,
        host_egress_lockdown=True,
    )
    card = SandboxCard(win, mgr, box, on_updated=lambda: None)
    assert card is not None
    assert isinstance(card.connect_btn, Adw.SplitButton)
    assert isinstance(card.cpu_bar, Gtk.LevelBar)
    assert isinstance(card.ram_bar, Gtk.LevelBar)

    # Check level bar values (normalized 0.0 to 1.0)
    assert abs(card.cpu_bar.get_value() - 0.45) < 0.01
    assert abs(card.ram_bar.get_value() - 0.60) < 0.01
    assert "45.0%" in card.cpu_label.get_text()
    assert "2.4 GiB / 4.0 GiB" in card.ram_label.get_text()

    # Check guardrail and changes buttons
    assert card.changes_btn is not None
    assert card.pause_btn is not None
    assert card.pause_btn.get_icon_name() == "media-playback-pause-symbolic"

    # Test pause button action
    with patch.object(mgr, "pause_sandbox", return_value=(True, "paused")) as mock_pause:
        card._on_pause_clicked(card.pause_btn)
        mock_pause.assert_called_once_with(box.name)

    # Update to paused status
    box.status = "paused"
    card.update_data(box)
    assert card.status_pill.get_text() == "PAUSED"
    assert card.toggle_btn.get_icon_name() == "media-playback-start-symbolic"
    assert card.toggle_btn.has_css_class("suggested-action")
    assert card.pause_btn.get_visible() is False

    # Test resume action
    with patch.object(mgr, "unpause_sandbox", return_value=(True, "resumed")) as mock_unpause:
        card._on_resume_clicked(card.toggle_btn)
        mock_unpause.assert_called_once_with(box.name)

    card.cleanup()
    win.close()


def test_create_sandbox_dialog_template_preset_selection(app, tmp_path):
    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)
    dlg = CreateSandboxDialog(win, mgr, on_created=lambda: None)

    # Find locked-down-reviewer template index
    reviewer_idx = None
    for idx, tmpl in enumerate(dlg._templates, start=1):
        if tmpl.id == "locked-down-reviewer":
            reviewer_idx = idx
            break
    assert reviewer_idx is not None

    dlg.template_combo.set_selected(reviewer_idx)
    dlg._on_template_selected(dlg.template_combo, None)

    assert int(dlg.cpu_row.get_value()) == 2
    assert int(dlg.ram_row.get_value()) == 2
    assert dlg.net_keys[dlg.net_combo.get_selected()] == "offline"
    assert dlg.git_hooks_switch.get_active() is True
    assert dlg.git_config_switch.get_active() is True
    assert dlg.env_files_switch.get_active() is True
    assert dlg.host_lockdown_switch.get_active() is True
    assert int(dlg.idle_timeout_row.get_value()) == 30

    dlg.close()
    win.close()


def test_settings_dialog_guardrails_page(app, tmp_path, monkeypatch):
    monkeypatch.setattr(core_settings, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", tmp_path / "settings.json")
    win = KrunboxWindow(app)
    dlg = SettingsDialog(win)

    assert hasattr(dlg, "git_hooks_switch")
    assert hasattr(dlg, "host_lockdown_switch")
    assert hasattr(dlg, "idle_timeout_row")
    assert hasattr(dlg, "mem_threshold_row")
    assert hasattr(dlg, "spike_threshold_row")
    assert hasattr(dlg, "tokens_budget_row")
    assert hasattr(dlg, "cost_budget_row")

    # Modify guardrails settings
    dlg.git_hooks_switch.set_active(False)
    dlg.host_lockdown_switch.set_active(True)
    dlg.idle_timeout_row.set_value(45)
    dlg.mem_threshold_row.set_value(85)
    dlg.spike_threshold_row.set_value(7)
    dlg.tokens_budget_row.set_value(500000)
    dlg.cost_budget_row.set_value(25.50)

    dlg._save_all_settings()
    dlg.close()
    win.close()

    saved = core_settings.load_settings()
    assert saved["default_protect_git_hooks"] is False
    assert saved["default_host_egress_lockdown"] is True
    assert saved["default_idle_timeout_minutes"] == 45
    assert saved["mem_pressure_threshold_percent"] == 85
    assert saved["blocked_egress_spike_threshold"] == 7
    assert saved["default_max_tokens_budget"] == 500000
    assert saved["default_max_cost_usd_budget"] == 25.50


def test_window_alert_banner_for_mcp_requests_and_idle_warnings(app, tmp_path):
    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)
    win.manager = mgr

    assert hasattr(win, "alert_banner")
    assert isinstance(win.alert_banner, Adw.Banner)
    assert win.alert_banner.get_revealed() is False

    # 1. MCP Permission Request reveals banner with "Review Request"
    req = AccessRequest(
        id="req-ui-1",
        sandbox_name="krunbox-agent-test",
        action="request_domain_access",
        domain="registry.npmjs.org",
        reason="Need npm packages",
        status="pending",
    )
    win._update_banner([req], [])
    assert win.alert_banner.get_revealed() is True
    assert "registry.npmjs.org" in win.alert_banner.get_title()
    assert win.alert_banner.get_button_label() == "Review Request"

    # 2. Idle Pre-Warning alert reveals banner with "Keep Active (30m)"
    idle_alert = AlertEvent(
        id="idle-warn-1",
        timestamp=time.time(),
        category="idle_pre_warning",
        sandbox_name="krunbox-agent-test",
        title="MicroVM Sleeping Soon",
        body="MicroVM 'krunbox-agent-test' has been idle and will pause in ~1 minute. Keep active if still in use.",
        severity="warning",
    )
    win._update_banner([], [idle_alert])
    assert win.alert_banner.get_revealed() is True
    assert "idle and will pause" in win.alert_banner.get_title()
    assert win.alert_banner.get_button_label() == "Keep Active (30m)"

    # Clicking keep-awake banner button
    with patch.object(mgr, "keep_awake", return_value=(True, "Kept active")) as mock_ka:
        win._on_banner_clicked(win.alert_banner)
        mock_ka.assert_called_once_with("krunbox-agent-test", extend_minutes=30)
        assert win.alert_banner.get_revealed() is False

    # 3. Clean state hides banner
    win._update_banner([], [])
    assert win.alert_banner.get_revealed() is False
    win.close()


def test_sandbox_card_keep_awake_action_and_badge(app, tmp_path):
    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)
    box = SandboxInfo(
        name="krunbox-awake-test",
        dir_path=str(tmp_path),
        hostname="krunbox-awake-test",
        container_name="krunbox-awake-test",
        ssh_port=2222,
        idle_timeout_minutes=0,  # Never sleep
        status="running",
    )
    card = SandboxCard(win, mgr, box, on_updated=lambda: None)

    # Check "Never Sleep" badge in guardrails summary
    assert "Never Sleep" in card.guard_pill.get_text()

    # Toggle keep awake via card action
    with patch.object(mgr, "keep_awake", return_value=(True, "Updated")) as mock_ka:
        card._on_keep_awake_clicked()
        mock_ka.assert_called_once()

    card.cleanup()
    win.close()


def test_egress_traffic_dialog_export_functionality(app, tmp_path):
    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)

    work_dir = tmp_path / "export_proj"
    work_dir.mkdir()
    box = SandboxInfo(
        name="krunbox-export-test",
        dir_path=str(work_dir),
        hostname="krunbox-export-test",
        container_name="krunbox-export-test",
        ssh_port=2255,
        status="running",
    )
    mgr._sandboxes[box.name] = box
    mgr.save_state()

    # 1. Test empty state: export_btn exists, is insensitive, and _on_export_clicked shows toast
    dlg = EgressTrafficDialog(win, mgr, sandbox_name=box.name)
    pump_gtk(20)

    assert hasattr(dlg, "export_btn")
    assert dlg.export_btn is not None
    assert dlg.export_btn.get_sensitive() is False

    # Calling _on_export_clicked on empty dialog triggers warning toast without error
    dlg._on_export_clicked()
    pump_gtk(10)

    # 2. Record traffic and refresh dialog
    et = mgr.egress_traffic
    for _ in range(3):
        et.record_event(box.name, "api.openai.com", action="allowed", port=443, reason="ai")
    et.record_event(box.name, "blocked.tracker.com", action="blocked", port=80, reason="denied")

    dlg.load_data()
    pump_gtk(25)

    assert dlg.export_btn.get_sensitive() is True
    assert len(dlg.get_filtered_sites()) == 2

    # 3. Test export_sites_to_file full list export
    csv_out = tmp_path / "all_sites.csv"
    ok, msg = dlg.export_sites_to_file(csv_out)
    assert ok is True
    assert csv_out.is_file()
    content = csv_out.read_text(encoding="utf-8")
    assert "api.openai.com" in content
    assert "blocked.tracker.com" in content

    # 4. Test export_sites_to_file with active filter (Blocked only)
    dlg.filter_blocked_btn.set_active(True)
    pump_gtk(15)
    filtered = dlg.get_filtered_sites()
    assert len(filtered) == 1
    assert filtered[0]["domain"] == "blocked.tracker.com"

    filtered_json = tmp_path / "filtered.json"
    ok, msg = dlg.export_sites_to_file(filtered_json)
    assert ok is True
    assert filtered_json.is_file()
    import json
    data = json.loads(filtered_json.read_text(encoding="utf-8"))
    assert data["total_sites"] == 1
    assert data["sites"][0]["domain"] == "blocked.tracker.com"

    # 5. Test export_sites_to_file with search query
    dlg.filter_all_btn.set_active(True)
    dlg.search_entry.set_text("openai")
    pump_gtk(15)
    search_filtered = dlg.get_filtered_sites()
    assert len(search_filtered) == 1
    assert search_filtered[0]["domain"] == "api.openai.com"

    search_csv = tmp_path / "search.csv"
    ok, msg = dlg.export_sites_to_file(search_csv)
    assert ok is True
    search_text = search_csv.read_text(encoding="utf-8")
    assert "api.openai.com" in search_text
    assert "blocked.tracker.com" not in search_text

    dlg.close()
    win.close()


def test_mcp_guide_dialog_syntax_highlighting(app):
    from krunbox.ui.mcp_guide_dialog import (
        McpGuideDialog,
        STDIO_MCP_CONFIG_JSON,
        highlight_json_markup,
        highlight_python_markup,
    )

    win = KrunboxWindow(app)
    guide = McpGuideDialog(parent_window=win)
    pump_gtk(15)

    assert hasattr(guide, "json_label")
    # Clean text content matches original JSON
    assert guide.json_label.get_text().strip() == STDIO_MCP_CONFIG_JSON.strip()
    assert len(guide._highlight_labels) >= 2

    # Verify markup highlights keys and strings
    dark_markup = highlight_json_markup(STDIO_MCP_CONFIG_JSON, dark=True)
    light_markup = highlight_json_markup(STDIO_MCP_CONFIG_JSON, dark=False)
    assert 'foreground="#78aeed"' in dark_markup  # Dark mode key color
    assert 'foreground="#8ff0a4"' in dark_markup  # Dark mode string color
    assert 'foreground="#1a5fb4"' in light_markup # Light mode key color
    assert 'foreground="#26a269"' in light_markup # Light mode string color

    # Python syntax highlighting check
    py_sample = 'import socket, json\n# comment\nsock.connect("path")'
    py_markup = highlight_python_markup(py_sample, dark=True)
    assert 'weight="bold"' in py_markup
    assert 'style="italic"' in py_markup

    guide.close()
    win.close()


def test_split_button_dropdown_arrow_icon(app, tmp_path):
    """Verify that SplitButton dropdown has an explicit widely-supported down-arrow icon."""
    from krunbox.ui.sandbox_row import _resolve_dropdown_arrow_icon

    icon_name = _resolve_dropdown_arrow_icon()
    assert icon_name in ("go-down-symbolic", "pan-down-symbolic")

    win = KrunboxWindow(app)
    mgr = make_isolated_manager(tmp_path)
    box = SandboxInfo(
        name="krunbox-icon-test",
        dir_path=str(tmp_path),
        hostname="krunbox-icon-test",
        container_name="krunbox-icon-test",
        ssh_port=2222,
    )
    card = SandboxCard(win, mgr, box, on_updated=lambda: None)

    assert card.connect_dropdown_btn is not None
    assert card.connect_dropdown_btn.get_icon_name() == icon_name
    assert card.connect_btn.get_dropdown_tooltip() == "Open in IDE or SFTP File Manager"

    card.cleanup()
    win.close()


