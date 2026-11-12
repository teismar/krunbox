"""
Main Libadwaita application window for krunbox.
"""

from typing import List, Optional
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib, Gio

from ..core.manager import SandboxManager
from ..core.notifications import send_desktop_notification
from ..core.settings import load_settings, save_settings
from .sandbox_row import SandboxCard
from .create_dialog import CreateSandboxDialog
from .egress_dialog import EgressTrafficDialog
from .doctor_dialog import DoctorDialog
from .telemetry_dialog import TelemetryDialog
from .settings_dialog import SettingsDialog
from .mcp_panel import McpRequestsSidepanel
from .dialogs import show_alert_dialog
from .worker import run_async


def _collect_about_debug_info(cached_sandboxes_count: int = 0) -> str:
    import os
    import platform
    import shutil
    import subprocess
    from pathlib import Path

    def get_distro() -> str:
        os_release = Path("/etc/os-release")
        if os_release.exists():
            try:
                for line in os_release.read_text(encoding="utf-8").splitlines():
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip('"\'')
            except Exception:
                pass
        return platform.platform()

    def get_cmd_version(cmd: str, args: Optional[List[str]] = None) -> str:
        bin_path = shutil.which(cmd)
        if not bin_path:
            return "Not installed"
        cmd_args = [bin_path] + (args or ["--version"])
        try:
            res = subprocess.run(cmd_args, capture_output=True, text=True, timeout=2)
            out = (res.stdout or res.stderr).strip().splitlines()
            return out[0] if out else bin_path
        except Exception as e:
            return f"{bin_path} (error: {e})"

    def get_kvm_status() -> str:
        p = Path("/dev/kvm")
        if not p.exists():
            return "Not available (/dev/kvm missing)"
        if os.access(p, os.R_OK | os.W_OK):
            return "Available (read/write acceleration active)"
        return "Permission denied (add user to 'kvm' group)"

    def get_subuid_status() -> str:
        subuid = Path("/etc/subuid")
        user = os.environ.get("USER", "root")
        if subuid.exists():
            try:
                content = subuid.read_text(encoding="utf-8")
                if user in content or "1000" in content:
                    return f"Configured for '{user}'"
            except Exception:
                pass
        return "Not configured"

    gtk_ver = "unknown"
    adw_ver = "unknown"
    try:
        gtk_ver = f"{Gtk.get_major_version()}.{Gtk.get_minor_version()}.{Gtk.get_micro_version()}"
    except Exception:
        pass
    try:
        adw_ver = f"{Adw.get_major_version()}.{Adw.get_minor_version()}.{Adw.get_micro_version()}"
    except Exception:
        pass

    krun_status = (
        get_cmd_version("krun")
        if shutil.which("krun")
        else (get_cmd_version("crun-krun") if shutil.which("crun-krun") else get_cmd_version("crun"))
    )

    info_lines = [
        "=== Krunbox System & Diagnostic Info ===",
        "Krunbox: 2.0.0",
        f"OS: {get_distro()}",
        f"Kernel: {platform.release()} ({platform.machine()})",
        f"Python: {platform.python_version()}",
        f"Desktop Stack: GTK {gtk_ver} · Libadwaita {adw_ver}",
        f"Session: {os.environ.get('XDG_SESSION_TYPE', 'n/a')} (desktop: {os.environ.get('XDG_CURRENT_DESKTOP', 'n/a')})",
        f"Active Sandboxes: {cached_sandboxes_count}",
        "",
        "=== Virtualization & Runtimes ===",
        f"Podman: {get_cmd_version('podman')}",
        f"Krun / crun-krun: {krun_status}",
        f"KVM Hardware Acceleration: {get_kvm_status()}",
        f"passt (Network Virtualization): {get_cmd_version('passt', ['--version'])}",
        f"Rootless SubUIDs: {get_subuid_status()}",
        f"OpenSSH: {get_cmd_version('ssh', ['-V'])}",
    ]
    return "\n".join(info_lines)


class KrunboxWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application):
        super().__init__(application=app)
        self.set_title("krunbox - MicroVM Sandboxes")
        self.set_icon_name("io.krunbox.Krunbox")
        self.set_default_size(940, 680)

        self.manager = SandboxManager()
        self.refresh_timer_id = None
        self._refresh_interval_secs = 3
        self.cached_sandboxes = []
        self.filter_query = ""
        self._cards = {}
        self._is_refreshing = False
        self._closed = False
        self._win_action_names: List[str] = []
        self._current_alert_type = None
        self._current_alert_data = None

        self._setup_window_actions()

        # Toast Overlay
        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        toolbar_view = Adw.ToolbarView()
        self.toast_overlay.set_child(toolbar_view)

        # Header Bar
        header = Adw.HeaderBar()
        toolbar_view.add_top_bar(header)

        # In-App Banner for MCP Permission Requests and Idle Pre-Warnings
        self.alert_banner = Adw.Banner()
        self.alert_banner.set_revealed(False)
        self.alert_banner.connect("button-clicked", self._on_banner_clicked)
        toolbar_view.add_top_bar(self.alert_banner)

        self.title_widget = Adw.WindowTitle(
            title="krunbox",
            subtitle="MicroVM Sandboxes",
        )
        header.set_title_widget(self.title_widget)

        # Start: Primary "New Sandbox" Action
        self.new_btn = Gtk.Button()
        new_btn_content = Adw.ButtonContent(
            icon_name="list-add-symbolic",
            label="New Sandbox",
        )
        self.new_btn.set_child(new_btn_content)
        self.new_btn.set_tooltip_text("Create a new microVM sandbox (Ctrl+N)")
        self.new_btn.add_css_class("suggested-action")
        self.new_btn.connect("clicked", self._on_new_clicked)
        header.pack_start(self.new_btn)

        # End: Primary MenuButton + High-frequency Icon Buttons
        menu = Gio.Menu()
        tools_section = Gio.Menu()
        tools_section.append("Egress Traffic Monitor", "win.egress-traffic")
        tools_section.append("AI API Telemetry", "win.telemetry")
        tools_section.append("MCP Integration Guide", "win.mcp-guide")
        tools_section.append("System Diagnostics", "win.doctor")
        tools_section.append("Prune Stopped Ephemerals", "win.prune")
        menu.append_section(None, tools_section)

        app_section = Gio.Menu()
        app_section.append("Preferences", "win.preferences")
        app_section.append("About krunbox", "win.about")
        menu.append_section(None, app_section)

        self.menu_btn = Gtk.MenuButton(
            icon_name="open-menu-symbolic",
            menu_model=menu,
            tooltip_text="Main Menu",
        )
        header.pack_end(self.menu_btn)

        self.theme_btn = Gtk.Button()
        self.theme_btn.set_tooltip_text("Toggle Color Scheme (System / Dark / Light)")
        self._update_theme_btn_icon()
        self.theme_btn.connect("clicked", self._on_quick_theme_toggle)
        header.pack_end(self.theme_btn)

        self.refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        self.refresh_btn.set_tooltip_text("Refresh Status (Ctrl+R)")
        self.refresh_btn.connect("clicked", lambda _: self.refresh())
        header.pack_end(self.refresh_btn)

        self.traffic_btn = Gtk.Button(icon_name="network-transmit-receive-symbolic")
        self.traffic_btn.set_tooltip_text("Egress Traffic Monitor")
        self.traffic_btn.connect("clicked", self._on_egress_traffic_clicked)
        header.pack_end(self.traffic_btn)

        # Agent MCP Requests Sidepanel Toggle
        self.mcp_toggle_btn = Gtk.ToggleButton()
        self.mcp_btn_content = Adw.ButtonContent(
            icon_name="security-high-symbolic",
            label="Agent Requests",
        )
        self.mcp_toggle_btn.set_child(self.mcp_btn_content)
        self.mcp_toggle_btn.set_tooltip_text("Toggle Agent Permission Requests Sidepanel")
        self.mcp_toggle_btn.connect("toggled", self._on_mcp_toggle_clicked)
        header.pack_end(self.mcp_toggle_btn)

        # Content Box (Clamped Search Bar + Stack)
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        # Overlay Split View containing main content and the MCP Sidepanel
        self.split_view = Adw.OverlaySplitView()
        self.split_view.set_sidebar_position(Gtk.PackType.END)
        self.split_view.set_show_sidebar(False)
        self.split_view.set_max_sidebar_width(380)
        self.split_view.set_min_sidebar_width(320)
        self.split_view.set_content(content_box)

        self.mcp_sidepanel = McpRequestsSidepanel(
            manager=self.manager,
            on_request_handled=lambda: self.refresh(silent=True),
            on_close_requested=self._on_mcp_sidepanel_close,
            parent_window=self,
        )
        self.split_view.set_sidebar(self.mcp_sidepanel)
        toolbar_view.set_content(self.split_view)

        search_clamp = Adw.Clamp(maximum_size=900, tightening_threshold=640)
        content_box.append(search_clamp)

        search_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        search_bar.set_margin_top(10)
        search_bar.set_margin_bottom(6)
        search_bar.set_margin_start(16)
        search_bar.set_margin_end(16)
        search_clamp.set_child(search_bar)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_hexpand(True)
        self.search_entry.set_placeholder_text("Filter sandboxes by name, directory, or port… (Ctrl+F)")
        self.search_entry.connect("changed", self._on_search_changed)
        self.search_entry.connect("search-changed", self._on_search_changed)
        search_bar.append(self.search_entry)

        search_controller = Gtk.ShortcutController.new()
        search_trigger = Gtk.ShortcutTrigger.parse_string("<Primary>f")
        search_action = Gtk.CallbackAction.new(lambda *_: (self.search_entry.grab_focus(), True)[1])
        search_shortcut = Gtk.Shortcut.new(search_trigger, search_action)
        search_controller.add_shortcut(search_shortcut)
        self.add_controller(search_controller)

        self.stats_pill = Gtk.Label(label="0 Active · 0 Forwarded Ports")
        self.stats_pill.add_css_class("caption")
        self.stats_pill.add_css_class("dim-label")
        self.stats_pill.add_css_class("numeric")
        search_bar.append(self.stats_pill)

        # Stack: Loading vs Empty vs No-Results vs List
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.stack.set_vexpand(True)
        content_box.append(self.stack)

        # Initial Loading State
        loading_page = Adw.StatusPage(
            icon_name="io.krunbox.Krunbox",
            title="Scanning MicroVM Sandboxes…",
            description="Connecting to container runtime and scanning active sandboxes…",
        )
        loading_spinner = Gtk.Spinner()
        loading_spinner.start()
        loading_spinner.set_halign(Gtk.Align.CENTER)
        loading_page.set_child(loading_spinner)
        self.stack.add_named(loading_page, "loading")
        self.stack.set_visible_child_name("loading")

        # Empty State
        status_page = Adw.StatusPage(
            icon_name="computer-symbolic",
            title="No MicroVM Sandboxes",
            description="Create an isolated crun-krun microVM sandbox with configurable CPU/RAM, egress filtering, and SSH access.",
        )
        launch_first_btn = Gtk.Button(label="New Sandbox")
        launch_first_btn.add_css_class("suggested-action")
        launch_first_btn.add_css_class("pill")
        launch_first_btn.set_halign(Gtk.Align.CENTER)
        launch_first_btn.connect("clicked", self._on_new_clicked)
        status_page.set_child(launch_first_btn)
        self.stack.add_named(status_page, "empty")

        # No Filter Matches State
        no_results_page = Adw.StatusPage(
            icon_name="system-search-symbolic",
            title="No Matching Sandboxes",
            description="No sandboxes match the current search filter.",
        )
        self.stack.add_named(no_results_page, "no-results")

        # Scrolled & Clamped Card List
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)

        list_clamp = Adw.Clamp(maximum_size=900, tightening_threshold=640)
        scrolled.set_child(list_clamp)

        self.list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.list_box.set_margin_top(6)
        self.list_box.set_margin_bottom(24)
        self.list_box.set_margin_start(16)
        self.list_box.set_margin_end(16)
        list_clamp.set_child(self.list_box)
        self.stack.add_named(scrolled, "list")

        self.refresh(silent=True)
        self._schedule_refresh_timer()
        self.connect("close-request", self._on_close_request)

    def _setup_window_actions(self):
        actions = [
            ("egress-traffic", lambda *_: self._on_egress_traffic_clicked(None)),
            ("telemetry", lambda *_: self._on_telemetry_clicked(None)),
            ("mcp-guide", lambda *_: self._on_mcp_guide_clicked(None)),
            ("doctor", lambda *_: self._on_doctor_clicked(None)),
            ("prune", lambda *_: self._on_prune_clicked(None)),
            ("preferences", lambda *_: self._on_settings_clicked(None)),
            ("about", lambda *_: self._on_about_clicked(None)),
        ]
        for name, callback in actions:
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", callback)
            self.add_action(act)
            self._win_action_names.append(name)

    def _schedule_refresh_timer(self):
        if self.refresh_timer_id:
            GLib.source_remove(self.refresh_timer_id)
            self.refresh_timer_id = None
        settings = load_settings()
        interval = max(1, int(settings.get("auto_refresh_seconds", 3)))
        self._refresh_interval_secs = interval
        self.refresh_timer_id = GLib.timeout_add_seconds(interval, self._on_periodic_refresh)

    def _on_settings_updated(self):
        self._update_theme_btn_icon()
        settings = load_settings()
        new_interval = max(1, int(settings.get("auto_refresh_seconds", 3)))
        if new_interval != self._refresh_interval_secs:
            self._schedule_refresh_timer()

    def _update_theme_btn_icon(self):
        settings = load_settings()
        theme = settings.get("color_scheme", "system")
        if theme == "light":
            self.theme_btn.set_icon_name("weather-clear-symbolic")
        elif theme == "dark":
            self.theme_btn.set_icon_name("weather-clear-night-symbolic")
        else:
            self.theme_btn.set_icon_name("preferences-desktop-display-symbolic")

    def _on_quick_theme_toggle(self, _btn):
        settings = load_settings()
        order = ["system", "dark", "light"]
        cur = settings.get("color_scheme", "system")
        cur_idx = order.index(cur) if cur in order else 0
        next_theme = order[(cur_idx + 1) % len(order)]
        settings["color_scheme"] = next_theme
        save_settings(settings)

        style_mgr = Adw.StyleManager.get_default()
        if next_theme == "light":
            style_mgr.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
        elif next_theme == "dark":
            style_mgr.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
        else:
            style_mgr.set_color_scheme(Adw.ColorScheme.DEFAULT)

        self._update_theme_btn_icon()
        names = {"system": "System", "dark": "Dark", "light": "Light"}
        self.toast_overlay.add_toast(Adw.Toast.new(f"Appearance: {names[next_theme]}"))

    def _on_settings_clicked(self, _btn):
        dialog = SettingsDialog(self, on_settings_changed=self._on_settings_updated)
        dialog.present()

    def _on_egress_traffic_clicked(self, _btn):
        dialog = EgressTrafficDialog(
            self,
            self.manager,
            sandbox_name=None,
            on_policy_updated=lambda: self.refresh(silent=True),
        )
        dialog.present()

    def _on_close_request(self, *_args):
        self._closed = True
        if self.refresh_timer_id:
            GLib.source_remove(self.refresh_timer_id)
            self.refresh_timer_id = None
        if self.menu_btn:
            self.menu_btn.set_menu_model(None)
        for act_name in self._win_action_names:
            self.remove_action(act_name)
        self._win_action_names.clear()
        for card in list(self._cards.values()):
            self.list_box.remove(card)
            card.cleanup()
        self._cards.clear()
        return False

    def _on_periodic_refresh(self):
        if self._closed:
            return False
        self.refresh(silent=True)
        return True

    def _on_search_changed(self, entry):
        new_query = entry.get_text().strip().lower()
        if new_query == self.filter_query:
            return
        self.filter_query = new_query
        self._render_cards()

    def refresh(self, silent: bool = False):
        if self._is_refreshing or self._closed:
            return
        self._is_refreshing = True

        def worker():
            sandboxes = self.manager.list_sandboxes(refresh_podman=True)
            stats = self.manager.get_stats()
            for s in sandboxes:
                st = stats.get(s.name, {})
                s.cpu_percent = st.get("cpu_percent", 0.0)
                s.mem_usage = st.get("mem_usage", "")
                s.mem_percent = st.get("mem_percent", 0.0)
            alerts = []
            if hasattr(self.manager, "evaluate_guardrails"):
                alerts, actions_taken = self.manager.evaluate_guardrails(sandboxes)
                if actions_taken:
                    sandboxes = self.manager.list_sandboxes(refresh_podman=False)
            pending_reqs = []
            if hasattr(self.manager, "get_pending_access_requests"):
                pending_reqs = self.manager.get_pending_access_requests()
            elif hasattr(self.manager, "list_pending_requests"):
                pending_reqs = self.manager.list_pending_requests()
            return sandboxes, alerts, pending_reqs

        def on_done(payload):
            self._is_refreshing = False
            if self._closed:
                return
            sandboxes, alerts, pending_reqs = payload
            self.cached_sandboxes = sandboxes
            self._render_cards()
            self._update_banner(pending_reqs, alerts)
            if alerts:
                settings = load_settings()
                notify_enabled = bool(settings.get("enable_desktop_notifications", True))
                app = self.get_application()
                for alert in alerts:
                    self.toast_overlay.add_toast(Adw.Toast.new(f"{alert.title}: {alert.body}"))
                    if notify_enabled:
                        send_desktop_notification(
                            title=alert.title,
                            body=alert.body,
                            notification_id=alert.id,
                            urgent=(alert.severity == "critical"),
                            app=app,
                        )
            if not silent:
                self.toast_overlay.add_toast(Adw.Toast.new("Sandboxes refreshed"))

        def on_error(err):
            self._is_refreshing = False
            print(f"[krunbox-ui] Error during status refresh: {err}")

        run_async(worker, on_success=on_done, on_error=on_error)

    def _on_mcp_toggle_clicked(self, btn):
        show = btn.get_active()
        self.split_view.set_show_sidebar(show)
        if show:
            self.mcp_sidepanel.reload_requests()

    def _on_mcp_sidepanel_close(self):
        self.split_view.set_show_sidebar(False)
        self.mcp_toggle_btn.set_active(False)

    def _update_banner(self, pending_requests, alerts):
        if pending_requests:
            count = len(pending_requests)
            self.mcp_btn_content.set_label(f"Requests ({count})")
            self.mcp_toggle_btn.add_css_class("suggested-action")
            req = pending_requests[0]
            self._current_alert_type = "mcp"
            self._current_alert_data = req
            rtype = getattr(req, "request_type", getattr(req, "action", "domain"))
            target = getattr(req, "target", "") or getattr(req, "domain", "") or str(getattr(req, "guest_port", ""))
            self.alert_banner.set_title(
                f"Agent in '{req.sandbox_name}' requests access to {rtype} '{target}': {req.reason}"
            )
            self.alert_banner.set_button_label("Review Request")
            self.alert_banner.set_revealed(True)
            return

        self.mcp_btn_content.set_label("Agent Requests")
        self.mcp_toggle_btn.remove_css_class("suggested-action")

        idle_warn = next((a for a in alerts if getattr(a, "category", "") == "idle_pre_warning"), None)
        if idle_warn:
            self._current_alert_type = "idle"
            self._current_alert_data = idle_warn
            self.alert_banner.set_title(idle_warn.body)
            self.alert_banner.set_button_label("Keep Active (30m)")
            self.alert_banner.set_revealed(True)
            return

        self._current_alert_type = None
        self._current_alert_data = None
        self.alert_banner.set_revealed(False)

    def _on_banner_clicked(self, _banner):
        if self._current_alert_type == "mcp" and self._current_alert_data:
            self.split_view.set_show_sidebar(True)
            self.mcp_toggle_btn.set_active(True)
            self.mcp_sidepanel.reload_requests()
            return

        elif self._current_alert_type == "idle" and self._current_alert_data:
            warn = self._current_alert_data
            box_name = getattr(warn, "sandbox_name", "")
            ok, msg = self.manager.keep_awake(box_name, extend_minutes=30)
            self.toast_overlay.add_toast(Adw.Toast.new(f"Kept '{box_name}' active for 30m"))
            self.alert_banner.set_revealed(False)
            self.refresh(silent=True)

    def _render_cards(self):
        running_count = sum(1 for s in self.cached_sandboxes if s.status == "running")
        paused_count = sum(1 for s in self.cached_sandboxes if s.status == "paused")
        total_ports = sum(len(s.all_ports) for s in self.cached_sandboxes if s.status == "running")
        stopped_count = max(0, len(self.cached_sandboxes) - running_count - paused_count)
        if paused_count > 0:
            self.title_widget.set_subtitle(
                f"{running_count} Running · {paused_count} Paused · {stopped_count} Stopped"
            )
        else:
            self.title_widget.set_subtitle(f"{running_count} Running · {stopped_count} Stopped")
        self.stats_pill.set_text(f"{running_count} Active · {total_ports} Forwarded Ports")

        filtered = self.cached_sandboxes
        if self.filter_query:
            filtered = [
                s for s in self.cached_sandboxes
                if self.filter_query in s.name.lower()
                or self.filter_query in s.dir_path.lower()
                or any(
                    self.filter_query in str(p.host_port) or self.filter_query in str(p.guest_port)
                    for p in s.all_ports
                )
            ]

        if not self.cached_sandboxes:
            self.stack.set_visible_child_name("empty")
            for card in list(self._cards.values()):
                self.list_box.remove(card)
                card.cleanup()
            self._cards.clear()
            return

        if not filtered:
            self.stack.set_visible_child_name("no-results")
            for card in list(self._cards.values()):
                self.list_box.remove(card)
                card.cleanup()
            self._cards.clear()
            return

        self.stack.set_visible_child_name("list")

        current_names = {b.name for b in filtered}
        for name in list(self._cards.keys()):
            if name not in current_names:
                card = self._cards.pop(name)
                self.list_box.remove(card)
                card.cleanup()

        for box in filtered:
            if box.name in self._cards:
                self._cards[box.name].update_data(box)
            else:
                card = SandboxCard(
                    self,
                    self.manager,
                    box,
                    on_updated=lambda: self.refresh(silent=True),
                )
                self._cards[box.name] = card
                self.list_box.append(card)

    def _on_about_clicked(self, _btn):
        use_dialog = hasattr(Adw, "AboutDialog")
        common_kwargs = dict(
            application_name="krunbox",
            application_icon="io.krunbox.Krunbox",
            developer_name="Krunbox Development Team",
            version="2.0.0",
            copyright="© 2026 Krunbox Authors",
            license_type=Gtk.License.APACHE_2_0,
            website="https://github.com/teismar/krunbox",
            issue_url="https://github.com/teismar/krunbox/issues",
            comments=(
                "Podman and crun-krun microVM orchestrator for isolated AI agent workflows.\n\n"
                "Made with &lt;3 in Vienna by @teismar"
            ),
        )

        if use_dialog:
            about = Adw.AboutDialog(**common_kwargs)
        else:
            about = Adw.AboutWindow(transient_for=self, **common_kwargs)

        about.set_developers(["teismar https://github.com/teismar"])

        if hasattr(about, "add_credit_section"):
            about.add_credit_section(
                "Powered by",
                [
                    "crun-krun / libkrun https://github.com/slp/crun-krun",
                    "Podman https://podman.io",
                    "Libadwaita & GNOME https://gitlab.gnome.org/GNOME/libadwaita",
                ],
            )

        if hasattr(about, "add_link"):
            about.add_link("Documentation", "https://github.com/teismar/krunbox#readme")
            about.add_link("Discussions", "https://github.com/teismar/krunbox/discussions")

        if hasattr(about, "set_debug_info"):
            debug_info = _collect_about_debug_info(len(self.cached_sandboxes))
            about.set_debug_info(debug_info)

        if use_dialog:
            about.present(self)
        else:
            about.present()

    def _on_new_clicked(self, _btn):
        dialog = CreateSandboxDialog(
            self,
            self.manager,
            on_created=lambda: self.refresh(silent=False),
        )
        dialog.present()

    def _on_doctor_clicked(self, _btn):
        dialog = DoctorDialog(self)
        dialog.present()

    def _on_mcp_guide_clicked(self, _btn):
        from .mcp_guide_dialog import McpGuideDialog
        dialog = McpGuideDialog(self)
        dialog.present()

    def _on_telemetry_clicked(self, _btn):
        dialog = TelemetryDialog(self, self.manager)
        dialog.present()

    def _on_prune_clicked(self, _btn):
        def on_response(response: str):
            if response == "prune":
                def worker():
                    return self.manager.prune()

                def on_done(count):
                    if self._closed:
                        return
                    self.toast_overlay.add_toast(Adw.Toast.new(f"Pruned {count} ephemeral sandboxes"))
                    self.refresh(silent=True)

                run_async(worker, on_success=on_done)

        show_alert_dialog(
            parent_window=self,
            heading="Prune Stopped Ephemeral Sandboxes?",
            body="Clean up all stopped ephemeral sandboxes and remove temporary SSH host entries.",
            responses=[
                ("cancel", "Cancel"),
                ("prune", "Prune", Adw.ResponseAppearance.DESTRUCTIVE),
            ],
            on_response=on_response,
            default_response="cancel",
            close_response="cancel",
        )
