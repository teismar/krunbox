"""
Native Libadwaita dialog to dynamically forward ports from a running sandbox to localhost
and manage active dynamic SSH tunnels.
"""

from typing import Callable, List
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from ..core.manager import SandboxManager
from ..core.ports import find_free_port
from .worker import run_async


class PortForwardDialog(Adw.Window):
    def __init__(
        self,
        parent_window: Gtk.Window,
        manager: SandboxManager,
        sandbox_name: str,
        on_forwarded: Callable[[], None],
    ):
        super().__init__(modal=True, transient_for=parent_window)
        self.set_title("Forward Port")
        self.set_default_size(500, 420)
        self.parent_window = parent_window
        self.manager = manager
        self.sandbox_name = sandbox_name
        self.on_forwarded = on_forwarded
        self._closed = False
        self._tunnel_rows: List[Gtk.Widget] = []

        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        toolbar_view = Adw.ToolbarView()
        self.toast_overlay.set_child(toolbar_view)

        header = Adw.HeaderBar(
            show_start_title_buttons=False,
            show_end_title_buttons=False,
        )
        toolbar_view.add_top_bar(header)

        self.cancel_btn = Gtk.Button(label="Cancel")
        self.cancel_btn.connect("clicked", lambda _: self.close())
        header.pack_start(self.cancel_btn)

        self.forward_btn = Gtk.Button(label="Forward")
        self.forward_btn.add_css_class("suggested-action")
        self.forward_btn.connect("clicked", self._on_forward_clicked)
        header.pack_end(self.forward_btn)

        self.error_banner = Adw.Banner()
        self.error_banner.set_use_markup(False)
        self.error_banner.set_revealed(False)
        toolbar_view.add_top_bar(self.error_banner)

        page = Adw.PreferencesPage()
        toolbar_view.set_content(page)

        safe_name = GLib.markup_escape_text(sandbox_name)
        group = Adw.PreferencesGroup(
            title="New Dynamic Tunnel",
            description=f"Forward a TCP port from {safe_name} to localhost",
        )
        page.add(group)

        self.guest_entry = Adw.EntryRow(title="Guest Port (Sandbox)")
        self.guest_entry.set_text("3000")
        self.guest_entry.connect("changed", self._on_guest_port_changed)
        group.add(self.guest_entry)

        self.host_entry = Adw.EntryRow(title="Host Port (Localhost)")
        self.host_entry.set_text("3000")
        self._user_edited_host_port = False
        self.host_entry.connect("changed", self._on_host_port_changed)
        group.add(self.host_entry)

        preset_row = Adw.ActionRow(title="Quick Presets")
        preset_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        preset_box.set_valign(Gtk.Align.CENTER)
        for port_num, desc in [
            (3000, "Web (3000)"),
            (5173, "Vite (5173)"),
            (8000, "API (8000)"),
            (8888, "Jupyter (8888)"),
        ]:
            btn = Gtk.Button(label=desc)
            btn.add_css_class("flat")
            btn.add_css_class("caption")
            btn.connect("clicked", lambda _b, p=port_num: self._set_preset(p))
            preset_box.append(btn)
        preset_row.add_suffix(preset_box)
        group.add(preset_row)

        # Active dynamic tunnels group (shown only when dynamic_tunnels exist)
        self.active_group = Adw.PreferencesGroup(
            title="Active Tunnels",
            description="Live SSH port forwards currently active for this sandbox",
        )
        page.add(self.active_group)
        self._refresh_active_tunnels()

        self.status_label = Gtk.Label(label="", wrap=True)
        self._update_free_host_port(3000)
        self.connect("close-request", self._on_close_request)

    def _on_close_request(self, *_args):
        self._closed = True
        return False

    def _refresh_active_tunnels(self):
        for r in self._tunnel_rows:
            self.active_group.remove(r)
        self._tunnel_rows.clear()

        box = None
        try:
            box = self.manager.get_sandbox(self.sandbox_name)
        except Exception:
            box = None

        tunnels = list(box.dynamic_tunnels) if box and box.dynamic_tunnels else []
        self.active_group.set_visible(bool(tunnels))

        for tun in tunnels:
            row = Adw.ActionRow(
                title=GLib.markup_escape_text(f"127.0.0.1:{tun.host_port} → :{tun.guest_port}"),
                subtitle="Dynamic SSH tunnel",
            )
            row.add_css_class("monospace")
            disc_btn = Gtk.Button(label="Disconnect")
            disc_btn.add_css_class("destructive-action")
            disc_btn.set_valign(Gtk.Align.CENTER)
            disc_btn.connect(
                "clicked",
                lambda b, gp=tun.guest_port: self._on_disconnect_tunnel(b, gp),
            )
            row.add_suffix(disc_btn)
            self.active_group.add(row)
            self._tunnel_rows.append(row)

    def _on_disconnect_tunnel(self, btn: Gtk.Button, guest_port: int):
        btn.set_sensitive(False)

        def worker():
            return self.manager.unforward_port(self.sandbox_name, guest_port)

        def on_done(res):
            if self._closed:
                return
            ok, msg = res
            self.toast_overlay.add_toast(Adw.Toast.new(msg))
            if ok:
                self._refresh_active_tunnels()
                if self.on_forwarded:
                    self.on_forwarded()
            else:
                btn.set_sensitive(True)

        run_async(worker, on_success=on_done)

    def _set_preset(self, port: int):
        self._user_edited_host_port = False
        self.guest_entry.set_text(str(port))
        self._update_free_host_port(port)

    def _on_host_port_changed(self, entry):
        if entry.has_focus():
            self._user_edited_host_port = True

    def _on_guest_port_changed(self, entry):
        text = entry.get_text().strip()
        if text.isdigit() and not getattr(self, "_user_edited_host_port", False):
            self._update_free_host_port(int(text))

    def _update_free_host_port(self, guest_port: int):
        used = self.manager._collect_used_host_ports()
        free_port = find_free_port(guest_port, avoid=used)
        self.host_entry.set_text(str(free_port))

    def _set_error(self, msg: str):
        self.status_label.set_text(msg)
        self.error_banner.set_title(msg)
        self.error_banner.set_revealed(bool(msg))

    def _on_forward_clicked(self, _btn):
        guest_text = self.guest_entry.get_text().strip()
        host_text = self.host_entry.get_text().strip()

        if not guest_text.isdigit() or not host_text.isdigit():
            self._set_error("Please enter valid numeric port numbers.")
            return

        guest_port = int(guest_text)
        host_port = int(host_text)
        if not (1 <= guest_port <= 65535 and 1 <= host_port <= 65535):
            self._set_error("Port numbers must be between 1 and 65535.")
            return

        self.forward_btn.set_sensitive(False)
        self._set_error("")

        def worker():
            return self.manager.forward_port(
                self.sandbox_name,
                guest_port=guest_port,
                host_port=host_port,
            )

        def on_done(result):
            if self._closed:
                return
            ok, msg, _mapping = result
            if ok:
                if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
                    self.parent_window.toast_overlay.add_toast(Adw.Toast.new(msg))
                if self.on_forwarded:
                    self.on_forwarded()
                self.close()
            else:
                self.forward_btn.set_sensitive(True)
                self._set_error(msg)

        def on_err(exc):
            if self._closed:
                return
            self.forward_btn.set_sensitive(True)
            self._set_error(str(exc))

        run_async(worker, on_success=on_done, on_error=on_err)
