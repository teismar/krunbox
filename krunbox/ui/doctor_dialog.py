"""
System Diagnostics & Host Health dialog in GTK4 / Libadwaita.
"""

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from ..core.doctor import Doctor
from .worker import run_async

SUBSYSTEM_ICONS = {
    "Hardware Virtualization (/dev/kvm)": "computer-symbolic",
    "crun-krun MicroVM Runtime": "utilities-terminal-symbolic",
    "passt (MicroVM Network Virtualization)": "network-wired-symbolic",
    "Podman Engine": "package-x-generic-symbolic",
    "Rootless SubUID Mappings": "system-users-symbolic",
    "Network Tunnel Device (/dev/net/tun)": "network-wired-symbolic",
    "FUSE Filesystem Device (/dev/fuse)": "drive-harddisk-symbolic",
    "GTK4 and Libadwaita Desktop Stack": "preferences-desktop-display-symbolic",
    "OpenSSH Client Tooling": "dialog-password-symbolic",
}


def _resolve_subsystem_icon(component: str) -> str:
    if component in SUBSYSTEM_ICONS:
        return SUBSYSTEM_ICONS[component]
    if "/dev/net/tun" in component:
        return "network-wired-symbolic"
    if "/dev/fuse" in component:
        return "drive-harddisk-symbolic"
    return "emblem-system-symbolic"


class DoctorDialog(Adw.Window):
    def __init__(self, parent_window: Gtk.Window):
        super().__init__(modal=True, transient_for=parent_window)
        self.set_title("System Diagnostics & Host Health")
        self.set_default_size(660, 580)
        self._closed = False

        toolbar_view = Adw.ToolbarView()
        self.set_content(toolbar_view)

        header = Adw.HeaderBar()
        toolbar_view.add_top_bar(header)

        self.refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        self.refresh_btn.set_tooltip_text("Re-run Diagnostics")
        self.refresh_btn.connect("clicked", lambda _: self._run_diagnostics())
        header.pack_start(self.refresh_btn)

        self.banner = Adw.Banner()
        toolbar_view.add_top_bar(self.banner)

        page = Adw.PreferencesPage()
        toolbar_view.set_content(page)

        self.pref_group = Adw.PreferencesGroup(
            title="Host Subsystem Checks",
            description="Hardware virtualization, microVM runtime, device permissions, and networking on Linux.",
        )
        page.add(self.pref_group)
        self._check_rows = []

        self.connect("close-request", self._on_close_request)
        self._run_diagnostics()

    def _on_close_request(self, *_args):
        self._closed = True
        return False

    def _run_diagnostics(self):
        self.refresh_btn.set_sensitive(False)

        def worker():
            doc = Doctor()
            return doc.check_all()

        def on_done(checks):
            if self._closed:
                return
            self.refresh_btn.set_sensitive(True)
            for r in self._check_rows:
                self.pref_group.remove(r)
            self._check_rows.clear()

            fails = sum(1 for c in checks if c["status"] == "fail")
            warns = sum(1 for c in checks if c["status"] == "warn")

            if fails > 0:
                self.banner.set_title(
                    f"{fails} critical subsystem failure{'s' if fails > 1 else ''} detected. MicroVM execution may fail."
                )
                self.banner.set_revealed(True)
            elif warns > 0:
                self.banner.set_title(
                    f"Host operational with {warns} warning{'s' if warns > 1 else ''}. Standard fallbacks active."
                )
                self.banner.set_revealed(True)
            else:
                self.banner.set_title("All host virtualization and container subsystems operational.")
                self.banner.set_revealed(True)

            for c in checks:
                escaped_title = GLib.markup_escape_text(c["component"])
                escaped_msg = GLib.markup_escape_text(c["message"])
                remediation = c.get("remediation", "")

                if c["status"] != "ok" and remediation:
                    escaped_fix = GLib.markup_escape_text(remediation)
                    subtitle_markup = f"{escaped_msg}\nFix: <tt>{escaped_fix}</tt>"
                else:
                    subtitle_markup = escaped_msg

                row = Adw.ActionRow(
                    title=escaped_title,
                    subtitle=subtitle_markup,
                )
                row.set_subtitle_lines(0)
                if c["status"] != "ok" and remediation:
                    row.set_subtitle_selectable(True)
                    row.set_tooltip_text(f"Remediation: {remediation}")

                icon_name = _resolve_subsystem_icon(c["component"])
                p_img = Gtk.Image.new_from_icon_name(icon_name)
                p_img.add_css_class("dim-label")
                row.add_prefix(p_img)

                status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                status_box.set_valign(Gtk.Align.CENTER)

                if c["status"] == "ok":
                    s_icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
                    s_icon.add_css_class("success")
                    s_lbl = Gtk.Label(label="Passed")
                    s_lbl.add_css_class("success")
                elif c["status"] == "warn":
                    s_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
                    s_icon.add_css_class("warning")
                    s_lbl = Gtk.Label(label="Warning")
                    s_lbl.add_css_class("warning")
                else:
                    s_icon = Gtk.Image.new_from_icon_name("dialog-error-symbolic")
                    s_icon.add_css_class("error")
                    s_lbl = Gtk.Label(label="Failed")
                    s_lbl.add_css_class("error")

                s_icon.set_pixel_size(16)
                s_lbl.add_css_class("caption-heading")

                status_box.append(s_icon)
                status_box.append(s_lbl)
                row.add_suffix(status_box)

                self.pref_group.add(row)
                self._check_rows.append(row)

        run_async(worker, on_success=on_done)
