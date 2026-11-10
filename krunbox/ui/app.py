"""
Native Libadwaita application entrypoint for krunbox.
"""

import sys
from pathlib import Path
from typing import List, Optional
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, Gdk

from .window import KrunboxWindow
from ..core.settings import load_settings


class KrunboxApplication(Adw.Application):
    def __init__(self, application_id: Optional[str] = "io.krunbox.Krunbox"):
        super().__init__(
            application_id=application_id,
            flags=Gio.ApplicationFlags.NON_UNIQUE | Gio.ApplicationFlags.HANDLES_OPEN,
        )
        self._setup_actions()

    def _setup_actions(self):
        new_action = Gio.SimpleAction.new("new-sandbox", None)
        new_action.connect("activate", self._on_new_sandbox_action)
        self.add_action(new_action)
        self.set_accels_for_action("app.new-sandbox", ["<Primary>n"])

        prefs_action = Gio.SimpleAction.new("preferences", None)
        prefs_action.connect("activate", self._on_preferences_action)
        self.add_action(prefs_action)
        self.set_accels_for_action("app.preferences", ["<Primary>comma"])

        refresh_action = Gio.SimpleAction.new("refresh", None)
        refresh_action.connect("activate", self._on_refresh_action)
        self.add_action(refresh_action)
        self.set_accels_for_action("app.refresh", ["<Primary>r"])

        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", self._on_quit_action)
        self.add_action(quit_action)
        self.set_accels_for_action("app.quit", ["<Primary>q"])

    def _on_new_sandbox_action(self, _action, _param):
        win = self.props.active_window
        if isinstance(win, KrunboxWindow):
            win._on_new_clicked(None)

    def _on_preferences_action(self, _action, _param):
        win = self.props.active_window
        if isinstance(win, KrunboxWindow):
            win._on_settings_clicked(None)

    def _on_refresh_action(self, _action, _param):
        win = self.props.active_window
        if isinstance(win, KrunboxWindow):
            win.refresh()

    def _on_quit_action(self, _action, _param):
        self.quit()

    def do_open(self, files, n_files, hint):
        self.activate()

    def do_activate(self):
        display = Gdk.Display.get_default()
        if display:
            icon_theme = Gtk.IconTheme.get_for_display(display)
            icons_dir = Path(__file__).parent.parent / "data" / "icons"
            if icons_dir.exists():
                icon_theme.add_search_path(str(icons_dir))
                for sz_dir in icons_dir.glob("*x*"):
                    if sz_dir.is_dir():
                        icon_theme.add_search_path(str(sz_dir))

        Gtk.Window.set_default_icon_name("io.krunbox.Krunbox")

        user_desktop = Path.home() / ".local" / "share" / "applications" / "io.krunbox.Krunbox.desktop"
        if not user_desktop.exists():
            from ..core.desktop import install_desktop_integration
            try:
                install_desktop_integration(system=False)
            except Exception:
                pass

        settings = load_settings()
        theme = settings.get("color_scheme", "system")
        style_mgr = Adw.StyleManager.get_default()
        if theme == "light":
            style_mgr.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
        elif theme == "dark":
            style_mgr.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
        else:
            style_mgr.set_color_scheme(Adw.ColorScheme.DEFAULT)

        win = self.props.active_window
        if not win:
            win = KrunboxWindow(self)
        win.present()


def run_app(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        clean_args = [sys.argv[0]]
        for arg in sys.argv[1:]:
            if arg.startswith("-") or arg.startswith("--"):
                clean_args.append(arg)
        argv = clean_args
    app = KrunboxApplication()
    return app.run(argv)


if __name__ == "__main__":
    sys.exit(run_app())
