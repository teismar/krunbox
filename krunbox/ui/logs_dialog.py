"""
Container log viewer dialog in GTK4 / Libadwaita with clipboard export.
"""

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw

from ..core.manager import SandboxManager
from .worker import run_async


class LogsDialog(Adw.Window):
    def __init__(self, parent_window: Gtk.Window, manager: SandboxManager, sandbox_name: str):
        super().__init__(modal=True, transient_for=parent_window)
        self.set_title(f"Logs: {sandbox_name}")
        self.set_default_size(720, 500)
        self.manager = manager
        self.sandbox_name = sandbox_name
        self._closed = False

        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        toolbar_view = Adw.ToolbarView()
        self.toast_overlay.set_child(toolbar_view)

        header = Adw.HeaderBar()
        toolbar_view.add_top_bar(header)

        self.refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        self.refresh_btn.set_tooltip_text("Refresh Logs")
        self.refresh_btn.connect("clicked", lambda _: self.refresh_logs())
        header.pack_start(self.refresh_btn)

        self.copy_btn = Gtk.Button(icon_name="edit-copy-symbolic")
        self.copy_btn.set_tooltip_text("Copy Logs")
        self.copy_btn.connect("clicked", self._on_copy_clicked)
        header.pack_end(self.copy_btn)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        toolbar_view.set_content(scrolled)

        self.text_view = Gtk.TextView()
        self.text_view.set_editable(False)
        self.text_view.set_monospace(True)
        self.text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.text_view.set_margin_top(12)
        self.text_view.set_margin_bottom(12)
        self.text_view.set_margin_start(12)
        self.text_view.set_margin_end(12)
        self.buffer = self.text_view.get_buffer()
        scrolled.set_child(self.text_view)

        self.connect("close-request", self._on_close_request)
        self.refresh_logs()

    def _on_close_request(self, *_args):
        self._closed = True
        return False

    def _on_copy_clicked(self, _btn):
        start_iter = self.buffer.get_start_iter()
        end_iter = self.buffer.get_end_iter()
        text = self.buffer.get_text(start_iter, end_iter, False)
        try:
            display = self.get_display()
            if display:
                display.get_clipboard().set(text)
            self.toast_overlay.add_toast(Adw.Toast.new("Logs copied to clipboard"))
        except Exception:
            self.toast_overlay.add_toast(Adw.Toast.new("Unable to access clipboard"))

    def refresh_logs(self):
        def worker():
            return self.manager.get_logs(self.sandbox_name, tail=250)

        def on_done(logs: str):
            if self._closed:
                return
            self.buffer.set_text(
                logs if logs.strip() else "[No container execution logs available yet]"
            )
            mark = self.buffer.get_insert()
            self.text_view.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)

        run_async(worker, on_success=on_done)
