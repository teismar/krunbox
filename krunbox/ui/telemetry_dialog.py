"""
Native Libadwaita AI API Telemetry & Audit dialog.
"""

from datetime import datetime
from typing import Optional
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from ..core.manager import SandboxManager
from .worker import run_async


class TelemetryDialog(Adw.Window):
    def __init__(
        self,
        parent_window: Gtk.Window,
        manager: SandboxManager,
        sandbox_name: Optional[str] = None,
    ):
        super().__init__(modal=True, transient_for=parent_window)
        title = f"AI API Telemetry - {sandbox_name}" if sandbox_name else "AI API Telemetry"
        self.set_title(title)
        self.set_default_size(760, 560)
        self.manager = manager
        self.sandbox_name = sandbox_name
        self._closed = False

        toolbar_view = Adw.ToolbarView()
        self.set_content(toolbar_view)

        header = Adw.HeaderBar()
        toolbar_view.add_top_bar(header)

        # Coming Soon Banner (remove when feature is ready)
        self.banner = Adw.Banner(title="Coming Soon: AI API Telemetry is currently under development.")
        self.banner.set_revealed(True)
        toolbar_view.add_top_bar(self.banner)

        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        refresh_btn.set_tooltip_text("Refresh Telemetry")
        refresh_btn.connect("clicked", lambda _: self.load_data())
        header.pack_start(refresh_btn)

        self.content_stack = Gtk.Stack()
        self.content_stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.content_stack.set_vexpand(True)
        toolbar_view.set_content(self.content_stack)

        self.empty_page = Adw.StatusPage(
            icon_name="utilities-system-monitor-symbolic",
            title="No AI API Telemetry Recorded",
            description="Model invocations, token counts, latency, and estimated spend will appear here once recorded.",
        )
        self.content_stack.add_named(self.empty_page, "empty")

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)

        clamp = Adw.Clamp(maximum_size=780, tightening_threshold=580)
        scrolled.set_child(clamp)

        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.main_box.set_margin_top(16)
        self.main_box.set_margin_bottom(24)
        self.main_box.set_margin_start(16)
        self.main_box.set_margin_end(16)
        clamp.set_child(self.main_box)

        self.summary_box = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=12,
            homogeneous=True,
        )
        self.main_box.append(self.summary_box)

        self.invocations_group = Adw.PreferencesGroup(title="Requests by Provider")
        self.main_box.append(self.invocations_group)

        self.calls_group = Adw.PreferencesGroup(title="Recent Invocations")
        self.main_box.append(self.calls_group)

        self.content_stack.add_named(scrolled, "populated")

        self._provider_rows = []
        self._call_rows = []

        self.connect("close-request", self._on_close_request)
        self.load_data()

    def _on_close_request(self, *_args):
        self._closed = True
        return False

    def load_data(self):
        def worker():
            try:
                telem = getattr(self.manager, "telemetry", None)
                if telem is None:
                    return {}, []
                summary = telem.get_summary(self.sandbox_name) if hasattr(telem, "get_summary") else {}
                calls = telem.get_calls(self.sandbox_name, limit=30) if hasattr(telem, "get_calls") else []
                return summary or {}, calls or []
            except Exception:
                return {}, []

        def on_done(result):
            if self._closed:
                return
            summary, calls = result
            if not isinstance(summary, dict):
                summary = {}
            if not isinstance(calls, list):
                calls = []

            while child := self.summary_box.get_first_child():
                self.summary_box.remove(child)

            for r in self._provider_rows:
                self.invocations_group.remove(r)
            self._provider_rows.clear()

            for r in self._call_rows:
                self.calls_group.remove(r)
            self._call_rows.clear()

            if summary.get("total_calls", 0) == 0 and not calls:
                self.content_stack.set_visible_child_name("empty")
                return

            self.content_stack.set_visible_child_name("populated")

            metrics = [
                ("Total Calls", f"{summary['total_calls']:,}"),
                ("Total Tokens", f"{summary['total_tokens']:,}"),
                ("Est. Spend", f"${summary['estimated_cost_usd']:.4f}"),
                ("Success Rate", f"{summary['success_rate']}%"),
            ]
            for label, val in metrics:
                card = Gtk.Frame()
                card.add_css_class("card")
                c_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
                c_box.set_margin_top(12)
                c_box.set_margin_bottom(12)
                c_box.set_margin_start(14)
                c_box.set_margin_end(14)
                card.set_child(c_box)

                l_widget = Gtk.Label(label=label, halign=Gtk.Align.START)
                l_widget.add_css_class("caption")
                l_widget.add_css_class("dim-label")
                c_box.append(l_widget)

                v_widget = Gtk.Label(label=val, halign=Gtk.Align.START)
                v_widget.add_css_class("title-2")
                v_widget.add_css_class("numeric")
                c_box.append(v_widget)
                self.summary_box.append(card)

            by_provider = summary.get("by_provider", {})
            self.invocations_group.set_visible(bool(by_provider))
            for prov, cnt in by_provider.items():
                row = Adw.ActionRow(
                    title=GLib.markup_escape_text(str(prov)),
                    subtitle=GLib.markup_escape_text(f"{cnt} request{'s' if cnt != 1 else ''} logged"),
                )
                self.invocations_group.add(row)
                self._provider_rows.append(row)

            for c in calls:
                t_str = datetime.fromtimestamp(c.timestamp).strftime("%H:%M:%S")
                title_str = f"{c.provider} · {c.model or c.endpoint}"
                sub_str = f"{t_str} · {c.total_tokens:,} tokens · {c.latency_ms:.0f} ms"
                row = Adw.ActionRow(
                    title=GLib.markup_escape_text(title_str),
                    subtitle=GLib.markup_escape_text(sub_str),
                )
                status_lbl = Gtk.Label(label=str(c.status_code), valign=Gtk.Align.CENTER)
                status_lbl.add_css_class("caption-heading")
                status_lbl.add_css_class("numeric")
                status_lbl.add_css_class("success" if c.status_code < 400 else "error")
                row.add_suffix(status_lbl)
                self.calls_group.add(row)
                self._call_rows.append(row)

        run_async(worker, on_success=on_done)
