"""
MCP Agent Permission Requests Sidepanel for krunbox.

Provides a dedicated sidebar to inspect, filter, and approve or deny
real-time agent requests for outbound domain access and port exposure.
"""

import time
from typing import Callable, List, Optional
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from ..core.ipc_server import AccessRequest
from ..core.manager import SandboxManager
from .worker import run_async


def _format_relative_time(ts: float) -> str:
    """Format timestamp into a concise human relative time ('just now', '5m ago')."""
    diff = max(0.0, time.time() - ts)
    if diff < 10:
        return "just now"
    if diff < 60:
        return f"{int(diff)}s ago"
    mins = int(diff // 60)
    if mins < 60:
        return f"{mins}m ago"
    hours = int(mins // 60)
    if hours < 24:
        return f"{hours}h ago"
    days = int(hours // 24)
    return f"{days}d ago"


class McpRequestCard(Gtk.Box):
    """Card widget rendering a single AccessRequest with inline Allow/Deny controls."""

    def __init__(
        self,
        request: AccessRequest,
        on_approve: Callable[[AccessRequest], None],
        on_deny: Callable[[AccessRequest, str], None],
        parent_window=None,
    ):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.request = request
        self.on_approve = on_approve
        self.on_deny = on_deny
        self.parent_window = parent_window

        self.add_css_class("card")
        self.set_margin_start(10)
        self.set_margin_end(10)
        self.set_margin_top(4)
        self.set_margin_bottom(6)

        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        inner.set_margin_start(12)
        inner.set_margin_end(12)
        inner.set_margin_top(10)
        inner.set_margin_bottom(10)
        self.append(inner)

        # Header: Icon + Target Name + Status Badge
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        inner.append(header_box)

        icon_name = (
            "network-server-symbolic"
            if request.request_type == "port"
            else "web-browser-symbolic"
        )
        type_icon = Gtk.Image.new_from_icon_name(icon_name)
        type_icon.set_pixel_size(18)
        header_box.append(type_icon)

        title_label = Gtk.Label()
        target_display = (
            f"Port {request.target}"
            if request.request_type == "port"
            else request.target
        )
        title_label.set_markup(f"<b>{GLib.markup_escape_text(target_display)}</b>")
        title_label.set_halign(Gtk.Align.START)
        title_label.set_hexpand(True)
        title_label.set_ellipsize(3)  # PANGO_ELLIPSIZE_END
        header_box.append(title_label)

        status_badge = Gtk.Label()
        status_badge.add_css_class("caption")
        status_badge.add_css_class("numeric")
        st = (request.status or "pending").lower()
        if st == "approved":
            status_badge.set_text("Approved")
            status_badge.add_css_class("success")
        elif st in ("denied", "rejected"):
            status_badge.set_text("Denied")
            status_badge.add_css_class("error")
        else:
            status_badge.set_text("Pending")
            status_badge.add_css_class("warning")
        header_box.append(status_badge)

        # Subtitle: Sandbox name · Relative timestamp
        sub_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        inner.append(sub_box)

        box_label = Gtk.Label(label=request.sandbox_name)
        box_label.add_css_class("caption")
        box_label.add_css_class("dim-label")
        box_label.set_halign(Gtk.Align.START)
        sub_box.append(box_label)

        sep = Gtk.Label(label="·")
        sep.add_css_class("caption")
        sep.add_css_class("dim-label")
        sub_box.append(sep)

        time_label = Gtk.Label(label=_format_relative_time(request.timestamp))
        time_label.add_css_class("caption")
        time_label.add_css_class("dim-label")
        time_label.set_halign(Gtk.Align.START)
        sub_box.append(time_label)

        # Reason provided by the agent
        if request.reason:
            reason_label = Gtk.Label(label=f"“{request.reason}”")
            reason_label.set_wrap(True)
            reason_label.set_xalign(0.0)
            reason_label.add_css_class("caption")
            inner.append(reason_label)

        # Result Details if decision already made
        if st == "approved" and request.assigned_host_port:
            port_info = Gtk.Label(
                label=f"Forwarded on host port: {request.assigned_host_port}"
            )
            port_info.add_css_class("caption")
            port_info.add_css_class("dim-label")
            port_info.set_halign(Gtk.Align.START)
            inner.append(port_info)
        elif st in ("denied", "rejected") and request.decision_reason:
            denial_info = Gtk.Label(label=f"Reason: {request.decision_reason}")
            denial_info.add_css_class("caption")
            denial_info.add_css_class("dim-label")
            denial_info.set_halign(Gtk.Align.START)
            inner.append(denial_info)

        # Action Buttons (only for pending status)
        if st == "pending":
            actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            actions_row.set_margin_top(4)
            inner.append(actions_row)

            self.allow_btn = Gtk.Button()
            allow_content = Adw.ButtonContent(
                icon_name="emblem-ok-symbolic",
                label="Allow",
            )
            self.allow_btn.set_child(allow_content)
            self.allow_btn.add_css_class("suggested-action")
            self.allow_btn.set_hexpand(True)
            self.allow_btn.connect("clicked", self._on_allow_clicked)
            actions_row.append(self.allow_btn)

            self.deny_btn = Gtk.Button()
            deny_content = Adw.ButtonContent(
                icon_name="process-stop-symbolic",
                label="Deny",
            )
            self.deny_btn.set_child(deny_content)
            self.deny_btn.add_css_class("destructive-action")
            self.deny_btn.set_hexpand(True)
            self.deny_btn.connect("clicked", self._on_deny_clicked)
            actions_row.append(self.deny_btn)

    def _on_allow_clicked(self, _btn):
        self.allow_btn.set_sensitive(False)
        self.deny_btn.set_sensitive(False)
        self.on_approve(self.request)

    def _on_deny_clicked(self, _btn):
        self.allow_btn.set_sensitive(False)
        self.deny_btn.set_sensitive(False)
        self.on_deny(self.request, "Denied by operator in UI")


class McpRequestsSidepanel(Gtk.Box):
    """
    Sidepanel for inspecting, filtering, and handling agent MCP permission requests.
    Supports sandbox filtering, type filtering (domain vs port), and status filtering.
    """

    def __init__(
        self,
        manager: SandboxManager,
        on_request_handled: Optional[Callable[[], None]] = None,
        on_close_requested: Optional[Callable[[], None]] = None,
        parent_window=None,
    ):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.manager = manager
        self.on_request_handled = on_request_handled
        self.on_close_requested = on_close_requested
        self.parent_window = parent_window

        self.set_size_request(340, -1)
        self.add_css_class("background")

        self._filter_sandbox = "all"
        self._filter_type = "all"
        self._filter_status = "pending"
        self._search_text = ""
        self._filtered_requests: List[AccessRequest] = []
        self._cached_requests: List[AccessRequest] = []
        self._known_sandboxes: List[str] = []

        # Top Header Bar
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(False)
        header.set_show_start_title_buttons(False)
        self.append(header)

        title_widget = Adw.WindowTitle(
            title="Agent Requests",
            subtitle="Human-in-the-Loop MCP",
        )
        header.set_title_widget(title_widget)

        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        refresh_btn.set_tooltip_text("Refresh Requests")
        refresh_btn.connect("clicked", lambda _: self.reload_requests())
        header.pack_start(refresh_btn)

        self.refresh_btn = refresh_btn

        self.help_btn = Gtk.Button(icon_name="help-browser-symbolic")
        self.help_btn.set_tooltip_text("MCP Setup Guide: How to connect any AI tool")
        self.help_btn.connect("clicked", self._on_open_setup_guide)
        header.pack_start(self.help_btn)

        self.close_btn = None
        if self.on_close_requested:
            self.close_btn = Gtk.Button(icon_name="window-close-symbolic")
            self.close_btn.set_tooltip_text("Close Panel")
            self.close_btn.connect("clicked", lambda _: self.on_close_requested())
            header.pack_end(self.close_btn)

        # Filters Area
        filter_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        filter_box.set_margin_start(10)
        filter_box.set_margin_end(10)
        filter_box.set_margin_top(8)
        filter_box.set_margin_bottom(8)
        self.append(filter_box)

        # Search Entry
        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Filter by domain or port…")
        self.search_entry.connect("search-changed", self._on_search_changed)
        filter_box.append(self.search_entry)

        # Controls Row: Sandbox Dropdown + Type Filter
        row1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        filter_box.append(row1)

        # Sandbox dropdown
        self.sandbox_dropdown = Gtk.DropDown.new_from_strings(["All Sandboxes"])
        self.sandbox_dropdown.set_hexpand(True)
        self.sandbox_dropdown.set_tooltip_text("Filter by sandbox")
        self.sandbox_dropdown.connect("notify::selected", self._on_sandbox_selected)
        row1.append(self.sandbox_dropdown)

        # Request Type dropdown
        self.type_dropdown = Gtk.DropDown.new_from_strings(
            ["All Types", "Domain Access", "Port Exposure"]
        )
        self.type_dropdown.set_tooltip_text("Filter by request type")
        self.type_dropdown.connect("notify::selected", self._on_type_selected)
        row1.append(self.type_dropdown)

        # Status Filter Row (Segmented style buttons: Pending / Approved / Denied / All)
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        status_box.add_css_class("linked")
        filter_box.append(status_box)

        self._status_buttons = {}
        for st_key, st_label in [
            ("pending", "Pending"),
            ("approved", "Approved"),
            ("denied", "Denied"),
            ("all", "All"),
        ]:
            btn = Gtk.ToggleButton(label=st_label)
            btn.set_hexpand(True)
            if st_key == "pending":
                btn.set_active(True)
            btn.connect("toggled", self._make_status_callback(st_key))
            status_box.append(btn)
            self._status_buttons[st_key] = btn

        # Batch Action Bar (Approve All / Deny All)
        self.batch_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.batch_bar.set_margin_start(10)
        self.batch_bar.set_margin_end(10)
        self.batch_bar.set_margin_bottom(6)
        self.append(self.batch_bar)

        self.approve_all_btn = Gtk.Button(label="Approve All Pending")
        self.approve_all_btn.add_css_class("suggested-action")
        self.approve_all_btn.set_hexpand(True)
        self.approve_all_btn.connect("clicked", self._on_approve_all_clicked)
        self.batch_bar.append(self.approve_all_btn)

        self.deny_all_btn = Gtk.Button(label="Deny All")
        self.deny_all_btn.add_css_class("destructive-action")
        self.deny_all_btn.set_hexpand(True)
        self.deny_all_btn.connect("clicked", self._on_deny_all_clicked)
        self.batch_bar.append(self.deny_all_btn)

        # Scrolled Stack for Requests
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_vexpand(True)
        self.append(self.stack)

        # Empty State
        empty_page = Adw.StatusPage(
            icon_name="security-high-symbolic",
            title="No Permission Requests",
            description="When AI agents inside microVMs request dynamic outbound internet domains or host port exposures, they appear here.",
        )
        empty_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        empty_box.set_halign(Gtk.Align.CENTER)
        self.empty_guide_btn = Gtk.Button()
        self.empty_guide_btn.set_child(
            Adw.ButtonContent(
                icon_name="help-browser-symbolic",
                label="How to Add MCP to AI Tools",
            )
        )
        self.empty_guide_btn.add_css_class("pill")
        self.empty_guide_btn.add_css_class("suggested-action")
        self.empty_guide_btn.connect("clicked", self._on_open_setup_guide)
        empty_box.append(self.empty_guide_btn)
        empty_page.set_child(empty_box)
        self.stack.add_named(empty_page, "empty")

        # No Results State
        no_results_page = Adw.StatusPage(
            icon_name="system-search-symbolic",
            title="No Matching Requests",
            description="Try adjusting your sandbox, type, or status filter.",
        )
        self.stack.add_named(no_results_page, "no-results")

        # List State
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        scrolled.set_child(self.list_box)
        self.stack.add_named(scrolled, "list")

        # Bottom Permanent Setup Guide Action Bar
        bottom_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        bottom_bar.set_margin_start(10)
        bottom_bar.set_margin_end(10)
        bottom_bar.set_margin_top(6)
        bottom_bar.set_margin_bottom(10)
        self.append(bottom_bar)

        self.guide_banner_btn = Gtk.Button()
        self.guide_banner_btn.set_child(
            Adw.ButtonContent(
                icon_name="dialog-information-symbolic",
                label="MCP Integration Guide",
            )
        )
        self.guide_banner_btn.add_css_class("flat")
        self.guide_banner_btn.set_hexpand(True)
        self.guide_banner_btn.set_tooltip_text(
            "Instructions to connect krunbox-gateway to any AI agent (Antigravity, Claude, Cursor, Cline, etc.)"
        )
        self.guide_banner_btn.connect("clicked", self._on_open_setup_guide)
        bottom_bar.append(self.guide_banner_btn)

        self.reload_requests()

    def _on_open_setup_guide(self, _btn=None):
        """Open the In-Sandbox MCP Integration & Setup Guide modal dialog."""
        from .mcp_guide_dialog import McpGuideDialog
        dialog = McpGuideDialog(parent_window=self.parent_window)
        dialog.present()

    def _make_status_callback(self, key: str):
        def cb(btn):
            if btn.get_active():
                for k, b in self._status_buttons.items():
                    if k != key and b.get_active():
                        b.set_active(False)
                self._filter_status = key
                self._render_list()

        return cb

    def _on_search_changed(self, entry):
        self._search_text = entry.get_text().strip().lower()
        self._render_list()

    def _on_sandbox_selected(self, dropdown, _param):
        idx = dropdown.get_selected()
        if idx == 0 or idx >= len(self._known_sandboxes) + 1:
            self._filter_sandbox = "all"
        else:
            self._filter_sandbox = self._known_sandboxes[idx - 1]
        self._render_list()

    def _on_type_selected(self, dropdown, _param):
        idx = dropdown.get_selected()
        types = ["all", "domain", "port"]
        self._filter_type = types[idx] if idx < len(types) else "all"
        self._render_list()

    def reload_requests(self):
        """Fetch all requests from the manager in a background thread."""

        def worker():
            if hasattr(self.manager, "list_all_requests"):
                reqs = self.manager.list_all_requests()
            elif hasattr(self.manager, "ipc_server") and self.manager.ipc_server is not None:
                reqs = self.manager.ipc_server.get_all_requests()
            elif hasattr(self.manager, "list_pending_requests"):
                reqs = self.manager.list_pending_requests()
            else:
                reqs = []

            # Also discover known sandboxes from manager and requests
            sandboxes = self.manager.list_sandboxes(refresh_podman=False)
            names = sorted({s.name for s in sandboxes} | {r.sandbox_name for r in reqs if getattr(r, "sandbox_name", "")})
            return reqs, names

        def on_done(payload):
            reqs, names = payload
            self._cached_requests = sorted(
                reqs, key=lambda r: getattr(r, "timestamp", 0), reverse=True
            )
            self._update_sandbox_dropdown(names)
            self._render_list()

        run_async(worker, on_success=on_done)

    def _update_sandbox_dropdown(self, names: List[str]):
        if names != self._known_sandboxes:
            self._known_sandboxes = names
            strings = ["All Sandboxes"] + names
            model = Gtk.StringList.new(strings)
            self.sandbox_dropdown.set_model(model)
            if self._filter_sandbox in names:
                self.sandbox_dropdown.set_selected(names.index(self._filter_sandbox) + 1)
            else:
                self.sandbox_dropdown.set_selected(0)
                self._filter_sandbox = "all"

    def _render_list(self):
        if not hasattr(self, "batch_bar") or not hasattr(self, "stack") or not hasattr(self, "list_box"):
            return
        filtered = []
        pending_count = 0

        for r in self._cached_requests:
            st = (r.status or "pending").lower()
            if st == "pending":
                pending_count += 1

            # Filter by status
            if self._filter_status != "all":
                if self._filter_status == "pending" and st != "pending":
                    continue
                if self._filter_status == "approved" and st != "approved":
                    continue
                if self._filter_status in ("denied", "rejected") and st not in (
                    "denied",
                    "rejected",
                ):
                    continue

            # Filter by sandbox
            if self._filter_sandbox != "all" and r.sandbox_name != self._filter_sandbox:
                continue

            # Filter by type
            if self._filter_type != "all" and r.request_type != self._filter_type:
                continue

            # Search text filter
            if self._search_text:
                target = (r.target or "").lower()
                reason = (r.reason or "").lower()
                sname = (r.sandbox_name or "").lower()
                if (
                    self._search_text not in target
                    and self._search_text not in reason
                    and self._search_text not in sname
                ):
                    continue

            filtered.append(r)

        # Update batch actions bar visibility
        self._filtered_requests = filtered
        self.batch_bar.set_visible(pending_count > 0 and self._filter_status in ("pending", "all"))

        # Clear existing rows
        while True:
            child = self.list_box.get_first_child()
            if not child:
                break
            self.list_box.remove(child)

        if not self._cached_requests:
            self.stack.set_visible_child_name("empty")
            return

        if not filtered:
            self.stack.set_visible_child_name("no-results")
            return

        self.stack.set_visible_child_name("list")
        for req in filtered:
            card = McpRequestCard(
                req,
                on_approve=self._on_approve_request,
                on_deny=self._on_deny_request,
                parent_window=self.parent_window,
            )
            self.list_box.append(card)

    def _on_approve_request(self, req: AccessRequest):
        def worker():
            return self.manager.approve_access_request(req.id)

        def on_done(res):
            ok, msg = res
            if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
                self.parent_window.toast_overlay.add_toast(
                    Adw.Toast.new(msg if ok else f"Approval failed: {msg}")
                )
            self.reload_requests()
            if self.on_request_handled:
                self.on_request_handled()

        run_async(worker, on_success=on_done)

    def _on_deny_request(self, req: AccessRequest, reason: str):
        def worker():
            return self.manager.deny_access_request(req.id, reason)

        def on_done(res):
            ok, msg = res
            if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
                self.parent_window.toast_overlay.add_toast(
                    Adw.Toast.new(f"Denied: {req.target}")
                )
            self.reload_requests()
            if self.on_request_handled:
                self.on_request_handled()

        run_async(worker, on_success=on_done)

    def _on_approve_all_clicked(self, _btn):
        pending = [r for r in self._cached_requests if (r.status or "pending").lower() == "pending"]
        if not pending:
            return

        def worker():
            results = []
            for r in pending:
                ok, msg = self.manager.approve_access_request(r.id)
                results.append((ok, msg))
            return len(results)

        def on_done(count):
            if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
                self.parent_window.toast_overlay.add_toast(
                    Adw.Toast.new(f"Approved {count} agent requests")
                )
            self.reload_requests()
            if self.on_request_handled:
                self.on_request_handled()

        run_async(worker, on_success=on_done)

    def _on_deny_all_clicked(self, _btn):
        pending = [r for r in self._cached_requests if (r.status or "pending").lower() == "pending"]
        if not pending:
            return

        def worker():
            results = []
            for r in pending:
                ok, msg = self.manager.deny_access_request(r.id, "Denied by operator in UI")
                results.append((ok, msg))
            return len(results)

        def on_done(count):
            if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
                self.parent_window.toast_overlay.add_toast(
                    Adw.Toast.new(f"Denied {count} agent requests")
                )
            self.reload_requests()
            if self.on_request_handled:
                self.on_request_handled()

        run_async(worker, on_success=on_done)

    @property
    def status_filter(self) -> str:
        return self._filter_status

    def set_status_filter(self, st_key: str):
        if hasattr(self, "_status_buttons") and st_key in self._status_buttons:
            self._status_buttons[st_key].set_active(True)
