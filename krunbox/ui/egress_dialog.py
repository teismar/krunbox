"""
Egress Traffic Monitor dialog in GTK4 / Libadwaita for inspecting outbound domain calls,
call frequency, policy evaluation history, and 1-click live Allow/Block policy updates.
"""

from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple, Union
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib, Gio

from ..core.manager import SandboxManager
from ..core.sandbox import NetworkPolicy
from .worker import run_async


class EgressTrafficDialog(Adw.Window):
    def __init__(
        self,
        parent_window: Gtk.Window,
        manager: SandboxManager,
        sandbox_name: Optional[str] = None,
        on_policy_updated: Optional[Callable[[], None]] = None,
    ):
        super().__init__(modal=True, transient_for=parent_window)
        self.parent_window = parent_window
        self.manager = manager
        self.initial_sandbox_name = sandbox_name
        self.selected_sandbox: Optional[str] = sandbox_name
        self.on_policy_updated = on_policy_updated

        title = f"Egress Traffic - {sandbox_name}" if sandbox_name else "Egress Traffic Monitor"
        self.set_title(title)
        self.set_default_size(780, 620)

        self.filter_mode: str = "all"
        self.search_query: str = ""
        self.current_stats: Dict = self._empty_stats()
        self.current_events: List = []
        self._site_rows: List[Gtk.Widget] = []
        self._event_rows: List[Gtk.Widget] = []
        self._sandbox_names: List[str] = []
        self._closed: bool = False

        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        toolbar_view = Adw.ToolbarView()
        self.toast_overlay.set_child(toolbar_view)

        self.view_stack = Adw.ViewStack()

        header = Adw.HeaderBar()
        toolbar_view.add_top_bar(header)

        self.view_switcher = Adw.ViewSwitcher(
            stack=self.view_stack,
            policy=Adw.ViewSwitcherPolicy.WIDE,
        )
        header.set_title_widget(self.view_switcher)

        # Header Start: Refresh + Optional Global Sandbox Selector
        self.refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        self.refresh_btn.set_tooltip_text("Refresh Outbound Traffic")
        self.refresh_btn.connect("clicked", lambda _: self.load_data())
        header.pack_start(self.refresh_btn)

        self.sandbox_dropdown: Optional[Gtk.DropDown] = None
        if sandbox_name is None:
            self._sandbox_names = [b.name for b in self._safe_list_sandboxes()]
            labels = ["All Sandboxes"] + self._sandbox_names
            self.sandbox_model = Gtk.StringList.new(labels)
            self.sandbox_dropdown = Gtk.DropDown(model=self.sandbox_model)
            self.sandbox_dropdown.set_tooltip_text("Filter traffic by sandbox")
            self.sandbox_dropdown.set_selected(0)
            self.sandbox_dropdown.connect("notify::selected", self._on_sandbox_dropdown_changed)
            header.pack_start(self.sandbox_dropdown)

        # Header End: Clear History
        self.clear_btn = Gtk.Button(icon_name="user-trash-symbolic")
        self.clear_btn.add_css_class("flat")
        self.clear_btn.set_tooltip_text("Clear Recorded Traffic Logs")
        self.clear_btn.connect("clicked", self._on_clear_clicked)
        header.pack_end(self.clear_btn)

        toolbar_view.set_content(self.view_stack)

        # ------------------------------------------------------------------
        # Tab 1: Sites & Frequency
        # ------------------------------------------------------------------
        sites_scroll = Gtk.ScrolledWindow()
        sites_scroll.set_vexpand(True)

        sites_clamp = Adw.Clamp(maximum_size=820, tightening_threshold=600)
        sites_scroll.set_child(sites_clamp)

        sites_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        sites_vbox.set_margin_top(16)
        sites_vbox.set_margin_bottom(24)
        sites_vbox.set_margin_start(16)
        sites_vbox.set_margin_end(16)
        sites_clamp.set_child(sites_vbox)

        # Overview Metrics Row (4 equal-width .card frames)
        self.metrics_box = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=12,
            homogeneous=True,
        )
        sites_vbox.append(self.metrics_box)

        self.unique_sites_label = self._add_metric_card("Unique Sites")
        self.total_calls_label = self._add_metric_card("Total Calls")
        self.allowed_calls_label = self._add_metric_card("Allowed")
        self.blocked_calls_label = self._add_metric_card("Blocked")

        # Filter Toolbar
        filter_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        sites_vbox.append(filter_bar)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_hexpand(True)
        self.search_entry.set_placeholder_text("Search called domains or categories…")
        self.search_entry.connect("changed", self._on_search_changed)
        self.search_entry.connect("search-changed", self._on_search_changed)
        filter_bar.append(self.search_entry)

        filter_group_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        filter_group_box.add_css_class("linked")
        self.filter_all_btn = Gtk.ToggleButton(label="All", active=True)
        self.filter_allowed_btn = Gtk.ToggleButton(label="Allowed", group=self.filter_all_btn)
        self.filter_blocked_btn = Gtk.ToggleButton(label="Blocked", group=self.filter_all_btn)

        self.filter_all_btn.connect("toggled", self._on_filter_toggled, "all")
        self.filter_allowed_btn.connect("toggled", self._on_filter_toggled, "allowed")
        self.filter_blocked_btn.connect("toggled", self._on_filter_toggled, "blocked")

        filter_group_box.append(self.filter_all_btn)
        filter_group_box.append(self.filter_allowed_btn)
        filter_group_box.append(self.filter_blocked_btn)
        filter_bar.append(filter_group_box)

        self.export_btn = Gtk.Button()
        self.export_btn.set_child(Adw.ButtonContent(icon_name="document-save-symbolic", label="Export"))
        self.export_btn.set_tooltip_text("Export Sites & Frequency Data to File (.csv or .json)")
        self.export_btn.set_sensitive(False)
        self.export_btn.connect("clicked", self._on_export_clicked)
        filter_bar.append(self.export_btn)

        # Sites Content Stack
        self.sites_stack = Gtk.Stack()
        self.sites_stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.sites_stack.set_vexpand(True)
        sites_vbox.append(self.sites_stack)

        self.empty_sites_page = Adw.StatusPage(
            icon_name="network-transmit-receive-symbolic",
            title="No Outbound Site Calls Recorded",
            description="Outbound DNS and web requests made inside running sandboxes will appear here with call counts and policy status.",
        )
        self.sites_stack.add_named(self.empty_sites_page, "empty")

        self.no_match_sites_page = Adw.StatusPage(
            icon_name="system-search-symbolic",
            title="No Matching Domains",
            description="No recorded outbound sites match the current search or filter.",
        )
        self.sites_stack.add_named(self.no_match_sites_page, "no-match")

        self.sites_group = Adw.PreferencesGroup(
            title="Called Sites by Frequency",
            description="Domains ranked by total outbound call count",
        )
        self.sites_stack.add_named(self.sites_group, "populated")

        self.view_stack.add_titled_with_icon(
            sites_scroll,
            "sites",
            "Sites & Frequency",
            "network-server-symbolic",
        )

        # ------------------------------------------------------------------
        # Tab 2: Activity Stream
        # ------------------------------------------------------------------
        events_scroll = Gtk.ScrolledWindow()
        events_scroll.set_vexpand(True)

        events_clamp = Adw.Clamp(maximum_size=820, tightening_threshold=600)
        events_scroll.set_child(events_clamp)

        self.events_stack = Gtk.Stack()
        self.events_stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.events_stack.set_vexpand(True)
        events_clamp.set_child(self.events_stack)

        self.empty_events_page = Adw.StatusPage(
            icon_name="view-list-symbolic",
            title="No Outbound Activity Recorded",
            description="Recent outbound DNS queries and connection evaluations will appear here chronologically.",
        )
        self.events_stack.add_named(self.empty_events_page, "empty")

        events_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        events_vbox.set_margin_top(16)
        events_vbox.set_margin_bottom(24)
        events_vbox.set_margin_start(16)
        events_vbox.set_margin_end(16)

        self.events_group = Adw.PreferencesGroup(
            title="Recent Outbound Requests",
            description="Chronological log of outbound requests and policy decisions",
        )
        events_vbox.append(self.events_group)
        self.events_stack.add_named(events_vbox, "populated")

        self.view_stack.add_titled_with_icon(
            events_scroll,
            "events",
            "Activity Stream",
            "view-list-symbolic",
        )

        self.connect("close-request", self._on_close_request)
        self.load_data()

    @staticmethod
    def _empty_stats() -> Dict:
        return {
            "total_requests": 0,
            "unique_domains": 0,
            "allowed_requests": 0,
            "blocked_requests": 0,
            "by_category": {},
            "sites": [],
        }

    def _safe_list_sandboxes(self):
        try:
            return self.manager.list_sandboxes(refresh_podman=False)
        except Exception:
            return []

    def _add_metric_card(self, title: str) -> Gtk.Label:
        frame = Gtk.Frame()
        frame.add_css_class("card")

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        vbox.set_margin_top(12)
        vbox.set_margin_bottom(12)
        vbox.set_margin_start(14)
        vbox.set_margin_end(14)
        frame.set_child(vbox)

        title_lbl = Gtk.Label(label=title, halign=Gtk.Align.START)
        title_lbl.add_css_class("caption")
        title_lbl.add_css_class("dim-label")
        vbox.append(title_lbl)

        val_lbl = Gtk.Label(label="0", halign=Gtk.Align.START)
        val_lbl.add_css_class("title-2")
        val_lbl.add_css_class("numeric")
        vbox.append(val_lbl)

        self.metrics_box.append(frame)
        return val_lbl

    def _on_close_request(self, *_args):
        self._closed = True
        self._clear_site_rows()
        self._clear_event_rows()
        return False

    def _on_sandbox_dropdown_changed(self, dropdown: Gtk.DropDown, _param):
        idx = dropdown.get_selected()
        if idx == 0 or idx == Gtk.INVALID_LIST_POSITION:
            self.selected_sandbox = None
            self.set_title("Egress Traffic Monitor")
        elif 1 <= idx <= len(self._sandbox_names):
            self.selected_sandbox = self._sandbox_names[idx - 1]
            self.set_title(f"Egress Traffic - {self.selected_sandbox}")
        self.load_data()

    def _on_search_changed(self, entry: Gtk.SearchEntry):
        new_query = entry.get_text().strip().lower()
        if new_query == self.search_query:
            return
        self.search_query = new_query
        self._render_sites()

    def _on_filter_toggled(self, btn: Gtk.ToggleButton, mode: str):
        if btn.get_active():
            self.filter_mode = mode
            self._render_sites()

    def _on_clear_clicked(self, _btn):
        def worker():
            et = getattr(self.manager, "egress_traffic", None)
            if et is not None and hasattr(et, "clear_logs"):
                et.clear_logs(self.selected_sandbox)
            return True

        def on_done(_res):
            if self._closed:
                return
            scope = f" for {self.selected_sandbox}" if self.selected_sandbox else ""
            self.toast_overlay.add_toast(Adw.Toast.new(f"Cleared recorded traffic history{scope}"))
            self.load_data()

        run_async(worker, on_success=on_done)

    def load_data(self):
        target = self.selected_sandbox

        def worker():
            et = getattr(self.manager, "egress_traffic", None)
            if et is None:
                return self._empty_stats(), []
            stats = et.get_domain_stats(sandbox_name=target) if hasattr(et, "get_domain_stats") else self._empty_stats()
            events = et.get_events(sandbox_name=target, limit=200) if hasattr(et, "get_events") else []
            return stats, events

        def on_done(result):
            if self._closed:
                return
            stats, events = result
            self._apply_loaded_data(stats, events)

        run_async(worker, on_success=on_done)

    def _apply_loaded_data(self, stats: Optional[Dict], events: Optional[List]):
        self.current_stats = stats if isinstance(stats, dict) else self._empty_stats()
        self.current_events = list(events) if events is not None else []
        self._render_sites()
        self._render_events()

    def _clear_site_rows(self):
        for r in self._site_rows:
            self.sites_group.remove(r)
        self._site_rows.clear()

    def _clear_event_rows(self):
        for r in self._event_rows:
            self.events_group.remove(r)
        self._event_rows.clear()

    def _render_sites(self):
        stats = self.current_stats
        all_sites = list(stats.get("sites", []))
        all_sites.sort(key=lambda s: (-int(s.get("total_count", 0)), str(s.get("domain", ""))))

        if hasattr(self, "export_btn"):
            self.export_btn.set_sensitive(bool(all_sites))

        unique_count = int(stats.get("unique_domains", len(all_sites)))
        total_req = int(stats.get("total_requests", 0))
        allowed_req = int(stats.get("allowed_requests", 0))
        blocked_req = int(stats.get("blocked_requests", 0))

        self.unique_sites_label.set_text(f"{unique_count:,}")
        self.total_calls_label.set_text(f"{total_req:,}")
        self.allowed_calls_label.set_text(f"{allowed_req:,}")
        if allowed_req > 0:
            self.allowed_calls_label.add_css_class("success")
        else:
            self.allowed_calls_label.remove_css_class("success")

        self.blocked_calls_label.set_text(f"{blocked_req:,}")
        if blocked_req > 0:
            self.blocked_calls_label.add_css_class("error")
        else:
            self.blocked_calls_label.remove_css_class("error")

        self._clear_site_rows()

        if not all_sites:
            self.sites_stack.set_visible_child_name("empty")
            return

        filtered = self.get_filtered_sites()

        if not filtered:
            self.sites_stack.set_visible_child_name("no-match")
            return

        self.sites_stack.set_visible_child_name("populated")
        max_count = max((int(s.get("total_count", 1)) for s in all_sites), default=1) or 1

        target_box = None
        if self.selected_sandbox:
            try:
                target_box = self.manager.get_sandbox(self.selected_sandbox)
            except Exception:
                target_box = None

        for site in filtered:
            domain = str(site.get("domain", ""))
            category = str(site.get("category", "General"))
            total_c = int(site.get("total_count", 0))
            allowed_c = int(site.get("allowed_count", 0))
            blocked_c = int(site.get("blocked_count", 0))
            last_seen = float(site.get("last_seen", 0.0) or 0.0)
            first_seen = float(site.get("first_seen", last_seen) or 0.0)
            last_action = str(site.get("last_action", "allowed" if blocked_c == 0 else "blocked"))
            ports = site.get("ports", [])
            sandboxes = site.get("sandboxes", [])

            last_str = datetime.fromtimestamp(last_seen).strftime("%H:%M:%S") if last_seen > 0 else "-"
            first_str = datetime.fromtimestamp(first_seen).strftime("%H:%M:%S") if first_seen > 0 else "-"

            subtitle = f"{category} · {allowed_c} allowed, {blocked_c} blocked · Last seen {last_str}"
            row = Adw.ExpanderRow(
                title=GLib.markup_escape_text(domain),
                subtitle=GLib.markup_escape_text(subtitle),
            )
            row._domain = domain

            # Status prefix icon
            if blocked_c == 0:
                status_icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
                status_icon.add_css_class("success")
            elif allowed_c > 0:
                status_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
                status_icon.add_css_class("warning")
            else:
                status_icon = Gtk.Image.new_from_icon_name("action-unavailable-symbolic")
                status_icon.add_css_class("error")
            row.add_prefix(status_icon)

            # Frequency level bar
            bar = Gtk.LevelBar.new_for_interval(0.0, 1.0)
            bar.set_value(min(max(total_c / max_count, 0.0), 1.0))
            bar.set_valign(Gtk.Align.CENTER)
            bar.set_size_request(72, -1)
            row.add_suffix(bar)

            # Call count badge
            count_lbl = Gtk.Label(label=f"{total_c} call{'s' if total_c != 1 else ''}")
            count_lbl.add_css_class("heading")
            count_lbl.add_css_class("numeric")
            count_lbl.set_valign(Gtk.Align.CENTER)
            row.add_suffix(count_lbl)

            # 1-click Allow / Block button when a target sandbox is selected
            if self.selected_sandbox:
                is_denied_in_policy = False
                is_allowed_in_policy = False
                if target_box and target_box.network_policy:
                    denied_lower = {d.lower() for d in target_box.network_policy.denied_domains}
                    allowed_lower = {d.lower() for d in target_box.network_policy.allowed_domains}
                    is_denied_in_policy = domain.lower() in denied_lower
                    is_allowed_in_policy = domain.lower() in allowed_lower

                should_offer_allow = is_denied_in_policy or (last_action == "blocked" and not is_allowed_in_policy)
                if should_offer_allow:
                    policy_btn = Gtk.Button(icon_name="emblem-ok-symbolic")
                    policy_btn.add_css_class("flat")
                    policy_btn.set_valign(Gtk.Align.CENTER)
                    policy_btn.set_tooltip_text("Add domain to sandbox whitelist")
                    policy_btn.connect(
                        "clicked",
                        lambda _b, d=domain, sb_name=self.selected_sandbox: self._apply_domain_policy(sb_name, d, allow=True),
                    )
                else:
                    policy_btn = Gtk.Button(icon_name="action-unavailable-symbolic")
                    policy_btn.add_css_class("flat")
                    policy_btn.set_valign(Gtk.Align.CENTER)
                    policy_btn.set_tooltip_text("Add domain to sandbox blacklist")
                    policy_btn.connect(
                        "clicked",
                        lambda _b, d=domain, sb_name=self.selected_sandbox: self._apply_domain_policy(sb_name, d, allow=False),
                    )
                row._policy_action_btn = policy_btn
                row.add_suffix(policy_btn)
            else:
                row._policy_action_btn = None

            # Expandable detail rows
            seen_detail = Adw.ActionRow(
                title="Activity Window",
                subtitle=GLib.markup_escape_text(f"First seen {first_str} · Last seen {last_str} · Last decision: {last_action}"),
            )
            seen_detail.add_css_class("property")
            row.add_row(seen_detail)

            ports_str = ", ".join(str(p) for p in ports) if ports else "Standard"
            ports_detail = Adw.ActionRow(
                title="Destination Ports",
                subtitle=GLib.markup_escape_text(ports_str),
            )
            ports_detail.add_css_class("property")
            row.add_row(ports_detail)

            if sandboxes:
                boxes_detail = Adw.ActionRow(
                    title="Sandboxes",
                    subtitle=GLib.markup_escape_text(", ".join(str(x) for x in sandboxes)),
                )
                boxes_detail.add_css_class("property")
                row.add_row(boxes_detail)

            self.sites_group.add(row)
            self._site_rows.append(row)

    def get_filtered_sites(self) -> List[dict]:
        """Return list of sites matching the active filter mode and search query."""
        all_sites = list(self.current_stats.get("sites", []))
        all_sites.sort(key=lambda s: (-int(s.get("total_count", 0)), str(s.get("domain", ""))))

        filtered = []
        for site in all_sites:
            allowed_c = int(site.get("allowed_count", 0))
            blocked_c = int(site.get("blocked_count", 0))
            if self.filter_mode == "allowed" and allowed_c <= 0:
                continue
            if self.filter_mode == "blocked" and blocked_c <= 0:
                continue

            if self.search_query:
                domain_l = str(site.get("domain", "")).lower()
                cat_l = str(site.get("category", "")).lower()
                boxes_l = " ".join(str(x).lower() for x in (site.get("sandboxes") or []))
                if (
                    self.search_query not in domain_l
                    and self.search_query not in cat_l
                    and self.search_query not in boxes_l
                ):
                    continue
            filtered.append(site)
        return filtered

    def export_sites_to_file(
        self,
        target_path: Union[str, Path],
        sites: Optional[List[dict]] = None,
        fmt: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Export domain stats to CSV or JSON using EgressTrafficManager."""
        et = getattr(self.manager, "egress_traffic", None)
        if et is None or not hasattr(et, "export_domain_stats"):
            return False, "Egress traffic manager unavailable"
        if sites is None:
            sites = self.get_filtered_sites()
        return et.export_domain_stats(
            target_path,
            sandbox_name=self.selected_sandbox,
            fmt=fmt,
            sites=sites,
        )

    def _on_export_clicked(self, _btn=None):
        if not self.current_stats.get("sites"):
            self.toast_overlay.add_toast(Adw.Toast.new("No sites data available to export"))
            return

        try:
            file_dialog = Gtk.FileDialog()
            file_dialog.set_title("Export Sites & Frequency Data")
            initial_name = (
                f"egress-sites-{self.selected_sandbox}.csv"
                if self.selected_sandbox
                else "egress-sites.csv"
            )
            file_dialog.set_initial_name(initial_name)

            filters = Gio.ListStore.new(Gtk.FileFilter)

            filter_csv = Gtk.FileFilter()
            filter_csv.set_name("CSV Files (*.csv)")
            filter_csv.add_pattern("*.csv")
            filters.append(filter_csv)

            filter_json = Gtk.FileFilter()
            filter_json.set_name("JSON Files (*.json)")
            filter_json.add_pattern("*.json")
            filters.append(filter_json)

            filter_all = Gtk.FileFilter()
            filter_all.set_name("All Files (*)")
            filter_all.add_pattern("*")
            filters.append(filter_all)

            file_dialog.set_filters(filters)
            file_dialog.set_default_filter(filter_csv)

            def on_save_finish(dialog, result):
                if self._closed:
                    return
                try:
                    file = dialog.save_finish(result)
                    file_path = file.get_path() if file else None
                    if not file_path:
                        if not self._closed:
                            self.toast_overlay.add_toast(
                                Adw.Toast.new("Export requires a local filesystem path")
                            )
                        return
                    ok, msg = self.export_sites_to_file(file_path)
                    if self._closed:
                        return
                    if ok:
                        self.toast_overlay.add_toast(
                            Adw.Toast.new(f"Exported sites to {Path(file_path).name}")
                        )
                    else:
                        self.toast_overlay.add_toast(
                            Adw.Toast.new(f"Export failed: {msg}")
                        )
                except Exception as e:
                    msg_l = str(e).lower()
                    is_cancelled = (
                        "dismissed" in msg_l
                        or "cancel" in msg_l
                        or (hasattr(e, "matches") and e.matches(Gio.io_error_quark(), Gio.IOErrorEnum.CANCELLED))
                    )
                    if not is_cancelled and not self._closed:
                        self.toast_overlay.add_toast(Adw.Toast.new(f"Export failed: {e}"))

            file_dialog.save(self, None, on_save_finish)
        except Exception as e:
            if not self._closed:
                self.toast_overlay.add_toast(Adw.Toast.new(f"Export failed: {e}"))

    def _render_events(self):
        self._clear_event_rows()
        if not self.current_events:
            self.events_stack.set_visible_child_name("empty")
            return

        self.events_stack.set_visible_child_name("populated")
        for ev in self.current_events:
            if isinstance(ev, dict):
                ts = float(ev.get("timestamp", 0.0) or 0.0)
                sb_name = str(ev.get("sandbox_name", ""))
                domain = str(ev.get("domain", ""))
                action = str(ev.get("action", "allowed"))
                protocol = str(ev.get("protocol", "tcp"))
                port = int(ev.get("port", 0) or 0)
                category = str(ev.get("category", ""))
                reason = str(ev.get("reason", ""))
            else:
                ts = float(getattr(ev, "timestamp", 0.0) or 0.0)
                sb_name = str(getattr(ev, "sandbox_name", ""))
                domain = str(getattr(ev, "domain", ""))
                action = str(getattr(ev, "action", "allowed"))
                protocol = str(getattr(ev, "protocol", "tcp"))
                port = int(getattr(ev, "port", 0) or 0)
                category = str(getattr(ev, "category", ""))
                reason = str(getattr(ev, "reason", ""))

            t_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts > 0 else "-"
            proto_part = f"{protocol.upper()}:{port}" if port else protocol.upper()
            meta_parts = [t_str]
            if sb_name:
                meta_parts.append(sb_name)
            if proto_part:
                meta_parts.append(proto_part)
            if category:
                meta_parts.append(category)
            if reason:
                meta_parts.append(reason)

            row = Adw.ActionRow(
                title=GLib.markup_escape_text(domain),
                subtitle=GLib.markup_escape_text(" · ".join(meta_parts)),
            )

            is_allowed = action.lower() == "allowed"
            icon = Gtk.Image.new_from_icon_name(
                "emblem-ok-symbolic" if is_allowed else "action-unavailable-symbolic"
            )
            icon.add_css_class("success" if is_allowed else "error")
            row.add_prefix(icon)

            badge = Gtk.Label(label="Allowed" if is_allowed else "Blocked")
            badge.add_css_class("caption-heading")
            badge.add_css_class("success" if is_allowed else "error")
            badge.set_valign(Gtk.Align.CENTER)
            row.add_suffix(badge)

            self.events_group.add(row)
            self._event_rows.append(row)

    def _apply_domain_policy(self, sandbox_name: str, domain: str, allow: bool):
        box = self.manager.get_sandbox(sandbox_name)
        if not box:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Sandbox '{sandbox_name}' not found"))
            return

        cur_policy = box.network_policy or NetworkPolicy()
        allowed = [d for d in cur_policy.allowed_domains if d.lower() != domain.lower()]
        denied = [d for d in cur_policy.denied_domains if d.lower() != domain.lower()]
        profile = cur_policy.profile

        if allow:
            if profile == "offline":
                profile = "custom"
            if profile != "full":
                allowed.append(domain.lower())
        else:
            denied.append(domain.lower())

        new_policy = NetworkPolicy(
            profile=profile,
            allowed_domains=allowed,
            denied_domains=denied,
        )

        def worker():
            if hasattr(self.manager, "update_sandbox"):
                res = self.manager.update_sandbox(sandbox_name, network_policy=new_policy)
                return res[0], res[1]
            ok = bool(self.manager.update_network_policy(sandbox_name, new_policy))
            return ok, ("Updated network policy." if ok else "Failed to update network policy.")

        def on_done(result):
            if self._closed:
                return
            ok, msg = result
            if ok:
                verb = "Allowed" if allow else "Blocked"
                self.toast_overlay.add_toast(Adw.Toast.new(f"{verb} '{domain}' for {sandbox_name}"))
                if self.on_policy_updated:
                    self.on_policy_updated()
                self.load_data()
            else:
                self.toast_overlay.add_toast(Adw.Toast.new(f"Policy update failed: {msg}"))

        run_async(worker, on_success=on_done)
