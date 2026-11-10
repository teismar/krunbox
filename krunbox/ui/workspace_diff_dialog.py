"""
Workspace Changes, Diff, and Rollback dialog in GTK4 / Libadwaita 1.5.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Callable, List, Optional
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk, Pango

from ..core.workspace_diff import FileChange, WorkspaceSnapshotManager
from .dialogs import show_alert_dialog
from .worker import run_async


_STATUS_META = {
    "added": ("list-add-symbolic", "success", "Added"),
    "deleted": ("list-remove-symbolic", "error", "Deleted"),
    "renamed": ("media-playlist-shuffle-symbolic", "accent", "Renamed"),
    "modified": ("document-edit-symbolic", "warning", "Modified"),
}


class _FileChangeListBoxRow(Gtk.ListBoxRow):
    """Sidebar row representing one changed workspace file."""

    def __init__(
        self,
        change: FileChange,
        on_revert: Callable[[FileChange], None],
    ):
        super().__init__()
        self.change = change

        outer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        outer.set_margin_top(6)
        outer.set_margin_bottom(6)
        outer.set_margin_start(8)
        outer.set_margin_end(6)
        self.set_child(outer)

        icon_name, color_cls, status_text = _STATUS_META.get(
            change.status, ("document-edit-symbolic", "warning", "Modified")
        )
        status_icon = Gtk.Image.new_from_icon_name(icon_name)
        status_icon.add_css_class(color_cls)
        status_icon.set_valign(Gtk.Align.CENTER)
        status_icon.set_tooltip_text(status_text)
        outer.append(status_icon)

        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        text_box.set_hexpand(True)
        outer.append(text_box)

        display_path = (
            f"{change.old_path} -> {change.path}"
            if change.old_path
            else change.path
        )
        self.path_label = Gtk.Label(label=display_path, xalign=0.0)
        self.path_label.add_css_class("monospace")
        self.path_label.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        self.path_label.set_tooltip_text(display_path)
        text_box.append(self.path_label)

        stats_text = f"{status_text}  ·  +{change.additions} / -{change.deletions}"
        self.caption_label = Gtk.Label(label=stats_text, xalign=0.0)
        self.caption_label.add_css_class("caption")
        self.caption_label.add_css_class("numeric")
        self.caption_label.add_css_class("dim-label")
        text_box.append(self.caption_label)

        self.revert_btn = Gtk.Button(icon_name="edit-undo-symbolic")
        self.revert_btn.add_css_class("flat")
        self.revert_btn.set_valign(Gtk.Align.CENTER)
        self.revert_btn.set_tooltip_text(f"Revert {change.path} to baseline")
        self.revert_btn.connect("clicked", lambda _btn: on_revert(change))
        outer.append(self.revert_btn)


class WorkspaceChangesDialog(Adw.Window):
    """
    Modal Libadwaita window for inspecting modified, added, deleted, and renamed
    workspace files relative to a sandbox baseline snapshot, with per-file revert,
    baseline acceptance, and full rollback.
    """

    def __init__(
        self,
        parent_window: Gtk.Window,
        snapshot_mgr: WorkspaceSnapshotManager,
        sandbox_name: str,
        dir_path: str,
        on_changed: Optional[Callable[[], None]] = None,
    ):
        super().__init__(modal=True, transient_for=parent_window)
        self.parent_window = parent_window
        self.snapshot_mgr = snapshot_mgr
        self.sandbox_name = sandbox_name
        self.dir_path = dir_path
        self.on_changed = on_changed

        self.set_title(f"Workspace Changes - {sandbox_name}")
        self.set_default_size(820, 640)

        self._closed: bool = False
        self._load_seq: int = 0
        self._diff_seq: int = 0
        self.changes: List[FileChange] = []
        self.snapshot_info: Optional[dict] = None
        self.selected_change: Optional[FileChange] = None
        self._active_confirm_dialog: Optional[Any] = None

        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        self.toolbar_view = Adw.ToolbarView()
        self.toast_overlay.set_child(self.toolbar_view)

        # HeaderBar
        header = Adw.HeaderBar()
        self.toolbar_view.add_top_bar(header)

        self.refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        self.refresh_btn.set_tooltip_text("Refresh Workspace Changes")
        self.refresh_btn.connect("clicked", lambda _btn: self.refresh_changes())
        header.pack_start(self.refresh_btn)

        self.accept_btn = Gtk.Button()
        accept_content = Adw.ButtonContent(
            icon_name="object-select-symbolic",
            label="Accept Baseline",
        )
        self.accept_btn.set_child(accept_content)
        self.accept_btn.set_tooltip_text(
            "Advance baseline snapshot to match current workspace files"
        )
        self.accept_btn.connect("clicked", self._on_accept_baseline_clicked)
        header.pack_start(self.accept_btn)

        self.rollback_btn = Gtk.Button()
        rollback_content = Adw.ButtonContent(
            icon_name="edit-undo-symbolic",
            label="Rollback All…",
        )
        self.rollback_btn.set_child(rollback_content)
        self.rollback_btn.add_css_class("destructive-action")
        self.rollback_btn.set_tooltip_text(
            "Revert all workspace changes back to the baseline snapshot"
        )
        self.rollback_btn.set_sensitive(False)
        self.rollback_btn.connect("clicked", self._on_rollback_all_clicked)
        header.pack_end(self.rollback_btn)

        # Info Banner (Libadwaita 1.5 safe: markup disabled)
        self.info_banner = Adw.Banner()
        self.info_banner.set_use_markup(False)
        self.info_banner.set_revealed(False)
        self.info_banner.connect("button-clicked", self._on_banner_button_clicked)
        self.toolbar_view.add_top_bar(self.info_banner)

        # Content Stack: "empty" vs "populated"
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.stack.set_vexpand(True)
        self.stack.set_hexpand(True)
        self.toolbar_view.set_content(self.stack)

        self.empty_page = Adw.StatusPage(
            icon_name="emblem-ok-symbolic",
            title="Workspace Clean",
            description="No modified, added, or deleted files relative to the baseline snapshot.",
        )
        self.stack.add_named(self.empty_page, "empty")

        # Populated split view
        self.paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.paned.set_position(330)
        self.paned.set_shrink_start_child(False)
        self.paned.set_shrink_end_child(False)
        self.paned.set_vexpand(True)
        self.paned.set_hexpand(True)
        self.stack.add_named(self.paned, "populated")

        # Left pane: ScrolledWindow + ListBox (.navigation-sidebar)
        left_scroll = Gtk.ScrolledWindow()
        left_scroll.set_vexpand(True)
        left_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        self.file_list = Gtk.ListBox()
        self.file_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.file_list.add_css_class("navigation-sidebar")
        self.file_list.connect("row-selected", self._on_row_selected)
        left_scroll.set_child(self.file_list)
        self.paned.set_start_child(left_scroll)

        # Right pane: file toolbar strip + read-only unified diff TextView
        right_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        right_box.set_vexpand(True)
        right_box.set_hexpand(True)
        self.paned.set_end_child(right_box)

        diff_toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        diff_toolbar.set_margin_top(8)
        diff_toolbar.set_margin_bottom(8)
        diff_toolbar.set_margin_start(12)
        diff_toolbar.set_margin_end(12)
        right_box.append(diff_toolbar)

        self.selected_path_label = Gtk.Label(
            label="Select a file to inspect unified diff",
            xalign=0.0,
        )
        self.selected_path_label.set_hexpand(True)
        self.selected_path_label.add_css_class("monospace")
        self.selected_path_label.add_css_class("heading")
        self.selected_path_label.set_ellipsize(Pango.EllipsizeMode.START)
        diff_toolbar.append(self.selected_path_label)

        self.diff_stats_label = Gtk.Label(label="")
        self.diff_stats_label.add_css_class("caption")
        self.diff_stats_label.add_css_class("numeric")
        self.diff_stats_label.add_css_class("dim-label")
        diff_toolbar.append(self.diff_stats_label)

        self.revert_file_btn = Gtk.Button()
        revert_file_content = Adw.ButtonContent(
            icon_name="edit-undo-symbolic",
            label="Revert File",
        )
        self.revert_file_btn.set_child(revert_file_content)
        self.revert_file_btn.set_tooltip_text(
            "Revert selected file back to baseline snapshot"
        )
        self.revert_file_btn.set_sensitive(False)
        self.revert_file_btn.connect("clicked", self._on_revert_selected_clicked)
        diff_toolbar.append(self.revert_file_btn)

        right_box.append(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))

        right_scroll = Gtk.ScrolledWindow()
        right_scroll.set_vexpand(True)
        right_scroll.set_hexpand(True)
        right_box.append(right_scroll)

        self.diff_view = Gtk.TextView(
            editable=False,
            left_margin=12,
            right_margin=12,
            top_margin=10,
            bottom_margin=10,
        )
        self.diff_view.add_css_class("monospace")
        self.diff_view.set_monospace(True)
        self.diff_view.set_cursor_visible(False)
        self.diff_view.set_wrap_mode(Gtk.WrapMode.NONE)
        self.diff_buffer = self.diff_view.get_buffer()
        self._init_diff_tags()
        right_scroll.set_child(self.diff_view)

        self.connect("close-request", self._on_close_request)
        self.refresh_changes()

    def _init_diff_tags(self) -> None:
        self._tag_add = self.diff_buffer.create_tag("diff-add", foreground="#2ec27e")
        self._tag_del = self.diff_buffer.create_tag("diff-del", foreground="#e01b24")
        self._tag_hunk = self.diff_buffer.create_tag("diff-hunk", foreground="#3584e4")
        self._tag_hdr = self.diff_buffer.create_tag(
            "diff-header", weight=Pango.Weight.BOLD
        )
        self._sync_tag_palette()

    def _sync_tag_palette(self) -> None:
        try:
            is_dark = Adw.StyleManager.get_default().get_dark()
        except Exception:
            is_dark = True
        self._tag_add.set_property("foreground", "#2ec27e" if is_dark else "#1b8553")
        self._tag_del.set_property("foreground", "#e01b24" if is_dark else "#c01c28")
        self._tag_hunk.set_property("foreground", "#3584e4" if is_dark else "#1c71d8")

    def _on_close_request(self, *_args) -> bool:
        self._closed = True
        self._active_confirm_dialog = None
        self._clear_file_list()
        return False

    def _clear_file_list(self) -> None:
        while True:
            child = self.file_list.get_first_child()
            if child is None:
                break
            self.file_list.remove(child)

    def refresh_changes(self) -> None:
        self._load_seq += 1
        req_seq = self._load_seq
        sandbox_name = self.sandbox_name
        dir_path = self.dir_path

        def worker():
            info = self.snapshot_mgr.get_snapshot_info(sandbox_name)
            if info is not None:
                try:
                    if Path(str(info.get("dir_path", ""))).resolve() != Path(dir_path).resolve():
                        info = None
                except OSError:
                    info = None
            changes = self.snapshot_mgr.list_changes(sandbox_name, dir_path)
            return info, changes

        def on_done(result):
            if self._closed or req_seq != self._load_seq:
                return
            info, changes = result
            self._apply_changes(info, changes)

        def on_err(exc: Exception):
            if self._closed or req_seq != self._load_seq:
                return
            self.toast_overlay.add_toast(
                Adw.Toast.new(f"Failed to inspect workspace: {exc}")
            )

        run_async(worker, on_success=on_done, on_error=on_err)

    def _apply_changes(
        self, info: Optional[dict], changes: List[FileChange]
    ) -> None:
        prev_selected_path = (
            self.selected_change.path if self.selected_change is not None else None
        )
        self.snapshot_info = info
        self.changes = list(changes)
        self._update_banner()

        self._clear_file_list()
        self.rollback_btn.set_sensitive(len(self.changes) > 0)

        if not self.changes:
            self.selected_change = None
            self.selected_path_label.set_text("No changed files")
            self.diff_stats_label.set_text("")
            self.revert_file_btn.set_sensitive(False)
            self.diff_buffer.set_text("")
            self.stack.set_visible_child_name("empty")
            return

        self.stack.set_visible_child_name("populated")
        row_to_select: Optional[_FileChangeListBoxRow] = None
        first_row: Optional[_FileChangeListBoxRow] = None

        for ch in self.changes:
            row = _FileChangeListBoxRow(ch, on_revert=self._revert_single_change)
            self.file_list.append(row)
            if first_row is None:
                first_row = row
            if prev_selected_path and ch.path == prev_selected_path:
                row_to_select = row

        target_row = row_to_select or first_row
        if target_row is not None:
            self.file_list.select_row(target_row)

    def _update_banner(self) -> None:
        info = self.snapshot_info
        if info is None:
            self.info_banner.set_title(
                "No baseline snapshot recorded yet for this workspace."
            )
            self.info_banner.set_button_label("Create Snapshot")
            self.info_banner.set_revealed(True)
            return

        ts = float(info.get("timestamp", 0.0) or 0.0)
        ts_str = (
            datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            if ts > 0
            else "Unknown time"
        )
        mode = str(info.get("mode", "git"))
        if mode == "git":
            tree_sha = str(info.get("tree_sha") or "")[:8]
            mode_label = f"Git snapshot ({tree_sha})" if tree_sha else "Git snapshot"
        else:
            mode_label = "Archive snapshot"

        total_changes = len(self.changes)
        summary = (
            f"{total_changes} changed file(s)"
            if total_changes > 0
            else "Workspace clean"
        )
        self.info_banner.set_title(f"{mode_label} · Captured {ts_str} · {summary}")
        self.info_banner.set_button_label(None)
        self.info_banner.set_revealed(True)

    def _on_banner_button_clicked(self, _banner: Adw.Banner) -> None:
        sandbox_name = self.sandbox_name
        dir_path = self.dir_path

        def worker():
            return self.snapshot_mgr.create_snapshot(sandbox_name, dir_path)

        def on_done(result):
            if self._closed:
                return
            ok, msg, _meta = result
            self.toast_overlay.add_toast(Adw.Toast.new(msg))
            if ok and self.on_changed:
                self.on_changed()
            self.refresh_changes()

        run_async(worker, on_success=on_done)

    def _on_row_selected(
        self, _listbox: Gtk.ListBox, row: Optional[Gtk.ListBoxRow]
    ) -> None:
        if row is None or not isinstance(row, _FileChangeListBoxRow):
            self.selected_change = None
            self.revert_file_btn.set_sensitive(False)
            return

        change = row.change
        self.selected_change = change
        header_path = (
            f"{change.old_path} -> {change.path}"
            if change.old_path
            else change.path
        )
        self.selected_path_label.set_text(header_path)
        self.diff_stats_label.set_text(f"+{change.additions} / -{change.deletions}")
        self.revert_file_btn.set_sensitive(True)
        self._load_diff_for_change(change)

    def _load_diff_for_change(self, change: FileChange) -> None:
        self._diff_seq += 1
        req_seq = self._diff_seq
        sandbox_name = self.sandbox_name
        dir_path = self.dir_path
        rel_path = change.path

        def worker():
            return self.snapshot_mgr.get_file_diff(sandbox_name, dir_path, rel_path)

        def on_done(diff_text: str):
            if self._closed or req_seq != self._diff_seq:
                return
            self._populate_diff_buffer(diff_text)

        def on_err(exc: Exception):
            if self._closed or req_seq != self._diff_seq:
                return
            self.diff_buffer.set_text(f"[Unable to load diff: {exc}]")

        run_async(worker, on_success=on_done, on_error=on_err)

    def _populate_diff_buffer(self, diff_text: str) -> None:
        self._sync_tag_palette()
        self.diff_buffer.set_text("")
        if not diff_text or not diff_text.strip():
            self.diff_buffer.set_text("[No textual line differences]")
            return

        end_iter = self.diff_buffer.get_end_iter()
        for line in diff_text.splitlines(keepends=True):
            tag_name: Optional[str] = None
            if line.startswith("@@"):
                tag_name = "diff-hunk"
            elif line.startswith("+++") or line.startswith("---"):
                tag_name = "diff-header"
            elif line.startswith("+"):
                tag_name = "diff-add"
            elif line.startswith("-"):
                tag_name = "diff-del"

            if tag_name is not None:
                self.diff_buffer.insert_with_tags_by_name(end_iter, line, tag_name)
            else:
                self.diff_buffer.insert(end_iter, line)

    def _on_revert_selected_clicked(self, _btn: Gtk.Button) -> None:
        if self.selected_change is not None:
            self._revert_single_change(self.selected_change)

    def _revert_single_change(self, change: FileChange) -> None:
        sandbox_name = self.sandbox_name
        dir_path = self.dir_path
        rel_path = change.path

        def worker():
            return self.snapshot_mgr.revert_file(sandbox_name, dir_path, rel_path)

        def on_done(result):
            if self._closed:
                return
            ok, msg = result
            self.toast_overlay.add_toast(Adw.Toast.new(msg))
            if ok and self.on_changed:
                self.on_changed()
            self.refresh_changes()

        run_async(worker, on_success=on_done)

    def _on_accept_baseline_clicked(self, _btn: Gtk.Button) -> None:
        sandbox_name = self.sandbox_name
        dir_path = self.dir_path

        def worker():
            return self.snapshot_mgr.accept_changes(sandbox_name, dir_path)

        def on_done(result):
            if self._closed:
                return
            ok, msg = result
            toast_text = (
                "Baseline snapshot updated to current workspace."
                if ok
                else f"Failed to update baseline: {msg}"
            )
            self.toast_overlay.add_toast(Adw.Toast.new(toast_text))
            if ok and self.on_changed:
                self.on_changed()
            self.refresh_changes()

        run_async(worker, on_success=on_done)

    def _on_rollback_all_clicked(self, _btn: Gtk.Button) -> None:
        if not self.changes:
            return

        count = len(self.changes)

        def on_response(response: str):
            self._active_confirm_dialog = None
            if response == "rollback":
                self._execute_rollback_all()

        self._active_confirm_dialog = show_alert_dialog(
            parent_window=self,
            heading=f"Rollback {count} changed file(s)?",
            body=(
                f"This will discard all workspace modifications, delete newly added files, "
                f"and restore deleted files in '{self.sandbox_name}' back to its baseline snapshot."
            ),
            responses=[
                ("cancel", "Cancel"),
                ("rollback", "Rollback All", Adw.ResponseAppearance.DESTRUCTIVE),
            ],
            on_response=on_response,
            default_response="cancel",
            close_response="cancel",
        )

    def _execute_rollback_all(self) -> None:
        sandbox_name = self.sandbox_name
        dir_path = self.dir_path
        self.rollback_btn.set_sensitive(False)

        def worker():
            return self.snapshot_mgr.rollback_all(sandbox_name, dir_path)

        def on_done(result):
            if self._closed:
                return
            ok, msg = result
            self.toast_overlay.add_toast(Adw.Toast.new(msg))
            if ok and self.on_changed:
                self.on_changed()
            self.refresh_changes()

        run_async(worker, on_success=on_done)
