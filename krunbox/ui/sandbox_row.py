"""
Native Libadwaita / GTK4 Sandbox Card component for krunbox.
"""

import re
import weakref
import webbrowser
from typing import Callable, Optional, Tuple
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib, Gio, Gdk, Pango

from ..core.config import NETWORK_PROFILES
from ..core.ide import IDE_SPECS, launch_ide
from ..core.manager import SandboxManager
from ..core.network import get_profile_domains
from ..core.sandbox import NetworkPolicy, SandboxInfo
from .edit_dialog import EditSandboxDialog
from .egress_dialog import EgressTrafficDialog
from .logs_dialog import LogsDialog
from .port_dialog import PortForwardDialog
from .telemetry_dialog import TelemetryDialog
from .dialogs import show_alert_dialog
from .worker import run_async

PROFILE_DISPLAY_NAMES = {
    "full": "Full",
    "ai-only": "AI APIs Only",
    "dev-common": "Dev Registries",
    "offline": "Offline",
    "custom": "Custom",
}

_MEM_TOKEN_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgt]i?b|b)?", re.IGNORECASE)


def parse_mem_token_mib(raw: str) -> Optional[float]:
    """Parse a human-readable memory token (e.g. '512MiB', '1.2GiB', '160MB') into MiB."""
    if not raw:
        return None
    m = _MEM_TOKEN_RE.match(raw.strip())
    if not m:
        return None
    val = float(m.group(1))
    unit = (m.group(2) or "b").lower()
    if unit == "b":
        return val / (1024.0 * 1024.0)
    if unit in ("kb", "kib"):
        return val / 1024.0
    if unit in ("mb", "mib"):
        return val
    if unit in ("gb", "gib"):
        return val * 1024.0
    if unit in ("tb", "tib"):
        return val * 1024.0 * 1024.0
    return None


def _resolve_dropdown_arrow_icon() -> str:
    """Resolve a standard arrow-down symbolic icon widely present across desktop themes.

    Default Libadwaita SplitButton leaves the dropdown MenuButton icon_name unset,
    relying on GTK4's internal GtkBuiltinIcon (arrow.down), which frequently fails to render
    or appears blank on Fedora and other distributions under custom desktop themes,
    icon themes, or font configurations.

    'go-down-symbolic' is part of the FreeDesktop / XDG Standard Icon Specification and
    is universally present across desktop themes (Adwaita, Breeze, Papirus, Yaru, etc.),
    with 'pan-down-symbolic' and 'go-down' as fallbacks.
    """
    display = Gdk.Display.get_default()
    if display:
        theme = Gtk.IconTheme.get_for_display(display)
        for icon in ("go-down-symbolic", "pan-down-symbolic", "go-down"):
            if theme.has_icon(icon):
                return icon
    return "go-down-symbolic"


class SandboxCard(Gtk.Frame):
    def __init__(
        self,
        parent_window: Gtk.Window,
        manager: SandboxManager,
        sandbox: SandboxInfo,
        on_updated: Callable[[], None],
    ):
        super().__init__()
        self.parent_window = parent_window
        self.manager = manager
        self.sandbox = sandbox
        self.on_updated = on_updated
        self._last_ports_key = None

        self.add_css_class("card")

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        main_box.set_margin_top(12)
        main_box.set_margin_bottom(12)
        main_box.set_margin_start(16)
        main_box.set_margin_end(16)
        self.set_child(main_box)

        # Double-click card to quick connect
        self.card_gesture = Gtk.GestureClick()
        self.card_gesture.set_button(1)
        self.card_gesture.connect("released", self._on_card_double_clicked)
        self.add_controller(self.card_gesture)

        # Card action group for Connect SplitButton & Overflow menu (weakref-guarded)
        self._action_group = Gio.SimpleActionGroup()
        self._setup_card_actions()
        self.insert_action_group("card", self._action_group)

        status = (sandbox.status or "stopped").lower()

        # ------------------------------------------------------------------
        # Row 1: Header (Status Icon, Name, Status Label, Split Connect, Actions)
        # ------------------------------------------------------------------
        top_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        main_box.append(top_row)

        self.status_icon = Gtk.Image()
        self.status_icon.set_valign(Gtk.Align.CENTER)
        top_row.append(self.status_icon)

        self.name_label = Gtk.Label(label=sandbox.name)
        self.name_label.set_halign(Gtk.Align.START)
        self.name_label.set_ellipsize(Pango.EllipsizeMode.END)
        self.name_label.add_css_class("heading")
        top_row.append(self.name_label)

        self.status_pill = Gtk.Label()
        self.status_pill.set_valign(Gtk.Align.CENTER)
        self.status_pill.add_css_class("caption-heading")
        top_row.append(self.status_pill)
        self._apply_status_visuals(status)

        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        top_row.append(spacer)

        # 1-Click Connect + IDE SplitButton (created ONCE with Adw.ButtonContent)
        ide_menu = Gio.Menu()
        sec_term = Gio.Menu()
        sec_term.append("Open SSH Terminal", "card.open-terminal")
        ide_menu.append_section(None, sec_term)

        sec_ides = Gio.Menu()
        sec_ides.append("Open in VS Code (Remote-SSH)", "card.open-vscode")
        sec_ides.append("Open in Cursor (Remote-SSH)", "card.open-cursor")
        sec_ides.append("Open in Zed (Remote-SSH)", "card.open-zed")
        sec_ides.append("Open in JetBrains Gateway", "card.open-jetbrains")
        sec_ides.append("Open File Manager (SFTP)", "card.open-sftp")
        ide_menu.append_section(None, sec_ides)

        self.connect_btn = Adw.SplitButton()
        self.connect_content = Adw.ButtonContent(
            icon_name="utilities-terminal-symbolic",
            label="Connect",
        )
        self.connect_btn.set_child(self.connect_content)
        self.connect_btn.set_menu_model(ide_menu)
        self.connect_btn.set_dropdown_tooltip("Open in IDE or SFTP File Manager")
        self.connect_btn.set_valign(Gtk.Align.CENTER)
        self.connect_dropdown_btn = self._setup_split_dropdown_icon(self.connect_btn)
        self._update_connect_btn(status)
        self.connect_btn.connect("clicked", self._on_quick_connect_clicked)
        top_row.append(self.connect_btn)

        # Linked Primary Control Bar (Start/Stop/Resume, Pause, Diff, Edit, Egress Traffic)
        action_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        action_bar.add_css_class("linked")
        action_bar.set_valign(Gtk.Align.CENTER)
        top_row.append(action_bar)

        self.toggle_btn = Gtk.Button()
        action_bar.append(self.toggle_btn)

        self.pause_btn = Gtk.Button(icon_name="media-playback-pause-symbolic")
        self.pause_btn.set_tooltip_text("Pause MicroVM (Freeze RAM & Processes)")
        self.pause_btn.connect("clicked", self._on_pause_clicked)
        action_bar.append(self.pause_btn)

        self._apply_toggle_visuals(status)
        self.toggle_btn.connect("clicked", self._on_toggle_clicked)

        self.changes_btn = Gtk.Button(icon_name="view-dual-symbolic")
        self.changes_btn.set_tooltip_text("Workspace Changes - Diff & 1-Click Rollback")
        self.changes_btn.connect("clicked", self._on_workspace_changes_clicked)
        action_bar.append(self.changes_btn)

        self.edit_btn = Gtk.Button(icon_name="document-edit-symbolic")
        self.edit_btn.set_tooltip_text("Edit Sandbox (Name, CPU/RAM, Egress, Guardrails, Secrets)")
        self.edit_btn.connect("clicked", self._on_edit_clicked)
        action_bar.append(self.edit_btn)

        self.traffic_btn = Gtk.Button(icon_name="network-transmit-receive-symbolic")
        self.traffic_btn.set_tooltip_text("View Egress Traffic & Called Sites")
        self.traffic_btn.connect("clicked", self._on_egress_traffic_clicked)
        action_bar.append(self.traffic_btn)

        self.recreate_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        self.recreate_btn.set_tooltip_text("Recreate Sandbox (Wipe & Rebuild with Same Settings)")
        self.recreate_btn.connect("clicked", self._on_recreate_clicked)
        action_bar.append(self.recreate_btn)

        # Overflow MenuButton
        overflow_menu = Gio.Menu()
        sec_ops = Gio.Menu()
        sec_ops.append("Workspace Changes & Diff…", "card.workspace-changes")
        sec_ops.append("Pause / Resume MicroVM", "card.pause-resume")
        sec_ops.append("Restart Sandbox", "card.restart")
        sec_ops.append("Forward Port…", "card.forward-port")
        sec_ops.append("Toggle Keep Awake (Never Sleep)", "card.keep-awake")
        sec_ops.append("Container Logs", "card.logs")
        sec_ops.append("AI API Telemetry", "card.telemetry")
        overflow_menu.append_section(None, sec_ops)

        sec_danger = Gio.Menu()
        sec_danger.append("Recreate Sandbox…", "card.recreate")
        sec_danger.append("Delete Sandbox…", "card.delete")
        overflow_menu.append_section(None, sec_danger)

        self.more_btn = Gtk.MenuButton(
            icon_name="view-more-symbolic",
            menu_model=overflow_menu,
            tooltip_text="More Actions",
        )
        self.more_btn.add_css_class("flat")
        self.more_btn.set_valign(Gtk.Align.CENTER)
        top_row.append(self.more_btn)

        # ------------------------------------------------------------------
        # Row 2: Metadata Summary Row (Lifecycle, Egress, Hardware, Guardrails, Image)
        # ------------------------------------------------------------------
        meta_flow = Gtk.FlowBox(
            selection_mode=Gtk.SelectionMode.NONE,
            column_spacing=14,
            row_spacing=4,
            max_children_per_line=7,
            homogeneous=False,
        )
        main_box.append(meta_flow)

        # 1. Lifecycle
        mode_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        self.mode_icon = Gtk.Image()
        self.mode_icon.set_pixel_size(14)
        self.mode_pill = Gtk.Label()
        self.mode_pill.add_css_class("caption")
        mode_box.append(self.mode_icon)
        mode_box.append(self.mode_pill)
        self._append_flow_item(meta_flow, mode_box)
        self._apply_lifecycle_visuals(sandbox.is_persistent)

        # 2. Egress Policy
        net_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        self.net_icon = Gtk.Image()
        self.net_icon.set_pixel_size(14)
        self.net_pill = Gtk.Label()
        self.net_pill.add_css_class("caption")
        net_box.append(self.net_icon)
        net_box.append(self.net_pill)
        self._append_flow_item(meta_flow, net_box)
        self._apply_net_summary(sandbox.network_policy)

        # 3. Compute Hardware
        hw_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        hw_icon = Gtk.Image.new_from_icon_name("computer-symbolic")
        hw_icon.set_pixel_size(14)
        hw_icon.add_css_class("dim-label")
        self.hw_pill = Gtk.Label(label=self._format_hw_text(sandbox))
        self.hw_pill.add_css_class("caption")
        self.hw_pill.add_css_class("numeric")
        self.hw_pill.add_css_class("dim-label")
        hw_box.append(hw_icon)
        hw_box.append(self.hw_pill)
        self._append_flow_item(meta_flow, hw_box)

        # 4. Guardrails & Security Summary
        self.guard_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        self.guard_icon = Gtk.Image.new_from_icon_name("changes-prevent-symbolic")
        self.guard_icon.set_pixel_size(14)
        self.guard_icon.add_css_class("dim-label")
        self.guard_pill = Gtk.Label()
        self.guard_pill.add_css_class("caption")
        self.guard_pill.add_css_class("dim-label")
        self.guard_box.append(self.guard_icon)
        self.guard_box.append(self.guard_pill)
        self._append_flow_item(meta_flow, self.guard_box)
        self._apply_guardrails_summary(sandbox)

        # 5. Base Image
        img_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        img_icon = Gtk.Image.new_from_icon_name("package-x-generic-symbolic")
        img_icon.set_pixel_size(14)
        img_icon.add_css_class("dim-label")
        self.img_pill = Gtk.Label(label=sandbox.base_image.split("/")[-1])
        self.img_pill.add_css_class("caption")
        self.img_pill.add_css_class("dim-label")
        img_box.append(img_icon)
        img_box.append(self.img_pill)
        self._append_flow_item(meta_flow, img_box)

        # ------------------------------------------------------------------
        # Row 3: Workspace Directory
        # ------------------------------------------------------------------
        dir_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        main_box.append(dir_row)

        folder_icon = Gtk.Image.new_from_icon_name("folder-symbolic")
        folder_icon.set_pixel_size(14)
        folder_icon.add_css_class("dim-label")
        dir_row.append(folder_icon)

        self.dir_label = Gtk.Label(label=sandbox.dir_path)
        self.dir_label.set_halign(Gtk.Align.START)
        self.dir_label.set_hexpand(True)
        self.dir_label.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        self.dir_label.set_tooltip_text(sandbox.dir_path)
        self.dir_label.add_css_class("monospace")
        self.dir_label.add_css_class("caption")
        self.dir_label.add_css_class("dim-label")
        dir_row.append(self.dir_label)

        # ------------------------------------------------------------------
        # Row 4: Live Dual CPU & RAM Utilization Bars (visible when running/paused)
        # ------------------------------------------------------------------
        self.telem_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        self.telem_box.set_margin_top(2)
        main_box.append(self.telem_box)

        # CPU Meter Column
        cpu_col = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        cpu_col.set_hexpand(True)
        self.telem_box.append(cpu_col)

        self.cpu_label = Gtk.Label()
        self.cpu_label.add_css_class("caption")
        self.cpu_label.add_css_class("numeric")
        self.cpu_label.add_css_class("dim-label")
        cpu_col.append(self.cpu_label)

        self.cpu_bar = Gtk.LevelBar.new_for_interval(0.0, 1.0)
        self.cpu_bar.set_mode(Gtk.LevelBarMode.CONTINUOUS)
        self.cpu_bar.add_offset_value("low", 0.75)
        self.cpu_bar.add_offset_value("high", 0.90)
        self.cpu_bar.add_offset_value("full", 1.0)
        self.cpu_bar.set_hexpand(True)
        self.cpu_bar.set_valign(Gtk.Align.CENTER)
        cpu_col.append(self.cpu_bar)

        # RAM Meter Column
        ram_col = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        ram_col.set_hexpand(True)
        self.telem_box.append(ram_col)

        self.ram_label = Gtk.Label()
        self.ram_label.add_css_class("caption")
        self.ram_label.add_css_class("numeric")
        self.ram_label.add_css_class("dim-label")
        # Alias mem_label for backward compatibility
        self.mem_label = self.ram_label
        ram_col.append(self.ram_label)

        self.ram_bar = Gtk.LevelBar.new_for_interval(0.0, 1.0)
        self.ram_bar.set_mode(Gtk.LevelBarMode.CONTINUOUS)
        self.ram_bar.add_offset_value("low", 0.75)
        self.ram_bar.add_offset_value("high", 0.90)
        self.ram_bar.add_offset_value("full", 1.0)
        self.ram_bar.set_hexpand(True)
        self.ram_bar.set_valign(Gtk.Align.CENTER)
        ram_col.append(self.ram_bar)

        self._update_resource_bars(sandbox, status)

        # ------------------------------------------------------------------
        # Row 5: Ports Row
        # ------------------------------------------------------------------
        self.ports_box = Gtk.FlowBox(
            selection_mode=Gtk.SelectionMode.NONE,
            column_spacing=6,
            row_spacing=4,
            max_children_per_line=10,
            homogeneous=False,
        )
        self.ports_box.set_margin_top(2)
        main_box.append(self.ports_box)
        self._rebuild_ports()

    @staticmethod
    def _append_flow_item(flow: Gtk.FlowBox, widget: Gtk.Widget):
        flow.append(widget)
        fb_child = widget.get_parent()
        if fb_child:
            fb_child.set_focusable(False)

    def _setup_card_actions(self):
        self_ref = weakref.ref(self)

        def bind(method_name: str, arg=None):
            def _handler(_act, _param):
                card = self_ref()
                if card is not None:
                    if arg is not None:
                        getattr(card, method_name)(arg)
                    else:
                        getattr(card, method_name)(None)
            return _handler

        for act_name, method_name in [
            ("workspace-changes", "_on_workspace_changes_clicked"),
            ("pause-resume", "_on_pause_or_resume_action"),
            ("restart", "_on_restart_clicked"),
            ("forward-port", "_on_forward_port_clicked"),
            ("keep-awake", "_on_keep_awake_clicked"),
            ("logs", "_on_logs_clicked"),
            ("telemetry", "_on_telemetry_clicked"),
            ("recreate", "_on_recreate_clicked"),
            ("delete", "_on_delete_clicked"),
        ]:
            act = Gio.SimpleAction.new(act_name, None)
            act.connect("activate", bind(method_name))
            self._action_group.add_action(act)

        for ide_key in IDE_SPECS.keys():
            act = Gio.SimpleAction.new(f"open-{ide_key}", None)
            act.connect("activate", bind("_on_open_ide_requested", ide_key))
            self._action_group.add_action(act)

    @staticmethod
    def _format_hw_text(sandbox: SandboxInfo) -> str:
        if sandbox.ram_mib % 1024 == 0:
            ram_display = f"{sandbox.ram_mib // 1024} GiB"
        else:
            ram_display = f"{sandbox.ram_mib / 1024:.1f} GiB"
        return f"{sandbox.cpus} vCPUs · {ram_display}"

    @staticmethod
    def _compute_ram_metrics(sandbox: SandboxInfo) -> Tuple[float, str]:
        """Compute (mem_percent 0..100, display_label) from sandbox stats and allocated RAM."""
        pct = float(sandbox.mem_percent or 0.0)
        usage_raw = (sandbox.mem_usage or "").strip()

        if pct <= 0.0 and usage_raw:
            left_part = usage_raw.split("/")[0].strip()
            used_mib = parse_mem_token_mib(left_part)
            if used_mib is not None and sandbox.ram_mib > 0:
                pct = min(100.0, max(0.0, (used_mib / float(sandbox.ram_mib)) * 100.0))

        pct = min(100.0, max(0.0, pct))
        if usage_raw:
            return pct, f"RAM {pct:.0f}% · {usage_raw}"

        if sandbox.ram_mib % 1024 == 0:
            alloc_str = f"{sandbox.ram_mib // 1024} GiB"
        else:
            alloc_str = f"{sandbox.ram_mib / 1024:.1f} GiB"
        if pct > 0.0:
            used_gib = (pct / 100.0) * (sandbox.ram_mib / 1024.0)
            return pct, f"RAM {pct:.0f}% · {used_gib:.1f} / {alloc_str}"
        return 0.0, f"RAM 0% · 0 / {alloc_str}"

    def _update_resource_bars(self, sandbox: SandboxInfo, status: str):
        active = status in ("running", "paused")
        self.telem_box.set_visible(active)
        if not active:
            return

        cpu_pct = max(0.0, float(sandbox.cpu_percent or 0.0))
        # Normalize CPU bar against 100% (or multi-vCPU ceiling if > 100%)
        cpu_fraction = min(max(cpu_pct / 100.0, 0.0), 1.0)
        self.cpu_label.set_text(f"CPU {cpu_pct:.1f}%")
        self.cpu_bar.set_value(cpu_fraction)
        self.cpu_bar.set_tooltip_text(f"CPU Utilization: {cpu_pct:.1f}%")

        ram_pct, ram_text = self._compute_ram_metrics(sandbox)
        ram_fraction = min(max(ram_pct / 100.0, 0.0), 1.0)
        self.ram_label.set_text(ram_text)
        self.ram_label.set_visible(True)
        self.ram_bar.set_value(ram_fraction)
        self.ram_bar.set_tooltip_text(f"Memory Utilization: {ram_text}")

    def _apply_guardrails_summary(self, sandbox: SandboxInfo):
        badges = []
        if sandbox.host_egress_lockdown:
            badges.append("Host Lockdown")
        if sandbox.protect_git_hooks:
            badges.append("Hooks :ro")
        if sandbox.protect_env_files:
            badges.append(".env :ro")
        if sandbox.idle_timeout_minutes > 0:
            badges.append(f"Idle {sandbox.idle_timeout_minutes}m")
        else:
            badges.append("Never Sleep")
        sec_cnt = len(sandbox.secret_keys or [])
        if sec_cnt > 0:
            badges.append(f"{sec_cnt} Secret{'s' if sec_cnt != 1 else ''}")

        fb_parent = self.guard_box.get_parent()
        if not badges:
            self.guard_box.set_visible(False)
            if fb_parent:
                fb_parent.set_visible(False)
            return

        self.guard_box.set_visible(True)
        if fb_parent:
            fb_parent.set_visible(True)
        self.guard_pill.set_text(" · ".join(badges))

    def _apply_status_visuals(self, status: str):
        for cls in ("success", "warning", "dim-label"):
            self.status_icon.remove_css_class(cls)
            self.status_pill.remove_css_class(cls)

        if status == "running":
            self.status_icon.set_from_icon_name("emblem-ok-symbolic")
            self.status_icon.add_css_class("success")
            self.status_pill.set_text("RUNNING")
            self.status_pill.add_css_class("success")
        elif status == "paused":
            self.status_icon.set_from_icon_name("media-playback-pause-symbolic")
            self.status_icon.add_css_class("warning")
            self.status_pill.set_text("PAUSED")
            self.status_pill.add_css_class("warning")
        else:
            self.status_icon.set_from_icon_name("media-playback-stop-symbolic")
            self.status_icon.add_css_class("dim-label")
            self.status_pill.set_text("STOPPED")
            self.status_pill.add_css_class("dim-label")

    def _apply_toggle_visuals(self, status: str):
        self.toggle_btn.set_sensitive(True)
        if hasattr(self, "pause_btn") and self.pause_btn:
            self.pause_btn.set_sensitive(True)
            self.pause_btn.set_visible(status == "running")

        if status == "running":
            self.toggle_btn.set_icon_name("media-playback-stop-symbolic")
            self.toggle_btn.set_tooltip_text("Stop Sandbox")
            self.toggle_btn.remove_css_class("suggested-action")
            self.toggle_btn.add_css_class("destructive-action")
        elif status == "paused":
            self.toggle_btn.set_icon_name("media-playback-start-symbolic")
            self.toggle_btn.set_tooltip_text("Resume Paused MicroVM")
            self.toggle_btn.remove_css_class("destructive-action")
            self.toggle_btn.add_css_class("suggested-action")
        else:
            self.toggle_btn.set_icon_name("media-playback-start-symbolic")
            self.toggle_btn.set_tooltip_text("Start Sandbox")
            self.toggle_btn.remove_css_class("destructive-action")
            self.toggle_btn.remove_css_class("suggested-action")

    def _apply_lifecycle_visuals(self, is_persistent: bool):
        for cls in ("accent", "dim-label"):
            self.mode_icon.remove_css_class(cls)
            self.mode_pill.remove_css_class(cls)
        if is_persistent:
            self.mode_icon.set_from_icon_name("drive-harddisk-symbolic")
            self.mode_icon.add_css_class("accent")
            self.mode_pill.set_text("Persistent")
            self.mode_pill.add_css_class("accent")
        else:
            self.mode_icon.set_from_icon_name("user-trash-symbolic")
            self.mode_icon.add_css_class("dim-label")
            self.mode_pill.set_text("Ephemeral")
            self.mode_pill.add_css_class("dim-label")

    def _apply_net_summary(self, policy: NetworkPolicy):
        prof = policy.profile if policy else "full"
        allowed_cnt = len(policy.allowed_domains) if policy else 0
        denied_cnt = len(policy.denied_domains) if policy else 0

        friendly = PROFILE_DISPLAY_NAMES.get(prof, prof.title())
        parts = [f"Egress: {friendly}"]
        if prof == "custom":
            parts.append(f"{allowed_cnt} allowed")
        elif allowed_cnt > 0 and prof != "full":
            parts.append(f"+{allowed_cnt} allowed")
        if denied_cnt > 0:
            parts.append(f"{denied_cnt} blocked")

        for cls in ("accent", "warning", "error", "dim-label"):
            self.net_pill.remove_css_class(cls)
            self.net_icon.remove_css_class(cls)

        if prof == "offline":
            icon_name = "network-wireless-offline-symbolic"
            sem_cls = "error"
        elif prof in ("ai-only", "dev-common", "custom"):
            icon_name = "security-high-symbolic"
            sem_cls = "accent"
        elif denied_cnt > 0:
            icon_name = "security-high-symbolic"
            sem_cls = "warning"
        else:
            icon_name = "network-workgroup-symbolic"
            sem_cls = "dim-label"

        self.net_icon.set_from_icon_name(icon_name)
        self.net_icon.add_css_class(sem_cls)
        self.net_pill.set_text(" · ".join(parts))
        self.net_pill.add_css_class(sem_cls)
        self.net_pill.set_tooltip_text(self._format_net_tooltip(policy))

    def update_data(self, sandbox: SandboxInfo):
        self.sandbox = sandbox
        status = (sandbox.status or "stopped").lower()

        self.name_label.set_text(sandbox.name)
        self._apply_status_visuals(status)
        self._update_connect_btn(status)
        self._apply_toggle_visuals(status)
        self._apply_lifecycle_visuals(sandbox.is_persistent)
        self._apply_net_summary(sandbox.network_policy)
        self.hw_pill.set_text(self._format_hw_text(sandbox))
        self._apply_guardrails_summary(sandbox)
        self.img_pill.set_text(sandbox.base_image.split("/")[-1])
        self.dir_label.set_text(sandbox.dir_path)
        self.dir_label.set_tooltip_text(sandbox.dir_path)
        self._update_resource_bars(sandbox, status)

        ports_key = (
            sandbox.status,
            sandbox.ssh_port,
            tuple((p.host_port, p.guest_port, p.is_tunnel) for p in sandbox.all_ports),
        )
        if ports_key != self._last_ports_key:
            self._rebuild_ports()

    def cleanup(self):
        if hasattr(self, "card_gesture") and self.card_gesture:
            self.remove_controller(self.card_gesture)
            self.card_gesture = None
        if getattr(self, "connect_btn", None) is not None:
            self.connect_btn.set_menu_model(None)
        if getattr(self, "more_btn", None) is not None:
            self.more_btn.set_menu_model(None)
            self.more_btn = None
        self.insert_action_group("card", None)
        self._action_group = None
        if self.ports_box:
            while child := self.ports_box.get_first_child():
                self.ports_box.remove(child)
        self.set_child(None)
        self.connect_btn = None
        self.connect_content = None
        self.connect_dropdown_btn = None
        self.toggle_btn = None
        self.pause_btn = None
        self.changes_btn = None
        self.edit_btn = None
        self.traffic_btn = None
        self.recreate_btn = None
        self._recreate_dialog = None
        self._recreate_confirm_check = None
        self._recreate_pull_check = None
        self._recreate_vol_check = None
        self.ports_box = None
        self.telem_box = None
        self.cpu_bar = None
        self.cpu_label = None
        self.ram_bar = None
        self.ram_label = None
        self.mem_label = None
        self.guard_box = None
        self.guard_icon = None
        self.guard_pill = None
        self.status_icon = None
        self.status_pill = None
        self.name_label = None
        self.mode_icon = None
        self.mode_pill = None
        self.net_icon = None
        self.net_pill = None
        self.hw_pill = None
        self.img_pill = None
        self.dir_label = None
        self.parent_window = None
        self.on_updated = None

    def _setup_split_dropdown_icon(self, split_btn: Adw.SplitButton) -> Optional[Gtk.MenuButton]:
        """Configure the dropdown MenuButton of Adw.SplitButton with a standard arrow-down icon.

        Ensures cross-theme visibility on Fedora and other distros where default GtkBuiltinIcon
        has no visible symbol.
        """
        icon_name = _resolve_dropdown_arrow_icon()
        child = split_btn.get_first_child()
        while child:
            if isinstance(child, Gtk.MenuButton):
                child.set_icon_name(icon_name)
                return child
            child = child.get_next_sibling()
        return None

    def _update_connect_btn(self, status: str):
        if status == "running":
            self.connect_btn.set_tooltip_text(
                f"Quick Connect - Open SSH terminal to {self.sandbox.name} (port {self.sandbox.ssh_port})"
            )
            self.connect_btn.remove_css_class("flat")
            self.connect_btn.add_css_class("suggested-action")
        elif status == "paused":
            self.connect_btn.set_tooltip_text(
                f"Quick Connect - Resume '{self.sandbox.name}' and open SSH terminal"
            )
            self.connect_btn.remove_css_class("suggested-action")
            self.connect_btn.add_css_class("flat")
        else:
            self.connect_btn.set_tooltip_text(
                f"Quick Connect - Start '{self.sandbox.name}' and open SSH terminal"
            )
            self.connect_btn.remove_css_class("suggested-action")
            self.connect_btn.add_css_class("flat")

    def _format_net_tooltip(self, policy: NetworkPolicy) -> str:
        prof = policy.profile if policy else "full"
        prof_info = NETWORK_PROFILES.get(prof, {})
        prof_name = prof_info.get("name", prof)
        lines = [f"Egress Policy: {prof_name}"]
        if prof_info.get("description"):
            lines.append(prof_info["description"])

        effective = get_profile_domains(prof, policy.allowed_domains if policy else None)
        if effective:
            lines.append(f"Effective allowed domains ({len(effective)}):")
            for d in effective[:6]:
                lines.append(f"  • {d}")
            if len(effective) > 6:
                lines.append(f"  … and {len(effective) - 6} more")
        elif prof == "offline":
            lines.append("All external internet egress is blocked.")

        if policy and policy.denied_domains:
            lines.append(f"Blocked domains ({len(policy.denied_domains)}):")
            for d in policy.denied_domains[:6]:
                lines.append(f"  • {d}")
            if len(policy.denied_domains) > 6:
                lines.append(f"  … and {len(policy.denied_domains) - 6} more")
        return "\n".join(lines)

    def _rebuild_ports(self):
        if not self.ports_box:
            return
        while child := self.ports_box.get_first_child():
            self.ports_box.remove(child)

        self._last_ports_key = (
            self.sandbox.status,
            self.sandbox.ssh_port,
            tuple((p.host_port, p.guest_port, p.is_tunnel) for p in self.sandbox.all_ports),
        )

        # SSH endpoint button
        ssh_btn = Gtk.Button()
        ssh_btn.add_css_class("flat")
        ssh_btn.add_css_class("caption")
        ssh_btn.add_css_class("monospace")
        ssh_btn.add_css_class("numeric")
        ssh_btn.set_tooltip_text(f"Connect via SSH: ssh {self.sandbox.name}")
        ssh_content = Adw.ButtonContent(
            icon_name="utilities-terminal-symbolic",
            label=f":{self.sandbox.ssh_port} SSH",
        )
        ssh_btn.set_child(ssh_content)
        ssh_btn.connect("clicked", self._on_ssh_clicked)
        self._append_flow_item(self.ports_box, ssh_btn)

        # Mapped web ports & dynamic tunnels
        for p in self.sandbox.all_ports:
            port_btn = Gtk.Button()
            port_btn.add_css_class("flat")
            port_btn.add_css_class("caption")
            port_btn.add_css_class("monospace")
            port_btn.add_css_class("numeric")
            port_content = Adw.ButtonContent(
                icon_name="web-browser-symbolic",
                label=f":{p.host_port} → :{p.guest_port}",
            )
            port_btn.set_child(port_content)
            port_btn.set_tooltip_text(f"Open http://127.0.0.1:{p.host_port}")
            port_btn.connect("clicked", lambda _b, hp=p.host_port: self._open_browser(hp))

            if p.is_tunnel:
                tunnel_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
                tunnel_box.add_css_class("linked")
                tunnel_box.append(port_btn)

                close_tun_btn = Gtk.Button(icon_name="window-close-symbolic")
                close_tun_btn.add_css_class("flat")
                close_tun_btn.add_css_class("caption")
                close_tun_btn.set_tooltip_text(f"Disconnect tunnel :{p.host_port} → :{p.guest_port}")
                close_tun_btn.connect(
                    "clicked",
                    lambda _b, gp=p.guest_port: self._on_unforward_port_clicked(gp),
                )
                tunnel_box.append(close_tun_btn)
                self._append_flow_item(self.ports_box, tunnel_box)
            else:
                self._append_flow_item(self.ports_box, port_btn)

        # "+ Forward Port" button when running
        if self.sandbox.status == "running":
            add_port_btn = Gtk.Button(label="+ Forward Port")
            add_port_btn.set_tooltip_text("Forward a guest TCP port to localhost")
            add_port_btn.add_css_class("flat")
            add_port_btn.add_css_class("caption")
            add_port_btn.connect("clicked", self._on_forward_port_clicked)
            self._append_flow_item(self.ports_box, add_port_btn)

    def _on_unforward_port_clicked(self, guest_port: int):
        sandbox_name = self.sandbox.name

        def worker():
            return self.manager.unforward_port(sandbox_name, guest_port)

        def on_done(res):
            ok, msg = res
            if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
                self.parent_window.toast_overlay.add_toast(Adw.Toast.new(msg))
            if ok and self.on_updated:
                self.on_updated()

        run_async(worker, on_success=on_done)

    def _on_keep_awake_clicked(self, _arg=None):
        indefinite = (self.sandbox.idle_timeout_minutes > 0)
        ok, msg = self.manager.keep_awake(self.sandbox.name, indefinite=indefinite, extend_minutes=30)
        if not indefinite:
            self.sandbox.idle_timeout_minutes = 30
            self.manager.save_state()
        if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
            self.parent_window.toast_overlay.add_toast(Adw.Toast.new(msg))
        if self.on_updated:
            self.on_updated()

    def _on_toggle_clicked(self, btn):
        st = (self.sandbox.status or "stopped").lower()
        if st == "running":
            self._on_stop_clicked(btn)
        elif st == "paused":
            self._on_resume_clicked(btn)
        else:
            self._on_start_clicked(btn)

    def _on_pause_or_resume_action(self, _btn):
        st = (self.sandbox.status or "stopped").lower()
        if st == "running":
            self._on_pause_clicked(self.pause_btn)
        elif st == "paused":
            self._on_resume_clicked(self.toggle_btn)

    def _on_pause_clicked(self, btn):
        if btn:
            btn.set_sensitive(False)

        def worker():
            if hasattr(self.manager, "pause_sandbox"):
                return self.manager.pause_sandbox(self.sandbox.name)
            return False, "Pause not supported"

        def on_done(res):
            ok, msg = res
            if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
                self.parent_window.toast_overlay.add_toast(Adw.Toast.new(msg))
            if self.on_updated:
                self.on_updated()

        run_async(worker, on_success=on_done)

    def _on_resume_clicked(self, btn):
        if btn:
            btn.set_sensitive(False)

        def worker():
            if hasattr(self.manager, "unpause_sandbox"):
                return self.manager.unpause_sandbox(self.sandbox.name)
            return self.manager.start_sandbox(self.sandbox.name, detach=True)

        def on_done(res):
            ok, msg = res
            if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
                self.parent_window.toast_overlay.add_toast(Adw.Toast.new(msg))
            if self.on_updated:
                self.on_updated()

        run_async(worker, on_success=on_done)

    def _notify_result(self, res, success_msg: Optional[str] = None):
        if not self.parent_window or not hasattr(self.parent_window, "toast_overlay"):
            return
        if isinstance(res, tuple) and len(res) >= 2:
            ok, msg = res[0], res[1]
            if not ok:
                self.parent_window.toast_overlay.add_toast(Adw.Toast.new(f"Error: {msg}"))
            elif success_msg:
                self.parent_window.toast_overlay.add_toast(Adw.Toast.new(success_msg))
        elif isinstance(res, Exception):
            self.parent_window.toast_overlay.add_toast(Adw.Toast.new(f"Error: {res}"))

    def _on_start_clicked(self, btn):
        if btn:
            btn.set_sensitive(False)

        def worker():
            return self.manager.start_sandbox(self.sandbox.name, detach=True)

        def on_done(res):
            if btn:
                btn.set_sensitive(True)
            self._notify_result(res)
            if self.on_updated:
                self.on_updated()

        def on_err(exc):
            if btn:
                btn.set_sensitive(True)
            self._notify_result(exc)

        run_async(worker, on_success=on_done, on_error=on_err)

    def _on_stop_clicked(self, btn):
        if btn:
            btn.set_sensitive(False)

        def worker():
            return self.manager.stop_sandbox(self.sandbox.name)

        def on_done(res):
            if btn:
                btn.set_sensitive(True)
            self._notify_result(res)
            if self.on_updated:
                self.on_updated()

        def on_err(exc):
            if btn:
                btn.set_sensitive(True)
            self._notify_result(exc)

        run_async(worker, on_success=on_done, on_error=on_err)

    def _on_restart_clicked(self, btn):
        if btn:
            btn.set_sensitive(False)

        def worker():
            return self.manager.restart_sandbox(self.sandbox.name)

        def on_done(res):
            if btn:
                btn.set_sensitive(True)
            self._notify_result(res)
            if self.on_updated:
                self.on_updated()

        def on_err(exc):
            if btn:
                btn.set_sensitive(True)
            self._notify_result(exc)

        run_async(worker, on_success=on_done, on_error=on_err)

    def _on_workspace_changes_clicked(self, _btn):
        if not self.parent_window:
            return
        from ..core.workspace_diff import WorkspaceSnapshotManager
        from .workspace_diff_dialog import WorkspaceChangesDialog

        snap_mgr = getattr(self.manager, "snapshots", None) or WorkspaceSnapshotManager()
        dialog = WorkspaceChangesDialog(
            self.parent_window,
            snap_mgr,
            self.sandbox.name,
            self.sandbox.dir_path,
            on_changed=self.on_updated,
        )
        dialog.present()

    def _on_edit_clicked(self, _btn):
        if not self.parent_window:
            return
        dialog = EditSandboxDialog(
            self.parent_window,
            self.manager,
            self.sandbox,
            on_saved=self.on_updated,
        )
        dialog.present()

    def _on_egress_traffic_clicked(self, _btn):
        if not self.parent_window:
            return
        dialog = EgressTrafficDialog(
            self.parent_window,
            self.manager,
            sandbox_name=self.sandbox.name,
            on_policy_updated=self.on_updated,
        )
        dialog.present()

    def _on_logs_clicked(self, _btn):
        if not self.parent_window:
            return
        dialog = LogsDialog(self.parent_window, self.manager, self.sandbox.name)
        dialog.present()

    def _on_telemetry_clicked(self, _btn):
        if not self.parent_window:
            return
        dialog = TelemetryDialog(self.parent_window, self.manager, self.sandbox.name)
        dialog.present()

    def _on_forward_port_clicked(self, _btn):
        if not self.parent_window:
            return
        dialog = PortForwardDialog(
            self.parent_window,
            self.manager,
            self.sandbox.name,
            on_forwarded=self.on_updated,
        )
        dialog.present()

    def _on_card_double_clicked(self, _gesture, n_press, _x, _y):
        if n_press == 2 and self.connect_btn:
            self._on_quick_connect_clicked(self.connect_btn)

    def _ensure_running_then(self, callback: Callable[[], None]):
        st = (self.sandbox.status or "stopped").lower()
        if st == "running":
            callback()
            return

        verb = "Resuming" if st == "paused" else "Starting"
        if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
            self.parent_window.toast_overlay.add_toast(
                Adw.Toast.new(f"{verb} '{self.sandbox.name}'…")
            )
        if self.connect_btn:
            self.connect_btn.set_sensitive(False)
        if self.toggle_btn:
            self.toggle_btn.set_sensitive(False)

        def worker():
            if st == "paused" and hasattr(self.manager, "unpause_sandbox"):
                return self.manager.unpause_sandbox(self.sandbox.name)
            return self.manager.start_sandbox(self.sandbox.name, detach=True)

        def on_done(res):
            if self.connect_btn:
                self.connect_btn.set_sensitive(True)
            if self.toggle_btn:
                self.toggle_btn.set_sensitive(True)
            ok, msg = res
            if ok:
                if self.on_updated:
                    self.on_updated()
                callback()
            elif self.parent_window and hasattr(self.parent_window, "toast_overlay"):
                self.parent_window.toast_overlay.add_toast(
                    Adw.Toast.new(f"Failed to start: {msg}")
                )

        run_async(worker, on_success=on_done)

    def _on_quick_connect_clicked(self, _btn):
        self._ensure_running_then(self._launch_terminal)

    def _on_open_ide_requested(self, ide_key: str):
        if ide_key == "terminal":
            self._ensure_running_then(self._launch_terminal)
            return
        self._ensure_running_then(lambda: self._launch_selected_ide(ide_key))

    def _launch_selected_ide(self, ide_key: str):
        ok, msg = launch_ide(
            self.sandbox.name,
            ide_key,
            remote_path="/workspace",
            ssh_port=self.sandbox.ssh_port,
        )
        if not ok:
            try:
                clipboard = self.get_display().get_clipboard()
                clipboard.set(f"ssh {self.sandbox.name}")
            except Exception:
                pass
        if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
            self.parent_window.toast_overlay.add_toast(Adw.Toast.new(msg))

    def _launch_terminal(self):
        from ..core.ssh import launch_sandbox_terminal

        ok, _msg = launch_sandbox_terminal(
            self.sandbox.name,
            container_name=self.sandbox.container_name,
            ssh_port=self.sandbox.ssh_port,
        )
        if ok:
            if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
                self.parent_window.toast_overlay.add_toast(
                    Adw.Toast.new(f"Terminal connected: {self.sandbox.name}")
                )
        else:
            try:
                clipboard = self.get_display().get_clipboard()
                clipboard.set(f"ssh {self.sandbox.name}")
            except Exception:
                pass
            if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
                self.parent_window.toast_overlay.add_toast(
                    Adw.Toast.new(
                        f"No terminal emulator found. Copied 'ssh {self.sandbox.name}' to clipboard."
                    )
                )

    def _on_ssh_clicked(self, btn):
        self._on_quick_connect_clicked(btn)

    def _open_browser(self, host_port: int):
        webbrowser.open(f"http://127.0.0.1:{host_port}")

    def _on_recreate_clicked(self, _btn):
        if not self.parent_window:
            return

        extra_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)

        pull_check = Gtk.CheckButton(
            label="Pull/verify latest image version",
            active=True,
        )
        extra_box.append(pull_check)

        vol_check = Gtk.CheckButton(
            label="Wipe persistent internal data volumes (fresh slate)",
            active=True,
        )
        extra_box.append(vol_check)

        confirm_check = Gtk.CheckButton(
            label="I confirm I want to wipe and recreate this sandbox",
            active=False,
        )
        extra_box.append(confirm_check)

        def on_response(response: str):
            if response == "recreate":
                if not confirm_check.get_active():
                    return
                pull_img = pull_check.get_active()
                wipe_vols = vol_check.get_active()
                sandbox_name = self.sandbox.name

                if self.recreate_btn:
                    self.recreate_btn.set_sensitive(False)
                if self.toggle_btn:
                    self.toggle_btn.set_sensitive(False)
                if self.parent_window and hasattr(self.parent_window, "toast_overlay"):
                    self.parent_window.toast_overlay.add_toast(
                        Adw.Toast.new(f"Recreating '{sandbox_name}'…")
                    )

                def worker():
                    return self.manager.recreate_sandbox(
                        sandbox_name,
                        pull_image=pull_img,
                        wipe_volumes=wipe_vols,
                        start_after=True,
                    )

                def on_done(res):
                    if self.recreate_btn:
                        self.recreate_btn.set_sensitive(True)
                    if self.toggle_btn:
                        self.toggle_btn.set_sensitive(True)
                    self._notify_result(res, success_msg=f"Recreated '{sandbox_name}'")
                    if self.on_updated:
                        self.on_updated()

                def on_err(exc):
                    if self.recreate_btn:
                        self.recreate_btn.set_sensitive(True)
                    if self.toggle_btn:
                        self.toggle_btn.set_sensitive(True)
                    self._notify_result(exc)

                run_async(worker, on_success=on_done, on_error=on_err)

        dlg = show_alert_dialog(
            parent_window=self.parent_window,
            heading=f"Recreate '{self.sandbox.name}'?",
            body=(
                "This will stop and remove the microVM container, then build and start a fresh one "
                "with the exact same configuration (image, hardware, egress policy, and port forwarding).\n\n"
                "Host workspace files are preserved."
            ),
            responses=[
                ("cancel", "Cancel"),
                ("recreate", "Recreate Sandbox", Adw.ResponseAppearance.DESTRUCTIVE),
            ],
            on_response=on_response,
            default_response="cancel",
            close_response="cancel",
            extra_child=extra_box,
        )
        self._recreate_dialog = dlg
        self._recreate_confirm_check = confirm_check
        self._recreate_pull_check = pull_check
        self._recreate_vol_check = vol_check
        if hasattr(dlg, "set_response_enabled"):
            dlg.set_response_enabled("recreate", False)
            confirm_check.connect(
                "toggled",
                lambda cb: dlg.set_response_enabled("recreate", cb.get_active()),
            )

    def _on_delete_clicked(self, _btn):
        if not self.parent_window:
            return
        vol_check = Gtk.CheckButton(
            label="Also remove persistent agent & Docker data volumes"
        )

        def on_response(response: str):
            if response == "delete":
                delete_vols = vol_check.get_active()
                sandbox_name = self.sandbox.name

                def worker():
                    return self.manager.delete_sandbox(sandbox_name, delete_volumes=delete_vols)

                def on_done(res):
                    self._notify_result(res, success_msg=f"Deleted '{sandbox_name}'")
                    if self.on_updated:
                        self.on_updated()

                def on_err(exc):
                    self._notify_result(exc)

                run_async(worker, on_success=on_done, on_error=on_err)

        show_alert_dialog(
            parent_window=self.parent_window,
            heading=f"Delete '{self.sandbox.name}'?",
            body="This removes the microVM container and SSH host entry. Host workspace files are never modified.",
            responses=[
                ("cancel", "Cancel"),
                ("delete", "Delete", Adw.ResponseAppearance.DESTRUCTIVE),
            ],
            on_response=on_response,
            default_response="cancel",
            close_response="cancel",
            extra_child=vol_check,
        )
