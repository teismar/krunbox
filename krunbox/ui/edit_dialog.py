"""
Native Libadwaita dialog for editing an existing sandbox's name, CPU/RAM resources,
live network egress policy, git/dotfile guardrails, idle timer, budgets, and scoped secrets.
"""

from typing import Callable, Dict, List, Optional, Set, Tuple
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from ..core.config import NETWORK_PROFILES
from ..core.manager import SandboxManager
from ..core.network import is_safe_domain_or_ip
from ..core.sandbox import NetworkPolicy, SandboxInfo
from ..core.secrets import SecretVaultManager, is_valid_env_key, sanitize_env_value
from .egress_dialog import EgressTrafficDialog
from .worker import run_async


class EditSandboxDialog(Adw.Window):
    def __init__(
        self,
        parent_window: Gtk.Window,
        manager: SandboxManager,
        sandbox: SandboxInfo,
        on_saved: Optional[Callable[[], None]] = None,
    ):
        super().__init__(modal=True, transient_for=parent_window)
        self.parent_window = parent_window
        self.manager = manager
        self.sandbox = sandbox
        self.on_saved = on_saved
        self._closed = False
        self._builtin_domain_rows: List[Gtk.Widget] = []
        self._env_rows: List[Gtk.Widget] = []

        self.secret_mgr: SecretVaultManager = getattr(manager, "secrets", None) or SecretVaultManager()

        self._orig_cpus = int(sandbox.cpus)
        self._orig_ram_gib = max(1, round(sandbox.ram_mib / 1024))
        self._orig_git_hooks = bool(sandbox.protect_git_hooks)
        self._orig_git_config = bool(sandbox.protect_git_config)
        self._orig_env_files = bool(sandbox.protect_env_files)
        self._orig_host_lockdown = bool(sandbox.host_egress_lockdown)

        self._edited_env: Dict[str, str] = dict(sandbox.env_vars or {})
        self._existing_secret_keys: Set[str] = set(
            self.secret_mgr.list_secret_keys(sandbox.name, known_keys=sandbox.secret_keys)
        )
        self._new_secret_values: Dict[str, str] = {}
        self._removed_secret_keys: Set[str] = set()

        self.set_title(f"Edit Sandbox - {sandbox.name}")
        self.set_default_size(620, 740)

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

        self.save_btn = Gtk.Button(label="Save Changes")
        self.save_btn.add_css_class("suggested-action")
        self.save_btn.connect("clicked", self._on_save_clicked)
        header.pack_end(self.save_btn)

        # Contextual banner shown when running sandbox's CPU/RAM or mount/lockdown settings change
        self.restart_banner = Adw.Banner(
            title="Changing CPU, RAM, or mount/lockdown guardrails will restart this running sandbox"
        )
        self.restart_banner.set_use_markup(False)
        self.restart_banner.set_revealed(False)
        toolbar_view.add_top_bar(self.restart_banner)

        # Validation / Save error banner
        self.error_banner = Adw.Banner()
        self.error_banner.set_use_markup(False)
        self.error_banner.set_revealed(False)
        toolbar_view.add_top_bar(self.error_banner)

        page = Adw.PreferencesPage()
        toolbar_view.set_content(page)

        # ------------------------------------------------------------------
        # Group 1: Sandbox Identity & Workspace Snapshot Diff
        # ------------------------------------------------------------------
        self.group_identity = Adw.PreferencesGroup(title="Sandbox Identity")
        page.add(self.group_identity)

        self.name_row = Adw.EntryRow(title="Sandbox Name")
        self.name_row.set_text(sandbox.name)

        self.sanitized_preview_label = Gtk.Label(valign=Gtk.Align.CENTER)
        self.sanitized_preview_label.add_css_class("caption")
        self.sanitized_preview_label.add_css_class("dim-label")
        self.sanitized_preview_label.add_css_class("monospace")
        self.name_row.add_suffix(self.sanitized_preview_label)
        self.name_row.connect("changed", self._on_name_changed)
        self.group_identity.add(self.name_row)
        self._update_name_preview(sandbox.name)

        self.dir_row = Adw.ActionRow(
            title="Workspace Directory",
            subtitle=GLib.markup_escape_text(sandbox.dir_path),
        )
        self.dir_row.set_subtitle_selectable(True)
        self.dir_row.add_css_class("property")

        lifecycle_lbl = Gtk.Label(
            label="Persistent" if sandbox.is_persistent else "Ephemeral",
            valign=Gtk.Align.CENTER,
        )
        lifecycle_lbl.add_css_class("caption-heading")
        lifecycle_lbl.add_css_class("accent" if sandbox.is_persistent else "dim-label")
        self.dir_row.add_suffix(lifecycle_lbl)
        self.group_identity.add(self.dir_row)

        self.changes_row = Adw.ActionRow(
            title="Workspace Changes &amp; Rollback…",
            subtitle="Inspect modified files, preview unified diffs, or revert agent edits",
        )
        self.changes_row.set_activatable(True)
        self.changes_row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
        self.changes_row.connect("activated", self._on_open_workspace_changes)
        self.group_identity.add(self.changes_row)

        # ------------------------------------------------------------------
        # Group 2: Compute Resources
        # ------------------------------------------------------------------
        group_compute = Adw.PreferencesGroup(
            title="Compute Resources",
            description="Allocated virtual CPUs and memory for this microVM",
        )
        page.add(group_compute)

        self.cpu_row = Adw.SpinRow.new_with_range(1, 32, 1)
        self.cpu_row.set_title("Virtual CPUs")
        self.cpu_row.set_subtitle("Default: 4 vCPUs")
        self.cpu_row.set_value(self._orig_cpus)
        self.cpu_row.connect("notify::value", self._update_restart_banner)
        group_compute.add(self.cpu_row)

        self.ram_row = Adw.SpinRow.new_with_range(1, 64, 1)
        self.ram_row.set_title("Memory (GiB)")
        self.ram_row.set_subtitle("Default: 4 GiB")
        self.ram_row.set_value(self._orig_ram_gib)
        self.ram_row.connect("notify::value", self._update_restart_banner)
        group_compute.add(self.ram_row)

        # ------------------------------------------------------------------
        # Group 3: Network Egress Policy & Host Lockdown
        # ------------------------------------------------------------------
        self.group_network = Adw.PreferencesGroup(
            title="Network Egress Policy",
            description="Changes to egress rules apply live to running sandboxes without restarting",
        )
        page.add(self.group_network)

        self.net_keys = list(NETWORK_PROFILES.keys())
        net_labels = [NETWORK_PROFILES[k]["name"] for k in self.net_keys]
        self.net_combo = Adw.ComboRow(
            title="Outbound Access Profile",
            subtitle="Applies live without restart",
        )
        self.net_combo.set_model(Gtk.StringList.new(net_labels))

        cur_profile = sandbox.network_policy.profile if sandbox.network_policy else "full"
        prof_idx = self.net_keys.index(cur_profile) if cur_profile in self.net_keys else 0
        self.net_combo.set_selected(prof_idx)
        self.net_combo.connect("notify::selected", self._on_profile_changed)
        self.group_network.add(self.net_combo)

        self.builtin_expander = Adw.ExpanderRow(title="Included Profile Domains")
        self.group_network.add(self.builtin_expander)

        # Custom Allowed Domains
        self.whitelist_entry = Adw.EntryRow(title="Custom Allowed Domains (comma-separated)")
        allowed_init = ", ".join(sandbox.network_policy.allowed_domains) if sandbox.network_policy else ""
        self.whitelist_entry.set_text(allowed_init)

        self.whitelist_warn_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        self.whitelist_warn_icon.add_css_class("warning")
        self.whitelist_warn_icon.set_visible(False)
        self.whitelist_entry.add_suffix(self.whitelist_warn_icon)
        self.whitelist_entry.connect("changed", self._on_domains_changed)
        self.group_network.add(self.whitelist_entry)

        # Blocked Domains / Blacklist
        self.blacklist_entry = Adw.EntryRow(title="Blocked Domains / Blacklist (comma-separated)")
        denied_init = ", ".join(sandbox.network_policy.denied_domains) if sandbox.network_policy else ""
        self.blacklist_entry.set_text(denied_init)

        self.blacklist_warn_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        self.blacklist_warn_icon.add_css_class("warning")
        self.blacklist_warn_icon.set_visible(False)
        self.blacklist_entry.add_suffix(self.blacklist_warn_icon)
        self.blacklist_entry.connect("changed", self._on_domains_changed)
        self.group_network.add(self.blacklist_entry)

        self.host_lockdown_switch = Adw.SwitchRow(
            title="Host-Boundary Egress Lockdown",
            subtitle="Enforce firewall in host netns and drop guest CAP_NET_ADMIN",
        )
        self.host_lockdown_switch.set_active(self._orig_host_lockdown)
        self.host_lockdown_switch.connect("notify::active", self._update_restart_banner)
        self.group_network.add(self.host_lockdown_switch)

        # View Outbound Traffic ActionRow
        self.traffic_row = Adw.ActionRow(
            title="View Outbound Traffic…",
            subtitle="Inspect called sites, call frequency, and live policy decisions",
        )
        self.traffic_row.set_activatable(True)
        self.traffic_row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
        self.traffic_row.connect("activated", self._on_open_traffic)
        self.group_network.add(self.traffic_row)

        # ------------------------------------------------------------------
        # Group 4: Workspace Git & Dotfile Guardrails
        # ------------------------------------------------------------------
        self.group_guardrails = Adw.PreferencesGroup(
            title="Workspace Git &amp; Dotfile Guardrails",
            description="Read-only bind-mounts protecting host git hooks, config, and .env files",
        )
        page.add(self.group_guardrails)

        self.git_hooks_switch = Adw.SwitchRow(
            title="Protect .git/hooks (Read-Only)",
            subtitle="Prevent agents from planting malicious host git hooks",
        )
        self.git_hooks_switch.set_active(self._orig_git_hooks)
        self.git_hooks_switch.connect("notify::active", self._update_restart_banner)
        self.group_guardrails.add(self.git_hooks_switch)

        self.git_config_switch = Adw.SwitchRow(
            title="Protect .git/config (Read-Only)",
            subtitle="Lock git remotes, aliases, and core.sshCommand",
        )
        self.git_config_switch.set_active(self._orig_git_config)
        self.git_config_switch.connect("notify::active", self._update_restart_banner)
        self.group_guardrails.add(self.git_config_switch)

        self.env_files_switch = Adw.SwitchRow(
            title="Protect Workspace .env Files (Read-Only)",
            subtitle="Mount existing .env and .env.* files read-only",
        )
        self.env_files_switch.set_active(self._orig_env_files)
        self.env_files_switch.connect("notify::active", self._update_restart_banner)
        self.group_guardrails.add(self.env_files_switch)

        # ------------------------------------------------------------------
        # Group 5: Idle Sleep & Budget Guardrails
        # ------------------------------------------------------------------
        self.group_budgets = Adw.PreferencesGroup(
            title="Idle Sleep and Budget Guardrails",
            description="Automatic idle sleep and AI token/USD spend ceilings",
        )
        page.add(self.group_budgets)

        self.idle_timeout_row = Adw.SpinRow.new_with_range(0, 480, 5)
        self.idle_timeout_row.set_title("Idle Sleep Timeout (minutes)")
        self.idle_timeout_row.set_subtitle("0 = Never Sleep (runs indefinitely); or set auto-sleep minutes")
        self.idle_timeout_row.set_value(max(0, int(sandbox.idle_timeout_minutes)))
        self.group_budgets.add(self.idle_timeout_row)

        self.idle_actions = ["stop", "pause"]
        self.idle_action_combo = Adw.ComboRow(
            title="Idle Sleep Action",
            subtitle="Action on idle timeout",
        )
        self.idle_action_combo.set_model(Gtk.StringList.new(["Stop Sandbox", "Pause MicroVM"]))
        cur_idle = sandbox.idle_action if sandbox.idle_action in self.idle_actions else "stop"
        self.idle_action_combo.set_selected(self.idle_actions.index(cur_idle))
        self.group_budgets.add(self.idle_action_combo)

        self.max_tokens_row = Adw.SpinRow.new_with_range(0, 50_000_000, 50_000)
        self.max_tokens_row.set_title("AI Token Budget Limit")
        self.max_tokens_row.set_subtitle("0 = Unlimited cumulative tokens")
        self.max_tokens_row.set_value(max(0, int(sandbox.max_tokens_budget)))
        self.group_budgets.add(self.max_tokens_row)

        self.max_cost_row = Adw.SpinRow.new_with_range(0, 1000, 1)
        self.max_cost_row.set_title("Max AI Spend Budget (USD)")
        self.max_cost_row.set_subtitle("0 = Unlimited estimated USD spend")
        self.max_cost_row.set_value(max(0, float(sandbox.max_cost_usd_budget)))
        self.group_budgets.add(self.max_cost_row)

        self.budget_actions = ["alert", "pause", "stop"]
        self.budget_action_combo = Adw.ComboRow(
            title="Budget Exceeded Action",
            subtitle="Response when spend cap is reached",
        )
        self.budget_action_combo.set_model(
            Gtk.StringList.new(["Desktop Alert Only", "Pause MicroVM", "Stop Sandbox"])
        )
        cur_b_act = sandbox.budget_exceeded_action if sandbox.budget_exceeded_action in self.budget_actions else "alert"
        self.budget_action_combo.set_selected(self.budget_actions.index(cur_b_act))
        self.group_budgets.add(self.budget_action_combo)

        # ------------------------------------------------------------------
        # Group 6: Scoped Secrets & Environment Vault
        # ------------------------------------------------------------------
        self.group_secrets = Adw.PreferencesGroup(
            title="Scoped Secrets &amp; Environment Vault",
            description="Manage in-memory environment variables and encrypted vault secrets for this sandbox",
        )
        page.add(self.group_secrets)

        self.env_key_entry = Adw.EntryRow(title="Variable Name (e.g. OPENAI_API_KEY)")
        self.group_secrets.add(self.env_key_entry)

        self.env_val_entry = Adw.PasswordEntryRow(title="New Value or Secret")
        self.group_secrets.add(self.env_val_entry)

        self.env_secret_switch = Adw.SwitchRow(
            title="Store in Secret Vault / Keyring",
            subtitle="Keep value out of sandboxes.json",
        )
        self.env_secret_switch.set_active(True)
        self.add_env_btn = Gtk.Button(label="Add / Update")
        self.add_env_btn.set_valign(Gtk.Align.CENTER)
        self.add_env_btn.connect("clicked", self._on_add_env_clicked)
        self.env_secret_switch.add_suffix(self.add_env_btn)
        self.group_secrets.add(self.env_secret_switch)

        self._rebuild_env_rows()
        self._refresh_profile_details()
        self._validate_domain_entries()
        self.connect("close-request", self._on_close_request)

    def _on_close_request(self, *_args):
        self._closed = True
        self._clear_builtin_domain_rows()
        self._clear_env_rows()
        self._new_secret_values.clear()
        return False

    # ------------------------------------------------------------------
    # Scoped Secrets & Env Management
    # ------------------------------------------------------------------
    def _clear_env_rows(self):
        for r in self._env_rows:
            self.group_secrets.remove(r)
        self._env_rows.clear()

    def _active_secret_keys(self) -> Set[str]:
        return (self._existing_secret_keys - self._removed_secret_keys) | set(self._new_secret_values.keys())

    def _rebuild_env_rows(self):
        self._clear_env_rows()
        sec_keys = self._active_secret_keys()
        all_keys = sorted(set(self._edited_env.keys()) | sec_keys)
        for key in all_keys:
            is_sec = key in sec_keys
            subtitle = "Encrypted Secret (Vault / Keyring)" if is_sec else "Plain Environment Variable"
            row = Adw.ActionRow(
                title=GLib.markup_escape_text(key),
                subtitle=subtitle,
            )
            row.add_css_class("monospace")
            badge = Gtk.Label(
                label="SECRET" if is_sec else "ENV",
                valign=Gtk.Align.CENTER,
            )
            badge.add_css_class("caption-heading")
            badge.add_css_class("accent" if is_sec else "dim-label")
            row.add_suffix(badge)

            rm_btn = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER)
            rm_btn.add_css_class("flat")
            rm_btn.set_tooltip_text(f"Remove {key}")
            rm_btn.connect("clicked", lambda _b, k=key: self._remove_var(k))
            row.add_suffix(rm_btn)
            self.group_secrets.add(row)
            self._env_rows.append(row)

    def _remove_var(self, key: str):
        self._edited_env.pop(key, None)
        self._new_secret_values.pop(key, None)
        if key in self._existing_secret_keys:
            self._removed_secret_keys.add(key)
        self._rebuild_env_rows()
        self._update_restart_banner()

    def stage_variable(self, key: str, value: str, is_secret: bool = True) -> Tuple[bool, str]:
        clean_key = key.strip()
        if not is_valid_env_key(clean_key):
            return False, f"Invalid or protected variable name: '{clean_key}'"
        clean_val = sanitize_env_value(value)
        if is_secret:
            self._edited_env.pop(clean_key, None)
            self._removed_secret_keys.discard(clean_key)
            self._new_secret_values[clean_key] = clean_val
        else:
            self._new_secret_values.pop(clean_key, None)
            if clean_key in self._existing_secret_keys:
                self._removed_secret_keys.add(clean_key)
            self._edited_env[clean_key] = clean_val
        self._rebuild_env_rows()
        self._update_restart_banner()
        return True, f"Staged {'secret' if is_secret else 'variable'} {clean_key}"

    def _on_add_env_clicked(self, _btn):
        key = self.env_key_entry.get_text()
        val = self.env_val_entry.get_text()
        ok, msg = self.stage_variable(key, val, is_secret=self.env_secret_switch.get_active())
        if not ok:
            self.error_banner.set_title(msg)
            self.error_banner.set_revealed(True)
            return
        self.error_banner.set_revealed(False)
        self.env_key_entry.set_text("")
        self.env_val_entry.set_text("")
        self.toast_overlay.add_toast(Adw.Toast.new(msg))

    def _on_open_workspace_changes(self, _row):
        from ..core.workspace_diff import WorkspaceSnapshotManager
        from .workspace_diff_dialog import WorkspaceChangesDialog

        snap_mgr = getattr(self.manager, "snapshots", None) or WorkspaceSnapshotManager()
        dlg = WorkspaceChangesDialog(
            self,
            snap_mgr,
            self.sandbox.name,
            self.sandbox.dir_path,
            on_changed=self.on_saved,
        )
        dlg.present()

    # ------------------------------------------------------------------
    # Name, Hardware & Network Egress Handlers
    # ------------------------------------------------------------------
    def _on_name_changed(self, entry: Adw.EntryRow):
        self._update_name_preview(entry.get_text())

    def _update_name_preview(self, raw_text: str):
        raw = raw_text.strip()
        if not raw:
            self.sanitized_preview_label.set_text("")
            self.sanitized_preview_label.set_visible(False)
            self.group_identity.set_description("")
            return
        sanitized = self.manager.sanitize_name(raw)
        if sanitized != raw:
            self.sanitized_preview_label.set_text(f"→ {sanitized}")
            self.sanitized_preview_label.set_visible(True)
        else:
            self.sanitized_preview_label.set_text("")
            self.sanitized_preview_label.set_visible(False)
        self.group_identity.set_description(f"Effective sandbox identifier: {sanitized}")

    def _env_or_mount_changed(self) -> bool:
        mount_changed = (
            self.git_hooks_switch.get_active() != self._orig_git_hooks
            or self.git_config_switch.get_active() != self._orig_git_config
            or self.env_files_switch.get_active() != self._orig_env_files
            or self.host_lockdown_switch.get_active() != self._orig_host_lockdown
        )
        env_changed = (
            self._edited_env != (self.sandbox.env_vars or {})
            or bool(self._new_secret_values)
            or bool(self._removed_secret_keys)
        )
        return mount_changed or env_changed

    def _update_restart_banner(self, *_args):
        cpus_changed = int(self.cpu_row.get_value()) != self._orig_cpus
        ram_changed = int(self.ram_row.get_value()) != self._orig_ram_gib
        should_reveal = self.sandbox.status == "running" and (
            cpus_changed or ram_changed or self._env_or_mount_changed()
        )
        self.restart_banner.set_revealed(should_reveal)

    def _clear_builtin_domain_rows(self):
        for r in self._builtin_domain_rows:
            self.builtin_expander.remove(r)
        self._builtin_domain_rows.clear()

    def _on_profile_changed(self, _combo, _param):
        self._refresh_profile_details()

    def _refresh_profile_details(self):
        idx = self.net_combo.get_selected()
        if idx == Gtk.INVALID_LIST_POSITION or idx >= len(self.net_keys):
            idx = 0
        key = self.net_keys[idx]
        prof = NETWORK_PROFILES[key]

        desc = prof.get("description", "")
        self.group_network.set_description(GLib.markup_escape_text(desc))

        self._clear_builtin_domain_rows()
        domains = prof.get("domains", [])

        if key == "full":
            self.builtin_expander.set_subtitle("All non-blocked destinations")
            self.builtin_expander.set_expanded(False)
            self.builtin_expander.set_enable_expansion(False)
        elif key == "offline":
            self.builtin_expander.set_subtitle("No outbound internet")
            self.builtin_expander.set_expanded(False)
            self.builtin_expander.set_enable_expansion(False)
        elif key == "custom":
            self.builtin_expander.set_subtitle("Custom whitelist only")
            self.builtin_expander.set_expanded(False)
            self.builtin_expander.set_enable_expansion(False)
        else:
            self.builtin_expander.set_subtitle(f"{len(domains)} built-in domains allowed")
            self.builtin_expander.set_enable_expansion(bool(domains))
            for dom in domains:
                d_row = Adw.ActionRow(title=GLib.markup_escape_text(dom))
                d_row.add_css_class("monospace")
                self.builtin_expander.add_row(d_row)
                self._builtin_domain_rows.append(d_row)

    @staticmethod
    def _parse_and_validate_domains(raw: str) -> Tuple[List[str], List[str]]:
        tokens = [t.strip().lower() for t in raw.split(",") if t.strip()]
        invalid = [t for t in tokens if not is_safe_domain_or_ip(t)]
        return tokens, invalid

    def _on_domains_changed(self, _entry):
        self._validate_domain_entries()

    def _validate_domain_entries(self) -> Tuple[List[str], List[str], Optional[str]]:
        allowed, bad_allowed = self._parse_and_validate_domains(self.whitelist_entry.get_text())
        denied, bad_denied = self._parse_and_validate_domains(self.blacklist_entry.get_text())

        if bad_allowed:
            self.whitelist_warn_icon.set_visible(True)
            self.whitelist_warn_icon.set_tooltip_text(
                f"Invalid domain or IP syntax: {', '.join(bad_allowed)}"
            )
        else:
            self.whitelist_warn_icon.set_visible(False)

        if bad_denied:
            self.blacklist_warn_icon.set_visible(True)
            self.blacklist_warn_icon.set_tooltip_text(
                f"Invalid domain or IP syntax: {', '.join(bad_denied)}"
            )
        else:
            self.blacklist_warn_icon.set_visible(False)

        if bad_allowed:
            return allowed, denied, f"Invalid allowed domain or IP: '{bad_allowed[0]}'"
        if bad_denied:
            return allowed, denied, f"Invalid blocked domain or IP: '{bad_denied[0]}'"
        return allowed, denied, None

    def _on_open_traffic(self, _row):
        dlg = EgressTrafficDialog(
            self,
            self.manager,
            sandbox_name=self.sandbox.name,
            on_policy_updated=self._sync_policy_from_manager,
        )
        dlg.present()

    def _sync_policy_from_manager(self):
        updated = self.manager.get_sandbox(self.sandbox.name)
        if updated and updated.network_policy:
            self.sandbox = updated
            prof = updated.network_policy.profile
            if prof in self.net_keys:
                self.net_combo.set_selected(self.net_keys.index(prof))
            self.whitelist_entry.set_text(", ".join(updated.network_policy.allowed_domains))
            self.blacklist_entry.set_text(", ".join(updated.network_policy.denied_domains))
        if self.on_saved:
            self.on_saved()

    def _on_save_clicked(self, _btn):
        raw_name = self.name_row.get_text().strip()
        if not raw_name:
            self.error_banner.set_title("Sandbox name cannot be empty")
            self.error_banner.set_revealed(True)
            return

        # Auto-stage pending variable text if entered
        pending_key = self.env_key_entry.get_text().strip()
        pending_val = self.env_val_entry.get_text()
        if pending_key:
            ok, msg = self.stage_variable(
                pending_key, pending_val, is_secret=self.env_secret_switch.get_active()
            )
            if not ok:
                self.error_banner.set_title(msg)
                self.error_banner.set_revealed(True)
                return
            self.env_key_entry.set_text("")
            self.env_val_entry.set_text("")

        allowed_domains, denied_domains, err = self._validate_domain_entries()
        if err:
            self.error_banner.set_title(err)
            self.error_banner.set_revealed(True)
            return

        self.error_banner.set_revealed(False)

        sanitized_new = self.manager.sanitize_name(raw_name)
        new_name: Optional[str] = sanitized_new if sanitized_new != self.sandbox.name else None

        cpus = int(self.cpu_row.get_value())
        ram_gib = int(self.ram_row.get_value())
        ram_mib = self.sandbox.ram_mib if ram_gib == self._orig_ram_gib else ram_gib * 1024

        prof_idx = self.net_combo.get_selected()
        if prof_idx == Gtk.INVALID_LIST_POSITION or prof_idx >= len(self.net_keys):
            prof_idx = 0
        net_profile = self.net_keys[prof_idx]

        net_policy = NetworkPolicy(
            profile=net_profile,
            allowed_domains=allowed_domains,
            denied_domains=denied_domains,
        )

        protect_git_hooks = self.git_hooks_switch.get_active()
        protect_git_config = self.git_config_switch.get_active()
        protect_env_files = self.env_files_switch.get_active()
        host_egress_lockdown = self.host_lockdown_switch.get_active()
        idle_timeout_minutes = int(self.idle_timeout_row.get_value())
        idle_idx = self.idle_action_combo.get_selected()
        idle_action = self.idle_actions[idle_idx] if idle_idx < len(self.idle_actions) else "stop"
        max_tokens_budget = int(self.max_tokens_row.get_value())
        max_cost_usd_budget = float(self.max_cost_row.get_value())
        b_idx = self.budget_action_combo.get_selected()
        budget_exceeded_action = self.budget_actions[b_idx] if b_idx < len(self.budget_actions) else "alert"

        env_vars_copy = dict(self._edited_env)
        secret_keys_sorted = sorted(self._active_secret_keys())
        new_secrets_copy = dict(self._new_secret_values)
        removed_secrets_copy = set(self._removed_secret_keys)

        self.save_btn.set_sensitive(False)
        self.cancel_btn.set_sensitive(False)

        def worker():
            orig_name = self.sandbox.name
            for rem_key in removed_secrets_copy:
                self.secret_mgr.delete_secret(orig_name, rem_key)
            for sec_key, sec_val in new_secrets_copy.items():
                self.secret_mgr.set_secret(orig_name, sec_key, sec_val)

            if hasattr(self.manager, "update_sandbox"):
                return self.manager.update_sandbox(
                    orig_name,
                    new_name=new_name,
                    cpus=cpus,
                    ram_mib=ram_mib,
                    network_policy=net_policy,
                    protect_git_hooks=protect_git_hooks,
                    protect_git_config=protect_git_config,
                    protect_env_files=protect_env_files,
                    host_egress_lockdown=host_egress_lockdown,
                    idle_timeout_minutes=idle_timeout_minutes,
                    idle_action=idle_action,
                    env_vars=env_vars_copy,
                    secret_keys=secret_keys_sorted,
                    max_tokens_budget=max_tokens_budget,
                    max_cost_usd_budget=max_cost_usd_budget,
                    budget_exceeded_action=budget_exceeded_action,
                    secrets_updated=bool(new_secrets_copy or removed_secrets_copy),
                )
            ok = bool(self.manager.update_network_policy(orig_name, net_policy))
            msg = "Updated network policy." if ok else "Failed to update network policy."
            return ok, msg, self.sandbox

        def on_done(result):
            if self._closed:
                return
            if isinstance(result, tuple) and len(result) >= 2:
                ok, msg = result[0], result[1]
            else:
                ok, msg = False, "Unexpected response from sandbox manager"

            if ok:
                if hasattr(self.parent_window, "toast_overlay") and self.parent_window.toast_overlay:
                    self.parent_window.toast_overlay.add_toast(Adw.Toast.new(msg))
                if self.on_saved:
                    self.on_saved()
                self.close()
            else:
                self.save_btn.set_sensitive(True)
                self.cancel_btn.set_sensitive(True)
                self.error_banner.set_title(msg)
                self.error_banner.set_revealed(True)

        def on_err(exc):
            if self._closed:
                return
            self.save_btn.set_sensitive(True)
            self.cancel_btn.set_sensitive(True)
            self.error_banner.set_title(str(exc))
            self.error_banner.set_revealed(True)

        run_async(worker, on_success=on_done, on_error=on_err)
