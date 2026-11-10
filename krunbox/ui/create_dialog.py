"""
Native Libadwaita dialog for creating and launching a new krunbox MicroVM sandbox.
"""

import os
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib, Gio

from ..core.config import BUILTIN_IMAGES, NETWORK_PROFILES
from ..core.manager import SandboxManager
from ..core.network import is_safe_domain_or_ip
from ..core.sandbox import NetworkPolicy
from ..core.secrets import SecretVaultManager, is_valid_env_key, sanitize_env_value
from ..core.settings import load_settings
from ..core.templates import SandboxTemplate, TemplateManager
from .dialogs import show_alert_dialog
from .network_policy_dialog import NetworkPolicyReferenceDialog
from .worker import run_async


class CreateSandboxDialog(Adw.Window):
    def __init__(
        self,
        parent_window: Gtk.Window,
        manager: SandboxManager,
        on_created: Callable[[], None],
    ):
        super().__init__(modal=True, transient_for=parent_window)
        self.set_title("New MicroVM Sandbox")
        self.set_default_size(640, 760)
        self.parent_window = parent_window
        self.manager = manager
        self.on_created = on_created
        self._closed = False
        self._applying_template = False

        self.template_mgr: TemplateManager = getattr(manager, "templates", None) or TemplateManager()
        self.secret_mgr: SecretVaultManager = getattr(manager, "secrets", None) or SecretVaultManager()

        self._templates: List[SandboxTemplate] = []
        self._staged_env: Dict[str, str] = {}
        self._staged_secrets: Dict[str, str] = {}
        self._staged_passthrough: List[str] = []
        self._env_rows: List[Gtk.Widget] = []

        settings = load_settings()

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

        self.launch_btn = Gtk.Button()
        self.launch_btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.launch_spinner = Gtk.Spinner()
        self.launch_spinner.set_visible(False)
        self.launch_label = Gtk.Label(label="Launch")
        self.launch_btn_box.append(self.launch_spinner)
        self.launch_btn_box.append(self.launch_label)
        self.launch_btn.set_child(self.launch_btn_box)
        self.launch_btn.add_css_class("suggested-action")
        self.launch_btn.connect("clicked", self._on_launch_clicked)
        header.pack_end(self.launch_btn)

        # Non-existent directory warning & quick-create banner
        self.dir_banner = Adw.Banner(title="Workspace directory does not exist")
        self.dir_banner.set_use_markup(False)
        self.dir_banner.set_button_label("Create Folder")
        self.dir_banner.connect("button-clicked", self._on_create_dir_clicked)
        self.dir_banner.set_revealed(False)
        toolbar_view.add_top_bar(self.dir_banner)

        # Launch / validation feedback banner
        self.error_banner = Adw.Banner()
        self.error_banner.set_use_markup(False)
        self.error_banner.set_revealed(False)
        toolbar_view.add_top_bar(self.error_banner)

        page = Adw.PreferencesPage()
        toolbar_view.set_content(page)

        # ------------------------------------------------------------------
        # Group 0: Sandbox Preset Template ("Profiles")
        # ------------------------------------------------------------------
        self.group_template = Adw.PreferencesGroup(
            title="Sandbox Profile Preset",
            description="Start from user defaults or pick a reusable hardware and security preset",
        )
        page.add(self.group_template)

        tmpl_actions_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        tmpl_actions_box.set_valign(Gtk.Align.CENTER)

        self.save_template_btn = Gtk.Button(label="Save Preset…")
        self.save_template_btn.add_css_class("flat")
        self.save_template_btn.set_tooltip_text("Save current configuration as a reusable preset")
        self.save_template_btn.connect("clicked", self._on_save_template_clicked)
        tmpl_actions_box.append(self.save_template_btn)

        self.delete_template_btn = Gtk.Button(icon_name="user-trash-symbolic")
        self.delete_template_btn.add_css_class("flat")
        self.delete_template_btn.set_tooltip_text("Delete selected custom preset")
        self.delete_template_btn.set_visible(False)
        self.delete_template_btn.connect("clicked", self._on_delete_template_clicked)
        tmpl_actions_box.append(self.delete_template_btn)
        self.group_template.set_header_suffix(tmpl_actions_box)

        self.template_combo = Adw.ComboRow(
            title="Preset Template",
            subtitle="Applies image, CPU/RAM and guardrails",
        )
        self._reload_template_model(select_id=None)
        self.template_combo.connect("notify::selected", self._on_template_selected)
        self.group_template.add(self.template_combo)

        # ------------------------------------------------------------------
        # Group 1: Target Workspace
        # ------------------------------------------------------------------
        group_identity = Adw.PreferencesGroup(title="Target Workspace")
        page.add(group_identity)

        self.dir_entry = Adw.EntryRow(title="Workspace Directory")
        self.dir_entry.set_text(os.getcwd())
        self.dir_entry.connect("changed", self._on_dir_changed)

        self.dir_warn_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        self.dir_warn_icon.set_tooltip_text("Directory does not exist on host filesystem")
        self.dir_warn_icon.add_css_class("warning")
        self.dir_warn_icon.set_visible(False)
        self.dir_entry.add_suffix(self.dir_warn_icon)

        self.browse_btn = Gtk.Button(icon_name="folder-open-symbolic")
        self.browse_btn.add_css_class("flat")
        self.browse_btn.set_valign(Gtk.Align.CENTER)
        self.browse_btn.set_tooltip_text("Select Workspace Folder")
        self.browse_btn.connect("clicked", self._on_browse_clicked)
        self.dir_entry.add_suffix(self.browse_btn)
        group_identity.add(self.dir_entry)

        self.name_row = Adw.EntryRow(title="Sandbox Name")
        default_name = self.manager.generate_name(os.getcwd())
        self.name_row.set_text(default_name)
        self._user_edited_name = False
        self.name_row.connect("changed", self._on_name_changed)
        group_identity.add(self.name_row)

        self._check_dir_exists(os.getcwd())

        # ------------------------------------------------------------------
        # Group 2: Runtime Image and Lifecycle
        # ------------------------------------------------------------------
        self.group_runtime = Adw.PreferencesGroup(title="Runtime Image &amp; Lifecycle")
        page.add(self.group_runtime)

        self.image_keys = list(BUILTIN_IMAGES.keys())
        self.image_combo = Adw.ComboRow(title="Base Container Image")
        self.image_combo.set_model(Gtk.StringList.new(self.image_keys))
        pref_image = settings.get("default_image", "agent-box")
        img_idx = self.image_keys.index(pref_image) if pref_image in self.image_keys else 0
        self.image_combo.set_selected(img_idx)
        self.image_combo.connect("notify::selected", self._on_image_changed)
        self.group_runtime.add(self.image_combo)
        self._update_image_description()

        self.persist_switch = Adw.SwitchRow(
            title="Persistent Sandbox State",
            subtitle="Preserve rootfs and container state across stops (Off = Ephemeral)",
        )
        self.persist_switch.set_active(bool(settings.get("default_persistent", False)))
        self.group_runtime.add(self.persist_switch)

        # ------------------------------------------------------------------
        # Group 3: Network Egress Policy & Host-Boundary Lockdown
        # ------------------------------------------------------------------
        self.group_network = Adw.PreferencesGroup(
            title="Network Egress Policy",
            description="Restrict outbound network access to mitigate data exfiltration",
        )
        page.add(self.group_network)

        self.net_keys = list(NETWORK_PROFILES.keys())
        net_labels = [NETWORK_PROFILES[k]["name"] for k in self.net_keys]
        self.net_combo = Adw.ComboRow(title="Outbound Access Profile")
        self.net_combo.set_model(Gtk.StringList.new(net_labels))
        pref_net = settings.get("default_network", "full")
        net_idx = self.net_keys.index(pref_net) if pref_net in self.net_keys else 0
        self.net_combo.set_selected(net_idx)
        self.net_combo.connect("notify::selected", self._on_net_profile_changed)

        self.policy_info_btn = Gtk.Button.new_from_icon_name("view-list-symbolic")
        self.policy_info_btn.set_valign(Gtk.Align.CENTER)
        self.policy_info_btn.add_css_class("flat")
        self.policy_info_btn.set_tooltip_text("Compare policy allowrules and domain table")
        self.policy_info_btn.connect("clicked", self._on_show_policy_reference)
        self.net_combo.add_suffix(self.policy_info_btn)

        self.group_network.add(self.net_combo)

        # Dropdown Expander for Policy Allowlist Table
        self.policy_ref_expander = Adw.ExpanderRow(
            title="Policy Allowlist Reference",
            subtitle="Compare allowed destinations and domains across policies",
        )
        self.policy_ref_expander.add_prefix(Gtk.Image.new_from_icon_name("network-wired-symbolic"))
        self._policy_ref_row_widgets: Dict[str, Tuple[Adw.ActionRow, Gtk.Widget]] = {}
        self._build_policy_reference_rows()
        self.group_network.add(self.policy_ref_expander)

        self._update_net_subtitle()

        self.whitelist_entry = Adw.EntryRow(title="Allowed Domains / Whitelist (comma-separated)")
        self.whitelist_warn_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        self.whitelist_warn_icon.add_css_class("warning")
        self.whitelist_warn_icon.set_visible(False)
        self.whitelist_entry.add_suffix(self.whitelist_warn_icon)
        self.whitelist_entry.connect("changed", self._on_domains_changed)
        self.group_network.add(self.whitelist_entry)

        self.blacklist_entry = Adw.EntryRow(title="Blocked Domains / Blacklist (comma-separated)")
        self.blacklist_warn_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        self.blacklist_warn_icon.add_css_class("warning")
        self.blacklist_warn_icon.set_visible(False)
        self.blacklist_entry.add_suffix(self.blacklist_warn_icon)
        self.blacklist_entry.connect("changed", self._on_domains_changed)
        self.group_network.add(self.blacklist_entry)

        self.host_lockdown_switch = Adw.SwitchRow(
            title="Host-Boundary Egress Lockdown",
            subtitle="Enforce firewall outside guest VM and drop guest CAP_NET_ADMIN",
        )
        self.host_lockdown_switch.set_active(
            bool(settings.get("default_host_egress_lockdown", False))
        )
        self.group_network.add(self.host_lockdown_switch)

        # ------------------------------------------------------------------
        # Group 4: Workspace Git & Dotfile Guardrails
        # ------------------------------------------------------------------
        self.group_guardrails = Adw.PreferencesGroup(
            title="Workspace Git &amp; Dotfile Guardrails",
            description="Mount sensitive host git hooks and dotfiles read-only inside /workspace",
        )
        page.add(self.group_guardrails)

        self.git_hooks_switch = Adw.SwitchRow(
            title="Protect .git/hooks (Read-Only)",
            subtitle="Block prompt-injected agents from planting host git hooks",
        )
        self.git_hooks_switch.set_active(bool(settings.get("default_protect_git_hooks", True)))
        self.group_guardrails.add(self.git_hooks_switch)

        self.git_config_switch = Adw.SwitchRow(
            title="Protect .git/config (Read-Only)",
            subtitle="Prevent changes to git remotes, aliases, and core.sshCommand",
        )
        self.git_config_switch.set_active(bool(settings.get("default_protect_git_config", False)))
        self.group_guardrails.add(self.git_config_switch)

        self.env_files_switch = Adw.SwitchRow(
            title="Protect Workspace .env Files (Read-Only)",
            subtitle="Mask existing .env and .env.* files read-only",
        )
        self.env_files_switch.set_active(bool(settings.get("default_protect_env_files", False)))
        self.group_guardrails.add(self.env_files_switch)

        # ------------------------------------------------------------------
        # Group 5: Compute, Idle Sleep & Budget Guardrails
        # ------------------------------------------------------------------
        group_hw = Adw.PreferencesGroup(
            title="Compute, Idle Sleep &amp; Budgets",
            description="Hardware limits, automatic idle sleep, and AI token/spend guardrails",
        )
        page.add(group_hw)

        default_cpus = int(settings.get("default_cpus", 4))
        default_ram_gib = max(1, round(int(settings.get("default_ram_mib", 4096)) / 1024))

        self.cpu_row = Adw.SpinRow.new_with_range(1, 32, 1)
        self.cpu_row.set_title("Virtual CPUs")
        self.cpu_row.set_subtitle("Default: 4 vCPUs")
        self.cpu_row.set_value(default_cpus)
        group_hw.add(self.cpu_row)

        self.ram_row = Adw.SpinRow.new_with_range(1, 64, 1)
        self.ram_row.set_title("Memory (GiB)")
        self.ram_row.set_subtitle("Default: 4 GiB")
        self.ram_row.set_value(default_ram_gib)
        group_hw.add(self.ram_row)

        self.idle_timeout_row = Adw.SpinRow.new_with_range(0, 480, 5)
        self.idle_timeout_row.set_title("Idle Sleep Timeout (minutes)")
        self.idle_timeout_row.set_subtitle("0 = Disabled; sleeps when 0 SSH sessions and CPU &lt; 1%")
        self.idle_timeout_row.set_value(max(0, int(settings.get("default_idle_timeout_minutes", 0))))
        group_hw.add(self.idle_timeout_row)

        self.idle_actions = ["stop", "pause"]
        self.idle_action_combo = Adw.ComboRow(
            title="Idle Sleep Action",
            subtitle="Action on idle timeout",
        )
        self.idle_action_combo.set_model(Gtk.StringList.new(["Stop Sandbox", "Pause MicroVM"]))
        def_idle_act = settings.get("default_idle_action", "stop")
        self.idle_action_combo.set_selected(
            self.idle_actions.index(def_idle_act) if def_idle_act in self.idle_actions else 0
        )
        group_hw.add(self.idle_action_combo)

        self.max_tokens_row = Adw.SpinRow.new_with_range(0, 50_000_000, 50_000)
        self.max_tokens_row.set_title("AI Token Budget Limit")
        self.max_tokens_row.set_subtitle("0 = Unlimited cumulative tokens")
        self.max_tokens_row.set_value(max(0, int(settings.get("default_max_tokens_budget", 0))))
        group_hw.add(self.max_tokens_row)

        self.max_cost_row = Adw.SpinRow.new_with_range(0, 1000, 1)
        self.max_cost_row.set_title("Max AI Spend Budget (USD)")
        self.max_cost_row.set_subtitle("0 = Unlimited estimated USD spend")
        self.max_cost_row.set_value(max(0, float(settings.get("default_max_cost_usd_budget", 0.0))))
        group_hw.add(self.max_cost_row)

        # ------------------------------------------------------------------
        # Group 6: Scoped Secrets & Environment Vault
        # ------------------------------------------------------------------
        self.group_secrets = Adw.PreferencesGroup(
            title="Scoped Secrets &amp; Environment Vault",
            description="Inject variables into microVM memory via Keyring or 0600 Vault without writing .env files to /workspace",
        )
        page.add(self.group_secrets)

        sec_hdr_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        sec_hdr_box.set_valign(Gtk.Align.CENTER)
        self.keyring_import_btn = Gtk.Button(label="Import Keyring…")
        self.keyring_import_btn.add_css_class("flat")
        self.keyring_import_btn.set_tooltip_text("Pull a secret from GNOME Keyring / secret-tool")
        self.keyring_import_btn.connect("clicked", self._on_import_keyring_clicked)
        sec_hdr_box.append(self.keyring_import_btn)
        self.group_secrets.set_header_suffix(sec_hdr_box)

        self.env_key_entry = Adw.EntryRow(title="Variable Name (e.g. OPENAI_API_KEY)")
        self.group_secrets.add(self.env_key_entry)

        self.env_val_entry = Adw.PasswordEntryRow(title="Secret or Variable Value")
        self.group_secrets.add(self.env_val_entry)

        self.env_secret_switch = Adw.SwitchRow(
            title="Store in Secret Vault / Keyring",
            subtitle="Keep value out of sandboxes.json",
        )
        self.env_secret_switch.set_active(True)
        self.add_env_btn = Gtk.Button(label="Add Variable")
        self.add_env_btn.set_valign(Gtk.Align.CENTER)
        self.add_env_btn.connect("clicked", self._on_add_env_clicked)
        self.env_secret_switch.add_suffix(self.add_env_btn)
        self.group_secrets.add(self.env_secret_switch)

        # ------------------------------------------------------------------
        # Group 7: Port Forwarding
        # ------------------------------------------------------------------
        group_ports = Adw.PreferencesGroup(
            title="Port Forwarding",
            description="Publish guest TCP ports to localhost (e.g. 3000:3000, 8080)",
        )
        page.add(group_ports)

        self.ports_entry = Adw.EntryRow(title="Published Ports (comma-separated)")
        self.ports_entry.set_text("3000")
        group_ports.add(self.ports_entry)

        preset_row = Adw.ActionRow(title="Quick Presets")
        preset_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        preset_box.set_valign(Gtk.Align.CENTER)
        presets = [
            ("Next.js (3000)", "3000"),
            ("Vite (5173)", "5173"),
            ("FastAPI (8000)", "8000"),
            ("Jupyter (8888)", "8888"),
        ]
        for label, port_str in presets:
            btn = Gtk.Button(label=label)
            btn.add_css_class("flat")
            btn.add_css_class("caption")
            btn.connect("clicked", lambda _b, p=port_str: self._add_port_preset(p))
            preset_box.append(btn)
        preset_row.add_suffix(preset_box)
        group_ports.add(preset_row)

        # Keep status_label attribute for compatibility
        self.status_label = Gtk.Label(label="", wrap=True)
        self.connect("close-request", self._on_close_request)

    def _on_close_request(self, *_args):
        self._closed = True
        self._clear_env_rows()
        self._staged_secrets.clear()
        return False

    # ------------------------------------------------------------------
    # Preset Templates
    # ------------------------------------------------------------------
    def _reload_template_model(self, select_id: Optional[str] = None):
        self._templates = self.template_mgr.list_templates()
        labels = ["Custom / User Defaults"] + [t.name for t in self._templates]
        self._applying_template = True
        self.template_combo.set_model(Gtk.StringList.new(labels))
        target_idx = 0
        if select_id:
            for idx, tmpl in enumerate(self._templates, start=1):
                if tmpl.id == select_id:
                    target_idx = idx
                    break
        self.template_combo.set_selected(target_idx)
        self._applying_template = False
        self._update_template_header_state()

    def _selected_template(self) -> Optional[SandboxTemplate]:
        idx = self.template_combo.get_selected()
        if idx == Gtk.INVALID_LIST_POSITION or idx == 0 or idx > len(self._templates):
            return None
        return self._templates[idx - 1]

    def _update_template_header_state(self):
        tmpl = self._selected_template()
        if tmpl is None:
            self.group_template.set_description(
                "Start from user defaults or pick a reusable hardware and security preset"
            )
            self.delete_template_btn.set_visible(False)
        else:
            desc = tmpl.description or f"Preset: {tmpl.name}"
            self.group_template.set_description(GLib.markup_escape_text(desc))
            self.delete_template_btn.set_visible(not tmpl.builtin)

    def _on_template_selected(self, _combo, _param):
        if self._applying_template:
            return
        self._update_template_header_state()
        tmpl = self._selected_template()
        if tmpl is None:
            return
        self.apply_template(tmpl)

    def apply_template(self, tmpl: SandboxTemplate):
        """Populate form fields from a SandboxTemplate."""
        if tmpl.base_image in self.image_keys:
            self.image_combo.set_selected(self.image_keys.index(tmpl.base_image))
        else:
            for i, k in enumerate(self.image_keys):
                if BUILTIN_IMAGES[k]["tag"] == tmpl.base_image:
                    self.image_combo.set_selected(i)
                    break
        self.persist_switch.set_active(bool(tmpl.is_persistent))
        if tmpl.network_profile in self.net_keys:
            self.net_combo.set_selected(self.net_keys.index(tmpl.network_profile))
        self.whitelist_entry.set_text(", ".join(tmpl.allowed_domains))
        self.blacklist_entry.set_text(", ".join(tmpl.denied_domains))
        self.host_lockdown_switch.set_active(bool(tmpl.host_egress_lockdown))
        self.git_hooks_switch.set_active(bool(tmpl.protect_git_hooks))
        self.git_config_switch.set_active(bool(tmpl.protect_git_config))
        self.env_files_switch.set_active(bool(tmpl.protect_env_files))
        self.cpu_row.set_value(max(1, min(32, int(tmpl.cpus))))
        self.ram_row.set_value(max(1, min(64, round(int(tmpl.ram_mib) / 1024))))
        self.idle_timeout_row.set_value(max(0, int(tmpl.idle_timeout_minutes)))
        if tmpl.idle_action in self.idle_actions:
            self.idle_action_combo.set_selected(self.idle_actions.index(tmpl.idle_action))
        self.ports_entry.set_text(", ".join(tmpl.ports))

    def _build_template_from_form(self, name: str, description: str = "") -> SandboxTemplate:
        sel_img = self.image_combo.get_selected()
        img_key = self.image_keys[sel_img] if sel_img < len(self.image_keys) else "agent-box"
        sel_net = self.net_combo.get_selected()
        net_prof = self.net_keys[sel_net] if sel_net < len(self.net_keys) else "full"
        wl, bl, _ = self._validate_domains()
        ports = [p.strip() for p in self.ports_entry.get_text().split(",") if p.strip()]
        sel_idle = self.idle_action_combo.get_selected()
        idle_act = self.idle_actions[sel_idle] if sel_idle < len(self.idle_actions) else "stop"
        return SandboxTemplate(
            id=self.template_mgr.slugify_id(name),
            name=name.strip(),
            description=description.strip(),
            builtin=False,
            base_image=img_key,
            cpus=int(self.cpu_row.get_value()),
            ram_mib=int(self.ram_row.get_value()) * 1024,
            is_persistent=self.persist_switch.get_active(),
            network_profile=net_prof,
            allowed_domains=wl,
            denied_domains=bl,
            ports=ports,
            protect_git_hooks=self.git_hooks_switch.get_active(),
            protect_git_config=self.git_config_switch.get_active(),
            protect_env_files=self.env_files_switch.get_active(),
            host_egress_lockdown=self.host_lockdown_switch.get_active(),
            idle_timeout_minutes=int(self.idle_timeout_row.get_value()),
            idle_action=idle_act,
        )

    def _on_save_template_clicked(self, _btn):
        form_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        form_list.add_css_class("boxed-list")
        name_entry = Adw.EntryRow(title="Preset Name")
        desc_entry = Adw.EntryRow(title="Short Description (optional)")
        form_list.append(name_entry)
        form_list.append(desc_entry)

        def on_resp(resp):
            if resp == "save":
                t_name = name_entry.get_text().strip()
                if not t_name:
                    self._set_feedback("Preset name cannot be empty.", is_error=True)
                    return
                tmpl = self._build_template_from_form(t_name, desc_entry.get_text())
                saved = self.template_mgr.save_custom_template(tmpl)
                self._reload_template_model(select_id=saved.id)
                self.toast_overlay.add_toast(Adw.Toast.new(f"Saved preset: {saved.name}"))

        show_alert_dialog(
            parent_window=self,
            heading="Save Sandbox Preset",
            body="Save the current image, CPU/RAM, network policy, ports, and guardrails as a reusable preset.",
            responses=[
                ("cancel", "Cancel"),
                ("save", "Save Preset", Adw.ResponseAppearance.SUGGESTED),
            ],
            on_response=on_resp,
            default_response="save",
            close_response="cancel",
            extra_child=form_list,
        )

    def _on_delete_template_clicked(self, _btn):
        tmpl = self._selected_template()
        if not tmpl or tmpl.builtin:
            return
        if self.template_mgr.delete_custom_template(tmpl.id):
            self._reload_template_model(select_id=None)
            self.toast_overlay.add_toast(Adw.Toast.new(f"Deleted preset: {tmpl.name}"))

    # ------------------------------------------------------------------
    # Scoped Secrets & Environment Variables
    # ------------------------------------------------------------------
    def _clear_env_rows(self):
        for r in self._env_rows:
            self.group_secrets.remove(r)
        self._env_rows.clear()

    def _rebuild_env_rows(self):
        self._clear_env_rows()
        for key in sorted(set(self._staged_env.keys()) | set(self._staged_secrets.keys())):
            is_sec = key in self._staged_secrets
            subtitle = "Encrypted Secret (Keyring / 0600 Vault)" if is_sec else "Plain Environment Variable"
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
            rm_btn.connect("clicked", lambda _b, k=key: self._remove_staged_var(k))
            row.add_suffix(rm_btn)
            self.group_secrets.add(row)
            self._env_rows.append(row)

    def _remove_staged_var(self, key: str):
        self._staged_env.pop(key, None)
        self._staged_secrets.pop(key, None)
        self._rebuild_env_rows()

    def stage_variable(self, key: str, value: str, is_secret: bool = True) -> Tuple[bool, str]:
        clean_key = key.strip()
        if not is_valid_env_key(clean_key):
            return False, f"Invalid or protected variable name: '{clean_key}'"
        clean_val = sanitize_env_value(value)
        if is_secret:
            self._staged_env.pop(clean_key, None)
            self._staged_secrets[clean_key] = clean_val
        else:
            self._staged_secrets.pop(clean_key, None)
            self._staged_env[clean_key] = clean_val
        self._rebuild_env_rows()
        return True, f"Staged {'secret' if is_secret else 'variable'} {clean_key}"

    def _on_add_env_clicked(self, _btn):
        key = self.env_key_entry.get_text()
        val = self.env_val_entry.get_text()
        is_sec = self.env_secret_switch.get_active()
        ok, msg = self.stage_variable(key, val, is_secret=is_sec)
        if not ok:
            self._set_feedback(msg, is_error=True)
            return
        self._set_feedback("", is_error=False)
        self.env_key_entry.set_text("")
        self.env_val_entry.set_text("")
        self.toast_overlay.add_toast(Adw.Toast.new(msg))

    def _on_import_keyring_clicked(self, _btn):
        form_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        form_list.add_css_class("boxed-list")
        var_row = Adw.EntryRow(title="Target Env Name (e.g. ANTHROPIC_API_KEY)")
        attr_k_row = Adw.EntryRow(title="Keyring Attribute (e.g. service)")
        attr_v_row = Adw.EntryRow(title="Attribute Value (e.g. anthropic)")
        form_list.append(var_row)
        form_list.append(attr_k_row)
        form_list.append(attr_v_row)

        def on_resp(resp):
            if resp != "import":
                return
            env_name = var_row.get_text().strip()
            ak = attr_k_row.get_text().strip()
            av = attr_v_row.get_text().strip()
            if not is_valid_env_key(env_name):
                self._set_feedback(f"Invalid target variable name: '{env_name}'", is_error=True)
                return
            try:
                secret_val = self.secret_mgr.lookup_system_keyring({ak: av})
            except Exception as e:
                self._set_feedback(str(e), is_error=True)
                return
            if secret_val is None:
                self._set_feedback(
                    f"No matching secret found in GNOME Keyring for {ak}={av}.",
                    is_error=True,
                )
                return
            ok, msg = self.stage_variable(env_name, secret_val, is_secret=True)
            if ok:
                self._set_feedback("", is_error=False)
                self.toast_overlay.add_toast(Adw.Toast.new(f"Imported {env_name} from Keyring"))

        show_alert_dialog(
            parent_window=self,
            heading="Import Secret from GNOME Keyring",
            body="Look up a secret via libsecret ('secret-tool lookup <attr> <value>') and stage it into this sandbox.",
            responses=[
                ("cancel", "Cancel"),
                ("import", "Lookup & Stage", Adw.ResponseAppearance.SUGGESTED),
            ],
            on_response=on_resp,
            extra_child=form_list,
        )

    # ------------------------------------------------------------------
    # Feedback & Validation Helpers
    # ------------------------------------------------------------------
    def _set_feedback(self, message: str, is_error: bool = True):
        self.status_label.set_text(message)
        if is_error:
            self.status_label.add_css_class("error")
        else:
            self.status_label.remove_css_class("error")
        if message:
            self.error_banner.set_title(message)
            self.error_banner.set_revealed(True)
        else:
            self.error_banner.set_revealed(False)

    def _on_name_changed(self, entry):
        if entry.has_focus():
            self._user_edited_name = True

    def _on_image_changed(self, _combo, _param):
        self._update_image_description()

    def _update_image_description(self):
        idx = self.image_combo.get_selected()
        if idx == Gtk.INVALID_LIST_POSITION or idx >= len(self.image_keys):
            idx = 0
        key = self.image_keys[idx]
        desc = BUILTIN_IMAGES[key].get("description", "")
        tag = BUILTIN_IMAGES[key].get("tag", "")
        if hasattr(self.manager, "images"):
            needs_build, reason = self.manager.images.should_build_or_update(tag)
            if needs_build:
                desc += f" • {reason} (auto-builds on launch)"
        self.group_runtime.set_description(GLib.markup_escape_text(desc))

    def _on_net_profile_changed(self, _combo, _param):
        self._update_net_subtitle()

    def _update_net_subtitle(self):
        idx = self.net_combo.get_selected()
        if idx == Gtk.INVALID_LIST_POSITION or idx >= len(self.net_keys):
            idx = 0
        key = self.net_keys[idx]
        desc = NETWORK_PROFILES[key].get("description", "")
        self.group_network.set_description(GLib.markup_escape_text(desc))
        if hasattr(self, "_policy_ref_row_widgets"):
            self._update_policy_reference_indicators(key)

    def _build_policy_reference_rows(self):
        summaries = {
            "full": ("Full Access", "All outbound internet traffic and DNS permitted (0.0.0.0/0)", "network-transmit-receive-symbolic"),
            "ai-only": ("AI APIs Only (10 domains)", "OpenAI, Anthropic, Gemini, Mistral, Groq, Cohere, HuggingFace", "system-run-symbolic"),
            "dev-common": ("Developer Repositories and AI (20 domains)", "AI APIs + PyPI, npm, GitHub, Docker Hub, Ubuntu and Debian mirrors", "applications-development-symbolic"),
            "offline": ("Offline / Airgapped", "Zero outbound network access (loopback only, all external packets dropped)", "network-offline-symbolic"),
            "custom": ("Custom Whitelist", "Only domains and IP CIDRs entered in the Allowed Domains field below", "preferences-system-network-symbolic"),
        }
        for key in self.net_keys:
            if key not in summaries:
                continue
            title, subtitle, icon_name = summaries[key]
            row = Adw.ActionRow(title=title, subtitle=subtitle)
            row.add_prefix(Gtk.Image.new_from_icon_name(icon_name))

            check = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
            check.add_css_class("success")
            check.set_visible(False)
            row.add_suffix(check)

            btn = Gtk.Button(label="Select")
            btn.add_css_class("flat")
            btn.set_valign(Gtk.Align.CENTER)
            btn.connect("clicked", self._make_policy_select_callback(key))
            row.add_suffix(btn)

            self.policy_ref_expander.add_row(row)
            self._policy_ref_row_widgets[key] = (row, check)

        table_row = Adw.ActionRow(
            title="Open Detailed Comparison Table…",
            subtitle="Searchable domain lists, security posture, and port rules",
        )
        table_row.add_prefix(Gtk.Image.new_from_icon_name("view-list-symbolic"))
        table_btn = Gtk.Button.new_from_icon_name("go-next-symbolic")
        table_btn.set_valign(Gtk.Align.CENTER)
        table_btn.add_css_class("flat")
        table_btn.connect("clicked", self._on_show_policy_reference)
        table_row.add_suffix(table_btn)
        table_row.set_activatable(True)
        table_row.connect("activated", self._on_show_policy_reference)
        self.policy_ref_expander.add_row(table_row)

    def _make_policy_select_callback(self, key: str):
        def _on_click(_btn):
            self._set_network_profile(key)
        return _on_click

    def _update_policy_reference_indicators(self, active_key: str):
        for key, (_, check) in self._policy_ref_row_widgets.items():
            check.set_visible(key == active_key)

    def _set_network_profile(self, key: str):
        if key in self.net_keys:
            idx = self.net_keys.index(key)
            self.net_combo.set_selected(idx)

    def _on_show_policy_reference(self, _widget):
        idx = self.net_combo.get_selected()
        current_key = self.net_keys[idx] if (idx != Gtk.INVALID_LIST_POSITION and idx < len(self.net_keys)) else "full"
        dlg = NetworkPolicyReferenceDialog(
            parent_window=self,
            current_profile=current_key,
            on_select=self._set_network_profile,
        )
        dlg.present()

    def _on_domains_changed(self, _entry):
        self._validate_domains()

    def _validate_domains(self) -> Tuple[List[str], List[str], Optional[str]]:
        wl_tokens = [d.strip().lower() for d in self.whitelist_entry.get_text().split(",") if d.strip()]
        bl_tokens = [d.strip().lower() for d in self.blacklist_entry.get_text().split(",") if d.strip()]
        bad_wl = [t for t in wl_tokens if not is_safe_domain_or_ip(t)]
        bad_bl = [t for t in bl_tokens if not is_safe_domain_or_ip(t)]

        if bad_wl:
            self.whitelist_warn_icon.set_visible(True)
            self.whitelist_warn_icon.set_tooltip_text(f"Invalid domain or IP: {', '.join(bad_wl)}")
        else:
            self.whitelist_warn_icon.set_visible(False)

        if bad_bl:
            self.blacklist_warn_icon.set_visible(True)
            self.blacklist_warn_icon.set_tooltip_text(f"Invalid domain or IP: {', '.join(bad_bl)}")
        else:
            self.blacklist_warn_icon.set_visible(False)

        if bad_wl:
            return wl_tokens, bl_tokens, f"Invalid allowed domain or IP: '{bad_wl[0]}'"
        if bad_bl:
            return wl_tokens, bl_tokens, f"Invalid blocked domain or IP: '{bad_bl[0]}'"
        return wl_tokens, bl_tokens, None

    def _add_port_preset(self, port_str: str):
        current = self.ports_entry.get_text().strip()
        ports = [p.strip() for p in current.split(",") if p.strip()]
        if port_str not in ports:
            ports.append(port_str)
        self.ports_entry.set_text(", ".join(ports))

    def _check_dir_exists(self, dir_path: str) -> bool:
        path_str = dir_path.strip() if dir_path else ""
        if not path_str:
            self.dir_warn_icon.set_visible(True)
            self.dir_warn_icon.set_tooltip_text("Directory path cannot be empty")
            self.dir_banner.set_title("Workspace directory path is empty")
            self.dir_banner.set_button_label(None)
            self.dir_banner.set_revealed(True)
            return False

        p = Path(path_str).expanduser()
        if p.exists():
            if p.is_dir():
                self.dir_warn_icon.set_visible(False)
                self.dir_banner.set_revealed(False)
                return True
            self.dir_warn_icon.set_visible(True)
            self.dir_warn_icon.set_tooltip_text(f"Path is not a directory: {p}")
            self.dir_banner.set_title(f"Target is a file, not a directory: {p}")
            self.dir_banner.set_button_label(None)
            self.dir_banner.set_revealed(True)
            return False

        self.dir_warn_icon.set_visible(True)
        self.dir_warn_icon.set_tooltip_text(f"Directory '{p}' does not exist on disk")
        self.dir_banner.set_title(f"Directory does not exist: {p}")
        self.dir_banner.set_button_label("Create Folder")
        self.dir_banner.set_revealed(True)
        return False

    def _on_dir_changed(self, entry):
        text = entry.get_text().strip()
        if text and not getattr(self, "_user_edited_name", False):
            name = self.manager.generate_name(text)
            self.name_row.set_text(name)
        self._check_dir_exists(text)

    def _on_create_dir_clicked(self, _banner):
        dir_text = self.dir_entry.get_text().strip()
        if not dir_text:
            return
        p = Path(dir_text).expanduser()
        try:
            p.mkdir(parents=True, exist_ok=True)
            self._check_dir_exists(dir_text)
            self._set_feedback(f"Created workspace directory: {p}", is_error=False)
            self.toast_overlay.add_toast(Adw.Toast.new(f"Created folder: {p.name}"))
        except Exception as e:
            self._set_feedback(f"Failed to create directory: {e}", is_error=True)

    def _browse_fallback(self):
        pass

    def _on_browse_clicked(self, _btn):
        try:
            file_dialog = Gtk.FileDialog()
            file_dialog.set_title("Select Project Workspace")

            curr_text = self.dir_entry.get_text().strip()
            if curr_text:
                p = Path(curr_text).expanduser()
                if p.exists() and p.is_dir():
                    file_dialog.set_initial_folder(Gio.File.new_for_path(str(p)))
                elif p.parent.exists() and p.parent.is_dir():
                    file_dialog.set_initial_folder(Gio.File.new_for_path(str(p.parent)))

            def on_selected(dialog, result):
                try:
                    folder = dialog.select_folder_finish(result)
                    if folder:
                        path = folder.get_path()
                        if path:
                            self.dir_entry.set_text(path)
                except Exception:
                    pass

            file_dialog.select_folder(self, None, on_selected)
        except Exception:
            self._browse_fallback()

    def _on_launch_clicked(self, _btn):
        dir_path = self.dir_entry.get_text().strip()
        name = self.name_row.get_text().strip()

        if not dir_path:
            self._set_feedback("Please enter a workspace directory path.", is_error=True)
            return

        # Auto-stage un-added text in env_key_entry if user typed a key/value without clicking Add
        pending_key = self.env_key_entry.get_text().strip()
        pending_val = self.env_val_entry.get_text()
        if pending_key:
            ok, msg = self.stage_variable(
                pending_key, pending_val, is_secret=self.env_secret_switch.get_active()
            )
            if not ok:
                self._set_feedback(msg, is_error=True)
                return
            self.env_key_entry.set_text("")
            self.env_val_entry.set_text("")

        _wl, _bl, dom_err = self._validate_domains()
        if dom_err:
            self._set_feedback(dom_err, is_error=True)
            return

        p = Path(dir_path).expanduser()
        if not p.exists() or not p.is_dir():
            self._prompt_create_and_launch(dir_path, name)
            return

        self._execute_launch(str(p), name)

    def _prompt_create_and_launch(self, dir_path: str, name: str):
        p = Path(dir_path).expanduser()

        def on_response(response_id: str):
            if response_id == "create":
                try:
                    p.mkdir(parents=True, exist_ok=True)
                    self._check_dir_exists(dir_path)
                    self._execute_launch(str(p), name)
                except Exception as e:
                    self._set_feedback(f"Failed to create directory: {e}", is_error=True)

        show_alert_dialog(
            parent_window=self,
            heading="Create Workspace Directory?",
            body=f"The directory '{p}' does not exist on disk.\n\nCreate it and launch the sandbox?",
            responses=[
                ("cancel", "Cancel"),
                ("create", "Create & Launch", Adw.ResponseAppearance.SUGGESTED),
            ],
            on_response=on_response,
            default_response="create",
            close_response="cancel",
        )

    def _execute_launch(self, dir_path: str, name: str):
        sel_idx = self.image_combo.get_selected()
        if sel_idx == Gtk.INVALID_LIST_POSITION or sel_idx >= len(self.image_keys):
            sel_idx = 0
        img_key = self.image_keys[sel_idx]
        image_tag = BUILTIN_IMAGES[img_key]["tag"]

        is_persistent = self.persist_switch.get_active()

        net_idx = self.net_combo.get_selected()
        if net_idx == Gtk.INVALID_LIST_POSITION or net_idx >= len(self.net_keys):
            net_idx = 0
        net_profile = self.net_keys[net_idx]

        allowed_domains, denied_domains, dom_err = self._validate_domains()
        if dom_err:
            self._set_feedback(dom_err, is_error=True)
            return

        net_policy = NetworkPolicy(
            profile=net_profile,
            allowed_domains=allowed_domains,
            denied_domains=denied_domains,
        )

        ports_raw = self.ports_entry.get_text().strip()
        ports_list = [p.strip() for p in ports_raw.split(",") if p.strip()]

        cpus = int(self.cpu_row.get_value())
        ram_mib = int(self.ram_row.get_value()) * 1024

        protect_git_hooks = self.git_hooks_switch.get_active()
        protect_git_config = self.git_config_switch.get_active()
        protect_env_files = self.env_files_switch.get_active()
        host_egress_lockdown = self.host_lockdown_switch.get_active()
        idle_timeout_minutes = int(self.idle_timeout_row.get_value())
        idle_idx = self.idle_action_combo.get_selected()
        idle_action = self.idle_actions[idle_idx] if idle_idx < len(self.idle_actions) else "stop"
        max_tokens_budget = int(self.max_tokens_row.get_value())
        max_cost_usd_budget = float(self.max_cost_row.get_value())
        selected_tmpl = self._selected_template()
        template_id = selected_tmpl.id if selected_tmpl else None

        staged_env_copy = dict(self._staged_env)
        staged_secrets_copy = dict(self._staged_secrets)
        staged_passthrough_copy = list(self._staged_passthrough)

        self.launch_btn.set_sensitive(False)
        self.cancel_btn.set_sensitive(False)
        self.launch_spinner.set_visible(True)
        self.launch_spinner.start()
        self.launch_label.set_text("Launching…")
        self._set_feedback("Initializing and booting microVM…", is_error=False)

        def worker():
            if hasattr(self.manager, "images"):
                needs_build, reason = self.manager.images.should_build_or_update(image_tag)
                if needs_build:
                    GLib.idle_add(self._set_feedback, f"Building container image '{img_key}' ({reason})…", False)
            box = self.manager.create_sandbox(
                dir_path=dir_path,
                name=name,
                base_image=image_tag,
                is_persistent=is_persistent,
                network_policy=net_policy,
                ports=ports_list,
                cpus=cpus,
                ram_mib=ram_mib,
                protect_git_hooks=protect_git_hooks,
                protect_git_config=protect_git_config,
                protect_env_files=protect_env_files,
                host_egress_lockdown=host_egress_lockdown,
                idle_timeout_minutes=idle_timeout_minutes,
                idle_action=idle_action,
                env_vars=staged_env_copy,
                secret_keys=sorted(staged_secrets_copy.keys()),
                host_env_passthrough=staged_passthrough_copy,
                max_tokens_budget=max_tokens_budget,
                max_cost_usd_budget=max_cost_usd_budget,
                template_id=template_id,
            )
            for sec_key, sec_val in staged_secrets_copy.items():
                self.secret_mgr.set_secret(box.name, sec_key, sec_val)
            return self.manager.start_sandbox(box.name, detach=True)

        def on_done(result):
            if self._closed:
                return
            self.launch_spinner.stop()
            self.launch_spinner.set_visible(False)
            self.launch_label.set_text("Launch")
            ok, msg = result
            if ok:
                self.on_created()
                self.close()
            else:
                self.launch_btn.set_sensitive(True)
                self.cancel_btn.set_sensitive(True)
                self._set_feedback(msg, is_error=True)

        def on_err(exc):
            if self._closed:
                return
            self.launch_spinner.stop()
            self.launch_spinner.set_visible(False)
            self.launch_label.set_text("Launch")
            self.launch_btn.set_sensitive(True)
            self.cancel_btn.set_sensitive(True)
            self._set_feedback(str(exc), is_error=True)

        run_async(worker, on_success=on_done, on_error=on_err)
