"""
Native Libadwaita Preferences Window for krunbox.
"""

from typing import Callable, Optional
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw

from ..core.config import BUILTIN_IMAGES, NETWORK_PROFILES
from ..core.settings import load_settings, save_settings


PreferencesBase = getattr(Adw, "PreferencesDialog", getattr(Adw, "PreferencesWindow", Gtk.Window))


class SettingsDialog(PreferencesBase):
    def __init__(
        self,
        parent_window: Gtk.Window,
        on_settings_changed: Optional[Callable[[], None]] = None,
    ):
        self.parent_window = parent_window
        self.on_settings_changed = on_settings_changed
        self.settings = load_settings()
        self._initializing = True

        if hasattr(Adw, "PreferencesDialog") and issubclass(self.__class__, Adw.PreferencesDialog):
            super().__init__()
        else:
            super().__init__(modal=True, transient_for=parent_window)
            self.set_default_size(580, 560)

        self.set_title("Preferences")

        page_general = Adw.PreferencesPage()
        page_general.set_title("General")
        page_general.set_icon_name("preferences-system-symbolic")
        self.add(page_general)

        # Group 1: Appearance & Interface
        group_theme = Adw.PreferencesGroup(
            title="Appearance &amp; Interface",
            description="Choose application color scheme and status polling cadence",
        )
        page_general.add(group_theme)

        self.theme_options = ["system", "light", "dark"]
        theme_labels = ["System", "Light", "Dark"]
        self.theme_combo = Adw.ComboRow(title="Color Scheme")
        self.theme_combo.set_model(Gtk.StringList.new(theme_labels))

        cur_theme = self.settings.get("color_scheme", "system")
        idx = self.theme_options.index(cur_theme) if cur_theme in self.theme_options else 0
        self.theme_combo.set_selected(idx)
        self.theme_combo.connect("notify::selected", self._on_theme_changed)
        group_theme.add(self.theme_combo)

        self.refresh_row = Adw.SpinRow.new_with_range(1, 60, 1)
        self.refresh_row.set_title("Refresh Interval (seconds)")
        self.refresh_row.set_subtitle("Background sandbox status and resource polling interval")
        self.refresh_row.set_value(max(1, int(self.settings.get("auto_refresh_seconds", 3))))
        self.refresh_row.connect("notify::value", self._save_all_settings)
        group_theme.add(self.refresh_row)

        # Group 2: Sandbox Defaults
        group_defaults = Adw.PreferencesGroup(
            title="Sandbox Defaults",
            description="Default configuration pre-selected when creating a new sandbox",
        )
        page_general.add(group_defaults)

        self.image_keys = list(BUILTIN_IMAGES.keys())
        self.image_combo = Adw.ComboRow(title="Default Base Image")
        self.image_combo.set_model(Gtk.StringList.new(self.image_keys))
        cur_image = self.settings.get("default_image", "agent-box")
        img_idx = self.image_keys.index(cur_image) if cur_image in self.image_keys else 0
        self.image_combo.set_selected(img_idx)
        self.image_combo.connect("notify::selected", self._save_all_settings)
        group_defaults.add(self.image_combo)

        self.cpu_row = Adw.SpinRow.new_with_range(1, 32, 1)
        self.cpu_row.set_title("Default Virtual CPUs")
        self.cpu_row.set_value(int(self.settings.get("default_cpus", 4)))
        self.cpu_row.connect("notify::value", self._save_all_settings)
        group_defaults.add(self.cpu_row)

        self.ram_row = Adw.SpinRow.new_with_range(1, 64, 1)
        self.ram_row.set_title("Default Memory (GiB)")
        self.ram_row.set_value(max(1, round(int(self.settings.get("default_ram_mib", 4096)) / 1024)))
        self.ram_row.connect("notify::value", self._save_all_settings)
        group_defaults.add(self.ram_row)

        self.net_options = list(NETWORK_PROFILES.keys())
        net_labels = [NETWORK_PROFILES[k]["name"] for k in self.net_options]
        self.net_combo = Adw.ComboRow(title="Default Egress Policy")
        self.net_combo.set_model(Gtk.StringList.new(net_labels))
        cur_net = self.settings.get("default_network", "full")
        net_idx = self.net_options.index(cur_net) if cur_net in self.net_options else 0
        self.net_combo.set_selected(net_idx)
        self.net_combo.connect("notify::selected", self._save_all_settings)
        group_defaults.add(self.net_combo)

        self.persist_switch = Adw.SwitchRow(
            title="Default to Persistent Sandboxes",
            subtitle="Preserve rootfs changes across stops (Off = Ephemeral)",
        )
        self.persist_switch.set_active(bool(self.settings.get("default_persistent", False)))
        self.persist_switch.connect("notify::active", self._save_all_settings)
        group_defaults.add(self.persist_switch)

        # Page 2: Security & Guardrails
        page_security = Adw.PreferencesPage()
        page_security.set_title("Guardrails")
        page_security.set_icon_name("security-high-symbolic")
        self.add(page_security)

        group_guardrails = Adw.PreferencesGroup(
            title="Workspace &amp; Egress Hardening",
            description="Default mount masks and host-boundary network protections for new sandboxes",
        )
        page_security.add(group_guardrails)

        self.git_hooks_switch = Adw.SwitchRow(
            title="Protect .git/hooks (Read-Only)",
            subtitle="Block agents from planting malicious host git hooks",
        )
        self.git_hooks_switch.set_active(bool(self.settings.get("default_protect_git_hooks", True)))
        self.git_hooks_switch.connect("notify::active", self._save_all_settings)
        group_guardrails.add(self.git_hooks_switch)

        self.git_config_switch = Adw.SwitchRow(
            title="Protect .git/config (Read-Only)",
            subtitle="Prevent modification of git remotes, aliases, and core.sshCommand",
        )
        self.git_config_switch.set_active(bool(self.settings.get("default_protect_git_config", False)))
        self.git_config_switch.connect("notify::active", self._save_all_settings)
        group_guardrails.add(self.git_config_switch)

        self.env_files_switch = Adw.SwitchRow(
            title="Protect Workspace .env Files (Read-Only)",
            subtitle="Mount existing .env and .env.* files read-only inside /workspace",
        )
        self.env_files_switch.set_active(bool(self.settings.get("default_protect_env_files", False)))
        self.env_files_switch.connect("notify::active", self._save_all_settings)
        group_guardrails.add(self.env_files_switch)

        self.host_lockdown_switch = Adw.SwitchRow(
            title="Host-Boundary Egress Lockdown",
            subtitle="Enforce egress firewall outside the guest VM and drop CAP_NET_ADMIN",
        )
        self.host_lockdown_switch.set_active(bool(self.settings.get("default_host_egress_lockdown", False)))
        self.host_lockdown_switch.connect("notify::active", self._save_all_settings)
        group_guardrails.add(self.host_lockdown_switch)

        # Idle Sleep & Notifications
        group_alerts = Adw.PreferencesGroup(
            title="Idle Sleep &amp; Desktop Alerts",
            description="Automatic battery/RAM conservation and native desktop notifications",
        )
        page_security.add(group_alerts)

        self.idle_timeout_row = Adw.SpinRow.new_with_range(0, 480, 5)
        self.idle_timeout_row.set_title("Default Idle Timeout (minutes)")
        self.idle_timeout_row.set_subtitle("0 disables idle sleep; triggers when 0 SSH sessions and CPU &lt; 1%")
        self.idle_timeout_row.set_value(max(0, int(self.settings.get("default_idle_timeout_minutes", 0))))
        self.idle_timeout_row.connect("notify::value", self._save_all_settings)
        group_alerts.add(self.idle_timeout_row)

        self.idle_actions = ["stop", "pause"]
        self.idle_action_combo = Adw.ComboRow(
            title="Default Idle Action",
            subtitle="Action when idle timer expires",
        )
        self.idle_action_combo.set_model(Gtk.StringList.new(["Stop Sandbox", "Pause MicroVM"]))
        cur_idle_act = self.settings.get("default_idle_action", "stop")
        idle_idx = self.idle_actions.index(cur_idle_act) if cur_idle_act in self.idle_actions else 0
        self.idle_action_combo.set_selected(idle_idx)
        self.idle_action_combo.connect("notify::selected", self._save_all_settings)
        group_alerts.add(self.idle_action_combo)

        self.notifications_switch = Adw.SwitchRow(
            title="Desktop Notifications",
            subtitle="Alert on blocked exfiltration spikes, RAM pressure, and budget limits",
        )
        self.notifications_switch.set_active(bool(self.settings.get("enable_desktop_notifications", True)))
        self.notifications_switch.connect("notify::active", self._save_all_settings)
        group_alerts.add(self.notifications_switch)

        self.mem_threshold_row = Adw.SpinRow.new_with_range(50, 99, 5)
        self.mem_threshold_row.set_title("Memory Pressure Alert (%)")
        self.mem_threshold_row.set_value(min(99, max(50, int(self.settings.get("mem_pressure_threshold_percent", 90)))))
        self.mem_threshold_row.connect("notify::value", self._save_all_settings)
        group_alerts.add(self.mem_threshold_row)

        self.spike_threshold_row = Adw.SpinRow.new_with_range(1, 100, 1)
        self.spike_threshold_row.set_title("Blocked Domain Spike Threshold")
        self.spike_threshold_row.set_subtitle("Blocked egress attempts per window before alerting")
        self.spike_threshold_row.set_value(max(1, int(self.settings.get("blocked_egress_spike_threshold", 5))))
        self.spike_threshold_row.connect("notify::value", self._save_all_settings)
        group_alerts.add(self.spike_threshold_row)

        # AI Token & Cost Guardrails
        group_budget = Adw.PreferencesGroup(
            title="AI Cost &amp; Token Budget Defaults",
            description="Default safety caps on API spend and token consumption for new sandboxes",
        )
        page_security.add(group_budget)

        self.tokens_budget_row = Adw.SpinRow.new_with_range(0, 100000000, 10000)
        self.tokens_budget_row.set_title("Default Token Budget (tokens)")
        self.tokens_budget_row.set_subtitle("0 disables token limit; stops or warns when consumed")
        self.tokens_budget_row.set_value(max(0, int(self.settings.get("default_max_tokens_budget", 0))))
        self.tokens_budget_row.connect("notify::value", self._save_all_settings)
        group_budget.add(self.tokens_budget_row)

        self.cost_budget_row = Adw.SpinRow.new_with_range(0.0, 5000.0, 1.0)
        self.cost_budget_row.set_digits(2)
        self.cost_budget_row.set_title("Default Cost Budget (USD $)")
        self.cost_budget_row.set_subtitle("0.00 disables spend limit")
        self.cost_budget_row.set_value(max(0.0, float(self.settings.get("default_max_cost_usd_budget", 0.0))))
        self.cost_budget_row.connect("notify::value", self._save_all_settings)
        group_budget.add(self.cost_budget_row)

        self._initializing = False

    def _on_theme_changed(self, combo, _param):
        sel_idx = combo.get_selected()
        if sel_idx == Gtk.INVALID_LIST_POSITION or sel_idx >= len(self.theme_options):
            sel_idx = 0
        theme = self.theme_options[sel_idx]
        self.settings["color_scheme"] = theme
        save_settings(self.settings)

        style_mgr = Adw.StyleManager.get_default()
        if theme == "light":
            style_mgr.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
        elif theme == "dark":
            style_mgr.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
        else:
            style_mgr.set_color_scheme(Adw.ColorScheme.DEFAULT)

        if self.on_settings_changed:
            self.on_settings_changed()

    def _save_all_settings(self, *_args):
        if self._initializing:
            return
        self.settings["auto_refresh_seconds"] = max(1, int(self.refresh_row.get_value()))
        img_idx = self.image_combo.get_selected()
        if img_idx != Gtk.INVALID_LIST_POSITION and img_idx < len(self.image_keys):
            self.settings["default_image"] = self.image_keys[img_idx]
        self.settings["default_cpus"] = int(self.cpu_row.get_value())
        self.settings["default_ram_mib"] = int(self.ram_row.get_value()) * 1024
        net_idx = self.net_combo.get_selected()
        if net_idx != Gtk.INVALID_LIST_POSITION and net_idx < len(self.net_options):
            self.settings["default_network"] = self.net_options[net_idx]
        self.settings["default_persistent"] = self.persist_switch.get_active()
        self.settings["default_protect_git_hooks"] = self.git_hooks_switch.get_active()
        self.settings["default_protect_git_config"] = self.git_config_switch.get_active()
        self.settings["default_protect_env_files"] = self.env_files_switch.get_active()
        self.settings["default_host_egress_lockdown"] = self.host_lockdown_switch.get_active()
        self.settings["default_idle_timeout_minutes"] = int(self.idle_timeout_row.get_value())
        idle_idx = self.idle_action_combo.get_selected()
        if idle_idx != Gtk.INVALID_LIST_POSITION and idle_idx < len(self.idle_actions):
            self.settings["default_idle_action"] = self.idle_actions[idle_idx]
        self.settings["enable_desktop_notifications"] = self.notifications_switch.get_active()
        self.settings["mem_pressure_threshold_percent"] = int(self.mem_threshold_row.get_value())
        self.settings["blocked_egress_spike_threshold"] = int(self.spike_threshold_row.get_value())
        self.settings["default_max_tokens_budget"] = int(self.tokens_budget_row.get_value())
        self.settings["default_max_cost_usd_budget"] = float(self.cost_budget_row.get_value())
        save_settings(self.settings)
        if self.on_settings_changed:
            self.on_settings_changed()

    def present(self, parent: Optional[Gtk.Widget] = None):
        target = parent or getattr(self, "parent_window", None)
        if hasattr(Adw, "Dialog") and isinstance(self, Adw.Dialog):
            if target:
                super().present(target)
            else:
                super().present()
        else:
            super().present()
