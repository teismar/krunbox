"""
Outbound Network Policy Reference & Comparison Dialog in GTK4 / Libadwaita.
Provides a clear, structured table view of allowed domains, destination scopes, and network rules across all policies.
"""

from typing import Callable, Dict, List, Optional
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk, Pango

from ..core.config import NETWORK_PROFILES


# Categorized domain breakdown for Developer Repositories & AI
DEV_COMMON_CATEGORIES: Dict[str, List[str]] = {
    "AI Model Providers": [
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "api.mistral.ai",
        "huggingface.co",
    ],
    "Package Registries": [
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "crates.io",
        "rubygems.org",
    ],
    "Code Repositories & Distro Mirrors": [
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "codeload.github.com",
        "deb.debian.org",
        "archive.ubuntu.com",
        "security.ubuntu.com",
        "registry-1.docker.io",
        "auth.docker.io",
        "production.cloudflare.docker.com",
    ],
}


class NetworkPolicyReferenceDialog(Adw.Window):
    """
    Modal dialog displaying a comprehensive reference table of outbound egress policies,
    detailing allowed endpoints, domain counts, and security posture.
    """

    def __init__(
        self,
        parent_window: Optional[Gtk.Window] = None,
        current_profile: str = "full",
        on_select: Optional[Callable[[str], None]] = None,
    ):
        super().__init__()
        self.set_title("Outbound Access Policies")
        self.set_default_size(700, 580)
        self.set_modal(True)
        if parent_window:
            self.set_transient_for(parent_window)

        self.current_profile = current_profile
        self.on_select = on_select

        toolbar_view = Adw.ToolbarView()
        self.set_content(toolbar_view)

        # HeaderBar
        header = Adw.HeaderBar()
        toolbar_view.add_top_bar(header)

        # Search Entry in header or below
        search_bar = Gtk.SearchBar()
        self.search_entry = Gtk.SearchEntry(placeholder_text="Search domains (e.g. pypi, openai, github)…")
        self.search_entry.connect("search-changed", self._on_search_changed)
        search_bar.set_child(self.search_entry)
        search_bar.set_key_capture_widget(self)
        search_bar.set_search_mode(True)
        toolbar_view.add_top_bar(search_bar)

        # Content Page
        page = Adw.PreferencesPage()
        toolbar_view.set_content(page)

        # Overview Group
        group_overview = Adw.PreferencesGroup(
            title="Egress Firewall Profiles",
            description="Hardware-enforced packet filtering applied at host network boundary",
        )
        page.add(group_overview)

        self.profile_rows: Dict[str, Adw.ExpanderRow] = {}
        self.domain_labels: List[Tuple[str, Gtk.Widget, str]] = []  # (profile_key, widget, domain_text)

        self._build_profile_sections(group_overview)

    def _build_profile_sections(self, group: Adw.PreferencesGroup):
        profile_icons = {
            "full": "network-transmit-receive-symbolic",
            "ai-only": "system-run-symbolic",
            "dev-common": "applications-development-symbolic",
            "offline": "network-offline-symbolic",
            "custom": "preferences-system-network-symbolic",
        }

        profile_scope_badges = {
            "full": "All Outbound Allowed (0.0.0.0/0)",
            "ai-only": "10 AI Endpoints Allowed",
            "dev-common": "20 Development and AI Endpoints Allowed",
            "offline": "Airgapped (0 External Endpoints)",
            "custom": "User-Defined Whitelist Only",
        }

        for key, info in NETWORK_PROFILES.items():
            name = info.get("name", key)
            desc = info.get("description", "")
            domains = info.get("domains", [])
            icon_name = profile_icons.get(key, "network-wired-symbolic")

            expander = Adw.ExpanderRow(
                title=name,
                subtitle=desc,
            )
            expander.add_prefix(Gtk.Image.new_from_icon_name(icon_name))

            # Suffix badge / button
            scope_badge = Gtk.Label(label=profile_scope_badges.get(key, ""))
            scope_badge.add_css_class("dim-label")
            scope_badge.add_css_class("caption")
            expander.add_suffix(scope_badge)

            if key == self.current_profile:
                active_icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
                active_icon.add_css_class("success")
                active_icon.set_tooltip_text("Currently Selected Profile")
                expander.add_suffix(active_icon)
            elif self.on_select:
                apply_btn = Gtk.Button(label="Select")
                apply_btn.add_css_class("flat")
                apply_btn.set_valign(Gtk.Align.CENTER)
                apply_btn.connect("clicked", self._make_select_handler(key))
                expander.add_suffix(apply_btn)

            # Add content rows inside expander
            if key == "full":
                r = Adw.ActionRow(
                    title="Unrestricted Outbound Internet",
                    subtitle="Direct outbound TCP/UDP traffic and standard DNS queries permitted to any destination host or IP.",
                )
                r.add_prefix(Gtk.Image.new_from_icon_name("network-transmit-receive-symbolic"))
                expander.add_row(r)
            elif key == "offline":
                r = Adw.ActionRow(
                    title="Airgapped Isolation",
                    subtitle="All egress traffic dropped by host firewall. Only loopback (127.0.0.1) and host IPC sockets allowed.",
                )
                r.add_prefix(Gtk.Image.new_from_icon_name("network-offline-symbolic"))
                expander.add_row(r)
            elif key == "custom":
                r = Adw.ActionRow(
                    title="Dynamic Whitelist Enforcement",
                    subtitle="Only destinations explicitly entered in the Allowed Domains field (e.g. example.com, 10.0.0.0/8) are permitted.",
                )
                r.add_prefix(Gtk.Image.new_from_icon_name("preferences-system-network-symbolic"))
                expander.add_row(r)
            elif key == "ai-only":
                r_summary = Adw.ActionRow(
                    title="Major AI Provider Endpoints (10 Domains)",
                    subtitle="Permits prompt streaming, tool execution, and token estimation exclusively with verified AI APIs.",
                )
                expander.add_row(r_summary)

                for domain in sorted(domains):
                    d_row = Adw.ActionRow(title=domain)
                    d_row.add_css_class("monospace")
                    lbl = Gtk.Label(label="Allowed")
                    lbl.add_css_class("success")
                    lbl.add_css_class("caption")
                    d_row.add_suffix(lbl)
                    expander.add_row(d_row)
                    self.domain_labels.append((key, d_row, domain))
            elif key == "dev-common":
                r_summary = Adw.ActionRow(
                    title="Comprehensive Development and AI Stack (20 Domains)",
                    subtitle="Includes major AI APIs plus essential package registries (pip, npm, cargo), GitHub, Docker Hub, and OS repos.",
                )
                expander.add_row(r_summary)

                for cat_name, cat_domains in DEV_COMMON_CATEGORIES.items():
                    cat_row = Adw.ActionRow(title=f"• {cat_name}")
                    cat_row.add_css_class("heading")
                    expander.add_row(cat_row)

                    for d in cat_domains:
                        d_row = Adw.ActionRow(title=f"  {d}")
                        d_row.add_css_class("monospace")
                        lbl = Gtk.Label(label="Allowed")
                        lbl.add_css_class("success")
                        lbl.add_css_class("caption")
                        d_row.add_suffix(lbl)
                        expander.add_row(d_row)
                        self.domain_labels.append((key, d_row, d))

            # Auto-expand the currently selected profile
            if key == self.current_profile or key in ("ai-only", "dev-common"):
                expander.set_expanded(key == self.current_profile)

            group.add(expander)
            self.profile_rows[key] = expander

    def _make_select_handler(self, key: str):
        def _handler(_btn):
            if self.on_select:
                self.on_select(key)
            self.close()
        return _handler

    def _on_search_changed(self, entry: Gtk.SearchEntry):
        query = entry.get_text().strip().lower()
        if not query:
            for _, widget, _ in self.domain_labels:
                widget.set_visible(True)
            for expander in self.profile_rows.values():
                expander.set_visible(True)
            return

        matching_profiles = set()
        for prof_key, widget, domain_text in self.domain_labels:
            matched = query in domain_text.lower()
            widget.set_visible(matched)
            if matched:
                matching_profiles.add(prof_key)

        for key, expander in self.profile_rows.items():
            name = NETWORK_PROFILES[key].get("name", "").lower()
            desc = NETWORK_PROFILES[key].get("description", "").lower()
            is_match = (key in matching_profiles) or (query in name) or (query in desc)
            expander.set_visible(is_match)
            if is_match and key in matching_profiles:
                expander.set_expanded(True)
