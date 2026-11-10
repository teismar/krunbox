"""
In-Sandbox MCP Integration & Setup Guide Dialog in GTK4 / Libadwaita.

Provides detailed, copyable instructions and configuration stanzas for connecting
any AI agent (Antigravity CLI, Claude, Cursor, Cline, Windsurf, or custom scripts)
to the in-sandbox krunbox-gateway Model Context Protocol (MCP) server.
"""

import re
from typing import Optional
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk, Pango

STDIO_MCP_CONFIG_JSON = """{
  "mcpServers": {
    "krunbox-gateway": {
      "command": "/run/krunbox/krunbox-mcp",
      "args": []
    }
  }
}"""

PYTHON_IPC_SNIPPET = """import socket, json

# Connect directly to the host permission gateway socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/run/krunbox/ipc.sock")

# Send domain whitelist access request
req = {
    "action": "request_domain_access",
    "domain": "example.com",
    "reason": "Fetch training dataset or external API"
}
sock.sendall(json.dumps(req).encode("utf-8") + b"\\n")

# Wait for operator response (approved or denied)
resp = json.loads(sock.recv(4096).decode("utf-8"))
print(resp)  # {"status": "approved", "domain": "example.com"}"""


def highlight_json_markup(json_str: str, dark: bool = False) -> str:
    """Syntax-highlight JSON code using Pango markup with theme-aware colors."""
    if dark:
        key_color = "#78aeed"    # bright blue (bold)
        str_color = "#8ff0a4"    # bright green
        num_color = "#dc8add"    # bright purple
        bool_color = "#ffbe6f"   # bright amber/orange
        punct_color = "#9a9996"  # dim gray
    else:
        key_color = "#1a5fb4"    # deep blue (bold)
        str_color = "#26a269"    # forest green
        num_color = "#813d9c"    # deep purple
        bool_color = "#c64600"   # deep amber/orange
        punct_color = "#77767b"  # gray

    tokens = re.split(
        r'(\"(?:\\.|[^"])*\"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|[{}\[\],:])',
        json_str,
    )
    result = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if not tok:
            i += 1
            continue

        escaped = GLib.markup_escape_text(tok)
        if tok.startswith('"'):
            # Lookahead to see if next non-whitespace token is a colon
            is_key = False
            for next_tok in tokens[i + 1:]:
                if not next_tok.strip():
                    continue
                if next_tok == ":":
                    is_key = True
                break

            if is_key:
                result.append(f'<span foreground="{key_color}" weight="bold">{escaped}</span>')
            else:
                result.append(f'<span foreground="{str_color}">{escaped}</span>')
        elif re.match(r'^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?$', tok):
            result.append(f'<span foreground="{num_color}">{escaped}</span>')
        elif tok in ("true", "false", "null"):
            result.append(f'<span foreground="{bool_color}" weight="bold">{escaped}</span>')
        elif tok in "{}[],:":
            result.append(f'<span foreground="{punct_color}">{escaped}</span>')
        else:
            result.append(escaped)
        i += 1
    return "".join(result)


def highlight_python_markup(py_str: str, dark: bool = False) -> str:
    """Syntax-highlight Python code using Pango markup with theme-aware colors."""
    kw_color = "#c061cb" if dark else "#813d9c"
    str_color = "#8ff0a4" if dark else "#26a269"
    comment_color = "#9a9996" if dark else "#77767b"
    num_color = "#dc8add" if dark else "#813d9c"

    tokens = re.split(
        r'(\"\"\"[\s\S]*?\"\"\"|\"(?:\\.|[^"])*\"|\'(?:\\.|[^\'])*\'|#[^\n]*|\b(?:import|from|as|def|return|if|else|elif|for|while|try|except|finally|with|print|True|False|None)\b|-?\b\d+\b)',
        py_str,
    )
    result = []
    for tok in tokens:
        if not tok:
            continue
        escaped = GLib.markup_escape_text(tok)
        if tok.startswith("#"):
            result.append(f'<span foreground="{comment_color}" style="italic">{escaped}</span>')
        elif tok.startswith(('"', "'")):
            result.append(f'<span foreground="{str_color}">{escaped}</span>')
        elif re.match(
            r"\b(?:import|from|as|def|return|if|else|elif|for|while|try|except|finally|with|print|True|False|None)\b",
            tok,
        ):
            result.append(f'<span foreground="{kw_color}" weight="bold">{escaped}</span>')
        elif re.match(r"^-?\b\d+\b$", tok):
            result.append(f'<span foreground="{num_color}">{escaped}</span>')
        else:
            result.append(escaped)
    return "".join(result)


class McpGuideDialog(Adw.Window):
    """
    Modal dialog providing step-by-step instructions for adding the
    krunbox-gateway MCP server to any AI tool or custom agent in a sandbox.
    """

    def __init__(self, parent_window: Optional[Gtk.Window] = None):
        super().__init__(modal=True, transient_for=parent_window)
        self.set_title("MCP Integration & Setup Guide")
        self.set_default_size(720, 640)

        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        self._highlight_labels = []

        toolbar_view = Adw.ToolbarView()
        self.toast_overlay.set_child(toolbar_view)

        # Header Bar
        header = Adw.HeaderBar()
        toolbar_view.add_top_bar(header)

        title_widget = Adw.WindowTitle(
            title="MCP Setup Guide",
            subtitle="Connect Any AI Agent to krunbox-gateway",
        )
        header.set_title_widget(title_widget)

        # Main Preferences Page
        page = Adw.PreferencesPage()
        toolbar_view.set_content(page)

        # -------------------------------------------------------------
        # Group 1: Overview & Gateway Endpoints
        # -------------------------------------------------------------
        overview_group = Adw.PreferencesGroup(
            title="In-Sandbox Permission Gateway",
            description=(
                "krunbox mounts an in-guest Model Context Protocol (MCP) bridge into every sandbox. "
                "AI agents inside the microVM call this server to request human-in-the-loop "
                "operator approval on the host for outbound domain access and port forwarding."
            ),
        )
        page.add(overview_group)

        self._add_copyable_row(
            overview_group,
            title="Bridge Executable (Stdio MCP)",
            subtitle="/run/krunbox/krunbox-mcp",
            copy_text="/run/krunbox/krunbox-mcp",
            icon_name="utilities-terminal-symbolic",
        )
        self._add_copyable_row(
            overview_group,
            title="Unix Domain Socket (IPC)",
            subtitle="/run/krunbox/ipc.sock",
            copy_text="/run/krunbox/ipc.sock",
            icon_name="network-transmit-receive-symbolic",
        )
        self._add_copyable_row(
            overview_group,
            title="Ready-Made Config Snippet",
            subtitle="/run/krunbox/krunbox_mcp_config.json",
            copy_text="/run/krunbox/krunbox_mcp_config.json",
            icon_name="document-properties-symbolic",
        )

        # -------------------------------------------------------------
        # Group 2: Universal Stdio MCP Configuration
        # -------------------------------------------------------------
        config_group = Adw.PreferencesGroup(
            title="Standard MCP Configuration (JSON)",
            description=(
                "Add this stanza to any MCP-compliant AI tool inside the sandbox. "
                "The tool will execute the bridge over stdio to communicate with the host daemon."
            ),
        )
        page.add(config_group)

        # JSON Code Box with Copy Button
        code_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        code_card.add_css_class("card")
        code_card.set_margin_start(4)
        code_card.set_margin_end(4)
        code_card.set_margin_top(4)
        code_card.set_margin_bottom(8)

        inner_code = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        inner_code.set_margin_start(14)
        inner_code.set_margin_end(14)
        inner_code.set_margin_top(12)
        inner_code.set_margin_bottom(12)
        code_card.append(inner_code)

        top_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        inner_code.append(top_row)

        json_badge = Gtk.Label(label="mcp_config.json")
        json_badge.add_css_class("caption")
        json_badge.add_css_class("dim-label")
        json_badge.set_halign(Gtk.Align.START)
        json_badge.set_hexpand(True)
        top_row.append(json_badge)

        copy_json_btn = Gtk.Button()
        copy_json_btn.set_child(
            Adw.ButtonContent(
                icon_name="edit-copy-symbolic",
                label="Copy JSON",
            )
        )
        copy_json_btn.add_css_class("flat")
        copy_json_btn.add_css_class("suggested-action")
        copy_json_btn.connect(
            "clicked",
            lambda _: self._copy_to_clipboard(
                STDIO_MCP_CONFIG_JSON, "MCP configuration JSON copied to clipboard"
            ),
        )
        top_row.append(copy_json_btn)

        self.json_label = Gtk.Label()
        self.json_label.add_css_class("monospace")
        self.json_label.set_xalign(0.0)
        self.json_label.set_selectable(True)
        inner_code.append(self.json_label)
        self._highlight_labels.append((self.json_label, STDIO_MCP_CONFIG_JSON, "json"))

        config_group.add(code_card)

        # -------------------------------------------------------------
        # Group 3: Setup Instructions by AI Tool
        # -------------------------------------------------------------
        tools_group = Adw.PreferencesGroup(
            title="Tool-Specific Setup Steps",
            description="Detailed configuration instructions for popular AI developer tools and agents:",
        )
        page.add(tools_group)

        # Antigravity CLI (agy)
        self._add_tool_expander(
            tools_group,
            title="Antigravity CLI (agy)",
            subtitle="Official Google Antigravity developer agent",
            icon_name="utilities-terminal-symbolic",
            steps=[
                (
                    "Method 1 - Automatic CLI Command",
                    "Inside your sandbox terminal, run:",
                    "agy mcp add --name krunbox-gateway --command /run/krunbox/krunbox-mcp",
                ),
                (
                    "Method 2 - Global Configuration File",
                    "Place the JSON stanza in ~/.gemini/config/mcp_config.json:",
                    "mkdir -p ~/.gemini/config && cp /run/krunbox/krunbox_mcp_config.json ~/.gemini/config/mcp_config.json",
                ),
                (
                    "Method 3 - Workspace Configuration File",
                    "Or place it in the workspace directory (<workspace>/.agents/ or .antigravity/):",
                    "mkdir -p /workspace/.agents && cp /run/krunbox/krunbox_mcp_config.json /workspace/.agents/mcp_config.json",
                ),
                (
                    "Verification",
                    "Launch agy in the container and type /mcp. You should see 'krunbox-gateway' connected with 3 active tools.",
                    None,
                ),
            ],
        )

        # Claude Desktop & Claude Code
        self._add_tool_expander(
            tools_group,
            title="Claude Desktop & Claude Code CLI",
            subtitle="Anthropic Claude agent environments",
            icon_name="applications-engineering-symbolic",
            steps=[
                (
                    "Claude Desktop Configuration",
                    "Add the krunbox-gateway stanza under 'mcpServers' in ~/.config/Claude/claude_desktop_config.json:",
                    "mkdir -p ~/.config/Claude && cp /run/krunbox/krunbox_mcp_config.json ~/.config/Claude/claude_desktop_config.json",
                ),
                (
                    "Claude Code CLI Command",
                    "If running the claude CLI tool, run:",
                    "claude mcp add krunbox-gateway /run/krunbox/krunbox-mcp",
                ),
                (
                    "Verification",
                    "The model will now recognize 'request_domain_access' and 'request_port_exposure' as available tools.",
                    None,
                ),
            ],
        )

        # Cursor IDE
        self._add_tool_expander(
            tools_group,
            title="Cursor IDE",
            subtitle="AI-native code editor",
            icon_name="accessories-text-editor-symbolic",
            steps=[
                (
                    "Cursor UI Settings",
                    "1. Open Cursor Settings (Ctrl+,) > Features > MCP.\n"
                    "2. Click '+ Add New MCP Server'.\n"
                    "3. Set Name to 'krunbox-gateway', Type to 'command', and Command to '/run/krunbox/krunbox-mcp'.",
                    None,
                ),
                (
                    "Or Edit Configuration File Directly",
                    "Add the stanza to ~/.cursor/mcp.json:",
                    "mkdir -p ~/.cursor && cp /run/krunbox/krunbox_mcp_config.json ~/.cursor/mcp.json",
                ),
            ],
        )

        # Cline / Roo Code
        self._add_tool_expander(
            tools_group,
            title="Cline & Roo Code (VS Code Extension)",
            subtitle="Autonomous coding agents in VS Code",
            icon_name="system-run-symbolic",
            steps=[
                (
                    "Settings File Path",
                    "Open the Cline/Roo Code extension panel > MCP Servers > Configure MCP Servers, or edit:",
                    "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
                ),
                (
                    "Add Stanza",
                    "Paste the krunbox-gateway configuration under 'mcpServers'.",
                    None,
                ),
            ],
        )

        # Windsurf / Codeium Cascade
        self._add_tool_expander(
            tools_group,
            title="Windsurf & Codeium Cascade",
            subtitle="Next-generation agentic IDE",
            icon_name="applications-system-symbolic",
            steps=[
                (
                    "Configuration File Path",
                    "Add the krunbox-gateway configuration under 'mcpServers' in:",
                    "~/.codeium/windsurf/mcp_config.json",
                ),
            ],
        )

        # Custom AI Tools & Raw Python/Node Scripts
        self._add_tool_expander(
            tools_group,
            title="Custom AI Scripts & SDKs (Python, Node.js, LangChain)",
            subtitle="Integrate with custom agent architectures or direct Unix domain socket calls",
            icon_name="text-x-python-symbolic",
            steps=[
                (
                    "Approach 1 - Stdio Child Process",
                    "Spawn /run/krunbox/krunbox-mcp as a child process using stdin/stdout. "
                    "Communicate using standard line-delimited JSON-RPC 2.0 messages (Model Context Protocol).",
                    "/run/krunbox/krunbox-mcp",
                ),
                (
                    "Approach 2 - Direct Unix Socket IPC",
                    "Send direct JSON requests over the Unix socket at /run/krunbox/ipc.sock:",
                    PYTHON_IPC_SNIPPET,
                ),
                (
                    "Environment Variable",
                    "Optionally set KRUNBOX_IPC_SOCK to override the socket path:",
                    "export KRUNBOX_IPC_SOCK=/run/krunbox/ipc.sock",
                ),
            ],
        )

        # -------------------------------------------------------------
        # Group 4: Gateway Tools Reference
        # -------------------------------------------------------------
        ref_group = Adw.PreferencesGroup(
            title="Available Gateway Tools Reference",
            description="Tools exposed to the agent by krunbox-gateway:",
        )
        page.add(ref_group)

        self._add_action_ref(
            ref_group,
            tool_name="request_domain_access(domain, reason)",
            summary="Request Host Firewall Domain Whitelist",
            description=(
                "Submits an approval request to the host operator to whitelist an outbound "
                "internet domain (e.g. 'github.com', 'teismar.de'). On approval, host nftables "
                "and DNS rules are hot-reloaded immediately without restarting the microVM."
            ),
        )
        self._add_action_ref(
            ref_group,
            tool_name="request_port_exposure(guest_port, reason)",
            summary="Request Host Port Exposure via SSH Tunnel",
            description=(
                "Submits an approval request to forward an internal TCP port (e.g. 3000, 5173, 8080) "
                "to an available host port via dynamic SSH reverse tunnel. Returns the assigned host port."
            ),
        )
        self._add_action_ref(
            ref_group,
            tool_name="get_sandbox_status()",
            summary="Query Sandbox Security & Hardware Status",
            description=(
                "Returns the current sandbox egress profile (full, ai-only, dev-common, offline), "
                "active whitelisted domains, forwarded ports, and CPU/RAM allocation."
            ),
        )

        self._style_manager = Adw.StyleManager.get_default()
        self._style_handler_id = self._style_manager.connect(
            "notify::dark", self._refresh_syntax_highlighting
        )
        self.connect("close-request", self._on_close_request)
        self._refresh_syntax_highlighting()

    def _refresh_syntax_highlighting(self, *_):
        is_dark = self._style_manager.get_dark() if hasattr(self, "_style_manager") else False
        for label, code, lang in self._highlight_labels:
            if lang == "json":
                label.set_markup(highlight_json_markup(code, dark=is_dark))
            elif lang == "python":
                label.set_markup(highlight_python_markup(code, dark=is_dark))
            else:
                label.set_text(code)

    def _on_close_request(self, *_):
        if getattr(self, "_style_handler_id", None):
            try:
                self._style_manager.disconnect(self._style_handler_id)
            except Exception:
                pass
            self._style_handler_id = None
        return False

    def _add_copyable_row(
        self,
        group: Adw.PreferencesGroup,
        title: str,
        subtitle: str,
        copy_text: str,
        icon_name: str,
    ):
        """Add an Adw.ActionRow with a dedicated copy button and tooltip."""
        row = Adw.ActionRow(
            title=GLib.markup_escape_text(title) if title else "",
            subtitle=GLib.markup_escape_text(subtitle) if subtitle else None,
        )
        if icon_name:
            row.add_prefix(Gtk.Image.new_from_icon_name(icon_name))

        copy_btn = Gtk.Button(icon_name="edit-copy-symbolic")
        copy_btn.set_valign(Gtk.Align.CENTER)
        copy_btn.set_tooltip_text(f"Copy '{copy_text}' to clipboard")
        copy_btn.add_css_class("flat")
        copy_btn.connect(
            "clicked",
            lambda _: self._copy_to_clipboard(
                copy_text, f"Copied '{copy_text}' to clipboard"
            ),
        )
        row.add_suffix(copy_btn)
        group.add(row)

    def _add_tool_expander(
        self,
        group: Adw.PreferencesGroup,
        title: str,
        subtitle: str,
        icon_name: str,
        steps: list,
    ):
        """Add an Adw.ExpanderRow containing step-by-step instructions with copyable code blocks."""
        expander = Adw.ExpanderRow(
            title=GLib.markup_escape_text(title) if title else "",
            subtitle=GLib.markup_escape_text(subtitle) if subtitle else None,
        )
        if icon_name:
            expander.add_prefix(Gtk.Image.new_from_icon_name(icon_name))

        for step_title, step_desc, code_snippet in steps:
            step_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            step_box.set_margin_start(14)
            step_box.set_margin_end(14)
            step_box.set_margin_top(8)
            step_box.set_margin_bottom(8)

            t_label = Gtk.Label()
            t_label.set_markup(f"<b>{GLib.markup_escape_text(step_title)}</b>")
            t_label.set_xalign(0.0)
            step_box.append(t_label)

            if step_desc:
                d_label = Gtk.Label(label=step_desc)
                d_label.set_wrap(True)
                d_label.set_xalign(0.0)
                d_label.add_css_class("caption")
                d_label.add_css_class("dim-label")
                step_box.append(d_label)

            if code_snippet:
                code_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                code_box.add_css_class("card")
                code_box.set_margin_top(4)

                c_label = Gtk.Label()
                c_label.add_css_class("monospace")
                c_label.set_xalign(0.0)
                c_label.set_wrap(True)
                c_label.set_selectable(True)
                c_label.set_hexpand(True)
                c_label.set_margin_start(10)
                c_label.set_margin_end(10)
                c_label.set_margin_top(8)
                c_label.set_margin_bottom(8)
                code_box.append(c_label)

                stripped = code_snippet.strip()
                if stripped.startswith(("{", "[")):
                    self._highlight_labels.append((c_label, code_snippet, "json"))
                elif "import " in code_snippet or "sock." in code_snippet:
                    self._highlight_labels.append((c_label, code_snippet, "python"))
                else:
                    c_label.set_text(code_snippet)

                btn = Gtk.Button(icon_name="edit-copy-symbolic")
                btn.set_valign(Gtk.Align.CENTER)
                btn.set_tooltip_text("Copy snippet")
                btn.add_css_class("flat")
                btn.set_margin_end(8)
                btn.connect(
                    "clicked",
                    lambda _, s=code_snippet: self._copy_to_clipboard(
                        s, "Copied snippet to clipboard"
                    ),
                )
                code_box.append(btn)
                step_box.append(code_box)

            expander.add_row(step_box)

        group.add(expander)

    def _add_action_ref(
        self,
        group: Adw.PreferencesGroup,
        tool_name: str,
        summary: str,
        description: str,
    ):
        """Add a formatted documentation row for an MCP tool."""
        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        info_box.set_margin_start(16)
        info_box.set_margin_end(16)
        info_box.set_margin_top(6)
        info_box.set_margin_bottom(10)

        desc_label = Gtk.Label(label=description)
        desc_label.set_wrap(True)
        desc_label.set_xalign(0.0)
        desc_label.add_css_class("caption")
        desc_label.add_css_class("dim-label")
        info_box.append(desc_label)

        expander = Adw.ExpanderRow(
            title=GLib.markup_escape_text(tool_name) if tool_name else "",
            subtitle=GLib.markup_escape_text(summary) if summary else None,
        )
        expander.add_prefix(Gtk.Image.new_from_icon_name("applications-utilities-symbolic"))
        expander.add_row(info_box)
        group.add(expander)

    def _copy_to_clipboard(self, text: str, toast_message: str = "Copied to clipboard"):
        """Copy given string to the system clipboard and display an Adw.Toast."""
        try:
            display = Gdk.Display.get_default() or self.get_display()
            if display:
                clipboard = display.get_clipboard()
                clipboard.set(text)
            self.toast_overlay.add_toast(Adw.Toast.new(toast_message))
        except Exception:
            self.toast_overlay.add_toast(Adw.Toast.new("Unable to access clipboard"))
