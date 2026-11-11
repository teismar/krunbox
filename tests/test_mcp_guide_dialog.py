"""
Unit tests for McpGuideDialog (In-Sandbox MCP Integration & Setup Guide).
"""

from unittest.mock import patch, MagicMock
import pytest
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from krunbox.ui.app import KrunboxApplication
from krunbox.ui.mcp_guide_dialog import McpGuideDialog, STDIO_MCP_CONFIG_JSON, PYTHON_IPC_SNIPPET


@pytest.fixture(scope="module")
def gtk_app():
    application = KrunboxApplication(application_id="io.krunbox.Krunbox.McpGuideTest")
    application.register()
    return application


def _pump_gtk(iterations: int = 15):
    ctx = GLib.MainContext.default()
    for _ in range(iterations):
        while ctx.iteration(False):
            pass


def test_mcp_guide_dialog_rendering(gtk_app):
    """Test dialog creation, layout structure, and essential instructions."""
    dialog = McpGuideDialog(parent_window=None)
    assert dialog is not None
    assert dialog.get_title() == "MCP Integration & Setup Guide"

    # Pump GTK event loop
    _pump_gtk(15)

    # Verify JSON configuration string
    assert "krunbox-gateway" in STDIO_MCP_CONFIG_JSON
    assert "/run/krunbox/krunbox-mcp" in STDIO_MCP_CONFIG_JSON
    assert "request_domain_access" in PYTHON_IPC_SNIPPET

    # Test clipboard copying logic
    with patch.object(dialog.toast_overlay, "add_toast") as mock_add_toast:
        dialog._copy_to_clipboard("test-copy-text", "Test Toast")
        _pump_gtk(5)
        assert mock_add_toast.called
        toast = mock_add_toast.call_args[0][0]
        assert toast.get_title() == "Test Toast"

    dialog.destroy()
    _pump_gtk(10)


def test_window_action_mcp_guide(gtk_app):
    from krunbox.ui.window import KrunboxWindow

    win = KrunboxWindow(gtk_app)
    _pump_gtk(10)

    act = win.lookup_action("mcp-guide")
    assert act is not None

    with patch("krunbox.ui.mcp_guide_dialog.McpGuideDialog.present") as mock_present:
        act.activate(None)
        _pump_gtk(10)
        assert mock_present.called

    win.destroy()
    _pump_gtk(10)
