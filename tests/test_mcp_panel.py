"""
Tests for Agent MCP Requests Sidepanel (McpRequestsSidepanel and McpRequestCard).
"""

from unittest.mock import MagicMock, patch
import pytest
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from krunbox.core.ipc_server import AccessRequest
from krunbox.core.manager import SandboxManager
from krunbox.ui.app import KrunboxApplication
from krunbox.ui.mcp_panel import McpRequestsSidepanel, McpRequestCard


@pytest.fixture(scope="module")
def gtk_app():
    application = KrunboxApplication(application_id="io.krunbox.Krunbox.McpTest")
    application.register()
    return application


def _pump_gtk(iterations: int = 15):
    ctx = GLib.MainContext.default()
    for _ in range(iterations):
        while ctx.iteration(False):
            pass


def test_mcp_request_card_rendering_and_actions(gtk_app):
    approved_list = []
    denied_list = []

    req = AccessRequest(
        id="req-card-test-1",
        sandbox_name="test-worker",
        action="request_domain_access",
        domain="registry.npmjs.org",
        reason="Need npm dependencies",
        status="pending",
    )

    card = McpRequestCard(
        request=req,
        on_approve=lambda r: approved_list.append(r.id),
        on_deny=lambda r, reason: denied_list.append((r.id, reason)),
        parent_window=None,
    )
    assert card is not None
    assert card.request.id == "req-card-test-1"
    assert card.allow_btn is not None
    assert card.deny_btn is not None

    card.allow_btn.emit("clicked")
    _pump_gtk(5)
    assert "req-card-test-1" in approved_list


def test_mcp_sidepanel_filtering_and_batch_actions(gtk_app, tmp_path):
    mgr = SandboxManager(state_file=tmp_path / "sandboxes.json")
    handled_events = []
    close_events = []

    req1 = AccessRequest(
        id="req-1",
        sandbox_name="box-alpha",
        action="request_domain_access",
        domain="github.com",
        reason="Clone git repos",
        status="pending",
    )
    req2 = AccessRequest(
        id="req-2",
        sandbox_name="box-beta",
        action="request_port_exposure",
        guest_port=8080,
        reason="Expose backend server",
        status="pending",
    )
    req3 = AccessRequest(
        id="req-3",
        sandbox_name="box-alpha",
        action="request_domain_access",
        domain="pypi.org",
        reason="Install packages",
        status="approved",
    )

    all_reqs = [req1, req2, req3]
    mgr.list_all_requests = MagicMock(return_value=all_reqs)
    mgr.list_pending_requests = MagicMock(return_value=[req1, req2])
    mgr.approve_access_request = MagicMock(return_value=(True, "Approved"))
    mgr.deny_access_request = MagicMock(return_value=(True, "Denied"))

    panel = McpRequestsSidepanel(
        manager=mgr,
        on_request_handled=lambda: handled_events.append("handled"),
        on_close_requested=lambda: close_events.append("closed"),
    )
    assert panel is not None

    panel.reload_requests()
    _pump_gtk(25)

    # By default, status filter is "pending", so req1 and req2 are matched
    assert panel.status_filter == "pending"
    assert len(panel._filtered_requests) == 2

    # Switch status filter to "all"
    panel.set_status_filter("all")
    _pump_gtk(15)
    assert len(panel._filtered_requests) == 3

    # Switch type filter to "Port Exposure" (index 2)
    panel.type_dropdown.set_selected(2)
    _pump_gtk(15)
    assert len(panel._filtered_requests) == 1
    assert panel._filtered_requests[0].id == "req-2"

    # Switch type filter back to "All Types" (index 0)
    panel.type_dropdown.set_selected(0)
    _pump_gtk(15)
    assert len(panel._filtered_requests) == 3

    # Test Batch Approve All
    panel.approve_all_btn.emit("clicked")
    _pump_gtk(20)
    assert mgr.approve_access_request.call_count >= 1

    # Test Close Request callback
    assert panel.close_btn is not None
    panel.close_btn.emit("clicked")
    assert "closed" in close_events

    # Test MCP Guide buttons
    assert panel.help_btn is not None
    assert panel.guide_banner_btn is not None
    assert panel.empty_guide_btn is not None

    with patch("krunbox.ui.mcp_guide_dialog.McpGuideDialog.present") as mock_present:
        panel.help_btn.emit("clicked")
        _pump_gtk(10)
        assert mock_present.called

    with patch("krunbox.ui.mcp_guide_dialog.McpGuideDialog.present") as mock_present:
        panel.guide_banner_btn.emit("clicked")
        _pump_gtk(10)
        assert mock_present.called

    with patch("krunbox.ui.mcp_guide_dialog.McpGuideDialog.present") as mock_present:
        panel.empty_guide_btn.emit("clicked")
        _pump_gtk(10)
        assert mock_present.called
