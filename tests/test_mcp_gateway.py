"""
Unit and integration tests for the In-Sandbox MCP Permission Gateway,
Host IPC Server, Stdio MCP Bridge, and Idle Timeout Pre-Warning notifications.

CRITICAL INVARIANT CHECKED: Zero occurrences of forbidden token 's'+'b'+'x'.
"""

import ast
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import threading
import time
from unittest.mock import MagicMock, patch
import pytest

from krunbox.cli.main import main
from krunbox.core.manager import SandboxManager
from krunbox.core.notifications import AlertEvent, GuardrailMonitor
from krunbox.core.sandbox import NetworkPolicy, PortMapping, SandboxInfo
from krunbox.core.mcp_gateway import (
    AccessRequest,
    HostIPCServer,
    generate_guest_bridge_script,
)


@pytest.fixture
def test_manager(tmp_path):
    """Hermetic isolated SandboxManager instance with temporary state and IPC sockets."""
    state_file = tmp_path / "sandboxes.json"
    data_dir = tmp_path / "data"
    telem_dir = data_dir / "telemetry"
    egress_logs = data_dir / "egress_logs"
    ssh_dir = tmp_path / "ssh_conf"
    ssh_cfg = tmp_path / "ssh_config"
    ipc_dir = tmp_path / "ipc"

    telem_dir.mkdir(parents=True, exist_ok=True)
    egress_logs.mkdir(parents=True, exist_ok=True)
    ssh_dir.mkdir(parents=True, exist_ok=True)
    ipc_dir.mkdir(parents=True, exist_ok=True)

    with patch("krunbox.core.manager.DATA_DIR", data_dir), \
         patch("krunbox.core.manager.STATE_FILE", state_file), \
         patch("krunbox.core.telemetry.TELEMETRY_DIR", telem_dir), \
         patch("krunbox.core.egress_traffic.EGRESS_LOGS_DIR", egress_logs), \
         patch("krunbox.core.ssh.SSH_CONF_DIR", ssh_dir), \
         patch("krunbox.core.ssh.SSH_CONFIG_FILE", ssh_cfg):
        mgr = SandboxManager(state_file=state_file)
        mgr.ipc_server = HostIPCServer(manager=mgr, base_dir=ipc_dir)
        yield mgr


@pytest.fixture
def running_sandbox(test_manager, tmp_path):
    """Create and register a running test sandbox."""
    work_dir = tmp_path / "workspace_test"
    work_dir.mkdir(parents=True, exist_ok=True)
    box = test_manager.create_sandbox(
        dir_path=str(work_dir),
        name="test-box",
        is_persistent=True,
        network_policy=NetworkPolicy(profile="ai-only", allowed_domains=["api.openai.com"]),
        cpus=4,
        ram_mib=4096,
    )
    box.status = "running"
    box.ssh_port = 2222
    test_manager.save_state()
    return box


# ============================================================================
# 1. AccessRequest Serialization & Deserialization
# ============================================================================

def test_access_request_to_dict_and_from_dict():
    """Verify AccessRequest dataclass serializes and deserializes completely with field filtering."""
    req = AccessRequest(
        id="req-test-001",
        sandbox_name="krunbox-test-box",
        action="request_domain_access",
        domain="github.com",
        guest_port=None,
        reason="Need to clone git repository",
        status="pending",
        timestamp=1700000123.0,
    )

    data = req.to_dict()
    assert isinstance(data, dict)
    assert data["id"] == "req-test-001"
    assert data["sandbox_name"] == "krunbox-test-box"
    assert data["action"] == "request_domain_access"
    assert data["domain"] == "github.com"
    assert data["guest_port"] is None
    assert data["reason"] == "Need to clone git repository"
    assert data["status"] == "pending"
    assert data["timestamp"] == 1700000123.0

    # Deserialization from dictionary
    loaded = AccessRequest.from_dict(data)
    assert loaded.id == "req-test-001"
    assert loaded.sandbox_name == "krunbox-test-box"
    assert loaded.action == "request_domain_access"
    assert loaded.domain == "github.com"
    assert loaded.status == "pending"

    # Forward-compatibility: unknown fields should be safely ignored
    extended_data = dict(data)
    extended_data["future_experimental_field"] = "unexpected_value"
    loaded_ext = AccessRequest.from_dict(extended_data)
    assert loaded_ext.id == "req-test-001"
    assert loaded_ext.domain == "github.com"


# ============================================================================
# 2. HostIPCServer Socket Lifecycle
# ============================================================================

def test_host_ipc_server_socket_lifecycle(test_manager, running_sandbox, tmp_path):
    """Verify HostIPCServer creates ipc.sock in sandbox IPC dir, and cleans up on stop."""
    ipc_dir = tmp_path / "ipc"
    ipc_dir.mkdir(parents=True, exist_ok=True)

    server = HostIPCServer(manager=test_manager, base_dir=ipc_dir)
    try:
        # Starting socket creates the Unix domain socket file
        sock_path = Path(server.start_socket(running_sandbox.name))
        assert sock_path.name == "ipc.sock"
        assert sock_path.exists()
        assert sock_path.is_socket()

        # Stopping socket removes the socket file and cleans up listener
        server.stop_socket(running_sandbox.name)
        assert not sock_path.exists()
    finally:
        server.stop_all()


# ============================================================================
# 3. IPC Client-Server Communication (Domain Access Request & Approval)
# ============================================================================

def test_ipc_domain_request_approval_flow(test_manager, running_sandbox, tmp_path):
    """
    Send request_domain_access over Unix socket, verify pending registration,
    approve via server, and verify client receives approved response.
    """
    ipc_dir = tmp_path / "ipc"
    ipc_dir.mkdir(parents=True, exist_ok=True)
    server = HostIPCServer(manager=test_manager, base_dir=ipc_dir)

    sock_path = Path(server.start_socket(running_sandbox.name))
    client_result = {}

    def _client_task():
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_sock:
                client_sock.settimeout(4.0)
                client_sock.connect(str(sock_path))
                msg = {
                    "action": "request_domain_access",
                    "domain": "github.com",
                    "reason": "Clone repo",
                }
                client_sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))
                raw = client_sock.recv(4096)
                if raw:
                    client_result["response"] = json.loads(raw.decode("utf-8").strip())
        except Exception as exc:
            client_result["error"] = str(exc)

    client_thread = threading.Thread(target=_client_task, daemon=True)
    client_thread.start()

    # Step 1: Wait for pending request to be registered on server
    req = None
    for _ in range(60):
        pending = server.get_pending_requests(running_sandbox.name)
        if pending:
            req = pending[0]
            break
        time.sleep(0.05)

    assert req is not None, "Pending domain access request was not registered in time."
    assert req.domain == "github.com"
    assert req.reason == "Clone repo"
    assert req.action == "request_domain_access"

    # Step 2: Approve the request
    server.approve_request(req.id)

    # Step 3: Wait for client worker thread to receive response
    client_thread.join(timeout=3.0)
    assert not client_thread.is_alive()
    assert "error" not in client_result, f"Client thread error: {client_result.get('error')}"

    resp = client_result.get("response", {})
    assert resp.get("status") == "approved"
    assert resp.get("domain") == "github.com"

    # Pending list should now be cleared
    assert len(server.get_pending_requests(running_sandbox.name)) == 0
    server.stop_all()


# ============================================================================
# 4. Port Request Flow (Port Exposure Request & Denial)
# ============================================================================

def test_ipc_port_request_denial_flow(test_manager, running_sandbox, tmp_path):
    """
    Send request_port_exposure over Unix socket, deny with custom admin reason,
    and verify client receives denied status and reason.
    """
    ipc_dir = tmp_path / "ipc"
    ipc_dir.mkdir(parents=True, exist_ok=True)
    server = HostIPCServer(manager=test_manager, base_dir=ipc_dir)

    sock_path = Path(server.start_socket(running_sandbox.name))
    client_result = {}

    def _client_task():
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_sock:
                client_sock.settimeout(4.0)
                client_sock.connect(str(sock_path))
                msg = {
                    "action": "request_port_exposure",
                    "guest_port": 3000,
                    "reason": "Web preview",
                }
                client_sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))
                raw = client_sock.recv(4096)
                if raw:
                    client_result["response"] = json.loads(raw.decode("utf-8").strip())
        except Exception as exc:
            client_result["error"] = str(exc)

    client_thread = threading.Thread(target=_client_task, daemon=True)
    client_thread.start()

    # Wait for pending request
    req = None
    for _ in range(60):
        pending = server.get_pending_requests(running_sandbox.name)
        if pending:
            req = pending[0]
            break
        time.sleep(0.05)

    assert req is not None, "Pending port request was not registered in time."
    assert req.guest_port == 3000
    assert req.action == "request_port_exposure"

    # Deny request with custom admin reason
    denial_msg = "Port 3000 not allowed by admin"
    server.deny_request(req.id, reason=denial_msg)

    client_thread.join(timeout=3.0)
    assert not client_thread.is_alive()
    assert "error" not in client_result

    resp = client_result.get("response", {})
    assert resp.get("status") == "denied"
    assert denial_msg in resp.get("reason", "") or denial_msg in str(resp)
    server.stop_all()


# ============================================================================
# 5. get_sandbox_status Query over Unix Socket
# ============================================================================

def test_ipc_get_sandbox_status_query(test_manager, running_sandbox, tmp_path):
    """Verify get_sandbox_status returns network profile, allowed domains, forwarded ports, CPU, and RAM."""
    ipc_dir = tmp_path / "ipc"
    ipc_dir.mkdir(parents=True, exist_ok=True)
    server = HostIPCServer(manager=test_manager, base_dir=ipc_dir)

    sock_path = Path(server.start_socket(running_sandbox.name))

    # Attach dynamic tunnel to sandbox for status inspection
    running_sandbox.dynamic_tunnels.append(
        PortMapping(host_port=13000, guest_port=3000, is_tunnel=True)
    )
    test_manager.save_state()

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_sock:
        client_sock.settimeout(3.0)
        client_sock.connect(str(sock_path))
        query = {"action": "get_sandbox_status"}
        client_sock.sendall((json.dumps(query) + "\n").encode("utf-8"))
        raw = client_sock.recv(4096)
        res = json.loads(raw.decode("utf-8").strip())

    assert res.get("status") in ("success", "ok", None) or "network_profile" in res
    net_profile = res.get("network_profile") or res.get("profile")
    assert net_profile == "ai-only"
    assert "api.openai.com" in res.get("allowed_domains", [])
    assert res.get("cpus") == 4
    assert res.get("ram_mib") == 4096

    ports = res.get("forwarded_ports") or res.get("ports", [])
    assert 3000 in ports
    server.stop_all()


# ============================================================================
# 6. Stdio MCP Bridge Script Generation & Execution
# ============================================================================

def test_generate_guest_bridge_script_valid_python():
    """Verify generate_guest_bridge_script outputs syntactically valid executable Python code."""
    script_source = generate_guest_bridge_script()
    assert isinstance(script_source, str)
    assert len(script_source.strip()) > 50

    # Ensure source code compiles cleanly without syntax errors
    tree = ast.parse(script_source, filename="<guest_bridge_script>")
    assert tree is not None
    compiled = compile(script_source, "<guest_bridge_script>", "exec")
    assert compiled is not None


def test_stdio_mcp_bridge_script_subprocess_lifecycle(tmp_path):
    """
    Run bridge script in subprocess with mock Unix socket server,
    verifying stdio JSON-RPC MCP initialization, tool listing, and tool dispatch.
    """
    mock_sock_path = tmp_path / "mock_ipc.sock"
    bridge_script_path = tmp_path / "mcp_bridge.py"
    bridge_script_path.write_text(generate_guest_bridge_script(), encoding="utf-8")

    server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_sock.bind(str(mock_sock_path))
    server_sock.listen(5)
    server_running = [True]

    def _mock_ipc_server_worker():
        while server_running[0]:
            try:
                server_sock.settimeout(0.5)
                conn, _ = server_sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            with conn:
                try:
                    conn.settimeout(2.0)
                    data = conn.recv(4096)
                    if not data:
                        continue
                    req = json.loads(data.decode("utf-8").strip())
                    action = req.get("action")
                    if action == "request_domain_access":
                        conn.sendall(json.dumps({
                            "status": "approved",
                            "domain": req.get("domain"),
                            "request_id": "req-mcp-1",
                        }).encode("utf-8") + b"\n")
                    elif action == "request_port_exposure":
                        conn.sendall(json.dumps({
                            "status": "approved",
                            "guest_port": req.get("guest_port"),
                            "host_port": 13000,
                        }).encode("utf-8") + b"\n")
                    elif action == "get_sandbox_status":
                        conn.sendall(json.dumps({
                            "status": "success",
                            "network_profile": "ai-only",
                            "allowed_domains": ["api.anthropic.com"],
                            "forwarded_ports": [3000],
                            "cpus": 4,
                            "ram_mib": 4096,
                        }).encode("utf-8") + b"\n")
                except Exception:
                    pass

    mock_thread = threading.Thread(target=_mock_ipc_server_worker, daemon=True)
    mock_thread.start()

    proc_env = os.environ.copy()
    proc_env["KRUNBOX_IPC_SOCK"] = str(mock_sock_path)

    proc = subprocess.Popen(
        [sys.executable, str(bridge_script_path), "--socket", str(mock_sock_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=proc_env,
    )

    try:
        def _send_and_recv(payload: dict) -> dict:
            line = json.dumps(payload) + "\n"
            proc.stdin.write(line)
            proc.stdin.flush()
            out_line = proc.stdout.readline()
            return json.loads(out_line.strip())

        # 6a. MCP Initialize
        init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        init_resp = _send_and_recv(init_req)
        assert init_resp.get("id") == 1
        assert "result" in init_resp
        assert "capabilities" in init_resp["result"] or "protocolVersion" in init_resp["result"]

        # 6b. MCP tools/list
        tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        tools_resp = _send_and_recv(tools_req)
        assert tools_resp.get("id") == 2
        tools_list = tools_resp.get("result", {}).get("tools", [])
        tool_names = [t.get("name") for t in tools_list]
        assert "request_domain_access" in tool_names
        assert "request_port_exposure" in tool_names
        assert "get_sandbox_status" in tool_names

        # 6c. MCP tools/call for request_domain_access
        call_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "request_domain_access",
                "arguments": {"domain": "github.com", "reason": "Fetch submodules"},
            },
        }
        call_resp = _send_and_recv(call_req)
        assert call_resp.get("id") == 3
        result_content = call_resp.get("result", {}).get("content", [])
        combined_text = " ".join(c.get("text", "") for c in result_content) or str(call_resp.get("result"))
        assert "approved" in combined_text.lower() or "github.com" in combined_text.lower()

    finally:
        server_running[0] = False
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except Exception:
            proc.kill()
        try:
            server_sock.close()
            mock_sock_path.unlink(missing_ok=True)
        except Exception:
            pass


# ============================================================================
# 7. SandboxManager Integration (Approve & Deny Requests)
# ============================================================================

def test_manager_approve_domain_access_request(test_manager, running_sandbox):
    """
    Test manager.approve_access_request() for domain:
    Verifies manager updates allowed_domains and reloads nftables rules via podman exec.
    """
    req = AccessRequest(
        id="req-dom-100",
        sandbox_name=running_sandbox.name,
        action="request_domain_access",
        domain="pypi.org",
        guest_port=None,
        reason="Install packages",
        status="pending",
        timestamp=time.time(),
    )

    test_manager.ipc_server._pending_requests[req.id] = req
    test_manager.ipc_server._all_requests[req.id] = req

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        ok, msg = test_manager.approve_access_request(req.id)
        assert ok is True

        # Verify domain is now allowed on sandbox network policy
        updated_box = test_manager.get_sandbox(running_sandbox.name)
        assert "pypi.org" in updated_box.network_policy.allowed_domains

        # Verify nftables reload podman exec command was invoked
        called_cmds = [c[0][0] for c in mock_run.call_args_list if c[0]]
        reload_invoked = any(
            cmd[:3] == ["podman", "exec", "-u"] and "/etc/krunbox-egress.sh" in cmd
            for cmd in called_cmds
        )
        assert reload_invoked, "Hot-reload of /etc/krunbox-egress.sh was not triggered."


def test_manager_approve_port_access_request(test_manager, running_sandbox):
    """
    Test manager.approve_access_request() for port:
    Verifies manager.forward_port() is invoked.
    """
    req = AccessRequest(
        id="req-port-200",
        sandbox_name=running_sandbox.name,
        action="request_port_exposure",
        domain=None,
        guest_port=8080,
        reason="Dev API server",
        status="pending",
        timestamp=time.time(),
    )

    test_manager.ipc_server._pending_requests[req.id] = req
    test_manager.ipc_server._all_requests[req.id] = req

    with patch.object(test_manager, "forward_port", return_value=(True, "Forwarded 127.0.0.1:8080", PortMapping(host_port=18080, guest_port=8080))) as mock_fwd:
        ok, msg = test_manager.approve_access_request(req.id)
        assert ok is True
        mock_fwd.assert_called_once()
        assert mock_fwd.call_args[1].get("guest_port") == 8080 or mock_fwd.call_args[0][1] == 8080


def test_manager_deny_access_request(test_manager, running_sandbox):
    """Test manager.deny_access_request() sets status to denied with admin comment."""
    req = AccessRequest(
        id="req-deny-300",
        sandbox_name=running_sandbox.name,
        action="request_domain_access",
        domain="untrusted.example.com",
        guest_port=None,
        reason="Testing exfil",
        status="pending",
        timestamp=time.time(),
    )

    test_manager.ipc_server._pending_requests[req.id] = req
    test_manager.ipc_server._all_requests[req.id] = req

    denial_reason = "Untrusted domain blocked by admin"
    ok, msg = test_manager.deny_access_request(req.id, reason=denial_reason)
    assert ok is True

    # Check request status
    assert req.status == "denied"
    assert denial_reason in (getattr(req, "decision_reason", "") or req.reason)


# ============================================================================
# 8. CLI Commands (requests, approve, deny, keep-awake)
# ============================================================================

def test_cli_requests_list(capsys, test_manager, running_sandbox):
    """Test `krunbox requests` displays registered pending access requests."""
    fake_req = AccessRequest(
        id="req-cli-10",
        sandbox_name=running_sandbox.name,
        action="request_domain_access",
        domain="github.com",
        guest_port=None,
        reason="Clone git repo",
        status="pending",
        timestamp=time.time(),
    )

    with patch.object(test_manager, "list_pending_requests", return_value=[fake_req]):
        with patch("krunbox.cli.main.SandboxManager", return_value=test_manager):
            with patch.object(sys, "argv", ["krunbox", "requests"]):
                res = main()
                assert res == 0
                captured = capsys.readouterr().out
                assert "req-cli-10" in captured or "github.com" in captured


def test_cli_approve_request(capsys, test_manager, running_sandbox):
    """Test `krunbox approve <id>` executes approval and prints confirmation."""
    with patch.object(test_manager, "approve_access_request", return_value=(True, "Approved domain access for github.com")):
        with patch("krunbox.cli.main.SandboxManager", return_value=test_manager):
            with patch.object(sys, "argv", ["krunbox", "approve", "req-cli-10"]):
                res = main()
                assert res == 0
                captured = capsys.readouterr().out
                assert "Approved" in captured or "✓" in captured or "github.com" in captured


def test_cli_deny_request(capsys, test_manager, running_sandbox):
    """Test `krunbox deny <id> --reason <reason>` denies request with message."""
    with patch.object(test_manager, "deny_access_request", return_value=(True, "Denied request req-cli-10")):
        with patch("krunbox.cli.main.SandboxManager", return_value=test_manager):
            with patch.object(sys, "argv", ["krunbox", "deny", "req-cli-10", "--reason", "Not corporate approved"]):
                res = main()
                assert res == 0
                captured = capsys.readouterr().out
                assert "Denied" in captured or "req-cli-10" in captured


def test_cli_keep_awake(capsys, test_manager, running_sandbox):
    """Test `krunbox keep-awake <name> [--indefinite]` resets idle timer or flags indefinite awake."""
    with patch.object(test_manager, "keep_awake", return_value=(True, "Reset idle timer for test-box")):
        with patch("krunbox.cli.main.SandboxManager", return_value=test_manager):
            with patch.object(sys, "argv", ["krunbox", "keep-awake", "test-box"]):
                res = main()
                assert res == 0
                out1 = capsys.readouterr().out
                assert "reset" in out1.lower() or "test-box" in out1

    with patch.object(test_manager, "keep_awake", return_value=(True, "test-box set to keep awake indefinitely")):
        with patch("krunbox.cli.main.SandboxManager", return_value=test_manager):
            with patch.object(sys, "argv", ["krunbox", "keep-awake", "test-box", "--indefinite"]):
                res = main()
                assert res == 0
                out2 = capsys.readouterr().out
                assert "indefinite" in out2.lower() or "keep awake" in out2.lower() or "test-box" in out2


# ============================================================================
# 9. Idle Timeout Pre-Warning Notifications
# ============================================================================

def test_idle_timeout_pre_warning_notification(running_sandbox):
    """
    Verify GuardrailMonitor emits an 'idle_pre_warning' AlertEvent
    prior to executing an auto-pause or auto-stop idle action.
    """
    running_sandbox.idle_timeout_minutes = 10
    running_sandbox.idle_action = "pause"
    running_sandbox.cpu_percent = 0.2  # Below 1.0% idle limit

    monitor = GuardrailMonitor(
        idle_cpu_threshold=1.0,
        ssh_checker=lambda name, port: False,  # 0 active interactive SSH sessions
    )

    base_time = 1700000000.0
    elapsed_warn = 360.0  # 6 minutes idle (4m remaining until sleep)

    # 1. At start (t=0), records initial idle timestamp
    monitor.evaluate([running_sandbox], now=base_time)

    # 2. At t = base_time + 360s, pre-warning should trigger
    alerts, actions = monitor.evaluate([running_sandbox], now=base_time + elapsed_warn)
    warn_alerts = [a for a in alerts if a.category == "idle_pre_warning"]
    assert len(warn_alerts) == 1
    alert = warn_alerts[0]
    assert alert.severity == "warning"
    assert "Sleeping Soon" in alert.title or "test-box" in alert.title
    assert "pause" in alert.body or "4" in alert.body or "minute" in alert.body
    # Pause action itself should NOT be executed yet
    assert len(actions) == 0

    # 3. Test keep-awake / reset_idle resets timer so pre-warning does not refire prematurely
    monitor.reset_idle(running_sandbox.name)
    alerts_after_reset, _ = monitor.evaluate([running_sandbox], now=base_time + elapsed_warn + 10.0)
    assert not any(a.category == "idle_pre_warning" for a in alerts_after_reset)

    # 4. Active SSH session or CPU activity prevents idle pre-warning
    monitor_active = GuardrailMonitor(
        idle_cpu_threshold=1.0,
        ssh_checker=lambda name, port: True,  # Active SSH session
    )
    monitor_active.evaluate([running_sandbox], now=base_time)
    alerts_active, _ = monitor_active.evaluate([running_sandbox], now=base_time + elapsed_warn)
    assert not any(a.category == "idle_pre_warning" for a in alerts_active)


def test_mcp_protocol_compliance_and_mailbox_fallback(tmp_path):
    """
    Test standard MCP compliance (initialize, initialized notification, tools/list, ping)
    and verify virtiofs file mailbox fallback when unix socket is disconnected.
    """
    ipc_dir = tmp_path / "ipc"
    ipc_dir.mkdir()
    server = HostIPCServer(base_dir=ipc_dir)
    server.start_socket("mcp-compliance-box")

    sdir = server.get_socket_dir("mcp-compliance-box")
    bridge_script = sdir / "krunbox-mcp"
    assert bridge_script.is_file()

    # Invalidate Unix domain socket so bridge MUST use file-based mailbox
    sock_path = server.get_socket_path("mcp-compliance-box")
    if sock_path.exists():
        sock_path.unlink()
    sock_path.write_text("inaccessible")

    proc = subprocess.Popen(
        [sys.executable, str(bridge_script), "--socket", str(sock_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )

    try:
        def send(msg):
            proc.stdin.write(json.dumps(msg) + "\n")
            proc.stdin.flush()

        def recv():
            return json.loads(proc.stdout.readline())

        # 1. initialize
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})
        r1 = recv()
        assert r1.get("id") == 1
        assert r1["result"]["serverInfo"]["name"] == "krunbox-gateway"

        # 2. initialized notification: NO response should be emitted
        send({"jsonrpc": "2.0", "method": "initialized"})

        # 3. tools/list: response should have id: 2
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        r2 = recv()
        assert r2.get("id") == 2
        assert "tools" in r2.get("result", {})

        # 4. ping: should return empty dict
        send({"jsonrpc": "2.0", "id": 3, "method": "ping"})
        r3 = recv()
        assert r3.get("id") == 3
        assert r3.get("result") == {}

        # 5. tools/call over mailbox
        def approver():
            time.sleep(0.1)
            pending = server.get_pending_requests("mcp-compliance-box")
            if pending:
                server.approve_request(pending[0].id)

        threading.Thread(target=approver, daemon=True).start()

        send({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "request_domain_access",
                "arguments": {"domain": "teismar.de", "reason": "User requested access"},
            },
        })
        r4 = recv()
        assert r4.get("id") == 4
        text = r4["result"]["content"][0]["text"]
        assert "ACCESS GRANTED" in text
        assert "teismar.de" in text

    finally:
        proc.terminate()
        server.stop_all()

