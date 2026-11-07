"""
Host IPC Server and In-Sandbox MCP Permission Gateway for krunbox.

Enables AI agents inside isolated microVMs to securely communicate with the host
via a bind-mounted Unix domain socket (/run/krunbox/ipc.sock) to request dynamic
firewall whitelist access and host port exposure with human-in-the-loop approval.
"""

from dataclasses import dataclass, field, asdict, fields
import json
import os
from pathlib import Path
import select
import shutil
import socket
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple, Any
import uuid

from .config import DATA_DIR
from .notifications import send_desktop_notification


@dataclass
class AccessRequest:
    id: str
    sandbox_name: str
    action: str  # "request_domain_access" or "request_port_exposure"
    target: str = ""  # Domain name or stringified guest port
    reason: str = ""
    domain: Optional[str] = None
    guest_port: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    status: str = "pending"  # "pending", "approved", "denied", "expired"
    decision_reason: str = ""
    assigned_host_port: Optional[int] = None

    def __post_init__(self):
        if self.domain and not self.target:
            self.target = self.domain
        elif self.guest_port is not None and not self.target:
            self.target = str(self.guest_port)
        if self.target:
            if self.action in ("request_domain_access", "domain") and not self.domain:
                self.domain = self.target
            elif self.action in ("request_port_exposure", "port") and self.guest_port is None:
                try:
                    self.guest_port = int(self.target)
                except ValueError:
                    pass

    @property
    def request_type(self) -> str:
        if self.action in ("request_port_exposure", "port") or self.guest_port is not None:
            return "port"
        return "domain"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AccessRequest":
        known = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


def generate_guest_bridge_script() -> str:
    """
    Generate a standalone, zero-dependency Python script that acts as a standard
    stdio MCP (Model Context Protocol) server inside the guest microVM.
    It proxies tool invocations over /run/krunbox/ipc.sock to the host IPC server.
    """
    return '''#!/usr/bin/env python3
"""
krunbox-mcp: In-Sandbox Model Context Protocol (MCP) Gateway.
Communicates with the host krunbox daemon over a Unix domain socket.
"""

import argparse
import json
import os
import socket
import sys

DEFAULT_SOCKET = "/run/krunbox/ipc.sock"

TOOLS = [
    {
        "name": "request_domain_access",
        "description": "Request human-in-the-loop operator approval on the host to whitelist an outbound internet domain on the host firewall.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The fully qualified domain name to whitelist (e.g. 'github.com', 'registry.npmjs.org', 'pypi.org')."
                },
                "reason": {
                    "type": "string",
                    "description": "Clear explanation of why the agent needs network access to this domain."
                }
            },
            "required": ["domain", "reason"]
        }
    },
    {
        "name": "request_port_exposure",
        "description": "Request human-in-the-loop operator approval on the host to expose an internal sandbox TCP port to the host system via SSH reverse tunnel.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "guest_port": {
                    "type": "integer",
                    "description": "The internal TCP port to expose (e.g. 3000, 5173, 8000, 8080)."
                },
                "reason": {
                    "type": "string",
                    "description": "Clear explanation of why this port needs to be exposed to the host."
                }
            },
            "required": ["guest_port", "reason"]
        }
    },
    {
        "name": "get_sandbox_status",
        "description": "Query the current sandbox isolation profile, whitelisted domains, forwarded ports, and hardware allocation.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]


def send_ipc_request(sock_path: str, payload: dict, timeout: float = 65.0) -> dict:
    # 1. Attempt Unix domain socket if accessible
    if os.path.exists(sock_path):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect(sock_path)
                req_data = (json.dumps(payload) + "\\n").encode("utf-8")
                s.sendall(req_data)
                chunks = []
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if b"\\n" in chunk:
                        break
                raw = b"".join(chunks).decode("utf-8").strip()
                if raw:
                    return json.loads(raw)
        except (socket.error, OSError):
            pass

    # 2. Virtiofs file-based mailbox IPC (microVM virtiofs safe)
    ipc_dir = os.path.dirname(sock_path)
    if os.path.isdir(ipc_dir):
        try:
            import time, uuid
            req_uuid = f"ipc-{uuid.uuid4().hex[:12]}"
            payload_with_id = dict(payload)
            payload_with_id["_ipc_req_id"] = req_uuid

            req_tmp = os.path.join(ipc_dir, f"req-{req_uuid}.tmp")
            req_file = os.path.join(ipc_dir, f"req-{req_uuid}.json")
            resp_file = os.path.join(ipc_dir, f"resp-{req_uuid}.json")

            with open(req_tmp, "w", encoding="utf-8") as f:
                json.dump(payload_with_id, f)
            try:
                os.chmod(req_tmp, 0o666)
            except Exception:
                pass
            os.replace(req_tmp, req_file)

            deadline = time.time() + timeout
            while time.time() < deadline:
                if os.path.exists(resp_file) and os.path.getsize(resp_file) > 0:
                    try:
                        with open(resp_file, "r", encoding="utf-8") as f:
                            resp = json.load(f)
                        try:
                            os.unlink(resp_file)
                        except Exception:
                            pass
                        try:
                            os.unlink(req_file)
                        except Exception:
                            pass
                        return resp
                    except Exception:
                        pass
                time.sleep(0.05)

            try:
                os.unlink(req_file)
            except Exception:
                pass
            return {"status": "timed_out", "message": "Request timed out waiting for operator response on host"}
        except Exception as e:
            return {"status": "error", "message": f"Failed communicating with host IPC via file mailbox: {e}"}

    return {
        "status": "error",
        "message": f"krunbox IPC socket '{sock_path}' or directory '{ipc_dir}' not found. Is the sandbox running under krunbox?"
    }


def handle_jsonrpc(req: dict, sock_path: str) -> dict:
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params") or {}

    # JSON-RPC 2.0 Notifications: MUST NOT reply to notifications
    if req_id is None or method in (
        "notifications/initialized",
        "initialized",
        "notifications/cancelled",
        "$/cancelRequest",
    ):
        return None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "initialize":
        client_version = params.get("protocolVersion") or "2024-11-05"
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": client_version,
                "capabilities": {
                    "tools": {
                        "listChanged": False
                    }
                },
                "serverInfo": {
                    "name": "krunbox-gateway",
                    "version": "1.0.0"
                }
            }
        }

    if method == "notifications/initialized" or method == "initialized":
        return None

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": TOOLS
            }
        }

    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments") or {}

        if tool_name == "request_domain_access":
            domain = str(args.get("domain", "")).strip()
            reason = str(args.get("reason", "")).strip()
            if not domain:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": "Error: 'domain' argument is required."}], "isError": True}
                }
            ipc_resp = send_ipc_request(sock_path, {
                "action": "request_domain_access",
                "domain": domain,
                "reason": reason
            })
            status = ipc_resp.get("status", "unknown")
            if status == "approved":
                text = f"✓ ACCESS GRANTED: Host operator approved access to domain '{domain}'. It has been dynamically whitelisted on the host firewall."
                is_err = False
            elif status == "denied":
                dec_reason = ipc_resp.get("reason") or "Operator rejected request"
                text = f"✗ ACCESS DENIED: Host operator denied access to domain '{domain}'. Reason: {dec_reason}"
                is_err = True
            elif status == "timed_out":
                text = f"⏱ REQUEST TIMED OUT: Host operator did not respond to the access request for '{domain}' within the timeout window."
                is_err = True
            else:
                text = f"ERROR: {ipc_resp.get('message', 'Unknown response from host')}"
                is_err = True
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": text}], "isError": is_err}
            }

        if tool_name == "request_port_exposure":
            try:
                gport = int(args.get("guest_port", 0))
            except (ValueError, TypeError):
                gport = 0
            reason = str(args.get("reason", "")).strip()
            if gport <= 0 or gport > 65535:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": "Error: Valid 'guest_port' (1-65535) is required."}], "isError": True}
                }
            ipc_resp = send_ipc_request(sock_path, {
                "action": "request_port_exposure",
                "guest_port": gport,
                "reason": reason
            })
            status = ipc_resp.get("status", "unknown")
            if status == "approved":
                hport = ipc_resp.get("host_port", gport)
                text = f"✓ PORT EXPOSED: Guest port {gport} is now accessible on the host at http://127.0.0.1:{hport}"
                is_err = False
            elif status == "denied":
                dec_reason = ipc_resp.get("reason") or "Operator rejected request"
                text = f"✗ PORT EXPOSURE DENIED: Host operator denied exposing guest port {gport}. Reason: {dec_reason}"
                is_err = True
            elif status == "timed_out":
                text = f"⏱ REQUEST TIMED OUT: Host operator did not respond to port exposure request for {gport}."
                is_err = True
            else:
                text = f"ERROR: {ipc_resp.get('message', 'Unknown response from host')}"
                is_err = True
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": text}], "isError": is_err}
            }

        if tool_name == "get_sandbox_status":
            ipc_resp = send_ipc_request(sock_path, {"action": "get_sandbox_status"})
            text = json.dumps(ipc_resp, indent=2)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": text}], "isError": False}
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{tool_name}' not found"}
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method '{method}' not found"}
    }


def main():
    parser = argparse.ArgumentParser(description="krunbox In-Sandbox MCP Gateway Bridge")
    parser.add_argument("--socket", default=os.environ.get("KRUNBOX_IPC_SOCK", DEFAULT_SOCKET), help="Path to host IPC Unix socket")
    args = parser.parse_args()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            err_resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {e}"}}
            sys.stdout.write(json.dumps(err_resp) + "\\n")
            sys.stdout.flush()
            continue

        resp = handle_jsonrpc(req, args.socket)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
'''


class HostIPCServer:
    """
    Host-side Unix Domain Socket IPC server managing permission requests from guest agents.
    """

    def __init__(self, manager: Optional[Any] = None, base_dir: Optional[Path] = None):
        self.manager = manager
        self.base_dir = Path(base_dir or (DATA_DIR / "ipc")).resolve()
        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            self.base_dir.chmod(0o700)
        except (OSError, Exception):
            pass

        self._sockets: Dict[str, socket.socket] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._mailbox_threads: Dict[str, threading.Thread] = {}
        self._running: Dict[str, bool] = {}
        self._requests_lock = threading.Lock()
        self._pending_requests: Dict[str, AccessRequest] = {}
        self._all_requests: Dict[str, AccessRequest] = {}
        self._events: Dict[str, threading.Event] = {}
        self.requests_file = self.base_dir / "requests.json"
        self._load_requests()

    def _load_requests(self) -> None:
        if not self.requests_file.exists():
            return
        try:
            with open(self.requests_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data:
                req = AccessRequest.from_dict(item)
                self._all_requests[req.id] = req
                if req.status == "pending":
                    self._pending_requests[req.id] = req
                    self._events[req.id] = threading.Event()
        except Exception:
            pass

    def _save_requests(self) -> None:
        try:
            with open(self.requests_file, "w", encoding="utf-8") as f:
                data = [r.to_dict() for r in self._all_requests.values()]
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def get_socket_dir(self, sandbox_name: str) -> Path:
        sdir = self.base_dir / sandbox_name
        sdir.mkdir(parents=True, exist_ok=True)
        try:
            sdir.chmod(0o755)
        except Exception:
            pass
        return sdir

    def get_socket_path(self, sandbox_name: str) -> Path:
        return self.get_socket_dir(sandbox_name) / "ipc.sock"

    def setup_guest_mcp_artifacts(self, sandbox_name: str, target_ipc_dir: Optional[Path] = None) -> Path:
        """
        Write the standalone stdio MCP bridge script and config snippets into target_ipc_dir.
        """
        dest_dir = target_ipc_dir or self.get_socket_dir(sandbox_name)
        dest_dir.mkdir(parents=True, exist_ok=True)

        bridge_path = dest_dir / "krunbox-mcp"
        bridge_path.write_text(generate_guest_bridge_script(), encoding="utf-8")
        try:
            bridge_path.chmod(0o755)
        except Exception:
            pass

        cfg_snippet = dest_dir / "krunbox_mcp_config.json"
        cfg_snippet.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "krunbox-gateway": {
                            "command": "/run/krunbox/krunbox-mcp",
                            "args": [],
                        }
                    }
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return bridge_path

    def start_socket(self, sandbox_name: str) -> Path:
        """
        Start Unix domain socket listener for sandbox_name.
        Returns path to ipc.sock.
        """
        sock_path = self.get_socket_path(sandbox_name)
        if sandbox_name in self._running and self._running[sandbox_name]:
            return sock_path

        # Setup guest bridge script in directory
        self.setup_guest_mcp_artifacts(sandbox_name)

        if sock_path.exists():
            try:
                sock_path.unlink()
            except Exception:
                pass

        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(str(sock_path))
        try:
            sock_path.chmod(0o666)  # Permissive so guest user (vscode) can connect
        except Exception:
            pass
        server_sock.listen(10)
        server_sock.settimeout(0.5)

        self._sockets[sandbox_name] = server_sock
        self._running[sandbox_name] = True

        t = threading.Thread(
            target=self._socket_worker,
            args=(sandbox_name, server_sock),
            name=f"krunbox-ipc-{sandbox_name}",
            daemon=True,
        )
        self._threads[sandbox_name] = t
        t.start()

        mb_t = threading.Thread(
            target=self._mailbox_worker,
            args=(sandbox_name, self.get_socket_dir(sandbox_name)),
            name=f"krunbox-mailbox-{sandbox_name}",
            daemon=True,
        )
        self._mailbox_threads[sandbox_name] = mb_t
        mb_t.start()
        return sock_path

    # Aliases for compatibility
    start_for_sandbox = start_socket
    start = start_socket

    def stop_socket(self, sandbox_name: str) -> None:
        """Stop socket listener and remove socket file."""
        self._running[sandbox_name] = False
        sock = self._sockets.pop(sandbox_name, None)
        if sock:
            try:
                sock.close()
            except Exception:
                pass

        t = self._threads.pop(sandbox_name, None)
        if t and t.is_alive():
            t.join(timeout=1.0)

        mb_t = self._mailbox_threads.pop(sandbox_name, None)
        if mb_t and mb_t.is_alive():
            mb_t.join(timeout=1.0)

        sock_path = self.get_socket_path(sandbox_name)
        if sock_path.exists():
            try:
                sock_path.unlink()
            except Exception:
                pass

    stop_for_sandbox = stop_socket
    stop = stop_socket

    def stop_all(self) -> None:
        """Stop all active socket listeners."""
        for name in list(self._running.keys()):
            self.stop_socket(name)

    def _socket_worker(self, sandbox_name: str, server_sock: socket.socket) -> None:
        while self._running.get(sandbox_name, False):
            try:
                conn, _ = server_sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            client_thread = threading.Thread(
                target=self._handle_client,
                args=(sandbox_name, conn),
                daemon=True,
            )
            client_thread.start()

    def _mailbox_worker(self, sandbox_name: str, sdir: Path) -> None:
        """Polls IPC directory for guest file-based mailbox requests (microVM virtiofs safe)."""
        while self._running.get(sandbox_name, False):
            try:
                for rf in list(sdir.glob("req-*.json")):
                    if not rf.is_file():
                        continue
                    try:
                        content = rf.read_text(encoding="utf-8")
                        rf.unlink(missing_ok=True)
                        if not content.strip():
                            continue
                        msg = json.loads(content)
                    except Exception:
                        continue

                    req_id = msg.get("_ipc_req_id")
                    if not req_id:
                        continue

                    def _dispatch(r_id=req_id, m=msg, s=sandbox_name, d=sdir):
                        resp = self.process_ipc_message(s, m)
                        resp_tmp = d / f"resp-{r_id}.tmp"
                        resp_final = d / f"resp-{r_id}.json"
                        try:
                            resp_tmp.write_text(json.dumps(resp), encoding="utf-8")
                            try:
                                resp_tmp.chmod(0o666)
                            except Exception:
                                pass
                            resp_tmp.replace(resp_final)
                            try:
                                resp_final.chmod(0o666)
                            except Exception:
                                pass
                        except Exception:
                            pass

                    threading.Thread(target=_dispatch, daemon=True).start()
            except Exception:
                pass
            time.sleep(0.05)

    def process_ipc_message(self, sandbox_name: str, msg: dict) -> dict:
        """Core business logic for handling guest IPC access requests."""
        action = msg.get("action")

        if action == "request_domain_access":
            domain = str(msg.get("domain", "")).strip()
            reason = str(msg.get("reason", "")).strip()
            if not domain:
                return {"status": "error", "message": "Missing required 'domain' parameter"}

            # If domain is already allowed, approve immediately without blocking
            if self.manager is not None:
                box = self.manager.get_sandbox(sandbox_name)
                if box and domain in box.network_policy.allowed_domains:
                    return {
                        "status": "approved",
                        "domain": domain,
                        "reason": "Already whitelisted on host firewall",
                        "request_id": "auto",
                    }

            req = self.create_request(
                sandbox_name=sandbox_name,
                action="request_domain_access",
                target=domain,
                reason=reason,
            )
            # Trigger desktop notification
            send_desktop_notification(
                title=f"Agent Access Request: {sandbox_name}",
                body=f"Agent requests access to domain '{domain}': {reason}",
                urgent=True,
            )
            # Wait for human-in-the-loop decision
            self.wait_for_decision(req.id, timeout=60.0)
            return {
                "status": req.status,
                "domain": domain,
                "reason": req.decision_reason,
                "request_id": req.id,
            }

        elif action == "request_port_exposure":
            gport = int(msg.get("guest_port", 0))
            reason = str(msg.get("reason", "")).strip()
            req = self.create_request(
                sandbox_name=sandbox_name,
                action="request_port_exposure",
                target=str(gport),
                reason=reason,
            )
            send_desktop_notification(
                title=f"Agent Port Request: {sandbox_name}",
                body=f"Agent requests exposing guest port {gport}: {reason}",
                urgent=True,
            )
            self.wait_for_decision(req.id, timeout=60.0)
            return {
                "status": req.status,
                "guest_port": gport,
                "host_port": req.assigned_host_port,
                "reason": req.decision_reason,
                "request_id": req.id,
            }

        elif action == "get_sandbox_status":
            return self._get_sandbox_status(sandbox_name)

        return {"status": "error", "message": f"Unknown action: {action}"}

    def _handle_client(self, sandbox_name: str, conn: socket.socket) -> None:
        with conn:
            try:
                conn.settimeout(120.0)
                chunks = []
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if b"\n" in chunk:
                        break
                raw = b"".join(chunks).decode("utf-8").strip()
                if not raw:
                    return

                msg = json.loads(raw)
                resp = self.process_ipc_message(sandbox_name, msg)
                conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            except Exception as e:
                try:
                    conn.sendall((json.dumps({"status": "error", "message": str(e)}) + "\n").encode("utf-8"))
                except Exception:
                    pass

    def _get_sandbox_status(self, sandbox_name: str) -> dict:
        if self.manager is not None:
            box = self.manager.get_sandbox(sandbox_name)
            if box:
                return {
                    "status": "success",
                    "sandbox_name": box.name,
                    "network_profile": box.network_policy.profile,
                    "allowed_domains": list(box.network_policy.allowed_domains),
                    "forwarded_ports": [p.guest_port for p in box.all_ports],
                    "cpus": box.cpus,
                    "ram_mib": box.ram_mib,
                    "idle_timeout_minutes": box.idle_timeout_minutes,
                }
        return {
            "status": "success",
            "sandbox_name": sandbox_name,
            "network_profile": "custom",
            "allowed_domains": [],
            "forwarded_ports": [],
            "cpus": 4,
            "ram_mib": 4096,
        }

    def create_request(
        self,
        sandbox_name: str,
        action: str,
        target: str,
        reason: str,
    ) -> AccessRequest:
        req_id = f"req-{uuid.uuid4().hex[:8]}"
        req = AccessRequest(
            id=req_id,
            sandbox_name=sandbox_name,
            action=action,
            target=target,
            reason=reason,
            timestamp=time.time(),
            status="pending",
        )
        with self._requests_lock:
            self._pending_requests[req_id] = req
            self._all_requests[req_id] = req
            self._events[req_id] = threading.Event()
            self._save_requests()
        return req

    def get_pending_requests(self, sandbox_name: Optional[str] = None) -> List[AccessRequest]:
        with self._requests_lock:
            reqs = list(self._pending_requests.values())
        if sandbox_name:
            reqs = [r for r in reqs if r.sandbox_name == sandbox_name]
        reqs.sort(key=lambda r: r.timestamp)
        return reqs

    def get_all_requests(self, sandbox_name: Optional[str] = None) -> List[AccessRequest]:
        with self._requests_lock:
            reqs = list(self._all_requests.values())
        if sandbox_name:
            reqs = [r for r in reqs if r.sandbox_name == sandbox_name]
        reqs.sort(key=lambda r: -r.timestamp)
        return reqs

    def get_request(self, req_id: str) -> Optional[AccessRequest]:
        with self._requests_lock:
            return self._all_requests.get(req_id)

    def approve_request(self, req_id: str, host_port: Optional[int] = None) -> Tuple[bool, str]:
        with self._requests_lock:
            req = self._pending_requests.pop(req_id, None)
            if not req:
                req = self._all_requests.get(req_id)
                if not req:
                    return False, f"Request '{req_id}' not found."
                if req.status != "pending":
                    return False, f"Request '{req_id}' is already {req.status}."

            req.status = "approved"
            if host_port is not None:
                req.assigned_host_port = host_port
            req.decision_reason = "Approved by operator"
            self._all_requests[req_id] = req
            self._save_requests()

            evt = self._events.get(req_id)
            if evt:
                evt.set()

        return True, f"Approved {req.request_type} request for '{req.target}'."

    def deny_request(self, req_id: str, reason: str = "Denied by operator") -> Tuple[bool, str]:
        with self._requests_lock:
            req = self._pending_requests.pop(req_id, None)
            if not req:
                req = self._all_requests.get(req_id)
                if not req:
                    return False, f"Request '{req_id}' not found."
                if req.status != "pending":
                    return False, f"Request '{req_id}' is already {req.status}."

            req.status = "denied"
            req.decision_reason = reason
            self._all_requests[req_id] = req
            self._save_requests()

            evt = self._events.get(req_id)
            if evt:
                evt.set()

        return True, f"Denied {req.request_type} request for '{req.target}': {reason}"

    def wait_for_decision(self, req_id: str, timeout: float = 60.0) -> Optional[AccessRequest]:
        evt = self._events.get(req_id)
        if not evt:
            return self.get_request(req_id)

        signaled = evt.wait(timeout=timeout)
        req = self.get_request(req_id)
        if not signaled and req and req.status == "pending":
            with self._requests_lock:
                req.status = "expired"
                req.decision_reason = "Timed out waiting for operator approval"
                self._pending_requests.pop(req_id, None)
                self._save_requests()
        return req

    def cleanup_sandbox_ipc(self, sandbox_name: str) -> None:
        self.stop_socket(sandbox_name)
        sdir = self.get_socket_dir(sandbox_name)
        if sdir.exists():
            try:
                shutil.rmtree(sdir, ignore_errors=True)
            except Exception:
                pass
