"""
Port management, collision detection, and dynamic SSH tunnel orchestration.
"""

import re
import socket
import subprocess
import os
import signal
from typing import Optional, Set
from .sandbox import PortMapping

def _validate_port(port: int) -> int:
    """Ensure port is within valid TCP port range (1-65535)."""
    if not (1 <= port <= 65535):
        raise ValueError(f"Port number {port} is out of valid range (1-65535)")
    return port

def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a TCP port is currently open and responding on the host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        try:
            return s.connect_ex((host, port)) == 0
        except Exception:
            return False

def find_free_port(start_port: int = 2222, avoid: Optional[Set[int]] = None) -> int:
    """Find the next available unallocated TCP port on 127.0.0.1."""
    if avoid is None:
        avoid = set()

    port = start_port
    while port < 65535:
        if port not in avoid and not is_port_in_use(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("127.0.0.1", port))
                    return port
            except OSError:
                pass
        port += 1

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def parse_port_spec(spec: str, avoid_ports: Optional[Set[int]] = None) -> PortMapping:
    """
    Parse a port specification string:
      - '3000' -> host: 3000 (or free), guest: 3000
      - '8080:80' -> host: 8080, guest: 80
      - '127.0.0.1:8080:80' -> host: 8080, guest: 80
    """
    spec = spec.strip()
    parts = spec.split(":")
    if len(parts) == 1:
        guest_port = _validate_port(int(parts[0]))
        host_port = guest_port
        if (avoid_ports and host_port in avoid_ports) or is_port_in_use(host_port):
            host_port = find_free_port(host_port + 1, avoid=avoid_ports)
        return PortMapping(host_port=host_port, guest_port=guest_port)
    elif len(parts) == 2:
        host_port = _validate_port(int(parts[0]))
        guest_port = _validate_port(int(parts[1]))
        return PortMapping(host_port=host_port, guest_port=guest_port)
    elif len(parts) == 3:
        host_port = _validate_port(int(parts[1]))
        guest_port = _validate_port(int(parts[2]))
        return PortMapping(host_port=host_port, guest_port=guest_port)
    else:
        raise ValueError(f"Invalid port specification: {spec}")

def start_ssh_tunnel(ssh_host: str, host_port: int, guest_port: int, ssh_port: Optional[int] = None) -> PortMapping:
    """
    Establish a background SSH port tunnel from host_port -> 127.0.0.1:guest_port in the sandbox.
    """
    _validate_port(host_port)
    _validate_port(guest_port)
    if ssh_port is not None:
        _validate_port(ssh_port)

    clean_host = re.sub(r"[^a-zA-Z0-9_.-]", "", ssh_host)
    if not clean_host or clean_host != ssh_host:
        raise ValueError(f"Invalid SSH host name: {ssh_host!r}")

    cmd = [
        "ssh",
        "-N",
        "-f",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-L", f"127.0.0.1:{host_port}:127.0.0.1:{guest_port}"
    ]
    if ssh_port:
        cmd.extend(["-p", str(ssh_port)])

    cmd.extend(["--", clean_host])

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to establish live SSH tunnel: {res.stderr.strip() or res.stdout.strip()}")

    pid = None
    try:
        uid = str(os.getuid())
        pgrep = subprocess.run(
            ["pgrep", "-u", uid, "-f", "--", f"-L 127.0.0.1:{host_port}:127.0.0.1:{guest_port}"],
            capture_output=True,
            text=True
        )
        if pgrep.returncode == 0 and pgrep.stdout.strip():
            pid = int(pgrep.stdout.strip().split()[-1])
    except Exception:
        pass

    return PortMapping(
        host_port=host_port,
        guest_port=guest_port,
        is_tunnel=True,
        tunnel_pid=pid,
        description=f"Live tunnel -> {guest_port}"
    )

def stop_ssh_tunnel(mapping: PortMapping) -> bool:
    """Terminate an active SSH port tunnel."""
    if mapping.tunnel_pid:
        try:
            os.kill(mapping.tunnel_pid, signal.SIGTERM)
            return True
        except ProcessLookupError:
            pass
        except Exception:
            pass

    try:
        uid = str(os.getuid())
        subprocess.run(
            ["pkill", "-u", uid, "-f", "--", f"-L 127.0.0.1:{mapping.host_port}:127.0.0.1:{mapping.guest_port}"],
            capture_output=True,
            check=False
        )
        return True
    except Exception:
        return False
