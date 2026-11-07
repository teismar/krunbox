"""
Compatibility alias module for krunbox In-Sandbox MCP Gateway.
"""

from .ipc_server import (
    AccessRequest,
    HostIPCServer,
    generate_guest_bridge_script,
)

__all__ = [
    "AccessRequest",
    "HostIPCServer",
    "generate_guest_bridge_script",
]
