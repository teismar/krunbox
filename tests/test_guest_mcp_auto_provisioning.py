"""
End-to-end tests for in-guest MCP auto-provisioning:
Verifies that newly created or started sandboxes (agent-box, minimal, etc.)
automatically have ~/.gemini/config/mcp_config.json and /workspace/.agents/mcp_config.json
configured with krunbox-gateway.
"""

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from krunbox.core.sandbox import SandboxInfo, NetworkPolicy
from krunbox.core.manager import SandboxManager
from krunbox.core.network import generate_egress_firewall_script, _mcp_config_shell_block


def test_egress_firewall_provisions_gemini_config(tmp_path):
    """
    Simulate container boot with fresh volumes:
    Verifies that running the generated /etc/krunbox-egress.sh automatically creates
    ~/.gemini/config/mcp_config.json with krunbox-gateway.
    """
    fake_home = tmp_path / "home" / "vscode"
    fake_ws = tmp_path / "workspace"
    fake_ipc = tmp_path / "run" / "krunbox"
    fake_home.mkdir(parents=True)
    fake_ws.mkdir(parents=True)
    fake_ipc.mkdir(parents=True)

    # Bridge binary exists in /run/krunbox
    (fake_ipc / "krunbox-mcp").write_text("#!/bin/sh\nexit 0\n")
    (fake_ipc / "krunbox-mcp").chmod(0o755)

    with patch("krunbox.core.network.resolve_domain_ips", return_value=["1.2.3.4"]):
        policy = NetworkPolicy(profile="ai-only")
        script = generate_egress_firewall_script(policy)

    # Adapt paths to simulated sandbox rootfs
    guest_script = (
        script
        .replace("/home/vscode", str(fake_home))
        .replace("/workspace", str(fake_ws))
        .replace("/run/krunbox", str(fake_ipc))
    )

    runner = f"""#!/bin/bash
set -e
{guest_script}
"""
    res = subprocess.run(["bash", "-c", runner], capture_output=True, text=True)
    assert res.returncode == 0, f"Script failed: {res.stderr}"

    # Verify ~/.gemini/config/mcp_config.json was created
    gemini_cfg = fake_home / ".gemini" / "config" / "mcp_config.json"
    assert gemini_cfg.is_file(), f"File {gemini_cfg} was not created!"
    data = json.loads(gemini_cfg.read_text(encoding="utf-8"))
    assert "mcpServers" in data
    assert "krunbox-gateway" in data["mcpServers"]
    assert data["mcpServers"]["krunbox-gateway"]["command"] == f"{fake_ipc}/krunbox-mcp"

    # Verify /workspace/.agents/mcp_config.json was created
    ws_cfg = fake_ws / ".agents" / "mcp_config.json"
    assert ws_cfg.is_file(), f"File {ws_cfg} was not created!"
    ws_data = json.loads(ws_cfg.read_text(encoding="utf-8"))
    assert ws_data["mcpServers"]["krunbox-gateway"]["command"] == f"{fake_ipc}/krunbox-mcp"


def test_entrypoint_preserves_existing_mcp_servers(tmp_path):
    """
    If a user has existing custom MCP servers configured, running auto-provisioning
    MUST preserve their custom servers while ensuring krunbox-gateway is added.
    """
    fake_home = tmp_path / "home" / "vscode"
    cfg_dir = fake_home / ".gemini" / "config"
    cfg_dir.mkdir(parents=True)
    cfg_file = cfg_dir / "mcp_config.json"

    initial_config = {
        "mcpServers": {
            "my-custom-tool": {
                "command": "python3",
                "args": ["-m", "my_server"]
            }
        }
    }
    cfg_file.write_text(json.dumps(initial_config, indent=2))

    block = "\n".join(_mcp_config_shell_block()).replace("/home/vscode", str(fake_home))
    res = subprocess.run(["bash", "-c", block], capture_output=True, text=True)
    assert res.returncode == 0

    merged = json.loads(cfg_file.read_text(encoding="utf-8"))
    assert "my-custom-tool" in merged["mcpServers"]
    assert "krunbox-gateway" in merged["mcpServers"]
    assert merged["mcpServers"]["krunbox-gateway"]["command"] == "/run/krunbox/krunbox-mcp"


def test_posix_fallback_when_python_unavailable(tmp_path):
    """
    Verify that even if python3 is unavailable or broken in guest,
    the POSIX shell fallback creates ~/.gemini/config/mcp_config.json.
    """
    fake_home = tmp_path / "home" / "vscode"
    fake_home.mkdir(parents=True)

    # Execute with python3 masked out in PATH
    block = "\n".join(_mcp_config_shell_block()).replace("/home/vscode", str(fake_home))
    fake_bin = tmp_path / "empty_bin"
    fake_bin.mkdir()

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:/bin:/usr/bin"
    # Ensure command -v python3 returns false
    runner = f"""#!/bin/bash
command() {{
    if [ "$2" = "python3" ]; then return 1; fi
    builtin command "$@"
}}
{block}
"""
    res = subprocess.run(["bash", "-c", runner], env=env, capture_output=True, text=True)
    assert res.returncode == 0

    cfg_file = fake_home / ".gemini" / "config" / "mcp_config.json"
    assert cfg_file.is_file()
    data = json.loads(cfg_file.read_text(encoding="utf-8"))
    assert "krunbox-gateway" in data["mcpServers"]
    assert data["mcpServers"]["krunbox-gateway"]["command"] == "/run/krunbox/krunbox-mcp"
