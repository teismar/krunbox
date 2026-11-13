"""
Unit tests for network egress filtering, domain whitelisting, and guest DNS bundle generation.
"""

import json
from unittest.mock import patch
import pytest

from krunbox.core.sandbox import NetworkPolicy
from krunbox.core.egress_traffic import EgressTrafficManager
from krunbox.core.network import (
    get_profile_domains,
    get_denied_domains,
    resolve_domain_ips,
    generate_egress_firewall_script,
    write_guest_egress_bundle,
)


def test_get_profile_domains():
    full_domains = get_profile_domains("full")
    assert len(full_domains) == 0

    ai_domains = get_profile_domains("ai-only")
    assert "api.openai.com" in ai_domains
    assert "api.anthropic.com" in ai_domains
    assert "generativelanguage.googleapis.com" in ai_domains
    assert "aicode.googleapis.com" in ai_domains
    assert "daily-cloudcode-pa.googleapis.com" in ai_domains
    assert "play.googleapis.com" in ai_domains
    assert "*.googleapis.com" in ai_domains
    assert "*.run.app" in ai_domains
    assert "oauth2.googleapis.com" in ai_domains
    assert "accounts.google.com" in ai_domains
    assert "codestral.mistral.ai" in ai_domains

    dev_domains = get_profile_domains("dev-common")
    assert "github.com" in dev_domains
    assert "registry.npmjs.org" in dev_domains
    assert "pypi.org" in dev_domains
    assert "aicode.googleapis.com" in dev_domains
    assert "daily-cloudcode-pa.googleapis.com" in dev_domains
    assert "play.googleapis.com" in dev_domains
    assert "*.googleapis.com" in dev_domains
    assert "*.run.app" in dev_domains
    assert "oauth2.googleapis.com" in dev_domains
    assert "accounts.google.com" in dev_domains
    assert "codestral.mistral.ai" in dev_domains


def test_get_custom_domains():
    custom = get_profile_domains("custom", custom_domains=["internal.corp.com", "custom.ai"])
    assert "internal.corp.com" in custom
    assert "custom.ai" in custom


def test_generate_egress_firewall_offline():
    policy = NetworkPolicy(profile="offline")
    script = generate_egress_firewall_script(policy)
    assert "nft 'add rule inet krunbox_filter output drop'" in script
    assert "nft 'add rule inet krunbox_filter forward drop'" in script
    assert "OFFLINE" in script
    # Offline mode MUST NOT allow any port 53 traffic
    assert "udp dport 53 accept" not in script
    assert "tcp dport 53 accept" not in script


def test_generate_egress_firewall_ai_only():
    policy = NetworkPolicy(profile="ai-only")
    script = generate_egress_firewall_script(policy)
    assert "table inet krunbox_filter" in script
    assert "allowed_egress" in script
    assert "nft 'add rule inet krunbox_filter output tcp dport { 80, 443 } drop'" in script
    assert "nft 'add rule inet krunbox_filter forward tcp dport { 80, 443 } drop'" in script
    # DNS Bypass guard: only 127.0.0.1 or redirect, and skuid 0 allowed to upstream
    assert "output ip daddr 127.0.0.1 udp dport 53 accept" in script
    assert "output meta skuid 0 udp dport 53 accept" in script
    assert "output meta skuid 0 accept" in script
    assert "krunbox_nat" in script


def test_generate_egress_firewall_full():
    policy = NetworkPolicy(profile="full")
    script = generate_egress_firewall_script(policy)
    assert "no egress firewall installed" in script
    assert "nft 'flush table inet krunbox_filter'" in script


def test_get_denied_domains():
    raw = [" Evil.com ", "malware.site", "evil.com", ""]
    clean = get_denied_domains(raw)
    assert clean == ["evil.com", "malware.site"]


def test_generate_egress_firewall_blacklist_on_full():
    # Full profile with specific blacklisted domains
    policy = NetworkPolicy(profile="full", denied_domains=["evil.com"])
    script = generate_egress_firewall_script(policy)
    assert "table inet krunbox_filter" in script
    assert "denied_egress" in script
    assert "nft 'add rule inet krunbox_filter output ip daddr @denied_egress_v4 drop'" in script
    assert "nft 'add rule inet krunbox_filter forward ip daddr @denied_egress_v4 drop'" in script


def test_generate_egress_firewall_combined_whitelist_and_blacklist():
    # AI-only profile with an extra allowed domain and an explicitly blocked provider
    policy = NetworkPolicy(
        profile="ai-only",
        allowed_domains=["custom-llm.corp.internal"],
        denied_domains=["api.openai.com", "malicious-telemetry.io"]
    )
    script = generate_egress_firewall_script(policy)
    assert "denied_egress" in script
    assert "allowed_egress" in script
    assert "nft 'add rule inet krunbox_filter output ip daddr @denied_egress_v4 drop'" in script
    assert "nft 'add rule inet krunbox_filter output ip daddr @allowed_egress_v4 tcp dport { 80, 443 } accept'" in script


def test_generate_egress_firewall_ipv6_rules():
    from unittest.mock import patch
    with patch("krunbox.core.network.resolve_domain_ips") as mock_resolve:
        mock_resolve.return_value = ["1.2.3.4", "2001:db8::1"]
        policy = NetworkPolicy(
            profile="ai-only",
            allowed_domains=["allowed.example.com"],
            denied_domains=["blocked.example.com"]
        )
        script = generate_egress_firewall_script(policy)
        assert "denied_egress_v6" in script
        assert "allowed_egress_v6" in script
        assert "2001:db8::1" in script
        assert "ip6 daddr @denied_egress_v6 drop" in script
        assert "ip6 daddr @allowed_egress_v6 tcp dport { 80, 443 } accept" in script


def test_write_guest_egress_bundle(tmp_path):
    bundle = tmp_path / "guest_bundle"
    policy = NetworkPolicy(
        profile="ai-only",
        allowed_domains=["extra.ai.example"],
        denied_domains=["api.openai.com"],
    )
    write_guest_egress_bundle("krunbox-test", policy, bundle)

    policy_file = bundle / "policy.json"
    monitor_file = bundle / "dns_monitor.py"
    assert policy_file.is_file()
    assert monitor_file.is_file()

    data = json.loads(policy_file.read_text(encoding="utf-8"))
    assert data["sandbox_name"] == "krunbox-test"
    assert data["profile"] == "ai-only"
    assert "extra.ai.example" in data["allowed_domains"]
    assert "api.openai.com" not in data["allowed_domains"]
    assert "api.openai.com" in data["denied_domains"]


def test_manager_update_network_policy(tmp_path):
    from krunbox.core.manager import SandboxManager

    data_dir = tmp_path / "data"
    with patch("krunbox.core.manager.DATA_DIR", data_dir):
        mgr = SandboxManager(state_file=tmp_path / "sandboxes.json")
        mgr.egress_traffic = EgressTrafficManager(logs_dir=data_dir / "egress_logs")

        box = mgr.create_sandbox(str(tmp_path), name="test-egress-box")
        assert box.network_policy.profile == "full"
        assert len(box.network_policy.denied_domains) == 0

        new_policy = NetworkPolicy(
            profile="ai-only",
            allowed_domains=["my-api.com"],
            denied_domains=["blocked.com"]
        )
        res = mgr.update_network_policy("test-egress-box", new_policy)
        assert res is True

        updated = mgr.get_sandbox("test-egress-box")
        assert updated.network_policy.profile == "ai-only"
        assert updated.network_policy.allowed_domains == ["my-api.com"]
        assert updated.network_policy.denied_domains == ["blocked.com"]


def test_generate_egress_firewall_contains_mcp_autoconfig():
    """Verify that every generated firewall profile auto-provisions krunbox-gateway MCP configs."""
    with patch("krunbox.core.network.resolve_domain_ips", return_value=["1.2.3.4"]):
        for profile in ("full", "offline", "ai-only", "dev-common", "custom"):
            policy = NetworkPolicy(profile=profile)
            script = generate_egress_firewall_script(policy)
            assert "Auto-configure in-sandbox krunbox-gateway MCP server" in script
            assert "krunbox-gateway" in script
            assert ".gemini/config/mcp_config.json" in script
            assert "/workspace/.agents/mcp_config.json" in script


def test_mcp_config_shell_block_execution(tmp_path):
    """Execute the MCP auto-config block directly in bash and verify JSON output on disk."""
    import subprocess
    from krunbox.core.network import _mcp_config_shell_block

    fake_home = tmp_path / "home" / "vscode"
    fake_home.mkdir(parents=True)
    fake_ws = tmp_path / "workspace"
    fake_ws.mkdir(parents=True)
    fake_ipc = tmp_path / "run" / "krunbox"
    fake_ipc.mkdir(parents=True)
    (fake_ipc / "krunbox-mcp").write_text("#!/bin/sh\nexit 0\n")
    (fake_ipc / "krunbox-mcp").chmod(0o755)

    block_lines = _mcp_config_shell_block()
    script_body = "\n".join(block_lines)

    # Adapt paths to temp dir for test execution
    adapted_script = (
        script_body
        .replace("/home/vscode", str(fake_home))
        .replace("/workspace", str(fake_ws))
        .replace("/run/krunbox", str(fake_ipc))
    )

    runner = f"""#!/bin/bash
set -e
{adapted_script}
"""
    res = subprocess.run(["bash", "-c", runner], capture_output=True, text=True)
    assert res.returncode == 0, f"Script failed: {res.stderr}"

    # Verify global config ~/.gemini/config/mcp_config.json
    gemini_cfg = fake_home / ".gemini" / "config" / "mcp_config.json"
    assert gemini_cfg.is_file(), f"Expected {gemini_cfg} to exist"
    data = json.loads(gemini_cfg.read_text(encoding="utf-8"))
    assert "mcpServers" in data
    assert "krunbox-gateway" in data["mcpServers"]
    assert data["mcpServers"]["krunbox-gateway"]["command"] == f"{fake_ipc}/krunbox-mcp"

    # Verify workspace config /workspace/.agents/mcp_config.json
    ws_cfg = fake_ws / ".agents" / "mcp_config.json"
    assert ws_cfg.is_file(), f"Expected {ws_cfg} to exist"
    ws_data = json.loads(ws_cfg.read_text(encoding="utf-8"))
    assert ws_data["mcpServers"]["krunbox-gateway"]["command"] == f"{fake_ipc}/krunbox-mcp"

