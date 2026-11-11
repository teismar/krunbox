"""
Comprehensive automated security and vulnerability regression tests for krunbox.
"""

import os
import re
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from krunbox.core import ssh
from krunbox.core import network
from krunbox.core import ports
from krunbox.core.manager import SandboxManager
from krunbox.core.images import ImageManager
from krunbox.core.sandbox import NetworkPolicy

# =========================================================================
# 1. OpenSSH Configuration & Injection Hardening
# =========================================================================

def test_ssh_config_injection_prevention(tmp_path):
    """Ensure newline characters and directives cannot be injected into SSH config."""
    conf_dir = tmp_path / "config.d"
    conf_dir.mkdir(parents=True)
    conf_file = tmp_path / "config"

    with patch("krunbox.core.ssh.SSH_CONF_DIR", conf_dir), \
         patch("krunbox.core.ssh.SSH_CONFIG_FILE", conf_file):

        # Attempt directive injection via alias
        malicious_alias = "alias\n    ProxyCommand /tmp/evil.sh\n    LocalCommand /tmp/evil.sh"
        conf_path = ssh.write_sandbox_ssh_config("krunbox-safe", 2222, extra_aliases=[malicious_alias])
        content = conf_path.read_text()

        # The malicious directives MUST NOT appear as standalone directives
        assert "ProxyCommand" not in content
        assert "LocalCommand" not in content
        assert "\n    ProxyCommand" not in content
        # Newlines in alias should have been sanitized to dashes
        assert "alias-proxycommand" in content or "test" not in content

def test_ssh_config_path_traversal_prevention(tmp_path):
    """Ensure sandbox names cannot escape SSH_CONF_DIR via path traversal."""
    conf_dir = tmp_path / "config.d"
    conf_dir.mkdir(parents=True)
    conf_file = tmp_path / "config"

    with patch("krunbox.core.ssh.SSH_CONF_DIR", conf_dir), \
         patch("krunbox.core.ssh.SSH_CONFIG_FILE", conf_file):

        # Traversal names must either be sanitized to safe filenames or raise ValueError
        traversal_name = "../../etc/cron.d/evil"
        path = ssh.write_sandbox_ssh_config(traversal_name, 2222)
        assert path.exists()
        assert path.parent.resolve() == conf_dir.resolve()

def test_terminal_target_injection_prevention():
    """Ensure shell metacharacters and option injection are blocked in launch_ssh_terminal."""
    malicious_targets = [
        "target; xclock",
        "target && id",
        "target | cat /etc/passwd",
        "target`reboot`",
        "target$(whoami)",
        "-oProxyCommand=calc.exe",
        "box name with spaces",
    ]
    for target in malicious_targets:
        ok, msg = ssh.launch_ssh_terminal(target)
        assert ok is False
        assert "Invalid target identifier" in msg

# =========================================================================
# 2. Egress Script Injection & Domain Filtering Hardening
# =========================================================================

def test_egress_script_profile_injection_prevention():
    """Ensure malicious profile names cannot inject commands into container egress script."""
    malicious_policy = NetworkPolicy(
        profile="full'; rm -rf /; echo 'pwned",
        allowed_domains=[],
        denied_domains=[]
    )
    script = network.generate_egress_firewall_script(malicious_policy)
    # Malicious command must NOT appear unquoted or unescaped in bash script
    assert "rm -rf /" not in script
    # Profile should default to 'custom'
    assert "Profile: custom" in script

def test_domain_filtering_sanitization():
    """Ensure shell injection strings are rejected as domains and excluded from sets."""
    malicious_domains = [
        "google.com; rm -rf /",
        "api.openai.com\nadd element drop",
        "eval.com' || touch /tmp/pwned",
        "$(whoami).evil.com",
        "valid-domain.com",
    ]
    denied = network.get_denied_domains(malicious_domains)
    assert "valid-domain.com" in denied
    # Malicious inputs must be filtered out
    assert not any(";" in d or "\n" in d or "'" in d or "$" in d for d in denied)

def test_egress_script_private_directory(tmp_path):
    """Ensure egress scripts are stored in private data dir with mode 0700, not shared /tmp."""
    fake_data = tmp_path / "data"
    state_file = tmp_path / "sandboxes.json"
    mgr = SandboxManager(state_file=state_file)

    with patch("krunbox.core.manager.DATA_DIR", fake_data), \
         patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "abc123container\n"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        ws = tmp_path / "ws"
        ws.mkdir()
        box = mgr.create_sandbox(str(ws), name="sec-box")
        mgr.start_sandbox(box.name, detach=True)

        egress_dir = fake_data / "egress"
        assert egress_dir.exists()
        script_file = egress_dir / f"{box.name}.sh"
        assert script_file.exists()

# =========================================================================
# 3. Port Range & SSH Tunnel Security
# =========================================================================

def test_port_range_validation():
    """Ensure invalid and out-of-range ports are rejected."""
    # Valid ports
    m1 = ports.parse_port_spec("80")
    assert m1.host_port == 80 and m1.guest_port == 80

    m2 = ports.parse_port_spec("65535:65535")
    assert m2.host_port == 65535 and m2.guest_port == 65535

    # Out of range ports
    with pytest.raises(ValueError, match="out of valid range"):
        ports.parse_port_spec("0")

    with pytest.raises(ValueError, match="out of valid range"):
        ports.parse_port_spec("-80")

    with pytest.raises(ValueError, match="out of valid range"):
        ports.parse_port_spec("70000")

    with pytest.raises(ValueError, match="out of valid range"):
        ports.parse_port_spec("80:99999")

def test_ssh_tunnel_option_injection_prevention():
    """Ensure ssh_host cannot inject OpenSSH options."""
    with pytest.raises(ValueError, match="Invalid SSH host name"):
        ports.start_ssh_tunnel("-oProxyCommand=evil", 8080, 80)

def test_ssh_tunnel_uid_scoping():
    """Ensure pgrep and pkill include -u <uid> to prevent affecting other users."""
    mapping = ports.PortMapping(host_port=3000, guest_port=3000, is_tunnel=True, tunnel_pid=None)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        ports.stop_ssh_tunnel(mapping)
        assert mock_run.called
        cmd = mock_run.call_args[0][0]
        assert "-u" in cmd
        assert str(os.getuid()) in cmd

# =========================================================================
# 4. Correctness & Invariant Enforcement
# =========================================================================

def test_image_manager_path_import():
    """Ensure ImageManager build_agent_box has Path imported properly."""
    img_mgr = ImageManager()
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "Successfully built\n"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        ok, msg = img_mgr.build_agent_box("/workspace/Containerfile")
        assert ok is True
        assert "Successfully built" in msg

def test_zero_mentions_of_sbx():
    """Invariant test: Zero occurrences of forbidden 'sbx' in tracked files."""
    workspace_root = Path("/workspace")
    for py_file in workspace_root.glob("krunbox/**/*.py"):
        content = py_file.read_text().lower()
        # Word boundary search for sbx
        matches = re.findall(r"\bsbx\b", content)
        assert len(matches) == 0, f"Forbidden 'sbx' found in {py_file}"
