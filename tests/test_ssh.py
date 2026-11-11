"""
Unit tests for SSH key management and configuration files.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from krunbox.core import ssh

def test_ensure_host_ssh_keys():
    keys = ssh.ensure_host_ssh_keys()
    assert isinstance(keys, list)

def test_write_sandbox_ssh_config(tmp_path):
    conf_dir = tmp_path / "config.d"
    conf_dir.mkdir(parents=True)
    conf_file = tmp_path / "config"

    with patch("krunbox.core.ssh.SSH_CONF_DIR", conf_dir), \
         patch("krunbox.core.ssh.SSH_CONFIG_FILE", conf_file):

        path = ssh.write_sandbox_ssh_config("krunbox-testbox", 2222, extra_aliases=["testbox-alias"])
        assert path.exists()

        content = path.read_text()
        assert "Host krunbox-testbox testbox-alias" in content
        assert "Port 2222" in content
        assert "User vscode" in content
        assert "StrictHostKeyChecking no" in content

        main_content = conf_file.read_text()
        assert "Include ~/.ssh/config.d/*" in main_content

def test_remove_sandbox_ssh_config(tmp_path):
    conf_dir = tmp_path / "config.d"
    conf_dir.mkdir(parents=True)
    conf_file = tmp_path / "config"

    with patch("krunbox.core.ssh.SSH_CONF_DIR", conf_dir), \
         patch("krunbox.core.ssh.SSH_CONFIG_FILE", conf_file):

        path = ssh.write_sandbox_ssh_config("krunbox-testbox", 2222)
        assert path.exists()

        ssh.remove_sandbox_ssh_config("krunbox-testbox")
        assert not path.exists()

def test_get_supported_terminals():
    terminals = ssh.get_supported_terminals("target-box")
    assert len(terminals) > 0
    # First candidate should be ptyxis
    assert terminals[0][0] == "ptyxis"
    # Ensure all candidates include target-box in arguments
    assert any("target-box" in cmd for cmd in terminals)

def test_launch_ssh_terminal_success():
    with patch("shutil.which", side_effect=lambda x: "/usr/bin/" + x if x == "ptyxis" else None), \
         patch("subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.pid = 9876
        mock_popen.return_value = mock_proc

        ok, msg = ssh.launch_ssh_terminal("box-1")
        assert ok is True
        assert "Launched ptyxis" in msg
        assert "9876" in msg
        mock_popen.assert_called_once()
        cmd_called = mock_popen.call_args[0][0]
        assert cmd_called[0] == "ptyxis"
        assert "box-1" in cmd_called

def test_launch_ssh_terminal_none_found():
    with patch("shutil.which", return_value=None):
        ok, msg = ssh.launch_ssh_terminal("box-1")
        assert ok is False
        assert "No supported terminal emulator found" in msg
        assert "ssh box-1" in msg
