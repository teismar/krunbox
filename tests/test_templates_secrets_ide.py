"""
Unit and security regression tests for krunbox Sandbox Templates,
Scoped Secret & Environment Variable Vault, and 1-Click IDE Launchers.
"""

import os
from pathlib import Path
import stat
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from krunbox.core import config as core_config
from krunbox.core.ide import IDE_SPECS, detect_installed_ides, launch_ide
from krunbox.core.secrets import (
    ENV_KEY_REGEX,
    FORBIDDEN_ENV_KEYS,
    SecretVaultManager,
    is_valid_env_key,
    sanitize_env_value,
)
from krunbox.core.templates import (
    BUILTIN_TEMPLATES,
    SandboxTemplate,
    TemplateManager,
)


# =========================================================================
# 1. Sandbox Templates (krunbox.core.templates)
# =========================================================================


def test_builtin_templates_catalog_and_image_resolution():
    """Verify all curated built-in presets and their resolved OCI tags."""
    mgr = TemplateManager()
    templates = mgr.list_templates()
    builtin_ids = [t.id for t in templates]
    assert builtin_ids == [
        "standard-agent",
        "locked-down-reviewer",
        "ai-only-coder",
        "fullstack-web",
        "python-data-ml",
        "reversing",
    ]
    assert len(BUILTIN_TEMPLATES) == 6

    std = mgr.get_template("standard-agent")
    assert std is not None
    assert std.builtin is True
    assert std.name == "Standard AI Agent"
    assert std.cpus == 4 and std.ram_mib == 4096
    assert std.network_profile == "full"
    assert std.ports == ["3000"]
    assert std.protect_git_hooks is True
    assert std.resolved_image_tag() == "localhost/agent-box:latest"

    reviewer = mgr.get_template("Locked-Down Reviewer")
    assert reviewer is not None
    assert reviewer.id == "locked-down-reviewer"
    assert reviewer.cpus == 2 and reviewer.ram_mib == 2048
    assert reviewer.network_profile == "offline"
    assert reviewer.ports == []
    assert reviewer.protect_git_hooks is True
    assert reviewer.protect_git_config is True
    assert reviewer.protect_env_files is True
    assert reviewer.host_egress_lockdown is True
    assert reviewer.idle_timeout_minutes == 30
    assert reviewer.idle_action == "stop"

    ai_coder = mgr.get_template("AI-Only Coding Agent")
    assert ai_coder is not None
    assert ai_coder.id == "ai-only-coder"
    assert ai_coder.network_profile == "ai-only"
    assert ai_coder.ports == ["3000"]
    assert ai_coder.host_egress_lockdown is True
    assert ai_coder.idle_timeout_minutes == 30

    web = mgr.get_template("fullstack-web")
    assert web is not None
    assert web.network_profile == "dev-common"
    assert web.ports == ["3000", "5173", "8000"]

    ml = mgr.get_template("python-data-ml")
    assert ml is not None
    assert ml.base_image == "python-data"
    assert ml.resolved_image_tag() == "localhost/krunbox-python:latest"
    assert ml.ram_mib == 8192
    assert ml.ports == ["8888"]
    assert ml.is_persistent is True

    rev = mgr.get_template("reversing")
    assert rev is not None
    assert rev.builtin is True
    assert rev.name == "Reverse Engineering & Binary Analysis"
    assert rev.base_image == "reversing"
    assert rev.resolved_image_tag() == "localhost/krunbox-reversing:latest"
    assert rev.cpus == 4 and rev.ram_mib == 8192
    assert rev.network_profile == "full"
    assert rev.is_persistent is True
    assert rev.ports == ["3000", "8000", "8089"]
    # Alias lookup verification
    rev_alias = mgr.get_template("reverse-engineering")
    assert rev_alias is not None
    assert rev_alias.id == "reversing"


def test_template_dataclass_roundtrip_and_custom_oci_tag():
    """Ensure unknown fields are filtered on load and custom OCI tags resolve intact."""
    raw = {
        "id": "rust-systems",
        "name": "Rust Systems",
        "description": "Custom Rust toolchain",
        "base_image": "docker.io/library/rust:1.82-bookworm",
        "cpus": 6,
        "ram_mib": 6144,
        "network_profile": "unknown-future-profile",
        "ports": [8080, "9090"],
        "unexpected_future_field": "ignored",
    }
    tmpl = SandboxTemplate.from_dict(raw)
    assert tmpl.id == "rust-systems"
    assert tmpl.resolved_image_tag() == "docker.io/library/rust:1.82-bookworm"
    assert tmpl.network_profile == "custom"
    assert tmpl.ports == ["8080", "9090"]
    serialized = tmpl.to_dict()
    assert "unexpected_future_field" not in serialized


def test_custom_template_crud_and_builtin_overwrite_protection():
    """Verify saving, sorting, retrieving, deleting, and protecting built-in IDs."""
    mgr = TemplateManager()
    assert mgr.templates_file == core_config.CONFIG_DIR / "templates.json"
    assert mgr.slugify_id("  My Custom Rust & Go Preset! ") == "my-custom-rust-go-preset"
    assert mgr.slugify_id("!!!") == "custom-template"

    # Attempt to overwrite built-in 'standard-agent' must suffix '-custom' and force builtin=False
    collision = SandboxTemplate(
        id="standard-agent",
        name="My Tweaked Standard Agent",
        description="Custom variant",
        builtin=True,
        cpus=8,
        ram_mib=8192,
    )
    saved_collision = mgr.save_custom_template(collision)
    assert saved_collision.id == "standard-agent-custom"
    assert saved_collision.builtin is False

    # Original built-in must remain intact
    orig = mgr.get_template("standard-agent")
    assert orig is not None
    assert orig.builtin is True
    assert orig.cpus == 4

    # Save another custom template to verify alphabetical ordering after built-ins
    alpha = SandboxTemplate(
        id="",
        name="Alpha Microservice",
        description="First alphabetically among custom presets",
        cpus=2,
        ram_mib=2048,
    )
    saved_alpha = mgr.save_custom_template(alpha)
    assert saved_alpha.id == "alpha-microservice"

    listed = mgr.list_templates()
    assert [t.id for t in listed[:6]] == [t.id for t in BUILTIN_TEMPLATES]
    assert [t.id for t in listed[6:]] == ["alpha-microservice", "standard-agent-custom"]

    # Built-in deletion must be refused
    assert mgr.delete_custom_template("standard-agent") is False
    assert mgr.delete_custom_template("nonexistent-id") is False

    # Custom deletion must succeed and persist
    assert mgr.delete_custom_template("standard-agent-custom") is True
    assert mgr.get_template("standard-agent-custom") is None
    assert mgr.get_template("Alpha Microservice") is not None


# =========================================================================
# 2. Scoped Secret & Environment Variable Vault (krunbox.core.secrets)
# =========================================================================


def test_env_key_validation_and_forbidden_keys():
    """Ensure loader/shell hijack variables and malformed keys are strictly rejected."""
    assert ENV_KEY_REGEX.match("OPENAI_API_KEY")
    assert is_valid_env_key("OPENAI_API_KEY") is True
    assert is_valid_env_key("_PRIVATE_TOKEN_2") is True
    assert is_valid_env_key("LD_SDK_KEY") is True  # legitimate key not in forbidden set

    expected_forbidden = {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "SSH_AUTH_KEYS",
        "IFS",
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "PYTHONPATH",
        "NODE_OPTIONS",
    }
    assert expected_forbidden.issubset(FORBIDDEN_ENV_KEYS)

    for forbidden in expected_forbidden:
        assert is_valid_env_key(forbidden) is False
        assert is_valid_env_key(forbidden.lower()) is False

    for invalid in ["", "1BAD", "BAD-KEY", "BAD KEY", "-e", "A" * 129, "KEY=VAL", "KEY\nTWO"]:
        assert is_valid_env_key(invalid) is False


def test_sanitize_env_value_strips_newlines_and_nulls():
    """Ensure CR, LF, and NUL bytes cannot inject extra lines into --env-file."""
    payload = "sk-secret\r\nLD_PRELOAD=/tmp/evil.so\nSECOND_VAR=1\x00tail"
    cleaned = sanitize_env_value(payload)
    assert "\n" not in cleaned
    assert "\r" not in cleaned
    assert "\x00" not in cleaned
    assert cleaned == "sk-secretLD_PRELOAD=/tmp/evil.soSECOND_VAR=1tail"


def test_local_vault_permissions_and_crud(tmp_path):
    """Verify 0700 directory, 0600 vault file permissions, and secret CRUD."""
    secrets_dir = tmp_path / "secrets"
    rt_dir = tmp_path / "rt"
    vault = SecretVaultManager(secrets_dir=secrets_dir, runtime_dir=rt_dir)

    assert secrets_dir.exists()
    assert stat.S_IMODE(secrets_dir.stat().st_mode) == 0o700

    with pytest.raises(ValueError):
        vault.set_secret("krunbox-demo", "LD_PRELOAD", "/evil.so", prefer_keyring=False)
    with pytest.raises(ValueError):
        vault.set_secret("krunbox-demo", "SSH_AUTH_KEYS", "ssh-ed25519 AAAA", prefer_keyring=False)
    with pytest.raises(ValueError):
        vault.set_secret("---", "OPENAI_API_KEY", "sk-123", prefer_keyring=False)

    backend = vault.set_secret("krunbox-demo", "ANTHROPIC_API_KEY", "sk-ant-123\ninjected=1", prefer_keyring=False)
    assert backend == "vault"

    vault_file = secrets_dir / "krunbox-demo.vault.json"
    assert vault_file.exists()
    assert stat.S_IMODE(vault_file.stat().st_mode) == 0o600

    assert vault.get_secret("krunbox-demo", "ANTHROPIC_API_KEY") == "sk-ant-123injected=1"
    assert vault.list_secret_keys("krunbox-demo", known_keys=["OPENAI_API_KEY", "PATH"]) == [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
    ]

    assert vault.delete_secret("krunbox-demo", "ANTHROPIC_API_KEY") is True
    assert vault.get_secret("krunbox-demo", "ANTHROPIC_API_KEY") is None
    assert not vault_file.exists()


def test_keyring_integration_and_system_keyring_lookup(tmp_path, monkeypatch):
    """Verify mocked secret-tool store (stdin only!), lookup, clear, and flag injection blocks."""
    secrets_dir = tmp_path / "secrets"
    vault = SecretVaultManager(secrets_dir=secrets_dir, runtime_dir=tmp_path / "rt")

    # Seed a stale copy in local vault first to confirm keyring write purges local copy
    vault.set_secret("krunbox-box", "OPENAI_API_KEY", "stale-local", prefer_keyring=False)
    assert (secrets_dir / "krunbox-box.vault.json").exists()

    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")

    with patch("krunbox.core.secrets.shutil.which", return_value="/usr/bin/secret-tool"), \
         patch("krunbox.core.secrets.subprocess.run") as mock_run:
        assert vault.has_keyring() is True

        # 1. set_secret stores via stdin and cleans up stale local vault copy
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        backend = vault.set_secret("krunbox-box", "OPENAI_API_KEY", "sk-live-secret-999")
        assert backend == "keyring"

        store_call = mock_run.call_args
        store_cmd = store_call.args[0]
        assert store_cmd[:2] == ["secret-tool", "store"]
        assert "sk-live-secret-999" not in store_cmd  # NEVER leaked in CLI argv
        assert store_call.kwargs["input"] == "sk-live-secret-999"
        assert not (secrets_dir / "krunbox-box.vault.json").exists()

        # 2. get_secret retrieves from secret-tool lookup
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="sk-live-secret-999\n", stderr=""
        )
        assert vault.get_secret("krunbox-box", "OPENAI_API_KEY") == "sk-live-secret-999"

        # 3. lookup_system_keyring pulls user secret and blocks leading '-' option flags
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="ghp_systemtoken123\n", stderr=""
        )
        tok = vault.lookup_system_keyring({"service": "github", "username": "alice"})
        assert tok == "ghp_systemtoken123"
        assert mock_run.call_args.args[0] == [
            "secret-tool",
            "lookup",
            "service",
            "github",
            "username",
            "alice",
        ]

        for bad_attrs in [
            {"--version": "1"},
            {"service": "--help"},
            {"-o": "evil"},
            {"service": "-x"},
            {"": "val"},
            {"service": ""},
            {"bad key": "val"},
        ]:
            with pytest.raises(ValueError):
                vault.lookup_system_keyring(bad_attrs)

        # 4. delete_secret invokes secret-tool clear
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        assert vault.delete_secret("krunbox-box", "OPENAI_API_KEY") is True
        assert mock_run.call_args.args[0][:2] == ["secret-tool", "clear"]


def test_runtime_env_file_staging_passthrough_and_zero_wipe(tmp_path, monkeypatch):
    """Verify --env-file formatting, host passthrough, 0600 perms, and zero-wipe before unlink."""
    secrets_dir = tmp_path / "secrets"
    rt_dir = tmp_path / "runtime_shm"
    vault = SecretVaultManager(secrets_dir=secrets_dir, runtime_dir=rt_dir)

    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.setenv("HOST_GEMINI_KEY", "gem-host-123\nEVIL=1")
    monkeypatch.setenv("LD_PRELOAD", "/host/evil.so")

    vault.set_secret("krunbox-agent", "OPENAI_API_KEY", "sk-vault-456", prefer_keyring=False)

    # Empty resolution returns None
    assert vault.prepare_runtime_env_file("krunbox-agent") is None

    env_path = vault.prepare_runtime_env_file(
        "krunbox-agent",
        plain_env={
            "CUSTOM_ENDPOINT": "https://api.example.com\r\nINJECTED=true",
            "PATH": "/malicious/bin",  # forbidden -> filtered out
        },
        secret_keys=["OPENAI_API_KEY"],
        host_env_passthrough=["HOST_GEMINI_KEY", "LD_PRELOAD", "UNSET_HOST_VAR"],
    )
    assert env_path is not None
    assert env_path.exists()
    assert env_path.parent == rt_dir
    assert stat.S_IMODE(rt_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600

    lines = env_path.read_text(encoding="utf-8").splitlines()
    assert lines == [
        "CUSTOM_ENDPOINT=https://api.example.comINJECTED=true",
        "HOST_GEMINI_KEY=gem-host-123EVIL=1",
        "OPENAI_API_KEY=sk-vault-456",
    ]

    # Intercept Path.unlink to prove file bytes are overwritten with zeros BEFORE unlinking
    original_size = env_path.stat().st_size
    assert original_size > 0
    observed_bytes_at_unlink = []
    real_unlink = Path.unlink

    def spy_unlink(self_path, *args, **kwargs):
        if self_path == env_path and self_path.exists():
            observed_bytes_at_unlink.append(self_path.read_bytes())
        return real_unlink(self_path, *args, **kwargs)

    with patch.object(Path, "unlink", spy_unlink):
        vault.cleanup_runtime_env_file(env_path)

    assert not env_path.exists()
    assert len(observed_bytes_at_unlink) == 1
    assert observed_bytes_at_unlink[0] == b"\x00" * original_size


def test_cleanup_runtime_env_file_refuses_symlink_overwrite(tmp_path):
    """Ensure cleanup_runtime_env_file unlinks symlinks without zeroing their target."""
    victim = tmp_path / "important.txt"
    victim.write_text("precious-content", encoding="utf-8")
    symlink_env = tmp_path / "evil.env"
    symlink_env.symlink_to(victim)

    SecretVaultManager.cleanup_runtime_env_file(symlink_env)
    assert not symlink_env.exists()
    assert victim.read_text(encoding="utf-8") == "precious-content"


def test_rename_and_delete_sandbox_secrets(tmp_path, monkeypatch):
    """Verify secret migration across sandbox rename and complete purge on sandbox delete."""
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    vault = SecretVaultManager(secrets_dir=tmp_path / "secrets", runtime_dir=tmp_path / "rt")

    vault.set_secret("krunbox-old", "OPENAI_API_KEY", "sk-111", prefer_keyring=False)
    vault.set_secret("krunbox-old", "MISTRAL_API_KEY", "ms-222", prefer_keyring=False)

    vault.rename_sandbox_secrets("krunbox-old", "krunbox-new")

    assert vault.get_secret("krunbox-old", "OPENAI_API_KEY") is None
    assert not (tmp_path / "secrets" / "krunbox-old.vault.json").exists()
    assert vault.get_secret("krunbox-new", "OPENAI_API_KEY") == "sk-111"
    assert vault.get_secret("krunbox-new", "MISTRAL_API_KEY") == "ms-222"

    vault.delete_sandbox_secrets("krunbox-new")
    assert vault.get_secret("krunbox-new", "OPENAI_API_KEY") is None
    assert not (tmp_path / "secrets" / "krunbox-new.vault.json").exists()


# =========================================================================
# 3. 1-Click IDE Launchers (krunbox.core.ide)
# =========================================================================


def test_detect_installed_ides():
    """Verify IDE binary probing across all 6 supported launcher specs."""
    assert list(IDE_SPECS.keys()) == [
        "terminal",
        "vscode",
        "cursor",
        "zed",
        "jetbrains",
        "sftp",
    ]

    def fake_which(binary: str):
        mapping = {
            "ptyxis": "/usr/bin/ptyxis",
            "codium": "/usr/bin/codium",
            "zeditor": "/usr/bin/zeditor",
            "gio": "/usr/bin/gio",
        }
        return mapping.get(binary)

    with patch("krunbox.core.ide.shutil.which", side_effect=fake_which):
        detected = detect_installed_ides()

    assert detected == {
        "terminal": "/usr/bin/ptyxis",
        "vscode": "/usr/bin/codium",
        "cursor": None,
        "zed": "/usr/bin/zeditor",
        "jetbrains": None,
        "sftp": "/usr/bin/gio",
    }


@pytest.mark.parametrize(
    "ide_key,available_bin,expected_cmd",
    [
        (
            "vscode",
            "code",
            ["code", "--remote", "ssh-remote+krunbox-web", "/workspace"],
        ),
        (
            "vscode",
            "code-insiders",
            ["code-insiders", "--remote", "ssh-remote+krunbox-web", "/workspace"],
        ),
        (
            "cursor",
            "cursor",
            ["cursor", "--remote", "ssh-remote+krunbox-web", "/workspace"],
        ),
        (
            "zed",
            "zed",
            ["zed", "ssh://krunbox-web/workspace"],
        ),
        (
            "jetbrains",
            "jetbrains-gateway",
            ["jetbrains-gateway", "ssh://vscode@127.0.0.1:2244/workspace"],
        ),
        (
            "sftp",
            "gio",
            ["gio", "open", "sftp://krunbox-web/workspace"],
        ),
        (
            "sftp",
            "nautilus",
            ["nautilus", "sftp://krunbox-web/workspace"],
        ),
    ],
)
def test_launch_ide_command_construction(ide_key, available_bin, expected_cmd):
    """Verify exact argv, start_new_session=True, and DEVNULL stdio for each IDE launcher."""
    mock_proc = MagicMock()
    mock_proc.pid = 4242

    with patch(
        "krunbox.core.ide.shutil.which",
        side_effect=lambda b: f"/usr/bin/{b}" if b == available_bin else None,
    ), patch("krunbox.core.ide.subprocess.Popen", return_value=mock_proc) as mock_popen:
        ok, msg = launch_ide(
            "krunbox-web",
            ide_key,
            remote_path="/workspace",
            ssh_port=2244,
        )

    assert ok is True
    assert "4242" in msg
    mock_popen.assert_called_once_with(
        expected_cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def test_launch_ide_terminal_delegation_and_missing_binary_message():
    """Verify 'terminal' delegates to launch_ssh_terminal and missing IDEs give manual instructions."""
    with patch(
        "krunbox.core.ide.launch_ssh_terminal",
        return_value=(True, "Launched ptyxis terminal (PID 111)"),
    ) as mock_term:
        ok, msg = launch_ide("krunbox-demo", "terminal")
        assert ok is True
        assert "PID 111" in msg
        mock_term.assert_called_once_with("krunbox-demo")

    with patch("krunbox.core.ide.shutil.which", return_value=None):
        ok, msg = launch_ide("krunbox-demo", "cursor", remote_path="/workspace")
        assert ok is False
        assert msg == (
            "Cursor is not installed on host "
            "(connect manually with: cursor --remote ssh-remote+krunbox-demo /workspace)"
        )

        ok_zed, msg_zed = launch_ide("krunbox-demo", "zed", remote_path="/workspace")
        assert ok_zed is False
        assert "zed ssh://krunbox-demo/workspace" in msg_zed


def test_launch_ide_security_injection_rejection():
    """Ensure malicious target names, paths, ports, and unknown IDE keys are rejected before Popen."""
    malicious_targets = [
        "",
        "   ",
        "-oProxyCommand=evil",
        "--remote=evil",
        "box; id",
        "box && whoami",
        "box$(reboot)",
        "box`id`",
        "box with spaces",
        "../escape",
    ]
    with patch("krunbox.core.ide.subprocess.Popen") as mock_popen:
        for bad_target in malicious_targets:
            ok, msg = launch_ide(bad_target, "vscode")
            assert ok is False
            assert "Invalid target identifier" in msg

        malicious_paths = [
            "",
            "relative/path",
            "/workspace with spaces",
            "/workspace;id",
            "/workspace\nid",
            "/workspace$(whoami)",
            "/workspace?query=1",
            "/workspace#frag",
        ]
        for bad_path in malicious_paths:
            ok, msg = launch_ide("krunbox-safe", "vscode", remote_path=bad_path)
            assert ok is False
            assert "Invalid remote workspace path" in msg

        for bad_port in [0, -1, 70000, True]:
            ok, msg = launch_ide("krunbox-safe", "jetbrains", ssh_port=bad_port)
            assert ok is False
            assert "Invalid SSH port" in msg

        ok, msg = launch_ide("krunbox-safe", "emacs-tramp")
        assert ok is False
        assert "Unsupported IDE launcher" in msg

        mock_popen.assert_not_called()
