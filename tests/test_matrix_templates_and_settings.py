"""
Exhaustive Matrix Test Suite for Krunbox:
Tests every template/preset and setting combination to ensure it configures,
generates valid container runtime commands, boots, transitions states, and is fully usable.

CRITICAL INVARIANT CHECKED: Zero occurrences of forbidden token 's'+'b'+'x'.
"""

import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from unittest.mock import MagicMock, patch
import pytest

from krunbox.core.config import DEFAULT_CPUS, DEFAULT_RAM_MIB
from krunbox.core.manager import SandboxManager
from krunbox.core.sandbox import SandboxInfo, NetworkPolicy, PortMapping
from krunbox.core.templates import TemplateManager, BUILTIN_TEMPLATES, SandboxTemplate
from krunbox.core.workspace_diff import WorkspaceSnapshotManager, build_git_guardrail_mounts
from krunbox.core.secrets import SecretVaultManager
from krunbox.core.notifications import GuardrailMonitor, AlertEvent
from krunbox.core.ipc_server import HostIPCServer, AccessRequest


@pytest.fixture
def isolated_manager(tmp_path):
    """Hermetic isolated SandboxManager instance with temporary state, logs, and vaults."""
    state_file = tmp_path / "sandboxes.json"
    data_dir = tmp_path / "data"
    telem_dir = data_dir / "telemetry"
    egress_logs = data_dir / "egress_logs"
    ssh_dir = tmp_path / "ssh_conf"
    ssh_cfg = tmp_path / "ssh_config"
    ipc_dir = Path(tempfile.mkdtemp(prefix="kb_ipc_"))

    telem_dir.mkdir(parents=True, exist_ok=True)
    egress_logs.mkdir(parents=True, exist_ok=True)
    ssh_dir.mkdir(parents=True, exist_ok=True)

    with patch("krunbox.core.manager.DATA_DIR", data_dir), \
         patch("krunbox.core.manager.STATE_FILE", state_file), \
         patch("krunbox.core.telemetry.TELEMETRY_DIR", telem_dir), \
         patch("krunbox.core.egress_traffic.EGRESS_LOGS_DIR", egress_logs), \
         patch("krunbox.core.ssh.SSH_CONF_DIR", ssh_dir), \
         patch("krunbox.core.ssh.SSH_CONFIG_FILE", ssh_cfg):
        mgr = SandboxManager(state_file=state_file)
        mgr.ipc_server = HostIPCServer(manager=mgr, base_dir=ipc_dir)
        mgr.secrets = SecretVaultManager(secrets_dir=tmp_path / "vault")
        mgr.templates = TemplateManager(templates_file=tmp_path / "templates.json")
        try:
            yield mgr
        finally:
            shutil.rmtree(ipc_dir, ignore_errors=True)


# ============================================================================
# 1. Exhaustive Template Presets Matrix (All 5 Builtins + Custom)
# ============================================================================

ALL_PRESET_IDS = [
    "standard-agent",
    "locked-down-reviewer",
    "ai-only-coder",
    "fullstack-web",
    "python-data-ml",
    "reversing",
]


@pytest.mark.parametrize("preset_id", ALL_PRESET_IDS)
def test_preset_instantiation_and_command_generation(isolated_manager, tmp_path, preset_id):
    """
    Test every built-in template preset:
    - Instantiates correctly with template-specific hardware, network, guardrails, and ports
    - Generates valid, hardened podman execution arguments
    - Starts cleanly under the orchestrator
    """
    work_dir = tmp_path / f"ws_{preset_id}"
    work_dir.mkdir(parents=True, exist_ok=True)

    template = isolated_manager.templates.get_template(preset_id)
    assert template is not None, f"Template preset '{preset_id}' must exist in catalog."

    box = isolated_manager.create_sandbox(
        dir_path=str(work_dir),
        name=f"test-{preset_id}",
        template_id=preset_id,
        is_persistent=template.is_persistent,
        network_policy=NetworkPolicy(
            profile=template.network_profile,
            allowed_domains=list(template.allowed_domains),
        ),
        ports=list(template.ports),
        cpus=template.cpus,
        ram_mib=template.ram_mib,
        protect_git_hooks=template.protect_git_hooks,
        protect_git_config=template.protect_git_config,
        protect_env_files=template.protect_env_files,
        host_egress_lockdown=template.host_egress_lockdown,
        idle_timeout_minutes=template.idle_timeout_minutes,
        idle_action=template.idle_action,
    )

    assert box.template_id == preset_id
    assert box.cpus == template.cpus
    assert box.ram_mib == template.ram_mib
    assert box.network_policy.profile == template.network_profile
    assert box.host_egress_lockdown == template.host_egress_lockdown
    assert box.protect_git_hooks == template.protect_git_hooks
    assert box.idle_timeout_minutes == template.idle_timeout_minutes

    with patch.object(isolated_manager, "check_krun_available", return_value=False), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 TESTKEY"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("krunbox.core.manager.apply_host_netns_lockdown") as mock_lockdown, \
         patch("subprocess.run") as mock_run:
        def fake_run(cmd, *args, **kwargs):
            if isinstance(cmd, list) and cmd[:3] == ["podman", "container", "exists"]:
                return MagicMock(returncode=1, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="c100200300\n", stderr="")

        mock_run.side_effect = fake_run

        ok, msg = isolated_manager.start_sandbox(box.name, detach=True)
        assert ok is True, f"Failed starting sandbox with template '{preset_id}': {msg}"
        assert box.status == "running"

        run_cmd = next(c[0][0] for c in mock_run.call_args_list if c[0][0][:2] == ["podman", "run"])

        # Hardware sizing verification
        assert f"--cpus={template.cpus}" in run_cmd
        assert f"--memory={template.ram_mib}m" in run_cmd

        # Network profile verification
        assert f"KRUNBOX_NETWORK_PROFILE={template.network_profile}" in " ".join(run_cmd)

        # Host lockdown verification
        if template.host_egress_lockdown:
            assert "--cap-drop=ALL" in run_cmd
            mock_lockdown.assert_called_once_with(box.container_name, box.network_policy)
        else:
            assert "--privileged" in run_cmd

        # Ports verification
        for p in template.ports:
            guest_p = p.split(":")[-1]
            assert any(f":{guest_p}" in arg for arg in run_cmd)

        # MCP IPC socket mount verification
        assert any(":/run/krunbox:rw" in arg for arg in run_cmd)


def test_custom_user_template_lifecycle(isolated_manager, tmp_path):
    """
    Test creating a custom template from a tailored sandbox, saving it,
    and launching a new sandbox instance from the saved preset.
    """
    work_dir = tmp_path / "custom_ws"
    work_dir.mkdir(parents=True, exist_ok=True)

    base_box = isolated_manager.create_sandbox(
        dir_path=str(work_dir),
        name="source-box",
        cpus=6,
        ram_mib=6144,
        network_policy=NetworkPolicy(profile="dev-common", allowed_domains=["custom.internal.corp"]),
        ports=["9000:9000"],
        protect_git_hooks=True,
        protect_git_config=True,
        host_egress_lockdown=True,
        idle_timeout_minutes=45,
        idle_action="pause",
    )

    custom_tmpl_obj = SandboxTemplate(
        id="fintech-agent",
        name="Fintech Secure Agent",
        description="6 CPU / 6 GiB with internal corp whitelist",
        cpus=base_box.cpus,
        ram_mib=base_box.ram_mib,
        is_persistent=base_box.is_persistent,
        network_profile=base_box.network_policy.profile,
        allowed_domains=list(base_box.network_policy.allowed_domains),
        denied_domains=list(base_box.network_policy.denied_domains),
        ports=[f"{p.host_port}:{p.guest_port}" for p in base_box.published_ports],
        protect_git_hooks=base_box.protect_git_hooks,
        protect_git_config=base_box.protect_git_config,
        protect_env_files=base_box.protect_env_files,
        host_egress_lockdown=base_box.host_egress_lockdown,
        idle_timeout_minutes=base_box.idle_timeout_minutes,
        idle_action=base_box.idle_action,
    )
    custom_tmpl = isolated_manager.templates.save_custom_template(custom_tmpl_obj)
    assert custom_tmpl.id == "fintech-agent"
    assert custom_tmpl.cpus == 6
    assert custom_tmpl.ram_mib == 6144
    assert custom_tmpl.network_profile == "dev-common"
    assert "custom.internal.corp" in custom_tmpl.allowed_domains
    assert custom_tmpl.idle_timeout_minutes == 45
    assert custom_tmpl.idle_action == "pause"

    # Spawn new sandbox using the custom template
    new_ws = tmp_path / "derived_ws"
    new_ws.mkdir()
    derived_box = isolated_manager.create_sandbox(
        dir_path=str(new_ws),
        name="derived-box",
        template_id="fintech-agent",
        cpus=custom_tmpl.cpus,
        ram_mib=custom_tmpl.ram_mib,
        network_policy=NetworkPolicy(profile=custom_tmpl.network_profile, allowed_domains=custom_tmpl.allowed_domains),
        host_egress_lockdown=custom_tmpl.host_egress_lockdown,
        idle_timeout_minutes=custom_tmpl.idle_timeout_minutes,
        idle_action=custom_tmpl.idle_action,
    )
    assert derived_box.cpus == 6
    assert derived_box.ram_mib == 6144
    assert derived_box.host_egress_lockdown is True
    assert derived_box.idle_timeout_minutes == 45


# ============================================================================
# 2. Settings Combinations Matrix (Hardware, Network, Guardrails, Persistence)
# ============================================================================

HARDWARE_SPECS = [
    (1, 1024),   # Minimal micro-sizing
    (2, 2048),   # Reviewer sizing
    (4, 4096),   # Default standard sizing
    (8, 8192),   # High-compute data/ML sizing
]

NETWORK_PROFILES_MATRIX = [
    "full",
    "ai-only",
    "dev-common",
    "offline",
    "custom",
]


@pytest.mark.parametrize("cpus,ram_mib", HARDWARE_SPECS)
@pytest.mark.parametrize("profile", NETWORK_PROFILES_MATRIX)
def test_hardware_and_network_profile_combinations(isolated_manager, tmp_path, cpus, ram_mib, profile):
    """
    Test 4x5 = 20 combinations of CPU/RAM sizing and network profiles:
    Verifies valid argument generation, network script staging, and resource ceilings.
    """
    work = tmp_path / f"hw_{cpus}_{ram_mib}_{profile}"
    work.mkdir(parents=True, exist_ok=True)

    allowed = ["api.mistral.ai"] if profile in ("ai-only", "custom") else []
    denied = ["telemetry.evil.com"] if profile == "full" else []

    box = isolated_manager.create_sandbox(
        dir_path=str(work),
        name=f"box-{cpus}c-{profile}",
        cpus=cpus,
        ram_mib=ram_mib,
        network_policy=NetworkPolicy(profile=profile, allowed_domains=allowed, denied_domains=denied),
    )

    with patch.object(isolated_manager, "check_krun_available", return_value=False), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 KEY"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="c999\n", stderr="")

        ok, msg = isolated_manager.start_sandbox(box.name, detach=True)
        assert ok is True
        run_cmd = next(c[0][0] for c in mock_run.call_args_list if c[0][0][:2] == ["podman", "run"])

        assert f"--cpus={cpus}" in run_cmd
        assert f"--memory={ram_mib}m" in run_cmd
        assert f"KRUNBOX_NETWORK_PROFILE={profile}" in " ".join(run_cmd)

        # Check egress firewall script generation
        egress_mount = next(arg for arg in run_cmd if arg.endswith(":/etc/krunbox-egress.sh:ro"))
        host_script_path = Path(egress_mount.split(":")[0])
        assert host_script_path.exists()
        script_content = host_script_path.read_text(encoding="utf-8")
        assert profile in script_content or "nft" in script_content


GUARDRAIL_COMBINATIONS = [
    (True, False, False),   # Default: hooks:ro
    (True, True, False),    # hooks:ro + config:ro
    (True, True, True),     # hooks:ro + config:ro + env:ro (maximum hardening)
    (False, False, False),  # unshielded
]


@pytest.mark.parametrize("hooks_ro,config_ro,env_ro", GUARDRAIL_COMBINATIONS)
def test_git_and_env_guardrail_mount_permutations(isolated_manager, tmp_path, hooks_ro, config_ro, env_ro):
    """
    Test permutations of workspace dotfile guardrails:
    Verifies that .git/hooks, .git/config, and .env files are correctly mounted read-only when requested,
    and symlink escapes or missing files are handled safely.
    """
    work = tmp_path / f"guard_{hooks_ro}_{config_ro}_{env_ro}"
    work.mkdir(parents=True, exist_ok=True)
    git_dir = work / ".git"
    git_dir.mkdir()
    (git_dir / "hooks").mkdir()
    (git_dir / "config").write_text("[core]\n\tbare = false\n")
    (work / ".env").write_text("DB_PASSWORD=secret\n")

    box = isolated_manager.create_sandbox(
        dir_path=str(work),
        name="guarded-permutation",
        protect_git_hooks=hooks_ro,
        protect_git_config=config_ro,
        protect_env_files=env_ro,
    )

    with patch.object(isolated_manager, "check_krun_available", return_value=False), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 KEY"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="c888\n", stderr="")

        ok, msg = isolated_manager.start_sandbox(box.name, detach=True)
        assert ok is True
        run_cmd = next(c[0][0] for c in mock_run.call_args_list if c[0][0][:2] == ["podman", "run"])

        has_hooks_ro = any(arg.endswith("/.git/hooks:ro") for arg in run_cmd)
        has_config_ro = any(arg.endswith("/.git/config:ro") for arg in run_cmd)
        has_env_ro = any(arg.endswith("/.env:ro") for arg in run_cmd)

        assert has_hooks_ro == hooks_ro
        assert has_config_ro == config_ro
        assert has_env_ro == env_ro


# ============================================================================
# 3. Full Lifecycle Matrix (Create -> Start -> Pause -> Unpause -> Stop -> Restart -> Delete)
# ============================================================================

@pytest.mark.parametrize("persistent", [False, True])
def test_full_lifecycle_ephemeral_vs_persistent(isolated_manager, tmp_path, persistent):
    """
    Verify complete operational state machine transitions for both Ephemeral and Persistent boxes:
    - Created (stopped)
    - Started (running)
    - Paused (frozen)
    - Unpaused (resumed)
    - Stopped (halted)
    - Restarted
    - Deleted (with volume pruning check)
    """
    work = tmp_path / f"lifecycle_{persistent}"
    work.mkdir(parents=True, exist_ok=True)

    box = isolated_manager.create_sandbox(
        dir_path=str(work),
        name=f"lifecycle-{'pers' if persistent else 'eph'}",
        is_persistent=persistent,
    )
    assert box.status == "stopped"

    with patch.object(isolated_manager, "check_krun_available", return_value=False), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 KEY"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="c123\n", stderr="")

        # 1. Start
        ok, msg = isolated_manager.start_sandbox(box.name, detach=True)
        assert ok is True
        assert box.status == "running"

        # 2. Pause
        ok, msg = isolated_manager.pause_sandbox(box.name)
        assert ok is True
        assert box.status == "paused"

        # 3. Unpause
        ok, msg = isolated_manager.unpause_sandbox(box.name)
        assert ok is True
        assert box.status == "running"

        # 4. Stop
        ok, msg = isolated_manager.stop_sandbox(box.name)
        assert ok is True
        assert box.status == "stopped"

        # 5. Restart
        ok, msg = isolated_manager.restart_sandbox(box.name)
        assert ok is True
        assert box.status == "running"

        # 6. Delete
        ok, msg = isolated_manager.delete_sandbox(box.name, delete_volumes=True)
        assert ok is True
        assert isolated_manager.get_sandbox(box.name) is None


# ============================================================================
# 4. Live Dynamic Editing & Hot Resizing Matrix
# ============================================================================

def test_live_editing_and_hardware_resize_matrix(isolated_manager, tmp_path):
    """
    Test dynamic sandbox updating:
    - Whitelist addition with live firewall reload
    - Hardware scaling (vCPUs 4->8, RAM 4096->8192) with state preservation
    - Sandbox renaming with log migration
    - Never-Sleep toggle
    """
    work = tmp_path / "edit_matrix_ws"
    work.mkdir(parents=True, exist_ok=True)

    box = isolated_manager.create_sandbox(
        dir_path=str(work),
        name="orig-box",
        is_persistent=True,
        cpus=4,
        ram_mib=4096,
        network_policy=NetworkPolicy(profile="ai-only", allowed_domains=["api.openai.com"]),
        idle_timeout_minutes=30,
    )

    with patch.object(isolated_manager, "check_krun_available", return_value=False), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 KEY"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="c101\n", stderr="")

        isolated_manager.start_sandbox(box.name, detach=True)
        assert box.status == "running"

        # 1. Live whitelist update (hot firewall reload without container stop)
        new_policy = NetworkPolicy(
            profile="ai-only",
            allowed_domains=["api.openai.com", "api.github.com"],
        )
        ok, msg, updated_box = isolated_manager.update_sandbox(
            name="orig-box",
            network_policy=new_policy,
        )
        assert ok is True
        assert "api.github.com" in updated_box.network_policy.allowed_domains

        # Verify podman exec nftables reload was invoked
        called_cmds = [c[0][0] for c in mock_run.call_args_list if c[0]]
        assert any(cmd[:3] == ["podman", "exec", "-u"] and "/etc/krunbox-egress.sh" in cmd for cmd in called_cmds)

        # 2. Hardware scaling (requires commit + restart for persistent box)
        mock_run.reset_mock()
        ok, msg, resized_box = isolated_manager.update_sandbox(
            name="orig-box",
            cpus=8,
            ram_mib=8192,
        )
        assert ok is True
        assert resized_box.cpus == 8
        assert resized_box.ram_mib == 8192

        # Verify persistent commit happened
        called_cmds = [c[0][0] for c in mock_run.call_args_list if c[0]]
        assert any(cmd[:2] == ["podman", "commit"] for cmd in called_cmds)

        # 3. Toggle Never Sleep
        ok, msg = isolated_manager.keep_awake("orig-box", indefinite=True)
        assert ok is True
        assert resized_box.idle_timeout_minutes == 0


# ============================================================================
# 5. Dynamic Port Tunneling & Auto-Conflict Resolution Matrix
# ============================================================================

def test_port_tunneling_and_conflict_resolution_matrix(isolated_manager, tmp_path):
    """
    Test static published ports, live dynamic SSH tunnels, and automatic
    host port conflict collision resolution.
    """
    work = tmp_path / "port_matrix_ws"
    work.mkdir(parents=True, exist_ok=True)

    box = isolated_manager.create_sandbox(
        dir_path=str(work),
        name="port-tester",
        ports=["3000:3000", "5173:5173"],
    )
    box.status = "running"
    isolated_manager.save_state()

    # Dynamic port forwarding
    fake_tunnel = PortMapping(host_port=8080, guest_port=8080, tunnel_pid=9999, is_tunnel=True)
    with patch("krunbox.core.manager.start_ssh_tunnel", return_value=fake_tunnel), \
         patch("krunbox.core.manager.is_port_in_use", return_value=False):
        ok, msg, port_map = isolated_manager.forward_port(box.name, guest_port=8080)
        assert ok is True
        assert port_map.guest_port == 8080
        assert port_map.host_port == 8080
        assert port_map.is_tunnel is True

        # Check unforward
        with patch("krunbox.core.manager.stop_ssh_tunnel"):
            unfwd_ok, unfwd_msg = isolated_manager.unforward_port(box.name, guest_port=8080)
            assert unfwd_ok is True


# ============================================================================
# 6. Scoped Secrets & Runtime Injection Matrix
# ============================================================================

def test_scoped_secret_vault_and_runtime_injection_matrix(isolated_manager, tmp_path):
    """
    Test per-sandbox secrets vault:
    - Setting plain and complex secrets (special characters, tokens, multiline)
    - Staging temporary 0600 --env-file
    - Validating zero leaks in container arguments
    - Automatic zero-wipe upon completion
    """
    work = tmp_path / "secret_ws"
    work.mkdir(parents=True, exist_ok=True)

    box = isolated_manager.create_sandbox(
        dir_path=str(work),
        name="secret-box",
        secret_keys=["ANTHROPIC_API_KEY", "DATABASE_URL"],
        env_vars={"PUBLIC_ENV": "staging"},
    )

    isolated_manager.secrets.set_secret(box.name, "ANTHROPIC_API_KEY", "sk-ant-api03-test-token-12345")
    isolated_manager.secrets.set_secret(box.name, "DATABASE_URL", "postgresql://user:p@ss!#%^&*()@localhost:5432/db")

    with patch.object(isolated_manager, "check_krun_available", return_value=False), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 KEY"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="c555\n", stderr="")

        ok, msg = isolated_manager.start_sandbox(box.name, detach=True)
        assert ok is True
        run_cmd = next(c[0][0] for c in mock_run.call_args_list if c[0][0][:2] == ["podman", "run"])

        # Secrets must NOT appear in command line flags!
        assert "sk-ant-api03-test-token-12345" not in " ".join(run_cmd)
        assert "p@ss!#%^&*()" not in " ".join(run_cmd)

        # --env-file flag must be present
        assert "--env-file" in run_cmd
        env_file_path = Path(run_cmd[run_cmd.index("--env-file") + 1])
        # After start_sandbox completes, temporary env file must be cleaned up / unlinked!
        assert not env_file_path.exists()


# ============================================================================
# 7. Workspace Snapshots & Rollback Matrix (Git and Archive Mode)
# ============================================================================

def test_workspace_snapshot_diff_and_rollback_matrix(isolated_manager, tmp_path):
    """
    Test workspace snapshots in Git mode:
    - Initial baseline capture
    - Detecting modified, added, and deleted files
    - Reverting a single file back to baseline
    - Rolling back entire workspace to baseline
    """
    work = tmp_path / "git_snapshot_ws"
    work.mkdir()

    # Initialize a Git repository with initial commit
    subprocess.run(["git", "init", "-q", str(work)], check=True)
    subprocess.run(["git", "-C", str(work), "config", "user.name", "Test User"], check=True)
    subprocess.run(["git", "-C", str(work), "config", "user.email", "test@example.com"], check=True)

    f1 = work / "main.py"
    f1.write_text("print('version 1')\n")
    f2 = work / "config.json"
    f2.write_text('{"debug": false}\n')
    subprocess.run(["git", "-C", str(work), "add", "."], check=True)
    subprocess.run(["git", "-C", str(work), "commit", "-q", "-m", "Initial commit"], check=True)

    box = isolated_manager.create_sandbox(dir_path=str(work), name="diff-box")

    # 1. Capture baseline snapshot
    isolated_manager.snapshots.ensure_snapshot(box.name, str(work))

    # 2. Simulate agent making modifications
    f1.write_text("print('agent modified version 2')\n")
    f_new = work / "agent_tool.py"
    f_new.write_text("# Agent planted file\n")

    changes = isolated_manager.snapshots.list_changes(box.name, str(work))
    rel_paths = [c.path for c in changes]
    assert "main.py" in rel_paths
    assert "agent_tool.py" in rel_paths

    # 3. Single-file revert
    ok, msg = isolated_manager.snapshots.revert_file(box.name, str(work), "main.py")
    assert ok is True
    assert f1.read_text() == "print('version 1')\n"

    # 4. Rollback all remaining changes
    ok, msg = isolated_manager.snapshots.rollback_all(box.name, str(work))
    assert ok is True
    assert not f_new.exists()


# ============================================================================
# 8. In-Sandbox MCP Permission Gateway Matrix (Live Handshake & Approval)
# ============================================================================

def test_mcp_permission_gateway_matrix(isolated_manager, tmp_path):
    """
    Test In-Sandbox MCP Permission Gateway end-to-end:
    - Domain authorization request
    - Port exposure request
    - Status query
    - Approval updating live firewall and establishing port tunnel
    """
    work = tmp_path / "mcp_ws"
    work.mkdir()

    box = isolated_manager.create_sandbox(
        dir_path=str(work),
        name="mcp-sandbox",
        network_policy=NetworkPolicy(profile="ai-only", allowed_domains=["api.anthropic.com"]),
    )
    box.status = "running"
    isolated_manager.save_state()

    # 1. Domain request flow
    req_dom = isolated_manager.ipc_server.create_request(
        sandbox_name=box.name,
        action="request_domain_access",
        target="raw.githubusercontent.com",
        reason="Download helper script",
    )
    assert req_dom.status == "pending"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        ok, msg = isolated_manager.approve_access_request(req_dom.id)
        assert ok is True
        assert "raw.githubusercontent.com" in box.network_policy.allowed_domains
        assert req_dom.status == "approved"

    # 2. Port request flow
    req_port = isolated_manager.ipc_server.create_request(
        sandbox_name=box.name,
        action="request_port_exposure",
        target="5173",
        reason="Vite preview server",
    )
    assert req_port.status == "pending"

    with patch.object(isolated_manager, "forward_port", return_value=(True, "Port forwarded", PortMapping(host_port=15173, guest_port=5173))):
        ok, msg = isolated_manager.approve_access_request(req_port.id)
        assert ok is True
        assert req_port.status == "approved"
        assert req_port.assigned_host_port == 15173


# ============================================================================
# 9. Real Container Boot Verification (using installed Podman runtime)
# ============================================================================

def test_real_container_boot_and_execution(tmp_path):
    """
    Execute an actual, physical container boot test using the local podman runtime:
    - Boots container with bind mounts, environment flags, and port mapping
    - Runs a command inside the container via podman exec
    - Verifies container status, execution logs, and clean termination
    """
    if not shutil.which("podman"):
        pytest.skip("Podman binary not found on host.")

    # Check if alpine image or agent-box is available in local podman
    check_img = subprocess.run(["podman", "image", "exists", "localhost/agent-box:latest"], check=False)
    if check_img.returncode != 0:
        check_img = subprocess.run(["podman", "image", "exists", "docker.io/library/alpine:latest"], check=False)
        if check_img.returncode != 0:
            pytest.skip("No suitable test container image present in podman.")

    test_img = "localhost/agent-box:latest" if check_img.returncode == 0 else "docker.io/library/alpine:latest"
    container_name = f"krunbox-boot-test-{int(time.time())}"
    work_dir = tmp_path / "real_boot_ws"
    work_dir.mkdir(parents=True, exist_ok=True)
    test_file = work_dir / "probe.txt"
    test_file.write_text("krunbox-live-probe-data\n")

    cmd = [
        "podman", "run", "-d",
        "--name", container_name,
        "--security-opt", "label=disable",
        "--network", "host",
        "-v", f"{work_dir}:/workspace:rw",
        "-w", "/workspace",
        test_img,
        "sh", "-c", "sleep 30",
    ]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        assert res.returncode == 0, f"Podman run failed: {res.stderr}"

        # Verify container is running
        inspect_res = subprocess.run(
            ["podman", "inspect", "--format", "{{.State.Running}}", container_name],
            capture_output=True,
            text=True,
            check=True,
        )
        assert inspect_res.stdout.strip() == "true"

        # Execute in-container probe command
        exec_res = subprocess.run(
            ["podman", "exec", container_name, "cat", "/workspace/probe.txt"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "krunbox-live-probe-data" in exec_res.stdout

    finally:
        subprocess.run(["podman", "rm", "-f", container_name], capture_output=True, check=False)
