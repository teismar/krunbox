"""
Unit tests for krunbox SandboxManager orchestrator, hardware right-sizing, and live sandbox editing.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from krunbox.core.config import DEFAULT_CPUS, DEFAULT_RAM_MIB
from krunbox.core.settings import DEFAULT_SETTINGS
from krunbox.core.manager import SandboxManager
from krunbox.core.sandbox import SandboxInfo, NetworkPolicy, PortMapping
from krunbox.core.egress_traffic import EgressTrafficManager


@pytest.fixture
def manager(tmp_path):
    state_file = tmp_path / "sandboxes.json"
    data_dir = tmp_path / "data"
    egress_logs = data_dir / "egress_logs"
    telem_dir = data_dir / "telemetry"
    ssh_dir = tmp_path / "ssh_conf"
    ssh_cfg = tmp_path / "ssh_config"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    telem_dir.mkdir(parents=True, exist_ok=True)

    with patch("krunbox.core.manager.DATA_DIR", data_dir), \
         patch("krunbox.core.telemetry.TELEMETRY_DIR", telem_dir), \
         patch("krunbox.core.ssh.SSH_CONF_DIR", ssh_dir), \
         patch("krunbox.core.ssh.SSH_CONFIG_FILE", ssh_cfg):
        mgr = SandboxManager(state_file=state_file)
        mgr.egress_traffic = EgressTrafficManager(logs_dir=egress_logs)
        mgr.telemetry.telemetry_dir = telem_dir
        yield mgr


def test_default_hardware_sizing(tmp_path, monkeypatch):
    import json
    import krunbox.core.settings as core_settings

    assert DEFAULT_CPUS == 4
    assert DEFAULT_RAM_MIB == 4096
    assert DEFAULT_SETTINGS["default_cpus"] == 4
    assert DEFAULT_SETTINGS["default_ram_mib"] == 4096

    info = SandboxInfo(
        name="krunbox-size-check",
        dir_path="/tmp",
        hostname="krunbox-size-check",
        container_name="krunbox-size-check",
        ssh_port=2222,
    )
    assert info.cpus == 4
    assert info.ram_mib == 4096

    # Verify v1 settings.json (8 CPU / 8192 MiB without schema_version) auto-migrates to 4 CPU / 4096 MiB
    legacy_file = tmp_path / "legacy_settings.json"
    legacy_file.write_text(
        json.dumps({"color_scheme": "dark", "default_cpus": 8, "default_ram_mib": 8192}),
        encoding="utf-8",
    )
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", legacy_file)
    migrated = core_settings.load_settings()
    assert migrated["default_cpus"] == 4
    assert migrated["default_ram_mib"] == 4096
    assert migrated["color_scheme"] == "dark"
    assert migrated["schema_version"] == 2

    # Verify explicit v2 user choice of 8 CPU / 8192 MiB is respected!
    v2_file = tmp_path / "v2_settings.json"
    v2_file.write_text(
        json.dumps({"schema_version": 2, "default_cpus": 8, "default_ram_mib": 8192}),
        encoding="utf-8",
    )
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", v2_file)
    v2_loaded = core_settings.load_settings()
    assert v2_loaded["default_cpus"] == 8
    assert v2_loaded["default_ram_mib"] == 8192


def test_sandbox_info_from_dict_ignores_unknown_fields():
    raw = {
        "name": "krunbox-legacy",
        "dir_path": "/workspace",
        "hostname": "krunbox-legacy",
        "container_name": "krunbox-legacy",
        "ssh_port": 2225,
        "legacy_deprecated_flag": True,
        "future_field": {"nested": 123},
    }
    box = SandboxInfo.from_dict(raw)
    assert box.name == "krunbox-legacy"
    assert box.cpus == 4
    assert box.ram_mib == 4096


def test_sanitize_name(manager):
    assert manager.sanitize_name("Corporate Service") == "krunbox-corporate-service"
    assert manager.sanitize_name("krunbox-already-prefixed") == "krunbox-already-prefixed"
    assert manager.sanitize_name("") == "krunbox-sandbox"


def test_generate_name_collision(manager, tmp_path):
    d1 = tmp_path / "backend"
    d1.mkdir()

    name1 = manager.generate_name(str(d1))
    assert name1 == "krunbox-backend"

    manager.create_sandbox(str(d1), name="krunbox-backend")
    name2 = manager.generate_name(str(d1))
    assert name2 == "krunbox-backend-2"

    manager.create_sandbox(str(d1), name="krunbox-backend-2")
    name3 = manager.generate_name(str(d1))
    assert name3 == "krunbox-backend-3"


def test_create_ephemeral_and_persistent(manager, tmp_path):
    w1 = tmp_path / "app1"
    w1.mkdir()
    w2 = tmp_path / "app2"
    w2.mkdir()

    # Ephemeral sandbox
    box1 = manager.create_sandbox(
        dir_path=str(w1),
        name="ephemeral-box",
        is_persistent=False,
        network_policy=NetworkPolicy(profile="ai-only")
    )
    assert box1.is_persistent is False
    assert box1.network_policy.profile == "ai-only"
    assert box1.cpus == 4
    assert box1.ram_mib == 4096
    assert box1.volume_prefix == "krunbox-ephemeral-box"

    # Persistent sandbox
    box2 = manager.create_sandbox(
        dir_path=str(w2),
        name="persistent-box",
        is_persistent=True,
        base_image="ghcr.io/astral-sh/uv:python3.12-bookworm-slim"
    )
    assert box2.is_persistent is True
    assert box2.base_image == "ghcr.io/astral-sh/uv:python3.12-bookworm-slim"


def test_prune_ephemeral_vs_persistent(manager, tmp_path):
    w1 = tmp_path / "app1"
    w1.mkdir()
    w2 = tmp_path / "app2"
    w2.mkdir()

    box1 = manager.create_sandbox(str(w1), name="box1", is_persistent=False)
    box1.status = "stopped"
    box2 = manager.create_sandbox(str(w2), name="box2", is_persistent=True)
    box2.status = "stopped"
    manager.save_state()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        pruned = manager.prune()
        # Only the ephemeral box should be pruned! Persistent box is preserved.
        assert pruned == 1
        assert manager.get_sandbox("krunbox-box1") is None
        assert manager.get_sandbox("krunbox-box2") is not None


def test_start_sandbox_podman_fallback_resource_flags_and_egress_mount(manager, tmp_path):
    work = tmp_path / "fallback_proj"
    work.mkdir()
    box = manager.create_sandbox(str(work), name="fallback-vm", cpus=6, ram_mib=6144)

    with patch.object(manager, "check_krun_available", return_value=False), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 AAAATEST"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="abcdef123456\n", stderr="")
        ok, _msg = manager.start_sandbox(box.name, detach=True)
        assert ok is True
        run_cmd = next(c[0][0] for c in mock_run.call_args_list if c[0][0][:2] == ["podman", "run"])
        assert "--cpus=6" in run_cmd
        assert "--memory=6144m" in run_cmd
        assert "--userns=keep-id" in run_cmd
        assert "--user" in run_cmd
        user_idx = run_cmd.index("--user")
        assert run_cmd[user_idx + 1] == "0:0"
        assert any(arg.endswith(":/run/krunbox-egress") for arg in run_cmd)
        assert any(arg.endswith(":/etc/krunbox-egress.sh:ro") for arg in run_cmd)


def test_start_sandbox_krun_mode_has_user_zero_and_keep_id(manager, tmp_path):
    work = tmp_path / "krun_proj"
    work.mkdir()
    box = manager.create_sandbox(str(work), name="krun-vm", cpus=4, ram_mib=4096)

    with patch.object(manager, "check_krun_available", return_value=True), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 AAAATEST"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="krun12345678\n", stderr="")
        ok, _msg = manager.start_sandbox(box.name, detach=True)
        assert ok is True
        run_cmd = next(c[0][0] for c in mock_run.call_args_list if c[0][0][:2] == ["podman", "run"])
        assert "--runtime=krun" in run_cmd
        assert "--userns=keep-id" in run_cmd
        assert "--user" in run_cmd
        user_idx = run_cmd.index("--user")
        assert run_cmd[user_idx + 1] == "0:0"


def test_update_sandbox_validation_errors(manager, tmp_path):
    w1 = tmp_path / "v1"
    w1.mkdir()
    manager.create_sandbox(str(w1), name="first")
    manager.create_sandbox(str(w1), name="second")

    ok, msg, _ = manager.update_sandbox("nonexistent", cpus=2)
    assert ok is False and "not found" in msg

    ok, msg, _ = manager.update_sandbox("first", cpus=0)
    assert ok is False and "CPU" in msg

    ok, msg, _ = manager.update_sandbox("first", ram_mib=256)
    assert ok is False and "RAM" in msg

    ok, msg, _ = manager.update_sandbox("first", network_policy=NetworkPolicy(profile="bogus"))
    assert ok is False and "Invalid network profile" in msg

    ok, msg, _ = manager.update_sandbox("first", new_name="second")
    assert ok is False and "already exists" in msg


def test_update_sandbox_live_network_policy(manager, tmp_path):
    work = tmp_path / "live_net"
    work.mkdir()
    box = manager.create_sandbox(str(work), name="live-net-vm")
    box.status = "running"
    manager.save_state()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        new_pol = NetworkPolicy(
            profile="ai-only",
            allowed_domains=["internal.corp.example"],
            denied_domains=["evil.example.com"],
        )
        ok, _msg, updated = manager.update_sandbox(box.name, network_policy=new_pol)
        assert ok is True
        assert updated.network_policy.profile == "ai-only"
        assert updated.network_policy.allowed_domains == ["internal.corp.example"]
        assert updated.network_policy.denied_domains == ["evil.example.com"]

        # Verify live podman exec was invoked to reload /etc/krunbox-egress.sh
        called_cmds = [c[0][0] for c in mock_run.call_args_list]
        assert ["podman", "exec", "-u", "0", "krunbox-live-net-vm", "/bin/bash", "/etc/krunbox-egress.sh"] in called_cmds

        # Verify guest policy.json was updated
        bundle_policy = manager.egress_traffic.get_sandbox_bundle_dir(box.name) / "policy.json"
        assert bundle_policy.is_file()
        assert "internal.corp.example" in bundle_policy.read_text(encoding="utf-8")


def test_update_sandbox_rename_preserves_volumes_and_migrates_logs(manager, tmp_path):
    work = tmp_path / "rename_proj"
    work.mkdir()
    box = manager.create_sandbox(str(work), name="orig-vm", is_persistent=True, persist_docker=True)
    box.status = "running"
    manager.egress_traffic.record_event("krunbox-orig-vm", "github.com", action="allowed")
    telem_file = manager.telemetry.telemetry_dir / "krunbox-orig-vm.jsonl"
    telem_file.write_text('{"provider":"OpenAI","model":"gpt-4o","total_tokens":42,"timestamp":100.0,"endpoint":"/v1"}\n')

    with patch("subprocess.run") as mock_run, \
         patch("krunbox.core.manager.remove_sandbox_ssh_config") as mock_rm_ssh, \
         patch("krunbox.core.manager.write_sandbox_ssh_config") as mock_wr_ssh:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        ok, _msg, updated = manager.update_sandbox("orig-vm", new_name="renamed-vm")
        assert ok is True
        assert updated.name == "krunbox-renamed-vm"
        assert updated.container_name == "krunbox-renamed-vm"
        assert updated.volume_prefix == "krunbox-orig-vm"
        assert manager.get_sandbox("orig-vm") is None
        assert manager.get_sandbox("renamed-vm") is updated

        called_cmds = [c[0][0] for c in mock_run.call_args_list]
        assert ["podman", "rename", "krunbox-orig-vm", "krunbox-renamed-vm"] in called_cmds
        mock_rm_ssh.assert_called_once_with("krunbox-orig-vm")
        mock_wr_ssh.assert_called_once()

    # Egress & telemetry logs migrated to new name
    assert manager.egress_traffic.get_domain_stats("krunbox-renamed-vm")["total_requests"] == 1
    assert (manager.telemetry.telemetry_dir / "krunbox-renamed-vm.jsonl").is_file()

    # Deleting with delete_volumes=True uses preserved volume_prefix
    with patch("subprocess.run") as mock_del_run, \
         patch("krunbox.core.manager.remove_sandbox_ssh_config"):
        mock_del_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        manager.delete_sandbox("renamed-vm", delete_volumes=True)
        del_cmds = [c[0][0] for c in mock_del_run.call_args_list]
        assert ["podman", "volume", "rm", "-f", "krunbox-orig-vm-gemini"] in del_cmds


def test_update_sandbox_resize_cpu_ram_commits_persistent_and_restarts(manager, tmp_path):
    work = tmp_path / "resize_proj"
    work.mkdir()
    box = manager.create_sandbox(str(work), name="persist-resize", is_persistent=True)
    box.status = "running"
    box.dynamic_tunnels.append(PortMapping(host_port=18080, guest_port=8080, is_tunnel=True, tunnel_pid=None))
    manager.save_state()

    with patch("subprocess.run") as mock_run, \
         patch.object(manager, "check_krun_available", return_value=True), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 AAAATEST"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch.object(manager, "forward_port", return_value=(True, "ok", None)) as mock_fwd:

        def _fake_run(cmd, *args, **kwargs):
            # After podman rm -f removes old container, container exists check in start_sandbox should return 1
            if cmd[:3] == ["podman", "container", "exists"]:
                # First call is before rm (exists=0), second call is inside start_sandbox after rm (exists=1)
                rm_called = any(
                    call[0][0][:3] == ["podman", "rm", "-f"]
                    for call in mock_run.call_args_list[:-1]
                )
                return MagicMock(returncode=1 if rm_called else 0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="123456abcdef\n", stderr="")

        mock_run.side_effect = _fake_run
        ok, _msg, updated = manager.update_sandbox("persist-resize", cpus=6, ram_mib=8192)
        assert ok is True
        assert updated.cpus == 6
        assert updated.ram_mib == 8192
        assert updated.committed_image == "localhost/krunbox-state-krunbox-persist-resize:latest"
        assert updated.status == "running"

        called_cmds = [c[0][0] for c in mock_run.call_args_list]
        assert [
            "podman",
            "commit",
            "krunbox-persist-resize",
            "localhost/krunbox-state-krunbox-persist-resize:latest",
        ] in called_cmds
        podman_run_cmds = [c for c in called_cmds if c[:2] == ["podman", "run"]]
        assert len(podman_run_cmds) == 1
        assert "--annotation=krun.cpus=6" in podman_run_cmds[0]
        assert "--annotation=krun.ram_mib=8192" in podman_run_cmds[0]
        assert "localhost/krunbox-state-krunbox-persist-resize:latest" in podman_run_cmds[0]
        mock_fwd.assert_called_once_with("krunbox-persist-resize", guest_port=8080, host_port=18080)


def test_get_stats_ram_normalization_and_proc_fallback(manager, tmp_path):
    work = tmp_path / "stats_ws"
    work.mkdir()
    box = manager.create_sandbox(str(work), name="stats-box", cpus=4, ram_mib=8192)
    box.status = "running"
    manager.save_state()

    # 1. Podman stats reports usage against 8192 MiB
    fake_stats_json = [
        {
            "Name": "krunbox-stats-box",
            "CPUPerc": "12.5%",
            "MemPerc": "1.0%",
            "MemUsage": "409.6MiB / 16GiB",
        }
    ]
    with patch("subprocess.run") as mock_run:
        import json
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(fake_stats_json), stderr="")
        stats = manager.get_stats()
        assert "krunbox-stats-box" in stats
        st = stats["krunbox-stats-box"]
        assert st["cpu_percent"] == 12.5
        # 409.6 MiB / 8192 MiB = 5.0%
        assert abs(st["mem_percent"] - 5.0) < 0.2
        assert "410 MiB / 8.0 GiB" in st["mem_usage"]

    # 2. When MemUsage is 0B or missing under microVMs, falls back to _probe_proc_rss_mib
    fake_stats_zero = [
        {
            "Name": "krunbox-stats-box",
            "CPUPerc": "5.0%",
            "MemPerc": "0%",
            "MemUsage": "0B / 0B",
        }
    ]
    with patch("subprocess.run") as mock_run, \
         patch.object(manager, "_probe_proc_rss_mib", return_value=819.2):
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(fake_stats_zero), stderr="")
        stats = manager.get_stats()
        st = stats["krunbox-stats-box"]
        # 819.2 MiB / 8192 MiB = 10.0%
        assert abs(st["mem_percent"] - 10.0) < 0.2
        assert "819 MiB / 8.0 GiB" in st["mem_usage"]


def test_pause_and_unpause_sandbox(manager, tmp_path):
    work = tmp_path / "pause_ws"
    work.mkdir()
    box = manager.create_sandbox(str(work), name="pause-box")
    box.status = "running"
    manager.save_state()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        ok, msg = manager.pause_sandbox(box.name)
        assert ok is True
        assert "paused" in msg
        assert manager.get_sandbox(box.name).status == "paused"
        called_cmd = mock_run.call_args[0][0]
        assert called_cmd == ["podman", "pause", "krunbox-pause-box"]

        # Pausing an already paused box is a no-op success
        ok2, _ = manager.pause_sandbox(box.name)
        assert ok2 is True

        # Unpause
        ok3, msg3 = manager.unpause_sandbox(box.name)
        assert ok3 is True
        assert "resumed" in msg3
        assert manager.get_sandbox(box.name).status == "running"
        called_cmd2 = mock_run.call_args[0][0]
        assert called_cmd2 == ["podman", "unpause", "krunbox-pause-box"]


def test_start_sandbox_git_guardrails_env_staging_and_cleanup(manager, tmp_path):
    work = tmp_path / "git_guard_ws"
    work.mkdir()
    git_dir = work / ".git"
    git_dir.mkdir()
    (git_dir / "hooks").mkdir()
    (git_dir / "config").write_text("[core]\n\trepositoryformatversion = 0\n")
    (work / ".env").write_text("SECRET=123\n")

    box = manager.create_sandbox(
        str(work),
        name="guarded-box",
        protect_git_hooks=True,
        protect_git_config=True,
        protect_env_files=True,
        host_egress_lockdown=True,
        env_vars={"APP_ENV": "production"},
        secret_keys=["MY_SECRET"],
    )
    manager.secrets.set_secret(box.name, "MY_SECRET", "super-secret-value")

    with patch.object(manager, "check_krun_available", return_value=False), \
         patch("krunbox.core.manager.ensure_host_ssh_keys", return_value=["ssh-ed25519 AAAATEST"]), \
         patch("krunbox.core.manager.write_sandbox_ssh_config"), \
         patch("krunbox.core.manager.apply_host_netns_lockdown") as mock_lockdown, \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="c1234567890\n", stderr="")

        ok, msg = manager.start_sandbox(box.name, detach=True)
        assert ok is True
        run_cmd = next(c[0][0] for c in mock_run.call_args_list if c[0][0][:2] == ["podman", "run"])

        # Verify read-only guardrails mounts
        assert any(arg.endswith("/.git/hooks:ro") for arg in run_cmd)
        assert any(arg.endswith("/.git/config:ro") for arg in run_cmd)
        assert any(arg.endswith("/.env:ro") for arg in run_cmd)

        # Verify host lockdown args and post-start lockdown call
        assert "--cap-drop=ALL" in run_cmd
        mock_lockdown.assert_called_once_with("krunbox-guarded-box", box.network_policy)

        # Verify --env-file was passed
        assert "--env-file" in run_cmd
        env_file_arg = run_cmd[run_cmd.index("--env-file") + 1]
        # Runtime env file should have been zero-wiped and unlinked in finally block!
        assert not Path(env_file_arg).exists()


def test_manager_evaluate_guardrails_auto_pause_and_stop(manager, tmp_path):
    work = tmp_path / "guard_eval_ws"
    work.mkdir()
    box1 = manager.create_sandbox(
        str(work),
        name="idle-box",
        idle_timeout_minutes=15,
        idle_action="pause",
    )
    box1.status = "running"
    manager.save_state()

    with patch.object(manager.guardrails, "evaluate") as mock_eval, \
         patch.object(manager, "pause_sandbox", return_value=(True, "paused")) as mock_pause:
        from krunbox.core.notifications import AlertEvent
        fake_alert = AlertEvent(
            id="a1",
            timestamp=100.0,
            category="idle_action",
            sandbox_name=box1.name,
            title="Idle Sandbox Paused",
            body="Sandbox idle for 15 minutes",
            severity="info",
        )
        mock_eval.return_value = ([fake_alert], [(box1.name, "pause", "idle timeout")])

        alerts, executed = manager.evaluate_guardrails()
        assert len(alerts) == 1
        assert len(executed) == 1
        assert executed[0] == (box1.name, "pause", "idle timeout")
        mock_pause.assert_called_once_with(box1.name)


def test_atomic_state_persistence_and_file_locking(tmp_path):
    import stat
    state_file = tmp_path / "sandboxes.json"
    mgr = SandboxManager(state_file=state_file)
    box = mgr.create_sandbox(str(tmp_path), name="atomic-box")
    mgr.save_state()

    assert state_file.is_file()
    file_mode = stat.S_IMODE(state_file.stat().st_mode)
    assert file_mode == 0o600

    lock_file = tmp_path / ".state.lock"
    assert lock_file.exists()

    mgr2 = SandboxManager(state_file=state_file)
    assert mgr2.get_sandbox("krunbox-atomic-box") is not None


def test_configure_guest_mcp_invokes_podman_exec(tmp_path):
    """Verify that _configure_guest_mcp properly formats and invokes podman exec with retry/fallback."""
    mgr = SandboxManager(state_file=tmp_path / "sandboxes.json")
    box = mgr.create_sandbox(str(tmp_path), name="mcp-test-box")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        mgr._configure_guest_mcp(box)

        assert mock_run.called
        args, kwargs = mock_run.call_args
        cmd = args[0]
        assert cmd[0] == "podman"
        assert cmd[1] == "exec"
        assert cmd[4] == box.container_name
        assert "krunbox-gateway" in cmd[7]
        assert "/home/vscode/.gemini/config/mcp_config.json" in cmd[7]
        assert "/workspace/.agents/mcp_config.json" in cmd[7]


