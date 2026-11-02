"""
Central Sandbox Orchestrator for krunbox using Podman and microVM isolation.
"""

import fcntl
import json
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

from .config import (
    STATE_FILE,
    DATA_DIR,
    TELEMETRY_DIR,
    DEFAULT_RAM_MIB,
    DEFAULT_CPUS,
    DEFAULT_SSH_PORT,
    BUILTIN_IMAGES,
)
from .sandbox import SandboxInfo, PortMapping, NetworkPolicy
from .ports import is_port_in_use, find_free_port, parse_port_spec, start_ssh_tunnel, stop_ssh_tunnel
from .ssh import ensure_host_ssh_keys, write_sandbox_ssh_config, remove_sandbox_ssh_config
from .network import (
    VALID_PROFILES,
    is_safe_domain_or_ip,
    get_denied_domains,
    generate_egress_firewall_script,
    write_guest_egress_bundle,
)
from .telemetry import TelemetryManager
from .egress_traffic import EgressTrafficManager
from .workspace_diff import WorkspaceSnapshotManager, build_git_guardrail_mounts
from .secrets import SecretVaultManager, is_valid_env_key, sanitize_env_value
from .templates import TemplateManager
from .images import ImageManager
from .host_egress import (
    build_host_lockdown_podman_args,
    get_fallback_capability_args,
    apply_host_netns_lockdown,
)
from .notifications import AlertEvent, GuardrailMonitor
from .ipc_server import HostIPCServer, AccessRequest
from .settings import load_settings

_MEM_SIZE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgt]i?b|b)?\s*$", re.IGNORECASE)


def is_uv_cli_image(image_tag: str) -> bool:
    """Detect if the image tag corresponds to Astral uv CLI base image (default bare 'uv' command)."""
    tag = (image_tag or "").lower().strip()
    return (
        tag == "python-data"
        or "astral-sh/uv" in tag
        or "ghcr.io/astral-sh/uv" in tag
        or tag.endswith("/uv")
        or tag == "uv"
        or (":uv" in tag)
    )


def build_uv_boot_script() -> str:
    """Build detached microVM initialization script for uv/python base images providing OpenSSH and keepalive."""
    return (
        "if ! command -v sshd >/dev/null 2>&1; then\n"
        "  echo '[krunbox] Provisioning OpenSSH server for microVM access...'\n"
        "  if command -v apt-get >/dev/null 2>&1; then\n"
        "    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true\n"
        "    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends openssh-server >/dev/null 2>&1 || true\n"
        "  fi\n"
        "fi\n"
        "if command -v sshd >/dev/null 2>&1; then\n"
        "  mkdir -p /var/run/sshd\n"
        "  if ! id vscode >/dev/null 2>&1; then\n"
        "    useradd -m -s /bin/bash vscode 2>/dev/null || true\n"
        "  fi\n"
        "  USER_SSH_DIR=/home/vscode/.ssh\n"
        "  mkdir -p \"$USER_SSH_DIR\"\n"
        "  if [ -n \"$SSH_AUTH_KEYS\" ]; then\n"
        "    echo \"$SSH_AUTH_KEYS\" > \"$USER_SSH_DIR/authorized_keys\"\n"
        "    chmod 600 \"$USER_SSH_DIR/authorized_keys\" 2>/dev/null || true\n"
        "  fi\n"
        "  chmod 700 \"$USER_SSH_DIR\" 2>/dev/null || true\n"
        "  chown -R vscode:vscode \"$USER_SSH_DIR\" 2>/dev/null || true\n"
        "  ssh-keygen -A >/dev/null 2>&1 || true\n"
        "  if command -v sudo >/dev/null 2>&1; then\n"
        "    echo 'vscode ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/99-vscode 2>/dev/null || true\n"
        "    chmod 0440 /etc/sudoers.d/99-vscode 2>/dev/null || true\n"
        "  fi\n"
        "  if ! grep -q 'SSH_CONNECTION.*workspace' /home/vscode/.bashrc 2>/dev/null; then\n"
        "    printf '\\nif [ -n \"$SSH_CONNECTION\" ] && [ \"$PWD\" = \"$HOME\" ] && [ -d /workspace ]; then\\n    cd /workspace\\nfi\\n' >> /home/vscode/.bashrc 2>/dev/null || true\n"
        "  fi\n"
        "  /usr/sbin/sshd -p 2222\n"
        "fi\n"
        "echo '[krunbox] Sandbox ready (Python 3.12, uv)'\n"
        "trap 'exit 0' TERM INT\n"
        "while :; do sleep 1 & wait $!; done\n"
    )


def parse_mem_size_mib(raw: str) -> Optional[float]:
    """Parse a byte/memory token like '512MiB', '1.25GiB', '160MB', or '1048576B' into MiB."""
    if not raw or not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    if not cleaned or cleaned in ("--", "N/A"):
        return None
    m = _MEM_SIZE_RE.match(cleaned)
    if not m:
        return None
    val = float(m.group(1))
    unit = (m.group(2) or "b").lower()
    if unit == "b":
        return val / (1024.0 * 1024.0)
    if unit in ("kb", "kib"):
        return val / 1024.0
    if unit in ("mb", "mib"):
        return val
    if unit in ("gb", "gib"):
        return val * 1024.0
    if unit in ("tb", "tib"):
        return val * 1024.0 * 1024.0
    return None


def format_mem_mib(mib: float) -> str:
    """Format MiB into a concise human-readable unit ('512 MiB' or '1.4 GiB')."""
    if mib >= 1024.0:
        return f"{mib / 1024.0:.1f} GiB"
    return f"{mib:.0f} MiB"


class SandboxManager:
    def __init__(self, state_file: Optional[Path] = None):
        self.state_file = state_file if state_file is not None else STATE_FILE
        self.telemetry = TelemetryManager()
        self.egress_traffic = EgressTrafficManager()
        self.snapshots = WorkspaceSnapshotManager()
        self.secrets = SecretVaultManager()
        self.templates = TemplateManager()
        self.images = ImageManager()
        self.guardrails = GuardrailMonitor()
        self.ipc_server = HostIPCServer(manager=self)
        self._sandboxes: Dict[str, SandboxInfo] = {}
        self.load_state()

    @property
    def sandboxes(self) -> Dict[str, SandboxInfo]:
        return self._sandboxes

    @property
    def snapshot_mgr(self) -> WorkspaceSnapshotManager:
        return self.snapshots

    def load_state(self) -> None:
        """Load sandbox definitions from disk with explicit file locking."""
        if not self.state_file.exists():
            self._sandboxes = {}
            return
        lock_file = self.state_file.parent / ".state.lock"
        lock_fd = None
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            lock_fd = open(lock_file, "a", encoding="utf-8")
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
            if not self.state_file.exists():
                self._sandboxes = {}
                return
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self._sandboxes = {
                    name: SandboxInfo.from_dict(info)
                    for name, info in data.items()
                }
        except Exception:
            self._sandboxes = {}
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
                    lock_fd.close()
                except Exception:
                    pass

    def save_state(self) -> None:
        """Persist registered sandboxes to disk atomically with explicit file locking and 0600 permissions."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        lock_file = self.state_file.parent / ".state.lock"
        tmp_file = self.state_file.parent / f"{self.state_file.name}.tmp.{os.getpid()}"
        lock_fd = None
        try:
            lock_fd = open(lock_file, "a", encoding="utf-8")
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)

            data = {name: box.to_dict() for name, box in self._sandboxes.items()}
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            try:
                os.chmod(tmp_file, 0o600)
            except Exception:
                pass

            os.replace(tmp_file, self.state_file)

            try:
                os.chmod(self.state_file, 0o600)
            except Exception:
                pass
        except Exception as e:
            print(f"[krunbox] Warning: Failed to save state: {e}")
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except Exception:
                    pass
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
                    lock_fd.close()
                except Exception:
                    pass

    def sanitize_name(self, name: str) -> str:
        """Sanitize name to lowercase alphanumeric with krunbox- prefix."""
        cleaned = re.sub(r"[^a-zA-Z0-9_-]", "-", name).strip("-").lower()
        if not cleaned:
            cleaned = "sandbox"
        if not cleaned.startswith("krunbox-"):
            cleaned = f"krunbox-{cleaned}"
        return cleaned

    def generate_name(self, dir_path: str, user_name: Optional[str] = None) -> str:
        """Generate a unique, collision-free sandbox identifier."""
        if user_name:
            base_name = self.sanitize_name(user_name)
        else:
            p = Path(dir_path).resolve()
            dir_name = p.name if p.name else "root"
            base_name = self.sanitize_name(dir_name)

        candidate = base_name
        counter = 2
        existing_names = set(self._sandboxes.keys())
        while candidate in existing_names:
            candidate = f"{base_name}-{counter}"
            counter += 1
        return candidate

    def check_krun_available(self) -> bool:
        """Check if crun-krun and passt are available on the host."""
        has_krun = shutil.which("krun") is not None
        has_passt = shutil.which("passt") is not None
        return has_krun and has_passt

    def list_sandboxes(self, refresh_podman: bool = True) -> List[SandboxInfo]:
        """List all sandboxes, synchronizing status with podman."""
        if refresh_podman:
            self._sync_with_podman()
        return sorted(self._sandboxes.values(), key=lambda s: s.name)

    def get_sandbox(self, name: str) -> Optional[SandboxInfo]:
        """Find sandbox by name or alias."""
        clean = self.sanitize_name(name)
        if clean in self._sandboxes:
            return self._sandboxes[clean]
        if name in self._sandboxes:
            return self._sandboxes[name]
        for sname, box in self._sandboxes.items():
            if sname.endswith(f"-{name}") or sname == f"krunbox-{name}":
                return box
        return None

    def get_sandbox_for_dir(self, dir_path: str) -> Optional[SandboxInfo]:
        """Find sandbox registered for a given directory path."""
        resolved = str(Path(dir_path).resolve())
        for box in self._sandboxes.values():
            if str(Path(box.dir_path).resolve()) == resolved:
                return box
        return None

    def _sync_with_podman(self) -> None:
        """Query podman for container states."""
        try:
            cmd = ["podman", "ps", "-a", "--filter", "label=krunbox=true", "--format", "json"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode != 0:
                return
            containers = json.loads(res.stdout) if res.stdout.strip() else []

            podman_by_name = {}
            for c in containers:
                c_names = c.get("Names") or []
                c_id = c.get("Id", "")[:12]
                c_state = c.get("State", "stopped").lower()
                labels = c.get("Labels") or {}
                lbl_port = labels.get("krunbox.ssh_port")
                port_val = int(lbl_port) if lbl_port and lbl_port.isdigit() else None
                for n in c_names:
                    clean_n = n.lstrip("/")
                    podman_by_name[clean_n] = (c_id, c_state, port_val)

                # Auto-discover unmanaged containers with krunbox labels
                krunbox_name = labels.get("krunbox.name") or (c_names[0].lstrip("/") if c_names else None)
                c_dir = labels.get("krunbox.dir")
                if krunbox_name and krunbox_name not in self._sandboxes and c_dir:
                    discovered_box = SandboxInfo(
                        name=krunbox_name,
                        dir_path=c_dir,
                        hostname=krunbox_name,
                        container_name=krunbox_name,
                        ssh_port=port_val or DEFAULT_SSH_PORT,
                        container_id=c_id,
                        status="running" if c_state in ("running", "up") else c_state,
                        is_persistent=(labels.get("krunbox.persistent") == "True"),
                        network_policy=NetworkPolicy(profile=labels.get("krunbox.network_profile", "full")),
                        volume_prefix=krunbox_name,
                    )
                    self._sandboxes[krunbox_name] = discovered_box

            for name, box in self._sandboxes.items():
                target_cname = box.container_name or name
                if target_cname in podman_by_name:
                    c_id, state, port_val = podman_by_name[target_cname]
                    box.container_id = c_id
                    box.status = "running" if state in ("running", "up") else state
                    if port_val:
                        box.ssh_port = port_val
                elif name in podman_by_name:
                    c_id, state, port_val = podman_by_name[name]
                    box.container_id = c_id
                    box.status = "running" if state in ("running", "up") else state
                    if port_val:
                        box.ssh_port = port_val
                else:
                    if box.status in ("running", "paused"):
                        box.status = "stopped"

            # Check dynamic tunnels
            for box in self._sandboxes.values():
                active_tunnels = []
                for tun in box.dynamic_tunnels:
                    if tun.tunnel_pid:
                        try:
                            os.kill(tun.tunnel_pid, 0)
                            active_tunnels.append(tun)
                        except OSError:
                            pass
                    else:
                        active_tunnels.append(tun)
                box.dynamic_tunnels = active_tunnels

            self.save_state()
        except Exception:
            pass

    @staticmethod
    def _probe_proc_rss_mib(container_name: str, container_id: Optional[str] = None) -> Optional[float]:
        """
        Inspect /proc for the VMM / conmon / crun process managing `container_name`
        when `podman stats` reports 0B under crun-krun microVMs. Makes zero subprocess calls.
        """
        proc_dir = Path("/proc")
        if not proc_dir.is_dir():
            return None
        uid = os.getuid()
        needles = [n for n in (container_name, container_id) if n]
        if not needles:
            return None

        best_rss_kib = 0
        try:
            for entry in proc_dir.iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    if entry.stat().st_uid != uid:
                        continue
                    cmdline_bytes = (entry / "cmdline").read_bytes()
                except OSError:
                    continue
                if not cmdline_bytes:
                    continue
                cmdline = cmdline_bytes.replace(b"\x00", b" ").decode("utf-8", errors="ignore")
                if not any(n in cmdline for n in needles):
                    continue
                first_tok = os.path.basename(cmdline.split(" ", 1)[0])
                if first_tok in ("python", "python3", "pytest"):
                    continue
                try:
                    status_txt = (entry / "status").read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for line in status_txt.splitlines():
                    if line.startswith("VmRSS:"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            best_rss_kib = max(best_rss_kib, int(parts[1]))
                        break
        except Exception:
            return None

        if best_rss_kib > 0:
            return best_rss_kib / 1024.0
        return None

    def get_stats(self) -> Dict[str, dict]:
        """
        Fetch live CPU and memory statistics across running/paused sandboxes.
        Computes accurate `mem_percent` and `mem_usage` against each sandbox's allocated `ram_mib`.
        """
        stats: Dict[str, dict] = {}
        try:
            cmd = ["podman", "stats", "--no-stream", "--format", "json"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if isinstance(data, list):
                    for item in data:
                        if not isinstance(item, dict):
                            continue
                        raw_name = item.get("Name") or item.get("name") or ""
                        name = str(raw_name).lstrip("/")
                        if not name:
                            continue

                        cpu_raw = str(
                            item.get("CPUPerc")
                            if item.get("CPUPerc") is not None
                            else item.get("cpu_percent", "0%")
                        ).rstrip("%").strip()
                        mem_raw = str(
                            item.get("MemPerc")
                            if item.get("MemPerc") is not None
                            else item.get("mem_percent", "0%")
                        ).rstrip("%").strip()
                        mem_usage_raw = str(
                            item.get("MemUsage")
                            if item.get("MemUsage") is not None
                            else item.get("mem_usage", "")
                        ).strip()

                        try:
                            cpu_f = max(0.0, float(cpu_raw)) if cpu_raw and cpu_raw != "--" else 0.0
                        except ValueError:
                            cpu_f = 0.0
                        try:
                            mem_f = max(0.0, float(mem_raw)) if mem_raw and mem_raw != "--" else 0.0
                        except ValueError:
                            mem_f = 0.0

                        box = self._sandboxes.get(name) or self.get_sandbox(name)
                        alloc_mib = int(box.ram_mib) if box and box.ram_mib > 0 else DEFAULT_RAM_MIB

                        used_mib: Optional[float] = None
                        if mem_usage_raw:
                            left_part = mem_usage_raw.split("/")[0].strip()
                            used_mib = parse_mem_size_mib(left_part)

                        if (used_mib is None or used_mib <= 0.0) and box is not None:
                            rss_mib = self._probe_proc_rss_mib(name, box.container_id)
                            if rss_mib is not None and rss_mib > 0.0:
                                used_mib = rss_mib

                        if used_mib is not None and used_mib > 0.0 and alloc_mib > 0:
                            mem_f = min(100.0, (used_mib / float(alloc_mib)) * 100.0)
                            mem_usage = f"{format_mem_mib(used_mib)} / {format_mem_mib(float(alloc_mib))}"
                        else:
                            mem_usage = mem_usage_raw if mem_usage_raw and mem_usage_raw != "-- / --" else ""

                        stats[name] = {
                            "cpu_percent": cpu_f,
                            "mem_percent": mem_f,
                            "mem_usage": mem_usage,
                        }
        except Exception:
            pass
        return stats

    def evaluate_guardrails(
        self,
        sandboxes: Optional[List[SandboxInfo]] = None,
        settings: Optional[dict] = None,
    ) -> Tuple[List[AlertEvent], List[Tuple[str, str, str]]]:
        """
        Evaluate memory pressure, blocked exfiltration domain spikes, AI token/USD budgets,
        and idle auto-pause/auto-stop timers across sandboxes, executing any triggered pause/stop actions.
        """
        target_boxes = sandboxes if sandboxes is not None else list(self._sandboxes.values())
        cfg = settings if settings is not None else load_settings()
        alerts, actions_to_run = self.guardrails.evaluate(
            target_boxes,
            egress_traffic_mgr=self.egress_traffic,
            telemetry_mgr=self.telemetry,
            settings=cfg,
        )
        executed: List[Tuple[str, str, str]] = []
        for box_name, action_verb, reason in actions_to_run:
            if action_verb == "pause":
                ok, _ = self.pause_sandbox(box_name)
            elif action_verb == "stop":
                ok, _ = self.stop_sandbox(box_name)
            else:
                ok = False
            if ok:
                executed.append((box_name, action_verb, reason))
        return alerts, executed

    def keep_awake(self, name: str, indefinite: bool = False, extend_minutes: int = 30) -> Tuple[bool, str]:
        """
        Reset idle timer and keep sandbox active. If indefinite=True, sets idle_timeout_minutes=0.
        """
        box = self.get_sandbox(name)
        if not box:
            return False, f"Sandbox '{name}' not found."
        self.guardrails.reset_idle(box.name)
        if indefinite:
            box.idle_timeout_minutes = 0
            self.save_state()
            return True, f"Sandbox '{box.name}' marked to run indefinitely (idle sleep disabled)."
        return True, f"Reset idle timer for '{box.name}'. Kept active for at least {extend_minutes} more minutes."

    @staticmethod
    def _clean_env_dict(raw_env: Optional[Dict[str, str]]) -> Dict[str, str]:
        cleaned: Dict[str, str] = {}
        if not raw_env:
            return cleaned
        for k, v in raw_env.items():
            if is_valid_env_key(k) and v is not None:
                cleaned[k] = sanitize_env_value(v)
        return cleaned

    @staticmethod
    def _clean_env_key_list(raw_keys: Optional[List[str]]) -> List[str]:
        if not raw_keys:
            return []
        seen: Set[str] = set()
        out: List[str] = []
        for k in raw_keys:
            ck = str(k or "").strip()
            if is_valid_env_key(ck) and ck not in seen:
                seen.add(ck)
                out.append(ck)
        return out

    def create_sandbox(
        self,
        dir_path: str,
        name: Optional[str] = None,
        base_image: str = "localhost/agent-box:latest",
        is_persistent: bool = False,
        network_policy: Optional[NetworkPolicy] = None,
        ports: Optional[List[str]] = None,
        cpus: int = DEFAULT_CPUS,
        ram_mib: int = DEFAULT_RAM_MIB,
        persist_docker: bool = False,
        protect_git_hooks: bool = True,
        protect_git_config: bool = False,
        protect_env_files: bool = False,
        host_egress_lockdown: bool = False,
        idle_timeout_minutes: int = 0,
        idle_action: str = "stop",
        env_vars: Optional[Dict[str, str]] = None,
        secret_keys: Optional[List[str]] = None,
        host_env_passthrough: Optional[List[str]] = None,
        max_tokens_budget: int = 0,
        max_cost_usd_budget: float = 0.0,
        budget_exceeded_action: str = "alert",
        template_id: Optional[str] = None,
    ) -> SandboxInfo:
        """Create and register a new sandbox instance."""
        resolved_path = str(Path(dir_path).resolve())
        box_name = self.generate_name(resolved_path, name)

        used_ports = self._collect_used_host_ports()
        ssh_port = find_free_port(DEFAULT_SSH_PORT, avoid=used_ports)
        used_ports.add(ssh_port)

        pub_mappings: List[PortMapping] = []
        if ports:
            for p in ports:
                mapping = parse_port_spec(p, avoid_ports=used_ports)
                pub_mappings.append(mapping)
                used_ports.add(mapping.host_port)

        clean_idle_act = str(idle_action or "stop").strip().lower()
        if clean_idle_act not in ("pause", "stop"):
            clean_idle_act = "stop"
        clean_budget_act = str(budget_exceeded_action or "alert").strip().lower()
        if clean_budget_act not in ("alert", "pause", "stop"):
            clean_budget_act = "alert"

        box = SandboxInfo(
            name=box_name,
            dir_path=resolved_path,
            hostname=box_name,
            container_name=box_name,
            ssh_port=ssh_port,
            base_image=base_image,
            is_persistent=is_persistent,
            network_policy=network_policy or NetworkPolicy(),
            published_ports=pub_mappings,
            ram_mib=ram_mib,
            cpus=cpus,
            persist_docker=persist_docker,
            volume_prefix=box_name,
            protect_git_hooks=bool(protect_git_hooks),
            protect_git_config=bool(protect_git_config),
            protect_env_files=bool(protect_env_files),
            host_egress_lockdown=bool(host_egress_lockdown),
            idle_timeout_minutes=max(0, int(idle_timeout_minutes or 0)),
            idle_action=clean_idle_act,
            env_vars=self._clean_env_dict(env_vars),
            secret_keys=self._clean_env_key_list(secret_keys),
            host_env_passthrough=self._clean_env_key_list(host_env_passthrough),
            max_tokens_budget=max(0, int(max_tokens_budget or 0)),
            max_cost_usd_budget=max(0.0, float(max_cost_usd_budget or 0.0)),
            budget_exceeded_action=clean_budget_act,
            template_id=template_id,
            status="stopped",
        )
        self._sandboxes[box_name] = box
        self.save_state()
        return box

    def _write_egress_artifacts(self, box: SandboxInfo) -> Tuple[Path, Path]:
        """Generate host egress firewall script and guest DNS bundle in private directories."""
        egress_script = generate_egress_firewall_script(box.network_policy)
        egress_dir = DATA_DIR / "egress"
        egress_dir.mkdir(parents=True, exist_ok=True)
        try:
            egress_dir.chmod(0o700)
        except Exception:
            pass
        egress_script_path = egress_dir / f"{box.name}.sh"
        egress_script_path.write_text(egress_script, encoding="utf-8")
        try:
            egress_script_path.chmod(0o755)
        except Exception:
            pass

        bundle_dir = self.egress_traffic.get_sandbox_bundle_dir(box.name)
        write_guest_egress_bundle(box.name, box.network_policy, bundle_dir)
        return egress_script_path, bundle_dir

    def _apply_live_egress_policy(self, box: SandboxInfo) -> None:
        """Re-apply /etc/krunbox-egress.sh inside a running sandbox and update host netns if locked."""
        try:
            res = subprocess.run(
                ["podman", "exec", "-u", "0", box.container_name, "/bin/bash", "/etc/krunbox-egress.sh"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if res.returncode != 0:
                subprocess.run(
                    [
                        "ssh",
                        "-o", "BatchMode=yes",
                        "-o", "ConnectTimeout=3",
                        box.name,
                        "--",
                        "sudo",
                        "/bin/bash",
                        "/etc/krunbox-egress.sh",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
        except Exception:
            pass

        if box.host_egress_lockdown:
            apply_host_netns_lockdown(box.container_name, box.network_policy)

        self._configure_guest_mcp(box)

    def _migrate_telemetry_log(self, old_name: str, new_name: str) -> None:
        """Rename per-sandbox AI telemetry JSONL file when a sandbox is renamed."""
        from . import telemetry as _telem_mod

        base_dir = getattr(self.telemetry, "telemetry_dir", None) or getattr(_telem_mod, "TELEMETRY_DIR", TELEMETRY_DIR)
        base_path = Path(base_dir)
        old_file = base_path / f"{old_name}.jsonl"
        new_file = base_path / f"{new_name}.jsonl"
        if old_file.is_file() and old_file != new_file:
            try:
                if new_file.is_file():
                    with open(new_file, "a", encoding="utf-8") as nf:
                        nf.write(old_file.read_text(encoding="utf-8", errors="replace"))
                    old_file.unlink(missing_ok=True)
                else:
                    old_file.rename(new_file)
            except Exception:
                pass

    def update_sandbox(
        self,
        name: str,
        new_name: Optional[str] = None,
        cpus: Optional[int] = None,
        ram_mib: Optional[int] = None,
        network_policy: Optional[NetworkPolicy] = None,
        protect_git_hooks: Optional[bool] = None,
        protect_git_config: Optional[bool] = None,
        protect_env_files: Optional[bool] = None,
        host_egress_lockdown: Optional[bool] = None,
        idle_timeout_minutes: Optional[int] = None,
        idle_action: Optional[str] = None,
        env_vars: Optional[Dict[str, str]] = None,
        secret_keys: Optional[List[str]] = None,
        host_env_passthrough: Optional[List[str]] = None,
        max_tokens_budget: Optional[int] = None,
        max_cost_usd_budget: Optional[float] = None,
        budget_exceeded_action: Optional[str] = None,
        secrets_updated: bool = False,
    ) -> Tuple[bool, str, Optional[SandboxInfo]]:
        """
        Update an existing sandbox's name, CPU/RAM hardware allocation, egress network policy,
        mount/host guardrails, idle sleep settings, budget caps, and scoped secrets/env vars.
        """
        box = self.get_sandbox(name)
        if not box:
            return False, f"Sandbox '{name}' not found.", None

        target_cpus: Optional[int] = None
        if cpus is not None:
            if isinstance(cpus, bool):
                return False, "CPUs must be an integer between 1 and 128.", None
            try:
                target_cpus = int(cpus)
            except (ValueError, TypeError):
                return False, "CPUs must be an integer between 1 and 128.", None
            if not (1 <= target_cpus <= 128):
                return False, "CPUs must be between 1 and 128.", None

        target_ram: Optional[int] = None
        if ram_mib is not None:
            if isinstance(ram_mib, bool):
                return False, "RAM must be an integer between 512 and 262144 MiB.", None
            try:
                target_ram = int(ram_mib)
            except (ValueError, TypeError):
                return False, "RAM must be an integer between 512 and 262144 MiB.", None
            if not (512 <= target_ram <= 262144):
                return False, "RAM must be between 512 and 262144 MiB.", None

        sanitized_policy: Optional[NetworkPolicy] = None
        if network_policy is not None:
            prof = str(network_policy.profile or "").strip().lower()
            if prof not in VALID_PROFILES:
                return False, f"Invalid network profile '{network_policy.profile}'.", None
            clean_allowed: List[str] = []
            for d in (network_policy.allowed_domains or []):
                cd = str(d).strip().lower().rstrip(".")
                if cd and is_safe_domain_or_ip(cd) and cd not in clean_allowed:
                    clean_allowed.append(cd)
            clean_denied = get_denied_domains(network_policy.denied_domains)
            sanitized_policy = NetworkPolicy(
                profile=prof,
                allowed_domains=clean_allowed,
                denied_domains=clean_denied,
            )

        if idle_action is not None and str(idle_action).strip().lower() not in ("pause", "stop"):
            return False, f"Invalid idle action '{idle_action}'. Must be 'pause' or 'stop'.", None
        if budget_exceeded_action is not None and str(budget_exceeded_action).strip().lower() not in ("alert", "pause", "stop"):
            return False, f"Invalid budget action '{budget_exceeded_action}'.", None

        if new_name is not None and new_name.strip():
            target_name = self.sanitize_name(new_name)
            if target_name != box.name and target_name in self._sandboxes:
                return False, f"Sandbox '{target_name}' already exists.", None
        else:
            target_name = box.name

        box.volume_prefix = box.volume_prefix or box.name

        name_changed = target_name != box.name
        hw_changed = (
            (target_cpus is not None and target_cpus != box.cpus)
            or (target_ram is not None and target_ram != box.ram_mib)
        )
        net_changed = (
            sanitized_policy is not None
            and sanitized_policy.to_dict() != box.network_policy.to_dict()
        )
        mount_or_lock_changed = (
            (protect_git_hooks is not None and bool(protect_git_hooks) != box.protect_git_hooks)
            or (protect_git_config is not None and bool(protect_git_config) != box.protect_git_config)
            or (protect_env_files is not None and bool(protect_env_files) != box.protect_env_files)
            or (host_egress_lockdown is not None and bool(host_egress_lockdown) != box.host_egress_lockdown)
        )

        cleaned_env = self._clean_env_dict(env_vars) if env_vars is not None else None
        cleaned_secrets = self._clean_env_key_list(secret_keys) if secret_keys is not None else None
        cleaned_pass = self._clean_env_key_list(host_env_passthrough) if host_env_passthrough is not None else None

        env_changed = (
            (cleaned_env is not None and cleaned_env != box.env_vars)
            or (cleaned_secrets is not None and cleaned_secrets != box.secret_keys)
            or (cleaned_pass is not None and cleaned_pass != box.host_env_passthrough)
            or bool(secrets_updated)
        )

        target_idle_min = max(0, int(idle_timeout_minutes)) if idle_timeout_minutes is not None else None
        target_idle_act = str(idle_action).strip().lower() if idle_action is not None else None
        target_max_tokens = max(0, int(max_tokens_budget)) if max_tokens_budget is not None else None
        target_max_cost = max(0.0, float(max_cost_usd_budget)) if max_cost_usd_budget is not None else None
        target_budget_act = str(budget_exceeded_action).strip().lower() if budget_exceeded_action is not None else None

        meta_changed = (
            (target_idle_min is not None and target_idle_min != box.idle_timeout_minutes)
            or (target_idle_act is not None and target_idle_act != box.idle_action)
            or (target_max_tokens is not None and target_max_tokens != box.max_tokens_budget)
            or (target_max_cost is not None and target_max_cost != box.max_cost_usd_budget)
            or (target_budget_act is not None and target_budget_act != box.budget_exceeded_action)
        )

        recreate_needed = hw_changed or mount_or_lock_changed or env_changed

        if not (name_changed or recreate_needed or net_changed or meta_changed):
            return True, f"No changes to '{box.name}'.", box

        old_name = box.name
        old_container = box.container_name
        was_running = box.status == "running"
        was_paused = box.status == "paused"
        saved_tunnels = [(t.guest_port, t.host_port) for t in box.dynamic_tunnels]

        if recreate_needed:
            for tun in box.dynamic_tunnels:
                stop_ssh_tunnel(tun)
            box.dynamic_tunnels.clear()

            if was_paused:
                subprocess.run(
                    ["podman", "unpause", old_container],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )

            exists_res = subprocess.run(
                ["podman", "container", "exists", old_container],
                capture_output=True,
                check=False,
            )
            if exists_res.returncode == 0 and box.is_persistent:
                commit_tag = f"localhost/krunbox-state-{box.volume_prefix}:latest"
                commit_res = subprocess.run(
                    ["podman", "commit", old_container, commit_tag],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60,
                )
                if commit_res.returncode == 0:
                    box.committed_image = commit_tag

            if was_running or was_paused:
                subprocess.run(
                    ["podman", "stop", old_container],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=15,
                )
                box.status = "stopped"

            subprocess.run(
                ["podman", "rm", "-f", old_container],
                capture_output=True,
                text=True,
                check=False,
            )
        elif name_changed:
            for tun in box.dynamic_tunnels:
                stop_ssh_tunnel(tun)
            box.dynamic_tunnels.clear()

            subprocess.run(
                ["podman", "rename", old_container, target_name],
                capture_output=True,
                text=True,
                check=False,
            )

        if target_cpus is not None:
            box.cpus = target_cpus
        if target_ram is not None:
            box.ram_mib = target_ram
        if sanitized_policy is not None:
            box.network_policy = sanitized_policy
        if protect_git_hooks is not None:
            box.protect_git_hooks = bool(protect_git_hooks)
        if protect_git_config is not None:
            box.protect_git_config = bool(protect_git_config)
        if protect_env_files is not None:
            box.protect_env_files = bool(protect_env_files)
        if host_egress_lockdown is not None:
            box.host_egress_lockdown = bool(host_egress_lockdown)
        if cleaned_env is not None:
            box.env_vars = cleaned_env
        if cleaned_secrets is not None:
            box.secret_keys = cleaned_secrets
        if cleaned_pass is not None:
            box.host_env_passthrough = cleaned_pass
        if target_idle_min is not None:
            box.idle_timeout_minutes = target_idle_min
        if target_idle_act is not None:
            box.idle_action = target_idle_act
        if target_max_tokens is not None:
            box.max_tokens_budget = target_max_tokens
        if target_max_cost is not None:
            box.max_cost_usd_budget = target_max_cost
        if target_budget_act is not None:
            box.budget_exceeded_action = target_budget_act

        if name_changed:
            if old_name in self._sandboxes:
                del self._sandboxes[old_name]
            box.name = target_name
            box.hostname = target_name
            box.container_name = target_name
            self._sandboxes[target_name] = box

            remove_sandbox_ssh_config(old_name)
            dir_basename = self.sanitize_name(Path(box.dir_path).name).replace("krunbox-", "")
            write_sandbox_ssh_config(
                target_name,
                box.ssh_port,
                extra_aliases=[dir_basename] if dir_basename else None,
            )

            self._migrate_telemetry_log(old_name, target_name)
            self.egress_traffic.rename_logs(old_name, target_name)
            self.snapshots.rename_snapshot(old_name, target_name)
            try:
                self.secrets.rename_sandbox_secrets(old_name, target_name, secret_keys=box.secret_keys)
            except Exception:
                pass

            egress_dir = DATA_DIR / "egress"
            old_sh = egress_dir / f"{old_name}.sh"
            new_sh = egress_dir / f"{target_name}.sh"
            if old_sh.is_file():
                try:
                    if not new_sh.exists():
                        old_sh.rename(new_sh)
                    else:
                        old_sh.unlink(missing_ok=True)
                except Exception:
                    pass

        self._write_egress_artifacts(box)
        self.save_state()

        if (was_running or was_paused) and recreate_needed:
            ok, start_msg = self.start_sandbox(box.name, detach=True)
            if ok:
                for guest_p, host_p in saved_tunnels:
                    self.forward_port(box.name, guest_port=guest_p, host_port=host_p)
                if was_paused:
                    self.pause_sandbox(box.name)
            else:
                return False, f"Updated '{box.name}', but restart failed: {start_msg}", box
        elif was_running:
            if name_changed:
                for guest_p, host_p in saved_tunnels:
                    self.forward_port(box.name, guest_port=guest_p, host_port=host_p)
            if net_changed:
                self._apply_live_egress_policy(box)

        changes = []
        if name_changed:
            changes.append(f"renamed '{old_name}' -> '{box.name}'")
        if hw_changed:
            changes.append(f"{box.cpus} vCPUs / {box.ram_mib} MiB RAM")
        if net_changed:
            changes.append(f"network={box.network_policy.profile}")
        if mount_or_lock_changed:
            changes.append("guardrails/lockdown")
        if env_changed:
            changes.append("env/secrets")
        if meta_changed:
            changes.append("idle/budgets")
        summary = f"Updated sandbox '{box.name}' ({', '.join(changes)})."
        return True, summary, box

    def update_network_policy(self, name: str, policy: NetworkPolicy) -> bool:
        """Update the egress network policy for a sandbox."""
        ok, _, _ = self.update_sandbox(name, network_policy=policy)
        return ok

    def _collect_used_host_ports(self) -> Set[int]:
        ports = set()
        for box in self._sandboxes.values():
            ports.add(box.ssh_port)
            for p in box.all_ports:
                ports.add(p.host_port)
        return ports

    def start_sandbox(
        self,
        name: str,
        detach: bool = True,
        extra_args: Optional[List[str]] = None
    ) -> Tuple[bool, str]:
        """Launch or resume a sandbox container."""
        box = self.get_sandbox(name)
        if not box:
            return False, f"Sandbox '{name}' not found."

        if not Path(box.dir_path).exists():
            return False, f"Workspace directory '{box.dir_path}' does not exist."

        if box.status == "paused" and detach:
            ok, msg = self.unpause_sandbox(box.name)
            if ok:
                return True, msg

        box.volume_prefix = box.volume_prefix or box.name

        # Ensure pre-run baseline workspace snapshot exists for diff/rollback
        try:
            self.snapshots.ensure_snapshot(box.name, box.dir_path)
        except Exception:
            pass

        # Re-allocate SSH port if taken
        if is_port_in_use(box.ssh_port):
            used = self._collect_used_host_ports()
            box.ssh_port = find_free_port(box.ssh_port + 1, avoid=used)
            self.save_state()

        # Re-check published ports
        for p in box.published_ports:
            if is_port_in_use(p.host_port):
                used = self._collect_used_host_ports()
                p.host_port = find_free_port(p.host_port + 1, avoid=used)
                self.save_state()

        # Setup SSH keys & config
        keys = ensure_host_ssh_keys()
        ssh_keys_str = "\n".join(keys)
        dir_basename = self.sanitize_name(Path(box.dir_path).name).replace("krunbox-", "")
        write_sandbox_ssh_config(box.name, box.ssh_port, extra_aliases=[dir_basename] if dir_basename else None)

        # Generate egress script & guest DNS monitor bundle in private data directories
        egress_script_path, egress_bundle_dir = self._write_egress_artifacts(box)

        # Setup host IPC server socket for sandbox
        try:
            self.ipc_server.start_socket(box.name)
            ipc_dir = self.ipc_server.get_socket_dir(box.name)
        except Exception:
            ipc_dir = None

        # If persistent and container already exists in stopped state, try resuming it first
        if box.is_persistent:
            check_exist = subprocess.run(["podman", "container", "exists", box.container_name], check=False)
            if check_exist.returncode == 0:
                res = subprocess.run(["podman", "start", box.container_name], capture_output=True, text=True)
                if res.returncode == 0:
                    self._apply_live_egress_policy(box)
                    self._configure_guest_mcp(box)
                    box.status = "running"
                    self.save_state()
                    return True, f"Resumed persistent sandbox '{box.name}' (SSH port: {box.ssh_port})"

        # Otherwise remove any leftover container before fresh run
        subprocess.run(["podman", "rm", "-f", box.container_name], capture_output=True, check=False)

        # Volumes: Dedicated volumes per sandbox for isolation (preserving volume_prefix across renames)
        vol_prefix = box.volume_prefix or box.name
        volumes = [
            "-v", f"{vol_prefix}-gemini:/home/vscode/.gemini",
            "-v", f"{vol_prefix}-vibe:/home/vscode/.vibe",
            "-v", f"{box.dir_path}:/workspace",
        ]
        # Append read-only workspace guardrails (.git/hooks:ro, optional .git/config:ro and .env*:ro)
        volumes.extend(
            build_git_guardrail_mounts(
                box.dir_path,
                protect_git_hooks=box.protect_git_hooks,
                protect_git_config=box.protect_git_config,
                protect_env_files=box.protect_env_files,
                guardrails_dir=DATA_DIR / "guardrails",
            )
        )
        if box.persist_docker:
            volumes.extend(["-v", f"{vol_prefix}-docker:/var/lib/docker"])

        volumes.extend([
            "-v", f"{egress_script_path}:/etc/krunbox-egress.sh:ro",
            "-v", f"{egress_bundle_dir}:/run/krunbox-egress",
        ])
        if ipc_dir is not None:
            volumes.extend(["-v", f"{ipc_dir}:/run/krunbox:rw"])

        cmd = [
            "podman", "run",
            "--name", box.container_name,
            "--hostname", box.hostname,
            "--label", "krunbox=true",
            "--label", f"krunbox.name={box.name}",
            "--label", f"krunbox.dir={box.dir_path}",
            "--label", f"krunbox.ssh_port={box.ssh_port}",
            "--label", f"krunbox.persistent={box.is_persistent}",
            "--label", f"krunbox.network_profile={box.network_policy.profile}",
            "-p", f"127.0.0.1:{box.ssh_port}:2222",
            "-e", f"SSH_AUTH_KEYS={ssh_keys_str}",
            "-e", f"KRUNBOX_NETWORK_PROFILE={box.network_policy.profile}",
            "-e", "KRUNBOX_TELEMETRY=1",
            "-w", "/workspace",
        ]

        for p in box.published_ports:
            cmd.extend(["-p", f"127.0.0.1:{p.host_port}:{p.guest_port}"])

        has_krun = self.check_krun_available()
        cmd.extend(
            build_host_lockdown_podman_args(
                box.network_policy,
                box.host_egress_lockdown,
                has_krun=has_krun,
                persist_docker=box.persist_docker,
            )
        )

        if has_krun:
            cmd.extend([
                "--runtime=krun",
                f"--annotation=krun.ram_mib={box.ram_mib}",
                f"--annotation=krun.cpus={box.cpus}",
                "--annotation=krun.nested_virt=1",
                "--annotation=krun.use_passt=1",
                "--pid=host",
                "--userns=keep-id",
                "--user", "0:0",
                "--security-opt", "label=disable",
            ])
        else:
            cmd.extend([
                f"--cpus={box.cpus}",
                f"--memory={box.ram_mib}m",
                "--userns=keep-id",
                "--user", "0:0",
                *get_fallback_capability_args(box.host_egress_lockdown),
                "--security-opt", "label=disable",
            ])

        env_file: Optional[Path] = None
        try:
            env_file = self.secrets.prepare_runtime_env_file(
                box.name,
                plain_env=box.env_vars,
                secret_keys=box.secret_keys,
                host_env_passthrough=box.host_env_passthrough,
            )
        except Exception:
            env_file = None

        if env_file is not None:
            cmd.extend(["--env-file", str(env_file)])

        cmd.extend(volumes)

        if detach:
            cmd.extend(["-d", "-t"])
            if not box.is_persistent:
                cmd.append("--rm")
        else:
            if not box.is_persistent:
                cmd.append("--rm")
            cmd.extend(["-it"])

        image_to_run = box.committed_image or box.base_image
        if not box.committed_image:
            ok_img, msg_img = self.images.ensure_image_ready(image_to_run)
            if not ok_img:
                return False, f"Failed to prepare container image '{image_to_run}': {msg_img}"

        is_uv = is_uv_cli_image(image_to_run) or (bool(box.base_image) and is_uv_cli_image(box.base_image))
        if is_uv:
            cmd.extend(["--entrypoint", ""])

        cmd.append(image_to_run)
        if extra_args:
            cmd.extend(extra_args)
        elif is_uv:
            if detach:
                cmd.extend(["sh", "-c", build_uv_boot_script()])
            else:
                cmd.append("bash")

        try:
            if detach:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                if res.returncode != 0:
                    err = res.stderr.strip() or res.stdout.strip()
                    return False, f"Podman failed to start: {err}"
                box.container_id = res.stdout.strip()[:12]
                box.status = "running"
                if box.host_egress_lockdown:
                    apply_host_netns_lockdown(box.container_name, box.network_policy)
                self._configure_guest_mcp(box)
                self.save_state()
                mode_str = "persistent" if box.is_persistent else "ephemeral"
                return True, f"Sandbox '{box.name}' ({mode_str}) started (SSH port: {box.ssh_port})"
            else:
                box.status = "running"
                self.save_state()
                if env_file is not None:
                    rc = subprocess.run(cmd, check=False).returncode
                    box.status = "stopped"
                    self.save_state()
                    return (rc == 0), f"Interactive session exited with code {rc}"
                os.execvp("podman", cmd)
        except Exception as e:
            return False, f"Exception starting sandbox: {str(e)}"
        finally:
            if env_file is not None:
                self.secrets.cleanup_runtime_env_file(env_file)

    def pause_sandbox(self, name: str) -> Tuple[bool, str]:
        """Freeze a running sandbox via `podman pause`."""
        box = self.get_sandbox(name)
        if not box:
            return False, f"Sandbox '{name}' not found."
        if box.status == "paused":
            return True, f"Sandbox '{box.name}' is already paused."
        if box.status != "running":
            return False, f"Sandbox '{box.name}' is not currently running."

        res = subprocess.run(
            ["podman", "pause", box.container_name],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if res.returncode == 0:
            box.status = "paused"
            self.save_state()
            return True, f"Sandbox '{box.name}' paused."
        err = res.stderr.strip() or res.stdout.strip() or "podman pause failed"
        return False, f"Failed to pause '{box.name}': {err}"

    def unpause_sandbox(self, name: str) -> Tuple[bool, str]:
        """Resume a paused sandbox via `podman unpause`."""
        box = self.get_sandbox(name)
        if not box:
            return False, f"Sandbox '{name}' not found."
        if box.status == "running":
            return True, f"Sandbox '{box.name}' is already running."

        res = subprocess.run(
            ["podman", "unpause", box.container_name],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if res.returncode == 0:
            box.status = "running"
            self.save_state()
            return True, f"Sandbox '{box.name}' resumed."
        err = res.stderr.strip() or res.stdout.strip() or "podman unpause failed"
        return False, f"Failed to resume '{box.name}': {err}"

    def stop_sandbox(self, name: str) -> Tuple[bool, str]:
        """Halt a running or paused sandbox."""
        box = self.get_sandbox(name)
        if not box:
            return False, f"Sandbox '{name}' not found."

        for tun in box.dynamic_tunnels:
            stop_ssh_tunnel(tun)
        box.dynamic_tunnels.clear()

        if box.status == "paused":
            subprocess.run(
                ["podman", "unpause", box.container_name],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        res = subprocess.run(["podman", "stop", box.container_name], capture_output=True, text=True, timeout=15)
        box.status = "stopped"

        try:
            self.ipc_server.stop_socket(box.name)
        except Exception:
            pass

        # If ephemeral, remove container
        if not box.is_persistent:
            subprocess.run(["podman", "rm", "-f", box.container_name], capture_output=True, check=False)

        self.save_state()
        if res.returncode == 0:
            return True, f"Sandbox '{box.name}' stopped."
        return False, f"Failed to stop: {res.stderr.strip()}"

    def restart_sandbox(self, name: str) -> Tuple[bool, str]:
        """Restart a sandbox."""
        self.stop_sandbox(name)
        time.sleep(1)
        return self.start_sandbox(name, detach=True)

    def recreate_sandbox(
        self,
        name: str,
        pull_image: bool = True,
        wipe_volumes: bool = True,
        start_after: bool = True,
    ) -> Tuple[bool, str]:
        """
        Recreate a sandbox (wipe container/volumes and rebuild with same configuration).
        """
        box = self.get_sandbox(name)
        if not box:
            return False, f"Sandbox '{name}' not found."

        # Stop dynamic SSH tunnels for this sandbox
        saved_tunnels = [(t.guest_port, t.host_port) for t in box.dynamic_tunnels]
        for tun in list(box.dynamic_tunnels):
            stop_ssh_tunnel(tun)
        box.dynamic_tunnels.clear()

        # Stop host IPC socket
        try:
            self.ipc_server.stop_socket(box.name)
        except Exception:
            pass

        # Unpause if currently paused
        if box.status == "paused":
            subprocess.run(
                ["podman", "unpause", box.container_name],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        # Stop container if running or paused
        if box.status in ("running", "paused"):
            subprocess.run(
                ["podman", "stop", box.container_name],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            box.status = "stopped"

        # Force remove the container and clear container ID
        subprocess.run(
            ["podman", "rm", "-f", box.container_name],
            capture_output=True,
            text=True,
            check=False,
        )
        box.container_id = None
        box.status = "stopped"

        # Force remove committed image if present
        if box.committed_image:
            subprocess.run(
                ["podman", "rmi", "-f", box.committed_image],
                capture_output=True,
                text=True,
                check=False,
            )
            box.committed_image = None

        # Wipe persistent storage volumes if requested
        if wipe_volumes:
            vol_prefix = box.volume_prefix or box.name
            for v in [f"{vol_prefix}-gemini", f"{vol_prefix}-vibe", f"{vol_prefix}-docker"]:
                subprocess.run(
                    ["podman", "volume", "rm", "-f", v],
                    capture_output=True,
                    text=True,
                    check=False,
                )

        # Persist intermediate state so state on disk is consistent even if image build/start fails
        self.save_state()

        # Pull/refresh latest base container image
        if pull_image:
            ok_img, msg_img = self.images.ensure_image_ready(box.base_image, force=True)
            if not ok_img:
                # If build/pull failed (e.g. offline or no network), check if base_image already exists locally:
                if not self.images.is_image_present(box.base_image):
                    return False, f"Failed to prepare container image '{box.base_image}': {msg_img}"

        # Start sandbox and restore dynamic tunnels
        if start_after:
            ok_start, msg_start = self.start_sandbox(box.name, detach=True)
            if not ok_start:
                return False, f"Failed to start recreated sandbox '{box.name}': {msg_start}"
            if saved_tunnels:
                from .ssh import wait_for_ssh_ready
                wait_for_ssh_ready("127.0.0.1", box.ssh_port, max_wait=4.0, poll_interval=0.2)
                for guest_port, host_port in saved_tunnels:
                    try:
                        self.forward_port(box.name, guest_port, host_port)
                    except Exception:
                        pass
            return True, f"Recreated and started sandbox '{box.name}'"
        else:
            box.status = "stopped"
            self.save_state()
            return True, f"Recreated sandbox '{box.name}' (stopped)"

    def delete_sandbox(self, name: str, delete_volumes: bool = False) -> Tuple[bool, str]:
        """Delete container, SSH configurations, snapshots, secrets, and optionally persistent storage."""
        box = self.get_sandbox(name)
        if not box:
            return False, f"Sandbox '{name}' not found."

        self.stop_sandbox(name)
        subprocess.run(["podman", "rm", "-f", box.container_name], capture_output=True, check=False)
        remove_sandbox_ssh_config(box.name)

        try:
            self.snapshots.delete_snapshot(box.name)
        except Exception:
            pass
        try:
            self.secrets.delete_sandbox_secrets(box.name, secret_keys=box.secret_keys)
        except Exception:
            pass

        egress_sh = DATA_DIR / "egress" / f"{box.name}.sh"
        try:
            egress_sh.unlink(missing_ok=True)
        except Exception:
            pass

        try:
            self.ipc_server.cleanup_sandbox_ipc(box.name)
        except Exception:
            pass

        if delete_volumes:
            vol_prefix = box.volume_prefix or box.name
            vols = [f"{vol_prefix}-gemini", f"{vol_prefix}-vibe", f"{vol_prefix}-docker"]
            for v in vols:
                subprocess.run(["podman", "volume", "rm", "-f", v], capture_output=True, check=False)
            if box.committed_image:
                subprocess.run(["podman", "rmi", "-f", box.committed_image], capture_output=True, check=False)

        if box.name in self._sandboxes:
            del self._sandboxes[box.name]
            self.save_state()

        return True, f"Sandbox '{box.name}' deleted."

    def forward_port(self, name: str, guest_port: int, host_port: Optional[int] = None) -> Tuple[bool, str, Optional[PortMapping]]:
        """Dynamically forward guest port to host via live SSH background tunnel."""
        box = self.get_sandbox(name)
        if not box:
            return False, f"Sandbox '{name}' not found.", None

        if box.status != "running":
            return False, f"Sandbox '{box.name}' is not currently running.", None

        if host_port is None:
            used = self._collect_used_host_ports()
            host_port = find_free_port(guest_port, avoid=used)

        if is_port_in_use(host_port):
            return False, f"Host port {host_port} is already in use.", None

        try:
            mapping = start_ssh_tunnel(box.name, host_port, guest_port, ssh_port=box.ssh_port)
            box.dynamic_tunnels.append(mapping)
            self.save_state()
            return True, f"Forwarded 127.0.0.1:{host_port} -> guest port {guest_port}", mapping
        except Exception as e:
            return False, str(e), None

    def unforward_port(self, name: str, guest_port: int) -> Tuple[bool, str]:
        """Tear down a dynamic SSH tunnel for a guest port."""
        box = self.get_sandbox(name)
        if not box:
            return False, f"Sandbox '{name}' not found."

        removed = []
        remaining = []
        for tun in box.dynamic_tunnels:
            if tun.guest_port == guest_port:
                stop_ssh_tunnel(tun)
                removed.append(tun)
            else:
                remaining.append(tun)

        box.dynamic_tunnels = remaining
        self.save_state()

        if removed:
            return True, f"Closed tunnel for guest port {guest_port}."
        return False, f"No active dynamic tunnel for guest port {guest_port}."

    def get_logs(self, name: str, tail: int = 100) -> str:
        """Fetch container execution logs."""
        box = self.get_sandbox(name)
        if not box:
            return f"Sandbox '{name}' not found."
        res = subprocess.run(["podman", "logs", "--tail", str(tail), box.container_name], capture_output=True, text=True)
        return res.stdout + res.stderr

    def prune(self) -> int:
        """Remove stopped ephemeral sandboxes."""
        stopped_ephemeral = [
            name for name, box in self._sandboxes.items()
            if box.status not in ("running", "paused") and not box.is_persistent
        ]
        count = 0
        for name in stopped_ephemeral:
            self.delete_sandbox(name, delete_volumes=False)
            count += 1
        return count

    def _configure_guest_mcp(self, box: SandboxInfo) -> None:
        """Best-effort auto-registration of krunbox-gateway MCP server in guest MCP configs."""
        def _exec_configure():
            py_code = (
                "import json, os\n"
                "cfg = {'command': '/run/krunbox/krunbox-mcp', 'args': []}\n"
                "homes = ['/home/vscode', '/root']\n"
                "paths = [\n"
                "    '/workspace/.agents/mcp_config.json',\n"
                "    '/workspace/.antigravity/mcp_config.json',\n"
                "    '/workspace/.gemini/mcp_config.json',\n"
                "]\n"
                "for h in homes:\n"
                "    if os.path.isdir(h):\n"
                "        paths.extend([\n"
                "            os.path.join(h, '.gemini/config/mcp_config.json'),\n"
                "            os.path.join(h, '.gemini/antigravity-cli/mcp_config.json'),\n"
                "            os.path.join(h, '.config/antigravity/mcp_config.json'),\n"
                "            os.path.join(h, '.config/Claude/claude_desktop_config.json'),\n"
                "            os.path.join(h, '.cursor/mcp.json'),\n"
                "        ])\n"
                "for p in paths:\n"
                "    try:\n"
                "        os.makedirs(os.path.dirname(p), exist_ok=True)\n"
                "        d = {}\n"
                "        if os.path.exists(p) and os.path.getsize(p) > 0:\n"
                "            try:\n"
                "                with open(p, 'r', encoding='utf-8') as rf:\n"
                "                    loaded = json.load(rf)\n"
                "                    if isinstance(loaded, dict):\n"
                "                        d = loaded\n"
                "            except Exception:\n"
                "                d = {}\n"
                "        servers = d.setdefault('mcpServers', {})\n"
                "        if 'krunbox-gateway' not in servers or servers['krunbox-gateway'] != cfg:\n"
                "            servers['krunbox-gateway'] = cfg\n"
                "            with open(p, 'w', encoding='utf-8') as wf:\n"
                "                json.dump(d, wf, indent=2)\n"
                "        try:\n"
                "            os.chmod(p, 0o666)\n"
                "        except Exception:\n"
                "            pass\n"
                "    except Exception:\n"
                "        pass\n"
            )
            guest_sh = (
                f"if command -v python3 >/dev/null 2>&1; then "
                f"python3 -c {shlex.quote(py_code)} 2>/dev/null; "
                f"fi; "
                f"_mcp_json='{{\"mcpServers\":{{\"krunbox-gateway\":{{\"command\":\"/run/krunbox/krunbox-mcp\",\"args\":[]}}}}}}'; "
                f"for _t in /home/vscode/.gemini/config/mcp_config.json /home/vscode/.gemini/antigravity-cli/mcp_config.json /home/vscode/.config/antigravity/mcp_config.json /home/vscode/.config/Claude/claude_desktop_config.json /home/vscode/.cursor/mcp.json /workspace/.agents/mcp_config.json /workspace/.antigravity/mcp_config.json /workspace/.gemini/mcp_config.json /root/.gemini/config/mcp_config.json; do "
                f"if [ ! -s \"$_t\" ]; then "
                f"mkdir -p \"$(dirname \"$_t\")\" 2>/dev/null || true; "
                f"printf '%s\\n' \"$_mcp_json\" > \"$_t\" 2>/dev/null || true; "
                f"chmod 0666 \"$_t\" 2>/dev/null || true; "
                f"fi; done; "
                f"if id -u vscode >/dev/null 2>&1; then "
                f"chown -R vscode:vscode /home/vscode/.gemini /home/vscode/.config /home/vscode/.cursor /workspace/.agents /workspace/.antigravity /workspace/.gemini 2>/dev/null || true; "
                f"fi"
            )
            cmd = ["podman", "exec", "-u", "0", box.container_name, "bash", "-c", guest_sh]
            for attempt in range(12):
                res = subprocess.run(cmd, capture_output=True, timeout=5, check=False)
                if res.returncode == 0:
                    break
                time.sleep(0.5)

        try:
            t = threading.Thread(target=_exec_configure, daemon=True)
            t.start()
            t.join(timeout=0.8)
        except Exception:
            pass

    def list_pending_requests(self, sandbox_name: Optional[str] = None) -> List[AccessRequest]:
        """Fetch pending MCP permission requests from guest agents."""
        if hasattr(self, "ipc_server") and self.ipc_server is not None:
            return self.ipc_server.get_pending_requests(sandbox_name)
        return []

    def list_all_requests(self, sandbox_name: Optional[str] = None) -> List[AccessRequest]:
        """Fetch all MCP permission requests (pending, approved, denied)."""
        if hasattr(self, "ipc_server") and self.ipc_server is not None:
            return self.ipc_server.get_all_requests(sandbox_name)
        return []

    get_pending_access_requests = list_pending_requests
    get_all_access_requests = list_all_requests

    def approve_access_request(self, request_id: str) -> Tuple[bool, str]:
        """
        Approve an agent's request to whitelist a domain or expose an internal port,
        hot-reloading firewall rules or establishing dynamic SSH tunnels.
        """
        req = None
        if hasattr(self, "ipc_server") and self.ipc_server is not None:
            req = self.ipc_server.get_request(request_id)
            if not req and hasattr(self.ipc_server, "_pending_requests"):
                req = self.ipc_server._pending_requests.get(request_id)

        if not req and hasattr(self, "_access_requests"):
            req = self._access_requests.get(request_id)

        if not req:
            return False, f"Request '{request_id}' not found."

        box = self.get_sandbox(req.sandbox_name)
        if not box:
            return False, f"Sandbox '{req.sandbox_name}' not found."

        if req.action == "request_domain_access" or getattr(req, "request_type", "") == "domain":
            domain = req.domain or req.target
            if domain and domain not in box.network_policy.allowed_domains:
                box.network_policy.allowed_domains.append(domain)
                self.save_state()
                self._apply_live_egress_policy(box)
            if hasattr(self, "ipc_server") and self.ipc_server is not None:
                self.ipc_server.approve_request(request_id)
            req.status = "approved"
            return True, f"Approved domain '{domain}' for '{box.name}'."

        elif req.action == "request_port_exposure" or getattr(req, "request_type", "") == "port":
            try:
                guest_port = int(req.guest_port or req.target)
            except (ValueError, TypeError):
                return False, f"Invalid guest port in request '{request_id}'."

            ok, msg, port_map = self.forward_port(box.name, guest_port=guest_port)
            if not ok:
                return False, msg
            host_port = port_map.host_port if port_map else guest_port
            if hasattr(self, "ipc_server") and self.ipc_server is not None:
                self.ipc_server.approve_request(request_id, host_port=host_port)
            req.status = "approved"
            req.assigned_host_port = host_port
            return True, f"Approved and exposed port {guest_port} on host port {host_port}."

        return False, f"Unknown request action '{req.action}'"

    approve_request = approve_access_request

    def deny_access_request(self, request_id: str, reason: str = "Denied by operator") -> Tuple[bool, str]:
        """Deny an agent's access request."""
        req = None
        if hasattr(self, "ipc_server") and self.ipc_server is not None:
            req = self.ipc_server.get_request(request_id)
            if not req and hasattr(self.ipc_server, "_pending_requests"):
                req = self.ipc_server._pending_requests.get(request_id)

        if not req and hasattr(self, "_access_requests"):
            req = self._access_requests.get(request_id)

        if not req:
            return False, f"Request '{request_id}' not found."

        req.status = "denied"
        req.decision_reason = reason
        if hasattr(self, "ipc_server") and self.ipc_server is not None:
            self.ipc_server.deny_request(request_id, reason=reason)
        return True, f"Denied request '{request_id}': {reason}"

    deny_request = deny_access_request

    def clone_sandbox(self, source_name: str, new_name: str) -> Tuple[bool, str, Optional[SandboxInfo]]:
        """Clone an existing sandbox configuration into a new independent sandbox."""
        source_box = self.get_sandbox(source_name)
        if not source_box:
            return False, f"Source sandbox '{source_name}' not found.", None

        sanitized_name = self.sanitize_name(new_name)
        if not sanitized_name:
            return False, f"Invalid target sandbox name '{new_name}'.", None

        if sanitized_name in self.sandboxes:
            return False, f"Sandbox '{sanitized_name}' already exists.", None

        used_ports = self._collect_used_host_ports()
        free_port = find_free_port(DEFAULT_SSH_PORT, avoid=used_ports)
        if not free_port:
            return False, "Failed to allocate free SSH port for cloned sandbox.", None

        cloned_dict = source_box.to_dict()
        cloned_dict["name"] = sanitized_name
        cloned_dict["container_name"] = f"krunbox-{sanitized_name}"
        cloned_dict["hostname"] = sanitized_name
        cloned_dict["ssh_port"] = free_port
        cloned_dict["status"] = "stopped"
        cloned_dict["container_id"] = None
        cloned_dict["created_at"] = time.time()
        cloned_dict["cpu_percent"] = 0.0
        cloned_dict["mem_usage"] = ""
        cloned_dict["mem_percent"] = 0.0
        cloned_dict["total_api_calls"] = 0
        cloned_dict["published_ports"] = []
        cloned_dict["dynamic_tunnels"] = []

        if source_box.is_persistent:
            cloned_dict["volume_prefix"] = f"krunbox-{sanitized_name}"
            source_vol = f"krunbox-{source_name}-rootfs"
            dest_vol = f"krunbox-{sanitized_name}-rootfs"
            try:
                subprocess.run(["podman", "volume", "create", dest_vol], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(
                    ["podman", "run", "--rm", "-v", f"{source_vol}:/src:ro", "-v", f"{dest_vol}:/dst", "alpine", "sh", "-c", "cp -a /src/. /dst/ 2>/dev/null || true"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
            except Exception:
                pass

        new_box = SandboxInfo.from_dict(cloned_dict)
        self.sandboxes[sanitized_name] = new_box
        self.save_state()

        try:
            src_snap = self.snapshot_mgr.get_snapshot_info(source_name)
            if src_snap:
                self.snapshot_mgr.create_snapshot(sanitized_name, new_box.dir_path)
        except Exception:
            pass

        return True, f"Successfully cloned '{source_name}' to '{sanitized_name}'.", new_box

    def export_sandbox(self, name: str, export_path: Path) -> Tuple[bool, str]:
        """Export sandbox configuration and snapshot to a compressed tar archive."""
        box = self.get_sandbox(name)
        if not box:
            return False, f"Sandbox '{name}' not found."

        export_path = Path(export_path).resolve()
        export_path.parent.mkdir(parents=True, exist_ok=True)

        manifest = {
            "version": "1.0",
            "krunbox_export": True,
            "exported_at": time.time(),
            "sandbox": box.to_dict(),
        }

        tmp_export_dir = export_path.parent / f".tmp_export_{name}_{int(time.time())}"
        tmp_export_dir.mkdir(parents=True, exist_ok=True)
        try:
            manifest_file = tmp_export_dir / "manifest.json"
            manifest_file.write_text(json.dumps(manifest, indent=2))

            snap_dir = self.snapshot_mgr.snapshots_dir / name
            if snap_dir.exists():
                shutil.copytree(snap_dir, tmp_export_dir / "snapshot", dirs_exist_ok=True)

            with tarfile.open(export_path, "w:gz") as tar:
                for entry in tmp_export_dir.iterdir():
                    tar.add(entry, arcname=entry.name)

            return True, f"Successfully exported sandbox '{name}' to {export_path}"
        except Exception as exc:
            return False, f"Failed to export sandbox '{name}': {exc}"
        finally:
            shutil.rmtree(tmp_export_dir, ignore_errors=True)

    def import_sandbox(self, archive_path: Path, new_name: Optional[str] = None) -> Tuple[bool, str, Optional[SandboxInfo]]:
        """Import a previously exported sandbox archive."""
        archive_path = Path(archive_path).resolve()
        if not archive_path.exists():
            return False, f"Archive '{archive_path}' does not exist.", None

        tmp_import_dir = archive_path.parent / f".tmp_import_{int(time.time())}"
        tmp_import_dir.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(archive_path, "r:*") as tar:
                try:
                    tar.extractall(tmp_import_dir, filter="data")
                except TypeError:
                    tar.extractall(tmp_import_dir)

            manifest_file = tmp_import_dir / "manifest.json"
            if not manifest_file.exists():
                return False, "Invalid krunbox archive: missing manifest.json", None

            data = json.loads(manifest_file.read_text())
            box_data = data.get("sandbox")
            if not box_data or not isinstance(box_data, dict):
                return False, "Invalid manifest format: missing sandbox definition", None

            target_name = self.sanitize_name(new_name) if new_name else self.sanitize_name(box_data.get("name", "imported"))
            if not target_name:
                target_name = f"imported-{int(time.time())}"

            base_name = target_name
            counter = 1
            while target_name in self.sandboxes:
                target_name = f"{base_name}-{counter}"
                counter += 1

            used_ports = self._collect_used_host_ports()
            free_port = find_free_port(DEFAULT_SSH_PORT, avoid=used_ports) or DEFAULT_SSH_PORT

            box_data["name"] = target_name
            box_data["container_name"] = f"krunbox-{target_name}"
            box_data["hostname"] = target_name
            box_data["ssh_port"] = free_port
            box_data["status"] = "stopped"
            box_data["container_id"] = None
            box_data["created_at"] = time.time()
            box_data["published_ports"] = []
            box_data["dynamic_tunnels"] = []

            imported_box = SandboxInfo.from_dict(box_data)
            self.sandboxes[target_name] = imported_box
            self.save_state()

            snap_dir = tmp_import_dir / "snapshot"
            if snap_dir.exists():
                dest_snap = self.snapshot_mgr.snapshots_dir / target_name
                dest_snap.mkdir(parents=True, exist_ok=True)
                shutil.copytree(snap_dir, dest_snap, dirs_exist_ok=True)

            return True, f"Successfully imported sandbox as '{target_name}'.", imported_box
        except Exception as exc:
            return False, f"Failed to import sandbox: {exc}", None
        finally:
            shutil.rmtree(tmp_import_dir, ignore_errors=True)
