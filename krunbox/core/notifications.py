"""
Desktop notifications, idle auto-pause/auto-stop monitor, and runtime budget/security guardrails for krunbox.
"""

from dataclasses import dataclass, asdict, fields
import os
import re
import shlex
import shutil
import subprocess
import time
from typing import Callable, Dict, List, Optional, Tuple


@dataclass
class AlertEvent:
    id: str
    timestamp: float
    category: str  # "egress_spike", "memory_pressure", "budget_exceeded", "idle_action", "exec_complete"
    sandbox_name: str
    title: str
    body: str
    severity: str = "warning"  # "info", "warning", "critical"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AlertEvent":
        known = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


def _format_duration(seconds: float) -> str:
    """Format elapsed seconds cleanly (e.g. 14.2s or 2m 05s)."""
    secs = max(0.0, float(seconds))
    if secs < 60.0:
        return f"{secs:.1f}s"
    if secs < 3600.0:
        mins = int(secs // 60)
        rem = int(secs % 60)
        return f"{mins}m {rem:02d}s"
    hours = int(secs // 3600)
    mins = int((secs % 3600) // 60)
    return f"{hours}h {mins:02d}m"


def send_desktop_notification(
    title: str,
    body: str,
    notification_id: Optional[str] = None,
    urgent: bool = False,
    app=None,
) -> bool:
    """
    Dispatch a desktop notification via Gio.Notification (when a registered GTK/Gio
    application is available) or `notify-send` fallback.
    Returns True if dispatched, False cleanly when headless or unavailable.
    """
    nid = notification_id or f"krunbox-alert-{int(time.time() * 1000)}"
    title_str = str(title or "krunbox")
    body_str = str(body or "")

    # 1. Try GTK / Gio.Notification via explicit `app` or registered default Gio.Application
    try:
        from gi.repository import Gio  # type: ignore

        target_app = app
        if target_app is None:
            default_app = Gio.Application.get_default()
            if default_app is not None and default_app.get_is_registered():
                target_app = default_app
        elif hasattr(target_app, "get_is_registered") and not target_app.get_is_registered():
            target_app = None

        if target_app is not None:
            notif = Gio.Notification.new(title_str)
            notif.set_body(body_str)
            priority = (
                Gio.NotificationPriority.HIGH
                if urgent
                else Gio.NotificationPriority.NORMAL
            )
            notif.set_priority(priority)
            notif.set_icon(Gio.ThemedIcon.new("io.krunbox.Krunbox"))
            target_app.send_notification(nid, notif)
            return True
    except Exception:
        pass

    # 2. Fallback to freedesktop notify-send when an active desktop session is present
    has_session = bool(
        os.environ.get("DISPLAY")
        or os.environ.get("WAYLAND_DISPLAY")
        or os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    )
    if has_session and shutil.which("notify-send"):
        urgency = "critical" if urgent else "normal"
        safe_title = f" {title_str}" if title_str.startswith("-") else title_str
        safe_body = f" {body_str}" if body_str.startswith("-") else body_str
        try:
            res = subprocess.run(
                ["notify-send", "-a", "krunbox", "-u", urgency, safe_title, safe_body],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass

    return False


_SSH_ARG_FLAGS = {
    "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J",
    "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w",
}


def _is_background_tunnel_cmd(tokens: List[str]) -> bool:
    """Return True if an `ssh` argv represents a non-interactive `-N` port-forward tunnel."""
    skip_next = False
    for tok in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if tok == "--":
            break
        if tok == "-N":
            return True
        if tok in _SSH_ARG_FLAGS:
            skip_next = True
            continue
        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 1:
            short_prefix = tok[:2]
            if short_prefix in _SSH_ARG_FLAGS:
                continue
            if tok[1:].isalpha() and "N" in tok[1:]:
                return True
    return False


def has_active_ssh_sessions(sandbox_name: str, ssh_port: int) -> bool:
    """
    Inspect current user's `ssh` processes via `pgrep -u <uid> -a ssh`.
    Ignores background `-N` / `-f -N` port-forward tunnels and returns True
    if any interactive `ssh` command references `sandbox_name` or `str(ssh_port)`.
    """
    clean_name = str(sandbox_name or "").strip()
    try:
        port_int = int(ssh_port)
    except (ValueError, TypeError):
        port_int = 0

    if not clean_name and port_int <= 0:
        return False

    try:
        uid = str(os.getuid())
        res = subprocess.run(
            ["pgrep", "-u", uid, "-a", "ssh"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except Exception:
        return False

    if res.returncode != 0 or not (res.stdout or "").strip():
        return False

    name_re = (
        re.compile(rf"(?<![a-zA-Z0-9_.-]){re.escape(clean_name)}(?![a-zA-Z0-9_.-])")
        if clean_name
        else None
    )
    port_re = (
        re.compile(rf"(?<!\d){re.escape(str(port_int))}(?!\d)")
        if port_int > 0
        else None
    )

    for raw_line in res.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        cmdline = parts[1].strip()
        if not cmdline:
            continue

        try:
            tokens = shlex.split(cmdline)
        except ValueError:
            tokens = cmdline.split()

        if not tokens:
            continue
        if os.path.basename(tokens[0]) != "ssh":
            continue
        if _is_background_tunnel_cmd(tokens):
            continue

        if name_re is not None and name_re.search(cmdline):
            return True
        if port_re is not None and port_re.search(cmdline):
            return True

    return False


def run_with_completion_notification(
    sandbox_name: str,
    cmd_display: str,
    runner: Callable[[], int],
    app=None,
) -> int:
    """
    Execute `runner()`, measure wall-clock duration, dispatch a desktop completion
    notification with exit status and formatted duration, and return the exit code.
    """
    start_mono = time.monotonic()
    rc = int(runner())
    elapsed = max(0.0, time.monotonic() - start_mono)
    dur_str = _format_duration(elapsed)

    clean_cmd = str(cmd_display or "").strip() or "command"
    if len(clean_cmd) > 80:
        clean_cmd = clean_cmd[:77] + "..."

    if rc == 0:
        title = f"Command Completed: {sandbox_name}"
        body = f"'{clean_cmd}' finished in {dur_str} (exit code 0)."
    else:
        title = f"Command Failed ({rc}): {sandbox_name}"
        body = f"'{clean_cmd}' exited with code {rc} after {dur_str}."

    send_desktop_notification(
        title=title,
        body=body,
        notification_id=f"exec-{sandbox_name}-{int(time.time() * 1000)}",
        urgent=(rc != 0),
        app=app,
    )
    return rc


class GuardrailMonitor:
    """
    Stateful monitor evaluating memory pressure, blocked egress spikes,
    AI token/cost budgets, and idle auto-pause / auto-stop timers across sandboxes.
    """

    def __init__(
        self,
        cooldown_seconds: float = 300.0,
        idle_cpu_threshold: float = 1.0,
        mem_pressure_threshold: float = 90.0,
        blocked_spike_threshold: int = 5,
        ssh_checker: Optional[Callable[[str, int], bool]] = None,
    ):
        self.cooldown_seconds: float = float(cooldown_seconds)
        self.idle_cpu_threshold: float = float(idle_cpu_threshold)
        self.mem_pressure_threshold: float = float(mem_pressure_threshold)
        self.blocked_spike_threshold: int = int(blocked_spike_threshold)
        self._custom_ssh_checker = ssh_checker

        self._last_alert_ts: Dict[Tuple[str, str], float] = {}
        self._idle_since: Dict[str, float] = {}
        self._last_blocked_counts: Dict[str, Tuple[float, int]] = {}

    def _ssh_checker(self, sandbox_name: str, ssh_port: int) -> bool:
        if self._custom_ssh_checker is not None:
            return self._custom_ssh_checker(sandbox_name, ssh_port)
        return has_active_ssh_sessions(sandbox_name, ssh_port)

    def _can_emit_alert(
        self,
        sandbox_name: str,
        category: str,
        now_ts: float,
        cooldown: Optional[float] = None,
    ) -> bool:
        cd = self.cooldown_seconds if cooldown is None else float(cooldown)
        key = (sandbox_name, category)
        last_ts = self._last_alert_ts.get(key)
        if last_ts is not None and (now_ts - last_ts) < cd:
            return False
        self._last_alert_ts[key] = now_ts
        return True

    def get_idle_seconds(self, sandbox_name: str, now: Optional[float] = None) -> float:
        """Return continuous idle duration in seconds for `sandbox_name` (0.0 if active)."""
        if sandbox_name not in self._idle_since:
            return 0.0
        now_ts = float(now) if now is not None else time.time()
        return max(0.0, now_ts - self._idle_since[sandbox_name])

    def reset_idle(self, sandbox_name: str) -> None:
        """Reset idle tracker for `sandbox_name`, resetting any pending timeout or pre-warning."""
        self._idle_since.pop(sandbox_name, None)
        self._last_alert_ts.pop((sandbox_name, "idle_pre_warning"), None)
        self._last_alert_ts.pop((sandbox_name, "idle_action"), None)

    def run_with_completion_notification(
        self,
        sandbox_name: str,
        cmd_display: str,
        runner: Callable[[], int],
        app=None,
    ) -> int:
        """Convenience wrapper around module-level `run_with_completion_notification`."""
        return run_with_completion_notification(
            sandbox_name=sandbox_name,
            cmd_display=cmd_display,
            runner=runner,
            app=app,
        )

    def _has_recent_blocked_events(
        self,
        egress_traffic_mgr,
        box_name: str,
        blocked_sites: List[dict],
        now_ts: float,
        window_sec: float = 120.0,
    ) -> bool:
        for site in blocked_sites:
            try:
                last_seen = float(site.get("last_seen", 0.0))
                if last_seen > 0.0 and (now_ts - last_seen) <= window_sec:
                    return True
            except (ValueError, TypeError):
                continue

        if hasattr(egress_traffic_mgr, "get_events"):
            try:
                events = egress_traffic_mgr.get_events(box_name, limit=100)
                for ev in events:
                    if getattr(ev, "action", "") == "blocked":
                        ev_ts = float(getattr(ev, "timestamp", 0.0))
                        if ev_ts > 0.0 and (now_ts - ev_ts) <= window_sec:
                            return True
            except Exception:
                pass

        return False

    def evaluate(
        self,
        sandboxes: List,
        egress_traffic_mgr=None,
        telemetry_mgr=None,
        settings: Optional[dict] = None,
        now: Optional[float] = None,
    ) -> Tuple[List[AlertEvent], List[Tuple[str, str, str]]]:
        """
        Evaluate runtime guardrails across `sandboxes`.
        Returns `(alerts, actions_to_run)` where each action tuple is
        `(sandbox_name, action_verb, reason)`.
        """
        cfg = settings or {}
        now_ts = float(now) if now is not None else time.time()

        mem_threshold = float(
            cfg.get(
                "mem_pressure_threshold_percent",
                cfg.get("mem_pressure_threshold", self.mem_pressure_threshold),
            )
        )
        spike_threshold = max(
            1,
            int(
                cfg.get(
                    "blocked_egress_spike_threshold",
                    cfg.get("blocked_spike_threshold", self.blocked_spike_threshold),
                )
            ),
        )
        idle_cpu_limit = float(cfg.get("idle_cpu_threshold", self.idle_cpu_threshold))
        cooldown = float(cfg.get("alert_cooldown_seconds", self.cooldown_seconds))

        alerts: List[AlertEvent] = []
        actions_to_run: List[Tuple[str, str, str]] = []

        for box in sandboxes:
            box_name = str(getattr(box, "name", ""))
            box_status = str(getattr(box, "status", "stopped")).strip().lower()
            if not box_name:
                continue

            # 1. Memory Pressure Guardrail
            mem_pct = float(getattr(box, "mem_percent", 0.0) or 0.0)
            if box_status == "running" and mem_pct >= mem_threshold:
                if self._can_emit_alert(box_name, "memory_pressure", now_ts, cooldown):
                    ram_mib = getattr(box, "ram_mib", 0)
                    ram_detail = f" ({ram_mib} MiB allocated)" if ram_mib else ""
                    alerts.append(
                        AlertEvent(
                            id=f"mem-{box_name}-{int(now_ts)}",
                            timestamp=now_ts,
                            category="memory_pressure",
                            sandbox_name=box_name,
                            title=f"Memory Pressure: {box_name}",
                            body=f"{box_name} is at {mem_pct:.1f}% RAM utilization{ram_detail}.",
                            severity="critical" if mem_pct >= 95.0 else "warning",
                        )
                    )

            # 2. Blocked Exfiltration Domain Spike
            if egress_traffic_mgr is not None:
                try:
                    stats = egress_traffic_mgr.get_domain_stats(box_name) or {}
                except Exception:
                    stats = {}

                blocked = int(stats.get("blocked_requests", 0) or 0)
                sites = stats.get("sites") or []
                blocked_sites = [
                    s for s in sites
                    if isinstance(s, dict) and int(s.get("blocked_count", 0) or 0) > 0
                ]
                blocked_sites.sort(
                    key=lambda s: (
                        -int(s.get("blocked_count", 0) or 0),
                        -float(s.get("last_seen", 0.0) or 0.0),
                    )
                )
                top_domains = [
                    str(s["domain"]) for s in blocked_sites[:3] if s.get("domain")
                ]

                spike_delta = 0
                if box_name not in self._last_blocked_counts:
                    if blocked >= spike_threshold and self._has_recent_blocked_events(
                        egress_traffic_mgr, box_name, blocked_sites, now_ts, window_sec=120.0
                    ):
                        spike_delta = blocked
                    self._last_blocked_counts[box_name] = (now_ts, blocked)
                else:
                    base_ts, prev_blocked = self._last_blocked_counts[box_name]
                    if blocked < prev_blocked:
                        prev_blocked = 0
                        base_ts = now_ts
                        self._last_blocked_counts[box_name] = (base_ts, prev_blocked)

                    if (blocked - prev_blocked) >= spike_threshold:
                        spike_delta = blocked - prev_blocked
                        self._last_blocked_counts[box_name] = (now_ts, blocked)
                    elif (now_ts - base_ts) > 120.0:
                        self._last_blocked_counts[box_name] = (now_ts, blocked)

                if spike_delta >= spike_threshold:
                    if self._can_emit_alert(box_name, "egress_spike", now_ts, cooldown):
                        domains_str = (
                            ", ".join(top_domains) if top_domains else "blocked endpoints"
                        )
                        alerts.append(
                            AlertEvent(
                                id=f"egress-{box_name}-{int(now_ts)}",
                                timestamp=now_ts,
                                category="egress_spike",
                                sandbox_name=box_name,
                                title=f"Blocked Egress Spike: {box_name}",
                                body=(
                                    f"Blocked {spike_delta} outbound requests from {box_name} "
                                    f"(top blocked: {domains_str})."
                                ),
                                severity="critical",
                            )
                        )

            # 3. AI Token / Cost Budget Guardrail
            raw_box_tokens = getattr(box, "max_tokens_budget", None)
            max_tokens = (
                int(raw_box_tokens)
                if (raw_box_tokens is not None and int(raw_box_tokens) > 0)
                else int(cfg.get("default_max_tokens_budget", 0) or 0)
            )
            raw_box_cost = getattr(box, "max_cost_usd_budget", None)
            max_cost = (
                float(raw_box_cost)
                if (raw_box_cost is not None and float(raw_box_cost) > 0.0)
                else float(cfg.get("default_max_cost_usd_budget", 0.0) or 0.0)
            )

            if (max_tokens > 0 or max_cost > 0.0) and telemetry_mgr is not None:
                try:
                    summary = telemetry_mgr.get_summary(box_name) or {}
                except Exception:
                    summary = {}

                total_tokens = int(summary.get("total_tokens", 0) or 0)
                est_cost = float(summary.get("estimated_cost_usd", 0.0) or 0.0)

                tokens_exceeded = max_tokens > 0 and total_tokens >= max_tokens
                cost_exceeded = max_cost > 0.0 and est_cost >= max_cost

                if tokens_exceeded or cost_exceeded:
                    raw_b_act = getattr(box, "budget_exceeded_action", None)
                    if raw_b_act is None or str(raw_b_act).strip() == "":
                        budget_act = str(cfg.get("default_budget_exceeded_action", "alert") or "alert").strip().lower()
                    else:
                        budget_act = str(raw_b_act).strip().lower()

                    if self._can_emit_alert(box_name, "budget_exceeded", now_ts, cooldown):
                        reasons = []
                        if tokens_exceeded:
                            reasons.append(f"{total_tokens:,} / {max_tokens:,} tokens")
                        if cost_exceeded:
                            reasons.append(f"${est_cost:.4f} / ${max_cost:.4f} USD")
                        alerts.append(
                            AlertEvent(
                                id=f"budget-{box_name}-{int(now_ts)}",
                                timestamp=now_ts,
                                category="budget_exceeded",
                                sandbox_name=box_name,
                                title=f"AI Budget Exceeded: {box_name}",
                                body=(
                                    f"{box_name} reached its AI budget limit "
                                    f"({', '.join(reasons)})."
                                ),
                                severity="critical" if budget_act in ("pause", "stop") else "warning",
                            )
                        )

                    if box_status == "running" and budget_act in ("pause", "stop"):
                        actions_to_run.append(
                            (box_name, budget_act, "AI budget guardrail exceeded")
                        )

            # 4. Idle Auto-Pause / Auto-Stop ("Sleep When Idle")
            raw_timeout = getattr(box, "idle_timeout_minutes", None)
            if raw_timeout is None or int(raw_timeout) <= 0:
                timeout_min = int(cfg.get("default_idle_timeout_minutes", 0) or 0)
            else:
                timeout_min = int(raw_timeout)

            raw_idle_act = (
                getattr(box, "idle_action", "")
                or cfg.get("default_idle_action", "stop")
                or "stop"
            )
            idle_act = str(raw_idle_act).strip().lower()
            if idle_act not in ("pause", "stop"):
                idle_act = "stop"

            if box_status == "running" and timeout_min > 0:
                cpu_pct = float(getattr(box, "cpu_percent", 0.0) or 0.0)
                ssh_port = int(getattr(box, "ssh_port", 0) or 0)
                is_idle = (cpu_pct < idle_cpu_limit) and (
                    not self._ssh_checker(box_name, ssh_port)
                )

                if is_idle:
                    if box_name not in self._idle_since:
                        self._idle_since[box_name] = now_ts
                    elapsed = now_ts - self._idle_since[box_name]
                    timeout_sec = timeout_min * 60.0
                    warning_window_sec = min(300.0, max(60.0, timeout_sec / 2.0))

                    # 4a. Pre-timeout warning notification (e.g. 5m before sleep)
                    if (timeout_sec - warning_window_sec) <= elapsed < timeout_sec:
                        rem_sec = max(1.0, timeout_sec - elapsed)
                        rem_min = max(1, int(round(rem_sec / 60.0)))
                        if self._can_emit_alert(box_name, "idle_pre_warning", now_ts, cooldown=warning_window_sec):
                            alerts.append(
                                AlertEvent(
                                    id=f"idle-warn-{box_name}-{int(now_ts)}",
                                    timestamp=now_ts,
                                    category="idle_pre_warning",
                                    sandbox_name=box_name,
                                    title=f"MicroVM Sleeping Soon: {box_name}",
                                    body=(
                                        f"MicroVM '{box_name}' has been idle for {int(elapsed // 60)}m "
                                        f"and will {idle_act} in ~{rem_min} minute{'s' if rem_min != 1 else ''}. "
                                        f"Keep active if still in use."
                                    ),
                                    severity="warning",
                                )
                            )

                    # 4b. Timeout expired -> execute pause or stop action
                    if elapsed >= timeout_sec:
                        self._idle_since.pop(box_name, None)
                        self._last_alert_ts.pop((box_name, "idle_pre_warning"), None)
                        reason = f"Idle for {timeout_min}m (<1% CPU, 0 SSH sessions)"
                        actions_to_run.append((box_name, idle_act, reason))
                        self._last_alert_ts[(box_name, "idle_action")] = now_ts
                        alerts.append(
                            AlertEvent(
                                id=f"idle-{box_name}-{int(now_ts)}",
                                timestamp=now_ts,
                                category="idle_action",
                                sandbox_name=box_name,
                                title=f"Auto-{idle_act.capitalize()}d Idle Box: {box_name}",
                                body=f"{box_name} was {idle_act}d automatically ({reason}).",
                                severity="info",
                            )
                        )
                else:
                    self._idle_since.pop(box_name, None)
                    self._last_alert_ts.pop((box_name, "idle_pre_warning"), None)
            else:
                self._idle_since.pop(box_name, None)
                self._last_alert_ts.pop((box_name, "idle_pre_warning"), None)

        return alerts, actions_to_run
