"""
CLI command handlers for krunbox with corporate presentation styling.
"""

from datetime import datetime
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Tuple
import webbrowser

from ..core.config import DEFAULT_CPUS, DEFAULT_RAM_MIB, NETWORK_PROFILES
from ..core.doctor import Doctor
from ..core.images import ImageManager
from ..core.manager import SandboxManager
from ..core.notifications import run_with_completion_notification, send_desktop_notification
from ..core.sandbox import NetworkPolicy, PortMapping, SandboxInfo
from ..core.secrets import is_valid_env_key, sanitize_env_value
from ..core.templates import SandboxTemplate
from rich.console import Console
from rich.table import Table
from rich import box as rich_box

# Shared Rich Console
_term_cols = max(shutil.get_terminal_size((120, 40)).columns, 120)
_term_lines = max(shutil.get_terminal_size((120, 40)).lines, 40)
console = Console(width=_term_cols, height=_term_lines, highlight=False)

# Corporate Terminal Palette (retained for legacy formatting compatibility)
BOLD = "\033[1m"
DIM = "\033[2m"
BLUE = "\033[34m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RED = "\033[31m"
GRAY = "\033[90m"
RESET = "\033[0m"


def format_status(status: str) -> str:
    s = status.lower()
    if s in ("running", "up"):
        return "[green]● RUNNING[/green]"
    elif s in ("stopped", "exited"):
        return "[dim]○ STOPPED[/dim]"
    elif s == "paused":
        return "[yellow]⏸ PAUSED[/yellow]"
    return f"[red]? {status.upper()}[/red]"


def format_mode(is_persistent: bool) -> str:
    if is_persistent:
        return "[cyan]PERSISTENT[/cyan]"
    return "[dim]EPHEMERAL[/dim]"


def format_net(profile: str) -> str:
    p = profile.lower()
    if p == "full":
        return "[blue]full[/blue]"
    elif p == "ai-only":
        return "[green]ai-only[/green]"
    elif p == "dev-common":
        return "[cyan]dev-common[/cyan]"
    elif p == "offline":
        return "[red]offline[/red]"
    return f"[yellow]{p}[/yellow]"


def parse_kv_pairs(pairs: Optional[List[str]]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not pairs:
        return result
    for pair in pairs:
        if "=" in pair:
            k, v = pair.split("=", 1)
        else:
            k, v = pair, ""
        k = k.strip()
        if is_valid_env_key(k):
            result[k] = sanitize_env_value(v)
    return result


def cmd_list(manager: SandboxManager, all_info: bool = False, json_output: bool = False) -> int:
    sandboxes = manager.list_sandboxes(refresh_podman=True)
    if json_output:
        import json
        print(json.dumps([b.to_dict() for b in sandboxes], indent=2))
        return 0

    if not sandboxes:
        console.print("[dim]No active or registered sandboxes. Launch one with `krunbox run [dir]`[/dim]")
        return 0

    stats = manager.get_stats()

    table = Table(
        box=rich_box.ROUNDED,
        header_style="bold cyan",
        show_header=True,
        pad_edge=True,
    )
    table.add_column("NAME", style="bold white", no_wrap=True)
    table.add_column("STATUS", no_wrap=True)
    table.add_column("MODE", no_wrap=True)
    table.add_column("NETWORK", no_wrap=True)
    table.add_column("SSH PORT", justify="right", no_wrap=True)
    table.add_column("PORTS")
    table.add_column("DIR")
    if all_info:
        table.add_column("RESOURCES", justify="right")

    for box_item in sandboxes:
        port_strs = []
        for p in box_item.published_ports:
            port_strs.append(f"{p.host_port}->{p.guest_port}")
        for p in box_item.dynamic_tunnels:
            port_strs.append(f"{p.host_port}->{p.guest_port}(t)")
        ports_display = ", ".join(port_strs) if port_strs else "-"
        if len(ports_display) > 20:
            ports_display = ports_display[:17] + "..."

        dir_display = box_item.dir_path
        if len(dir_display) > 22:
            dir_display = "..." + dir_display[-19:]

        stat = stats.get(box_item.name, {})
        row = [
            box_item.name,
            format_status(box_item.status),
            format_mode(box_item.is_persistent),
            format_net(box_item.network_policy.profile),
            str(box_item.ssh_port),
            ports_display,
            dir_display,
        ]
        if all_info:
            cpu_val = stat.get('cpu_percent', 0.0)
            row.append(f"{cpu_val:.1f}% CPU ({box_item.cpus}c/{box_item.ram_mib}M)")
        table.add_row(*row)

    console.print()
    console.print(table)
    console.print(f"\n[dim]Active instances: {len(sandboxes)}[/dim]\n")
    return 0


def _resolve_template_and_params(
    manager: SandboxManager,
    template_id: Optional[str],
    image: Optional[str],
    persistent: Optional[bool],
    network_profile: Optional[str],
    allowed_domains: Optional[List[str]],
    denied_domains: Optional[List[str]],
    ports: Optional[List[str]],
    cpus: Optional[int],
    ram_mib: Optional[int],
    protect_git_hooks: Optional[bool],
    protect_git_config: Optional[bool],
    protect_env_files: Optional[bool],
    host_egress_lockdown: Optional[bool],
    idle_timeout_minutes: Optional[int],
    idle_action: Optional[str],
) -> Tuple[Optional[SandboxTemplate], dict]:
    tmpl: Optional[SandboxTemplate] = None
    if template_id:
        tmpl = manager.templates.get_template(template_id)
        if not tmpl:
            print(f"{RED}Error: Template '{template_id}' not found.{RESET}", file=sys.stderr)
            return None, {}

    eff_image = image if image is not None else (tmpl.resolved_image_tag() if tmpl else "localhost/agent-box:latest")
    eff_persistent = persistent if persistent is not None else (tmpl.is_persistent if tmpl else False)
    eff_net_profile = network_profile if network_profile is not None else (tmpl.network_profile if tmpl else "full")

    eff_allowed = list(allowed_domains or [])
    if tmpl and tmpl.allowed_domains and not allowed_domains:
        eff_allowed = list(tmpl.allowed_domains)

    eff_denied = list(denied_domains or [])
    if tmpl and tmpl.denied_domains and not denied_domains:
        eff_denied = list(tmpl.denied_domains)

    eff_ports = list(ports or [])
    if tmpl and tmpl.ports and not ports:
        eff_ports = list(tmpl.ports)

    eff_cpus = cpus if cpus is not None else (tmpl.cpus if tmpl else DEFAULT_CPUS)
    eff_ram = ram_mib if ram_mib is not None else (tmpl.ram_mib if tmpl else DEFAULT_RAM_MIB)

    eff_protect_git_hooks = protect_git_hooks if protect_git_hooks is not None else (tmpl.protect_git_hooks if tmpl else True)
    eff_protect_git_config = protect_git_config if protect_git_config is not None else (tmpl.protect_git_config if tmpl else False)
    eff_protect_env_files = protect_env_files if protect_env_files is not None else (tmpl.protect_env_files if tmpl else False)
    eff_host_egress_lockdown = host_egress_lockdown if host_egress_lockdown is not None else (tmpl.host_egress_lockdown if tmpl else False)

    eff_idle_timeout = idle_timeout_minutes if idle_timeout_minutes is not None else (tmpl.idle_timeout_minutes if tmpl else 0)
    eff_idle_action = idle_action if idle_action is not None else (tmpl.idle_action if tmpl else "stop")

    params = {
        "image": eff_image,
        "persistent": eff_persistent,
        "network_profile": eff_net_profile,
        "allowed_domains": eff_allowed,
        "denied_domains": eff_denied,
        "ports": eff_ports,
        "cpus": eff_cpus,
        "ram_mib": eff_ram,
        "protect_git_hooks": eff_protect_git_hooks,
        "protect_git_config": eff_protect_git_config,
        "protect_env_files": eff_protect_env_files,
        "host_egress_lockdown": eff_host_egress_lockdown,
        "idle_timeout_minutes": eff_idle_timeout,
        "idle_action": eff_idle_action,
        "template_id": tmpl.id if tmpl else None,
    }
    return tmpl, params


def cmd_run(
    manager: SandboxManager,
    dir_path: str,
    name: Optional[str] = None,
    template_id: Optional[str] = None,
    image: Optional[str] = None,
    persistent: Optional[bool] = None,
    network_profile: Optional[str] = None,
    allowed_domains: Optional[List[str]] = None,
    denied_domains: Optional[List[str]] = None,
    ports: Optional[List[str]] = None,
    detach: bool = False,
    cpus: Optional[int] = None,
    ram_mib: Optional[int] = None,
    persist_docker: bool = False,
    protect_git_hooks: Optional[bool] = None,
    protect_git_config: Optional[bool] = None,
    protect_env_files: Optional[bool] = None,
    host_egress_lockdown: Optional[bool] = None,
    idle_timeout_minutes: Optional[int] = None,
    idle_action: Optional[str] = None,
    env_pairs: Optional[List[str]] = None,
    pass_env: Optional[List[str]] = None,
    secret_pairs: Optional[List[str]] = None,
    max_tokens_budget: Optional[int] = None,
    max_cost_usd_budget: Optional[float] = None,
    budget_exceeded_action: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> int:
    resolved_dir = str(Path(dir_path).resolve())
    tmpl, p = _resolve_template_and_params(
        manager=manager,
        template_id=template_id,
        image=image,
        persistent=persistent,
        network_profile=network_profile,
        allowed_domains=allowed_domains,
        denied_domains=denied_domains,
        ports=ports,
        cpus=cpus,
        ram_mib=ram_mib,
        protect_git_hooks=protect_git_hooks,
        protect_git_config=protect_git_config,
        protect_env_files=protect_env_files,
        host_egress_lockdown=host_egress_lockdown,
        idle_timeout_minutes=idle_timeout_minutes,
        idle_action=idle_action,
    )
    if template_id and not tmpl:
        return 1

    net_policy = NetworkPolicy(
        profile=p["network_profile"],
        allowed_domains=p["allowed_domains"],
        denied_domains=p["denied_domains"],
    )

    parsed_env = parse_kv_pairs(env_pairs)
    parsed_secrets = parse_kv_pairs(secret_pairs)

    existing = manager.get_sandbox_for_dir(resolved_dir)
    if existing and (not name or existing.name == name):
        box = existing
        box.is_persistent = p["persistent"]
        box.network_policy = net_policy
        box.cpus = p["cpus"]
        box.ram_mib = p["ram_mib"]
        box.protect_git_hooks = p["protect_git_hooks"]
        box.protect_git_config = p["protect_git_config"]
        box.protect_env_files = p["protect_env_files"]
        box.host_egress_lockdown = p["host_egress_lockdown"]
        box.idle_timeout_minutes = p["idle_timeout_minutes"]
        box.idle_action = p["idle_action"]
        if p.get("template_id"):
            box.template_id = p["template_id"]
        if p["ports"]:
            used = manager._collect_used_host_ports()
            for port_spec in p["ports"]:
                from ..core.ports import parse_port_spec
                mapping = parse_port_spec(port_spec, avoid_ports=used)
                box.published_ports.append(mapping)
                used.add(mapping.host_port)
        if parsed_env:
            box.env_vars.update(parsed_env)
        if pass_env:
            for pk in pass_env:
                if is_valid_env_key(pk) and pk not in box.host_env_passthrough:
                    box.host_env_passthrough.append(pk)
        if max_tokens_budget is not None:
            box.max_tokens_budget = max(0, int(max_tokens_budget))
        if max_cost_usd_budget is not None:
            box.max_cost_usd_budget = max(0.0, float(max_cost_usd_budget))
        if budget_exceeded_action is not None:
            box.budget_exceeded_action = budget_exceeded_action
        manager.save_state()
    else:
        box = manager.create_sandbox(
            dir_path=resolved_dir,
            name=name,
            base_image=p["image"],
            is_persistent=p["persistent"],
            network_policy=net_policy,
            ports=p["ports"],
            cpus=p["cpus"],
            ram_mib=p["ram_mib"],
            persist_docker=persist_docker,
            protect_git_hooks=p["protect_git_hooks"],
            protect_git_config=p["protect_git_config"],
            protect_env_files=p["protect_env_files"],
            host_egress_lockdown=p["host_egress_lockdown"],
            idle_timeout_minutes=p["idle_timeout_minutes"],
            idle_action=p["idle_action"],
            env_vars=parsed_env,
            secret_keys=list(parsed_secrets.keys()),
            host_env_passthrough=pass_env,
            max_tokens_budget=max_tokens_budget or 0,
            max_cost_usd_budget=max_cost_usd_budget or 0.0,
            budget_exceeded_action=budget_exceeded_action or "alert",
            template_id=p.get("template_id"),
        )

    # Store any secrets into vault
    for sk, sv in parsed_secrets.items():
        manager.secrets.set_secret(box.name, sk, sv)
        if sk not in box.secret_keys:
            box.secret_keys.append(sk)
    if parsed_secrets:
        manager.save_state()

    mode_label = "Persistent" if box.is_persistent else "Ephemeral"
    tmpl_tag = f" [Template: {box.template_id}]" if box.template_id else ""
    print(f"{BLUE}▶ Initializing {mode_label} MicroVM '{box.name}'{tmpl_tag} [Net: {box.network_policy.profile}]...{RESET}")
    ok, msg = manager.start_sandbox(box.name, detach=detach, extra_args=extra_args)
    if not ok:
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1

    print(f"{GREEN}✓ {msg}{RESET}")
    print(f"  {BOLD}SSH Target:{RESET} ssh {box.name} (Port {box.ssh_port})")
    for p_map in box.published_ports:
        print(f"  {BOLD}Host Forward:{RESET} http://127.0.0.1:{p_map.host_port} -> guest {p_map.guest_port}")
    if box.protect_git_hooks:
        print(f"  {BOLD}Guardrail:{RESET} .git/hooks read-only protection active")
    if box.host_egress_lockdown:
        print(f"  {BOLD}Guardrail:{RESET} Host-boundary egress lockdown enforced")
    print()
    return 0


def cmd_create(
    manager: SandboxManager,
    dir_path: str,
    name: Optional[str] = None,
    template_id: Optional[str] = None,
    image: Optional[str] = None,
    persistent: Optional[bool] = None,
    network_profile: Optional[str] = None,
    allowed_domains: Optional[List[str]] = None,
    denied_domains: Optional[List[str]] = None,
    ports: Optional[List[str]] = None,
    cpus: Optional[int] = None,
    ram_mib: Optional[int] = None,
    persist_docker: bool = False,
    protect_git_hooks: Optional[bool] = None,
    protect_git_config: Optional[bool] = None,
    protect_env_files: Optional[bool] = None,
    host_egress_lockdown: Optional[bool] = None,
    idle_timeout_minutes: Optional[int] = None,
    idle_action: Optional[str] = None,
    env_pairs: Optional[List[str]] = None,
    pass_env: Optional[List[str]] = None,
    secret_pairs: Optional[List[str]] = None,
    max_tokens_budget: Optional[int] = None,
    max_cost_usd_budget: Optional[float] = None,
    budget_exceeded_action: Optional[str] = None,
) -> int:
    resolved_dir = str(Path(dir_path).resolve())
    tmpl, p = _resolve_template_and_params(
        manager=manager,
        template_id=template_id,
        image=image,
        persistent=persistent,
        network_profile=network_profile,
        allowed_domains=allowed_domains,
        denied_domains=denied_domains,
        ports=ports,
        cpus=cpus,
        ram_mib=ram_mib,
        protect_git_hooks=protect_git_hooks,
        protect_git_config=protect_git_config,
        protect_env_files=protect_env_files,
        host_egress_lockdown=host_egress_lockdown,
        idle_timeout_minutes=idle_timeout_minutes,
        idle_action=idle_action,
    )
    if template_id and not tmpl:
        return 1

    net_policy = NetworkPolicy(
        profile=p["network_profile"],
        allowed_domains=p["allowed_domains"],
        denied_domains=p["denied_domains"],
    )

    parsed_env = parse_kv_pairs(env_pairs)
    parsed_secrets = parse_kv_pairs(secret_pairs)

    box = manager.create_sandbox(
        dir_path=resolved_dir,
        name=name,
        base_image=p["image"],
        is_persistent=p["persistent"],
        network_policy=net_policy,
        ports=p["ports"],
        cpus=p["cpus"],
        ram_mib=p["ram_mib"],
        persist_docker=persist_docker,
        protect_git_hooks=p["protect_git_hooks"],
        protect_git_config=p["protect_git_config"],
        protect_env_files=p["protect_env_files"],
        host_egress_lockdown=p["host_egress_lockdown"],
        idle_timeout_minutes=p["idle_timeout_minutes"],
        idle_action=p["idle_action"],
        env_vars=parsed_env,
        secret_keys=list(parsed_secrets.keys()),
        host_env_passthrough=pass_env,
        max_tokens_budget=max_tokens_budget or 0,
        max_cost_usd_budget=max_cost_usd_budget or 0.0,
        budget_exceeded_action=budget_exceeded_action or "alert",
        template_id=p.get("template_id"),
    )

    for sk, sv in parsed_secrets.items():
        manager.secrets.set_secret(box.name, sk, sv)

    print(f"Registered sandbox '{box.name}' (Mode: {'Persistent' if box.is_persistent else 'Ephemeral'}, SSH: {box.ssh_port})")
    return 0


def _merge_network_policy(
    current: NetworkPolicy,
    profile: Optional[str] = None,
    allow: Optional[List[str]] = None,
    remove_allow: Optional[List[str]] = None,
    clear_allow: bool = False,
    deny: Optional[List[str]] = None,
    remove_deny: Optional[List[str]] = None,
    clear_deny: bool = False,
) -> Optional[NetworkPolicy]:
    has_net_args = any([
        profile is not None,
        bool(allow),
        bool(remove_allow),
        clear_allow,
        bool(deny),
        bool(remove_deny),
        clear_deny,
    ])
    if not has_net_args:
        return None

    new_profile = profile.lower() if profile else current.profile
    new_allowed = [] if clear_allow else list(current.allowed_domains)
    if remove_allow:
        rem_set = {d.strip().lower().rstrip(".") for d in remove_allow if d and d.strip()}
        new_allowed = [d for d in new_allowed if d.strip().lower().rstrip(".") not in rem_set]
    if allow:
        for d in allow:
            clean = d.strip().lower().rstrip(".")
            if clean and clean not in new_allowed:
                new_allowed.append(clean)

    new_denied = [] if clear_deny else list(current.denied_domains)
    if remove_deny:
        rem_d_set = {d.strip().lower().rstrip(".") for d in remove_deny if d and d.strip()}
        new_denied = [d for d in new_denied if d.strip().lower().rstrip(".") not in rem_d_set]
    if deny:
        for d in deny:
            clean = d.strip().lower().rstrip(".")
            if clean and clean not in new_denied:
                new_denied.append(clean)

    return NetworkPolicy(
        profile=new_profile,
        allowed_domains=new_allowed,
        denied_domains=new_denied,
    )


def cmd_edit(
    manager: SandboxManager,
    name: str,
    new_name: Optional[str] = None,
    cpus: Optional[int] = None,
    ram_mib: Optional[int] = None,
    network: Optional[str] = None,
    allow: Optional[List[str]] = None,
    remove_allow: Optional[List[str]] = None,
    clear_allow: bool = False,
    deny: Optional[List[str]] = None,
    remove_deny: Optional[List[str]] = None,
    clear_deny: bool = False,
    protect_git_hooks: Optional[bool] = None,
    protect_git_config: Optional[bool] = None,
    protect_env_files: Optional[bool] = None,
    host_egress_lockdown: Optional[bool] = None,
    idle_timeout_minutes: Optional[int] = None,
    idle_action: Optional[str] = None,
    env_pairs: Optional[List[str]] = None,
    unset_env: Optional[List[str]] = None,
    pass_env: Optional[List[str]] = None,
    unset_pass_env: Optional[List[str]] = None,
    secret_pairs: Optional[List[str]] = None,
    unset_secret: Optional[List[str]] = None,
    max_tokens_budget: Optional[int] = None,
    max_cost_usd_budget: Optional[float] = None,
    budget_exceeded_action: Optional[str] = None,
) -> int:
    box = manager.get_sandbox(name)
    if not box:
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1

    target_policy = _merge_network_policy(
        box.network_policy,
        profile=network,
        allow=allow,
        remove_allow=remove_allow,
        clear_allow=clear_allow,
        deny=deny,
        remove_deny=remove_deny,
        clear_deny=clear_deny,
    )

    # Process env and secret additions / deletions
    target_env = dict(box.env_vars)
    if env_pairs:
        target_env.update(parse_kv_pairs(env_pairs))
    if unset_env:
        for k in unset_env:
            target_env.pop(k.strip(), None)

    target_pass = list(box.host_env_passthrough)
    if pass_env:
        for pk in pass_env:
            clean_pk = pk.strip()
            if is_valid_env_key(clean_pk) and clean_pk not in target_pass:
                target_pass.append(clean_pk)
    if unset_pass_env:
        target_pass = [p for p in target_pass if p not in unset_pass_env]

    target_secret_keys = list(box.secret_keys)
    secrets_updated = False
    if secret_pairs:
        parsed_sec = parse_kv_pairs(secret_pairs)
        for sk, sv in parsed_sec.items():
            manager.secrets.set_secret(box.name, sk, sv)
            if sk not in target_secret_keys:
                target_secret_keys.append(sk)
            secrets_updated = True
    if unset_secret:
        for sk in unset_secret:
            clean_sk = sk.strip()
            manager.secrets.delete_secret(box.name, clean_sk)
            if clean_sk in target_secret_keys:
                target_secret_keys.remove(clean_sk)
            secrets_updated = True

    ok, msg, updated = manager.update_sandbox(
        box.name,
        new_name=new_name,
        cpus=cpus,
        ram_mib=ram_mib,
        network_policy=target_policy,
        protect_git_hooks=protect_git_hooks,
        protect_git_config=protect_git_config,
        protect_env_files=protect_env_files,
        host_egress_lockdown=host_egress_lockdown,
        idle_timeout_minutes=idle_timeout_minutes,
        idle_action=idle_action,
        env_vars=target_env if (env_pairs or unset_env) else None,
        secret_keys=target_secret_keys if (secret_pairs or unset_secret) else None,
        host_env_passthrough=target_pass if (pass_env or unset_pass_env) else None,
        max_tokens_budget=max_tokens_budget,
        max_cost_usd_budget=max_cost_usd_budget,
        budget_exceeded_action=budget_exceeded_action,
        secrets_updated=secrets_updated,
    )
    if not ok or updated is None:
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1

    print(f"{GREEN}✓ {msg}{RESET}")
    print(f"  {BOLD}Sandbox:{RESET}   {updated.name} ({updated.status.upper()})")
    print(f"  {BOLD}Hardware:{RESET}  {updated.cpus} vCPUs / {updated.ram_mib} MiB RAM")
    print(f"  {BOLD}Network:{RESET}   {updated.network_policy.profile} (+{len(updated.network_policy.allowed_domains)} custom allow, -{len(updated.network_policy.denied_domains)} deny)")
    print(f"  {BOLD}SSH Port:{RESET}  {updated.ssh_port}")
    if updated.idle_timeout_minutes > 0:
        print(f"  {BOLD}Idle Sleep:{RESET} {updated.idle_timeout_minutes}m ({updated.idle_action})")
    print()
    return 0


def cmd_start(manager: SandboxManager, name: str, detach: bool = True) -> int:
    box = manager.get_sandbox(name)
    if not box:
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1
    ok, msg = manager.start_sandbox(box.name, detach=detach)
    if not ok:
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1
    print(f"{GREEN}✓ {msg}{RESET}")
    return 0


def cmd_stop(manager: SandboxManager, name: str) -> int:
    ok, msg = manager.stop_sandbox(name)
    if not ok:
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1
    print(f"{GREEN}✓ {msg}{RESET}")
    return 0


def cmd_pause(manager: SandboxManager, name: str) -> int:
    ok, msg = manager.pause_sandbox(name)
    if not ok:
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1
    print(f"{GREEN}✓ {msg}{RESET}")
    return 0


def cmd_unpause(manager: SandboxManager, name: str) -> int:
    ok, msg = manager.unpause_sandbox(name)
    if not ok:
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1
    print(f"{GREEN}✓ {msg}{RESET}")
    return 0


def cmd_restart(manager: SandboxManager, name: str) -> int:
    ok, msg = manager.restart_sandbox(name)
    if not ok:
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1
    print(f"{GREEN}✓ {msg}{RESET}")
    return 0


def cmd_recreate(
    manager: SandboxManager,
    name: str,
    pull: bool = True,
    wipe_volumes: bool = True,
    yes: bool = False,
) -> int:
    """Recreate a sandbox (wipe container/volumes and rebuild with same configuration)."""
    if not yes:
        try:
            ans = input(
                f"Are you sure you want to recreate sandbox '{name}'? "
                f"This wipes all container data and rebuilds it with the same settings. [y/N]: "
            )
        except (EOFError, KeyboardInterrupt):
            print("\nRecreation cancelled.")
            return 0
        if ans.strip().lower() not in ("y", "yes"):
            print("Recreation cancelled.")
            return 0

    ok, msg = manager.recreate_sandbox(
        name,
        pull_image=pull,
        wipe_volumes=wipe_volumes,
        start_after=True,
    )
    if not ok:
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1
    print(f"{GREEN}✓ {msg}{RESET}")
    return 0


def cmd_rm(manager: SandboxManager, name: str, volumes: bool = False) -> int:
    ok, msg = manager.delete_sandbox(name, delete_volumes=volumes)
    if not ok:
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1
    print(f"{GREEN}✓ {msg}{RESET}")
    return 0


def cmd_ssh(manager: SandboxManager, name_or_dir: Optional[str] = None, open_terminal: bool = False) -> int:
    if name_or_dir:
        box = manager.get_sandbox(name_or_dir) or manager.get_sandbox_for_dir(name_or_dir)
    else:
        box = manager.get_sandbox_for_dir(os.getcwd())

    if not box:
        print(f"{RED}Error: No sandbox found for target.{RESET}", file=sys.stderr)
        return 1

    if box.status != "running":
        print(f"{YELLOW}Starting stopped sandbox '{box.name}'...{RESET}")
        ok, msg = manager.start_sandbox(box.name, detach=True)
        if not ok:
            print(f"{RED}Error starting sandbox:{RESET} {msg}", file=sys.stderr)
            return 1

    if open_terminal:
        from ..core.ssh import launch_ssh_terminal, wait_for_ssh_ready, is_ssh_ready
        if not is_ssh_ready("127.0.0.1", box.ssh_port, timeout=0.2):
            wait_for_ssh_ready("127.0.0.1", box.ssh_port, max_wait=3.0, poll_interval=0.25)
        ok, msg = launch_ssh_terminal(box.name)
        if ok:
            print(f"{GREEN}✓ {msg}{RESET}")
            return 0
        else:
            print(f"{YELLOW}Notice: {msg}{RESET}")
            return subprocess.run(["ssh", box.name]).returncode

    from ..core.ssh import wait_for_ssh_ready, is_ssh_ready
    if not is_ssh_ready("127.0.0.1", box.ssh_port, timeout=0.2):
        wait_for_ssh_ready("127.0.0.1", box.ssh_port, max_wait=3.0, poll_interval=0.25)
    return subprocess.run(["ssh", box.name]).returncode


def cmd_code(manager: SandboxManager, name: str, ide_key: str = "vscode", remote_path: str = "/workspace") -> int:
    box = manager.get_sandbox(name)
    if not box:
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1

    if box.status != "running":
        print(f"{YELLOW}Resuming sandbox '{box.name}'...{RESET}")
        ok, msg = manager.start_sandbox(box.name, detach=True)
        if not ok:
            print(f"{RED}Error starting sandbox:{RESET} {msg}", file=sys.stderr)
            return 1

    from ..core.ide import launch_ide
    ok, msg = launch_ide(box.name, ide_key=ide_key, remote_path=remote_path, ssh_port=box.ssh_port)
    if ok:
        print(f"{GREEN}✓ {msg}{RESET}")
        return 0
    else:
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1


def cmd_exec(manager: SandboxManager, name: str, command: List[str], notify: bool = False) -> int:
    box = manager.get_sandbox(name)
    if not box:
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1

    if box.status != "running":
        print(f"{RED}Error: Sandbox '{box.name}' is not running.{RESET}", file=sys.stderr)
        return 1

    from ..core.ssh import wait_for_ssh_ready, is_ssh_ready
    if not is_ssh_ready("127.0.0.1", box.ssh_port, timeout=0.2):
        wait_for_ssh_ready("127.0.0.1", box.ssh_port, max_wait=3.0, poll_interval=0.25)
    cmd = ["ssh", box.name, "--"] + command
    if notify:
        def runner() -> int:
            return subprocess.run(cmd).returncode
        return run_with_completion_notification(box.name, " ".join(command), runner)

    return subprocess.run(cmd).returncode


def cmd_diff(manager: SandboxManager, name: str, rel_file: Optional[str] = None, stat_only: bool = False, json_output: bool = False) -> int:
    box = manager.get_sandbox(name)
    if not box:
        if json_output:
            import json
            print(json.dumps({"error": f"Sandbox '{name}' not found"}, indent=2))
            return 1
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1

    changes = manager.snapshots.list_changes(box.name, box.dir_path)
    if json_output:
        import json
        payload = {
            "sandbox": box.name,
            "changes": [c.to_dict() for c in changes],
        }
        if rel_file:
            payload["diff"] = manager.snapshots.get_file_diff(box.name, box.dir_path, rel_file)
        print(json.dumps(payload, indent=2))
        return 0

    if not changes:
        console.print("[green]✓ No modifications detected. Workspace matches pre-run baseline.[/green]")
        return 0

    console.print(f"\n[bold]Workspace Changes for '{box.name}':[/bold]")
    table = Table(box=rich_box.ROUNDED, header_style="bold cyan")
    table.add_column("STATUS", justify="center", no_wrap=True)
    table.add_column("FILE", style="bold white")
    table.add_column("DIFF STATS", justify="right")

    for ch in changes:
        status_disp = {
            "modified": "[yellow]M[/yellow]",
            "added": "[green]A[/green]",
            "deleted": "[red]D[/red]",
            "renamed": "[cyan]R[/cyan]",
        }.get(ch.status, ch.status)
        diff_stats = f"[green]+{ch.additions}[/green] / [red]-{ch.deletions}[/red]"
        table.add_row(f"[{status_disp}]", ch.path, diff_stats)

    console.print(table)

    if stat_only:
        console.print()
        return 0

    if rel_file:
        diff_text = manager.snapshots.get_file_diff(box.name, box.dir_path, rel_file)
        if diff_text:
            console.print(f"\n[bold]Diff for {rel_file}:[/bold]\n{diff_text}")
        else:
            console.print(f"\n[dim]No diff for {rel_file}.[/dim]")
    else:
        console.print(f"\n[dim]Use `krunbox diff {box.name} <file>` to inspect unified diff for a single file.[/dim]\n")
    return 0


def cmd_rollback(manager: SandboxManager, name: str, rel_file: Optional[str] = None, accept: bool = False) -> int:
    box = manager.get_sandbox(name)
    if not box:
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1

    if accept:
        ok, msg = manager.snapshots.accept_changes(box.name, box.dir_path)
        if ok:
            print(f"{GREEN}✓ {msg}{RESET}")
            return 0
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1

    if rel_file:
        ok, msg = manager.snapshots.revert_file(box.name, box.dir_path, rel_file)
        if ok:
            print(f"{GREEN}✓ {msg}{RESET}")
            return 0
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1

    ok, msg = manager.snapshots.rollback_all(box.name, box.dir_path)
    if ok:
        print(f"{GREEN}✓ {msg}{RESET}")
        return 0
    print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
    return 1


def cmd_snapshot(manager: SandboxManager, name: str) -> int:
    box = manager.get_sandbox(name)
    if not box:
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1
    ok, msg, _ = manager.snapshots.create_snapshot(box.name, box.dir_path)
    if ok:
        print(f"{GREEN}✓ {msg}{RESET}")
        return 0
    print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
    return 1


def cmd_templates(
    manager: SandboxManager,
    action: str = "list",
    target: Optional[str] = None,
    from_sandbox: Optional[str] = None,
    description: str = "",
) -> int:
    clean_action = (action or "list").lower()
    if clean_action in ("list", "ls"):
        tmpls = manager.templates.list_templates()
        table = Table(box=rich_box.ROUNDED, header_style="bold cyan")
        table.add_column("ID", style="bold white", no_wrap=True)
        table.add_column("NAME")
        table.add_column("TYPE", no_wrap=True)
        table.add_column("CPUS/RAM", justify="right", no_wrap=True)
        table.add_column("NETWORK", no_wrap=True)
        table.add_column("PORTS")
        for t in tmpls:
            type_tag = "[blue]BUILTIN[/blue]" if t.builtin else "[cyan]CUSTOM[/cyan]"
            hw = f"{t.cpus}c / {t.ram_mib}m"
            ports_str = ", ".join(t.ports) if t.ports else "-"
            table.add_row(t.id, t.name, type_tag, hw, t.network_profile, ports_str)
        console.print()
        console.print(table)
        console.print(f"\n[dim]Use `krunbox run --template <id>` to launch a sandbox from a preset.[/dim]\n")
        return 0

    if clean_action == "save":
        if not target:
            print(f"{RED}Error: Must provide template ID to save.{RESET}", file=sys.stderr)
            return 1
        if not from_sandbox:
            print(f"{RED}Error: Must provide --from-sandbox <name>.{RESET}", file=sys.stderr)
            return 1
        box = manager.get_sandbox(from_sandbox)
        if not box:
            print(f"{RED}Error: Source sandbox '{from_sandbox}' not found.{RESET}", file=sys.stderr)
            return 1

        tmpl = SandboxTemplate(
            id=target,
            name=target,
            description=description or f"Preset saved from {box.name}",
            builtin=False,
            base_image=box.base_image,
            cpus=box.cpus,
            ram_mib=box.ram_mib,
            is_persistent=box.is_persistent,
            network_profile=box.network_policy.profile,
            allowed_domains=list(box.network_policy.allowed_domains),
            denied_domains=list(box.network_policy.denied_domains),
            ports=[str(p.guest_port) for p in box.published_ports],
            protect_git_hooks=box.protect_git_hooks,
            protect_git_config=box.protect_git_config,
            protect_env_files=box.protect_env_files,
            host_egress_lockdown=box.host_egress_lockdown,
            idle_timeout_minutes=box.idle_timeout_minutes,
            idle_action=box.idle_action,
        )
        saved = manager.templates.save_custom_template(tmpl)
        print(f"{GREEN}✓ Saved custom template '{saved.id}'.{RESET}")
        return 0

    if clean_action in ("delete", "rm"):
        if not target:
            print(f"{RED}Error: Must provide template ID to delete.{RESET}", file=sys.stderr)
            return 1
        if manager.templates.delete_custom_template(target):
            print(f"{GREEN}✓ Deleted custom template '{target}'.{RESET}")
            return 0
        print(f"{RED}Error: Could not delete template '{target}' (built-in templates cannot be deleted).{RESET}", file=sys.stderr)
        return 1

    return 0


def cmd_secret(
    manager: SandboxManager,
    action: str,
    name: str,
    key: Optional[str] = None,
    value: Optional[str] = None,
) -> int:
    box = manager.get_sandbox(name)
    if not box:
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1

    clean_act = action.lower()
    if clean_act in ("list", "ls"):
        keys = manager.secrets.list_secret_keys(box.name, known_keys=box.secret_keys)
        console.print(f"\n[bold]Scoped Secret Vault for '{box.name}':[/bold]")
        if not keys:
            console.print("  [dim]No scoped secrets stored in vault.[/dim]\n")
            return 0
        table = Table(box=rich_box.ROUNDED, header_style="bold cyan")
        table.add_column("SECRET KEY", style="bold white")
        table.add_column("VALUE / MASK", style="dim")
        for k in keys:
            stored_val = manager.secrets.get_secret(box.name, k)
            masked = f"{stored_val[:3]}... ({len(stored_val)} chars)" if stored_val and len(stored_val) > 4 else "(masked)"
            table.add_row(k, masked)
        console.print(table)
        console.print()
        return 0

    if clean_act == "set":
        if not key or not is_valid_env_key(key):
            print(f"{RED}Error: Invalid secret key name '{key}'. Must be alphanumeric identifier.{RESET}", file=sys.stderr)
            return 1
        val_to_store = value
        if val_to_store is None:
            if not sys.stdin.isatty():
                val_to_store = sys.stdin.read().rstrip("\r\n")
            else:
                import getpass
                val_to_store = getpass.getpass(f"Enter secret value for '{key}': ")
        backend = manager.secrets.set_secret(box.name, key, val_to_store)
        if key not in box.secret_keys:
            box.secret_keys.append(key)
            manager.save_state()
        print(f"{GREEN}✓ Stored '{key}' into {backend} for sandbox '{box.name}'.{RESET}")
        return 0

    if clean_act in ("rm", "delete", "unset"):
        if not key:
            print(f"{RED}Error: Must provide secret key name to delete.{RESET}", file=sys.stderr)
            return 1
        manager.secrets.delete_secret(box.name, key)
        if key in box.secret_keys:
            box.secret_keys.remove(key)
            manager.save_state()
        print(f"{GREEN}✓ Removed secret '{key}' from vault for '{box.name}'.{RESET}")
        return 0

    return 0


def cmd_idle_check(manager: SandboxManager, notify: bool = False) -> int:
    alerts, executed = manager.evaluate_guardrails()
    print(f"\n{BOLD}krunbox Guardrail & Idle Check Evaluation:{RESET}")
    print("─" * 60)
    if not alerts and not executed:
        print(f"  {GREEN}✓ All guardrails within nominal operating thresholds. No actions taken.{RESET}\n")
        return 0

    for alert in alerts:
        sev_color = RED if alert.severity == "critical" else YELLOW
        print(f"  [{sev_color}{alert.severity.upper()}{RESET}] {alert.title}: {alert.body}")
        if notify:
            send_desktop_notification(alert.title, alert.body, urgent=(alert.severity == "critical"))

    for box_name, action_verb, reason in executed:
        print(f"  {CYAN}Action Executed:{RESET} {action_verb.upper()} '{box_name}' ({reason})")

    print()
    return 0


def cmd_forward(manager: SandboxManager, name: str, spec: str) -> int:
    box = manager.get_sandbox(name)
    if not box:
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1

    try:
        parts = spec.split(":")
        if len(parts) == 1:
            guest_port = int(parts[0])
            host_port = None
        elif len(parts) == 2:
            host_port = int(parts[0])
            guest_port = int(parts[1])
        else:
            print(f"{RED}Invalid port format. Use GUEST or HOST:GUEST.{RESET}", file=sys.stderr)
            return 1
    except ValueError:
        print(f"{RED}Invalid port format. Port numbers must be valid integers.{RESET}", file=sys.stderr)
        return 1

    ok, msg, mapping = manager.forward_port(box.name, guest_port=guest_port, host_port=host_port)
    if not ok:
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1

    print(f"{GREEN}✓ {msg}{RESET}")
    print(f"  {CYAN}Live URL:{RESET} http://127.0.0.1:{mapping.host_port}")
    return 0


def cmd_unforward(manager: SandboxManager, name: str, guest_port: int) -> int:
    ok, msg = manager.unforward_port(name, guest_port=guest_port)
    if not ok:
        print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
        return 1
    print(f"{GREEN}✓ {msg}{RESET}")
    return 0


def cmd_ports(manager: SandboxManager, name: str, json_output: bool = False) -> int:
    box = manager.get_sandbox(name)
    if not box:
        if json_output:
            import json
            print(json.dumps({"error": f"Sandbox '{name}' not found"}, indent=2))
            return 1
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1

    if json_output:
        import json
        payload = {
            "sandbox": box.name,
            "ssh_port": box.ssh_port,
            "published_ports": [p.to_dict() for p in box.published_ports],
            "dynamic_tunnels": [p.to_dict() for p in box.dynamic_tunnels],
        }
        print(json.dumps(payload, indent=2))
        return 0

    console.print(f"\n[bold]Port Configurations for {box.name}:[/bold]")
    console.print(f"  SSH Management: 127.0.0.1:{box.ssh_port} -> guest 2222")

    if box.published_ports or box.dynamic_tunnels:
        table = Table(box=rich_box.ROUNDED, header_style="bold cyan")
        table.add_column("TYPE", style="bold white")
        table.add_column("HOST PORT", justify="right")
        table.add_column("GUEST PORT", justify="right")
        table.add_column("DETAILS")
        for p in box.published_ports:
            table.add_row("Static (Podman)", str(p.host_port), str(p.guest_port), f"http://127.0.0.1:{p.host_port} -> guest {p.guest_port}")
        for p in box.dynamic_tunnels:
            pid_str = f" [PID {p.tunnel_pid}]" if p.tunnel_pid else ""
            table.add_row("Dynamic Tunnel", str(p.host_port), str(p.guest_port), f"http://127.0.0.1:{p.host_port} -> guest {p.guest_port}{pid_str}")
        console.print()
        console.print(table)
    else:
        console.print(f"  [dim]No application ports mapped. Use `krunbox forward {box.name} <port>` to expose one.[/dim]")
    console.print()
    return 0


def cmd_network(
    manager: SandboxManager,
    name: str,
    allow: Optional[List[str]] = None,
    deny: Optional[List[str]] = None,
    profile: Optional[str] = None,
    remove_allow: Optional[List[str]] = None,
    remove_deny: Optional[List[str]] = None,
    show_traffic: bool = False,
) -> int:
    box = manager.get_sandbox(name)
    if not box:
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1

    target_policy = _merge_network_policy(
        box.network_policy,
        profile=profile,
        allow=allow,
        remove_allow=remove_allow,
        deny=deny,
        remove_deny=remove_deny,
    )
    if target_policy is not None:
        ok, msg, updated = manager.update_sandbox(box.name, network_policy=target_policy)
        if not ok or updated is None:
            print(f"{RED}Error:{RESET} {msg}", file=sys.stderr)
            return 1
        box = updated
        print(f"{GREEN}✓ Updated network egress policy for '{box.name}'.{RESET}")

    from ..core.network import get_profile_domains
    print(f"\n{BOLD}Network Egress Policy: {box.name}{RESET}")
    print("─" * 60)
    print(f"Profile:        {BOLD}{box.network_policy.profile.upper()}{RESET}")

    target_allowed = get_profile_domains(box.network_policy.profile, box.network_policy.allowed_domains)
    print(f"\n{GREEN}Whitelisted Domains ({len(target_allowed)} total):{RESET}")
    if target_allowed:
        for d in sorted(target_allowed):
            custom_tag = f" {CYAN}(custom allow){RESET}" if d in box.network_policy.allowed_domains else ""
            print(f"  • {d}{custom_tag}")
    else:
        print("  (all outbound traffic permitted if 'full' or none if 'offline')")

    print(f"\n{RED}Blacklisted / Denied Domains ({len(box.network_policy.denied_domains)} total):{RESET}")
    if box.network_policy.denied_domains:
        for d in sorted(box.network_policy.denied_domains):
            print(f"  • {d} {RED}[BLOCKED]{RESET}")
    else:
        print("  (no domains blacklisted)")
    print()

    if show_traffic:
        return cmd_traffic(manager, name=box.name)
    return 0


def cmd_traffic(
    manager: SandboxManager,
    name: Optional[str] = None,
    limit: int = 20,
    clear: bool = False,
    json_output: bool = False,
    export_path: Optional[str] = None,
) -> int:
    """Display corporate outbound domain egress traffic analytics and blocked call audit."""
    target_name: Optional[str] = None
    if name:
        box = manager.get_sandbox(name)
        target_name = box.name if box else name

    if clear:
        manager.egress_traffic.clear_logs(sandbox_name=target_name)
        scope = f"for '{target_name}'" if target_name else "across all sandboxes"
        if json_output:
            import json
            print(json.dumps({"status": "cleared", "scope": target_name}, indent=2))
            return 0
        print(f"{GREEN}✓ Cleared egress traffic logs {scope}.{RESET}")
        return 0

    if export_path:
        ok, msg = manager.egress_traffic.export_domain_stats(export_path, sandbox_name=target_name)
        if ok:
            if json_output:
                import json
                print(json.dumps({"status": "ok", "message": msg, "path": str(export_path)}, indent=2))
            else:
                print(f"\n{GREEN}✓ {msg}{RESET}\n")
            return 0
        else:
            if json_output:
                import json
                print(json.dumps({"status": "error", "message": msg, "path": str(export_path)}, indent=2), file=sys.stderr)
            else:
                print(f"\n{RED}✗ Export failed: {msg}{RESET}\n", file=sys.stderr)
            return 1

    stats = manager.egress_traffic.get_domain_stats(sandbox_name=target_name)
    recent = manager.egress_traffic.get_events(sandbox_name=target_name, limit=max(1, limit))

    if json_output:
        import json
        payload = {
            "sandbox": target_name,
            "stats": stats,
            "events": [ev.to_dict() for ev in recent],
        }
        print(json.dumps(payload, indent=2))
        return 0

    title_target = f"for '{target_name}'" if target_name else "Across All Sandboxes"
    console.print(f"\n[bold]Outbound Egress Traffic Audit {title_target}[/bold]")
    console.print("═" * 92)
    console.print(f"  [bold]Total Requests:[/bold]   {stats['total_requests']}")
    console.print(f"  [bold]Unique Sites:[/bold]     {stats['unique_domains']}")
    console.print(f"  [bold]Allowed:[/bold]          [green]{stats['allowed_requests']}[/green]")
    console.print(f"  [bold]Blocked:[/bold]          [red]{stats['blocked_requests']}[/red]")

    if stats["by_category"]:
        console.print(f"\n  [bold]Calls by Category:[/bold]")
        for cat, count in stats["by_category"].items():
            console.print(f"    • {cat:<22}: {count} calls")

    sites = stats["sites"][: max(1, limit)]
    if sites:
        table_sites = Table(box=rich_box.ROUNDED, header_style="bold cyan", title="Top Domain Destinations")
        table_sites.add_column("DOMAIN", style="bold white", no_wrap=True)
        table_sites.add_column("CATEGORY")
        table_sites.add_column("CALLS", justify="right", no_wrap=True)
        table_sites.add_column("ALLOWED", justify="right", no_wrap=True)
        table_sites.add_column("BLOCKED", justify="right", no_wrap=True)
        table_sites.add_column("LAST SEEN")
        for site in sites:
            dt = datetime.fromtimestamp(site["last_seen"]).strftime("%Y-%m-%d %H:%M:%S") if site["last_seen"] > 0 else "-"
            blk_str = f"[red]{site['blocked_count']}[/red]" if site["blocked_count"] > 0 else str(site["blocked_count"])
            table_sites.add_row(
                site["domain"],
                site["category"],
                str(site["total_count"]),
                f"[green]{site['allowed_count']}[/green]",
                blk_str,
                dt,
            )
        console.print()
        console.print(table_sites)
    else:
        console.print(f"\n  [dim]No outbound domain calls recorded yet.[/dim]")

    if recent:
        table_recent = Table(box=rich_box.ROUNDED, header_style="bold cyan", title="Recent Egress Events")
        table_recent.add_column("TIME", no_wrap=True)
        table_recent.add_column("SANDBOX")
        table_recent.add_column("ACTION", no_wrap=True)
        table_recent.add_column("PROTO", no_wrap=True)
        table_recent.add_column("DOMAIN", style="bold white", no_wrap=True)
        table_recent.add_column("REASON")
        for ev in recent:
            tm = datetime.fromtimestamp(ev.timestamp).strftime("%H:%M:%S") if ev.timestamp > 0 else "-"
            act_disp = "[red]BLOCKED[/red]" if ev.action == "blocked" else "[green]ALLOWED[/green]"
            table_recent.add_row(
                tm,
                ev.sandbox_name,
                act_disp,
                ev.protocol,
                ev.domain,
                ev.reason or "-",
            )
        console.print()
        console.print(table_recent)

    console.print()
    return 0


def cmd_open(manager: SandboxManager, name: str, port: Optional[int] = None) -> int:
    box = manager.get_sandbox(name)
    if not box:
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1

    all_ports = box.all_ports
    if not all_ports:
        print(f"{YELLOW}No ports forwarded for '{box.name}'.{RESET}")
        return 1

    target = None
    if port:
        for p in all_ports:
            if p.guest_port == port or p.host_port == port:
                target = p
                break
    else:
        target = all_ports[0]

    if not target:
        print(f"{RED}Port {port} not found on sandbox '{box.name}'.{RESET}", file=sys.stderr)
        return 1

    url = f"http://127.0.0.1:{target.host_port}"
    print(f"{CYAN}Opening {url} in default browser...{RESET}")
    webbrowser.open(url)
    return 0


def cmd_logs(manager: SandboxManager, name: str, tail: int = 100, follow: bool = False) -> int:
    box = manager.get_sandbox(name)
    if not box:
        print(f"{RED}Error: Sandbox '{name}' not found.{RESET}", file=sys.stderr)
        return 1

    if follow:
        cmd = ["podman", "logs", "-f", "--tail", str(tail), box.container_name]
        return subprocess.run(cmd).returncode
    else:
        print(manager.get_logs(box.name, tail=tail))
        return 0


def cmd_stats(manager: SandboxManager, json_output: bool = False) -> int:
    if json_output:
        import json
        print(json.dumps(manager.get_stats(), indent=2))
        return 0
    cmd = ["podman", "stats", "--filter", "label=krunbox=true"]
    return subprocess.run(cmd).returncode


def cmd_api_stats(manager: SandboxManager, name: Optional[str] = None, json_output: bool = False) -> int:
    """Display corporate AI API telemetry audit statistics."""
    summary = manager.telemetry.get_summary(sandbox_name=name)
    recent_calls = manager.telemetry.get_calls(sandbox_name=name, limit=15)

    if json_output:
        import json
        payload = {
            "sandbox": name,
            "summary": summary,
            "recent_calls": [c.to_dict() for c in recent_calls],
        }
        print(json.dumps(payload, indent=2))
        return 0

    title_target = f"for '{name}'" if name else "Across All Sandboxes"
    console.print(f"\n[bold]AI Model Invocation Audit {title_target}[/bold]")
    console.print("═" * 70)
    console.print(f"  [bold]Total API Invocations:[/bold]   {summary['total_calls']}")
    console.print(f"  [bold]Cumulative Tokens:[/bold]       {summary['total_tokens']:,}")
    console.print(f"  [bold]Estimated Spend:[/bold]         ${summary['estimated_cost_usd']:.4f} USD")
    console.print(f"  [bold]Success / Health Rate:[/bold]   {summary['success_rate']}% ({summary['error_count']} errors)")

    if summary["by_provider"]:
        console.print(f"\n  [bold]Invocations by AI Provider:[/bold]")
        for prov, count in summary["by_provider"].items():
            console.print(f"    • {prov:<18}: {count} requests")

    if summary["by_model"]:
        console.print(f"\n  [bold]Invocations by Model Tag:[/bold]")
        for m, count in summary["by_model"].items():
            console.print(f"    • {m:<28}: {count} calls")

    if recent_calls:
        table_calls = Table(box=rich_box.ROUNDED, header_style="bold cyan", title="Recent AI Invocations")
        table_calls.add_column("TIME")
        table_calls.add_column("PROVIDER")
        table_calls.add_column("MODEL", style="bold white")
        table_calls.add_column("STATUS")
        table_calls.add_column("TOKENS", justify="right")
        for c in recent_calls:
            dt = datetime.fromtimestamp(c.timestamp).strftime("%H:%M:%S")
            st_color = "[green]" if c.status_code < 400 else "[red]"
            table_calls.add_row(
                dt,
                c.provider,
                c.model,
                f"{st_color}{c.status_code}[/]",
                str(c.total_tokens),
            )
        console.print()
        console.print(table_calls)

    console.print()
    return 0


def cmd_images(image_mgr: ImageManager, action: str = "list", target: Optional[str] = None, json_output: bool = False, force: bool = False) -> int:
    clean_action = (action or "list").lower().strip()
    if clean_action == "build":
        target_name = target or "all"
        if target_name in ("all", "*"):
            from rich.progress import (
                Progress,
                SpinnerColumn,
                TextColumn,
                BarColumn,
                TaskProgressColumn,
                TimeElapsedColumn,
            )

            console.print("[bold cyan]Building all required base images...[/bold cyan]")
            all_ok = True
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}[/bold cyan]"),
                BarColumn(bar_width=30),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            ) as progress:
                overall = progress.add_task("Preparing builds...", total=4)

                def _progress_cb(target_key: str, line: str):
                    if line.startswith("STEP ") or "-->" in line or "Successfully" in line:
                        short = line[:55] + "..." if len(line) > 55 else line
                        progress.update(
                            overall,
                            description=f"Building [bold white]{target_key}[/bold white] [dim]({short})[/dim]",
                        )

                def _item_complete(target_key: str, ok: bool, msg: str):
                    progress.advance(overall)
                    if ok:
                        console.print(f"  [green]✓[/green] [{target_key}] {msg}")
                    else:
                        console.print(f"  [red]✗[/red] [{target_key}] {msg}")

                results = image_mgr.build_all_images(
                    on_progress=_progress_cb,
                    on_image_complete=_item_complete,
                )

                # Fallback if mock or method returned results without triggering on_image_complete
                if progress.tasks[overall].completed == 0 and results:
                    for t, ok, msg in results:
                        progress.advance(overall)
                        if ok:
                            console.print(f"  [green]✓[/green] [{t}] {msg}")
                        else:
                            console.print(f"  [red]✗[/red] [{t}] {msg}")

                for t, ok, msg in results:
                    if not ok:
                        all_ok = False

                if all_ok:
                    progress.update(overall, description="[bold green]All base images built successfully[/bold green]")
                else:
                    progress.update(overall, description="[bold red]Some base images failed to build[/bold red]")

            return 0 if all_ok else 1

        from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}[/bold cyan]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task(f"Building image target '{target_name}'...", total=None)

            def _step_cb(line: str):
                if line.startswith("STEP ") or "-->" in line or "Successfully" in line:
                    short = line[:60] + "..." if len(line) > 60 else line
                    progress.update(task_id, description=f"Building [bold white]{target_name}[/bold white] [dim]({short})[/dim]")

            ok, msg = image_mgr.build_image(target_name, on_progress=_step_cb)

        if ok:
            console.print(f"[bold green]✓[/bold green] {msg}")
            return 0
        print(f"{RED}Error building image:{RESET} {msg}", file=sys.stderr)
        return 1

    images = image_mgr.list_images()
    if json_output:
        import json
        print(json.dumps(images, indent=2))
        return 0

    if clean_action in ("check", "status"):
        table = Table(box=rich_box.ROUNDED, header_style="bold cyan")
        table.add_column("ID", style="bold white", no_wrap=True)
        table.add_column("STATUS", no_wrap=True)
        table.add_column("AGE", justify="right", no_wrap=True)
        table.add_column("SPEC / REBUILD REASON")
        for img in images:
            if not img["is_present"]:
                st = "[red]MISSING[/red]"
            elif img.get("needs_rebuild"):
                st = "[yellow]OUTDATED[/yellow]"
            else:
                st = "[green]UP-TO-DATE[/green]"
            age_str = f"{img['age_days']}d" if img.get("age_days") is not None else "--"
            reason = img.get("rebuild_reason", "Ready")
            table.add_row(img["id"], st, age_str, reason)
        console.print()
        console.print(table)
        console.print()
        return 0

    table = Table(box=rich_box.ROUNDED, header_style="bold cyan")
    table.add_column("ID", style="bold white", no_wrap=True)
    table.add_column("STATUS", no_wrap=True)
    table.add_column("TAG")
    table.add_column("DESCRIPTION")
    for img in images:
        if not img["is_present"]:
            st = "[dim]AVAILABLE[/dim]"
        elif img.get("needs_rebuild"):
            st = "[yellow]REBUILD[/yellow]"
        else:
            st = "[green]PRESENT[/green]"
        table.add_row(img["id"], st, img["tag"], img["description"])
    console.print()
    console.print(table)
    console.print()
    return 0


def cmd_doctor(json_output: bool = False) -> int:
    doc = Doctor()
    checks = doc.check_all()
    if json_output:
        import json
        print(json.dumps(checks, indent=2))
        return 0
    console.print(f"\n[bold]krunbox System Diagnostics (Fedora 44 / Linux Host)[/bold]")
    console.print("═" * 70)
    all_ok = True
    table = Table(box=rich_box.ROUNDED, header_style="bold cyan")
    table.add_column("STATUS", justify="center", no_wrap=True)
    table.add_column("COMPONENT", style="bold white", no_wrap=True)
    table.add_column("MESSAGE")
    table.add_column("REMEDIATION / FIX")

    for c in checks:
        if c["status"] == "ok":
            pill = "[green]✓ PASS[/green]"
        elif c["status"] == "warn":
            pill = "[yellow]! WARN[/yellow]"
        else:
            pill = "[red]✗ FAIL[/red]"
            all_ok = False
        fix = c.get("remediation") if (c.get("remediation") and c["status"] != "ok") else "-"
        table.add_row(pill, c["component"], c["message"], fix)

    console.print(table)

    if all_ok:
        console.print(f"\n[green]✓ Host environment fully primed for crun-krun microVM acceleration.[/green]\n")
    else:
        console.print(f"\n[yellow]! Some optional microVM capabilities missing. Review recommendations above.[/yellow]\n")
    return 0


def cmd_prune(manager: SandboxManager) -> int:
    count = manager.prune()
    print(f"{GREEN}✓ Pruned {count} stopped ephemeral sandbox(es).{RESET}")
    return 0


def cmd_install_desktop(system: bool = False) -> int:
    from ..core.desktop import install_desktop_integration
    res = install_desktop_integration(system=system)
    if res["success"]:
        print(f"\n{GREEN}✓ Installed {res['files_count']} desktop integration files.{RESET}")
        print(f"  Target: {res['target_base']}")
        print(f"  GNOME App Manager metadata & icon cache refreshed.\n")
        return 0
    print(f"{RED}✗ Desktop integration installation failed.{RESET}\n")
    return 1


def cmd_requests(manager: SandboxManager, sandbox: Optional[str] = None, all_info: bool = False, json_output: bool = False) -> int:
    """List pending or recent permission requests from agents in sandboxes."""
    if all_info and hasattr(manager, "ipc_server") and manager.ipc_server is not None:
        reqs = manager.ipc_server.get_all_requests(sandbox)
    elif hasattr(manager, "list_pending_requests"):
        reqs = manager.list_pending_requests(sandbox)
    elif hasattr(manager, "get_pending_access_requests"):
        reqs = manager.get_pending_access_requests(sandbox)
    else:
        reqs = []

    if json_output:
        import json
        print(json.dumps([r.to_dict() for r in reqs], indent=2))
        return 0

    if not reqs:
        scope = f" for '{sandbox}'" if sandbox else ""
        console.print(f"[dim]No pending agent access requests{scope}.[/dim]\n")
        return 0

    table = Table(box=rich_box.ROUNDED, header_style="bold cyan", title="Agent Access Requests")
    table.add_column("REQUEST ID", style="bold white", no_wrap=True)
    table.add_column("SANDBOX")
    table.add_column("TYPE", no_wrap=True)
    table.add_column("TARGET")
    table.add_column("STATUS", no_wrap=True)
    table.add_column("REASON")

    for r in reqs:
        st = r.status.upper()
        if st == "PENDING":
            st_color = "[yellow]PENDING[/yellow]"
        elif st == "APPROVED":
            st_color = "[green]APPROVED[/green]"
        elif st == "DENIED":
            st_color = "[red]DENIED[/red]"
        else:
            st_color = f"[dim]{st}[/dim]"

        rtype = getattr(r, "request_type", getattr(r, "action", ""))
        if "port" in rtype:
            rtype_str = "[cyan]PORT[/cyan]"
        else:
            rtype_str = "[blue]DOMAIN[/blue]"

        target = str(getattr(r, "target", "") or getattr(r, "domain", "") or getattr(r, "guest_port", ""))
        table.add_row(r.id, r.sandbox_name, rtype_str, target, st_color, r.reason or "")

    console.print()
    console.print(table)
    console.print(f"\n[dim]Use 'krunbox approve <id>' or 'krunbox deny <id> --reason ...' to respond.[/dim]\n")
    return 0


def cmd_clone(manager: SandboxManager, source: str, new_name: str) -> int:
    """Clone an existing sandbox configuration to a new sandbox."""
    ok, msg, box = manager.clone_sandbox(source, new_name)
    if ok:
        print(f"\n{GREEN}✓ {msg}{RESET}")
        if box:
            print(f"  SSH Port: {box.ssh_port}")
            print(f"  Container: {box.container_name}\n")
        return 0
    print(f"\n{RED}✗ Failed to clone sandbox: {msg}{RESET}\n", file=sys.stderr)
    return 1


def cmd_export(manager: SandboxManager, name: str, output: Optional[str] = None) -> int:
    """Export sandbox configuration and snapshot to an archive."""
    out_path = Path(output) if output else Path(f"{name}.tar.gz")
    ok, msg = manager.export_sandbox(name, out_path)
    if ok:
        print(f"\n{GREEN}✓ {msg}{RESET}\n")
        return 0
    print(f"\n{RED}✗ {msg}{RESET}\n", file=sys.stderr)
    return 1


def cmd_import(manager: SandboxManager, archive: str, new_name: Optional[str] = None) -> int:
    """Import a sandbox from an archive."""
    arc_path = Path(archive)
    ok, msg, box = manager.import_sandbox(arc_path, new_name=new_name)
    if ok:
        print(f"\n{GREEN}✓ {msg}{RESET}")
        if box:
            print(f"  Directory: {box.dir_path}")
            print(f"  SSH Port: {box.ssh_port}\n")
        return 0
    print(f"\n{RED}✗ {msg}{RESET}\n", file=sys.stderr)
    return 1


def cmd_daemon(manager: SandboxManager, interval: int = 15, once: bool = False) -> int:
    """Run continuous background daemon evaluating guardrails and idle limits."""
    print(f"{BOLD}krunbox daemon{RESET} starting (evaluating guardrails every {interval}s)...")
    if once:
        alerts = manager.evaluate_guardrails(notify=True)
        print(f"Single pass completed: {len(alerts)} alerts generated.")
        return 0

    import signal
    running = True

    def sig_handler(_sig, _frame):
        nonlocal running
        print("\nShutting down krunbox daemon...")
        running = False

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    while running:
        try:
            alerts = manager.evaluate_guardrails(notify=True)
            for alert in alerts:
                print(f"  [{alert.category.upper()}] {alert.message}")
        except Exception as exc:
            print(f"Daemon error in guardrail cycle: {exc}", file=sys.stderr)

        for _ in range(max(1, interval)):
            if not running:
                break
            time.sleep(1)

    print("krunbox daemon terminated cleanly.")
    return 0


def cmd_completion(shell: str, install: bool = False) -> int:
    """Generate or install shell completion scripts for bash, zsh, fish."""
    from .completion import get_completion_script, install_completion_script
    if install:
        ok, msg = install_completion_script(shell)
        if ok:
            print(f"\n{GREEN}✓ {msg}{RESET}\n")
            return 0
        print(f"\n{RED}✗ {msg}{RESET}\n", file=sys.stderr)
        return 1
    else:
        try:
            script = get_completion_script(shell)
            print(script, end="")
            return 0
        except ValueError as exc:
            print(f"\n{RED}✗ {exc}{RESET}\n", file=sys.stderr)
            return 1


def cmd_approve(manager: SandboxManager, request_id: str) -> int:
    """Approve an in-sandbox agent permission request."""
    ok, msg = manager.approve_access_request(request_id)
    if ok:
        print(f"\n{GREEN}✓ {msg}{RESET}\n")
        return 0
    print(f"\n{RED}✗ Failed to approve request '{request_id}': {msg}{RESET}\n")
    return 1


def cmd_deny(manager: SandboxManager, request_id: str, reason: str = "Denied by operator") -> int:
    """Deny an in-sandbox agent permission request."""
    ok, msg = manager.deny_access_request(request_id, reason=reason)
    if ok:
        print(f"\n{YELLOW}✓ {msg}{RESET}\n")
        return 0
    print(f"\n{RED}✗ Failed to deny request '{request_id}': {msg}{RESET}\n")
    return 1


def cmd_keep_awake(manager: SandboxManager, name: str, indefinite: bool = False, extend_minutes: int = 30) -> int:
    """Reset idle sleep timer or configure sandbox to never sleep."""
    ok, msg = manager.keep_awake(name, indefinite=indefinite, extend_minutes=extend_minutes)
    if ok:
        print(f"\n{GREEN}✓ {msg}{RESET}\n")
        return 0
    print(f"\n{RED}✗ {msg}{RESET}\n")
    return 1


def cmd_ui() -> int:
    from ..ui.app import run_app
    return run_app()
