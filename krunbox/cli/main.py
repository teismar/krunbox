"""
CLI Argument Parser and Entry Point for krunbox.
"""

import argparse
import sys
from ..core.manager import SandboxManager
from ..core.images import ImageManager
from . import commands


def _add_creation_flags(p: argparse.ArgumentParser, include_detach: bool = False) -> None:
    p.add_argument("dir", nargs="?", default=".", help="Workspace host directory")
    p.add_argument("--name", "-n", help="Sandbox identifier")
    p.add_argument("--template", "-T", default=None, help="Apply sandbox profile preset (e.g. locked-down-reviewer, fullstack-web)")
    p.add_argument("--image", "-i", default=None, help="Base container image")
    p.add_argument("-P", "--persistent", action="store_true", default=None, help="Make sandbox persistent across stops")
    p.add_argument("--network", "--net", choices=["full", "ai-only", "dev-common", "offline", "custom"], default=None, help="Network egress policy profile")
    p.add_argument("--allow-domain", "--allow", "--whitelist", action="append", help="Extra domains for custom whitelist")
    p.add_argument("--deny-domain", "--deny", "--blacklist", action="append", help="Extra domains for custom blacklist")
    p.add_argument("-p", "--port", action="append", help="Port forward: GUEST or HOST:GUEST")
    if include_detach:
        p.add_argument("-d", "--detach", action="store_true", help="Run in background")
    p.add_argument("--cpus", type=int, default=None, help="Allocated vCPUs")
    p.add_argument("--ram", type=int, default=None, help="Allocated RAM in MiB")
    p.add_argument("--persist-docker", action="store_true", help="Persist nested DinD volume")
    p.add_argument("--protect-git-hooks", dest="protect_git_hooks", action="store_true", default=None, help="Mount .git/hooks read-only inside /workspace (default)")
    p.add_argument("--no-git-guardrails", "--no-protect-git-hooks", dest="protect_git_hooks", action="store_false", help="Disable read-only .git/hooks mount guardrail")
    p.add_argument("--protect-git-config", dest="protect_git_config", action="store_true", default=None, help="Mount .git/config read-only inside /workspace")
    p.add_argument("--protect-env", dest="protect_env_files", action="store_true", default=None, help="Mask workspace .env / .env.* files read-only")
    p.add_argument("--lock-egress", dest="host_egress_lockdown", action="store_true", default=None, help="Enforce host-boundary egress lockdown and drop guest CAP_NET_ADMIN")
    p.add_argument("--idle-timeout", type=int, default=None, help="Auto-pause/stop after N idle minutes (0 = disabled)")
    p.add_argument("--idle-action", choices=["stop", "pause"], default=None, help="Action when idle timeout triggers")
    p.add_argument("-e", "--env", action="append", default=None, help="Environment variable KEY=VALUE")
    p.add_argument("--pass-env", action="append", default=None, help="Pass host environment variable KEY into microVM")
    p.add_argument("--secret", action="append", default=None, help="Store scoped secret KEY=VALUE in vault and inject into RAM")
    p.add_argument("--max-tokens", type=int, default=None, help="Token budget guardrail threshold (0 = unlimited)")
    p.add_argument("--max-cost", type=float, default=None, help="USD spend budget guardrail threshold (0 = unlimited)")
    p.add_argument("--budget-action", choices=["alert", "pause", "stop"], default=None, help="Action when AI budget threshold is exceeded")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="krunbox",
        description="krunbox - Enterprise Podman & microVM Sandboxing Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Corporate Infrastructure Examples:
  krunbox run .                             # Ephemeral sandbox in current dir (4 CPU / 4 GiB)
  krunbox run . --template locked-down-reviewer -d
  krunbox run . --network ai-only --lock-egress
  krunbox edit my-project --cpus 6 --ram 6144 --idle-timeout 30
  krunbox code my-project --ide vscode      # Open directly in VS Code Remote-SSH
  krunbox diff my-project                   # Inspect workspace diff vs pre-run snapshot
  krunbox rollback my-project               # Revert workspace changes to pre-run snapshot
  krunbox secret set my-project OPENAI_API_KEY sk-...
  krunbox traffic                           # Audit outbound domain calls & blocked sites
  krunbox ui                                # Launch native GTK4 Libadwaita console
"""
    )
    subparsers = parser.add_subparsers(dest="command", help="Available operations")

    # run
    p_run = subparsers.add_parser("run", help="Launch an ephemeral or persistent sandbox")
    _add_creation_flags(p_run, include_detach=True)

    # create
    p_create = subparsers.add_parser("create", help="Register a sandbox without starting")
    _add_creation_flags(p_create, include_detach=False)

    # edit / update / config
    p_edit = subparsers.add_parser("edit", aliases=["update", "config"], help="Edit an existing sandbox's name, CPU/RAM, guardrails, secrets, or network policy")
    p_edit.add_argument("name", help="Existing sandbox identifier")
    p_edit.add_argument("--name", "--rename", dest="new_name", help="Rename sandbox identifier")
    p_edit.add_argument("--cpus", type=int, default=None, help="Update allocated vCPUs (1-128)")
    p_edit.add_argument("--ram", type=int, default=None, help="Update allocated RAM in MiB (512-262144)")
    p_edit.add_argument("--network", "--profile", dest="network", choices=["full", "ai-only", "dev-common", "offline", "custom"], default=None, help="Update egress profile")
    p_edit.add_argument("--allow", "--allow-domain", "--whitelist", dest="allow", action="append", help="Add domain(s) to whitelist")
    p_edit.add_argument("--remove-allow", dest="remove_allow", action="append", help="Remove domain(s) from whitelist")
    p_edit.add_argument("--clear-allow", dest="clear_allow", action="store_true", help="Clear custom whitelist")
    p_edit.add_argument("--deny", "--deny-domain", "--blacklist", dest="deny", action="append", help="Add domain(s) to blacklist")
    p_edit.add_argument("--remove-deny", dest="remove_deny", action="append", help="Remove domain(s) from blacklist")
    p_edit.add_argument("--clear-deny", dest="clear_deny", action="store_true", help="Clear blacklist")
    p_edit.add_argument("--protect-git-hooks", dest="protect_git_hooks", action="store_true", default=None, help="Enable read-only .git/hooks mount")
    p_edit.add_argument("--no-protect-git-hooks", "--no-git-guardrails", dest="protect_git_hooks", action="store_false", help="Disable read-only .git/hooks mount")
    p_edit.add_argument("--protect-git-config", dest="protect_git_config", action="store_true", default=None, help="Enable read-only .git/config mount")
    p_edit.add_argument("--no-protect-git-config", dest="protect_git_config", action="store_false", help="Disable read-only .git/config mount")
    p_edit.add_argument("--protect-env", dest="protect_env_files", action="store_true", default=None, help="Enable read-only .env* masking")
    p_edit.add_argument("--no-protect-env", dest="protect_env_files", action="store_false", help="Disable read-only .env* masking")
    p_edit.add_argument("--lock-egress", dest="host_egress_lockdown", action="store_true", default=None, help="Enable host-boundary egress lockdown")
    p_edit.add_argument("--no-lock-egress", dest="host_egress_lockdown", action="store_false", help="Disable host-boundary egress lockdown")
    p_edit.add_argument("--idle-timeout", type=int, default=None, help="Idle timeout in minutes (0 = disabled)")
    p_edit.add_argument("--no-idle", "--never-sleep", dest="no_idle", action="store_true", help="Disable idle timeout (never sleep)")
    p_edit.add_argument("--idle-action", choices=["stop", "pause"], default=None, help="Idle action ('stop' or 'pause')")
    p_edit.add_argument("-e", "--env", action="append", default=None, help="Set environment variable KEY=VALUE")
    p_edit.add_argument("--unset-env", action="append", default=None, help="Remove environment variable KEY")
    p_edit.add_argument("--pass-env", action="append", default=None, help="Add host environment passthrough KEY")
    p_edit.add_argument("--unset-pass-env", action="append", default=None, help="Remove host environment passthrough KEY")
    p_edit.add_argument("--secret", action="append", default=None, help="Set scoped secret KEY=VALUE")
    p_edit.add_argument("--unset-secret", action="append", default=None, help="Remove scoped secret KEY")
    p_edit.add_argument("--max-tokens", type=int, default=None, help="Update token budget cap (0 = unlimited)")
    p_edit.add_argument("--max-cost", type=float, default=None, help="Update USD cost budget cap (0 = unlimited)")
    p_edit.add_argument("--budget-action", choices=["alert", "pause", "stop"], default=None, help="Action on budget breach")

    # start, stop, pause, unpause, restart, rm
    p_start = subparsers.add_parser("start", help="Start or resume a stopped/paused sandbox")
    p_start.add_argument("name", help="Sandbox name")
    p_start.add_argument("-d", "--detach", action="store_true", default=True, help="Run in background")

    p_stop = subparsers.add_parser("stop", help="Halt a running sandbox")
    p_stop.add_argument("name", help="Sandbox name")

    p_pause = subparsers.add_parser("pause", help="Freeze a running sandbox (podman pause)")
    p_pause.add_argument("name", help="Sandbox name")

    p_unpause = subparsers.add_parser("unpause", aliases=["resume"], help="Resume a paused sandbox (podman unpause)")
    p_unpause.add_argument("name", help="Sandbox name")

    p_restart = subparsers.add_parser("restart", help="Restart a sandbox")
    p_restart.add_argument("name", help="Sandbox name")

    p_recreate = subparsers.add_parser("recreate", help="Recreate a sandbox (wipe container/volumes and rebuild with same configuration)")
    p_recreate.add_argument("name", help="Sandbox name")
    p_recreate.add_argument("--no-pull", dest="pull", action="store_false", default=True, help="Do not pull/rebuild latest image")
    p_recreate.add_argument("--keep-volumes", dest="wipe_volumes", action="store_false", default=True, help="Keep persistent volumes instead of wiping")
    p_recreate.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")

    p_rm = subparsers.add_parser("rm", aliases=["delete"], help="Delete a sandbox")
    p_rm.add_argument("name", help="Sandbox name")
    p_rm.add_argument("-v", "--volumes", action="store_true", help="Also purge persistent storage volumes")

    # list
    p_ls = subparsers.add_parser("list", aliases=["ls", "ps"], help="List sandboxes and telemetry")
    p_ls.add_argument("-a", "--all", action="store_true", help="Display verbose metadata")
    p_ls.add_argument("--json", action="store_true", help="Output in machine-readable JSON format")

    # ssh, connect, code, exec
    p_ssh = subparsers.add_parser("ssh", aliases=["connect"], help="Connect to sandbox terminal via SSH (optional new terminal window)")
    p_ssh.add_argument("name", nargs="?", help="Sandbox identifier")
    p_ssh.add_argument("--terminal", "-t", action="store_true", help="Launch SSH connection in a new graphical terminal window")

    p_code = subparsers.add_parser("code", aliases=["ide"], help="Open sandbox workspace in VS Code, Cursor, Zed, JetBrains, or SFTP")
    p_code.add_argument("name", help="Sandbox identifier")
    p_code.add_argument("--ide", choices=["vscode", "cursor", "zed", "jetbrains", "sftp", "terminal"], default="vscode", help="Target IDE / file manager")
    p_code.add_argument("--path", default="/workspace", help="Remote path inside microVM (default: /workspace)")

    p_exec = subparsers.add_parser("exec", help="Execute command inside sandbox")
    p_exec.add_argument("-N", "--notify", action="store_true", help="Send desktop notification upon command completion")
    p_exec.add_argument("name", help="Sandbox name")
    p_exec.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to execute")

    # workspace diff, rollback, snapshot
    p_diff = subparsers.add_parser("diff", aliases=["changes"], help="Inspect modified, added, or deleted workspace files vs baseline snapshot")
    p_diff.add_argument("name", help="Sandbox identifier")
    p_diff.add_argument("file", nargs="?", default=None, help="Optional workspace-relative file path")
    p_diff.add_argument("--stat", action="store_true", help="Show changed file summary without unified diff patches")
    p_diff.add_argument("--json", action="store_true", help="Output diff in machine-readable JSON format")

    p_rb = subparsers.add_parser("rollback", help="Revert workspace changes back to pre-run snapshot or accept current state")
    p_rb.add_argument("name", help="Sandbox identifier")
    p_rb.add_argument("--file", "-f", dest="rel_file", default=None, help="Revert only a single workspace-relative file")
    p_rb.add_argument("--accept", action="store_true", help="Advance baseline snapshot to accept current workspace changes")

    p_snap = subparsers.add_parser("snapshot", help="Capture or refresh pre-run workspace baseline snapshot")
    p_snap.add_argument("name", help="Sandbox identifier")

    # templates / presets
    p_tmpl = subparsers.add_parser("templates", aliases=["template", "presets"], help="List, save, or delete sandbox profile presets")
    p_tmpl.add_argument("action", nargs="?", choices=["list", "save", "delete", "rm"], default="list", help="Template operation")
    p_tmpl.add_argument("target", nargs="?", default=None, help="Template ID or name (for save/delete)")
    p_tmpl.add_argument("--from-sandbox", dest="from_sandbox", default=None, help="Source sandbox name when saving a custom preset")
    p_tmpl.add_argument("--description", default="", help="Optional preset description")

    # secret vault
    p_sec = subparsers.add_parser("secret", aliases=["secrets"], help="Manage per-sandbox scoped secrets (GNOME Keyring / 0600 vault)")
    p_sec.add_argument("action", choices=["set", "list", "ls", "rm", "delete", "unset"], help="Secret vault operation")
    p_sec.add_argument("name", help="Sandbox identifier")
    p_sec.add_argument("key", nargs="?", default=None, help="Environment variable name (e.g. OPENAI_API_KEY)")
    p_sec.add_argument("value", nargs="?", default=None, help="Secret value (omit to read from stdin)")

    # idle-check / guardrails-check
    p_idle = subparsers.add_parser("idle-check", aliases=["guardrails-check"], help="Evaluate idle sleep, memory pressure, egress spikes, and AI budgets once")
    p_idle.add_argument("--notify", action="store_true", help="Dispatch desktop notifications for any triggered alerts")

    # port forwarding
    p_fwd = subparsers.add_parser("forward", help="Establish live dynamic port tunnel")
    p_fwd.add_argument("name", help="Sandbox name")
    p_fwd.add_argument("port", help="Port specification: GUEST or HOST:GUEST")

    p_unfwd = subparsers.add_parser("unforward", help="Close dynamic port tunnel")
    p_unfwd.add_argument("name", help="Sandbox name")
    p_unfwd.add_argument("guest_port", type=int, help="Guest port to close")

    p_ports = subparsers.add_parser("ports", help="Inspect all active ports")
    p_ports.add_argument("name", help="Sandbox name")
    p_ports.add_argument("--json", action="store_true", help="Output ports in machine-readable JSON format")

    # network / egress
    p_net = subparsers.add_parser("network", aliases=["egress", "net"], help="Inspect or update network egress whitelist and blacklist")
    p_net.add_argument("name", help="Sandbox identifier")
    p_net.add_argument("--profile", choices=["full", "ai-only", "dev-common", "offline", "custom"], help="Switch egress security profile")
    p_net.add_argument("--allow", "--allow-domain", "--whitelist", dest="allow", action="append", help="Whitelist a domain")
    p_net.add_argument("--remove-allow", dest="remove_allow", action="append", help="Remove domain(s) from whitelist")
    p_net.add_argument("--deny", "--deny-domain", "--blacklist", dest="deny", action="append", help="Blacklist a domain")
    p_net.add_argument("--remove-deny", dest="remove_deny", action="append", help="Remove domain(s) from blacklist")
    p_net.add_argument("--traffic", "--stats", dest="show_traffic", action="store_true", help="Also display egress traffic summary")

    # traffic / egress-stats / net-stats
    p_traffic = subparsers.add_parser("traffic", aliases=["egress-stats", "net-stats"], help="Inspect outbound domain egress calls and blocked attempts")
    p_traffic.add_argument("name", nargs="?", help="Optional sandbox name filter")
    p_traffic.add_argument("-n", "--limit", type=int, default=20, help="Maximum ranked domains and recent events to show")
    p_traffic.add_argument("-o", "--export", dest="export_path", help="Export egress sites and frequency data to a file (.csv or .json)")
    p_traffic.add_argument("--clear", action="store_true", help="Clear recorded egress traffic logs")
    p_traffic.add_argument("--json", action="store_true", help="Output traffic in machine-readable JSON format")

    p_open = subparsers.add_parser("open", help="Open forwarded web service in host browser")
    p_open.add_argument("name", help="Sandbox name")
    p_open.add_argument("port", type=int, nargs="?", help="Port to open")

    # logs, stats, api-stats
    p_logs = subparsers.add_parser("logs", help="Stream or view container logs")
    p_logs.add_argument("name", help="Sandbox name")
    p_logs.add_argument("-n", "--tail", type=int, default=100, help="Lines to view")
    p_logs.add_argument("-f", "--follow", action="store_true", help="Follow output")

    p_stats = subparsers.add_parser("stats", help="Inspect live CPU and memory utilization")
    p_stats.add_argument("--json", action="store_true", help="Output stats in machine-readable JSON format")

    p_api = subparsers.add_parser("api-stats", help="Audit AI model invocations and token usage")
    p_api.add_argument("name", nargs="?", help="Optional sandbox name filter")
    p_api.add_argument("--json", action="store_true", help="Output API stats in machine-readable JSON format")

    # images
    p_img = subparsers.add_parser("images", aliases=["image"], help="List or build supported base images")
    p_img.add_argument("action", nargs="?", default="list", choices=["list", "ls", "build", "check", "status"], help="Action: list, build, check, or status")
    p_img.add_argument("target", nargs="?", default=None, help="Target image to build (base, python, node, agent-box, all)")
    p_img.add_argument("--force", "-f", action="store_true", help="Force rebuild even if image is fresh")
    p_img.add_argument("--json", action="store_true", help="Output images in machine-readable JSON format")

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Run system diagnostics for Fedora 44 and Linux microVMs")
    p_doc.add_argument("--json", action="store_true", help="Output diagnostics in machine-readable JSON format")

    # prune
    subparsers.add_parser("prune", help="Clean up stopped ephemeral sandboxes")

    # install-desktop
    p_dt = subparsers.add_parser("install-desktop", help="Install GNOME App Manager entry, icons, and AppStream metadata")
    p_dt.add_argument("--system", action="store_true", help="Install into /usr/share (requires root)")

    # requests
    p_reqs = subparsers.add_parser("requests", help="List agent permission requests (domain access / port exposure)")
    p_reqs.add_argument("sandbox", nargs="?", default=None, help="Filter by sandbox name")
    p_reqs.add_argument("--all", "-a", action="store_true", help="Show all requests including approved/denied")
    p_reqs.add_argument("--json", action="store_true", help="Output requests in machine-readable JSON format")

    # approve
    p_app = subparsers.add_parser("approve", help="Approve an agent permission request")
    p_app.add_argument("request_id", help="Access request ID (e.g. req-abc12345)")

    # deny
    p_deny = subparsers.add_parser("deny", help="Deny an agent permission request")
    p_deny.add_argument("request_id", help="Access request ID")
    p_deny.add_argument("--reason", "-r", default="Denied by operator", help="Denial explanation")

    # keep-awake
    p_ka = subparsers.add_parser("keep-awake", help="Reset idle sleep timer or configure sandbox to never sleep")
    p_ka.add_argument("name", help="Sandbox identifier")
    p_ka.add_argument("--indefinite", "--never-sleep", "--no-idle", action="store_true", help="Disable idle auto-pause/stop indefinitely")
    p_ka.add_argument("--extend", type=int, default=30, help="Extend idle window by N minutes (default: 30)")

    # clone
    p_clone = subparsers.add_parser("clone", help="Clone an existing sandbox configuration into a new sandbox")
    p_clone.add_argument("source", help="Source sandbox identifier")
    p_clone.add_argument("new_name", help="New sandbox identifier")

    # export
    p_exp = subparsers.add_parser("export", help="Export a sandbox configuration and snapshot to an archive")
    p_exp.add_argument("name", help="Sandbox identifier to export")
    p_exp.add_argument("-o", "--output", default=None, help="Output archive path (default: <name>.tar.gz)")

    # import
    p_imp = subparsers.add_parser("import", aliases=["load"], help="Import a sandbox from an archive")
    p_imp.add_argument("archive", help="Path to exported sandbox archive")
    p_imp.add_argument("--name", "-n", default=None, help="Optional new name for imported sandbox")

    # daemon
    p_daemon = subparsers.add_parser("daemon", help="Run background daemon for guardrails, idle monitors, and IPC")
    p_daemon.add_argument("--interval", type=int, default=15, help="Guardrails polling interval in seconds (default: 15)")
    p_daemon.add_argument("--once", action="store_true", help="Run a single evaluation pass and exit")

    # completion
    p_comp = subparsers.add_parser("completion", help="Generate or install shell completion scripts")
    p_comp.add_argument("shell", choices=["bash", "zsh", "fish"], help="Target shell")
    p_comp.add_argument("--install", action="store_true", help="Install completion script to standard user directory")

    # ui
    subparsers.add_parser("ui", help="Launch native GTK4 / Libadwaita management console")

    args, unknown = parser.parse_known_args()
    if args.command == "run":
        if unknown and unknown[0] == "--":
            unknown = unknown[1:]
        extra_args = unknown if unknown else None
    else:
        if unknown:
            parser.error(f"unrecognized arguments: {' '.join(unknown)}")
        extra_args = None

    manager = SandboxManager()
    image_mgr = ImageManager()

    if not args.command:
        return commands.cmd_list(manager)

    if args.command == "run":
        return commands.cmd_run(
            manager=manager,
            dir_path=args.dir,
            name=args.name,
            template_id=args.template,
            image=args.image,
            persistent=args.persistent,
            network_profile=args.network,
            allowed_domains=args.allow_domain,
            denied_domains=args.deny_domain,
            ports=args.port,
            detach=args.detach,
            cpus=args.cpus,
            ram_mib=args.ram,
            persist_docker=args.persist_docker,
            protect_git_hooks=args.protect_git_hooks,
            protect_git_config=args.protect_git_config,
            protect_env_files=args.protect_env_files,
            host_egress_lockdown=args.host_egress_lockdown,
            idle_timeout_minutes=0 if getattr(args, "no_idle", False) else args.idle_timeout,
            idle_action=args.idle_action,
            env_pairs=args.env,
            pass_env=args.pass_env,
            secret_pairs=args.secret,
            max_tokens_budget=args.max_tokens,
            max_cost_usd_budget=args.max_cost,
            budget_exceeded_action=args.budget_action,
            extra_args=extra_args,
        )
    elif args.command == "create":
        return commands.cmd_create(
            manager=manager,
            dir_path=args.dir,
            name=args.name,
            template_id=args.template,
            image=args.image,
            persistent=args.persistent,
            network_profile=args.network,
            allowed_domains=args.allow_domain,
            denied_domains=args.deny_domain,
            ports=args.port,
            cpus=args.cpus,
            ram_mib=args.ram,
            persist_docker=args.persist_docker,
            protect_git_hooks=args.protect_git_hooks,
            protect_git_config=args.protect_git_config,
            protect_env_files=args.protect_env_files,
            host_egress_lockdown=args.host_egress_lockdown,
            idle_timeout_minutes=0 if getattr(args, "no_idle", False) else args.idle_timeout,
            idle_action=args.idle_action,
            env_pairs=args.env,
            pass_env=args.pass_env,
            secret_pairs=args.secret,
            max_tokens_budget=args.max_tokens,
            max_cost_usd_budget=args.max_cost,
            budget_exceeded_action=args.budget_action,
        )
    elif args.command in ("edit", "update", "config"):
        return commands.cmd_edit(
            manager=manager,
            name=args.name,
            new_name=args.new_name,
            cpus=args.cpus,
            ram_mib=args.ram,
            network=args.network,
            allow=args.allow,
            remove_allow=args.remove_allow,
            clear_allow=args.clear_allow,
            deny=args.deny,
            remove_deny=args.remove_deny,
            clear_deny=args.clear_deny,
            protect_git_hooks=args.protect_git_hooks,
            protect_git_config=args.protect_git_config,
            protect_env_files=args.protect_env_files,
            host_egress_lockdown=args.host_egress_lockdown,
            idle_timeout_minutes=0 if getattr(args, "no_idle", False) else args.idle_timeout,
            idle_action=args.idle_action,
            env_pairs=args.env,
            unset_env=args.unset_env,
            pass_env=args.pass_env,
            unset_pass_env=args.unset_pass_env,
            secret_pairs=args.secret,
            unset_secret=args.unset_secret,
            max_tokens_budget=args.max_tokens,
            max_cost_usd_budget=args.max_cost,
            budget_exceeded_action=args.budget_action,
        )
    elif args.command == "start":
        return commands.cmd_start(manager, args.name, detach=args.detach)
    elif args.command == "stop":
        return commands.cmd_stop(manager, args.name)
    elif args.command == "pause":
        return commands.cmd_pause(manager, args.name)
    elif args.command in ("unpause", "resume"):
        return commands.cmd_unpause(manager, args.name)
    elif args.command == "restart":
        return commands.cmd_restart(manager, args.name)
    elif args.command == "recreate":
        return commands.cmd_recreate(
            manager=manager,
            name=args.name,
            pull=args.pull,
            wipe_volumes=args.wipe_volumes,
            yes=args.yes,
        )
    elif args.command in ("rm", "delete"):
        return commands.cmd_rm(manager, args.name, volumes=args.volumes)
    elif args.command in ("list", "ls", "ps"):
        return commands.cmd_list(manager, all_info=args.all, json_output=getattr(args, "json", False))
    elif args.command in ("ssh", "connect"):
        return commands.cmd_ssh(manager, args.name, open_terminal=getattr(args, "terminal", False))
    elif args.command in ("code", "ide"):
        return commands.cmd_code(manager, args.name, ide_key=args.ide, remote_path=args.path)
    elif args.command == "exec":
        cmd = list(args.cmd or [])
        notify = bool(args.notify)
        while cmd and cmd[0] in ("--notify", "-N"):
            notify = True
            cmd = cmd[1:]
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        return commands.cmd_exec(manager, args.name, cmd, notify=notify)
    elif args.command in ("diff", "changes"):
        return commands.cmd_diff(
            manager,
            args.name,
            rel_file=args.file,
            stat_only=args.stat,
            json_output=getattr(args, "json", False),
        )
    elif args.command == "rollback":
        return commands.cmd_rollback(manager, args.name, rel_file=args.rel_file, accept=args.accept)
    elif args.command == "snapshot":
        return commands.cmd_snapshot(manager, args.name)
    elif args.command in ("templates", "template", "presets"):
        return commands.cmd_templates(
            manager,
            action=args.action,
            target=args.target,
            from_sandbox=args.from_sandbox,
            description=args.description,
        )
    elif args.command in ("secret", "secrets"):
        return commands.cmd_secret(
            manager,
            action=args.action,
            name=args.name,
            key=args.key,
            value=args.value,
        )
    elif args.command in ("idle-check", "guardrails-check"):
        return commands.cmd_idle_check(manager, notify=args.notify)
    elif args.command == "forward":
        return commands.cmd_forward(manager, args.name, args.port)
    elif args.command == "unforward":
        return commands.cmd_unforward(manager, args.name, args.guest_port)
    elif args.command == "ports":
        return commands.cmd_ports(manager, args.name, json_output=getattr(args, "json", False))
    elif args.command in ("network", "egress", "net"):
        return commands.cmd_network(
            manager,
            args.name,
            allow=args.allow,
            deny=args.deny,
            profile=args.profile,
            remove_allow=args.remove_allow,
            remove_deny=args.remove_deny,
            show_traffic=args.show_traffic,
        )
    elif args.command in ("traffic", "egress-stats", "net-stats"):
        return commands.cmd_traffic(
            manager,
            name=args.name,
            limit=args.limit,
            clear=args.clear,
            json_output=getattr(args, "json", False),
            export_path=getattr(args, "export_path", None),
        )
    elif args.command == "open":
        return commands.cmd_open(manager, args.name, args.port)
    elif args.command == "logs":
        return commands.cmd_logs(manager, args.name, tail=args.tail, follow=args.follow)
    elif args.command == "stats":
        return commands.cmd_stats(manager, json_output=getattr(args, "json", False))
    elif args.command == "api-stats":
        return commands.cmd_api_stats(manager, args.name, json_output=getattr(args, "json", False))
    elif args.command in ("images", "image"):
        return commands.cmd_images(
            image_mgr,
            action=getattr(args, "action", "list"),
            target=getattr(args, "target", None),
            json_output=getattr(args, "json", False),
            force=getattr(args, "force", False),
        )
    elif args.command == "doctor":
        return commands.cmd_doctor(json_output=getattr(args, "json", False))
    elif args.command == "prune":
        return commands.cmd_prune(manager)
    elif args.command == "install-desktop":
        return commands.cmd_install_desktop(system=args.system)
    elif args.command == "requests":
        return commands.cmd_requests(
            manager,
            sandbox=args.sandbox,
            all_info=args.all,
            json_output=getattr(args, "json", False),
        )
    elif args.command == "approve":
        return commands.cmd_approve(manager, args.request_id)
    elif args.command == "deny":
        return commands.cmd_deny(manager, args.request_id, reason=args.reason)
    elif args.command == "keep-awake":
        return commands.cmd_keep_awake(manager, args.name, indefinite=args.indefinite, extend_minutes=args.extend)
    elif args.command == "clone":
        return commands.cmd_clone(manager, args.source, args.new_name)
    elif args.command == "export":
        return commands.cmd_export(manager, args.name, output=args.output)
    elif args.command in ("import", "load"):
        return commands.cmd_import(manager, args.archive, new_name=args.name)
    elif args.command == "daemon":
        return commands.cmd_daemon(manager, interval=args.interval, once=args.once)
    elif args.command == "completion":
        return commands.cmd_completion(args.shell, install=args.install)
    elif args.command == "ui":
        return commands.cmd_ui()

    return 0


if __name__ == "__main__":
    sys.exit(main())
