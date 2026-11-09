"""
Shell completion generator and installer for krunbox.

Provides complete dynamic shell completion scripts for Bash, Zsh, and Fish,
with dynamic sandbox name resolution, full subcommand support, and automatic
installation into standard user shell completion directories.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Supported shells
SUPPORTED_SHELLS: Tuple[str, ...] = ("bash", "zsh", "fish")

# Standard completion installation paths according to shell and XDG conventions
DEFAULT_INSTALL_PATHS: Dict[str, Path] = {
    "bash": Path.home() / ".local" / "share" / "bash-completion" / "completions" / "krunbox",
    "zsh": Path.home() / ".local" / "share" / "zsh" / "site-functions" / "_krunbox",
    "fish": Path.home() / ".config" / "fish" / "completions" / "krunbox.fish",
}

# Complete list of subcommands required for completion
SUBCOMMANDS: List[str] = [
    "run",
    "create",
    "edit",
    "start",
    "stop",
    "pause",
    "unpause",
    "restart",
    "rm",
    "list",
    "ssh",
    "code",
    "exec",
    "diff",
    "rollback",
    "snapshot",
    "templates",
    "secret",
    "idle-check",
    "forward",
    "unforward",
    "ports",
    "network",
    "traffic",
    "open",
    "logs",
    "stats",
    "api-stats",
    "images",
    "doctor",
    "prune",
    "install-desktop",
    "requests",
    "approve",
    "deny",
    "keep-awake",
    "clone",
    "export",
    "import",
    "daemon",
    "completion",
    "ui",
]

# Command descriptions for shells with rich completion menus (Zsh, Fish)
COMMAND_DESCRIPTIONS: Dict[str, str] = {
    "run": "Launch an ephemeral or persistent sandbox",
    "create": "Register a sandbox without starting",
    "edit": "Edit sandbox configuration, resources, or guardrails",
    "start": "Start or resume a stopped/paused sandbox",
    "stop": "Halt a running sandbox",
    "pause": "Freeze a running sandbox",
    "unpause": "Resume a paused sandbox",
    "restart": "Restart a sandbox",
    "rm": "Delete a sandbox",
    "list": "List sandboxes and telemetry",
    "ssh": "Connect to sandbox terminal via SSH",
    "code": "Open sandbox workspace in IDE (VS Code, Cursor, Zed, SFTP)",
    "exec": "Execute command inside sandbox",
    "diff": "Inspect modified workspace files vs baseline snapshot",
    "rollback": "Revert workspace changes back to pre-run snapshot",
    "snapshot": "Capture or refresh pre-run workspace baseline snapshot",
    "templates": "Manage sandbox profile presets",
    "secret": "Manage per-sandbox scoped secrets",
    "idle-check": "Evaluate idle sleep and guardrails",
    "forward": "Establish live dynamic port tunnel",
    "unforward": "Close dynamic port tunnel",
    "ports": "Inspect all active ports",
    "network": "Inspect or update network egress policy",
    "traffic": "Inspect outbound domain egress calls and blocked attempts",
    "open": "Open forwarded web service in host browser",
    "logs": "Stream or view container logs",
    "stats": "Inspect live CPU and memory utilization",
    "api-stats": "Audit AI model invocations and token usage",
    "images": "List supported and local base images",
    "doctor": "Run system diagnostics for microVMs",
    "prune": "Clean up stopped ephemeral sandboxes",
    "install-desktop": "Install GNOME App Manager entry and desktop files",
    "requests": "List agent permission requests",
    "approve": "Approve an agent permission request",
    "deny": "Deny an agent permission request",
    "keep-awake": "Reset idle sleep timer or configure sandbox to never sleep",
    "clone": "Clone an existing sandbox",
    "export": "Export sandbox filesystem or configuration",
    "import": "Import sandbox filesystem or configuration",
    "daemon": "Manage background monitor daemon",
    "completion": "Generate or install shell completion script",
    "ui": "Launch native GTK4 / Libadwaita console",
}


def _get_bash_completion_script() -> str:
    """Generate the Bash completion script for krunbox."""
    subcommands_str = " ".join(SUBCOMMANDS)
    aliases_str = "update config resume delete ls ps connect ide changes presets secrets guardrails-check egress net egress-stats net-stats image"
    all_cmds_str = f"{subcommands_str} {aliases_str}"

    return f"""# Bash completion for krunbox
# Generated automatically by krunbox completion generator

_krunbox_sandboxes() {{
    local boxes=""
    if [[ -f "$HOME/.config/krunbox/sandboxes.json" ]]; then
        boxes=$(sed -n 's/^[[:space:]]*"\\([^"]*\\)": {{/\\1/p' "$HOME/.config/krunbox/sandboxes.json" 2>/dev/null)
    fi
    if [[ -z "$boxes" ]] && command -v krunbox >/dev/null 2>&1; then
        boxes=$(krunbox list 2>/dev/null | sed -r 's/\\x1B\\[[0-9;]*[mK]//g' | awk 'NR>2 && $1 !~ /^[─-]/ && $1 != "" {{print $1}}')
    fi
    echo "$boxes"
}}

_krunbox_completions() {{
    local cur prev words cword
    _init_completion -n : 2>/dev/null || {{
        cur="${{COMP_WORDS[COMP_CWORD]}}"
        prev="${{COMP_WORDS[COMP_CWORD-1]}}"
        words=("${{COMP_WORDS[@]}}")
        cword=$COMP_CWORD
    }}

    local commands="{all_cmds_str}"

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        return 0
    fi

    local cmd="${{words[1]}}"

    # Common flag values
    case "$prev" in
        --network|--net|--profile)
            COMPREPLY=( $(compgen -W "full ai-only dev-common offline custom" -- "$cur") )
            return 0
            ;;
        --ide)
            COMPREPLY=( $(compgen -W "vscode cursor zed jetbrains sftp terminal" -- "$cur") )
            return 0
            ;;
        --idle-action)
            COMPREPLY=( $(compgen -W "stop pause" -- "$cur") )
            return 0
            ;;
        --budget-action)
            COMPREPLY=( $(compgen -W "alert pause stop" -- "$cur") )
            return 0
            ;;
        --template|-T)
            COMPREPLY=( $(compgen -W "standard-agent locked-down-reviewer ai-only-coder fullstack-web python-data-ml reversing reverse-engineering" -- "$cur") )
            return 0
            ;;
        --image|-i)
            COMPREPLY=( $(compgen -W "localhost/agent-box:latest ghcr.io/astral-sh/uv:python3.12-bookworm-slim docker.io/library/node:22-bookworm-slim docker.io/library/debian:bookworm-slim" -- "$cur") )
            return 0
            ;;
        -p|--port)
            COMPREPLY=( $(compgen -W "3000:3000 5173:5173 8000:8000 8080:8080 8888:8888" -- "$cur") )
            return 0
            ;;
        --shell|-s)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
            return 0
            ;;
    esac

    case "$cmd" in
        completion)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--install -i --shell -s --help -h" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
            fi
            return 0
            ;;
        templates|template|presets)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--from-sandbox --description --help -h" -- "$cur") )
            elif [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "list save delete rm" -- "$cur") )
            elif [[ "$prev" == "--from-sandbox" ]]; then
                COMPREPLY=( $(compgen -W "$(_krunbox_sandboxes)" -- "$cur") )
            fi
            return 0
            ;;
        secret|secrets)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "set list ls rm delete unset" -- "$cur") )
            elif [[ $cword -eq 3 ]]; then
                COMPREPLY=( $(compgen -W "$(_krunbox_sandboxes)" -- "$cur") )
            fi
            return 0
            ;;
        run|create)
            if [[ "$cur" == -* ]]; then
                local run_flags="--name -n --template -T --image -i -P --persistent --network --net --allow-domain --deny-domain -p --port -d --detach --cpus --ram --persist-docker --protect-git-hooks --no-git-guardrails --protect-git-config --protect-env --lock-egress --idle-timeout --idle-action -e --env --pass-env --secret --max-tokens --max-cost --budget-action --help -h"
                COMPREPLY=( $(compgen -W "$run_flags" -- "$cur") )
                return 0
            fi
            _filedir -d 2>/dev/null || COMPREPLY=( $(compgen -d -- "$cur") )
            return 0
            ;;
        edit|update|config)
            if [[ "$cur" == -* ]]; then
                local edit_flags="--name --rename --cpus --ram --network --profile --allow --allow-domain --whitelist --remove-allow --clear-allow --deny --deny-domain --blacklist --remove-deny --clear-deny --protect-git-hooks --no-protect-git-hooks --no-git-guardrails --protect-git-config --no-protect-git-config --protect-env --no-protect-env --lock-egress --no-lock-egress --idle-timeout --no-idle --never-sleep --idle-action -e --env --unset-env --pass-env --unset-pass-env --secret --unset-secret --max-tokens --max-cost --budget-action --help -h"
                COMPREPLY=( $(compgen -W "$edit_flags" -- "$cur") )
                return 0
            fi
            COMPREPLY=( $(compgen -W "$(_krunbox_sandboxes)" -- "$cur") )
            return 0
            ;;
        stop|start|pause|unpause|resume|restart|rm|delete|ssh|connect|code|ide|ports|open|logs|forward|unforward|api-stats|network|egress|net|traffic|egress-stats|net-stats|diff|changes|rollback|snapshot|keep-awake|clone|export|exec|requests)
            if [[ "$cur" == -* ]]; then
                case "$cmd" in
                    ssh|connect)
                        COMPREPLY=( $(compgen -W "--terminal -t --help -h" -- "$cur") )
                        ;;
                    code|ide)
                        COMPREPLY=( $(compgen -W "--ide --path --help -h" -- "$cur") )
                        ;;
                    exec)
                        COMPREPLY=( $(compgen -W "-N --notify --help -h" -- "$cur") )
                        ;;
                    logs)
                        COMPREPLY=( $(compgen -W "-n --tail -f --follow --help -h" -- "$cur") )
                        ;;
                    diff|changes)
                        COMPREPLY=( $(compgen -W "--stat --help -h" -- "$cur") )
                        ;;
                    rollback)
                        COMPREPLY=( $(compgen -W "--file -f --accept --help -h" -- "$cur") )
                        ;;
                    network|egress|net)
                        COMPREPLY=( $(compgen -W "--profile --allow --allow-domain --remove-allow --deny --remove-deny --traffic --stats --help -h" -- "$cur") )
                        ;;
                    traffic|egress-stats|net-stats)
                        COMPREPLY=( $(compgen -W "-n --limit --clear --help -h" -- "$cur") )
                        ;;
                    keep-awake)
                        COMPREPLY=( $(compgen -W "--indefinite --never-sleep --no-idle --extend --help -h" -- "$cur") )
                        ;;
                    rm|delete)
                        COMPREPLY=( $(compgen -W "-v --volumes --help -h" -- "$cur") )
                        ;;
                    requests)
                        COMPREPLY=( $(compgen -W "--all -a --help -h" -- "$cur") )
                        ;;
                    *)
                        COMPREPLY=( $(compgen -W "--help -h" -- "$cur") )
                        ;;
                esac
                return 0
            fi
            COMPREPLY=( $(compgen -W "$(_krunbox_sandboxes)" -- "$cur") )
            return 0
            ;;
        list|ls|ps)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-a --all --help -h" -- "$cur") )
                return 0
            fi
            ;;
        install-desktop)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--system --help -h" -- "$cur") )
                return 0
            fi
            ;;
        idle-check|guardrails-check)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--notify --help -h" -- "$cur") )
                return 0
            fi
            ;;
        approve|deny)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-r --reason --help -h" -- "$cur") )
                return 0
            fi
            ;;
        *)
            COMPREPLY=( $(compgen -W "$(_krunbox_sandboxes)" -- "$cur") )
            ;;
    esac
}}

complete -F _krunbox_completions krunbox
"""


def _get_zsh_completion_script() -> str:
    """Generate the Zsh completion script for krunbox."""
    subcommands_lines = []
    for cmd in SUBCOMMANDS:
        desc = COMMAND_DESCRIPTIONS.get(cmd, f"{cmd} command").replace("'", "\\'")
        subcommands_lines.append(f"        '{cmd}:{desc}'")
    subcommands_zsh = "\n".join(subcommands_lines)

    return f"""#compdef krunbox
# Zsh completion for krunbox
# Generated automatically by krunbox completion generator

_krunbox_sandboxes() {{
    local -a sandboxes
    if [[ -f "$HOME/.config/krunbox/sandboxes.json" ]]; then
        sandboxes=(${{(f)"$(sed -n 's/^[[:space:]]*"\\([^"]*\\)": {{/\\1/p' "$HOME/.config/krunbox/sandboxes.json" 2>/dev/null)"}})
    fi
    if (( ${{#sandboxes}} == 0 )) && (( $+commands[krunbox] )); then
        sandboxes=(${{(f)"$(krunbox list 2>/dev/null | sed -r 's/\\x1B\\[[0-9;]*[mK]//g' | awk 'NR>2 && $1 !~ /^[─-]/ && $1 != "" {{print $1}}')"}})
    fi
    _describe -t sandboxes 'sandbox' sandboxes
}}

_krunbox() {{
    local curcontext="$curcontext" state line
    typeset -A opt_args

    local -a commands
    commands=(
{subcommands_zsh}
    )

    _arguments -C \\
        '1: :->command' \\
        '*:: :->args'

    case $state in
        command)
            _describe -t commands 'krunbox command' commands
            ;;
        args)
            case $words[1] in
                completion)
                    _arguments \\
                        '(-i --install)'{{-i,--install}}'[Install completion script for specified shell]' \\
                        '(-s --shell)'{{-s,--shell}}'[Target shell]:shell:(bash zsh fish)' \\
                        '1:shell:(bash zsh fish)'
                    ;;
                templates|template|presets)
                    local -a tmpl_actions
                    tmpl_actions=('list:List templates' 'save:Save template' 'delete:Delete template' 'rm:Delete template')
                    if (( CURRENT == 2 )); then
                        _describe -t tmpl_actions 'template action' tmpl_actions
                    else
                        _arguments \\
                            '--from-sandbox[Source sandbox name]:sandbox:_krunbox_sandboxes' \\
                            '--description[Preset description]:desc:' \\
                            '*:target:'
                    fi
                    ;;
                secret|secrets)
                    local -a sec_actions
                    sec_actions=('set:Set scoped secret' 'list:List secrets' 'ls:List secrets' 'rm:Remove secret' 'delete:Remove secret' 'unset:Unset secret')
                    if (( CURRENT == 2 )); then
                        _describe -t sec_actions 'secret action' sec_actions
                    elif (( CURRENT == 3 )); then
                        _krunbox_sandboxes
                    fi
                    ;;
                run|create)
                    _arguments \\
                        '(-n --name)'{{-n,--name}}'[Sandbox identifier]:name:' \\
                        '(-T --template)'{{-T,--template}}'[Apply sandbox profile preset]:template:(standard-agent locked-down-reviewer ai-only-coder fullstack-web python-data-ml reversing reverse-engineering)' \\
                        '(-i --image)'{{-i,--image}}'[Base container image]:image:(localhost/agent-box:latest ghcr.io/astral-sh/uv:python3.12-bookworm-slim docker.io/library/node:22-bookworm-slim docker.io/library/debian:bookworm-slim)' \\
                        '(-P --persistent)'{{-P,--persistent}}'[Make sandbox persistent across stops]' \\
                        '--network[Network egress policy]:network:(full ai-only dev-common offline custom)' \\
                        '(-p --port)'{{-p,--port}}'[Port forward]:port:' \\
                        '(-d --detach)'{{-d,--detach}}'[Run in background]' \\
                        '--cpus[Allocated vCPUs]:cpus:' \\
                        '--ram[Allocated RAM in MiB]:ram:' \\
                        '--idle-action[Action on idle timeout]:action:(stop pause)' \\
                        '--budget-action[Action on AI budget exceed]:action:(alert pause stop)' \\
                        '*:directory:_files -/'
                    ;;
                edit|update|config)
                    _arguments \\
                        '--name[Rename sandbox]:new_name:' \\
                        '--cpus[Update allocated vCPUs]:cpus:' \\
                        '--ram[Update allocated RAM in MiB]:ram:' \\
                        '--network[Update egress policy]:network:(full ai-only dev-common offline custom)' \\
                        '--idle-action[Idle action]:action:(stop pause)' \\
                        '--budget-action[Budget action]:action:(alert pause stop)' \\
                        '1:sandbox:_krunbox_sandboxes'
                    ;;
                ssh|connect)
                    _arguments \\
                        '(-t --terminal)'{{-t,--terminal}}'[Launch in a new terminal window]' \\
                        '1:sandbox:_krunbox_sandboxes'
                    ;;
                code|ide)
                    _arguments \\
                        '--ide[Target IDE]:ide:(vscode cursor zed jetbrains sftp terminal)' \\
                        '--path[Remote workspace path]:path:' \\
                        '1:sandbox:_krunbox_sandboxes'
                    ;;
                exec)
                    _arguments \\
                        '(-N --notify)'{{-N,--notify}}'[Send desktop notification upon completion]' \\
                        '1:sandbox:_krunbox_sandboxes' \\
                        '*:command:_command_names -e'
                    ;;
                diff|changes)
                    _arguments \\
                        '--stat[Show changed file summary only]' \\
                        '1:sandbox:_krunbox_sandboxes'
                    ;;
                rollback)
                    _arguments \\
                        '(-f --file)'{{-f,--file}}'[Revert only single file]:file:_files' \\
                        '--accept[Advance baseline snapshot]' \\
                        '1:sandbox:_krunbox_sandboxes'
                    ;;
                network|egress|net)
                    _arguments \\
                        '--profile[Switch egress security profile]:profile:(full ai-only dev-common offline custom)' \\
                        '--traffic[Display egress traffic summary]' \\
                        '1:sandbox:_krunbox_sandboxes'
                    ;;
                traffic|egress-stats|net-stats)
                    _arguments \\
                        '(-n --limit)'{{-n,--limit}}'[Max ranked domains to show]:limit:' \\
                        '--clear[Clear recorded egress logs]' \\
                        '1:sandbox:_krunbox_sandboxes'
                    ;;
                keep-awake)
                    _arguments \\
                        '--indefinite[Disable idle auto-pause indefinitely]' \\
                        '--extend[Extend idle window in minutes]:minutes:' \\
                        '1:sandbox:_krunbox_sandboxes'
                    ;;
                rm|delete)
                    _arguments \\
                        '(-v --volumes)'{{-v,--volumes}}'[Purge persistent storage volumes]' \\
                        '1:sandbox:_krunbox_sandboxes'
                    ;;
                start|stop|pause|unpause|resume|restart|snapshot|forward|unforward|ports|open|logs|api-stats|clone|export|requests)
                    _krunbox_sandboxes
                    ;;
                *)
                    _files
                    ;;
            esac
            ;;
    esac
}}

_krunbox "$@"
"""


def _get_fish_completion_script() -> str:
    """Generate the Fish completion script for krunbox."""
    subcommands_str = " ".join(SUBCOMMANDS)
    aliases_str = "update config resume delete ls ps connect ide changes presets secrets guardrails-check egress net egress-stats net-stats image"
    all_cmds_str = f"{subcommands_str} {aliases_str}"

    lines = [
        "# Fish completion for krunbox",
        "# Generated automatically by krunbox completion generator",
        "",
        "function __fish_krunbox_sandboxes",
        '    if test -f "$HOME/.config/krunbox/sandboxes.json"',
        "        sed -n 's/^[[:space:]]*\"\\([^\"]*\\)\": {/\\1/p' \"$HOME/.config/krunbox/sandboxes.json\" 2>/dev/null",
        "    else if type -q krunbox",
        "        krunbox list 2>/dev/null | string replace -r '\\x1B\\[[0-9;]*[mK]' '' | awk 'NR>2 && $1 !~ /^[─-]/ && $1 != \"\" {print $1}'",
        "    end",
        "end",
        "",
        "# Disable default file completions unless requested",
        "complete -c krunbox -f",
        "",
        f"set -l __krunbox_all_commands {all_cmds_str}",
        "",
        "# Subcommand completions",
    ]

    for cmd in SUBCOMMANDS:
        desc = COMMAND_DESCRIPTIONS.get(cmd, f"{cmd} command").replace('"', '\\"')
        lines.append(
            f'complete -c krunbox -n "not __fish_seen_subcommand_from $__krunbox_all_commands" -a {cmd} -d "{desc}"'
        )

    lines.extend([
        "",
        "# Sandbox argument completion for subcommands",
        "set -l __krunbox_sandbox_cmds start stop pause unpause resume restart rm delete ssh connect code ide diff changes rollback snapshot forward unforward ports network egress net traffic egress-stats net-stats open logs api-stats keep-awake clone export edit update config requests exec",
        'complete -c krunbox -n "__fish_seen_subcommand_from $__krunbox_sandbox_cmds" -a "(__fish_krunbox_sandboxes)" -d "Sandbox"',
        "",
        "# Common parameter values",
        'complete -c krunbox -l network -a "full ai-only dev-common offline custom" -d "Network egress policy"',
        'complete -c krunbox -l profile -a "full ai-only dev-common offline custom" -d "Network egress policy"',
        'complete -c krunbox -l ide -a "vscode cursor zed jetbrains sftp terminal" -d "Target IDE"',
        'complete -c krunbox -l idle-action -a "stop pause" -d "Action on idle timeout"',
        'complete -c krunbox -l budget-action -a "alert pause stop" -d "Action on AI budget exceeded"',
        'complete -c krunbox -s T -l template -a "standard-agent locked-down-reviewer ai-only-coder fullstack-web python-data-ml reversing reverse-engineering" -d "Profile template preset"',
        'complete -c krunbox -s i -l image -a "localhost/agent-box:latest ghcr.io/astral-sh/uv:python3.12-bookworm-slim docker.io/library/node:22-bookworm-slim docker.io/library/debian:bookworm-slim" -d "Base container image"',
        "",
        "# Command-specific options",
        'complete -c krunbox -n "__fish_seen_subcommand_from completion" -a "bash zsh fish" -d "Shell type"',
        'complete -c krunbox -n "__fish_seen_subcommand_from completion" -s i -l install -d "Install completion script to shell directory"',
        'complete -c krunbox -n "__fish_seen_subcommand_from completion" -s s -l shell -a "bash zsh fish" -d "Target shell"',
        'complete -c krunbox -n "__fish_seen_subcommand_from templates template presets" -a "list save delete rm" -d "Template action"',
        'complete -c krunbox -n "__fish_seen_subcommand_from templates template presets" -l from-sandbox -a "(__fish_krunbox_sandboxes)" -d "Source sandbox"',
        'complete -c krunbox -n "__fish_seen_subcommand_from secret secrets" -a "set list ls rm delete unset" -d "Secret vault action"',
        'complete -c krunbox -n "__fish_seen_subcommand_from run create" -s n -l name -d "Sandbox identifier"',
        'complete -c krunbox -n "__fish_seen_subcommand_from run create" -s P -l persistent -d "Make sandbox persistent across stops"',
        'complete -c krunbox -n "__fish_seen_subcommand_from run create" -s d -l detach -d "Run in background"',
        'complete -c krunbox -n "__fish_seen_subcommand_from run create" -s p -l port -d "Port mapping"',
        'complete -c krunbox -n "__fish_seen_subcommand_from run create" -l cpus -d "Allocated vCPUs"',
        'complete -c krunbox -n "__fish_seen_subcommand_from run create" -l ram -d "Allocated RAM in MiB"',
        'complete -c krunbox -n "__fish_seen_subcommand_from ssh connect" -s t -l terminal -d "Launch in external graphical terminal"',
        'complete -c krunbox -n "__fish_seen_subcommand_from exec" -s N -l notify -d "Send desktop notification upon completion"',
        'complete -c krunbox -n "__fish_seen_subcommand_from diff changes" -l stat -d "Summary diff without unified patches"',
        'complete -c krunbox -n "__fish_seen_subcommand_from rollback" -s f -l file -d "Revert single relative file"',
        'complete -c krunbox -n "__fish_seen_subcommand_from rollback" -l accept -d "Advance baseline snapshot"',
        'complete -c krunbox -n "__fish_seen_subcommand_from logs" -s n -l tail -d "Lines to view"',
        'complete -c krunbox -n "__fish_seen_subcommand_from logs" -s f -l follow -d "Follow output"',
        'complete -c krunbox -n "__fish_seen_subcommand_from rm delete" -s v -l volumes -d "Purge persistent storage volumes"',
        'complete -c krunbox -n "__fish_seen_subcommand_from list ls ps" -s a -l all -d "Display verbose telemetry"',
        'complete -c krunbox -n "__fish_seen_subcommand_from requests" -s a -l all -d "Show approved and denied requests"',
        'complete -c krunbox -n "__fish_seen_subcommand_from keep-awake" -l indefinite -d "Disable idle auto-pause indefinitely"',
        'complete -c krunbox -n "__fish_seen_subcommand_from keep-awake" -l extend -d "Extend idle window in minutes"',
        'complete -c krunbox -n "__fish_seen_subcommand_from install-desktop" -l system -d "Install system-wide into /usr/share"',
    ])

    return "\n".join(lines) + "\n"


def get_completion_script(shell: str) -> str:
    """
    Generate the shell completion script for the requested shell.

    Parameters:
        shell: The target shell ('bash', 'zsh', or 'fish'). Case-insensitive.

    Returns:
        The completion script as a string.

    Raises:
        ValueError: If an unsupported shell is requested.
    """
    s = (shell or "").strip().lower()
    if s == "bash":
        return _get_bash_completion_script()
    elif s == "zsh":
        return _get_zsh_completion_script()
    elif s == "fish":
        return _get_fish_completion_script()
    else:
        supported = ", ".join(SUPPORTED_SHELLS)
        raise ValueError(f"Unsupported shell: '{shell}'. Supported shells: {supported}")


def install_completion_script(shell: str, target_path: Optional[Path] = None) -> Tuple[bool, str]:
    """
    Install the shell completion script to the standard or specified location.

    Standard paths:
        - bash: ~/.local/share/bash-completion/completions/krunbox
        - zsh:  ~/.local/share/zsh/site-functions/_krunbox
        - fish: ~/.config/fish/completions/krunbox.fish

    Parameters:
        shell: The target shell ('bash', 'zsh', or 'fish').
        target_path: Optional custom destination file path.

    Returns:
        A tuple of (success: bool, message: str).
    """
    s = (shell or "").strip().lower()
    if s not in SUPPORTED_SHELLS:
        supported = ", ".join(SUPPORTED_SHELLS)
        return False, f"Unsupported shell: '{shell}'. Supported shells: {supported}"

    try:
        script = get_completion_script(s)
    except Exception as e:
        return False, f"Failed to generate {s} completion script: {e}"

    dest = target_path if target_path is not None else DEFAULT_INSTALL_PATHS[s]
    dest = Path(dest).expanduser().resolve()

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(script, encoding="utf-8")
        dest.chmod(0o644)
        return True, f"Successfully installed {s} completion script to {dest}"
    except Exception as e:
        return False, f"Failed to install {s} completion script to {dest}: {e}"
