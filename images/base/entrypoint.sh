#!/bin/bash
# Root-side boot entrypoint for krunbox lightweight base microVMs.
# Starts sshd on port 2222, provisions user keys, and drops privileges to vscode.
set -u

USERNAME="${USERNAME:-vscode}"
USER_HOME="/home/${USERNAME}"
USER_SSH_DIR="${USER_HOME}/.ssh"

log() { echo "[krunbox-base] $*"; }

# 1. SSH Server and host keys
if [ "$(id -u)" = "0" ]; then
    mkdir -p /var/run/sshd
    ssh-keygen -A 2>/dev/null || true
fi

# 2. Inject host public SSH keys if passed in SSH_AUTH_KEYS
mkdir -p "${USER_SSH_DIR}"
if [ -n "${SSH_AUTH_KEYS:-}" ]; then
    echo "${SSH_AUTH_KEYS}" > "${USER_SSH_DIR}/authorized_keys"
    chmod 600 "${USER_SSH_DIR}/authorized_keys" 2>/dev/null || true
fi
chmod 700 "${USER_SSH_DIR}" 2>/dev/null || true
chown -R "${USERNAME}:${USERNAME}" "${USER_SSH_DIR}" 2>/dev/null || true

# 3. Ensure /workspace is writable by the vscode user
mkdir -p /workspace
chown "${USERNAME}:${USERNAME}" /workspace 2>/dev/null || true

# 4. Default interactive SSH sessions directly into /workspace
if ! grep -q 'SSH_CONNECTION.*workspace' "${USER_HOME}/.bashrc" 2>/dev/null; then
    printf '\n# Default to /workspace on interactive SSH sessions\nif [ -n "${SSH_CONNECTION:-}" ] && [ "$PWD" = "$HOME" ] && [ -d /workspace ]; then\n    cd /workspace\nfi\n' >> "${USER_HOME}/.bashrc" 2>/dev/null || true
fi

# 5. Fix ownership for persistent named volumes if present
for d in "${USER_HOME}/.gemini" "${USER_HOME}/.vibe"; do
    [ -d "$d" ] || continue
    chown -R "${USERNAME}:${USERNAME}" "$d" 2>/dev/null || true
done

# 6. Start OpenSSH daemon on microVM port 2222 (or custom $SSH_PORT)
SSH_PORT="${SSH_PORT:-2222}"
if [ "$(id -u)" = "0" ]; then
    /usr/sbin/sshd -p "${SSH_PORT}" -E /var/log/sshd.log 2>/dev/null || /usr/sbin/sshd -p "${SSH_PORT}" || log "WARN: could not start sshd"
elif command -v sudo >/dev/null 2>&1; then
    sudo mkdir -p /var/run/sshd 2>/dev/null || true
    sudo ssh-keygen -A 2>/dev/null || true
    sudo /usr/sbin/sshd -p "${SSH_PORT}" -E /var/log/sshd.log 2>/dev/null || sudo /usr/sbin/sshd -p "${SSH_PORT}" || log "WARN: could not start sshd"
else
    log "WARN: non-root user and sudo unavailable; sshd cannot be started"
fi
log "OpenSSH daemon ready on port ${SSH_PORT}"

# 7. Apply krunbox egress security policy if configured
if [ -f /etc/krunbox-egress.sh ]; then
    if [ "$(id -u)" = "0" ]; then
        /bin/bash /etc/krunbox-egress.sh 2>&1 || log "WARN: failed to apply egress policy"
    elif command -v sudo >/dev/null 2>&1; then
        sudo /bin/bash /etc/krunbox-egress.sh 2>&1 || log "WARN: failed to apply egress policy"
    fi
fi

# 8. Auto-register in-sandbox krunbox-gateway MCP server if available
if [ -f /run/krunbox/krunbox-mcp ] || [ -f /usr/local/bin/krunbox-mcp ] || [ -d /run/krunbox ] || [ -f /etc/krunbox-egress.sh ]; then
    _krun_mcp_cmd="/run/krunbox/krunbox-mcp"
    if [ ! -f "$_krun_mcp_cmd" ] && [ -x /usr/local/bin/krunbox-mcp ]; then
        _krun_mcp_cmd="/usr/local/bin/krunbox-mcp"
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import json, os, sys
cmd = sys.argv[1] if len(sys.argv) > 1 else '/run/krunbox/krunbox-mcp'
cfg = {'command': cmd, 'args': []}
homes = ['${USER_HOME}', '/root']
paths = [
    '/workspace/.agents/mcp_config.json',
    '/workspace/.antigravity/mcp_config.json',
    '/workspace/.gemini/mcp_config.json'
]
for h in homes:
    if os.path.isdir(h):
        paths.extend([
            os.path.join(h, '.gemini/config/mcp_config.json'),
            os.path.join(h, '.gemini/antigravity-cli/mcp_config.json'),
            os.path.join(h, '.config/antigravity/mcp_config.json'),
            os.path.join(h, '.config/Claude/claude_desktop_config.json'),
            os.path.join(h, '.cursor/mcp.json'),
        ])
for p in paths:
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        d = {}
        if os.path.exists(p) and os.path.getsize(p) > 0:
            try:
                with open(p, 'r', encoding='utf-8') as rf:
                    loaded = json.load(rf)
                    if isinstance(loaded, dict):
                        d = loaded
            except Exception:
                d = {}
        servers = d.setdefault('mcpServers', {})
        if 'krunbox-gateway' not in servers or servers['krunbox-gateway'] != cfg:
            servers['krunbox-gateway'] = cfg
            with open(p, 'w', encoding='utf-8') as wf:
                json.dump(d, wf, indent=2)
        try:
            os.chmod(p, 0o666)
        except Exception:
            pass
    except Exception:
        pass
" "$_krun_mcp_cmd" 2>/dev/null || true
    fi
    _mcp_json='{
  "mcpServers": {
    "krunbox-gateway": {
      "command": "'"${_krun_mcp_cmd}"'",
      "args": []
    }
  }
}'
    for _target in \
        "${USER_HOME}/.gemini/config/mcp_config.json" \
        "${USER_HOME}/.gemini/antigravity-cli/mcp_config.json" \
        "${USER_HOME}/.config/antigravity/mcp_config.json" \
        "${USER_HOME}/.config/Claude/claude_desktop_config.json" \
        "${USER_HOME}/.cursor/mcp.json" \
        "/workspace/.agents/mcp_config.json" \
        "/workspace/.antigravity/mcp_config.json" \
        "/workspace/.gemini/mcp_config.json" \
        "/root/.gemini/config/mcp_config.json"; do
        if [ ! -s "$_target" ]; then
            mkdir -p "$(dirname "$_target")" 2>/dev/null || true
            printf '%s\n' "$_mcp_json" > "$_target" 2>/dev/null || true
            chmod 0666 "$_target" 2>/dev/null || true
        fi
    done
    chown -R "${USERNAME}:${USERNAME}" "${USER_HOME}/.gemini" "${USER_HOME}/.config" "${USER_HOME}/.cursor" /workspace/.agents /workspace/.antigravity /workspace/.gemini 2>/dev/null || true
fi

# 9. Dropping to vscode user or running keepalive loop
drop_to_user() {
    if [ "$(id -u)" = "0" ]; then
        exec gosu "${USERNAME}" "$@"
    else
        exec "$@"
    fi
}

if [ $# -gt 0 ] && [ "$*" != "/bin/bash" ] && [ "$*" != "bash" ]; then
    drop_to_user "$@"
elif [ -t 0 ]; then
    drop_to_user /bin/bash
else
    trap "exit 0" TERM INT
    while :; do sleep 1 & wait $!; done
fi
