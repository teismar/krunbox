#!/bin/bash
# Root-side boot for the agent box.
# Runs as root (container ENTRYPOINT): prepares the guest for nested
# containers, starts dockerd, then drops privileges to the agent user.
set -u

USERNAME="${USERNAME:-vscode}"
log() { echo "[entrypoint] $*"; }

# 1. cgroup v2 -- krun's guest init usually has this mounted already.
if ! mountpoint -q /sys/fs/cgroup 2>/dev/null; then
    if mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null; then
        log "mounted cgroup2"
    else
        log "WARN: could not mount cgroup2; nested containers may fail"
    fi
fi

# 2. SSH daemon (start early so host access is available immediately).
mkdir -p /var/run/sshd
ssh-keygen -A 2>/dev/null || true
USER_SSH_DIR="/home/${USERNAME}/.ssh"
mkdir -p "$USER_SSH_DIR"
if [ -n "${SSH_AUTH_KEYS:-}" ]; then
    echo "$SSH_AUTH_KEYS" > "${USER_SSH_DIR}/authorized_keys"
    chmod 600 "${USER_SSH_DIR}/authorized_keys"
fi
chown -R "${USERNAME}:${USERNAME}" "$USER_SSH_DIR" 2>/dev/null || true
chmod 700 "$USER_SSH_DIR" 2>/dev/null || true
if ! grep -q 'SSH_CONNECTION.*workspace' "/home/${USERNAME}/.bashrc" 2>/dev/null; then
    printf '\n# Default to /workspace on interactive SSH sessions\nif [ -n "${SSH_CONNECTION:-}" ] && [ "$PWD" = "$HOME" ] && [ -d /workspace ]; then\n    cd /workspace\nfi\n' >> "/home/${USERNAME}/.bashrc"
fi
/usr/sbin/sshd -E /var/log/sshd.log && log "sshd up on port 2222" || log "WARN: could not start sshd"
chmod 644 /var/log/sshd.log 2>/dev/null || true

# 3. Networking for the nested containers.
#    The krun guest kernel has no xtables (iptables) support, but full
#    nftables NAT. dockerd runs with iptables disabled (see daemon.json);
#    we masquerade the RFC1918 docker pools out of the default interface.
sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null || true
UPLINK="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
UPLINK="${UPLINK:-eth0}"
nft add table ip docker-nat 2>/dev/null || true
nft 'add chain ip docker-nat postrouting { type nat hook postrouting priority srcnat; policy accept; }' 2>/dev/null || true
if nft add rule ip docker-nat postrouting ip saddr '{ 172.16.0.0/12, 192.168.0.0/16 }' oifname "$UPLINK" masquerade 2>/dev/null; then
    log "nftables masquerade for nested containers up (via $UPLINK)"
else
    log "WARN: could not install nftables masquerade; nested containers may lack outbound network"
fi

# 3b. krunbox egress security policy (domain whitelist / offline airgap)
if [ -f /etc/krunbox-egress.sh ]; then
    log "applying krunbox egress firewall policy..."
    /bin/bash /etc/krunbox-egress.sh 2>&1 | while read -r line; do log "$line"; done || log "WARN: failed to apply egress policy"
fi

# 3. Docker data directory.
#    The container rootfs is virtiofs (krun) or overlayfs (plain podman/docker),
#    neither of which supports the overlayfs upper layer the containerd
#    overlayfs snapshotter needs. So:
#      - a persistent volume mounted at /var/lib/docker -> keep it, but use
#        the vfs storage driver (virtiofs volumes also lack overlay support)
#      - otherwise -> mount a tmpfs sized to half the guest RAM, which does
#        support overlay; inner containers then use the fast overlayfs driver
mkdir -p /var/lib/docker /var/run/docker
DOCKERD_ARGS=()
if mountpoint -q /var/lib/docker; then
    log "/var/lib/docker is a mounted volume; using vfs storage driver"
    DOCKERD_ARGS=(--storage-driver=vfs)
else
    SIZE_KB=$(( $(awk '/MemTotal/{print $2}' /proc/meminfo) / 2 ))
    if mount -t tmpfs -o "size=${SIZE_KB}k" tmpfs /var/lib/docker; then
        log "tmpfs ($((SIZE_KB / 1024)) MiB) mounted at /var/lib/docker"
    else
        log "WARN: could not mount tmpfs for /var/lib/docker; using vfs storage driver"
        DOCKERD_ARGS=(--storage-driver=vfs)
    fi
fi

# 4. dockerd -- Docker-in-Docker inside the microVM.
start_dockerd() {
    dockerd "${DOCKERD_ARGS[@]}" "$@" >/tmp/dockerd.log 2>&1 &
    echo $!
}

wait_docker() {
    local i
    for i in $(seq 1 60); do
        docker info >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

dockerd_pid="$(start_dockerd)"
if wait_docker; then
    log "dockerd up (storage driver: $(docker info --format '{{.Driver}}' 2>/dev/null))"
else
    # overlay2 may not work on the virtiofs-backed rootfs -> fall back to vfs.
    log "dockerd failed with default settings, retrying with --storage-driver=vfs"
    kill "$dockerd_pid" 2>/dev/null || true
    sleep 2
    dockerd_pid="$(start_dockerd --storage-driver=vfs)"
    if wait_docker; then
        log "dockerd up (vfs)"
    else
        log "WARN: dockerd did not come up; nested containers will not work."
        log "      Inspect /tmp/dockerd.log inside the container for details."
    fi
fi

# 5. Hand the persisted config dirs (named volumes) to the agent
#    user. Podman creates named-volume directories owned by the container's
#    root mapping, so without this the agent CLIs fail with
#    "permission denied" when writing ~/.gemini / ~/.vibe.
#    The chown is only possible on a fresh volume (afterwards the dirs are
#    owned by the host user, which the guest root cannot chown again), so it
#    is skipped once the ownership is already correct.
AGENT_UID="$(id -u "${USERNAME}")"
AGENT_GID="$(id -g "${USERNAME}")"
for d in /home/vscode/.gemini /home/vscode/.vibe; do
    [ -d "$d" ] || continue
    if [ "$(stat -c '%u:%g' "$d" 2>/dev/null)" = "${AGENT_UID}:${AGENT_GID}" ]; then
        continue
    fi
    chown -R "${USERNAME}:${USERNAME}" "$d" 2>/dev/null \
        || log "WARN: could not chown $d to ${USERNAME}"
done

# 5b. Auto-provision in-guest krunbox-gateway MCP server config
_krun_mcp_cmd="/run/krunbox/krunbox-mcp"
if [ ! -f "$_krun_mcp_cmd" ] && [ -x /usr/local/bin/krunbox-mcp ]; then
    _krun_mcp_cmd="/usr/local/bin/krunbox-mcp"
fi
if command -v python3 >/dev/null 2>&1; then
    python3 -c "import json, os, sys
cmd = sys.argv[1] if len(sys.argv) > 1 else '/run/krunbox/krunbox-mcp'
cfg = {'command': cmd, 'args': []}
paths = [
    '/workspace/.agents/mcp_config.json',
    '/workspace/.antigravity/mcp_config.json',
    '/workspace/.gemini/mcp_config.json',
]
for h in ['/home/${USERNAME}', '/root']:
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
    "/home/${USERNAME}/.gemini/config/mcp_config.json" \
    "/home/${USERNAME}/.gemini/antigravity-cli/mcp_config.json" \
    "/home/${USERNAME}/.config/antigravity/mcp_config.json" \
    "/home/${USERNAME}/.config/Claude/claude_desktop_config.json" \
    "/home/${USERNAME}/.cursor/mcp.json" \
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
chown -R "${USERNAME}:${USERNAME}" "/home/${USERNAME}/.gemini" "/home/${USERNAME}/.config" "/home/${USERNAME}/.cursor" /workspace/.agents /workspace/.antigravity /workspace/.gemini 2>/dev/null || true


# 6. Optional host-requested egress & privilege lockdown (KRUNBOX_LOCK_EGRESS=1)
if [ "${KRUNBOX_LOCK_EGRESS:-0}" = "1" ]; then
    log "applying in-guest egress lockdown (sudoers firewall restriction & capability drop)"
    mkdir -p /etc/sudoers.d
    cat > /etc/sudoers.d/zz-krunbox-egress-lockdown <<EOF
${USERNAME} ALL=(ALL) NOPASSWD: ALL, !/usr/sbin/nft, !/sbin/nft, !/usr/sbin/iptables, !/usr/sbin/iptables-nft, !/usr/sbin/ip6tables, !/sbin/ip, !/usr/sbin/ip, !/bin/ip, !/usr/bin/nsenter, !/usr/bin/unshare
EOF
    chmod 0440 /etc/sudoers.d/zz-krunbox-egress-lockdown 2>/dev/null || true
fi

# 7. Drop to the agent user (session dbus + keyring are set up there).
if [ "${KRUNBOX_LOCK_EGRESS:-0}" = "1" ] && command -v setpriv >/dev/null 2>&1 && setpriv --bounding-set=-net_admin true 2>/dev/null; then
    exec setpriv --bounding-set=-net_admin gosu "${USERNAME}" /usr/local/bin/agent-session.sh "$@"
else
    exec gosu "${USERNAME}" /usr/local/bin/agent-session.sh "$@"
fi
