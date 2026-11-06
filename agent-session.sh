#!/bin/bash
# User-side boot for the agent box (invoked by entrypoint.sh via gosu).
#
# Deliberately NO session dbus / gnome-keyring: a half-initialized Secret
# Service produces "keyring" errors in both CLIs. Both detect headless /
# container environments and store credentials in plain files instead:
#   agy   -> ~/.gemini/antigravity-cli/antigravity-oauth-token
#   vibe  -> ~/.vibe/.env
# Both directories are persisted by named volumes in krunbox.
set -u
export HOME="${HOME:-/home/vscode}"
export USER="${USER:-vscode}"

if [ "${1:-}" = "--" ]; then
    shift
fi

if [ $# -eq 0 ]; then
    exec /bin/bash
else
    exec "$@"
fi
