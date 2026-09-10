#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
python=${ACTIVECHAIN_TEST_PYTHON:-/opt/homebrew/bin/python3}
umask 077
"$python" -m venv "$root/venv"
"$root/venv/bin/pip" install -r "$root/requirements.txt"
# A session-scoped development service, deliberately separate from validator launch agents.
# Re-run after a host restart. Refuse to start over an existing listener.
if /usr/sbin/lsof -nP -iTCP:49159 -sTCP:LISTEN >/dev/null; then
    echo "Port 49159 is already in use; keep the existing receiver." >&2
    exit 1
fi
nohup "$root/venv/bin/python" "$root/receiver.py" --database "$root/sessions.sqlite" > "$root/service.log" 2>&1 < /dev/null &
echo "$!" > "$root/service.pid"
