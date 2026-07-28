#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=scripts/lib/formal-output.sh
source "$root/scripts/lib/formal-output.sh"

captured=$(
  capture_formal_output sh -c \
    'printf "%s\n" stdout-marker; printf "%s\n" stderr-marker >&2'
)
grep -qx 'stdout-marker' <<<"$captured"
grep -qx 'stderr-marker' <<<"$captured"

if capture_formal_output sh -c 'exit 23' | tee /dev/null; then
  echo "formal output capture hid a command failure" >&2
  exit 1
fi

echo "formal output capture test passed"
