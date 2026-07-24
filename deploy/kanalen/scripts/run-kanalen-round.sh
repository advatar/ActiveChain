#!/bin/sh
set -eu

deployment_root=${ACTIVECHAIN_KANALEN_ROOT:-"$HOME/activechain-deploy/kanalen"}
state_root="$deployment_root/chain"
binary_root="$deployment_root/current/bin"
lock="$state_root/round.lock"

mkdir "$lock" 2>/dev/null || exit 0
trap 'rmdir "$lock"' EXIT

for port in 49154 49155; do
  attempts=0
  until nc -z 127.0.0.1 "$port"; do
    attempts=$((attempts + 1))
    test "$attempts" -lt 50 || {
      echo "validator listener $port is unavailable" >&2
      exit 1
    }
    sleep 0.1
  done
done

"$binary_root/validator-node" \
  49150 "$state_root/validator-0.snapshot" "$state_root/genesis.bin" 0 0 --once \
  --peer=2@127.0.0.1:49154 --peer=3@127.0.0.1:49155
"$binary_root/activechain-rpc-ingest" \
  "$state_root/validator-0.snapshot" "$deployment_root/rpc/rpc-index.snapshot"
