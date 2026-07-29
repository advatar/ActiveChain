#!/bin/sh
set -eu

deployment_root=${ACTIVECHAIN_KANALEN_ROOT:-"$HOME/activechain-deploy/kanalen"}
state_root="$deployment_root/chain"
binary_root="$deployment_root/current/bin"
rpc_root="$deployment_root/rpc"
rpc_snapshot="$rpc_root/rpc-index.snapshot"
network_env="$deployment_root/network.env"
lock="$state_root/round.lock"

test -f "$network_env" || {
  echo "runtime network manifest is missing: $network_env" >&2
  exit 1
}

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

attempt=1
max_attempts=3
while ! "$binary_root/validator-node" \
  49150 "$state_root/validator-0.snapshot" "$state_root/genesis.bin" 0 0 --once \
  --key-file="$state_root/keys/validator-0.key" \
  --peer=2@127.0.0.1:49154 --peer=3@127.0.0.1:49155; do
  if test "$attempt" -ge "$max_attempts"; then
    echo "validator round failed after $max_attempts attempts" >&2
    exit 1
  fi
  echo "validator round attempt $attempt failed; retrying" >&2
  attempt=$((attempt + 1))
  sleep 1
done
if test ! -f "$rpc_snapshot"; then
  chain_id=$(sed -n 's/^ACTIVECHAIN_CHAIN_ID_HEX=//p' "$network_env")
  test -n "$chain_id" || {
    echo "network.env does not define ACTIVECHAIN_CHAIN_ID_HEX" >&2
    exit 1
  }
  "$binary_root/activechain-rpc-bootstrap" \
    "$state_root/genesis.bin" "$chain_id" "$rpc_snapshot"
fi
if test -f "$state_root/finalized-cash.snapshot" && test -f "$state_root/finality.bundle"; then
  "$binary_root/activechain-rpc-ingest" \
    "$state_root/validator-0.snapshot" "$deployment_root/rpc/rpc-index.snapshot" \
    "$state_root/finalized-cash.snapshot" "$state_root/finality.bundle"
else
  "$binary_root/activechain-rpc-ingest" \
    "$state_root/validator-0.snapshot" "$deployment_root/rpc/rpc-index.snapshot"
fi
