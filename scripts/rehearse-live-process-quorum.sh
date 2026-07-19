#!/usr/bin/env bash
set -euo pipefail

workdir="$(mktemp -d "${TMPDIR:-/tmp}/activechain-live-quorum.XXXXXX")"
genesis="$workdir/genesis.bin"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

cargo run --quiet -p activechain-consensus-runtime --bin genesis-tool -- "$genesis" 1 1 3 >/dev/null

cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  4511 "$workdir/v1.snapshot" "$genesis" 0 1 >"$workdir/v1.out" 2>&1 &
pids+=("$!")
cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  4512 "$workdir/v2.snapshot" "$genesis" 0 2 >"$workdir/v2.out" 2>&1 &
pids+=("$!")
sleep 2

cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  4510 "$workdir/v0.snapshot" "$genesis" 0 0 --once \
  --peer=2@127.0.0.1:4511 --peer=3@127.0.0.1:4512 | tee "$workdir/proposer.out"

rg --fixed-strings "completed network round: finalized_height=1" "$workdir/proposer.out"
test -s "$workdir/v0.snapshot"
echo "live process quorum rehearsal passed"
