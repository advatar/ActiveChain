#!/usr/bin/env bash
set -euo pipefail

workdir="$(mktemp -d "${TMPDIR:-/tmp}/activechain-view-change.XXXXXX")"
genesis="$workdir/genesis.bin"
keys="$workdir/keys"
pids=()

cleanup() {
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
}
diagnose() {
  status=$?
  if (( status != 0 )); then
    for log in "$workdir"/*.out; do
      test -f "$log" || continue
      echo "=== $log ===" >&2
      tail -n 80 "$log" >&2
    done
  fi
  cleanup
  exit "$status"
}
trap diagnose EXIT

cargo run --quiet -p activechain-consensus-runtime --bin genesis-tool -- \
  "$genesis" 1 1 3 "$keys" >/dev/null

for index in 0 1 2; do
  port=$((4520 + index))
  peer_one=$(((index + 1) % 3))
  peer_two=$(((index + 2) % 3))
  cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
    "$port" "$workdir/v${index}.snapshot" "$genesis" 0 "$index" \
    --timeout-once --timeout-delay-ms=2000 \
    --key-file="$keys/validator-${index}.key" \
    --peer="$((peer_one + 1))@127.0.0.1:$((4520 + peer_one))" \
    --peer="$((peer_two + 1))@127.0.0.1:$((4520 + peer_two))" \
    >"$workdir/v${index}.out" 2>&1 &
  pids+=("$!")
done

for pid in "${pids[@]}"; do
  wait "$pid"
done
pids=()

for index in 0 1 2; do
  rg --fixed-strings \
    "completed timeout quorum: height=1 timed_out_round=0 next_round=1" \
    "$workdir/v${index}.out"
done

# Round one belongs to validator index one. The failed round-zero leader cannot keep proposing.
if cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  4523 "$workdir/v0.snapshot" "$genesis" 0 0 --once \
  --key-file="$keys/validator-0.key" >"$workdir/stale-leader.out" 2>&1; then
  echo "stale leader unexpectedly proposed after view change" >&2
  exit 1
fi
rg --fixed-strings "IneligibleProposer" "$workdir/stale-leader.out"

cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  4524 "$workdir/v1.snapshot" "$genesis" 0 1 --once \
  --key-file="$keys/validator-1.key" >"$workdir/rotated-leader.out" 2>&1
rg --fixed-strings "completed deterministic round" "$workdir/rotated-leader.out"

echo "consensus view-change process rehearsal passed"
