#!/usr/bin/env bash
set -euo pipefail

workdir="$(mktemp -d "${TMPDIR:-/tmp}/activechain-live-quorum.XXXXXX")"
genesis="$workdir/genesis.bin"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
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

wait_for_listener() {
  local port="$1"
  local log="$2"
  for _ in {1..300}; do
    if rg --quiet --fixed-strings "activechain validator listening on 0.0.0.0:$port" "$log"; then
      sleep 1
      return 0
    fi
    sleep 0.1
  done
  cat "$log" >&2
  return 1
}

cargo run --quiet -p activechain-consensus-runtime --bin genesis-tool -- "$genesis" 1 1 3 >/dev/null

cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  4511 "$workdir/v1.snapshot" "$genesis" 0 1 >"$workdir/v1.out" 2>&1 &
pids+=("$!")
cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  4512 "$workdir/v2.snapshot" "$genesis" 0 2 >"$workdir/v2.out" 2>&1 &
pids+=("$!")
wait_for_listener 4511 "$workdir/v1.out"
wait_for_listener 4512 "$workdir/v2.out"

cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  4510 "$workdir/v0.snapshot" "$genesis" 0 0 --once \
  --peer=2@127.0.0.1:4511 --peer=3@127.0.0.1:4512 | tee "$workdir/proposer.out"

rg --fixed-strings "completed network round: finalized_height=0" "$workdir/proposer.out"
rg --fixed-strings "votes=3" "$workdir/proposer.out"
python3 - <<'PY'
import socket
for _ in range(32):
    sock = socket.create_connection(("127.0.0.1", 4511), timeout=2)
    sock.sendall((16 * 1024 + 1).to_bytes(4, "big"))
    sock.close()
PY
cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  4510 "$workdir/v0.snapshot" "$genesis" 0 0 --once \
  --peer=2@127.0.0.1:4511 --peer=3@127.0.0.1:4512 | tee "$workdir/proposer-child.out"
rg --fixed-strings "completed network round: finalized_height=1" "$workdir/proposer-child.out"
test -s "$workdir/v0.snapshot"
kill "${pids[1]}" 2>/dev/null || true
python3 - <<'PY'
import socket
try:
    socket.create_connection(("127.0.0.1", 4512), timeout=1)
except OSError:
    pass
else:
    raise SystemExit("partition probe unexpectedly connected")
PY
cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  4512 "$workdir/v2.snapshot" "$genesis" 0 2 >"$workdir/v2-restart.out" 2>&1 &
pids[1]="$!"
wait_for_listener 4512 "$workdir/v2-restart.out"
kill "${pids[0]}" 2>/dev/null || true
cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  4511 "$workdir/v1.snapshot" "$genesis" 0 1 >"$workdir/v1-restart.out" 2>&1 &
pids[0]="$!"
wait_for_listener 4511 "$workdir/v1-restart.out"
rg --fixed-strings "activechain validator listening on 0.0.0.0:4511" "$workdir/v1-restart.out"
echo "live process quorum rehearsal passed"
