#!/usr/bin/env bash
set -euo pipefail

duration_seconds="${1:-30}"
workers_per_mode="${2:-1}"

case "$duration_seconds" in
  ''|*[!0-9]*) echo "duration must be a positive integer" >&2; exit 2 ;;
esac
case "$workers_per_mode" in
  ''|*[!0-9]*) echo "workers per mode must be a positive integer" >&2; exit 2 ;;
esac
if (( duration_seconds == 0 || workers_per_mode == 0 )); then
  echo "duration and workers per mode must be positive" >&2
  exit 2
fi

# Build exactly once. Workers invoke the resulting test executable directly, avoiding
# overlapping Cargo builds and exercising distinct operating-system processes.
cargo test --offline -p activechain-payment-connector-host --no-run
target_directory="$(cargo metadata --offline --no-deps --format-version 1 \
  | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')"
test_binary="$(find "$target_directory/debug/deps" -type f \
  -name 'activechain_payment_connector_host-*' -perm -111 \
  | LC_ALL=C sort | tail -n 1)"
if [[ -z "$test_binary" || ! -x "$test_binary" ]]; then
  echo "connector-host test executable was not found" >&2
  exit 1
fi

run_worker() {
  local mode="$1"
  local test_name="$2"
  local worker="$3"
  local deadline=$((SECONDS + duration_seconds))
  local iterations=0
  while (( SECONDS < deadline )); do
    if [[ "$mode" == "fd-exhaustion" ]]; then
      (ulimit -n 128 && "$test_binary" "$test_name" --exact --test-threads=1 >/dev/null)
    else
      "$test_binary" "$test_name" --exact --test-threads=1 >/dev/null
    fi
    iterations=$((iterations + 1))
  done
  if (( iterations == 0 )); then
    echo "$mode worker $worker completed no iterations" >&2
    return 1
  fi
  printf '%s,%s,%s\n' "$mode" "$worker" "$iterations"
}

work_directory="$(mktemp -d "${TMPDIR:-/tmp}/activebridge-chaos.XXXXXX")"
trap 'rm -rf "$work_directory"' EXIT

modes=(
  "load:tests::bounded_multi_intent_restart_soak_preserves_complete_aggregate"
  "outage:simulator::tests::contract_suite_covers_success_rejection_reversal_and_unknown"
  "partition:simulator::tests::invalid_terminal_edges_and_sequence_faults_fail_closed"
  "write-pressure:tests::settlement_state_rejects_partial_state_and_failed_atomic_write"
  "fd-exhaustion:tests::file_descriptor_exhaustion_cannot_advance_live_or_durable_settlement_state"
)

pids=()
for entry in "${modes[@]}"; do
  mode="${entry%%:*}"
  test_name="${entry#*:}"
  for ((worker = 1; worker <= workers_per_mode; worker++)); do
    run_worker "$mode" "$test_name" "$worker" >"$work_directory/$mode-$worker.result" &
    pids+=("$!")
  done
done

failed=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    failed=1
  fi
done
if (( failed != 0 )); then
  echo "one or more chaos workers failed" >&2
  exit 1
fi

total_iterations=0
for result in "$work_directory"/*.result; do
  IFS=, read -r _mode _worker iterations <"$result"
  total_iterations=$((total_iterations + iterations))
done

printf '{"schema":"activechain-activebridge-multiprocess-chaos-v1","duration_seconds":%s,"workers_per_mode":%s,"modes":5,"processes":%s,"iterations":%s,"result":"passed"}\n' \
  "$duration_seconds" "$workers_per_mode" "$((workers_per_mode * 5))" "$total_iterations"
