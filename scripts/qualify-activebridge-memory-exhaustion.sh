#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
image=${ACTIVECHAIN_LINUX_RUST_IMAGE:-providehr-ci-runner:ubuntu-24.04-arm64}
memory_limit=${ACTIVECHAIN_MEMORY_LIMIT:-192m}
suffix="$$"
target_volume="activechain-memory-target-${suffix}"
state_volume="activechain-memory-state-${suffix}"
test_name="tests::memory_exhaustion_cannot_replace_durable_settlement_state"

cleanup() {
  docker volume rm -f "$target_volume" "$state_volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "$target_volume" >/dev/null
docker volume create "$state_volume" >/dev/null

docker run --rm --entrypoint sh \
  -v "$root:/workspace:ro" \
  -v "$target_volume:/target" \
  "$image" -lc \
  'cd /workspace && CARGO_TARGET_DIR=/target cargo test -p activechain-payment-connector-host --no-run'

run_test() {
  local mode="$1"
  docker run --rm --entrypoint sh \
    -e ACTIVECHAIN_MEMORY_EXHAUSTION_MODE="$mode" \
    -e ACTIVECHAIN_MEMORY_EXHAUSTION_PATH=/state/settlement.bin \
    -v "$target_volume:/target:ro" \
    -v "$state_volume:/state" \
    "$image" -lc \
    "binary=\$(find /target/debug/deps -type f -name 'activechain_payment_connector_host-*' -perm -111 | LC_ALL=C sort | tail -n 1); exec \"\$binary\" '$test_name' --exact --test-threads=1"
}

run_test prepare
before=$(docker run --rm --entrypoint sha256sum -v "$state_volume:/state:ro" "$image" /state/settlement.bin)

set +e
docker run --rm --memory "$memory_limit" --memory-swap "$memory_limit" --entrypoint sh \
  -e ACTIVECHAIN_MEMORY_EXHAUSTION_MODE=mutate \
  -e ACTIVECHAIN_MEMORY_EXHAUSTION_PATH=/state/settlement.bin \
  -v "$target_volume:/target:ro" \
  -v "$state_volume:/state" \
  "$image" -lc \
  "binary=\$(find /target/debug/deps -type f -name 'activechain_payment_connector_host-*' -perm -111 | LC_ALL=C sort | tail -n 1); exec \"\$binary\" '$test_name' --exact --test-threads=1"
child_status=$?
set -e
if (( child_status == 0 )); then
  echo "memory-constrained settlement child unexpectedly succeeded" >&2
  exit 1
fi

after=$(docker run --rm --entrypoint sha256sum -v "$state_volume:/state:ro" "$image" /state/settlement.bin)
if [[ "$before" != "$after" ]]; then
  echo "memory exhaustion changed the authoritative settlement snapshot" >&2
  exit 1
fi
run_test verify
printf '{"schema":"activechain-activebridge-memory-exhaustion-v1","limit":"%s","child_status":%s,"snapshot":"unchanged","restart":"verified","result":"passed"}\n' \
  "$memory_limit" "$child_status"
