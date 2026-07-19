#!/usr/bin/env bash
set -euo pipefail

workdir="$(mktemp -d "${TMPDIR:-/tmp}/activechain-process-rehearsal.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

genesis="$workdir/genesis.bin"
cargo run --quiet -p activechain-consensus-runtime --bin genesis-tool -- "$genesis" 1 1 3

for index in 0 1 2; do
  snapshot="$workdir/validator-${index}.snapshot"
  output="$workdir/validator-${index}.out"
  cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
    $((4400 + index)) "$snapshot" "$genesis" 0 "$index" --once >"$output"
  rg --fixed-strings "finalized_height=0" "$output"
  rg --fixed-strings "proposals=1 votes=1 rejected=0" "$output"
  test -s "$snapshot"
  restart_output="$workdir/validator-${index}-restart.out"
  cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
    $((4400 + index)) "$snapshot" "$genesis" 0 "$index" --once >"$restart_output"
  rg --fixed-strings "proposals=1 votes=1 rejected=0" "$restart_output"
done

echo "validator process rehearsal passed for three genesis-bound PQ nodes"
