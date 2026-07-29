#!/usr/bin/env bash
set -euo pipefail

workdir="$(mktemp -d "${TMPDIR:-/tmp}/activechain-process-rehearsal.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

genesis="$workdir/genesis.bin"
keys="$workdir/keys"
cargo run --quiet -p activechain-consensus-runtime --bin genesis-tool -- "$genesis" 1 1 3 "$keys"

for index in 0 1 2; do
  snapshot="$workdir/validator-${index}.snapshot"
  output="$workdir/validator-${index}.out"
  cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
    $((4400 + index)) "$snapshot" "$genesis" 0 "$index" --once \
    "--key-file=$keys/validator-$index.key" >"$output"
  rg --fixed-strings "finalized_height=0" "$output"
  rg --fixed-strings "proposals=1 votes=1 rejected=0" "$output"
  test -s "$snapshot"
  snapshot_before_restart=$(shasum -a 256 "$snapshot" | awk '{print $1}')
  restart_output="$workdir/validator-${index}-restart.out"
  cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
    $((4400 + index)) "$snapshot" "$genesis" 0 "$index" --once \
    "--key-file=$keys/validator-$index.key" >"$restart_output"
  # One member of a three-validator genesis cannot finalize without quorum. The separate live
  # process rehearsal below the CI gate supplies all three votes and requires height 1.
  rg --fixed-strings "finalized_height=0" "$restart_output"
  rg --fixed-strings "proposals=1 votes=1 rejected=0" "$restart_output"
  snapshot_after_restart=$(shasum -a 256 "$snapshot" | awk '{print $1}')
  test "$snapshot_before_restart" != "$snapshot_after_restart"
done

echo "validator process rehearsal passed for three genesis-bound PQ nodes"
