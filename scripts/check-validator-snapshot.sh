#!/usr/bin/env bash
set -euo pipefail

snapshot=${1:?usage: check-validator-snapshot.sh <validator-snapshot> [indexer-tool]}
indexer=${2:-target/release/indexer-tool}
expected_schema=${ACTIVECHAIN_EXPECTED_SNAPSHOT_SCHEMA_VERSION:-1}

test -r "$snapshot"
test -x "$indexer"
metadata=$("$indexer" "$snapshot")
schema=$(printf '%s\n' "$metadata" | sed -n 's/.*"snapshot_schema_version":\([0-9][0-9]*\).*/\1/p')
test "$schema" = "$expected_schema" || {
  echo "validator snapshot schema mismatch: expected $expected_schema, got ${schema:-missing}" >&2
  exit 1
}
if test -n "${ACTIVECHAIN_EXPECTED_GENESIS_COMMITMENT:-}"; then
  genesis=$(printf '%s\n' "$metadata" | sed -n 's/.*"genesis_commitment":"\([0-9a-fA-F]*\)".*/\1/p')
  test "$genesis" = "$ACTIVECHAIN_EXPECTED_GENESIS_COMMITMENT" || {
    echo "validator snapshot genesis mismatch" >&2
    exit 1
  }
fi
echo "validator snapshot compatible: $snapshot"
