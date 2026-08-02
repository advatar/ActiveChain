#!/usr/bin/env bash
set -euo pipefail

snapshot=${1:?usage: check-execution-snapshot.sh <execution-snapshot> [indexer-tool]}
indexer=${2:-target/release/indexer-tool}
expected_schema=${ACTIVECHAIN_EXPECTED_EXECUTION_SCHEMA_VERSION:-5}

test -r "$snapshot"
test -x "$indexer"
metadata=$("$indexer" --execution "$snapshot")
target_schema=$(printf '%s\n' "$metadata" | sed -n 's/.*"target_schema_version":\([0-9][0-9]*\).*/\1/p')
test "$target_schema" = "$expected_schema" || {
  echo "execution snapshot target schema mismatch: expected $expected_schema, got ${target_schema:-missing}" >&2
  exit 1
}
if test -n "${ACTIVECHAIN_EXPECTED_CHAIN_ID:-}"; then
  chain=$(printf '%s\n' "$metadata" | sed -n 's/.*"chain_id":"\([0-9a-fA-F]*\)".*/\1/p')
  test "$chain" = "$ACTIVECHAIN_EXPECTED_CHAIN_ID" || {
    echo "execution snapshot chain mismatch" >&2
    exit 1
  }
fi
if test -n "${ACTIVECHAIN_EXPECTED_EXECUTION_HEIGHT:-}"; then
  height=$(printf '%s\n' "$metadata" | sed -n 's/.*"height":\([0-9][0-9]*\).*/\1/p')
  test "$height" = "$ACTIVECHAIN_EXPECTED_EXECUTION_HEIGHT" || {
    echo "execution snapshot height mismatch: expected $ACTIVECHAIN_EXPECTED_EXECUTION_HEIGHT, got ${height:-missing}" >&2
    exit 1
  }
fi
echo "execution snapshot compatible: $snapshot"
