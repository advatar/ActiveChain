#!/usr/bin/env bash
set -euo pipefail

snapshot=${1:?usage: check-validator-snapshot.sh <validator-snapshot> [indexer-tool]}
indexer=${2:-target/release/indexer-tool}

test -r "$snapshot"
test -x "$indexer"
"$indexer" "$snapshot" >/dev/null
echo "validator snapshot compatible: $snapshot"
