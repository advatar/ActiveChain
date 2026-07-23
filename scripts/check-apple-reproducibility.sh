#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
source_revision=${1:-$(git -C "$repo_root" rev-parse HEAD)}
temporary=$(mktemp -d /tmp/activechain-apple-reproducibility.XXXXXX)
cleanup() {
  rm -rf "$temporary"
}
trap cleanup EXIT

"$repo_root/scripts/build-apple-distribution.sh" "$temporary/first" "$source_revision"
"$repo_root/scripts/build-apple-distribution.sh" "$temporary/second" "$source_revision"

cmp \
  "$temporary/first/activechain-compatibility.json" \
  "$temporary/second/activechain-compatibility.json"
diff -qr "$temporary/first" "$temporary/second"
"$repo_root/scripts/check-apple-distribution.sh" "$temporary/first"
