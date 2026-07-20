#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
manifest="$root/testing/vectors/manifest-v1.json"

jq -e '.manifest == "activechain-verifier-v1" and (.vectors | length > 0) and (.malformed_cases | length >= 4)' "$manifest" >/dev/null

jq -r '.vectors[] | [.source, .sha256] | @tsv' "$manifest" | while IFS=$'\t' read -r source expected; do
  actual=$(shasum -a 256 "$root/testing/vectors/$source" | awk '{print $1}')
  test "$actual" = "$expected" || { echo "hash mismatch: $source" >&2; exit 1; }
done

jq -r '.malformed_cases[].source' "$manifest" | while read -r source; do
  test -s "$root/testing/vectors/$source" || { echo "missing malformed fixture: $source" >&2; exit 1; }
done

light="$root/testing/vectors/light-client-v1.json"
jq -e '.manifest == "activechain-light-client-v1" and (.requirements | length >= 6)' "$light" >/dev/null
jq -r '.requirements[] | select(.source != null) | [.source, .sha256] | @tsv' "$light" | while IFS=$'\t' read -r source expected; do
  actual=$(shasum -a 256 "$root/testing/vectors/$source" | awk '{print $1}')
  test "$actual" = "$expected" || { echo "light-client hash mismatch: $source" >&2; exit 1; }
done

echo "verifier manifest checks passed"
