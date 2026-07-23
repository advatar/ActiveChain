#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
manifest="$root/testing/vectors/manifest-v1.json"

jq -e '.manifest == "activechain-verifier-v1"
  and .envelope_hash_manifest == "envelope-manifest-v1.json"
  and (.vectors | length > 0)
  and (.malformed_cases | length >= 4)' "$manifest" >/dev/null

jq -r '.vectors[] | [.source, .sha256] | @tsv' "$manifest" | while IFS=$'\t' read -r source expected; do
  actual=$(shasum -a 256 "$root/testing/vectors/$source" | awk '{print $1}')
  test "$actual" = "$expected" || { echo "hash mismatch: $source" >&2; exit 1; }
done

jq -r '.malformed_cases[].source' "$manifest" | while read -r source; do
  test -s "$root/testing/vectors/$source" || { echo "missing malformed fixture: $source" >&2; exit 1; }
  hex=$(tr -d '[:space:]' < "$root/testing/vectors/$source")
  test $(( ${#hex} % 2 )) -eq 0 || { echo "odd-length malformed fixture: $source" >&2; exit 1; }
  printf '%s' "$hex" | LC_ALL=C grep -Eq '^[0-9a-fA-F]+$' || { echo "non-hex malformed fixture: $source" >&2; exit 1; }
done

envelope_manifest="$root/testing/vectors/envelope-manifest-v1.json"
jq -e '.manifest == "activechain-envelope-hashes-v1"
  and (.envelopes | length == 39)
  and ([.envelopes[] | .source + "#" + .field] as $ids
    | ($ids | length) == 39 and ($ids | unique | length) == 39)' \
  "$envelope_manifest" >/dev/null
jq -r '.envelopes[] | [.source, .field, .type_tag, (.schema_version | tostring),
  .envelope_sha256, .canonical_value_commitment] | @tsv' "$envelope_manifest" |
while IFS=$'\t' read -r source field type_tag schema envelope_sha256 commitment; do
  test ${#envelope_sha256} -eq 64 || { echo "invalid envelope SHA-256: $source#$field" >&2; exit 1; }
  test ${#commitment} -eq 96 || { echo "invalid canonical commitment: $source#$field" >&2; exit 1; }
  printf '%s%s%s%s' "$type_tag" "$schema" "$envelope_sha256" "$commitment" |
    LC_ALL=C grep -Eq '^0x[0-9a-f]{4}[0-9]+[0-9a-f]{160}$' ||
    { echo "invalid envelope hash entry: $source#$field" >&2; exit 1; }
done
generated=$(mktemp)
trap 'rm -f "$generated"' EXIT
cargo run --locked --quiet -p activechain-vector-generator -- envelope-manifest-v1 > "$generated"
cmp -s "$generated" "$envelope_manifest" ||
  { echo "envelope hash manifest drift; regenerate it with activechain-vector-generator" >&2; exit 1; }

light="$root/testing/vectors/light-client-v1.json"
jq -e '.manifest == "activechain-light-client-v1" and (.requirements | length >= 6)' "$light" >/dev/null
jq -r '.requirements[] | select(.source != null) | [.source, .sha256] | @tsv' "$light" | while IFS=$'\t' read -r source expected; do
  actual=$(shasum -a 256 "$root/testing/vectors/$source" | awk '{print $1}')
  test "$actual" = "$expected" || { echo "light-client hash mismatch: $source" >&2; exit 1; }
done

echo "verifier manifest checks passed"
