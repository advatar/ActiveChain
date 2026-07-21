#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)

(cd "$root/formal/lean" && lake build)

found=0
for model in "$root"/formal/tamarin/*.spthy; do
  test -f "$model" || continue
  found=1
  output=$(mktemp "${TMPDIR:-/tmp}/activechain-tamarin.XXXXXX")
  trap 'rm -f "$output"' EXIT
  tamarin-prover "$model" --prove --derivcheck-timeout=60 | tee "$output"
  if grep -Eq 'falsified|WARNING:|wellformedness check failed' "$output"; then
    echo "formal proof gate failed: $model" >&2
    exit 1
  fi
  if ! grep -q 'All wellformedness checks were successful' "$output"; then
    echo "missing successful Tamarin wellformedness result: $model" >&2
    exit 1
  fi
  if ! grep -q 'verified' "$output"; then
    echo "no verified lemma found: $model" >&2
    exit 1
  fi
  rm -f "$output"
  trap - EXIT
done

test "$found" -eq 1 || { echo "no Tamarin models found" >&2; exit 1; }
echo "formal model checks passed"
