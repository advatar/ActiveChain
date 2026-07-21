#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
derivcheck_timeout=${ACTIVECHAIN_TAMARIN_DERIVCHECK_TIMEOUT:-180}

if ! tamarin-prover --version 2>&1 | grep -q 'tamarin-prover 1\.12\.0'; then
  echo "formal proof gate requires Tamarin 1.12.0" >&2
  exit 1
fi

(cd "$root/formal/lean" && lake build)

found=0
for model in "$root"/formal/tamarin/*.spthy; do
  test -f "$model" || continue
  found=1
  output=$(mktemp "${TMPDIR:-/tmp}/activechain-tamarin.XXXXXX")
  trap 'rm -f "$output"' EXIT
  lemma_file="${model%.spthy}.lemmas"
  if test -f "$lemma_file"; then
    while IFS= read -r lemma; do
      test -n "$lemma" || continue
      tamarin-prover "$model" --prove="$lemma" \
        --derivcheck-timeout="$derivcheck_timeout" | tee -a "$output"
    done < "$lemma_file"
  else
    tamarin-prover "$model" --prove \
      --derivcheck-timeout="$derivcheck_timeout" | tee "$output"
  fi
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
