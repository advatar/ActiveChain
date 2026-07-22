#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
derivcheck_timeout=${ACTIVECHAIN_TAMARIN_DERIVCHECK_TIMEOUT:-180}
tamarin_process_timeout=${ACTIVECHAIN_TAMARIN_PROCESS_TIMEOUT:-300}

python3 "$root/scripts/check-formal-coverage.py"

if ! tamarin_version=$(tamarin-prover --version 2>&1); then
  echo "unable to run the pinned Tamarin prover" >&2
  exit 1
fi
if ! grep -Eq '(tamarin-prover|Tamarin version) 1\.12\.0([^0-9]|$)' <<<"$tamarin_version"; then
  echo "formal proof gate requires Tamarin 1.12.0" >&2
  printf '%s\n' "$tamarin_version" >&2
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
  tamarin_args=(--derivcheck-timeout="$derivcheck_timeout")
  if [[ "$(basename "$model")" == activechain_pq_session.spthy ]]; then
    tamarin_args+=(--auto-sources)
  fi
  if test -f "$lemma_file"; then
    while IFS= read -r lemma; do
      test -n "$lemma" || continue
      lemma_output=$(mktemp "${TMPDIR:-/tmp}/activechain-tamarin-lemma.XXXXXX")
      perl -e '$seconds=shift; alarm $seconds; exec @ARGV' "$tamarin_process_timeout" \
        tamarin-prover "$model" --prove="$lemma" "${tamarin_args[@]}" \
        | tee "$lemma_output" | tee -a "$output"
      if ! grep -Eq "^[[:space:]]*${lemma} .*: verified" "$lemma_output"; then
        echo "selected Tamarin lemma was not verified: $model / $lemma" >&2
        rm -f "$lemma_output"
        exit 1
      fi
      rm -f "$lemma_output"
    done < "$lemma_file"
  else
    perl -e '$seconds=shift; alarm $seconds; exec @ARGV' "$tamarin_process_timeout" \
      tamarin-prover "$model" --prove "${tamarin_args[@]}" | tee "$output"
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
"$root/scripts/check-tla-consensus.sh"
"$root/scripts/check-tla-consensus.sh" ActiveChainReconfiguration ActiveChainReconfigurationSafety.cfg
"$root/scripts/check-tla-consensus.sh" ActiveChainReconfiguration ActiveChainReconfigurationLiveness.cfg
"$root/scripts/check-tla-proof-pipeline.sh"
echo "formal model checks passed"
