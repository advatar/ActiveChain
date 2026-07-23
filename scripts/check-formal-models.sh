#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
derivcheck_timeout=${ACTIVECHAIN_TAMARIN_DERIVCHECK_TIMEOUT:-180}
tamarin_process_timeout=${ACTIVECHAIN_TAMARIN_PROCESS_TIMEOUT:-300}
authorization_derivcheck_timeout=${ACTIVECHAIN_AUTHORIZATION_DERIVCHECK_TIMEOUT:-900}
authorization_preflight_timeout=${ACTIVECHAIN_AUTHORIZATION_PREFLIGHT_TIMEOUT:-1200}
authorization_proof_timeout=${ACTIVECHAIN_AUTHORIZATION_PROOF_TIMEOUT:-1200}

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
  model_name=$(basename "$model")
  if [[ "$(basename "$model")" == activechain_pq_session.spthy ]]; then
    tamarin_args+=(--auto-sources)
  fi

  if [[ "$model_name" == activechain_authorization_chain.spthy ]]; then
    test -f "$lemma_file" || {
      echo "missing authorization-chain lemma manifest: $lemma_file" >&2
      exit 1
    }
    model_hash_before=$(shasum -a 256 "$model" | awk '{print $1}')
    perl -e '$seconds=shift; alarm $seconds; exec @ARGV' \
      "$authorization_preflight_timeout" tamarin-prover "$model" \
      --precompute-only --quiet --open-chains=50 \
      --derivcheck-timeout="$authorization_derivcheck_timeout" \
      --quit-on-warning | tee -a "$output"
    model_hash_after=$(shasum -a 256 "$model" | awk '{print $1}')
    if [[ "$model_hash_before" != "$model_hash_after" ]]; then
      echo "authorization model changed after derivation preflight" >&2
      exit 1
    fi
    if ! grep -q 'Derivation checks ended' "$output"; then
      echo "authorization derivation preflight did not complete" >&2
      exit 1
    fi
    if ! grep -q 'deconstructions complete' "$output"; then
      echo "authorization source precomputation was incomplete" >&2
      exit 1
    fi

    authorization_prove_args=()
    while IFS= read -r lemma; do
      test -n "$lemma" || continue
      authorization_prove_args+=(--prove="$lemma")
    done < "$lemma_file"
    test "${#authorization_prove_args[@]}" -gt 0 || {
      echo "authorization-chain lemma manifest is empty" >&2
      exit 1
    }
    perl -e '$seconds=shift; alarm $seconds; exec @ARGV' \
      "$authorization_proof_timeout" tamarin-prover "$model" \
      "${authorization_prove_args[@]}" --quiet --open-chains=50 \
      --derivcheck-timeout=0 --quit-on-warning | tee -a "$output"
    model_hash_proved=$(shasum -a 256 "$model" | awk '{print $1}')
    if [[ "$model_hash_before" != "$model_hash_proved" ]]; then
      echo "authorization model changed between preflight and proof" >&2
      exit 1
    fi

    while IFS= read -r lemma; do
      test -n "$lemma" || continue
      if ! grep -Eq "^[[:space:]]+${lemma} .*: verified" "$output"; then
        echo "authorization lemma was not verified: $lemma" >&2
        exit 1
      fi
    done < "$lemma_file"
    if grep -q 'analysis incomplete' "$output"; then
      echo "authorization proof selection left an incomplete lemma" >&2
      exit 1
    fi
  elif test -f "$lemma_file"; then
    while IFS= read -r lemma; do
      test -n "$lemma" || continue
      perl -e '$seconds=shift; alarm $seconds; exec @ARGV' "$tamarin_process_timeout" \
        tamarin-prover "$model" --prove="$lemma" "${tamarin_args[@]}" | tee -a "$output"
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
"$root/scripts/check-tla-proof-pipeline.sh"
echo "formal model checks passed"
