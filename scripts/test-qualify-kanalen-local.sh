#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
output=$(bash "$repo_root/scripts/qualify-kanalen-local.sh" --dry-run)

printf '%s\n' "$output" | grep -q 'cargo build --locked --release'
printf '%s\n' "$output" | grep -q -- '-p activechain-consensus-runtime'
printf '%s\n' "$output" | grep -q -- '-p activechain-rpc-server'
printf '%s\n' "$output" | grep -q -- '-p activechain-wallet-core'
printf '%s\n' "$output" | grep -q -- '-p activechain-wallet-ffi'
printf '%s\n' "$output" | grep -q -- '-p activechain-verifier-ffi'
printf '%s\n' "$output" | grep -q 'scripts/check-verifier-manifest.sh'
printf '%s\n' "$output" | grep -q 'cargo test --locked -p activechain-verifier-api'
printf '%s\n' "$output" | grep -q 'scripts/test-kanalen-round-cash-gate.sh'
printf '%s\n' "$output" | grep -q 'scripts/rehearse-testnet-wallet-acceptance.sh'
printf '%s\n' "$output" | grep -q 'Kanalen local developmental testnet qualification passed'

skip_output=$(bash "$repo_root/scripts/qualify-kanalen-local.sh" --skip-build --dry-run)
if printf '%s\n' "$skip_output" | grep -q 'cargo build'; then
  echo "--skip-build unexpectedly retained the release build" >&2
  exit 1
fi

echo "Kanalen local qualification command plan passed"
