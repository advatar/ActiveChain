#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
lean_output=$(mktemp)
trap 'rm -f "$lean_output"' EXIT

(cd "$root/formal/lean" && lake env lean ActiveChain/OpenWalletConsent.lean)
(cd "$root/formal/lean" && lake exe openWalletConsentTable) >"$lean_output"
diff -u "$root/testing/vectors/credential/openwallet-consent-model-table.txt" "$lean_output"
cargo test --locked --manifest-path "$root/Cargo.toml" -p activechain-wallet-core \
  rust_openwallet_consent_matches_frozen_lean_refinement_table

echo "OpenWallet consent-bound issuance Rust/Lean refinement trace passed"
