#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
lean_output=$(mktemp)
trap 'rm -f "$lean_output"' EXIT

(cd "$root/formal/lean" && lake env lean ActiveChain/DutySettlement.lean)
(cd "$root/formal/lean" && lake exe dutySettlementTable) >"$lean_output"
diff -u "$root/testing/vectors/cash/duty-settlement-model-table.txt" "$lean_output"
cargo test --locked --manifest-path "$root/Cargo.toml" -p activechain-cash-kernel \
  rust_duty_settlement_matches_frozen_lean_refinement_table

echo "verifier duty settlement Rust/Lean refinement trace passed"
