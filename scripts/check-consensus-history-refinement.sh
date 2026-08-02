#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
lean_output=$(mktemp)
trap 'rm -f "$lean_output"' EXIT

(cd "$root/formal/lean" && lake env lean ActiveChain/ConsensusHistory.lean)
(cd "$root/formal/lean" && lake exe consensusHistoryTable) >"$lean_output"
diff -u "$root/testing/vectors/consensus/consensus-history-model-table.txt" "$lean_output"
cargo test --locked --manifest-path "$root/Cargo.toml" -p activechain-consensus-runtime \
  rust_consensus_history_trace_matches_frozen_lean_refinement_table

echo "consensus history Rust/Lean refinement trace passed"
