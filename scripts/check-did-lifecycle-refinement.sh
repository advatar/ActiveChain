#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
lean_output=$(mktemp)
trap 'rm -f "$lean_output"' EXIT

(cd "$root/formal/lean" && lake env lean ActiveChain/DidLifecycle.lean)
(cd "$root/formal/lean" && lake exe didLifecycleTable) >"$lean_output"
diff -u "$root/testing/vectors/did-lifecycle-model-table.txt" "$lean_output"
cargo test --locked --manifest-path "$root/Cargo.toml" -p activechain-protocol-types \
  rust_did_lifecycle_matches_frozen_lean_refinement_table

echo "DID controller lifecycle Rust/Lean refinement trace passed"
