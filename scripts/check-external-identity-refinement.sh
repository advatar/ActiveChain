#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_file=$(mktemp)
trap 'rm -f "$output_file"' EXIT
cd "$repo_root/formal/lean"
lake build ActiveChain externalIdentityTable
lake env lean --run ExternalIdentityTable.lean > "$output_file"
cmp "$output_file" "$repo_root/testing/vectors/external-identity-refinement-v1.tsv"
echo "external identity Lean/Rust refinement table verified"
