#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
version=0.67.0
target_dir=${ACTIVECHAIN_KANI_TARGET_DIR:-${TMPDIR:-/tmp}/activechain-kani-commitment}
command -v cargo-kani >/dev/null 2>&1 || { echo "cargo-kani $version is required" >&2; exit 1; }
[[ "$(cargo kani --version)" == "cargo-kani $version" ]] || { echo "Kani $version is required" >&2; exit 1; }
mkdir -p "$target_dir"
cargo kani --manifest-path "$root/Cargo.toml" --package activechain-protocol-commitment \
  --lib --target-dir "$target_dir" --output-format terse --default-unwind 64
