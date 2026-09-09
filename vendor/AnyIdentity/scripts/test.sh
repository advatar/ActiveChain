#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
scripts/rust.sh fmt --manifest-path rust/Cargo.toml -- --check
scripts/rust.sh clippy --manifest-path rust/Cargo.toml --locked --all-targets -- -D warnings
scripts/rust.sh test --manifest-path rust/Cargo.toml --locked
scripts/build-rust.sh --all
swift test
swift run AuthorityDemo
