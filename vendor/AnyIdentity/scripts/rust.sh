#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
toolchain="1.97.1"
# Select both tools explicitly: Homebrew installations can otherwise mix incompatible
# rustc/rustdoc binaries with rustup cross-platform standard libraries.
export RUSTC="$(rustup which --toolchain "$toolchain" rustc)"
export RUSTDOC="$(rustup which --toolchain "$toolchain" rustdoc)"
exec rustup run "$toolchain" cargo "$@"
