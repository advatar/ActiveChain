#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
output=${1:-"$repo_root/mobile/android/app/build/generated/jniLibs"}
sdk_root=${ANDROID_SDK_ROOT:-"$HOME/Library/Android/sdk"}
ndk_version=${ACTIVECHAIN_ANDROID_NDK_VERSION:-"28.2.13676358"}
ndk="$sdk_root/ndk/$ndk_version"
toolchain="$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"
linker="$toolchain/aarch64-linux-android26-clang"

if [[ ! -x "$linker" ]]; then
  echo "Android NDK linker not found: $linker" >&2
  exit 1
fi

rustup target add aarch64-linux-android
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$linker" \
  cargo build --manifest-path "$repo_root/Cargo.toml" --locked --release \
  --target aarch64-linux-android -p activechain-wallet-ffi

mkdir -p "$output/arm64-v8a"
cp "$repo_root/target/aarch64-linux-android/release/libactivechain_wallet_ffi.so" \
  "$output/arm64-v8a/libactivechain_wallet_ffi.so"
