#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:---all}"
toolchain="1.97.1"
cargo_command=(rustup run "$toolchain" cargo)
export RUSTC="$(rustup which --toolchain "$toolchain" rustc)"
if [[ "$mode" != "--all" && "$mode" != "--host" ]]; then
  echo "Usage: $0 [--all|--host]" >&2; exit 2
fi
# One build at a time. Never remove an existing valid artifact until its replacement is built.
staging=$(mktemp -d "${TMPDIR:-/tmp}/anyidentity-build.XXXXXX")
trap 'rm -rf "$staging"' EXIT
headers="$PWD/Sources/CAnyIdentity/include"
args=()
if [[ "$mode" == "--host" ]]; then
  target=$(rustup run "$toolchain" rustc -vV | sed -n 's/^host: //p')
  case "$target" in aarch64-apple-darwin|x86_64-apple-darwin) ;; *) echo "Apple host required" >&2; exit 1;; esac
  MACOSX_DEPLOYMENT_TARGET=13.0 "${cargo_command[@]}" build --manifest-path rust/Cargo.toml --locked --release --target "$target"
  args+=(-library "$PWD/rust/target/$target/release/libanyidentity_core.a" -headers "$headers")
else
  for target in aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    rustup target add --toolchain "$toolchain" "$target"
    MACOSX_DEPLOYMENT_TARGET=13.0 IPHONEOS_DEPLOYMENT_TARGET=16.0 "${cargo_command[@]}" build --manifest-path rust/Cargo.toml --locked --release --target "$target"
  done
  mkdir -p "$staging/macos" "$staging/simulator"
  lipo -create rust/target/{aarch64,x86_64}-apple-darwin/release/libanyidentity_core.a -output "$staging/macos/libanyidentity_core.a"
  lipo -create rust/target/{aarch64-apple-ios-sim,x86_64-apple-ios}/release/libanyidentity_core.a -output "$staging/simulator/libanyidentity_core.a"
  args+=(-library "$staging/macos/libanyidentity_core.a" -headers "$headers")
  args+=(-library "$PWD/rust/target/aarch64-apple-ios/release/libanyidentity_core.a" -headers "$headers")
  args+=(-library "$staging/simulator/libanyidentity_core.a" -headers "$headers")
fi
xcodebuild -create-xcframework "${args[@]}" -output "$staging/CAnyIdentity.xcframework"
mkdir -p Artifacts
rm -rf Artifacts/CAnyIdentity.xcframework
mv "$staging/CAnyIdentity.xcframework" Artifacts/CAnyIdentity.xcframework

# SwiftPM may copy a changed static binary without relinking existing products.
# Invalidate this package's generated build cache after replacing the XCFramework.
swift package clean
