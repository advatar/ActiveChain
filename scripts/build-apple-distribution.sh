#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
output=${1:-"$repo_root/dist/apple"}
source_revision=${2:-$(git -C "$repo_root" rev-parse HEAD)}
head_revision=$(git -C "$repo_root" rev-parse HEAD)
if [[ -n ${CARGO_TARGET_DIR:-} ]]; then
  case "$CARGO_TARGET_DIR" in
    /*) cargo_target_dir=$CARGO_TARGET_DIR ;;
    *) cargo_target_dir="$PWD/$CARGO_TARGET_DIR" ;;
  esac
else
  cargo_target_dir="$repo_root/target"
fi
export CARGO_TARGET_DIR=$cargo_target_dir

if [[ "$source_revision" != "$head_revision" ]]; then
  echo "source revision must equal the checked-out HEAD ($head_revision)" >&2
  exit 1
fi
if [[ ${ACTIVECHAIN_ALLOW_DIRTY_DISTRIBUTION:-0} != 1 ]] &&
   [[ -n $(git -C "$repo_root" status --porcelain --untracked-files=normal) ]]; then
  echo "refusing to label Apple artifacts from a dirty worktree" >&2
  exit 1
fi

case "$output" in
  /|"$repo_root"|"$repo_root/"|"$HOME"|"$HOME/")
    echo "refusing unsafe Apple distribution output: $output" >&2
    exit 1
    ;;
esac
if [[ -e "$output" ]]; then
  echo "Apple distribution output already exists: $output" >&2
  exit 1
fi
if [[ $(uname -s) != Darwin ]]; then
  echo "Apple distribution builds require macOS and Xcode" >&2
  exit 1
fi

output_parent=$(dirname "$output")
mkdir -p "$output_parent"
staging=$(mktemp -d "$output_parent/.activechain-apple.XXXXXX")
cleanup() {
  rm -rf "$staging"
}
trap cleanup EXIT

headers="$staging/generated-headers"
cargo run --locked --manifest-path "$repo_root/Cargo.toml" \
  -p activechain-apple-distribution -- headers "$repo_root" "$headers"

verifier_headers="$staging/verifier-headers"
wallet_headers="$staging/wallet-headers"
mkdir -p "$verifier_headers" "$wallet_headers"
cp "$headers/activechain_verifier.h" "$verifier_headers/"
cp "$headers/activechain_wallet.h" "$wallet_headers/"
cp "$repo_root/distribution/apple/ActiveChainVerifier.modulemap" \
  "$verifier_headers/module.modulemap"
cp "$repo_root/distribution/apple/ActiveChainWallet.modulemap" \
  "$wallet_headers/module.modulemap"

targets=(
  aarch64-apple-darwin
  x86_64-apple-darwin
  aarch64-apple-ios
  aarch64-apple-ios-sim
)
for target in "${targets[@]}"; do
  cargo build --locked --release --manifest-path "$repo_root/Cargo.toml" \
    --target "$target" \
    -p activechain-verifier-ffi \
    -p activechain-wallet-ffi
done

universal_macos="$staging/macos-universal"
mkdir -p "$universal_macos"
xcrun lipo -create \
  "$cargo_target_dir/aarch64-apple-darwin/release/libactivechain_verifier_ffi.a" \
  "$cargo_target_dir/x86_64-apple-darwin/release/libactivechain_verifier_ffi.a" \
  -output "$universal_macos/libactivechain_verifier_ffi.a"
xcrun lipo -create \
  "$cargo_target_dir/aarch64-apple-darwin/release/libactivechain_wallet_ffi.a" \
  "$cargo_target_dir/x86_64-apple-darwin/release/libactivechain_wallet_ffi.a" \
  -output "$universal_macos/libactivechain_wallet_ffi.a"

xcodebuild -create-xcframework \
  -library "$universal_macos/libactivechain_verifier_ffi.a" \
  -headers "$verifier_headers" \
  -library "$cargo_target_dir/aarch64-apple-ios/release/libactivechain_verifier_ffi.a" \
  -headers "$verifier_headers" \
  -library "$cargo_target_dir/aarch64-apple-ios-sim/release/libactivechain_verifier_ffi.a" \
  -headers "$verifier_headers" \
  -output "$staging/ActiveChainVerifier.xcframework"

xcodebuild -create-xcframework \
  -library "$universal_macos/libactivechain_wallet_ffi.a" \
  -headers "$wallet_headers" \
  -library "$cargo_target_dir/aarch64-apple-ios/release/libactivechain_wallet_ffi.a" \
  -headers "$wallet_headers" \
  -library "$cargo_target_dir/aarch64-apple-ios-sim/release/libactivechain_wallet_ffi.a" \
  -headers "$wallet_headers" \
  -output "$staging/ActiveChainWallet.xcframework"

normalize_xcframework_plist() {
  local plist=$1
  local json="$plist.json"
  local sorted="$plist.sorted.json"
  plutil -convert json -o "$json" "$plist"
  jq --sort-keys '.AvailableLibraries |= sort_by(.LibraryIdentifier)' "$json" > "$sorted"
  plutil -convert xml1 -o "$plist" "$sorted"
  rm "$json" "$sorted"
}
normalize_xcframework_plist "$staging/ActiveChainVerifier.xcframework/Info.plist"
normalize_xcframework_plist "$staging/ActiveChainWallet.xcframework/Info.plist"

rm -rf "$headers" "$verifier_headers" "$wallet_headers"
cargo run --locked --manifest-path "$repo_root/Cargo.toml" \
  -p activechain-apple-distribution -- package "$staging/Package.swift"
cargo run --locked --manifest-path "$repo_root/Cargo.toml" \
  -p activechain-apple-distribution -- manifest \
  "$staging" "$source_revision" "$staging/activechain-compatibility.json"
cargo run --locked --manifest-path "$repo_root/Cargo.toml" \
  -p activechain-apple-distribution -- verify \
  "$staging/activechain-compatibility.json" "$staging"

mv "$staging" "$output"
trap - EXIT
echo "ActiveChain Apple distribution: $output"
