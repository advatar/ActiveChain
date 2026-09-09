#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
distribution=${1:?usage: test-wallet-identity.sh <verified Apple distribution>}
distribution=$(cd "$distribution" && pwd)
cd "$repo_root"
if pgrep -x xcodebuild >/dev/null; then
  echo 'Another xcodebuild is active; wallet qualification must run serially.' >&2
  exit 1
fi
scripts/build-anyidentity.sh --force
env -u CARGO_TARGET_DIR cargo fmt --manifest-path vendor/AnyIdentity/rust/Cargo.toml --check -- --config-path distribution/anyidentity/rustfmt.toml
env -u CARGO_TARGET_DIR cargo clippy --manifest-path vendor/AnyIdentity/rust/Cargo.toml --locked --all-targets --all-features -- -D warnings
env -u CARGO_TARGET_DIR cargo test --manifest-path vendor/AnyIdentity/rust/Cargo.toml --locked --all-features
swift test --package-path vendor/AnyIdentity
swift test --package-path mobile/ios/ActiveChainWallet

# Use the same exact-revision distribution that the kernel gate just verified.
current="$repo_root/dist/apple/current"
mkdir -p "$(dirname "$current")"
previous=$(readlink "$current" || true)
if [[ -e "$current" && ! -L "$current" ]]; then
  echo "Refusing to replace a non-symlink distribution path: $current" >&2
  exit 1
fi
temporary=$(mktemp -d /tmp/activechain-wallet-identity.XXXXXX)
cleanup() {
  if [[ -n "$previous" ]]; then ln -sfn "$previous" "$current"; else rm -f "$current"; fi
  rm -rf "$temporary"
}
trap cleanup EXIT
ln -sfn "$distribution" "$current"
project="$repo_root/mobile/ios/ActiveChainWalletApp/ActiveChainWallet.xcodeproj"
xcodegen generate --spec mobile/ios/ActiveChainWalletApp/project.yml --project mobile/ios/ActiveChainWalletApp
# Both Rust static libraries must link in each actual application, including the identity gate.
for platform in ios macos; do
  if [[ "$platform" == ios ]]; then
    scheme=ActiveChainWallet
    destination='generic/platform=iOS Simulator'
  else
    scheme=ActiveChainWalletMac
    destination='generic/platform=macOS'
  fi
  xcodebuild -project "$project" -scheme "$scheme" -destination "$destination" \
    -derivedDataPath "$temporary/$platform" ARCHS=arm64 ONLY_ACTIVE_ARCH=YES \
    CODE_SIGNING_ALLOWED=NO build
 done
