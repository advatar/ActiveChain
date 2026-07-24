#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
distribution=${1:?usage: check-apple-distribution.sh <distribution>}
manifest="$distribution/activechain-compatibility.json"

cargo run --locked --manifest-path "$repo_root/Cargo.toml" \
  -p activechain-apple-distribution -- verify "$manifest" "$distribution"

verifier_slice="$distribution/ActiveChainVerifier.xcframework/macos-arm64_x86_64"
wallet_slice="$distribution/ActiveChainWallet.xcframework/macos-arm64_x86_64"
if [[ ! -d "$verifier_slice" || ! -d "$wallet_slice" ]]; then
  echo "required universal macOS XCFramework slices are missing" >&2
  exit 1
fi
for library in \
  "$verifier_slice/libactivechain_verifier_ffi.a" \
  "$wallet_slice/libactivechain_wallet_ffi.a"; do
  for architecture in arm64 x86_64; do
    if ! xcrun lipo "$library" -verify_arch "$architecture"; then
      echo "$library is missing required architecture $architecture" >&2
      exit 1
    fi
  done
done

temporary=$(mktemp -d /tmp/activechain-apple-consumer.XXXXXX)
cleanup() {
  rm -rf "$temporary"
}
trap cleanup EXIT

clang -std=c17 -Wall -Wextra -Werror \
  -I "$verifier_slice/Headers" \
  "$repo_root/testing/apple-consumer/verifier.c" \
  "$verifier_slice/libactivechain_verifier_ffi.a" \
  -framework Security -framework SystemConfiguration \
  -o "$temporary/verifier-consumer"
"$temporary/verifier-consumer"

clang -std=c17 -Wall -Wextra -Werror \
  -I "$wallet_slice/Headers" \
  "$repo_root/testing/apple-consumer/wallet.c" \
  "$wallet_slice/libactivechain_wallet_ffi.a" \
  -framework Security -framework SystemConfiguration \
  -o "$temporary/wallet-consumer"
"$temporary/wallet-consumer"

swiftc \
  -I "$verifier_slice/Headers" \
  "$repo_root/testing/apple-consumer/VerifierConsumer.swift" \
  "$verifier_slice/libactivechain_verifier_ffi.a" \
  -framework Security -framework SystemConfiguration \
  -o "$temporary/verifier-swift-consumer"
"$temporary/verifier-swift-consumer"

swiftc \
  -I "$wallet_slice/Headers" \
  "$repo_root/testing/apple-consumer/WalletConsumer.swift" \
  "$wallet_slice/libactivechain_wallet_ffi.a" \
  -framework Security -framework SystemConfiguration \
  -o "$temporary/wallet-swift-consumer"
"$temporary/wallet-swift-consumer"

# Link Intel consumers as well. They cannot run on every ARM64 CI host, but this
# proves that both universal libraries expose their complete ABI to x86_64.
clang -arch x86_64 -std=c17 -Wall -Wextra -Werror \
  -I "$verifier_slice/Headers" \
  "$repo_root/testing/apple-consumer/verifier.c" \
  "$verifier_slice/libactivechain_verifier_ffi.a" \
  -framework Security -framework SystemConfiguration \
  -o "$temporary/verifier-consumer-x86_64"
clang -arch x86_64 -std=c17 -Wall -Wextra -Werror \
  -I "$wallet_slice/Headers" \
  "$repo_root/testing/apple-consumer/wallet.c" \
  "$wallet_slice/libactivechain_wallet_ffi.a" \
  -framework Security -framework SystemConfiguration \
  -o "$temporary/wallet-consumer-x86_64"

ios_sdk=$(xcrun --sdk iphoneos --show-sdk-path)
simulator_sdk=$(xcrun --sdk iphonesimulator --show-sdk-path)
xcrun --sdk iphoneos swiftc -emit-executable \
  -target arm64-apple-ios15.0 \
  -sdk "$ios_sdk" \
  -I "$distribution/ActiveChainVerifier.xcframework/ios-arm64/Headers" \
  "$repo_root/testing/apple-consumer/VerifierConsumer.swift" \
  "$distribution/ActiveChainVerifier.xcframework/ios-arm64/libactivechain_verifier_ffi.a" \
  -framework Security -framework SystemConfiguration \
  -o "$temporary/verifier-ios-consumer"
xcrun --sdk iphoneos swiftc -emit-executable \
  -target arm64-apple-ios15.0 \
  -sdk "$ios_sdk" \
  -I "$distribution/ActiveChainWallet.xcframework/ios-arm64/Headers" \
  "$repo_root/testing/apple-consumer/WalletConsumer.swift" \
  "$distribution/ActiveChainWallet.xcframework/ios-arm64/libactivechain_wallet_ffi.a" \
  -framework Security -framework SystemConfiguration \
  -o "$temporary/wallet-ios-consumer"
xcrun --sdk iphonesimulator swiftc -emit-executable \
  -target arm64-apple-ios15.0-simulator \
  -sdk "$simulator_sdk" \
  -I "$distribution/ActiveChainVerifier.xcframework/ios-arm64-simulator/Headers" \
  "$repo_root/testing/apple-consumer/VerifierConsumer.swift" \
  "$distribution/ActiveChainVerifier.xcframework/ios-arm64-simulator/libactivechain_verifier_ffi.a" \
  -framework Security -framework SystemConfiguration \
  -o "$temporary/verifier-simulator-consumer"
xcrun --sdk iphonesimulator swiftc -emit-executable \
  -target arm64-apple-ios15.0-simulator \
  -sdk "$simulator_sdk" \
  -I "$distribution/ActiveChainWallet.xcframework/ios-arm64-simulator/Headers" \
  "$repo_root/testing/apple-consumer/WalletConsumer.swift" \
  "$distribution/ActiveChainWallet.xcframework/ios-arm64-simulator/libactivechain_wallet_ffi.a" \
  -framework Security -framework SystemConfiguration \
  -o "$temporary/wallet-simulator-consumer"

(cd "$distribution" && swift package dump-package >/dev/null)
