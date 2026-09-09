#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"
if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
  echo "Commit the candidate before running exact-revision iOS acceptance." >&2
  exit 1
fi

# Refuse overlap before touching generated projects, DerivedData or simulators.
if pgrep -x xcodebuild >/dev/null; then
  echo "Another xcodebuild is active; run the iOS acceptance test serially." >&2
  exit 1
fi
python3 scripts/probe-kanalen-rpc.py --require-healthy

revision=$(git rev-parse HEAD)
distribution="$repo_root/dist/apple/$revision"
if [[ ! -d "$distribution" ]]; then
  scripts/build-apple-distribution.sh "$distribution" "$revision"
fi
ln -sfn "$revision" "$repo_root/dist/apple/current"
project="$repo_root/mobile/ios/ActiveChainWalletApp"
"$repo_root/scripts/build-anyidentity.sh"
xcodegen generate --spec "$project/project.yml" --project "$project"

runtime=${ACTIVECHAIN_IOS_E2E_RUNTIME:-com.apple.CoreSimulator.SimRuntime.iOS-26-5}
device_type=${ACTIVECHAIN_IOS_E2E_DEVICE_TYPE:-com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro}
mkdir -p "$repo_root/tmp"
run_root=$(mktemp -d "$repo_root/tmp/ios-wallet-e2e.XXXXXX")
simulator=$(xcrun simctl create "ActiveChain fresh wallet $(date -u +%Y%m%dT%H%M%SZ)" "$device_type" "$runtime")
printf '%s\n' "$simulator" > "$run_root/simulator.txt"
echo "Fresh wallet simulator: $simulator; evidence: $run_root"

cleanup() {
  # Keep this individual simulator and its funded wallet for inspection.
  xcrun simctl shutdown "$simulator" >/dev/null 2>&1 || true
  if ! pgrep -x xcodebuild >/dev/null; then
    xcrun simctl --set "$HOME/Library/Developer/XCTestDevices" shutdown all
    xcrun simctl --set "$HOME/Library/Developer/XCTestDevices" delete all
  else
    echo "Another xcodebuild is active; deferred disposable XCTest clone cleanup." >&2
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
xcrun simctl boot "$simulator"
xcrun simctl bootstatus "$simulator" -b

xcodebuild \
  -project "$project/ActiveChainWallet.xcodeproj" \
  -scheme ActiveChainWalletLiveE2E \
  -destination "platform=iOS Simulator,id=$simulator" \
  -derivedDataPath "$run_root/DerivedData" \
  -resultBundlePath "$run_root/LiveWallet.xcresult" \
  -parallel-testing-enabled NO \
  -maximum-concurrent-test-simulator-destinations 1 \
  -collect-test-diagnostics never \
  -test-timeouts-enabled YES \
  -default-test-execution-time-allowance 600 \
  -maximum-test-execution-time-allowance 600 \
  CODE_SIGNING_ALLOWED=YES \
  CODE_SIGN_IDENTITY=- \
  test

python3 scripts/probe-kanalen-rpc.py --require-healthy
echo "Live iOS wallet acceptance passed; funded wallet retained on $simulator"
