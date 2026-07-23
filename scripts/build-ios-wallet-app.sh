#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
revision=$(git -C "$repo_root" rev-parse HEAD)
distribution="$repo_root/dist/apple/$revision"
current="$repo_root/dist/apple/current"
project="$repo_root/mobile/ios/ActiveChainWalletApp"

if [[ -n $(git -C "$repo_root" status --porcelain --untracked-files=normal) ]]; then
  echo "build-ios-wallet-app requires a clean worktree" >&2
  exit 1
fi
if [[ ! -d "$distribution" ]]; then
  "$repo_root/scripts/build-apple-distribution.sh" "$distribution" "$revision"
fi
mkdir -p "$(dirname "$current")"
ln -sfn "$revision" "$current"
xcodegen generate --spec "$project/project.yml" --project "$project"

destination=${ACTIVECHAIN_IOS_DESTINATION:-"generic/platform=iOS Simulator"}
xcodebuild \
  -project "$project/ActiveChainWallet.xcodeproj" \
  -scheme ActiveChainWallet \
  -destination "$destination" \
  ARCHS=arm64 \
  ONLY_ACTIVE_ARCH=YES \
  CODE_SIGNING_ALLOWED=NO \
  build
