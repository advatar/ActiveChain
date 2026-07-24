#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
revision=$(git -C "$repo_root" rev-parse HEAD)
distribution="$repo_root/dist/apple/$revision"
current="$repo_root/dist/apple/current"
project="$repo_root/mobile/ios/ActiveChainWalletApp"

if [[ -n $(git -C "$repo_root" status --porcelain --untracked-files=normal) ]]; then
  echo "build-macos-wallet-app requires a clean worktree" >&2
  exit 1
fi
if [[ ! -d "$distribution" ]]; then
  "$repo_root/scripts/build-apple-distribution.sh" "$distribution" "$revision"
fi
mkdir -p "$(dirname "$current")"
ln -sfn "$revision" "$current"
xcodegen generate --spec "$project/project.yml" --project "$project"

archive_path=${ACTIVECHAIN_MACOS_ARCHIVE_PATH:-"$repo_root/target/apple-archives/ActiveChainWalletMac-$revision.xcarchive"}
mkdir -p "$(dirname "$archive_path")"
if [[ -e "$archive_path" ]]; then
  echo "macOS wallet archive already exists: $archive_path" >&2
  exit 1
fi
xcodebuild \
  -project "$project/ActiveChainWallet.xcodeproj" \
  -scheme ActiveChainWalletMac \
  -destination "generic/platform=macOS" \
  -archivePath "$archive_path" \
  CODE_SIGNING_ALLOWED=NO \
  archive
echo "ActiveChain macOS wallet archive: $archive_path"
