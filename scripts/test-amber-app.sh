#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
project="$repo_root/mobile/apple/AmberApp"
derived_data=$(mktemp -d "${TMPDIR:-/tmp}/activechain-amber-derived.XXXXXX")
trap 'rm -rf "$derived_data"' EXIT

xcodegen generate --spec "$project/project.yml" --project "$project"

xcodebuild \
  -project "$project/Amber.xcodeproj" \
  -scheme AmberMac \
  -destination "platform=macOS,arch=arm64" \
  -derivedDataPath "$derived_data/macos" \
  CODE_SIGNING_ALLOWED=NO \
  test

ios_destination=${AMBER_IOS_TEST_DESTINATION:-"platform=iOS Simulator,name=iPhone 17 Pro,OS=latest"}
xcodebuild \
  -project "$project/Amber.xcodeproj" \
  -scheme Amber \
  -destination "$ios_destination" \
  -derivedDataPath "$derived_data/ios" \
  CODE_SIGNING_ALLOWED=NO \
  test
