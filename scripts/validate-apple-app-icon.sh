#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/Application.app" >&2
  exit 64
fi

application=$1
plist="$application/Info.plist"
assets="$application/Assets.car"

if [[ ! -f "$plist" ]]; then
  echo "missing application Info.plist: $plist" >&2
  exit 1
fi
if [[ ! -f "$assets" ]]; then
  echo "missing compiled asset catalog: $assets" >&2
  exit 1
fi

icon_name=$(
  /usr/libexec/PlistBuddy \
    -c "Print :CFBundleIcons:CFBundlePrimaryIcon:CFBundleIconName" \
    "$plist" 2>/dev/null || true
)
if [[ "$icon_name" != "AppIcon" ]]; then
  echo "CFBundleIcons.CFBundlePrimaryIcon.CFBundleIconName must equal AppIcon; found: ${icon_name:-<missing>}" >&2
  exit 1
fi

bundle_id=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$plist")
echo "validated AppIcon metadata and compiled catalog for $bundle_id"
