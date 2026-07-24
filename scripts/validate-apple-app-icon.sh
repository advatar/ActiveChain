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

supports_ipad=$(
  /usr/libexec/PlistBuddy \
    -c "Print :UIDeviceFamily" \
    "$plist" 2>/dev/null | rg -q '2' && echo yes || echo no
)
if [[ "$supports_ipad" == "yes" ]]; then
  ipad_icon_name=$(
    /usr/libexec/PlistBuddy \
      -c "Print :CFBundleIcons~ipad:CFBundlePrimaryIcon:CFBundleIconName" \
      "$plist" 2>/dev/null || true
  )
  if [[ "$ipad_icon_name" != "AppIcon" ]]; then
    echo "iPad-enabled bundle is missing CFBundleIcons~ipad AppIcon metadata" >&2
    exit 1
  fi

  ipad_icon=$(
    find "$application" -maxdepth 1 -type f \
      \( -name 'AppIcon76x76@2x.png' -o -name 'AppIcon76x76@2x~ipad.png' \) \
      -print -quit
  )
  if [[ -z "$ipad_icon" ]]; then
    echo "iPad-enabled bundle is missing the required 152x152 AppIcon rendition" >&2
    exit 1
  fi
  dimensions=$(sips -g pixelWidth -g pixelHeight "$ipad_icon" 2>/dev/null)
  if ! rg -q 'pixelWidth: 152' <<<"$dimensions" \
      || ! rg -q 'pixelHeight: 152' <<<"$dimensions"; then
    echo "required iPad AppIcon rendition is not exactly 152x152: $ipad_icon" >&2
    exit 1
  fi
fi

echo "validated AppIcon metadata and compiled catalog for $bundle_id"
