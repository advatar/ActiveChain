#!/usr/bin/env bash
set -euo pipefail

framework="$TARGET_BUILD_DIR/$FULL_PRODUCT_NAME/Frameworks/CAnyIdentity.framework"
binary="$framework/CAnyIdentity"
if [[ ! -f "$binary" ]]; then
  if [[ ${ACTION:-} == install ]]; then
    echo "CAnyIdentity framework is missing from the archive product: $framework" >&2
    exit 1
  fi
  exit 0
fi

dsym="$DWARF_DSYM_FOLDER_PATH/CAnyIdentity.framework.dSYM"
mkdir -p "$DWARF_DSYM_FOLDER_PATH"
# SwiftPM materializes a thin framework stub from the static binary target. Its
# UUID needs a companion dSYM; the Rust source symbols live in the app dSYM.
xcrun dsymutil "$binary" -o "$dsym"

python3 - "$binary" "$dsym" <<'PY'
import re
import subprocess
import sys

def uuids(path):
    output = subprocess.check_output(['xcrun', 'dwarfdump', '--uuid', path], text=True)
    return set(re.findall(r'UUID: ([0-9A-F-]+)', output))

binary, dsym = sys.argv[1:]
if not uuids(binary) or uuids(binary) != uuids(dsym):
    raise SystemExit('CAnyIdentity dSYM UUID does not match the embedded framework')
PY
