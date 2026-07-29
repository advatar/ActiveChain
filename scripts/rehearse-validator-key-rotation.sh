#!/usr/bin/env bash
set -euo pipefail

workdir="$(mktemp -d "${TMPDIR:-/tmp}/activechain-key-rotation.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

for generation in old new; do
  cargo run --quiet -p activechain-consensus-runtime --bin genesis-tool -- \
    "$workdir/$generation.genesis" 1 1 3 "$workdir/$generation-keys"
done

cmp -s "$workdir/old.genesis" "$workdir/new.genesis" && {
  echo "independent key generations produced the same genesis" >&2
  exit 1
}
python3 - "$workdir/old-keys" "$workdir/new-keys" <<'PY'
import os
import pathlib
import stat
import sys

for directory in sys.argv[1:]:
    for path in pathlib.Path(directory).glob("validator-*.key"):
        mode = stat.S_IMODE(os.lstat(path).st_mode)
        if mode != 0o600:
            raise SystemExit(f"{path} has mode {mode:o}, expected 600")
PY

if cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  0 "$workdir/mismatch.snapshot" "$workdir/new.genesis" 0 0 --once \
  --key-file="$workdir/old-keys/validator-0.key" >"$workdir/mismatch.out" 2>&1; then
  echo "validator accepted a key from the retired generation" >&2
  exit 1
fi
rg --quiet --fixed-strings "ManifestMismatch" "$workdir/mismatch.out"
test ! -e "$workdir/mismatch.snapshot"

if cargo run --quiet -p activechain-consensus-runtime --bin validator-node -- \
  0 "$workdir/missing.snapshot" "$workdir/new.genesis" 0 0 --once \
  >"$workdir/missing.out" 2>&1; then
  echo "validator started without an operator key" >&2
  exit 1
fi
rg --quiet --fixed-strings "requires --key-file" "$workdir/missing.out"
test ! -e "$workdir/missing.snapshot"

echo "validator key rotation rehearsal passed"
