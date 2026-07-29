#!/usr/bin/env bash
set -euo pipefail

workdir="$(mktemp -d "${TMPDIR:-/tmp}/activechain-key-rotation.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

for generation in old new; do
  output=$(cargo run --quiet -p activechain-consensus-runtime --bin genesis-tool -- \
    "$workdir/$generation.genesis" 1 1 3 "$workdir/$generation-keys"
  )
  commitment=$(sed -n 's/^genesis_commitment=//p' <<<"$output")
  [[ "$commitment" =~ ^[0-9a-f]{96}$ ]] || {
    echo "genesis-tool did not emit a canonical commitment" >&2
    exit 1
  }
  printf '%s\n' "$commitment" >"$workdir/$generation.commitment"
done

cmp -s "$workdir/old.genesis" "$workdir/new.genesis" && {
  echo "independent key generations produced the same genesis" >&2
  exit 1
}
cmp -s "$workdir/old.commitment" "$workdir/new.commitment" && {
  echo "independent key generations produced the same genesis commitment" >&2
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

deployment="$workdir/deployment"
mkdir -p "$deployment/current/bin" "$deployment/current/scripts" "$deployment/chain" \
  "$deployment/rpc"
cp target/debug/genesis-tool "$deployment/current/bin/"
cp deploy/kanalen/network.env "$deployment/current/"
cp deploy/kanalen/scripts/reset-kanalen-state.sh "$deployment/current/scripts/"
ACTIVECHAIN_KANALEN_ROOT="$deployment" \
  "$deployment/current/scripts/reset-kanalen-state.sh" --confirm
runtime_commitment=$(sed -n 's/^ACTIVECHAIN_GENESIS_COMMITMENT_HEX=//p' \
  "$deployment/network.env")
[[ "$runtime_commitment" =~ ^[0-9a-f]{96}$ ]] || {
  echo "reset did not bind the runtime network manifest to genesis" >&2
  exit 1
}
test "$(stat -f '%Lp' "$deployment/chain/keys")" = 700
for key in "$deployment"/chain/keys/validator-*.key; do
  test "$(stat -f '%Lp' "$key")" = 600
done

echo "validator key rotation rehearsal passed"
