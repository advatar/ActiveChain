#!/bin/sh
set -eu

deployment_root=${ACTIVECHAIN_KANALEN_ROOT:-"$HOME/activechain-deploy/kanalen"}
if test "${1:-}" != "--confirm"; then
  echo "refusing destructive reset; pass --confirm to archive and rebuild Kanalen state" >&2
  exit 2
fi

test -d "$deployment_root" || {
  echo "deployment root does not exist: $deployment_root" >&2
  exit 1
}
test -x "$deployment_root/current/bin/genesis-tool" || {
  echo "active release does not contain genesis-tool" >&2
  exit 1
}

timestamp=$(date +%Y%m%d-%H%M%S)
rollback="$deployment_root/rollback-clean-rebuild-$timestamp"
mkdir -p "$rollback/chain" "$rollback/rpc"

for path in \
  chain/genesis.bin \
  chain/keys \
  chain/validator-0.snapshot \
  chain/validator-1.snapshot \
  chain/validator-2.snapshot \
  chain/validator-1.pq-sessions \
  chain/validator-2.pq-sessions \
  rpc/rpc-index.snapshot; do
  if test -e "$deployment_root/$path"; then
    mkdir -p "$rollback/$(dirname "$path")"
    mv "$deployment_root/$path" "$rollback/$path"
  fi
done

"$deployment_root/current/bin/genesis-tool" \
  "$deployment_root/chain/genesis.bin" 1 1 3 "$deployment_root/chain/keys"

printf 'archived previous state at %s\n' "$rollback"
printf 'generated fresh genesis at %s\n' "$deployment_root/chain/genesis.bin"
