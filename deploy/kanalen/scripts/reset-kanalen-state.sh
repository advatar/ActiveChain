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
test -x "$deployment_root/current/bin/cash-genesis-tool" || {
  echo "active release does not contain cash-genesis-tool" >&2
  exit 1
}

cash_owner=${ACTIVECHAIN_CASH_GENESIS_OWNER_HEX:-$(sed -n 's/^ACTIVECHAIN_CASH_GENESIS_OWNER_HEX=//p' "$deployment_root/current/network.env")}
cash_supply=${ACTIVECHAIN_CASH_GENESIS_SUPPLY:-$(sed -n 's/^ACTIVECHAIN_CASH_GENESIS_SUPPLY=//p' "$deployment_root/current/network.env")}
cash_reserve=${ACTIVECHAIN_CASH_SECURITY_RESERVE:-$(sed -n 's/^ACTIVECHAIN_CASH_SECURITY_RESERVE=//p' "$deployment_root/current/network.env")}
case "$cash_owner" in
  *[!0-9a-f]*|'')
    echo "an explicit hexadecimal ACTIVECHAIN_CASH_GENESIS_OWNER_HEX is required" >&2
    exit 1
    ;;
esac
test "${#cash_owner}" -eq 96 || {
  echo "cash genesis owner has the wrong length" >&2
  exit 1
}
case "$cash_supply:$cash_reserve" in
  *[!0-9:]*|:|*:)
    echo "cash genesis supply and reserve must be explicit unsigned integers" >&2
    exit 1
    ;;
esac

timestamp=$(date +%Y%m%d-%H%M%S)
rollback="$deployment_root/rollback-clean-rebuild-$timestamp"
mkdir -p "$rollback/chain" "$rollback/rpc"

for path in \
  chain/genesis.bin \
  chain/cash-ledger.snapshot \
  chain/pending-cash-actions.batch \
  chain/keys \
  chain/validator-0.snapshot \
  chain/validator-1.snapshot \
  chain/validator-2.snapshot \
  chain/validator-1.pq-sessions \
  chain/validator-2.pq-sessions \
  network.env \
  rpc/rpc-index.snapshot; do
  if test -e "$deployment_root/$path"; then
    mkdir -p "$rollback/$(dirname "$path")"
    mv "$deployment_root/$path" "$rollback/$path"
  fi
done

genesis_output=$("$deployment_root/current/bin/genesis-tool" \
  "$deployment_root/chain/genesis.bin" 1 1 3 "$deployment_root/chain/keys")
genesis_commitment=$(printf '%s\n' "$genesis_output" |
  sed -n 's/^genesis_commitment=//p')
case "$genesis_commitment" in
  *[!0-9a-f]*|'')
    echo "genesis-tool did not return a hexadecimal genesis commitment" >&2
    exit 1
    ;;
esac
test "${#genesis_commitment}" -eq 96 || {
  echo "genesis-tool returned a genesis commitment with the wrong length" >&2
  exit 1
}
chain_id=$(sed -n 's/^ACTIVECHAIN_CHAIN_ID_HEX=//p' "$deployment_root/current/network.env")
"$deployment_root/current/bin/cash-genesis-tool" \
  "$deployment_root/chain/cash-ledger.snapshot" "$chain_id" "$cash_owner" \
  "$cash_supply" "$cash_reserve"

runtime_network_env="$deployment_root/network.env"
network_env_temp="$runtime_network_env.tmp.$$"
trap 'rm -f "$network_env_temp"' EXIT
sed '/^ACTIVECHAIN_GENESIS_COMMITMENT_HEX=/d' \
  "$deployment_root/current/network.env" >"$network_env_temp"
printf 'ACTIVECHAIN_GENESIS_COMMITMENT_HEX=%s\n' "$genesis_commitment" >>"$network_env_temp"
chmod 644 "$network_env_temp"
mv "$network_env_temp" "$runtime_network_env"
trap - EXIT

printf 'archived previous state at %s\n' "$rollback"
printf 'generated fresh genesis at %s\n' "$deployment_root/chain/genesis.bin"
printf 'generated fresh cash ledger at %s\n' "$deployment_root/chain/cash-ledger.snapshot"
printf 'bound runtime network manifest to genesis %s\n' "$genesis_commitment"
