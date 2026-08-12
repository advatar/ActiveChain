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

cash_supply=${ACTIVECHAIN_CASH_GENESIS_SUPPLY:-$(sed -n 's/^ACTIVECHAIN_CASH_GENESIS_SUPPLY=//p' "$deployment_root/current/network.env")}
cash_reserve=${ACTIVECHAIN_CASH_SECURITY_RESERVE:-$(sed -n 's/^ACTIVECHAIN_CASH_SECURITY_RESERVE=//p' "$deployment_root/current/network.env")}
cash_cells=${ACTIVECHAIN_CASH_TREASURY_CELLS:-}
case "$cash_cells" in
  ''|*[0-9]) ;;
  *) echo "treasury cell count must be an unsigned integer" >&2; exit 1 ;;
esac
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
  chain/execution.snapshot \
  chain/execution.authorization \
  chain/execution.round-staging \
  chain/execution.round-committed \
  chain/finalized-cash.snapshot \
  chain/finality.bundle \
  chain/pending-cash-actions.batch \
  chain/cash-action-spool \
  chain/cash-action-spool.inflight \
  chain/keys \
  chain/validator-0.snapshot \
  chain/validator-1.snapshot \
  chain/validator-2.snapshot \
  chain/validator-1.pq-sessions \
  chain/validator-2.pq-sessions \
  network.env \
  rpc/rpc-index.snapshot \
  rpc/faucet.snapshot \
  rpc/faucet-settlement.journal; do
  if test -e "$deployment_root/$path"; then
    mkdir -p "$rollback/$(dirname "$path")"
    mv "$deployment_root/$path" "$rollback/$path"
  fi
done

for path in "$deployment_root"/chain/pending-cash-actions.batch.finalized-* \
  "$deployment_root"/chain/finality.bundle.finalized-* \
  "$deployment_root"/chain/validator-*.sessions \
  "$deployment_root"/chain/validator-*.pq-sessions \
  "$deployment_root"/chain/execution.snapshot.pre-*; do
  if test -f "$path"; then
    mv "$path" "$rollback/chain/$(basename "$path")"
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
operator_seed="$deployment_root/chain/keys/faucet-operator.seed"
openssl rand 32 > "$operator_seed"
chmod 600 "$operator_seed"
# The treasury must be split across many cells: each grant costs one, and a
# one-cell treasury cannot spend at all. The upper bound is the RPC index,
# which republishes a finality bundle per indexed cell against a 4 MiB frame.
cash_output=$("$deployment_root/current/bin/cash-genesis-tool" \
  "$deployment_root/chain/cash-ledger.snapshot" "$chain_id" operator \
  "$cash_supply" "$cash_reserve" "--operator-seed=$operator_seed" \
  ${cash_cells:+"--treasury-cells=$cash_cells"})
cash_owner=$(printf '%s\n' "$cash_output" | sed -n 's/^cash_genesis_owner=//p')
test "${#cash_owner}" -eq 96 || { echo "cash genesis owner derivation failed" >&2; exit 1; }

runtime_network_env="$deployment_root/network.env"
network_env_temp="$runtime_network_env.tmp.$$"
trap 'rm -f "$network_env_temp"' EXIT
sed '/^ACTIVECHAIN_GENESIS_COMMITMENT_HEX=/d' \
  "$deployment_root/current/network.env" >"$network_env_temp"
printf 'ACTIVECHAIN_GENESIS_COMMITMENT_HEX=%s\n' "$genesis_commitment" >>"$network_env_temp"
printf 'ACTIVECHAIN_CASH_GENESIS_OWNER_HEX=%s\n' "$cash_owner" >>"$network_env_temp"
chmod 644 "$network_env_temp"
mv "$network_env_temp" "$runtime_network_env"
trap - EXIT

printf 'archived previous state at %s\n' "$rollback"
printf 'generated fresh genesis at %s\n' "$deployment_root/chain/genesis.bin"
printf 'generated fresh cash ledger at %s\n' "$deployment_root/chain/cash-ledger.snapshot"
printf 'bound runtime network manifest to genesis %s\n' "$genesis_commitment"
