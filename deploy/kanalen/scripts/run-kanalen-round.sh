#!/bin/sh
set -eu

deployment_root=${ACTIVECHAIN_NETWORK_ROOT:-${ACTIVECHAIN_KANALEN_ROOT:-"$HOME/activechain-deploy/${ACTIVECHAIN_NETWORK:-kanalen}"}}
state_root="$deployment_root/chain"
binary_root="$deployment_root/current/bin"
rpc_root="$deployment_root/rpc"
rpc_snapshot="$rpc_root/rpc-index.snapshot"
network_env="$deployment_root/network.env"
lock="$state_root/round.lock"
cash_snapshot="$state_root/finalized-cash.snapshot"
finality_bundle="$state_root/finality.bundle"
cash_ledger="$state_root/cash-ledger.snapshot"
cash_actions="$state_root/pending-cash-actions.batch"
cash_action_spool="$state_root/cash-action-spool"
cash_action_inflight="$state_root/cash-action-spool.inflight"
transfer_snapshot="$rpc_root/transfers.snapshot"
anchor_actions="$state_root/anchor-actions.batch"
anchor_operator=${ACTIVECHAIN_ANCHOR_OPERATOR:-"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}
anchor_fee_balance=${ACTIVECHAIN_ANCHOR_FEE_BALANCE:-"1000000000"}
anchor_nonce_channel=${ACTIVECHAIN_ANCHOR_NONCE_CHANNEL:-"0"}

test -f "$network_env" || {
  echo "runtime network manifest is missing: $network_env" >&2
  exit 1
}
chain_id=$(sed -n 's/^ACTIVECHAIN_CHAIN_ID_HEX=//p' "$network_env")
test -n "$chain_id" || {
  echo "network.env does not define ACTIVECHAIN_CHAIN_ID_HEX" >&2
  exit 1
}
test -f "$cash_ledger" || {
  echo "authoritative cash ledger is missing: $cash_ledger" >&2
  exit 1
}

mkdir "$lock" 2>/dev/null || exit 0
trap 'rmdir "$lock"' EXIT

cash_actions_preexisting=0
test ! -e "$cash_actions" || cash_actions_preexisting=1
if test "$cash_actions_preexisting" -eq 0 && test -d "$cash_action_spool"; then
  if find "$cash_action_spool" -type f -name '*.action' -print -quit | grep -q .; then
    test ! -e "$cash_action_inflight" || {
      echo "stale faucet action inflight directory requires recovery: $cash_action_inflight" >&2
      exit 1
    }
    mv "$cash_action_spool" "$cash_action_inflight"
    mkdir "$cash_action_spool"
    find "$cash_action_inflight" -type f -name '*.action' -print | LC_ALL=C sort | xargs cat > "$cash_actions"
  fi
fi
if test "$cash_actions_preexisting" -eq 0 && test -f "$transfer_snapshot"; then
  "$binary_root/activechain-transfer-spool" prepare \
    "$transfer_snapshot" "$cash_ledger" "$rpc_snapshot" "$cash_actions"
  test -s "$cash_actions" || rm -f "$cash_actions"
fi
cash_actions_submitted=0
test ! -s "$cash_actions" || cash_actions_submitted=1

for port in 49153 49154 49155; do
  attempts=0
  until nc -z 127.0.0.1 "$port"; do
    attempts=$((attempts + 1))
    test "$attempts" -lt 50 || {
      echo "validator listener $port is unavailable" >&2
      exit 1
    }
    sleep 0.1
  done
done

launchctl_bin=${ACTIVECHAIN_LAUNCHCTL:-launchctl}
launch_domain="gui/$(id -u)"
round_complete=0
proposer_snapshot=
for validator in 0 1 2; do
  case "$validator" in
    0) candidate_port=49153; peers="--peer=2@127.0.0.1:49154 --peer=3@127.0.0.1:49155" ;;
    1) candidate_port=49154; peers="--peer=1@127.0.0.1:49153 --peer=3@127.0.0.1:49155" ;;
    2) candidate_port=49155; peers="--peer=1@127.0.0.1:49153 --peer=2@127.0.0.1:49154" ;;
  esac
  label="dev.activechain.kanalen.validator$validator"
  plist="$deployment_root/current/launchagents/$label.plist"
  "$launchctl_bin" bootout "$launch_domain/$label" 2>/dev/null || true
  set -- "$binary_root/validator-node" \
    49150 "$state_root/validator-$validator.snapshot" "$state_root/genesis.bin" 0 "$validator" --once \
    --key-file="$state_root/keys/validator-$validator.key" \
    --chain-id-hex="$chain_id" \
    --cash-ledger="$cash_ledger" \
    --execution-state="$state_root/execution.snapshot" \
    --anchor-operator="$anchor_operator" \
    --anchor-fee-balance="$anchor_fee_balance" \
    --anchor-nonce-channel="$anchor_nonce_channel" \
    --finalized-cash-out="$cash_snapshot" \
    --finality-out="$finality_bundle"
  for peer in $peers; do
    set -- "$@" "$peer"
  done
  if test -s "$cash_actions"; then
    set -- "$@" --cash-actions="$cash_actions"
  fi
  if test -s "$anchor_actions"; then
    set -- "$@" --anchor-actions="$anchor_actions"
  fi
  if "$@"; then
    round_complete=1
    proposer_snapshot="$state_root/validator-$validator.snapshot"
  fi
  "$launchctl_bin" bootstrap "$launch_domain" "$plist"
  attempts=0
  until nc -z 127.0.0.1 "$candidate_port"; do
    attempts=$((attempts + 1))
    test "$attempts" -lt 50 || {
      echo "validator $validator did not recover its listener" >&2
      exit 1
    }
    sleep 0.1
  done
  test "$round_complete" -eq 0 || break
done
test "$round_complete" -eq 1 || {
  echo "no eligible validator completed the round" >&2
  exit 1
}
if test ! -f "$rpc_snapshot"; then
  "$binary_root/activechain-rpc-bootstrap" \
    "$state_root/genesis.bin" "$chain_id" "$rpc_snapshot"
fi
test -f "$cash_snapshot" || {
  echo "finalized cash snapshot is missing; refusing metadata-only RPC publication: $cash_snapshot" >&2
  exit 1
}
test -f "$finality_bundle" || {
  echo "cash finality bundle is missing; refusing unauthenticated RPC publication: $finality_bundle" >&2
  exit 1
}
"$binary_root/activechain-rpc-ingest" \
  "$proposer_snapshot" "$rpc_snapshot" \
  "$cash_snapshot" "$finality_bundle" "$state_root/execution.snapshot"
if test "$cash_actions_submitted" -eq 1 && test -f "$transfer_snapshot"; then
  "$binary_root/activechain-transfer-spool" reconcile-latest \
    "$transfer_snapshot" "$rpc_snapshot" "$state_root"
fi
if test ! -e "$cash_actions" && test -d "$cash_action_inflight"; then
  find "$cash_action_inflight" -type f -name '*.action' -delete
  rmdir "$cash_action_inflight"
fi
