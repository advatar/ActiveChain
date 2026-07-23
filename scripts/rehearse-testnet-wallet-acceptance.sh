#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rehearsal_dir="$(mktemp -d "${TMPDIR:-/tmp}/activechain-wallet-acceptance.XXXXXX")"
trap 'rm -rf "$rehearsal_dir"' EXIT
cd "$repo_root"

echo "1/7 generating canonical three-validator genesis"
cargo run --quiet -p activechain-consensus-runtime --bin genesis-tool -- \
  "$rehearsal_dir/genesis.bin" 1 1 3
test -s "$rehearsal_dir/genesis.bin"

echo "2/7 deriving deterministic operator wallet identity"
cargo run --quiet -p activechain-wallet-core --bin activechain-wallet -- \
  derive 17 1 1 >"$rehearsal_dir/wallet.out"
rg --quiet --fixed-strings "principal_id=" "$rehearsal_dir/wallet.out"

echo "3/7 issuing a genesis-bound faucet grant"
cargo run --quiet -p activechain-wallet-core --bin activechain-faucet -- \
  grant 1 17 1000000 >"$rehearsal_dir/faucet.out"
rg --quiet --fixed-strings "claim_id=" "$rehearsal_dir/faucet.out"

echo "4/7 admitting a signed funded transfer through validator ingress"
cargo test --quiet -p activechain-consensus-runtime wallet_gateway_binds_a_genesis_ledger

echo "5/7 proving faucet and authorized-transfer replay rejection"
cargo test --quiet -p activechain-wallet-core faucet_grants_are_genesis_bound_and_one_shot
cargo test --quiet -p activechain-wallet-core \
  durable_cash_admission_survives_restart_and_rejects_corruption_and_replay

echo "6/7 finalizing through three authenticated persistent validator processes"
"$repo_root/scripts/rehearse-live-process-quorum.sh"

echo "7/7 restarting every genesis-bound validator from durable state"
"$repo_root/scripts/rehearse-validator-processes.sh"

echo "testnet wallet acceptance rehearsal passed"
