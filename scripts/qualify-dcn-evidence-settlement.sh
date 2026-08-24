#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "usage: $0 <output-directory>" >&2
  exit 64
fi

output_directory=$1
repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$repo_root"
if [[ -e "$output_directory" ]]; then
  echo "output directory already exists: $output_directory" >&2
  exit 64
fi
mkdir -p "$output_directory"

evidence_id=sha256:bd838cf468609808e2c4333277f220ba5792a7911884b2baaa24ef215ac47679
evidence_commitment=sha256:ca136341911241af68064f3f4a3cd1a77422776ed7903864de40c05dc41e9c89
settlement_domain=dcn.generation-attestation.settlement-state.v1
chain_id=$(printf '01%.0s' {1..48})
anchor_operator=$(printf 'a1%.0s' {1..48})
settlement_authority=$(printf 'a2%.0s' {1..48})
payer=$(printf 'b1%.0s' {1..48})
executor=$(printf 'c1%.0s' {1..48})
agreement=$(printf 'd1%.0s' {1..48})
capability=$(printf 'e1%.0s' {1..48})
unit=$(printf 'f1%.0s' {1..48})
scope_commitment=sha256:$(printf '11%.0s' {1..32})
amount=125
logical_time=1787526000

target_directory=${CARGO_TARGET_DIR:-$repo_root/target}
bin="$target_directory/debug"
rpc_port=${ACTIVECHAIN_G81_RPC_PORT:-49451}
validator_port_0=${ACTIVECHAIN_G81_VALIDATOR_PORT_0:-49453}
validator_port_1=${ACTIVECHAIN_G81_VALIDATOR_PORT_1:-49454}
validator_port_2=${ACTIVECHAIN_G81_VALIDATOR_PORT_2:-49455}
proposer_port=${ACTIVECHAIN_G81_PROPOSER_PORT:-49450}
rpc_address="127.0.0.1:$rpc_port"
pids=()

cleanup() {
  for pid in "${pids[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
}
diagnose() {
  status=$?
  if (( status != 0 )); then
    find "$output_directory" -type f -name '*.log' -maxdepth 4 -print | while read -r log; do
      echo "=== $log ===" >&2
      tail -n 100 "$log" >&2
    done
  fi
  cleanup
  exit "$status"
}
trap diagnose EXIT

wait_for_log() {
  local log=$1
  local expected=$2
  for _ in {1..400}; do
    if rg --quiet --fixed-strings "$expected" "$log" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

now_ns() {
  perl -MTime::HiRes=time -e 'printf("%.0f\n", time() * 1000000000)'
}

RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.97.1} cargo build --quiet \
  -p activechain-consensus-runtime --bin validator-node \
  -p activechain-rpc-server --bin activechain-rpc-ingest --bin activechain-rpc-node \
  --bin activechain-rpc-probe --bin actum-anchor-submit --bin actum-anchor-export \
  --bin actum-evidence-settle

# First reproduce the exact qualified G8 evidence and native finality envelope.
ACTIVECHAIN_G8_RPC_PORT=$rpc_port \
ACTIVECHAIN_G8_VALIDATOR_PORT_0=$validator_port_0 \
ACTIVECHAIN_G8_VALIDATOR_PORT_1=$validator_port_1 \
ACTIVECHAIN_G8_VALIDATOR_PORT_2=$validator_port_2 \
ACTIVECHAIN_G8_PROPOSER_PORT=$proposer_port \
  scripts/qualify-dcn-evidence-anchor.sh \
    "$evidence_id" "$evidence_commitment" "$output_directory/g8"

workdir="$output_directory/g8/network"
genesis_commitment=$(sed -n 's/.*"genesisCommitment":"\([0-9a-f]*\)".*/\1/p' \
  "$output_directory/g8/network-qualification.json")
statement_reference=$(sed -n 's/^submission_reference=//p' "$output_directory/g8/finality.txt")
evidence_transaction=$(sed -n 's/^transaction_id=//p' "$output_directory/g8/finality.txt")
evidence_height=$(sed -n 's/^checkpoint_height=//p' "$output_directory/g8/finality.txt")
evidence_block=$(sed -n 's/^finalized_block=//p' "$output_directory/g8/finality.txt")
[[ ${#genesis_commitment} -eq 96 ]]
[[ ${#statement_reference} -eq 96 ]]
[[ ${#evidence_transaction} -eq 96 ]]
[[ "$evidence_height" =~ ^[0-9]+$ ]]
[[ ${#evidence_block} -eq 96 ]]

"$bin/actum-evidence-settle" init \
  "$output_directory/settlement-ledger.bin" "$chain_id" "$unit" "$settlement_authority" \
  "$payer" 1000 "$executor" 50 1050 >"$output_directory/ledger-init.json"

apply_settlement() {
  local result=$1
  if [[ -n "${DCN_G81_SETTLEMENT_BIN:-}" ]]; then
    "$bin/actum-evidence-settle" apply \
      "$output_directory/settlement-ledger.bin" \
      "$output_directory/g8/native-finality-evidence.bin" \
      "$output_directory/settlement-instruction.bin" \
      "$output_directory/settlement-record.bin" "$output_directory/reputation-event.bin" \
      "$output_directory/settlement-state-anchor.bin" >"$result"
  else
    "$bin/actum-evidence-settle" settle \
      "$output_directory/settlement-ledger.bin" \
      "$output_directory/g8/native-finality-evidence.bin" \
      "$evidence_commitment" "$statement_reference" "$evidence_transaction" \
      "$evidence_height" "$evidence_block" "$chain_id" "$genesis_commitment" \
      "$settlement_authority" "$payer" "$executor" "$agreement" "$capability" \
      "$scope_commitment" "$amount" "$unit" "$logical_time" \
      "$output_directory/settlement-record.bin" "$output_directory/reputation-event.bin" \
      "$output_directory/settlement-state-anchor.bin" >"$result"
  fi
}

if [[ -n "${DCN_G81_SETTLEMENT_BIN:-}" ]]; then
  [[ -x "$DCN_G81_SETTLEMENT_BIN" ]]
  [[ -n "${DCN_G81_AGREEMENT:-}" && -f "$DCN_G81_AGREEMENT" ]]
  [[ -n "${DCN_G8_STORE:-}" && -f "$DCN_G8_STORE" ]]
  [[ -n "${DCN_G8_ATTESTATION_ID:-}" ]]
  "$DCN_G81_SETTLEMENT_BIN" prepare \
    "$DCN_G8_STORE" "$DCN_G8_ATTESTATION_ID" "$DCN_G81_AGREEMENT" \
    "$output_directory/g8/native-finality-evidence.bin" "$chain_id" "$genesis_commitment" \
    1 1 "$output_directory/settlement-instruction.bin" \
    >"$output_directory/dcn-prepared-settlement.json"
fi

settlement_started=$(now_ns)
apply_settlement "$output_directory/settlement.json"
settlement_finished=$(now_ns)
grep -q '"duplicate":false' "$output_directory/settlement.json"
grep -q '"payerBalance":"875"' "$output_directory/settlement.json"
grep -q '"executorBalance":"175"' "$output_directory/settlement.json"

settlement_id=$(sed -n 's/.*"settlementId":"\([0-9a-f]*\)".*/\1/p' "$output_directory/settlement.json")
state_anchor_digest=$(sed -n 's/.*"stateAnchorDigest":"\([0-9a-f]*\)".*/\1/p' "$output_directory/settlement.json")
state_anchor_reference=$(sed -n 's/.*"stateAnchorReference":"\([0-9a-f]*\)".*/\1/p' "$output_directory/settlement.json")
[[ ${#settlement_id} -eq 96 ]]
[[ ${#state_anchor_digest} -eq 64 ]]
[[ ${#state_anchor_reference} -eq 96 ]]

start_validator_listener() {
  local index=$1
  local port=$2
  local log=$3
  "$bin/validator-node" \
    "$port" "$workdir/v$index.snapshot" "$workdir/genesis.bin" 0 "$index" \
    "--key-file=$workdir/keys/validator-$index.key" >"$log" 2>&1 &
  pids+=("$!")
  wait_for_log "$log" "activechain validator listening on 0.0.0.0:$port"
}

start_rpc() {
  ACTIVECHAIN_ANCHOR_ACTION_SPOOL="$workdir/settlement-actions.batch" \
  ACTIVECHAIN_ANCHOR_EXECUTION_STATE="$workdir/execution.snapshot" \
  ACTIVECHAIN_ANCHOR_OPERATOR="$anchor_operator" \
  ACTIVECHAIN_ANCHOR_SNAPSHOT="$workdir/anchor-registry.snapshot" \
    "$bin/activechain-rpc-node" "$workdir/rpc-index.snapshot" "$rpc_address" \
    >"$workdir/g81-rpc.log" 2>&1 &
  rpc_pid=$!
  pids+=("$rpc_pid")
  wait_for_log "$workdir/g81-rpc.log" "ActiveChain development RPC listening on $rpc_address"
}

start_rpc
request=$(printf '{"schema":"actum.anchor.submit.request.v1","operation":"submit_external_digest_anchor","checkpoint":{"checkpointId":"%s","checkpointHash":"%s"}}' \
  "$settlement_id" "$state_anchor_digest")
submit_settlement_anchor() {
  local output=$1
  printf '%s' "$request" | \
    ACTUM_ANCHOR_APPLICATION_DOMAIN="$settlement_domain" \
    ACTUM_ANCHOR_RPC_ADDRESS="$rpc_address" \
    "$bin/actum-anchor-submit" >"$output"
  grep -q "$state_anchor_reference" "$output"
}

submit_started=$(now_ns)
submit_settlement_anchor "$output_directory/settlement-submission.json"
submit_finished=$(now_ns)
submit_settlement_anchor "$output_directory/settlement-duplicate-before-restart.json"

# Restart both the application worker and RPC; neither retry may duplicate the debit/credit.
kill "$rpc_pid"
wait "$rpc_pid" 2>/dev/null || true
printf '' >"$workdir/g81-rpc.log"
start_rpc
submit_settlement_anchor "$output_directory/settlement-duplicate-after-rpc-restart.json"
apply_settlement "$output_directory/settlement-after-restart.json"
grep -q '"duplicate":true' "$output_directory/settlement-after-restart.json"
grep -q '"payerBalance":"875"' "$output_directory/settlement-after-restart.json"
grep -q '"executorBalance":"175"' "$output_directory/settlement-after-restart.json"

application_lookup_started=$(now_ns)
"$bin/actum-evidence-settle" query-evidence \
  "$output_directory/settlement-ledger.bin" "$evidence_commitment" \
  >"$output_directory/query-by-evidence.json"
"$bin/actum-evidence-settle" query-settlement \
  "$output_directory/settlement-ledger.bin" "$settlement_id" \
  >"$output_directory/query-settlement.json"
"$bin/actum-evidence-settle" query-account \
  "$output_directory/settlement-ledger.bin" "$payer" \
  >"$output_directory/query-payer.json"
"$bin/actum-evidence-settle" query-reputation \
  "$output_directory/settlement-ledger.bin" "$executor" \
  >"$output_directory/query-reputation.json"
application_lookup_finished=$(now_ns)
grep -q "$settlement_id" "$output_directory/query-by-evidence.json"
grep -q "$evidence_commitment" "$output_directory/query-settlement.json"
grep -q '"balance":"875"' "$output_directory/query-payer.json"
grep -q '"settlementCompleted":true' "$output_directory/query-reputation.json"

# Continue the same three-validator chain and finalize the accounting-state commitment.
start_validator_listener 0 "$validator_port_0" "$workdir/g81-v0-listener.log"
start_validator_listener 1 "$validator_port_1" "$workdir/g81-v1-listener.log"
round_started=$(now_ns)
"$bin/validator-node" \
  "$proposer_port" "$workdir/v2.snapshot" "$workdir/genesis.bin" 0 2 --once \
  "--key-file=$workdir/keys/validator-2.key" \
  "--chain-id-hex=$chain_id" \
  "--cash-ledger=$workdir/cash-ledger.snapshot" \
  "--execution-state=$workdir/execution.snapshot" \
  "--anchor-operator=$anchor_operator" \
  --anchor-fee-balance=1000000000 \
  "--anchor-actions=$workdir/settlement-actions.batch" \
  "--finalized-cash-out=$workdir/g81-finalized-cash.snapshot" \
  "--finality-out=$workdir/g81-finality.bundle" \
  "--peer=1@127.0.0.1:$validator_port_0" \
  "--peer=2@127.0.0.1:$validator_port_1" >"$workdir/g81-round.log" 2>&1
round_finished=$(now_ns)
rg --quiet 'completed network round: finalized_height=' "$workdir/g81-round.log"
archive=$(find "$workdir" -maxdepth 1 -type f -name 'settlement-actions.batch.finalized-*' -print)
[[ $(printf '%s\n' "$archive" | wc -l | tr -d ' ') -eq 1 ]]
settlement_finalized_height=${archive##*-}

"$bin/activechain-rpc-probe" "$rpc_address" >"$workdir/g81-reconcile-probe.log"
kill "$rpc_pid"
wait "$rpc_pid" 2>/dev/null || true
"$bin/activechain-rpc-ingest" \
  "$workdir/v2.snapshot" "$workdir/rpc-index.snapshot" \
  "$workdir/g81-finalized-cash.snapshot" "$workdir/g81-finality.bundle" \
  "$workdir/execution.snapshot" >"$workdir/g81-rpc-ingest.log"
printf '' >"$workdir/g81-rpc.log"
start_rpc

lookup_started=$(now_ns)
"$bin/actum-anchor-export" "$rpc_address" "$state_anchor_reference" \
  "$output_directory/settlement-finalized-record.bin" \
  "$output_directory/settlement-state-proof.bin" \
  "$output_directory/settlement-checkpoint-finality.bin" \
  "$output_directory/settlement-native-finality-evidence.bin" \
  >"$output_directory/settlement-finality.txt"
lookup_finished=$(now_ns)
grep -q "submission_reference=$state_anchor_reference" "$output_directory/settlement-finality.txt"
grep -q "^checkpoint_height=$settlement_finalized_height$" "$output_directory/settlement-finality.txt"
settlement_transaction=$(sed -n 's/^transaction_id=//p' "$output_directory/settlement-finality.txt")
settlement_finalized_block=$(sed -n 's/^finalized_block=//p' "$output_directory/settlement-finality.txt")
settlement_state_root=$(sed -n 's/^checkpoint_state_root=//p' "$output_directory/settlement-finality.txt")
settlement_object_count=$(sed -n 's/^checkpoint_object_count=//p' "$output_directory/settlement-finality.txt")
accounting_commitment=$(sed -n 's/.*"accountingCommitment":"\([0-9a-f]*\)".*/\1/p' "$output_directory/settlement.json")
state_commitment=$(sed -n 's/.*"stateCommitment":"\([0-9a-f]*\)".*/\1/p' "$output_directory/settlement.json")
reputation_event=$(sed -n 's/.*"reputationEventId":"\([0-9a-f]*\)".*/\1/p' "$output_directory/settlement.json")
idempotency_id=$(sed -n 's/.*"idempotencyId":"\([0-9a-f]*\)".*/\1/p' "$output_directory/settlement.json")
[[ ${#settlement_transaction} -eq 96 ]]
[[ ${#settlement_finalized_block} -eq 96 ]]
[[ ${#settlement_state_root} -eq 96 ]]
[[ "$settlement_object_count" =~ ^[0-9]+$ ]]
[[ ${#accounting_commitment} -eq 96 ]]
[[ ${#state_commitment} -eq 96 ]]
[[ ${#reputation_event} -eq 96 ]]
[[ ${#idempotency_id} -eq 96 ]]

settlement_ms=$(( (settlement_finished - settlement_started) / 1000000 ))
submit_ms=$(( (submit_finished - submit_started) / 1000000 ))
consensus_ms=$(( (round_finished - round_started) / 1000000 ))
lookup_ms=$(( (lookup_finished - lookup_started) / 1000000 ))
application_lookup_ms=$(( (application_lookup_finished - application_lookup_started) / 1000000 ))
printf '{"schema":"actum.dcn-evidence-settlement-qualification.v1","status":"finalized","evidenceAnchorCommitment":"%s","evidenceAction":"%s","evidenceHeight":%s,"settlementId":"%s","idempotencyId":"%s","accountingCommitment":"%s","stateCommitment":"%s","stateAnchorDigest":"%s","stateAnchorReference":"%s","settlementAction":"%s","settlementFinalizedHeight":%s,"settlementFinalizedBlock":"%s","settlementStateRoot":"%s","settlementObjectCount":%s,"reputationEventId":"%s","payer":"%s","payerBefore":"1000","payerAfter":"875","executor":"%s","executorBefore":"50","executorAfter":"175","amount":"%s","conservedTotal":"1050","assurance":"cryptographic","settlementPolicyVersion":1,"reputationPolicyVersion":1,"validatorCount":3,"duplicateApplicationAfterRestart":true,"duplicateSubmissionBeforeRestart":true,"duplicateSubmissionAfterRestart":true,"finalityRevalidation":true,"queryRoundtrip":true,"settlementMs":%s,"anchorSubmitMs":%s,"consensusMs":%s,"lookupMs":%s,"applicationLookupMs":%s,"accountingFirst":true,"nativeTokenTransfer":false}\n' \
  "$evidence_commitment" "$evidence_transaction" "$evidence_height" "$settlement_id" \
  "$idempotency_id" "$accounting_commitment" "$state_commitment" "$state_anchor_digest" \
  "$state_anchor_reference" "$settlement_transaction" "$settlement_finalized_height" \
  "$settlement_finalized_block" "$settlement_state_root" "$settlement_object_count" \
  "$reputation_event" "$payer" "$executor" "$amount" "$settlement_ms" "$submit_ms" \
  "$consensus_ms" "$lookup_ms" \
  "$application_lookup_ms" \
  >"$output_directory/network-qualification.json"

echo "DCN finalized-evidence settlement anchored at height $settlement_finalized_height: $state_anchor_reference"
