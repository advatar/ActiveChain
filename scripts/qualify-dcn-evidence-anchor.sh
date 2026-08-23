#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo "usage: $0 <evidence-id> <sha256-evidence-commitment> <output-directory>" >&2
  exit 64
fi

evidence_id=$1
evidence_commitment=$2
output_directory=$3
if [[ ! "$evidence_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "evidence ID must use canonical sha256:<lowercase-hex> syntax" >&2
  exit 64
fi
if [[ ! "$evidence_commitment" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "evidence commitment must use canonical sha256:<lowercase-hex> syntax" >&2
  exit 64
fi
digest=${evidence_commitment#sha256:}

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$repo_root"
if [[ -e "$output_directory" ]]; then
  echo "output directory already exists: $output_directory" >&2
  exit 64
fi
mkdir -p "$output_directory"
workdir="$output_directory/network"
mkdir -p "$workdir"

target_directory=${CARGO_TARGET_DIR:-$repo_root/target}
bin="$target_directory/debug"
chain_id=$(printf '01%.0s' {1..48})
anchor_operator=$(printf 'a1%.0s' {1..48})
application_domain=dcn.generation-attestation.evidence-anchor.v1
rpc_port=${ACTIVECHAIN_G8_RPC_PORT:-49351}
validator_port_0=${ACTIVECHAIN_G8_VALIDATOR_PORT_0:-49353}
validator_port_1=${ACTIVECHAIN_G8_VALIDATOR_PORT_1:-49354}
validator_port_2=${ACTIVECHAIN_G8_VALIDATOR_PORT_2:-49355}
proposer_port=${ACTIVECHAIN_G8_PROPOSER_PORT:-49350}
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
    for log in "$workdir"/*.log; do
      [[ -f "$log" ]] || continue
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

RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.97.1} cargo build --quiet \
  -p activechain-consensus-runtime --bin genesis-tool --bin cash-genesis-tool --bin validator-node \
  -p activechain-rpc-server --bin activechain-rpc-bootstrap --bin activechain-rpc-ingest \
  --bin activechain-rpc-node --bin activechain-rpc-probe --bin actum-anchor-submit \
  --bin actum-anchor-export

genesis_output=$("$bin/genesis-tool" "$workdir/genesis.bin" 1 1 3 "$workdir/keys")
genesis_commitment=$(printf '%s\n' "$genesis_output" | sed -n 's/^genesis_commitment=//p')
[[ ${#genesis_commitment} -eq 96 ]]
"$bin/cash-genesis-tool" \
  "$workdir/cash-ledger.snapshot" "$chain_id" "$anchor_operator" \
  1000000000 1000 --treasury-cells=2 >"$workdir/cash-genesis.log"

start_validator_listener 1 "$validator_port_1" "$workdir/v1-listener.log"
start_validator_listener 2 "$validator_port_2" "$workdir/v2-listener.log"

"$bin/validator-node" \
  "$proposer_port" "$workdir/v0.snapshot" "$workdir/genesis.bin" 0 0 --once \
  "--key-file=$workdir/keys/validator-0.key" \
  "--chain-id-hex=$chain_id" \
  "--cash-ledger=$workdir/cash-ledger.snapshot" \
  "--execution-state=$workdir/execution.snapshot" \
  "--anchor-operator=$anchor_operator" \
  --anchor-fee-balance=1000000000 \
  "--finalized-cash-out=$workdir/finalized-cash.snapshot" \
  "--finality-out=$workdir/finality.bundle" \
  "--peer=2@127.0.0.1:$validator_port_1" \
  "--peer=3@127.0.0.1:$validator_port_2" >"$workdir/round-0.log" 2>&1
rg --quiet --fixed-strings "completed network round: finalized_height=0" "$workdir/round-0.log"

"$bin/activechain-rpc-bootstrap" \
  "$workdir/genesis.bin" "$chain_id" "$workdir/rpc-index.snapshot" 3600 \
  >"$workdir/rpc-bootstrap.log"

start_rpc() {
  ACTIVECHAIN_ANCHOR_ACTION_SPOOL="$workdir/anchor-actions.batch" \
  ACTIVECHAIN_ANCHOR_EXECUTION_STATE="$workdir/execution.snapshot" \
  ACTIVECHAIN_ANCHOR_OPERATOR="$anchor_operator" \
  ACTIVECHAIN_ANCHOR_SNAPSHOT="$workdir/anchor-registry.snapshot" \
    "$bin/activechain-rpc-node" "$workdir/rpc-index.snapshot" "$rpc_address" \
    >"$workdir/rpc.log" 2>&1 &
  rpc_pid=$!
  pids+=("$rpc_pid")
  wait_for_log "$workdir/rpc.log" "ActiveChain development RPC listening on $rpc_address"
}

start_rpc
request=$(printf '{"schema":"actum.evidence-anchor.submit.request.v1","operation":"submit_evidence_anchor","evidence":{"evidenceId":"%s","evidenceCommitment":"%s","applicationDomain":"%s"}}' \
  "$evidence_id" "$evidence_commitment" "$application_domain")
submit_evidence() {
  local output=$1
  local actum_output="$output.actum"
  printf '%s' "$request" | \
    ACTUM_ANCHOR_APPLICATION_DOMAIN="$application_domain" \
    ACTUM_ANCHOR_RPC_ADDRESS="$rpc_address" \
    "$bin/actum-anchor-submit" >"$actum_output"
  if [[ -n ${DCN_G8_ANCHOR_BIN:-} ]]; then
    : "${DCN_G8_ATTESTATION:?DCN_G8_ATTESTATION is required}"
    : "${DCN_G8_CONTEXT:?DCN_G8_CONTEXT is required}"
    : "${DCN_G8_STORE:?DCN_G8_STORE is required}"
    local submitted_reference
    submitted_reference=$(sed -n 's/.*"reference":"\([0-9a-f]*\)".*/\1/p' "$actum_output")
    [[ ${#submitted_reference} -eq 96 ]]
    "$DCN_G8_ANCHOR_BIN" stage \
      "$DCN_G8_ATTESTATION" "$DCN_G8_CONTEXT" "$DCN_G8_STORE" \
      "$submitted_reference" "actum-native:$submitted_reference" >"$output"
  else
    mv "$actum_output" "$output"
  fi
}

submit_started=$(now_ns)
submit_evidence "$output_directory/submission.json"
submit_finished=$(now_ns)
if [[ -n ${DCN_G8_ANCHOR_BIN:-} ]]; then
  reference=$(sed -n 's/.*"statementReference":"\([0-9a-f]*\)".*/\1/p' "$output_directory/submission.json")
  grep -q "\"evidenceAnchorCommitment\":\"$evidence_commitment\"" "$output_directory/submission.json"
else
  reference=$(sed -n 's/.*"reference":"\([0-9a-f]*\)".*/\1/p' "$output_directory/submission.json")
fi
[[ ${#reference} -eq 96 ]]
[[ -s "$workdir/anchor-actions.batch" ]]

# Exact duplicate submission is deterministic before and after a process restart.
submit_evidence "$output_directory/duplicate-before-restart.json"
grep -q "$reference" "$output_directory/duplicate-before-restart.json"
kill "$rpc_pid"
wait "$rpc_pid" 2>/dev/null || true
printf '' >"$workdir/rpc.log"
start_rpc
submit_evidence "$output_directory/duplicate-after-restart.json"
grep -q "$reference" "$output_directory/duplicate-after-restart.json"

# Round one is led by validator 1. Replace its listener with validator 0 and
# include the exact operator-owned anchor action in real three-validator consensus.
kill "${pids[0]}" 2>/dev/null || true
wait "${pids[0]}" 2>/dev/null || true
start_validator_listener 0 "$validator_port_0" "$workdir/v0-listener.log"
round_started=$(now_ns)
"$bin/validator-node" \
  "$proposer_port" "$workdir/v1.snapshot" "$workdir/genesis.bin" 0 1 --once \
  "--key-file=$workdir/keys/validator-1.key" \
  "--chain-id-hex=$chain_id" \
  "--cash-ledger=$workdir/cash-ledger.snapshot" \
  "--execution-state=$workdir/execution.snapshot" \
  "--anchor-operator=$anchor_operator" \
  --anchor-fee-balance=1000000000 \
  "--anchor-actions=$workdir/anchor-actions.batch" \
  "--finalized-cash-out=$workdir/finalized-cash.snapshot" \
  "--finality-out=$workdir/finality.bundle" \
  "--peer=1@127.0.0.1:$validator_port_0" \
  "--peer=3@127.0.0.1:$validator_port_2" >"$workdir/round-1.log" 2>&1
round_finished=$(now_ns)
rg --quiet --fixed-strings "completed network round: finalized_height=1" "$workdir/round-1.log"
archive=$(find "$workdir" -maxdepth 1 -type f -name 'anchor-actions.batch.finalized-*' -print)
[[ $(printf '%s\n' "$archive" | wc -l | tr -d ' ') -eq 1 ]]
anchor_finalized_height=${archive##*-}
[[ "$anchor_finalized_height" =~ ^[0-9]+$ ]]
[[ -s "$workdir/anchor-actions.batch.receipt.finalized-$anchor_finalized_height" ]]
[[ -s "$workdir/anchor-actions.batch.finality.finalized-$anchor_finalized_height" ]]

# Any RPC request first reconciles the native finality archive into the durable
# anchor registry. Then restart around RPC-index ingestion to serve an exact
# sparse-state membership proof at the finalized checkpoint.
"$bin/activechain-rpc-probe" "$rpc_address" >"$workdir/reconcile-probe.log"
kill "$rpc_pid"
wait "$rpc_pid" 2>/dev/null || true
"$bin/activechain-rpc-ingest" \
  "$workdir/v1.snapshot" "$workdir/rpc-index.snapshot" \
  "$workdir/finalized-cash.snapshot" "$workdir/finality.bundle" \
  "$workdir/execution.snapshot" >"$workdir/rpc-ingest.log"
printf '' >"$workdir/rpc.log"
start_rpc

lookup_started=$(now_ns)
"$bin/actum-anchor-export" "$rpc_address" "$reference" \
  "$output_directory/finalized-record.bin" \
  "$output_directory/anchor-state-proof.bin" \
  "$output_directory/checkpoint-finality.bin" \
  "$output_directory/native-finality-evidence.bin" >"$output_directory/finality.txt"
lookup_finished=$(now_ns)
grep -q "submission_reference=$reference" "$output_directory/finality.txt"
grep -q "^checkpoint_height=$anchor_finalized_height$" "$output_directory/finality.txt"

if [[ -n ${DCN_G8_ANCHOR_BIN:-} ]]; then
  : "${DCN_G8_ATTESTATION_ID:?DCN_G8_ATTESTATION_ID is required}"
  "$DCN_G8_ANCHOR_BIN" finalize-files \
    "$DCN_G8_STORE" "$DCN_G8_ATTESTATION_ID" \
    "$output_directory/native-finality-evidence.bin" \
    "$chain_id" "$genesis_commitment" 1 1 \
    >"$output_directory/dcn-finalization.json"
  grep -q '"status":"NETWORK_FINALIZED"' "$output_directory/dcn-finalization.json"
  grep -q "\"evidenceAnchorCommitment\":\"$evidence_commitment\"" "$output_directory/dcn-finalization.json"
  grep -q "$reference" "$output_directory/dcn-finalization.json"
fi

transaction_id=$(sed -n 's/^transaction_id=//p' "$output_directory/finality.txt")
action_id=$(sed -n 's/^action_id=//p' "$output_directory/finality.txt")
checkpoint_state_root=$(sed -n 's/^checkpoint_state_root=//p' "$output_directory/finality.txt")
checkpoint_object_count=$(sed -n 's/^checkpoint_object_count=//p' "$output_directory/finality.txt")
record_bytes=$(stat -f '%z' "$output_directory/finalized-record.bin" 2>/dev/null || stat -c '%s' "$output_directory/finalized-record.bin")
proof_bytes=$(stat -f '%z' "$output_directory/anchor-state-proof.bin" 2>/dev/null || stat -c '%s' "$output_directory/anchor-state-proof.bin")
finality_bytes=$(stat -f '%z' "$output_directory/checkpoint-finality.bin" 2>/dev/null || stat -c '%s' "$output_directory/checkpoint-finality.bin")
native_evidence_bytes=$(stat -f '%z' "$output_directory/native-finality-evidence.bin" 2>/dev/null || stat -c '%s' "$output_directory/native-finality-evidence.bin")

submit_ms=$(( (submit_finished - submit_started) / 1000000 ))
consensus_ms=$(( (round_finished - round_started) / 1000000 ))
lookup_ms=$(( (lookup_finished - lookup_started) / 1000000 ))
printf '{"schema":"actum.dcn-evidence-anchor-qualification.v1","status":"finalized","evidenceId":"%s","evidenceCommitment":"%s","applicationDomain":"%s","chainId":"%s","genesisCommitment":"%s","submissionReference":"%s","transactionId":"%s","actionId":"%s","finalizedHeight":%s,"checkpointStateRoot":"%s","checkpointObjectCount":%s,"submitMs":%s,"consensusMs":%s,"lookupMs":%s,"finalizedRecordBytes":%s,"stateProofBytes":%s,"checkpointFinalityBytes":%s,"nativeEvidenceBytes":%s,"duplicateBeforeRestart":true,"duplicateAfterRestart":true,"rpcRestartRecovery":true,"validatorCount":3}\n' \
  "$evidence_id" "$evidence_commitment" "$application_domain" "$chain_id" \
  "$genesis_commitment" "$reference" "$transaction_id" "$action_id" "$anchor_finalized_height" \
  "$checkpoint_state_root" "$checkpoint_object_count" "$submit_ms" "$consensus_ms" \
  "$lookup_ms" "$record_bytes" "$proof_bytes" "$finality_bytes" "$native_evidence_bytes" \
  >"$output_directory/network-qualification.json"

echo "DCN evidence anchor finalized at height $anchor_finalized_height: $reference"
