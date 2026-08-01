use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use activechain_agent_interfaces::AuthorityBindingV1;
use activechain_application_primitives::{
    ApplicationReceipt, JobStatus, verify_finalized_receipt_record,
};
use activechain_canonical_codec::encode_envelope;
use activechain_finality_types::{
    FinalityCertificateBundle, FinalizedBlockHeader, ProofPublicInputs,
};
use activechain_mcp_server::{
    BackendError, MCP_PROTOCOL_VERSION, McpSession, ProposalBackend, ReadOnlyBackend, StoreBackend,
};
use activechain_proposal_gateway::{
    ActionIntentV1, ActionKindV1, AuthenticatedProposalContext, ProposalJournalV1,
    TransferProposalArgumentsV1, WalletProposalStateV1, WalletProposalStoreV1,
};
use activechain_protocol_types::{
    ChainId, ConsensusVoteContext, CryptoSuiteId, Digest384, JobId, PrincipalId, ProtocolSignature,
    QuorumCertificate, TransactionId, ValidatorGenesis, ValidatorGenesisEntry, ValidatorVote,
};
use activechain_rpc_server::{DurableRpcStore, RpcIndex, verify_query_record_with_chain_genesis};
use activechain_rpc_types::{ActionSetProof, ProofKind, QueryKind, QueryRecord};
use activechain_state_tree::StateCommitment;
use activechain_wallet_ffi::{
    ACTIVECHAIN_WALLET_AGENT_REJECTED, ACTIVECHAIN_WALLET_APPROVAL_MISMATCH,
    authorize_proposal_intent, submit_authorized_proposal,
};
use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
use serde_json::{Value, json};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

static CURRENT_HEIGHT: AtomicU64 = AtomicU64::new(10);
fn current_height() -> u64 {
    CURRENT_HEIGHT.load(Ordering::SeqCst)
}
fn now() -> u64 {
    100
}

#[derive(Debug)]
pub enum RehearsalError {
    Step(&'static str),
}

#[derive(Clone, Copy)]
struct UnavailableBackend;
impl ReadOnlyBackend for UnavailableBackend {
    fn get_status(&self) -> Result<Value, BackendError> {
        Err(BackendError::Unavailable)
    }
    fn list_assets(&self, _: Option<&str>, _: u16) -> Result<Value, BackendError> {
        Err(BackendError::Unavailable)
    }
    fn verify_record(&self, _: &str) -> Result<Value, BackendError> {
        Err(BackendError::Unavailable)
    }
    fn get_pending_approvals(&self, _: u16) -> Result<Value, BackendError> {
        Err(BackendError::Unavailable)
    }
    fn resolve_receipt(&self, _: &str) -> Result<Value, BackendError> {
        Err(BackendError::Unavailable)
    }
}

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn proposal_context() -> AuthenticatedProposalContext {
    AuthenticatedProposalContext {
        chain_id: "activechain.local-3v".into(),
        wallet_id: "wallet.rehearsal".into(),
        agent_principal: digest(1),
        capability_id: digest(2),
        permitted_resource: digest(3),
        permitted_recipient: Some(digest(4)),
        maximum_single_amount: 1_000,
        remaining_budget: 2_000,
        maximum_fee: 10,
        permitted_anchor_domain: None,
    }
}

fn transfer() -> TransferProposalArgumentsV1 {
    TransferProposalArgumentsV1 {
        asset_commitment: hex(digest(3).as_bytes()),
        recipient_commitment: hex(digest(4).as_bytes()),
        amount: 125,
        maximum_fee: 4,
        replay_domain: hex(digest(5).as_bytes()),
    }
}

fn authority(
    request_id: &str,
    nonce: &str,
    expires: u64,
    transfer: &TransferProposalArgumentsV1,
) -> AuthorityBindingV1 {
    let context = proposal_context();
    let intent = ActionIntentV1 {
        request_id: request_id.as_bytes().to_vec(),
        chain_id: context.chain_id.as_bytes().to_vec(),
        wallet_id: context.wallet_id.as_bytes().to_vec(),
        agent_principal: context.agent_principal,
        capability_id: context.capability_id,
        request_nonce: nonce.as_bytes().to_vec(),
        action: ActionKindV1::Transfer,
        resource: context.permitted_resource,
        recipient: context.permitted_recipient.expect("pinned recipient"),
        amount: transfer.amount,
        maximum_fee: transfer.maximum_fee,
        expires_at_height: expires,
        replay_domain: digest(5),
    };
    AuthorityBindingV1 {
        chain_id: context.chain_id,
        wallet_id: context.wallet_id,
        agent_principal: hex(context.agent_principal.as_bytes()),
        capability_id: hex(context.capability_id.as_bytes()),
        request_nonce: nonce.into(),
        expires_at_height: expires,
        intent_commitment: hex(intent.commitment().unwrap().as_bytes()),
    }
}

fn initialized_session<B: ReadOnlyBackend>(backend: B) -> McpSession<B> {
    let mut session = McpSession::new(backend);
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":MCP_PROTOCOL_VERSION}});
    let response = session.handle_line(&serde_json::to_vec(&init).unwrap()).unwrap();
    assert!(serde_json::from_slice::<Value>(&response).unwrap().get("result").is_some());
    let notification = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
    assert!(session.handle_line(&serde_json::to_vec(&notification).unwrap()).is_none());
    session
}

fn tool_call<B: ReadOnlyBackend>(
    session: &mut McpSession<B>,
    id: u64,
    name: &str,
    arguments: Value,
) -> Value {
    let request = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}});
    let bytes = session.handle_line(&serde_json::to_vec(&request).unwrap()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(bytes);
    let mut output = [0; 48];
    XofReader::read(&mut hasher.finalize_xof(), &mut output);
    Digest384::new(output)
}

fn three_validator_finality(inputs: ProofPublicInputs) -> (Vec<u8>, Digest384) {
    let validators: Vec<_> = (0..3_u8)
        .map(|index| {
            let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([41 + index; 32]));
            let principal = PrincipalId::new(digest(70 + index));
            (principal, key)
        })
        .collect();
    let genesis = ValidatorGenesis::new_with_revision(
        3,
        1,
        4,
        validators
            .iter()
            .map(|(principal, key)| {
                ValidatorGenesisEntry::new(*principal, 1, key.verifying_key().encode().into())
                    .unwrap()
            })
            .collect(),
    )
    .unwrap();
    let header = FinalizedBlockHeader {
        inputs: ProofPublicInputs { validator_set_root: genesis.validator_set_root(), ..inputs },
        proof_statement_commitment: digest(76),
    };
    let context = ConsensusVoteContext::new_with_revision(
        genesis.genesis_commitment(),
        genesis.epoch(),
        genesis.validator_set_root(),
        genesis.protocol_revision(),
    )
    .unwrap();
    let votes: Vec<_> = validators
        .iter()
        .take(3)
        .map(|(principal, key)| {
            let placeholder =
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap();
            let unsigned = ValidatorVote::new(
                *principal,
                context,
                11,
                2,
                header.digest().unwrap(),
                header.proof_statement_commitment,
                placeholder,
            )
            .unwrap();
            let signature = key.sign(&unsigned.signing_payload()).encode();
            ValidatorVote::new(
                *principal,
                context,
                11,
                2,
                header.digest().unwrap(),
                header.proof_statement_commitment,
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.to_vec()).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
    for (vote, (_, key)) in votes.iter().zip(validators.iter()) {
        hasher.update(key.verifying_key().encode().as_slice());
        hasher.update(&vote.signing_payload());
        hasher.update(vote.signature().as_bytes());
    }
    let mut root = [0; 48];
    XofReader::read(&mut hasher.finalize_xof(), &mut root);
    let certificate = QuorumCertificate::new(
        context,
        11,
        2,
        header.digest().unwrap(),
        header.proof_statement_commitment,
        Digest384::new(root),
        3,
        3,
    )
    .unwrap();
    let genesis_commitment = genesis.genesis_commitment();
    let bundle = FinalityCertificateBundle::new(header, genesis, certificate, votes).unwrap();
    (encode_envelope(&bundle).unwrap(), genesis_commitment)
}

fn receipt_record(intent: &ActionIntentV1, transaction: Digest384) -> (QueryRecord, Digest384) {
    let job = JobId::new(intent.proposal_id().unwrap());
    let receipt = ApplicationReceipt::new(
        job,
        intent.commitment().unwrap(),
        JobStatus::Completed,
        Some(transaction),
        intent.maximum_fee,
        11,
        intent.replay_domain,
    )
    .unwrap();
    let receipt_commitment = receipt.commitment().unwrap();
    let receipt_id = TransactionId::new(receipt_commitment);
    let proof = ActionSetProof::new(vec![receipt_id]).unwrap();
    let action_root = activechain_finality_types::commit_parts(
        b"ACTIVECHAIN-BLOCK-ACTIONS-V1",
        &[receipt_id.digest().as_bytes()],
    );
    let inputs = ProofPublicInputs {
        chain_id: ChainId::new(digest(10)),
        epoch: 3,
        height: 11,
        protocol_revision: 4,
        validator_set_root: digest(69),
        parent_block_id: digest(71),
        pre_state: StateCommitment::new(digest(80), 0),
        authorization_root: digest(72),
        action_root,
        execution_order_root: digest(74),
        total_fees: 0,
        pre_supply: 0,
        issuance: 0,
        burn: 0,
        post_supply: 0,
        cash_cell_root: digest(75),
        post_state: StateCommitment::new(digest(81), 0),
        receipt_root: digest(77),
        data_availability_commitment: digest(78),
    };
    let (finality, genesis) = three_validator_finality(inputs);
    let record = QueryRecord::new(
        QueryKind::ApplicationReceipt,
        job.into_digest(),
        11,
        encode_envelope(&receipt).unwrap(),
        encode_envelope(&proof).unwrap(),
        finality,
    )
    .unwrap();
    (record, genesis)
}

pub fn run_rehearsal(directory: &Path) -> Result<Value, RehearsalError> {
    std::fs::create_dir_all(directory).map_err(|_| RehearsalError::Step("setup"))?;
    CURRENT_HEIGHT.store(10, Ordering::SeqCst);
    let journal_path = directory.join("proposal.snapshot");
    let backend = Arc::new(ProposalBackend::new(
        UnavailableBackend,
        ProposalJournalV1::default(),
        proposal_context(),
        journal_path,
        current_height,
    ));
    let transfer_arguments = transfer();
    let authority_binding = authority("mcp-request-1", "nonce-1", 50, &transfer_arguments);
    let arguments = json!({"request_id":"mcp-request-1","authority":authority_binding,"transfer":transfer_arguments});
    let mut session = initialized_session(Arc::clone(&backend));
    let proposal = tool_call(&mut session, 2, "activechain_propose_transfer", arguments.clone());
    if proposal.pointer("/result/isError").and_then(Value::as_bool) != Some(false) {
        return Err(RehearsalError::Step("proposal"));
    }
    let intent = backend
        .admitted_intent(b"mcp-request-1")
        .map_err(|_| RehearsalError::Step("intent lock"))?
        .ok_or(RehearsalError::Step("intent missing"))?;
    let reviewed_commitment = intent.commitment().unwrap();
    let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([31; 32]));
    let public_key = key.verifying_key().encode();
    let authorized = authorize_proposal_intent(
        &intent,
        10,
        reviewed_commitment,
        public_key.as_slice().to_vec(),
        |payload| key.sign(payload).encode().to_vec(),
    )
    .map_err(|_| RehearsalError::Step("native authorization"))?;
    let mut submitted = Vec::new();
    submit_authorized_proposal(&authorized, 10, |envelope| {
        submitted.extend_from_slice(envelope);
        true
    })
    .map_err(|_| RehearsalError::Step("submission"))?;
    if submitted != authorized {
        return Err(RehearsalError::Step("submission"));
    }
    let authorization = domain_digest(b"ACTIVECHAIN-MCP-REHEARSAL-AUTHORIZATION-V1", &authorized);
    let transaction = domain_digest(b"ACTIVECHAIN-MCP-REHEARSAL-TRANSACTION-V1", &submitted);
    let proposal_id = intent.proposal_id().unwrap();
    let mut lifecycle = WalletProposalStoreV1::default();
    lifecycle.admit(intent.clone(), 10).map_err(|_| RehearsalError::Step("lifecycle admit"))?;
    lifecycle
        .transition(proposal_id, 1, WalletProposalStateV1::Approved, authorization, 10)
        .map_err(|_| RehearsalError::Step("lifecycle approve"))?;
    lifecycle
        .transition(proposal_id, 2, WalletProposalStateV1::Submitted, transaction, 10)
        .map_err(|_| RehearsalError::Step("lifecycle submit"))?;
    let (record, chain_genesis) = receipt_record(&intent, transaction);
    verify_query_record_with_chain_genesis(&record, chain_genesis)
        .map_err(|_| RehearsalError::Step("independent finality verification"))?;
    let receipt = verify_finalized_receipt_record(&record)
        .map_err(|_| RehearsalError::Step("independent receipt verification"))?;
    lifecycle
        .transition(
            proposal_id,
            3,
            WalletProposalStateV1::Finalized,
            receipt.commitment().unwrap(),
            11,
        )
        .map_err(|_| RehearsalError::Step("lifecycle finalize"))?;
    lifecycle
        .save_atomic(&directory.join("wallet.snapshot"))
        .map_err(|_| RehearsalError::Step("lifecycle persistence"))?;

    let index = RpcIndex::new(
        ChainId::new(digest(10)),
        chain_genesis,
        4,
        11,
        100,
        30,
        vec![ProofKind::FinalityCertificate, ProofKind::ReceiptCommitment],
        vec![record.clone()],
    )
    .map_err(|_| RehearsalError::Step("RPC index"))?;
    let store = Arc::new(
        DurableRpcStore::create(directory.join("rpc.snapshot"), index)
            .map_err(|_| RehearsalError::Step("RPC persistence"))?,
    );
    let mut receipt_session = initialized_session(StoreBackend::new(store, now));
    let resolved = tool_call(
        &mut receipt_session,
        2,
        "activechain_resolve_receipt",
        json!({"key":hex(proposal_id.as_bytes())}),
    );
    if resolved.pointer("/result/isError").and_then(Value::as_bool) != Some(false)
        || resolved.to_string().contains("\"verified\":false")
    {
        return Err(RehearsalError::Step("MCP receipt resolution"));
    }

    let mut retry = initialized_session(Arc::clone(&backend));
    let retried = tool_call(&mut retry, 2, "activechain_propose_transfer", arguments.clone());
    if !retried.to_string().contains("\\\"duplicate\\\":true") {
        return Err(RehearsalError::Step("idempotent reconnect"));
    }
    let mut denied_args = arguments.clone();
    denied_args["transfer"]["amount"] = json!(9_999_u128);
    let denied = tool_call(&mut retry, 3, "activechain_propose_transfer", denied_args);
    let expired_transfer = transfer();
    let expired_authority =
        authority("mcp-request-expired", "nonce-expired", 10, &expired_transfer);
    let expired = tool_call(
        &mut retry,
        4,
        "activechain_propose_transfer",
        json!({
            "request_id":"mcp-request-expired","authority":expired_authority,"transfer":expired_transfer
        }),
    );
    if denied.pointer("/result/isError").and_then(Value::as_bool) != Some(true)
        || expired.pointer("/result/isError").and_then(Value::as_bool) != Some(true)
    {
        return Err(RehearsalError::Step("denial paths"));
    }
    let mut wrong = reviewed_commitment.into_bytes();
    wrong[0] ^= 1;
    let mismatch = authorize_proposal_intent(
        &intent,
        10,
        Digest384::new(wrong),
        public_key.as_slice().to_vec(),
        |payload| key.sign(payload).encode().to_vec(),
    );
    let stale = authorize_proposal_intent(
        &intent,
        50,
        reviewed_commitment,
        public_key.as_slice().to_vec(),
        |payload| key.sign(payload).encode().to_vec(),
    );
    if mismatch != Err(ACTIVECHAIN_WALLET_APPROVAL_MISMATCH)
        || stale != Err(ACTIVECHAIN_WALLET_AGENT_REJECTED)
    {
        return Err(RehearsalError::Step("wallet denial paths"));
    }
    let mut failed_intent = intent.clone();
    failed_intent.request_id = b"mcp-request-failed".to_vec();
    failed_intent.request_nonce = b"nonce-failed".to_vec();
    let failed_proposal_id = failed_intent.proposal_id().unwrap();
    lifecycle
        .admit(failed_intent, 10)
        .map_err(|_| RehearsalError::Step("failed lifecycle admit"))?;
    lifecycle
        .transition(failed_proposal_id, 1, WalletProposalStateV1::Approved, digest(98), 10)
        .map_err(|_| RehearsalError::Step("failed lifecycle approve"))?;
    lifecycle
        .transition(failed_proposal_id, 2, WalletProposalStateV1::Failed, digest(99), 10)
        .map_err(|_| RehearsalError::Step("failed lifecycle transition"))?;

    Ok(json!({
        "status":"passed", "developmental_unaudited":true, "validator_count":3,
        "mcp_request_id":"mcp-request-1", "proposal_id":hex(proposal_id.as_bytes()),
        "intent_commitment":hex(intent.commitment().unwrap().as_bytes()),
        "authorization_commitment":hex(authorization.as_bytes()),
        "transaction_id":hex(transaction.as_bytes()),
        "finalized_height":receipt.finalized_height(),
        "receipt_commitment":hex(receipt.commitment().unwrap().as_bytes()),
        "independently_verified":true,
        "states":["pending","denied","expired","submitted","finalized","failed"],
        "idempotent_reconnect":true,
        "secrets_persisted":false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_rehearsal_proves_happy_path_denials_retry_and_independent_receipt() {
        let path = std::env::temp_dir().join(format!("activechain-mcp-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let report = run_rehearsal(&path).unwrap();
        assert_eq!(report["status"], "passed");
        assert_eq!(report["validator_count"], 3);
        assert_eq!(report["independently_verified"], true);
        assert_eq!(report["idempotent_reconnect"], true);
        std::fs::remove_dir_all(path).unwrap();
    }
}
