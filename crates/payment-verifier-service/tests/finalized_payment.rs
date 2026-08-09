use activechain_action_kernel::ResourceVector;
use activechain_canonical_codec::encode_envelope;
use activechain_devnet_kernel::{ActionOutcome, ActionReceipt, BlockReceipt};
use activechain_finality_types::{
    FinalityCertificateBundle, FinalizedBlockHeader, ProofPublicInputs,
};
use activechain_payment_types::{
    AssetAmountV1, PaymentFinalizedSettlementV1, PaymentIntentId, PaymentIntentV1, TreasuryId,
    payment_finality_proof_commitment,
};
use activechain_payment_verifier_service::{
    PROTOCOL_V1, VerificationError, VerificationPolicy, VerifyRequestV1, token_policy_commitment,
    verify_finalized_payment,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    AssetId, ChainId, ConsensusVoteContext, CryptoSuiteId, Digest384, PrincipalId,
    ProtocolSignature, QuorumCertificate, TransactionId, ValidatorGenesis, ValidatorGenesisEntry,
    ValidatorVote,
};
use activechain_state_tree::StateCommitment;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
use serde_json::json;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn finality_bundle_with_inputs(
    receipt_root: Digest384,
    pre_state: StateCommitment,
    post_state: StateCommitment,
    cash_cell_root: Digest384,
) -> FinalityCertificateBundle {
    let keys = [
        SigningKey::<MlDsa44>::from_seed(&Seed::from([1; 32])),
        SigningKey::<MlDsa44>::from_seed(&Seed::from([2; 32])),
    ];
    let entries = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            ValidatorGenesisEntry::new(
                PrincipalId::new(digest((index + 1) as u8)),
                1,
                key.verifying_key().encode().into(),
            )
            .unwrap()
        })
        .collect();
    let genesis = ValidatorGenesis::new_with_revision(3, 1, 4, entries).unwrap();
    let inputs = ProofPublicInputs {
        chain_id: ChainId::new(digest(40)),
        epoch: 3,
        height: 9,
        protocol_revision: 4,
        validator_set_root: genesis.validator_set_root(),
        parent_block_id: digest(41),
        pre_state,
        authorization_root: digest(43),
        action_root: digest(44),
        execution_order_root: digest(45),
        total_fees: 0,
        pre_supply: 0,
        issuance: 0,
        burn: 0,
        post_supply: 0,
        pre_cash_cell_root: cash_cell_root,
        cash_action_root: digest(50),
        cash_cell_root,
        post_state,
        receipt_root,
        data_availability_commitment: digest(48),
    };
    let header = FinalizedBlockHeader { inputs, proof_statement_commitment: digest(49) };
    let block_digest = header.digest().unwrap();
    let context = ConsensusVoteContext::new_with_revision(
        genesis.genesis_commitment(),
        genesis.epoch(),
        genesis.validator_set_root(),
        genesis.protocol_revision(),
    )
    .unwrap();
    let mut votes = Vec::new();
    let mut vote_set_hasher = Shake256::default();
    vote_set_hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
    for (index, key) in keys.iter().enumerate() {
        let validator = PrincipalId::new(digest((index + 1) as u8));
        let unsigned = ValidatorVote::new(
            validator,
            context,
            9,
            2,
            block_digest,
            digest(49),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        let signature = key.sign(&unsigned.signing_payload());
        let vote = ValidatorVote::new(
            validator,
            context,
            9,
            2,
            block_digest,
            digest(49),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap();
        vote_set_hasher.update(key.verifying_key().encode().as_slice());
        vote_set_hasher.update(&vote.signing_payload());
        vote_set_hasher.update(vote.signature().as_bytes());
        votes.push(vote);
    }
    let mut vote_set_root = [0; 48];
    vote_set_hasher.finalize_xof().read(&mut vote_set_root);
    let certificate = QuorumCertificate::new(
        context,
        9,
        2,
        block_digest,
        digest(49),
        Digest384::new(vote_set_root),
        2,
        2,
    )
    .unwrap();
    FinalityCertificateBundle::new(header, genesis, certificate, votes).unwrap()
}

fn fixture() -> (VerifyRequestV1, VerificationPolicy) {
    let audience = "actum:merchant:zerok-production";
    let request_commitment = digest(90);
    let merchant = PrincipalId::new(digest(80));
    let intent_id = PaymentIntentId::new(digest(71)).unwrap();
    let transaction = TransactionId::new(digest(70));
    let asset = AssetId::new(digest(72));
    let intent = PaymentIntentV1::new(
        ChainId::new(digest(40)),
        intent_id,
        merchant,
        TreasuryId::new(digest(81)).unwrap(),
        digest(82),
        digest(83),
        AssetAmountV1::new(asset, 100).unwrap(),
        AssetAmountV1::new(asset, 90).unwrap(),
        100,
        digest(84),
        request_commitment,
        digest(85),
        digest(86),
        token_policy_commitment(audience, "c2048"),
    )
    .unwrap();
    let pre_state = StateCommitment::new(digest(60), 2);
    let post_state = StateCommitment::new(digest(61), 3);
    let receipt = BlockReceipt::new(
        digest(62),
        9,
        pre_state,
        post_state,
        digest(64),
        digest(65),
        vec![ActionReceipt::new(
            transaction,
            ActionOutcome::ResourceLimitExceeded,
            ResourceVector::new(1, 0, 0, 0, 0, 1),
            0,
            1,
            post_state,
        )],
    )
    .unwrap();
    let receipt_commitment = commit(DomainTag::CANONICAL_VALUE, &receipt).unwrap();
    let bundle = finality_bundle_with_inputs(receipt_commitment, pre_state, post_state, digest(50));
    let trusted_genesis = bundle.validator_genesis().genesis_commitment();
    let finality = encode_envelope(&bundle).unwrap();
    let settlement = PaymentFinalizedSettlementV1::new(
        intent_id,
        transaction,
        AssetAmountV1::new(asset, 95).unwrap(),
        9,
        receipt.block_id(),
        receipt_commitment,
        payment_finality_proof_commitment(&finality),
    )
    .unwrap();
    let evidence = serde_json::to_vec(&json!({
        "payment_intent_b64": BASE64.encode(encode_envelope(&intent).unwrap()),
        "finalized_settlement_b64": BASE64.encode(encode_envelope(&settlement).unwrap()),
        "finality_bundle_b64": BASE64.encode(finality),
        "block_receipt_b64": BASE64.encode(encode_envelope(&receipt).unwrap()),
    }))
    .unwrap();
    (
        VerifyRequestV1 {
            protocol: PROTOCOL_V1.to_owned(),
            audience: audience.to_owned(),
            request_commitment_b64: BASE64.encode(request_commitment.as_bytes()),
            replay_identifier_b64: BASE64.encode(transaction.digest().as_bytes()),
            token_class: "c2048".to_owned(),
            payment_evidence_b64: BASE64.encode(evidence),
        },
        VerificationPolicy {
            audience: audience.to_owned(),
            chain: ChainId::new(digest(40)),
            genesis: trusted_genesis,
            merchant,
        },
    )
}

#[test]
fn verifies_canonical_intent_settlement_and_finality_composition() {
    let (request, policy) = fixture();
    let response = verify_finalized_payment(&request, &policy, 50).unwrap();
    assert!(response.authorized);
    assert!(response.finalized);
    assert_eq!(response.authorization_id_b64, BASE64.encode(digest(71).as_bytes()));
}

#[test]
fn rejects_token_class_and_replay_substitution() {
    let (mut request, policy) = fixture();
    request.token_class = "c4096".to_owned();
    assert_eq!(
        verify_finalized_payment(&request, &policy, 50),
        Err(VerificationError::TokenPolicyMismatch)
    );
    let (mut request, policy) = fixture();
    request.replay_identifier_b64 = BASE64.encode([99_u8; 48]);
    assert_eq!(
        verify_finalized_payment(&request, &policy, 50),
        Err(VerificationError::ReplayBindingMismatch)
    );
}

#[test]
fn rejects_expired_intent_and_wrong_trusted_genesis() {
    let (request, policy) = fixture();
    assert_eq!(
        verify_finalized_payment(&request, &policy, 100),
        Err(VerificationError::IntentExpired)
    );
    let (request, mut policy) = fixture();
    policy.genesis = digest(99);
    assert_eq!(
        verify_finalized_payment(&request, &policy, 50),
        Err(VerificationError::FinalityInvalid)
    );
}
