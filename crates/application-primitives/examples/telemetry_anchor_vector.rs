use activechain_application_primitives::{
    ActivityEpochV1, ActumVerifierTrustBundleV1, AnchorFinalizedEvidenceV1, AnchorRegistry,
    AnchorRegistryKeyV1, AnchorStateRecordV1, CheckpointedTelemetryAnchorEvidenceV1,
    TelemetryEpochAnchorRequestV1, TrustSignatureAlgorithmV1, TrustSignerSetV1, TrustSignerV1,
    anchor_state_object,
};
use activechain_canonical_codec::{CanonicalType, encode_envelope};
use activechain_protocol_types::{ChainId, Digest384, TransactionId};
use activechain_state_tree::{StateProof, commit_objects, prove_object};

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let epoch = ActivityEpochV1 {
        collector_id: digest(1),
        project_id: digest(2),
        first_collector_sequence: 10,
        last_collector_sequence: 11,
        first_project_sequence: 20,
        last_project_sequence: 21,
        event_count: 2,
        wall_start_ms: 1_700_000_000_000,
        wall_end_ms: 1_700_000_001_000,
        monotonic_start_ns: 5_000_000,
        monotonic_end_ns: 6_000_000,
        event_root: digest(3),
        previous_epoch_id: digest(4),
        authorization_revision: 7,
        policy_id: digest(5),
    };
    let request = TelemetryEpochAnchorRequestV1::new(
        digest(6),
        digest(7),
        1,
        digest(8),
        b"pow-anchor-vector-1".to_vec(),
        epoch,
    )
    .unwrap();
    let statement = request.statement().unwrap();
    let reference = statement.submission_reference().unwrap();
    let transaction = TransactionId::new(digest(16));
    let anchor_block = digest(17);
    let state_record =
        AnchorStateRecordV1::new(statement.clone(), transaction, 41, anchor_block).unwrap();
    let registry_key = state_record.registry_key().unwrap();
    let state_object = anchor_state_object(&state_record).unwrap();
    let state_objects = vec![state_object.clone()];
    let checkpoint_state = commit_objects(&state_objects).unwrap();
    let state_proof = prove_object(&state_objects, state_object.object_id()).unwrap();
    let mut registry = AnchorRegistry::default();
    registry.submit_action(statement.clone(), transaction).unwrap();
    registry
        .finalize(
            reference,
            AnchorFinalizedEvidenceV1::new(
                ChainId::new(request.chain_id),
                request.genesis_commitment,
                transaction,
                vec![0x11],
                41,
                anchor_block,
                statement.clone(),
                None,
                None,
                1,
                1,
                vec![0x12],
                vec![0x13],
            )
            .unwrap(),
        )
        .unwrap();
    let signer_set = TrustSignerSetV1 {
        revision: 1,
        signers: vec![TrustSignerV1 {
            signer_id: digest(9),
            algorithm: TrustSignatureAlgorithmV1::MlDsa44,
            public_key: vec![0xaa; 1_312],
            valid_from_sequence: 1,
            valid_until_sequence: 100,
        }],
        threshold: 1,
    };
    let signer_set_id = signer_set.signer_set_id().unwrap();
    let bundle = ActumVerifierTrustBundleV1 {
        schema_revision: 1,
        bundle_sequence: 1,
        previous_bundle_id: Digest384::ZERO,
        chain_id: request.chain_id,
        genesis_commitment: request.genesis_commitment,
        protocol_revision: 1,
        checkpoint_height: 42,
        checkpoint_block_id: digest(10),
        checkpoint_state_root: checkpoint_state.root(),
        checkpoint_finality_commitment: digest(12),
        validator_set_root: digest(13),
        proof_profile_id: digest(14),
        proof_system_revision: 1,
        verifier_revision: 1,
        risc0_image_id: [0x0f; 32],
        policy_id: request.epoch.policy_id,
        policy_revision: request.epoch.authorization_revision,
        issued_at_ms: 1_700_000_000_000,
        not_before_ms: 1_700_000_000_000,
        not_after_ms: 1_700_086_400_000,
        signer_set_id,
        signer_set_revision: signer_set.revision,
        signer_threshold: signer_set.threshold,
        next_signer_set_id: Digest384::ZERO,
        next_signer_set_revision: 0,
        next_signer_threshold: 0,
        next_signer_activation_sequence: 0,
    };
    let checkpoint_evidence = CheckpointedTelemetryAnchorEvidenceV1::new(
        request.clone(),
        reference,
        registry.resolve(reference).unwrap().clone(),
        bundle.bundle_id().unwrap(),
        bundle.checkpoint_height,
        bundle.checkpoint_block_id,
        bundle.checkpoint_state_root,
        checkpoint_state.object_count(),
        state_proof.clone(),
    )
    .unwrap();
    let request_envelope = encode_envelope(&request).unwrap();
    let statement_envelope = encode_envelope(&statement).unwrap();
    let registry_key_envelope = encode_envelope(&registry_key).unwrap();
    let state_record_envelope = encode_envelope(&state_record).unwrap();
    let state_object_envelope = encode_envelope(&state_object).unwrap();
    let state_proof_envelope = encode_envelope(&state_proof).unwrap();
    let checkpoint_evidence_envelope = encode_envelope(&checkpoint_evidence).unwrap();
    let signer_set_envelope = encode_envelope(&signer_set).unwrap();
    let bundle_envelope = encode_envelope(&bundle).unwrap();
    println!("profile=actum.telemetry-anchor.v1");
    println!("request_type_tag=0x{:04x}", TelemetryEpochAnchorRequestV1::TYPE_TAG);
    println!("request_canonical_bytes_hex={}", hex(&request_envelope));
    println!("statement_canonical_bytes_hex={}", hex(&statement_envelope));
    println!("anchor_reference={}", hex(reference.as_bytes()));
    println!("registry_key_type_tag=0x{:04x}", AnchorRegistryKeyV1::TYPE_TAG);
    println!("registry_key_canonical_bytes_hex={}", hex(&registry_key_envelope));
    println!("anchor_state_record_type_tag=0x{:04x}", AnchorStateRecordV1::TYPE_TAG);
    println!("anchor_state_record_canonical_bytes_hex={}", hex(&state_record_envelope));
    println!("anchor_state_object_id={}", hex(state_object.object_id().into_digest().as_bytes()));
    println!("anchor_state_object_canonical_bytes_hex={}", hex(&state_object_envelope));
    println!("checkpoint_state_root={}", hex(checkpoint_state.root().as_bytes()));
    println!("checkpoint_object_count={}", checkpoint_state.object_count());
    println!("state_proof_type_tag=0x{:04x}", StateProof::TYPE_TAG);
    println!("state_proof_canonical_bytes_hex={}", hex(&state_proof_envelope));
    println!("signer_set_type_tag=0x{:04x}", TrustSignerSetV1::TYPE_TAG);
    println!("signer_set_canonical_bytes_hex={}", hex(&signer_set_envelope));
    println!("signer_set_id={}", hex(signer_set_id.as_bytes()));
    println!("trust_bundle_type_tag=0x{:04x}", ActumVerifierTrustBundleV1::TYPE_TAG);
    println!("trust_bundle_canonical_bytes_hex={}", hex(&bundle_envelope));
    println!("trust_bundle_id={}", hex(bundle.bundle_id().unwrap().as_bytes()));
    println!(
        "checkpoint_evidence_type_tag=0x{:04x}",
        CheckpointedTelemetryAnchorEvidenceV1::TYPE_TAG
    );
    println!(
        "checkpoint_evidence_schema_revision={}",
        CheckpointedTelemetryAnchorEvidenceV1::SCHEMA_VERSION
    );
    println!("checkpoint_evidence_canonical_bytes_hex={}", hex(&checkpoint_evidence_envelope));
}
