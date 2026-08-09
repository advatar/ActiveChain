use activechain_application_primitives::{
    ActivityEpochV1, ActumVerifierTrustBundleV1, TelemetryEpochAnchorRequestV1,
    TrustSignatureAlgorithmV1, TrustSignerSetV1, TrustSignerV1,
};
use activechain_canonical_codec::{CanonicalType, encode_envelope};
use activechain_protocol_types::Digest384;

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
        checkpoint_state_root: digest(11),
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
    let request_envelope = encode_envelope(&request).unwrap();
    let statement_envelope = encode_envelope(&statement).unwrap();
    let signer_set_envelope = encode_envelope(&signer_set).unwrap();
    let bundle_envelope = encode_envelope(&bundle).unwrap();
    println!("profile=actum.telemetry-anchor.v1");
    println!("request_type_tag=0x{:04x}", TelemetryEpochAnchorRequestV1::TYPE_TAG);
    println!("request_canonical_bytes_hex={}", hex(&request_envelope));
    println!("statement_canonical_bytes_hex={}", hex(&statement_envelope));
    println!("anchor_reference={}", hex(statement.submission_reference().unwrap().as_bytes()));
    println!("signer_set_type_tag=0x{:04x}", TrustSignerSetV1::TYPE_TAG);
    println!("signer_set_canonical_bytes_hex={}", hex(&signer_set_envelope));
    println!("signer_set_id={}", hex(signer_set_id.as_bytes()));
    println!("trust_bundle_type_tag=0x{:04x}", ActumVerifierTrustBundleV1::TYPE_TAG);
    println!("trust_bundle_canonical_bytes_hex={}", hex(&bundle_envelope));
    println!("trust_bundle_id={}", hex(bundle.bundle_id().unwrap().as_bytes()));
}
