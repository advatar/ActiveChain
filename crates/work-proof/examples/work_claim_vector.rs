use activechain_application_primitives::{
    DeveloperEventMeasurementV1, DeveloperEventV1, event_leaf_hash, event_node_hash,
};
use activechain_canonical_codec::encode_envelope;
use activechain_protocol_types::Digest384;
use activechain_work_proof::{
    MeteringPolicyV1, WorkClaimAggregateV1, WorkClaimPublicV1, WorkClaimRelationInputV1,
    WorkEventWitnessV1, derive_nullifier_bindings, public_journal, verify_relation,
};
use sha3::{Digest, Sha3_384};

fn d(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
fn claimant_key(secret: Digest384) -> Digest384 {
    let mut hash = Sha3_384::new();
    hash.update(b"ACTUM-WORK-CLAIMANT-V1");
    hash.update(secret.as_bytes());
    Digest384::new(hash.finalize().into())
}
fn event(sequence: u64, start_ms: u64, end_ms: u64) -> DeveloperEventV1 {
    DeveloperEventV1 {
        collector_id: d(2),
        project_id: d(4),
        collector_sequence: sequence,
        project_sequence: sequence,
        wall_start_ms: 100,
        wall_end_ms: 200,
        monotonic_start_ns: start_ms * 1_000_000,
        monotonic_end_ns: end_ms * 1_000_000,
        measurement: DeveloperEventMeasurementV1::HumanInteraction { interaction_count: 1 },
        source_commitment: d(20),
        subject_commitment: d(sequence as u8),
        payload_commitment: d(sequence as u8 + 20),
        authorization_revision: 7,
    }
}
fn main() {
    let policy = MeteringPolicyV1 {
        revision: 7,
        accepted_measurement_kinds: 0x1f,
        idle_timeout_ms: 100,
        max_human_event_ms: 80,
        max_attention_claim_ms: 1_000,
        model_input_weight: 500_000,
        model_output_weight: 2_000_000,
    };
    let first = event(10, 0, 70);
    let second = event(11, 50, 100);
    let first_id = first.event_id().unwrap();
    let second_id = second.event_id().unwrap();
    let first_leaf = event_leaf_hash(first_id);
    let second_leaf = event_leaf_hash(second_id);
    let events = vec![
        WorkEventWitnessV1 { event: first, merkle_index: 0, merkle_path: vec![second_leaf] },
        WorkEventWitnessV1 { event: second, merkle_index: 1, merkle_path: vec![first_leaf] },
    ];
    let secret = d(9);
    let mut public = WorkClaimPublicV1 {
        chain_id: d(1),
        genesis: d(3),
        telemetry_schema: 1,
        policy_id: policy.policy_id().unwrap(),
        policy_revision: policy.revision,
        authorization_revision: 7,
        usage_domain: d(6),
        collector_id: d(2),
        project_id: d(4),
        claimant_key: claimant_key(secret),
        epoch_root: event_node_hash(first_leaf, second_leaf),
        first_sequence: 10,
        last_sequence: 11,
        event_count: 2,
        epoch_event_count: 2,
        interval_start_ms: 100,
        interval_end_ms: 200,
        aggregate: WorkClaimAggregateV1::Attention { attributable_ms: 100, interaction_count: 2 },
        nullifier_root: Digest384::ZERO,
        usage_nullifier_root: Digest384::ZERO,
        usage_nullifiers: vec![],
    };
    let (class_root, usage_root, usage) =
        derive_nullifier_bindings(&public, secret, &events).unwrap();
    public.nullifier_root = class_root;
    public.usage_nullifier_root = usage_root;
    public.usage_nullifiers = usage;
    let input = WorkClaimRelationInputV1 { public, policy, claimant_secret: secret, events };
    verify_relation(&input).unwrap();
    println!("profile=actum.non-overlap.risc0.v1");
    println!("policy_id={}", hex(input.public.policy_id.as_bytes()));
    println!("policy_envelope={}", hex(&encode_envelope(&input.policy).unwrap()));
    println!("relation_envelope={}", hex(&encode_envelope(&input).unwrap()));
    println!("public_journal={}", hex(&public_journal(&input.public).unwrap()));
    println!("class_nullifier_root={}", hex(input.public.nullifier_root.as_bytes()));
    println!("usage_nullifier_root={}", hex(input.public.usage_nullifier_root.as_bytes()));
    for (index, nullifier) in input.public.usage_nullifiers.iter().enumerate() {
        println!("usage_nullifier_{index}={}", hex(nullifier.as_bytes()));
    }
}
