#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
pub use activechain_application_primitives::telemetry::DeveloperEventV1;
use activechain_application_primitives::telemetry::{event_leaf_hash, event_node_hash};
use activechain_protocol_types::Digest384;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_384};

pub const PROFILE: &str = "actum.non-overlap.risc0.v1";
pub const MAX_WORK_EVENTS: usize = 256;
pub const MAX_EPOCH_DEPTH: usize = 12;
pub const JOURNAL_DOMAIN: &[u8] = b"ACTUM-NON-OVERLAP-RISC0-V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimClass {
    Attention,
    Compute,
    Contribution,
}
impl CanonicalEncode for ClaimClass {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for ClaimClass {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Attention),
            1 => Ok(Self::Compute),
            2 => Ok(Self::Contribution),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ClaimClass", tag }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkClaimPublicV1 {
    pub chain_id: Digest384,
    pub genesis: Digest384,
    pub telemetry_schema: u16,
    pub policy_id: Digest384,
    pub policy_revision: u32,
    pub authorization_revision: u32,
    pub usage_domain: Digest384,
    pub collector_id: Digest384,
    pub project_id: Digest384,
    pub claimant_key: Digest384,
    pub epoch_root: Digest384,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub event_count: u16,
    pub epoch_event_count: u32,
    pub claim_class: ClaimClass,
    pub claimed_units: u64,
    pub interval_start_ms: u64,
    pub interval_end_ms: u64,
    pub nullifier_root: Digest384,
    pub usage_nullifier_root: Digest384,
    pub usage_nullifiers: Vec<Digest384>,
}
impl CanonicalEncode for WorkClaimPublicV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.genesis.encode(e)?;
        self.telemetry_schema.encode(e)?;
        self.policy_id.encode(e)?;
        self.policy_revision.encode(e)?;
        self.authorization_revision.encode(e)?;
        self.usage_domain.encode(e)?;
        self.collector_id.encode(e)?;
        self.project_id.encode(e)?;
        self.claimant_key.encode(e)?;
        self.epoch_root.encode(e)?;
        self.first_sequence.encode(e)?;
        self.last_sequence.encode(e)?;
        self.event_count.encode(e)?;
        self.epoch_event_count.encode(e)?;
        self.claim_class.encode(e)?;
        self.claimed_units.encode(e)?;
        self.interval_start_ms.encode(e)?;
        self.interval_end_ms.encode(e)?;
        self.nullifier_root.encode(e)?;
        self.usage_nullifier_root.encode(e)?;
        self.usage_nullifiers.encode(e)
    }
}
impl CanonicalDecode for WorkClaimPublicV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            chain_id: Digest384::decode(d)?,
            genesis: Digest384::decode(d)?,
            telemetry_schema: u16::decode(d)?,
            policy_id: Digest384::decode(d)?,
            policy_revision: u32::decode(d)?,
            authorization_revision: u32::decode(d)?,
            usage_domain: Digest384::decode(d)?,
            collector_id: Digest384::decode(d)?,
            project_id: Digest384::decode(d)?,
            claimant_key: Digest384::decode(d)?,
            epoch_root: Digest384::decode(d)?,
            first_sequence: u64::decode(d)?,
            last_sequence: u64::decode(d)?,
            event_count: u16::decode(d)?,
            epoch_event_count: u32::decode(d)?,
            claim_class: ClaimClass::decode(d)?,
            claimed_units: u64::decode(d)?,
            interval_start_ms: u64::decode(d)?,
            interval_end_ms: u64::decode(d)?,
            nullifier_root: Digest384::decode(d)?,
            usage_nullifier_root: Digest384::decode(d)?,
            usage_nullifiers: Vec::<Digest384>::decode(d)?,
        })
    }
}
impl CanonicalType for WorkClaimPublicV1 {
    const TYPE_TAG: u16 = 0x01BB;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 11 + 2 + 4 * 3 + 8 * 5 + 2 + 1 + 5 + MAX_WORK_EVENTS * 48;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkEventWitnessV1 {
    pub event: DeveloperEventV1,
    pub merkle_index: u32,
    pub merkle_path: Vec<Digest384>,
}
impl CanonicalEncode for WorkEventWitnessV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.event.encode(e)?;
        self.merkle_index.encode(e)?;
        self.merkle_path.encode(e)
    }
}
impl CanonicalDecode for WorkEventWitnessV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            event: DeveloperEventV1::decode(d)?,
            merkle_index: u32::decode(d)?,
            merkle_path: Vec::<Digest384>::decode(d)?,
        };
        if value.merkle_path.len() > MAX_EPOCH_DEPTH {
            return Err(DecodeError::InvalidValue("work event Merkle path too deep"));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkClaimRelationInputV1 {
    pub public: WorkClaimPublicV1,
    pub claimant_secret: Digest384,
    pub events: Vec<WorkEventWitnessV1>,
}
impl CanonicalEncode for WorkClaimRelationInputV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.public.encode(e)?;
        self.claimant_secret.encode(e)?;
        self.events.encode(e)
    }
}
impl CanonicalDecode for WorkClaimRelationInputV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            public: WorkClaimPublicV1::decode(d)?,
            claimant_secret: Digest384::decode(d)?,
            events: Vec::<WorkEventWitnessV1>::decode(d)?,
        };
        if value.events.len() > MAX_WORK_EVENTS {
            return Err(DecodeError::InvalidValue("too many work events"));
        }
        Ok(value)
    }
}
impl CanonicalType for WorkClaimRelationInputV1 {
    const TYPE_TAG: u16 = 0x01BC;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = WorkClaimPublicV1::MAX_ENCODED_LEN
        + 48
        + 5
        + MAX_WORK_EVENTS * (DeveloperEventV1::MAX_ENCODED_LEN + 4 + 5 + MAX_EPOCH_DEPTH * 48);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkProofError {
    Malformed,
    Relation,
}
fn hash(domain: &[u8], fields: &[&[u8]]) -> Digest384 {
    let mut h = Sha3_384::new();
    h.update(domain);
    for field in fields {
        h.update(field);
    }
    Digest384::new(h.finalize().into())
}
fn epoch_leaf(event_id: Digest384) -> Digest384 {
    event_leaf_hash(event_id)
}
fn epoch_node(left: Digest384, right: Digest384) -> Digest384 {
    event_node_hash(left, right)
}
fn included_root(event_id: Digest384, index: u32, path: &[Digest384]) -> Digest384 {
    let mut current = epoch_leaf(event_id);
    let mut position = index;
    for sibling in path {
        current = if position & 1 == 0 {
            epoch_node(current, *sibling)
        } else {
            epoch_node(*sibling, current)
        };
        position >>= 1;
    }
    current
}
fn epoch_depth(mut count: u32) -> usize {
    let mut depth = 0;
    while count > 1 {
        count = count.div_ceil(2);
        depth += 1;
    }
    depth
}
fn class_nullifier(
    public: &WorkClaimPublicV1,
    secret: Digest384,
    event_id: Digest384,
) -> Digest384 {
    hash(
        b"ACTUM-WORK-CLASS-NULLIFIER-V1",
        &[
            public.chain_id.as_bytes(),
            public.project_id.as_bytes(),
            public.policy_id.as_bytes(),
            &[public.claim_class as u8],
            event_id.as_bytes(),
            secret.as_bytes(),
        ],
    )
}
fn usage_nullifier(
    public: &WorkClaimPublicV1,
    secret: Digest384,
    event_id: Digest384,
) -> Digest384 {
    hash(
        b"ACTUM-WORK-USAGE-NULLIFIER-V1",
        &[
            public.chain_id.as_bytes(),
            public.project_id.as_bytes(),
            public.usage_domain.as_bytes(),
            event_id.as_bytes(),
            secret.as_bytes(),
        ],
    )
}
fn root(mut nodes: Vec<Digest384>, domain: &[u8]) -> Digest384 {
    while nodes.len() > 1 {
        if nodes.len() % 2 == 1 {
            nodes.push(*nodes.last().expect("non-empty"));
        }
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| hash(domain, &[pair[0].as_bytes(), pair[1].as_bytes()]))
            .collect();
    }
    nodes[0]
}
pub fn verify_relation(input: &WorkClaimRelationInputV1) -> Result<(), WorkProofError> {
    let p = &input.public;
    if input.events.is_empty()
        || input.events.len() > MAX_WORK_EVENTS
        || p.chain_id == Digest384::ZERO
        || p.genesis == Digest384::ZERO
        || p.policy_id == Digest384::ZERO
        || p.usage_domain == Digest384::ZERO
        || p.collector_id == Digest384::ZERO
        || p.project_id == Digest384::ZERO
        || p.telemetry_schema != 1
        || p.policy_revision == 0
        || p.authorization_revision == 0
        || p.event_count as usize != input.events.len()
        || p.usage_nullifiers.len() != input.events.len()
        || p.epoch_event_count == 0
        || p.first_sequence == 0
        || p.last_sequence.checked_sub(p.first_sequence).and_then(|v| v.checked_add(1))
            != Some(input.events.len() as u64)
        || p.interval_start_ms > p.interval_end_ms
        || hash(b"ACTUM-WORK-CLAIMANT-V1", &[input.claimant_secret.as_bytes()]) != p.claimant_key
    {
        return Err(WorkProofError::Malformed);
    }
    let mut total = 0_u64;
    let mut prior_end = None;
    let mut class_nullifiers = Vec::with_capacity(input.events.len());
    let mut usage_nullifiers = Vec::with_capacity(input.events.len());
    for (index, event) in input.events.iter().enumerate() {
        let value = &event.event;
        let event_id = value.event_id().map_err(|_| WorkProofError::Malformed)?;
        if value.collector_id != p.collector_id
            || value.project_id != p.project_id
            || value.authorization_revision != p.authorization_revision
            || value.project_sequence != p.first_sequence + index as u64
            || value.wall_start_ms < p.interval_start_ms
            || value.wall_end_ms > p.interval_end_ms
            || prior_end.is_some_and(|end| value.wall_start_ms < end)
            || event.merkle_index >= p.epoch_event_count
            || event.merkle_path.len() != epoch_depth(p.epoch_event_count)
            || included_root(event_id, event.merkle_index, &event.merkle_path) != p.epoch_root
        {
            return Err(WorkProofError::Relation);
        }
        total = total.checked_add(value.units).ok_or(WorkProofError::Relation)?;
        prior_end = Some(value.wall_end_ms);
        class_nullifiers.push(class_nullifier(p, input.claimant_secret, event_id));
        usage_nullifiers.push(usage_nullifier(p, input.claimant_secret, event_id));
    }
    if total != p.claimed_units
        || root(class_nullifiers, b"ACTUM-WORK-CLASS-NULLIFIER-NODE-V1") != p.nullifier_root
        || usage_nullifiers != p.usage_nullifiers
        || root(usage_nullifiers, b"ACTUM-WORK-USAGE-NULLIFIER-NODE-V1") != p.usage_nullifier_root
    {
        return Err(WorkProofError::Relation);
    }
    Ok(())
}
pub fn public_journal(public: &WorkClaimPublicV1) -> Result<Vec<u8>, EncodeError> {
    let encoded = activechain_canonical_codec::encode_envelope(public)?;
    let mut journal = JOURNAL_DOMAIN.to_vec();
    journal.extend_from_slice(&encoded);
    Ok(journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_application_primitives::telemetry::DeveloperEventKindV1;

    fn d(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn event(sequence: u64, start: u64, end: u64, units: u64) -> DeveloperEventV1 {
        DeveloperEventV1 {
            collector_id: d(2),
            project_id: d(4),
            collector_sequence: sequence,
            project_sequence: sequence,
            wall_start_ms: start,
            wall_end_ms: end,
            monotonic_start_ns: start * 1_000_000,
            monotonic_end_ns: end * 1_000_000,
            kind: DeveloperEventKindV1::HumanInteraction,
            source_commitment: d(20),
            subject_commitment: d(21),
            payload_commitment: d(22),
            units,
            authorization_revision: 7,
        }
    }
    fn bind_nullifiers(input: &mut WorkClaimRelationInputV1) {
        let class = input
            .events
            .iter()
            .map(|witness| {
                class_nullifier(
                    &input.public,
                    input.claimant_secret,
                    witness.event.event_id().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let usage = input
            .events
            .iter()
            .map(|witness| {
                usage_nullifier(
                    &input.public,
                    input.claimant_secret,
                    witness.event.event_id().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        input.public.nullifier_root = root(class, b"ACTUM-WORK-CLASS-NULLIFIER-NODE-V1");
        input.public.usage_nullifier_root =
            root(usage.clone(), b"ACTUM-WORK-USAGE-NULLIFIER-NODE-V1");
        input.public.usage_nullifiers = usage;
    }
    fn valid() -> WorkClaimRelationInputV1 {
        let first = event(10, 100, 120, 20);
        let second = event(11, 120, 150, 30);
        let first_leaf = epoch_leaf(first.event_id().unwrap());
        let second_leaf = epoch_leaf(second.event_id().unwrap());
        let secret = d(9);
        let public = WorkClaimPublicV1 {
            chain_id: d(1),
            genesis: d(3),
            telemetry_schema: 1,
            policy_id: d(5),
            policy_revision: 7,
            authorization_revision: 7,
            usage_domain: d(6),
            collector_id: d(2),
            project_id: d(4),
            claimant_key: hash(b"ACTUM-WORK-CLAIMANT-V1", &[secret.as_bytes()]),
            epoch_root: epoch_node(first_leaf, second_leaf),
            first_sequence: 10,
            last_sequence: 11,
            event_count: 2,
            epoch_event_count: 2,
            claim_class: ClaimClass::Attention,
            claimed_units: 50,
            interval_start_ms: 100,
            interval_end_ms: 150,
            nullifier_root: d(7),
            usage_nullifier_root: d(8),
            usage_nullifiers: Vec::new(),
        };
        let mut input = WorkClaimRelationInputV1 {
            public,
            claimant_secret: secret,
            events: alloc::vec![
                WorkEventWitnessV1 {
                    event: first,
                    merkle_index: 0,
                    merkle_path: alloc::vec![second_leaf]
                },
                WorkEventWitnessV1 {
                    event: second,
                    merkle_index: 1,
                    merkle_path: alloc::vec![first_leaf]
                },
            ],
        };
        bind_nullifiers(&mut input);
        input
    }

    #[test]
    fn canonical_events_are_bound_to_the_exact_epoch_root() {
        let input = valid();
        verify_relation(&input).unwrap();
        assert!(public_journal(&input.public).unwrap().starts_with(JOURNAL_DOMAIN));
        let encoded = activechain_canonical_codec::encode_envelope(&input.events[0].event).unwrap();
        assert_eq!(
            activechain_canonical_codec::decode_envelope::<DeveloperEventV1>(&encoded),
            Ok(input.events[0].event)
        );
    }
    #[test]
    fn substituted_event_or_merkle_path_is_rejected() {
        let mut event_mutation = valid();
        event_mutation.events[0].event.payload_commitment = d(99);
        assert_eq!(verify_relation(&event_mutation), Err(WorkProofError::Relation));
        let mut path_mutation = valid();
        path_mutation.events[0].merkle_path[0] = d(98);
        assert_eq!(verify_relation(&path_mutation), Err(WorkProofError::Relation));
    }
    #[test]
    fn overlap_partial_range_and_false_total_are_rejected() {
        let mut overlap = valid();
        overlap.events[1].event.wall_start_ms = 119;
        assert_eq!(verify_relation(&overlap), Err(WorkProofError::Relation));
        let mut partial = valid();
        partial.events[0].event.wall_end_ms = 119;
        assert_eq!(verify_relation(&partial), Err(WorkProofError::Relation));
        let mut total = valid();
        total.public.claimed_units += 1;
        assert_eq!(verify_relation(&total), Err(WorkProofError::Relation));
    }
    #[test]
    fn usage_domains_allow_attribution_without_reusing_a_billing_entitlement() {
        let attention = valid();
        let mut contribution = valid();
        contribution.public.claim_class = ClaimClass::Contribution;
        contribution.public.usage_domain = d(40);
        bind_nullifiers(&mut contribution);
        verify_relation(&attention).unwrap();
        verify_relation(&contribution).unwrap();
        assert_ne!(attention.public.usage_nullifiers, contribution.public.usage_nullifiers);
    }
    #[test]
    fn public_usage_nullifier_or_domain_substitution_fails() {
        let mut nullifier = valid();
        nullifier.public.usage_nullifiers[0] = d(50);
        assert_eq!(verify_relation(&nullifier), Err(WorkProofError::Relation));
        let mut domain = valid();
        domain.public.usage_domain = d(51);
        assert_eq!(verify_relation(&domain), Err(WorkProofError::Relation));
    }
    #[test]
    fn checked_unit_overflow_fails() {
        let mut input = valid();
        input.events[0].event.units = u64::MAX;
        input.events[1].event.units = 1;
        assert_eq!(verify_relation(&input), Err(WorkProofError::Relation));
    }
}
