#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::Digest384;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_384};

pub const PROFILE: &str = "actum.non-overlap.risc0.v1";
pub const MAX_WORK_EVENTS: usize = 256;
pub const JOURNAL_DOMAIN: &[u8] = b"ACTUM-NON-OVERLAP-RISC0-V1";

#[derive(Clone, Debug, Eq, PartialEq)]
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
    pub project_id: Digest384,
    pub claimant_key: Digest384,
    pub epoch_root: Digest384,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub event_count: u16,
    pub claim_class: ClaimClass,
    pub claimed_units: u64,
    pub interval_start_ms: u64,
    pub interval_end_ms: u64,
    pub nullifier_root: Digest384,
    pub nullifiers: Vec<Digest384>,
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
        self.project_id.encode(e)?;
        self.claimant_key.encode(e)?;
        self.epoch_root.encode(e)?;
        self.first_sequence.encode(e)?;
        self.last_sequence.encode(e)?;
        self.event_count.encode(e)?;
        self.claim_class.encode(e)?;
        self.claimed_units.encode(e)?;
        self.interval_start_ms.encode(e)?;
        self.interval_end_ms.encode(e)?;
        self.nullifier_root.encode(e)?;
        self.nullifiers.encode(e)?;
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
            project_id: Digest384::decode(d)?,
            claimant_key: Digest384::decode(d)?,
            epoch_root: Digest384::decode(d)?,
            first_sequence: u64::decode(d)?,
            last_sequence: u64::decode(d)?,
            event_count: u16::decode(d)?,
            claim_class: ClaimClass::decode(d)?,
            claimed_units: u64::decode(d)?,
            interval_start_ms: u64::decode(d)?,
            interval_end_ms: u64::decode(d)?,
            nullifier_root: Digest384::decode(d)?,
            nullifiers: Vec::<Digest384>::decode(d)?,
            usage_nullifier_root: Digest384::decode(d)?,
            usage_nullifiers: Vec::<Digest384>::decode(d)?,
        })
    }
}
impl CanonicalType for WorkClaimPublicV1 {
    const TYPE_TAG: u16 = 0x01BB;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 9 + 2 + 4 + 8 * 5 + 2 + 1 + 10 + MAX_WORK_EVENTS * 48 * 2;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkEventWitnessV1 {
    pub sequence: u64,
    pub start_ms: u64,
    pub end_ms: u64,
    pub units: u64,
    pub nonce: Digest384,
}
impl CanonicalEncode for WorkEventWitnessV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.sequence.encode(e)?;
        self.start_ms.encode(e)?;
        self.end_ms.encode(e)?;
        self.units.encode(e)?;
        self.nonce.encode(e)
    }
}
impl CanonicalDecode for WorkEventWitnessV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            sequence: u64::decode(d)?,
            start_ms: u64::decode(d)?,
            end_ms: u64::decode(d)?,
            units: u64::decode(d)?,
            nonce: Digest384::decode(d)?,
        })
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
    const MAX_ENCODED_LEN: usize =
        WorkClaimPublicV1::MAX_ENCODED_LEN + 48 + 5 + MAX_WORK_EVENTS * 80;
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
fn event_leaf(public: &WorkClaimPublicV1, event: &WorkEventWitnessV1) -> Digest384 {
    hash(
        b"ACTUM-WORK-EVENT-V1",
        &[
            public.chain_id.as_bytes(),
            public.project_id.as_bytes(),
            public.policy_id.as_bytes(),
            &[public.claim_class as u8],
            &event.sequence.to_be_bytes(),
            &event.start_ms.to_be_bytes(),
            &event.end_ms.to_be_bytes(),
            &event.units.to_be_bytes(),
            event.nonce.as_bytes(),
        ],
    )
}
fn nullifier(public: &WorkClaimPublicV1, secret: Digest384, leaf: Digest384) -> Digest384 {
    hash(
        b"ACTUM-WORK-NULLIFIER-V1",
        &[
            public.chain_id.as_bytes(),
            public.project_id.as_bytes(),
            public.policy_id.as_bytes(),
            &[public.claim_class as u8],
            leaf.as_bytes(),
            secret.as_bytes(),
        ],
    )
}
fn usage_nullifier(public: &WorkClaimPublicV1, secret: Digest384, leaf: Digest384) -> Digest384 {
    hash(
        b"ACTUM-WORK-USAGE-NULLIFIER-V1",
        &[
            public.chain_id.as_bytes(),
            public.project_id.as_bytes(),
            public.policy_id.as_bytes(),
            leaf.as_bytes(),
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
        || p.project_id == Digest384::ZERO
        || p.telemetry_schema != 1
        || p.policy_revision == 0
        || p.event_count as usize != input.events.len()
        || p.nullifiers.len() != input.events.len()
        || p.usage_nullifiers.len() != input.events.len()
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
    let mut leaves = Vec::with_capacity(input.events.len());
    let mut nullifiers = Vec::with_capacity(input.events.len());
    let mut usage_nullifiers = Vec::with_capacity(input.events.len());
    for (index, event) in input.events.iter().enumerate() {
        if event.sequence != p.first_sequence + index as u64
            || event.start_ms > event.end_ms
            || event.start_ms < p.interval_start_ms
            || event.end_ms > p.interval_end_ms
            || prior_end.is_some_and(|end| event.start_ms < end)
        {
            return Err(WorkProofError::Relation);
        }
        total = total.checked_add(event.units).ok_or(WorkProofError::Relation)?;
        prior_end = Some(event.end_ms);
        let leaf = event_leaf(p, event);
        leaves.push(leaf);
        nullifiers.push(nullifier(p, input.claimant_secret, leaf));
        usage_nullifiers.push(usage_nullifier(p, input.claimant_secret, leaf));
    }
    if total != p.claimed_units
        || root(leaves, b"ACTUM-WORK-EPOCH-NODE-V1") != p.epoch_root
        || nullifiers != p.nullifiers
        || root(nullifiers, b"ACTUM-WORK-NULLIFIER-NODE-V1") != p.nullifier_root
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
    fn d(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn valid() -> WorkClaimRelationInputV1 {
        let secret = d(9);
        let events = alloc::vec![
            WorkEventWitnessV1 {
                sequence: 10,
                start_ms: 100,
                end_ms: 120,
                units: 20,
                nonce: d(10)
            },
            WorkEventWitnessV1 {
                sequence: 11,
                start_ms: 120,
                end_ms: 150,
                units: 30,
                nonce: d(11)
            },
        ];
        let mut public = WorkClaimPublicV1 {
            chain_id: d(1),
            genesis: d(2),
            telemetry_schema: 1,
            policy_id: d(3),
            policy_revision: 7,
            project_id: d(4),
            claimant_key: hash(b"ACTUM-WORK-CLAIMANT-V1", &[secret.as_bytes()]),
            epoch_root: d(5),
            first_sequence: 10,
            last_sequence: 11,
            event_count: 2,
            claim_class: ClaimClass::Attention,
            claimed_units: 50,
            interval_start_ms: 100,
            interval_end_ms: 150,
            nullifier_root: d(6),
            nullifiers: Vec::new(),
            usage_nullifier_root: d(7),
            usage_nullifiers: Vec::new(),
        };
        let leaves = events.iter().map(|event| event_leaf(&public, event)).collect::<Vec<_>>();
        let nullifiers =
            leaves.iter().map(|leaf| nullifier(&public, secret, *leaf)).collect::<Vec<_>>();
        public.epoch_root = root(leaves.clone(), b"ACTUM-WORK-EPOCH-NODE-V1");
        let usage_nullifiers =
            leaves.iter().map(|leaf| usage_nullifier(&public, secret, *leaf)).collect::<Vec<_>>();
        public.nullifier_root = root(nullifiers.clone(), b"ACTUM-WORK-NULLIFIER-NODE-V1");
        public.nullifiers = nullifiers;
        public.usage_nullifier_root =
            root(usage_nullifiers.clone(), b"ACTUM-WORK-USAGE-NULLIFIER-NODE-V1");
        public.usage_nullifiers = usage_nullifiers;
        WorkClaimRelationInputV1 { public, claimant_secret: secret, events }
    }
    #[test]
    fn valid_relation_has_stable_bounded_public_journal() {
        let input = valid();
        verify_relation(&input).unwrap();
        let journal = public_journal(&input.public).unwrap();
        assert!(journal.starts_with(JOURNAL_DOMAIN));
        assert_eq!(journal, public_journal(&input.public).unwrap());
    }
    #[test]
    fn overlap_is_rejected() {
        let mut input = valid();
        input.events[1].start_ms = 119;
        assert_eq!(verify_relation(&input), Err(WorkProofError::Relation));
    }
    #[test]
    fn duplicate_or_partial_event_reuse_is_rejected() {
        let mut duplicate = valid();
        duplicate.events[1] = duplicate.events[0];
        assert_eq!(verify_relation(&duplicate), Err(WorkProofError::Relation));
        let mut partial = valid();
        partial.events[0].end_ms = 119;
        assert_eq!(verify_relation(&partial), Err(WorkProofError::Relation));
    }
    #[test]
    fn chain_project_policy_and_nullifier_substitution_fail() {
        for mutate in [0_u8, 1, 2, 3] {
            let mut input = valid();
            match mutate {
                0 => input.public.chain_id = d(20),
                1 => input.public.project_id = d(21),
                2 => input.public.policy_id = d(22),
                _ => input.public.nullifier_root = d(23),
            };
            assert_eq!(verify_relation(&input), Err(WorkProofError::Relation));
        }
    }
    #[test]
    fn unit_overflow_and_false_total_fail() {
        let mut input = valid();
        input.events[0].units = u64::MAX;
        input.events[1].units = 1;
        assert_eq!(verify_relation(&input), Err(WorkProofError::Relation));
        let mut false_total = valid();
        false_total.public.claimed_units += 1;
        assert_eq!(verify_relation(&false_total), Err(WorkProofError::Relation));
    }
}
