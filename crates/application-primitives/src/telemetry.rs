use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::Digest384;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_384};

pub const MAX_TELEMETRY_EVENTS: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeveloperEventKindV1 {
    HumanInteraction,
    AgentExecution,
    GitArtifact,
    BuildTest,
    ModelUsage,
}

impl CanonicalEncode for DeveloperEventKindV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for DeveloperEventKindV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::HumanInteraction),
            1 => Ok(Self::AgentExecution),
            2 => Ok(Self::GitArtifact),
            3 => Ok(Self::BuildTest),
            4 => Ok(Self::ModelUsage),
            _ => Err(DecodeError::InvalidValue("unknown developer event kind")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperEventV1 {
    pub collector_id: Digest384,
    pub project_id: Digest384,
    pub collector_sequence: u64,
    pub project_sequence: u64,
    pub wall_start_ms: u64,
    pub wall_end_ms: u64,
    pub monotonic_start_ns: u64,
    pub monotonic_end_ns: u64,
    pub kind: DeveloperEventKindV1,
    pub source_commitment: Digest384,
    pub subject_commitment: Digest384,
    pub payload_commitment: Digest384,
    pub units: u64,
    pub authorization_revision: u32,
}

impl DeveloperEventV1 {
    pub fn validate(&self) -> Result<(), TelemetryPrimitiveError> {
        if self.collector_id == Digest384::ZERO
            || self.project_id == Digest384::ZERO
            || self.collector_sequence == 0
            || self.project_sequence == 0
            || self.wall_start_ms > self.wall_end_ms
            || self.monotonic_start_ns > self.monotonic_end_ns
            || self.source_commitment == Digest384::ZERO
            || self.subject_commitment == Digest384::ZERO
            || self.payload_commitment == Digest384::ZERO
            || self.units == 0
            || self.authorization_revision == 0
        {
            return Err(TelemetryPrimitiveError::InvalidEvent);
        }
        Ok(())
    }

    pub fn event_id(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }

    pub const fn duration_ns(&self) -> u64 {
        self.monotonic_end_ns - self.monotonic_start_ns
    }
}

impl CanonicalEncode for DeveloperEventV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.collector_id.encode(encoder)?;
        self.project_id.encode(encoder)?;
        self.collector_sequence.encode(encoder)?;
        self.project_sequence.encode(encoder)?;
        self.wall_start_ms.encode(encoder)?;
        self.wall_end_ms.encode(encoder)?;
        self.monotonic_start_ns.encode(encoder)?;
        self.monotonic_end_ns.encode(encoder)?;
        self.kind.encode(encoder)?;
        self.source_commitment.encode(encoder)?;
        self.subject_commitment.encode(encoder)?;
        self.payload_commitment.encode(encoder)?;
        self.units.encode(encoder)?;
        self.authorization_revision.encode(encoder)
    }
}

impl CanonicalDecode for DeveloperEventV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            collector_id: Digest384::decode(decoder)?,
            project_id: Digest384::decode(decoder)?,
            collector_sequence: u64::decode(decoder)?,
            project_sequence: u64::decode(decoder)?,
            wall_start_ms: u64::decode(decoder)?,
            wall_end_ms: u64::decode(decoder)?,
            monotonic_start_ns: u64::decode(decoder)?,
            monotonic_end_ns: u64::decode(decoder)?,
            kind: DeveloperEventKindV1::decode(decoder)?,
            source_commitment: Digest384::decode(decoder)?,
            subject_commitment: Digest384::decode(decoder)?,
            payload_commitment: Digest384::decode(decoder)?,
            units: u64::decode(decoder)?,
            authorization_revision: u32::decode(decoder)?,
        };
        value.validate().map_err(|_| DecodeError::InvalidValue("invalid developer event"))?;
        Ok(value)
    }
}

impl CanonicalType for DeveloperEventV1 {
    const TYPE_TAG: u16 = 0x01B2;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 5 + 8 * 7 + 4 + 1;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityEpochV1 {
    pub collector_id: Digest384,
    pub project_id: Digest384,
    pub first_collector_sequence: u64,
    pub last_collector_sequence: u64,
    pub first_project_sequence: u64,
    pub last_project_sequence: u64,
    pub event_count: u32,
    pub wall_start_ms: u64,
    pub wall_end_ms: u64,
    pub monotonic_start_ns: u64,
    pub monotonic_end_ns: u64,
    pub event_root: Digest384,
    pub previous_epoch_id: Digest384,
    pub authorization_revision: u32,
    pub policy_id: Digest384,
}

impl ActivityEpochV1 {
    pub fn validate(&self) -> Result<(), TelemetryPrimitiveError> {
        let count = u64::from(self.event_count);
        if self.collector_id == Digest384::ZERO
            || self.project_id == Digest384::ZERO
            || count == 0
            || self.event_count as usize > MAX_TELEMETRY_EVENTS
            || self.first_collector_sequence == 0
            || self.first_project_sequence == 0
            || self.last_collector_sequence.checked_sub(self.first_collector_sequence)
                != Some(count - 1)
            || self.last_project_sequence.checked_sub(self.first_project_sequence)
                != Some(count - 1)
            || self.wall_start_ms > self.wall_end_ms
            || self.monotonic_start_ns > self.monotonic_end_ns
            || self.event_root == Digest384::ZERO
            || self.authorization_revision == 0
            || self.policy_id == Digest384::ZERO
        {
            return Err(TelemetryPrimitiveError::InvalidEpoch);
        }
        Ok(())
    }

    pub fn epoch_id(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }
}

impl CanonicalEncode for ActivityEpochV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.collector_id.encode(encoder)?;
        self.project_id.encode(encoder)?;
        self.first_collector_sequence.encode(encoder)?;
        self.last_collector_sequence.encode(encoder)?;
        self.first_project_sequence.encode(encoder)?;
        self.last_project_sequence.encode(encoder)?;
        self.event_count.encode(encoder)?;
        self.wall_start_ms.encode(encoder)?;
        self.wall_end_ms.encode(encoder)?;
        self.monotonic_start_ns.encode(encoder)?;
        self.monotonic_end_ns.encode(encoder)?;
        self.event_root.encode(encoder)?;
        self.previous_epoch_id.encode(encoder)?;
        self.authorization_revision.encode(encoder)?;
        self.policy_id.encode(encoder)
    }
}

impl CanonicalDecode for ActivityEpochV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            collector_id: Digest384::decode(decoder)?,
            project_id: Digest384::decode(decoder)?,
            first_collector_sequence: u64::decode(decoder)?,
            last_collector_sequence: u64::decode(decoder)?,
            first_project_sequence: u64::decode(decoder)?,
            last_project_sequence: u64::decode(decoder)?,
            event_count: u32::decode(decoder)?,
            wall_start_ms: u64::decode(decoder)?,
            wall_end_ms: u64::decode(decoder)?,
            monotonic_start_ns: u64::decode(decoder)?,
            monotonic_end_ns: u64::decode(decoder)?,
            event_root: Digest384::decode(decoder)?,
            previous_epoch_id: Digest384::decode(decoder)?,
            authorization_revision: u32::decode(decoder)?,
            policy_id: Digest384::decode(decoder)?,
        };
        value.validate().map_err(|_| DecodeError::InvalidValue("invalid activity epoch"))?;
        Ok(value)
    }
}

impl CanonicalType for ActivityEpochV1 {
    const TYPE_TAG: u16 = 0x01B3;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 5 + 8 * 8 + 4 * 2;
}

pub fn event_leaf_hash(event_id: Digest384) -> Digest384 {
    hash_with_prefix(0x00, &[event_id])
}

pub fn event_node_hash(left: Digest384, right: Digest384) -> Digest384 {
    hash_with_prefix(0x01, &[left, right])
}

pub fn telemetry_merkle_root(
    event_ids: &[Digest384],
) -> Result<Digest384, TelemetryPrimitiveError> {
    if event_ids.is_empty() || event_ids.len() > MAX_TELEMETRY_EVENTS {
        return Err(TelemetryPrimitiveError::InvalidEpoch);
    }
    let mut level: Vec<_> = event_ids.iter().copied().map(event_leaf_hash).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty level"));
        }
        level = level.chunks_exact(2).map(|pair| event_node_hash(pair[0], pair[1])).collect();
    }
    Ok(level[0])
}

fn hash_with_prefix(prefix: u8, values: &[Digest384]) -> Digest384 {
    let mut hasher = Sha3_384::new();
    hasher.update([prefix]);
    for value in values {
        hasher.update(value.as_bytes());
    }
    Digest384::new(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryPrimitiveError {
    InvalidEvent,
    InvalidEpoch,
}
