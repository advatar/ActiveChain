#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub use activechain_application_primitives::DeveloperEventV1;
use activechain_application_primitives::{
    DeveloperEventMeasurementV1, event_leaf_hash, event_node_hash, telemetry_merkle_root,
};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::Digest384;
use alloc::vec::Vec;
use core::cmp::{max, min};
use sha3::{Digest, Sha3_384};

pub const PROFILE: &str = "actum.non-overlap.risc0.v1";
pub const MAX_WORK_EVENTS: usize = 256;
pub const MAX_EPOCH_DEPTH: usize = 12;
pub const MODEL_WEIGHT_DENOMINATOR: u128 = 1_000_000;
pub const JOURNAL_DOMAIN: &[u8] = b"ACTUM-NON-OVERLAP-RISC0-V1";

const KIND_HUMAN: u8 = 1 << 0;
const KIND_AGENT: u8 = 1 << 1;
const KIND_GIT: u8 = 1 << 2;
const KIND_BUILD: u8 = 1 << 3;
const KIND_MODEL: u8 = 1 << 4;
const ALL_KINDS: u8 = KIND_HUMAN | KIND_AGENT | KIND_GIT | KIND_BUILD | KIND_MODEL;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeteringPolicyV1 {
    pub revision: u32,
    pub accepted_measurement_kinds: u8,
    pub idle_timeout_ms: u64,
    pub max_human_event_ms: u64,
    pub max_attention_claim_ms: u64,
    pub model_input_weight: u32,
    pub model_output_weight: u32,
}

impl MeteringPolicyV1 {
    pub fn validate(&self) -> Result<(), WorkProofError> {
        if self.revision == 0
            || self.accepted_measurement_kinds == 0
            || self.accepted_measurement_kinds & !ALL_KINDS != 0
            || self.idle_timeout_ms == 0
            || self.max_human_event_ms == 0
            || self.max_attention_claim_ms == 0
            || (self.model_input_weight == 0 && self.model_output_weight == 0)
        {
            return Err(WorkProofError::Malformed);
        }
        Ok(())
    }

    pub fn policy_id(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }

    fn accepts(&self, measurement: DeveloperEventMeasurementV1) -> bool {
        let bit = match measurement {
            DeveloperEventMeasurementV1::HumanInteraction { .. } => KIND_HUMAN,
            DeveloperEventMeasurementV1::AgentExecution { .. } => KIND_AGENT,
            DeveloperEventMeasurementV1::GitArtifact { .. } => KIND_GIT,
            DeveloperEventMeasurementV1::BuildTest { .. } => KIND_BUILD,
            DeveloperEventMeasurementV1::ModelUsage { .. } => KIND_MODEL,
        };
        self.accepted_measurement_kinds & bit != 0
    }
}

impl CanonicalEncode for MeteringPolicyV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.revision.encode(e)?;
        self.accepted_measurement_kinds.encode(e)?;
        self.idle_timeout_ms.encode(e)?;
        self.max_human_event_ms.encode(e)?;
        self.max_attention_claim_ms.encode(e)?;
        self.model_input_weight.encode(e)?;
        self.model_output_weight.encode(e)
    }
}
impl CanonicalDecode for MeteringPolicyV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            revision: u32::decode(d)?,
            accepted_measurement_kinds: u8::decode(d)?,
            idle_timeout_ms: u64::decode(d)?,
            max_human_event_ms: u64::decode(d)?,
            max_attention_claim_ms: u64::decode(d)?,
            model_input_weight: u32::decode(d)?,
            model_output_weight: u32::decode(d)?,
        };
        value.validate().map_err(|_| DecodeError::InvalidValue("invalid metering policy"))?;
        Ok(value)
    }
}
impl CanonicalType for MeteringPolicyV1 {
    const TYPE_TAG: u16 = 0x01BE;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 4 + 1 + 8 * 3 + 4 * 2;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkClaimAggregateV1 {
    Attention {
        attributable_ms: u64,
        interaction_count: u32,
    },
    Compute {
        agent_runtime_ms: u64,
        model_input_tokens: u64,
        model_output_tokens: u64,
        normalized_model_units: u64,
        run_count: u32,
    },
    Contribution {
        artifact_count: u32,
        artifact_set_commitment: Digest384,
        evidence_root: Digest384,
    },
}
impl WorkClaimAggregateV1 {
    const fn class_tag(self) -> u8 {
        match self {
            Self::Attention { .. } => 0,
            Self::Compute { .. } => 1,
            Self::Contribution { .. } => 2,
        }
    }
}
impl CanonicalEncode for WorkClaimAggregateV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.class_tag().encode(e)?;
        match self {
            Self::Attention { attributable_ms, interaction_count } => {
                attributable_ms.encode(e)?;
                interaction_count.encode(e)
            }
            Self::Compute {
                agent_runtime_ms,
                model_input_tokens,
                model_output_tokens,
                normalized_model_units,
                run_count,
            } => {
                agent_runtime_ms.encode(e)?;
                model_input_tokens.encode(e)?;
                model_output_tokens.encode(e)?;
                normalized_model_units.encode(e)?;
                run_count.encode(e)
            }
            Self::Contribution { artifact_count, artifact_set_commitment, evidence_root } => {
                artifact_count.encode(e)?;
                artifact_set_commitment.encode(e)?;
                evidence_root.encode(e)
            }
        }
    }
}
impl CanonicalDecode for WorkClaimAggregateV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Attention {
                attributable_ms: u64::decode(d)?,
                interaction_count: u32::decode(d)?,
            }),
            1 => Ok(Self::Compute {
                agent_runtime_ms: u64::decode(d)?,
                model_input_tokens: u64::decode(d)?,
                model_output_tokens: u64::decode(d)?,
                normalized_model_units: u64::decode(d)?,
                run_count: u32::decode(d)?,
            }),
            2 => Ok(Self::Contribution {
                artifact_count: u32::decode(d)?,
                artifact_set_commitment: Digest384::decode(d)?,
                evidence_root: Digest384::decode(d)?,
            }),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "WorkClaimAggregateV1", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
    pub interval_start_ms: u64,
    pub interval_end_ms: u64,
    pub aggregate: WorkClaimAggregateV1,
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
        self.interval_start_ms.encode(e)?;
        self.interval_end_ms.encode(e)?;
        self.aggregate.encode(e)?;
        self.nullifier_root.encode(e)?;
        self.usage_nullifier_root.encode(e)?;
        e.write_length(self.usage_nullifiers.len(), MAX_WORK_EVENTS)?;
        for nullifier in &self.usage_nullifiers {
            nullifier.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for WorkClaimPublicV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let mut value = Self {
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
            interval_start_ms: u64::decode(d)?,
            interval_end_ms: u64::decode(d)?,
            aggregate: WorkClaimAggregateV1::decode(d)?,
            nullifier_root: Digest384::decode(d)?,
            usage_nullifier_root: Digest384::decode(d)?,
            usage_nullifiers: Vec::new(),
        };
        let count = d.read_length(MAX_WORK_EVENTS)?;
        value.usage_nullifiers.reserve(count);
        for _ in 0..count {
            value.usage_nullifiers.push(Digest384::decode(d)?);
        }
        Ok(value)
    }
}
impl CanonicalType for WorkClaimPublicV1 {
    const TYPE_TAG: u16 = 0x01BB;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        48 * 11 + 2 * 2 + 4 * 3 + 8 * 6 + 1 + 48 * 2 + 5 + MAX_WORK_EVENTS * 48;
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
        e.write_length(self.merkle_path.len(), MAX_EPOCH_DEPTH)?;
        for sibling in &self.merkle_path {
            sibling.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for WorkEventWitnessV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let event = DeveloperEventV1::decode(d)?;
        let merkle_index = u32::decode(d)?;
        let count = d.read_length(MAX_EPOCH_DEPTH)?;
        let mut merkle_path = Vec::with_capacity(count);
        for _ in 0..count {
            merkle_path.push(Digest384::decode(d)?);
        }
        Ok(Self { event, merkle_index, merkle_path })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkClaimRelationInputV1 {
    pub public: WorkClaimPublicV1,
    pub policy: MeteringPolicyV1,
    pub claimant_secret: Digest384,
    pub events: Vec<WorkEventWitnessV1>,
}
impl CanonicalEncode for WorkClaimRelationInputV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.public.encode(e)?;
        self.policy.encode(e)?;
        self.claimant_secret.encode(e)?;
        e.write_length(self.events.len(), MAX_WORK_EVENTS)?;
        for event in &self.events {
            event.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for WorkClaimRelationInputV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let public = WorkClaimPublicV1::decode(d)?;
        let policy = MeteringPolicyV1::decode(d)?;
        let claimant_secret = Digest384::decode(d)?;
        let count = d.read_length(MAX_WORK_EVENTS)?;
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            events.push(WorkEventWitnessV1::decode(d)?);
        }
        Ok(Self { public, policy, claimant_secret, events })
    }
}
impl CanonicalType for WorkClaimRelationInputV1 {
    const TYPE_TAG: u16 = 0x01BC;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = WorkClaimPublicV1::MAX_ENCODED_LEN
        + MeteringPolicyV1::MAX_ENCODED_LEN
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
fn included_root(event_id: Digest384, index: u32, path: &[Digest384]) -> Digest384 {
    let mut current = event_leaf_hash(event_id);
    let mut position = index;
    for sibling in path {
        current = if position & 1 == 0 {
            event_node_hash(current, *sibling)
        } else {
            event_node_hash(*sibling, current)
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
            &[public.aggregate.class_tag()],
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
pub fn derive_nullifier_bindings(
    public: &WorkClaimPublicV1,
    claimant_secret: Digest384,
    events: &[WorkEventWitnessV1],
) -> Result<(Digest384, Digest384, Vec<Digest384>), WorkProofError> {
    if events.is_empty() || events.len() > MAX_WORK_EVENTS {
        return Err(WorkProofError::Malformed);
    }
    let ids = events
        .iter()
        .map(|event| event.event.event_id().map_err(|_| WorkProofError::Malformed))
        .collect::<Result<Vec<_>, _>>()?;
    let class = ids.iter().map(|id| class_nullifier(public, claimant_secret, *id)).collect();
    let usage =
        ids.iter().map(|id| usage_nullifier(public, claimant_secret, *id)).collect::<Vec<_>>();
    Ok((
        root(class, b"ACTUM-WORK-CLASS-NULLIFIER-NODE-V1"),
        root(usage.clone(), b"ACTUM-WORK-USAGE-NULLIFIER-NODE-V1"),
        usage,
    ))
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
fn duration_ms(event: &DeveloperEventV1) -> Result<u64, WorkProofError> {
    event
        .monotonic_end_ns
        .checked_sub(event.monotonic_start_ns)
        .map(|duration| duration / 1_000_000)
        .ok_or(WorkProofError::Relation)
}
fn artifact_set_commitment(artifacts: &[Digest384]) -> Digest384 {
    let mut h = Sha3_384::new();
    h.update(b"ACTUM-CONTRIBUTION-ARTIFACT-SET-V1");
    for artifact in artifacts {
        h.update(artifact.as_bytes());
    }
    Digest384::new(h.finalize().into())
}

fn evaluate_attention(
    policy: &MeteringPolicyV1,
    events: &[(Digest384, &DeveloperEventV1)],
) -> Result<WorkClaimAggregateV1, WorkProofError> {
    let mut intervals = Vec::with_capacity(events.len());
    let mut interactions = 0_u32;
    for (event_id, event) in events {
        let DeveloperEventMeasurementV1::HumanInteraction { interaction_count } = event.measurement
        else {
            return Err(WorkProofError::Relation);
        };
        interactions =
            interactions.checked_add(interaction_count).ok_or(WorkProofError::Relation)?;
        let clipped_ms =
            min(duration_ms(event)?, min(policy.idle_timeout_ms, policy.max_human_event_ms));
        let clipped_ns = clipped_ms.checked_mul(1_000_000).ok_or(WorkProofError::Relation)?;
        let end =
            event.monotonic_start_ns.checked_add(clipped_ns).ok_or(WorkProofError::Relation)?;
        intervals.push((event.monotonic_start_ns, end, *event_id));
    }
    intervals.sort_unstable();
    let mut total_ns = 0_u64;
    let mut current = intervals[0];
    for interval in intervals.into_iter().skip(1) {
        if interval.0 <= current.1 {
            current.1 = max(current.1, interval.1);
        } else {
            total_ns = total_ns
                .checked_add(current.1.checked_sub(current.0).ok_or(WorkProofError::Relation)?)
                .ok_or(WorkProofError::Relation)?;
            current = interval;
        }
    }
    total_ns = total_ns
        .checked_add(current.1.checked_sub(current.0).ok_or(WorkProofError::Relation)?)
        .ok_or(WorkProofError::Relation)?;
    Ok(WorkClaimAggregateV1::Attention {
        attributable_ms: min(total_ns / 1_000_000, policy.max_attention_claim_ms),
        interaction_count: interactions,
    })
}

fn evaluate_compute(
    policy: &MeteringPolicyV1,
    events: &[(Digest384, &DeveloperEventV1)],
) -> Result<WorkClaimAggregateV1, WorkProofError> {
    let mut runtime = 0_u64;
    let mut input = 0_u64;
    let mut output = 0_u64;
    let mut runs = 0_u32;
    for (_, event) in events {
        match event.measurement {
            DeveloperEventMeasurementV1::AgentExecution { run_count } => {
                runtime =
                    runtime.checked_add(duration_ms(event)?).ok_or(WorkProofError::Relation)?;
                runs = runs.checked_add(run_count).ok_or(WorkProofError::Relation)?;
            }
            DeveloperEventMeasurementV1::BuildTest { run_count, .. } => {
                runtime =
                    runtime.checked_add(duration_ms(event)?).ok_or(WorkProofError::Relation)?;
                runs = runs.checked_add(run_count).ok_or(WorkProofError::Relation)?;
            }
            DeveloperEventMeasurementV1::ModelUsage { input_tokens, output_tokens, run_count } => {
                input = input.checked_add(input_tokens).ok_or(WorkProofError::Relation)?;
                output = output.checked_add(output_tokens).ok_or(WorkProofError::Relation)?;
                runs = runs.checked_add(run_count).ok_or(WorkProofError::Relation)?;
            }
            _ => return Err(WorkProofError::Relation),
        }
    }
    let weighted = u128::from(input)
        .checked_mul(u128::from(policy.model_input_weight))
        .and_then(|value| {
            u128::from(output)
                .checked_mul(u128::from(policy.model_output_weight))
                .and_then(|other| value.checked_add(other))
        })
        .ok_or(WorkProofError::Relation)?;
    let normalized =
        u64::try_from(weighted / MODEL_WEIGHT_DENOMINATOR).map_err(|_| WorkProofError::Relation)?;
    Ok(WorkClaimAggregateV1::Compute {
        agent_runtime_ms: runtime,
        model_input_tokens: input,
        model_output_tokens: output,
        normalized_model_units: normalized,
        run_count: runs,
    })
}

fn evaluate_contribution(
    events: &[(Digest384, &DeveloperEventV1)],
) -> Result<WorkClaimAggregateV1, WorkProofError> {
    let mut artifacts = Vec::with_capacity(events.len());
    let mut evidence = Vec::with_capacity(events.len());
    for (_, event) in events {
        let DeveloperEventMeasurementV1::GitArtifact { artifact_count: 1 } = event.measurement
        else {
            return Err(WorkProofError::Relation);
        };
        artifacts.push(event.subject_commitment);
        evidence.push(event.payload_commitment);
    }
    artifacts.sort_unstable();
    if artifacts.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(WorkProofError::Relation);
    }
    evidence.sort_unstable();
    Ok(WorkClaimAggregateV1::Contribution {
        artifact_count: u32::try_from(artifacts.len()).map_err(|_| WorkProofError::Relation)?,
        artifact_set_commitment: artifact_set_commitment(&artifacts),
        evidence_root: telemetry_merkle_root(&evidence).map_err(|_| WorkProofError::Relation)?,
    })
}

pub fn verify_relation(input: &WorkClaimRelationInputV1) -> Result<(), WorkProofError> {
    let p = &input.public;
    input.policy.validate()?;
    if input.events.is_empty()
        || input.events.len() > MAX_WORK_EVENTS
        || p.chain_id == Digest384::ZERO
        || p.genesis == Digest384::ZERO
        || p.policy_id == Digest384::ZERO
        || p.usage_domain == Digest384::ZERO
        || p.collector_id == Digest384::ZERO
        || p.project_id == Digest384::ZERO
        || p.telemetry_schema != 1
        || p.policy_revision != input.policy.revision
        || p.policy_id != input.policy.policy_id().map_err(|_| WorkProofError::Malformed)?
        || p.authorization_revision == 0
        || p.event_count as usize != input.events.len()
        || p.usage_nullifiers.len() != input.events.len()
        || p.epoch_event_count == 0
        || p.first_sequence == 0
        || p.last_sequence < p.first_sequence
        || p.interval_start_ms > p.interval_end_ms
        || hash(b"ACTUM-WORK-CLAIMANT-V1", &[input.claimant_secret.as_bytes()]) != p.claimant_key
    {
        return Err(WorkProofError::Malformed);
    }
    let mut prior_sequence = None;
    let mut prior_index = None;
    let mut selected = Vec::with_capacity(input.events.len());
    let mut class_nullifiers = Vec::with_capacity(input.events.len());
    let mut usage_nullifiers = Vec::with_capacity(input.events.len());
    for event in &input.events {
        let value = &event.event;
        let event_id = value.event_id().map_err(|_| WorkProofError::Malformed)?;
        if value.collector_id != p.collector_id
            || value.project_id != p.project_id
            || value.authorization_revision != p.authorization_revision
            || !input.policy.accepts(value.measurement)
            || prior_sequence.is_some_and(|sequence| value.project_sequence <= sequence)
            || prior_index.is_some_and(|index| event.merkle_index <= index)
            || value.wall_start_ms < p.interval_start_ms
            || value.wall_end_ms > p.interval_end_ms
            || event.merkle_index >= p.epoch_event_count
            || event.merkle_path.len() != epoch_depth(p.epoch_event_count)
            || included_root(event_id, event.merkle_index, &event.merkle_path) != p.epoch_root
        {
            return Err(WorkProofError::Relation);
        }
        prior_sequence = Some(value.project_sequence);
        prior_index = Some(event.merkle_index);
        selected.push((event_id, value));
        class_nullifiers.push(class_nullifier(p, input.claimant_secret, event_id));
        usage_nullifiers.push(usage_nullifier(p, input.claimant_secret, event_id));
    }
    if selected.first().map(|(_, event)| event.project_sequence) != Some(p.first_sequence)
        || selected.last().map(|(_, event)| event.project_sequence) != Some(p.last_sequence)
    {
        return Err(WorkProofError::Relation);
    }
    let aggregate = match p.aggregate {
        WorkClaimAggregateV1::Attention { .. } => evaluate_attention(&input.policy, &selected)?,
        WorkClaimAggregateV1::Compute { .. } => evaluate_compute(&input.policy, &selected)?,
        WorkClaimAggregateV1::Contribution { .. } => evaluate_contribution(&selected)?,
    };
    if aggregate != p.aggregate
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
    use activechain_application_primitives::DeveloperEventMeasurementV1;

    fn d(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn event(
        sequence: u64,
        start_ns: u64,
        end_ns: u64,
        measurement: DeveloperEventMeasurementV1,
    ) -> DeveloperEventV1 {
        DeveloperEventV1 {
            collector_id: d(2),
            project_id: d(4),
            collector_sequence: sequence,
            project_sequence: sequence,
            wall_start_ms: 100,
            wall_end_ms: 200,
            monotonic_start_ns: start_ns,
            monotonic_end_ns: end_ns,
            measurement,
            source_commitment: d(20),
            subject_commitment: d(sequence as u8),
            payload_commitment: d(sequence as u8 + 20),
            authorization_revision: 7,
        }
    }
    fn policy() -> MeteringPolicyV1 {
        MeteringPolicyV1 {
            revision: 7,
            accepted_measurement_kinds: ALL_KINDS,
            idle_timeout_ms: 100,
            max_human_event_ms: 80,
            max_attention_claim_ms: 1_000,
            model_input_weight: 500_000,
            model_output_weight: 2_000_000,
        }
    }
    fn witnesses(events: Vec<DeveloperEventV1>) -> (Digest384, Vec<WorkEventWitnessV1>) {
        let ids = events.iter().map(|event| event.event_id().unwrap()).collect::<Vec<_>>();
        assert_eq!(ids.len(), 2);
        let leaves = [event_leaf_hash(ids[0]), event_leaf_hash(ids[1])];
        (
            event_node_hash(leaves[0], leaves[1]),
            alloc::vec![
                WorkEventWitnessV1 {
                    event: events[0].clone(),
                    merkle_index: 0,
                    merkle_path: alloc::vec![leaves[1]]
                },
                WorkEventWitnessV1 {
                    event: events[1].clone(),
                    merkle_index: 1,
                    merkle_path: alloc::vec![leaves[0]]
                },
            ],
        )
    }
    fn input(
        events: Vec<DeveloperEventV1>,
        aggregate: WorkClaimAggregateV1,
    ) -> WorkClaimRelationInputV1 {
        let policy = policy();
        let (epoch_root, witnesses) = witnesses(events);
        let secret = d(9);
        let mut input = WorkClaimRelationInputV1 {
            public: WorkClaimPublicV1 {
                chain_id: d(1),
                genesis: d(3),
                telemetry_schema: 1,
                policy_id: policy.policy_id().unwrap(),
                policy_revision: policy.revision,
                authorization_revision: 7,
                usage_domain: d(6),
                collector_id: d(2),
                project_id: d(4),
                claimant_key: hash(b"ACTUM-WORK-CLAIMANT-V1", &[secret.as_bytes()]),
                epoch_root,
                first_sequence: witnesses[0].event.project_sequence,
                last_sequence: witnesses[1].event.project_sequence,
                event_count: 2,
                epoch_event_count: 2,
                interval_start_ms: 100,
                interval_end_ms: 200,
                aggregate,
                nullifier_root: d(7),
                usage_nullifier_root: d(8),
                usage_nullifiers: Vec::new(),
            },
            policy,
            claimant_secret: secret,
            events: witnesses,
        };
        bind(&mut input);
        input
    }
    fn bind(input: &mut WorkClaimRelationInputV1) {
        let (class_root, usage_root, usage) =
            derive_nullifier_bindings(&input.public, input.claimant_secret, &input.events).unwrap();
        input.public.nullifier_root = class_root;
        input.public.usage_nullifier_root = usage_root;
        input.public.usage_nullifiers = usage;
    }
    fn human(sequence: u64, start_ms: u64, end_ms: u64) -> DeveloperEventV1 {
        event(
            sequence,
            start_ms * 1_000_000,
            end_ms * 1_000_000,
            DeveloperEventMeasurementV1::HumanInteraction { interaction_count: 1 },
        )
    }
    fn agent(sequence: u64, start_ms: u64, end_ms: u64) -> DeveloperEventV1 {
        event(
            sequence,
            start_ms * 1_000_000,
            end_ms * 1_000_000,
            DeveloperEventMeasurementV1::AgentExecution { run_count: 1 },
        )
    }

    #[test]
    fn overlapping_attention_is_unioned_and_adjacent_intervals_merge() {
        let input = input(
            alloc::vec![human(10, 0, 70), human(11, 50, 100)],
            WorkClaimAggregateV1::Attention { attributable_ms: 100, interaction_count: 2 },
        );
        assert_eq!(verify_relation(&input), Ok(()));
    }
    #[test]
    fn nested_attention_does_not_double_count() {
        let input = input(
            alloc::vec![human(10, 0, 80), human(11, 20, 40)],
            WorkClaimAggregateV1::Attention { attributable_ms: 80, interaction_count: 2 },
        );
        assert_eq!(verify_relation(&input), Ok(()));
    }
    #[test]
    fn overlapping_compute_is_summed() {
        let input = input(
            alloc::vec![agent(10, 0, 70), agent(11, 20, 90)],
            WorkClaimAggregateV1::Compute {
                agent_runtime_ms: 140,
                model_input_tokens: 0,
                model_output_tokens: 0,
                normalized_model_units: 0,
                run_count: 2,
            },
        );
        assert_eq!(verify_relation(&input), Ok(()));
    }
    #[test]
    fn sub_millisecond_fragments_round_down() {
        let first =
            event(10, 0, 999_999, DeveloperEventMeasurementV1::AgentExecution { run_count: 1 });
        let second = event(
            11,
            1_000_000,
            1_999_999,
            DeveloperEventMeasurementV1::AgentExecution { run_count: 1 },
        );
        let input = input(
            alloc::vec![first, second],
            WorkClaimAggregateV1::Compute {
                agent_runtime_ms: 0,
                model_input_tokens: 0,
                model_output_tokens: 0,
                normalized_model_units: 0,
                run_count: 2,
            },
        );
        assert_eq!(verify_relation(&input), Ok(()));
    }
    #[test]
    fn model_tokens_aggregate_before_one_rounding() {
        let model = |sequence| {
            event(
                sequence,
                0,
                0,
                DeveloperEventMeasurementV1::ModelUsage {
                    input_tokens: 1,
                    output_tokens: 0,
                    run_count: 1,
                },
            )
        };
        let input = input(
            alloc::vec![model(10), model(11)],
            WorkClaimAggregateV1::Compute {
                agent_runtime_ms: 0,
                model_input_tokens: 2,
                model_output_tokens: 0,
                normalized_model_units: 1,
                run_count: 2,
            },
        );
        assert_eq!(verify_relation(&input), Ok(()));
    }
    #[test]
    fn weighted_result_that_cannot_fit_u64_is_rejected() {
        let model = |sequence| {
            event(
                sequence,
                0,
                0,
                DeveloperEventMeasurementV1::ModelUsage {
                    input_tokens: u64::MAX,
                    output_tokens: 0,
                    run_count: 1,
                },
            )
        };
        let mut input = input(
            alloc::vec![model(10), model(11)],
            WorkClaimAggregateV1::Compute {
                agent_runtime_ms: 0,
                model_input_tokens: u64::MAX,
                model_output_tokens: 0,
                normalized_model_units: 0,
                run_count: 2,
            },
        );
        input.policy.model_input_weight = u32::MAX;
        input.public.policy_id = input.policy.policy_id().unwrap();
        bind(&mut input);
        assert_eq!(verify_relation(&input), Err(WorkProofError::Relation));
    }
    #[test]
    fn wrong_kind_for_claim_is_rejected() {
        let input = input(
            alloc::vec![human(10, 0, 10), agent(11, 10, 20)],
            WorkClaimAggregateV1::Attention { attributable_ms: 20, interaction_count: 2 },
        );
        assert_eq!(verify_relation(&input), Err(WorkProofError::Relation));
    }
    #[test]
    fn duplicate_contribution_artifact_is_rejected() {
        let mut first =
            event(10, 0, 0, DeveloperEventMeasurementV1::GitArtifact { artifact_count: 1 });
        let mut second =
            event(11, 0, 0, DeveloperEventMeasurementV1::GitArtifact { artifact_count: 1 });
        first.subject_commitment = d(30);
        second.subject_commitment = d(30);
        let input = input(
            alloc::vec![first, second],
            WorkClaimAggregateV1::Contribution {
                artifact_count: 2,
                artifact_set_commitment: d(31),
                evidence_root: d(32),
            },
        );
        assert_eq!(verify_relation(&input), Err(WorkProofError::Relation));
    }
    #[test]
    fn contribution_commitment_substitution_is_rejected() {
        let first = event(10, 0, 0, DeveloperEventMeasurementV1::GitArtifact { artifact_count: 1 });
        let second =
            event(11, 0, 0, DeveloperEventMeasurementV1::GitArtifact { artifact_count: 1 });
        let mut expected_artifacts =
            alloc::vec![first.subject_commitment, second.subject_commitment];
        expected_artifacts.sort_unstable();
        let mut evidence = alloc::vec![first.payload_commitment, second.payload_commitment];
        evidence.sort_unstable();
        let mut input = input(
            alloc::vec![first, second],
            WorkClaimAggregateV1::Contribution {
                artifact_count: 2,
                artifact_set_commitment: artifact_set_commitment(&expected_artifacts),
                evidence_root: telemetry_merkle_root(&evidence).unwrap(),
            },
        );
        assert_eq!(verify_relation(&input), Ok(()));
        if let WorkClaimAggregateV1::Contribution { ref mut evidence_root, .. } =
            input.public.aggregate
        {
            *evidence_root = d(99);
        }
        assert_eq!(verify_relation(&input), Err(WorkProofError::Relation));
    }
    #[test]
    fn policy_weight_and_revision_substitution_fail() {
        let model = |sequence| {
            event(
                sequence,
                0,
                0,
                DeveloperEventMeasurementV1::ModelUsage {
                    input_tokens: 2,
                    output_tokens: 1,
                    run_count: 1,
                },
            )
        };
        let mut input = input(
            alloc::vec![model(10), model(11)],
            WorkClaimAggregateV1::Compute {
                agent_runtime_ms: 0,
                model_input_tokens: 4,
                model_output_tokens: 2,
                normalized_model_units: 6,
                run_count: 2,
            },
        );
        assert_eq!(verify_relation(&input), Ok(()));
        input.policy.model_output_weight = 1_000_000;
        assert_eq!(verify_relation(&input), Err(WorkProofError::Malformed));
        input.public.policy_id = input.policy.policy_id().unwrap();
        assert_eq!(verify_relation(&input), Err(WorkProofError::Relation));
        input.policy.revision += 1;
        input.public.policy_id = input.policy.policy_id().unwrap();
        assert_eq!(verify_relation(&input), Err(WorkProofError::Malformed));
    }
    #[test]
    fn clipping_boundaries_are_exact() {
        let mut idle = input(
            alloc::vec![human(10, 0, 100), human(11, 200, 280)],
            WorkClaimAggregateV1::Attention { attributable_ms: 180, interaction_count: 2 },
        );
        idle.policy.max_human_event_ms = 200;
        idle.public.policy_id = idle.policy.policy_id().unwrap();
        bind(&mut idle);
        assert_eq!(verify_relation(&idle), Ok(()));

        let mut maximum = input(
            alloc::vec![human(10, 0, 100), human(11, 200, 280)],
            WorkClaimAggregateV1::Attention { attributable_ms: 160, interaction_count: 2 },
        );
        maximum.policy.idle_timeout_ms = 200;
        maximum.public.policy_id = maximum.policy.policy_id().unwrap();
        bind(&mut maximum);
        assert_eq!(verify_relation(&maximum), Ok(()));

        let mut capped = maximum;
        capped.policy.max_attention_claim_ms = 100;
        capped.public.policy_id = capped.policy.policy_id().unwrap();
        capped.public.aggregate =
            WorkClaimAggregateV1::Attention { attributable_ms: 100, interaction_count: 2 };
        bind(&mut capped);
        assert_eq!(verify_relation(&capped), Ok(()));
    }

    #[test]
    fn revised_policy_can_accept_a_different_normalization() {
        let model = |sequence| {
            event(
                sequence,
                0,
                0,
                DeveloperEventMeasurementV1::ModelUsage {
                    input_tokens: 2,
                    output_tokens: 1,
                    run_count: 1,
                },
            )
        };
        let mut input = input(
            alloc::vec![model(10), model(11)],
            WorkClaimAggregateV1::Compute {
                agent_runtime_ms: 0,
                model_input_tokens: 4,
                model_output_tokens: 2,
                normalized_model_units: 4,
                run_count: 2,
            },
        );
        input.policy.revision = 8;
        input.policy.model_output_weight = 1_000_000;
        input.public.policy_revision = 8;
        input.public.policy_id = input.policy.policy_id().unwrap();
        bind(&mut input);
        assert_eq!(verify_relation(&input), Ok(()));
    }
    #[test]
    fn usage_nullifier_is_class_neutral() {
        let events = alloc::vec![human(10, 0, 10), human(11, 10, 20)];
        let attention = input(
            events.clone(),
            WorkClaimAggregateV1::Attention { attributable_ms: 20, interaction_count: 2 },
        );
        let mut compute = input(
            events,
            WorkClaimAggregateV1::Compute {
                agent_runtime_ms: 20,
                model_input_tokens: 0,
                model_output_tokens: 0,
                normalized_model_units: 0,
                run_count: 2,
            },
        );
        compute.public.aggregate = WorkClaimAggregateV1::Contribution {
            artifact_count: 2,
            artifact_set_commitment: d(40),
            evidence_root: d(41),
        };
        bind(&mut compute);
        assert_eq!(attention.public.usage_nullifiers, compute.public.usage_nullifiers);
        assert_ne!(attention.public.nullifier_root, compute.public.nullifier_root);
    }
    #[test]
    fn event_or_merkle_substitution_fails() {
        let mut substituted = input(
            alloc::vec![human(10, 0, 10), human(11, 10, 20)],
            WorkClaimAggregateV1::Attention { attributable_ms: 20, interaction_count: 2 },
        );
        substituted.events[0].event.payload_commitment = d(99);
        assert_eq!(verify_relation(&substituted), Err(WorkProofError::Relation));
        let mut substituted = input(
            alloc::vec![human(10, 0, 10), human(11, 10, 20)],
            WorkClaimAggregateV1::Attention { attributable_ms: 20, interaction_count: 2 },
        );
        substituted.events[0].merkle_path[0] = d(98);
        assert_eq!(verify_relation(&substituted), Err(WorkProofError::Relation));
    }
}
