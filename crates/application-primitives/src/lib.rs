#![no_std]
#![forbid(unsafe_code)]

//! Stable, bounded application primitives for browser and delegated-agent jobs.

extern crate alloc;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    ActionId, Amount, CapabilityId, ChainId, Digest384, Height, JobId, PrincipalId, ResourceUnits,
};
use alloc::{collections::BTreeMap, vec::Vec};

pub const APPLICATION_PRIMITIVES_REVISION: u16 = 1;
pub const MAX_ARTIFACTS: usize = 32;
pub const MAX_MEDIA_TYPE_LENGTH: usize = 96;
pub const MAX_ENTRYPOINT_LENGTH: usize = 128;

macro_rules! canonical_type {
    ($type:ty, $tag:expr, $max:expr) => {
        impl CanonicalType for $type {
            const TYPE_TAG: u16 = $tag;
            const SCHEMA_VERSION: u16 = APPLICATION_PRIMITIVES_REVISION;
            const MAX_ENCODED_LEN: usize = $max;
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Artifact {
    digest: Digest384,
    media_type: Vec<u8>,
    byte_length: u64,
    producer: PrincipalId,
    provenance: Digest384,
}

impl Artifact {
    pub fn new(
        digest: Digest384,
        media_type: Vec<u8>,
        byte_length: u64,
        producer: PrincipalId,
        provenance: Digest384,
    ) -> Result<Self, ApplicationError> {
        if digest == Digest384::ZERO
            || provenance == Digest384::ZERO
            || media_type.is_empty()
            || media_type.len() > MAX_MEDIA_TYPE_LENGTH
            || byte_length == 0
        {
            return Err(ApplicationError::InvalidArtifact);
        }
        Ok(Self { digest, media_type, byte_length, producer, provenance })
    }
    pub const fn digest(&self) -> Digest384 {
        self.digest
    }
    pub const fn producer(&self) -> PrincipalId {
        self.producer
    }
}

impl CanonicalEncode for Artifact {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.digest.encode(e)?;
        e.write_bytes(&self.media_type, MAX_MEDIA_TYPE_LENGTH)?;
        self.byte_length.encode(e)?;
        self.producer.encode(e)?;
        self.provenance.encode(e)
    }
}
impl CanonicalDecode for Artifact {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            d.read_bytes(MAX_MEDIA_TYPE_LENGTH)?.to_vec(),
            u64::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid application artifact"))
    }
}
canonical_type!(Artifact, 0x00c0, 48 + 2 + MAX_MEDIA_TYPE_LENGTH + 8 + 48 + 48);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationManifest {
    chain: ChainId,
    application: Digest384,
    revision: u32,
    entrypoint: Vec<u8>,
    action: ActionId,
    artifact_digests: Vec<Digest384>,
    max_compute: ResourceUnits,
    max_storage_bytes: u64,
    max_network_bytes: u64,
    max_fee: Amount,
}

#[allow(clippy::too_many_arguments)]
impl ApplicationManifest {
    pub fn new(
        chain: ChainId,
        application: Digest384,
        revision: u32,
        entrypoint: Vec<u8>,
        action: ActionId,
        artifact_digests: Vec<Digest384>,
        max_compute: ResourceUnits,
        max_storage_bytes: u64,
        max_network_bytes: u64,
        max_fee: Amount,
    ) -> Result<Self, ApplicationError> {
        if application == Digest384::ZERO
            || revision == 0
            || entrypoint.is_empty()
            || entrypoint.len() > MAX_ENTRYPOINT_LENGTH
            || artifact_digests.len() > MAX_ARTIFACTS
            || artifact_digests.windows(2).any(|pair| pair[0] >= pair[1])
            || max_compute == 0
            || max_fee == 0
        {
            return Err(ApplicationError::InvalidManifest);
        }
        Ok(Self {
            chain,
            application,
            revision,
            entrypoint,
            action,
            artifact_digests,
            max_compute,
            max_storage_bytes,
            max_network_bytes,
            max_fee,
        })
    }
    pub const fn chain(&self) -> ChainId {
        self.chain
    }
    pub const fn max_compute(&self) -> ResourceUnits {
        self.max_compute
    }
    pub const fn max_storage_bytes(&self) -> u64 {
        self.max_storage_bytes
    }
    pub const fn max_network_bytes(&self) -> u64 {
        self.max_network_bytes
    }
    pub const fn max_fee(&self) -> Amount {
        self.max_fee
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }
}
impl CanonicalEncode for ApplicationManifest {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain.encode(e)?;
        self.application.encode(e)?;
        self.revision.encode(e)?;
        e.write_bytes(&self.entrypoint, MAX_ENTRYPOINT_LENGTH)?;
        self.action.encode(e)?;
        e.write_length(self.artifact_digests.len(), MAX_ARTIFACTS)?;
        for digest in &self.artifact_digests {
            digest.encode(e)?;
        }
        self.max_compute.encode(e)?;
        self.max_storage_bytes.encode(e)?;
        self.max_network_bytes.encode(e)?;
        self.max_fee.encode(e)
    }
}
impl CanonicalDecode for ApplicationManifest {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain = ChainId::decode(d)?;
        let application = Digest384::decode(d)?;
        let revision = u32::decode(d)?;
        let entrypoint = d.read_bytes(MAX_ENTRYPOINT_LENGTH)?.to_vec();
        let action = ActionId::decode(d)?;
        let count = d.read_length(MAX_ARTIFACTS)?;
        let mut artifacts = Vec::with_capacity(count);
        for _ in 0..count {
            artifacts.push(Digest384::decode(d)?);
        }
        Self::new(
            chain,
            application,
            revision,
            entrypoint,
            action,
            artifacts,
            u128::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u128::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid application manifest"))
    }
}
canonical_type!(
    ApplicationManifest,
    0x00c1,
    48 + 48 + 4 + 2 + MAX_ENTRYPOINT_LENGTH + 48 + 2 + MAX_ARTIFACTS * 48 + 16 + 8 + 8 + 16
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegatedAction {
    job: JobId,
    chain: ChainId,
    requester: PrincipalId,
    executor: PrincipalId,
    capability: CapabilityId,
    sequence: u64,
    valid_from: Height,
    valid_until: Height,
    manifest: Digest384,
    input: Digest384,
    max_fee: Amount,
}
impl DelegatedAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: JobId,
        chain: ChainId,
        requester: PrincipalId,
        executor: PrincipalId,
        capability: CapabilityId,
        sequence: u64,
        valid_from: Height,
        valid_until: Height,
        manifest: Digest384,
        input: Digest384,
        max_fee: Amount,
    ) -> Result<Self, ApplicationError> {
        if sequence == 0
            || valid_from > valid_until
            || manifest == Digest384::ZERO
            || input == Digest384::ZERO
            || max_fee == 0
            || requester == executor
        {
            return Err(ApplicationError::InvalidDelegation);
        }
        Ok(Self {
            job,
            chain,
            requester,
            executor,
            capability,
            sequence,
            valid_from,
            valid_until,
            manifest,
            input,
            max_fee,
        })
    }
    pub const fn job(&self) -> JobId {
        self.job
    }
    pub const fn chain(&self) -> ChainId {
        self.chain
    }
    pub const fn requester(&self) -> PrincipalId {
        self.requester
    }
    pub const fn executor(&self) -> PrincipalId {
        self.executor
    }
    pub const fn capability(&self) -> CapabilityId {
        self.capability
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn valid_from(&self) -> Height {
        self.valid_from
    }
    pub const fn valid_until(&self) -> Height {
        self.valid_until
    }
    pub const fn manifest(&self) -> Digest384 {
        self.manifest
    }
    pub const fn max_fee(&self) -> Amount {
        self.max_fee
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::SIGNING_PAYLOAD, self)
    }
}
impl CanonicalEncode for DelegatedAction {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.job.encode(e)?;
        self.chain.encode(e)?;
        self.requester.encode(e)?;
        self.executor.encode(e)?;
        self.capability.encode(e)?;
        self.sequence.encode(e)?;
        self.valid_from.encode(e)?;
        self.valid_until.encode(e)?;
        self.manifest.encode(e)?;
        self.input.encode(e)?;
        self.max_fee.encode(e)
    }
}
impl CanonicalDecode for DelegatedAction {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            JobId::decode(d)?,
            ChainId::decode(d)?,
            PrincipalId::decode(d)?,
            PrincipalId::decode(d)?,
            CapabilityId::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u128::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid delegated action"))
    }
}
canonical_type!(DelegatedAction, 0x00c2, 48 * 8 + 8 * 3 + 16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionEvidence {
    job: JobId,
    action: Digest384,
    executor: PrincipalId,
    result: Digest384,
    artifact_set: Digest384,
    provenance: Digest384,
    compute_used: ResourceUnits,
    storage_bytes: u64,
    network_bytes: u64,
    completed_at: Height,
}
impl ExecutionEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: JobId,
        action: Digest384,
        executor: PrincipalId,
        result: Digest384,
        artifact_set: Digest384,
        provenance: Digest384,
        compute_used: ResourceUnits,
        storage_bytes: u64,
        network_bytes: u64,
        completed_at: Height,
    ) -> Result<Self, ApplicationError> {
        if action == Digest384::ZERO
            || result == Digest384::ZERO
            || artifact_set == Digest384::ZERO
            || provenance == Digest384::ZERO
            || compute_used == 0
        {
            return Err(ApplicationError::InvalidEvidence);
        }
        Ok(Self {
            job,
            action,
            executor,
            result,
            artifact_set,
            provenance,
            compute_used,
            storage_bytes,
            network_bytes,
            completed_at,
        })
    }
    pub const fn job(&self) -> JobId {
        self.job
    }
    pub const fn action(&self) -> Digest384 {
        self.action
    }
    pub const fn executor(&self) -> PrincipalId {
        self.executor
    }
    pub const fn compute_used(&self) -> ResourceUnits {
        self.compute_used
    }
    pub const fn storage_bytes(&self) -> u64 {
        self.storage_bytes
    }
    pub const fn network_bytes(&self) -> u64 {
        self.network_bytes
    }
    pub const fn completed_at(&self) -> Height {
        self.completed_at
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }
}
impl CanonicalEncode for ExecutionEvidence {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.job.encode(e)?;
        self.action.encode(e)?;
        self.executor.encode(e)?;
        self.result.encode(e)?;
        self.artifact_set.encode(e)?;
        self.provenance.encode(e)?;
        self.compute_used.encode(e)?;
        self.storage_bytes.encode(e)?;
        self.network_bytes.encode(e)?;
        self.completed_at.encode(e)
    }
}
impl CanonicalDecode for ExecutionEvidence {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            JobId::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid execution evidence"))
    }
}
canonical_type!(ExecutionEvidence, 0x00c3, 48 * 6 + 16 + 8 * 3);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum JobStatus {
    Accepted = 0,
    Cancelled = 1,
    TimedOut = 2,
    Completed = 3,
}
impl CanonicalEncode for JobStatus {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for JobStatus {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::Cancelled),
            2 => Ok(Self::TimedOut),
            3 => Ok(Self::Completed),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "JobStatus", tag }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationReceipt {
    job: JobId,
    action: Digest384,
    status: JobStatus,
    evidence: Option<Digest384>,
    fee_charged: Amount,
    finalized_height: Height,
    replay_domain: Digest384,
}
impl ApplicationReceipt {
    pub fn new(
        job: JobId,
        action: Digest384,
        status: JobStatus,
        evidence: Option<Digest384>,
        fee_charged: Amount,
        finalized_height: Height,
        replay_domain: Digest384,
    ) -> Result<Self, ApplicationError> {
        if action == Digest384::ZERO
            || replay_domain == Digest384::ZERO
            || (status == JobStatus::Completed) != evidence.is_some()
            || status != JobStatus::Completed && fee_charged != 0
        {
            return Err(ApplicationError::InvalidReceipt);
        }
        Ok(Self { job, action, status, evidence, fee_charged, finalized_height, replay_domain })
    }
    pub const fn job(&self) -> JobId {
        self.job
    }
    pub const fn status(&self) -> JobStatus {
        self.status
    }
    pub const fn fee_charged(&self) -> Amount {
        self.fee_charged
    }
}
impl CanonicalEncode for ApplicationReceipt {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.job.encode(e)?;
        self.action.encode(e)?;
        self.status.encode(e)?;
        self.evidence.encode(e)?;
        self.fee_charged.encode(e)?;
        self.finalized_height.encode(e)?;
        self.replay_domain.encode(e)
    }
}
impl CanonicalDecode for ApplicationReceipt {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            JobId::decode(d)?,
            Digest384::decode(d)?,
            JobStatus::decode(d)?,
            Option::<Digest384>::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid application receipt"))
    }
}
canonical_type!(ApplicationReceipt, 0x00c4, 48 + 48 + 1 + 49 + 16 + 8 + 48);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveJob {
    action: DelegatedAction,
    action_commitment: Digest384,
}

#[derive(Default)]
pub struct JobLedger {
    jobs: BTreeMap<JobId, ActiveJob>,
    last_sequence: BTreeMap<(PrincipalId, Digest384), u64>,
    receipts: BTreeMap<JobId, ApplicationReceipt>,
}
impl JobLedger {
    pub fn accept(
        &mut self,
        action: DelegatedAction,
        manifest: &ApplicationManifest,
        capability_holder: PrincipalId,
        capability_grant: CapabilityId,
        height: Height,
    ) -> Result<(), ApplicationError> {
        if action.chain() != manifest.chain()
            || action.manifest() != manifest.commitment().map_err(|_| ApplicationError::Encoding)?
            || action.executor() != capability_holder
            || action.capability() != capability_grant
            || height < action.valid_from()
            || height > action.valid_until()
            || action.max_fee() > manifest.max_fee()
        {
            return Err(ApplicationError::ContextMismatch);
        }
        if self.jobs.contains_key(&action.job()) || self.receipts.contains_key(&action.job()) {
            return Err(ApplicationError::Replay);
        }
        let domain = (action.requester(), action.manifest());
        if self.last_sequence.get(&domain).is_some_and(|last| action.sequence() <= *last) {
            return Err(ApplicationError::Replay);
        }
        let action_commitment = action.commitment().map_err(|_| ApplicationError::Encoding)?;
        self.last_sequence.insert(domain, action.sequence());
        self.jobs.insert(action.job(), ActiveJob { action, action_commitment });
        Ok(())
    }

    pub fn cancel(
        &mut self,
        job: JobId,
        requester: PrincipalId,
        height: Height,
    ) -> Result<ApplicationReceipt, ApplicationError> {
        let active = self.jobs.get(&job).ok_or(ApplicationError::UnknownJob)?;
        if active.action.requester() != requester || height > active.action.valid_until() {
            return Err(ApplicationError::ContextMismatch);
        }
        self.finish(job, JobStatus::Cancelled, None, 0, height)
    }

    pub fn timeout(
        &mut self,
        job: JobId,
        height: Height,
    ) -> Result<ApplicationReceipt, ApplicationError> {
        let active = self.jobs.get(&job).ok_or(ApplicationError::UnknownJob)?;
        if height <= active.action.valid_until() {
            return Err(ApplicationError::NotTimedOut);
        }
        self.finish(job, JobStatus::TimedOut, None, 0, height)
    }

    pub fn complete(
        &mut self,
        evidence: &ExecutionEvidence,
        manifest: &ApplicationManifest,
        fee: Amount,
        finalized_height: Height,
    ) -> Result<ApplicationReceipt, ApplicationError> {
        let active = self.jobs.get(&evidence.job()).ok_or(ApplicationError::UnknownJob)?;
        if evidence.action() != active.action_commitment
            || evidence.executor() != active.action.executor()
            || evidence.completed_at() > active.action.valid_until()
            || evidence.compute_used() > manifest.max_compute()
            || evidence.storage_bytes() > manifest.max_storage_bytes()
            || evidence.network_bytes() > manifest.max_network_bytes()
            || fee > active.action.max_fee()
            || fee > manifest.max_fee()
        {
            return Err(ApplicationError::ContextMismatch);
        }
        let evidence_commitment = evidence.commitment().map_err(|_| ApplicationError::Encoding)?;
        self.finish(
            evidence.job(),
            JobStatus::Completed,
            Some(evidence_commitment),
            fee,
            finalized_height,
        )
    }

    fn finish(
        &mut self,
        job: JobId,
        status: JobStatus,
        evidence: Option<Digest384>,
        fee: Amount,
        height: Height,
    ) -> Result<ApplicationReceipt, ApplicationError> {
        let active = self.jobs.remove(&job).ok_or(ApplicationError::UnknownJob)?;
        let receipt = ApplicationReceipt::new(
            job,
            active.action_commitment,
            status,
            evidence,
            fee,
            height,
            active.action.manifest(),
        )?;
        self.receipts.insert(job, receipt);
        Ok(receipt)
    }
    pub fn receipt(&self, job: JobId) -> Option<&ApplicationReceipt> {
        self.receipts.get(&job)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationError {
    InvalidArtifact,
    InvalidManifest,
    InvalidDelegation,
    InvalidEvidence,
    InvalidReceipt,
    ContextMismatch,
    Replay,
    UnknownJob,
    NotTimedOut,
    Encoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::vec;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }
    fn manifest() -> ApplicationManifest {
        ApplicationManifest::new(
            ChainId::new(digest(1)),
            digest(2),
            1,
            b"run".to_vec(),
            ActionId::new(digest(3)),
            vec![digest(4)],
            100,
            200,
            300,
            50,
        )
        .unwrap()
    }
    fn action(manifest: &ApplicationManifest) -> DelegatedAction {
        DelegatedAction::new(
            JobId::new(digest(5)),
            manifest.chain(),
            principal(6),
            principal(7),
            CapabilityId::new(digest(8)),
            1,
            10,
            20,
            manifest.commitment().unwrap(),
            digest(9),
            40,
        )
        .unwrap()
    }
    fn evidence(action: &DelegatedAction) -> ExecutionEvidence {
        ExecutionEvidence::new(
            action.job(),
            action.commitment().unwrap(),
            action.executor(),
            digest(10),
            digest(11),
            digest(12),
            90,
            190,
            290,
            19,
        )
        .unwrap()
    }

    #[test]
    fn canonical_application_values_round_trip() {
        let artifact =
            Artifact::new(digest(1), b"application/wasm".to_vec(), 12, principal(2), digest(3))
                .unwrap();
        assert_eq!(decode_envelope::<Artifact>(&encode_envelope(&artifact).unwrap()), Ok(artifact));
        let manifest = manifest();
        assert_eq!(
            decode_envelope::<ApplicationManifest>(&encode_envelope(&manifest).unwrap()),
            Ok(manifest.clone())
        );
        let action = action(&manifest);
        assert_eq!(
            decode_envelope::<DelegatedAction>(&encode_envelope(&action).unwrap()),
            Ok(action)
        );
        let evidence = evidence(&action);
        assert_eq!(
            decode_envelope::<ExecutionEvidence>(&encode_envelope(&evidence).unwrap()),
            Ok(evidence)
        );
    }

    #[test]
    fn lifecycle_is_bound_bounded_and_exactly_once() {
        let manifest = manifest();
        let action = action(&manifest);
        let mut ledger = JobLedger::default();
        ledger.accept(action, &manifest, action.executor(), action.capability(), 10).unwrap();
        assert_eq!(
            ledger.accept(action, &manifest, action.executor(), action.capability(), 10),
            Err(ApplicationError::Replay)
        );
        let evidence = evidence(&action);
        let receipt = ledger.complete(&evidence, &manifest, 40, 20).unwrap();
        assert_eq!(receipt.status(), JobStatus::Completed);
        assert_eq!(receipt.fee_charged(), 40);
        assert_eq!(
            ledger.complete(&evidence, &manifest, 40, 20),
            Err(ApplicationError::UnknownJob)
        );
    }

    #[test]
    fn cancellation_timeout_substitution_and_resource_excess_fail_closed() {
        let manifest = manifest();
        let action = action(&manifest);
        let mut ledger = JobLedger::default();
        assert_eq!(
            ledger.accept(action, &manifest, principal(99), action.capability(), 10),
            Err(ApplicationError::ContextMismatch)
        );
        ledger.accept(action, &manifest, action.executor(), action.capability(), 10).unwrap();
        let excessive = ExecutionEvidence::new(
            action.job(),
            action.commitment().unwrap(),
            action.executor(),
            digest(10),
            digest(11),
            digest(12),
            101,
            0,
            0,
            19,
        )
        .unwrap();
        assert_eq!(
            ledger.complete(&excessive, &manifest, 1, 20),
            Err(ApplicationError::ContextMismatch)
        );
        assert_eq!(ledger.timeout(action.job(), 20), Err(ApplicationError::NotTimedOut));
        assert_eq!(ledger.timeout(action.job(), 21).unwrap().status(), JobStatus::TimedOut);

        let second = DelegatedAction::new(
            JobId::new(digest(20)),
            manifest.chain(),
            action.requester(),
            action.executor(),
            action.capability(),
            2,
            10,
            20,
            manifest.commitment().unwrap(),
            digest(21),
            40,
        )
        .unwrap();
        ledger.accept(second, &manifest, second.executor(), second.capability(), 10).unwrap();
        assert_eq!(
            ledger.cancel(second.job(), principal(99), 11),
            Err(ApplicationError::ContextMismatch)
        );
        assert_eq!(
            ledger.cancel(second.job(), second.requester(), 11).unwrap().status(),
            JobStatus::Cancelled
        );
    }
}
