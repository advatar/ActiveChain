#![forbid(unsafe_code)]

//! Permissioned local collection for canonical Actum developer telemetry.
//! JSON is used only for durable transport; commitments and signatures bind
//! canonical binary envelopes.

use activechain_application_primitives::{
    ActivityEpochV1, DeveloperEventKindV1, DeveloperEventMeasurementV1, DeveloperEventV1,
    MAX_TELEMETRY_EVENTS, telemetry_merkle_root,
};
use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_protocol_types::Digest384;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

pub const MAX_LABEL_BYTES: usize = 128;
pub const ML_DSA_ALGORITHM_REVISION: u16 = 1;
const EVENT_SIGNATURE_DOMAIN: &[u8] = b"actum.developer-event.v1";
const COLLECTOR_KEY_DOMAIN: &[u8] = b"actum.collector-key-record.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    HumanInteraction,
    AgentExecution,
    GitArtifact,
    BuildTest,
    ModelUsage,
}

impl From<DeveloperEventKindV1> for Category {
    fn from(value: DeveloperEventKindV1) -> Self {
        match value {
            DeveloperEventKindV1::HumanInteraction => Self::HumanInteraction,
            DeveloperEventKindV1::AgentExecution => Self::AgentExecution,
            DeveloperEventKindV1::GitArtifact => Self::GitArtifact,
            DeveloperEventKindV1::BuildTest => Self::BuildTest,
            DeveloperEventKindV1::ModelUsage => Self::ModelUsage,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Authorization {
    pub revision: u32,
    pub project_id: String,
    pub policy_id: String,
    pub purpose: String,
    pub categories: BTreeSet<Category>,
    pub valid_from_ms: u64,
    pub retain_until_ms: u64,
}

impl Authorization {
    pub fn validate(&self, now_ms: u64) -> Result<(), Error> {
        bounded(&self.purpose)?;
        nonzero_digest(&self.project_id)?;
        nonzero_digest(&self.policy_id)?;
        if self.revision == 0
            || self.categories.is_empty()
            || self.valid_from_ms > now_ms
            || self.retain_until_ms <= now_ms
        {
            return Err(Error::InvalidAuthorization);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventInput {
    pub measurement: EventMeasurementInput,
    pub wall_start_ms: u64,
    pub wall_end_ms: u64,
    pub monotonic_start_ns: u64,
    pub monotonic_end_ns: u64,
    pub source_commitment: String,
    pub subject_commitment: String,
    pub payload_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventMeasurementInput {
    HumanInteraction { interaction_count: u32 },
    AgentExecution { run_count: u32 },
    GitArtifact { artifact_count: u32 },
    BuildTest { run_count: u32, test_count: u32 },
    ModelUsage { input_tokens: u64, output_tokens: u64, run_count: u32 },
}

impl From<EventMeasurementInput> for DeveloperEventMeasurementV1 {
    fn from(value: EventMeasurementInput) -> Self {
        match value {
            EventMeasurementInput::HumanInteraction { interaction_count } => {
                Self::HumanInteraction { interaction_count }
            }
            EventMeasurementInput::AgentExecution { run_count } => {
                Self::AgentExecution { run_count }
            }
            EventMeasurementInput::GitArtifact { artifact_count } => {
                Self::GitArtifact { artifact_count }
            }
            EventMeasurementInput::BuildTest { run_count, test_count } => {
                Self::BuildTest { run_count, test_count }
            }
            EventMeasurementInput::ModelUsage { input_tokens, output_tokens, run_count } => {
                Self::ModelUsage { input_tokens, output_tokens, run_count }
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedDeveloperEventV1 {
    pub event_envelope_hex: String,
    pub event_id: String,
    pub algorithm_revision: u16,
    pub collector_public_key_hex: String,
    pub signature_hex: String,
}

impl SignedDeveloperEventV1 {
    pub fn event(&self) -> Result<DeveloperEventV1, Error> {
        let bytes = hex::decode(&self.event_envelope_hex).map_err(|_| Error::InvalidEvent)?;
        decode_envelope(&bytes).map_err(|_| Error::InvalidEvent)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedActivityEpochV1 {
    pub epoch_envelope_hex: String,
    pub epoch_id: String,
}

impl SealedActivityEpochV1 {
    pub fn epoch(&self) -> Result<ActivityEpochV1, Error> {
        let bytes = hex::decode(&self.epoch_envelope_hex).map_err(|_| Error::InvalidEpoch)?;
        decode_envelope(&bytes).map_err(|_| Error::InvalidEpoch)
    }
}

pub trait EventSigner {
    fn sign(&self, payload: &[u8]) -> Vec<u8>;
    fn public_key(&self) -> Vec<u8>;
}

#[derive(Debug)]
pub struct Collector {
    path: PathBuf,
    authorization: Authorization,
    collector_id: Digest384,
    next_collector_sequence: u64,
    next_project_sequence: u64,
    previous_epoch_id: Digest384,
    paused: bool,
    pending_events: Vec<SignedDeveloperEventV1>,
}

impl Collector {
    pub fn create(
        path: impl Into<PathBuf>,
        authorization: Authorization,
        signer: &impl EventSigner,
        now_ms: u64,
    ) -> Result<Self, Error> {
        authorization.validate(now_ms)?;
        let collector = Self {
            path: path.into(),
            authorization,
            collector_id: collector_id(&signer.public_key()),
            next_collector_sequence: 1,
            next_project_sequence: 1,
            previous_epoch_id: Digest384::ZERO,
            paused: false,
            pending_events: Vec::new(),
        };
        collector.persist()?;
        Ok(collector)
    }

    pub fn open(path: impl Into<PathBuf>, now_ms: u64) -> Result<Self, Error> {
        let path = path.into();
        let state: Persisted = serde_json::from_slice(&fs::read(&path)?)?;
        state.authorization.validate(now_ms)?;
        if state.pending_events.len() > MAX_TELEMETRY_EVENTS {
            return Err(Error::Capacity);
        }
        let collector_id = nonzero_digest(&state.collector_id)?;
        let previous_epoch_id = decode_digest(&state.previous_epoch_id)?;
        validate_pending(
            &state.pending_events,
            collector_id,
            nonzero_digest(&state.authorization.project_id)?,
            state.authorization.revision,
            state.next_collector_sequence,
            state.next_project_sequence,
        )?;
        Ok(Self {
            path,
            authorization: state.authorization,
            collector_id,
            next_collector_sequence: state.next_collector_sequence,
            next_project_sequence: state.next_project_sequence,
            previous_epoch_id,
            paused: state.paused,
            pending_events: state.pending_events,
        })
    }

    pub fn pause(&mut self) -> Result<(), Error> {
        self.paused = true;
        self.persist()
    }

    pub fn resume(&mut self) -> Result<(), Error> {
        self.paused = false;
        self.persist()
    }

    pub fn record(
        &mut self,
        input: EventInput,
        signer: &impl EventSigner,
        now_ms: u64,
    ) -> Result<&SignedDeveloperEventV1, Error> {
        if self.paused {
            return Err(Error::Paused);
        }
        if now_ms < self.authorization.valid_from_ms
            || now_ms >= self.authorization.retain_until_ms
            || !self.authorization.categories.contains(&Category::from(
                DeveloperEventMeasurementV1::from(input.measurement.clone()).kind(),
            ))
        {
            return Err(Error::NotAuthorized);
        }
        if self.pending_events.len() >= MAX_TELEMETRY_EVENTS {
            return Err(Error::Capacity);
        }
        if input.wall_start_ms > input.wall_end_ms
            || input.wall_end_ms > now_ms
            || input.monotonic_start_ns > input.monotonic_end_ns
            || collector_id(&signer.public_key()) != self.collector_id
        {
            return Err(Error::InvalidEvent);
        }
        let event = DeveloperEventV1 {
            collector_id: self.collector_id,
            project_id: nonzero_digest(&self.authorization.project_id)?,
            collector_sequence: self.next_collector_sequence,
            project_sequence: self.next_project_sequence,
            wall_start_ms: input.wall_start_ms,
            wall_end_ms: input.wall_end_ms,
            monotonic_start_ns: input.monotonic_start_ns,
            monotonic_end_ns: input.monotonic_end_ns,
            measurement: input.measurement.into(),
            source_commitment: nonzero_digest(&input.source_commitment)?,
            subject_commitment: nonzero_digest(&input.subject_commitment)?,
            payload_commitment: nonzero_digest(&input.payload_commitment)?,
            authorization_revision: self.authorization.revision,
        };
        event.validate().map_err(|_| Error::InvalidEvent)?;
        let event_id = event.event_id().map_err(|_| Error::InvalidEvent)?;
        let signed = SignedDeveloperEventV1 {
            event_envelope_hex: hex::encode(
                encode_envelope(&event).map_err(|_| Error::InvalidEvent)?,
            ),
            event_id: hex::encode(event_id.as_bytes()),
            algorithm_revision: ML_DSA_ALGORITHM_REVISION,
            collector_public_key_hex: hex::encode(signer.public_key()),
            signature_hex: hex::encode(signer.sign(&signature_payload(event_id))),
        };
        verify_event(&signed)?;
        self.pending_events.push(signed);
        if let Err(error) = self.persist_with_next_sequences() {
            self.pending_events.pop();
            return Err(error);
        }
        self.next_collector_sequence += 1;
        self.next_project_sequence += 1;
        Ok(self.pending_events.last().expect("event was appended"))
    }

    pub fn seal_epoch(&mut self) -> Result<SealedActivityEpochV1, Error> {
        let events = self
            .pending_events
            .iter()
            .map(SignedDeveloperEventV1::event)
            .collect::<Result<Vec<_>, _>>()?;
        let first = events.first().ok_or(Error::EmptyEpoch)?;
        let last = events.last().ok_or(Error::EmptyEpoch)?;
        let event_ids = events
            .iter()
            .map(|event| event.event_id().map_err(|_| Error::InvalidEvent))
            .collect::<Result<Vec<_>, _>>()?;
        let epoch = ActivityEpochV1 {
            collector_id: self.collector_id,
            project_id: nonzero_digest(&self.authorization.project_id)?,
            first_collector_sequence: first.collector_sequence,
            last_collector_sequence: last.collector_sequence,
            first_project_sequence: first.project_sequence,
            last_project_sequence: last.project_sequence,
            event_count: u32::try_from(events.len()).map_err(|_| Error::Capacity)?,
            wall_start_ms: events.iter().map(|event| event.wall_start_ms).min().unwrap(),
            wall_end_ms: events.iter().map(|event| event.wall_end_ms).max().unwrap(),
            monotonic_start_ns: events.iter().map(|event| event.monotonic_start_ns).min().unwrap(),
            monotonic_end_ns: events.iter().map(|event| event.monotonic_end_ns).max().unwrap(),
            event_root: telemetry_merkle_root(&event_ids).map_err(|_| Error::InvalidEpoch)?,
            previous_epoch_id: self.previous_epoch_id,
            authorization_revision: self.authorization.revision,
            policy_id: nonzero_digest(&self.authorization.policy_id)?,
        };
        epoch.validate().map_err(|_| Error::InvalidEpoch)?;
        let epoch_id = epoch.epoch_id().map_err(|_| Error::InvalidEpoch)?;
        let sealed = SealedActivityEpochV1 {
            epoch_envelope_hex: hex::encode(
                encode_envelope(&epoch).map_err(|_| Error::InvalidEpoch)?,
            ),
            epoch_id: hex::encode(epoch_id.as_bytes()),
        };
        let prior_events = core::mem::take(&mut self.pending_events);
        let prior_epoch_id = self.previous_epoch_id;
        self.previous_epoch_id = epoch_id;
        if let Err(error) = self.persist() {
            self.pending_events = prior_events;
            self.previous_epoch_id = prior_epoch_id;
            return Err(error);
        }
        Ok(sealed)
    }

    pub fn export(&self, destination: impl AsRef<Path>) -> Result<(), Error> {
        atomic_write(destination.as_ref(), &serde_json::to_vec_pretty(&self.pending_events)?)?;
        Ok(())
    }

    pub fn purge_expired(&mut self, now_ms: u64) -> Result<usize, Error> {
        if now_ms < self.authorization.retain_until_ms {
            return Ok(0);
        }
        let removed = self.pending_events.len();
        self.pending_events.clear();
        self.persist()?;
        Ok(removed)
    }

    pub fn events(&self) -> &[SignedDeveloperEventV1] {
        &self.pending_events
    }

    fn persist_with_next_sequences(&self) -> Result<(), Error> {
        self.persist_values(self.next_collector_sequence + 1, self.next_project_sequence + 1)
    }

    fn persist(&self) -> Result<(), Error> {
        self.persist_values(self.next_collector_sequence, self.next_project_sequence)
    }

    fn persist_values(
        &self,
        next_collector_sequence: u64,
        next_project_sequence: u64,
    ) -> Result<(), Error> {
        let state = Persisted {
            authorization: self.authorization.clone(),
            collector_id: hex::encode(self.collector_id.as_bytes()),
            next_collector_sequence,
            next_project_sequence,
            previous_epoch_id: hex::encode(self.previous_epoch_id.as_bytes()),
            paused: self.paused,
            pending_events: self.pending_events.clone(),
        };
        atomic_write(&self.path, &serde_json::to_vec_pretty(&state)?)?;
        Ok(())
    }
}

pub fn verify_event(signed: &SignedDeveloperEventV1) -> Result<(), Error> {
    if signed.algorithm_revision != ML_DSA_ALGORITHM_REVISION {
        return Err(Error::InvalidSignature);
    }
    let event = signed.event()?;
    let event_id = event.event_id().map_err(|_| Error::InvalidEvent)?;
    if signed.event_id != hex::encode(event_id.as_bytes()) {
        return Err(Error::InvalidEvent);
    }
    let public_key =
        hex::decode(&signed.collector_public_key_hex).map_err(|_| Error::InvalidKey)?;
    if collector_id(&public_key) != event.collector_id {
        return Err(Error::InvalidKey);
    }
    let key: EncodedVerifyingKey<MlDsa44> = public_key.try_into().map_err(|_| Error::InvalidKey)?;
    let signature_bytes =
        hex::decode(&signed.signature_hex).map_err(|_| Error::InvalidSignature)?;
    let signature: EncodedSignature<MlDsa44> =
        signature_bytes.as_slice().try_into().map_err(|_| Error::InvalidSignature)?;
    let key = VerifyingKey::<MlDsa44>::decode(&key);
    let signature = Signature::<MlDsa44>::decode(&signature).ok_or(Error::InvalidSignature)?;
    key.verify(&signature_payload(event_id), &signature).map_err(|_| Error::InvalidSignature)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Persisted {
    authorization: Authorization,
    collector_id: String,
    next_collector_sequence: u64,
    next_project_sequence: u64,
    previous_epoch_id: String,
    paused: bool,
    pending_events: Vec<SignedDeveloperEventV1>,
}

fn validate_pending(
    events: &[SignedDeveloperEventV1],
    collector_id: Digest384,
    project_id: Digest384,
    authorization_revision: u32,
    next_collector_sequence: u64,
    next_project_sequence: u64,
) -> Result<(), Error> {
    let collector_start =
        next_collector_sequence.checked_sub(events.len() as u64).ok_or(Error::InvalidChain)?;
    let project_start =
        next_project_sequence.checked_sub(events.len() as u64).ok_or(Error::InvalidChain)?;
    for (index, signed) in events.iter().enumerate() {
        verify_event(signed)?;
        let event = signed.event()?;
        let offset = index as u64;
        if event.collector_id != collector_id
            || event.project_id != project_id
            || event.authorization_revision != authorization_revision
            || event.collector_sequence != collector_start + offset
            || event.project_sequence != project_start + offset
        {
            return Err(Error::InvalidChain);
        }
    }
    Ok(())
}

fn collector_id(public_key: &[u8]) -> Digest384 {
    let mut hasher = Sha3_384::new();
    hasher.update(COLLECTOR_KEY_DOMAIN);
    hasher.update(ML_DSA_ALGORITHM_REVISION.to_be_bytes());
    hasher.update(public_key);
    Digest384::new(hasher.finalize().into())
}

fn signature_payload(event_id: Digest384) -> Vec<u8> {
    let mut payload = Vec::with_capacity(EVENT_SIGNATURE_DOMAIN.len() + 2 + 48);
    payload.extend_from_slice(EVENT_SIGNATURE_DOMAIN);
    payload.extend_from_slice(&ML_DSA_ALGORITHM_REVISION.to_be_bytes());
    payload.extend_from_slice(event_id.as_bytes());
    payload
}

fn bounded(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > MAX_LABEL_BYTES || value.chars().any(char::is_control) {
        return Err(Error::InvalidText);
    }
    Ok(())
}

fn nonzero_digest(value: &str) -> Result<Digest384, Error> {
    let digest = decode_digest(value)?;
    if digest == Digest384::ZERO {
        return Err(Error::InvalidDigest);
    }
    Ok(digest)
}

fn decode_digest(value: &str) -> Result<Digest384, Error> {
    let bytes: [u8; 48] = hex::decode(value)
        .map_err(|_| Error::InvalidDigest)?
        .try_into()
        .map_err(|_| Error::InvalidDigest)?;
    Ok(Digest384::new(bytes))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    let mut file = File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Json(serde_json::Error),
    InvalidAuthorization,
    InvalidEvent,
    InvalidEpoch,
    InvalidDigest,
    InvalidText,
    NotAuthorized,
    Paused,
    Capacity,
    EmptyEpoch,
    InvalidChain,
    InvalidKey,
    InvalidSignature,
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{Keypair, Seed, Signer, SigningKey, signature::SignatureEncoding};
    use tempfile::tempdir;

    struct TestSigner(SigningKey<MlDsa44>);
    impl EventSigner for TestSigner {
        fn sign(&self, payload: &[u8]) -> Vec<u8> {
            self.0.sign(payload).to_bytes().to_vec()
        }
        fn public_key(&self) -> Vec<u8> {
            self.0.verifying_key().encode().as_slice().to_vec()
        }
    }

    fn d(byte: u8) -> String {
        hex::encode([byte; 48])
    }
    fn authorization() -> Authorization {
        Authorization {
            revision: 7,
            project_id: d(2),
            policy_id: d(3),
            purpose: "developer contribution proof".into(),
            categories: [Category::BuildTest].into_iter().collect(),
            valid_from_ms: 1,
            retain_until_ms: 10_000,
        }
    }
    fn input(index: u64) -> EventInput {
        EventInput {
            measurement: EventMeasurementInput::BuildTest {
                run_count: 1,
                test_count: u32::try_from(index).unwrap(),
            },
            wall_start_ms: 100 + index,
            wall_end_ms: 200 + index,
            monotonic_start_ns: 1_000 + index * 20,
            monotonic_end_ns: 1_010 + index * 20,
            source_commitment: d(4),
            subject_commitment: d(5),
            payload_commitment: d(index as u8 + 5),
        }
    }
    fn setup() -> (tempfile::TempDir, PathBuf, TestSigner) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("collector.json");
        let signer = TestSigner(SigningKey::from_seed(&Seed::from([7; 32])));
        (directory, path, signer)
    }

    #[test]
    fn records_canonical_events_and_persists_both_sequences() {
        let (_dir, path, signer) = setup();
        let mut collector = Collector::create(&path, authorization(), &signer, 1).unwrap();
        collector.record(input(1), &signer, 1_000).unwrap();
        collector.record(input(2), &signer, 1_000).unwrap();
        let reopened = Collector::open(path, 1_000).unwrap();
        let first = reopened.events()[0].event().unwrap();
        let second = reopened.events()[1].event().unwrap();
        assert_eq!((first.collector_sequence, first.project_sequence), (1, 1));
        assert_eq!((second.collector_sequence, second.project_sequence), (2, 2));
        assert_eq!(first.duration_ns(), 10);
    }

    #[test]
    fn sealing_advances_canonical_epoch_lineage_across_restart() {
        let (_dir, path, signer) = setup();
        let mut collector = Collector::create(&path, authorization(), &signer, 1).unwrap();
        collector.record(input(1), &signer, 1_000).unwrap();
        collector.record(input(2), &signer, 1_000).unwrap();
        let first = collector.seal_epoch().unwrap();
        let first_id = decode_digest(&first.epoch_id).unwrap();
        let mut reopened = Collector::open(&path, 1_000).unwrap();
        reopened.record(input(3), &signer, 1_000).unwrap();
        let second = reopened.seal_epoch().unwrap().epoch().unwrap();
        assert_eq!(second.previous_epoch_id, first_id);
        assert_eq!((second.first_collector_sequence, second.first_project_sequence), (3, 3));
    }

    #[test]
    fn wall_clock_does_not_determine_duration() {
        let (_dir, path, signer) = setup();
        let mut collector = Collector::create(path, authorization(), &signer, 1).unwrap();
        let mut event = input(1);
        event.wall_start_ms = 10;
        event.wall_end_ms = 900;
        event.monotonic_start_ns = 100;
        event.monotonic_end_ns = 107;
        collector.record(event, &signer, 1_000).unwrap();
        assert_eq!(collector.events()[0].event().unwrap().duration_ns(), 7);
    }

    #[test]
    fn rejects_tampering_wrong_signer_and_inverted_monotonic_range() {
        let (_dir, path, signer) = setup();
        let other = TestSigner(SigningKey::from_seed(&Seed::from([8; 32])));
        let mut collector = Collector::create(&path, authorization(), &signer, 1).unwrap();
        assert!(matches!(collector.record(input(1), &other, 1_000), Err(Error::InvalidEvent)));
        let mut inverted = input(1);
        inverted.monotonic_end_ns = inverted.monotonic_start_ns - 1;
        assert!(matches!(collector.record(inverted, &signer, 1_000), Err(Error::InvalidEvent)));
        collector.record(input(1), &signer, 1_000).unwrap();
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        state["pending_events"][0]["event_id"] = d(9).into();
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(Collector::open(path, 1_000).is_err());
    }

    #[test]
    fn pause_and_authorization_are_fail_closed() {
        let (_dir, path, signer) = setup();
        let mut collector = Collector::create(path, authorization(), &signer, 1).unwrap();
        collector.pause().unwrap();
        assert!(matches!(collector.record(input(1), &signer, 1_000), Err(Error::Paused)));
    }

    #[test]
    fn fixed_seed_reproduces_the_published_canonical_vector() {
        let published: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testing/vectors/developer-telemetry-canonical-v1.json"
        ))
        .unwrap();
        let (_dir, path, signer) = setup();
        let mut collector = Collector::create(path, authorization(), &signer, 1).unwrap();
        for index in 1..=3 {
            collector.record(input(index), &signer, 1_000).unwrap();
        }
        assert_eq!(published["events"], serde_json::to_value(collector.events()).unwrap());
        assert_eq!(
            published["epoch"],
            serde_json::to_value(collector.seal_epoch().unwrap()).unwrap()
        );
    }
}
