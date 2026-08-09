#![forbid(unsafe_code)]

//! Permissioned, local-first collection for Actum developer telemetry.
//!
//! The collector admits bounded metadata only. It never accepts prompts, source,
//! diffs, command output, environment values, or file contents.

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

pub const MAX_EVENTS: usize = 16_384;
pub const MAX_LABEL_BYTES: usize = 128;
pub const EVENT_TYPE_TAG: u16 = 0x01b2;
pub const EPOCH_TYPE_TAG: u16 = 0x01b3;
const TRANSCRIPT: &[u8] = b"ACTUM-DEVELOPER-TELEMETRY-V1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    HumanInteraction,
    AgentExecution,
    Git,
    BuildTest,
    ModelUsage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Authorization {
    pub revision: u64,
    pub project_commitment: String,
    pub purpose: String,
    pub categories: BTreeSet<Category>,
    pub retain_until_ms: u64,
}

impl Authorization {
    pub fn validate(&self, now_ms: u64) -> Result<(), Error> {
        bounded(&self.project_commitment)?;
        bounded(&self.purpose)?;
        if self.revision == 0 || self.categories.is_empty() || self.retain_until_ms <= now_ms {
            return Err(Error::InvalidAuthorization);
        }
        Ok(())
    }
}

/// Privacy-bounded metadata accepted from IDE, agent, Git, build, and model adapters.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventInput {
    pub category: Category,
    pub kind: String,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub units: u64,
    pub evidence_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedEvent {
    pub schema: String,
    pub project_commitment: String,
    pub policy_revision: u64,
    pub session_id: String,
    pub sequence: u64,
    pub category: Category,
    pub kind: String,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub units: u64,
    pub evidence_commitment: String,
    pub signer_public_key_hex: String,
    pub previous_event_hash: String,
    pub event_hash: String,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivityEpoch {
    pub schema: String,
    pub project_commitment: String,
    pub policy_revision: u64,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub event_count: u32,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub merkle_root: String,
}

pub trait EventSigner {
    fn sign(&self, payload: &[u8]) -> Vec<u8>;
    fn public_key(&self) -> Vec<u8>;
}

#[derive(Debug)]
pub struct Collector {
    path: PathBuf,
    authorization: Authorization,
    session_id: String,
    paused: bool,
    events: Vec<SignedEvent>,
}

impl Collector {
    pub fn create(
        path: impl Into<PathBuf>,
        authorization: Authorization,
        session_id: String,
        now_ms: u64,
    ) -> Result<Self, Error> {
        authorization.validate(now_ms)?;
        bounded(&session_id)?;
        let collector = Self {
            path: path.into(),
            authorization,
            session_id,
            paused: false,
            events: Vec::new(),
        };
        collector.persist()?;
        Ok(collector)
    }

    pub fn open(path: impl Into<PathBuf>, now_ms: u64) -> Result<Self, Error> {
        let path = path.into();
        let state: Persisted = serde_json::from_slice(&fs::read(&path)?)?;
        state.authorization.validate(now_ms)?;
        if state.events.len() > MAX_EVENTS {
            return Err(Error::Capacity);
        }
        validate_chain(&state.events)?;
        Ok(Self {
            path,
            authorization: state.authorization,
            session_id: state.session_id,
            paused: state.paused,
            events: state.events,
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

    pub fn replace_authorization(
        &mut self,
        authorization: Authorization,
        now_ms: u64,
    ) -> Result<(), Error> {
        authorization.validate(now_ms)?;
        if authorization.revision <= self.authorization.revision
            || authorization.project_commitment != self.authorization.project_commitment
            || !self.events.is_empty()
        {
            return Err(Error::InvalidAuthorization);
        }
        self.authorization = authorization;
        self.persist()
    }

    pub fn record(
        &mut self,
        input: EventInput,
        signer: &impl EventSigner,
        now_ms: u64,
    ) -> Result<&SignedEvent, Error> {
        if self.paused {
            return Err(Error::Paused);
        }
        if now_ms >= self.authorization.retain_until_ms
            || !self.authorization.categories.contains(&input.category)
        {
            return Err(Error::NotAuthorized);
        }
        if self.events.len() >= MAX_EVENTS {
            return Err(Error::Capacity);
        }
        bounded(&input.kind)?;
        bounded(&input.evidence_commitment)?;
        if input.ended_at_ms < input.started_at_ms || input.ended_at_ms > now_ms {
            return Err(Error::InvalidEvent);
        }
        let sequence = self.events.last().map_or(1, |event| event.sequence + 1);
        let previous_event_hash = self
            .events
            .last()
            .map_or_else(|| hex::encode([0_u8; 48]), |event| event.event_hash.clone());
        let mut event = SignedEvent {
            schema: "actum.dev.telemetry.event.v1".into(),
            project_commitment: self.authorization.project_commitment.clone(),
            policy_revision: self.authorization.revision,
            session_id: self.session_id.clone(),
            sequence,
            category: input.category,
            kind: input.kind,
            started_at_ms: input.started_at_ms,
            ended_at_ms: input.ended_at_ms,
            units: input.units,
            evidence_commitment: input.evidence_commitment,
            signer_public_key_hex: hex::encode(signer.public_key()),
            previous_event_hash,
            event_hash: String::new(),
            signature_hex: String::new(),
        };
        let payload = signing_payload(&event)?;
        event.event_hash = digest_hex(&payload);
        event.signature_hex = hex::encode(signer.sign(&payload));
        self.events.push(event);
        self.persist()?;
        Ok(self.events.last().expect("event was just appended"))
    }

    pub fn epoch(&self) -> Result<ActivityEpoch, Error> {
        let first = self.events.first().ok_or(Error::EmptyEpoch)?;
        let last = self.events.last().ok_or(Error::EmptyEpoch)?;
        let leaves = self
            .events
            .iter()
            .map(|event| decode_digest(&event.event_hash))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ActivityEpoch {
            schema: "actum.dev.telemetry.epoch.v1".into(),
            project_commitment: self.authorization.project_commitment.clone(),
            policy_revision: self.authorization.revision,
            first_sequence: first.sequence,
            last_sequence: last.sequence,
            event_count: u32::try_from(self.events.len()).map_err(|_| Error::Capacity)?,
            started_at_ms: first.started_at_ms,
            ended_at_ms: last.ended_at_ms,
            merkle_root: hex::encode(merkle_root(leaves)),
        })
    }

    pub fn export(&self, destination: impl AsRef<Path>) -> Result<(), Error> {
        atomic_write(destination.as_ref(), &serde_json::to_vec_pretty(&self.events)?)?;
        Ok(())
    }

    pub fn purge_expired(&mut self, now_ms: u64) -> Result<usize, Error> {
        if now_ms < self.authorization.retain_until_ms {
            return Ok(0);
        }
        let removed = self.events.len();
        self.events.clear();
        self.persist()?;
        Ok(removed)
    }

    pub fn delete(mut self) -> Result<(), Error> {
        self.events.clear();
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn events(&self) -> &[SignedEvent] {
        &self.events
    }

    fn persist(&self) -> Result<(), Error> {
        let state = Persisted {
            authorization: self.authorization.clone(),
            session_id: self.session_id.clone(),
            paused: self.paused,
            events: self.events.clone(),
        };
        atomic_write(&self.path, &serde_json::to_vec_pretty(&state)?)?;
        Ok(())
    }
}

pub fn verify_event(event: &SignedEvent, public_key: &[u8]) -> Result<(), Error> {
    let payload = signing_payload(event)?;
    if digest_hex(&payload) != event.event_hash {
        return Err(Error::InvalidChain);
    }
    let key: EncodedVerifyingKey<MlDsa44> = public_key.try_into().map_err(|_| Error::InvalidKey)?;
    let signature_bytes = hex::decode(&event.signature_hex).map_err(|_| Error::InvalidSignature)?;
    let signature: EncodedSignature<MlDsa44> =
        signature_bytes.as_slice().try_into().map_err(|_| Error::InvalidSignature)?;
    let key = VerifyingKey::<MlDsa44>::decode(&key);
    let signature = Signature::<MlDsa44>::decode(&signature).ok_or(Error::InvalidSignature)?;
    key.verify(&payload, &signature).map_err(|_| Error::InvalidSignature)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Persisted {
    authorization: Authorization,
    session_id: String,
    paused: bool,
    events: Vec<SignedEvent>,
}

fn signing_payload(event: &SignedEvent) -> Result<Vec<u8>, Error> {
    let mut unsigned = event.clone();
    unsigned.event_hash.clear();
    unsigned.signature_hex.clear();
    let json = serde_json::to_vec(&unsigned)?;
    let mut payload = Vec::with_capacity(TRANSCRIPT.len() + 4 + json.len());
    payload.extend_from_slice(TRANSCRIPT);
    payload.extend_from_slice(&EVENT_TYPE_TAG.to_be_bytes());
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&json);
    Ok(payload)
}

fn validate_chain(events: &[SignedEvent]) -> Result<(), Error> {
    let mut previous = hex::encode([0_u8; 48]);
    for (index, event) in events.iter().enumerate() {
        if event.sequence != u64::try_from(index + 1).map_err(|_| Error::Capacity)?
            || event.previous_event_hash != previous
            || digest_hex(&signing_payload(event)?) != event.event_hash
        {
            return Err(Error::InvalidChain);
        }
        let public_key =
            hex::decode(&event.signer_public_key_hex).map_err(|_| Error::InvalidKey)?;
        verify_event(event, &public_key)?;
        previous.clone_from(&event.event_hash);
    }
    Ok(())
}

fn merkle_root(mut level: Vec<[u8; 48]>) -> [u8; 48] {
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty level"));
        }
        level = level
            .chunks_exact(2)
            .map(|pair| {
                let mut transcript = Vec::with_capacity(98);
                transcript.extend_from_slice(&EPOCH_TYPE_TAG.to_be_bytes());
                transcript.extend_from_slice(&pair[0]);
                transcript.extend_from_slice(&pair[1]);
                digest(&transcript)
            })
            .collect();
    }
    level[0]
}

fn bounded(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > MAX_LABEL_BYTES || value.chars().any(char::is_control) {
        return Err(Error::InvalidText);
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> [u8; 48] {
    Sha3_384::digest(bytes).into()
}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(digest(bytes))
}

fn decode_digest(value: &str) -> Result<[u8; 48], Error> {
    hex::decode(value).map_err(|_| Error::InvalidChain)?.try_into().map_err(|_| Error::InvalidChain)
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

    fn authorization() -> Authorization {
        Authorization {
            revision: 1,
            project_commitment: "project-commitment".into(),
            purpose: "developer contribution proof".into(),
            categories: [Category::BuildTest].into_iter().collect(),
            retain_until_ms: 10_000,
        }
    }

    fn input(sequence: u64) -> EventInput {
        EventInput {
            category: Category::BuildTest,
            kind: "test.completed".into(),
            started_at_ms: 100 + sequence,
            ended_at_ms: 110 + sequence,
            units: 1,
            evidence_commitment: format!("evidence-{sequence}"),
        }
    }

    fn setup() -> (tempfile::TempDir, PathBuf, TestSigner) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("journal.json");
        let signer = TestSigner(SigningKey::from_seed(&Seed::from([7; 32])));
        (directory, path, signer)
    }

    #[test]
    fn records_authorized_signed_events_and_builds_stable_epoch() {
        let (_directory, path, signer) = setup();
        let mut collector =
            Collector::create(&path, authorization(), "session-1".into(), 1).unwrap();
        collector.record(input(1), &signer, 1_000).unwrap();
        collector.record(input(2), &signer, 1_000).unwrap();

        let reopened = Collector::open(&path, 1_000).unwrap();
        assert_eq!(collector.epoch().unwrap(), reopened.epoch().unwrap());
        for event in reopened.events() {
            verify_event(event, signer.0.verifying_key().encode().as_slice()).unwrap();
        }
    }

    #[test]
    fn rejects_unapproved_category_and_paused_collection() {
        let (_directory, path, signer) = setup();
        let mut collector =
            Collector::create(path, authorization(), "session-1".into(), 1).unwrap();
        let mut denied = input(1);
        denied.category = Category::ModelUsage;
        assert!(matches!(collector.record(denied, &signer, 1_000), Err(Error::NotAuthorized)));
        collector.pause().unwrap();
        assert!(matches!(collector.record(input(1), &signer, 1_000), Err(Error::Paused)));
    }

    #[test]
    fn rejects_tampered_journal_chain() {
        let (_directory, path, signer) = setup();
        let mut collector =
            Collector::create(&path, authorization(), "session-1".into(), 1).unwrap();
        collector.record(input(1), &signer, 1_000).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["events"][0]["units"] = 999.into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(Collector::open(path, 1_000), Err(Error::InvalidChain)));
    }

    #[test]
    fn rejects_a_valid_hash_chain_with_a_substituted_signature() {
        let (_directory, path, signer) = setup();
        let mut collector =
            Collector::create(&path, authorization(), "session-1".into(), 1).unwrap();
        collector.record(input(1), &signer, 1_000).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["events"][0]["signature_hex"] = hex::encode(vec![0_u8; 2_420]).into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(Collector::open(path, 1_000), Err(Error::InvalidSignature)));
    }

    #[test]
    fn expires_and_deletes_local_evidence() {
        let (directory, path, signer) = setup();
        let mut collector =
            Collector::create(&path, authorization(), "session-1".into(), 1).unwrap();
        collector.record(input(1), &signer, 1_000).unwrap();
        assert_eq!(collector.purge_expired(10_000).unwrap(), 1);
        assert!(collector.events().is_empty());
        collector.delete().unwrap();
        assert!(!path.exists());
        drop(directory);
    }

    #[test]
    fn policy_revision_must_increase_and_remain_project_bound() {
        let (_directory, path, _signer) = setup();
        let mut collector =
            Collector::create(path, authorization(), "session-1".into(), 1).unwrap();
        assert!(matches!(
            collector.replace_authorization(authorization(), 2),
            Err(Error::InvalidAuthorization)
        ));
        let mut replacement = authorization();
        replacement.revision = 2;
        replacement.project_commitment = "another-project".into();
        assert!(matches!(
            collector.replace_authorization(replacement, 2),
            Err(Error::InvalidAuthorization)
        ));

        let mut valid_replacement = authorization();
        valid_replacement.revision = 2;
        collector.replace_authorization(valid_replacement, 2).unwrap();
    }

    #[test]
    fn policy_revision_requires_a_new_journal_after_collection_starts() {
        let (_directory, path, signer) = setup();
        let mut collector =
            Collector::create(path, authorization(), "session-1".into(), 1).unwrap();
        collector.record(input(1), &signer, 1_000).unwrap();
        let mut replacement = authorization();
        replacement.revision = 2;
        assert!(matches!(
            collector.replace_authorization(replacement, 2),
            Err(Error::InvalidAuthorization)
        ));
    }
}
