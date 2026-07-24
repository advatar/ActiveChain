use crate::{NtzsEndpoint, NtzsRequest, commitment};
use activechain_payment_types::PaymentAttemptId;
use activechain_protocol_types::Digest384;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{fs::File, io::Write, path::Path};

const MAX_ATTEMPTS: usize = 65_535;
const SNAPSHOT_MAGIC: &[u8; 8] = b"ACNZAT01";
const SNAPSHOT_TAG_BYTES: usize = 48;
const ENTRY_BYTES: usize = 48 + 1 + 48 + 1 + 1 + 48;
const REQUEST_DOMAIN: &[u8] = b"ACTIVECHAIN-NTZS-ATTEMPT-REQUEST-V1";
const SNAPSHOT_DOMAIN: &[u8] = b"ACTIVECHAIN-NTZS-ATTEMPT-SNAPSHOT-V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NtzsAttemptPhase {
    /// Exact request is durable and has not crossed the ambiguous network boundary.
    Prepared = 0,
    /// The connector persisted intent to send before calling transport.
    MayHaveReachedProvider = 1,
    /// A response or reconciliation bound an immutable provider reference.
    ProviderReferenceBound = 2,
}

impl NtzsAttemptPhase {
    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Prepared),
            1 => Some(Self::MayHaveReachedProvider),
            2 => Some(Self::ProviderReferenceBound),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptDispatchDecision {
    /// The exact prepared request may cross the transport boundary once.
    Ready,
    /// A prior crash/timeout may have followed dispatch; reconcile rather than resend.
    Reconcile,
    /// The provider reference is already bound; do not send.
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AttemptRecord {
    attempt: PaymentAttemptId,
    endpoint: NtzsEndpoint,
    request_commitment: Digest384,
    phase: NtzsAttemptPhase,
    provider_reference_commitment: Option<Digest384>,
}

/// Crash-safe connector-owned idempotency barrier for provider attempts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NtzsAttemptJournal {
    attempts: Vec<AttemptRecord>,
}

impl NtzsAttemptJournal {
    #[must_use]
    pub fn len(&self) -> usize {
        self.attempts.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attempts.is_empty()
    }

    pub fn prepare_durable(
        &mut self,
        attempt: PaymentAttemptId,
        request: &NtzsRequest,
        path: &Path,
    ) -> Result<bool, AttemptJournalError> {
        let mut next = self.clone();
        let changed = next.prepare(attempt, request)?;
        if changed {
            next.save_atomic(path)?;
            *self = next;
        }
        Ok(changed)
    }

    /// Persists the ambiguous boundary before the caller invokes transport.
    pub fn mark_may_have_reached_provider_durable(
        &mut self,
        attempt: PaymentAttemptId,
        path: &Path,
    ) -> Result<(), AttemptJournalError> {
        let mut next = self.clone();
        let record = next.record_mut(attempt)?;
        if record.phase != NtzsAttemptPhase::Prepared {
            return Err(AttemptJournalError::InvalidTransition);
        }
        record.phase = NtzsAttemptPhase::MayHaveReachedProvider;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    /// Binds the first authenticated response/reconciliation reference; exact replay is a no-op.
    pub fn bind_provider_reference_durable(
        &mut self,
        attempt: PaymentAttemptId,
        provider_reference_commitment: Digest384,
        path: &Path,
    ) -> Result<bool, AttemptJournalError> {
        if provider_reference_commitment == Digest384::ZERO {
            return Err(AttemptJournalError::InvalidReference);
        }
        let mut next = self.clone();
        let record = next.record_mut(attempt)?;
        let changed = match (record.phase, record.provider_reference_commitment) {
            (NtzsAttemptPhase::MayHaveReachedProvider, None) => {
                record.phase = NtzsAttemptPhase::ProviderReferenceBound;
                record.provider_reference_commitment = Some(provider_reference_commitment);
                true
            }
            (NtzsAttemptPhase::ProviderReferenceBound, Some(existing))
                if existing == provider_reference_commitment =>
            {
                false
            }
            _ => return Err(AttemptJournalError::InvalidTransition),
        };
        if changed {
            next.save_atomic(path)?;
            *self = next;
        }
        Ok(changed)
    }

    pub fn dispatch_decision(
        &self,
        attempt: PaymentAttemptId,
    ) -> Result<AttemptDispatchDecision, AttemptJournalError> {
        let record = self.record(attempt)?;
        Ok(match record.phase {
            NtzsAttemptPhase::Prepared => AttemptDispatchDecision::Ready,
            NtzsAttemptPhase::MayHaveReachedProvider => AttemptDispatchDecision::Reconcile,
            NtzsAttemptPhase::ProviderReferenceBound => AttemptDispatchDecision::Complete,
        })
    }

    pub fn provider_reference_commitment(
        &self,
        attempt: PaymentAttemptId,
    ) -> Result<Option<Digest384>, AttemptJournalError> {
        Ok(self.record(attempt)?.provider_reference_commitment)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), AttemptJournalError> {
        let body = self.encode_snapshot();
        let tag = snapshot_tag(&body);
        let parent = path.parent().ok_or(AttemptJournalError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| AttemptJournalError::Persistence)?;
        let name = path.file_name().ok_or(AttemptJournalError::Persistence)?.to_string_lossy();
        let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
        let result = (|| {
            let mut file =
                File::create(&temporary).map_err(|_| AttemptJournalError::Persistence)?;
            file.write_all(&body)
                .and_then(|_| file.write_all(&tag))
                .and_then(|_| file.sync_all())
                .map_err(|_| AttemptJournalError::Persistence)?;
            std::fs::rename(&temporary, path).map_err(|_| AttemptJournalError::Persistence)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| AttemptJournalError::Persistence)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }

    pub fn load(path: &Path) -> Result<Self, AttemptJournalError> {
        let bytes = std::fs::read(path).map_err(|_| AttemptJournalError::Persistence)?;
        if bytes.len() < SNAPSHOT_MAGIC.len() + 4 + SNAPSHOT_TAG_BYTES {
            return Err(AttemptJournalError::InvalidSnapshot);
        }
        let body_length = bytes.len() - SNAPSHOT_TAG_BYTES;
        if snapshot_tag(&bytes[..body_length]) != bytes[body_length..] {
            return Err(AttemptJournalError::InvalidSnapshot);
        }
        Self::decode_snapshot(&bytes[..body_length])
    }

    fn prepare(
        &mut self,
        attempt: PaymentAttemptId,
        request: &NtzsRequest,
    ) -> Result<bool, AttemptJournalError> {
        let request_commitment = request_commitment(request);
        match self.attempts.binary_search_by_key(&attempt, |record| record.attempt) {
            Ok(index) => {
                let existing = self.attempts[index];
                if existing.endpoint == request.endpoint()
                    && existing.request_commitment == request_commitment
                {
                    Ok(false)
                } else {
                    Err(AttemptJournalError::IdempotencyConflict)
                }
            }
            Err(index) => {
                if self.attempts.len() == MAX_ATTEMPTS {
                    return Err(AttemptJournalError::Capacity);
                }
                self.attempts.insert(
                    index,
                    AttemptRecord {
                        attempt,
                        endpoint: request.endpoint(),
                        request_commitment,
                        phase: NtzsAttemptPhase::Prepared,
                        provider_reference_commitment: None,
                    },
                );
                Ok(true)
            }
        }
    }

    fn record(&self, attempt: PaymentAttemptId) -> Result<&AttemptRecord, AttemptJournalError> {
        self.attempts
            .binary_search_by_key(&attempt, |record| record.attempt)
            .map(|index| &self.attempts[index])
            .map_err(|_| AttemptJournalError::UnknownAttempt)
    }

    fn record_mut(
        &mut self,
        attempt: PaymentAttemptId,
    ) -> Result<&mut AttemptRecord, AttemptJournalError> {
        self.attempts
            .binary_search_by_key(&attempt, |record| record.attempt)
            .map(|index| &mut self.attempts[index])
            .map_err(|_| AttemptJournalError::UnknownAttempt)
    }

    fn encode_snapshot(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(SNAPSHOT_MAGIC.len() + 4 + self.attempts.len() * ENTRY_BYTES);
        bytes.extend_from_slice(SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&(self.attempts.len() as u32).to_be_bytes());
        for record in &self.attempts {
            bytes.extend_from_slice(record.attempt.digest().as_bytes());
            bytes.push(record.endpoint as u8);
            bytes.extend_from_slice(record.request_commitment.as_bytes());
            bytes.push(record.phase as u8);
            match record.provider_reference_commitment {
                Some(reference) => {
                    bytes.push(1);
                    bytes.extend_from_slice(reference.as_bytes());
                }
                None => {
                    bytes.push(0);
                    bytes.extend_from_slice(&[0; 48]);
                }
            }
        }
        bytes
    }

    fn decode_snapshot(bytes: &[u8]) -> Result<Self, AttemptJournalError> {
        if bytes.get(..SNAPSHOT_MAGIC.len()) != Some(SNAPSHOT_MAGIC.as_slice()) {
            return Err(AttemptJournalError::InvalidSnapshot);
        }
        let count_bytes: [u8; 4] = bytes
            .get(SNAPSHOT_MAGIC.len()..SNAPSHOT_MAGIC.len() + 4)
            .ok_or(AttemptJournalError::InvalidSnapshot)?
            .try_into()
            .map_err(|_| AttemptJournalError::InvalidSnapshot)?;
        let count = u32::from_be_bytes(count_bytes) as usize;
        if count > MAX_ATTEMPTS || bytes.len() != SNAPSHOT_MAGIC.len() + 4 + count * ENTRY_BYTES {
            return Err(AttemptJournalError::InvalidSnapshot);
        }
        let mut attempts = Vec::with_capacity(count);
        let mut cursor = SNAPSHOT_MAGIC.len() + 4;
        for _ in 0..count {
            let attempt_bytes: [u8; 48] = bytes[cursor..cursor + 48]
                .try_into()
                .map_err(|_| AttemptJournalError::InvalidSnapshot)?;
            cursor += 48;
            let endpoint = NtzsEndpoint::from_tag(bytes[cursor])
                .ok_or(AttemptJournalError::InvalidSnapshot)?;
            cursor += 1;
            let request_bytes: [u8; 48] = bytes[cursor..cursor + 48]
                .try_into()
                .map_err(|_| AttemptJournalError::InvalidSnapshot)?;
            cursor += 48;
            let phase = NtzsAttemptPhase::from_tag(bytes[cursor])
                .ok_or(AttemptJournalError::InvalidSnapshot)?;
            cursor += 1;
            let reference_flag = bytes[cursor];
            cursor += 1;
            let reference_bytes: [u8; 48] = bytes[cursor..cursor + 48]
                .try_into()
                .map_err(|_| AttemptJournalError::InvalidSnapshot)?;
            cursor += 48;

            let attempt = PaymentAttemptId::new(Digest384::new(attempt_bytes))
                .map_err(|_| AttemptJournalError::InvalidSnapshot)?;
            let request_commitment = Digest384::new(request_bytes);
            if request_commitment == Digest384::ZERO {
                return Err(AttemptJournalError::InvalidSnapshot);
            }
            let provider_reference_commitment = match reference_flag {
                0 if reference_bytes == [0; 48] => None,
                1 if reference_bytes != [0; 48] => Some(Digest384::new(reference_bytes)),
                _ => return Err(AttemptJournalError::InvalidSnapshot),
            };
            if (phase == NtzsAttemptPhase::ProviderReferenceBound)
                != provider_reference_commitment.is_some()
            {
                return Err(AttemptJournalError::InvalidSnapshot);
            }
            let record = AttemptRecord {
                attempt,
                endpoint,
                request_commitment,
                phase,
                provider_reference_commitment,
            };
            if attempts
                .last()
                .is_some_and(|previous: &AttemptRecord| previous.attempt >= record.attempt)
            {
                return Err(AttemptJournalError::InvalidSnapshot);
            }
            attempts.push(record);
        }
        Ok(Self { attempts })
    }
}

fn request_commitment(request: &NtzsRequest) -> Digest384 {
    let endpoint = [request.endpoint() as u8];
    let idempotency = request.idempotency_key().unwrap_or_default().as_bytes();
    commitment(REQUEST_DOMAIN, &[&endpoint, request.body(), idempotency])
}

fn snapshot_tag(bytes: &[u8]) -> [u8; SNAPSHOT_TAG_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(SNAPSHOT_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    let mut output = [0_u8; SNAPSHOT_TAG_BYTES];
    hasher.finalize_xof().read(&mut output);
    output
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptJournalError {
    Capacity,
    IdempotencyConflict,
    InvalidReference,
    InvalidSnapshot,
    InvalidTransition,
    Persistence,
    UnknownAttempt,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn attempt(byte: u8) -> PaymentAttemptId {
        PaymentAttemptId::new(digest(byte)).unwrap()
    }

    fn request(body: &[u8]) -> NtzsRequest {
        NtzsRequest::new(NtzsEndpoint::CreateDeposit, body.to_vec(), None).unwrap()
    }

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "activebridge-ntzs-attempt-{name}-{}-{}.bin",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[test]
    fn exact_prepare_is_idempotent_but_changed_request_conflicts() {
        let path = path("prepare");
        let _ = std::fs::remove_file(&path);
        let mut journal = NtzsAttemptJournal::default();
        let first = request(br#"{"amountTzs":10000}"#);
        assert_eq!(journal.prepare_durable(attempt(1), &first, &path), Ok(true));
        assert_eq!(journal.prepare_durable(attempt(1), &first, &path), Ok(false));
        assert_eq!(
            journal.prepare_durable(attempt(1), &request(br#"{"amountTzs":10001}"#), &path,),
            Err(AttemptJournalError::IdempotencyConflict)
        );
        assert_eq!(
            journal.prepare_durable(
                attempt(1),
                &NtzsRequest::new(
                    NtzsEndpoint::CreateTransfer,
                    br#"{"amountTzs":10000}"#.to_vec(),
                    None,
                )
                .unwrap(),
                &path,
            ),
            Err(AttemptJournalError::IdempotencyConflict)
        );
        let ramp = NtzsRequest::new(
            NtzsEndpoint::RampOfframp,
            br#"{"quoteId":"fixture"}"#.to_vec(),
            Some("key-one".to_owned()),
        )
        .unwrap();
        assert_eq!(journal.prepare_durable(attempt(2), &ramp, &path), Ok(true));
        let changed_key = NtzsRequest::new(
            NtzsEndpoint::RampOfframp,
            br#"{"quoteId":"fixture"}"#.to_vec(),
            Some("key-two".to_owned()),
        )
        .unwrap();
        assert_eq!(
            journal.prepare_durable(attempt(2), &changed_key, &path),
            Err(AttemptJournalError::IdempotencyConflict)
        );
        assert_eq!(journal.len(), 2);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn dispatch_boundary_survives_restart_and_forces_reconciliation() {
        let path = path("dispatch");
        let _ = std::fs::remove_file(&path);
        let mut journal = NtzsAttemptJournal::default();
        journal.prepare_durable(attempt(1), &request(br#"{"amountTzs":10000}"#), &path).unwrap();
        assert_eq!(journal.dispatch_decision(attempt(1)), Ok(AttemptDispatchDecision::Ready));
        journal.mark_may_have_reached_provider_durable(attempt(1), &path).unwrap();
        let loaded = NtzsAttemptJournal::load(&path).unwrap();
        assert_eq!(loaded.dispatch_decision(attempt(1)), Ok(AttemptDispatchDecision::Reconcile));
        let mut loaded = loaded;
        assert_eq!(
            loaded.mark_may_have_reached_provider_durable(attempt(1), &path),
            Err(AttemptJournalError::InvalidTransition)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn first_provider_reference_is_immutable_and_completes_attempt() {
        let path = path("response");
        let _ = std::fs::remove_file(&path);
        let mut journal = NtzsAttemptJournal::default();
        journal.prepare_durable(attempt(1), &request(br#"{"amountTzs":10000}"#), &path).unwrap();
        journal.mark_may_have_reached_provider_durable(attempt(1), &path).unwrap();
        assert_eq!(journal.bind_provider_reference_durable(attempt(1), digest(9), &path), Ok(true));
        assert_eq!(
            journal.bind_provider_reference_durable(attempt(1), digest(9), &path),
            Ok(false)
        );
        assert_eq!(
            journal.bind_provider_reference_durable(attempt(1), digest(8), &path),
            Err(AttemptJournalError::InvalidTransition)
        );
        assert_eq!(journal.dispatch_decision(attempt(1)), Ok(AttemptDispatchDecision::Complete));
        assert_eq!(journal.provider_reference_commitment(attempt(1)), Ok(Some(digest(9))));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_persistence_does_not_advance_phase() {
        let snapshot_path = path("phase");
        let _ = std::fs::remove_file(&snapshot_path);
        let mut journal = NtzsAttemptJournal::default();
        journal
            .prepare_durable(attempt(1), &request(br#"{"amountTzs":10000}"#), &snapshot_path)
            .unwrap();
        let directory = path("directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        assert_eq!(
            journal.mark_may_have_reached_provider_durable(attempt(1), &directory),
            Err(AttemptJournalError::Persistence)
        );
        assert_eq!(journal.dispatch_decision(attempt(1)), Ok(AttemptDispatchDecision::Ready));
        std::fs::remove_file(snapshot_path).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn corruption_and_unknown_attempts_fail_closed() {
        let path = path("corruption");
        let _ = std::fs::remove_file(&path);
        let mut journal = NtzsAttemptJournal::default();
        journal.prepare_durable(attempt(2), &request(br#"{"amountTzs":10000}"#), &path).unwrap();
        journal.prepare_durable(attempt(1), &request(br#"{"amountTzs":20000}"#), &path).unwrap();
        assert_eq!(NtzsAttemptJournal::load(&path).unwrap(), journal);
        assert_eq!(journal.dispatch_decision(attempt(3)), Err(AttemptJournalError::UnknownAttempt));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[12] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(NtzsAttemptJournal::load(&path), Err(AttemptJournalError::InvalidSnapshot));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn published_attempt_decisions_match_the_state_machine() {
        let vectors = include_str!("../../../testing/ntzs-attempt-vectors-v1.tsv");
        for (line_number, line) in vectors.lines().enumerate().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 3, "malformed vector line {}", line_number + 1);
            let phase = match fields[0] {
                "prepared" => NtzsAttemptPhase::Prepared,
                "may_have_reached_provider" => NtzsAttemptPhase::MayHaveReachedProvider,
                "provider_reference_bound" => NtzsAttemptPhase::ProviderReferenceBound,
                value => panic!("unknown phase {value}"),
            };
            let decision = match phase {
                NtzsAttemptPhase::Prepared => AttemptDispatchDecision::Ready,
                NtzsAttemptPhase::MayHaveReachedProvider => AttemptDispatchDecision::Reconcile,
                NtzsAttemptPhase::ProviderReferenceBound => AttemptDispatchDecision::Complete,
            };
            let decision_name = match decision {
                AttemptDispatchDecision::Ready => "ready",
                AttemptDispatchDecision::Reconcile => "reconcile",
                AttemptDispatchDecision::Complete => "complete",
            };
            assert_eq!(decision_name, fields[1], "vector line {}", line_number + 1);
            assert_eq!(
                phase == NtzsAttemptPhase::Prepared,
                fields[2] == "yes",
                "vector line {}",
                line_number + 1
            );
        }
    }
}
