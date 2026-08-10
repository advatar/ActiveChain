#![deny(unsafe_op_in_unsafe_fn)]

pub mod json_adapter;
pub mod status;

#[cfg(all(test, unix))]
mod storage_tests;

use activechain_application_primitives::{
    AnchorFinalizedEvidenceV1, SignedActumVerifierTrustBundleV1, TelemetryEpochAnchorRequestV1,
    TrustSignatureAlgorithmV1, TrustSignerSetV1, verify_trust_bundle_bootstrap,
    verify_trust_bundle_transition,
};
use activechain_canonical_codec::{CanonicalType, decode_envelope, encode_envelope};
use activechain_finality_types::FinalityCertificateBundle;
use activechain_pq_zk::{
    MAX_WORK_PROOF_BYTES, WORK_PROOF_SYSTEM_REVISION, WorkNonOverlapProof, work_image_id,
};
use activechain_protocol_types::{ChainId, Digest384};
use activechain_work_proof::{MAX_WORK_EVENTS, WorkClaimAggregateV1, WorkClaimPublicV1};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_384};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

pub const WORK_VERIFIER_REVISION: u32 = 1;
pub const MAX_WORK_PUBLIC_ENVELOPE_BYTES: usize = WorkClaimPublicV1::MAX_ENCODED_LEN + 9;
pub const MAX_OFFLINE_WORK_PROOF_BYTES: usize = MAX_WORK_PROOF_BYTES;
pub const MAX_SUBPROCESS_FRAME_BYTES: usize = MAX_WORK_PROOF_BYTES + 128 * 1024;
pub const MAX_CLAIMS: usize = 1_000_000;
pub const MAX_PAGE_SIZE: usize = 100;
const MAX_USAGE_ENTRIES: usize = 1_000_000;
const MAX_RATE_CLIENTS: usize = 100_000;
const IPC_MAGIC: &[u8; 8] = b"ACWPV1\0\0";
const USAGE_MAGIC: &[u8; 8] = b"ACUNV1\0\0";
const TRUST_MAGIC: &[u8; 8] = b"ACTBV1\0\0";
const USAGE_ENTRY_BYTES: usize = 48 * 3 + 4 + 8 * 2;
const MAX_USAGE_FILE_BYTES: u64 = (12 + MAX_USAGE_ENTRIES * USAGE_ENTRY_BYTES) as u64;
const MAX_TRUST_FILE_BYTES: u64 =
    (12 + SignedActumVerifierTrustBundleV1::MAX_ENCODED_LEN + 9) as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLifecycleV1 {
    ProofGenerated,
    Delivered,
    AnchorSubmitted,
    AnchorFinalized,
    AnchorRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationErrorCodeV1 {
    RateLimited,
    MalformedRequest,
    ClaimIdMismatch,
    ProofTooLarge,
    RelationRejected,
    VerifierUnavailable,
    VerifierTimeout,
    WrongChain,
    WrongGenesis,
    WrongImage,
    WrongPolicy,
    StaleTrust,
    InvalidAnchor,
    AnchorPending,
    AnchorRejected,
    UsageDoubleSpend,
    PersistenceUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationErrorV1 {
    pub code: VerificationErrorCodeV1,
    pub retryable: bool,
}

impl VerificationErrorV1 {
    const fn terminal(code: VerificationErrorCodeV1) -> Self {
        Self { code, retryable: false }
    }
    const fn retryable(code: VerificationErrorCodeV1) -> Self {
        Self { code, retryable: true }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum ExplorerAggregateV1 {
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
        artifact_set_commitment: String,
        evidence_root: String,
    },
}

impl From<WorkClaimAggregateV1> for ExplorerAggregateV1 {
    fn from(value: WorkClaimAggregateV1) -> Self {
        match value {
            WorkClaimAggregateV1::Attention { attributable_ms, interaction_count } => {
                Self::Attention { attributable_ms, interaction_count }
            }
            WorkClaimAggregateV1::Compute {
                agent_runtime_ms,
                model_input_tokens,
                model_output_tokens,
                normalized_model_units,
                run_count,
            } => Self::Compute {
                agent_runtime_ms,
                model_input_tokens,
                model_output_tokens,
                normalized_model_units,
                run_count,
            },
            WorkClaimAggregateV1::Contribution {
                artifact_count,
                artifact_set_commitment,
                evidence_root,
            } => Self::Contribution {
                artifact_count,
                artifact_set_commitment: digest_hex(artifact_set_commitment),
                evidence_root: digest_hex(evidence_root),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnchorFinalizedDtoV1 {
    pub statement_id: String,
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub checkpoint_bundle_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedClaimDtoV1 {
    pub claim_id: String,
    pub lifecycle: ProofLifecycleV1,
    pub relation_verified: bool,
    pub anchor_verified: bool,
    pub usage_verified: bool,
    pub idempotent: bool,
    pub chain_id: String,
    pub project_id: String,
    pub usage_domain: String,
    pub policy_id: String,
    pub policy_revision: u32,
    pub aggregate: ExplorerAggregateV1,
    pub anchor: AnchorFinalizedDtoV1,
    pub accepted_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimPageV1 {
    pub claims: Vec<ClaimSummaryDtoV1>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimSummaryDtoV1 {
    pub claim_id: String,
    pub lifecycle: ProofLifecycleV1,
    pub relation_verified: bool,
    pub anchor_verified: bool,
    pub usage_verified: bool,
    pub usage_domain: String,
    pub verifier_revision: u32,
    pub trust_bundle_sequence: u64,
    pub accepted_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageRegistrationV1 {
    Inserted,
    Idempotent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UsageEntry {
    usage_domain: Digest384,
    nullifier: Digest384,
    claim_id: Digest384,
    verifier_revision: u32,
    trust_sequence: u64,
    accepted_at_ms: u64,
}

#[derive(Default)]
struct UsageState {
    entries: BTreeMap<(Digest384, Digest384), UsageEntry>,
}

pub struct DurableUsageRegistry {
    path: PathBuf,
    state: Mutex<UsageState>,
}

impl DurableUsageRegistry {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, VerificationErrorV1> {
        let path = path.into();
        let state = if path.exists() {
            decode_usage(&read_bounded_regular_file(&path, MAX_USAGE_FILE_BYTES)?)?
        } else {
            UsageState::default()
        };
        Ok(Self { path, state: Mutex::new(state) })
    }

    pub fn register_all(
        &self,
        usage_domain: Digest384,
        nullifiers: &[Digest384],
        claim_id: Digest384,
        verifier_revision: u32,
        trust_sequence: u64,
        accepted_at_ms: u64,
    ) -> Result<UsageRegistrationV1, VerificationErrorV1> {
        if usage_domain == Digest384::ZERO
            || claim_id == Digest384::ZERO
            || nullifiers.is_empty()
            || nullifiers.len() > MAX_WORK_EVENTS
            || verifier_revision == 0
            || trust_sequence == 0
        {
            return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::MalformedRequest));
        }
        let mut canonical = nullifiers.to_vec();
        canonical.sort_unstable();
        if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::MalformedRequest));
        }
        let mut state = self.state.lock().map_err(|_| persistence(()))?;
        let existing_claim = state
            .entries
            .values()
            .filter(|entry| entry.claim_id == claim_id)
            .map(|entry| (entry.usage_domain, entry.nullifier))
            .collect::<Vec<_>>();
        if !existing_claim.is_empty() {
            let expected =
                canonical.iter().map(|nullifier| (usage_domain, *nullifier)).collect::<Vec<_>>();
            if existing_claim == expected {
                return Ok(UsageRegistrationV1::Idempotent);
            }
            return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::UsageDoubleSpend));
        }
        if canonical.iter().any(|nullifier| state.entries.contains_key(&(usage_domain, *nullifier)))
        {
            return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::UsageDoubleSpend));
        }
        if state.entries.len().saturating_add(canonical.len()) > MAX_USAGE_ENTRIES {
            return Err(persistence(()));
        }
        let mut candidate = UsageState { entries: state.entries.clone() };
        for nullifier in canonical {
            let entry = UsageEntry {
                usage_domain,
                nullifier,
                claim_id,
                verifier_revision,
                trust_sequence,
                accepted_at_ms,
            };
            candidate.entries.insert((usage_domain, nullifier), entry);
        }
        persist_atomic(&self.path, &encode_usage(&candidate))?;
        *state = candidate;
        Ok(UsageRegistrationV1::Inserted)
    }

    fn claim_entries(&self) -> Result<Vec<UsageEntry>, VerificationErrorV1> {
        let state = self.state.lock().map_err(|_| persistence(()))?;
        let mut seen = BTreeSet::new();
        Ok(state.entries.values().copied().filter(|entry| seen.insert(entry.claim_id)).collect())
    }
}

fn encode_usage(state: &UsageState) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12 + state.entries.len() * 172);
    bytes.extend_from_slice(USAGE_MAGIC);
    bytes.extend_from_slice(&(state.entries.len() as u32).to_be_bytes());
    for entry in state.entries.values() {
        bytes.extend_from_slice(entry.usage_domain.as_bytes());
        bytes.extend_from_slice(entry.nullifier.as_bytes());
        bytes.extend_from_slice(entry.claim_id.as_bytes());
        bytes.extend_from_slice(&entry.verifier_revision.to_be_bytes());
        bytes.extend_from_slice(&entry.trust_sequence.to_be_bytes());
        bytes.extend_from_slice(&entry.accepted_at_ms.to_be_bytes());
    }
    bytes
}

fn decode_usage(bytes: &[u8]) -> Result<UsageState, VerificationErrorV1> {
    if bytes.len() < 12 || &bytes[..8] != USAGE_MAGIC {
        return Err(persistence(()));
    }
    let count = u32::from_be_bytes(bytes[8..12].try_into().map_err(persistence)?) as usize;
    if count > MAX_USAGE_ENTRIES || bytes.len() != 12 + count * USAGE_ENTRY_BYTES {
        return Err(persistence(()));
    }
    let mut entries = BTreeMap::new();
    let mut cursor = 12;
    for _ in 0..count {
        let usage_domain = read_digest(bytes, &mut cursor)?;
        let nullifier = read_digest(bytes, &mut cursor)?;
        let claim_id = read_digest(bytes, &mut cursor)?;
        let verifier_revision = read_u32(bytes, &mut cursor)?;
        let trust_sequence = read_u64(bytes, &mut cursor)?;
        let accepted_at_ms = read_u64(bytes, &mut cursor)?;
        let entry = UsageEntry {
            usage_domain,
            nullifier,
            claim_id,
            verifier_revision,
            trust_sequence,
            accepted_at_ms,
        };
        if entries.insert((usage_domain, nullifier), entry).is_some() {
            return Err(persistence(()));
        }
    }
    Ok(UsageState { entries })
}

pub struct DurableTrustStore {
    path: PathBuf,
    bundle: Mutex<SignedActumVerifierTrustBundleV1>,
}

impl DurableTrustStore {
    pub fn bootstrap(
        path: impl Into<PathBuf>,
        bundle: SignedActumVerifierTrustBundleV1,
        signer_set: &TrustSignerSetV1,
        now_ms: u64,
        verify: &impl Fn(TrustSignatureAlgorithmV1, &[u8], Digest384, &[u8]) -> bool,
    ) -> Result<Self, VerificationErrorV1> {
        verify_trust_bundle_bootstrap(&bundle, signer_set, now_ms, verify)
            .map_err(|_| VerificationErrorV1::terminal(VerificationErrorCodeV1::StaleTrust))?;
        let path = path.into();
        persist_trust(&path, &bundle)?;
        Ok(Self { path, bundle: Mutex::new(bundle) })
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self, VerificationErrorV1> {
        let path = path.into();
        let bytes = read_bounded_regular_file(&path, MAX_TRUST_FILE_BYTES)?;
        if bytes.len() < 12 || &bytes[..8] != TRUST_MAGIC {
            return Err(persistence(()));
        }
        let length = u32::from_be_bytes(bytes[8..12].try_into().map_err(persistence)?) as usize;
        if length == 0 || length != bytes.len() - 12 {
            return Err(persistence(()));
        }
        let bundle = decode_envelope(&bytes[12..]).map_err(|_| persistence(()))?;
        Ok(Self { path, bundle: Mutex::new(bundle) })
    }

    pub fn transition(
        &self,
        next: SignedActumVerifierTrustBundleV1,
        current_set: &TrustSignerSetV1,
        activated_set: Option<&TrustSignerSetV1>,
        now_ms: u64,
        verify: &impl Fn(TrustSignatureAlgorithmV1, &[u8], Digest384, &[u8]) -> bool,
    ) -> Result<(), VerificationErrorV1> {
        let mut current = self.bundle.lock().map_err(|_| persistence(()))?;
        verify_trust_bundle_transition(&current, &next, current_set, activated_set, now_ms, verify)
            .map_err(|_| VerificationErrorV1::terminal(VerificationErrorCodeV1::StaleTrust))?;
        persist_trust(&self.path, &next)?;
        *current = next;
        Ok(())
    }

    pub fn accepted_bundle(&self) -> Result<SignedActumVerifierTrustBundleV1, VerificationErrorV1> {
        self.bundle.lock().map(|bundle| bundle.clone()).map_err(|_| persistence(()))
    }
}

fn persist_trust(
    path: &Path,
    bundle: &SignedActumVerifierTrustBundleV1,
) -> Result<(), VerificationErrorV1> {
    let envelope = encode_envelope(bundle).map_err(|_| persistence(()))?;
    let mut bytes = Vec::with_capacity(12 + envelope.len());
    bytes.extend_from_slice(TRUST_MAGIC);
    bytes.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&envelope);
    persist_atomic(path, &bytes)
}

pub trait RelationVerifier: Send + Sync {
    fn verify(&self, public: &WorkClaimPublicV1, proof: &[u8]) -> Result<(), VerificationErrorV1>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct InProcessRelationVerifier;

impl RelationVerifier for InProcessRelationVerifier {
    fn verify(&self, public: &WorkClaimPublicV1, proof: &[u8]) -> Result<(), VerificationErrorV1> {
        WorkNonOverlapProof::from_envelope_bytes(proof, public)
            .map(|_| ())
            .map_err(|_| VerificationErrorV1::terminal(VerificationErrorCodeV1::RelationRejected))
    }
}

pub struct SubprocessRelationVerifier {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
}

impl SubprocessRelationVerifier {
    pub fn new(program: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self { program: program.into(), args: Vec::new(), timeout }
    }
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }
}

impl RelationVerifier for SubprocessRelationVerifier {
    fn verify(&self, public: &WorkClaimPublicV1, proof: &[u8]) -> Result<(), VerificationErrorV1> {
        let frame = encode_ipc_request(public, proof)?;
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| {
                VerificationErrorV1::retryable(VerificationErrorCodeV1::VerifierUnavailable)
            })?;
        child
            .stdin
            .take()
            .ok_or_else(|| {
                VerificationErrorV1::retryable(VerificationErrorCodeV1::VerifierUnavailable)
            })?
            .write_all(&frame)
            .map_err(|_| {
                VerificationErrorV1::retryable(VerificationErrorCodeV1::VerifierUnavailable)
            })?;
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut output = Vec::new();
                    if let Some(mut stdout) = child.stdout.take() {
                        stdout.read_to_end(&mut output).map_err(|_| {
                            VerificationErrorV1::retryable(
                                VerificationErrorCodeV1::VerifierUnavailable,
                            )
                        })?;
                    }
                    return if status.success() && output == [0] {
                        Ok(())
                    } else {
                        Err(VerificationErrorV1::terminal(
                            VerificationErrorCodeV1::RelationRejected,
                        ))
                    };
                }
                Ok(None) if started.elapsed() < self.timeout => {
                    thread::sleep(Duration::from_millis(5))
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(VerificationErrorV1::retryable(
                        VerificationErrorCodeV1::VerifierTimeout,
                    ));
                }
                Err(_) => {
                    return Err(VerificationErrorV1::retryable(
                        VerificationErrorCodeV1::VerifierUnavailable,
                    ));
                }
            }
        }
    }
}

pub fn encode_ipc_request(
    public: &WorkClaimPublicV1,
    proof: &[u8],
) -> Result<Vec<u8>, VerificationErrorV1> {
    if proof.is_empty() || proof.len() > MAX_WORK_PROOF_BYTES {
        return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::ProofTooLarge));
    }
    let public = encode_envelope(public)
        .map_err(|_| VerificationErrorV1::terminal(VerificationErrorCodeV1::MalformedRequest))?;
    let total = 8 + 4 + 4 + public.len() + proof.len();
    if total > MAX_SUBPROCESS_FRAME_BYTES {
        return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::ProofTooLarge));
    }
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(IPC_MAGIC);
    frame.extend_from_slice(&(public.len() as u32).to_be_bytes());
    frame.extend_from_slice(&(proof.len() as u32).to_be_bytes());
    frame.extend_from_slice(&public);
    frame.extend_from_slice(proof);
    Ok(frame)
}

pub fn verify_ipc_request(frame: &[u8]) -> u8 {
    if frame.len() < 16 || frame.len() > MAX_SUBPROCESS_FRAME_BYTES || &frame[..8] != IPC_MAGIC {
        return 2;
    }
    let public_len = u32::from_be_bytes(match frame[8..12].try_into() {
        Ok(value) => value,
        Err(_) => return 2,
    }) as usize;
    let proof_len = u32::from_be_bytes(match frame[12..16].try_into() {
        Ok(value) => value,
        Err(_) => return 2,
    }) as usize;
    if proof_len == 0
        || proof_len > MAX_WORK_PROOF_BYTES
        || public_len > WorkClaimPublicV1::MAX_ENCODED_LEN + 9
        || 16usize.checked_add(public_len).and_then(|value| value.checked_add(proof_len))
            != Some(frame.len())
    {
        return 2;
    }
    let public = match decode_envelope::<WorkClaimPublicV1>(&frame[16..16 + public_len]) {
        Ok(public) => public,
        Err(_) => return 2,
    };
    match InProcessRelationVerifier.verify(&public, &frame[16 + public_len..]) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

pub struct VerifyWorkClaimRequestV1 {
    pub client_id: Digest384,
    pub claim_id: Digest384,
    pub public: WorkClaimPublicV1,
    pub proof_envelope: Vec<u8>,
    pub anchor_request: TelemetryEpochAnchorRequestV1,
    pub anchor_evidence: AnchorFinalizedEvidenceV1,
}

pub struct FixedWindowRateLimiter {
    maximum: u32,
    window_ms: u64,
    clients: Mutex<BTreeMap<Digest384, (u64, u32)>>,
}

impl FixedWindowRateLimiter {
    pub fn new(maximum: u32, window_ms: u64) -> Result<Self, VerificationErrorV1> {
        if maximum == 0 || window_ms == 0 {
            return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::MalformedRequest));
        }
        Ok(Self { maximum, window_ms, clients: Mutex::new(BTreeMap::new()) })
    }
    fn admit(&self, client: Digest384, now_ms: u64) -> Result<(), VerificationErrorV1> {
        let window = now_ms / self.window_ms;
        let mut clients = self.clients.lock().map_err(|_| persistence(()))?;
        clients.retain(|_, value| value.0 == window);
        if !clients.contains_key(&client) && clients.len() >= MAX_RATE_CLIENTS {
            return Err(VerificationErrorV1::retryable(VerificationErrorCodeV1::RateLimited));
        }
        let value = clients.entry(client).or_insert((window, 0));
        if value.0 != window {
            *value = (window, 0);
        }
        if value.1 >= self.maximum {
            return Err(VerificationErrorV1::retryable(VerificationErrorCodeV1::RateLimited));
        }
        value.1 += 1;
        Ok(())
    }
}

pub struct WorkProofVerificationService<R> {
    relation: R,
    trust: DurableTrustStore,
    usage: DurableUsageRegistry,
    rate_limiter: FixedWindowRateLimiter,
}

impl<R: RelationVerifier> WorkProofVerificationService<R> {
    pub fn new(
        relation: R,
        trust: DurableTrustStore,
        usage: DurableUsageRegistry,
        rate_limiter: FixedWindowRateLimiter,
    ) -> Self {
        Self { relation, trust, usage, rate_limiter }
    }

    pub fn verify(
        &self,
        request: &VerifyWorkClaimRequestV1,
        now_ms: u64,
    ) -> Result<VerifiedClaimDtoV1, VerificationErrorV1> {
        self.rate_limiter.admit(request.client_id, now_ms)?;
        if request.claim_id != derive_claim_id(&request.public, &request.proof_envelope)? {
            return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::ClaimIdMismatch));
        }
        let bundle = self.trust.accepted_bundle()?;
        verify_trust_bindings(&bundle, &request.public, now_ms)?;
        self.relation.verify(&request.public, &request.proof_envelope)?;
        let (finalized, anchor_reference) = verify_finalized_anchor_checkpoint(
            &bundle,
            &request.public,
            &request.anchor_request,
            &request.anchor_evidence,
        )?;
        let registration = self.usage.register_all(
            request.public.usage_domain,
            &request.public.usage_nullifiers,
            request.claim_id,
            WORK_VERIFIER_REVISION,
            bundle.body.bundle_sequence,
            now_ms,
        )?;
        Ok(VerifiedClaimDtoV1 {
            claim_id: digest_hex(request.claim_id),
            lifecycle: ProofLifecycleV1::AnchorFinalized,
            relation_verified: true,
            anchor_verified: true,
            usage_verified: true,
            idempotent: registration == UsageRegistrationV1::Idempotent,
            chain_id: digest_hex(request.public.chain_id),
            project_id: digest_hex(request.public.project_id),
            usage_domain: digest_hex(request.public.usage_domain),
            policy_id: digest_hex(request.public.policy_id),
            policy_revision: request.public.policy_revision,
            aggregate: request.public.aggregate.into(),
            anchor: AnchorFinalizedDtoV1 {
                statement_id: digest_hex(anchor_reference),
                finalized_height: finalized.finalized_height(),
                finalized_block_id: digest_hex(finalized.finalized_block()),
                checkpoint_bundle_id: digest_hex(bundle.bundle_id),
            },
            accepted_at_ms: now_ms,
        })
    }

    pub fn list_claims(
        &self,
        cursor: Option<Digest384>,
        limit: usize,
    ) -> Result<ClaimPageV1, VerificationErrorV1> {
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::MalformedRequest));
        }
        let mut entries = self.usage.claim_entries()?;
        entries.sort_by_key(|entry| entry.claim_id);
        let filtered =
            entries.into_iter().filter(|entry| cursor.is_none_or(|value| entry.claim_id > value));
        let selected = filtered.take(limit + 1).collect::<Vec<_>>();
        let has_more = selected.len() > limit;
        let claims = selected
            .iter()
            .take(limit)
            .map(|entry| ClaimSummaryDtoV1 {
                claim_id: digest_hex(entry.claim_id),
                lifecycle: ProofLifecycleV1::AnchorFinalized,
                relation_verified: true,
                anchor_verified: true,
                usage_verified: true,
                usage_domain: digest_hex(entry.usage_domain),
                verifier_revision: entry.verifier_revision,
                trust_bundle_sequence: entry.trust_sequence,
                accepted_at_ms: entry.accepted_at_ms,
            })
            .collect::<Vec<_>>();
        let next_cursor = has_more.then(|| digest_hex(selected[limit - 1].claim_id));
        Ok(ClaimPageV1 { claims, next_cursor })
    }
}

pub fn derive_claim_id(
    public: &WorkClaimPublicV1,
    proof: &[u8],
) -> Result<Digest384, VerificationErrorV1> {
    if proof.is_empty() || proof.len() > MAX_WORK_PROOF_BYTES {
        return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::ProofTooLarge));
    }
    let public = encode_envelope(public)
        .map_err(|_| VerificationErrorV1::terminal(VerificationErrorCodeV1::MalformedRequest))?;
    Ok(domain_hash(b"ACTUM-WORK-CLAIM-V1", &[&public, proof]))
}

pub fn work_proof_profile_id() -> Digest384 {
    domain_hash(b"ACTUM-WORK-PROOF-PROFILE-V1", &[activechain_pq_zk::PROFILE_ID.as_bytes()])
}

fn verify_trust_bindings(
    bundle: &SignedActumVerifierTrustBundleV1,
    public: &WorkClaimPublicV1,
    now_ms: u64,
) -> Result<(), VerificationErrorV1> {
    let body = &bundle.body;
    if now_ms < body.not_before_ms || now_ms > body.not_after_ms {
        return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::StaleTrust));
    }
    if body.chain_id != public.chain_id {
        return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::WrongChain));
    }
    if body.genesis_commitment != public.genesis {
        return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::WrongGenesis));
    }
    if body.risc0_image_id != work_image_id()
        || body.proof_system_revision != WORK_PROOF_SYSTEM_REVISION
        || body.proof_profile_id != work_proof_profile_id()
        || body.verifier_revision != WORK_VERIFIER_REVISION
    {
        return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::WrongImage));
    }
    if body.policy_id != public.policy_id || body.policy_revision != public.policy_revision {
        return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::WrongPolicy));
    }
    Ok(())
}

fn verify_anchor_public_bindings(
    public: &WorkClaimPublicV1,
    request: &TelemetryEpochAnchorRequestV1,
) -> Result<(), VerificationErrorV1> {
    let epoch = &request.epoch;
    if request.chain_id != public.chain_id
        || request.genesis_commitment != public.genesis
        || request.telemetry_schema_revision != public.telemetry_schema
        || epoch.collector_id != public.collector_id
        || epoch.project_id != public.project_id
        || epoch.event_root != public.epoch_root
        || epoch.event_count != public.epoch_event_count
        || epoch.authorization_revision != public.authorization_revision
        || epoch.policy_id != public.policy_id
        || public.first_sequence < epoch.first_project_sequence
        || public.last_sequence > epoch.last_project_sequence
        || public.interval_start_ms < epoch.wall_start_ms
        || public.interval_end_ms > epoch.wall_end_ms
    {
        return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::InvalidAnchor));
    }
    Ok(())
}

fn verify_finalized_anchor_checkpoint(
    bundle: &SignedActumVerifierTrustBundleV1,
    public: &WorkClaimPublicV1,
    request: &TelemetryEpochAnchorRequestV1,
    evidence: &AnchorFinalizedEvidenceV1,
) -> Result<(AnchorFinalizedEvidenceV1, Digest384), VerificationErrorV1> {
    verify_anchor_public_bindings(public, request)?;
    let statement = request
        .statement()
        .map_err(|_| VerificationErrorV1::terminal(VerificationErrorCodeV1::InvalidAnchor))?;
    let statement_bytes = encode_envelope(&statement)
        .map_err(|_| VerificationErrorV1::terminal(VerificationErrorCodeV1::InvalidAnchor))?;
    let evidence_bytes = encode_envelope(evidence)
        .map_err(|_| VerificationErrorV1::terminal(VerificationErrorCodeV1::InvalidAnchor))?;
    let finalized = activechain_verifier_api::verify_anchor_finalized_evidence(
        &evidence_bytes,
        &statement_bytes,
        ChainId::new(bundle.body.chain_id),
        bundle.body.genesis_commitment,
        u64::from(bundle.body.protocol_revision),
        bundle.body.verifier_revision,
    )
    .map_err(|_| VerificationErrorV1::terminal(VerificationErrorCodeV1::InvalidAnchor))?;
    let finality = decode_envelope::<FinalityCertificateBundle>(finalized.finality_proof())
        .map_err(|_| VerificationErrorV1::terminal(VerificationErrorCodeV1::InvalidAnchor))?;
    let header = finality.header();
    if bundle.body.checkpoint_height != finalized.finalized_height()
        || bundle.body.checkpoint_block_id != finalized.finalized_block()
        || bundle.body.checkpoint_state_root != header.inputs.post_state.root()
        || bundle.body.checkpoint_finality_commitment != header.proof_statement_commitment
        || bundle.body.validator_set_root != header.inputs.validator_set_root
    {
        return Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::InvalidAnchor));
    }
    let reference = statement
        .submission_reference()
        .map_err(|_| VerificationErrorV1::terminal(VerificationErrorCodeV1::InvalidAnchor))?;
    Ok((finalized, reference))
}

fn domain_hash(domain: &[u8], values: &[&[u8]]) -> Digest384 {
    let mut hash = Sha3_384::new();
    hash.update(domain);
    for value in values {
        hash.update(value);
    }
    Digest384::new(hash.finalize().into())
}

fn digest_hex(value: Digest384) -> String {
    value.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<(), VerificationErrorV1> {
    let parent = path.parent().ok_or_else(|| persistence(()))?;
    fs::create_dir_all(parent).map_err(persistence)?;
    let temporary = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .map_err(persistence)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(persistence)?;
        }
        file.write_all(bytes).map_err(persistence)?;
        file.sync_all().map_err(persistence)?;
    }
    fs::rename(&temporary, path).map_err(persistence)?;
    if let Ok(directory) = OpenOptions::new().read(true).open(parent) {
        directory.sync_all().map_err(persistence)?;
    }
    Ok(())
}

fn read_bounded_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, VerificationErrorV1> {
    let metadata = fs::symlink_metadata(path).map_err(persistence)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(persistence(()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(persistence(()));
        }
    }
    fs::read(path).map_err(persistence)
}

fn persistence<T>(_: T) -> VerificationErrorV1 {
    VerificationErrorV1::retryable(VerificationErrorCodeV1::PersistenceUnavailable)
}

fn read_digest(bytes: &[u8], cursor: &mut usize) -> Result<Digest384, VerificationErrorV1> {
    let end = cursor.checked_add(48).ok_or_else(|| persistence(()))?;
    let value = bytes.get(*cursor..end).ok_or_else(|| persistence(()))?;
    let mut digest = [0; 48];
    digest.copy_from_slice(value);
    *cursor = end;
    Ok(Digest384::new(digest))
}
fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, VerificationErrorV1> {
    let end = cursor.checked_add(4).ok_or_else(|| persistence(()))?;
    let value = bytes.get(*cursor..end).ok_or_else(|| persistence(()))?;
    *cursor = end;
    Ok(u32::from_be_bytes(value.try_into().map_err(persistence)?))
}
fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, VerificationErrorV1> {
    let end = cursor.checked_add(8).ok_or_else(|| persistence(()))?;
    let value = bytes.get(*cursor..end).ok_or_else(|| persistence(()))?;
    *cursor = end;
    Ok(u64::from_be_bytes(value.try_into().map_err(persistence)?))
}

pub const OFFLINE_VERIFY_OK: i32 = 0;
pub const OFFLINE_VERIFY_REJECTED: i32 = 1;
pub const OFFLINE_VERIFY_MALFORMED: i32 = 2;
pub const OFFLINE_VERIFY_TOO_LARGE: i32 = 3;

pub fn verify_relation_envelopes(public: &[u8], proof: &[u8]) -> i32 {
    if public.len() > WorkClaimPublicV1::MAX_ENCODED_LEN + 9 || proof.len() > MAX_WORK_PROOF_BYTES {
        return OFFLINE_VERIFY_TOO_LARGE;
    }
    if public.is_empty() || proof.is_empty() {
        return OFFLINE_VERIFY_MALFORMED;
    }
    let public = match decode_envelope::<WorkClaimPublicV1>(public) {
        Ok(value) => value,
        Err(_) => return OFFLINE_VERIFY_MALFORMED,
    };
    match InProcessRelationVerifier.verify(&public, proof) {
        Ok(()) => OFFLINE_VERIFY_OK,
        Err(_) => OFFLINE_VERIFY_REJECTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_action_kernel::{
        ACTION_PROTOCOL_VERSION, ActionEnvelope, ActionPayloadV2, FeeTicket, ResourceVector,
        ValidityInterval, action_id,
    };
    use activechain_application_primitives::{
        ActivityEpochV1, ActumVerifierTrustBundleV1, AnchorFinalizedEvidenceV1,
        TelemetryEpochAnchorRequestV1, TrustBundleSignatureV1, TrustSignerV1,
    };
    use activechain_devnet_kernel::{ActionOutcome, ActionReceipt, BlockReceipt};
    use activechain_finality_types::{
        FinalityCertificateBundle, FinalizedBlockHeader, ProofPublicInputs,
    };
    use activechain_protocol_commitment::{DomainTag, commit};
    use activechain_protocol_types::{
        ChainId, ConsensusVoteContext, CryptoSuiteId, ObjectId, PrincipalId, ProtocolSignature,
        QuorumCertificate, ValidatorGenesis, ValidatorGenesisEntry, ValidatorVote,
    };
    use activechain_state_tree::StateCommitment;
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    fn d(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn usage_registration_is_atomic_idempotent_durable_and_concurrent() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("usage.bin");
        let registry = Arc::new(DurableUsageRegistry::open(&path).unwrap());
        assert_eq!(
            registry.register_all(d(1), &[d(2), d(3)], d(4), 1, 1, 100),
            Ok(UsageRegistrationV1::Inserted)
        );
        assert_eq!(
            registry.register_all(d(1), &[d(2), d(3)], d(4), 1, 1, 100),
            Ok(UsageRegistrationV1::Idempotent)
        );
        assert_eq!(
            registry.register_all(d(1), &[d(3), d(5)], d(6), 1, 1, 101),
            Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::UsageDoubleSpend))
        );
        assert_eq!(registry.claim_entries().unwrap().len(), 1);
        drop(registry);
        assert_eq!(DurableUsageRegistry::open(&path).unwrap().claim_entries().unwrap().len(), 1);

        let concurrent =
            Arc::new(DurableUsageRegistry::open(directory.path().join("race.bin")).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for claim in [d(7), d(8)] {
            let concurrent = Arc::clone(&concurrent);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                concurrent.register_all(d(1), &[d(9)], claim, 1, 1, 100)
            }));
        }
        barrier.wait();
        let results = handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(concurrent.claim_entries().unwrap().len(), 1);
    }

    #[test]
    fn corrupt_usage_snapshot_fails_closed() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("usage.bin");
        fs::write(&path, b"corrupt").unwrap();
        assert!(DurableUsageRegistry::open(path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_timeout_is_bounded() {
        let verifier = SubprocessRelationVerifier::new("/bin/sh", Duration::from_millis(25))
            .with_args(vec!["-c".into(), "sleep 2".into()]);
        let public = public();
        assert_eq!(
            verifier.verify(&public, &[1]),
            Err(VerificationErrorV1::retryable(VerificationErrorCodeV1::VerifierTimeout))
        );
    }

    #[test]
    fn ipc_and_offline_api_reject_malformed_and_oversized_inputs() {
        assert_eq!(verify_ipc_request(b"bad"), 2);
        assert_eq!(verify_relation_envelopes(&[], &[]), OFFLINE_VERIFY_MALFORMED);
        assert_eq!(
            verify_relation_envelopes(&vec![0; WorkClaimPublicV1::MAX_ENCODED_LEN + 10], &[1]),
            OFFLINE_VERIFY_TOO_LARGE
        );
    }

    #[test]
    fn rate_limit_is_explicit_and_windowed() {
        let limiter = FixedWindowRateLimiter::new(1, 100).unwrap();
        assert_eq!(limiter.admit(d(1), 1), Ok(()));
        assert_eq!(
            limiter.admit(d(1), 2),
            Err(VerificationErrorV1::retryable(VerificationErrorCodeV1::RateLimited))
        );
        assert_eq!(limiter.admit(d(1), 101), Ok(()));
    }

    fn signer_set() -> TrustSignerSetV1 {
        let signer = TrustSignerV1 {
            signer_id: d(20),
            algorithm: TrustSignatureAlgorithmV1::MlDsa44,
            public_key: vec![20; 1_312],
            valid_from_sequence: 1,
            valid_until_sequence: 100,
        };
        TrustSignerSetV1 { revision: 1, signers: vec![signer], threshold: 1 }
    }

    fn bundle(set: &TrustSignerSetV1) -> SignedActumVerifierTrustBundleV1 {
        let body = ActumVerifierTrustBundleV1 {
            schema_revision: 1,
            bundle_sequence: 1,
            previous_bundle_id: Digest384::ZERO,
            chain_id: d(1),
            genesis_commitment: d(2),
            protocol_revision: 1,
            checkpoint_height: 10,
            checkpoint_block_id: d(3),
            checkpoint_state_root: d(4),
            checkpoint_finality_commitment: d(5),
            validator_set_root: d(6),
            proof_profile_id: d(16),
            proof_system_revision: 1,
            verifier_revision: WORK_VERIFIER_REVISION,
            risc0_image_id: [17; 32],
            policy_id: d(7),
            policy_revision: 1,
            issued_at_ms: 100,
            not_before_ms: 100,
            not_after_ms: 1_000,
            signer_set_id: set.signer_set_id().unwrap(),
            signer_set_revision: set.revision,
            signer_threshold: set.threshold,
            next_signer_set_id: Digest384::ZERO,
            next_signer_set_revision: 0,
            next_signer_threshold: 0,
            next_signer_activation_sequence: 0,
        };
        let id = body.bundle_id().unwrap();
        let mut signature = vec![20; 2_420];
        signature[..48].copy_from_slice(id.as_bytes());
        SignedActumVerifierTrustBundleV1 {
            body,
            bundle_id: id,
            signatures: vec![TrustBundleSignatureV1 {
                signer_set_id: set.signer_set_id().unwrap(),
                signer_id: set.signers[0].signer_id,
                algorithm: TrustSignatureAlgorithmV1::MlDsa44,
                signature,
            }],
        }
    }

    fn production_bundle(
        set: &TrustSignerSetV1,
        evidence: &AnchorFinalizedEvidenceV1,
    ) -> SignedActumVerifierTrustBundleV1 {
        let finality =
            decode_envelope::<FinalityCertificateBundle>(evidence.finality_proof()).unwrap();
        let header = finality.header();
        let mut value = bundle(set);
        value.body.chain_id = *evidence.chain().digest();
        value.body.genesis_commitment = evidence.genesis();
        value.body.protocol_revision = u32::try_from(evidence.protocol_revision()).unwrap();
        value.body.checkpoint_height = evidence.finalized_height();
        value.body.checkpoint_block_id = evidence.finalized_block();
        value.body.checkpoint_state_root = header.inputs.post_state.root();
        value.body.checkpoint_finality_commitment = header.proof_statement_commitment;
        value.body.validator_set_root = header.inputs.validator_set_root;
        value.body.proof_profile_id = work_proof_profile_id();
        value.body.proof_system_revision = WORK_PROOF_SYSTEM_REVISION;
        if work_image_id() != [0; 32] {
            value.body.risc0_image_id = work_image_id();
        }
        value.bundle_id = value.body.bundle_id().unwrap();
        value.signatures[0].signature[..48].copy_from_slice(value.bundle_id.as_bytes());
        value
    }

    fn verify_signature(
        _: TrustSignatureAlgorithmV1,
        key: &[u8],
        id: Digest384,
        signature: &[u8],
    ) -> bool {
        signature.len() == 2_420
            && signature[..48] == *id.as_bytes()
            && signature[48..].iter().all(|byte| *byte == key[0])
    }

    #[test]
    fn trust_store_persists_operator_selected_bundle() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("trust.bin");
        let set = signer_set();
        let expected = bundle(&set);
        let store =
            DurableTrustStore::bootstrap(&path, expected.clone(), &set, 200, &verify_signature)
                .unwrap();
        assert_eq!(store.accepted_bundle().unwrap(), expected);
        drop(store);
        assert_eq!(DurableTrustStore::open(path).unwrap().accepted_bundle().unwrap(), expected);
    }

    fn public() -> WorkClaimPublicV1 {
        WorkClaimPublicV1 {
            chain_id: d(1),
            genesis: d(2),
            telemetry_schema: 1,
            policy_id: d(7),
            policy_revision: 1,
            authorization_revision: 1,
            usage_domain: d(8),
            collector_id: d(9),
            project_id: d(10),
            claimant_key: d(11),
            epoch_root: d(12),
            first_sequence: 1,
            last_sequence: 1,
            event_count: 1,
            epoch_event_count: 1,
            interval_start_ms: 100,
            interval_end_ms: 200,
            aggregate: WorkClaimAggregateV1::Attention {
                attributable_ms: 100,
                interaction_count: 1,
            },
            nullifier_root: d(13),
            usage_nullifier_root: d(14),
            usage_nullifiers: vec![d(15)],
        }
    }

    #[derive(Clone, Copy)]
    struct AcceptRelation;
    impl RelationVerifier for AcceptRelation {
        fn verify(&self, _: &WorkClaimPublicV1, proof: &[u8]) -> Result<(), VerificationErrorV1> {
            if proof == [1] {
                Ok(())
            } else {
                Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::RelationRejected))
            }
        }
    }

    fn finalized_anchor_evidence() -> (TelemetryEpochAnchorRequestV1, AnchorFinalizedEvidenceV1) {
        let epoch = ActivityEpochV1 {
            collector_id: d(9),
            project_id: d(10),
            first_collector_sequence: 1,
            last_collector_sequence: 1,
            first_project_sequence: 1,
            last_project_sequence: 1,
            event_count: 1,
            wall_start_ms: 100,
            wall_end_ms: 200,
            monotonic_start_ns: 1,
            monotonic_end_ns: 2,
            event_root: d(12),
            previous_epoch_id: Digest384::ZERO,
            authorization_revision: 1,
            policy_id: d(7),
        };
        let request = TelemetryEpochAnchorRequestV1::new(
            d(1),
            d(2),
            1,
            d(30),
            b"claim-anchor-1".to_vec(),
            epoch,
        )
        .unwrap();
        let statement = request.statement().unwrap();
        let pre_state = StateCommitment::new(d(60), 2);
        let post_state = StateCommitment::new(d(61), 3);
        let sender = PrincipalId::new(d(42));
        let payload = ActionPayloadV2::submit_anchor(9, statement.clone());
        let resources = ResourceVector::new(10, 0, 0, 0, 1, 4096);
        let ticket = FeeTicket::new(ObjectId::new(d(43)), sender, 10_000, 9, 0, resources).unwrap();
        let action = ActionEnvelope::new_payload(
            ACTION_PROTOCOL_VERSION,
            ChainId::new(d(1)),
            sender,
            ticket,
            0,
            0,
            ValidityInterval::new(9, 9).unwrap(),
            resources,
            payload.commitment().unwrap(),
            payload,
            statement.submission_reference().unwrap(),
        )
        .unwrap();
        let transaction = action_id(&action).unwrap();
        let receipt = BlockReceipt::new(
            d(32),
            9,
            pre_state,
            post_state,
            d(64),
            d(65),
            vec![ActionReceipt::new(
                transaction,
                ActionOutcome::AnchorSubmitted {
                    reference: statement.submission_reference().unwrap(),
                },
                ResourceVector::new(1, 0, 0, 0, 0, 1),
                0,
                1,
                post_state,
            )],
        )
        .unwrap();
        let receipt_root = commit(DomainTag::CANONICAL_VALUE, &receipt).unwrap();
        let finality = finality_bundle_with_inputs(receipt_root, pre_state, post_state);
        let evidence = AnchorFinalizedEvidenceV1::new(
            ChainId::new(d(1)),
            finality.validator_genesis().genesis_commitment(),
            transaction,
            encode_envelope(&action).unwrap(),
            9,
            receipt.block_id(),
            statement,
            None,
            None,
            4,
            WORK_VERIFIER_REVISION,
            encode_envelope(&receipt).unwrap(),
            encode_envelope(&finality).unwrap(),
        )
        .unwrap();
        (request, evidence)
    }

    fn finality_bundle_with_inputs(
        receipt_root: Digest384,
        pre_state: StateCommitment,
        post_state: StateCommitment,
    ) -> FinalityCertificateBundle {
        let keys = [
            SigningKey::<MlDsa44>::from_seed(&Seed::from([1; 32])),
            SigningKey::<MlDsa44>::from_seed(&Seed::from([2; 32])),
        ];
        let entries = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                ValidatorGenesisEntry::new(
                    PrincipalId::new(d((index + 1) as u8)),
                    1,
                    key.verifying_key().encode().into(),
                )
                .unwrap()
            })
            .collect();
        let genesis = ValidatorGenesis::new_with_revision(3, 1, 4, entries).unwrap();
        let inputs = ProofPublicInputs {
            chain_id: ChainId::new(d(1)),
            epoch: 3,
            height: 9,
            protocol_revision: 4,
            validator_set_root: genesis.validator_set_root(),
            parent_block_id: d(41),
            pre_state,
            authorization_root: d(43),
            action_root: d(44),
            execution_order_root: d(45),
            total_fees: 0,
            pre_supply: 0,
            issuance: 0,
            burn: 0,
            post_supply: 0,
            pre_cash_cell_root: d(50),
            cash_action_root: d(51),
            cash_cell_root: d(50),
            post_state,
            receipt_root,
            data_availability_commitment: d(48),
        };
        let header = FinalizedBlockHeader { inputs, proof_statement_commitment: d(49) };
        let block_digest = header.digest().unwrap();
        let context = ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        let mut votes = Vec::new();
        let mut vote_set_hasher = Shake256::default();
        vote_set_hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
        for (index, key) in keys.iter().enumerate() {
            let validator = PrincipalId::new(d((index + 1) as u8));
            let unsigned = ValidatorVote::new(
                validator,
                context,
                9,
                2,
                block_digest,
                d(49),
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
            )
            .unwrap();
            let signature = key.sign(&unsigned.signing_payload());
            let vote = ValidatorVote::new(
                validator,
                context,
                9,
                2,
                block_digest,
                d(49),
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                    .unwrap(),
            )
            .unwrap();
            vote_set_hasher.update(key.verifying_key().encode().as_slice());
            vote_set_hasher.update(&vote.signing_payload());
            vote_set_hasher.update(vote.signature().as_bytes());
            votes.push(vote);
        }
        let mut vote_set_root = [0; 48];
        XofReader::read(&mut vote_set_hasher.finalize_xof(), &mut vote_set_root);
        let certificate = QuorumCertificate::new(
            context,
            9,
            2,
            block_digest,
            d(49),
            Digest384::new(vote_set_root),
            2,
            2,
        )
        .unwrap();
        FinalityCertificateBundle::new(header, genesis, certificate, votes).unwrap()
    }

    #[test]
    fn finalized_anchor_checkpoint_is_direct_and_exact() {
        let set = signer_set();
        let (request, evidence) = finalized_anchor_evidence();
        let accepted = production_bundle(&set, &evidence);
        let (verified, reference) =
            verify_finalized_anchor_checkpoint(&accepted, &public(), &request, &evidence).unwrap();
        assert_eq!(verified, evidence);
        assert_eq!(reference, request.statement().unwrap().submission_reference().unwrap());

        let mut substituted = accepted;
        substituted.body.checkpoint_block_id = d(99);
        assert_eq!(
            verify_finalized_anchor_checkpoint(&substituted, &public(), &request, &evidence),
            Err(VerificationErrorV1::terminal(VerificationErrorCodeV1::InvalidAnchor))
        );
    }

    #[test]
    fn service_requires_relation_anchor_and_atomic_usage_before_verified_status() {
        if work_image_id() == [0; 32] {
            return;
        }
        let directory = tempdir().unwrap();
        let set = signer_set();
        let (anchor_request, anchor_evidence) = finalized_anchor_evidence();
        let accepted = production_bundle(&set, &anchor_evidence);
        let trust = DurableTrustStore::bootstrap(
            directory.path().join("trust.bin"),
            accepted.clone(),
            &set,
            200,
            &verify_signature,
        )
        .unwrap();
        let usage = DurableUsageRegistry::open(directory.path().join("usage.bin")).unwrap();
        let service = WorkProofVerificationService::new(
            AcceptRelation,
            trust,
            usage,
            FixedWindowRateLimiter::new(10, 1_000).unwrap(),
        );
        let public = public();
        let proof_envelope = vec![1];
        let request = VerifyWorkClaimRequestV1 {
            client_id: d(40),
            claim_id: derive_claim_id(&public, &proof_envelope).unwrap(),
            public,
            proof_envelope,
            anchor_request,
            anchor_evidence,
        };
        let first = service.verify(&request, 200).unwrap();
        assert!(first.relation_verified && first.anchor_verified && first.usage_verified);
        assert!(!first.idempotent);
        let retry = service.verify(&request, 201).unwrap();
        assert!(retry.idempotent);
        let page = service.list_claims(None, 10).unwrap();
        assert_eq!(page.claims.len(), 1);
        assert_eq!(page.claims[0].trust_bundle_sequence, 1);
    }
}
