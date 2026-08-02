#![forbid(unsafe_code)]

//! Authoritative joined authorization and crash-atomic transition admission.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_capability::verify_attenuation;
use activechain_credential::{
    PresentationContext, PreverifiedIssuerEvidence, PreverifiedStatusEvidence,
    canonical_schema_facts, verify_presentation,
};
use activechain_policy_kernel::{
    ActorBinding, ApprovalFact, DecisionResult, PolicyRequest, PolicyRequestFields, evaluate,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    CapabilityGrant, CapabilityId, Credential, CredentialAcceptancePolicy, CredentialId,
    CredentialStatusRegistry, CryptoSuiteId, Digest384, FreezeState, HolderBinding, PrincipalId,
    ProtocolSignature, RateLimit, ResourceSelector,
};
use activechain_state_tree::commit_objects;
use activechain_transition::{
    ObjectState, ReceiptResult, TRANSFER_OBJECT_ACTION_ID, TransferTransaction, TransitionReceipt,
    apply_transfer_transaction,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

pub const MAX_AUTHORIZATION_CREDENTIALS: usize = 16;
pub const MAX_CAPABILITY_DEPTH: usize = 16;
pub const MAX_AUTHORIZATION_INVOCATIONS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationEnvelope {
    invocation_id: Digest384,
    chain_genesis_commitment: Digest384,
    epoch: u64,
    actor: PrincipalId,
    height: u64,
    timestamp: u64,
    finalized_state_root: Digest384,
    transition_commitment: Digest384,
    value: u128,
    compute: u128,
    freeze_state: FreezeState,
    declared_purpose: Option<Digest384>,
    approvals: Vec<ApprovalFact>,
    credential_ids: Vec<CredentialId>,
    capability_ids: Vec<CapabilityId>,
    actor_signature: ProtocolSignature,
}

impl AuthorizationEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invocation_id: Digest384,
        chain_genesis_commitment: Digest384,
        epoch: u64,
        actor: PrincipalId,
        height: u64,
        timestamp: u64,
        finalized_state_root: Digest384,
        transition_commitment: Digest384,
        value: u128,
        compute: u128,
        freeze_state: FreezeState,
        declared_purpose: Option<Digest384>,
        approvals: Vec<ApprovalFact>,
        credential_ids: Vec<CredentialId>,
        capability_ids: Vec<CapabilityId>,
        actor_signature: ProtocolSignature,
    ) -> Result<Self, AuthorizationError> {
        if invocation_id == Digest384::ZERO
            || chain_genesis_commitment == Digest384::ZERO
            || finalized_state_root == Digest384::ZERO
            || transition_commitment == Digest384::ZERO
            || actor_signature.suite() != CryptoSuiteId::ML_DSA_44
            || credential_ids.len() > MAX_AUTHORIZATION_CREDENTIALS
            || capability_ids.is_empty()
            || capability_ids.len() > MAX_CAPABILITY_DEPTH
            || credential_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || capability_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || approvals.windows(2).any(|pair| pair[0].role() >= pair[1].role())
        {
            return Err(AuthorizationError::MalformedEnvelope);
        }
        Ok(Self {
            invocation_id,
            chain_genesis_commitment,
            epoch,
            actor,
            height,
            timestamp,
            finalized_state_root,
            transition_commitment,
            value,
            compute,
            freeze_state,
            declared_purpose,
            approvals,
            credential_ids,
            capability_ids,
            actor_signature,
        })
    }
    pub const fn invocation_id(&self) -> Digest384 {
        self.invocation_id
    }
    pub const fn chain_genesis_commitment(&self) -> Digest384 {
        self.chain_genesis_commitment
    }
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    pub const fn actor(&self) -> PrincipalId {
        self.actor
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn finalized_state_root(&self) -> Digest384 {
        self.finalized_state_root
    }
    pub const fn transition_commitment(&self) -> Digest384 {
        self.transition_commitment
    }
    pub fn signing_payload(&self) -> Result<Vec<u8>, EncodeError> {
        let mut unsigned = self.clone();
        unsigned.actor_signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420])
            .map_err(|_| EncodeError::LengthOverflow)?;
        let body = encode_envelope(&unsigned)?;
        let mut payload = b"ACTIVECHAIN-AUTHORIZATION-ENVELOPE-V1".to_vec();
        payload.extend_from_slice(&body);
        Ok(payload)
    }
}

impl CanonicalEncode for AuthorizationEnvelope {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.invocation_id.encode(e)?;
        self.chain_genesis_commitment.encode(e)?;
        self.epoch.encode(e)?;
        self.actor.encode(e)?;
        self.height.encode(e)?;
        self.timestamp.encode(e)?;
        self.finalized_state_root.encode(e)?;
        self.transition_commitment.encode(e)?;
        self.value.encode(e)?;
        self.compute.encode(e)?;
        self.freeze_state.encode(e)?;
        self.declared_purpose.encode(e)?;
        e.write_length(self.approvals.len(), activechain_policy_kernel::MAX_APPROVAL_FACTS)?;
        for v in &self.approvals {
            v.encode(e)?
        }
        e.write_length(self.credential_ids.len(), MAX_AUTHORIZATION_CREDENTIALS)?;
        for v in &self.credential_ids {
            v.encode(e)?
        }
        e.write_length(self.capability_ids.len(), MAX_CAPABILITY_DEPTH)?;
        for v in &self.capability_ids {
            v.encode(e)?
        }
        self.actor_signature.encode(e)
    }
}
impl CanonicalDecode for AuthorizationEnvelope {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let invocation_id = Digest384::decode(d)?;
        let chain_genesis_commitment = Digest384::decode(d)?;
        let epoch = u64::decode(d)?;
        let actor = PrincipalId::decode(d)?;
        let height = u64::decode(d)?;
        let timestamp = u64::decode(d)?;
        let root = Digest384::decode(d)?;
        let transition = Digest384::decode(d)?;
        let value = u128::decode(d)?;
        let compute = u128::decode(d)?;
        let freeze = FreezeState::decode(d)?;
        let purpose = Option::<Digest384>::decode(d)?;
        let count = d.read_length(activechain_policy_kernel::MAX_APPROVAL_FACTS)?;
        let mut approvals = Vec::with_capacity(count);
        for _ in 0..count {
            approvals.push(ApprovalFact::decode(d)?)
        }
        let count = d.read_length(MAX_AUTHORIZATION_CREDENTIALS)?;
        let mut credentials = Vec::with_capacity(count);
        for _ in 0..count {
            credentials.push(CredentialId::decode(d)?)
        }
        let count = d.read_length(MAX_CAPABILITY_DEPTH)?;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(CapabilityId::decode(d)?)
        }
        Self::new(
            invocation_id,
            chain_genesis_commitment,
            epoch,
            actor,
            height,
            timestamp,
            root,
            transition,
            value,
            compute,
            freeze,
            purpose,
            approvals,
            credentials,
            capabilities,
            ProtocolSignature::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid authorization envelope"))
    }
}
impl CanonicalType for AuthorizationEnvelope {
    const TYPE_TAG: u16 = 0x007d;
    const SCHEMA_VERSION: u16 = 2;
    const MAX_ENCODED_LEN: usize = 48
        + 48
        + 8
        + 48
        + 8
        + 8
        + 48
        + 48
        + 16
        + 16
        + 1
        + 49
        + 1
        + activechain_policy_kernel::MAX_APPROVAL_FACTS * 49
        + 1
        + MAX_AUTHORIZATION_CREDENTIALS * 48
        + 1
        + MAX_CAPABILITY_DEPTH * 48
        + 2423;
}

pub struct CredentialMaterial {
    pub credential: Credential,
    pub policy: CredentialAcceptancePolicy,
    pub issuer_evidence: PreverifiedIssuerEvidence,
    pub registry: Option<CredentialStatusRegistry>,
    pub status_evidence: Option<PreverifiedStatusEvidence>,
}

pub struct AuthorizationCandidate {
    pub envelope: AuthorizationEnvelope,
    pub credentials: Vec<CredentialMaterial>,
    pub capability_chain: Vec<CapabilityGrant>,
    pub transaction: TransferTransaction,
}

pub trait AuthorizationVerifier {
    fn verify_actor_signature(&self, envelope: &AuthorizationEnvelope) -> bool;
    fn verify_finalized_context(&self, envelope: &AuthorizationEnvelope) -> bool;
    fn verify_credential_signature(&self, credential: &Credential) -> bool;
    fn verify_credential_status(&self, material: &CredentialMaterial) -> bool;
    fn verify_capability_signature(&self, capability: &CapabilityGrant) -> bool;
    fn verify_capability_active(
        &self,
        capability: &CapabilityGrant,
        height: u64,
        state_root: Digest384,
    ) -> bool;
}

/// Opaque capability emitted only by the complete joined authorization verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAuthorization {
    envelope: AuthorizationEnvelope,
    envelope_commitment: Digest384,
    leaf_capability: CapabilityGrant,
}

impl VerifiedAuthorization {
    pub const fn invocation_id(&self) -> Digest384 {
        self.envelope.invocation_id
    }
    pub const fn chain_genesis_commitment(&self) -> Digest384 {
        self.envelope.chain_genesis_commitment
    }
    pub const fn epoch(&self) -> u64 {
        self.envelope.epoch
    }
    pub const fn actor(&self) -> PrincipalId {
        self.envelope.actor
    }
    pub const fn finalized_state_root(&self) -> Digest384 {
        self.envelope.finalized_state_root
    }
    pub const fn transition_commitment(&self) -> Digest384 {
        self.envelope.transition_commitment
    }
    pub const fn envelope_commitment(&self) -> Digest384 {
        self.envelope_commitment
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BudgetUsage {
    uses: u64,
    money: u128,
    compute: u128,
    window_start: u64,
    window_uses: u64,
}
impl CanonicalEncode for BudgetUsage {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.uses.encode(e)?;
        self.money.encode(e)?;
        self.compute.encode(e)?;
        self.window_start.encode(e)?;
        self.window_uses.encode(e)
    }
}
impl CanonicalDecode for BudgetUsage {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            uses: u64::decode(d)?,
            money: u128::decode(d)?,
            compute: u128::decode(d)?,
            window_start: u64::decode(d)?,
            window_uses: u64::decode(d)?,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct AuthorizationLedger {
    invocations: BTreeMap<Digest384, Digest384>,
    budgets: BTreeMap<CapabilityId, BudgetUsage>,
}
impl AuthorizationLedger {
    fn consume(
        &mut self,
        authorization: &VerifiedAuthorization,
        receipt: Digest384,
    ) -> Result<(), AuthorizationError> {
        let envelope = &authorization.envelope;
        if self.invocations.len() >= MAX_AUTHORIZATION_INVOCATIONS
            || self.invocations.contains_key(&envelope.invocation_id)
        {
            return Err(AuthorizationError::Replay);
        }
        let fields = authorization.leaf_capability.fields();
        let usage = self.budgets.entry(fields.capability_id).or_default();
        let uses = usage.uses.checked_add(1).ok_or(AuthorizationError::Budget)?;
        let money = usage.money.checked_add(envelope.value).ok_or(AuthorizationError::Budget)?;
        let compute =
            usage.compute.checked_add(envelope.compute).ok_or(AuthorizationError::Budget)?;
        if fields.use_limit.is_some_and(|v| uses > v)
            || fields.monetary_limit.is_some_and(|v| money > v)
            || fields.compute_limit.is_some_and(|v| compute > v)
        {
            return Err(AuthorizationError::Budget);
        }
        let (window_start, window_uses) = rate_usage(fields.rate_limit, envelope.height, *usage)?;
        usage.uses = uses;
        usage.money = money;
        usage.compute = compute;
        usage.window_start = window_start;
        usage.window_uses = window_uses;
        self.invocations.insert(envelope.invocation_id, receipt);
        Ok(())
    }
}

fn rate_usage(
    limit: Option<RateLimit>,
    height: u64,
    usage: BudgetUsage,
) -> Result<(u64, u64), AuthorizationError> {
    let Some(limit) = limit else { return Ok((0, 0)) };
    let start = height - (height % limit.window_blocks());
    let used = if usage.window_start == start {
        usage.window_uses.checked_add(1).ok_or(AuthorizationError::Budget)?
    } else {
        1
    };
    if used > limit.maximum_uses() {
        return Err(AuthorizationError::RateLimit);
    }
    Ok((start, used))
}

impl CanonicalEncode for AuthorizationLedger {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_length(self.invocations.len(), MAX_AUTHORIZATION_INVOCATIONS)?;
        for (k, v) in &self.invocations {
            k.encode(e)?;
            v.encode(e)?
        }
        e.write_length(self.budgets.len(), MAX_AUTHORIZATION_INVOCATIONS)?;
        for (k, v) in &self.budgets {
            k.encode(e)?;
            v.encode(e)?
        }
        Ok(())
    }
}
impl CanonicalDecode for AuthorizationLedger {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = d.read_length(MAX_AUTHORIZATION_INVOCATIONS)?;
        let mut invocations = BTreeMap::new();
        let mut prior = None;
        for _ in 0..count {
            let k = Digest384::decode(d)?;
            let v = Digest384::decode(d)?;
            if prior.is_some_and(|p| p >= k) || invocations.insert(k, v).is_some() {
                return Err(DecodeError::InvalidValue("unordered invocations"));
            }
            prior = Some(k)
        }
        let count = d.read_length(MAX_AUTHORIZATION_INVOCATIONS)?;
        let mut budgets = BTreeMap::new();
        let mut prior = None;
        for _ in 0..count {
            let k = CapabilityId::decode(d)?;
            let v = BudgetUsage::decode(d)?;
            if prior.is_some_and(|p| p >= k) || budgets.insert(k, v).is_some() {
                return Err(DecodeError::InvalidValue("unordered budgets"));
            }
            prior = Some(k)
        }
        Ok(Self { invocations, budgets })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizationReplaySnapshot {
    chain_genesis_commitment: Digest384,
    epoch: u64,
    ledger: AuthorizationLedger,
}
impl CanonicalEncode for AuthorizationReplaySnapshot {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_genesis_commitment.encode(e)?;
        self.epoch.encode(e)?;
        self.ledger.encode(e)
    }
}
impl CanonicalDecode for AuthorizationReplaySnapshot {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            chain_genesis_commitment: Digest384::decode(d)?,
            epoch: u64::decode(d)?,
            ledger: AuthorizationLedger::decode(d)?,
        })
    }
}
impl CanonicalType for AuthorizationReplaySnapshot {
    const TYPE_TAG: u16 = 0x0143;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48
        + 8
        + 2
        + MAX_AUTHORIZATION_INVOCATIONS * 96
        + 2
        + MAX_AUTHORIZATION_INVOCATIONS * (48 + 56);
}

/// Durable replay and capability-budget state for finalized-block authorization.
pub struct AuthorizationReplayStore {
    inner: Mutex<ReplayRuntime>,
    snapshot_path: PathBuf,
    chain_genesis_commitment: Digest384,
    epoch: u64,
}
struct ReplayRuntime {
    ledger: AuthorizationLedger,
    poisoned: bool,
}
impl AuthorizationReplayStore {
    pub fn new(
        snapshot_path: PathBuf,
        chain_genesis_commitment: Digest384,
        epoch: u64,
    ) -> Result<Self, AuthorizationError> {
        if chain_genesis_commitment == Digest384::ZERO {
            return Err(AuthorizationError::MalformedEnvelope);
        }
        Ok(Self {
            inner: Mutex::new(ReplayRuntime {
                ledger: AuthorizationLedger::default(),
                poisoned: false,
            }),
            snapshot_path,
            chain_genesis_commitment,
            epoch,
        })
    }

    pub fn load(snapshot_path: PathBuf) -> std::io::Result<Self> {
        let snapshot: AuthorizationReplaySnapshot = load_typed_snapshot(&snapshot_path)?;
        if snapshot.chain_genesis_commitment == Digest384::ZERO {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "authorization replay snapshot has zero genesis",
            ));
        }
        Ok(Self {
            inner: Mutex::new(ReplayRuntime { ledger: snapshot.ledger, poisoned: false }),
            snapshot_path,
            chain_genesis_commitment: snapshot.chain_genesis_commitment,
            epoch: snapshot.epoch,
        })
    }

    #[must_use]
    pub const fn chain_genesis_commitment(&self) -> Digest384 {
        self.chain_genesis_commitment
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Atomically persists the whole block's replay and budget effects before admission returns.
    pub fn admit_batch(
        &self,
        authorizations: &[VerifiedAuthorization],
    ) -> Result<(), AuthorizationError> {
        let mut runtime = self.inner.lock().map_err(|_| AuthorizationError::Poisoned)?;
        if runtime.poisoned {
            return Err(AuthorizationError::Poisoned);
        }
        let mut next = runtime.ledger.clone();
        for authorization in authorizations {
            if authorization.chain_genesis_commitment() != self.chain_genesis_commitment
                || authorization.epoch() != self.epoch
            {
                return Err(AuthorizationError::Authentication);
            }
            next.consume(authorization, authorization.transition_commitment())?;
        }
        let snapshot = AuthorizationReplaySnapshot {
            chain_genesis_commitment: self.chain_genesis_commitment,
            epoch: self.epoch,
            ledger: next.clone(),
        };
        if save_typed_snapshot(&self.snapshot_path, &snapshot).is_err() {
            runtime.poisoned = true;
            return Err(AuthorizationError::Persistence);
        }
        runtime.ledger = next;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizedSnapshot {
    chain_genesis_commitment: Digest384,
    epoch: u64,
    state: ObjectState,
    ledger: AuthorizationLedger,
    last_receipt: TransitionReceipt,
    last_envelope: Digest384,
}
impl CanonicalEncode for AuthorizedSnapshot {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_genesis_commitment.encode(e)?;
        self.epoch.encode(e)?;
        self.state.encode(e)?;
        self.ledger.encode(e)?;
        self.last_receipt.encode(e)?;
        self.last_envelope.encode(e)
    }
}
impl CanonicalDecode for AuthorizedSnapshot {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            chain_genesis_commitment: Digest384::decode(d)?,
            epoch: u64::decode(d)?,
            state: ObjectState::decode(d)?,
            ledger: AuthorizationLedger::decode(d)?,
            last_receipt: TransitionReceipt::decode(d)?,
            last_envelope: Digest384::decode(d)?,
        })
    }
}
impl CanonicalType for AuthorizedSnapshot {
    const TYPE_TAG: u16 = 0x007e;
    const SCHEMA_VERSION: u16 = 2;
    const MAX_ENCODED_LEN: usize = 48
        + 8
        + ObjectState::MAX_ENCODED_LEN
        + 2
        + MAX_AUTHORIZATION_INVOCATIONS * 96
        + 2
        + MAX_AUTHORIZATION_INVOCATIONS * (48 + 56)
        + TransitionReceipt::MAX_ENCODED_LEN
        + 48;
}

struct RuntimeState {
    state: ObjectState,
    ledger: AuthorizationLedger,
    poisoned: bool,
}
pub struct AuthorizationGateway {
    inner: Mutex<RuntimeState>,
    snapshot_path: PathBuf,
    chain_genesis_commitment: Digest384,
    epoch: u64,
}
impl AuthorizationGateway {
    pub fn new(
        state: ObjectState,
        snapshot_path: PathBuf,
        chain_genesis_commitment: Digest384,
        epoch: u64,
    ) -> Result<Self, AuthorizationError> {
        if chain_genesis_commitment == Digest384::ZERO {
            return Err(AuthorizationError::MalformedEnvelope);
        }
        Ok(Self {
            inner: Mutex::new(RuntimeState {
                state,
                ledger: AuthorizationLedger::default(),
                poisoned: false,
            }),
            snapshot_path,
            chain_genesis_commitment,
            epoch,
        })
    }
    pub fn load(snapshot_path: PathBuf) -> std::io::Result<Self> {
        let snapshot = load_snapshot(&snapshot_path)?;
        if snapshot.chain_genesis_commitment == Digest384::ZERO {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "authorization gateway snapshot has zero genesis",
            ));
        }
        Ok(Self {
            inner: Mutex::new(RuntimeState {
                state: snapshot.state,
                ledger: snapshot.ledger,
                poisoned: false,
            }),
            snapshot_path,
            chain_genesis_commitment: snapshot.chain_genesis_commitment,
            epoch: snapshot.epoch,
        })
    }
    pub fn state(&self) -> Result<ObjectState, AuthorizationError> {
        let runtime = self.inner.lock().map_err(|_| AuthorizationError::Poisoned)?;
        if runtime.poisoned {
            return Err(AuthorizationError::Poisoned);
        }
        Ok(runtime.state.clone())
    }
    pub fn admit<V: AuthorizationVerifier>(
        &self,
        candidate: AuthorizationCandidate,
        verifier: &V,
    ) -> Result<TransitionReceipt, AuthorizationError> {
        let mut runtime = self.inner.lock().map_err(|_| AuthorizationError::Poisoned)?;
        if runtime.poisoned {
            return Err(AuthorizationError::Poisoned);
        }
        if runtime.ledger.invocations.contains_key(&candidate.envelope.invocation_id) {
            return Err(AuthorizationError::Replay);
        }
        let finalized_state_root = commit_objects(runtime.state.objects())
            .map_err(|_| AuthorizationError::Encoding)?
            .root();
        let authorization = verify_authorization_candidate(
            &candidate,
            self.chain_genesis_commitment,
            self.epoch,
            finalized_state_root,
            verifier,
        )?;
        let mut ledger = runtime.ledger.clone();
        ledger.consume(&authorization, Digest384::ZERO)?;
        let output = apply_transfer_transaction(&runtime.state, &candidate.transaction)
            .map_err(|_| AuthorizationError::Transition)?;
        if !matches!(output.receipt().result(), ReceiptResult::Success) {
            return Err(AuthorizationError::Transition);
        }
        let receipt_commitment = commit(DomainTag::CANONICAL_VALUE, &output.receipt())
            .map_err(|_| AuthorizationError::Encoding)?;
        ledger.invocations.insert(candidate.envelope.invocation_id, receipt_commitment);
        let snapshot = AuthorizedSnapshot {
            chain_genesis_commitment: self.chain_genesis_commitment,
            epoch: self.epoch,
            state: output.state().clone(),
            ledger: ledger.clone(),
            last_receipt: output.receipt(),
            last_envelope: authorization.envelope_commitment,
        };
        if save_snapshot(&self.snapshot_path, &snapshot).is_err() {
            runtime.poisoned = true;
            return Err(AuthorizationError::Persistence);
        }
        runtime.state = output.state().clone();
        runtime.ledger = ledger;
        Ok(output.receipt())
    }
}

pub fn verify_authorization_candidate<V: AuthorizationVerifier>(
    candidate: &AuthorizationCandidate,
    expected_chain_genesis_commitment: Digest384,
    expected_epoch: u64,
    expected_finalized_state_root: Digest384,
    verifier: &V,
) -> Result<VerifiedAuthorization, AuthorizationError> {
    let envelope = &candidate.envelope;
    if envelope.chain_genesis_commitment != expected_chain_genesis_commitment
        || envelope.epoch != expected_epoch
        || envelope.finalized_state_root != expected_finalized_state_root
        || !verifier.verify_actor_signature(envelope)
        || !verifier.verify_finalized_context(envelope)
    {
        return Err(AuthorizationError::Authentication);
    }
    let transition = commit(DomainTag::CANONICAL_VALUE, &candidate.transaction)
        .map_err(|_| AuthorizationError::Encoding)?;
    if transition != envelope.transition_commitment {
        return Err(AuthorizationError::TransitionSubstitution);
    }
    if candidate.transaction.commands().len() != 1 {
        return Err(AuthorizationError::RequestSubstitution);
    }
    if candidate.credentials.len() > MAX_AUTHORIZATION_CREDENTIALS {
        return Err(AuthorizationError::Credential);
    }
    let mut facts = Vec::with_capacity(candidate.credentials.len());
    let mut ids = Vec::with_capacity(candidate.credentials.len());
    for material in &candidate.credentials {
        if !verifier.verify_credential_signature(&material.credential)
            || !verifier.verify_credential_status(material)
        {
            return Err(AuthorizationError::Credential);
        }
        let fact = verify_presentation(
            &material.credential,
            &material.policy,
            &material.issuer_evidence,
            material.registry.as_ref(),
            material.status_evidence.as_ref(),
            PresentationContext::new(*envelope.actor.digest(), envelope.height, envelope.timestamp),
        )
        .map_err(|_| AuthorizationError::Credential)?;
        ids.push(fact.credential_id());
        facts.push(fact)
    }
    ids.sort_unstable();
    if ids != envelope.credential_ids {
        return Err(AuthorizationError::CredentialSubstitution);
    }
    let schemas = canonical_schema_facts(&facts).map_err(|_| AuthorizationError::Credential)?;
    let chain = &candidate.capability_chain;
    if chain.is_empty() || chain.len() > MAX_CAPABILITY_DEPTH {
        return Err(AuthorizationError::Capability);
    }
    for (index, capability) in chain.iter().enumerate() {
        if !verifier.verify_capability_signature(capability)
            || !verifier.verify_capability_active(
                capability,
                envelope.height,
                envelope.finalized_state_root,
            )
        {
            return Err(AuthorizationError::Capability);
        }
        if index == 0 && capability.fields().parent_capability.is_some() {
            return Err(AuthorizationError::Capability);
        }
        if index > 0 {
            verify_attenuation(&chain[index - 1], capability)
                .map_err(|_| AuthorizationError::Attenuation)?
        }
    }
    let mut ids = chain.iter().map(|v| v.fields().capability_id).collect::<Vec<_>>();
    ids.sort_unstable();
    if ids != envelope.capability_ids {
        return Err(AuthorizationError::CapabilitySubstitution);
    }
    let leaf = chain.last().ok_or(AuthorizationError::Capability)?;
    let fields = leaf.fields();
    if fields.holder_binding != HolderBinding::Principal(envelope.actor)
        || !fields.permitted_actions.as_slice().contains(&TRANSFER_OBJECT_ACTION_ID)
        || !ResourceSelector::exact(candidate.transaction.commands()[0].input().object_id())
            .is_subset_of(&fields.resource_scope)
        || envelope.height < fields.valid_from
        || fields.valid_until.is_some_and(|end| envelope.height > end)
    {
        return Err(AuthorizationError::CapabilityScope);
    }
    let request = PolicyRequest::new(PolicyRequestFields {
        actor: ActorBinding::Principal(envelope.actor),
        action: TRANSFER_OBJECT_ACTION_ID,
        resource: candidate.transaction.commands()[0].input().object_id(),
        height: envelope.height,
        value: envelope.value,
        freeze_state: envelope.freeze_state,
        declared_purpose: envelope.declared_purpose,
        credential_schemas: schemas,
        capabilities: envelope.capability_ids.clone(),
        approvals: envelope.approvals.clone(),
    })
    .map_err(|_| AuthorizationError::Policy)?;
    let decision = evaluate(candidate.transaction.commands()[0].control_policy(), &request);
    if decision.result() != DecisionResult::Permit || !decision.obligations().is_empty() {
        return Err(AuthorizationError::Policy);
    }
    if candidate.transaction.commands()[0].request() != &request {
        return Err(AuthorizationError::RequestSubstitution);
    }
    let envelope_commitment =
        commit(DomainTag::CANONICAL_VALUE, envelope).map_err(|_| AuthorizationError::Encoding)?;
    Ok(VerifiedAuthorization {
        envelope: envelope.clone(),
        envelope_commitment,
        leaf_capability: leaf.clone(),
    })
}

fn save_typed_snapshot<T: CanonicalType>(path: &Path, snapshot: &T) -> std::io::Result<()> {
    let mut bytes = encode_envelope(snapshot).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "authorization snapshot encoding failed",
        )
    })?;
    let tag = snapshot_tag(&bytes);
    bytes.extend_from_slice(&tag);
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    let parent =
        path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)?.sync_all()
}
fn load_typed_snapshot<T: CanonicalType>(path: &Path) -> std::io::Result<T> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "authorization snapshot truncated",
        ));
    }
    let body = bytes.len() - 32;
    if snapshot_tag(&bytes[..body]) != bytes[body..] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "authorization snapshot corrupt",
        ));
    }
    decode_envelope(&bytes[..body]).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "authorization snapshot invalid")
    })
}
fn save_snapshot(path: &Path, snapshot: &AuthorizedSnapshot) -> std::io::Result<()> {
    save_typed_snapshot(path, snapshot)
}
fn load_snapshot(path: &Path) -> std::io::Result<AuthorizedSnapshot> {
    load_typed_snapshot(path)
}
fn snapshot_tag(bytes: &[u8]) -> [u8; 32] {
    let mut h = Shake256::default();
    h.update(b"ACTIVECHAIN-AUTHORIZATION-SNAPSHOT-V1");
    h.update(bytes);
    let mut out = [0; 32];
    h.finalize_xof().read(&mut out);
    out
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationError {
    MalformedEnvelope,
    Authentication,
    Encoding,
    Credential,
    CredentialSubstitution,
    Capability,
    CapabilitySubstitution,
    Attenuation,
    CapabilityScope,
    TransitionSubstitution,
    RequestSubstitution,
    Policy,
    Replay,
    Budget,
    RateLimit,
    Transition,
    Persistence,
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_credential::{CredentialStatus, credential_id, credential_issuance_commitment};
    use activechain_policy_kernel::{
        APL_LANGUAGE_VERSION, PolicyEffect, PolicyPredicate, PolicyRule, PolicySet,
    };
    use activechain_protocol_types::{
        AccessManifest, AccessManifestFields, BoundedActionSet, CREDENTIAL_FORMAT_VERSION,
        CapabilityGrantFields, CredentialStatement, DataSelector, Object, ObjectFields,
        ObjectFlags, ObjectId, ObjectOwner, ObjectVersionRef,
    };
    use activechain_transition::TransferCommand;
    use std::sync::{Arc, Barrier};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn actor() -> PrincipalId {
        PrincipalId::new(digest(0x20))
    }
    fn genesis() -> Digest384 {
        digest(0x98)
    }
    const EPOCH: u64 = 7;
    fn object_id() -> ObjectId {
        ObjectId::new(digest(0x40))
    }
    fn cap_id(byte: u8) -> CapabilityId {
        CapabilityId::new(digest(byte))
    }
    fn signature() -> ProtocolSignature {
        ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![7; 2420]).unwrap()
    }

    fn capability_chain() -> Vec<CapabilityGrant> {
        let intermediary = PrincipalId::new(digest(0x55));
        let common =
            |id, issuer, holder, parent, depth, allowed, money, uses| CapabilityGrantFields {
                capability_id: id,
                issuer,
                holder_binding: HolderBinding::Principal(holder),
                parent_capability: parent,
                permitted_actions: BoundedActionSet::new(vec![TRANSFER_OBJECT_ACTION_ID]).unwrap(),
                resource_scope: ResourceSelector::exact(object_id()),
                data_scope: DataSelector::ANY,
                monetary_limit: Some(money),
                compute_limit: Some(100),
                rate_limit: Some(RateLimit::new(1, 10).unwrap()),
                use_limit: Some(uses),
                valid_from: 1,
                valid_until: Some(100),
                delegation_depth_remaining: depth,
                delegation_allowed: allowed,
                revocation_registry: Some(ObjectId::new(digest(0x70))),
                constraint_hash: digest(0x71),
            };
        vec![
            CapabilityGrant::new(
                common(
                    cap_id(0x61),
                    PrincipalId::new(digest(0x54)),
                    intermediary,
                    None,
                    1,
                    true,
                    20,
                    2,
                ),
                signature(),
            )
            .unwrap(),
            CapabilityGrant::new(
                common(cap_id(0x62), intermediary, actor(), Some(cap_id(0x61)), 0, false, 10, 1),
                signature(),
            )
            .unwrap(),
        ]
    }

    fn credential_material() -> CredentialMaterial {
        let registry_id = ObjectId::new(digest(0x50));
        let statement = CredentialStatement::new(
            CREDENTIAL_FORMAT_VERSION,
            PrincipalId::new(digest(0x10)),
            digest(0x20),
            digest(0x30),
            digest(0x40),
            40,
            900,
            Some(1100),
            Some(registry_id),
            Some(digest(0x60)),
            Some(digest(0x70)),
        )
        .unwrap();
        let credential = Credential::new(
            statement,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, vec![8; 3309]).unwrap(),
        )
        .unwrap();
        let registry = CredentialStatusRegistry::new(
            registry_id,
            PrincipalId::new(digest(0x10)),
            digest(0x30),
            digest(0x90),
            4,
            45,
        );
        let issuer_evidence = PreverifiedIssuerEvidence::new(
            statement.issuer(),
            credential_issuance_commitment(&statement).unwrap(),
            credential.issuer_signature().suite(),
            Some(digest(0x60)),
        );
        let status_evidence = PreverifiedStatusEvidence::new(
            registry.registry_id(),
            credential_id(&credential).unwrap(),
            registry.status_root(),
            registry.sequence(),
            CredentialStatus::Active,
        );
        CredentialMaterial {
            credential,
            policy: CredentialAcceptancePolicy::new(
                vec![PrincipalId::new(digest(0x10))],
                vec![digest(0x30)],
                5,
                true,
                true,
            )
            .unwrap(),
            issuer_evidence,
            registry: Some(registry),
            status_evidence: Some(status_evidence),
        }
    }

    fn policy() -> PolicySet {
        PolicySet::new(
            APL_LANGUAGE_VERSION,
            vec![
                PolicyRule::new(
                    PolicyEffect::Permit,
                    vec![
                        PolicyPredicate::ActorIs(ActorBinding::Principal(actor())),
                        PolicyPredicate::ActionIs(TRANSFER_OBJECT_ACTION_ID),
                        PolicyPredicate::ResourceMatches(ResourceSelector::exact(object_id())),
                        PolicyPredicate::HasCredentialSchema(digest(0x30)),
                        PolicyPredicate::HasCapability(cap_id(0x62)),
                        PolicyPredicate::FreezeStateIs(FreezeState::Active),
                        PolicyPredicate::ValueAtMost(20),
                    ],
                    vec![],
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    fn state() -> ObjectState {
        let policy = policy();
        let hash = commit(DomainTag::CANONICAL_VALUE, &policy).unwrap();
        ObjectState::new(vec![
            Object::new(ObjectFields {
                object_id: object_id(),
                object_version: 1,
                type_id: digest(0x41),
                owner: ObjectOwner::Principal(actor()),
                control_policy_hash: hash,
                use_policy_hash: digest(0x42),
                disclosure_policy_hash: digest(0x43),
                upgrade_policy_hash: digest(0x44),
                package_id: None,
                value_root: digest(0x45),
                public_value: None,
                lease_expiry_epoch: 100,
                storage_deposit: 1,
                flags: ObjectFlags::TRANSFERABLE,
            })
            .unwrap(),
        ])
        .unwrap()
    }

    fn gateway(path: PathBuf) -> AuthorizationGateway {
        AuthorizationGateway::new(state(), path, genesis(), EPOCH).unwrap()
    }

    fn state_root() -> Digest384 {
        commit_objects(state().objects()).unwrap().root()
    }

    fn candidate(invocation: u8, value: u128) -> AuthorizationCandidate {
        let caps = capability_chain();
        let material = credential_material();
        let credential_ids = vec![credential_id(&material.credential).unwrap()];
        let capability_ids = caps.iter().map(|v| v.fields().capability_id).collect::<Vec<_>>();
        let request = PolicyRequest::new(PolicyRequestFields {
            actor: ActorBinding::Principal(actor()),
            action: TRANSFER_OBJECT_ACTION_ID,
            resource: object_id(),
            height: 50,
            value,
            freeze_state: FreezeState::Active,
            declared_purpose: None,
            credential_schemas: vec![digest(0x30)],
            capabilities: capability_ids.clone(),
            approvals: vec![],
        })
        .unwrap();
        let input = ObjectVersionRef::new(object_id(), 1);
        let transaction = TransferTransaction::new(
            50,
            AccessManifest::new(AccessManifestFields {
                exact_reads: vec![],
                exact_writes: vec![input],
                immutable_reads: vec![],
                creation_namespaces: vec![],
                maximum_created_objects: 0,
                maximum_dynamic_reads: 0,
                dynamic_read_policy: None,
            })
            .unwrap(),
            vec![TransferCommand::new(input, ObjectOwner::Shared, policy(), request)],
        )
        .unwrap();
        let transition = commit(DomainTag::CANONICAL_VALUE, &transaction).unwrap();
        let envelope = AuthorizationEnvelope::new(
            digest(invocation),
            genesis(),
            EPOCH,
            actor(),
            50,
            1000,
            state_root(),
            transition,
            value,
            1,
            FreezeState::Active,
            None,
            vec![],
            credential_ids,
            capability_ids,
            signature(),
        )
        .unwrap();
        AuthorizationCandidate {
            envelope,
            credentials: vec![material],
            capability_chain: caps,
            transaction,
        }
    }

    struct Verifier {
        actor: bool,
        context: bool,
        credential: bool,
        status: bool,
        capability: bool,
        active: bool,
    }
    impl Default for Verifier {
        fn default() -> Self {
            Self {
                actor: true,
                context: true,
                credential: true,
                status: true,
                capability: true,
                active: true,
            }
        }
    }
    impl AuthorizationVerifier for Verifier {
        fn verify_actor_signature(&self, _: &AuthorizationEnvelope) -> bool {
            self.actor
        }
        fn verify_finalized_context(&self, _: &AuthorizationEnvelope) -> bool {
            self.context
        }
        fn verify_credential_signature(&self, _: &Credential) -> bool {
            self.credential
        }
        fn verify_credential_status(&self, _: &CredentialMaterial) -> bool {
            self.status
        }
        fn verify_capability_signature(&self, _: &CapabilityGrant) -> bool {
            self.capability
        }
        fn verify_capability_active(&self, _: &CapabilityGrant, _: u64, _: Digest384) -> bool {
            self.active
        }
    }

    #[test]
    fn joined_chain_accepts_once_persists_and_fails_closed() {
        let path =
            std::env::temp_dir().join(format!("activechain-auth-{}.snapshot", std::process::id()));
        let gateway = gateway(path.clone());
        assert_eq!(
            commit(DomainTag::CANONICAL_VALUE, &candidate(1, 5).envelope).unwrap(),
            Digest384::new([
                80, 87, 26, 234, 234, 21, 147, 104, 247, 71, 49, 91, 21, 148, 221, 74, 138, 155,
                166, 205, 26, 3, 175, 56, 190, 50, 147, 157, 216, 184, 80, 88, 200, 150, 149, 246,
                184, 149, 85, 172, 230, 12, 46, 59, 194, 219, 164, 216,
            ])
        );
        assert_eq!(
            include_str!("../../../testing/vectors/authority/authorization-chain-v1.txt"),
            "type_tag=0x007d\nschema_version=2\ncredential_count=1\ncapability_depth=2\nenvelope_commitment=50571aeaea159368f747315b1594dd4a8a9ba6cd1a03af38be32939dd8b85058c89695f6b89555ace60c2e3bc2dba4d8\n"
        );
        for (expected_genesis, expected_epoch, expected_root) in [
            (digest(0x99), EPOCH, state_root()),
            (genesis(), EPOCH + 1, state_root()),
            (genesis(), EPOCH, digest(0x97)),
        ] {
            assert_eq!(
                verify_authorization_candidate(
                    &candidate(1, 5),
                    expected_genesis,
                    expected_epoch,
                    expected_root,
                    &Verifier::default(),
                ),
                Err(AuthorizationError::Authentication)
            );
        }
        assert_eq!(
            gateway.admit(candidate(1, 5), &Verifier::default()).unwrap().result(),
            ReceiptResult::Success
        );
        assert_eq!(
            gateway.admit(candidate(1, 5), &Verifier::default()),
            Err(AuthorizationError::Replay)
        );
        let mut exhausted = candidate(2, 5);
        exhausted.envelope.finalized_state_root =
            commit_objects(gateway.state().unwrap().objects()).unwrap().root();
        assert_eq!(gateway.admit(exhausted, &Verifier::default()), Err(AuthorizationError::Budget));
        let restarted = AuthorizationGateway::load(path.clone()).unwrap();
        assert_eq!(restarted.state().unwrap().objects()[0].owner(), ObjectOwner::Shared);
        // A snapshot declaring a zero genesis must be refused on load, exactly as
        // AuthorizationGateway::new refuses one. Restoring it would produce a gateway whose
        // context no AuthorizationEnvelope can ever match.
        let mut zeroed = load_snapshot(&path).unwrap();
        zeroed.chain_genesis_commitment = Digest384::ZERO;
        let zero_path = path.with_extension("zero");
        save_snapshot(&zero_path, &zeroed).unwrap();
        assert!(AuthorizationGateway::load(zero_path.clone()).is_err());
        let _ = std::fs::remove_file(zero_path);

        let mut bytes = std::fs::read(&path).unwrap();
        bytes[10] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(AuthorizationGateway::load(path.clone()).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn signatures_status_attenuation_scope_and_budgets_fail_closed() {
        let unique = |suffix| {
            std::env::temp_dir()
                .join(format!("activechain-auth-{}-{suffix}.snapshot", std::process::id()))
        };
        for (verifier, error) in [
            (Verifier { actor: false, ..Verifier::default() }, AuthorizationError::Authentication),
            (
                Verifier { context: false, ..Verifier::default() },
                AuthorizationError::Authentication,
            ),
            (Verifier { credential: false, ..Verifier::default() }, AuthorizationError::Credential),
            (Verifier { status: false, ..Verifier::default() }, AuthorizationError::Credential),
            (Verifier { capability: false, ..Verifier::default() }, AuthorizationError::Capability),
            (Verifier { active: false, ..Verifier::default() }, AuthorizationError::Capability),
        ] {
            assert_eq!(gateway(unique(error as u8)).admit(candidate(2, 5), &verifier), Err(error));
        }
        assert_eq!(
            gateway(unique(9)).admit(candidate(3, 11), &Verifier::default()),
            Err(AuthorizationError::Budget)
        );
        let mut substituted = candidate(10, 5);
        substituted.envelope.transition_commitment = digest(0xee);
        assert_eq!(
            gateway(unique(10)).admit(substituted, &Verifier::default()),
            Err(AuthorizationError::TransitionSubstitution)
        );
        let mut amplified = candidate(11, 5);
        let mut fields = amplified.capability_chain[1].fields().clone();
        fields.monetary_limit = Some(21);
        amplified.capability_chain[1] = CapabilityGrant::new(fields, signature()).unwrap();
        assert_eq!(
            gateway(unique(11)).admit(amplified, &Verifier::default()),
            Err(AuthorizationError::Attenuation)
        );
        let mut stale = candidate(12, 5);
        stale.credentials[0].registry = Some(CredentialStatusRegistry::new(
            ObjectId::new(digest(0x50)),
            PrincipalId::new(digest(0x10)),
            digest(0x30),
            digest(0x90),
            4,
            44,
        ));
        assert_eq!(
            gateway(unique(12)).admit(stale, &Verifier::default()),
            Err(AuthorizationError::Credential)
        );
        let mut revoked = candidate(13, 5);
        let credential = &revoked.credentials[0].credential;
        let registry = revoked.credentials[0].registry.as_ref().unwrap();
        revoked.credentials[0].status_evidence = Some(PreverifiedStatusEvidence::new(
            registry.registry_id(),
            credential_id(credential).unwrap(),
            registry.status_root(),
            registry.sequence(),
            CredentialStatus::Revoked,
        ));
        assert_eq!(
            gateway(unique(13)).admit(revoked, &Verifier::default()),
            Err(AuthorizationError::Credential)
        );
        let mut request_substitution = candidate(14, 5);
        let original = request_substitution.transaction.commands()[0].clone();
        let wrong_request = PolicyRequest::new(PolicyRequestFields {
            actor: ActorBinding::Principal(actor()),
            action: TRANSFER_OBJECT_ACTION_ID,
            resource: object_id(),
            height: 50,
            value: 5,
            freeze_state: FreezeState::Active,
            declared_purpose: None,
            credential_schemas: vec![],
            capabilities: request_substitution.envelope.capability_ids.clone(),
            approvals: vec![],
        })
        .unwrap();
        request_substitution.transaction = TransferTransaction::new(
            50,
            request_substitution.transaction.access_manifest().clone(),
            vec![TransferCommand::new(
                original.input(),
                original.new_owner(),
                original.control_policy().clone(),
                wrong_request,
            )],
        )
        .unwrap();
        request_substitution.envelope.transition_commitment =
            commit(DomainTag::CANONICAL_VALUE, &request_substitution.transaction).unwrap();
        assert_eq!(
            gateway(unique(14)).admit(request_substitution, &Verifier::default()),
            Err(AuthorizationError::RequestSubstitution)
        );
        let missing_parent = std::env::temp_dir()
            .join(format!("activechain-auth-missing-{}", std::process::id()))
            .join("snapshot");
        let failed_publish = gateway(missing_parent);
        assert_eq!(
            failed_publish.admit(candidate(15, 5), &Verifier::default()),
            Err(AuthorizationError::Persistence)
        );
        assert_eq!(failed_publish.state(), Err(AuthorizationError::Poisoned));
        assert_eq!(
            failed_publish.admit(candidate(15, 5), &Verifier::default()),
            Err(AuthorizationError::Poisoned)
        );
        let rate_candidate = |invocation| {
            let mut value = candidate(invocation, 1);
            for capability in &mut value.capability_chain {
                let mut fields = capability.fields().clone();
                fields.use_limit = None;
                *capability = CapabilityGrant::new(fields, signature()).unwrap();
            }
            value
        };
        let rate_path = unique(16);
        let rate_gateway = gateway(rate_path.clone());
        assert!(rate_gateway.admit(rate_candidate(16), &Verifier::default()).is_ok());
        let mut second = rate_candidate(17);
        second.envelope.finalized_state_root =
            commit_objects(rate_gateway.state().unwrap().objects()).unwrap().root();
        assert_eq!(
            rate_gateway.admit(second, &Verifier::default()),
            Err(AuthorizationError::RateLimit)
        );
        let _ = std::fs::remove_file(rate_path);
        let mut compute_exhausted = candidate(18, 1);
        compute_exhausted.envelope.compute = 101;
        assert_eq!(
            gateway(unique(18)).admit(compute_exhausted, &Verifier::default()),
            Err(AuthorizationError::Budget)
        );
    }

    #[test]
    fn concurrent_duplicate_invocation_has_one_atomic_winner() {
        let path = std::env::temp_dir()
            .join(format!("activechain-auth-concurrent-{}.snapshot", std::process::id()));
        let gateway = Arc::new(gateway(path.clone()));
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let gateway = Arc::clone(&gateway);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                gateway.admit(candidate(4, 5), &Verifier::default())
            }));
        }
        barrier.wait();
        let results = handles.into_iter().map(|v| v.join().unwrap()).collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|v| v.is_ok()).count(), 1);
        assert_eq!(
            results.iter().filter(|v| matches!(v, Err(AuthorizationError::Replay))).count(),
            1
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn finalized_replay_store_is_batch_atomic_and_restart_safe() {
        let path = std::env::temp_dir()
            .join(format!("activechain-authorization-replay-{}.snapshot", std::process::id()));
        let untrusted = candidate(21, 5);
        let verified = verify_authorization_candidate(
            &untrusted,
            genesis(),
            EPOCH,
            state_root(),
            &Verifier::default(),
        )
        .unwrap();
        let store = AuthorizationReplayStore::new(path.clone(), genesis(), EPOCH).unwrap();

        assert_eq!(
            store.admit_batch(&[verified.clone(), verified.clone()]),
            Err(AuthorizationError::Replay)
        );
        assert!(store.admit_batch(std::slice::from_ref(&verified)).is_ok());

        let restored = AuthorizationReplayStore::load(path.clone()).unwrap();
        assert_eq!(
            restored.admit_batch(std::slice::from_ref(&verified)),
            Err(AuthorizationError::Replay)
        );
        let unavailable = std::env::temp_dir()
            .join(format!("activechain-auth-replay-missing-{}", std::process::id()))
            .join("snapshot");
        let failed = AuthorizationReplayStore::new(unavailable, genesis(), EPOCH).unwrap();
        assert_eq!(
            failed.admit_batch(std::slice::from_ref(&verified)),
            Err(AuthorizationError::Persistence)
        );
        assert_eq!(
            failed.admit_batch(std::slice::from_ref(&verified)),
            Err(AuthorizationError::Poisoned)
        );
        let _ = std::fs::remove_file(path);
    }
}
