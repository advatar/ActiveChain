use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope, inspect_canonical_envelope,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    AssetId, ChainId, ComplianceError, ComplianceEvidenceBindingV1, ComplianceReplayKey,
    ComplianceReplaySet, ComplianceReplayWitness, ComplianceSignatureEnvelopeV2,
    CredentialAssuranceClassV1, CredentialPredicateV1, Digest384, Height, KenyaRegulatedProfileV1,
    ML_DSA44_PUBLIC_KEY_LENGTH, PrincipalId, ProfileSelection, TlsCredentialEvidenceV1,
    TransactionId, TravelRuleBindingV1,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::vec::Vec;

const MAX_COMPLIANCE_PROVIDER_KEYS: usize = 256;

/// Operator-owned profile-to-provider key registry. Keys are configuration
/// state, never public ledger data, and are bounded to prevent untrusted
/// profile configuration from becoming an allocation vector.
#[derive(Clone, Debug, Default)]
pub struct ComplianceKeyRegistry {
    keys: BTreeMap<(Digest384, PrincipalId), Vec<u8>>,
}

impl ComplianceKeyRegistry {
    pub fn register(
        &mut self,
        profile: Digest384,
        provider: PrincipalId,
        public_key: Vec<u8>,
    ) -> Result<(), ComplianceAdmissionError> {
        if profile == Digest384::ZERO || public_key.len() != ML_DSA44_PUBLIC_KEY_LENGTH {
            return Err(ComplianceAdmissionError::InvalidSignature);
        }
        let identity = (profile, provider);
        if !self.keys.contains_key(&identity) && self.keys.len() >= MAX_COMPLIANCE_PROVIDER_KEYS {
            return Err(ComplianceAdmissionError::InvalidSignature);
        }
        self.keys.insert(identity, public_key);
        Ok(())
    }

    /// Revoke all signatures for a profile. Revocation is idempotent so an
    /// operator can safely replay a governance decision during restart.
    pub fn revoke(&mut self, profile: Digest384, provider: PrincipalId) -> bool {
        self.keys.remove(&(profile, provider)).is_some()
    }

    pub fn contains(&self, profile: Digest384, provider: PrincipalId) -> bool {
        self.keys.contains_key(&(profile, provider))
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), CompliancePersistenceError> {
        let records = self
            .keys
            .iter()
            .map(|((profile, provider), key)| ComplianceProviderKeyRecord {
                profile: *profile,
                provider: *provider,
                key: key.clone(),
            })
            .collect();
        let snapshot = ComplianceProviderKeySet { records };
        let bytes =
            encode_envelope(&snapshot).map_err(|_| CompliancePersistenceError::Persistence)?;
        let path = path.as_ref();
        let parent = path.parent().ok_or(CompliancePersistenceError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| CompliancePersistenceError::Persistence)?;
        let temporary = path.with_extension("tmp");
        let mut file = std::fs::File::create(&temporary)
            .map_err(|_| CompliancePersistenceError::Persistence)?;
        file.write_all(&bytes).map_err(|_| CompliancePersistenceError::Persistence)?;
        file.sync_all().map_err(|_| CompliancePersistenceError::Persistence)?;
        std::fs::rename(&temporary, path).map_err(|_| CompliancePersistenceError::Persistence)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, CompliancePersistenceError> {
        let bytes = std::fs::read(path).map_err(|_| CompliancePersistenceError::Persistence)?;
        let snapshot: ComplianceProviderKeySet =
            decode_envelope(&bytes).map_err(|_| CompliancePersistenceError::Persistence)?;
        let mut registry = Self::default();
        for record in snapshot.records {
            registry
                .register(record.profile, record.provider, record.key)
                .map_err(|_| CompliancePersistenceError::Persistence)?;
        }
        Ok(registry)
    }

    pub fn verify(&self, signature: &ComplianceSignatureEnvelopeV2) -> bool {
        self.keys
            .get(&(signature.profile(), signature.provider()))
            .is_some_and(|key| verify_compliance_signature(key, signature))
    }
}

const MAX_PROVIDER_KEY_RECORDS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ComplianceProviderKeyRecord {
    profile: Digest384,
    provider: PrincipalId,
    key: Vec<u8>,
}
impl CanonicalEncode for ComplianceProviderKeyRecord {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.profile.encode(e)?;
        self.provider.encode(e)?;
        e.write_bytes(&self.key, ML_DSA44_PUBLIC_KEY_LENGTH)
    }
}
impl CanonicalDecode for ComplianceProviderKeyRecord {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            profile: Digest384::decode(d)?,
            provider: PrincipalId::decode(d)?,
            key: d.read_bytes(ML_DSA44_PUBLIC_KEY_LENGTH)?.to_vec(),
        })
    }
}
impl CanonicalType for ComplianceProviderKeyRecord {
    const TYPE_TAG: u16 = 0x012E;
    const SCHEMA_VERSION: u16 = 2;
    const MAX_ENCODED_LEN: usize = 48 + 48 + 2 + ML_DSA44_PUBLIC_KEY_LENGTH;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ComplianceProviderKeySet {
    records: Vec<ComplianceProviderKeyRecord>,
}
impl CanonicalEncode for ComplianceProviderKeySet {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_length(self.records.len(), MAX_PROVIDER_KEY_RECORDS)?;
        for record in &self.records {
            record.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for ComplianceProviderKeySet {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = d.read_length(MAX_PROVIDER_KEY_RECORDS)?;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            records.push(ComplianceProviderKeyRecord::decode(d)?);
        }
        if records
            .windows(2)
            .any(|pair| (pair[0].profile, pair[0].provider) >= (pair[1].profile, pair[1].provider))
        {
            return Err(DecodeError::InvalidValue("provider keys not ordered"));
        }
        Ok(Self { records })
    }
}
impl CanonicalType for ComplianceProviderKeySet {
    const TYPE_TAG: u16 = 0x00d7;
    const SCHEMA_VERSION: u16 = 2;
    const MAX_ENCODED_LEN: usize =
        2 + MAX_PROVIDER_KEY_RECORDS * ComplianceProviderKeyRecord::MAX_ENCODED_LEN;
}

#[derive(Debug, Eq, PartialEq)]
pub enum CompliancePersistenceError {
    Persistence,
    Replay,
    Capacity,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ComplianceAdmissionError {
    InvalidEvidence,
    WrongChainOrAction,
    TravelRuleMismatch,
    Replay(CompliancePersistenceError),
    InvalidSignature,
    ProfileNotSelected,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CredentialPredicateAdmissionError {
    Expired,
    ContextMismatch,
    EvidenceMismatch,
    InsufficientAssurance,
    InvalidValueProof,
}

/// Admits a TLS-derived credential predicate while preserving its exact provenance class.
/// The evidence commitment occupies the predicate's claims-commitment slot, preventing an adapter
/// from substituting a different transcript, disclosure, holder, schema, or assurance class.
#[allow(clippy::too_many_arguments)]
pub fn admit_tls_credential_predicate(
    evidence: &TlsCredentialEvidenceV1,
    predicate: &CredentialPredicateV1,
    minimum_assurance: CredentialAssuranceClassV1,
    chain_id: ChainId,
    audience: PrincipalId,
    action: TransactionId,
    height: u64,
    verify_value: impl FnOnce(&CredentialPredicateV1) -> bool,
) -> Result<(), CredentialPredicateAdmissionError> {
    if !evidence.valid_at(height) || !predicate.valid_at(height) {
        return Err(CredentialPredicateAdmissionError::Expired);
    }
    if evidence.assurance() < minimum_assurance {
        return Err(CredentialPredicateAdmissionError::InsufficientAssurance);
    }
    if evidence.schema_id() != predicate.schema_id()
        || evidence.holder_binding() != predicate.holder_binding()
        || evidence.commitment().ok() != Some(predicate.claims_commitment())
    {
        return Err(CredentialPredicateAdmissionError::EvidenceMismatch);
    }
    if !predicate.binds_action(chain_id, audience, action) {
        return Err(CredentialPredicateAdmissionError::ContextMismatch);
    }
    if !verify_value(predicate) {
        return Err(CredentialPredicateAdmissionError::InvalidValueProof);
    }
    Ok(())
}

/// Admits a selective-disclosure predicate without exposing credential claims.
pub fn admit_credential_predicate(
    predicate: &CredentialPredicateV1,
    chain_id: ChainId,
    audience: activechain_protocol_types::PrincipalId,
    action: TransactionId,
    height: u64,
    verify_value: impl FnOnce(&CredentialPredicateV1) -> bool,
) -> Result<(), CredentialPredicateAdmissionError> {
    if !predicate.valid_at(height) {
        return Err(CredentialPredicateAdmissionError::Expired);
    }
    if !predicate.binds_action(chain_id, audience, action) {
        return Err(CredentialPredicateAdmissionError::ContextMismatch);
    }
    if !verify_value(predicate) {
        return Err(CredentialPredicateAdmissionError::InvalidValueProof);
    }
    Ok(())
}

/// Verifies a provider's ML-DSA-44 signature over the exact canonical
/// compliance envelope. The key registry remains an operator boundary; this
/// function performs the cryptographic check and never accepts a shape-only
/// signature.
pub fn verify_compliance_signature(
    public_key: &[u8],
    signature: &ComplianceSignatureEnvelopeV2,
) -> bool {
    activechain_crypto_provider::verify_ml_dsa44(
        public_key,
        &signature.signing_payload(),
        signature.signature().as_bytes(),
    )
    .is_ok()
}

pub fn require_selected_profile(
    selection: &ProfileSelection,
    profile: activechain_protocol_types::Digest384,
) -> Result<(), ComplianceAdmissionError> {
    match selection {
        ProfileSelection::Selected(ids) if ids.binary_search(&profile).is_ok() => Ok(()),
        _ => Err(ComplianceAdmissionError::ProfileNotSelected),
    }
}

/// Computes the only evidence commitment accepted by the V2 provider transcript.
pub fn compliance_evidence_commitment(
    evidence: &ComplianceEvidenceBindingV1,
) -> Result<Digest384, ComplianceAdmissionError> {
    commit(DomainTag::CANONICAL_VALUE, evidence)
        .map_err(|_| ComplianceAdmissionError::InvalidEvidence)
}

/// Admit one regulated transfer only after all public commitments match and the
/// nonce is durably consumed. Confidential payloads are never inspected here.
#[allow(clippy::too_many_arguments)]
pub fn admit_regulated_transfer(
    journal: &mut DurableComplianceReplayJournal,
    replay_witness: &ComplianceReplayWitness,
    evidence: ComplianceEvidenceBindingV1,
    signature: &ComplianceSignatureEnvelopeV2,
    travel: Option<&TravelRuleBindingV1>,
    chain_id: ChainId,
    genesis: Digest384,
    protocol_revision: u64,
    action: TransactionId,
    asset: Option<AssetId>,
    amount: Option<u128>,
    height: u64,
    registry: &ComplianceKeyRegistry,
) -> Result<(), ComplianceAdmissionError> {
    if !registry.verify(signature) {
        return Err(ComplianceAdmissionError::InvalidSignature);
    }
    let evidence_commitment = compliance_evidence_commitment(&evidence)?;
    if evidence.chain_id() != chain_id
        || evidence.genesis() != genesis
        || evidence.action() != action
        || !evidence.valid_at(height)
        || signature.chain_id() != chain_id
        || signature.genesis() != genesis
        || signature.protocol_revision() != protocol_revision
        || signature.provider() != evidence.operator()
        || signature.profile() != evidence.profile()
        || signature.subject() != evidence.subject()
        || signature.action() != action
        || signature.evidence_commitment() != evidence_commitment
        || signature.valid_from() != evidence.valid_from()
        || signature.valid_until() != evidence.valid_until()
        || signature.nonce() != evidence.nonce()
        || height < signature.valid_from()
        || height > signature.valid_until()
    {
        return Err(ComplianceAdmissionError::WrongChainOrAction);
    }
    if let Some(t) = travel
        && (t.chain_id() != chain_id
            || t.transfer() != action
            || asset.is_some_and(|a| t.asset() != a)
            || amount.is_some_and(|v| t.amount() != v)
            || t.expires_at() < height)
    {
        return Err(ComplianceAdmissionError::TravelRuleMismatch);
    }
    let key = ComplianceReplayKey::new(
        evidence.profile(),
        evidence.operator(),
        action,
        signature.nonce(),
    );
    journal.insert(key, replay_witness).map_err(ComplianceAdmissionError::Replay)
}

pub struct DurableComplianceReplayJournal {
    path: PathBuf,
    set: ComplianceReplaySet,
}
impl DurableComplianceReplayJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CompliancePersistenceError> {
        let path = path.as_ref().to_path_buf();
        let set = match std::fs::read(&path) {
            Ok(bytes) => decode_envelope(&bytes)
                .or_else(|_| decode_legacy_compliance_replay_set(&bytes))
                .map_err(|_| CompliancePersistenceError::Persistence)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ComplianceReplaySet::empty()
            }
            Err(_) => return Err(CompliancePersistenceError::Persistence),
        };
        Ok(Self { path, set })
    }
    pub const fn root(&self) -> Digest384 {
        self.set.root()
    }
    pub const fn count(&self) -> u64 {
        self.set.count()
    }
    pub fn insert(
        &mut self,
        key: ComplianceReplayKey,
        witness: &ComplianceReplayWitness,
    ) -> Result<(), CompliancePersistenceError> {
        let mut next = self.set.clone();
        next.insert(key, witness).map_err(|e| match e {
            ComplianceError::Replay => CompliancePersistenceError::Replay,
            _ => CompliancePersistenceError::Persistence,
        })?;
        let bytes = encode_envelope(&next).map_err(|_| CompliancePersistenceError::Persistence)?;
        let parent = self.path.parent().ok_or(CompliancePersistenceError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| CompliancePersistenceError::Persistence)?;
        let temporary = self.path.with_extension("tmp");
        let mut file = std::fs::File::create(&temporary)
            .map_err(|_| CompliancePersistenceError::Persistence)?;
        file.write_all(&bytes).map_err(|_| CompliancePersistenceError::Persistence)?;
        file.sync_all().map_err(|_| CompliancePersistenceError::Persistence)?;
        std::fs::rename(&temporary, &self.path)
            .map_err(|_| CompliancePersistenceError::Persistence)?;
        self.set = next;
        Ok(())
    }
}

fn decode_legacy_compliance_replay_set(bytes: &[u8]) -> Result<ComplianceReplaySet, DecodeError> {
    let envelope = inspect_canonical_envelope(
        bytes,
        ComplianceReplaySet::TYPE_TAG,
        1,
        2 + activechain_protocol_types::LEGACY_MAX_COMPLIANCE_REPLAY_KEYS
            * ComplianceReplayKey::MAX_ENCODED_LEN,
    )?;
    let mut decoder = Decoder::new(envelope.body());
    let set = ComplianceReplaySet::decode_legacy_v1(&mut decoder)?;
    decoder.finish()?;
    Ok(set)
}

const MAX_ACTIVATED_PROFILES: usize = 128;

/// Why a jurisdiction profile could not be activated, or a registry restored.
#[derive(Debug, Eq, PartialEq)]
pub enum JurisdictionRegistryError {
    /// The snapshot could not be read, decoded, or atomically replaced.
    Persistence,
    /// More activations than the registry will hold.
    Capacity,
    /// The snapshot names a different chain or genesis. Refused rather than
    /// adopted: a profile activated on one chain says nothing about another,
    /// and silently carrying one across is how a dev activation would reach a
    /// production ledger.
    CrossGenesis,
    /// A revision that does not advance the one already activated. Activation
    /// is monotone so that replaying a governance decision during restart is
    /// safe while a downgrade is not.
    NotAdvancing,
    /// A profile whose identity cannot key a registry.
    InvalidProfile,
}

/// The jurisdiction profiles a chain has activated, and the heights they bind.
///
/// Activation is consensus-visible state, never local process configuration.
/// Two validators reading the same chain must reach the same admission answer,
/// so this registry is derived from what the chain records — a genesis feature
/// set or an activation transition at a stated height — and never from an
/// environment variable, which would let a configuration difference fork the
/// chain.
///
/// A chain that activates nothing carries an empty registry and behaves exactly
/// as it did before this type existed. That is what keeps Kanalen bit-identical.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JurisdictionProfileRegistry {
    chain_id: ChainId,
    genesis_commitment: Digest384,
    profiles: BTreeMap<Digest384, KenyaRegulatedProfileV1>,
}

impl JurisdictionProfileRegistry {
    /// Opens an empty registry bound to one chain.
    ///
    /// # Errors
    /// Refuses a zero genesis commitment, which would bind the registry to
    /// nothing and make the cross-genesis check vacuous.
    pub fn new(
        chain_id: ChainId,
        genesis_commitment: Digest384,
    ) -> Result<Self, JurisdictionRegistryError> {
        if genesis_commitment == Digest384::ZERO {
            return Err(JurisdictionRegistryError::CrossGenesis);
        }
        Ok(Self { chain_id, genesis_commitment, profiles: BTreeMap::new() })
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub const fn genesis_commitment(&self) -> Digest384 {
        self.genesis_commitment
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Records one profile as activated.
    ///
    /// The profile itself is already complete by construction —
    /// [`KenyaRegulatedProfileV1::new`] refuses a missing commitment, an
    /// incomplete control mask, or a window that does not open before it
    /// closes — so activation adds what a single profile cannot know: that no
    /// earlier revision is being reinstated, and that the registry stays
    /// bounded.
    ///
    /// # Errors
    /// Refuses a zero profile id, a revision that does not advance the
    /// activated one, and an activation beyond the registry's capacity.
    pub fn activate(
        &mut self,
        profile: KenyaRegulatedProfileV1,
    ) -> Result<(), JurisdictionRegistryError> {
        let id = profile.profile_id();
        if id == Digest384::ZERO {
            return Err(JurisdictionRegistryError::InvalidProfile);
        }
        match self.profiles.get(&id) {
            Some(active) if profile.revision() <= active.revision() => {
                return Err(JurisdictionRegistryError::NotAdvancing);
            }
            None if self.profiles.len() >= MAX_ACTIVATED_PROFILES => {
                return Err(JurisdictionRegistryError::Capacity);
            }
            _ => {}
        }
        self.profiles.insert(id, profile);
        Ok(())
    }

    /// The profiles in force at a height.
    ///
    /// The window itself belongs to the profile, so this defers to
    /// [`KenyaRegulatedProfileV1::active_at`] rather than restating it — one
    /// definition of "in force", not two that can drift. Ids come back
    /// ascending because [`require_selected_profile`] resolves them by binary
    /// search.
    #[must_use]
    pub fn active_at(&self, height: Height) -> Vec<Digest384> {
        self.profiles
            .iter()
            .filter(|(_, profile)| profile.active_at(height))
            .map(|(id, _)| *id)
            .collect()
    }

    /// The selection to admit against at a height.
    ///
    /// A height with nothing in force yields `Rejected`, not an empty
    /// `Selected`: an empty selection would let [`require_selected_profile`]
    /// be asked a question it answers negatively for every profile, which
    /// reads the same as a refusal but arrives there by accident. A chain that
    /// activates nothing never reaches this call at all.
    #[must_use]
    pub fn selection_at(&self, height: Height) -> ProfileSelection {
        let active = self.active_at(height);
        if active.is_empty() {
            ProfileSelection::Rejected
        } else {
            ProfileSelection::Selected(active)
        }
    }

    fn snapshot(&self) -> ActivatedProfileSet {
        ActivatedProfileSet {
            chain: *self.chain_id.digest(),
            genesis_commitment: self.genesis_commitment,
            profiles: self.profiles.values().cloned().collect(),
        }
    }

    /// The commitment naming this exact activation set.
    ///
    /// A local snapshot is a cache, not an authority. The canonical envelope
    /// carries tag, version and length but no integrity check, so a damaged or
    /// edited file can decode as a different yet well-formed set — a flipped
    /// byte in a revision reads as a real profile at another revision. What
    /// makes that detectable is not a checksum the same writer could recompute,
    /// but comparing this root against the activation record the chain carries.
    /// That comparison is what keeps admission `f(consensus state)` rather than
    /// `f(process environment)`.
    ///
    /// # Errors
    /// Fails only if the set cannot be encoded, which a bounded registry of
    /// valid profiles does not.
    pub fn activation_root(&self) -> Result<Digest384, JurisdictionRegistryError> {
        commit(DomainTag::CANONICAL_VALUE, &self.snapshot())
            .map_err(|_| JurisdictionRegistryError::Persistence)
    }

    /// Writes the registry, replacing any previous snapshot atomically.
    ///
    /// # Errors
    /// Fails when the snapshot cannot be encoded, written, flushed, or renamed
    /// into place.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), JurisdictionRegistryError> {
        let snapshot = self.snapshot();
        let bytes =
            encode_envelope(&snapshot).map_err(|_| JurisdictionRegistryError::Persistence)?;
        let path = path.as_ref();
        let parent = path.parent().ok_or(JurisdictionRegistryError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| JurisdictionRegistryError::Persistence)?;
        let temporary = path.with_extension("tmp");
        let mut file = std::fs::File::create(&temporary)
            .map_err(|_| JurisdictionRegistryError::Persistence)?;
        file.write_all(&bytes).map_err(|_| JurisdictionRegistryError::Persistence)?;
        file.sync_all().map_err(|_| JurisdictionRegistryError::Persistence)?;
        std::fs::rename(&temporary, path).map_err(|_| JurisdictionRegistryError::Persistence)
    }

    /// Restores the registry for one chain, or starts an empty one.
    ///
    /// An absent snapshot is a new registry. A snapshot that cannot be decoded
    /// is an error rather than an empty registry, because starting empty would
    /// silently deactivate every profile a chain had activated — the failure
    /// mode a compliance store must never have.
    ///
    /// # Errors
    /// Refuses a snapshot naming another chain or genesis, one that does not
    /// decode, and one whose contents do not satisfy the activation rules.
    pub fn open(
        path: impl AsRef<Path>,
        chain_id: ChainId,
        genesis_commitment: Digest384,
    ) -> Result<Self, JurisdictionRegistryError> {
        let mut registry = Self::new(chain_id, genesis_commitment)?;
        let path = path.as_ref();
        if !path.exists() {
            return Ok(registry);
        }
        let bytes = std::fs::read(path).map_err(|_| JurisdictionRegistryError::Persistence)?;
        let snapshot: ActivatedProfileSet =
            decode_envelope(&bytes).map_err(|_| JurisdictionRegistryError::Persistence)?;
        if snapshot.chain != *chain_id.digest() || snapshot.genesis_commitment != genesis_commitment
        {
            return Err(JurisdictionRegistryError::CrossGenesis);
        }
        for profile in snapshot.profiles {
            registry.activate(profile)?;
        }
        Ok(registry)
    }
}

/// The canonical form of an activated profile set.
///
/// Carries the chain and genesis it was written under so a restore can refuse
/// a snapshot from elsewhere rather than adopt it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ActivatedProfileSet {
    chain: Digest384,
    genesis_commitment: Digest384,
    profiles: Vec<KenyaRegulatedProfileV1>,
}

impl CanonicalEncode for ActivatedProfileSet {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain.encode(encoder)?;
        self.genesis_commitment.encode(encoder)?;
        encoder.write_length(self.profiles.len(), MAX_ACTIVATED_PROFILES)?;
        for profile in &self.profiles {
            profile.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for ActivatedProfileSet {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain = Digest384::decode(decoder)?;
        let genesis_commitment = Digest384::decode(decoder)?;
        let count = decoder.read_length(MAX_ACTIVATED_PROFILES)?;
        let mut profiles = Vec::with_capacity(count);
        for _ in 0..count {
            profiles.push(KenyaRegulatedProfileV1::decode(decoder)?);
        }
        // Ascending and distinct, so a snapshot cannot smuggle in a duplicate
        // profile whose second copy would silently win the restore.
        if chain == Digest384::ZERO
            || genesis_commitment == Digest384::ZERO
            || profiles.windows(2).any(|pair| pair[0].profile_id() >= pair[1].profile_id())
        {
            return Err(DecodeError::InvalidValue("invalid activated profile set"));
        }
        Ok(Self { chain, genesis_commitment, profiles })
    }
}

impl CanonicalType for ActivatedProfileSet {
    const TYPE_TAG: u16 = 0x01c6;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        48 + 48 + 3 + MAX_ACTIVATED_PROFILES * KenyaRegulatedProfileV1::MAX_ENCODED_LEN;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_accumulator::{AccumulatorDomain, ReferenceSet};
    use activechain_protocol_types::{
        ChainId, CryptoSuiteId, Digest384, Height, KenyaRegulatedProfileV1, PrincipalId,
        ProtocolSignature, TransactionId,
    };
    use alloc::format;
    use alloc::vec;
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};

    fn digest(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    fn provider() -> PrincipalId {
        PrincipalId::new(digest(2))
    }
    fn evidence() -> ComplianceEvidenceBindingV1 {
        evidence_with_screening(digest(7))
    }
    fn evidence_with_screening(screening: Digest384) -> ComplianceEvidenceBindingV1 {
        ComplianceEvidenceBindingV1::new(
            digest(1),
            ChainId::new(digest(3)),
            digest(4),
            provider(),
            digest(5),
            TransactionId::new(digest(6)),
            screening,
            digest(8),
            digest(9),
            10,
            20,
            digest(10),
        )
        .unwrap()
    }
    fn signed_attestation(
        evidence: ComplianceEvidenceBindingV1,
        key: &SigningKey<MlDsa44>,
    ) -> ComplianceSignatureEnvelopeV2 {
        let commitment = commit(DomainTag::CANONICAL_VALUE, &evidence).unwrap();
        let unsigned = ComplianceSignatureEnvelopeV2::new(
            evidence.operator(),
            evidence.profile(),
            evidence.chain_id(),
            evidence.genesis(),
            7,
            evidence.subject(),
            evidence.action(),
            commitment,
            evidence.valid_from(),
            evidence.valid_until(),
            evidence.nonce(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        let signature = key.sign(&unsigned.signing_payload());
        ComplianceSignatureEnvelopeV2::new(
            unsigned.provider(),
            unsigned.profile(),
            unsigned.chain_id(),
            unsigned.genesis(),
            unsigned.protocol_revision(),
            unsigned.subject(),
            unsigned.action(),
            unsigned.evidence_commitment(),
            unsigned.valid_from(),
            unsigned.valid_until(),
            unsigned.nonce(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap()
    }
    fn key(n: u8) -> ComplianceReplayKey {
        ComplianceReplayKey::new(
            Digest384::new([1; 48]),
            PrincipalId::new(Digest384::new([2; 48])),
            TransactionId::new(Digest384::new([3; 48])),
            Digest384::new([n; 48]),
        )
    }
    fn replay_witness(
        prior: &[ComplianceReplayKey],
        candidate: ComplianceReplayKey,
    ) -> ComplianceReplayWitness {
        let mut reference = ReferenceSet::new(AccumulatorDomain::SpentInput);
        for key in prior {
            reference.insert(key.accumulator_key().into_bytes()).unwrap();
        }
        let candidate = candidate.accumulator_key();
        let witness = reference.non_membership_witness(candidate.into_bytes()).unwrap();
        ComplianceReplayWitness::new(
            candidate,
            witness.siblings.into_iter().map(Digest384::new).collect(),
        )
        .unwrap()
    }
    #[test]
    fn journal_survives_restart_and_rejects_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.bin");
        let mut j = DurableComplianceReplayJournal::open(&path).unwrap();
        let witness = replay_witness(&[], key(4));
        j.insert(key(4), &witness).unwrap();
        assert!(matches!(j.insert(key(4), &witness), Err(CompliancePersistenceError::Replay)));
        let j2 = DurableComplianceReplayJournal::open(&path).unwrap();
        assert_eq!(j2.count(), 1);
        assert_eq!(j2.root(), j.root());
    }

    #[test]
    fn legacy_journal_migrates_and_accepts_an_archived_witness() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy-replay.bin");
        let prior = [key(4), key(5)];
        let mut body = Encoder::new(2 + prior.len() * ComplianceReplayKey::MAX_ENCODED_LEN);
        body.write_length(
            prior.len(),
            activechain_protocol_types::LEGACY_MAX_COMPLIANCE_REPLAY_KEYS,
        )
        .unwrap();
        for key in prior {
            key.encode(&mut body).unwrap();
        }
        let body = body.finish();
        let mut envelope = Encoder::new(body.len() + 8);
        envelope.write_u16(ComplianceReplaySet::TYPE_TAG).unwrap();
        envelope.write_u16(1).unwrap();
        envelope
            .write_length(
                body.len(),
                2 + activechain_protocol_types::LEGACY_MAX_COMPLIANCE_REPLAY_KEYS
                    * ComplianceReplayKey::MAX_ENCODED_LEN,
            )
            .unwrap();
        envelope.write_raw(&body).unwrap();
        std::fs::write(&path, envelope.finish()).unwrap();

        let mut journal = DurableComplianceReplayJournal::open(&path).unwrap();
        assert_eq!(journal.count(), 2);
        let witness = replay_witness(&prior, key(6));
        journal.insert(key(6), &witness).unwrap();
        assert_eq!(journal.count(), 3);
        let restarted = DurableComplianceReplayJournal::open(&path).unwrap();
        assert_eq!(restarted.root(), journal.root());
        assert_eq!(restarted.count(), 3);
    }

    #[test]
    fn provider_key_registry_rejects_bad_shape_and_unknown_profiles() {
        let mut registry = ComplianceKeyRegistry::default();
        let profile = Digest384::new([4; 48]);
        assert!(
            registry
                .register(Digest384::ZERO, provider(), vec![0; ML_DSA44_PUBLIC_KEY_LENGTH])
                .is_err()
        );
        assert!(registry.register(profile, provider(), vec![0; 32]).is_err());
        assert!(!registry.contains(profile, provider()));
        assert!(!registry.revoke(profile, provider()));
        let signature = ComplianceSignatureEnvelopeV2::new(
            provider(),
            Digest384::new([5; 48]),
            activechain_protocol_types::ChainId::new(Digest384::new([6; 48])),
            digest(11),
            7,
            digest(12),
            TransactionId::new(Digest384::new([7; 48])),
            Digest384::new([8; 48]),
            1,
            2,
            Digest384::new([9; 48]),
            activechain_protocol_types::ProtocolSignature::new(
                activechain_protocol_types::CryptoSuiteId::ML_DSA_44,
                vec![0; 2_420],
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!registry.verify(&signature));
        assert!(
            registry.register(profile, provider(), vec![0; ML_DSA44_PUBLIC_KEY_LENGTH]).is_ok()
        );
        assert!(registry.contains(profile, provider()));
        assert!(registry.revoke(profile, provider()));
        assert!(!registry.contains(profile, provider()));
        assert!(!registry.revoke(profile, provider()));
    }

    #[test]
    fn provider_key_registry_round_trips_durably() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider-keys.bin");
        let profile = Digest384::new([12; 48]);
        let mut registry = ComplianceKeyRegistry::default();
        registry.register(profile, provider(), vec![7; ML_DSA44_PUBLIC_KEY_LENGTH]).unwrap();
        registry.save(&path).unwrap();
        let restored = ComplianceKeyRegistry::load(&path).unwrap();
        assert!(restored.contains(profile, provider()));
        assert_eq!(
            restored.keys.get(&(profile, provider())),
            Some(&vec![7; ML_DSA44_PUBLIC_KEY_LENGTH])
        );

        // Schema V1 did not bind keys to provider identities. It must be reissued,
        // never interpreted under the stronger V2 semantics.
        let mut legacy = std::fs::read(&path).unwrap();
        legacy[2..4].copy_from_slice(&1_u16.to_be_bytes());
        let legacy_path = dir.path().join("legacy-provider-keys.bin");
        std::fs::write(&legacy_path, legacy).unwrap();
        assert!(matches!(
            ComplianceKeyRegistry::load(&legacy_path),
            Err(CompliancePersistenceError::Persistence)
        ));
    }

    #[test]
    fn regulated_admission_binds_complete_evidence_context_and_replay() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([42; 32]));
        let evidence = evidence();
        let signature = signed_attestation(evidence, &key);
        let mut registry = ComplianceKeyRegistry::default();
        registry
            .register(
                evidence.profile(),
                evidence.operator(),
                key.verifying_key().encode().to_vec(),
            )
            .unwrap();
        let replay_key = ComplianceReplayKey::new(
            evidence.profile(),
            evidence.operator(),
            evidence.action(),
            signature.nonce(),
        );
        let replay_witness = replay_witness(&[], replay_key);
        let admit = |journal: &mut DurableComplianceReplayJournal,
                     candidate: ComplianceEvidenceBindingV1,
                     height,
                     genesis,
                     revision| {
            admit_regulated_transfer(
                journal,
                &replay_witness,
                candidate,
                &signature,
                None,
                evidence.chain_id(),
                genesis,
                revision,
                evidence.action(),
                None,
                None,
                height,
                &registry,
            )
        };
        let mut journal =
            DurableComplianceReplayJournal::open(dir.path().join("valid.bin")).unwrap();
        assert_eq!(admit(&mut journal, evidence, 15, evidence.genesis(), 7), Ok(()));
        assert_eq!(
            admit(&mut journal, evidence, 15, evidence.genesis(), 7),
            Err(ComplianceAdmissionError::Replay(CompliancePersistenceError::Replay))
        );

        for (name, candidate, height, genesis, revision) in [
            ("evidence", evidence_with_screening(digest(99)), 15, evidence.genesis(), 7),
            ("expired", evidence, 21, evidence.genesis(), 7),
            ("genesis", evidence, 15, digest(99), 7),
            ("revision", evidence, 15, evidence.genesis(), 8),
        ] {
            let mut isolated =
                DurableComplianceReplayJournal::open(dir.path().join(format!("{name}.bin")))
                    .unwrap();
            assert_eq!(
                admit(&mut isolated, candidate, height, genesis, revision),
                Err(ComplianceAdmissionError::WrongChainOrAction)
            );
        }

        let mut forged = signature.clone();
        let encoded = encode_envelope(&forged).unwrap();
        let last = encoded.len() - 1;
        let mut tampered = encoded;
        tampered[last] ^= 1;
        forged = decode_envelope(&tampered).unwrap();
        assert!(!registry.verify(&forged));
    }

    #[test]
    fn credential_predicate_admission_binds_context_and_expiry() {
        let chain = ChainId::new(Digest384::new([10; 48]));
        let audience = PrincipalId::new(Digest384::new([11; 48]));
        let action = TransactionId::new(Digest384::new([12; 48]));
        let predicate = CredentialPredicateV1::new(
            Digest384::new([1; 48]),
            Digest384::new([2; 48]),
            Digest384::new([3; 48]),
            chain,
            audience,
            action,
            Digest384::new([4; 48]),
            1,
            100,
            activechain_protocol_types::CredentialPredicateKind::AgeAtLeast,
            Digest384::new([5; 48]),
        )
        .unwrap();
        assert!(
            admit_credential_predicate(&predicate, chain, audience, action, 50, |_| true).is_ok()
        );
        assert_eq!(
            admit_credential_predicate(&predicate, chain, audience, action, 100, |_| true),
            Err(CredentialPredicateAdmissionError::Expired)
        );
        assert_eq!(
            admit_credential_predicate(
                &predicate,
                chain,
                PrincipalId::new(Digest384::new([9; 48])),
                action,
                50,
                |_| true
            ),
            Err(CredentialPredicateAdmissionError::ContextMismatch)
        );
    }

    #[test]
    fn tls_predicate_admission_rejects_assurance_and_evidence_substitution() {
        use activechain_protocol_types::{
            CredentialAssuranceClassV1, CredentialPredicateKind, TlsCredentialEvidenceV1,
        };

        let chain = ChainId::new(Digest384::new([10; 48]));
        let audience = PrincipalId::new(Digest384::new([11; 48]));
        let action = TransactionId::new(Digest384::new([12; 48]));
        let evidence = TlsCredentialEvidenceV1::new(
            Digest384::new([1; 48]),
            Digest384::new([2; 48]),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            10,
            100,
            Digest384::new([7; 48]),
            CredentialAssuranceClassV1::HolderSelfIssued,
            None,
        )
        .unwrap();
        let predicate = CredentialPredicateV1::new(
            evidence.schema_id(),
            evidence.commitment().unwrap(),
            evidence.holder_binding(),
            chain,
            audience,
            action,
            Digest384::new([8; 48]),
            1,
            90,
            CredentialPredicateKind::AssetAmountAtLeast,
            Digest384::new([9; 48]),
        )
        .unwrap();
        assert_eq!(
            admit_tls_credential_predicate(
                &evidence,
                &predicate,
                CredentialAssuranceClassV1::HolderSelfIssued,
                chain,
                audience,
                action,
                50,
                |_| true,
            ),
            Ok(())
        );
        assert_eq!(
            admit_tls_credential_predicate(
                &evidence,
                &predicate,
                CredentialAssuranceClassV1::IssuerUpgraded,
                chain,
                audience,
                action,
                50,
                |_| true,
            ),
            Err(CredentialPredicateAdmissionError::InsufficientAssurance)
        );

        let substituted = TlsCredentialEvidenceV1::new(
            Digest384::new([1; 48]),
            Digest384::new([2; 48]),
            Digest384::new([30; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            10,
            100,
            Digest384::new([7; 48]),
            CredentialAssuranceClassV1::HolderSelfIssued,
            None,
        )
        .unwrap();
        assert_eq!(
            admit_tls_credential_predicate(
                &substituted,
                &predicate,
                CredentialAssuranceClassV1::TlsNotarizedEvidence,
                chain,
                audience,
                action,
                50,
                |_| true,
            ),
            Err(CredentialPredicateAdmissionError::EvidenceMismatch)
        );
    }

    fn vasp_profile(
        id: u8,
        effective: Height,
        expires: Height,
        revision: u16,
    ) -> KenyaRegulatedProfileV1 {
        KenyaRegulatedProfileV1::new(
            digest(id),
            PrincipalId::new(digest(200)),
            activechain_protocol_types::KenyaRegulatedActivity::VirtualAssetService,
            activechain_protocol_types::KenyaControlSet::VASP_REQUIRED,
            digest(3),
            digest(4),
            digest(5),
            digest(6),
            digest(7),
            digest(8),
            digest(9),
            digest(10),
            digest(11),
            digest(12),
            digest(13),
            digest(14),
            Digest384::ZERO,
            Digest384::ZERO,
            Digest384::ZERO,
            Digest384::ZERO,
            effective,
            expires,
            revision,
        )
        .expect("a complete VASP profile")
    }

    fn registry() -> JurisdictionProfileRegistry {
        JurisdictionProfileRegistry::new(ChainId::new(digest(90)), digest(91))
            .expect("a registry bound to a real genesis")
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(alloc::format!(
            "activechain-jurisdiction-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch");
        path.join("profiles.snapshot")
    }

    /// The window belongs to the profile; the registry must not widen it.
    #[test]
    fn a_profile_admits_only_inside_the_window_it_declares() {
        let mut registry = registry();
        registry.activate(vasp_profile(1, 100, 200, 1)).unwrap();
        assert!(registry.active_at(99).is_empty(), "not yet effective");
        assert_eq!(
            registry.active_at(100),
            alloc::vec![digest(1)],
            "effective height is inclusive"
        );
        assert_eq!(registry.active_at(199), alloc::vec![digest(1)]);
        assert!(registry.active_at(200).is_empty(), "expiry is exclusive");
    }

    /// Replaying a governance decision during restart must be safe; reinstating
    /// a superseded profile must not be.
    #[test]
    fn activation_advances_or_is_refused() {
        let mut registry = registry();
        registry.activate(vasp_profile(1, 100, 200, 2)).unwrap();
        assert_eq!(
            registry.activate(vasp_profile(1, 100, 200, 2)),
            Err(JurisdictionRegistryError::NotAdvancing),
            "the same revision is not an advance"
        );
        assert_eq!(
            registry.activate(vasp_profile(1, 100, 200, 1)),
            Err(JurisdictionRegistryError::NotAdvancing),
            "an earlier revision must not reinstate itself"
        );
        registry.activate(vasp_profile(1, 100, 200, 3)).unwrap();
        assert_eq!(registry.len(), 1, "a revision replaces rather than accumulates");
    }

    /// A profile activated on one chain says nothing about another.
    #[test]
    fn a_snapshot_from_another_genesis_is_refused_rather_than_adopted() {
        let path = scratch("cross-genesis");
        let mut written = registry();
        written.activate(vasp_profile(1, 100, 200, 1)).unwrap();
        written.save(&path).unwrap();

        assert_eq!(
            JurisdictionProfileRegistry::open(&path, ChainId::new(digest(90)), digest(92)),
            Err(JurisdictionRegistryError::CrossGenesis),
            "a different genesis must not be adopted"
        );
        assert_eq!(
            JurisdictionProfileRegistry::open(&path, ChainId::new(digest(93)), digest(91)),
            Err(JurisdictionRegistryError::CrossGenesis),
            "a different chain must not be adopted"
        );
        let restored =
            JurisdictionProfileRegistry::open(&path, ChainId::new(digest(90)), digest(91)).unwrap();
        assert_eq!(restored, written, "its own chain and genesis restore exactly");
    }

    /// Starting empty would silently deactivate every activated profile, which
    /// is the one failure mode a compliance store must not have.
    #[test]
    fn a_truncated_snapshot_fails_closed_rather_than_starting_empty() {
        let path = scratch("truncated");
        let mut written = registry();
        written.activate(vasp_profile(1, 100, 200, 1)).unwrap();
        written.save(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();

        assert_eq!(
            JurisdictionProfileRegistry::open(&path, ChainId::new(digest(90)), digest(91)),
            Err(JurisdictionRegistryError::Persistence),
            "a truncated snapshot must not read as an empty registry"
        );
    }

    /// The envelope carries no integrity check, so a flipped byte inside a
    /// field decodes as a different but well-formed profile — here a revision
    /// reads as 254 rather than 1, and nothing local can tell. That is why the
    /// file is a cache and the chain holds the authority: the activation root
    /// moves, so a validator comparing against a chain-recorded root sees it.
    #[test]
    fn tampering_a_snapshot_moves_the_activation_root_that_consensus_pins() {
        let path = scratch("tampered");
        let mut written = registry();
        written.activate(vasp_profile(1, 100, 200, 1)).unwrap();
        written.save(&path).unwrap();
        let honest_root = written.activation_root().unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        let tampered =
            JurisdictionProfileRegistry::open(&path, ChainId::new(digest(90)), digest(91))
                .expect("a flipped field still decodes, which is the point");
        assert_ne!(tampered, written, "the set really did change");
        assert_ne!(
            tampered.activation_root().unwrap(),
            honest_root,
            "a chain-recorded root must not accept the altered set"
        );
    }

    /// The root names the set, not the order it was activated in, or two
    /// validators reaching the same state by different routes would disagree.
    #[test]
    fn the_activation_root_depends_on_the_set_and_not_the_order() {
        let mut forwards = registry();
        let mut backwards = registry();
        for id in [1_u8, 5, 9] {
            forwards.activate(vasp_profile(id, 100, 200, 1)).unwrap();
        }
        for id in [9_u8, 5, 1] {
            backwards.activate(vasp_profile(id, 100, 200, 1)).unwrap();
        }
        assert_eq!(forwards.activation_root().unwrap(), backwards.activation_root().unwrap());
    }

    /// A chain that has activated nothing must not present a selection that
    /// merely happens to admit nothing.
    #[test]
    fn a_height_with_nothing_in_force_is_rejected_not_an_empty_selection() {
        let mut registry = registry();
        registry.activate(vasp_profile(1, 100, 200, 1)).unwrap();
        assert_eq!(registry.selection_at(50), ProfileSelection::Rejected);
        assert_eq!(registry.selection_at(100), ProfileSelection::Selected(alloc::vec![digest(1)]));
    }

    /// `require_selected_profile` resolves by binary search, so a selection
    /// that is not ascending would refuse a profile it holds.
    #[test]
    fn a_selection_resolves_every_profile_it_contains() {
        let mut registry = registry();
        for id in [7_u8, 3, 9, 1] {
            registry.activate(vasp_profile(id, 100, 200, 1)).unwrap();
        }
        let selection = registry.selection_at(150);
        let ProfileSelection::Selected(ids) = &selection else { panic!("expected a selection") };
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "ids must ascend: {ids:?}");
        for id in [7_u8, 3, 9, 1] {
            assert_eq!(
                require_selected_profile(&selection, digest(id)),
                Ok(()),
                "an activated profile must resolve"
            );
        }
        assert_eq!(
            require_selected_profile(&selection, digest(2)),
            Err(ComplianceAdmissionError::ProfileNotSelected),
            "an unactivated profile must not"
        );
    }

    /// A chain that activates nothing behaves exactly as it did before this
    /// type existed, which is what keeps an existing network bit-identical.
    #[test]
    fn an_absent_snapshot_opens_an_empty_registry() {
        let path = scratch("absent");
        let registry =
            JurisdictionProfileRegistry::open(&path, ChainId::new(digest(90)), digest(91)).unwrap();
        assert!(registry.is_empty());
        assert_eq!(registry.selection_at(150), ProfileSelection::Rejected);
    }

    /// A registry bound to nothing would make the cross-genesis check vacuous.
    #[test]
    fn a_registry_must_be_bound_to_a_real_genesis() {
        assert_eq!(
            JurisdictionProfileRegistry::new(ChainId::new(digest(90)), Digest384::ZERO),
            Err(JurisdictionRegistryError::CrossGenesis)
        );
    }
}
