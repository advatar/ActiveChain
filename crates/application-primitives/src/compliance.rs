use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    AssetId, ChainId, ComplianceError, ComplianceEvidenceBindingV1, ComplianceReplayKey,
    ComplianceReplaySet, ComplianceSignatureEnvelopeV2, CredentialPredicateV1, Digest384,
    ML_DSA44_PUBLIC_KEY_LENGTH, PrincipalId, ProfileSelection, TransactionId, TravelRuleBindingV1,
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
    InvalidValueProof,
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

/// Admit one regulated transfer only after all public commitments match and the
/// nonce is durably consumed. Confidential payloads are never inspected here.
#[allow(clippy::too_many_arguments)]
pub fn admit_regulated_transfer(
    journal: &mut DurableComplianceReplayJournal,
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
    let evidence_commitment = commit(DomainTag::CANONICAL_VALUE, &evidence)
        .map_err(|_| ComplianceAdmissionError::InvalidEvidence)?;
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
    journal.insert(key).map_err(ComplianceAdmissionError::Replay)
}

pub struct DurableComplianceReplayJournal {
    path: PathBuf,
    set: ComplianceReplaySet,
}
impl DurableComplianceReplayJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CompliancePersistenceError> {
        let path = path.as_ref().to_path_buf();
        let set = match std::fs::read(&path) {
            Ok(bytes) => {
                decode_envelope(&bytes).map_err(|_| CompliancePersistenceError::Persistence)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ComplianceReplaySet::new(Vec::new())
                    .map_err(|_| CompliancePersistenceError::Persistence)?
            }
            Err(_) => return Err(CompliancePersistenceError::Persistence),
        };
        Ok(Self { path, set })
    }
    pub fn contains(&self, key: ComplianceReplayKey) -> bool {
        self.set.contains(key)
    }
    pub fn insert(&mut self, key: ComplianceReplayKey) -> Result<(), CompliancePersistenceError> {
        let mut next = self.set.clone();
        next.insert(key).map_err(|e| match e {
            ComplianceError::Replay => CompliancePersistenceError::Replay,
            ComplianceError::TooManyEntries => CompliancePersistenceError::Capacity,
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

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{
        CryptoSuiteId, Digest384, PrincipalId, ProtocolSignature, TransactionId,
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
    #[test]
    fn journal_survives_restart_and_rejects_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.bin");
        let mut j = DurableComplianceReplayJournal::open(&path).unwrap();
        j.insert(key(4)).unwrap();
        assert!(matches!(j.insert(key(4)), Err(CompliancePersistenceError::Replay)));
        let j2 = DurableComplianceReplayJournal::open(&path).unwrap();
        assert!(j2.contains(key(4)));
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
        let admit = |journal: &mut DurableComplianceReplayJournal,
                     candidate: ComplianceEvidenceBindingV1,
                     height,
                     genesis,
                     revision| {
            admit_regulated_transfer(
                journal,
                candidate,
                &signature,
                None,
                evidence.chain_id(),
                genesis,
                revision,
                evidence.action(),
                None,
                None,
                height, &registry,
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
}
