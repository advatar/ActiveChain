use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_protocol_types::{
    AssetId, ChainId, ComplianceError, ComplianceEvidenceBindingV1, ComplianceReplayKey,
    ComplianceReplaySet, ComplianceSignatureEnvelopeV1, Digest384, ML_DSA44_PUBLIC_KEY_LENGTH,
    ProfileSelection, TransactionId, TravelRuleBindingV1,
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
    keys: BTreeMap<Digest384, Vec<u8>>,
}

impl ComplianceKeyRegistry {
    pub fn register(
        &mut self,
        profile: Digest384,
        public_key: Vec<u8>,
    ) -> Result<(), ComplianceAdmissionError> {
        if profile == Digest384::ZERO || public_key.len() != ML_DSA44_PUBLIC_KEY_LENGTH {
            return Err(ComplianceAdmissionError::InvalidSignature);
        }
        if !self.keys.contains_key(&profile) && self.keys.len() >= MAX_COMPLIANCE_PROVIDER_KEYS {
            return Err(ComplianceAdmissionError::InvalidSignature);
        }
        self.keys.insert(profile, public_key);
        Ok(())
    }

    pub fn verify(&self, signature: &ComplianceSignatureEnvelopeV1) -> bool {
        self.keys
            .get(&signature.profile())
            .is_some_and(|key| verify_compliance_signature(key, signature))
    }
}

#[derive(Debug)]
pub enum CompliancePersistenceError {
    Persistence,
    Replay,
    Capacity,
}

#[derive(Debug)]
pub enum ComplianceAdmissionError {
    InvalidEvidence,
    WrongChainOrAction,
    TravelRuleMismatch,
    Replay(CompliancePersistenceError),
    InvalidSignature,
    ProfileNotSelected,
}

/// Verifies a provider's ML-DSA-44 signature over the exact canonical
/// compliance envelope. The key registry remains an operator boundary; this
/// function performs the cryptographic check and never accepts a shape-only
/// signature.
pub fn verify_compliance_signature(
    public_key: &[u8],
    signature: &ComplianceSignatureEnvelopeV1,
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
    signature: &ComplianceSignatureEnvelopeV1,
    travel: Option<&TravelRuleBindingV1>,
    chain_id: ChainId,
    action: TransactionId,
    asset: Option<AssetId>,
    amount: Option<u128>,
    height: u64,
    verify_signature: impl Fn(&ComplianceSignatureEnvelopeV1) -> bool,
) -> Result<(), ComplianceAdmissionError> {
    if !verify_signature(signature) {
        return Err(ComplianceAdmissionError::InvalidSignature);
    }
    if evidence.chain_id() != chain_id
        || evidence.action() != action
        || !evidence.valid_at(height)
        || signature.chain_id() != chain_id
        || signature.profile() != evidence.profile()
        || signature.action() != action
        || signature.commitment() == activechain_protocol_types::Digest384::ZERO
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
    use activechain_protocol_types::{Digest384, PrincipalId, TransactionId};
    use alloc::vec;
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
        assert!(registry.register(Digest384::ZERO, vec![0; ML_DSA44_PUBLIC_KEY_LENGTH]).is_err());
        assert!(registry.register(Digest384::new([4; 48]), vec![0; 32]).is_err());
        let signature = ComplianceSignatureEnvelopeV1::new(
            Digest384::new([5; 48]),
            activechain_protocol_types::ChainId::new(Digest384::new([6; 48])),
            TransactionId::new(Digest384::new([7; 48])),
            Digest384::new([8; 48]),
            Digest384::new([9; 48]),
            activechain_protocol_types::ProtocolSignature::new(
                activechain_protocol_types::CryptoSuiteId::ML_DSA_44,
                vec![0; 2_420],
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!registry.verify(&signature));
    }
}
