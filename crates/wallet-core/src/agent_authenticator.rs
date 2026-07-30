use crate::WalletError;
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_types::{
    AuthenticatorDescriptor, AuthenticatorId, AuthenticatorPurpose, CryptoSuiteId, Digest384,
    PrincipalId,
};
use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{io::Write, path::Path};

pub const MAX_AGENT_AUTHENTICATORS: usize = 256;
pub const MAX_AGENT_KEY_VERSIONS: usize = 16;
const SNAPSHOT_TAG_LENGTH: usize = 32;

fn rotation_allowed(
    compromised: bool,
    history_len: usize,
    current_revision: u64,
    expected_revision: u64,
    current_active: bool,
    valid_from: u64,
    rotation_height: u64,
) -> bool {
    !compromised
        && history_len < MAX_AGENT_KEY_VERSIONS
        && current_revision == expected_revision
        && current_active
        && valid_from == rotation_height
        && expected_revision < u64::MAX
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AgentKeyProvenance {
    UnattestedSoftware = 0,
    PlatformHardware = 1,
    ExternalHardware = 2,
    ManagedServiceHsm = 3,
}
impl CanonicalEncode for AgentKeyProvenance {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for AgentKeyProvenance {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::UnattestedSoftware),
            1 => Ok(Self::PlatformHardware),
            2 => Ok(Self::ExternalHardware),
            3 => Ok(Self::ManagedServiceHsm),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "AgentKeyProvenance", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentAuthenticatorVersionV1 {
    revision: u64,
    descriptor: AuthenticatorDescriptor,
    provenance: AgentKeyProvenance,
    deactivated_at: Option<u64>,
}
impl AgentAuthenticatorVersionV1 {
    pub fn new(
        revision: u64,
        descriptor: AuthenticatorDescriptor,
        provenance: AgentKeyProvenance,
    ) -> Result<Self, WalletError> {
        if revision == 0
            || descriptor.authenticator_id().into_digest() == Digest384::ZERO
            || descriptor.scheme() != CryptoSuiteId::ML_DSA_65
            || descriptor.purpose() != AuthenticatorPurpose::Control
            || descriptor.revoked_at().is_some()
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self { revision, descriptor, provenance, deactivated_at: None })
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn descriptor(&self) -> &AuthenticatorDescriptor {
        &self.descriptor
    }
    pub const fn provenance(&self) -> AgentKeyProvenance {
        self.provenance
    }
    pub const fn deactivated_at(&self) -> Option<u64> {
        self.deactivated_at
    }
}
impl CanonicalEncode for AgentAuthenticatorVersionV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.revision.encode(e)?;
        self.descriptor.encode(e)?;
        self.provenance.encode(e)?;
        self.deactivated_at.encode(e)
    }
}
impl CanonicalDecode for AgentAuthenticatorVersionV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let revision = u64::decode(d)?;
        let descriptor = AuthenticatorDescriptor::decode(d)?;
        let provenance = AgentKeyProvenance::decode(d)?;
        let deactivated_at = Option::<u64>::decode(d)?;
        let mut value = Self::new(revision, descriptor, provenance)
            .map_err(|_| DecodeError::InvalidValue("invalid agent authenticator version"))?;
        if deactivated_at == Some(0) {
            return Err(DecodeError::InvalidValue("zero agent key deactivation height"));
        }
        value.deactivated_at = deactivated_at;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentAuthenticatorRecordV1 {
    principal: PrincipalId,
    versions: Vec<AgentAuthenticatorVersionV1>,
    compromised_at: Option<u64>,
}
impl AgentAuthenticatorRecordV1 {
    pub fn principal(&self) -> PrincipalId {
        self.principal
    }
    pub fn versions(&self) -> &[AgentAuthenticatorVersionV1] {
        &self.versions
    }
    pub fn current(&self) -> &AgentAuthenticatorVersionV1 {
        self.versions.last().expect("records always contain one version")
    }
    pub const fn compromised_at(&self) -> Option<u64> {
        self.compromised_at
    }
}
impl CanonicalEncode for AgentAuthenticatorRecordV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.principal.encode(e)?;
        e.write_length(self.versions.len(), MAX_AGENT_KEY_VERSIONS)?;
        for version in &self.versions {
            version.encode(e)?;
        }
        self.compromised_at.encode(e)
    }
}
impl CanonicalDecode for AgentAuthenticatorRecordV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let principal = PrincipalId::decode(d)?;
        if principal.into_digest() == Digest384::ZERO {
            return Err(DecodeError::InvalidValue("zero agent principal"));
        }
        let count = d.read_length(MAX_AGENT_KEY_VERSIONS)?;
        if count == 0 {
            return Err(DecodeError::InvalidValue("agent has no authenticator"));
        }
        let mut versions = Vec::with_capacity(count);
        for _ in 0..count {
            let version = AgentAuthenticatorVersionV1::decode(d)?;
            if versions.last().is_some_and(|previous: &AgentAuthenticatorVersionV1| {
                previous.revision >= version.revision
                    || previous.descriptor.authenticator_id()
                        == version.descriptor.authenticator_id()
                    || previous.deactivated_at.is_none()
            }) {
                return Err(DecodeError::InvalidValue("invalid agent key history"));
            }
            versions.push(version);
        }
        let compromised_at = Option::<u64>::decode(d)?;
        if compromised_at == Some(0)
            || (compromised_at.is_some()
                && versions.last().is_some_and(|key| key.deactivated_at.is_none()))
        {
            return Err(DecodeError::InvalidValue("invalid compromised agent state"));
        }
        Ok(Self { principal, versions, compromised_at })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentAuthenticatorRegistryV1 {
    records: Vec<AgentAuthenticatorRecordV1>,
}
impl AgentAuthenticatorRegistryV1 {
    pub fn records(&self) -> &[AgentAuthenticatorRecordV1] {
        &self.records
    }

    pub fn enroll(
        &mut self,
        principal: PrincipalId,
        descriptor: AuthenticatorDescriptor,
        provenance: AgentKeyProvenance,
    ) -> Result<(), WalletError> {
        if principal.into_digest() == Digest384::ZERO {
            return Err(WalletError::MalformedAuthorization);
        }
        if self.records.len() >= MAX_AGENT_AUTHENTICATORS {
            return Err(WalletError::StateLimit);
        }
        if self.records.binary_search_by_key(&principal, |record| record.principal).is_ok()
            || self.contains_authenticator(descriptor.authenticator_id())
        {
            return Err(WalletError::AgentExists);
        }
        let version = AgentAuthenticatorVersionV1::new(1, descriptor, provenance)?;
        let position =
            self.records.binary_search_by_key(&principal, |record| record.principal).unwrap_err();
        self.records.insert(
            position,
            AgentAuthenticatorRecordV1 {
                principal,
                versions: alloc::vec![version],
                compromised_at: None,
            },
        );
        Ok(())
    }

    pub fn rotate(
        &mut self,
        principal: PrincipalId,
        expected_revision: u64,
        expected_authenticator: AuthenticatorId,
        descriptor: AuthenticatorDescriptor,
        provenance: AgentKeyProvenance,
        rotation_height: u64,
    ) -> Result<(), WalletError> {
        if rotation_height == 0 || self.contains_authenticator(descriptor.authenticator_id()) {
            return Err(WalletError::MalformedAuthorization);
        }
        let record = self.record_mut(principal)?;
        if !rotation_allowed(
            record.compromised_at.is_some(),
            record.versions.len(),
            record.current().revision,
            expected_revision,
            record.current().deactivated_at.is_none(),
            descriptor.valid_from(),
            rotation_height,
        ) || record.current().descriptor.authenticator_id() != expected_authenticator
        {
            return Err(WalletError::MalformedAuthorization);
        }
        let next_revision = expected_revision.checked_add(1).ok_or(WalletError::StateLimit)?;
        let next = AgentAuthenticatorVersionV1::new(next_revision, descriptor, provenance)?;
        record.versions.last_mut().expect("record has current key").deactivated_at =
            Some(rotation_height);
        record.versions.push(next);
        Ok(())
    }

    pub fn deactivate_compromised(
        &mut self,
        principal: PrincipalId,
        expected_revision: u64,
        height: u64,
    ) -> Result<(), WalletError> {
        if height == 0 {
            return Err(WalletError::MalformedAuthorization);
        }
        let record = self.record_mut(principal)?;
        if record.compromised_at.is_some()
            || record.current().revision != expected_revision
            || record.current().deactivated_at.is_some()
        {
            return Err(WalletError::AgentRevoked);
        }
        record.versions.last_mut().expect("record has current key").deactivated_at = Some(height);
        record.compromised_at = Some(height);
        Ok(())
    }

    pub fn current(
        &self,
        principal: PrincipalId,
        height: u64,
    ) -> Result<&AuthenticatorDescriptor, WalletError> {
        let index = self
            .records
            .binary_search_by_key(&principal, |record| record.principal)
            .map_err(|_| WalletError::UnknownAgent)?;
        let record = &self.records[index];
        let current = record.current();
        if record.compromised_at.is_some()
            || current.deactivated_at.is_some()
            || height < current.descriptor.valid_from()
            || current.descriptor.valid_until().is_some_and(|until| height > until)
        {
            return Err(WalletError::AgentRevoked);
        }
        Ok(&current.descriptor)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), WalletError> {
        let body = encode_envelope(self).map_err(|_| WalletError::Persistence)?;
        let tag = snapshot_tag(&body);
        let parent = path.parent().ok_or(WalletError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| WalletError::Persistence)?;
        let temporary = path.with_extension("tmp");
        let mut file = std::fs::File::create(&temporary).map_err(|_| WalletError::Persistence)?;
        file.write_all(&body).map_err(|_| WalletError::Persistence)?;
        file.write_all(&tag).map_err(|_| WalletError::Persistence)?;
        file.sync_all().map_err(|_| WalletError::Persistence)?;
        std::fs::rename(&temporary, path).map_err(|_| WalletError::Persistence)?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| WalletError::Persistence)
    }

    pub fn load(path: &Path) -> Result<Self, WalletError> {
        let bytes = std::fs::read(path).map_err(|_| WalletError::Persistence)?;
        if bytes.len() < SNAPSHOT_TAG_LENGTH {
            return Err(WalletError::Persistence);
        }
        let body = bytes.len() - SNAPSHOT_TAG_LENGTH;
        if snapshot_tag(&bytes[..body]) != bytes[body..] {
            return Err(WalletError::Persistence);
        }
        decode_envelope(&bytes[..body]).map_err(|_| WalletError::Persistence)
    }

    fn contains_authenticator(&self, id: AuthenticatorId) -> bool {
        self.records.iter().any(|record| {
            record.versions.iter().any(|version| version.descriptor.authenticator_id() == id)
        })
    }
    fn record_mut(
        &mut self,
        principal: PrincipalId,
    ) -> Result<&mut AgentAuthenticatorRecordV1, WalletError> {
        let index = self
            .records
            .binary_search_by_key(&principal, |record| record.principal)
            .map_err(|_| WalletError::UnknownAgent)?;
        Ok(&mut self.records[index])
    }
}
impl CanonicalEncode for AgentAuthenticatorRegistryV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_length(self.records.len(), MAX_AGENT_AUTHENTICATORS)?;
        for record in &self.records {
            record.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for AgentAuthenticatorRegistryV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = d.read_length(MAX_AGENT_AUTHENTICATORS)?;
        let mut records = Vec::with_capacity(count);
        let mut ids = Vec::new();
        for _ in 0..count {
            let record = AgentAuthenticatorRecordV1::decode(d)?;
            if records.last().is_some_and(|previous: &AgentAuthenticatorRecordV1| {
                previous.principal >= record.principal
            }) {
                return Err(DecodeError::InvalidValue("agent authenticators not ordered"));
            }
            for version in &record.versions {
                let id = version.descriptor.authenticator_id();
                if ids.contains(&id) {
                    return Err(DecodeError::InvalidValue("duplicate agent authenticator"));
                }
                ids.push(id);
            }
            records.push(record);
        }
        Ok(Self { records })
    }
}
impl CanonicalType for AgentAuthenticatorRegistryV1 {
    const TYPE_TAG: u16 = 0x012C;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 3 + MAX_AGENT_AUTHENTICATORS
        * (48
            + 1
            + MAX_AGENT_KEY_VERSIONS * (8 + AuthenticatorDescriptor::MAX_ENCODED_LEN + 1 + 9)
            + 9);
}

fn snapshot_tag(bytes: &[u8]) -> [u8; SNAPSHOT_TAG_LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-AGENT-AUTHENTICATOR-SNAPSHOT-V1");
    hasher.update(bytes);
    let mut output = [0; SNAPSHOT_TAG_LENGTH];
    XofReader::read(&mut hasher.finalize_xof(), &mut output);
    output
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn accepted_rotation_strictly_increments_revision_and_respects_every_gate() {
        let compromised: bool = kani::any();
        let history_len: usize = kani::any();
        let current_revision: u64 = kani::any();
        let expected_revision: u64 = kani::any();
        let current_active: bool = kani::any();
        let valid_from: u64 = kani::any();
        let rotation_height: u64 = kani::any();

        if rotation_allowed(
            compromised,
            history_len,
            current_revision,
            expected_revision,
            current_active,
            valid_from,
            rotation_height,
        ) {
            assert!(!compromised);
            assert!(history_len < MAX_AGENT_KEY_VERSIONS);
            assert_eq!(current_revision, expected_revision);
            assert!(current_active);
            assert_eq!(valid_from, rotation_height);
            assert!(expected_revision.checked_add(1).is_some());
            assert!(expected_revision + 1 > current_revision);
        }
    }

    #[kani::proof]
    fn compromised_or_deactivated_agent_cannot_rotate() {
        let history_len: usize = kani::any();
        let revision: u64 = kani::any();
        let height: u64 = kani::any();
        assert!(!rotation_allowed(true, history_len, revision, revision, true, height, height,));
        assert!(!rotation_allowed(false, history_len, revision, revision, false, height, height,));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }
    fn descriptor(byte: u8, valid_from: u64) -> AuthenticatorDescriptor {
        AuthenticatorDescriptor::new(
            AuthenticatorId::new(digest(byte)),
            CryptoSuiteId::ML_DSA_65,
            alloc::vec![byte; CryptoSuiteId::ML_DSA_65.verification_key_length().unwrap()],
            AuthenticatorPurpose::Control,
            valid_from,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn enrollment_rotation_and_compromise_are_monotonic() {
        let mut registry = AgentAuthenticatorRegistryV1::default();
        registry
            .enroll(principal(1), descriptor(2, 1), AgentKeyProvenance::PlatformHardware)
            .unwrap();
        assert_eq!(
            registry.current(principal(1), 1).unwrap().authenticator_id(),
            AuthenticatorId::new(digest(2))
        );
        registry
            .rotate(
                principal(1),
                1,
                AuthenticatorId::new(digest(2)),
                descriptor(3, 10),
                AgentKeyProvenance::ExternalHardware,
                10,
            )
            .unwrap();
        assert_eq!(registry.records()[0].versions()[0].deactivated_at(), Some(10));
        assert_eq!(registry.records()[0].current().revision(), 2);
        assert!(
            registry
                .rotate(
                    principal(1),
                    1,
                    AuthenticatorId::new(digest(2)),
                    descriptor(4, 11),
                    AgentKeyProvenance::ExternalHardware,
                    11
                )
                .is_err()
        );
        registry.deactivate_compromised(principal(1), 2, 12).unwrap();
        assert_eq!(registry.current(principal(1), 12), Err(WalletError::AgentRevoked));
        assert!(
            registry
                .rotate(
                    principal(1),
                    2,
                    AuthenticatorId::new(digest(3)),
                    descriptor(5, 13),
                    AgentKeyProvenance::ExternalHardware,
                    13
                )
                .is_err()
        );
    }

    #[test]
    fn duplicate_authenticators_and_corrupt_snapshots_fail_closed() {
        let mut registry = AgentAuthenticatorRegistryV1::default();
        registry
            .enroll(principal(1), descriptor(2, 1), AgentKeyProvenance::UnattestedSoftware)
            .unwrap();
        assert!(
            registry
                .enroll(principal(3), descriptor(2, 1), AgentKeyProvenance::UnattestedSoftware)
                .is_err()
        );
        let directory =
            std::env::temp_dir().join(format!("activechain-agent-auth-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("registry.bin");
        registry.save_atomic(&path).unwrap();
        assert_eq!(AgentAuthenticatorRegistryV1::load(&path).unwrap(), registry);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(AgentAuthenticatorRegistryV1::load(&path), Err(WalletError::Persistence));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
