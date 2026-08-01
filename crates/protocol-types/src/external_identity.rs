//! Governed bindings between external credential issuers and ActiveChain principals.

extern crate alloc;

use crate::{ChainId, Digest384, Height, PrincipalId};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_EXTERNAL_ISSUER_PROFILES: usize = 16;
pub const MAX_EXTERNAL_ISSUER_BINDINGS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalIssuerBindingError {
    InvalidIdentity,
    InvalidProfiles,
    InvalidValidity,
    InvalidSequence,
    InvalidLifecycleTransition,
    PreviousBindingMismatch,
    StableIdentityMismatch,
    TooManyBindings,
    BindingsNotOrdered,
    ExternalIdentityCollision,
    FinalizedHeightRollback,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExternalIssuerProfileV1 {
    credential_configuration_id: Digest384,
    credential_type: Digest384,
    rulebook_id: Digest384,
    rulebook_version: u32,
    rulebook_digest: Digest384,
    signing_identity_commitment: Digest384,
}

impl ExternalIssuerProfileV1 {
    pub const MAX_ENCODED_LEN: usize = 48 * 5 + 4;
    pub fn new(
        configuration: Digest384,
        credential_type: Digest384,
        rulebook_id: Digest384,
        rulebook_version: u32,
        rulebook_digest: Digest384,
        signing_identity: Digest384,
    ) -> Result<Self, ExternalIssuerBindingError> {
        if [configuration, credential_type, rulebook_id, rulebook_digest, signing_identity]
            .into_iter()
            .any(|value| value == Digest384::ZERO)
            || rulebook_version == 0
        {
            return Err(ExternalIssuerBindingError::InvalidProfiles);
        }
        Ok(Self {
            credential_configuration_id: configuration,
            credential_type,
            rulebook_id,
            rulebook_version,
            rulebook_digest,
            signing_identity_commitment: signing_identity,
        })
    }
    pub const fn credential_configuration_id(&self) -> Digest384 {
        self.credential_configuration_id
    }
}
impl CanonicalEncode for ExternalIssuerProfileV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.credential_configuration_id.encode(e)?;
        self.credential_type.encode(e)?;
        self.rulebook_id.encode(e)?;
        self.rulebook_version.encode(e)?;
        self.rulebook_digest.encode(e)?;
        self.signing_identity_commitment.encode(e)
    }
}
impl CanonicalDecode for ExternalIssuerProfileV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u32::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid external issuer profile"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExternalIssuerBindingStatusV1 {
    Active = 0,
    Suspended = 1,
    Superseded = 2,
    Retired = 3,
}
impl ExternalIssuerBindingStatusV1 {
    const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Active, Self::Active | Self::Suspended | Self::Superseded | Self::Retired)
                | (
                    Self::Suspended,
                    Self::Active | Self::Suspended | Self::Superseded | Self::Retired
                )
        )
    }
}
impl CanonicalEncode for ExternalIssuerBindingStatusV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for ExternalIssuerBindingStatusV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Active),
            1 => Ok(Self::Suspended),
            2 => Ok(Self::Superseded),
            3 => Ok(Self::Retired),
            tag => {
                Err(DecodeError::InvalidEnumTag { type_name: "ExternalIssuerBindingStatusV1", tag })
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalIssuerBindingV1 {
    chain_id: ChainId,
    genesis_commitment: Digest384,
    issuer: PrincipalId,
    external_issuer_identity: Digest384,
    trust_identity_commitment: Digest384,
    profiles: Vec<ExternalIssuerProfileV1>,
    valid_from_height: Height,
    valid_until_height: Option<Height>,
    sequence: u64,
    previous_binding_commitment: Option<Digest384>,
    governance_authorization: Digest384,
    status: ExternalIssuerBindingStatusV1,
}
impl ExternalIssuerBindingV1 {
    pub const TYPE_TAG: u16 = 0x0153;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 6
        + 4
        + MAX_EXTERNAL_ISSUER_PROFILES * ExternalIssuerProfileV1::MAX_ENCODED_LEN
        + 8
        + 9
        + 8
        + 49
        + 1;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        genesis: Digest384,
        issuer: PrincipalId,
        external_identity: Digest384,
        trust_identity: Digest384,
        profiles: Vec<ExternalIssuerProfileV1>,
        valid_from: Height,
        valid_until: Option<Height>,
        sequence: u64,
        previous: Option<Digest384>,
        governance: Digest384,
        status: ExternalIssuerBindingStatusV1,
    ) -> Result<Self, ExternalIssuerBindingError> {
        if chain_id.digest() == &Digest384::ZERO
            || genesis == Digest384::ZERO
            || issuer.digest() == &Digest384::ZERO
            || external_identity == Digest384::ZERO
            || trust_identity == Digest384::ZERO
            || governance == Digest384::ZERO
            || previous == Some(Digest384::ZERO)
        {
            return Err(ExternalIssuerBindingError::InvalidIdentity);
        }
        if profiles.is_empty()
            || profiles.len() > MAX_EXTERNAL_ISSUER_PROFILES
            || !profiles
                .windows(2)
                .all(|p| p[0].credential_configuration_id() < p[1].credential_configuration_id())
        {
            return Err(ExternalIssuerBindingError::InvalidProfiles);
        }
        if valid_until.is_some_and(|end| end <= valid_from) {
            return Err(ExternalIssuerBindingError::InvalidValidity);
        }
        if sequence == 0 || (sequence == 1) != previous.is_none() {
            return Err(ExternalIssuerBindingError::InvalidSequence);
        }
        Ok(Self {
            chain_id,
            genesis_commitment: genesis,
            issuer,
            external_issuer_identity: external_identity,
            trust_identity_commitment: trust_identity,
            profiles,
            valid_from_height: valid_from,
            valid_until_height: valid_until,
            sequence,
            previous_binding_commitment: previous,
            governance_authorization: governance,
            status,
        })
    }
    pub const fn issuer(&self) -> PrincipalId {
        self.issuer
    }
    pub const fn external_issuer_identity(&self) -> Digest384 {
        self.external_issuer_identity
    }
    pub const fn status(&self) -> ExternalIssuerBindingStatusV1 {
        self.status
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn profiles(&self) -> &[ExternalIssuerProfileV1] {
        &self.profiles
    }
    pub fn admits_profile(&self, configuration: Digest384) -> bool {
        self.profiles
            .binary_search_by_key(&configuration, |p| p.credential_configuration_id())
            .is_ok()
    }
    pub fn active_at(&self, height: Height) -> bool {
        self.status == ExternalIssuerBindingStatusV1::Active
            && height >= self.valid_from_height
            && self.valid_until_height.is_none_or(|end| height < end)
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-EXTERNAL-ISSUER-BINDING-V1");
        hasher.update(&bytes);
        let mut output = [0; 48];
        XofReader::read(&mut hasher.finalize_xof(), &mut output);
        Ok(Digest384::new(output))
    }
    pub fn validate_successor(&self, next: &Self) -> Result<(), ExternalIssuerBindingError> {
        if self.chain_id != next.chain_id
            || self.genesis_commitment != next.genesis_commitment
            || self.issuer != next.issuer
            || self.external_issuer_identity != next.external_issuer_identity
        {
            return Err(ExternalIssuerBindingError::StableIdentityMismatch);
        }
        if !self.status.can_transition_to(next.status) {
            return Err(ExternalIssuerBindingError::InvalidLifecycleTransition);
        }
        if next.sequence
            != self.sequence.checked_add(1).ok_or(ExternalIssuerBindingError::InvalidSequence)?
        {
            return Err(ExternalIssuerBindingError::InvalidSequence);
        }
        if next.previous_binding_commitment
            != Some(
                self.commitment()
                    .map_err(|_| ExternalIssuerBindingError::PreviousBindingMismatch)?,
            )
        {
            return Err(ExternalIssuerBindingError::PreviousBindingMismatch);
        }
        Ok(())
    }
}
impl CanonicalEncode for ExternalIssuerBindingV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.genesis_commitment.encode(e)?;
        self.issuer.encode(e)?;
        self.external_issuer_identity.encode(e)?;
        self.trust_identity_commitment.encode(e)?;
        e.write_length(self.profiles.len(), MAX_EXTERNAL_ISSUER_PROFILES)?;
        for profile in &self.profiles {
            profile.encode(e)?;
        }
        self.valid_from_height.encode(e)?;
        self.valid_until_height.encode(e)?;
        self.sequence.encode(e)?;
        self.previous_binding_commitment.encode(e)?;
        self.governance_authorization.encode(e)?;
        self.status.encode(e)
    }
}
impl CanonicalDecode for ExternalIssuerBindingV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            {
                let count = d.read_length(MAX_EXTERNAL_ISSUER_PROFILES)?;
                let mut profiles = Vec::with_capacity(count);
                for _ in 0..count {
                    profiles.push(ExternalIssuerProfileV1::decode(d)?);
                }
                profiles
            },
            Height::decode(d)?,
            Option::decode(d)?,
            u64::decode(d)?,
            Option::decode(d)?,
            Digest384::decode(d)?,
            ExternalIssuerBindingStatusV1::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid external issuer binding"))
    }
}
impl CanonicalType for ExternalIssuerBindingV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalIssuerRegistryV1 {
    finalized_height: Height,
    bindings: Vec<ExternalIssuerBindingV1>,
}
impl ExternalIssuerRegistryV1 {
    pub const TYPE_TAG: u16 = 0x0154;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        8 + 4 + MAX_EXTERNAL_ISSUER_BINDINGS * ExternalIssuerBindingV1::MAX_ENCODED_LEN;
    pub fn new(
        finalized_height: Height,
        bindings: Vec<ExternalIssuerBindingV1>,
    ) -> Result<Self, ExternalIssuerBindingError> {
        if bindings.len() > MAX_EXTERNAL_ISSUER_BINDINGS {
            return Err(ExternalIssuerBindingError::TooManyBindings);
        }
        if !bindings.windows(2).all(|p| p[0].issuer < p[1].issuer) {
            return Err(ExternalIssuerBindingError::BindingsNotOrdered);
        }
        for (index, binding) in bindings.iter().enumerate() {
            if bindings[index + 1..]
                .iter()
                .any(|other| other.external_issuer_identity == binding.external_issuer_identity)
            {
                return Err(ExternalIssuerBindingError::ExternalIdentityCollision);
            }
        }
        Ok(Self { finalized_height, bindings })
    }
    pub fn resolve_by_issuer(
        &self,
        issuer: PrincipalId,
        height: Height,
    ) -> Option<&ExternalIssuerBindingV1> {
        if height > self.finalized_height {
            return None;
        }
        self.bindings
            .binary_search_by_key(&issuer, |b| b.issuer)
            .ok()
            .map(|i| &self.bindings[i])
            .filter(|b| b.active_at(height))
    }
    pub fn resolve_by_external_identity(
        &self,
        identity: Digest384,
        height: Height,
    ) -> Option<&ExternalIssuerBindingV1> {
        if height > self.finalized_height {
            return None;
        }
        self.bindings
            .iter()
            .find(|b| b.external_issuer_identity == identity)
            .filter(|b| b.active_at(height))
    }
    pub fn apply(
        &mut self,
        next: ExternalIssuerBindingV1,
        finalized_height: Height,
    ) -> Result<(), ExternalIssuerBindingError> {
        if finalized_height <= self.finalized_height {
            return Err(ExternalIssuerBindingError::FinalizedHeightRollback);
        }
        match self.bindings.binary_search_by_key(&next.issuer, |b| b.issuer) {
            Ok(index) => {
                self.bindings[index].validate_successor(&next)?;
                self.bindings[index] = next;
            }
            Err(index) => {
                if self.bindings.len() >= MAX_EXTERNAL_ISSUER_BINDINGS {
                    return Err(ExternalIssuerBindingError::TooManyBindings);
                }
                if next.sequence != 1
                    || next.previous_binding_commitment.is_some()
                    || next.status != ExternalIssuerBindingStatusV1::Active
                {
                    return Err(ExternalIssuerBindingError::InvalidSequence);
                }
                if self
                    .bindings
                    .iter()
                    .any(|b| b.external_issuer_identity == next.external_issuer_identity)
                {
                    return Err(ExternalIssuerBindingError::ExternalIdentityCollision);
                }
                self.bindings.insert(index, next);
            }
        }
        self.finalized_height = finalized_height;
        Ok(())
    }
}
impl CanonicalEncode for ExternalIssuerRegistryV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.finalized_height.encode(e)?;
        e.write_length(self.bindings.len(), MAX_EXTERNAL_ISSUER_BINDINGS)?;
        for binding in &self.bindings {
            binding.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for ExternalIssuerRegistryV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let finalized_height = Height::decode(d)?;
        let count = d.read_length(MAX_EXTERNAL_ISSUER_BINDINGS)?;
        let mut bindings = Vec::with_capacity(count);
        for _ in 0..count {
            bindings.push(ExternalIssuerBindingV1::decode(d)?);
        }
        Self::new(finalized_height, bindings)
            .map_err(|_| DecodeError::InvalidValue("invalid external issuer registry"))
    }
}
impl CanonicalType for ExternalIssuerRegistryV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::vec;
    fn d(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    fn p(n: u8) -> ExternalIssuerProfileV1 {
        ExternalIssuerProfileV1::new(d(n), d(n + 1), d(n + 2), 1, d(n + 3), d(n + 4)).unwrap()
    }
    #[allow(clippy::too_many_arguments)]
    fn binding(
        issuer: u8,
        external: u8,
        sequence: u64,
        previous: Option<Digest384>,
        status: ExternalIssuerBindingStatusV1,
        chain: u8,
    ) -> ExternalIssuerBindingV1 {
        ExternalIssuerBindingV1::new(
            ChainId::new(d(chain)),
            d(2),
            PrincipalId::new(d(issuer)),
            d(external),
            d(4),
            vec![p(10)],
            5,
            Some(100),
            sequence,
            previous,
            d(5),
            status,
        )
        .unwrap()
    }
    #[test]
    fn binding_round_trips_and_only_admits_pinned_profiles() {
        let value = binding(20, 30, 1, None, ExternalIssuerBindingStatusV1::Active, 1);
        let bytes = encode_envelope(&value).unwrap();
        assert_eq!(decode_envelope::<ExternalIssuerBindingV1>(&bytes), Ok(value.clone()));
        assert!(value.admits_profile(d(10)));
        assert!(!value.admits_profile(d(11)));
        assert!(value.active_at(5));
        assert!(!value.active_at(100));
    }
    #[test]
    fn lifecycle_is_previous_bound_and_preserves_stable_identity() {
        let first = binding(20, 30, 1, None, ExternalIssuerBindingStatusV1::Active, 1);
        let suspended = binding(
            20,
            30,
            2,
            Some(first.commitment().unwrap()),
            ExternalIssuerBindingStatusV1::Suspended,
            1,
        );
        assert_eq!(first.validate_successor(&suspended), Ok(()));
        let wrong_chain = binding(
            20,
            30,
            2,
            Some(first.commitment().unwrap()),
            ExternalIssuerBindingStatusV1::Suspended,
            9,
        );
        assert_eq!(
            first.validate_successor(&wrong_chain),
            Err(ExternalIssuerBindingError::StableIdentityMismatch)
        );
        let wrong_previous =
            binding(20, 30, 2, Some(d(99)), ExternalIssuerBindingStatusV1::Suspended, 1);
        assert_eq!(
            first.validate_successor(&wrong_previous),
            Err(ExternalIssuerBindingError::PreviousBindingMismatch)
        );
        let retired = binding(
            20,
            30,
            2,
            Some(first.commitment().unwrap()),
            ExternalIssuerBindingStatusV1::Retired,
            1,
        );
        let revival = binding(
            20,
            30,
            3,
            Some(retired.commitment().unwrap()),
            ExternalIssuerBindingStatusV1::Active,
            1,
        );
        assert_eq!(
            retired.validate_successor(&revival),
            Err(ExternalIssuerBindingError::InvalidLifecycleTransition)
        );
    }
    #[test]
    fn registry_is_bounded_unique_finalized_and_restart_safe() {
        let first = binding(20, 30, 1, None, ExternalIssuerBindingStatusV1::Active, 1);
        let mut registry = ExternalIssuerRegistryV1::new(5, vec![]).unwrap();
        registry.apply(first.clone(), 6).unwrap();
        assert_eq!(registry.resolve_by_issuer(first.issuer(), 6), Some(&first));
        assert!(registry.resolve_by_issuer(first.issuer(), 7).is_none());
        let duplicate = binding(21, 30, 1, None, ExternalIssuerBindingStatusV1::Active, 1);
        assert_eq!(
            registry.apply(duplicate, 7),
            Err(ExternalIssuerBindingError::ExternalIdentityCollision)
        );
        assert_eq!(
            registry.apply(first, 6),
            Err(ExternalIssuerBindingError::FinalizedHeightRollback)
        );
        let bytes = encode_envelope(&registry).unwrap();
        assert_eq!(decode_envelope::<ExternalIssuerRegistryV1>(&bytes), Ok(registry));
    }
    #[test]
    fn malformed_identity_profiles_and_order_fail_closed() {
        assert_eq!(
            ExternalIssuerProfileV1::new(Digest384::ZERO, d(2), d(3), 1, d(4), d(5)),
            Err(ExternalIssuerBindingError::InvalidProfiles)
        );
        let a = binding(20, 30, 1, None, ExternalIssuerBindingStatusV1::Active, 1);
        let b = binding(19, 31, 1, None, ExternalIssuerBindingStatusV1::Active, 1);
        assert_eq!(
            ExternalIssuerRegistryV1::new(5, vec![a, b]),
            Err(ExternalIssuerBindingError::BindingsNotOrdered)
        );
    }

    #[test]
    fn published_lifecycle_vector_is_closed_and_complete() {
        let vector = include_str!("../../../testing/vectors/external-issuer-binding-v1.tsv");
        let mut lines = vector.lines();
        assert_eq!(
            lines.next(),
            Some(
                "case\tsequence\tprevious\tstatus\tchain\tissuer\texternal_identity\tprofiles\tfinalized_height\texpected\treason"
            )
        );
        let rows = lines.map(|line| line.split('\t').collect::<Vec<_>>()).collect::<Vec<_>>();
        assert_eq!(rows.len(), 11);
        assert!(rows.iter().all(|row| row.len() == 11));
        assert_eq!(rows.iter().filter(|row| row[9] == "accept").count(), 4);
        assert_eq!(rows.iter().filter(|row| row[9] == "reject").count(), 7);
    }
}
