//! Wallet-authorized associations between external credential holders and ActiveChain principals.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{ChainId, Digest384, Height, PrincipalId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalSubjectBindingError {
    InvalidIdentity,
    InvalidProfile,
    InvalidScope,
    InvalidValidity,
    InvalidSequence,
    StableContextMismatch,
    PreviousBindingMismatch,
    ReplayOrRollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExternalSubjectBindingKindV1 {
    Account = 0,
    Pairwise = 1,
    PrivateProof = 2,
    Device = 3,
}

impl CanonicalEncode for ExternalSubjectBindingKindV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for ExternalSubjectBindingKindV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Account),
            1 => Ok(Self::Pairwise),
            2 => Ok(Self::PrivateProof),
            3 => Ok(Self::Device),
            tag => {
                Err(DecodeError::InvalidEnumTag { type_name: "ExternalSubjectBindingKindV1", tag })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExternalSubjectScopeKindV1 {
    Verifier = 0,
    Purpose = 1,
    Asset = 2,
}
impl CanonicalEncode for ExternalSubjectScopeKindV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for ExternalSubjectScopeKindV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Verifier),
            1 => Ok(Self::Purpose),
            2 => Ok(Self::Asset),
            tag => {
                Err(DecodeError::InvalidEnumTag { type_name: "ExternalSubjectScopeKindV1", tag })
            }
        }
    }
}

/// Canonical wallet approval transcript for associating an external holder/device key with a
/// principal. This value remains wallet/verifier evidence; only its derived subject commitment is
/// needed by credential predicates and consensus receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalSubjectBindingV1 {
    chain_id: ChainId,
    genesis_commitment: Digest384,
    issuer_binding_commitment: Digest384,
    schema_id: Digest384,
    principal: PrincipalId,
    holder_key_commitment: Digest384,
    device_attestation_commitment: Option<Digest384>,
    kind: ExternalSubjectBindingKindV1,
    scope_kind: Option<ExternalSubjectScopeKindV1>,
    scope_commitment: Option<Digest384>,
    private_witness_commitment: Option<Digest384>,
    purpose_commitment: Digest384,
    audience: PrincipalId,
    nonce: Digest384,
    binding_version: u32,
    sequence: u64,
    issued_height: Height,
    expires_height: Height,
    previous_binding_commitment: Option<Digest384>,
    consequences_commitment: Digest384,
    wallet_authorization_commitment: Digest384,
}

impl ExternalSubjectBindingV1 {
    pub const TYPE_TAG: u16 = 0x0155;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 12 + 49 * 4 + 1 + 2 + 4 + 8 * 3;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        genesis_commitment: Digest384,
        issuer_binding_commitment: Digest384,
        schema_id: Digest384,
        principal: PrincipalId,
        holder_key_commitment: Digest384,
        device_attestation_commitment: Option<Digest384>,
        kind: ExternalSubjectBindingKindV1,
        scope_kind: Option<ExternalSubjectScopeKindV1>,
        scope_commitment: Option<Digest384>,
        private_witness_commitment: Option<Digest384>,
        purpose_commitment: Digest384,
        audience: PrincipalId,
        nonce: Digest384,
        binding_version: u32,
        sequence: u64,
        issued_height: Height,
        expires_height: Height,
        previous_binding_commitment: Option<Digest384>,
        consequences_commitment: Digest384,
        wallet_authorization_commitment: Digest384,
    ) -> Result<Self, ExternalSubjectBindingError> {
        if chain_id.digest() == &Digest384::ZERO
            || principal.digest() == &Digest384::ZERO
            || audience.digest() == &Digest384::ZERO
            || [
                genesis_commitment,
                issuer_binding_commitment,
                schema_id,
                holder_key_commitment,
                purpose_commitment,
                nonce,
                consequences_commitment,
                wallet_authorization_commitment,
            ]
            .into_iter()
            .any(|value| value == Digest384::ZERO)
            || [
                device_attestation_commitment,
                scope_commitment,
                private_witness_commitment,
                previous_binding_commitment,
            ]
            .into_iter()
            .flatten()
            .any(|value| value == Digest384::ZERO)
        {
            return Err(ExternalSubjectBindingError::InvalidIdentity);
        }
        let profile_valid = match kind {
            ExternalSubjectBindingKindV1::Account => {
                device_attestation_commitment.is_none()
                    && scope_kind.is_none()
                    && scope_commitment.is_none()
                    && private_witness_commitment.is_none()
            }
            ExternalSubjectBindingKindV1::Pairwise => {
                device_attestation_commitment.is_none()
                    && scope_kind.is_some()
                    && scope_commitment.is_some()
                    && private_witness_commitment.is_none()
            }
            ExternalSubjectBindingKindV1::PrivateProof => {
                device_attestation_commitment.is_none()
                    && scope_kind.is_some()
                    && scope_commitment.is_some()
                    && private_witness_commitment.is_some()
            }
            ExternalSubjectBindingKindV1::Device => {
                device_attestation_commitment.is_some()
                    && scope_kind.is_none()
                    && scope_commitment.is_none()
                    && private_witness_commitment.is_none()
            }
        };
        if !profile_valid || scope_kind.is_some() != scope_commitment.is_some() {
            return Err(ExternalSubjectBindingError::InvalidProfile);
        }
        if binding_version == 0
            || sequence == 0
            || (sequence == 1) != previous_binding_commitment.is_none()
        {
            return Err(ExternalSubjectBindingError::InvalidSequence);
        }
        if issued_height >= expires_height {
            return Err(ExternalSubjectBindingError::InvalidValidity);
        }
        Ok(Self {
            chain_id,
            genesis_commitment,
            issuer_binding_commitment,
            schema_id,
            principal,
            holder_key_commitment,
            device_attestation_commitment,
            kind,
            scope_kind,
            scope_commitment,
            private_witness_commitment,
            purpose_commitment,
            audience,
            nonce,
            binding_version,
            sequence,
            issued_height,
            expires_height,
            previous_binding_commitment,
            consequences_commitment,
            wallet_authorization_commitment,
        })
    }

    pub const fn kind(&self) -> ExternalSubjectBindingKindV1 {
        self.kind
    }
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }
    pub const fn expires_height(&self) -> Height {
        self.expires_height
    }
    pub const fn wallet_authorization_commitment(&self) -> Digest384 {
        self.wallet_authorization_commitment
    }
    pub fn active_at(&self, height: Height) -> bool {
        self.issued_height <= height && height < self.expires_height
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        digest_transcript(b"ACTIVECHAIN-EXTERNAL-SUBJECT-ASSOCIATION-V1", &[&bytes])
    }
    pub fn replay_key(&self) -> Result<Digest384, EncodeError> {
        self.commitment()
    }
    pub fn slot_commitment(&self) -> Result<Digest384, EncodeError> {
        let kind = [self.kind as u8];
        let scope_kind = [self.scope_kind.map(|value| value as u8).unwrap_or(u8::MAX)];
        let scope = self.scope_commitment.unwrap_or(Digest384::ZERO);
        digest_transcript(
            b"ACTIVECHAIN-EXTERNAL-SUBJECT-SLOT-V1",
            &[
                self.chain_id.digest().as_bytes(),
                self.genesis_commitment.as_bytes(),
                self.issuer_binding_commitment.as_bytes(),
                self.schema_id.as_bytes(),
                self.principal.digest().as_bytes(),
                &kind,
                &scope_kind,
                scope.as_bytes(),
            ],
        )
    }
    pub fn subject_commitment(&self) -> Result<Digest384, EncodeError> {
        let kind = [self.kind as u8];
        let scope_kind = self.scope_kind.map(|value| value as u8).unwrap_or(u8::MAX);
        let scope_kind_bytes = [scope_kind];
        let binding_version = self.binding_version.to_be_bytes();
        let scope_commitment = self.scope_commitment.unwrap_or(Digest384::ZERO);
        let private_witness = self.private_witness_commitment.unwrap_or(Digest384::ZERO);
        let device_attestation = self.device_attestation_commitment.unwrap_or(Digest384::ZERO);
        let mut inputs: [&[u8]; 10] = [
            self.chain_id.digest().as_bytes(),
            self.genesis_commitment.as_bytes(),
            self.issuer_binding_commitment.as_bytes(),
            self.schema_id.as_bytes(),
            self.principal.digest().as_bytes(),
            self.holder_key_commitment.as_bytes(),
            &kind,
            &scope_kind_bytes,
            scope_commitment.as_bytes(),
            &binding_version,
        ];
        if self.kind == ExternalSubjectBindingKindV1::PrivateProof {
            inputs[5] = private_witness.as_bytes();
        }
        if self.kind == ExternalSubjectBindingKindV1::Device {
            inputs[8] = device_attestation.as_bytes();
        }
        digest_transcript(b"ACTIVECHAIN-EXTERNAL-SUBJECT-BINDING-V1", &inputs)
    }
    pub fn validate_successor(&self, next: &Self) -> Result<(), ExternalSubjectBindingError> {
        if self.chain_id != next.chain_id
            || self.genesis_commitment != next.genesis_commitment
            || self.issuer_binding_commitment != next.issuer_binding_commitment
            || self.schema_id != next.schema_id
            || self.principal != next.principal
            || self.kind != next.kind
            || self.scope_kind != next.scope_kind
            || self.scope_commitment != next.scope_commitment
        {
            return Err(ExternalSubjectBindingError::StableContextMismatch);
        }
        if next.sequence
            != self.sequence.checked_add(1).ok_or(ExternalSubjectBindingError::InvalidSequence)?
            || next.binding_version <= self.binding_version
        {
            return Err(ExternalSubjectBindingError::InvalidSequence);
        }
        if next.issued_height <= self.issued_height
            || next.nonce == self.nonce
            || next.wallet_authorization_commitment == self.wallet_authorization_commitment
        {
            return Err(ExternalSubjectBindingError::ReplayOrRollback);
        }
        if next.previous_binding_commitment
            != Some(
                self.commitment()
                    .map_err(|_| ExternalSubjectBindingError::PreviousBindingMismatch)?,
            )
        {
            return Err(ExternalSubjectBindingError::PreviousBindingMismatch);
        }
        Ok(())
    }
}

fn digest_transcript(domain: &[u8], inputs: &[&[u8]]) -> Result<Digest384, EncodeError> {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    for input in inputs {
        hasher.update(
            &u32::try_from(input.len()).map_err(|_| EncodeError::LengthOverflow)?.to_be_bytes(),
        );
        hasher.update(input);
    }
    let mut output = [0; 48];
    XofReader::read(&mut hasher.finalize_xof(), &mut output);
    Ok(Digest384::new(output))
}

impl CanonicalEncode for ExternalSubjectBindingV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.genesis_commitment.encode(e)?;
        self.issuer_binding_commitment.encode(e)?;
        self.schema_id.encode(e)?;
        self.principal.encode(e)?;
        self.holder_key_commitment.encode(e)?;
        self.device_attestation_commitment.encode(e)?;
        self.kind.encode(e)?;
        self.scope_kind.encode(e)?;
        self.scope_commitment.encode(e)?;
        self.private_witness_commitment.encode(e)?;
        self.purpose_commitment.encode(e)?;
        self.audience.encode(e)?;
        self.nonce.encode(e)?;
        self.binding_version.encode(e)?;
        self.sequence.encode(e)?;
        self.issued_height.encode(e)?;
        self.expires_height.encode(e)?;
        self.previous_binding_commitment.encode(e)?;
        self.consequences_commitment.encode(e)?;
        self.wallet_authorization_commitment.encode(e)
    }
}

impl CanonicalDecode for ExternalSubjectBindingV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Option::<Digest384>::decode(d)?,
            ExternalSubjectBindingKindV1::decode(d)?,
            Option::<ExternalSubjectScopeKindV1>::decode(d)?,
            Option::<Digest384>::decode(d)?,
            Option::<Digest384>::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            u32::decode(d)?,
            u64::decode(d)?,
            Height::decode(d)?,
            Height::decode(d)?,
            Option::<Digest384>::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid external subject binding"))
    }
}

impl CanonicalType for ExternalSubjectBindingV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};

    fn d(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    #[allow(clippy::too_many_arguments)]
    fn binding(
        kind: ExternalSubjectBindingKindV1,
        sequence: u64,
        version: u32,
        previous: Option<Digest384>,
        holder: u8,
        scope: u8,
    ) -> ExternalSubjectBindingV1 {
        let (device, scope_kind, scope_commitment, witness) = match kind {
            ExternalSubjectBindingKindV1::Account => (None, None, None, None),
            ExternalSubjectBindingKindV1::Pairwise => {
                (None, Some(ExternalSubjectScopeKindV1::Verifier), Some(d(scope)), None)
            }
            ExternalSubjectBindingKindV1::PrivateProof => {
                (None, Some(ExternalSubjectScopeKindV1::Purpose), Some(d(scope)), Some(d(18)))
            }
            ExternalSubjectBindingKindV1::Device => (Some(d(17)), None, None, None),
        };
        ExternalSubjectBindingV1::new(
            ChainId::new(d(1)),
            d(2),
            d(3),
            d(4),
            PrincipalId::new(d(5)),
            d(holder),
            device,
            kind,
            scope_kind,
            scope_commitment,
            witness,
            d(7),
            PrincipalId::new(d(8)),
            d(8 + sequence as u8),
            version,
            sequence,
            9 + sequence,
            30,
            previous,
            d(11),
            d(11 + sequence as u8),
        )
        .unwrap()
    }

    #[test]
    fn all_profiles_round_trip_and_are_domain_separated() {
        let kinds = [
            ExternalSubjectBindingKindV1::Account,
            ExternalSubjectBindingKindV1::Pairwise,
            ExternalSubjectBindingKindV1::PrivateProof,
            ExternalSubjectBindingKindV1::Device,
        ];
        let mut commitments = [Digest384::ZERO; 4];
        for (index, kind) in kinds.into_iter().enumerate() {
            let value = binding(kind, 1, 1, None, 6, 15);
            assert_eq!(
                decode_envelope::<ExternalSubjectBindingV1>(&encode_envelope(&value).unwrap()),
                Ok(value)
            );
            commitments[index] = value.subject_commitment().unwrap();
        }
        for left in 0..commitments.len() {
            for right in left + 1..commitments.len() {
                assert_ne!(commitments[left], commitments[right]);
            }
        }
    }

    #[test]
    fn pairwise_scope_and_holder_changes_change_the_subject() {
        let first = binding(ExternalSubjectBindingKindV1::Pairwise, 1, 1, None, 6, 15);
        let other_scope = binding(ExternalSubjectBindingKindV1::Pairwise, 1, 1, None, 6, 16);
        let other_holder = binding(ExternalSubjectBindingKindV1::Pairwise, 1, 1, None, 13, 15);
        assert_ne!(first.subject_commitment().unwrap(), other_scope.subject_commitment().unwrap());
        assert_ne!(first.subject_commitment().unwrap(), other_holder.subject_commitment().unwrap());
    }

    #[test]
    fn rotation_is_previous_bound_and_rejects_scope_or_principal_substitution() {
        let first = binding(ExternalSubjectBindingKindV1::Device, 1, 1, None, 6, 0);
        let next = binding(
            ExternalSubjectBindingKindV1::Device,
            2,
            2,
            Some(first.commitment().unwrap()),
            14,
            0,
        );
        assert_eq!(first.validate_successor(&next), Ok(()));
        let stale = binding(ExternalSubjectBindingKindV1::Device, 2, 2, Some(d(99)), 14, 0);
        assert_eq!(
            first.validate_successor(&stale),
            Err(ExternalSubjectBindingError::PreviousBindingMismatch)
        );
        let wrong_kind = binding(
            ExternalSubjectBindingKindV1::Account,
            2,
            2,
            Some(first.commitment().unwrap()),
            14,
            0,
        );
        assert_eq!(
            first.validate_successor(&wrong_kind),
            Err(ExternalSubjectBindingError::StableContextMismatch)
        );
        assert_eq!(first.replay_key().unwrap(), first.commitment().unwrap());
    }

    #[test]
    fn malformed_profile_zero_authorization_and_expiry_fail_closed() {
        assert!(
            ExternalSubjectBindingV1::new(
                ChainId::new(d(1)),
                d(2),
                d(3),
                d(4),
                PrincipalId::new(d(5)),
                d(6),
                None,
                ExternalSubjectBindingKindV1::Pairwise,
                None,
                None,
                None,
                d(7),
                PrincipalId::new(d(8)),
                d(9),
                1,
                1,
                10,
                20,
                None,
                d(11),
                d(12)
            )
            .is_err()
        );
        assert!(
            ExternalSubjectBindingV1::new(
                ChainId::new(d(1)),
                d(2),
                d(3),
                d(4),
                PrincipalId::new(d(5)),
                d(6),
                None,
                ExternalSubjectBindingKindV1::Account,
                None,
                None,
                None,
                d(7),
                PrincipalId::new(d(8)),
                d(9),
                1,
                1,
                20,
                20,
                None,
                d(11),
                Digest384::ZERO
            )
            .is_err()
        );
    }

    #[test]
    fn published_subject_binding_matrix_is_closed() {
        let vector = include_str!("../../../testing/vectors/external-subject-binding-v1.tsv");
        let mut lines = vector.lines();
        assert_eq!(
            lines.next(),
            Some(
                "case\tprofile\tscope\tdevice\tprivate_witness\tsequence\tprevious\tnonce\twallet_authorization\texpected\treason"
            )
        );
        let rows = lines
            .map(|line| line.split('\t').collect::<alloc::vec::Vec<_>>())
            .collect::<alloc::vec::Vec<_>>();
        assert_eq!(rows.len(), 12);
        assert!(rows.iter().all(|row| row.len() == 11));
        assert_eq!(rows.iter().filter(|row| row[9] == "accept").count(), 4);
        assert_eq!(rows.iter().filter(|row| row[9] == "reject").count(), 8);
    }
}
