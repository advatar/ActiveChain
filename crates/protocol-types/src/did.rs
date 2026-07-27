use crate::{Digest384, PrincipalId};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidRecordError {
    InvalidIdentity,
    InvalidCommitment,
    InvalidSequence,
    PreviousMismatch,
    Inactive,
    InvalidOperation,
}

/// Derives the stable `did:activechain` method-specific identifier from the
/// principal commitment and method version. Key material and ENS aliases are
/// intentionally excluded from this identity function.
pub fn derive_activechain_did(principal: PrincipalId) -> Result<Digest384, DidRecordError> {
    if principal.digest() == &Digest384::ZERO {
        return Err(DidRecordError::InvalidIdentity);
    }
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-DID-METHOD-V1");
    hasher.update(principal.digest().as_bytes());
    let mut bytes = [0_u8; 48];
    hasher.finalize_xof().read(&mut bytes);
    Ok(Digest384::new(bytes))
}

/// Public controller state for `did:activechain`. Private credentials,
/// transaction history, and key material are represented only by commitments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DidControllerRecordV1 {
    principal: PrincipalId,
    document_commitment: Digest384,
    authentication_commitment: Digest384,
    key_agreement_commitment: Digest384,
    recovery_commitment: Option<Digest384>,
    services_commitment: Option<Digest384>,
    sequence: u64,
    active: bool,
}

impl DidControllerRecordV1 {
    pub const TYPE_TAG: u16 = 0x00d8;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 48 * 5 + 1 + 8 + 1;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal: PrincipalId,
        document_commitment: Digest384,
        authentication_commitment: Digest384,
        key_agreement_commitment: Digest384,
        recovery_commitment: Option<Digest384>,
        services_commitment: Option<Digest384>,
        sequence: u64,
        active: bool,
    ) -> Result<Self, DidRecordError> {
        if principal.digest() == &Digest384::ZERO {
            return Err(DidRecordError::InvalidIdentity);
        }
        if document_commitment == Digest384::ZERO
            || authentication_commitment == Digest384::ZERO
            || key_agreement_commitment == Digest384::ZERO
            || recovery_commitment.is_some_and(|value| value == Digest384::ZERO)
            || services_commitment.is_some_and(|value| value == Digest384::ZERO)
        {
            return Err(DidRecordError::InvalidCommitment);
        }
        if sequence == 0 {
            return Err(DidRecordError::InvalidSequence);
        }
        Ok(Self {
            principal,
            document_commitment,
            authentication_commitment,
            key_agreement_commitment,
            recovery_commitment,
            services_commitment,
            sequence,
            active,
        })
    }

    pub const fn principal(self) -> PrincipalId { self.principal }
    pub const fn document_commitment(self) -> Digest384 { self.document_commitment }
    pub const fn authentication_commitment(self) -> Digest384 { self.authentication_commitment }
    pub const fn key_agreement_commitment(self) -> Digest384 { self.key_agreement_commitment }
    pub const fn recovery_commitment(self) -> Option<Digest384> { self.recovery_commitment }
    pub const fn services_commitment(self) -> Option<Digest384> { self.services_commitment }
    pub const fn sequence(self) -> u64 { self.sequence }
    pub const fn active(self) -> bool { self.active }

    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-DID-CONTROLLER-RECORD-V1");
        hasher.update(&bytes);
        let mut digest = [0_u8; 48];
        hasher.finalize_xof().read(&mut digest);
        Ok(Digest384::new(digest))
    }

    pub fn apply_update(
        &self,
        previous_commitment: Digest384,
        next: Self,
    ) -> Result<Self, DidRecordError> {
        if !self.active {
            return Err(DidRecordError::Inactive);
        }
        if previous_commitment != self.commitment().map_err(|_| DidRecordError::PreviousMismatch)?
            || next.principal != self.principal
            || next.sequence != self.sequence.saturating_add(1)
        {
            return Err(DidRecordError::PreviousMismatch);
        }
        Ok(next)
    }
}

impl CanonicalEncode for DidControllerRecordV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.principal.encode(e)?;
        self.document_commitment.encode(e)?;
        self.authentication_commitment.encode(e)?;
        self.key_agreement_commitment.encode(e)?;
        self.recovery_commitment.encode(e)?;
        self.services_commitment.encode(e)?;
        self.sequence.encode(e)?;
        self.active.encode(e)
    }
}
impl CanonicalDecode for DidControllerRecordV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Option::<Digest384>::decode(d)?,
            Option::<Digest384>::decode(d)?,
            u64::decode(d)?,
            bool::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid did controller record"))
    }
}
impl CanonicalType for DidControllerRecordV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidResolutionV1 {
    did: Digest384,
    finalized_height: u64,
    record: Option<DidControllerRecordV1>,
}

impl DidResolutionV1 {
    pub const TYPE_TAG: u16 = 0x00d9;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 8 + 2 + DidControllerRecordV1::MAX_ENCODED_LEN;

    pub fn new(
        did: Digest384,
        finalized_height: u64,
        record: Option<DidControllerRecordV1>,
    ) -> Result<Self, DidRecordError> {
        if did == Digest384::ZERO {
            return Err(DidRecordError::InvalidIdentity);
        }
        if record.is_some_and(|value| value.principal().digest() == &Digest384::ZERO) {
            return Err(DidRecordError::InvalidIdentity);
        }
        Ok(Self { did, finalized_height, record })
    }
    pub const fn did(&self) -> Digest384 { self.did }
    pub const fn finalized_height(&self) -> u64 { self.finalized_height }
    pub const fn record(&self) -> Option<&DidControllerRecordV1> { self.record.as_ref() }
}

impl CanonicalEncode for DidResolutionV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.did.encode(e)?;
        self.finalized_height.encode(e)?;
        self.record.encode(e)
    }
}
impl CanonicalDecode for DidResolutionV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(Digest384::decode(d)?, u64::decode(d)?, Option::<DidControllerRecordV1>::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid did resolution"))
    }
}
impl CanonicalType for DidResolutionV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DidOperationKind {
    Create = 0,
    Update = 1,
    Recover = 2,
    Deactivate = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidControllerOperationV1 {
    kind: DidOperationKind,
    principal: PrincipalId,
    previous_commitment: Option<Digest384>,
    next: DidControllerRecordV1,
    authorization_commitment: Digest384,
}

impl DidControllerOperationV1 {
    pub const TYPE_TAG: u16 = 0x00da;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 1 + 48 + 1 + 48 + DidControllerRecordV1::MAX_ENCODED_LEN + 48;

    pub fn new(
        kind: DidOperationKind,
        principal: PrincipalId,
        previous_commitment: Option<Digest384>,
        next: DidControllerRecordV1,
        authorization_commitment: Digest384,
    ) -> Result<Self, DidRecordError> {
        if principal.digest() == &Digest384::ZERO
            || next.principal() != principal
            || authorization_commitment == Digest384::ZERO
            || previous_commitment.is_some_and(|value| value == Digest384::ZERO)
        {
            return Err(DidRecordError::InvalidOperation);
        }
        match kind {
            DidOperationKind::Create if previous_commitment.is_some() || next.sequence() != 1 => {
                Err(DidRecordError::InvalidOperation)
            }
            DidOperationKind::Create if !next.active() => Err(DidRecordError::InvalidOperation),
            DidOperationKind::Deactivate if next.active() || previous_commitment.is_none() => {
                Err(DidRecordError::InvalidOperation)
            }
            DidOperationKind::Update | DidOperationKind::Recover
                if previous_commitment.is_none() || !next.active() =>
            {
                Err(DidRecordError::InvalidOperation)
            }
            _ => Ok(Self { kind, principal, previous_commitment, next, authorization_commitment }),
        }
    }
    pub const fn kind(&self) -> DidOperationKind { self.kind }
    pub const fn principal(&self) -> PrincipalId { self.principal }
    pub const fn previous_commitment(&self) -> Option<Digest384> { self.previous_commitment }
    pub const fn next(&self) -> &DidControllerRecordV1 { &self.next }
    pub const fn authorization_commitment(&self) -> Digest384 { self.authorization_commitment }
}

impl CanonicalEncode for DidOperationKind {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> { (*self as u8).encode(e) }
}
impl CanonicalDecode for DidOperationKind {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Create),
            1 => Ok(Self::Update),
            2 => Ok(Self::Recover),
            3 => Ok(Self::Deactivate),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "DidOperationKind", tag }),
        }
    }
}
impl CanonicalEncode for DidControllerOperationV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.kind.encode(e)?;
        self.principal.encode(e)?;
        self.previous_commitment.encode(e)?;
        self.next.encode(e)?;
        self.authorization_commitment.encode(e)
    }
}
impl CanonicalDecode for DidControllerOperationV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            DidOperationKind::decode(d)?,
            PrincipalId::decode(d)?,
            Option::<Digest384>::decode(d)?,
            DidControllerRecordV1::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid did controller operation"))
    }
}
impl CanonicalType for DidControllerOperationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};

    fn digest(value: u8) -> Digest384 { Digest384::new([value; 48]) }
    fn principal(value: u8) -> PrincipalId { PrincipalId::new(digest(value)) }

    #[test]
    fn controller_record_round_trips_and_updates_monotonically() {
        let first = DidControllerRecordV1::new(
            principal(1), digest(2), digest(3), digest(4), Some(digest(5)), None, 1, true,
        )
        .unwrap();
        assert_eq!(decode_envelope::<DidControllerRecordV1>(&encode_envelope(&first).unwrap()), Ok(first));
        let second = DidControllerRecordV1::new(
            principal(1), digest(6), digest(7), digest(8), Some(digest(9)), Some(digest(10)), 2, true,
        )
        .unwrap();
        let previous = first.commitment().unwrap();
        assert_eq!(first.apply_update(previous, second), Ok(second));
        assert_eq!(first.apply_update(digest(99), second), Err(DidRecordError::PreviousMismatch));
        assert_eq!(first.apply_update(previous, DidControllerRecordV1 { sequence: 4, ..second }), Err(DidRecordError::PreviousMismatch));
    }

    #[test]
    fn controller_record_rejects_zero_identity_and_commitments() {
        assert_eq!(
            DidControllerRecordV1::new(
                PrincipalId::new(Digest384::ZERO), digest(2), digest(3), digest(4), None, None, 1, true,
            ),
            Err(DidRecordError::InvalidIdentity)
        );
        assert_eq!(
            DidControllerRecordV1::new(
                principal(1), Digest384::ZERO, digest(3), digest(4), None, None, 1, true,
            ),
            Err(DidRecordError::InvalidCommitment)
        );
    }

    #[test]
    fn method_did_derivation_is_stable_and_domain_separated() {
        assert_eq!(derive_activechain_did(principal(1)), derive_activechain_did(principal(1)));
        assert_ne!(derive_activechain_did(principal(1)), derive_activechain_did(principal(2)));
        assert!(derive_activechain_did(PrincipalId::new(Digest384::ZERO)).is_err());
    }

    #[test]
    fn resolution_round_trips_and_supports_deactivated_absence() {
        let resolution = DidResolutionV1::new(digest(20), 42, None).unwrap();
        assert_eq!(decode_envelope::<DidResolutionV1>(&encode_envelope(&resolution).unwrap()), Ok(resolution));
        assert!(DidResolutionV1::new(Digest384::ZERO, 42, None).is_err());
    }

    #[test]
    fn operations_bind_kind_sequence_and_authorization() {
        let record = DidControllerRecordV1::new(principal(1), digest(2), digest(3), digest(4), None, None, 1, true).unwrap();
        let operation = DidControllerOperationV1::new(
            DidOperationKind::Create,
            principal(1),
            None,
            record,
            digest(5),
        )
        .unwrap();
        assert_eq!(decode_envelope::<DidControllerOperationV1>(&encode_envelope(&operation).unwrap()), Ok(operation));
        assert!(DidControllerOperationV1::new(DidOperationKind::Create, principal(1), Some(digest(6)), record, digest(5)).is_err());
        assert!(DidControllerOperationV1::new(DidOperationKind::Create, principal(1), None, record, Digest384::ZERO).is_err());
    }
}
