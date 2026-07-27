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
}
