#![no_std]
#![forbid(unsafe_code)]

//! Domain-separated SHAKE256 commitments over canonical protocol bodies.

use activechain_canonical_codec::{CanonicalType, EncodeError, encode_body};
use activechain_protocol_types::{DIGEST_LENGTH, Digest384};
use sha3::{Shake256, digest::ExtendableOutput, digest::Update, digest::XofReader};

const TRANSCRIPT_PREFIX: &[u8] = b"ACTIVECHAIN-COMMITMENT";
const TRANSCRIPT_VERSION: u16 = 1;

/// A registered purpose for a protocol commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct DomainTag(u16);

impl DomainTag {
    /// Commitment to a canonical value without assigning it another role.
    pub const CANONICAL_VALUE: Self = Self(0x0001);
    /// Derivation of an object identifier from canonical creation material.
    pub const OBJECT_ID_DERIVATION: Self = Self(0x0002);
    /// Bytes committed for a protocol signing operation.
    pub const SIGNING_PAYLOAD: Self = Self(0x0003);
    /// Commitment to a canonical state-tree leaf.
    pub const STATE_LEAF: Self = Self(0x0004);
    /// Derivation of an admitted action identifier.
    pub const ACTION_ID: Self = Self(0x0005);
    /// Derivation of a canonical finalized development block identifier.
    pub const BLOCK_ID: Self = Self(0x0006);

    /// Returns the registered numeric tag.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// Computes a 384-bit SHAKE256 commitment over the P-001 transcript.
///
/// The canonical envelope is deliberately not hashed as part of the body: its
/// type tag and schema version already occupy unambiguous transcript fields.
pub fn commit<T: CanonicalType>(domain: DomainTag, value: &T) -> Result<Digest384, EncodeError> {
    let body = encode_body(value)?;
    let body_length = u64::try_from(body.len()).map_err(|_| EncodeError::LengthOverflow)?;

    let mut hasher = Shake256::default();
    hasher.update(TRANSCRIPT_PREFIX);
    hasher.update(&TRANSCRIPT_VERSION.to_be_bytes());
    hasher.update(&domain.as_u16().to_be_bytes());
    hasher.update(&T::TYPE_TAG.to_be_bytes());
    hasher.update(&T::SCHEMA_VERSION.to_be_bytes());
    hasher.update(&body_length.to_be_bytes());
    hasher.update(&body);

    let mut output = [0_u8; DIGEST_LENGTH];
    hasher.finalize_xof().read(&mut output);
    Ok(Digest384::new(output))
}

#[cfg(test)]
mod tests {
    use activechain_canonical_codec::{
        CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    };
    use activechain_protocol_types::{
        Digest384, FreezeState, Principal, PrincipalId, PrincipalKind,
    };

    use super::{DomainTag, commit};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn vector_principal() -> Principal {
        Principal::new(
            PrincipalId::new(digest(0x11)),
            PrincipalKind::Agent,
            digest(0x22),
            digest(0x33),
            digest(0x44),
            7,
            FreezeState::Active,
            digest(0x55),
            1_000,
            42,
            43,
        )
        .expect("vector principal satisfies its invariants")
    }

    #[derive(Clone, Copy)]
    struct AlternatePrincipal(Principal);

    impl CanonicalEncode for AlternatePrincipal {
        fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
            self.0.encode(encoder)
        }
    }

    impl CanonicalDecode for AlternatePrincipal {
        fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            Ok(Self(Principal::decode(decoder)?))
        }
    }

    impl CanonicalType for AlternatePrincipal {
        const TYPE_TAG: u16 = 0x0021;
        const SCHEMA_VERSION: u16 = 1;
        const MAX_ENCODED_LEN: usize = Principal::ENCODED_LENGTH;
    }

    #[test]
    fn domain_separation_changes_the_commitment() {
        let principal = vector_principal();
        let canonical = commit(DomainTag::CANONICAL_VALUE, &principal).expect("principal encodes");
        let signing = commit(DomainTag::SIGNING_PAYLOAD, &principal).expect("principal encodes");
        assert_ne!(canonical, signing);
    }

    #[test]
    fn type_separation_changes_the_commitment_for_identical_bodies() {
        let principal = vector_principal();
        let first = commit(DomainTag::CANONICAL_VALUE, &principal).expect("principal encodes");
        let second = commit(DomainTag::CANONICAL_VALUE, &AlternatePrincipal(principal))
            .expect("alternate principal encodes");
        assert_ne!(first, second);
    }

    #[test]
    fn principal_commitment_matches_the_published_vector() {
        let actual =
            commit(DomainTag::CANONICAL_VALUE, &vector_principal()).expect("principal encodes");
        let expected = Digest384::new([
            182, 199, 121, 144, 243, 2, 35, 121, 164, 99, 147, 157, 12, 122, 68, 48, 13, 141, 87,
            95, 197, 12, 13, 246, 231, 112, 229, 94, 84, 86, 211, 181, 194, 160, 89, 99, 12, 49,
            167, 228, 236, 133, 154, 138, 212, 178, 168, 67,
        ]);
        assert_eq!(actual, expected);
    }
}
