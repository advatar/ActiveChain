#![no_std]
#![forbid(unsafe_code)]

use activechain_canonical_codec::{DecodeError, decode_envelope, inspect_canonical_envelope};
use activechain_protocol_types::{Digest384, INITIAL_PROTOCOL_REVISION, Principal};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_ENVELOPE_LENGTH: usize = 256 * 1024;
pub const VERIFIER_ABI_REVISION: u32 = 1;
pub const VERIFIER_SCHEMA_REVISION: u32 = 1;
pub const VERIFIER_PROTOCOL_REVISION: u64 = INITIAL_PROTOCOL_REVISION;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeMetadata {
    pub type_tag: u16,
    pub schema_version: u16,
    pub body_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    TooLarge,
    Decode(DecodeError),
    TypeMismatch,
    VersionMismatch,
    CommitmentMismatch,
}

impl VerifyError {
    pub const fn code(self) -> u32 {
        match self {
            Self::TooLarge => 1,
            Self::Decode(_) => 2,
            Self::TypeMismatch => 3,
            Self::VersionMismatch => 4,
            Self::CommitmentMismatch => 5,
        }
    }
}

pub const VERIFY_OK: u32 = 0;

pub fn inspect_envelope_code(bytes: &[u8], expected_type: u16, expected_version: u16) -> u32 {
    inspect_envelope(bytes, expected_type, expected_version)
        .map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_commitment_code(domain: &[u8], body: &[u8], expected: Digest384) -> u32 {
    verify_shake_commitment(domain, body, expected).map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_principal_code(bytes: &[u8]) -> u32 {
    verify_principal(bytes).map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_principal(bytes: &[u8]) -> Result<Principal, VerifyError> {
    inspect_envelope(bytes, Principal::TYPE_TAG, Principal::SCHEMA_VERSION)?;
    decode_envelope::<Principal>(bytes).map_err(VerifyError::Decode)
}

pub fn verify_shake_commitment(
    domain: &[u8],
    body: &[u8],
    expected: Digest384,
) -> Result<(), VerifyError> {
    if domain.len().checked_add(body.len()).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return Err(VerifyError::TooLarge);
    }
    let mut output = [0_u8; 48];
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(body);
    hasher.finalize_xof().read(&mut output);
    if Digest384::new(output) == expected { Ok(()) } else { Err(VerifyError::CommitmentMismatch) }
}

pub fn inspect_envelope(
    bytes: &[u8],
    expected_type: u16,
    expected_version: u16,
) -> Result<EnvelopeMetadata, VerifyError> {
    if bytes.len() > MAX_ENVELOPE_LENGTH {
        return Err(VerifyError::TooLarge);
    }
    let envelope =
        inspect_canonical_envelope(bytes, expected_type, expected_version, MAX_ENVELOPE_LENGTH)
            .map_err(|error| match error {
                DecodeError::InvalidTypeTag { .. } => VerifyError::TypeMismatch,
                DecodeError::UnsupportedSchemaVersion { .. } => VerifyError::VersionMismatch,
                error => VerifyError::Decode(error),
            })?;
    Ok(EnvelopeMetadata {
        type_tag: envelope.type_tag(),
        schema_version: envelope.schema_version(),
        body_length: envelope.body().len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::encode_envelope;
    use activechain_protocol_types::{FreezeState, PrincipalId, PrincipalKind};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn principal() -> Principal {
        Principal::new(
            PrincipalId::new(digest(1)),
            PrincipalKind::Human,
            digest(2),
            digest(3),
            digest(4),
            7,
            FreezeState::Active,
            digest(5),
            10,
            11,
            12,
        )
        .unwrap()
    }

    #[test]
    fn strict_inspection_rejects_wrong_version_and_trailing_bytes() {
        let valid = [0x12, 0x34, 0, 1, 2, 0xaa, 0xbb];
        assert_eq!(inspect_envelope(&valid, 0x1234, 1).unwrap().body_length, 2);
        assert_eq!(inspect_envelope(&valid, 0x1234, 2), Err(VerifyError::VersionMismatch));
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert!(matches!(inspect_envelope(&trailing, 0x1234, 1), Err(VerifyError::Decode(_))));
        let expected = {
            let mut output = [0_u8; 48];
            let mut h = Shake256::default();
            h.update(b"demo");
            h.update(&[0xaa, 0xbb]);
            h.finalize_xof().read(&mut output);
            Digest384::new(output)
        };
        assert_eq!(verify_shake_commitment(b"demo", &[0xaa, 0xbb], expected), Ok(()));
        assert_eq!(
            verify_shake_commitment(b"wrong", &[0xaa, 0xbb], expected),
            Err(VerifyError::CommitmentMismatch)
        );
        assert_eq!(inspect_envelope_code(&valid, 0x1234, 1), VERIFY_OK);
        assert_eq!(inspect_envelope_code(&valid, 0x1234, 2), 4);
        assert_eq!(verify_commitment_code(b"wrong", &[0xaa, 0xbb], expected), 5);
    }

    #[test]
    fn principal_verifier_checks_semantics_and_exact_framing() {
        assert_eq!(VERIFIER_ABI_REVISION, 1);
        assert_eq!(VERIFIER_SCHEMA_REVISION, 1);
        assert_eq!(VERIFIER_PROTOCOL_REVISION, INITIAL_PROTOCOL_REVISION);
        let encoded = encode_envelope(&principal()).unwrap();
        assert_eq!(verify_principal(&encoded), Ok(principal()));
        assert_eq!(verify_principal_code(&encoded), VERIFY_OK);

        let mut wrong_version = encoded.clone();
        wrong_version[3] = 2;
        assert_eq!(verify_principal_code(&wrong_version), VerifyError::VersionMismatch.code());

        let mut invalid_height_order = encoded.clone();
        let body_start = invalid_height_order.len() - Principal::ENCODED_LENGTH;
        invalid_height_order[body_start + Principal::ENCODED_LENGTH - 16..][..8]
            .copy_from_slice(&13_u64.to_be_bytes());
        invalid_height_order[body_start + Principal::ENCODED_LENGTH - 8..]
            .copy_from_slice(&12_u64.to_be_bytes());
        assert_eq!(
            verify_principal_code(&invalid_height_order),
            VerifyError::Decode(DecodeError::InvalidValue("last_updated_at predates created_at"))
                .code()
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            verify_principal_code(&trailing),
            VerifyError::Decode(DecodeError::TrailingData { remaining: 1 }).code()
        );
    }
}
