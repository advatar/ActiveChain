#![no_std]
#![forbid(unsafe_code)]

use activechain_canonical_codec::{DecodeError, Decoder};

pub const MAX_ENVELOPE_LENGTH: usize = 256 * 1024;

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
}

pub fn inspect_envelope(
    bytes: &[u8],
    expected_type: u16,
    expected_version: u16,
) -> Result<EnvelopeMetadata, VerifyError> {
    if bytes.len() > MAX_ENVELOPE_LENGTH {
        return Err(VerifyError::TooLarge);
    }
    let mut decoder = Decoder::new(bytes);
    let type_tag = decoder.read_u16().map_err(VerifyError::Decode)?;
    let schema_version = decoder.read_u16().map_err(VerifyError::Decode)?;
    if type_tag != expected_type {
        return Err(VerifyError::TypeMismatch);
    }
    if schema_version != expected_version {
        return Err(VerifyError::VersionMismatch);
    }
    let body = decoder.read_bytes(MAX_ENVELOPE_LENGTH).map_err(VerifyError::Decode)?;
    decoder.finish().map_err(VerifyError::Decode)?;
    Ok(EnvelopeMetadata { type_tag, schema_version, body_length: body.len() })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_inspection_rejects_wrong_version_and_trailing_bytes() {
        let valid = [0x12, 0x34, 0, 1, 2, 0xaa, 0xbb];
        assert_eq!(inspect_envelope(&valid, 0x1234, 1).unwrap().body_length, 2);
        assert_eq!(inspect_envelope(&valid, 0x1234, 2), Err(VerifyError::VersionMismatch));
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert!(matches!(inspect_envelope(&trailing, 0x1234, 1), Err(VerifyError::Decode(_))));
    }
}
