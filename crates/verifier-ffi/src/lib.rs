#![allow(unsafe_code)]

use activechain_protocol_types::Digest384;

const TOO_LARGE: u32 = 1;
const NULL_POINTER: u32 = 6;
const MAX_ENVELOPE_LENGTH: u32 = activechain_verifier_api::MAX_ENVELOPE_LENGTH as u32;

#[unsafe(no_mangle)]
pub extern "C" fn activechain_verifier_abi_revision() -> u32 {
    activechain_verifier_api::VERIFIER_ABI_REVISION
}

#[unsafe(no_mangle)]
pub extern "C" fn activechain_verifier_schema_revision() -> u32 {
    activechain_verifier_api::VERIFIER_SCHEMA_REVISION
}

#[unsafe(no_mangle)]
pub extern "C" fn activechain_verifier_protocol_revision() -> u64 {
    activechain_verifier_api::VERIFIER_PROTOCOL_REVISION
}

#[unsafe(no_mangle)]
/// # Safety
/// For lengths through [`activechain_verifier_api::MAX_ENVELOPE_LENGTH`], the caller must provide a
/// readable `bytes` buffer of `bytes_len` bytes, or a null pointer only when `bytes_len` is zero.
/// Oversized inputs are rejected before the pointer is materialized. The verifier does not retain
/// or write through the pointer.
pub unsafe extern "C" fn activechain_inspect_envelope_code(
    bytes: *const u8,
    bytes_len: u32,
    expected_type: u16,
    expected_version: u16,
) -> u32 {
    if bytes.is_null() && bytes_len != 0 {
        return NULL_POINTER;
    }
    if bytes_len > MAX_ENVELOPE_LENGTH {
        return TOO_LARGE;
    }
    let input = if bytes_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(bytes, bytes_len as usize) }
    };
    activechain_verifier_api::inspect_envelope_code(input, expected_type, expected_version)
}

#[unsafe(no_mangle)]
/// # Safety
/// For lengths through [`activechain_verifier_api::MAX_ENVELOPE_LENGTH`], the caller must provide a
/// readable `bytes` buffer of `bytes_len` bytes. The verifier does not retain or write through it.
pub unsafe extern "C" fn activechain_verify_principal_code(
    bytes: *const u8,
    bytes_len: u32,
) -> u32 {
    if bytes.is_null() && bytes_len != 0 {
        return NULL_POINTER;
    }
    if bytes_len > MAX_ENVELOPE_LENGTH {
        return TOO_LARGE;
    }
    let input = if bytes_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(bytes, bytes_len as usize) }
    };
    activechain_verifier_api::verify_principal_code(input)
}

#[cfg(kani)]
mod kani_proofs;

#[unsafe(no_mangle)]
/// # Safety
/// The caller must provide readable buffers for the declared lengths and a readable 48-byte digest.
/// Null pointers are permitted only for zero-length buffers and no pointer is retained.
pub unsafe extern "C" fn activechain_verify_commitment_code(
    domain: *const u8,
    domain_len: u32,
    body: *const u8,
    body_len: u32,
    expected_digest: *const u8,
) -> u32 {
    if (domain.is_null() && domain_len != 0)
        || (body.is_null() && body_len != 0)
        || expected_digest.is_null()
    {
        return NULL_POINTER;
    }
    if domain_len.checked_add(body_len).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return TOO_LARGE;
    }
    let domain = if domain_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(domain, domain_len as usize) }
    };
    let body = if body_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(body, body_len as usize) }
    };
    let digest_bytes = unsafe { core::slice::from_raw_parts(expected_digest, 48) };
    let mut digest = [0_u8; 48];
    digest.copy_from_slice(digest_bytes);
    activechain_verifier_api::verify_commitment_code(domain, body, Digest384::new(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::encode_envelope;
    use activechain_protocol_types::{FreezeState, Principal, PrincipalId, PrincipalKind};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn abi_rejects_null_and_accepts_canonical_envelopes() {
        assert_eq!(activechain_verifier_abi_revision(), 1);
        assert_eq!(activechain_verifier_schema_revision(), 1);
        assert_eq!(activechain_verifier_protocol_revision(), 1);
        assert_eq!(
            unsafe { activechain_inspect_envelope_code(core::ptr::null(), 1, 0x1234, 1) },
            NULL_POINTER
        );
        let bytes = [0x12, 0x34, 0, 1, 1, 0xaa];
        assert_eq!(
            unsafe {
                activechain_inspect_envelope_code(bytes.as_ptr(), bytes.len() as u32, 0x1234, 1)
            },
            0
        );
        assert_eq!(
            unsafe {
                activechain_inspect_envelope_code(
                    core::ptr::NonNull::<u8>::dangling().as_ptr(),
                    MAX_ENVELOPE_LENGTH + 1,
                    0x1234,
                    1,
                )
            },
            TOO_LARGE
        );
    }

    #[test]
    fn principal_abi_matches_rust_verifier_codes() {
        let principal = Principal::new(
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
        .unwrap();
        let encoded = encode_envelope(&principal).unwrap();
        assert_eq!(
            unsafe { activechain_verify_principal_code(encoded.as_ptr(), encoded.len() as u32) },
            activechain_verifier_api::verify_principal_code(&encoded)
        );
        assert_eq!(
            unsafe { activechain_verify_principal_code(core::ptr::null(), 1) },
            NULL_POINTER
        );
    }

    #[test]
    fn abi_rejects_null_commitment_and_checks_known_commitment() {
        assert_eq!(
            unsafe {
                activechain_verify_commitment_code(
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                )
            },
            NULL_POINTER
        );
        let digest = [0_u8; 48];
        assert_eq!(
            unsafe {
                activechain_verify_commitment_code(
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    digest.as_ptr(),
                )
            },
            5
        );
        assert_eq!(
            unsafe {
                activechain_verify_commitment_code(
                    core::ptr::NonNull::<u8>::dangling().as_ptr(),
                    MAX_ENVELOPE_LENGTH,
                    core::ptr::NonNull::<u8>::dangling().as_ptr(),
                    1,
                    digest.as_ptr(),
                )
            },
            TOO_LARGE
        );

        let mut empty_digest = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
            0x6e, 0xd5, 0x76, 0x2f, 0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00, 0xcb, 0x05,
            0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6,
        ];
        assert_eq!(
            unsafe {
                activechain_verify_commitment_code(
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    empty_digest.as_ptr(),
                )
            },
            0
        );
        empty_digest[0] ^= 1;
        assert_eq!(
            unsafe {
                activechain_verify_commitment_code(
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    empty_digest.as_ptr(),
                )
            },
            5
        );
    }
}
