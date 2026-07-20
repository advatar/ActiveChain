#![allow(unsafe_code)]

use activechain_protocol_types::Digest384;

const NULL_POINTER: u32 = 6;

#[unsafe(no_mangle)]
/// # Safety
/// The caller must provide a readable `bytes` buffer of `bytes_len` bytes, or a null pointer only
/// when `bytes_len` is zero. The verifier does not retain the pointer.
pub unsafe extern "C" fn activechain_inspect_envelope_code(
    bytes: *const u8,
    bytes_len: u32,
    expected_type: u16,
    expected_version: u16,
) -> u32 {
    if bytes.is_null() && bytes_len != 0 {
        return NULL_POINTER;
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

    #[test]
    fn abi_rejects_null_and_accepts_canonical_envelopes() {
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
    }

    #[test]
    fn abi_rejects_null_commitment_and_wrong_commitment() {
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
    }
}
