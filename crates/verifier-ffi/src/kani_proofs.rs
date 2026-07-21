//! Bounded Kani proofs for the production verifier C ABI adapter.
//!
//! The harnesses call the exported `extern "C"` functions directly. Foreign callers remain
//! responsible for making every accepted non-null pointer readable for its declared in-bound
//! length; Kani cannot quantify over allocations owned by another language runtime.

use super::{
    MAX_ENVELOPE_LENGTH, NULL_POINTER, TOO_LARGE, activechain_inspect_envelope_code,
    activechain_verify_commitment_code,
};

const DECODE_ERROR: u32 = 2;
const TYPE_MISMATCH: u32 = 3;
const VERSION_MISMATCH: u32 = 4;
const VERIFY_OK: u32 = 0;

#[kani::proof]
fn null_envelope_pointer_with_nonzero_length_always_fails_closed() {
    let length: u32 = kani::any();
    let expected_type: u16 = kani::any();
    let expected_version: u16 = kani::any();
    kani::assume(length != 0);

    let code = unsafe {
        activechain_inspect_envelope_code(
            core::ptr::null(),
            length,
            expected_type,
            expected_version,
        )
    };

    assert_eq!(code, NULL_POINTER);
}

#[kani::proof]
fn oversized_envelope_is_rejected_before_pointer_materialization() {
    let length: u32 = kani::any();
    let expected_type: u16 = kani::any();
    let expected_version: u16 = kani::any();
    kani::assume(length > MAX_ENVELOPE_LENGTH);

    let code = unsafe {
        activechain_inspect_envelope_code(
            core::ptr::NonNull::<u8>::dangling().as_ptr(),
            length,
            expected_type,
            expected_version,
        )
    };

    assert_eq!(code, TOO_LARGE);
}

#[kani::proof]
fn bounded_envelope_pointer_path_refines_the_safe_verifier() {
    let bytes: [u8; 9] = kani::any();
    let original = bytes;
    let length: usize = kani::any();
    let expected_type: u16 = kani::any();
    let expected_version: u16 = kani::any();
    kani::assume(length <= bytes.len());

    let ffi_code = unsafe {
        activechain_inspect_envelope_code(
            bytes.as_ptr(),
            length as u32,
            expected_type,
            expected_version,
        )
    };
    let safe_code = activechain_verifier_api::inspect_envelope_code(
        &bytes[..length],
        expected_type,
        expected_version,
    );

    assert_eq!(ffi_code, safe_code);
    assert_eq!(bytes, original);
}

#[kani::proof]
fn strict_envelope_codes_reject_truncation_and_ambiguity() {
    let canonical = [0x12, 0x34, 0x00, 0x01, 0x01, 0xaa];
    let truncation: usize = kani::any();
    kani::assume(truncation < canonical.len());

    assert_eq!(
        unsafe {
            activechain_inspect_envelope_code(canonical.as_ptr(), canonical.len() as u32, 0x1234, 1)
        },
        VERIFY_OK
    );
    assert_eq!(
        unsafe {
            activechain_inspect_envelope_code(canonical.as_ptr(), truncation as u32, 0x1234, 1)
        },
        DECODE_ERROR
    );
    assert_eq!(
        unsafe {
            activechain_inspect_envelope_code(canonical.as_ptr(), canonical.len() as u32, 0x1235, 1)
        },
        TYPE_MISMATCH
    );
    assert_eq!(
        unsafe {
            activechain_inspect_envelope_code(canonical.as_ptr(), canonical.len() as u32, 0x1234, 2)
        },
        VERSION_MISMATCH
    );

    let trailing = [0x12, 0x34, 0x00, 0x01, 0x01, 0xaa, 0x00];
    assert_eq!(
        unsafe {
            activechain_inspect_envelope_code(trailing.as_ptr(), trailing.len() as u32, 0x1234, 1)
        },
        DECODE_ERROR
    );
}

#[kani::proof]
fn commitment_null_contracts_always_fail_closed() {
    let nonzero_length: u32 = kani::any();
    let digest = [0_u8; 48];
    kani::assume(nonzero_length != 0);

    assert_eq!(
        unsafe {
            activechain_verify_commitment_code(
                core::ptr::null(),
                nonzero_length,
                core::ptr::null(),
                0,
                digest.as_ptr(),
            )
        },
        NULL_POINTER
    );
    assert_eq!(
        unsafe {
            activechain_verify_commitment_code(
                core::ptr::null(),
                0,
                core::ptr::null(),
                nonzero_length,
                digest.as_ptr(),
            )
        },
        NULL_POINTER
    );
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
}
