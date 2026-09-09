use crate::{crypto, dispatch, Error};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::{
    ffi::{c_char, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};
use zeroize::Zeroizing;

const MAX_REQUEST: usize = 1024 * 1024;

#[no_mangle]
pub extern "C" fn anyidentity_abi_version() -> u32 {
    1
}
#[no_mangle]
pub extern "C" fn anyidentity_key_generate() -> *mut SigningKey {
    catch_unwind(|| {
        crypto::random_key()
            .map(|k| Box::into_raw(Box::new(k)))
            .unwrap_or(ptr::null_mut())
    })
    .unwrap_or(ptr::null_mut())
}
/// # Safety
/// `seed` must point to `len` readable bytes; accepts exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn anyidentity_key_import(seed: *const u8, len: usize) -> *mut SigningKey {
    if seed.is_null() || len != 32 {
        return ptr::null_mut();
    }
    catch_unwind(|| {
        let mut copy = Zeroizing::new([0u8; 32]);
        copy.copy_from_slice(slice::from_raw_parts(seed, len));
        Box::into_raw(Box::new(SigningKey::from_bytes(&copy)))
    })
    .unwrap_or(ptr::null_mut())
}
/// # Safety
/// Key must be a live key returned by this library; output must have 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn anyidentity_key_export(
    key: *const SigningKey,
    output: *mut u8,
    len: usize,
) -> bool {
    if key.is_null() || output.is_null() || len != 32 {
        return false;
    }
    catch_unwind(|| {
        let bytes = Zeroizing::new((*key).to_bytes());
        ptr::copy_nonoverlapping(bytes.as_ptr(), output, 32);
        true
    })
    .unwrap_or(false)
}
/// # Safety
/// Key must be live; audience must point to `len` readable UTF-8 bytes.
#[no_mangle]
pub unsafe extern "C" fn anyidentity_key_derive(
    key: *const SigningKey,
    audience: *const u8,
    len: usize,
) -> *mut SigningKey {
    if key.is_null() || audience.is_null() || len == 0 || len > 4096 {
        return ptr::null_mut();
    }
    catch_unwind(|| {
        let Ok(audience) = std::str::from_utf8(slice::from_raw_parts(audience, len)) else {
            return ptr::null_mut();
        };
        crypto::derive(&*key, audience)
            .map(|k| Box::into_raw(Box::new(k)))
            .unwrap_or(ptr::null_mut())
    })
    .unwrap_or(ptr::null_mut())
}
/// # Safety
/// Key must be null or a live allocation from this library, freed exactly once,
/// with no concurrent operations still using it.
#[no_mangle]
pub unsafe extern "C" fn anyidentity_key_free(key: *mut SigningKey) {
    if !key.is_null() {
        drop(Box::from_raw(key));
    }
}
/// # Safety
/// Key may be null for verification. Non-null key must remain live throughout call.
/// Request must point to `len` readable bytes. Result must be freed with string_free.
#[no_mangle]
pub unsafe extern "C" fn anyidentity_call(
    key: *const SigningKey,
    request: *const u8,
    len: usize,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if request.is_null() || len == 0 || len > MAX_REQUEST {
            return Err(Error::invalid("empty or oversized FFI request"));
        }
        dispatch(key.as_ref(), slice::from_raw_parts(request, len))
    }))
    .unwrap_or_else(|_| Err(Error::new("internal", "Rust operation failed")));
    let response = match result {
        Ok(value) => json!({"ok":true,"value":value}),
        Err(error) => json!({"ok":false,"error":error}),
    };
    // JSON escapes embedded NUL, so CString conversion cannot fail for valid JSON.
    CString::new(response.to_string())
        .map(CString::into_raw)
        .unwrap_or(ptr::null_mut())
}
/// # Safety
/// Value must be null or an allocation returned by anyidentity_call, freed once.
#[no_mangle]
pub unsafe extern "C" fn anyidentity_string_free(value: *mut c_char) {
    if !value.is_null() {
        drop(CString::from_raw(value));
    }
}
/// # Safety
/// Input must point to `len` readable bytes (or be null for zero length).
/// Output must point to at least 65 writable bytes. Writes lowercase SHA-256 + NUL.
#[no_mangle]
pub unsafe extern "C" fn anyidentity_sha256(
    input: *const u8,
    len: usize,
    output: *mut c_char,
) -> bool {
    if output.is_null() || (input.is_null() && len != 0) {
        return false;
    }
    catch_unwind(|| {
        let bytes = if len == 0 {
            &[]
        } else {
            slice::from_raw_parts(input, len)
        };
        let hash = crypto::digest(bytes);
        ptr::copy_nonoverlapping(hash.as_ptr(), output.cast(), 64);
        *output.add(64) = 0;
        true
    })
    .unwrap_or(false)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    #[test]
    fn malformed_ffi_requests_are_errors_and_allocations_can_be_freed() {
        unsafe {
            assert!(anyidentity_key_import(ptr::null(), 32).is_null());
            for bytes in [
                b"{".as_slice(),
                b"{\"op\":\"unknown\"}",
                b"{\"op\":\"public_key\",\"extra\":1}",
            ] {
                let result = anyidentity_call(ptr::null(), bytes.as_ptr(), bytes.len());
                assert!(!result.is_null());
                assert!(CStr::from_ptr(result)
                    .to_str()
                    .unwrap()
                    .contains("\"ok\":false"));
                anyidentity_string_free(result);
            }
            let result = anyidentity_call(ptr::null(), ptr::null(), MAX_REQUEST + 1);
            assert!(CStr::from_ptr(result)
                .to_str()
                .unwrap()
                .contains("oversized"));
            anyidentity_string_free(result);
            anyidentity_key_free(ptr::null_mut());
            anyidentity_string_free(ptr::null_mut());
        }
    }
}
