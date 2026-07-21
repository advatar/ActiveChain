#![allow(unsafe_code)]

use activechain_protocol_types::Digest384;

/// Returns the ABI revision consumed by native wallet shells.
#[unsafe(no_mangle)]
pub extern "C" fn activechain_wallet_ffi_revision() -> u32 {
    1
}

/// Validates a bounded OpenWallet session tuple without accepting secret material.
///
/// # Safety
///
/// `session_id` and `relying_party` must each point to a readable 48-byte buffer for the
/// duration of this call. The function does not retain either pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_session_valid(
    session_id: *const u8,
    relying_party: *const u8,
    expires_at: u64,
    height: u64,
) -> u32 {
    if session_id.is_null() || relying_party.is_null() || expires_at < height {
        return 0;
    }
    let _session =
        Digest384::new(unsafe { std::slice::from_raw_parts(session_id, 48) }.try_into().unwrap());
    let _rp = Digest384::new(
        unsafe { std::slice::from_raw_parts(relying_party, 48) }.try_into().unwrap(),
    );
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn revision_is_stable() {
        assert_eq!(activechain_wallet_ffi_revision(), 1);
    }
}
