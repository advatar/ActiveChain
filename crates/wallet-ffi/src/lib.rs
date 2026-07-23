#![allow(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_cash_kernel::CoinCellSet;
use activechain_protocol_types::{CoinCellId, Digest384, PrincipalId};

const MAX_WALLET_INPUT: u32 = 256 * 1024;
const WALLET_OK: u32 = 0;
const WALLET_NULL_POINTER: u32 = 1;
const WALLET_TOO_LARGE: u32 = 2;
const WALLET_MALFORMED: u32 = 3;
const WALLET_INSUFFICIENT_FUNDS: u32 = 4;

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

/// Selects distinct payment and fee-reserve Coin Cells from a canonical bounded set.
///
/// # Safety
///
/// The caller must provide readable buffers for the declared lengths, a readable 48-byte owner,
/// and writable 48-byte output buffers. No pointer is retained. Oversized input is rejected before
/// the input pointer is materialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_select_cells(
    cells: *const u8,
    cells_len: u32,
    owner: *const u8,
    amount_high: u64,
    amount_low: u64,
    fee_high: u64,
    fee_low: u64,
    payment_out: *mut u8,
    fee_reserve_out: *mut u8,
) -> u32 {
    if (cells.is_null() && cells_len != 0)
        || owner.is_null()
        || payment_out.is_null()
        || fee_reserve_out.is_null()
    {
        return WALLET_NULL_POINTER;
    }
    if cells_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let cells = if cells_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(cells, cells_len as usize) }
    };
    let Ok(cells) = decode_envelope::<CoinCellSet>(cells) else {
        return WALLET_MALFORMED;
    };
    let owner_bytes = unsafe { core::slice::from_raw_parts(owner, 48) };
    let mut owner_digest = [0; 48];
    owner_digest.copy_from_slice(owner_bytes);
    let owner = PrincipalId::new(Digest384::new(owner_digest));
    let amount = (u128::from(amount_high) << 64) | u128::from(amount_low);
    let fee = (u128::from(fee_high) << 64) | u128::from(fee_low);
    let Ok((payment, reserve)) =
        activechain_wallet_core::select_cells(cells.as_slice(), owner, amount, fee)
    else {
        return WALLET_INSUFFICIENT_FUNDS;
    };
    unsafe {
        write_cell_id(payment_out, payment);
        write_cell_id(fee_reserve_out, reserve);
    }
    WALLET_OK
}

unsafe fn write_cell_id(output: *mut u8, id: CoinCellId) {
    unsafe {
        core::ptr::copy_nonoverlapping(id.into_digest().as_bytes().as_ptr(), output, 48);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::encode_envelope;
    use activechain_cash_kernel::{CoinCell, CoinCellOrigin, CoinCellRecord};
    use activechain_protocol_types::TransactionId;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn revision_is_stable() {
        assert_eq!(activechain_wallet_ffi_revision(), 1);
    }

    #[test]
    fn cell_discovery_decodes_canonical_state_and_returns_distinct_cells() {
        let owner = PrincipalId::new(digest(9));
        let records = [10_u8, 11]
            .into_iter()
            .enumerate()
            .map(|(index, byte)| {
                CoinCellRecord::new(
                    CoinCellId::new(digest(byte)),
                    CoinCell::new(
                        CoinCellOrigin::new(TransactionId::new(digest(byte + 20)), index as u16),
                        owner,
                        if index == 0 { 100 } else { 10 },
                        1,
                    )
                    .unwrap(),
                )
            })
            .collect();
        let encoded = encode_envelope(&CoinCellSet::new(records).unwrap()).unwrap();
        let mut payment = [0; 48];
        let mut reserve = [0; 48];
        assert_eq!(
            unsafe {
                activechain_wallet_select_cells(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    owner.digest().as_bytes().as_ptr(),
                    0,
                    50,
                    0,
                    5,
                    payment.as_mut_ptr(),
                    reserve.as_mut_ptr(),
                )
            },
            WALLET_OK
        );
        assert_eq!(payment, [10; 48]);
        assert_eq!(reserve, [11; 48]);
        assert_eq!(
            unsafe {
                activechain_wallet_select_cells(
                    core::ptr::null(),
                    1,
                    owner.digest().as_bytes().as_ptr(),
                    0,
                    1,
                    0,
                    1,
                    payment.as_mut_ptr(),
                    reserve.as_mut_ptr(),
                )
            },
            WALLET_NULL_POINTER
        );
        let malformed = [0_u8];
        assert_eq!(
            unsafe {
                activechain_wallet_select_cells(
                    malformed.as_ptr(),
                    1,
                    owner.digest().as_bytes().as_ptr(),
                    0,
                    1,
                    0,
                    1,
                    payment.as_mut_ptr(),
                    reserve.as_mut_ptr(),
                )
            },
            WALLET_MALFORMED
        );
    }
}
