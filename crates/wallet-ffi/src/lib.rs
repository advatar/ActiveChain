#![allow(unsafe_code)]

use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_cash_kernel::{CoinCellSet, CoinTransfer};
use activechain_protocol_types::{ChainId, CoinCellId, Digest384, PrincipalId};
use activechain_wallet_core::CashAuthorizationRequestV1;

const MAX_WALLET_INPUT: u32 = 256 * 1024;
const WALLET_OK: u32 = 0;
const WALLET_NULL_POINTER: u32 = 1;
const WALLET_TOO_LARGE: u32 = 2;
const WALLET_MALFORMED: u32 = 3;
const WALLET_INSUFFICIENT_FUNDS: u32 = 4;
const WALLET_BUFFER_TOO_SMALL: u32 = 5;

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

/// Evaluates the exact wallet-core spending policy without side effects.
///
/// # Safety
///
/// `recipient` must point to 48 readable bytes. `allowed_recipient` may be null to express an
/// unpinned policy; otherwise it must point to 48 readable bytes. No pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_policy_allows(
    daily_limit_high: u64,
    daily_limit_low: u64,
    max_single_high: u64,
    max_single_low: u64,
    allowed_recipient: *const u8,
    amount_high: u64,
    amount_low: u64,
    recipient: *const u8,
    spent_high: u64,
    spent_low: u64,
) -> u32 {
    if recipient.is_null() {
        return 0;
    }
    let policy = activechain_wallet_core::SpendPolicy {
        daily_limit: join_u128(daily_limit_high, daily_limit_low),
        max_single_payment: join_u128(max_single_high, max_single_low),
        recipient_commitment: if allowed_recipient.is_null() {
            None
        } else {
            Some(unsafe { read_digest(allowed_recipient) })
        },
    };
    u32::from(policy.allows(
        join_u128(amount_high, amount_low),
        unsafe { read_digest(recipient) },
        join_u128(spent_high, spent_low),
    ))
}

/// Builds the exact canonical request shown for approval and later signed by the secure key.
///
/// # Safety
///
/// All identifier inputs must point to readable 48-byte buffers. `required_len` and `intent_out`
/// must be writable. `output` may be null only when `output_capacity` is zero for a size query.
/// No output bytes or intent ID are published unless the complete request fits.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_build_cash_intent(
    chain_id: *const u8,
    signer: *const u8,
    recipient: *const u8,
    input: *const u8,
    fee_reserve: *const u8,
    nonce: u64,
    session_id: *const u8,
    session_expires_at: u64,
    amount_high: u64,
    amount_low: u64,
    fee_high: u64,
    fee_low: u64,
    valid_until: u64,
    output: *mut u8,
    output_capacity: u32,
    required_len: *mut u32,
    intent_out: *mut u8,
) -> u32 {
    if chain_id.is_null()
        || signer.is_null()
        || recipient.is_null()
        || input.is_null()
        || fee_reserve.is_null()
        || session_id.is_null()
        || required_len.is_null()
        || intent_out.is_null()
        || (output.is_null() && output_capacity != 0)
    {
        return WALLET_NULL_POINTER;
    }
    let signer = PrincipalId::new(unsafe { read_digest(signer) });
    let transfer = match CoinTransfer::new(
        signer,
        PrincipalId::new(unsafe { read_digest(recipient) }),
        vec![CoinCellId::new(unsafe { read_digest(input) })],
        CoinCellId::new(unsafe { read_digest(fee_reserve) }),
        join_u128(amount_high, amount_low),
        join_u128(fee_high, fee_low),
        valid_until,
    ) {
        Ok(transfer) => transfer,
        Err(_) => return WALLET_MALFORMED,
    };
    let request = match CashAuthorizationRequestV1::new(
        ChainId::new(unsafe { read_digest(chain_id) }),
        signer,
        nonce,
        unsafe { read_digest(session_id) },
        session_expires_at,
        transfer,
    ) {
        Ok(request) => request,
        Err(_) => return WALLET_MALFORMED,
    };
    let encoded = match encode_envelope(&request) {
        Ok(encoded) => encoded,
        Err(_) => return WALLET_MALFORMED,
    };
    let Ok(length) = u32::try_from(encoded.len()) else {
        return WALLET_TOO_LARGE;
    };
    unsafe {
        *required_len = length;
    }
    if output_capacity < length {
        return WALLET_BUFFER_TOO_SMALL;
    }
    if length != 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len());
        }
    }
    let intent = match request.intent_id() {
        Ok(intent) => intent,
        Err(_) => return WALLET_MALFORMED,
    };
    unsafe {
        core::ptr::copy_nonoverlapping(intent.as_bytes().as_ptr(), intent_out, 48);
    }
    WALLET_OK
}

const fn join_u128(high: u64, low: u64) -> u128 {
    (high as u128) << 64 | low as u128
}

unsafe fn read_digest(input: *const u8) -> Digest384 {
    let bytes = unsafe { core::slice::from_raw_parts(input, 48) };
    let mut digest = [0; 48];
    digest.copy_from_slice(bytes);
    Digest384::new(digest)
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

    #[test]
    fn policy_abi_matches_limits_and_optional_recipient_pinning() {
        let recipient = digest(40);
        assert_eq!(
            unsafe {
                activechain_wallet_policy_allows(
                    0,
                    100,
                    0,
                    60,
                    recipient.as_bytes().as_ptr(),
                    0,
                    50,
                    recipient.as_bytes().as_ptr(),
                    0,
                    40,
                )
            },
            1
        );
        assert_eq!(
            unsafe {
                activechain_wallet_policy_allows(
                    0,
                    100,
                    0,
                    60,
                    recipient.as_bytes().as_ptr(),
                    0,
                    50,
                    digest(41).as_bytes().as_ptr(),
                    0,
                    40,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                activechain_wallet_policy_allows(
                    0,
                    100,
                    0,
                    60,
                    core::ptr::null(),
                    0,
                    50,
                    recipient.as_bytes().as_ptr(),
                    0,
                    60,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                activechain_wallet_policy_allows(
                    0,
                    100,
                    0,
                    60,
                    core::ptr::null(),
                    0,
                    1,
                    core::ptr::null(),
                    0,
                    0,
                )
            },
            0
        );
    }

    #[test]
    fn intent_builder_supports_size_query_and_publishes_exact_canonical_request() {
        let chain = digest(1);
        let signer = digest(2);
        let recipient = digest(3);
        let input = digest(4);
        let reserve = digest(5);
        let session = digest(6);
        let mut required = 0;
        let mut intent = [0; 48];
        assert_eq!(
            unsafe {
                activechain_wallet_build_cash_intent(
                    chain.as_bytes().as_ptr(),
                    signer.as_bytes().as_ptr(),
                    recipient.as_bytes().as_ptr(),
                    input.as_bytes().as_ptr(),
                    reserve.as_bytes().as_ptr(),
                    7,
                    session.as_bytes().as_ptr(),
                    9,
                    0,
                    50,
                    0,
                    2,
                    10,
                    core::ptr::null_mut(),
                    0,
                    &mut required,
                    intent.as_mut_ptr(),
                )
            },
            WALLET_BUFFER_TOO_SMALL
        );
        assert!(required > 0);
        assert_eq!(intent, [0; 48]);
        let mut output = vec![0; required as usize];
        assert_eq!(
            unsafe {
                activechain_wallet_build_cash_intent(
                    chain.as_bytes().as_ptr(),
                    signer.as_bytes().as_ptr(),
                    recipient.as_bytes().as_ptr(),
                    input.as_bytes().as_ptr(),
                    reserve.as_bytes().as_ptr(),
                    7,
                    session.as_bytes().as_ptr(),
                    9,
                    0,
                    50,
                    0,
                    2,
                    10,
                    output.as_mut_ptr(),
                    required,
                    &mut required,
                    intent.as_mut_ptr(),
                )
            },
            WALLET_OK
        );
        let decoded = decode_envelope::<CashAuthorizationRequestV1>(&output).unwrap();
        assert_eq!(decoded.nonce(), 7);
        assert_eq!(decoded.intent_id().unwrap().as_bytes(), &intent);
        assert_eq!(
            unsafe {
                activechain_wallet_build_cash_intent(
                    chain.as_bytes().as_ptr(),
                    signer.as_bytes().as_ptr(),
                    recipient.as_bytes().as_ptr(),
                    input.as_bytes().as_ptr(),
                    input.as_bytes().as_ptr(),
                    7,
                    session.as_bytes().as_ptr(),
                    9,
                    0,
                    50,
                    0,
                    2,
                    10,
                    output.as_mut_ptr(),
                    required,
                    &mut required,
                    intent.as_mut_ptr(),
                )
            },
            WALLET_MALFORMED
        );
    }
}
