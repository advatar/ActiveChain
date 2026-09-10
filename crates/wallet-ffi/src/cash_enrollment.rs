use super::*;
use activechain_wallet_core::{
    AuthorizedCashSessionGrantV1, CashKeyEnrollmentV1, CashSessionGrantV1,
};

/// Derives the Coin Cell output origin from the exact reviewed cash request.
/// This transfer identifier differs from the authorization intent committed by finality.
/// # Safety
/// Request is readable for request_len bytes; transition_out is writable for 48 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_cash_transition_id(
    request: *const u8,
    request_len: u32,
    transition_out: *mut u8,
) -> u32 {
    if request.is_null() || transition_out.is_null() {
        return WALLET_NULL_POINTER;
    }
    if request_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let Ok(request) = decode_envelope::<CashAuthorizationRequestV1>(unsafe {
        core::slice::from_raw_parts(request, request_len as usize)
    }) else {
        return WALLET_MALFORMED;
    };
    let Ok(id) = activechain_protocol_commitment::cash_transition_id(request.transfer()) else {
        return WALLET_MALFORMED;
    };
    unsafe { core::ptr::copy_nonoverlapping(id.digest().as_bytes().as_ptr(), transition_out, 48) };
    WALLET_OK
}

/// Encodes and verifies a signed wallet-key enrollment. Querying requires no signature.
/// # Safety
/// Fixed inputs are readable for 48/1312/2420 bytes; outputs are writable. Signature may be null
/// only for a zero-capacity query, and output may be null only when capacity is zero.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_encode_key_enrollment(
    chain: *const u8,
    public_key: *const u8,
    valid_from: u64,
    expires_at: u64,
    signature: *const u8,
    output: *mut u8,
    capacity: u32,
    required: *mut u32,
    reference: *mut u8,
) -> u32 {
    if chain.is_null()
        || public_key.is_null()
        || required.is_null()
        || reference.is_null()
        || (capacity > 0 && (signature.is_null() || output.is_null()))
    {
        return WALLET_NULL_POINTER;
    }
    let chain = ChainId::new(unsafe { read_digest(chain) });
    let key = unsafe { core::slice::from_raw_parts(public_key, 1312) };
    if CashKeyEnrollmentV1::signing_payload(chain, key, valid_from, expires_at).is_err() {
        return WALLET_MALFORMED;
    }
    // Envelope body: chain + ULEB key + key + heights + suite + ULEB signature + signature.
    let length = 4 + 2 + 48 + 2 + 1312 + 16 + 6 + 2 + 2420;
    unsafe {
        *required = length;
    }
    if capacity < length {
        return WALLET_BUFFER_TOO_SMALL;
    }
    let sig = unsafe { core::slice::from_raw_parts(signature, 2420) }.to_vec();
    let Ok(signature) = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, sig) else {
        return WALLET_INVALID_SIGNATURE;
    };
    let Ok(enrollment) =
        CashKeyEnrollmentV1::new(chain, key.to_vec(), valid_from, expires_at, signature)
    else {
        return WALLET_INVALID_SIGNATURE;
    };
    let Ok(bytes) = encode_envelope(&enrollment) else {
        return WALLET_MALFORMED;
    };
    let Ok(id) = enrollment.reference() else {
        return WALLET_MALFORMED;
    };
    if bytes.len() > capacity as usize {
        return WALLET_BUFFER_TOO_SMALL;
    }
    unsafe {
        *required = bytes.len() as u32;
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
        core::ptr::copy_nonoverlapping(id.as_bytes().as_ptr(), reference, 48);
    }
    WALLET_OK
}

/// Encodes a bounded session grant whose budget and identity come from the reviewed cash request.
/// # Safety
/// Request has request_len readable bytes; key/signature are 1312/2420 bytes. Output/required are
/// writable. Signature may be null only for a size query; output may be null at zero capacity.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_encode_cash_session(
    request: *const u8,
    request_len: u32,
    public_key: *const u8,
    valid_from: u64,
    signature: *const u8,
    output: *mut u8,
    capacity: u32,
    required: *mut u32,
) -> u32 {
    if request.is_null()
        || public_key.is_null()
        || required.is_null()
        || (capacity > 0 && (output.is_null() || signature.is_null()))
    {
        return WALLET_NULL_POINTER;
    }
    if request_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let Ok(request) = decode_envelope::<CashAuthorizationRequestV1>(unsafe {
        core::slice::from_raw_parts(request, request_len as usize)
    }) else {
        return WALLET_MALFORMED;
    };
    let key = unsafe { core::slice::from_raw_parts(public_key, 1312) };
    if activechain_wallet_core::wallet_principal_id(key) != request.signer() {
        return WALLET_APPROVAL_MISMATCH;
    }
    let Some(budget) = request.transfer().amount().checked_add(request.transfer().fee()) else {
        return WALLET_MALFORMED;
    };
    let Ok(grant) = CashSessionGrantV1::new(
        request.chain_id(),
        request.signer(),
        request.session_id(),
        valid_from,
        request.session_expires_at(),
        budget,
    ) else {
        return WALLET_MALFORMED;
    };
    let sig = if capacity == 0 {
        vec![0; 2420]
    } else {
        unsafe { core::slice::from_raw_parts(signature, 2420) }.to_vec()
    };
    let Ok(signature) = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, sig) else {
        return WALLET_MALFORMED;
    };
    let Ok(authorized) = AuthorizedCashSessionGrantV1::new(grant, signature) else {
        return WALLET_MALFORMED;
    };
    let Ok(bytes) = encode_envelope(&authorized) else {
        return WALLET_MALFORMED;
    };
    unsafe {
        *required = bytes.len() as u32;
    }
    if capacity < bytes.len() as u32 {
        return WALLET_BUFFER_TOO_SMALL;
    }
    if authorized.verify(key).is_err() {
        return WALLET_INVALID_SIGNATURE;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
    }
    WALLET_OK
}

/// Verifies the exact cash-action inclusion under a pinned chain's native finality certificate.
/// # Safety
/// Chain/genesis/reference are readable 48-byte values; IDs/finality have their declared lengths;
/// height_out is writable. The ID list preserves consensus order and contains at most 32 IDs.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_verify_cash_finality(
    chain: *const u8,
    genesis: *const u8,
    reference: *const u8,
    ids: *const u8,
    ids_len: u32,
    finality: *const u8,
    finality_len: u32,
    height_out: *mut u64,
) -> u32 {
    if chain.is_null()
        || genesis.is_null()
        || reference.is_null()
        || ids.is_null()
        || finality.is_null()
        || height_out.is_null()
    {
        return WALLET_NULL_POINTER;
    }
    if ids_len == 0
        || ids_len > 32 * 48
        || !ids_len.is_multiple_of(48)
        || finality_len > MAX_WALLET_INPUT
    {
        return WALLET_TOO_LARGE;
    }
    let ids = unsafe { core::slice::from_raw_parts(ids, ids_len as usize) };
    let reference = unsafe { core::slice::from_raw_parts(reference, 48) };
    if ids.chunks_exact(48).filter(|id| *id == reference).count() != 1 {
        return WALLET_INVALID_PROOF;
    }
    let Ok(bundle) = activechain_verifier_api::verify_finality_bundle_with_chain_genesis(
        unsafe { core::slice::from_raw_parts(finality, finality_len as usize) },
        unsafe { read_digest(genesis) },
    ) else {
        return WALLET_INVALID_PROOF;
    };
    if bundle.header().inputs.chain_id.digest() != &unsafe { read_digest(chain) }
        || bundle.header().inputs.cash_action_root
            != activechain_finality_types::commit_parts(
                b"ACTIVECHAIN-BLOCK-CASH-ACTIONS-V1",
                &[ids],
            )
    {
        return WALLET_INVALID_PROOF;
    }
    unsafe {
        *height_out = bundle.header().inputs.height;
    }
    WALLET_OK
}

/// Checks signed enrollment bytes against the exact wallet, chain and expected action ID.
/// # Safety
/// Bytes are readable for length; chain/owner/reference each point to 48 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_check_key_enrollment(
    bytes: *const u8,
    length: u32,
    chain: *const u8,
    owner: *const u8,
    reference: *const u8,
) -> u32 {
    if bytes.is_null() || chain.is_null() || owner.is_null() || reference.is_null() {
        return WALLET_NULL_POINTER;
    }
    if length > 4096 {
        return WALLET_TOO_LARGE;
    }
    let Ok(enrollment) = decode_envelope::<CashKeyEnrollmentV1>(unsafe {
        core::slice::from_raw_parts(bytes, length as usize)
    }) else {
        return WALLET_MALFORMED;
    };
    if enrollment.chain_id().digest() != &unsafe { read_digest(chain) }
        || enrollment.signer().digest() != &unsafe { read_digest(owner) }
        || enrollment.reference().ok() != Some(unsafe { read_digest(reference) })
    {
        return WALLET_APPROVAL_MISMATCH;
    }
    WALLET_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cash_output_origin_matches_real_ledger_and_change_is_combined() {
        use activechain_cash_kernel::{
            CashLedger, GenesisAllocation, GenesisEconomy, NativeAssetDefinition,
        };
        let chain = ChainId::new(Digest384::new([1; 48]));
        let owner = PrincipalId::new(Digest384::new([2; 48]));
        let merchant = PrincipalId::new(Digest384::new([3; 48]));
        let definition = NativeAssetDefinition::new(
            chain,
            b"ACT".to_vec(),
            18,
            1000,
            150,
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
        )
        .unwrap();
        let economy = GenesisEconomy::new(
            definition,
            vec![
                GenesisAllocation::new(owner, 700, 100).unwrap(),
                GenesisAllocation::new(owner, 100, 0).unwrap(),
            ],
            100,
        )
        .unwrap();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        let cells = ledger.cells().as_slice();
        let transfer =
            CoinTransfer::new(owner, merchant, vec![cells[0].id()], cells[1].id(), 10, 1, 20)
                .unwrap();
        let request = CashAuthorizationRequestV1::new(
            chain,
            owner,
            0,
            Digest384::new([7; 48]),
            20,
            transfer.clone(),
        )
        .unwrap();
        let bytes = encode_envelope(&request).unwrap();
        let mut origin = [0; 48];
        assert_eq!(
            unsafe {
                activechain_wallet_cash_transition_id(
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    origin.as_mut_ptr(),
                )
            },
            WALLET_OK
        );
        assert_ne!(&origin, request.intent_id().unwrap().as_bytes());
        ledger.apply_transfer(&transfer, 7).unwrap();
        let outputs = ledger.cells().as_slice();
        assert_eq!(outputs.len(), 2);
        for record in outputs {
            assert_eq!(record.cell().origin().transition_id().digest().as_bytes(), &origin);
            assert_eq!(record.cell().creation_height(), 7);
            match record.cell().origin().output_index() {
                0 => {
                    assert_eq!(record.cell().owner(), merchant);
                    assert_eq!(record.cell().amount(), 10);
                }
                1 => {
                    assert_eq!(record.cell().owner(), owner);
                    assert_eq!(record.cell().amount(), 789);
                }
                _ => panic!("ordinary cash transfer must have one combined change output"),
            }
        }
        let before = origin;
        assert_eq!(
            unsafe {
                activechain_wallet_cash_transition_id(
                    bytes.as_ptr(),
                    bytes.len() as u32 - 1,
                    origin.as_mut_ptr(),
                )
            },
            WALLET_MALFORMED
        );
        assert_eq!(origin, before);
        assert_eq!(
            unsafe {
                activechain_wallet_cash_transition_id(core::ptr::null(), 0, origin.as_mut_ptr())
            },
            WALLET_NULL_POINTER
        );
        assert_eq!(
            unsafe {
                activechain_wallet_cash_transition_id(
                    bytes.as_ptr(),
                    MAX_WALLET_INPUT + 1,
                    origin.as_mut_ptr(),
                )
            },
            WALLET_TOO_LARGE
        );
        assert_eq!(origin, before);
    }
    #[test]
    fn native_enrollment_verifies_ownership_and_size_query_needs_no_secret() {
        let seed = ml_dsa::Seed::from([54; 32]);
        let key = SigningKey::<MlDsa44>::from_seed(&seed);
        let public = key.verifying_key().encode();
        let chain = ChainId::new(Digest384::new([8; 48]));
        let payload =
            CashKeyEnrollmentV1::signing_payload(chain, public.as_slice(), 12, 100).unwrap();
        let mut signature = key.sign(&payload).encode().to_vec();
        let mut required = 0;
        let mut reference = [0; 48];
        assert_eq!(
            unsafe {
                activechain_wallet_encode_key_enrollment(
                    chain.digest().as_bytes().as_ptr(),
                    public.as_ptr(),
                    12,
                    100,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    0,
                    &mut required,
                    reference.as_mut_ptr(),
                )
            },
            WALLET_BUFFER_TOO_SMALL
        );
        assert_eq!(reference, [0; 48]);
        let mut output = vec![0; required as usize];
        assert_eq!(
            unsafe {
                activechain_wallet_encode_key_enrollment(
                    chain.digest().as_bytes().as_ptr(),
                    public.as_ptr(),
                    12,
                    100,
                    signature.as_ptr(),
                    output.as_mut_ptr(),
                    output.len() as u32,
                    &mut required,
                    reference.as_mut_ptr(),
                )
            },
            WALLET_OK
        );
        let enrollment = decode_envelope::<CashKeyEnrollmentV1>(&output).unwrap();
        assert_eq!(enrollment.reference().unwrap().as_bytes(), &reference);
        assert_eq!(
            enrollment.signer(),
            activechain_wallet_core::wallet_principal_id(public.as_slice())
        );
        signature[100] ^= 1;
        let before = output.clone();
        assert_eq!(
            unsafe {
                activechain_wallet_encode_key_enrollment(
                    chain.digest().as_bytes().as_ptr(),
                    public.as_ptr(),
                    12,
                    100,
                    signature.as_ptr(),
                    output.as_mut_ptr(),
                    output.len() as u32,
                    &mut required,
                    reference.as_mut_ptr(),
                )
            },
            WALLET_INVALID_SIGNATURE
        );
        assert_eq!(output, before);
    }
    #[test]
    fn cash_evidence_rejects_duplicates_oversize_and_malformed_certificates() {
        let digest = [1; 48];
        let mut height = 99;
        for ids in [digest.to_vec(), [digest, digest].concat(), vec![1; 33 * 48]] {
            assert_ne!(
                unsafe {
                    activechain_wallet_verify_cash_finality(
                        digest.as_ptr(),
                        digest.as_ptr(),
                        digest.as_ptr(),
                        ids.as_ptr(),
                        ids.len() as u32,
                        digest.as_ptr(),
                        48,
                        &mut height,
                    )
                },
                WALLET_OK
            );
            assert_eq!(height, 99);
        }
    }
}
