#![allow(unsafe_code)]

use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_cash_kernel::{CoinCellSet, CoinTransfer};
use activechain_protocol_types::{
    CapabilityId, ChainId, CoinCellId, CryptoSuiteId, Digest384, PrincipalId, ProtocolSignature,
    TransactionId,
};
use activechain_wallet_core::{
    AgentConnectionKind, AgentLifecycle, AgentRegistryCommandV1, AgentRegistryV1,
    AuthorizedCashTransferV1, CashAuthorizationRequestV1, ManagedAgentV1, OpenWalletConsentV1,
    OpenWalletCredentialOfferV1, OpenWalletPresentationRequestV1,
};
use core::ffi::c_void;

const MAX_WALLET_INPUT: u32 = 256 * 1024;
pub const ACTIVECHAIN_WALLET_OK: u32 = 0;
pub const ACTIVECHAIN_WALLET_NULL_POINTER: u32 = 1;
pub const ACTIVECHAIN_WALLET_TOO_LARGE: u32 = 2;
pub const ACTIVECHAIN_WALLET_MALFORMED: u32 = 3;
pub const ACTIVECHAIN_WALLET_INSUFFICIENT_FUNDS: u32 = 4;
pub const ACTIVECHAIN_WALLET_BUFFER_TOO_SMALL: u32 = 5;
pub const ACTIVECHAIN_WALLET_CALLBACK_FAILED: u32 = 6;
pub const ACTIVECHAIN_WALLET_INVALID_SIGNATURE: u32 = 7;
pub const ACTIVECHAIN_WALLET_AGENT_REJECTED: u32 = 8;
pub const ACTIVECHAIN_WALLET_OPENWALLET_OFFER: u32 = 1;
pub const ACTIVECHAIN_WALLET_OPENWALLET_PRESENTATION_REQUEST: u32 = 2;
pub const ACTIVECHAIN_WALLET_OPENWALLET_CONSENT: u32 = 3;
const WALLET_OK: u32 = ACTIVECHAIN_WALLET_OK;
const WALLET_NULL_POINTER: u32 = ACTIVECHAIN_WALLET_NULL_POINTER;
const WALLET_TOO_LARGE: u32 = ACTIVECHAIN_WALLET_TOO_LARGE;
const WALLET_MALFORMED: u32 = ACTIVECHAIN_WALLET_MALFORMED;
const WALLET_INSUFFICIENT_FUNDS: u32 = ACTIVECHAIN_WALLET_INSUFFICIENT_FUNDS;
const WALLET_BUFFER_TOO_SMALL: u32 = ACTIVECHAIN_WALLET_BUFFER_TOO_SMALL;
const WALLET_CALLBACK_FAILED: u32 = ACTIVECHAIN_WALLET_CALLBACK_FAILED;
const WALLET_INVALID_SIGNATURE: u32 = ACTIVECHAIN_WALLET_INVALID_SIGNATURE;
const WALLET_AGENT_REJECTED: u32 = ACTIVECHAIN_WALLET_AGENT_REJECTED;
const ML_DSA44_SIGNATURE_LENGTH: usize = 2_420;
const ML_DSA44_PUBLIC_KEY_LENGTH: usize = 1_312;

pub type ActivechainWalletSignCallback = unsafe extern "C" fn(
    context: *mut c_void,
    payload: *const u8,
    payload_len: u32,
    signature_out: *mut u8,
    signature_len: u32,
) -> u32;
pub type ActivechainWalletSubmitCallback =
    unsafe extern "C" fn(context: *mut c_void, envelope: *const u8, envelope_len: u32) -> u32;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivechainWalletAgentSummary {
    pub principal: [u8; 48],
    pub connection: u32,
    pub lifecycle: u32,
    pub capability_count: u32,
    pub budget_limit_high: u64,
    pub budget_limit_low: u64,
    pub budget_spent_high: u64,
    pub budget_spent_low: u64,
    pub expires_at: u64,
    pub revocation_finalized_height: u64,
}

impl Default for ActivechainWalletAgentSummary {
    fn default() -> Self {
        Self {
            principal: [0; 48],
            connection: 0,
            lifecycle: 0,
            capability_count: 0,
            budget_limit_high: 0,
            budget_limit_low: 0,
            budget_spent_high: 0,
            budget_spent_low: 0,
            expires_at: 0,
            revocation_finalized_height: 0,
        }
    }
}

/// Returns the ABI revision consumed by native wallet shells.
#[unsafe(no_mangle)]
pub extern "C" fn activechain_wallet_ffi_revision() -> u32 {
    2
}

/// Validates one canonical OpenWallet envelope and returns its protocol commitment.
///
/// `kind` must be one of the `ACTIVECHAIN_WALLET_OPENWALLET_*` constants. This boundary
/// deliberately accepts canonical ActiveChain envelopes rather than JSON so native transport
/// adapters cannot silently reinterpret a consent or presentation request.
///
/// # Safety
///
/// `envelope` must be readable for `envelope_len` bytes and `commitment_out` must point to a
/// writable 48-byte buffer. Neither pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_openwallet_validate(
    kind: u32,
    envelope: *const u8,
    envelope_len: u32,
    commitment_out: *mut u8,
) -> u32 {
    if (envelope.is_null() && envelope_len != 0) || commitment_out.is_null() {
        return WALLET_NULL_POINTER;
    }
    if envelope_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let envelope = if envelope_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(envelope, envelope_len as usize) }
    };
    let commitment = match kind {
        ACTIVECHAIN_WALLET_OPENWALLET_OFFER => {
            decode_envelope::<OpenWalletCredentialOfferV1>(envelope)
                .ok()
                .and_then(|value| value.commitment().ok())
        }
        ACTIVECHAIN_WALLET_OPENWALLET_PRESENTATION_REQUEST => {
            decode_envelope::<OpenWalletPresentationRequestV1>(envelope)
                .ok()
                .and_then(|value| value.commitment().ok())
        }
        ACTIVECHAIN_WALLET_OPENWALLET_CONSENT => decode_envelope::<OpenWalletConsentV1>(envelope)
            .ok()
            .and_then(|value| value.commitment().ok()),
        _ => return WALLET_MALFORMED,
    };
    let Some(commitment) = commitment else {
        return WALLET_MALFORMED;
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            commitment.as_bytes().as_ptr(),
            commitment_out,
            commitment.as_bytes().len(),
        );
    }
    WALLET_OK
}

/// Applies one canonical agent-registry command and returns the complete next registry snapshot.
///
/// Pass an empty registry buffer to start from the canonical empty registry. The input registry is
/// never modified, and no output bytes are published unless the complete next state fits.
///
/// # Safety
///
/// Non-empty inputs must point to readable buffers for their declared lengths. `required_len` must
/// be writable. `output` may be null only when `output_capacity` is zero for a size query. No
/// pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_agent_apply(
    registry: *const u8,
    registry_len: u32,
    command: *const u8,
    command_len: u32,
    output: *mut u8,
    output_capacity: u32,
    required_len: *mut u32,
) -> u32 {
    if (registry.is_null() && registry_len != 0)
        || (command.is_null() && command_len != 0)
        || command_len == 0
        || required_len.is_null()
        || (output.is_null() && output_capacity != 0)
    {
        return WALLET_NULL_POINTER;
    }
    if registry_len > MAX_WALLET_INPUT || command_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let mut registry = if registry_len == 0 {
        AgentRegistryV1::default()
    } else {
        let bytes = unsafe { core::slice::from_raw_parts(registry, registry_len as usize) };
        match decode_envelope(bytes) {
            Ok(registry) => registry,
            Err(_) => return WALLET_MALFORMED,
        }
    };
    let command_bytes = unsafe { core::slice::from_raw_parts(command, command_len as usize) };
    let command = match decode_envelope::<AgentRegistryCommandV1>(command_bytes) {
        Ok(command) => command,
        Err(_) => return WALLET_MALFORMED,
    };
    if registry.apply(command).is_err() {
        return WALLET_AGENT_REJECTED;
    }
    let encoded = match encode_envelope(&registry) {
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
    unsafe {
        core::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len());
    }
    WALLET_OK
}

/// Registers one native agent and returns the complete canonical next registry.
///
/// Capabilities are a contiguous array of `capability_count * 48` bytes and must already be
/// strictly ordered. The label must be non-empty UTF-8.
///
/// # Safety
///
/// All non-empty inputs and outputs must point to readable/writable buffers for their declared
/// lengths. Fixed identifiers point to 48 bytes. No pointer is retained.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_agent_register(
    registry: *const u8,
    registry_len: u32,
    principal: *const u8,
    label: *const u8,
    label_len: u32,
    connection: u32,
    capabilities: *const u8,
    capability_count: u32,
    budget_limit_high: u64,
    budget_limit_low: u64,
    expires_at: u64,
    output: *mut u8,
    output_capacity: u32,
    required_len: *mut u32,
) -> u32 {
    if principal.is_null()
        || label.is_null()
        || label_len == 0
        || capabilities.is_null()
        || capability_count == 0
    {
        return WALLET_NULL_POINTER;
    }
    let Ok(label_len) = usize::try_from(label_len) else {
        return WALLET_TOO_LARGE;
    };
    let Ok(capability_count) = usize::try_from(capability_count) else {
        return WALLET_TOO_LARGE;
    };
    let Some(capabilities_len) = capability_count.checked_mul(48) else {
        return WALLET_TOO_LARGE;
    };
    if label_len > activechain_wallet_core::MAX_AGENT_LABEL
        || capability_count > activechain_wallet_core::MAX_AGENT_CAPABILITIES
    {
        return WALLET_TOO_LARGE;
    }
    let connection = match connection {
        0 => AgentConnectionKind::SameTeamAppGroup,
        1 => AgentConnectionKind::ThirdPartyProtocol,
        2 => AgentConnectionKind::RemoteService,
        3 => AgentConnectionKind::ManagedDeviceExtension,
        _ => return WALLET_MALFORMED,
    };
    let label = unsafe { core::slice::from_raw_parts(label, label_len) }.to_vec();
    let capability_bytes = unsafe { core::slice::from_raw_parts(capabilities, capabilities_len) };
    let mut capability_ids = Vec::with_capacity(capability_count);
    for bytes in capability_bytes.chunks_exact(48) {
        let mut digest = [0; 48];
        digest.copy_from_slice(bytes);
        capability_ids.push(CapabilityId::new(Digest384::new(digest)));
    }
    let agent = match ManagedAgentV1::new(
        PrincipalId::new(unsafe { read_digest(principal) }),
        label,
        connection,
        capability_ids,
        join_u128(budget_limit_high, budget_limit_low),
        expires_at,
    ) {
        Ok(agent) => agent,
        Err(_) => return WALLET_MALFORMED,
    };
    unsafe {
        apply_agent_command(
            registry,
            registry_len,
            AgentRegistryCommandV1::Register(agent),
            output,
            output_capacity,
            required_len,
        )
    }
}

/// Pauses or resumes one agent and returns the canonical next registry.
///
/// # Safety
///
/// `principal` points to 48 readable bytes; registry and output pointers follow
/// `activechain_wallet_agent_apply`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_agent_set_paused(
    registry: *const u8,
    registry_len: u32,
    principal: *const u8,
    paused: u32,
    output: *mut u8,
    output_capacity: u32,
    required_len: *mut u32,
) -> u32 {
    if principal.is_null() || paused > 1 {
        return WALLET_NULL_POINTER;
    }
    let principal = PrincipalId::new(unsafe { read_digest(principal) });
    let command = if paused == 1 {
        AgentRegistryCommandV1::Pause(principal)
    } else {
        AgentRegistryCommandV1::Resume(principal)
    };
    unsafe {
        apply_agent_command(registry, registry_len, command, output, output_capacity, required_len)
    }
}

/// Starts or finalizes an agent revocation and returns the canonical next registry.
///
/// Pass `finalized_height == 0` to begin revocation; a non-zero height finalizes the same
/// transaction.
///
/// # Safety
///
/// Principal and transaction pointers each point to 48 readable bytes; other pointers follow
/// `activechain_wallet_agent_apply`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_agent_revoke(
    registry: *const u8,
    registry_len: u32,
    principal: *const u8,
    transaction: *const u8,
    finalized_height: u64,
    output: *mut u8,
    output_capacity: u32,
    required_len: *mut u32,
) -> u32 {
    if principal.is_null() || transaction.is_null() {
        return WALLET_NULL_POINTER;
    }
    let principal = PrincipalId::new(unsafe { read_digest(principal) });
    let transaction = TransactionId::new(unsafe { read_digest(transaction) });
    let command = if finalized_height == 0 {
        AgentRegistryCommandV1::BeginRevocation { principal, transaction }
    } else {
        AgentRegistryCommandV1::FinalizeRevocation { principal, transaction, finalized_height }
    };
    unsafe {
        apply_agent_command(registry, registry_len, command, output, output_capacity, required_len)
    }
}

/// Returns the number of agents in a canonical registry.
///
/// # Safety
///
/// Registry bytes must be readable and `count_out` writable. No pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_agent_count(
    registry: *const u8,
    registry_len: u32,
    count_out: *mut u32,
) -> u32 {
    if registry.is_null() || registry_len == 0 || count_out.is_null() {
        return WALLET_NULL_POINTER;
    }
    if registry_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let bytes = unsafe { core::slice::from_raw_parts(registry, registry_len as usize) };
    let registry = match decode_envelope::<AgentRegistryV1>(bytes) {
        Ok(registry) => registry,
        Err(_) => return WALLET_MALFORMED,
    };
    let Ok(count) = u32::try_from(registry.agents().len()) else {
        return WALLET_TOO_LARGE;
    };
    unsafe {
        *count_out = count;
    }
    WALLET_OK
}

/// Returns one agent summary and its UTF-8 label.
///
/// Label output supports the standard size-query pattern. The summary is not written unless the
/// complete label fits, so callers never observe a partial record.
///
/// # Safety
///
/// Registry bytes must be readable, summary and required-length outputs writable, and `label_out`
/// may be null only for a zero-capacity size query.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_agent_summary(
    registry: *const u8,
    registry_len: u32,
    index: u32,
    summary_out: *mut ActivechainWalletAgentSummary,
    label_out: *mut u8,
    label_capacity: u32,
    label_required: *mut u32,
) -> u32 {
    if registry.is_null()
        || registry_len == 0
        || summary_out.is_null()
        || label_required.is_null()
        || (label_out.is_null() && label_capacity != 0)
    {
        return WALLET_NULL_POINTER;
    }
    if registry_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let bytes = unsafe { core::slice::from_raw_parts(registry, registry_len as usize) };
    let registry = match decode_envelope::<AgentRegistryV1>(bytes) {
        Ok(registry) => registry,
        Err(_) => return WALLET_MALFORMED,
    };
    let Some(agent) = registry.agents().get(index as usize) else {
        return WALLET_MALFORMED;
    };
    let Ok(label_length) = u32::try_from(agent.label().len()) else {
        return WALLET_TOO_LARGE;
    };
    unsafe {
        *label_required = label_length;
    }
    if label_capacity < label_length {
        return WALLET_BUFFER_TOO_SMALL;
    }
    let (lifecycle, revocation_finalized_height) = match agent.lifecycle() {
        AgentLifecycle::Active => (0, 0),
        AgentLifecycle::Paused => (1, 0),
        AgentLifecycle::RevocationPending { .. } => (2, 0),
        AgentLifecycle::Revoked { finalized_height, .. } => (3, finalized_height),
    };
    let principal = *agent.principal().into_digest().as_bytes();
    let (budget_limit_high, budget_limit_low) = split_u128(agent.budget_limit());
    let (budget_spent_high, budget_spent_low) = split_u128(agent.budget_spent());
    let summary = ActivechainWalletAgentSummary {
        principal,
        connection: agent.connection() as u32,
        lifecycle,
        capability_count: agent.capabilities().len() as u32,
        budget_limit_high,
        budget_limit_low,
        budget_spent_high,
        budget_spent_low,
        expires_at: agent.expires_at(),
        revocation_finalized_height,
    };
    unsafe {
        core::ptr::copy_nonoverlapping(agent.label().as_ptr(), label_out, agent.label().len());
        *summary_out = summary;
    }
    WALLET_OK
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

/// Invokes a secure-key callback for one exact canonical request and verifies its result.
///
/// # Safety
///
/// `request` and `public_key` must be readable for their fixed lengths. `callback` must obey its
/// declared contract for the duration of the call. `output` may be null only for a zero-capacity
/// size query; `required_len` must be writable. The callback is never retained.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_sign_cash_intent(
    request: *const u8,
    request_len: u32,
    public_key: *const u8,
    callback: Option<ActivechainWalletSignCallback>,
    callback_context: *mut c_void,
    output: *mut u8,
    output_capacity: u32,
    required_len: *mut u32,
) -> u32 {
    if (request.is_null() && request_len != 0)
        || public_key.is_null()
        || callback.is_none()
        || required_len.is_null()
        || (output.is_null() && output_capacity != 0)
    {
        return WALLET_NULL_POINTER;
    }
    if request_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let request_bytes = if request_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(request, request_len as usize) }
    };
    let request = match decode_envelope::<CashAuthorizationRequestV1>(request_bytes) {
        Ok(request) => request,
        Err(_) => return WALLET_MALFORMED,
    };
    let placeholder =
        ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; ML_DSA44_SIGNATURE_LENGTH])
            .expect("the protocol publishes the ML-DSA-44 signature length");
    let placeholder = AuthorizedCashTransferV1::new(request.clone(), placeholder)
        .expect("ML-DSA-44 is the cash authorization suite");
    let required = match encode_envelope(&placeholder) {
        Ok(encoded) => encoded.len(),
        Err(_) => return WALLET_MALFORMED,
    };
    let Ok(required_u32) = u32::try_from(required) else {
        return WALLET_TOO_LARGE;
    };
    unsafe {
        *required_len = required_u32;
    }
    if output_capacity < required_u32 {
        return WALLET_BUFFER_TOO_SMALL;
    }
    let payload = match request.signing_payload() {
        Ok(payload) => payload,
        Err(_) => return WALLET_MALFORMED,
    };
    let Ok(payload_len) = u32::try_from(payload.len()) else {
        return WALLET_TOO_LARGE;
    };
    let mut signature = [0; ML_DSA44_SIGNATURE_LENGTH];
    let callback_code = unsafe {
        callback.expect("checked above")(
            callback_context,
            payload.as_ptr(),
            payload_len,
            signature.as_mut_ptr(),
            ML_DSA44_SIGNATURE_LENGTH as u32,
        )
    };
    if callback_code != 0 {
        return WALLET_CALLBACK_FAILED;
    }
    let signature =
        ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.to_vec()).expect("exact length");
    let authorized = AuthorizedCashTransferV1::new(request, signature)
        .expect("ML-DSA-44 is the cash authorization suite");
    let public_key = unsafe { core::slice::from_raw_parts(public_key, ML_DSA44_PUBLIC_KEY_LENGTH) };
    if authorized.verify(public_key).is_err() {
        return WALLET_INVALID_SIGNATURE;
    }
    let encoded = match encode_envelope(&authorized) {
        Ok(encoded) => encoded,
        Err(_) => return WALLET_MALFORMED,
    };
    debug_assert_eq!(encoded.len(), required);
    unsafe {
        core::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len());
    }
    WALLET_OK
}

/// Verifies and forwards one exact authorized envelope to a caller-owned transport.
///
/// # Safety
///
/// `envelope` and `public_key` must be readable for their declared/fixed lengths. `callback` must
/// obey its contract for the duration of the call. No pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_submit_authorized(
    envelope: *const u8,
    envelope_len: u32,
    public_key: *const u8,
    callback: Option<ActivechainWalletSubmitCallback>,
    callback_context: *mut c_void,
) -> u32 {
    if (envelope.is_null() && envelope_len != 0) || public_key.is_null() || callback.is_none() {
        return WALLET_NULL_POINTER;
    }
    if envelope_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let envelope = if envelope_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(envelope, envelope_len as usize) }
    };
    let authorized = match decode_envelope::<AuthorizedCashTransferV1>(envelope) {
        Ok(authorized) => authorized,
        Err(_) => return WALLET_MALFORMED,
    };
    let public_key = unsafe { core::slice::from_raw_parts(public_key, ML_DSA44_PUBLIC_KEY_LENGTH) };
    if authorized.verify(public_key).is_err() {
        return WALLET_INVALID_SIGNATURE;
    }
    let callback_code = unsafe {
        callback.expect("checked above")(callback_context, envelope.as_ptr(), envelope_len)
    };
    if callback_code != 0 {
        return WALLET_CALLBACK_FAILED;
    }
    WALLET_OK
}

unsafe fn apply_agent_command(
    registry: *const u8,
    registry_len: u32,
    command: AgentRegistryCommandV1,
    output: *mut u8,
    output_capacity: u32,
    required_len: *mut u32,
) -> u32 {
    if (registry.is_null() && registry_len != 0)
        || required_len.is_null()
        || (output.is_null() && output_capacity != 0)
    {
        return WALLET_NULL_POINTER;
    }
    if registry_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let mut registry = if registry_len == 0 {
        AgentRegistryV1::default()
    } else {
        let bytes = unsafe { core::slice::from_raw_parts(registry, registry_len as usize) };
        match decode_envelope(bytes) {
            Ok(registry) => registry,
            Err(_) => return WALLET_MALFORMED,
        }
    };
    if registry.apply(command).is_err() {
        return WALLET_AGENT_REJECTED;
    }
    let encoded = match encode_envelope(&registry) {
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
    unsafe {
        core::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len());
    }
    WALLET_OK
}

const fn join_u128(high: u64, low: u64) -> u128 {
    (high as u128) << 64 | low as u128
}

const fn split_u128(value: u128) -> (u64, u64) {
    ((value >> 64) as u64, value as u64)
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
    use ml_dsa::{Keypair, MlDsa44, Signer, SigningKey};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn revision_is_stable() {
        assert_eq!(activechain_wallet_ffi_revision(), 2);
    }

    #[test]
    fn openwallet_abi_validates_exact_envelope_kind_and_commits_it() {
        use activechain_wallet_core::{OpenWalletCredentialOfferV1, OpenWalletSessionV1};

        let offer = OpenWalletCredentialOfferV1::new(
            OpenWalletSessionV1 {
                session_id: digest(1),
                relying_party: digest(2),
                expires_at: 100,
            },
            b"https://issuer.example".to_vec(),
            vec![digest(3)],
            digest(4),
            digest(5),
            digest(6),
        )
        .unwrap();
        let envelope = encode_envelope(&offer).unwrap();
        let mut commitment = [0; 48];
        assert_eq!(
            unsafe {
                activechain_wallet_openwallet_validate(
                    ACTIVECHAIN_WALLET_OPENWALLET_OFFER,
                    envelope.as_ptr(),
                    envelope.len() as u32,
                    commitment.as_mut_ptr(),
                )
            },
            WALLET_OK
        );
        assert_eq!(commitment, *offer.commitment().unwrap().as_bytes());
        assert_eq!(
            unsafe {
                activechain_wallet_openwallet_validate(
                    ACTIVECHAIN_WALLET_OPENWALLET_CONSENT,
                    envelope.as_ptr(),
                    envelope.len() as u32,
                    commitment.as_mut_ptr(),
                )
            },
            WALLET_MALFORMED
        );
        let mut trailing = envelope;
        trailing.push(0);
        assert_eq!(
            unsafe {
                activechain_wallet_openwallet_validate(
                    ACTIVECHAIN_WALLET_OPENWALLET_OFFER,
                    trailing.as_ptr(),
                    trailing.len() as u32,
                    commitment.as_mut_ptr(),
                )
            },
            WALLET_MALFORMED
        );
    }

    #[test]
    fn agent_abi_applies_canonical_commands_and_preserves_replay_state() {
        use activechain_protocol_types::{CapabilityId, PrincipalId};
        use activechain_wallet_core::{AgentActionRequestV1, AgentConnectionKind, ManagedAgentV1};

        let principal = PrincipalId::new(digest(20));
        let capability = CapabilityId::new(digest(21));
        let register = encode_envelope(&AgentRegistryCommandV1::Register(
            ManagedAgentV1::new(
                principal,
                b"Third-party research agent".to_vec(),
                AgentConnectionKind::ThirdPartyProtocol,
                vec![capability],
                100,
                100,
            )
            .unwrap(),
        ))
        .unwrap();
        let mut required = 0;
        assert_eq!(
            unsafe {
                activechain_wallet_agent_apply(
                    core::ptr::null(),
                    0,
                    register.as_ptr(),
                    register.len() as u32,
                    core::ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            WALLET_BUFFER_TOO_SMALL
        );
        let mut registry = vec![0; required as usize];
        assert_eq!(
            unsafe {
                activechain_wallet_agent_apply(
                    core::ptr::null(),
                    0,
                    register.as_ptr(),
                    register.len() as u32,
                    registry.as_mut_ptr(),
                    registry.len() as u32,
                    &mut required,
                )
            },
            WALLET_OK
        );
        let mut count = 0;
        assert_eq!(
            unsafe {
                activechain_wallet_agent_count(registry.as_ptr(), registry.len() as u32, &mut count)
            },
            WALLET_OK
        );
        assert_eq!(count, 1);
        let mut summary = ActivechainWalletAgentSummary::default();
        let mut label_required = 0;
        assert_eq!(
            unsafe {
                activechain_wallet_agent_summary(
                    registry.as_ptr(),
                    registry.len() as u32,
                    0,
                    &mut summary,
                    core::ptr::null_mut(),
                    0,
                    &mut label_required,
                )
            },
            WALLET_BUFFER_TOO_SMALL
        );
        let mut label = vec![0; label_required as usize];
        assert_eq!(
            unsafe {
                activechain_wallet_agent_summary(
                    registry.as_ptr(),
                    registry.len() as u32,
                    0,
                    &mut summary,
                    label.as_mut_ptr(),
                    label.len() as u32,
                    &mut label_required,
                )
            },
            WALLET_OK
        );
        assert_eq!(label, b"Third-party research agent");
        assert_eq!(summary.connection, 1);
        assert_eq!(summary.lifecycle, 0);
        assert_eq!(summary.capability_count, 1);
        assert_eq!(summary.budget_limit_low, 100);
        let authorize = encode_envelope(&AgentRegistryCommandV1::Authorize {
            request: AgentActionRequestV1 {
                request_id: digest(22),
                agent: principal,
                capability,
                budget: 10,
                expires_at: 50,
            },
            current_height: 10,
        })
        .unwrap();
        let mut next_required = 0;
        assert_eq!(
            unsafe {
                activechain_wallet_agent_apply(
                    registry.as_ptr(),
                    registry.len() as u32,
                    authorize.as_ptr(),
                    authorize.len() as u32,
                    core::ptr::null_mut(),
                    0,
                    &mut next_required,
                )
            },
            WALLET_BUFFER_TOO_SMALL
        );
        let mut next = vec![0; next_required as usize];
        assert_eq!(
            unsafe {
                activechain_wallet_agent_apply(
                    registry.as_ptr(),
                    registry.len() as u32,
                    authorize.as_ptr(),
                    authorize.len() as u32,
                    next.as_mut_ptr(),
                    next.len() as u32,
                    &mut next_required,
                )
            },
            WALLET_OK
        );
        assert_eq!(
            unsafe {
                activechain_wallet_agent_apply(
                    next.as_ptr(),
                    next.len() as u32,
                    authorize.as_ptr(),
                    authorize.len() as u32,
                    core::ptr::null_mut(),
                    0,
                    &mut next_required,
                )
            },
            WALLET_AGENT_REJECTED
        );
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

    unsafe extern "C" fn sign_callback(
        context: *mut c_void,
        payload: *const u8,
        payload_len: u32,
        signature_out: *mut u8,
        signature_len: u32,
    ) -> u32 {
        if context.is_null()
            || payload.is_null()
            || signature_out.is_null()
            || signature_len != ML_DSA44_SIGNATURE_LENGTH as u32
        {
            return 1;
        }
        let key = unsafe { &*context.cast::<SigningKey<MlDsa44>>() };
        let payload = unsafe { core::slice::from_raw_parts(payload, payload_len as usize) };
        let signature = key.sign(payload).encode();
        unsafe {
            core::ptr::copy_nonoverlapping(
                signature.as_slice().as_ptr(),
                signature_out,
                signature.len(),
            );
        }
        0
    }

    #[test]
    fn secure_callback_signs_only_the_canonical_payload_and_is_verified_before_publication() {
        let transfer = CoinTransfer::new(
            PrincipalId::new(digest(2)),
            PrincipalId::new(digest(3)),
            vec![CoinCellId::new(digest(4))],
            CoinCellId::new(digest(5)),
            50,
            2,
            10,
        )
        .unwrap();
        let request = CashAuthorizationRequestV1::new(
            ChainId::new(digest(1)),
            PrincipalId::new(digest(2)),
            7,
            digest(6),
            9,
            transfer,
        )
        .unwrap();
        let request = encode_envelope(&request).unwrap();
        let key = SigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from([7; 32]));
        let public_key = key.verifying_key().encode();
        let mut required = 0;
        assert_eq!(
            unsafe {
                activechain_wallet_sign_cash_intent(
                    request.as_ptr(),
                    request.len() as u32,
                    public_key.as_slice().as_ptr(),
                    Some(sign_callback),
                    (&key as *const SigningKey<MlDsa44>).cast_mut().cast(),
                    core::ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            WALLET_BUFFER_TOO_SMALL
        );
        let mut output = vec![0; required as usize];
        assert_eq!(
            unsafe {
                activechain_wallet_sign_cash_intent(
                    request.as_ptr(),
                    request.len() as u32,
                    public_key.as_slice().as_ptr(),
                    Some(sign_callback),
                    (&key as *const SigningKey<MlDsa44>).cast_mut().cast(),
                    output.as_mut_ptr(),
                    required,
                    &mut required,
                )
            },
            WALLET_OK
        );
        let authorized = decode_envelope::<AuthorizedCashTransferV1>(&output).unwrap();
        assert_eq!(authorized.verify(public_key.as_slice()), Ok(()));

        let wrong_key = SigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from([8; 32]));
        assert_eq!(
            unsafe {
                activechain_wallet_sign_cash_intent(
                    request.as_ptr(),
                    request.len() as u32,
                    wrong_key.verifying_key().encode().as_slice().as_ptr(),
                    Some(sign_callback),
                    (&key as *const SigningKey<MlDsa44>).cast_mut().cast(),
                    output.as_mut_ptr(),
                    required,
                    &mut required,
                )
            },
            WALLET_INVALID_SIGNATURE
        );
    }

    unsafe extern "C" fn submit_callback(
        context: *mut c_void,
        envelope: *const u8,
        envelope_len: u32,
    ) -> u32 {
        if context.is_null() || envelope.is_null() || envelope_len == 0 {
            return 1;
        }
        let count = unsafe { &mut *context.cast::<usize>() };
        *count += 1;
        0
    }

    #[test]
    fn submission_reverifies_authorization_before_reaching_transport() {
        let key = SigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from([9; 32]));
        let request = CashAuthorizationRequestV1::new(
            ChainId::new(digest(1)),
            PrincipalId::new(digest(2)),
            7,
            digest(6),
            9,
            CoinTransfer::new(
                PrincipalId::new(digest(2)),
                PrincipalId::new(digest(3)),
                vec![CoinCellId::new(digest(4))],
                CoinCellId::new(digest(5)),
                50,
                2,
                10,
            )
            .unwrap(),
        )
        .unwrap();
        let signature = key.sign(&request.signing_payload().unwrap()).encode();
        let authorized = AuthorizedCashTransferV1::new(
            request,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.as_slice().to_vec())
                .unwrap(),
        )
        .unwrap();
        let encoded = encode_envelope(&authorized).unwrap();
        let public_key = key.verifying_key().encode();
        let mut submissions = 0_usize;
        assert_eq!(
            unsafe {
                activechain_wallet_submit_authorized(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    public_key.as_slice().as_ptr(),
                    Some(submit_callback),
                    (&mut submissions as *mut usize).cast(),
                )
            },
            WALLET_OK
        );
        assert_eq!(submissions, 1);

        let mut substituted = encoded;
        let last = substituted.len() - 1;
        substituted[last] ^= 1;
        assert_eq!(
            unsafe {
                activechain_wallet_submit_authorized(
                    substituted.as_ptr(),
                    substituted.len() as u32,
                    public_key.as_slice().as_ptr(),
                    Some(submit_callback),
                    (&mut submissions as *mut usize).cast(),
                )
            },
            WALLET_INVALID_SIGNATURE
        );
        assert_eq!(submissions, 1);
    }
}
