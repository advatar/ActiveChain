#![allow(unsafe_code)]

use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_cash_kernel::{CoinCellSet, CoinTransfer, FungibleCoinCellSet};
use activechain_crypto_provider::verify_did_signature;
use activechain_proposal_gateway::{ActionIntentV1, ActionKindV1, AuthorizedActionIntentV1};
use activechain_protocol_types::{
    AuthenticatorId, CapabilityId, ChainId, CoinCellId, CryptoSuiteId, DidControllerOperationV1,
    DidOperationAuthorizationV1, Digest384, PrincipalId, ProtocolSignature, TransactionId,
};
use activechain_wallet_core::{
    AgentConnectionKind, AgentLifecycle, AgentRegistryCommandV1, AgentRegistryV1,
    AuthorizedCashTransferV1, CashAuthorizationRequestV1, ManagedAgentV1, OpenWalletConsentV1,
    OpenWalletCredentialOfferV1, OpenWalletPresentationRequestV1,
};

#[cfg(target_os = "android")]
mod android;
use core::ffi::c_void;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa44, Signature, Signer, SigningKey,
    Verifier, VerifyingKey,
};

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
pub const ACTIVECHAIN_WALLET_INVALID_PROOF: u32 = 9;
pub const ACTIVECHAIN_WALLET_APPROVAL_MISMATCH: u32 = 10;
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
const WALLET_INVALID_PROOF: u32 = ACTIVECHAIN_WALLET_INVALID_PROOF;
const WALLET_APPROVAL_MISMATCH: u32 = ACTIVECHAIN_WALLET_APPROVAL_MISMATCH;
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

/// Fixed-layout human-review fields decoded from one canonical cash authorization request.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivechainWalletCashApproval {
    pub chain_id: [u8; 48],
    pub signer: [u8; 48],
    pub recipient: [u8; 48],
    pub fee_reserve: [u8; 48],
    pub session_id: [u8; 48],
    pub intent_id: [u8; 48],
    pub nonce: u64,
    pub session_expires_at: u64,
    pub amount_high: u64,
    pub amount_low: u64,
    pub fee_high: u64,
    pub fee_low: u64,
    pub valid_until: u64,
    pub input_count: u32,
}

/// Fixed-layout review fields decoded from one canonical MCP action intent.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivechainWalletProposalApproval {
    pub request_id: [u8; 128],
    pub request_id_len: u32,
    pub chain_id: [u8; 128],
    pub chain_id_len: u32,
    pub wallet_id: [u8; 128],
    pub wallet_id_len: u32,
    pub request_nonce: [u8; 128],
    pub request_nonce_len: u32,
    pub agent_principal: [u8; 48],
    pub capability_id: [u8; 48],
    pub resource: [u8; 48],
    pub recipient: [u8; 48],
    pub replay_domain: [u8; 48],
    pub intent_commitment: [u8; 48],
    pub proposal_id: [u8; 48],
    pub action: u32,
    pub amount_high: u64,
    pub amount_low: u64,
    pub maximum_fee_high: u64,
    pub maximum_fee_low: u64,
    pub expires_at_height: u64,
}

impl Default for ActivechainWalletProposalApproval {
    fn default() -> Self {
        Self {
            request_id: [0; 128],
            request_id_len: 0,
            chain_id: [0; 128],
            chain_id_len: 0,
            wallet_id: [0; 128],
            wallet_id_len: 0,
            request_nonce: [0; 128],
            request_nonce_len: 0,
            agent_principal: [0; 48],
            capability_id: [0; 48],
            resource: [0; 48],
            recipient: [0; 48],
            replay_domain: [0; 48],
            intent_commitment: [0; 48],
            proposal_id: [0; 48],
            action: 0,
            amount_high: 0,
            amount_low: 0,
            maximum_fee_high: 0,
            maximum_fee_low: 0,
            expires_at_height: 0,
        }
    }
}

impl Default for ActivechainWalletCashApproval {
    fn default() -> Self {
        Self {
            chain_id: [0; 48],
            signer: [0; 48],
            recipient: [0; 48],
            fee_reserve: [0; 48],
            session_id: [0; 48],
            intent_id: [0; 48],
            nonce: 0,
            session_expires_at: 0,
            amount_high: 0,
            amount_low: 0,
            fee_high: 0,
            fee_low: 0,
            valid_until: 0,
            input_count: 0,
        }
    }
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
    4
}

/// Returns the proof verifier ABI revision consumed by native wallet shells.
#[unsafe(no_mangle)]
pub extern "C" fn activechain_wallet_verifier_abi_revision() -> u32 {
    activechain_verifier_api::VERIFIER_ABI_REVISION
}

/// Returns the canonical proof-envelope schema revision consumed by native wallet shells.
#[unsafe(no_mangle)]
pub extern "C" fn activechain_wallet_verifier_schema_revision() -> u32 {
    activechain_verifier_api::VERIFIER_SCHEMA_REVISION
}

/// Returns the protocol revision accepted by the proof verifier.
#[unsafe(no_mangle)]
pub extern "C" fn activechain_wallet_verifier_protocol_revision() -> u64 {
    activechain_verifier_api::VERIFIER_PROTOCOL_REVISION
}

/// Derives the canonical ML-DSA-44 public key for one transient 32-byte seed.
///
/// # Safety
///
/// `seed` must point to 32 readable bytes and `public_key_out` to 1,312 writable bytes. Neither
/// pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_mldsa44_public_key(
    seed: *const u8,
    seed_len: u32,
    public_key_out: *mut u8,
    public_key_len: u32,
) -> u32 {
    if seed.is_null() || public_key_out.is_null() {
        return WALLET_NULL_POINTER;
    }
    if seed_len != 32 || public_key_len != ML_DSA44_PUBLIC_KEY_LENGTH as u32 {
        return WALLET_MALFORMED;
    }
    let mut seed_bytes = [0_u8; 32];
    seed_bytes.copy_from_slice(unsafe { core::slice::from_raw_parts(seed, seed_len as usize) });
    let key = SigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from(seed_bytes));
    seed_bytes.fill(0);
    let public_key = key.verifying_key().encode();
    unsafe {
        core::ptr::copy_nonoverlapping(
            public_key.as_slice().as_ptr(),
            public_key_out,
            public_key.len(),
        );
    }
    WALLET_OK
}

/// Derives the canonical wallet principal for one ML-DSA-44 public key.
///
/// Clients cannot restate this themselves without duplicating a SHAKE256-384
/// derivation that decides who owns a Coin Cell, so the identity is computed
/// here and shared with the CLI through `wallet-core`.
///
/// # Safety
///
/// `public_key` must point to 1,312 readable bytes and `principal_out` to 48 writable bytes.
/// Neither pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_principal_id(
    public_key: *const u8,
    public_key_len: u32,
    principal_out: *mut u8,
    principal_len: u32,
) -> u32 {
    if public_key.is_null() || principal_out.is_null() {
        return WALLET_NULL_POINTER;
    }
    if public_key_len != ML_DSA44_PUBLIC_KEY_LENGTH as u32 || principal_len != 48 {
        return WALLET_MALFORMED;
    }
    let key = unsafe { core::slice::from_raw_parts(public_key, public_key_len as usize) };
    let principal = activechain_wallet_core::wallet_principal_id(key);
    unsafe {
        core::ptr::copy_nonoverlapping(
            principal.into_digest().as_bytes().as_ptr(),
            principal_out,
            48,
        );
    }
    WALLET_OK
}

/// Signs one bounded payload with a transient ML-DSA-44 seed and verifies the signature before
/// publishing it to the caller.
///
/// # Safety
///
/// `seed` must point to 32 readable bytes. A non-empty `payload` must be readable for
/// `payload_len` bytes, and `signature_out` must point to 2,420 writable bytes. No pointer is
/// retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_mldsa44_sign(
    seed: *const u8,
    seed_len: u32,
    payload: *const u8,
    payload_len: u32,
    signature_out: *mut u8,
    signature_len: u32,
) -> u32 {
    if seed.is_null() || (payload.is_null() && payload_len != 0) || signature_out.is_null() {
        return WALLET_NULL_POINTER;
    }
    if payload_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    if seed_len != 32 || signature_len != ML_DSA44_SIGNATURE_LENGTH as u32 {
        return WALLET_MALFORMED;
    }
    let mut seed_bytes = [0_u8; 32];
    seed_bytes.copy_from_slice(unsafe { core::slice::from_raw_parts(seed, seed_len as usize) });
    let key = SigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from(seed_bytes));
    seed_bytes.fill(0);
    let payload = if payload_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(payload, payload_len as usize) }
    };
    let signature = key.sign(payload);
    if key.verifying_key().verify(payload, &signature).is_err() {
        return WALLET_INVALID_SIGNATURE;
    }
    let encoded = signature.encode();
    unsafe {
        core::ptr::copy_nonoverlapping(encoded.as_slice().as_ptr(), signature_out, encoded.len());
    }
    WALLET_OK
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

/// Creates a non-authorizing agent record that can become active only after exact finality.
///
/// # Safety
///
/// Inputs follow `activechain_wallet_agent_register`; `transaction` points to 48 readable bytes.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_agent_register_pending(
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
    transaction: *const u8,
    output: *mut u8,
    output_capacity: u32,
    required_len: *mut u32,
) -> u32 {
    if principal.is_null()
        || label.is_null()
        || label_len == 0
        || capabilities.is_null()
        || capability_count == 0
        || transaction.is_null()
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
    let agent = match ManagedAgentV1::pending(
        PrincipalId::new(unsafe { read_digest(principal) }),
        label,
        connection,
        capability_ids,
        join_u128(budget_limit_high, budget_limit_low),
        expires_at,
        TransactionId::new(unsafe { read_digest(transaction) }),
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

/// Activates the exact pending enrollment after its transaction is finalized.
///
/// # Safety
///
/// Principal and transaction point to 48 readable bytes; registry/output follow
/// `activechain_wallet_agent_apply`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_agent_finalize_enrollment(
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
    if finalized_height == 0 {
        return WALLET_MALFORMED;
    }
    unsafe {
        apply_agent_command(
            registry,
            registry_len,
            AgentRegistryCommandV1::FinalizeEnrollment {
                principal: PrincipalId::new(read_digest(principal)),
                transaction: TransactionId::new(read_digest(transaction)),
                finalized_height,
            },
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
        AgentLifecycle::EnrollmentPending { .. } => (4, 0),
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

/// Verifies a proof-bearing owner-scoped Coin Cell against a trusted chain genesis.
///
/// # Safety
/// Fixed identifiers must point to readable 48-byte values. Canonical value, proof, and finality
/// buffers must be readable for their declared lengths. No pointer is retained.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_verify_owner_coin_cell_record(
    key: *const u8,
    finalized_height: u64,
    value: *const u8,
    value_len: u32,
    proof: *const u8,
    proof_len: u32,
    finality: *const u8,
    finality_len: u32,
    owner: *const u8,
    trusted_genesis: *const u8,
) -> u32 {
    if key.is_null()
        || owner.is_null()
        || trusted_genesis.is_null()
        || (value.is_null() && value_len != 0)
        || (proof.is_null() && proof_len != 0)
        || (finality.is_null() && finality_len != 0)
    {
        return WALLET_NULL_POINTER;
    }
    if value_len
        .checked_add(proof_len)
        .and_then(|length| length.checked_add(finality_len))
        .is_none_or(|length| length > MAX_WALLET_INPUT)
    {
        return WALLET_TOO_LARGE;
    }
    let read_buffer = |pointer: *const u8, length: u32| {
        if length == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(pointer, length as usize) }
        }
    };
    let code = activechain_verifier_api::verify_owner_coin_cell_record_code(
        unsafe { read_digest(key) },
        finalized_height,
        read_buffer(value, value_len),
        read_buffer(proof, proof_len),
        read_buffer(finality, finality_len),
        PrincipalId::new(unsafe { read_digest(owner) }),
        unsafe { read_digest(trusted_genesis) },
    );
    if code == activechain_verifier_api::VERIFY_OK { WALLET_OK } else { WALLET_INVALID_PROOF }
}

/// Verifies a proof-bearing NFT series or minted-token registry against trusted finality.
///
/// # Safety
/// Fixed identifiers must point to readable 48-byte values. Canonical value, proof, and finality
/// buffers must be readable for their declared lengths. No pointer is retained.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_verify_nft_state_record(
    query_kind: u32,
    key: *const u8,
    finalized_height: u64,
    value: *const u8,
    value_len: u32,
    proof: *const u8,
    proof_len: u32,
    finality: *const u8,
    finality_len: u32,
    trusted_genesis: *const u8,
) -> u32 {
    if key.is_null()
        || trusted_genesis.is_null()
        || (value.is_null() && value_len != 0)
        || (proof.is_null() && proof_len != 0)
        || (finality.is_null() && finality_len != 0)
    {
        return WALLET_NULL_POINTER;
    }
    if value_len
        .checked_add(proof_len)
        .and_then(|length| length.checked_add(finality_len))
        .is_none_or(|length| length > MAX_WALLET_INPUT)
    {
        return WALLET_TOO_LARGE;
    }
    let Ok(query_kind) = u8::try_from(query_kind) else {
        return WALLET_INVALID_PROOF;
    };
    let read_buffer = |pointer: *const u8, length: u32| {
        if length == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(pointer, length as usize) }
        }
    };
    let code = activechain_verifier_api::verify_nft_state_record_code(
        query_kind,
        unsafe { read_digest(key) },
        finalized_height,
        read_buffer(value, value_len),
        read_buffer(proof, proof_len),
        read_buffer(finality, finality_len),
        unsafe { read_digest(trusted_genesis) },
    );
    if code == activechain_verifier_api::VERIFY_OK { WALLET_OK } else { WALLET_INVALID_PROOF }
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

/// Selects payment and fee-reserve cells from an explicit fungible asset set.
///
/// # Safety
/// All pointers must reference buffers valid for their declared lengths; output buffers must be
/// writable for 48 bytes. No pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_select_fungible_cells(
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
    let bytes = if cells_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(cells, cells_len as usize) }
    };
    let Ok(cells) = decode_envelope::<FungibleCoinCellSet>(bytes) else {
        return WALLET_MALFORMED;
    };
    let owner = PrincipalId::new(Digest384::new(
        unsafe { core::slice::from_raw_parts(owner, 48) }.try_into().unwrap(),
    ));
    let amount = (u128::from(amount_high) << 64) | u128::from(amount_low);
    let fee = (u128::from(fee_high) << 64) | u128::from(fee_low);
    let Ok((payment, reserve)) =
        activechain_wallet_core::select_fungible_cells(&cells, owner, amount, fee)
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

/// Builds a cash authorization whose signature binds an exact faucet settlement reference.
///
/// # Safety
///
/// All identifier inputs, including `settlement_reference`, must point to readable 48-byte
/// buffers. Output pointer requirements match [`activechain_wallet_build_cash_intent`].
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_build_faucet_cash_intent(
    chain_id: *const u8,
    signer: *const u8,
    recipient: *const u8,
    input: *const u8,
    fee_reserve: *const u8,
    nonce: u64,
    session_id: *const u8,
    session_expires_at: u64,
    settlement_reference: *const u8,
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
        || settlement_reference.is_null()
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
    let request = match CashAuthorizationRequestV1::new_with_settlement_reference(
        ChainId::new(unsafe { read_digest(chain_id) }),
        signer,
        nonce,
        unsafe { read_digest(session_id) },
        session_expires_at,
        Some(unsafe { read_digest(settlement_reference) }),
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

/// Decodes the exact canonical cash request into fixed human-review fields.
///
/// # Safety
/// `request` must be readable for `request_len` bytes and `approval_out` must be writable. No
/// pointer is retained and the output is published only after strict canonical decoding succeeds.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_cash_approval(
    request: *const u8,
    request_len: u32,
    approval_out: *mut ActivechainWalletCashApproval,
) -> u32 {
    if (request.is_null() && request_len != 0) || approval_out.is_null() {
        return WALLET_NULL_POINTER;
    }
    if request_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let bytes = if request_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(request, request_len as usize) }
    };
    let request = match decode_envelope::<CashAuthorizationRequestV1>(bytes) {
        Ok(request) => request,
        Err(_) => return WALLET_MALFORMED,
    };
    let intent_id = match request.intent_id() {
        Ok(intent) => intent.into_bytes(),
        Err(_) => return WALLET_MALFORMED,
    };
    let transfer = request.transfer();
    let (amount_high, amount_low) = split_u128(transfer.amount());
    let (fee_high, fee_low) = split_u128(transfer.fee());
    let Ok(input_count) = u32::try_from(transfer.inputs().len()) else {
        return WALLET_TOO_LARGE;
    };
    let approval = ActivechainWalletCashApproval {
        chain_id: request.chain_id().into_digest().into_bytes(),
        signer: request.signer().into_digest().into_bytes(),
        recipient: transfer.recipient().into_digest().into_bytes(),
        fee_reserve: transfer.fee_reserve().into_digest().into_bytes(),
        session_id: request.session_id().into_bytes(),
        intent_id,
        nonce: request.nonce(),
        session_expires_at: request.session_expires_at(),
        amount_high,
        amount_low,
        fee_high,
        fee_low,
        valid_until: transfer.valid_until(),
        input_count,
    };
    unsafe {
        *approval_out = approval;
    }
    WALLET_OK
}

fn copy_identifier<const N: usize>(source: &[u8]) -> Result<([u8; N], u32), u32> {
    let length = u32::try_from(source.len()).map_err(|_| WALLET_TOO_LARGE)?;
    let mut output = [0; N];
    let Some(target) = output.get_mut(..source.len()) else { return Err(WALLET_TOO_LARGE) };
    target.copy_from_slice(source);
    Ok((output, length))
}

/// Strictly decodes one canonical MCP action intent into fields suitable for native review.
///
/// The current finalized height is checked here so a stale intent can never reach a platform
/// authentication prompt. Display fields are reconstructed exclusively from canonical bytes.
///
/// # Safety
/// `intent` must be readable for `intent_len`; `approval_out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_proposal_approval(
    intent: *const u8,
    intent_len: u32,
    current_finalized_height: u64,
    approval_out: *mut ActivechainWalletProposalApproval,
) -> u32 {
    if (intent.is_null() && intent_len != 0) || approval_out.is_null() {
        return WALLET_NULL_POINTER;
    }
    if intent_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let bytes = if intent_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(intent, intent_len as usize) }
    };
    let intent = match decode_envelope::<ActionIntentV1>(bytes) {
        Ok(value) => value,
        Err(_) => return WALLET_MALFORMED,
    };
    if current_finalized_height >= intent.expires_at_height {
        return WALLET_AGENT_REJECTED;
    }
    let commitment = match intent.commitment() {
        Ok(value) => value,
        Err(_) => return WALLET_MALFORMED,
    };
    let proposal_id = match intent.proposal_id() {
        Ok(value) => value,
        Err(_) => return WALLET_MALFORMED,
    };
    let (request_id, request_id_len) = match copy_identifier(&intent.request_id) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let (chain_id, chain_id_len) = match copy_identifier(&intent.chain_id) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let (wallet_id, wallet_id_len) = match copy_identifier(&intent.wallet_id) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let (request_nonce, request_nonce_len) = match copy_identifier(&intent.request_nonce) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let (amount_high, amount_low) = split_u128(intent.amount);
    let (maximum_fee_high, maximum_fee_low) = split_u128(intent.maximum_fee);
    let approval = ActivechainWalletProposalApproval {
        request_id,
        request_id_len,
        chain_id,
        chain_id_len,
        wallet_id,
        wallet_id_len,
        request_nonce,
        request_nonce_len,
        agent_principal: intent.agent_principal.into_bytes(),
        capability_id: intent.capability_id.into_bytes(),
        resource: intent.resource.into_bytes(),
        recipient: intent.recipient.into_bytes(),
        replay_domain: intent.replay_domain.into_bytes(),
        intent_commitment: commitment.into_bytes(),
        proposal_id: proposal_id.into_bytes(),
        action: match intent.action {
            ActionKindV1::Transfer => 0,
            ActionKindV1::SubmitAnchor => 1,
        },
        amount_high,
        amount_low,
        maximum_fee_high,
        maximum_fee_low,
        expires_at_height: intent.expires_at_height,
    };
    unsafe {
        *approval_out = approval;
    }
    WALLET_OK
}

fn verify_proposal_signature(public_key: &[u8], signature: &[u8], payload: &[u8]) -> bool {
    let Ok(key): Result<EncodedVerifyingKey<MlDsa44>, _> = public_key.try_into() else {
        return false;
    };
    let Ok(signature): Result<EncodedSignature<MlDsa44>, _> = signature.try_into() else {
        return false;
    };
    let key = VerifyingKey::<MlDsa44>::decode(&key);
    let Some(signature) = Signature::<MlDsa44>::decode(&signature) else { return false };
    key.verify(payload, &signature).is_ok()
}

/// Produces one network-bound DID authorization through caller-owned opaque custody and
/// re-verifies the returned signature before releasing the canonical envelope.
pub fn authorize_did_operation<F>(
    operation: &DidControllerOperationV1,
    chain_genesis: Digest384,
    approved_commitment: Digest384,
    authorizer: AuthenticatorId,
    suite: CryptoSuiteId,
    public_key: &[u8],
    sign: F,
) -> Result<Vec<u8>, u32>
where
    F: FnOnce(&[u8]) -> Vec<u8>,
{
    if operation.commitment().map_err(|_| WALLET_MALFORMED)? != approved_commitment {
        return Err(WALLET_APPROVAL_MISMATCH);
    }
    let signature_len = suite.signature_length().ok_or(WALLET_INVALID_SIGNATURE)?;
    let unsigned = DidOperationAuthorizationV1::new(
        chain_genesis,
        operation,
        authorizer,
        ProtocolSignature::new(suite, vec![0; signature_len])
            .map_err(|_| WALLET_INVALID_SIGNATURE)?,
    )
    .map_err(|_| WALLET_MALFORMED)?;
    let payload = unsigned.signing_payload();
    let signature = sign(&payload);
    verify_did_signature(suite, public_key, &payload, &signature)
        .map_err(|_| WALLET_INVALID_SIGNATURE)?;
    let authorization = DidOperationAuthorizationV1::new(
        chain_genesis,
        operation,
        authorizer,
        ProtocolSignature::new(suite, signature).map_err(|_| WALLET_INVALID_SIGNATURE)?,
    )
    .map_err(|_| WALLET_MALFORMED)?;
    encode_envelope(&authorization).map_err(|_| WALLET_MALFORMED)
}

fn did_signature_suite(value: u32) -> Option<CryptoSuiteId> {
    match value {
        0 => Some(CryptoSuiteId::ML_DSA_65),
        1 => Some(CryptoSuiteId::ML_DSA_87),
        2 => Some(CryptoSuiteId::SLH_DSA_SHAKE_192S),
        _ => None,
    }
}

/// Signs one reviewed DID lifecycle operation using a native custody callback.
///
/// # Safety
/// Every non-empty input must be readable for its declared/fixed length. Output pointers must be
/// writable. The callback receives only the exact network-bound signing payload and writes the
/// suite-exact signature; no secret key crosses this boundary.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_authorize_did_operation(
    operation: *const u8,
    operation_len: u32,
    chain_genesis: *const u8,
    approved_commitment: *const u8,
    authorizer: *const u8,
    suite: u32,
    public_key: *const u8,
    public_key_len: u32,
    callback: Option<ActivechainWalletSignCallback>,
    callback_context: *mut c_void,
    output: *mut u8,
    output_capacity: u32,
    required_len: *mut u32,
) -> u32 {
    if operation.is_null()
        || operation_len == 0
        || operation_len > MAX_WALLET_INPUT
        || chain_genesis.is_null()
        || approved_commitment.is_null()
        || authorizer.is_null()
        || public_key.is_null()
        || public_key_len == 0
        || callback.is_none()
        || required_len.is_null()
        || (output.is_null() && output_capacity != 0)
    {
        return if operation_len > MAX_WALLET_INPUT {
            WALLET_TOO_LARGE
        } else {
            WALLET_NULL_POINTER
        };
    }
    let Some(suite) = did_signature_suite(suite) else { return WALLET_INVALID_SIGNATURE };
    let Some(expected_key_len) = suite.verification_key_length() else {
        return WALLET_INVALID_SIGNATURE;
    };
    if public_key_len as usize != expected_key_len {
        return WALLET_INVALID_SIGNATURE;
    }
    let operation_bytes = unsafe { core::slice::from_raw_parts(operation, operation_len as usize) };
    let Ok(operation) = decode_envelope::<DidControllerOperationV1>(operation_bytes) else {
        return WALLET_MALFORMED;
    };
    let chain_genesis = Digest384::new(
        unsafe { core::slice::from_raw_parts(chain_genesis, 48) }.try_into().unwrap(),
    );
    let approved_commitment = Digest384::new(
        unsafe { core::slice::from_raw_parts(approved_commitment, 48) }.try_into().unwrap(),
    );
    let authorizer = AuthenticatorId::new(Digest384::new(
        unsafe { core::slice::from_raw_parts(authorizer, 48) }.try_into().unwrap(),
    ));
    let public_key = unsafe { core::slice::from_raw_parts(public_key, public_key_len as usize) };
    let signature_len = suite.signature_length().unwrap();
    let mut callback_failed = false;
    let result = authorize_did_operation(
        &operation,
        chain_genesis,
        approved_commitment,
        authorizer,
        suite,
        public_key,
        |payload| {
            let mut signature = vec![0; signature_len];
            let status = unsafe {
                callback.unwrap()(
                    callback_context,
                    payload.as_ptr(),
                    payload.len() as u32,
                    signature.as_mut_ptr(),
                    signature_len as u32,
                )
            };
            if status == 0 {
                signature
            } else {
                callback_failed = true;
                Vec::new()
            }
        },
    );
    if callback_failed {
        return WALLET_CALLBACK_FAILED;
    }
    let encoded = match result {
        Ok(value) => value,
        Err(error) => return error,
    };
    let Ok(required) = u32::try_from(encoded.len()) else { return WALLET_TOO_LARGE };
    unsafe { *required_len = required };
    if output_capacity < required {
        return WALLET_BUFFER_TOO_SMALL;
    }
    unsafe { core::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len()) };
    WALLET_OK
}

/// Safe Rust entry point for authorizing an already reviewed MCP proposal.
///
/// The caller retains custody of the signing key through `sign`; this function enforces the same
/// expiry, commitment-matching, signature-verification, and canonical-envelope rules as the C ABI.
pub fn authorize_proposal_intent<F>(
    intent: &ActionIntentV1,
    current_finalized_height: u64,
    approved_commitment: Digest384,
    public_key: Vec<u8>,
    sign: F,
) -> Result<Vec<u8>, u32>
where
    F: FnOnce(&[u8]) -> Vec<u8>,
{
    if current_finalized_height >= intent.expires_at_height {
        return Err(WALLET_AGENT_REJECTED);
    }
    if intent.commitment().map_err(|_| WALLET_MALFORMED)? != approved_commitment {
        return Err(WALLET_APPROVAL_MISMATCH);
    }
    if public_key.len() != ML_DSA44_PUBLIC_KEY_LENGTH {
        return Err(WALLET_INVALID_SIGNATURE);
    }
    let payload = intent.signing_payload().map_err(|_| WALLET_MALFORMED)?;
    let signature = sign(&payload);
    if !verify_proposal_signature(&public_key, &signature, &payload) {
        return Err(WALLET_INVALID_SIGNATURE);
    }
    let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature)
        .map_err(|_| WALLET_INVALID_SIGNATURE)?;
    let authorized = AuthorizedActionIntentV1::new(intent.clone(), public_key, signature)
        .map_err(|_| WALLET_MALFORMED)?;
    encode_envelope(&authorized).map_err(|_| WALLET_MALFORMED)
}

/// Safe Rust entry point for verifying and forwarding an authorized MCP proposal.
pub fn submit_authorized_proposal<F>(
    envelope: &[u8],
    current_finalized_height: u64,
    submit: F,
) -> Result<(), u32>
where
    F: FnOnce(&[u8]) -> bool,
{
    if envelope.len() > MAX_WALLET_INPUT as usize {
        return Err(WALLET_TOO_LARGE);
    }
    let authorized =
        decode_envelope::<AuthorizedActionIntentV1>(envelope).map_err(|_| WALLET_MALFORMED)?;
    if current_finalized_height >= authorized.intent.expires_at_height {
        return Err(WALLET_AGENT_REJECTED);
    }
    let payload = authorized.intent.signing_payload().map_err(|_| WALLET_MALFORMED)?;
    if !verify_proposal_signature(&authorized.public_key, authorized.signature.as_bytes(), &payload)
    {
        return Err(WALLET_INVALID_SIGNATURE);
    }
    if !submit(envelope) {
        return Err(WALLET_CALLBACK_FAILED);
    }
    Ok(())
}

/// Signs exactly one reviewed canonical MCP action intent through caller-owned native custody.
///
/// # Safety
/// Input pointers must be readable for their declared/fixed lengths; outputs must be writable.
/// The callback is invoked only after strict decoding, expiry validation, and commitment matching.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_sign_proposal_intent(
    intent: *const u8,
    intent_len: u32,
    current_finalized_height: u64,
    approved_commitment: *const u8,
    public_key: *const u8,
    callback: Option<ActivechainWalletSignCallback>,
    callback_context: *mut c_void,
    output: *mut u8,
    output_capacity: u32,
    required_len: *mut u32,
) -> u32 {
    if (intent.is_null() && intent_len != 0)
        || approved_commitment.is_null()
        || public_key.is_null()
        || callback.is_none()
        || required_len.is_null()
        || (output.is_null() && output_capacity != 0)
    {
        return WALLET_NULL_POINTER;
    }
    if intent_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let bytes = if intent_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(intent, intent_len as usize) }
    };
    let intent = match decode_envelope::<ActionIntentV1>(bytes) {
        Ok(value) => value,
        Err(_) => return WALLET_MALFORMED,
    };
    if current_finalized_height >= intent.expires_at_height {
        return WALLET_AGENT_REJECTED;
    }
    let commitment = match intent.commitment() {
        Ok(value) => value,
        Err(_) => return WALLET_MALFORMED,
    };
    if commitment.as_bytes() != unsafe { core::slice::from_raw_parts(approved_commitment, 48) } {
        return WALLET_APPROVAL_MISMATCH;
    }
    let placeholder_signature =
        ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; ML_DSA44_SIGNATURE_LENGTH])
            .expect("fixed signature length");
    let placeholder = AuthorizedActionIntentV1::new(
        intent.clone(),
        vec![0; ML_DSA44_PUBLIC_KEY_LENGTH],
        placeholder_signature,
    )
    .expect("fixed key and suite");
    let required = match encode_envelope(&placeholder) {
        Ok(value) => value.len(),
        Err(_) => return WALLET_MALFORMED,
    };
    let Ok(required_u32) = u32::try_from(required) else { return WALLET_TOO_LARGE };
    unsafe {
        *required_len = required_u32;
    }
    if output_capacity < required_u32 {
        return WALLET_BUFFER_TOO_SMALL;
    }
    let payload = match intent.signing_payload() {
        Ok(value) => value,
        Err(_) => return WALLET_MALFORMED,
    };
    let mut signature = [0; ML_DSA44_SIGNATURE_LENGTH];
    let code = unsafe {
        callback.expect("checked")(
            callback_context,
            payload.as_ptr(),
            payload.len() as u32,
            signature.as_mut_ptr(),
            ML_DSA44_SIGNATURE_LENGTH as u32,
        )
    };
    if code != 0 {
        return WALLET_CALLBACK_FAILED;
    }
    let public_key = unsafe { core::slice::from_raw_parts(public_key, ML_DSA44_PUBLIC_KEY_LENGTH) };
    if !verify_proposal_signature(public_key, &signature, &payload) {
        return WALLET_INVALID_SIGNATURE;
    }
    let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.to_vec())
        .expect("fixed signature length");
    let authorized = match AuthorizedActionIntentV1::new(intent, public_key.to_vec(), signature) {
        Ok(value) => value,
        Err(_) => return WALLET_MALFORMED,
    };
    let encoded = match encode_envelope(&authorized) {
        Ok(value) => value,
        Err(_) => return WALLET_MALFORMED,
    };
    debug_assert_eq!(encoded.len(), required);
    unsafe {
        core::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len());
    }
    WALLET_OK
}

/// Verifies and forwards one unexpired, exactly authorized MCP action envelope.
///
/// # Safety
/// `envelope` must be readable for `envelope_len`; the callback must obey its contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn activechain_wallet_submit_authorized_proposal(
    envelope: *const u8,
    envelope_len: u32,
    current_finalized_height: u64,
    callback: Option<ActivechainWalletSubmitCallback>,
    callback_context: *mut c_void,
) -> u32 {
    if (envelope.is_null() && envelope_len != 0) || callback.is_none() {
        return WALLET_NULL_POINTER;
    }
    if envelope_len > MAX_WALLET_INPUT {
        return WALLET_TOO_LARGE;
    }
    let bytes = if envelope_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(envelope, envelope_len as usize) }
    };
    let authorized = match decode_envelope::<AuthorizedActionIntentV1>(bytes) {
        Ok(value) => value,
        Err(_) => return WALLET_MALFORMED,
    };
    if current_finalized_height >= authorized.intent.expires_at_height {
        return WALLET_AGENT_REJECTED;
    }
    let payload = match authorized.intent.signing_payload() {
        Ok(value) => value,
        Err(_) => return WALLET_MALFORMED,
    };
    if !verify_proposal_signature(&authorized.public_key, authorized.signature.as_bytes(), &payload)
    {
        return WALLET_INVALID_SIGNATURE;
    }
    let code = unsafe { callback.expect("checked")(callback_context, envelope, envelope_len) };
    if code != 0 {
        return WALLET_CALLBACK_FAILED;
    }
    WALLET_OK
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
/// Builds a canonical asset-bound transfer envelope with size-query support.
///
/// # Safety
/// All input pointers must reference readable buffers and `required_len` must be writable;
/// `output` must be writable for `output_capacity` bytes.
pub unsafe extern "C" fn activechain_wallet_build_fungible_transfer(
    cells: *const u8,
    cells_len: u32,
    asset: *const u8,
    sender: *const u8,
    recipient: *const u8,
    input_ids: *const u8,
    input_count: u16,
    amount_high: u64,
    amount_low: u64,
    output: *mut u8,
    output_capacity: u32,
    required_len: *mut u32,
) -> u32 {
    if (cells.is_null() && cells_len != 0)
        || asset.is_null()
        || sender.is_null()
        || recipient.is_null()
        || (input_ids.is_null() && input_count != 0)
        || required_len.is_null()
        || (output.is_null() && output_capacity != 0)
    {
        return WALLET_NULL_POINTER;
    }
    if cells_len > MAX_WALLET_INPUT || input_count == 0 {
        return WALLET_MALFORMED;
    }
    let bytes = if cells_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(cells, cells_len as usize) }
    };
    let Ok(cells) = decode_envelope::<FungibleCoinCellSet>(bytes) else {
        return WALLET_MALFORMED;
    };
    let ids = unsafe { core::slice::from_raw_parts(input_ids, input_count as usize * 48) };
    let mut input_ids_vec = Vec::with_capacity(input_count as usize);
    for chunk in ids.chunks_exact(48) {
        input_ids_vec.push(CoinCellId::new(Digest384::new(chunk.try_into().unwrap())));
    }
    let Ok(transfer) = activechain_wallet_core::build_fungible_transfer(
        &cells,
        activechain_protocol_types::AssetId::new(unsafe { read_digest(asset) }),
        PrincipalId::new(unsafe { read_digest(sender) }),
        PrincipalId::new(unsafe { read_digest(recipient) }),
        &input_ids_vec,
        join_u128(amount_high, amount_low),
    ) else {
        return WALLET_MALFORMED;
    };
    let Ok(encoded) = encode_envelope(&transfer) else {
        return WALLET_MALFORMED;
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
    WALLET_OK
}

/// Invokes a secure-key callback for one exact canonical request and verifies its result.
///
/// # Safety
///
/// `request`, the 48-byte `approved_intent`, and `public_key` must be readable for their declared
/// or fixed lengths. The approved intent must be the commitment returned with the human-reviewed
/// summary. `callback` must obey its declared contract for the duration of the call. `output` may
/// be null only for a zero-capacity size query; `required_len` must be writable. The callback is
/// never retained.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn activechain_wallet_sign_cash_intent(
    request: *const u8,
    request_len: u32,
    approved_intent: *const u8,
    public_key: *const u8,
    callback: Option<ActivechainWalletSignCallback>,
    callback_context: *mut c_void,
    output: *mut u8,
    output_capacity: u32,
    required_len: *mut u32,
) -> u32 {
    if (request.is_null() && request_len != 0)
        || approved_intent.is_null()
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
    let intent = match request.intent_id() {
        Ok(intent) => intent,
        Err(_) => return WALLET_MALFORMED,
    };
    let approved_intent = unsafe { core::slice::from_raw_parts(approved_intent, 48) };
    if intent.as_bytes() != approved_intent {
        return WALLET_APPROVAL_MISMATCH;
    }
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
    use activechain_protocol_types::{DidControllerRecordV1, DidOperationKind, TransactionId};
    use ml_dsa::{
        EncodedSignature, Keypair, MlDsa44, MlDsa65, Signature, Signer, SigningKey, Verifier,
    };

    fn approval_vector() -> std::collections::BTreeMap<&'static str, &'static str> {
        include_str!("../../../testing/vectors/wallet-canonical-approval-v1.txt")
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.split_once('=').expect("key=value approval vector"))
            .collect()
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn wallet_abi_exposes_exact_verifier_compatibility_revisions() {
        assert_eq!(
            activechain_wallet_verifier_abi_revision(),
            activechain_verifier_api::VERIFIER_ABI_REVISION
        );
        assert_eq!(
            activechain_wallet_verifier_schema_revision(),
            activechain_verifier_api::VERIFIER_SCHEMA_REVISION
        );
        assert_eq!(
            activechain_wallet_verifier_protocol_revision(),
            activechain_verifier_api::VERIFIER_PROTOCOL_REVISION
        );
    }

    unsafe extern "C" fn did_sign_callback(
        context: *mut c_void,
        payload: *const u8,
        payload_len: u32,
        signature_out: *mut u8,
        signature_len: u32,
    ) -> u32 {
        if context.is_null()
            || payload.is_null()
            || signature_out.is_null()
            || signature_len != 3_309
        {
            return 1;
        }
        let key = unsafe { &*context.cast::<SigningKey<MlDsa65>>() };
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
    fn revision_is_stable() {
        assert_eq!(activechain_wallet_ffi_revision(), 4);
    }

    #[test]
    fn native_callback_signs_only_the_approved_network_bound_did_operation() {
        let principal = PrincipalId::new(digest(1));
        let next = DidControllerRecordV1::new(
            principal,
            digest(2),
            digest(3),
            digest(4),
            Some(digest(5)),
            None,
            2,
            true,
        )
        .unwrap();
        let operation = DidControllerOperationV1::new(
            DidOperationKind::Update,
            principal,
            Some(digest(6)),
            next,
            digest(7),
        )
        .unwrap();
        let encoded = encode_envelope(&operation).unwrap();
        let commitment = operation.commitment().unwrap();
        let authorizer = AuthenticatorId::new(digest(8));
        let genesis = digest(9);
        let key = SigningKey::<MlDsa65>::from_seed(&ml_dsa::Seed::from([10; 32]));
        let public_key = key.verifying_key().encode();
        let mut required = 0;
        assert_eq!(
            unsafe {
                activechain_wallet_authorize_did_operation(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    genesis.as_bytes().as_ptr(),
                    commitment.as_bytes().as_ptr(),
                    authorizer.digest().as_bytes().as_ptr(),
                    0,
                    public_key.as_slice().as_ptr(),
                    public_key.len() as u32,
                    Some(did_sign_callback),
                    (&key as *const SigningKey<MlDsa65>).cast_mut().cast(),
                    core::ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            WALLET_BUFFER_TOO_SMALL
        );
        let mut authorization = vec![0; required as usize];
        assert_eq!(
            unsafe {
                activechain_wallet_authorize_did_operation(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    genesis.as_bytes().as_ptr(),
                    commitment.as_bytes().as_ptr(),
                    authorizer.digest().as_bytes().as_ptr(),
                    0,
                    public_key.as_slice().as_ptr(),
                    public_key.len() as u32,
                    Some(did_sign_callback),
                    (&key as *const SigningKey<MlDsa65>).cast_mut().cast(),
                    authorization.as_mut_ptr(),
                    authorization.len() as u32,
                    &mut required,
                )
            },
            WALLET_OK
        );
        let decoded = decode_envelope::<DidOperationAuthorizationV1>(&authorization).unwrap();
        assert!(decoded.binds(genesis, &operation));
        assert!(
            verify_did_signature(
                CryptoSuiteId::ML_DSA_65,
                public_key.as_slice(),
                &decoded.signing_payload(),
                decoded.signature().as_bytes(),
            )
            .is_ok()
        );

        let mut wrong = *commitment.as_bytes();
        wrong[0] ^= 1;
        assert_eq!(
            unsafe {
                activechain_wallet_authorize_did_operation(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    genesis.as_bytes().as_ptr(),
                    wrong.as_ptr(),
                    authorizer.digest().as_bytes().as_ptr(),
                    0,
                    public_key.as_slice().as_ptr(),
                    public_key.len() as u32,
                    Some(did_sign_callback),
                    (&key as *const SigningKey<MlDsa65>).cast_mut().cast(),
                    authorization.as_mut_ptr(),
                    authorization.len() as u32,
                    &mut required,
                )
            },
            WALLET_APPROVAL_MISMATCH
        );
    }

    #[test]
    fn native_mldsa44_engine_derives_and_self_verifies_wire_values() {
        let seed = [73_u8; 32];
        let payload = b"canonical Apple custody signing payload";
        let mut public_key = [0_u8; ML_DSA44_PUBLIC_KEY_LENGTH];
        let mut signature = [0_u8; ML_DSA44_SIGNATURE_LENGTH];
        assert_eq!(
            unsafe {
                activechain_wallet_mldsa44_public_key(
                    seed.as_ptr(),
                    seed.len() as u32,
                    public_key.as_mut_ptr(),
                    public_key.len() as u32,
                )
            },
            WALLET_OK
        );
        assert_eq!(
            unsafe {
                activechain_wallet_mldsa44_sign(
                    seed.as_ptr(),
                    seed.len() as u32,
                    payload.as_ptr(),
                    payload.len() as u32,
                    signature.as_mut_ptr(),
                    signature.len() as u32,
                )
            },
            WALLET_OK
        );
        let expected = SigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from(seed));
        assert_eq!(public_key.as_slice(), expected.verifying_key().encode().as_slice());
        let encoded: EncodedSignature<MlDsa44> = signature.into();
        let signature = Signature::<MlDsa44>::decode(&encoded).unwrap();
        assert!(expected.verifying_key().verify(payload, &signature).is_ok());
    }

    #[test]
    fn native_mldsa44_engine_rejects_invalid_lengths_and_oversized_payloads() {
        let seed = [1_u8; 32];
        let payload = [2_u8; 1];
        let mut public_key = [0_u8; ML_DSA44_PUBLIC_KEY_LENGTH];
        let mut signature = [0_u8; ML_DSA44_SIGNATURE_LENGTH];
        assert_eq!(
            unsafe {
                activechain_wallet_mldsa44_public_key(
                    seed.as_ptr(),
                    31,
                    public_key.as_mut_ptr(),
                    public_key.len() as u32,
                )
            },
            WALLET_MALFORMED
        );
        assert_eq!(
            unsafe {
                activechain_wallet_mldsa44_sign(
                    seed.as_ptr(),
                    seed.len() as u32,
                    payload.as_ptr(),
                    MAX_WALLET_INPUT + 1,
                    signature.as_mut_ptr(),
                    signature.len() as u32,
                )
            },
            WALLET_TOO_LARGE
        );
    }

    #[test]
    fn owner_coin_cell_verifier_abi_rejects_null_and_malformed_evidence() {
        let key = [1_u8; 48];
        let owner = [2_u8; 48];
        let genesis = [3_u8; 48];
        let malformed = [4_u8];
        assert_eq!(
            unsafe {
                activechain_wallet_verify_owner_coin_cell_record(
                    key.as_ptr(),
                    1,
                    malformed.as_ptr(),
                    malformed.len() as u32,
                    malformed.as_ptr(),
                    malformed.len() as u32,
                    malformed.as_ptr(),
                    malformed.len() as u32,
                    owner.as_ptr(),
                    genesis.as_ptr(),
                )
            },
            WALLET_INVALID_PROOF
        );
        assert_eq!(
            unsafe {
                activechain_wallet_verify_owner_coin_cell_record(
                    core::ptr::null(),
                    1,
                    malformed.as_ptr(),
                    malformed.len() as u32,
                    malformed.as_ptr(),
                    malformed.len() as u32,
                    malformed.as_ptr(),
                    malformed.len() as u32,
                    owner.as_ptr(),
                    genesis.as_ptr(),
                )
            },
            WALLET_NULL_POINTER
        );
    }

    #[test]
    fn nft_state_verifier_abi_rejects_unknown_kind_null_and_malformed_evidence() {
        let key = [1_u8; 48];
        let genesis = [3_u8; 48];
        let malformed = [4_u8];
        for kind in [
            u32::from(activechain_verifier_api::NFT_SERIES_QUERY_KIND),
            u32::from(activechain_verifier_api::NFT_TOKEN_REGISTRY_QUERY_KIND),
            999,
        ] {
            assert_eq!(
                unsafe {
                    activechain_wallet_verify_nft_state_record(
                        kind,
                        key.as_ptr(),
                        1,
                        malformed.as_ptr(),
                        malformed.len() as u32,
                        malformed.as_ptr(),
                        malformed.len() as u32,
                        malformed.as_ptr(),
                        malformed.len() as u32,
                        genesis.as_ptr(),
                    )
                },
                WALLET_INVALID_PROOF
            );
        }
        assert_eq!(
            unsafe {
                activechain_wallet_verify_nft_state_record(
                    u32::from(activechain_verifier_api::NFT_SERIES_QUERY_KIND),
                    core::ptr::null(),
                    1,
                    malformed.as_ptr(),
                    malformed.len() as u32,
                    malformed.as_ptr(),
                    malformed.len() as u32,
                    malformed.as_ptr(),
                    malformed.len() as u32,
                    genesis.as_ptr(),
                )
            },
            WALLET_NULL_POINTER
        );
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
    fn agent_abi_keeps_pending_enrollment_inactive_until_exact_finality() {
        let principal = [0x31; 48];
        let capability = [0x41; 48];
        let transaction = [0x51; 48];
        let wrong_transaction = [0x52; 48];
        let label = b"Invoice assistant";
        let mut required = 0;
        let query = unsafe {
            activechain_wallet_agent_register_pending(
                core::ptr::null(),
                0,
                principal.as_ptr(),
                label.as_ptr(),
                label.len() as u32,
                1,
                capability.as_ptr(),
                1,
                0,
                100,
                500,
                transaction.as_ptr(),
                core::ptr::null_mut(),
                0,
                &mut required,
            )
        };
        assert_eq!(query, WALLET_BUFFER_TOO_SMALL);
        let mut registry = vec![0; required as usize];
        assert_eq!(
            unsafe {
                activechain_wallet_agent_register_pending(
                    core::ptr::null(),
                    0,
                    principal.as_ptr(),
                    label.as_ptr(),
                    label.len() as u32,
                    1,
                    capability.as_ptr(),
                    1,
                    0,
                    100,
                    500,
                    transaction.as_ptr(),
                    registry.as_mut_ptr(),
                    registry.len() as u32,
                    &mut required,
                )
            },
            WALLET_OK
        );

        let mut summary = ActivechainWalletAgentSummary::default();
        let mut label_required = label.len() as u32;
        let mut label_output = vec![0; label.len()];
        assert_eq!(
            unsafe {
                activechain_wallet_agent_summary(
                    registry.as_ptr(),
                    registry.len() as u32,
                    0,
                    &mut summary,
                    label_output.as_mut_ptr(),
                    label_output.len() as u32,
                    &mut label_required,
                )
            },
            WALLET_OK
        );
        assert_eq!(summary.lifecycle, 4);

        let mut next_required = 0;
        assert_eq!(
            unsafe {
                activechain_wallet_agent_finalize_enrollment(
                    registry.as_ptr(),
                    registry.len() as u32,
                    principal.as_ptr(),
                    wrong_transaction.as_ptr(),
                    42,
                    core::ptr::null_mut(),
                    0,
                    &mut next_required,
                )
            },
            WALLET_AGENT_REJECTED
        );
        assert_eq!(
            unsafe {
                activechain_wallet_agent_finalize_enrollment(
                    registry.as_ptr(),
                    registry.len() as u32,
                    principal.as_ptr(),
                    transaction.as_ptr(),
                    0,
                    core::ptr::null_mut(),
                    0,
                    &mut next_required,
                )
            },
            WALLET_MALFORMED
        );
        assert_eq!(
            unsafe {
                activechain_wallet_agent_finalize_enrollment(
                    registry.as_ptr(),
                    registry.len() as u32,
                    principal.as_ptr(),
                    transaction.as_ptr(),
                    42,
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
                activechain_wallet_agent_finalize_enrollment(
                    registry.as_ptr(),
                    registry.len() as u32,
                    principal.as_ptr(),
                    transaction.as_ptr(),
                    42,
                    next.as_mut_ptr(),
                    next.len() as u32,
                    &mut next_required,
                )
            },
            WALLET_OK
        );
        assert_eq!(
            unsafe {
                activechain_wallet_agent_summary(
                    next.as_ptr(),
                    next.len() as u32,
                    0,
                    &mut summary,
                    label_output.as_mut_ptr(),
                    label_output.len() as u32,
                    &mut label_required,
                )
            },
            WALLET_OK
        );
        assert_eq!(summary.lifecycle, 0);
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
    fn fungible_transfer_abi_rejects_null_and_malformed_inputs() {
        let mut required = 0_u32;
        assert_eq!(
            unsafe {
                activechain_wallet_build_fungible_transfer(
                    core::ptr::null(),
                    1,
                    [1_u8; 48].as_ptr(),
                    [2_u8; 48].as_ptr(),
                    [3_u8; 48].as_ptr(),
                    [4_u8; 48].as_ptr(),
                    1,
                    0,
                    1,
                    core::ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            WALLET_NULL_POINTER
        );
        let malformed = [0_u8];
        assert_eq!(
            unsafe {
                activechain_wallet_build_fungible_transfer(
                    malformed.as_ptr(),
                    malformed.len() as u32,
                    [1_u8; 48].as_ptr(),
                    [2_u8; 48].as_ptr(),
                    [3_u8; 48].as_ptr(),
                    [4_u8; 48].as_ptr(),
                    1,
                    0,
                    1,
                    core::ptr::null_mut(),
                    0,
                    &mut required,
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
    fn shared_approval_vector_is_strictly_decoded_by_the_production_abi() {
        let vector = approval_vector();
        let request = decode_hex(vector["request_hex"]);
        let mut approval = ActivechainWalletCashApproval::default();
        assert_eq!(
            unsafe {
                activechain_wallet_cash_approval(
                    request.as_ptr(),
                    request.len() as u32,
                    &mut approval,
                )
            },
            WALLET_OK
        );
        for (actual, name) in [
            (&approval.chain_id, "chain_id"),
            (&approval.signer, "signer"),
            (&approval.recipient, "recipient"),
            (&approval.fee_reserve, "fee_reserve"),
            (&approval.session_id, "session_id"),
            (&approval.intent_id, "intent_id"),
        ] {
            assert_eq!(actual.as_slice(), decode_hex(vector[name]));
        }
        assert_eq!(approval.nonce, vector["nonce"].parse::<u64>().unwrap());
        assert_eq!(
            approval.session_expires_at,
            vector["session_expires_at"].parse::<u64>().unwrap()
        );
        assert_eq!(approval.amount_high, vector["amount_high"].parse::<u64>().unwrap());
        assert_eq!(approval.amount_low, vector["amount_low"].parse::<u64>().unwrap());
        assert_eq!(approval.fee_high, vector["fee_high"].parse::<u64>().unwrap());
        assert_eq!(approval.fee_low, vector["fee_low"].parse::<u64>().unwrap());
        assert_eq!(approval.valid_until, vector["valid_until"].parse::<u64>().unwrap());
        assert_eq!(approval.input_count, vector["input_count"].parse::<u32>().unwrap());

        let mut alternate = request;
        alternate.push(0);
        assert_eq!(
            unsafe {
                activechain_wallet_cash_approval(
                    alternate.as_ptr(),
                    alternate.len() as u32,
                    &mut approval,
                )
            },
            WALLET_MALFORMED
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
        let mut approval = ActivechainWalletCashApproval::default();
        assert_eq!(
            unsafe {
                activechain_wallet_cash_approval(
                    output.as_ptr(),
                    output.len() as u32,
                    &mut approval,
                )
            },
            WALLET_OK
        );
        assert_eq!(approval.chain_id, [1; 48]);
        assert_eq!(approval.signer, [2; 48]);
        assert_eq!(approval.recipient, [3; 48]);
        assert_eq!(approval.fee_reserve, [5; 48]);
        assert_eq!(approval.session_id, [6; 48]);
        assert_eq!(approval.intent_id, intent);
        assert_eq!(approval.nonce, 7);
        assert_eq!(approval.session_expires_at, 9);
        assert_eq!((approval.amount_high, approval.amount_low), (0, 50));
        assert_eq!((approval.fee_high, approval.fee_low), (0, 2));
        assert_eq!(approval.valid_until, 10);
        assert_eq!(approval.input_count, 1);

        let mut mutated = output.clone();
        *mutated.last_mut().unwrap() ^= 1;
        let original_intent = approval.intent_id;
        assert_eq!(
            unsafe {
                activechain_wallet_cash_approval(
                    mutated.as_ptr(),
                    mutated.len() as u32,
                    &mut approval,
                )
            },
            WALLET_OK
        );
        assert_ne!(approval.intent_id, original_intent);
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

    #[test]
    fn faucet_intent_builder_binds_settlement_reference() {
        let values = [digest(1), digest(2), digest(3), digest(4), digest(5), digest(6), digest(7)];
        let mut required = 0;
        let mut intent = [0; 48];
        assert_eq!(
            unsafe {
                activechain_wallet_build_faucet_cash_intent(
                    values[0].as_bytes().as_ptr(),
                    values[1].as_bytes().as_ptr(),
                    values[2].as_bytes().as_ptr(),
                    values[3].as_bytes().as_ptr(),
                    values[4].as_bytes().as_ptr(),
                    7,
                    values[5].as_bytes().as_ptr(),
                    9,
                    values[6].as_bytes().as_ptr(),
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
        let mut output = vec![0; required as usize];
        assert_eq!(
            unsafe {
                activechain_wallet_build_faucet_cash_intent(
                    values[0].as_bytes().as_ptr(),
                    values[1].as_bytes().as_ptr(),
                    values[2].as_bytes().as_ptr(),
                    values[3].as_bytes().as_ptr(),
                    values[4].as_bytes().as_ptr(),
                    7,
                    values[5].as_bytes().as_ptr(),
                    9,
                    values[6].as_bytes().as_ptr(),
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
        assert_eq!(decoded.settlement_reference(), Some(values[6]));
        assert_eq!(decoded.intent_id().unwrap().as_bytes(), &intent);
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
        let approved_intent = request.intent_id().unwrap().into_bytes();
        let request = encode_envelope(&request).unwrap();
        let key = SigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from([7; 32]));
        let public_key = key.verifying_key().encode();
        let mut required = 0;
        assert_eq!(
            unsafe {
                activechain_wallet_sign_cash_intent(
                    request.as_ptr(),
                    request.len() as u32,
                    approved_intent.as_ptr(),
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
                    approved_intent.as_ptr(),
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

        let substituted_intent = [0_u8; 48];
        assert_eq!(
            unsafe {
                activechain_wallet_sign_cash_intent(
                    request.as_ptr(),
                    request.len() as u32,
                    substituted_intent.as_ptr(),
                    public_key.as_slice().as_ptr(),
                    Some(sign_callback),
                    (&key as *const SigningKey<MlDsa44>).cast_mut().cast(),
                    output.as_mut_ptr(),
                    required,
                    &mut required,
                )
            },
            WALLET_APPROVAL_MISMATCH
        );

        let wrong_key = SigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from([8; 32]));
        assert_eq!(
            unsafe {
                activechain_wallet_sign_cash_intent(
                    request.as_ptr(),
                    request.len() as u32,
                    approved_intent.as_ptr(),
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

    fn proposal_intent() -> ActionIntentV1 {
        ActionIntentV1 {
            request_id: b"mcp-request-7".to_vec(),
            chain_id: b"activechain-devnet".to_vec(),
            wallet_id: b"wallet-primary".to_vec(),
            agent_principal: digest(21),
            capability_id: digest(22),
            request_nonce: b"nonce-unique-7".to_vec(),
            action: ActionKindV1::Transfer,
            resource: digest(23),
            recipient: digest(24),
            amount: (3_u128 << 64) | 17,
            maximum_fee: 9,
            expires_at_height: 500,
            replay_domain: digest(25),
        }
    }

    #[test]
    fn canonical_mcp_proposal_review_signing_and_submission_fail_closed() {
        let intent = proposal_intent();
        let encoded = encode_envelope(&intent).unwrap();
        let commitment = intent.commitment().unwrap();
        let mut approval = ActivechainWalletProposalApproval::default();
        assert_eq!(
            unsafe {
                activechain_wallet_proposal_approval(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    499,
                    &mut approval,
                )
            },
            WALLET_OK
        );
        assert_eq!(&approval.request_id[..approval.request_id_len as usize], b"mcp-request-7");
        assert_eq!(&approval.chain_id[..approval.chain_id_len as usize], b"activechain-devnet");
        assert_eq!(approval.agent_principal, [21; 48]);
        assert_eq!(approval.capability_id, [22; 48]);
        assert_eq!(approval.recipient, [24; 48]);
        assert_eq!(approval.intent_commitment, commitment.into_bytes());
        assert_eq!((approval.amount_high, approval.amount_low), (3, 17));

        assert_eq!(
            unsafe {
                activechain_wallet_proposal_approval(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    500,
                    &mut approval,
                )
            },
            WALLET_AGENT_REJECTED
        );

        let key = SigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from([31; 32]));
        let public_key = key.verifying_key().encode();
        let mut required = 0;
        assert_eq!(
            unsafe {
                activechain_wallet_sign_proposal_intent(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    100,
                    approval.intent_commitment.as_ptr(),
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
        let mut authorized = vec![0; required as usize];
        assert_eq!(
            unsafe {
                activechain_wallet_sign_proposal_intent(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    100,
                    approval.intent_commitment.as_ptr(),
                    public_key.as_slice().as_ptr(),
                    Some(sign_callback),
                    (&key as *const SigningKey<MlDsa44>).cast_mut().cast(),
                    authorized.as_mut_ptr(),
                    authorized.len() as u32,
                    &mut required,
                )
            },
            WALLET_OK
        );
        let decoded = decode_envelope::<AuthorizedActionIntentV1>(&authorized).unwrap();
        assert_eq!(decoded.intent, intent);
        assert!(verify_proposal_signature(
            &decoded.public_key,
            decoded.signature.as_bytes(),
            &decoded.intent.signing_payload().unwrap(),
        ));

        let mut submissions = 0_usize;
        assert_eq!(
            unsafe {
                activechain_wallet_submit_authorized_proposal(
                    authorized.as_ptr(),
                    authorized.len() as u32,
                    499,
                    Some(submit_callback),
                    (&mut submissions as *mut usize).cast(),
                )
            },
            WALLET_OK
        );
        assert_eq!(submissions, 1);
        assert_eq!(
            unsafe {
                activechain_wallet_submit_authorized_proposal(
                    authorized.as_ptr(),
                    authorized.len() as u32,
                    500,
                    Some(submit_callback),
                    (&mut submissions as *mut usize).cast(),
                )
            },
            WALLET_AGENT_REJECTED
        );

        let mut wrong_commitment = approval.intent_commitment;
        wrong_commitment[0] ^= 1;
        assert_eq!(
            unsafe {
                activechain_wallet_sign_proposal_intent(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    100,
                    wrong_commitment.as_ptr(),
                    public_key.as_slice().as_ptr(),
                    Some(sign_callback),
                    (&key as *const SigningKey<MlDsa44>).cast_mut().cast(),
                    authorized.as_mut_ptr(),
                    authorized.len() as u32,
                    &mut required,
                )
            },
            WALLET_APPROVAL_MISMATCH
        );
    }
}
