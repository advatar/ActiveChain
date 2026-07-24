#![forbid(unsafe_code)]

//! Fail-closed nTZS sandbox adapter for ActiveBridge.
//!
//! This crate deliberately has no HTTP implementation. It fixes the documented provider contract,
//! verifies webhook authentication over exact bytes, and leaves transport and secret custody to
//! the isolated connector host. Provider evidence never becomes ActiveChain finality here.

use activechain_payment_types::{
    AssetAmountV1, ConnectorId, EvidenceClass, PaymentAttemptId, PaymentIntentId,
    ProviderObservationV1, ProviderOperationState,
};
use activechain_protocol_types::{ChainId, Digest384};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::fmt;
use std::{collections::BTreeSet, fs::File, io::Write, path::Path};

type HmacSha256 = Hmac<Sha256>;

/// The only base URL published by the reviewed nTZS developer contract.
pub const NTZS_API_BASE_URL: &str = "https://www.ntzs.co.tz";
/// Maximum request or webhook body accepted by the adapter.
pub const MAX_BODY_BYTES: usize = 256 * 1024;
/// Maximum opaque provider identifier length accepted from JSON.
pub const MAX_PROVIDER_REFERENCE_BYTES: usize = 256;
/// Maximum replay identities retained by the reference journal.
pub const MAX_REPLAY_IDENTITIES: usize = 65_535;

const REPLAY_MAGIC: &[u8; 8] = b"ACNZRPL1";
const REPLAY_TAG_BYTES: usize = 48;
const REFERENCE_DOMAIN: &[u8] = b"ACTIVECHAIN-NTZS-PROVIDER-REFERENCE-V1";
const REPLAY_KEY_DOMAIN: &[u8] = b"ACTIVECHAIN-NTZS-WEBHOOK-REPLAY-V1";
const PAYLOAD_DOMAIN: &[u8] = b"ACTIVECHAIN-NTZS-WEBHOOK-PAYLOAD-V1";
const SNAPSHOT_DOMAIN: &[u8] = b"ACTIVECHAIN-NTZS-REPLAY-SNAPSHOT-V1";

/// Documented HTTP verb.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// Reviewed nTZS endpoint. Templates are returned for identifier-bearing GET operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtzsEndpoint {
    CreateUser,
    GetUser,
    CreateDeposit,
    CreateTransfer,
    CreateWithdrawal,
    SwapRate,
    CreateSwap,
    RampBalance,
    RampQuote,
    RampOfframp,
    RampOnramp,
    GetRampSettlement,
    ListRampSettlements,
}

impl NtzsEndpoint {
    #[must_use]
    pub const fn method(self) -> HttpMethod {
        match self {
            Self::GetUser
            | Self::SwapRate
            | Self::RampBalance
            | Self::GetRampSettlement
            | Self::ListRampSettlements => HttpMethod::Get,
            Self::CreateUser
            | Self::CreateDeposit
            | Self::CreateTransfer
            | Self::CreateWithdrawal
            | Self::CreateSwap
            | Self::RampQuote
            | Self::RampOfframp
            | Self::RampOnramp => HttpMethod::Post,
        }
    }

    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::CreateUser => "/api/v1/users",
            Self::GetUser => "/api/v1/users/{id}",
            Self::CreateDeposit => "/api/v1/deposits",
            Self::CreateTransfer => "/api/v1/transfers",
            Self::CreateWithdrawal => "/api/v1/withdrawals",
            Self::SwapRate => "/api/v1/swap/rate",
            Self::CreateSwap => "/api/v1/swap",
            Self::RampBalance => "/api/v1/ramp/balance",
            Self::RampQuote => "/api/v1/ramp/quote",
            Self::RampOfframp => "/api/v1/ramp/offramp",
            Self::RampOnramp => "/api/v1/ramp/onramp",
            Self::GetRampSettlement => "/api/v1/ramp/{id}",
            Self::ListRampSettlements => "/api/v1/ramp/settlements",
        }
    }

    #[must_use]
    pub const fn requires_authentication(self) -> bool {
        !matches!(self, Self::SwapRate)
    }

    #[must_use]
    pub const fn requires_idempotency_key(self) -> bool {
        matches!(self, Self::RampOfframp | Self::RampOnramp)
    }
}

/// nTZS key environment inferred from the documented key prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiKeyEnvironment {
    Test,
    Live,
}

impl ApiKeyEnvironment {
    #[must_use]
    pub fn classify(api_key: &str) -> Option<Self> {
        if api_key.strip_prefix("ntzs_test_").is_some_and(|suffix| !suffix.is_empty()) {
            Some(Self::Test)
        } else if api_key.strip_prefix("ntzs_live_").is_some_and(|suffix| !suffix.is_empty()) {
            Some(Self::Live)
        } else {
            None
        }
    }
}

/// A bounded request handed to an operator-supplied backend transport.
#[derive(Clone, Eq, PartialEq)]
pub struct NtzsRequest {
    endpoint: NtzsEndpoint,
    body: Vec<u8>,
    idempotency_key: Option<String>,
}

impl NtzsRequest {
    pub fn new(
        endpoint: NtzsEndpoint,
        body: Vec<u8>,
        idempotency_key: Option<String>,
    ) -> Result<Self, AdapterError> {
        if body.len() > MAX_BODY_BYTES {
            return Err(AdapterError::BodyTooLarge);
        }
        if endpoint.method() == HttpMethod::Get && !body.is_empty() {
            return Err(AdapterError::InvalidRequest);
        }
        if endpoint.method() == HttpMethod::Post
            && !matches!(serde_json::from_slice::<Value>(&body), Ok(Value::Object(_)))
        {
            return Err(AdapterError::InvalidRequest);
        }
        if endpoint.requires_idempotency_key()
            && idempotency_key.as_deref().is_none_or(str::is_empty)
        {
            return Err(AdapterError::MissingIdempotencyKey);
        }
        if idempotency_key.as_ref().is_some_and(|key| key.len() > 128) {
            return Err(AdapterError::InvalidRequest);
        }
        Ok(Self { endpoint, body, idempotency_key })
    }

    #[must_use]
    pub const fn endpoint(&self) -> NtzsEndpoint {
        self.endpoint
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }
}

impl fmt::Debug for NtzsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NtzsRequest")
            .field("endpoint", &self.endpoint)
            .field("body_bytes", &self.body.len())
            .field("has_idempotency_key", &self.idempotency_key.is_some())
            .finish()
    }
}

/// A bounded transport response. Bodies remain provider JSON until explicitly validated.
#[derive(Clone, Eq, PartialEq)]
pub struct NtzsResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl fmt::Debug for NtzsResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NtzsResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Backend-only transport boundary. Implementations must use TLS and must not log `api_key`.
pub trait NtzsTransport {
    type Error;

    fn send(
        &self,
        base_url: &str,
        api_key: &str,
        request: &NtzsRequest,
    ) -> Result<NtzsResponse, Self::Error>;
}

/// Adapter that refuses live credentials and arbitrary provider base URLs.
#[derive(Clone)]
pub struct NtzsSandboxAdapter<T> {
    transport: T,
}

impl<T> NtzsSandboxAdapter<T> {
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T: NtzsTransport> NtzsSandboxAdapter<T> {
    pub fn execute(
        &self,
        api_key: &str,
        request: &NtzsRequest,
    ) -> Result<NtzsResponse, ExecuteError<T::Error>> {
        let credential_environment = ApiKeyEnvironment::classify(api_key);
        if (request.endpoint().requires_authentication()
            && credential_environment != Some(ApiKeyEnvironment::Test))
            || (!api_key.is_empty() && credential_environment != Some(ApiKeyEnvironment::Test))
        {
            return Err(ExecuteError::Adapter(AdapterError::SandboxCredentialRequired));
        }
        let response = self
            .transport
            .send(NTZS_API_BASE_URL, api_key, request)
            .map_err(ExecuteError::Transport)?;
        if !(200..=599).contains(&response.status) || response.body.len() > MAX_BODY_BYTES {
            return Err(ExecuteError::Adapter(AdapterError::InvalidResponse));
        }
        Ok(response)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterError {
    BodyTooLarge,
    InvalidRequest,
    InvalidResponse,
    MissingIdempotencyKey,
    SandboxCredentialRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecuteError<T> {
    Adapter(AdapterError),
    Transport(T),
}

/// Provider operation whose API status is being normalized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtzsOperation {
    Deposit,
    Transfer,
    Withdrawal,
    Swap,
    RampSettlement,
}

impl NtzsOperation {
    const fn domain_tag(self) -> u8 {
        match self {
            Self::Deposit => 1,
            Self::Transfer => 2,
            Self::Withdrawal => 3,
            Self::Swap => 4,
            Self::RampSettlement => 5,
        }
    }
}

/// Derives the provider-reference binding stored with an operation before webhook admission.
pub fn provider_reference_commitment(
    operation: NtzsOperation,
    reference: &str,
) -> Result<Digest384, WebhookError> {
    if reference.is_empty() || reference.len() > MAX_PROVIDER_REFERENCE_BYTES {
        return Err(WebhookError::MissingReference);
    }
    Ok(commitment(REFERENCE_DOMAIN, &[&[operation.domain_tag()], reference.as_bytes()]))
}

/// Maps only explicitly documented API response/SSE states. Everything else is unknown.
#[must_use]
pub fn map_api_status(operation: NtzsOperation, status: &str) -> ProviderOperationState {
    match (operation, status) {
        (NtzsOperation::Deposit, "submitted") => ProviderOperationState::Pending,
        (NtzsOperation::Transfer, "completed") => ProviderOperationState::Succeeded,
        (NtzsOperation::Withdrawal, "requested" | "burned") => ProviderOperationState::Pending,
        (NtzsOperation::Swap, "CHECKING" | "SENDING" | "FILLING") => {
            ProviderOperationState::Pending
        }
        (NtzsOperation::Swap, "FILLED") => ProviderOperationState::Succeeded,
        (NtzsOperation::Swap, "FAILED") => ProviderOperationState::Rejected,
        (NtzsOperation::RampSettlement, "paying_out" | "minting") => {
            ProviderOperationState::Pending
        }
        (NtzsOperation::RampSettlement, "completed") => ProviderOperationState::Succeeded,
        (NtzsOperation::RampSettlement, "failed") => ProviderOperationState::Rejected,
        _ => ProviderOperationState::Unknown,
    }
}

/// Exact documented provider error taxonomy. Unknown additions never inherit retry semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtzsErrorCode {
    MissingRequiredFields,
    InvalidAmount,
    InvalidTransfer,
    WalletNotProvisioned,
    InsufficientBalance,
    UserNotFound,
    Unauthorized,
    RelayerUnavailable,
    BlockchainError,
    NetworkError,
    Unknown,
}

impl NtzsErrorCode {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value {
            "missing_required_fields" => Self::MissingRequiredFields,
            "invalid_amount" => Self::InvalidAmount,
            "invalid_transfer" => Self::InvalidTransfer,
            "wallet_not_provisioned" => Self::WalletNotProvisioned,
            "insufficient_balance" => Self::InsufficientBalance,
            "user_not_found" => Self::UserNotFound,
            "unauthorized" => Self::Unauthorized,
            "relayer_unavailable" => Self::RelayerUnavailable,
            "blockchain_error" => Self::BlockchainError,
            "network_error" => Self::NetworkError,
            _ => Self::Unknown,
        }
    }
}

/// Webhook freshness policy supplied by the connector operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebhookFreshness {
    max_age_seconds: u64,
    max_future_skew_seconds: u64,
}

impl WebhookFreshness {
    pub fn new(max_age_seconds: u64, max_future_skew_seconds: u64) -> Result<Self, WebhookError> {
        if max_age_seconds == 0 {
            return Err(WebhookError::InvalidFreshnessPolicy);
        }
        Ok(Self { max_age_seconds, max_future_skew_seconds })
    }
}

/// Documented completion webhook kinds with published reference fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtzsWebhookKind {
    DepositCompleted,
    TransferCompleted,
    WithdrawalCompleted,
}

impl NtzsWebhookKind {
    const fn operation(self) -> NtzsOperation {
        match self {
            Self::DepositCompleted => NtzsOperation::Deposit,
            Self::TransferCompleted => NtzsOperation::Transfer,
            Self::WithdrawalCompleted => NtzsOperation::Withdrawal,
        }
    }

    const fn reference_field(self) -> &'static str {
        match self {
            Self::DepositCompleted => "depositId",
            Self::TransferCompleted => "transferId",
            Self::WithdrawalCompleted => "withdrawalId",
        }
    }

    const fn domain_tag(self) -> u8 {
        match self {
            Self::DepositCompleted => 1,
            Self::TransferCompleted => 2,
            Self::WithdrawalCompleted => 3,
        }
    }
}

/// Authenticated external event, still strictly below provider signature and chain finality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedNtzsWebhook {
    kind: NtzsWebhookKind,
    signed_at: u64,
    provider_reference_commitment: Digest384,
    payload_commitment: Digest384,
    replay_identity: Digest384,
}

impl VerifiedNtzsWebhook {
    #[must_use]
    pub const fn kind(&self) -> NtzsWebhookKind {
        self.kind
    }

    #[must_use]
    pub const fn signed_at(&self) -> u64 {
        self.signed_at
    }

    #[must_use]
    pub const fn replay_identity(&self) -> Digest384 {
        self.replay_identity
    }

    fn to_observation(
        &self,
        context: NtzsObservationContext,
    ) -> Result<ProviderObservationV1, WebhookError> {
        if context.provider_reference_commitment != self.provider_reference_commitment {
            return Err(WebhookError::InvalidObservation);
        }
        ProviderObservationV1::new(
            context.chain,
            context.connector,
            context.attempt,
            context.intent,
            context.provider_account_commitment,
            self.provider_reference_commitment,
            context.sequence,
            ProviderOperationState::Succeeded,
            context.amount,
            self.signed_at,
            context.observed_at,
            EvidenceClass::ConnectorAuthenticated,
            self.payload_commitment,
        )
        .map_err(|_| WebhookError::InvalidObservation)
    }
}

/// ActiveBridge bindings supplied independently of untrusted provider JSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtzsObservationContext {
    pub chain: ChainId,
    pub connector: ConnectorId,
    pub attempt: PaymentAttemptId,
    pub intent: PaymentIntentId,
    pub provider_account_commitment: Digest384,
    pub provider_reference_commitment: Digest384,
    pub sequence: u64,
    pub amount: AssetAmountV1,
    pub observed_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookError {
    BodyTooLarge,
    Duplicate,
    FutureTimestamp,
    InvalidBody,
    InvalidFreshnessPolicy,
    InvalidObservation,
    InvalidSignature,
    InvalidTimestamp,
    MissingReference,
    Persistence,
    ReplayCapacity,
    StaleTimestamp,
    UnsupportedEvent,
}

/// Verifies nTZS HMAC-SHA256 over the exact `timestamp.body` bytes before parsing JSON.
pub fn verify_webhook(
    secret: &[u8],
    signature_hex: &str,
    timestamp_header: &str,
    raw_body: &[u8],
    now: u64,
    freshness: WebhookFreshness,
) -> Result<VerifiedNtzsWebhook, WebhookError> {
    if raw_body.len() > MAX_BODY_BYTES {
        return Err(WebhookError::BodyTooLarge);
    }
    if secret.is_empty() {
        return Err(WebhookError::InvalidSignature);
    }
    let signed_at = timestamp_header.parse::<u64>().map_err(|_| WebhookError::InvalidTimestamp)?;
    if signed_at > now.saturating_add(freshness.max_future_skew_seconds) {
        return Err(WebhookError::FutureTimestamp);
    }
    if now.saturating_sub(signed_at) > freshness.max_age_seconds {
        return Err(WebhookError::StaleTimestamp);
    }
    let signature = decode_signature(signature_hex)?;
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| WebhookError::InvalidSignature)?;
    Mac::update(&mut mac, timestamp_header.as_bytes());
    Mac::update(&mut mac, b".");
    Mac::update(&mut mac, raw_body);
    mac.verify_slice(&signature).map_err(|_| WebhookError::InvalidSignature)?;

    let document: Value =
        serde_json::from_slice(raw_body).map_err(|_| WebhookError::InvalidBody)?;
    let event_type =
        document.get("type").and_then(Value::as_str).ok_or(WebhookError::InvalidBody)?;
    let kind = match event_type {
        "deposit.completed" => NtzsWebhookKind::DepositCompleted,
        "transfer.completed" => NtzsWebhookKind::TransferCompleted,
        "withdrawal.completed" => NtzsWebhookKind::WithdrawalCompleted,
        _ => return Err(WebhookError::UnsupportedEvent),
    };
    let reference = document
        .get("data")
        .and_then(|data| data.get(kind.reference_field()))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= MAX_PROVIDER_REFERENCE_BYTES)
        .ok_or(WebhookError::MissingReference)?;
    let provider_reference_commitment = provider_reference_commitment(kind.operation(), reference)?;
    let payload_commitment = commitment(PAYLOAD_DOMAIN, &[timestamp_header.as_bytes(), raw_body]);
    let replay_identity =
        commitment(REPLAY_KEY_DOMAIN, &[&[kind.domain_tag()], reference.as_bytes()]);
    Ok(VerifiedNtzsWebhook {
        kind,
        signed_at,
        provider_reference_commitment,
        payload_commitment,
        replay_identity,
    })
}

/// Verifies, binds, and durably replay-protects one webhook before exposing an observation.
pub fn admit_webhook_durable(
    delivery: WebhookDelivery<'_>,
    context: NtzsObservationContext,
    journal: &mut NtzsReplayJournal,
    journal_path: &Path,
) -> Result<ProviderObservationV1, WebhookError> {
    let verified = verify_webhook(
        delivery.secret,
        delivery.signature_hex,
        delivery.timestamp_header,
        delivery.raw_body,
        delivery.now,
        delivery.freshness,
    )?;
    let observation = verified.to_observation(context)?;
    journal.record_durable(verified.replay_identity(), journal_path)?;
    Ok(observation)
}

/// Exact unparsed webhook delivery and operator clock input.
#[derive(Clone, Copy)]
pub struct WebhookDelivery<'a> {
    pub secret: &'a [u8],
    pub signature_hex: &'a str,
    pub timestamp_header: &'a str,
    pub raw_body: &'a [u8],
    pub now: u64,
    pub freshness: WebhookFreshness,
}

fn decode_signature(value: &str) -> Result<[u8; 32], WebhookError> {
    if value.len() != 64 {
        return Err(WebhookError::InvalidSignature);
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, WebhookError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(WebhookError::InvalidSignature),
    }
}

fn commitment(domain: &[u8], fields: &[&[u8]]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    for field in fields {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

/// Durable, sorted replay barrier for authenticated provider event identities.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NtzsReplayJournal {
    identities: BTreeSet<Digest384>,
}

impl NtzsReplayJournal {
    #[must_use]
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    pub fn record(&mut self, identity: Digest384) -> Result<(), WebhookError> {
        if identity == Digest384::ZERO {
            return Err(WebhookError::InvalidBody);
        }
        if self.identities.contains(&identity) {
            return Err(WebhookError::Duplicate);
        }
        if self.identities.len() == MAX_REPLAY_IDENTITIES {
            return Err(WebhookError::ReplayCapacity);
        }
        self.identities.insert(identity);
        Ok(())
    }

    pub fn record_durable(&mut self, identity: Digest384, path: &Path) -> Result<(), WebhookError> {
        let mut next = self.clone();
        next.record(identity)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), WebhookError> {
        let body = self.encode_snapshot();
        let tag = snapshot_tag(&body);
        let parent = path.parent().ok_or(WebhookError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| WebhookError::Persistence)?;
        let name = path.file_name().ok_or(WebhookError::Persistence)?.to_string_lossy();
        let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
        let result = (|| {
            let mut file = File::create(&temporary).map_err(|_| WebhookError::Persistence)?;
            file.write_all(&body)
                .and_then(|_| file.write_all(&tag))
                .and_then(|_| file.sync_all())
                .map_err(|_| WebhookError::Persistence)?;
            std::fs::rename(&temporary, path).map_err(|_| WebhookError::Persistence)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| WebhookError::Persistence)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }

    pub fn load(path: &Path) -> Result<Self, WebhookError> {
        let bytes = std::fs::read(path).map_err(|_| WebhookError::Persistence)?;
        if bytes.len() < REPLAY_MAGIC.len() + 4 + REPLAY_TAG_BYTES {
            return Err(WebhookError::Persistence);
        }
        let body_length = bytes.len() - REPLAY_TAG_BYTES;
        if snapshot_tag(&bytes[..body_length]) != bytes[body_length..] {
            return Err(WebhookError::Persistence);
        }
        Self::decode_snapshot(&bytes[..body_length])
    }

    fn encode_snapshot(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(REPLAY_MAGIC.len() + 4 + self.identities.len() * 48);
        bytes.extend_from_slice(REPLAY_MAGIC);
        bytes.extend_from_slice(&(self.identities.len() as u32).to_be_bytes());
        for identity in &self.identities {
            bytes.extend_from_slice(identity.as_bytes());
        }
        bytes
    }

    fn decode_snapshot(bytes: &[u8]) -> Result<Self, WebhookError> {
        if bytes.get(..REPLAY_MAGIC.len()) != Some(REPLAY_MAGIC.as_slice()) {
            return Err(WebhookError::Persistence);
        }
        let count_bytes: [u8; 4] = bytes
            .get(REPLAY_MAGIC.len()..REPLAY_MAGIC.len() + 4)
            .ok_or(WebhookError::Persistence)?
            .try_into()
            .map_err(|_| WebhookError::Persistence)?;
        let count = u32::from_be_bytes(count_bytes) as usize;
        if count > MAX_REPLAY_IDENTITIES || bytes.len() != REPLAY_MAGIC.len() + 4 + count * 48 {
            return Err(WebhookError::Persistence);
        }
        let mut identities = BTreeSet::new();
        let mut previous = None;
        for chunk in bytes[REPLAY_MAGIC.len() + 4..].chunks_exact(48) {
            let value: [u8; 48] = chunk.try_into().map_err(|_| WebhookError::Persistence)?;
            let identity = Digest384::new(value);
            if value == [0; 48]
                || previous.is_some_and(|prior| prior >= identity)
                || !identities.insert(identity)
            {
                return Err(WebhookError::Persistence);
            }
            previous = Some(identity);
        }
        Ok(Self { identities })
    }
}

fn snapshot_tag(bytes: &[u8]) -> [u8; REPLAY_TAG_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(SNAPSHOT_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    let mut output = [0_u8; REPLAY_TAG_BYTES];
    hasher.finalize_xof().read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::AssetId;
    use std::{cell::RefCell, path::PathBuf};

    const TEST_SECRET: &[u8] = b"activechain-ntzs-sanitized-fixture-secret";
    const TIMESTAMP: &str = "1784912400";

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn signature(body: &[u8], timestamp: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(TEST_SECRET).unwrap();
        Mac::update(&mut mac, timestamp.as_bytes());
        Mac::update(&mut mac, b".");
        Mac::update(&mut mac, body);
        mac.finalize().into_bytes().iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn freshness() -> WebhookFreshness {
        WebhookFreshness::new(300, 15).unwrap()
    }

    fn fixture(name: &str) -> &'static [u8] {
        match name {
            "deposit" => include_bytes!("../fixtures/deposit-completed.json"),
            "transfer" => include_bytes!("../fixtures/transfer-completed.json"),
            "withdrawal" => include_bytes!("../fixtures/withdrawal-completed.json"),
            _ => panic!("unknown fixture"),
        }
    }

    fn verify(name: &str) -> VerifiedNtzsWebhook {
        let body = fixture(name);
        verify_webhook(
            TEST_SECRET,
            &signature(body, TIMESTAMP),
            TIMESTAMP,
            body,
            1_784_912_460,
            freshness(),
        )
        .unwrap()
    }

    #[test]
    fn api_contract_is_fixed_and_sandbox_rejects_live_keys() {
        assert_eq!(NtzsEndpoint::CreateDeposit.method(), HttpMethod::Post);
        assert_eq!(NtzsEndpoint::CreateDeposit.path_template(), "/api/v1/deposits");
        assert!(!NtzsEndpoint::SwapRate.requires_authentication());
        assert!(NtzsEndpoint::RampOfframp.requires_idempotency_key());
        assert_eq!(ApiKeyEnvironment::classify("ntzs_test_fixture"), Some(ApiKeyEnvironment::Test));
        assert_eq!(ApiKeyEnvironment::classify("ntzs_live_fixture"), Some(ApiKeyEnvironment::Live));
        assert_eq!(ApiKeyEnvironment::classify("ntzs_test_"), None);

        #[derive(Default)]
        struct MockTransport {
            calls: RefCell<Vec<String>>,
        }
        impl NtzsTransport for MockTransport {
            type Error = ();
            fn send(
                &self,
                base_url: &str,
                _api_key: &str,
                request: &NtzsRequest,
            ) -> Result<NtzsResponse, Self::Error> {
                self.calls
                    .borrow_mut()
                    .push(format!("{base_url}{}", request.endpoint().path_template()));
                Ok(NtzsResponse { status: 202, body: b"{}".to_vec() })
            }
        }

        let adapter = NtzsSandboxAdapter::new(MockTransport::default());
        let request = NtzsRequest::new(NtzsEndpoint::CreateDeposit, b"{}".to_vec(), None).unwrap();
        assert!(matches!(
            adapter.execute("ntzs_live_fixture", &request),
            Err(ExecuteError::Adapter(AdapterError::SandboxCredentialRequired))
        ));
        assert_eq!(adapter.execute("ntzs_test_fixture", &request).unwrap().status, 202);
        assert_eq!(
            adapter.transport.calls.borrow().as_slice(),
            ["https://www.ntzs.co.tz/api/v1/deposits"]
        );
    }

    #[test]
    fn request_validation_requires_ramp_idempotency_and_bounds_bodies() {
        assert_eq!(
            NtzsRequest::new(NtzsEndpoint::RampOfframp, b"{}".to_vec(), None),
            Err(AdapterError::MissingIdempotencyKey)
        );
        assert_eq!(
            NtzsRequest::new(NtzsEndpoint::SwapRate, b"{}".to_vec(), None),
            Err(AdapterError::InvalidRequest)
        );
        assert_eq!(
            NtzsRequest::new(NtzsEndpoint::CreateDeposit, vec![0; MAX_BODY_BYTES + 1], None,),
            Err(AdapterError::BodyTooLarge)
        );
    }

    #[test]
    fn every_documented_status_maps_explicitly_and_unknown_fails_closed() {
        let cases = [
            (NtzsOperation::Deposit, "submitted", ProviderOperationState::Pending),
            (NtzsOperation::Transfer, "completed", ProviderOperationState::Succeeded),
            (NtzsOperation::Withdrawal, "requested", ProviderOperationState::Pending),
            (NtzsOperation::Withdrawal, "burned", ProviderOperationState::Pending),
            (NtzsOperation::Swap, "CHECKING", ProviderOperationState::Pending),
            (NtzsOperation::Swap, "SENDING", ProviderOperationState::Pending),
            (NtzsOperation::Swap, "FILLING", ProviderOperationState::Pending),
            (NtzsOperation::Swap, "FILLED", ProviderOperationState::Succeeded),
            (NtzsOperation::Swap, "FAILED", ProviderOperationState::Rejected),
            (NtzsOperation::RampSettlement, "paying_out", ProviderOperationState::Pending),
            (NtzsOperation::RampSettlement, "minting", ProviderOperationState::Pending),
            (NtzsOperation::RampSettlement, "completed", ProviderOperationState::Succeeded),
            (NtzsOperation::RampSettlement, "failed", ProviderOperationState::Rejected),
        ];
        for (operation, status, expected) in cases {
            assert_eq!(map_api_status(operation, status), expected);
        }
        assert_eq!(
            map_api_status(NtzsOperation::Deposit, "completed"),
            ProviderOperationState::Unknown
        );
        assert_eq!(
            map_api_status(NtzsOperation::Withdrawal, "burned_and_paid"),
            ProviderOperationState::Unknown
        );
    }

    #[test]
    fn published_mapping_vector_matches_the_adapter() {
        let vectors = include_str!("../../../testing/ntzs-provider-contract-v1.tsv");
        for (line_number, line) in vectors.lines().enumerate().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 4, "malformed vector line {}", line_number + 1);
            let actual = match fields[0] {
                "api" | "sse" => {
                    let operation = match fields[1] {
                        "deposit" => NtzsOperation::Deposit,
                        "transfer" => NtzsOperation::Transfer,
                        "withdrawal" => NtzsOperation::Withdrawal,
                        "swap" => NtzsOperation::Swap,
                        "ramp" => NtzsOperation::RampSettlement,
                        value => panic!("unknown operation {value}"),
                    };
                    match map_api_status(operation, fields[2]) {
                        ProviderOperationState::Pending => "pending",
                        ProviderOperationState::Succeeded => "succeeded",
                        ProviderOperationState::Rejected => "rejected",
                        ProviderOperationState::Unknown => "unknown",
                        value => panic!("unexpected mapped state {value:?}"),
                    }
                }
                "webhook" => match fields[2] {
                    "deposit.completed" | "transfer.completed" | "withdrawal.completed" => {
                        "succeeded"
                    }
                    _ => "unsupported",
                },
                value => panic!("unknown vector channel {value}"),
            };
            assert_eq!(actual, fields[3], "vector line {}", line_number + 1);
        }
    }

    #[test]
    fn authenticated_fixtures_emit_connector_evidence_not_finality() {
        assert_eq!(verify("deposit").kind(), NtzsWebhookKind::DepositCompleted);
        assert_eq!(verify("transfer").kind(), NtzsWebhookKind::TransferCompleted);
        let body = fixture("withdrawal");
        let signature = signature(body, TIMESTAMP);
        let journal_path = path("admission");
        let _ = std::fs::remove_file(&journal_path);
        let mut journal = NtzsReplayJournal::default();
        let context = NtzsObservationContext {
            chain: ChainId::new(digest(1)),
            connector: ConnectorId::new(digest(2)).unwrap(),
            attempt: PaymentAttemptId::new(digest(3)).unwrap(),
            intent: PaymentIntentId::new(digest(4)).unwrap(),
            provider_account_commitment: digest(5),
            provider_reference_commitment: provider_reference_commitment(
                NtzsOperation::Withdrawal,
                "wdr_fixture_001",
            )
            .unwrap(),
            sequence: 1,
            amount: AssetAmountV1::new(AssetId::new(digest(6)), 10_000).unwrap(),
            observed_at: 1_784_912_460,
        };
        assert_eq!(
            admit_webhook_durable(
                WebhookDelivery {
                    secret: TEST_SECRET,
                    signature_hex: &signature,
                    timestamp_header: TIMESTAMP,
                    raw_body: body,
                    now: 1_784_912_460,
                    freshness: freshness(),
                },
                NtzsObservationContext { provider_reference_commitment: digest(9), ..context },
                &mut journal,
                &journal_path,
            ),
            Err(WebhookError::InvalidObservation)
        );
        assert!(journal.is_empty());
        assert!(!journal_path.exists());
        let observation = admit_webhook_durable(
            WebhookDelivery {
                secret: TEST_SECRET,
                signature_hex: &signature,
                timestamp_header: TIMESTAMP,
                raw_body: body,
                now: 1_784_912_460,
                freshness: freshness(),
            },
            context,
            &mut journal,
            &journal_path,
        )
        .unwrap();
        assert_eq!(observation.state(), ProviderOperationState::Succeeded);
        assert_eq!(observation.evidence_class(), EvidenceClass::ConnectorAuthenticated);
        assert_eq!(
            admit_webhook_durable(
                WebhookDelivery {
                    secret: TEST_SECRET,
                    signature_hex: &signature,
                    timestamp_header: TIMESTAMP,
                    raw_body: body,
                    now: 1_784_912_460,
                    freshness: freshness(),
                },
                context,
                &mut journal,
                &journal_path,
            ),
            Err(WebhookError::Duplicate)
        );
        std::fs::remove_file(journal_path).unwrap();
    }

    #[test]
    fn signature_timestamp_body_and_event_shape_are_all_bound() {
        let body = fixture("deposit");
        let valid_signature = signature(body, TIMESTAMP);
        assert_eq!(
            valid_signature,
            "809fb0fc98632d8a7747382b302e2c44b2dda81de8f2c0d89f3b775a38ee5dab"
        );
        let mut substituted = body.to_vec();
        let index = substituted.iter().position(|byte| *byte == b'd').unwrap();
        substituted[index] = b'x';
        assert_eq!(
            verify_webhook(
                TEST_SECRET,
                &valid_signature,
                TIMESTAMP,
                &substituted,
                1_784_912_460,
                freshness(),
            ),
            Err(WebhookError::InvalidSignature)
        );
        assert_eq!(
            verify_webhook(
                TEST_SECRET,
                &valid_signature,
                "1784912401",
                body,
                1_784_912_460,
                freshness(),
            ),
            Err(WebhookError::InvalidSignature)
        );
        assert_eq!(
            verify_webhook(
                TEST_SECRET,
                &valid_signature,
                TIMESTAMP,
                body,
                1_784_913_000,
                freshness(),
            ),
            Err(WebhookError::StaleTimestamp)
        );
        assert_eq!(
            verify_webhook(
                TEST_SECRET,
                &valid_signature,
                TIMESTAMP,
                body,
                1_784_912_300,
                freshness(),
            ),
            Err(WebhookError::FutureTimestamp)
        );
    }

    #[test]
    fn unsupported_or_missing_event_contracts_fail_closed_after_authentication() {
        let unsupported =
            br#"{"type":"ramp.settlement.completed","data":{"settlementId":"fixture"}}"#;
        assert_eq!(
            verify_webhook(
                TEST_SECRET,
                &signature(unsupported, TIMESTAMP),
                TIMESTAMP,
                unsupported,
                1_784_912_460,
                freshness(),
            ),
            Err(WebhookError::UnsupportedEvent)
        );
        let missing = br#"{"type":"deposit.completed","data":{}}"#;
        assert_eq!(
            verify_webhook(
                TEST_SECRET,
                &signature(missing, TIMESTAMP),
                TIMESTAMP,
                missing,
                1_784_912_460,
                freshness(),
            ),
            Err(WebhookError::MissingReference)
        );
    }

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "activebridge-ntzs-{name}-{}-{}.bin",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[test]
    fn replay_journal_rejects_duplicates_across_restart_and_corruption() {
        let path = path("replay");
        let _ = std::fs::remove_file(&path);
        let identity = verify("deposit").replay_identity();
        let mut journal = NtzsReplayJournal::default();
        journal.record_durable(identity, &path).unwrap();
        assert_eq!(journal.len(), 1);
        let mut loaded = NtzsReplayJournal::load(&path).unwrap();
        assert_eq!(loaded.record(identity), Err(WebhookError::Duplicate));

        let mut bytes = std::fs::read(&path).unwrap();
        bytes[10] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(NtzsReplayJournal::load(&path), Err(WebhookError::Persistence));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_replay_persistence_does_not_mutate_memory() {
        let directory = path("replay-directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let identity = verify("deposit").replay_identity();
        let mut journal = NtzsReplayJournal::default();
        assert_eq!(journal.record_durable(identity, &directory), Err(WebhookError::Persistence));
        assert!(journal.is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn documented_error_codes_are_exact_and_extensions_are_unknown() {
        assert_eq!(
            NtzsErrorCode::parse("insufficient_balance"),
            NtzsErrorCode::InsufficientBalance
        );
        assert_eq!(NtzsErrorCode::parse("network_error"), NtzsErrorCode::NetworkError);
        assert_eq!(NtzsErrorCode::parse("temporarily_successful"), NtzsErrorCode::Unknown);
    }
}
