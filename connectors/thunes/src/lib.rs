#![forbid(unsafe_code)]

//! Fail-closed Thunes Money Transfer API v2 adapter for ActiveBridge.
//!
//! This crate deliberately does not own sockets or credentials. It fixes the provider request and
//! response contract, derives deterministic external IDs, and normalizes authenticated provider
//! responses below ActiveChain finality. The isolated connector host must enforce the exact HTTPS
//! origin, resolve opaque credential handles, apply deadlines, and persist observations before ack.

use activechain_payment_types::{PaymentAttemptId, PaymentQuoteId};
use activechain_protocol_types::Digest384;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::fmt::Write as _;

mod amount;
mod recovery;
mod request;
mod response;

pub use amount::{AmountError, parse_atomic_units, parse_decimal};
pub use recovery::{RecoveryAction, ThunesAttemptPhase, ThunesRecoveryState};
pub use request::{HttpMethod, QuotationMode, QuotationRequest, ThunesRequest, ThunesRequests};
pub use response::{
    ThunesCallbackHint, ThunesObservationContext, ThunesQuotation, ThunesTransaction,
    authenticated_transaction_observation, map_status_class, parse_callback_hint, parse_quotation,
    parse_transaction, provider_reference_commitment,
};

/// Money Transfer v2 API prefix. Environment-specific HTTPS origins are provided during account
/// onboarding and remain under connector-host allow-list policy rather than being hard-coded here.
pub const MONEY_TRANSFER_V2_PREFIX: &str = "/v2/money-transfer";
pub const MAX_BODY_BYTES: usize = 256 * 1024;
pub const MAX_EXTERNAL_ID_BYTES: usize = 64;
const EXTERNAL_ID_DIGEST_BYTES: usize = 24;
const QUOTE_EXTERNAL_ID_DOMAIN: &[u8] = b"ACTIVECHAIN-THUNES-QUOTE-EXTERNAL-ID-V1";
const TRANSACTION_EXTERNAL_ID_DOMAIN: &[u8] = b"ACTIVECHAIN-THUNES-TRANSACTION-EXTERNAL-ID-V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterError {
    AmountMismatch,
    BodyTooLarge,
    FieldSubstitution,
    InvalidExternalId,
    InvalidObservation,
    InvalidRequest,
    InvalidResponse,
    OriginNotAuthorized,
}

/// Bounded provider response returned by an operator-owned HTTP backend.
#[derive(Clone, Eq, PartialEq)]
pub struct ThunesResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl core::fmt::Debug for ThunesResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ThunesResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Backend-only transport boundary. Implementations MUST use TLS, HTTP Basic Authentication, the
/// connector-host deadline, and MUST NOT log either credential or raw PII-bearing request bodies.
pub trait ThunesTransport {
    type Error;

    fn send(
        &self,
        origin: &str,
        api_key: &str,
        api_secret: &str,
        request: &ThunesRequest,
    ) -> Result<ThunesResponse, Self::Error>;
}

/// Thin executor whose origin is fixed at construction by the connector host policy.
#[derive(Clone)]
pub struct ThunesAdapter<T> {
    origin: String,
    transport: T,
}

impl<T> ThunesAdapter<T> {
    pub fn new(origin: String, transport: T) -> Result<Self, AdapterError> {
        if !valid_https_origin(&origin) {
            return Err(AdapterError::OriginNotAuthorized);
        }
        Ok(Self { origin, transport })
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

impl<T: ThunesTransport> ThunesAdapter<T> {
    pub fn execute(
        &self,
        api_key: &str,
        api_secret: &str,
        request: &ThunesRequest,
    ) -> Result<ThunesResponse, ExecuteError<T::Error>> {
        if api_key.is_empty() || api_secret.is_empty() {
            return Err(ExecuteError::Adapter(AdapterError::InvalidRequest));
        }
        let response = self
            .transport
            .send(&self.origin, api_key, api_secret, request)
            .map_err(ExecuteError::Transport)?;
        if !(200..=599).contains(&response.status) || response.body.len() > MAX_BODY_BYTES {
            return Err(ExecuteError::Adapter(AdapterError::InvalidResponse));
        }
        Ok(response)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecuteError<T> {
    Adapter(AdapterError),
    Transport(T),
}

/// 192-bit domain-separated ID encoded in 52 ASCII bytes, below Thunes' 64-byte limit.
#[must_use]
pub fn quote_external_id(quote: PaymentQuoteId) -> String {
    external_id("acq", QUOTE_EXTERNAL_ID_DOMAIN, quote.digest())
}

/// 192-bit domain-separated ID encoded in 52 ASCII bytes, below Thunes' 64-byte limit.
#[must_use]
pub fn transaction_external_id(attempt: PaymentAttemptId) -> String {
    external_id("act", TRANSACTION_EXTERNAL_ID_DOMAIN, attempt.digest())
}

fn external_id(prefix: &str, domain: &[u8], digest: &Digest384) -> String {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(digest.as_bytes());
    let mut bytes = [0_u8; EXTERNAL_ID_DIGEST_BYTES];
    hasher.finalize_xof().read(&mut bytes);
    let mut value = String::with_capacity(prefix.len() + 1 + bytes.len() * 2);
    value.push_str(prefix);
    value.push('_');
    for byte in bytes {
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn valid_https_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("https://") else {
        return false;
    };
    !rest.is_empty()
        && !rest.contains('/')
        && !rest.contains('?')
        && !rest.contains('#')
        && !rest.contains('@')
        && !rest.chars().any(char::is_whitespace)
        && rest.len() <= 253
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::Digest384;

    #[derive(Clone, Copy)]
    struct RecordingTransport;

    impl ThunesTransport for RecordingTransport {
        type Error = ();

        fn send(
            &self,
            origin: &str,
            api_key: &str,
            api_secret: &str,
            _request: &ThunesRequest,
        ) -> Result<ThunesResponse, Self::Error> {
            assert_eq!(origin, "https://sandbox.example.thunes.invalid");
            assert_eq!(api_key, "key");
            assert_eq!(api_secret, "secret");
            Ok(ThunesResponse { status: 200, body: b"{}".to_vec() })
        }
    }

    #[test]
    fn external_ids_are_deterministic_domain_separated_and_bounded() {
        let digest = Digest384::new([7; 48]);
        let quote = PaymentQuoteId::new(digest).unwrap();
        let attempt = PaymentAttemptId::new(digest).unwrap();
        let first = quote_external_id(quote);
        assert_eq!(first, quote_external_id(quote));
        assert_ne!(first, transaction_external_id(attempt));
        assert!(first.len() <= MAX_EXTERNAL_ID_BYTES);
        assert!(transaction_external_id(attempt).len() <= MAX_EXTERNAL_ID_BYTES);
    }

    #[test]
    fn origin_must_be_a_bare_https_origin() {
        assert!(ThunesAdapter::new("http://example.com".into(), RecordingTransport).is_err());
        assert!(ThunesAdapter::new("https://example.com/path".into(), RecordingTransport).is_err());
        assert!(ThunesAdapter::new("https://example.com".into(), RecordingTransport).is_ok());
    }

    #[test]
    fn execution_requires_both_basic_auth_components() {
        let adapter = ThunesAdapter::new(
            "https://sandbox.example.thunes.invalid".into(),
            RecordingTransport,
        )
        .unwrap();
        let request = ThunesRequests::list_payers(1, 50).unwrap();
        assert!(matches!(
            adapter.execute("", "secret", &request),
            Err(ExecuteError::Adapter(AdapterError::InvalidRequest))
        ));
        assert_eq!(adapter.execute("key", "secret", &request).unwrap().status, 200);
    }
}
