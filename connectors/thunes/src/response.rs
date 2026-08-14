use activechain_payment_types::{
    AssetAmountV1, ConnectorId, EvidenceClass, PaymentAttemptId, PaymentIntentId,
    ProviderObservationV1, ProviderOperationState,
};
use activechain_protocol_types::{ChainId, Digest384};
use serde_json::Value;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{AdapterError, MAX_BODY_BYTES, amount::parse_atomic_units};

const REFERENCE_DOMAIN: &[u8] = b"ACTIVECHAIN-THUNES-PROVIDER-REFERENCE-V1";
const PAYLOAD_DOMAIN: &[u8] = b"ACTIVECHAIN-THUNES-AUTHENTICATED-RESPONSE-V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThunesQuotation {
    pub id: u64,
    pub external_id: String,
    pub source_currency: String,
    pub source_amount: Value,
    pub destination_currency: String,
    pub destination_amount: Value,
    pub fee_currency: String,
    pub fee_amount: Value,
    pub expiration_date: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThunesTransaction {
    pub id: u64,
    pub external_id: String,
    pub status: String,
    pub status_message: String,
    pub status_class: String,
    pub status_class_message: String,
    pub source_currency: String,
    pub source_amount: Value,
    pub destination_currency: String,
    pub destination_amount: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThunesCallbackHint {
    pub id: u64,
    pub external_id: String,
    pub status_class: String,
}

/// Which Thunes amount the ActiveBridge route binds to. A funding asset may bind to `Source`,
/// while a fiat/tokenized-fiat payout route can bind to the beneficiary's `Destination` amount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderAmountSide {
    Source,
    Destination,
}

/// ActiveBridge bindings supplied independently of provider JSON.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThunesObservationContext {
    pub chain: ChainId,
    pub connector: ConnectorId,
    pub attempt: PaymentAttemptId,
    pub intent: PaymentIntentId,
    pub provider_account_commitment: Digest384,
    pub transaction_external_id: String,
    pub sequence: u64,
    pub amount: AssetAmountV1,
    pub provider_amount_side: ProviderAmountSide,
    pub provider_currency: String,
    pub provider_precision: u8,
    pub occurred_at: u64,
    pub observed_at: u64,
}

pub fn parse_quotation(body: &[u8]) -> Result<ThunesQuotation, AdapterError> {
    let root = owned_object(body)?;
    let source = object_field(&root, "source")?;
    let destination = object_field(&root, "destination")?;
    let fee = object_field(&root, "fee")?;
    Ok(ThunesQuotation {
        id: u64_field(&root, "id")?,
        external_id: string_field(&root, "external_id", 64)?,
        source_currency: currency_field(source, "currency")?,
        source_amount: scalar_amount(source, "amount")?,
        destination_currency: currency_field(destination, "currency")?,
        destination_amount: scalar_amount(destination, "amount")?,
        fee_currency: currency_field(fee, "currency")?,
        fee_amount: scalar_amount(fee, "amount")?,
        expiration_date: string_field(&root, "expiration_date", 64)?,
    })
}

pub fn parse_transaction(body: &[u8]) -> Result<ThunesTransaction, AdapterError> {
    let root = owned_object(body)?;
    let source = object_field(&root, "source")?;
    let destination = object_field(&root, "destination")?;
    let status = string_field(&root, "status", 5)?;
    let status_message = string_field(&root, "status_message", 64)?;
    let status_class = string_field(&root, "status_class", 1)?;
    let status_class_message = string_field(&root, "status_class_message", 64)?;
    validate_status_binding(&status, &status_class, &status_class_message)?;
    Ok(ThunesTransaction {
        id: u64_field(&root, "id")?,
        external_id: string_field(&root, "external_id", 64)?,
        status,
        status_message,
        status_class,
        status_class_message,
        source_currency: currency_field(source, "currency")?,
        source_amount: scalar_amount(source, "amount")?,
        destination_currency: currency_field(destination, "currency")?,
        destination_amount: scalar_amount(destination, "amount")?,
    })
}

/// Thunes Money Transfer v2 does not document a callback signature. Callback JSON is therefore
/// only a wake-up hint: the connector must poll with Basic Auth before recording provider evidence.
pub fn parse_callback_hint(body: &[u8]) -> Result<ThunesCallbackHint, AdapterError> {
    let root = owned_object(body)?;
    Ok(ThunesCallbackHint {
        id: u64_field(&root, "id")?,
        external_id: string_field(&root, "external_id", 64)?,
        status_class: string_field(&root, "status_class", 1)?,
    })
}

#[must_use]
pub fn map_status_class(status_class: &str) -> ProviderOperationState {
    match status_class {
        "1" | "2" | "5" | "6" => ProviderOperationState::Pending,
        "3" | "9" => ProviderOperationState::Rejected,
        "4" => ProviderOperationState::Cancelled,
        "7" => ProviderOperationState::Succeeded,
        "8" => ProviderOperationState::Reversed,
        _ => ProviderOperationState::Unknown,
    }
}

/// Whether an authenticated provider status proves the confirm call reached a confirmed-or-later
/// state. This deliberately treats rejection/cancellation after confirmation as confirmation having
/// reached Thunes; CREATED alone does not.
#[must_use]
pub fn confirmed_or_later(status_class: &str) -> bool {
    matches!(status_class, "2" | "4" | "5" | "6" | "7" | "8" | "9")
}

/// Convert only a response obtained through authenticated Thunes API access into an observation.
/// This deliberately yields `ConnectorAuthenticated`, never `ActiveChainFinalized`.
pub fn authenticated_transaction_observation(
    context: &ThunesObservationContext,
    response_body: &[u8],
) -> Result<ProviderObservationV1, AdapterError> {
    let transaction = parse_transaction(response_body)?;
    if transaction.external_id != context.transaction_external_id {
        return Err(AdapterError::FieldSubstitution);
    }
    let (currency, provider_amount) = match context.provider_amount_side {
        ProviderAmountSide::Source => (&transaction.source_currency, &transaction.source_amount),
        ProviderAmountSide::Destination => {
            (&transaction.destination_currency, &transaction.destination_amount)
        }
    };
    if currency != &context.provider_currency
        || parse_atomic_units(provider_amount, context.provider_precision)
            .map_err(|_| AdapterError::AmountMismatch)?
            != context.amount.atomic_units()
    {
        return Err(AdapterError::AmountMismatch);
    }
    let provider_reference =
        provider_reference_commitment(transaction.id, &transaction.external_id)?;
    let payload = commitment(PAYLOAD_DOMAIN, &[response_body]);
    ProviderObservationV1::new(
        context.chain,
        context.connector,
        context.attempt,
        context.intent,
        context.provider_account_commitment,
        provider_reference,
        context.sequence,
        map_status_class(&transaction.status_class),
        context.amount,
        context.occurred_at,
        context.observed_at,
        EvidenceClass::ConnectorAuthenticated,
        payload,
    )
    .map_err(|_| AdapterError::InvalidObservation)
}

pub fn provider_reference_commitment(
    transaction_id: u64,
    external_id: &str,
) -> Result<Digest384, AdapterError> {
    if transaction_id == 0 || external_id.is_empty() || external_id.len() > 64 {
        return Err(AdapterError::InvalidResponse);
    }
    Ok(commitment(REFERENCE_DOMAIN, &[&transaction_id.to_be_bytes(), external_id.as_bytes()]))
}

fn validate_status_binding(
    status: &str,
    status_class: &str,
    status_class_message: &str,
) -> Result<(), AdapterError> {
    if status.len() != 5
        || !status.bytes().all(|byte| byte.is_ascii_digit())
        || status_class.len() != 1
        || !status_class.bytes().all(|byte| byte.is_ascii_digit())
        || status.as_bytes()[0] != status_class.as_bytes()[0]
    {
        return Err(AdapterError::InvalidResponse);
    }
    let expected = match status_class {
        "1" => Some("CREATED"),
        "2" => Some("CONFIRMED"),
        "3" => Some("REJECTED"),
        "4" => Some("CANCELLED"),
        "5" => Some("SUBMITTED"),
        "6" => Some("AVAILABLE"),
        "7" => Some("COMPLETED"),
        "8" => Some("REVERSED"),
        "9" => Some("DECLINED"),
        _ => None,
    };
    if expected.is_some_and(|value| value != status_class_message) {
        return Err(AdapterError::InvalidResponse);
    }
    Ok(())
}

fn owned_object(body: &[u8]) -> Result<serde_json::Map<String, Value>, AdapterError> {
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(AdapterError::InvalidResponse);
    }
    match serde_json::from_slice::<Value>(body).map_err(|_| AdapterError::InvalidResponse)? {
        Value::Object(map) => Ok(map),
        _ => Err(AdapterError::InvalidResponse),
    }
}

fn object_field<'a>(
    root: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a serde_json::Map<String, Value>, AdapterError> {
    root.get(name).and_then(Value::as_object).ok_or(AdapterError::InvalidResponse)
}

fn string_field(
    root: &serde_json::Map<String, Value>,
    name: &str,
    max_len: usize,
) -> Result<String, AdapterError> {
    let value = root.get(name).and_then(Value::as_str).ok_or(AdapterError::InvalidResponse)?;
    if value.is_empty() || value.len() > max_len {
        return Err(AdapterError::InvalidResponse);
    }
    Ok(value.to_owned())
}

fn currency_field(
    root: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<String, AdapterError> {
    let value = string_field(root, name, 3)?;
    if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(AdapterError::InvalidResponse);
    }
    Ok(value)
}

fn u64_field(root: &serde_json::Map<String, Value>, name: &str) -> Result<u64, AdapterError> {
    root.get(name)
        .and_then(Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or(AdapterError::InvalidResponse)
}

fn scalar_amount(root: &serde_json::Map<String, Value>, name: &str) -> Result<Value, AdapterError> {
    match root.get(name) {
        Some(Value::Number(value)) => Ok(Value::Number(value.clone())),
        Some(Value::String(value)) if !value.is_empty() => Ok(Value::String(value.clone())),
        _ => Err(AdapterError::InvalidResponse),
    }
}

fn commitment(domain: &[u8], parts: &[&[u8]]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    for part in parts {
        hasher.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(part);
    }
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::AssetId;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn transaction(status: &str, status_class: &str, class_message: &str) -> Vec<u8> {
        format!(
            r#"{{"id":17,"status":"{status}","status_message":"DETAIL","status_class":"{status_class}","status_class_message":"{class_message}","external_id":"act_deadbeef","source":{{"currency":"EUR","amount":10.00}},"destination":{{"currency":"TZS","amount":1500}},"future_field":{{"safe":"ignored"}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn status_classes_are_closed_and_future_classes_are_unknown() {
        assert_eq!(map_status_class("1"), ProviderOperationState::Pending);
        assert_eq!(map_status_class("7"), ProviderOperationState::Succeeded);
        assert_eq!(map_status_class("8"), ProviderOperationState::Reversed);
        assert_eq!(map_status_class("9"), ProviderOperationState::Rejected);
        assert_eq!(map_status_class("0"), ProviderOperationState::Unknown);
    }

    #[test]
    fn response_parser_tolerates_additive_fields_but_rejects_status_substitution() {
        let body = transaction("70000", "7", "COMPLETED");
        let parsed = parse_transaction(&body).unwrap();
        assert_eq!(parsed.external_id, "act_deadbeef");
        assert_eq!(parsed.status_class, "7");
        assert!(parse_transaction(&transaction("70000", "3", "REJECTED")).is_err());
        assert!(parse_transaction(&transaction("70000", "7", "SUBMITTED")).is_err());
    }

    #[test]
    fn authenticated_poll_can_bind_exact_tanzania_destination_amount() {
        let context = ThunesObservationContext {
            chain: ChainId::new(digest(1)),
            connector: ConnectorId::new(digest(2)).unwrap(),
            attempt: PaymentAttemptId::new(digest(3)).unwrap(),
            intent: PaymentIntentId::new(digest(4)).unwrap(),
            provider_account_commitment: digest(5),
            transaction_external_id: "act_deadbeef".into(),
            sequence: 1,
            amount: AssetAmountV1::new(AssetId::new(digest(6)), 1500).unwrap(),
            provider_amount_side: ProviderAmountSide::Destination,
            provider_currency: "TZS".into(),
            provider_precision: 0,
            occurred_at: 100,
            observed_at: 101,
        };
        let body = transaction("70000", "7", "COMPLETED");
        let observation = authenticated_transaction_observation(&context, &body).unwrap();
        assert_eq!(observation.state(), ProviderOperationState::Succeeded);
        assert_eq!(observation.evidence_class(), EvidenceClass::ConnectorAuthenticated);

        let wrong_currency =
            ThunesObservationContext { provider_currency: "KES".into(), ..context.clone() };
        assert_eq!(
            authenticated_transaction_observation(&wrong_currency, &body),
            Err(AdapterError::AmountMismatch)
        );
    }

    #[test]
    fn callback_remains_a_hint_not_an_observation() {
        let body = transaction("50000", "5", "SUBMITTED");
        let hint = parse_callback_hint(&body).unwrap();
        assert_eq!(hint.external_id, "act_deadbeef");
        assert_eq!(hint.status_class, "5");
    }

    #[test]
    fn confirm_recovery_uses_authenticated_status_class() {
        assert!(!confirmed_or_later("1"));
        assert!(confirmed_or_later("2"));
        assert!(confirmed_or_later("7"));
        assert!(confirmed_or_later("9"));
    }
}
