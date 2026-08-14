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
    pub source_currency: String,
    pub source_precision: u8,
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
        source_currency: string_field(source, "currency", 3)?,
        source_amount: scalar_amount(source, "amount")?,
        destination_currency: string_field(destination, "currency", 3)?,
        destination_amount: scalar_amount(destination, "amount")?,
        fee_currency: string_field(fee, "currency", 3)?,
        fee_amount: scalar_amount(fee, "amount")?,
        expiration_date: string_field(&root, "expiration_date", 64)?,
    })
}

pub fn parse_transaction(body: &[u8]) -> Result<ThunesTransaction, AdapterError> {
    let root = owned_object(body)?;
    let source = object_field(&root, "source")?;
    let destination = object_field(&root, "destination")?;
    Ok(ThunesTransaction {
        id: u64_field(&root, "id")?,
        external_id: string_field(&root, "external_id", 64)?,
        status: string_field(&root, "status", 5)?,
        status_message: string_field(&root, "status_message", 64)?,
        status_class: string_field(&root, "status_class", 1)?,
        status_class_message: string_field(&root, "status_class_message", 64)?,
        source_currency: string_field(source, "currency", 3)?,
        source_amount: scalar_amount(source, "amount")?,
        destination_currency: string_field(destination, "currency", 3)?,
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

/// Convert only a response obtained through authenticated Thunes API access into an observation.
/// This deliberately yields `ConnectorAuthenticated`, never `ActiveChainFinalized`.
pub fn authenticated_transaction_observation(
    context: &ThunesObservationContext,
    response_body: &[u8],
) -> Result<ProviderObservationV1, AdapterError> {
    let transaction = parse_transaction(response_body)?;
    if transaction.external_id != context.transaction_external_id
        || transaction.source_currency != context.source_currency
        || parse_atomic_units(&transaction.source_amount, context.source_precision)
            .map_err(|_| AdapterError::AmountMismatch)?
            != context.amount.atomic_units()
    {
        return Err(AdapterError::AmountMismatch);
    }
    let provider_reference = provider_reference_commitment(transaction.id, &transaction.external_id)?;
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
    Ok(commitment(
        REFERENCE_DOMAIN,
        &[&transaction_id.to_be_bytes(), external_id.as_bytes()],
    ))
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
    root.get(name)
        .and_then(Value::as_object)
        .ok_or(AdapterError::InvalidResponse)
}

fn string_field(
    root: &serde_json::Map<String, Value>,
    name: &str,
    max_len: usize,
) -> Result<String, AdapterError> {
    let value = root
        .get(name)
        .and_then(Value::as_str)
        .ok_or(AdapterError::InvalidResponse)?;
    if value.is_empty() || value.len() > max_len {
        return Err(AdapterError::InvalidResponse);
    }
    Ok(value.to_owned())
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

    fn transaction(status_class: &str) -> Vec<u8> {
        format!(
            r#"{{"id":17,"status":"70000","status_message":"COMPLETED","status_class":"{status_class}","status_class_message":"COMPLETED","external_id":"act_deadbeef","source":{{"currency":"EUR","amount":10.00}},"destination":{{"currency":"KES","amount":1500}},"future_field":{{"safe":"ignored"}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn status_classes_are_closed_and_future_classes_are_unknown() {
        assert_eq!(map_status_class("1"), ProviderOperationState::Pending);
        assert_eq!(map_status_class("7"), ProviderOperationState::Succeeded);
        assert_eq!(map_status_class("8"), ProviderOperationState::Reversed);
        assert_eq!(map_status_class("9"), ProviderOperationState::Rejected);
        assert_eq!(map_status_class("A"), ProviderOperationState::Unknown);
    }

    #[test]
    fn response_parser_tolerates_additive_fields() {
        let parsed = parse_transaction(&transaction("7")).unwrap();
        assert_eq!(parsed.external_id, "act_deadbeef");
        assert_eq!(parsed.status_class, "7");
    }

    #[test]
    fn authenticated_poll_becomes_connector_evidence_not_finality() {
        let context = ThunesObservationContext {
            chain: ChainId::new(digest(1)),
            connector: ConnectorId::new(digest(2)).unwrap(),
            attempt: PaymentAttemptId::new(digest(3)).unwrap(),
            intent: PaymentIntentId::new(digest(4)).unwrap(),
            provider_account_commitment: digest(5),
            transaction_external_id: "act_deadbeef".into(),
            sequence: 1,
            amount: AssetAmountV1::new(AssetId::new(digest(6)), 1000).unwrap(),
            source_currency: "EUR".into(),
            source_precision: 2,
            occurred_at: 100,
            observed_at: 101,
        };
        let observation = authenticated_transaction_observation(&context, &transaction("7")).unwrap();
        assert_eq!(observation.state(), ProviderOperationState::Succeeded);
        assert_eq!(observation.evidence_class(), EvidenceClass::ConnectorAuthenticated);
    }
}
