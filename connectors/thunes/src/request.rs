use serde_json::{Map, Value, json};
use std::fmt;

use crate::{AdapterError, MAX_BODY_BYTES};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ThunesRequest {
    method: HttpMethod,
    path: String,
    body: Vec<u8>,
    simulated: bool,
}

impl ThunesRequest {
    fn new(
        method: HttpMethod,
        path: String,
        body: Vec<u8>,
        simulated: bool,
    ) -> Result<Self, AdapterError> {
        if !path.starts_with("/v2/money-transfer/")
            || path.len() > 512
            || body.len() > MAX_BODY_BYTES
        {
            return Err(AdapterError::InvalidRequest);
        }
        if method == HttpMethod::Get && !body.is_empty() {
            return Err(AdapterError::InvalidRequest);
        }
        if method == HttpMethod::Post
            && !matches!(serde_json::from_slice::<Value>(&body), Ok(Value::Object(_)))
            && !body.is_empty()
        {
            return Err(AdapterError::InvalidRequest);
        }
        Ok(Self { method, path, body, simulated })
    }

    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Whether the connector host must attach Thunes' `x-simulated-transaction: true` header.
    /// This is intentionally exposed as metadata rather than embedded in the provider JSON body.
    #[must_use]
    pub const fn simulated(&self) -> bool {
        self.simulated
    }
}

impl fmt::Debug for ThunesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThunesRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body_bytes", &self.body.len())
            .field("simulated", &self.simulated)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotationMode {
    SourceAmount,
    DestinationAmount,
}

impl QuotationMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SourceAmount => "SOURCE_AMOUNT",
            Self::DestinationAmount => "DESTINATION_AMOUNT",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotationRequest<'a> {
    pub external_id: &'a str,
    pub payer_id: u64,
    pub mode: QuotationMode,
    pub transaction_type: &'a str,
    pub source_country_iso_code: &'a str,
    pub source_currency: &'a str,
    pub source_amount: Option<&'a str>,
    pub destination_currency: &'a str,
    pub destination_amount: Option<&'a str>,
}

pub struct ThunesRequests;

impl ThunesRequests {
    pub fn list_payers(page: u16, per_page: u8) -> Result<ThunesRequest, AdapterError> {
        if page == 0 || !(1..=100).contains(&per_page) {
            return Err(AdapterError::InvalidRequest);
        }
        ThunesRequest::new(
            HttpMethod::Get,
            format!("/v2/money-transfer/payers?page={page}&per_page={per_page}"),
            Vec::new(),
            false,
        )
    }

    /// Retrieves one payer including its current transaction-type requirements. These requirements
    /// are intentionally data-driven because Thunes may add payer-specific required fields without
    /// changing the Money Transfer major API version.
    pub fn get_payer(payer_id: u64) -> Result<ThunesRequest, AdapterError> {
        if payer_id == 0 {
            return Err(AdapterError::InvalidRequest);
        }
        ThunesRequest::new(
            HttpMethod::Get,
            format!("/v2/money-transfer/payers/{payer_id}"),
            Vec::new(),
            false,
        )
    }

    pub fn list_countries(page: u16, per_page: u8) -> Result<ThunesRequest, AdapterError> {
        if page == 0 || !(1..=100).contains(&per_page) {
            return Err(AdapterError::InvalidRequest);
        }
        ThunesRequest::new(
            HttpMethod::Get,
            format!("/v2/money-transfer/countries?page={page}&per_page={per_page}"),
            Vec::new(),
            false,
        )
    }

    pub fn credit_party_information(
        payer_id: u64,
        transaction_type: &str,
        credit_party_identifier: Value,
    ) -> Result<ThunesRequest, AdapterError> {
        Self::credit_party_request(
            payer_id,
            transaction_type,
            "credit-party-information",
            credit_party_identifier,
            None,
            None,
        )
    }

    /// Basic CPV form for payers that require only account identifiers.
    pub fn credit_party_verification(
        payer_id: u64,
        transaction_type: &str,
        credit_party_identifier: Value,
    ) -> Result<ThunesRequest, AdapterError> {
        Self::credit_party_verification_with_entity(
            payer_id,
            transaction_type,
            credit_party_identifier,
            None,
            None,
        )
    }

    /// CPV form that can carry the payer-required receiving entity. Thunes documents beneficiary
    /// or receiving-business fields as conditionally required based on payer discovery, so the
    /// connector must not hard-code one global schema.
    pub fn credit_party_verification_with_entity(
        payer_id: u64,
        transaction_type: &str,
        credit_party_identifier: Value,
        beneficiary: Option<Value>,
        receiving_business: Option<Value>,
    ) -> Result<ThunesRequest, AdapterError> {
        if beneficiary.is_some() && receiving_business.is_some() {
            return Err(AdapterError::InvalidRequest);
        }
        Self::credit_party_request(
            payer_id,
            transaction_type,
            "credit-party-verification",
            credit_party_identifier,
            beneficiary,
            receiving_business,
        )
    }

    fn credit_party_request(
        payer_id: u64,
        transaction_type: &str,
        operation: &str,
        credit_party_identifier: Value,
        beneficiary: Option<Value>,
        receiving_business: Option<Value>,
    ) -> Result<ThunesRequest, AdapterError> {
        validate_token(transaction_type, 16)?;
        if payer_id == 0 || !matches!(credit_party_identifier, Value::Object(_)) {
            return Err(AdapterError::InvalidRequest);
        }
        if beneficiary.as_ref().is_some_and(|value| !matches!(value, Value::Object(_)))
            || receiving_business.as_ref().is_some_and(|value| !matches!(value, Value::Object(_)))
        {
            return Err(AdapterError::InvalidRequest);
        }
        let mut fields = Map::new();
        fields.insert("credit_party_identifier".to_owned(), credit_party_identifier);
        if let Some(value) = beneficiary {
            fields.insert("beneficiary".to_owned(), value);
        }
        if let Some(value) = receiving_business {
            fields.insert("receiving_business".to_owned(), value);
        }
        let body =
            serde_json::to_vec(&Value::Object(fields)).map_err(|_| AdapterError::InvalidRequest)?;
        ThunesRequest::new(
            HttpMethod::Post,
            format!("/v2/money-transfer/payers/{payer_id}/{transaction_type}/{operation}"),
            body,
            false,
        )
    }

    pub fn create_quotation(input: QuotationRequest<'_>) -> Result<ThunesRequest, AdapterError> {
        validate_external_id(input.external_id)?;
        validate_token(input.transaction_type, 16)?;
        validate_iso3(input.source_country_iso_code)?;
        validate_currency(input.source_currency)?;
        validate_currency(input.destination_currency)?;
        if input.payer_id == 0 {
            return Err(AdapterError::InvalidRequest);
        }
        match input.mode {
            QuotationMode::SourceAmount
                if input.source_amount.is_none() || input.destination_amount.is_some() =>
            {
                return Err(AdapterError::InvalidRequest);
            }
            QuotationMode::DestinationAmount
                if input.destination_amount.is_none() || input.source_amount.is_some() =>
            {
                return Err(AdapterError::InvalidRequest);
            }
            _ => {}
        }
        if let Some(value) = input.source_amount {
            validate_decimal_text(value)?;
        }
        if let Some(value) = input.destination_amount {
            validate_decimal_text(value)?;
        }
        let source_amount =
            input.source_amount.map_or(Value::Null, |value| Value::String(value.to_owned()));
        let destination_amount =
            input.destination_amount.map_or(Value::Null, |value| Value::String(value.to_owned()));
        let body = serde_json::to_vec(&json!({
            "external_id": input.external_id,
            "payer_id": input.payer_id.to_string(),
            "mode": input.mode.as_str(),
            "transaction_type": input.transaction_type,
            "source": {
                "amount": source_amount,
                "currency": input.source_currency,
                "country_iso_code": input.source_country_iso_code,
            },
            "destination": {
                "amount": destination_amount,
                "currency": input.destination_currency,
            }
        }))
        .map_err(|_| AdapterError::InvalidRequest)?;
        ThunesRequest::new(
            HttpMethod::Post,
            "/v2/money-transfer/quotations".to_owned(),
            body,
            false,
        )
    }

    pub fn get_quotation_by_external_id(external_id: &str) -> Result<ThunesRequest, AdapterError> {
        validate_external_id(external_id)?;
        ThunesRequest::new(
            HttpMethod::Get,
            format!("/v2/money-transfer/quotations/ext-{external_id}"),
            Vec::new(),
            false,
        )
    }

    pub fn create_transaction(
        quotation_external_id: &str,
        transaction_external_id: &str,
        mut provider_fields: Map<String, Value>,
        simulated: bool,
    ) -> Result<ThunesRequest, AdapterError> {
        validate_external_id(quotation_external_id)?;
        validate_external_id(transaction_external_id)?;
        if provider_fields.contains_key("external_id") {
            return Err(AdapterError::FieldSubstitution);
        }
        provider_fields
            .insert("external_id".to_owned(), Value::String(transaction_external_id.to_owned()));
        let body = serde_json::to_vec(&Value::Object(provider_fields))
            .map_err(|_| AdapterError::InvalidRequest)?;
        ThunesRequest::new(
            HttpMethod::Post,
            format!("/v2/money-transfer/quotations/ext-{quotation_external_id}/transactions"),
            body,
            simulated,
        )
    }

    pub fn confirm_transaction(external_id: &str) -> Result<ThunesRequest, AdapterError> {
        validate_external_id(external_id)?;
        ThunesRequest::new(
            HttpMethod::Post,
            format!("/v2/money-transfer/transactions/ext-{external_id}/confirm"),
            Vec::new(),
            false,
        )
    }

    pub fn get_transaction_by_external_id(
        external_id: &str,
    ) -> Result<ThunesRequest, AdapterError> {
        validate_external_id(external_id)?;
        ThunesRequest::new(
            HttpMethod::Get,
            format!("/v2/money-transfer/transactions/ext-{external_id}"),
            Vec::new(),
            false,
        )
    }
}

fn validate_external_id(value: &str) -> Result<(), AdapterError> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AdapterError::InvalidExternalId);
    }
    Ok(())
}

fn validate_token(value: &str, max_len: usize) -> Result<(), AdapterError> {
    if value.is_empty()
        || value.len() > max_len
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(AdapterError::InvalidRequest);
    }
    Ok(())
}

fn validate_iso3(value: &str) -> Result<(), AdapterError> {
    if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(AdapterError::InvalidRequest);
    }
    Ok(())
}

fn validate_currency(value: &str) -> Result<(), AdapterError> {
    validate_iso3(value)
}

fn validate_decimal_text(value: &str) -> Result<(), AdapterError> {
    if value.is_empty()
        || value.starts_with('-')
        || value.starts_with('+')
        || value.contains('e')
        || value.contains('E')
    {
        return Err(AdapterError::InvalidRequest);
    }
    let mut parts = value.split('.');
    let whole = parts.next().ok_or(AdapterError::InvalidRequest)?;
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_some_and(|digits| {
            digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(AdapterError::InvalidRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn quote_is_exact_and_external_id_is_bound() {
        let request = ThunesRequests::create_quotation(QuotationRequest {
            external_id: "acq_abc123",
            payer_id: 7,
            mode: QuotationMode::SourceAmount,
            transaction_type: "C2C",
            source_country_iso_code: "SWE",
            source_currency: "EUR",
            source_amount: Some("100.00"),
            destination_currency: "TZS",
            destination_amount: None,
        })
        .unwrap();
        let body: Value = serde_json::from_slice(request.body()).unwrap();
        assert_eq!(body["external_id"], json!("acq_abc123"));
        assert_eq!(body["source"]["amount"], json!("100.00"));
        assert_eq!(body["destination"]["currency"], json!("TZS"));
        assert_eq!(body["destination"]["amount"], Value::Null);
    }

    #[test]
    fn payer_discovery_is_exact_and_cp_verification_can_follow_dynamic_requirements() {
        assert_eq!(ThunesRequests::get_payer(42).unwrap().path(), "/v2/money-transfer/payers/42");
        let request = ThunesRequests::credit_party_verification_with_entity(
            42,
            "C2C",
            json!({"msisdn": "255712345678"}),
            Some(json!({"firstname": "A", "lastname": "B", "msisdn": "255712345678"})),
            None,
        )
        .unwrap();
        let body: Value = serde_json::from_slice(request.body()).unwrap();
        assert_eq!(body["credit_party_identifier"]["msisdn"], json!("255712345678"));
        assert_eq!(body["beneficiary"]["firstname"], json!("A"));
    }

    #[test]
    fn quote_rejects_non_decimal_or_exponent_amounts() {
        let invalid = |amount| QuotationRequest {
            external_id: "acq_abc123",
            payer_id: 7,
            mode: QuotationMode::SourceAmount,
            transaction_type: "C2C",
            source_country_iso_code: "SWE",
            source_currency: "EUR",
            source_amount: Some(amount),
            destination_currency: "TZS",
            destination_amount: None,
        };
        assert!(ThunesRequests::create_quotation(invalid("1e3")).is_err());
        assert!(ThunesRequests::create_quotation(invalid("-1")).is_err());
        assert!(ThunesRequests::create_quotation(invalid("abc")).is_err());
    }

    #[test]
    fn transaction_builder_rejects_external_id_substitution() {
        let mut fields = Map::new();
        fields.insert("external_id".into(), json!("attacker"));
        assert_eq!(
            ThunesRequests::create_transaction("acq_abc", "act_def", fields, false),
            Err(AdapterError::FieldSubstitution)
        );
    }

    #[test]
    fn simulated_header_is_explicit_only_on_transaction_creation() {
        let request =
            ThunesRequests::create_transaction("acq_abc", "act_def", Map::new(), true).unwrap();
        assert!(request.simulated());
        assert_eq!(request.method(), HttpMethod::Post);
    }
}
