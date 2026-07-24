use crate::{
    EvidenceClass, MAX_BODY_BYTES, NtzsAssetBinding, NtzsExternalAmount, NtzsExternalUnit,
    NtzsObservationContext, NtzsOperation, ProviderObservationV1, ProviderOperationState,
    commitment, map_api_status, provider_reference_commitment,
};
use activechain_protocol_types::Digest384;
use serde_json::{Map, Value};
use std::fmt;

const RESPONSE_PAYLOAD_DOMAIN: &[u8] = b"ACTIVECHAIN-NTZS-API-RESPONSE-PAYLOAD-V1";

/// Validated core-operation response containing no raw account or provider identifier.
#[derive(Clone, Eq, PartialEq)]
pub struct NtzsProviderResult {
    operation: NtzsOperation,
    state: ProviderOperationState,
    amount: NtzsExternalAmount,
    provider_reference_commitment: Digest384,
    payload_commitment: Digest384,
}

impl fmt::Debug for NtzsProviderResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NtzsProviderResult")
            .field("operation", &self.operation)
            .field("state", &self.state)
            .field("amount", &self.amount)
            .field("provider_reference_commitment", &self.provider_reference_commitment)
            .field("payload_commitment", &self.payload_commitment)
            .finish()
    }
}

impl NtzsProviderResult {
    #[must_use]
    pub const fn operation(&self) -> NtzsOperation {
        self.operation
    }

    #[must_use]
    pub const fn state(&self) -> ProviderOperationState {
        self.state
    }

    #[must_use]
    pub const fn amount(&self) -> NtzsExternalAmount {
        self.amount
    }

    /// Emits an observation only after exact reference, asset, unit, and quantity binding.
    pub fn to_observation(
        &self,
        context: NtzsObservationContext,
        asset_binding: NtzsAssetBinding,
    ) -> Result<ProviderObservationV1, ResponseSchemaError> {
        if context.provider_reference_commitment != self.provider_reference_commitment {
            return Err(ResponseSchemaError::ReferenceMismatch);
        }
        asset_binding
            .validate(self.amount, context.amount)
            .map_err(|_| ResponseSchemaError::AmountMismatch)?;
        ProviderObservationV1::new(
            context.chain,
            context.connector,
            context.attempt,
            context.intent,
            context.provider_account_commitment,
            self.provider_reference_commitment,
            context.sequence,
            self.state,
            context.amount,
            context.observed_at,
            context.observed_at,
            EvidenceClass::ConnectorAuthenticated,
            self.payload_commitment,
        )
        .map_err(|_| ResponseSchemaError::InvalidObservation)
    }
}

/// Parses reviewed deposit, transfer, and withdrawal response fields without floating point.
pub fn parse_operation_response(
    operation: NtzsOperation,
    raw_body: &[u8],
) -> Result<NtzsProviderResult, ResponseSchemaError> {
    if matches!(operation, NtzsOperation::Swap | NtzsOperation::RampSettlement) {
        return Err(ResponseSchemaError::UnsupportedSchema);
    }
    if raw_body.len() > MAX_BODY_BYTES {
        return Err(ResponseSchemaError::BodyTooLarge);
    }
    let document: Value =
        serde_json::from_slice(raw_body).map_err(|_| ResponseSchemaError::InvalidBody)?;
    let object = document.as_object().ok_or(ResponseSchemaError::InvalidBody)?;
    let reference = required_string(object, "id")?;
    let status = required_string(object, "status")?;
    let amount = match operation {
        NtzsOperation::Deposit | NtzsOperation::Withdrawal => {
            parse_number(object, "amountTzs", NtzsExternalUnit::Tzs)?
        }
        NtzsOperation::Transfer => parse_transfer_amount(object)?,
        NtzsOperation::Swap | NtzsOperation::RampSettlement => {
            return Err(ResponseSchemaError::UnsupportedSchema);
        }
    };
    Ok(NtzsProviderResult {
        operation,
        state: map_api_status(operation, status),
        amount,
        provider_reference_commitment: provider_reference_commitment(operation, reference)
            .map_err(|_| ResponseSchemaError::InvalidReference)?,
        payload_commitment: commitment(RESPONSE_PAYLOAD_DOMAIN, &[raw_body]),
    })
}

fn parse_transfer_amount(
    object: &Map<String, Value>,
) -> Result<NtzsExternalAmount, ResponseSchemaError> {
    match object.get("token") {
        None => parse_number(object, "amountTzs", NtzsExternalUnit::Tzs),
        Some(Value::String(token)) if token == "usdc" => {
            parse_number(object, "amount", NtzsExternalUnit::Usdc)
        }
        _ => Err(ResponseSchemaError::UnsupportedAsset),
    }
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, ResponseSchemaError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(ResponseSchemaError::MissingField)
}

fn parse_number(
    object: &Map<String, Value>,
    field: &str,
    unit: NtzsExternalUnit,
) -> Result<NtzsExternalAmount, ResponseSchemaError> {
    let number =
        object.get(field).and_then(Value::as_number).ok_or(ResponseSchemaError::MissingField)?;
    NtzsExternalAmount::parse(unit, &number.to_string())
        .map_err(|_| ResponseSchemaError::InvalidAmount)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseSchemaError {
    AmountMismatch,
    BodyTooLarge,
    InvalidAmount,
    InvalidBody,
    InvalidObservation,
    InvalidReference,
    MissingField,
    ReferenceMismatch,
    UnsupportedAsset,
    UnsupportedSchema,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectorId, PaymentAttemptId, PaymentIntentId};
    use activechain_payment_types::AssetAmountV1;
    use activechain_protocol_types::{AssetId, ChainId};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn fixture(name: &str) -> &'static [u8] {
        match name {
            "deposit" => include_bytes!("../fixtures/deposit-submitted.json"),
            "transfer-usdc" => include_bytes!("../fixtures/transfer-usdc-completed.json"),
            "withdrawal" => include_bytes!("../fixtures/withdrawal-burned.json"),
            _ => panic!("unknown fixture"),
        }
    }

    fn context(
        operation: NtzsOperation,
        reference: &str,
        amount: AssetAmountV1,
    ) -> NtzsObservationContext {
        NtzsObservationContext {
            chain: ChainId::new(digest(1)),
            connector: ConnectorId::new(digest(2)).unwrap(),
            attempt: PaymentAttemptId::new(digest(3)).unwrap(),
            intent: PaymentIntentId::new(digest(4)).unwrap(),
            provider_account_commitment: digest(5),
            provider_reference_commitment: provider_reference_commitment(operation, reference)
                .unwrap(),
            sequence: 1,
            amount,
            observed_at: 1_784_912_460,
        }
    }

    #[test]
    fn core_fixtures_parse_without_binary_floating_point() {
        let deposit = parse_operation_response(NtzsOperation::Deposit, fixture("deposit")).unwrap();
        assert_eq!(deposit.state(), ProviderOperationState::Pending);
        assert_eq!(
            deposit.amount(),
            NtzsExternalAmount::parse(NtzsExternalUnit::Tzs, "10000").unwrap()
        );

        let transfer =
            parse_operation_response(NtzsOperation::Transfer, fixture("transfer-usdc")).unwrap();
        assert_eq!(transfer.state(), ProviderOperationState::Succeeded);
        assert_eq!(transfer.amount().value().to_atomic_units(6), Ok(12_500_001));

        let withdrawal =
            parse_operation_response(NtzsOperation::Withdrawal, fixture("withdrawal")).unwrap();
        assert_eq!(withdrawal.state(), ProviderOperationState::Pending);
    }

    #[test]
    fn response_observation_requires_exact_reference_asset_and_amount() {
        let asset = AssetId::new(digest(6));
        let expected = AssetAmountV1::new(asset, 1_000_000).unwrap();
        let result = parse_operation_response(NtzsOperation::Deposit, fixture("deposit")).unwrap();
        let binding = NtzsAssetBinding::new(NtzsExternalUnit::Tzs, asset, 2).unwrap();
        let context = context(NtzsOperation::Deposit, "dep_fixture_response_001", expected);
        let observation = result.to_observation(context, binding).unwrap();
        assert_eq!(observation.state(), ProviderOperationState::Pending);
        assert_eq!(observation.evidence_class(), EvidenceClass::ConnectorAuthenticated);

        assert_eq!(
            result.to_observation(
                NtzsObservationContext { provider_reference_commitment: digest(9), ..context },
                binding,
            ),
            Err(ResponseSchemaError::ReferenceMismatch)
        );
        assert_eq!(
            result.to_observation(
                NtzsObservationContext {
                    amount: AssetAmountV1::new(asset, 999_999).unwrap(),
                    ..context
                },
                binding,
            ),
            Err(ResponseSchemaError::AmountMismatch)
        );
    }

    #[test]
    fn malformed_precision_assets_and_missing_fields_fail_closed() {
        let fractional_tzs = br#"{"id":"fixture","status":"submitted","amountTzs":10000.0}"#;
        assert_eq!(
            parse_operation_response(NtzsOperation::Deposit, fractional_tzs),
            Err(ResponseSchemaError::InvalidAmount)
        );
        let unsupported_asset =
            br#"{"id":"fixture","status":"completed","token":"usdt","amount":1}"#;
        assert_eq!(
            parse_operation_response(NtzsOperation::Transfer, unsupported_asset),
            Err(ResponseSchemaError::UnsupportedAsset)
        );
        let missing = br#"{"id":"fixture","status":"submitted"}"#;
        assert_eq!(
            parse_operation_response(NtzsOperation::Deposit, missing),
            Err(ResponseSchemaError::MissingField)
        );
        assert_eq!(
            parse_operation_response(NtzsOperation::Swap, b"{}"),
            Err(ResponseSchemaError::UnsupportedSchema)
        );
    }

    #[test]
    fn arbitrary_precision_json_number_remains_exact() {
        let body = br#"{"id":"fixture","status":"completed","token":"usdc","amount":9007199254740993.000001}"#;
        let result = parse_operation_response(NtzsOperation::Transfer, body).unwrap();
        assert_eq!(result.amount().value().coefficient(), 9_007_199_254_740_993_000_001);
        assert_eq!(result.amount().value().scale(), 6);
    }
}
