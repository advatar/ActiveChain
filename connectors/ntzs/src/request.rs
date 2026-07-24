use crate::{ExactProviderAmount, NtzsEndpoint, NtzsExternalAmount, NtzsExternalUnit, NtzsRequest};
use serde_json::{Map, Number, Value};
use std::str::FromStr;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_HTTPS_URL_BYTES: usize = 2_048;
const MIN_DEPOSIT_TZS: u128 = 500;
const MIN_WITHDRAWAL_TZS: u128 = 5_000;

/// Exactly one destination for a provider transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtzsTransferDestination<'a> {
    UserId(&'a str),
    EvmAddress(&'a str),
}

/// Typed constructors for the reviewed core nTZS request profiles.
#[derive(Clone, Copy, Debug, Default)]
pub struct NtzsCoreRequests;

impl NtzsCoreRequests {
    pub fn deposit_mobile_money(
        user_id: &str,
        amount_tzs: &str,
        phone_number: &str,
        collect_to_treasury: bool,
    ) -> Result<NtzsRequest, NtzsRequestBuildError> {
        validate_identifier(user_id)?;
        validate_phone(phone_number)?;
        let amount = parse_tzs(amount_tzs, MIN_DEPOSIT_TZS)?;
        let mut body = base_user_amount(user_id, amount)?;
        body.insert("paymentMethod".to_owned(), Value::String("mobile_money".to_owned()));
        body.insert("phoneNumber".to_owned(), Value::String(phone_number.to_owned()));
        if collect_to_treasury {
            body.insert("collectToTreasury".to_owned(), Value::Bool(true));
        }
        build(NtzsEndpoint::CreateDeposit, body)
    }

    pub fn deposit_card(
        user_id: &str,
        amount_tzs: &str,
        redirect_url: &str,
        cancel_url: &str,
    ) -> Result<NtzsRequest, NtzsRequestBuildError> {
        validate_identifier(user_id)?;
        validate_https_url(redirect_url)?;
        validate_https_url(cancel_url)?;
        let amount = parse_tzs(amount_tzs, MIN_DEPOSIT_TZS)?;
        let mut body = base_user_amount(user_id, amount)?;
        body.insert("paymentMethod".to_owned(), Value::String("card".to_owned()));
        body.insert("redirectUrl".to_owned(), Value::String(redirect_url.to_owned()));
        body.insert("cancelUrl".to_owned(), Value::String(cancel_url.to_owned()));
        build(NtzsEndpoint::CreateDeposit, body)
    }

    pub fn transfer_tzs(
        from_user_id: &str,
        destination: NtzsTransferDestination<'_>,
        amount_tzs: &str,
    ) -> Result<NtzsRequest, NtzsRequestBuildError> {
        validate_identifier(from_user_id)?;
        let amount = parse_tzs(amount_tzs, 1)?;
        let mut body = Map::new();
        body.insert("fromUserId".to_owned(), Value::String(from_user_id.to_owned()));
        insert_destination(&mut body, destination)?;
        body.insert("amountTzs".to_owned(), Value::Number(decimal_number(amount)?));
        build(NtzsEndpoint::CreateTransfer, body)
    }

    pub fn transfer_usdc(
        from_user_id: &str,
        destination: NtzsTransferDestination<'_>,
        amount: &str,
    ) -> Result<NtzsRequest, NtzsRequestBuildError> {
        validate_identifier(from_user_id)?;
        let amount = NtzsExternalAmount::parse(NtzsExternalUnit::Usdc, amount)
            .map_err(|_| NtzsRequestBuildError::InvalidAmount)?;
        let mut body = Map::new();
        body.insert("fromUserId".to_owned(), Value::String(from_user_id.to_owned()));
        insert_destination(&mut body, destination)?;
        body.insert("token".to_owned(), Value::String("USDC".to_owned()));
        body.insert("amount".to_owned(), Value::Number(decimal_number(amount.value())?));
        build(NtzsEndpoint::CreateTransfer, body)
    }

    pub fn withdrawal(
        user_id: &str,
        amount_tzs: &str,
        phone_number: &str,
    ) -> Result<NtzsRequest, NtzsRequestBuildError> {
        validate_identifier(user_id)?;
        validate_phone(phone_number)?;
        let amount = parse_tzs(amount_tzs, MIN_WITHDRAWAL_TZS)?;
        let mut body = base_user_amount(user_id, amount)?;
        body.insert("phoneNumber".to_owned(), Value::String(phone_number.to_owned()));
        build(NtzsEndpoint::CreateWithdrawal, body)
    }
}

fn base_user_amount(
    user_id: &str,
    amount: ExactProviderAmount,
) -> Result<Map<String, Value>, NtzsRequestBuildError> {
    let mut body = Map::new();
    body.insert("userId".to_owned(), Value::String(user_id.to_owned()));
    body.insert("amountTzs".to_owned(), Value::Number(decimal_number(amount)?));
    Ok(body)
}

fn insert_destination(
    body: &mut Map<String, Value>,
    destination: NtzsTransferDestination<'_>,
) -> Result<(), NtzsRequestBuildError> {
    match destination {
        NtzsTransferDestination::UserId(user_id) => {
            validate_identifier(user_id)?;
            body.insert("toUserId".to_owned(), Value::String(user_id.to_owned()));
        }
        NtzsTransferDestination::EvmAddress(address) => {
            validate_evm_address(address)?;
            body.insert("toAddress".to_owned(), Value::String(address.to_owned()));
        }
    }
    Ok(())
}

fn parse_tzs(value: &str, minimum: u128) -> Result<ExactProviderAmount, NtzsRequestBuildError> {
    let amount = NtzsExternalAmount::parse(NtzsExternalUnit::Tzs, value)
        .map_err(|_| NtzsRequestBuildError::InvalidAmount)?
        .value();
    if amount.coefficient() < minimum {
        return Err(NtzsRequestBuildError::BelowMinimum);
    }
    Ok(amount)
}

fn decimal_number(amount: ExactProviderAmount) -> Result<Number, NtzsRequestBuildError> {
    Number::from_str(&amount.to_decimal_string()).map_err(|_| NtzsRequestBuildError::InvalidAmount)
}

fn validate_identifier(value: &str) -> Result<(), NtzsRequestBuildError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(NtzsRequestBuildError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_phone(value: &str) -> Result<(), NtzsRequestBuildError> {
    if value.len() != 12
        || !value.starts_with("255")
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(NtzsRequestBuildError::InvalidPhone);
    }
    Ok(())
}

fn validate_evm_address(value: &str) -> Result<(), NtzsRequestBuildError> {
    let Some(hex) = value.strip_prefix("0x") else {
        return Err(NtzsRequestBuildError::InvalidDestination);
    };
    if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(NtzsRequestBuildError::InvalidDestination);
    }
    Ok(())
}

fn validate_https_url(value: &str) -> Result<(), NtzsRequestBuildError> {
    let Some(authority_and_path) = value.strip_prefix("https://") else {
        return Err(NtzsRequestBuildError::InvalidHttpsUrl);
    };
    let authority = authority_and_path.split(['/', '?', '#']).next().unwrap_or_default();
    if value.len() > MAX_HTTPS_URL_BYTES
        || authority.is_empty()
        || authority.contains('@')
        || !authority.is_ascii()
        || !authority.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
        || !authority.bytes().any(|byte| byte.is_ascii_alphanumeric())
        || value.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(NtzsRequestBuildError::InvalidHttpsUrl);
    }
    Ok(())
}

fn build(
    endpoint: NtzsEndpoint,
    body: Map<String, Value>,
) -> Result<NtzsRequest, NtzsRequestBuildError> {
    let body = serde_json::to_vec(&Value::Object(body))
        .map_err(|_| NtzsRequestBuildError::Serialization)?;
    NtzsRequest::new(endpoint, body, None).map_err(|_| NtzsRequestBuildError::Serialization)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtzsRequestBuildError {
    BelowMinimum,
    InvalidAmount,
    InvalidDestination,
    InvalidHttpsUrl,
    InvalidIdentifier,
    InvalidPhone,
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(request: &NtzsRequest) -> Value {
        serde_json::from_slice(request.body()).unwrap()
    }

    #[test]
    fn mobile_and_card_deposits_use_reviewed_exact_fields() {
        let mobile =
            NtzsCoreRequests::deposit_mobile_money("usr_fixture", "500", "255712345678", true)
                .unwrap();
        assert_eq!(mobile.endpoint(), NtzsEndpoint::CreateDeposit);
        let mobile = body(&mobile);
        assert_eq!(mobile["amountTzs"], 500);
        assert_eq!(mobile["paymentMethod"], "mobile_money");
        assert_eq!(mobile["collectToTreasury"], true);

        let card = NtzsCoreRequests::deposit_card(
            "usr_fixture",
            "10000",
            "https://merchant.example/success",
            "https://merchant.example/cancel",
        )
        .unwrap();
        let card = body(&card);
        assert_eq!(card["paymentMethod"], "card");
        assert_eq!(card["redirectUrl"], "https://merchant.example/success");
        assert!(card.get("phoneNumber").is_none());
    }

    #[test]
    fn transfer_destination_type_is_exclusive_and_amounts_are_exact() {
        let user = NtzsCoreRequests::transfer_tzs(
            "usr_sender",
            NtzsTransferDestination::UserId("usr_recipient"),
            "1",
        )
        .unwrap();
        let user = body(&user);
        assert_eq!(user["toUserId"], "usr_recipient");
        assert!(user.get("toAddress").is_none());

        let address = NtzsCoreRequests::transfer_usdc(
            "usr_sender",
            NtzsTransferDestination::EvmAddress("0x0000000000000000000000000000000000000002"),
            "12.500001",
        )
        .unwrap();
        let address = body(&address);
        assert_eq!(address["token"], "USDC");
        assert_eq!(address["amount"].as_number().unwrap().to_string(), "12.500001");
        assert!(address.get("toUserId").is_none());
    }

    #[test]
    fn minimums_phone_urls_identifiers_and_addresses_fail_closed() {
        assert_eq!(
            NtzsCoreRequests::deposit_mobile_money("usr_fixture", "499", "255712345678", false,),
            Err(NtzsRequestBuildError::BelowMinimum)
        );
        assert_eq!(
            NtzsCoreRequests::withdrawal("usr_fixture", "4999", "255712345678"),
            Err(NtzsRequestBuildError::BelowMinimum)
        );
        assert_eq!(
            NtzsCoreRequests::withdrawal("usr_fixture", "5000", "+255712345678"),
            Err(NtzsRequestBuildError::InvalidPhone)
        );
        assert_eq!(
            NtzsCoreRequests::deposit_card(
                "usr_fixture",
                "500",
                "http://merchant.example/success",
                "https://merchant.example/cancel",
            ),
            Err(NtzsRequestBuildError::InvalidHttpsUrl)
        );
        assert_eq!(
            NtzsCoreRequests::transfer_tzs(
                "usr sender",
                NtzsTransferDestination::UserId("usr_recipient"),
                "1",
            ),
            Err(NtzsRequestBuildError::InvalidIdentifier)
        );
        assert_eq!(
            NtzsCoreRequests::transfer_tzs(
                "usr_sender",
                NtzsTransferDestination::EvmAddress("0x1234"),
                "1",
            ),
            Err(NtzsRequestBuildError::InvalidDestination)
        );
    }

    #[test]
    fn withdrawal_contains_only_validated_core_fields() {
        let request = NtzsCoreRequests::withdrawal("usr_fixture", "5000", "255712345678").unwrap();
        assert_eq!(request.endpoint(), NtzsEndpoint::CreateWithdrawal);
        let value = body(&request);
        assert_eq!(value["userId"], "usr_fixture");
        assert_eq!(value["amountTzs"], 5000);
        assert_eq!(value["phoneNumber"], "255712345678");
        assert_eq!(value.as_object().unwrap().len(), 3);
    }

    #[test]
    fn published_request_vectors_match_typed_constructors() {
        let vectors = include_str!("../../../testing/ntzs-request-vectors-v1.tsv");
        for (line_number, line) in vectors.lines().enumerate().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 3, "malformed vector line {}", line_number + 1);
            let accepted = match (fields[0], fields[1]) {
                ("deposit_mobile", "minimum_500") => NtzsCoreRequests::deposit_mobile_money(
                    "usr_fixture",
                    "500",
                    "255712345678",
                    false,
                )
                .is_ok(),
                ("deposit_mobile", "below_500") => NtzsCoreRequests::deposit_mobile_money(
                    "usr_fixture",
                    "499",
                    "255712345678",
                    false,
                )
                .is_ok(),
                ("deposit_card", "https_redirects") => NtzsCoreRequests::deposit_card(
                    "usr_fixture",
                    "500",
                    "https://merchant.example/success",
                    "https://merchant.example/cancel",
                )
                .is_ok(),
                ("deposit_card", "http_redirect") => NtzsCoreRequests::deposit_card(
                    "usr_fixture",
                    "500",
                    "http://merchant.example/success",
                    "https://merchant.example/cancel",
                )
                .is_ok(),
                ("transfer_tzs", "user_destination") => NtzsCoreRequests::transfer_tzs(
                    "usr_sender",
                    NtzsTransferDestination::UserId("usr_recipient"),
                    "1",
                )
                .is_ok(),
                ("transfer_tzs", "evm_destination") => NtzsCoreRequests::transfer_tzs(
                    "usr_sender",
                    NtzsTransferDestination::EvmAddress(
                        "0x0000000000000000000000000000000000000002",
                    ),
                    "1",
                )
                .is_ok(),
                ("transfer_tzs", "both_destinations") => {
                    assert_eq!(fields[2], "unrepresentable");
                    continue;
                }
                ("transfer_usdc", "six_decimals") => NtzsCoreRequests::transfer_usdc(
                    "usr_sender",
                    NtzsTransferDestination::UserId("usr_recipient"),
                    "0.000001",
                )
                .is_ok(),
                ("transfer_usdc", "seventh_decimal") => NtzsCoreRequests::transfer_usdc(
                    "usr_sender",
                    NtzsTransferDestination::UserId("usr_recipient"),
                    "0.0000001",
                )
                .is_ok(),
                ("withdrawal", "minimum_5000") => {
                    NtzsCoreRequests::withdrawal("usr_fixture", "5000", "255712345678").is_ok()
                }
                ("withdrawal", "below_5000") => {
                    NtzsCoreRequests::withdrawal("usr_fixture", "4999", "255712345678").is_ok()
                }
                ("withdrawal", "noncanonical_phone") => {
                    NtzsCoreRequests::withdrawal("usr_fixture", "5000", "+255712345678").is_ok()
                }
                values => panic!("unknown request vector {values:?}"),
            };
            assert_eq!(accepted, fields[2] == "accept", "vector line {}", line_number + 1);
        }
    }
}
