#![forbid(unsafe_code)]

use activechain_canonical_codec::{CanonicalType, decode_envelope};
use activechain_payment_types::{PaymentFinalizedSettlementV1, PaymentIntentV1};
use activechain_protocol_types::{ChainId, Digest384, PrincipalId};
use activechain_verifier_api::verify_payment_finalized_settlement;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const PROTOCOL_V1: &str = "actum.payment-finality.v1";
pub const MAX_PAYMENT_EVIDENCE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_REPLAY_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Debug)]
pub struct VerificationPolicy {
    pub audience: String,
    pub chain: ChainId,
    pub genesis: Digest384,
    pub merchant: PrincipalId,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequestV1 {
    pub protocol: String,
    pub audience: String,
    pub request_commitment_b64: String,
    pub replay_identifier_b64: String,
    pub token_class: String,
    pub payment_evidence_b64: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifyResponseV1 {
    pub authorized: bool,
    pub finalized: bool,
    pub request_commitment_b64: String,
    pub authorization_id_b64: String,
    pub token_class: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPaymentEvidenceV1 {
    payment_intent_b64: String,
    finalized_settlement_b64: String,
    finality_bundle_b64: String,
    block_receipt_b64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevelopmentPaymentEvidenceV1 {
    schema: String,
    request_commitment_b64: String,
    replay_identifier_b64: String,
    token_class: String,
    finalized: bool,
    authorization_id_b64: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    Malformed,
    UnsupportedProtocol,
    AudienceMismatch,
    RequestBindingMismatch,
    TokenPolicyMismatch,
    ReplayBindingMismatch,
    IntentExpired,
    PaymentRelationMismatch,
    FinalityInvalid,
    TooLarge,
}

impl VerificationError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "malformed_evidence",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::AudienceMismatch => "audience_mismatch",
            Self::RequestBindingMismatch => "request_binding_mismatch",
            Self::TokenPolicyMismatch => "token_policy_mismatch",
            Self::ReplayBindingMismatch => "replay_binding_mismatch",
            Self::IntentExpired => "intent_expired",
            Self::PaymentRelationMismatch => "payment_relation_mismatch",
            Self::FinalityInvalid => "finality_invalid",
            Self::TooLarge => "evidence_too_large",
        }
    }
}

pub fn token_policy_commitment(audience: &str, token_class: &str) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-INFERENCE-TOKEN-POLICY-V1");
    hasher.update(&(audience.len() as u32).to_be_bytes());
    hasher.update(audience.as_bytes());
    hasher.update(&(token_class.len() as u32).to_be_bytes());
    hasher.update(token_class.as_bytes());
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

pub fn verify_finalized_payment(
    request: &VerifyRequestV1,
    policy: &VerificationPolicy,
    now: u64,
) -> Result<VerifyResponseV1, VerificationError> {
    if request.protocol != PROTOCOL_V1 {
        return Err(VerificationError::UnsupportedProtocol);
    }
    if request.audience != policy.audience {
        return Err(VerificationError::AudienceMismatch);
    }
    if !matches!(request.token_class.as_str(), "c256" | "c512" | "c1024" | "c2048" | "c4096") {
        return Err(VerificationError::TokenPolicyMismatch);
    }
    let request_commitment = decode_fixed::<48>(&request.request_commitment_b64)?;
    let replay_identifier =
        decode_bounded(&request.replay_identifier_b64, 1, MAX_REPLAY_IDENTIFIER_BYTES)?;
    let evidence_bytes =
        decode_bounded(&request.payment_evidence_b64, 1, MAX_PAYMENT_EVIDENCE_BYTES)?;
    let evidence: CanonicalPaymentEvidenceV1 =
        serde_json::from_slice(&evidence_bytes).map_err(|_| VerificationError::Malformed)?;
    let intent_bytes =
        decode_bounded(&evidence.payment_intent_b64, 1, PaymentIntentV1::MAX_ENCODED_LEN + 6)?;
    let settlement_bytes = decode_bounded(
        &evidence.finalized_settlement_b64,
        1,
        PaymentFinalizedSettlementV1::MAX_ENCODED_LEN + 6,
    )?;
    let finality = decode_bounded(&evidence.finality_bundle_b64, 1, MAX_PAYMENT_EVIDENCE_BYTES)?;
    let receipt = decode_bounded(&evidence.block_receipt_b64, 1, MAX_PAYMENT_EVIDENCE_BYTES)?;

    let intent: PaymentIntentV1 =
        decode_envelope(&intent_bytes).map_err(|_| VerificationError::Malformed)?;
    if intent.chain() != policy.chain || intent.merchant() != policy.merchant {
        return Err(VerificationError::PaymentRelationMismatch);
    }
    if !intent.active_at(now) {
        return Err(VerificationError::IntentExpired);
    }
    if intent.authorization_context() != Digest384::new(request_commitment) {
        return Err(VerificationError::RequestBindingMismatch);
    }
    if intent.metadata_commitment()
        != token_policy_commitment(&request.audience, &request.token_class)
    {
        return Err(VerificationError::TokenPolicyMismatch);
    }
    let settlement =
        verify_payment_finalized_settlement(&settlement_bytes, &finality, &receipt, policy.genesis)
            .map_err(|_| VerificationError::FinalityInvalid)?;
    if settlement.intent() != intent.intent()
        || !intent.accepts_settlement(settlement.settled_amount())
    {
        return Err(VerificationError::PaymentRelationMismatch);
    }
    if replay_identifier.as_slice() != settlement.transaction().digest().as_bytes() {
        return Err(VerificationError::ReplayBindingMismatch);
    }

    Ok(VerifyResponseV1 {
        authorized: true,
        finalized: true,
        request_commitment_b64: request.request_commitment_b64.clone(),
        authorization_id_b64: BASE64.encode(intent.intent().digest().as_bytes()),
        token_class: request.token_class.clone(),
    })
}

/// Validates deterministic contract fixtures for isolated local integration only.
///
/// This function does not verify ActiveChain finality and must never be selected by a production
/// service profile. Keeping it in the ActiveChain service makes the development transport contract
/// identical while preserving an explicit, auditable profile boundary.
pub fn verify_development_fixture(
    request: &VerifyRequestV1,
    expected_audience: &str,
) -> Result<VerifyResponseV1, VerificationError> {
    if request.protocol != PROTOCOL_V1 {
        return Err(VerificationError::UnsupportedProtocol);
    }
    if request.audience != expected_audience {
        return Err(VerificationError::AudienceMismatch);
    }
    let request_commitment = decode_fixed::<48>(&request.request_commitment_b64)?;
    let replay_identifier =
        decode_bounded(&request.replay_identifier_b64, 1, MAX_REPLAY_IDENTIFIER_BYTES)?;
    let evidence_bytes =
        decode_bounded(&request.payment_evidence_b64, 1, MAX_PAYMENT_EVIDENCE_BYTES)?;
    let evidence: DevelopmentPaymentEvidenceV1 =
        serde_json::from_slice(&evidence_bytes).map_err(|_| VerificationError::Malformed)?;
    let evidence_commitment = decode_fixed::<48>(&evidence.request_commitment_b64)?;
    let evidence_replay =
        decode_bounded(&evidence.replay_identifier_b64, 1, MAX_REPLAY_IDENTIFIER_BYTES)?;
    let authorization_id = decode_fixed::<48>(&evidence.authorization_id_b64)?;
    if evidence.schema != PROTOCOL_V1 || !evidence.finalized {
        return Err(VerificationError::FinalityInvalid);
    }
    if evidence_commitment != request_commitment {
        return Err(VerificationError::RequestBindingMismatch);
    }
    if evidence_replay != replay_identifier {
        return Err(VerificationError::ReplayBindingMismatch);
    }
    if evidence.token_class != request.token_class {
        return Err(VerificationError::TokenPolicyMismatch);
    }
    Ok(VerifyResponseV1 {
        authorized: true,
        finalized: true,
        request_commitment_b64: request.request_commitment_b64.clone(),
        authorization_id_b64: BASE64.encode(authorization_id),
        token_class: request.token_class.clone(),
    })
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], VerificationError> {
    let decoded = decode_bounded(value, N, N)?;
    decoded.try_into().map_err(|_| VerificationError::Malformed)
}

fn decode_bounded(
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, VerificationError> {
    let maximum_encoded = maximum
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or(VerificationError::TooLarge)?;
    if value.len() > maximum_encoded {
        return Err(VerificationError::TooLarge);
    }
    let decoded = BASE64.decode(value).map_err(|_| VerificationError::Malformed)?;
    if decoded.len() < minimum {
        return Err(VerificationError::Malformed);
    }
    if decoded.len() > maximum {
        return Err(VerificationError::TooLarge);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn token_policy_commitment_is_domain_and_class_bound() {
        assert_ne!(
            token_policy_commitment("merchant-a", "c512"),
            token_policy_commitment("merchant-b", "c512")
        );
        assert_ne!(
            token_policy_commitment("merchant-a", "c512"),
            token_policy_commitment("merchant-a", "c1024")
        );
    }

    #[test]
    fn rejects_unsupported_protocol_before_evidence_decode() {
        let request = VerifyRequestV1 {
            protocol: "future".to_owned(),
            audience: "a".to_owned(),
            request_commitment_b64: String::new(),
            replay_identifier_b64: String::new(),
            token_class: "c512".to_owned(),
            payment_evidence_b64: String::new(),
        };
        let policy = VerificationPolicy {
            audience: "a".to_owned(),
            chain: ChainId::new(Digest384::new([1; 48])),
            genesis: Digest384::new([2; 48]),
            merchant: PrincipalId::new(Digest384::new([3; 48])),
        };
        assert_eq!(
            verify_finalized_payment(&request, &policy, 1),
            Err(VerificationError::UnsupportedProtocol)
        );
    }

    #[test]
    fn development_fixture_enforces_exact_bindings() {
        let commitment = [7_u8; 48];
        let replay = [8_u8; 48];
        let authorization = [9_u8; 48];
        let evidence = serde_json::to_vec(&json!({
            "schema": PROTOCOL_V1,
            "request_commitment_b64": BASE64.encode(commitment),
            "replay_identifier_b64": BASE64.encode(replay),
            "token_class": "c2048",
            "finalized": true,
            "authorization_id_b64": BASE64.encode(authorization),
        }))
        .unwrap();
        let request = VerifyRequestV1 {
            protocol: PROTOCOL_V1.to_owned(),
            audience: "actum:merchant:zerok-local".to_owned(),
            request_commitment_b64: BASE64.encode(commitment),
            replay_identifier_b64: BASE64.encode(replay),
            token_class: "c2048".to_owned(),
            payment_evidence_b64: BASE64.encode(evidence),
        };
        let verified = verify_development_fixture(&request, "actum:merchant:zerok-local").unwrap();
        assert_eq!(verified.authorization_id_b64, BASE64.encode(authorization));

        let mut substituted = request;
        substituted.request_commitment_b64 = BASE64.encode([10_u8; 48]);
        assert_eq!(
            verify_development_fixture(&substituted, "actum:merchant:zerok-local"),
            Err(VerificationError::RequestBindingMismatch)
        );
    }

    #[test]
    fn development_fixture_rejects_non_finalized_evidence() {
        let evidence = serde_json::to_vec(&json!({
            "schema": PROTOCOL_V1,
            "request_commitment_b64": BASE64.encode([7_u8; 48]),
            "replay_identifier_b64": BASE64.encode([8_u8; 48]),
            "token_class": "c512",
            "finalized": false,
            "authorization_id_b64": BASE64.encode([9_u8; 48]),
        }))
        .unwrap();
        let request = VerifyRequestV1 {
            protocol: PROTOCOL_V1.to_owned(),
            audience: "local".to_owned(),
            request_commitment_b64: BASE64.encode([7_u8; 48]),
            replay_identifier_b64: BASE64.encode([8_u8; 48]),
            token_class: "c512".to_owned(),
            payment_evidence_b64: BASE64.encode(evidence),
        };
        assert_eq!(
            verify_development_fixture(&request, "local"),
            Err(VerificationError::FinalityInvalid)
        );
    }
}
