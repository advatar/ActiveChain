//! Strict JSON boundary for the stateful work-proof admission service.

use activechain_application_primitives::{
    CheckpointedTelemetryAnchorEvidenceV1, TelemetryEpochAnchorRequestV1,
};
use activechain_canonical_codec::{CanonicalType, decode_envelope};
use activechain_protocol_types::Digest384;
use activechain_work_proof::WorkClaimPublicV1;
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_384};

use crate::{
    MAX_OFFLINE_WORK_PROOF_BYTES, MAX_WORK_PUBLIC_ENVELOPE_BYTES, VerificationErrorV1,
    VerifiedClaimDtoV1, VerifyWorkClaimRequestV1,
};

pub const STATEFUL_VERIFY_REQUEST_SCHEMA_V1: &str = "actum.work-proof.admit.request.v1";
pub const STATEFUL_VERIFY_RESULT_SCHEMA_V1: &str = "actum.work-proof.admit.result.v1";
pub const STATEFUL_VERIFY_OPERATION_V1: &str = "verify_and_register";
pub const MAX_STATEFUL_VERIFY_REQUEST_BYTES: usize = 2
    * (MAX_OFFLINE_WORK_PROOF_BYTES
        + MAX_WORK_PUBLIC_ENVELOPE_BYTES
        + TelemetryEpochAnchorRequestV1::MAX_ENCODED_LEN
        + CheckpointedTelemetryAnchorEvidenceV1::MAX_ENCODED_LEN)
    + 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatefulVerifyJsonRequestV1 {
    schema: String,
    operation: String,
    profile: String,
    claim_id: String,
    public_claim_envelope_hex: String,
    proof_envelope_hex: String,
    anchor_request_envelope_hex: String,
    checkpointed_anchor_evidence_envelope_hex: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ApiRequestErrorV1 {
    Malformed,
    Unsupported,
}

#[derive(Debug, Serialize)]
pub struct StatefulVerificationResponseV1 {
    pub schema: &'static str,
    pub result: VerifiedClaimDtoV1,
}

impl StatefulVerificationResponseV1 {
    pub const fn new(result: VerifiedClaimDtoV1) -> Self {
        Self { schema: STATEFUL_VERIFY_RESULT_SCHEMA_V1, result }
    }
}

#[derive(Debug, Serialize)]
pub struct StatefulVerificationErrorResponseV1 {
    pub schema: &'static str,
    pub error: VerificationErrorV1,
}

impl StatefulVerificationErrorResponseV1 {
    pub const fn new(error: VerificationErrorV1) -> Self {
        Self { schema: STATEFUL_VERIFY_RESULT_SCHEMA_V1, error }
    }
}

pub fn decode_stateful_verification_request(
    input: &[u8],
    client_id: Digest384,
) -> Result<VerifyWorkClaimRequestV1, ApiRequestErrorV1> {
    if input.is_empty() || input.len() > MAX_STATEFUL_VERIFY_REQUEST_BYTES {
        return Err(ApiRequestErrorV1::Malformed);
    }
    let request: StatefulVerifyJsonRequestV1 =
        serde_json::from_slice(input).map_err(|_| ApiRequestErrorV1::Malformed)?;
    if request.schema != STATEFUL_VERIFY_REQUEST_SCHEMA_V1
        || request.operation != STATEFUL_VERIFY_OPERATION_V1
        || request.profile != activechain_work_proof::PROFILE
    {
        return Err(ApiRequestErrorV1::Unsupported);
    }
    let claim_id = decode_digest_hex(&request.claim_id).ok_or(ApiRequestErrorV1::Malformed)?;
    let public = decode_canonical_hex::<WorkClaimPublicV1>(
        &request.public_claim_envelope_hex,
        MAX_WORK_PUBLIC_ENVELOPE_BYTES,
    )?;
    let proof_envelope =
        decode_lower_hex(&request.proof_envelope_hex, MAX_OFFLINE_WORK_PROOF_BYTES)
            .ok_or(ApiRequestErrorV1::Malformed)?;
    let anchor_request = decode_canonical_hex::<TelemetryEpochAnchorRequestV1>(
        &request.anchor_request_envelope_hex,
        TelemetryEpochAnchorRequestV1::MAX_ENCODED_LEN + 9,
    )?;
    let checkpointed_anchor_evidence = request
        .checkpointed_anchor_evidence_envelope_hex
        .as_deref()
        .map(|value| {
            decode_canonical_hex::<CheckpointedTelemetryAnchorEvidenceV1>(
                value,
                CheckpointedTelemetryAnchorEvidenceV1::MAX_ENCODED_LEN + 9,
            )
        })
        .transpose()?;
    Ok(VerifyWorkClaimRequestV1 {
        client_id,
        claim_id,
        public,
        proof_envelope,
        anchor_request,
        checkpointed_anchor_evidence,
    })
}

pub fn rate_limit_client_id(source: &[u8]) -> Digest384 {
    let mut hash = Sha3_384::new();
    hash.update(b"ACTUM-WORK-VERIFIER-RATE-CLIENT-V1");
    hash.update(source);
    Digest384::new(hash.finalize().into())
}

pub fn decode_digest_hex(value: &str) -> Option<Digest384> {
    let bytes = decode_lower_hex(value, 48)?;
    let bytes: [u8; 48] = bytes.try_into().ok()?;
    let digest = Digest384::new(bytes);
    (digest != Digest384::ZERO).then_some(digest)
}

fn decode_canonical_hex<T: CanonicalType>(
    value: &str,
    maximum_bytes: usize,
) -> Result<T, ApiRequestErrorV1> {
    let bytes = decode_lower_hex(value, maximum_bytes).ok_or(ApiRequestErrorV1::Malformed)?;
    decode_envelope(&bytes).map_err(|_| ApiRequestErrorV1::Malformed)
}

fn decode_lower_hex(value: &str, maximum_bytes: usize) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() > maximum_bytes.checked_mul(2)?
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        output.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(output)
}

const fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateful_request_rejects_unknown_fields_profiles_and_noncanonical_hex() {
        let unknown = br#"{"schema":"actum.work-proof.admit.request.v1","operation":"verify_and_register","profile":"actum.non-overlap.risc0.v1","claim_id":"010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101","public_claim_envelope_hex":"00","proof_envelope_hex":"00","anchor_request_envelope_hex":"00","checkpointed_anchor_evidence_envelope_hex":"00","trust_bundle":"caller"}"#;
        assert!(matches!(
            decode_stateful_verification_request(unknown, rate_limit_client_id(b"client")),
            Err(ApiRequestErrorV1::Malformed)
        ));
        let future = br#"{"schema":"actum.work-proof.admit.request.v1","operation":"verify_and_register","profile":"future","claim_id":"010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101","public_claim_envelope_hex":"00","proof_envelope_hex":"00","anchor_request_envelope_hex":"00","checkpointed_anchor_evidence_envelope_hex":"00"}"#;
        assert!(matches!(
            decode_stateful_verification_request(future, rate_limit_client_id(b"client")),
            Err(ApiRequestErrorV1::Unsupported)
        ));
        assert!(decode_digest_hex(&"A".repeat(96)).is_none());
        assert!(decode_digest_hex(&"0".repeat(96)).is_none());
    }

    #[test]
    fn rate_client_identity_is_domain_separated_and_stable() {
        assert_eq!(rate_limit_client_id(b"127.0.0.1"), rate_limit_client_id(b"127.0.0.1"));
        assert_ne!(rate_limit_client_id(b"127.0.0.1"), rate_limit_client_id(b"127.0.0.2"));
    }
}
