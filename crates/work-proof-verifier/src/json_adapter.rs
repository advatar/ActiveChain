//! Bounded JSON compatibility adapter for external work-proof consumers.

use serde::{Deserialize, Serialize};

use crate::{
    MAX_OFFLINE_WORK_PROOF_BYTES, MAX_WORK_PUBLIC_ENVELOPE_BYTES, OFFLINE_VERIFY_MALFORMED,
    OFFLINE_VERIFY_OK, OFFLINE_VERIFY_TOO_LARGE, verify_relation_envelopes,
};

pub const JSON_REQUEST_SCHEMA_V1: &str = "actum.work-proof.verify.request.v1";
pub const JSON_RESULT_SCHEMA_V1: &str = "actum.work-proof.verify.result.v1";
pub const JSON_VERIFY_OPERATION_V1: &str = "verify_non_overlap";
pub const JSON_WORK_PROOF_PROFILE_V1: &str = activechain_work_proof::PROFILE;
pub const MAX_JSON_VERIFIER_REQUEST_BYTES: usize =
    2 * (MAX_OFFLINE_WORK_PROOF_BYTES + MAX_WORK_PUBLIC_ENVELOPE_BYTES) + 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonVerifierRequestV1 {
    schema: String,
    operation: String,
    profile: String,
    proof: JsonProofV1,
    expected: JsonExpectedV1,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonProofV1 {
    proof_envelope_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonExpectedV1 {
    public_claim_envelope_hex: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JsonVerifierCodeV1 {
    Verified,
    Invalid,
    Unsupported,
    Malformed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JsonVerifierResultV1 {
    pub schema: &'static str,
    pub code: JsonVerifierCodeV1,
    pub verified: bool,
    pub profile: &'static str,
}

impl JsonVerifierResultV1 {
    const fn new(code: JsonVerifierCodeV1) -> Self {
        Self {
            schema: JSON_RESULT_SCHEMA_V1,
            verified: matches!(code, JsonVerifierCodeV1::Verified),
            code,
            profile: JSON_WORK_PROOF_PROFILE_V1,
        }
    }
}

pub fn verify_json_request(input: &[u8]) -> JsonVerifierResultV1 {
    if input.is_empty() || input.len() > MAX_JSON_VERIFIER_REQUEST_BYTES {
        return JsonVerifierResultV1::new(JsonVerifierCodeV1::Malformed);
    }
    let request: JsonVerifierRequestV1 = match serde_json::from_slice(input) {
        Ok(request) => request,
        Err(_) => return JsonVerifierResultV1::new(JsonVerifierCodeV1::Malformed),
    };
    if request.schema != JSON_REQUEST_SCHEMA_V1
        || request.operation != JSON_VERIFY_OPERATION_V1
        || request.profile != JSON_WORK_PROOF_PROFILE_V1
    {
        return JsonVerifierResultV1::new(JsonVerifierCodeV1::Unsupported);
    }
    let public = match decode_lower_hex(
        &request.expected.public_claim_envelope_hex,
        MAX_WORK_PUBLIC_ENVELOPE_BYTES,
    ) {
        Some(bytes) => bytes,
        None => return JsonVerifierResultV1::new(JsonVerifierCodeV1::Malformed),
    };
    let proof =
        match decode_lower_hex(&request.proof.proof_envelope_hex, MAX_OFFLINE_WORK_PROOF_BYTES) {
            Some(bytes) => bytes,
            None => return JsonVerifierResultV1::new(JsonVerifierCodeV1::Malformed),
        };

    match verify_relation_envelopes(&public, &proof) {
        OFFLINE_VERIFY_OK => JsonVerifierResultV1::new(JsonVerifierCodeV1::Verified),
        OFFLINE_VERIFY_MALFORMED | OFFLINE_VERIFY_TOO_LARGE => {
            JsonVerifierResultV1::new(JsonVerifierCodeV1::Malformed)
        }
        _ => JsonVerifierResultV1::new(JsonVerifierCodeV1::Invalid),
    }
}

fn decode_lower_hex(value: &str, maximum_bytes: usize) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() > maximum_bytes.checked_mul(2)?
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        decoded.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
    }
    Some(decoded)
}

const fn hex_nibble(value: u8) -> Option<u8> {
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
    fn adapter_rejects_unknown_contracts_and_fields() {
        let unsupported = br#"{"schema":"future","operation":"verify_non_overlap","profile":"actum.non-overlap.risc0.v1","proof":{"proof_envelope_hex":"00"},"expected":{"public_claim_envelope_hex":"00"}}"#;
        assert_eq!(verify_json_request(unsupported).code, JsonVerifierCodeV1::Unsupported);

        let unknown = br#"{"schema":"actum.work-proof.verify.request.v1","operation":"verify_non_overlap","profile":"actum.non-overlap.risc0.v1","proof":{"proof_envelope_hex":"00"},"expected":{"public_claim_envelope_hex":"00"},"trusted":true}"#;
        assert_eq!(verify_json_request(unknown).code, JsonVerifierCodeV1::Malformed);
    }

    #[test]
    fn adapter_rejects_noncanonical_hex_and_oversized_input() {
        let uppercase = br#"{"schema":"actum.work-proof.verify.request.v1","operation":"verify_non_overlap","profile":"actum.non-overlap.risc0.v1","proof":{"proof_envelope_hex":"AA"},"expected":{"public_claim_envelope_hex":"00"}}"#;
        assert_eq!(verify_json_request(uppercase).code, JsonVerifierCodeV1::Malformed);
        assert_eq!(
            verify_json_request(&vec![b' '; MAX_JSON_VERIFIER_REQUEST_BYTES + 1]).code,
            JsonVerifierCodeV1::Malformed
        );
    }

    #[test]
    fn result_code_and_boolean_cannot_disagree() {
        for code in [
            JsonVerifierCodeV1::Verified,
            JsonVerifierCodeV1::Invalid,
            JsonVerifierCodeV1::Unsupported,
            JsonVerifierCodeV1::Malformed,
        ] {
            let result = JsonVerifierResultV1::new(code);
            assert_eq!(result.verified, code == JsonVerifierCodeV1::Verified);
            let encoded = serde_json::to_string(&result).expect("encode bounded result");
            assert!(encoded.len() < 256);
        }
    }
}
