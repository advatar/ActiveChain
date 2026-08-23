//! Submits an application's external digest as a native ActiveChain anchor.
//!
//! Applications hold digests, not canonical envelopes. Letting them encode
//! `DigestAnchorStatementV1` themselves would put a second canonical encoder in
//! every consumer language and drift from this one, so this binary is the
//! Actum-owned side of that boundary: an application hands over a 32-byte
//! digest and receives a submission reference.
//!
//! The contract mirrors `ACTUM_FINALITY_VERIFIER`: one JSON request on stdin,
//! one JSON receipt on stdout, non-zero exit when the anchor did not land.
//!
//! ```text
//! {"schema":"actum.anchor.submit.request.v1",
//!  "operation":"submit_external_digest_anchor",
//!  "checkpoint":{"checkpointId":"…","checkpointHash":"<64 lowercase hex>"}}
//! ```
//!
//! DCN verified-execution evidence uses the same native primitive with a
//! privacy-safe commitment and an explicitly configured application domain:
//!
//! ```text
//! {"schema":"actum.evidence-anchor.submit.request.v1",
//!  "operation":"submit_evidence_anchor",
//!  "evidence":{"evidenceId":"sha256:…",
//!              "evidenceCommitment":"sha256:…",
//!              "applicationDomain":"dcn.generation-attestation.evidence-anchor.v1"}}
//! ```
//!
//! Transport is the framed RPC protocol over plain TCP, so
//! `ACTUM_ANCHOR_RPC_ADDRESS` must name a directly reachable node such as
//! `127.0.0.1:49151`. A TLS-terminating edge like `rpc.kanalen.activechain.dev`
//! is not a valid target for this client.

use activechain_application_primitives::DigestAnchorStatementV1;
use activechain_canonical_codec::encode_envelope;
use activechain_rpc_server::query;
use activechain_rpc_types::{RpcRequest, RpcResponse};
use serde::Deserialize;
use std::{
    env,
    io::{Read as _, Write as _},
    process::ExitCode,
};

const MAX_REQUEST_BYTES: usize = 256 * 1024;
const DEFAULT_APPLICATION_DOMAIN: &str = "proof-of-work.checkpoint.v1";
const DCN_EVIDENCE_APPLICATION_DOMAIN: &str = "dcn.generation-attestation.evidence-anchor.v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitRequest {
    schema: String,
    operation: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    checkpoint: Option<Checkpoint>,
    #[serde(default)]
    evidence: Option<Evidence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    #[serde(rename = "checkpointId")]
    checkpoint_id: String,
    #[serde(rename = "checkpointHash")]
    checkpoint_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    #[serde(rename = "evidenceId")]
    evidence_id: String,
    #[serde(rename = "evidenceCommitment")]
    evidence_commitment: String,
    #[serde(rename = "applicationDomain")]
    application_domain: String,
}

struct PreparedSubmission {
    result_schema: &'static str,
    subject_id: String,
    digest_hex: String,
    domain: String,
    is_evidence: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(receipt) => {
            println!("{receipt}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|error| format!("could not read request: {error}"))?;
    if input.is_empty() || input.len() > MAX_REQUEST_BYTES {
        return Err("request must be a bounded non-empty JSON document".to_owned());
    }
    let request: SubmitRequest =
        serde_json::from_slice(&input).map_err(|error| format!("malformed request: {error}"))?;
    // Resolution is separate: callers poll ResolveAnchor and independently
    // verify finality. This binary accepts only submission operations.
    let configured_domain = env::var("ACTUM_ANCHOR_APPLICATION_DOMAIN").ok();
    let prepared = prepare_submission(&request, configured_domain.as_deref())?;
    let digest = decode_digest(&prepared.digest_hex)?;
    let statement = DigestAnchorStatementV1::new(prepared.domain.clone().into_bytes(), digest)
        .map_err(|error| format!("invalid anchor statement: {error:?}"))?;
    let reference = statement
        .submission_reference()
        .map_err(|error| format!("could not derive submission reference: {error:?}"))?;
    let encoded =
        encode_envelope(&statement).map_err(|_| "statement could not be encoded".to_owned())?;

    // The endpoint the caller knows is a TLS origin; the framed RPC address is
    // operator configuration, so the two are deliberately separate inputs.
    let address = env::var("ACTUM_ANCHOR_RPC_ADDRESS")
        .map_err(|_| "ACTUM_ANCHOR_RPC_ADDRESS is required".to_owned())?;
    let response = query(&address, &RpcRequest::SubmitAnchor { statement: encoded })
        .map_err(|error| format!("anchor submission failed: {error:?}"))?;
    let submitted = match response {
        RpcResponse::AnchorSubmission(value) => value,
        RpcResponse::Error(error) => return Err(format!("node rejected the anchor: {error:?}")),
        _ => return Err("node returned an unexpected response".to_owned()),
    };
    // Resubmitting the same statement is idempotent and must resolve to the
    // reference the statement itself commits to.
    if submitted != reference {
        return Err("node returned a reference the statement does not commit to".to_owned());
    }

    let mut result = serde_json::json!({
        "schema": prepared.result_schema,
        "status": "submitted",
        "applicationDomain": prepared.domain,
        "reference": hex(reference.as_bytes()),
        "endpoint": request.endpoint,
        "rpcAddress": address,
    });
    if prepared.is_evidence {
        result["evidenceId"] = prepared.subject_id.into();
        result["evidenceCommitment"] = format!("sha256:{}", prepared.digest_hex).into();
    } else {
        result["checkpointId"] = prepared.subject_id.into();
        result["checkpointHash"] = prepared.digest_hex.into();
    }
    Ok(result.to_string())
}

fn prepare_submission(
    request: &SubmitRequest,
    configured_domain: Option<&str>,
) -> Result<PreparedSubmission, String> {
    match (request.schema.as_str(), request.operation.as_str()) {
        ("actum.anchor.submit.request.v1", "submit_external_digest_anchor") => {
            let checkpoint = request
                .checkpoint
                .as_ref()
                .ok_or_else(|| "checkpoint request is missing checkpoint".to_owned())?;
            if request.evidence.is_some() || checkpoint.checkpoint_id.trim().is_empty() {
                return Err("checkpoint request is malformed".to_owned());
            }
            decode_digest(&checkpoint.checkpoint_hash)?;
            Ok(PreparedSubmission {
                result_schema: "actum.anchor.submit.result.v1",
                subject_id: checkpoint.checkpoint_id.clone(),
                digest_hex: checkpoint.checkpoint_hash.clone(),
                domain: configured_domain.unwrap_or(DEFAULT_APPLICATION_DOMAIN).to_owned(),
                is_evidence: false,
            })
        }
        ("actum.evidence-anchor.submit.request.v1", "submit_evidence_anchor") => {
            let evidence = request
                .evidence
                .as_ref()
                .ok_or_else(|| "evidence request is missing evidence".to_owned())?;
            if request.checkpoint.is_some()
                || evidence.application_domain != DCN_EVIDENCE_APPLICATION_DOMAIN
            {
                return Err("evidence request is malformed".to_owned());
            }
            decode_sha256_commitment(&evidence.evidence_id, "evidenceId")?;
            let configured_domain = configured_domain.ok_or_else(|| {
                "ACTUM_ANCHOR_APPLICATION_DOMAIN is required for evidence submission".to_owned()
            })?;
            if configured_domain != evidence.application_domain {
                return Err("evidence application domain is not authorized".to_owned());
            }
            let digest_hex =
                decode_sha256_commitment(&evidence.evidence_commitment, "evidenceCommitment")?;
            Ok(PreparedSubmission {
                result_schema: "actum.evidence-anchor.submit.result.v1",
                subject_id: evidence.evidence_id.clone(),
                digest_hex,
                domain: evidence.application_domain.clone(),
                is_evidence: true,
            })
        }
        _ => Err("unsupported request schema or operation".to_owned()),
    }
}

fn decode_sha256_commitment(value: &str, field: &str) -> Result<String, String> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("{field} must be a canonical sha256 commitment"))?;
    decode_digest(digest)?;
    Ok(digest.to_owned())
}

fn decode_digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("checkpointHash must be 64 lowercase hex characters".to_owned());
    }
    let mut digest = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = nibble(pair[0])?;
        let low = nibble(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

fn nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("checkpointHash must be lowercase hex".to_owned()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{DCN_EVIDENCE_APPLICATION_DOMAIN, SubmitRequest, prepare_submission};

    #[test]
    fn dcn_evidence_request_is_explicitly_domain_authorized() {
        let request: SubmitRequest = serde_json::from_value(serde_json::json!({
            "schema": "actum.evidence-anchor.submit.request.v1",
            "operation": "submit_evidence_anchor",
            "evidence": {
                "evidenceId": format!("sha256:{}", "11".repeat(32)),
                "evidenceCommitment": format!("sha256:{}", "22".repeat(32)),
                "applicationDomain": DCN_EVIDENCE_APPLICATION_DOMAIN
            }
        }))
        .unwrap();
        let prepared = prepare_submission(&request, Some(DCN_EVIDENCE_APPLICATION_DOMAIN)).unwrap();
        assert!(prepared.is_evidence);
        assert_eq!(prepared.digest_hex, "22".repeat(32));
        assert_eq!(prepared.domain, DCN_EVIDENCE_APPLICATION_DOMAIN);
    }

    #[test]
    fn dcn_evidence_rejects_wrong_domain_missing_configuration_and_mixed_shape() {
        let request = || -> SubmitRequest {
            serde_json::from_value(serde_json::json!({
                "schema": "actum.evidence-anchor.submit.request.v1",
                "operation": "submit_evidence_anchor",
                "evidence": {
                    "evidenceId": "evidence:1",
                    "evidenceCommitment": format!("sha256:{}", "22".repeat(32)),
                    "applicationDomain": DCN_EVIDENCE_APPLICATION_DOMAIN
                }
            }))
            .unwrap()
        };
        assert!(prepare_submission(&request(), None).is_err());
        assert!(prepare_submission(&request(), Some("other.application.v1")).is_err());

        let alias_id: SubmitRequest = serde_json::from_value(serde_json::json!({
            "schema": "actum.evidence-anchor.submit.request.v1",
            "operation": "submit_evidence_anchor",
            "evidence": {
                "evidenceId": "evidence:alias-only",
                "evidenceCommitment": format!("sha256:{}", "22".repeat(32)),
                "applicationDomain": DCN_EVIDENCE_APPLICATION_DOMAIN
            }
        }))
        .unwrap();
        assert!(prepare_submission(&alias_id, Some(DCN_EVIDENCE_APPLICATION_DOMAIN)).is_err());

        let mixed: SubmitRequest = serde_json::from_value(serde_json::json!({
            "schema": "actum.evidence-anchor.submit.request.v1",
            "operation": "submit_evidence_anchor",
            "checkpoint": {"checkpointId": "c", "checkpointHash": "11".repeat(32)},
            "evidence": {
                "evidenceId": "evidence:1",
                "evidenceCommitment": format!("sha256:{}", "22".repeat(32)),
                "applicationDomain": DCN_EVIDENCE_APPLICATION_DOMAIN
            }
        }))
        .unwrap();
        assert!(prepare_submission(&mixed, Some(DCN_EVIDENCE_APPLICATION_DOMAIN)).is_err());
    }

    #[test]
    fn legacy_checkpoint_request_remains_compatible() {
        let request: SubmitRequest = serde_json::from_value(serde_json::json!({
            "schema": "actum.anchor.submit.request.v1",
            "operation": "submit_external_digest_anchor",
            "checkpoint": {
                "checkpointId": "checkpoint:1",
                "checkpointHash": "33".repeat(32)
            }
        }))
        .unwrap();
        let prepared = prepare_submission(&request, None).unwrap();
        assert!(!prepared.is_evidence);
        assert_eq!(prepared.domain, "proof-of-work.checkpoint.v1");
    }
}
