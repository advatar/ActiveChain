use activechain_application_primitives::{
    AnchorRecord, AnchorStateRecordV1, AnchorStatus, DigestAnchorStatementV1, anchor_state_object,
};
use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_state_tree::{StateCommitment, StateProof, verify_membership};
use activechain_work_proof_verifier::DurableTrustStore;
use serde::{Deserialize, Serialize};
use std::{
    env,
    io::Read as _,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_REQUEST_BYTES: usize = 512 * 1024;
const REQUEST_SCHEMA: &str = "actum.anchor.finality.verify.request.v1";
const RESULT_SCHEMA: &str = "actum.anchor.finality.verify.result.v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    schema: String,
    operation: String,
    #[serde(rename = "applicationDomain")]
    application_domain: String,
    #[serde(rename = "digestHex")]
    digest_hex: String,
    #[serde(rename = "finalizedRecordEnvelopeHex")]
    finalized_record_envelope_hex: String,
    #[serde(rename = "anchorStateProofEnvelopeHex")]
    anchor_state_proof_envelope_hex: String,
    #[serde(rename = "checkpointObjectCount")]
    checkpoint_object_count: u64,
}

#[derive(Serialize)]
struct VerifyResult {
    schema: &'static str,
    status: &'static str,
    #[serde(rename = "applicationDomain")]
    application_domain: String,
    #[serde(rename = "digestHex")]
    digest_hex: String,
    #[serde(rename = "submissionReference")]
    submission_reference: String,
    #[serde(rename = "finalizedHeight")]
    finalized_height: u64,
    #[serde(rename = "finalizedBlock")]
    finalized_block: String,
    #[serde(rename = "checkpointBundleId")]
    checkpoint_bundle_id: String,
    #[serde(rename = "checkpointHeight")]
    checkpoint_height: u64,
    #[serde(rename = "checkpointBlock")]
    checkpoint_block: String,
    #[serde(rename = "checkpointStateRoot")]
    checkpoint_state_root: String,
    #[serde(rename = "chainId")]
    chain_id: String,
    #[serde(rename = "genesisCommitment")]
    genesis_commitment: String,
    #[serde(rename = "protocolRevision")]
    protocol_revision: u32,
    #[serde(rename = "verifierRevision")]
    verifier_revision: u32,
}

fn main() -> ExitCode {
    match run() {
        Ok(result) => match serde_json::to_string(&result) {
            Ok(value) => {
                println!("{value}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("could not encode verification result: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<VerifyResult, String> {
    let trust_path = env::var("ACTUM_ANCHOR_TRUST_STORE")
        .map_err(|_| "ACTUM_ANCHOR_TRUST_STORE is required".to_owned())?;
    let trust = DurableTrustStore::open(trust_path)
        .map_err(|_| "operator trust store could not be opened".to_owned())?;
    let bundle =
        trust.accepted_bundle().map_err(|_| "operator trust bundle unavailable".to_owned())?;
    bundle.validate().map_err(|_| "operator trust bundle is invalid".to_owned())?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock before unix epoch".to_owned())?
        .as_millis();
    let now_ms = u64::try_from(now_ms).map_err(|_| "system clock out of range".to_owned())?;
    if now_ms < bundle.body.not_before_ms || now_ms > bundle.body.not_after_ms {
        return Err("operator trust bundle is outside its validity window".to_owned());
    }

    let mut input = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|error| format!("could not read request: {error}"))?;
    if input.is_empty() || input.len() > MAX_REQUEST_BYTES {
        return Err("request must be a bounded non-empty JSON document".to_owned());
    }
    let request: VerifyRequest =
        serde_json::from_slice(&input).map_err(|error| format!("malformed request: {error}"))?;
    if request.schema != REQUEST_SCHEMA
        || request.operation != "verify_finalized_external_digest_anchor"
    {
        return Err("unsupported request schema or operation".to_owned());
    }
    if request.checkpoint_object_count == 0 {
        return Err("checkpointObjectCount must be positive".to_owned());
    }

    let digest = decode_fixed_hex::<32>(&request.digest_hex, "digestHex")?;
    let statement =
        DigestAnchorStatementV1::new(request.application_domain.as_bytes().to_vec(), digest)
            .map_err(|_| "invalid application domain or digest".to_owned())?;
    let statement_envelope = encode_envelope(&statement)
        .map_err(|_| "could not encode expected anchor statement".to_owned())?;
    let reference = statement
        .submission_reference()
        .map_err(|_| "could not derive anchor submission reference".to_owned())?;

    let record_bytes =
        decode_hex(&request.finalized_record_envelope_hex, "finalizedRecordEnvelopeHex")?;
    let record: AnchorRecord = decode_envelope(&record_bytes)
        .map_err(|_| "invalid finalized anchor record envelope".to_owned())?;
    if encode_envelope(&record)
        .map_err(|_| "could not canonicalize finalized anchor record".to_owned())?
        != record_bytes
    {
        return Err("finalized anchor record envelope is not canonical".to_owned());
    }
    if record.status() != AnchorStatus::Finalized || record.statement() != &statement {
        return Err("finalized anchor record does not bind expected statement".to_owned());
    }
    let native = record
        .evidence()
        .ok_or_else(|| "finalized anchor record lacks native evidence".to_owned())?;
    let native_envelope = encode_envelope(native)
        .map_err(|_| "could not encode native finality evidence".to_owned())?;
    let verified = activechain_verifier_api::verify_anchor_finalized_evidence(
        &native_envelope,
        &statement_envelope,
        activechain_protocol_types::ChainId::new(bundle.body.chain_id),
        bundle.body.genesis_commitment,
        u64::from(bundle.body.protocol_revision),
        bundle.body.verifier_revision,
    )
    .map_err(|_| "native anchor finality verification failed".to_owned())?;
    if verified != *native || verified.finalized_height() > bundle.body.checkpoint_height {
        return Err("native finality is not admitted by the accepted checkpoint".to_owned());
    }

    let state_record = AnchorStateRecordV1::from_finalized_record(&record)
        .map_err(|_| "could not derive finalized anchor state record".to_owned())?;
    let state_object = anchor_state_object(&state_record)
        .map_err(|_| "could not derive finalized anchor state object".to_owned())?;
    let proof_bytes =
        decode_hex(&request.anchor_state_proof_envelope_hex, "anchorStateProofEnvelopeHex")?;
    let proof: StateProof = decode_envelope(&proof_bytes)
        .map_err(|_| "invalid anchor state proof envelope".to_owned())?;
    if encode_envelope(&proof)
        .map_err(|_| "could not canonicalize anchor state proof".to_owned())?
        != proof_bytes
    {
        return Err("anchor state proof envelope is not canonical".to_owned());
    }
    verify_membership(
        StateCommitment::new(bundle.body.checkpoint_state_root, request.checkpoint_object_count),
        &state_object,
        &proof,
    )
    .map_err(|_| "anchor state membership verification failed".to_owned())?;

    Ok(VerifyResult {
        schema: RESULT_SCHEMA,
        status: "verified",
        application_domain: request.application_domain,
        digest_hex: request.digest_hex,
        submission_reference: hex(reference.as_bytes()),
        finalized_height: verified.finalized_height(),
        finalized_block: hex(verified.finalized_block().as_bytes()),
        checkpoint_bundle_id: hex(bundle.bundle_id.as_bytes()),
        checkpoint_height: bundle.body.checkpoint_height,
        checkpoint_block: hex(bundle.body.checkpoint_block_id.as_bytes()),
        checkpoint_state_root: hex(bundle.body.checkpoint_state_root.as_bytes()),
        chain_id: hex(bundle.body.chain_id.as_bytes()),
        genesis_commitment: hex(bundle.body.genesis_commitment.as_bytes()),
        protocol_revision: bundle.body.protocol_revision,
        verifier_revision: bundle.body.verifier_revision,
    })
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || !value.len().is_multiple_of(2) || !value.bytes().all(is_lower_hex) {
        return Err(format!("{field} must be non-empty lowercase hex"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn decode_fixed_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = decode_hex(value, field)?;
    bytes.try_into().map_err(|_| format!("{field} must contain exactly {N} bytes"))
}

fn is_lower_hex(value: u8) -> bool {
    value.is_ascii_digit() || (b'a'..=b'f').contains(&value)
}

fn nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("invalid lowercase hex".to_owned()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_rejects_caller_supplied_trust_fields() {
        let request = r#"{
            "schema":"actum.anchor.finality.verify.request.v1",
            "operation":"verify_finalized_external_digest_anchor",
            "applicationDomain":"cognation.sovereign-intelligence.v1",
            "digestHex":"0000000000000000000000000000000000000000000000000000000000000000",
            "finalizedRecordEnvelopeHex":"00",
            "anchorStateProofEnvelopeHex":"00",
            "checkpointObjectCount":1,
            "chainId":"00"
        }"#;
        assert!(serde_json::from_str::<VerifyRequest>(request).is_err());
    }

    #[test]
    fn request_rejects_noncanonical_or_oversized_hex() {
        assert!(decode_hex("AA", "field").is_err());
        assert!(decode_hex("0", "field").is_err());
        assert!(decode_fixed_hex::<32>(&"00".repeat(31), "digestHex").is_err());
        assert!(decode_fixed_hex::<32>(&"00".repeat(33), "digestHex").is_err());
    }

    #[test]
    fn native_ids_are_lowercase_digest384_hex_without_sha256_prefix() {
        let bytes = [0xab; 48];
        assert_eq!(hex(&bytes), "ab".repeat(48));
        assert!(!hex(&bytes).starts_with("sha256:"));
    }
}
