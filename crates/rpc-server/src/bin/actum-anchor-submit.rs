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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitRequest {
    schema: String,
    operation: String,
    #[serde(default)]
    endpoint: Option<String>,
    checkpoint: Checkpoint,
}

#[derive(Deserialize)]
struct Checkpoint {
    #[serde(rename = "checkpointId")]
    checkpoint_id: String,
    #[serde(rename = "checkpointHash")]
    checkpoint_hash: String,
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
    if request.schema != "actum.anchor.submit.request.v1" {
        return Err("unsupported request schema".to_owned());
    }
    let resolving = match request.operation.as_str() {
        "submit_external_digest_anchor" => false,
        "resolve_external_digest_anchor" => true,
        _ => return Err("unsupported operation".to_owned()),
    };

    let digest = decode_digest(&request.checkpoint.checkpoint_hash)?;
    let domain = env::var("ACTUM_ANCHOR_APPLICATION_DOMAIN")
        .unwrap_or_else(|_| DEFAULT_APPLICATION_DOMAIN.to_owned());
    let statement = DigestAnchorStatementV1::new(domain.clone().into_bytes(), digest)
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

    Ok(serde_json::json!({
        "schema": "actum.anchor.submit.result.v1",
        "status": "submitted",
        "checkpointId": request.checkpoint.checkpoint_id,
        "checkpointHash": request.checkpoint.checkpoint_hash,
        "applicationDomain": domain,
        "reference": hex(reference.as_bytes()),
        "endpoint": request.endpoint,
        "rpcAddress": address,
    })
    .to_string())
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
