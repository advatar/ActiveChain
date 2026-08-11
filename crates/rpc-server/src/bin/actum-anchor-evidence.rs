//! Assembles checkpointed telemetry-anchor evidence from a live RPC node.
//!
//! The stateful work-proof API rejects a claim with retryable
//! `CheckpointUnavailable` until it is given a
//! `CheckpointedTelemetryAnchorEvidenceV1`, and nothing else in the tree builds
//! one. This binary resolves a finalized anchor, fetches the authenticated
//! anchor state object at the operator-pinned checkpoint, and packs both into
//! the exact evidence the verifier consumes.
//!
//! It never invents trust: the checkpoint identity comes from the operator's
//! accepted trust bundle, and the assembled evidence is verified with the same
//! `verify_checkpointed_telemetry_anchor` the verifier runs before anything is
//! written to disk.

use activechain_application_primitives::{
    AnchorRecord, AnchorStateRecordV1, AnchorStatus, CheckpointedTelemetryAnchorEvidenceV1,
    SignedActumVerifierTrustBundleV1, TelemetryEpochAnchorRequestV1,
    verify_checkpointed_telemetry_anchor,
};
use activechain_canonical_codec::{CanonicalType, decode_envelope, encode_envelope};
use activechain_finality_types::FinalityCertificateBundle;
use activechain_protocol_types::Digest384;
use activechain_rpc_server::query;
use activechain_rpc_types::{QueryKind, RpcRequest, RpcResponse};
use activechain_state_tree::StateProof;
use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let address = arguments.next().ok_or(
        "usage: actum-anchor-evidence <host:port> <anchor-request> <trust-bundle> <output>",
    )?;
    let request_path = arguments.next().ok_or("anchor request envelope is required")?;
    let trust_path = arguments.next().ok_or("trust bundle is required")?;
    let output = arguments.next().ok_or("output path is required")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let output = Path::new(&output);
    if output.exists() {
        return Err("refusing to overwrite existing evidence".into());
    }

    let request = read_canonical::<TelemetryEpochAnchorRequestV1>(Path::new(&request_path))?;
    let bundle = read_trust_bundle(Path::new(&trust_path))?;
    let statement = request.statement().map_err(|error| format!("invalid request: {error:?}"))?;
    let reference = statement
        .submission_reference()
        .map_err(|error| format!("invalid submission reference: {error:?}"))?;

    let record = resolve_anchor(&address, reference)?;
    if record.status() != AnchorStatus::Finalized {
        return Err(format!("anchor {} is not finalized yet", hex(reference.as_bytes())).into());
    }

    // The registry key is derived from the finalized record, so the object we
    // prove membership for cannot be chosen by whoever runs this tool.
    let state_record = AnchorStateRecordV1::from_finalized_record(&record)
        .map_err(|error| format!("anchor record is not finalized evidence: {error:?}"))?;
    let object_id = state_record
        .registry_key()
        .and_then(|key| key.object_id())
        .map_err(|error| format!("anchor registry key is unusable: {error:?}"))?;

    let (proof, finality) = fetch_state_proof(&address, *object_id.digest())?;
    let served = decode_envelope::<FinalityCertificateBundle>(&finality)
        .map_err(|_| "RPC returned an undecodable finality bundle")?;
    let served_inputs = served.header().inputs;

    // A proof only authenticates against the state it was produced for. If the
    // node has moved past the pinned checkpoint, say so precisely instead of
    // emitting evidence the verifier will reject.
    if served_inputs.post_state.root() != bundle.body.checkpoint_state_root {
        return Err(format!(
            "RPC serves finalized height {} but the accepted trust bundle pins checkpoint height \
             {}; re-issue the bundle at the served checkpoint and retry",
            served_inputs.height, bundle.body.checkpoint_height
        )
        .into());
    }

    let evidence = CheckpointedTelemetryAnchorEvidenceV1::new(
        request.clone(),
        reference,
        record,
        bundle.bundle_id,
        bundle.body.checkpoint_height,
        bundle.body.checkpoint_block_id,
        bundle.body.checkpoint_state_root,
        served_inputs.post_state.object_count(),
        proof,
    )
    .map_err(|error| format!("evidence could not be assembled: {error:?}"))?;
    verify_checkpointed_telemetry_anchor(&evidence, &request, &bundle)
        .map_err(|error| format!("assembled evidence failed verification: {error:?}"))?;

    let encoded = encode_envelope(&evidence).map_err(|_| "evidence could not be encoded")?;
    fs::write(output, &encoded)?;

    println!("anchor_reference {}", hex(reference.as_bytes()));
    println!("object_id {}", hex(object_id.digest().as_bytes()));
    println!("checkpoint_height {}", bundle.body.checkpoint_height);
    println!("checkpoint_state_root {}", hex(bundle.body.checkpoint_state_root.as_bytes()));
    println!("checkpoint_object_count {}", served_inputs.post_state.object_count());
    println!("evidence_bytes {}", encoded.len());
    println!("evidence_hex {}", hex(&encoded));
    Ok(())
}

fn resolve_anchor(
    address: &str,
    reference: Digest384,
) -> Result<AnchorRecord, Box<dyn std::error::Error>> {
    let response = query(address, &RpcRequest::ResolveAnchor { reference })
        .map_err(|error| format!("ResolveAnchor failed: {error:?}"))?;
    let RpcResponse::AnchorRecord(bytes) = response else {
        return Err("RPC did not return an anchor record".into());
    };
    Ok(decode_envelope::<AnchorRecord>(&bytes).map_err(|_| "undecodable anchor record")?)
}

fn fetch_state_proof(
    address: &str,
    object_id: Digest384,
) -> Result<(StateProof, Vec<u8>), Box<dyn std::error::Error>> {
    let response = query(address, &RpcRequest::Get { kind: QueryKind::State, key: object_id })
        .map_err(|error| format!("state query failed: {error:?}"))?;
    let RpcResponse::Record(record) = response else {
        return Err("RPC did not return a state record for the anchor object".into());
    };
    let proof = decode_envelope::<StateProof>(record.proof())
        .map_err(|_| "RPC returned an undecodable state proof")?;
    Ok((proof, record.finality().to_vec()))
}

fn read_trust_bundle(
    path: &Path,
) -> Result<SignedActumVerifierTrustBundleV1, Box<dyn std::error::Error>> {
    let bytes = read_bounded(path, (SignedActumVerifierTrustBundleV1::MAX_ENCODED_LEN + 9) as u64)?;
    // Accept both the bare canonical envelope and the verifier's durable
    // trust.bin framing (TRUST_MAGIC in activechain-work-proof-verifier, which
    // does not export it) so an operator can point at either artifact.
    if bytes.len() > 12 && &bytes[..8] == b"ACTBV1\0\0" {
        return Ok(decode_envelope(&bytes[12..]).map_err(|_| "invalid durable trust store")?);
    }
    Ok(decode_envelope(&bytes).map_err(|_| "invalid signed trust bundle")?)
}

fn read_canonical<T: CanonicalType>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    let bytes = read_bounded(path, (T::MAX_ENCODED_LEN + 9) as u64)?;
    Ok(decode_envelope(&bytes).map_err(|_| "invalid canonical input")?)
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err("input is not a bounded regular file".into());
    }
    Ok(fs::read(path)?)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
