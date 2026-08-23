//! Exports the canonical public evidence for one finalized native digest anchor.
//!
//! The RPC node remains the only source of the finalized record and checkpointed
//! state proof. This tool derives the immutable anchor state object from the
//! resolved record, queries that exact object through the generic state API, and
//! verifies the proof-bearing RPC response before writing any artifact.

use activechain_action_kernel::{ActionEnvelope, action_id};
use activechain_application_primitives::{
    AnchorRecord, AnchorStateRecordV1, AnchorStatus, anchor_state_object,
};
use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_finality_types::FinalityCertificateBundle;
use activechain_protocol_types::{Digest384, Object};
use activechain_rpc_server::{query, verify_query_record};
use activechain_rpc_types::{QueryKind, RpcRequest, RpcResponse};
use std::{env, fs, io::Write as _, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let address = arguments.next().ok_or(usage())?;
    let reference = digest384(&arguments.next().ok_or(usage())?)?;
    let record_output = arguments.next().ok_or(usage())?;
    let proof_output = arguments.next().ok_or(usage())?;
    let finality_output = arguments.next().ok_or(usage())?;
    let native_evidence_output = arguments.next();
    if arguments.next().is_some() {
        return Err(usage().into());
    }

    let response = query(&address, &RpcRequest::ResolveAnchor { reference })
        .map_err(|error| format!("ResolveAnchor failed: {error:?}"))?;
    let RpcResponse::AnchorRecord(record_bytes) = response else {
        return Err("RPC did not return an anchor record".into());
    };
    let record: AnchorRecord =
        decode_envelope(&record_bytes).map_err(|_| "RPC returned a malformed anchor record")?;
    if record.status() != AnchorStatus::Finalized
        || encode_envelope(&record).map_err(|_| "anchor record encoding failed")? != record_bytes
    {
        return Err("RPC anchor record is not canonical finalized evidence".into());
    }

    let state_record = AnchorStateRecordV1::from_finalized_record(&record)
        .map_err(|_| "finalized record cannot derive an immutable anchor state record")?;
    let native = record.evidence().ok_or("finalized record lacks native evidence")?;
    let action: ActionEnvelope = decode_envelope(native.action_envelope())
        .map_err(|_| "finalized record contains a malformed native action")?;
    let native_action_id =
        action_id(&action).map_err(|_| "finalized record native action ID derivation failed")?;
    if native_action_id != state_record.transaction() {
        return Err("finalized record transaction/action identity is inconsistent".into());
    }
    let expected_object =
        anchor_state_object(&state_record).map_err(|_| "anchor state object derivation failed")?;
    let object_id = expected_object.object_id().into_digest();
    let response = query(&address, &RpcRequest::Get { kind: QueryKind::State, key: object_id })
        .map_err(|error| format!("state query failed: {error:?}"))?;
    let RpcResponse::Record(query_record) = response else {
        return Err("RPC did not return a proof-bearing anchor state record".into());
    };
    verify_query_record(&query_record)
        .map_err(|error| format!("RPC state record failed native verification: {error:?}"))?;
    let served_object: Object =
        decode_envelope(query_record.value()).map_err(|_| "RPC state object is malformed")?;
    if query_record.kind() != QueryKind::State
        || query_record.key() != object_id
        || served_object != expected_object
    {
        return Err("RPC state response substituted another anchor object".into());
    }
    let finality: FinalityCertificateBundle = decode_envelope(query_record.finality())
        .map_err(|_| "RPC checkpoint finality is malformed")?;
    let checkpoint = finality.header().inputs;
    if checkpoint.height != query_record.finalized_height() {
        return Err("RPC checkpoint height is inconsistent".into());
    }

    write_new(Path::new(&record_output), &record_bytes)?;
    write_new(Path::new(&proof_output), query_record.proof())?;
    write_new(Path::new(&finality_output), query_record.finality())?;
    if let Some(output) = native_evidence_output {
        let native = record.evidence().ok_or("finalized record lacks native evidence")?;
        let native = encode_envelope(native).map_err(|_| "native evidence encoding failed")?;
        write_new(Path::new(&output), &native)?;
        println!("native_evidence_bytes={}", native.len());
    }

    println!("submission_reference={}", hex(reference.as_bytes()));
    println!("transaction_id={}", hex(state_record.transaction().digest().as_bytes()));
    println!("action_id={}", hex(native_action_id.digest().as_bytes()));
    println!("anchor_state_object_id={}", hex(object_id.as_bytes()));
    println!("checkpoint_height={}", checkpoint.height);
    println!("checkpoint_state_root={}", hex(checkpoint.post_state.root().as_bytes()));
    println!("checkpoint_object_count={}", checkpoint.post_state.object_count());
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn digest384(value: &str) -> Result<Digest384, Box<dyn std::error::Error>> {
    if value.len() != 96
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("reference must be exactly 96 lowercase hexadecimal characters".into());
    }
    let mut bytes = [0_u8; 48];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    let digest = Digest384::new(bytes);
    if digest == Digest384::ZERO {
        return Err("reference cannot be zero".into());
    }
    Ok(digest)
}

fn nibble(value: u8) -> Result<u8, Box<dyn std::error::Error>> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("reference must use lowercase hexadecimal".into()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn usage() -> &'static str {
    "usage: actum-anchor-export <host:port> <reference-hex> <record-output> \
     <state-proof-output> <checkpoint-finality-output> [native-evidence-output]"
}

#[cfg(test)]
mod tests {
    use super::digest384;

    #[test]
    fn reference_parser_accepts_only_canonical_nonzero_digest384() {
        assert!(digest384(&"11".repeat(48)).is_ok());
        assert!(digest384(&"00".repeat(48)).is_err());
        assert!(digest384(&"AA".repeat(48)).is_err());
        assert!(digest384("11").is_err());
    }
}
