use activechain_application_primitives::{
    AnchorFinalizedEvidenceV1, AnchorStatus, DurableAnchorRegistry,
};
use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_protocol_types::{ChainId, Digest384};
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or(usage())?;
    let snapshot = PathBuf::from(arguments.next().ok_or(usage())?);
    let reference = digest384(&arguments.next().ok_or(usage())?)?;
    let mut registry = DurableAnchorRegistry::open(snapshot)
        .map_err(|error| format!("could not open anchor registry: {error:?}"))?;

    match command.as_str() {
        "reject" => {
            if arguments.next().is_some() {
                return Err(usage().into());
            }
            registry
                .update(|anchors| anchors.set_status(reference, AnchorStatus::Rejected))
                .map_err(|error| format!("could not reject anchor: {error:?}"))?;
        }
        "finalize" => {
            let evidence_path = PathBuf::from(arguments.next().ok_or(usage())?);
            let trusted_chain = ChainId::new(digest384(&arguments.next().ok_or(usage())?)?);
            let trusted_genesis = digest384(&arguments.next().ok_or(usage())?)?;
            let protocol_revision = arguments.next().ok_or(usage())?.parse::<u64>()?;
            let verifier_revision = arguments.next().ok_or(usage())?.parse::<u32>()?;
            if arguments.next().is_some() {
                return Err(usage().into());
            }
            let evidence_bytes = fs::read(evidence_path)?;
            let evidence = decode_envelope::<AnchorFinalizedEvidenceV1>(&evidence_bytes)
                .map_err(|error| format!("invalid finalized evidence: {error:?}"))?;
            let statement = registry
                .registry()
                .resolve(reference)
                .ok_or("unknown anchor reference")?
                .statement();
            let statement_bytes = encode_envelope(statement)
                .map_err(|error| format!("could not encode anchor statement: {error:?}"))?;
            activechain_verifier_api::verify_anchor_finalized_evidence(
                &evidence_bytes,
                &statement_bytes,
                trusted_chain,
                trusted_genesis,
                protocol_revision,
                verifier_revision,
            )
            .map_err(|error| format!("anchor evidence verification failed: {error:?}"))?;
            registry
                .update(|anchors| anchors.finalize(reference, evidence))
                .map_err(|error| format!("could not finalize anchor: {error:?}"))?;
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn digest384(value: &str) -> Result<Digest384, Box<dyn std::error::Error>> {
    if value.len() != 96 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("expected exactly 96 hexadecimal characters".into());
    }
    let mut bytes = [0_u8; 48];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)?;
        bytes[index] = u8::from_str_radix(pair, 16)?;
    }
    Ok(Digest384::new(bytes))
}

fn usage() -> &'static str {
    "usage:\n  activechain-anchor-admin reject <anchor-snapshot> <reference-hex>\n  \
     activechain-anchor-admin finalize <anchor-snapshot> <reference-hex> <evidence-envelope> \
     <trusted-chain-hex> <trusted-genesis-hex> <protocol-revision> <verifier-revision>"
}
