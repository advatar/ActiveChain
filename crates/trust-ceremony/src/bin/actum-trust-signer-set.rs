//! Encodes a canonical trust signer set from published public keys.
//!
//! Takes only public material, so it can run anywhere. The JSON input is an
//! array of `{"public_key_hex", "valid_from_sequence", "valid_until_sequence"}`
//! entries; signer identities are derived from the keys and sorted canonically.

use activechain_canonical_codec::encode_envelope;
use activechain_trust_ceremony::{SignerEntry, build_signer_set, encode_hex};
use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let output = arguments
        .next()
        .ok_or("usage: actum-trust-signer-set <output> <revision> <threshold> <entries.json>")?;
    let revision = arguments.next().ok_or("revision is required")?.parse::<u32>()?;
    let threshold = arguments.next().ok_or("threshold is required")?.parse::<u16>()?;
    let entries_path = arguments.next().ok_or("entries JSON is required")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let output = Path::new(&output);
    if output.exists() {
        return Err("refusing to overwrite an existing signer set".into());
    }

    let entries: Vec<SignerEntry> = serde_json::from_slice(&fs::read(&entries_path)?)?;
    let set = build_signer_set(revision, threshold, &entries)?;
    let set_id = set.signer_set_id()?;
    fs::write(output, encode_envelope(&set)?)?;

    println!("signer_set_id {}", encode_hex(set_id.as_bytes()));
    println!("revision {revision}");
    println!("threshold {threshold} of {}", set.signers.len());
    for signer in &set.signers {
        println!(
            "signer {} valid {}..={}",
            encode_hex(signer.signer_id.as_bytes()),
            signer.valid_from_sequence,
            signer.valid_until_sequence
        );
    }
    Ok(())
}
