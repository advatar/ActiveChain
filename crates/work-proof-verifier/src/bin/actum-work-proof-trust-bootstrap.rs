use activechain_application_primitives::{
    SignedActumVerifierTrustBundleV1, TrustSignatureAlgorithmV1, TrustSignerSetV1,
};
use activechain_canonical_codec::{CanonicalType, decode_envelope};
use activechain_pq_zk::{WORK_PROOF_SYSTEM_REVISION, work_image_id};
use activechain_work_proof_verifier::{
    DurableTrustStore, WORK_VERIFIER_REVISION, work_proof_profile_id,
};
use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let output = arguments.next().ok_or(
        "usage: actum-work-proof-trust-bootstrap <output> <signed-bundle> <signer-set> <now-ms>\n\
         \x20      actum-work-proof-trust-bootstrap --emit-trust-inputs",
    )?;
    if output == "--emit-trust-inputs" {
        if arguments.next().is_some() {
            return Err("unexpected argument".into());
        }
        // The ceremony must pin exactly what this build verifies against, so
        // the proof binding is read out of the deployed binary instead of
        // being transcribed into the bundle specification by hand.
        emit_trust_inputs();
        return Ok(());
    }
    let bundle = read_canonical::<SignedActumVerifierTrustBundleV1>(Path::new(
        &arguments.next().ok_or("signed bundle is required")?,
    ))?;
    let signer_set = read_canonical::<TrustSignerSetV1>(Path::new(
        &arguments.next().ok_or("signer set is required")?,
    ))?;
    let now_ms = arguments.next().ok_or("now-ms is required")?.parse::<u64>()?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    DurableTrustStore::bootstrap(output, bundle, &signer_set, now_ms, &verify_signature)?;
    Ok(())
}

fn emit_trust_inputs() {
    let hex = |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("{{");
    println!("  \"proof_profile_id_hex\": \"{}\",", hex(work_proof_profile_id().as_bytes()));
    println!("  \"proof_system_revision\": {WORK_PROOF_SYSTEM_REVISION},");
    println!("  \"verifier_revision\": {WORK_VERIFIER_REVISION},");
    println!("  \"risc0_image_id_hex\": \"{}\"", hex(&work_image_id()));
    println!("}}");
}

fn read_canonical<T: CanonicalType>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > (T::MAX_ENCODED_LEN + 9) as u64 {
        return Err("canonical input is not a bounded regular file".into());
    }
    decode_envelope(&fs::read(path)?).map_err(|_| "invalid canonical input".into())
}

fn verify_signature(
    algorithm: TrustSignatureAlgorithmV1,
    public_key: &[u8],
    bundle_id: activechain_protocol_types::Digest384,
    signature: &[u8],
) -> bool {
    match algorithm {
        TrustSignatureAlgorithmV1::MlDsa44 => activechain_consensus_verifier::verify_ml_dsa44(
            public_key,
            bundle_id.as_bytes(),
            signature,
        )
        .is_ok(),
    }
}
