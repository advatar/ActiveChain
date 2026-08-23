use activechain_application_primitives::{
    SignedActumVerifierTrustBundleV1, TrustSignatureAlgorithmV1, TrustSignerSetV1,
};
use activechain_canonical_codec::{CanonicalType, decode_envelope};
use activechain_work_proof_verifier::DurableTrustStore;
use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let trust_store = arguments.next().ok_or(usage())?;
    let next_bundle = read_canonical::<SignedActumVerifierTrustBundleV1>(Path::new(
        &arguments.next().ok_or(usage())?,
    ))?;
    let current_set =
        read_canonical::<TrustSignerSetV1>(Path::new(&arguments.next().ok_or(usage())?))?;
    let activated_set_path = arguments.next().ok_or(usage())?;
    let activated_set = if activated_set_path == "-" {
        None
    } else {
        Some(read_canonical::<TrustSignerSetV1>(Path::new(&activated_set_path))?)
    };
    let now_ms = arguments.next().ok_or(usage())?.parse::<u64>()?;
    if arguments.next().is_some() {
        return Err(usage().into());
    }
    let store = DurableTrustStore::open(trust_store)?;
    store.transition(
        next_bundle,
        &current_set,
        activated_set.as_ref(),
        now_ms,
        &verify_signature,
    )?;
    println!("work-proof trust transition installed");
    Ok(())
}

fn usage() -> &'static str {
    "usage: actum-work-proof-trust-transition <trust-store> <signed-next-bundle> \
     <current-signer-set> <activated-signer-set|-> <now-ms>"
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
