//! Guarded trust bootstrap for an unused, explicitly identified testnet.
//!
//! This command creates a candidate trust store only. The host deployment
//! script is responsible for stopping the verifier and atomically installing
//! that candidate with rollback. Production renewal remains transition-only.

use activechain_application_primitives::{
    SignedActumVerifierTrustBundleV1, TrustSignatureAlgorithmV1, TrustSignerSetV1,
};
use activechain_canonical_codec::{CanonicalType, decode_envelope};
use activechain_protocol_types::Digest384;
use activechain_work_proof_verifier::{DurableTrustStore, DurableUsageRegistry};
use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let output = arguments.next().ok_or(usage())?;
    let bundle = read_canonical::<SignedActumVerifierTrustBundleV1>(Path::new(
        &arguments.next().ok_or(usage())?,
    ))?;
    let signer_set =
        read_canonical::<TrustSignerSetV1>(Path::new(&arguments.next().ok_or(usage())?))?;
    let usage_store = arguments.next().ok_or(usage())?;
    let now_ms = arguments.next().ok_or(usage())?.parse::<u64>()?;
    let expected_chain = decode_digest(&arguments.next().ok_or(usage())?)?;
    let expected_genesis = decode_digest(&arguments.next().ok_or(usage())?)?;
    let expected_policy = decode_digest(&arguments.next().ok_or(usage())?)?;
    if arguments.next().is_some() {
        return Err(usage().into());
    }
    if bundle.body.chain_id != expected_chain
        || bundle.body.genesis_commitment != expected_genesis
        || bundle.body.policy_id != expected_policy
    {
        return Err("signed bundle does not match the explicitly permitted testnet identity".into());
    }
    if !DurableUsageRegistry::open(usage_store)?.is_empty()? {
        return Err("testnet trust bootstrap refused because durable usage is not empty".into());
    }
    DurableTrustStore::bootstrap(output, bundle, &signer_set, now_ms, &verify_signature)?;
    println!("unused testnet trust candidate created");
    Ok(())
}

fn usage() -> &'static str {
    "usage: actum-work-proof-testnet-trust-bootstrap <output> <signed-bundle> \
     <signer-set> <usage-store> <now-ms> <expected-chain-id-hex> \
     <expected-genesis-commitment-hex> <expected-policy-id-hex>"
}

fn decode_digest(value: &str) -> Result<Digest384, Box<dyn std::error::Error>> {
    if value.len() != 96 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("expected identity must be exactly 96 hexadecimal characters".into());
    }
    let mut bytes = [0_u8; 48];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair)?;
        bytes[index] = u8::from_str_radix(text, 16)?;
    }
    Ok(Digest384::new(bytes))
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
    bundle_id: Digest384,
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
