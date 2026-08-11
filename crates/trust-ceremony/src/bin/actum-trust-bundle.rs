//! Prepares, inspects, signs, and assembles an Actum verifier trust bundle.
//!
//! The four subcommands exist so that the signing step is the only one that
//! needs secret material, and so that a signer can independently recompute the
//! identity it authorizes instead of trusting a handed-over digest:
//!
//! ```text
//! prepare   build host    unsigned body + bundle id
//! inspect   any host      human review of what will be signed
//! sign      offline host  detached signature, secret never leaves
//! assemble  build host    deployable signed-trust-bundle.bin
//! ```

use activechain_application_primitives::{ActumVerifierTrustBundleV1, TrustSignerSetV1};
use activechain_canonical_codec::{CanonicalType, decode_envelope, encode_envelope};
use activechain_protocol_types::Digest384;
use activechain_trust_ceremony::{
    BundleSpec, DetachedSignature, ProofBinding, SignerSeed, build_body, bundle_id_for_signing,
    checkpoint_inputs, decode_hex, derive_signer_id, encode_hex, sign_bundle_id,
};
use serde::{Deserialize, Serialize};
use std::{env, fs, path::Path};

const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
struct DetachedSignatureFile {
    signer_id_hex: String,
    signature_hex: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or(
        "usage: actum-trust-bundle <prepare|inspect|sign|assemble> ...\n\
         \x20 prepare  <body-out> <spec.json> <proof.json> <finality.bundle> <receipt.bin> <signer-set.bin>\n\
         \x20 inspect  <body.bin>\n\
         \x20 sign     <signature-out> <secret-seed> <body.bin>\n\
         \x20 assemble <bundle-out> <body.bin> <signer-set.bin> <now-ms> <signature.json>...",
    )?;
    let rest = arguments.collect::<Vec<_>>();
    match command.as_str() {
        "prepare" => prepare(&rest),
        "inspect" => inspect(&rest),
        "sign" => sign(&rest),
        "assemble" => assemble(&rest),
        _ => Err("unknown subcommand".into()),
    }
}

fn prepare(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [output, spec_path, proof_path, finality_path, receipt_path, set_path] = arguments else {
        return Err("prepare takes exactly six arguments".into());
    };
    let output = Path::new(output);
    if output.exists() {
        return Err("refusing to overwrite an existing body".into());
    }
    let spec: BundleSpec = serde_json::from_slice(&read_bounded(Path::new(spec_path))?)?;
    let proof: ProofBinding = serde_json::from_slice(&read_bounded(Path::new(proof_path))?)?;
    let checkpoint = checkpoint_inputs(
        &read_bounded(Path::new(finality_path))?,
        &read_bounded(Path::new(receipt_path))?,
    )?;
    let set = read_canonical::<TrustSignerSetV1>(Path::new(set_path))?;
    let body = build_body(&spec, &checkpoint, &proof, &set)?;
    let bundle_id = bundle_id_for_signing(&body)?;
    fs::write(output, encode_envelope(&body).map_err(|_| "body could not be encoded")?)?;

    println!("bundle_id {}", encode_hex(bundle_id.as_bytes()));
    print_body(&body);
    println!("distribute {} to each signer for offline review", output.display());
    Ok(())
}

fn inspect(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [body_path] = arguments else {
        return Err("inspect takes exactly one argument".into());
    };
    let body = read_canonical::<ActumVerifierTrustBundleV1>(Path::new(body_path))?;
    println!("bundle_id {}", encode_hex(bundle_id_for_signing(&body)?.as_bytes()));
    print_body(&body);
    Ok(())
}

fn sign(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [output, secret_path, body_path] = arguments else {
        return Err("sign takes exactly three arguments".into());
    };
    let output = Path::new(output);
    if output.exists() {
        return Err("refusing to overwrite an existing signature".into());
    }
    // The signer recomputes the identity from the canonical body rather than
    // accepting a digest from whoever requested the signature.
    let body = read_canonical::<ActumVerifierTrustBundleV1>(Path::new(body_path))?;
    let bundle_id = bundle_id_for_signing(&body)?;
    let seed = read_seed(Path::new(secret_path))?;
    let signer_id = derive_signer_id(&seed.public_key())?;
    let signature = sign_bundle_id(&seed, bundle_id);
    fs::write(
        output,
        serde_json::to_vec_pretty(&DetachedSignatureFile {
            signer_id_hex: encode_hex(signer_id.as_bytes()),
            signature_hex: encode_hex(&signature),
        })?,
    )?;

    println!("signed bundle_id {}", encode_hex(bundle_id.as_bytes()));
    println!("signer_id {}", encode_hex(signer_id.as_bytes()));
    print_body(&body);
    Ok(())
}

fn assemble(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [output, body_path, set_path, now_ms, signature_paths @ ..] = arguments else {
        return Err("assemble takes at least five arguments".into());
    };
    if signature_paths.is_empty() {
        return Err("at least one detached signature is required".into());
    }
    let output = Path::new(output);
    if output.exists() {
        return Err("refusing to overwrite an existing signed bundle".into());
    }
    let body = read_canonical::<ActumVerifierTrustBundleV1>(Path::new(body_path))?;
    let set = read_canonical::<TrustSignerSetV1>(Path::new(set_path))?;
    let now_ms = now_ms.parse::<u64>()?;
    let mut signatures = Vec::with_capacity(signature_paths.len());
    for path in signature_paths {
        let file: DetachedSignatureFile = serde_json::from_slice(&read_bounded(Path::new(path))?)?;
        let signer_id: [u8; 48] = decode_hex(&file.signer_id_hex, 48)?
            .try_into()
            .map_err(|_| "malformed signer identity")?;
        signatures.push(DetachedSignature {
            signer_id: Digest384::new(signer_id),
            signature: decode_hex(&file.signature_hex, 2_420)?,
        });
    }
    let bundle = activechain_trust_ceremony::assemble_bootstrap(body, &set, &signatures, now_ms)?;
    fs::write(output, encode_envelope(&bundle).map_err(|_| "bundle could not be encoded")?)?;

    println!("bundle_id {}", encode_hex(bundle.bundle_id.as_bytes()));
    println!("signatures {} of threshold {}", bundle.signatures.len(), set.threshold);
    println!("verified against the deployed bootstrap rules at now_ms {now_ms}");
    println!("install {} as signed-trust-bundle.bin (mode 0600)", output.display());
    Ok(())
}

fn print_body(body: &ActumVerifierTrustBundleV1) {
    println!("bundle_sequence {}", body.bundle_sequence);
    println!("chain_id {}", encode_hex(body.chain_id.as_bytes()));
    println!("genesis_commitment {}", encode_hex(body.genesis_commitment.as_bytes()));
    println!("checkpoint_height {}", body.checkpoint_height);
    println!("checkpoint_block_id {}", encode_hex(body.checkpoint_block_id.as_bytes()));
    println!("checkpoint_state_root {}", encode_hex(body.checkpoint_state_root.as_bytes()));
    println!("validator_set_root {}", encode_hex(body.validator_set_root.as_bytes()));
    println!("risc0_image_id {}", encode_hex(&body.risc0_image_id));
    println!("verifier_revision {}", body.verifier_revision);
    println!("policy {} revision {}", encode_hex(body.policy_id.as_bytes()), body.policy_revision);
    println!("valid {}..={}", body.not_before_ms, body.not_after_ms);
    println!("signer_set_id {}", encode_hex(body.signer_set_id.as_bytes()));
    println!("signer_threshold {}", body.signer_threshold);
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_INPUT_BYTES {
        return Err("input is not a bounded regular file".into());
    }
    Ok(fs::read(path)?)
}

fn read_canonical<T: CanonicalType>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > (T::MAX_ENCODED_LEN + 9) as u64 {
        return Err("canonical input is not a bounded regular file".into());
    }
    decode_envelope(&fs::read(path)?).map_err(|_| "invalid canonical input".into())
}

fn read_seed(path: &Path) -> Result<SignerSeed, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err("signer seed must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("signer seed must not be group or world accessible".into());
        }
    }
    let bytes: [u8; 32] = fs::read(path)?.try_into().map_err(|_| "signer seed must be 32 bytes")?;
    Ok(SignerSeed::from_bytes(bytes))
}
