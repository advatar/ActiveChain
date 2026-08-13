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
         \x20 prepare  <body-out> <spec.json> <proof.json> <finality.bundle> <execution.snapshot> <signer-set.bin>\n\
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
    let [output, spec_path, proof_path, finality_path, execution_path, set_path] = arguments else {
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
        &read_bounded(Path::new(execution_path))?,
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

/// Renders every field a signer authorizes.
///
/// A signature is over the whole body, so a review that shows part of it is a
/// review of nothing in particular. The rotation fields matter most: a bundle
/// can name the signer set that replaces this one, and a signer who never saw
/// that is handing over control without knowing it. They are stated in words
/// rather than left as another digest for exactly that reason.
fn render_body(body: &ActumVerifierTrustBundleV1) -> String {
    let mut out = String::new();
    out.push_str(&format!("bundle_sequence {}\n", body.bundle_sequence));
    out.push_str(&format!(
        "previous_bundle_id {}\n",
        if body.previous_bundle_id == Digest384::ZERO {
            "none (this is a bootstrap bundle)".to_owned()
        } else {
            encode_hex(body.previous_bundle_id.as_bytes())
        }
    ));
    out.push_str(&format!("chain_id {}\n", encode_hex(body.chain_id.as_bytes())));
    out.push_str(&format!(
        "genesis_commitment {}\n",
        encode_hex(body.genesis_commitment.as_bytes())
    ));
    out.push_str(&format!("protocol_revision {}\n", body.protocol_revision));
    out.push_str(&format!("checkpoint_height {}\n", body.checkpoint_height));
    out.push_str(&format!(
        "checkpoint_block_id {}\n",
        encode_hex(body.checkpoint_block_id.as_bytes())
    ));
    out.push_str(&format!(
        "checkpoint_state_root {}\n",
        encode_hex(body.checkpoint_state_root.as_bytes())
    ));
    out.push_str(&format!(
        "checkpoint_finality_commitment {}\n",
        encode_hex(body.checkpoint_finality_commitment.as_bytes())
    ));
    out.push_str(&format!(
        "validator_set_root {}\n",
        encode_hex(body.validator_set_root.as_bytes())
    ));
    out.push_str(&format!("proof_profile_id {}\n", encode_hex(body.proof_profile_id.as_bytes())));
    out.push_str(&format!("proof_system_revision {}\n", body.proof_system_revision));
    out.push_str(&format!("risc0_image_id {}\n", encode_hex(&body.risc0_image_id)));
    out.push_str(&format!("verifier_revision {}\n", body.verifier_revision));
    out.push_str(&format!(
        "policy {} revision {}\n",
        encode_hex(body.policy_id.as_bytes()),
        body.policy_revision
    ));
    out.push_str(&format!("issued_at_ms {}\n", body.issued_at_ms));
    out.push_str(&format!("valid {}..={}\n", body.not_before_ms, body.not_after_ms));
    out.push_str(&format!("signer_set_id {}\n", encode_hex(body.signer_set_id.as_bytes())));
    out.push_str(&format!("signer_set_revision {}\n", body.signer_set_revision));
    out.push_str(&format!("signer_threshold {}\n", body.signer_threshold));

    if body.next_signer_set_id == Digest384::ZERO {
        out.push_str("rotation none: this bundle does not change who signs\n");
    } else {
        out.push_str("ROTATION: this bundle hands signing authority to a different signer set.\n");
        out.push_str(&format!(
            "  next_signer_set_id {}\n  next_signer_set_revision {}\n               next_signer_threshold {}\n  next_signer_activation_sequence {}\n",
            encode_hex(body.next_signer_set_id.as_bytes()),
            body.next_signer_set_revision,
            body.next_signer_threshold,
            body.next_signer_activation_sequence
        ));
        out.push_str(
            "  Do not sign unless you recognise that signer set and intend it to replace \
             this one.\n",
        );
    }
    out
}

fn print_body(body: &ActumVerifierTrustBundleV1) {
    print!("{}", render_body(body));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn body(rotating: bool) -> ActumVerifierTrustBundleV1 {
        let digest = |byte: u8| Digest384::new([byte; 48]);
        ActumVerifierTrustBundleV1 {
            schema_revision: 1,
            bundle_sequence: 1,
            previous_bundle_id: Digest384::ZERO,
            chain_id: digest(0x11),
            genesis_commitment: digest(0x22),
            protocol_revision: 7,
            checkpoint_height: 4_242,
            checkpoint_block_id: digest(0x33),
            checkpoint_state_root: digest(0x44),
            checkpoint_finality_commitment: digest(0x55),
            validator_set_root: digest(0x66),
            proof_profile_id: digest(0x77),
            proof_system_revision: 9,
            verifier_revision: 11,
            risc0_image_id: [0x88; 32],
            policy_id: digest(0x99),
            policy_revision: 13,
            issued_at_ms: 1_000,
            not_before_ms: 1_000,
            not_after_ms: 9_000,
            signer_set_id: digest(0xaa),
            signer_set_revision: 3,
            signer_threshold: 2,
            next_signer_set_id: if rotating { digest(0xbb) } else { Digest384::ZERO },
            next_signer_set_revision: if rotating { 4 } else { 0 },
            next_signer_threshold: if rotating { 3 } else { 0 },
            next_signer_activation_sequence: if rotating { 99 } else { 0 },
        }
    }

    /// A signature covers the whole body, so a review showing part of it is a
    /// review of nothing in particular. Every distinctive value must appear.
    #[test]
    fn the_review_shows_every_field_the_signature_covers() {
        let rendered = render_body(&body(true));
        for expected in [
            "4242", // checkpoint height
            "protocol_revision 7",
            "proof_system_revision 9",
            "verifier_revision 11",
            "policy_revision 13", // rendered as "revision 13"
            "signer_set_revision 3",
            "signer_threshold 2",
            "issued_at_ms 1000",
        ] {
            let needle = expected.rsplit(' ').next().unwrap_or(expected);
            assert!(
                rendered.contains(needle),
                "the review omits {expected}; a signer would authorize it unseen"
            );
        }
        for byte in [0x11_u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb] {
            let hex = format!("{byte:02x}{byte:02x}{byte:02x}{byte:02x}");
            assert!(
                rendered.contains(&hex),
                "the review omits the field whose bytes are {byte:02x}; \
                 a signer would authorize it unseen"
            );
        }
    }

    /// Handing signing authority to another set is the most consequential thing
    /// a bundle can say. It must be stated, not left as an unremarked digest.
    #[test]
    fn a_rotation_is_announced_in_words_and_its_absence_is_too() {
        let rotating = render_body(&body(true));
        assert!(rotating.contains("ROTATION"), "a rotation must be impossible to miss");
        assert!(rotating.contains("99"), "the activation sequence must be shown");
        assert!(rotating.contains("Do not sign unless you recognise that signer set"));

        let ordinary = render_body(&body(false));
        assert!(
            ordinary.contains("rotation none"),
            "the absence of a rotation must be stated, so silence is never the signal"
        );
        assert!(!ordinary.contains("ROTATION"));
    }

    /// A bootstrap bundle has no predecessor, and saying so is clearer than
    /// printing 96 zeroes for a signer to interpret.
    #[test]
    fn a_bootstrap_bundle_says_it_has_no_predecessor() {
        assert!(render_body(&body(false)).contains("none (this is a bootstrap bundle)"));
    }
}
