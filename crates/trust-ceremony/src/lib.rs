//! Offline construction and signing of Actum verifier trust bundles.
//!
//! The ceremony is deliberately split so that a signing key never has to exist
//! on a verifier host. [`bundle_id_for_signing`] derives the exact 48-byte
//! value a signer authorizes, [`sign_bundle_id`] is the only entry point that
//! touches secret material, and [`assemble_bootstrap`] recombines detached
//! signatures and refuses to emit a bundle that the deployed verifier would
//! reject.
//!
//! The repository does not choose production trust authority. This crate only
//! encodes what an operator decided, and fails closed when the decision does
//! not satisfy the frozen `SignedActumVerifierTrustBundleV1` semantics.

use activechain_application_primitives::{
    ActumVerifierTrustBundleV1, MAX_TRUST_PUBLIC_KEY_BYTES, MAX_TRUST_SIGNATURE_BYTES,
    SignedActumVerifierTrustBundleV1, TrustBundleSignatureV1, TrustSignatureAlgorithmV1,
    TrustSignerSetV1, TrustSignerV1, verify_trust_bundle_bootstrap,
};
use activechain_canonical_codec::decode_envelope;
use activechain_devnet_kernel::BlockReceipt;
use activechain_finality_types::FinalityCertificateBundle;
use activechain_protocol_types::Digest384;
use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_384};
use zeroize::Zeroize;

/// Domain separator for the tool's deterministic signer identity convention.
pub const SIGNER_ID_DOMAIN: &[u8] = b"ACTUM-TRUST-SIGNER-ID-V1";
/// Byte length of an ML-DSA-44 seed, the only secret this crate persists.
pub const SEED_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyError {
    /// Randomness was unavailable, so no seed was produced.
    Entropy,
    /// A public key, signature, or digest had the wrong length or was zero.
    MalformedInput,
    /// A canonical envelope could not be decoded.
    Decode,
    /// A canonical value could not be encoded.
    Encode,
    /// The requested signer set violates the frozen signer-set rules.
    InvalidSignerSet,
    /// The requested body violates the frozen trust-bundle rules.
    InvalidBundle,
    /// A detached signature did not name a signer in the set.
    UnknownSigner,
    /// Fewer valid signatures were supplied than the threshold requires.
    ThresholdNotMet,
    /// The assembled bundle failed the deployed bootstrap verification.
    Rejected,
}

impl core::fmt::Display for CeremonyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::Entropy => "system randomness was unavailable",
            Self::MalformedInput => "input was not a well-formed fixed-length value",
            Self::Decode => "canonical envelope could not be decoded",
            Self::Encode => "canonical value could not be encoded",
            Self::InvalidSignerSet => "signer set violates the frozen signer-set rules",
            Self::InvalidBundle => "bundle body violates the frozen trust-bundle rules",
            Self::UnknownSigner => "detached signature names a signer outside the set",
            Self::ThresholdNotMet => "fewer signatures than the signer set requires",
            Self::Rejected => "assembled bundle failed deployed bootstrap verification",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CeremonyError {}

/// A secret ML-DSA-44 seed that zeroizes when it leaves scope.
pub struct SignerSeed([u8; SEED_BYTES]);

impl SignerSeed {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SEED_BYTES]) -> Self {
        Self(bytes)
    }

    /// Draws a fresh seed from the operating system CSPRNG.
    pub fn generate() -> Result<Self, CeremonyError> {
        let mut bytes = [0u8; SEED_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| CeremonyError::Entropy)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn expose(&self) -> &[u8; SEED_BYTES] {
        &self.0
    }

    /// Returns the ML-DSA-44 public key this seed authorizes.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        signing_key(&self.0).verifying_key().encode().as_slice().to_vec()
    }
}

impl Drop for SignerSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn signing_key(seed: &[u8; SEED_BYTES]) -> SigningKey<MlDsa44> {
    SigningKey::<MlDsa44>::from_seed(&Seed::from(*seed))
}

/// Derives this tool's deterministic signer identity from a public key.
///
/// Binding the identity to the key means a signer set cannot mislabel which
/// key a signer holds, and any party can recompute the identity offline.
pub fn derive_signer_id(public_key: &[u8]) -> Result<Digest384, CeremonyError> {
    if public_key.len() != MAX_TRUST_PUBLIC_KEY_BYTES {
        return Err(CeremonyError::MalformedInput);
    }
    let mut hash = Sha3_384::new();
    hash.update(SIGNER_ID_DOMAIN);
    hash.update(public_key);
    Ok(Digest384::new(hash.finalize().into()))
}

/// Signs one bundle identity. This is the only function that reads a secret.
pub fn sign_bundle_id(seed: &SignerSeed, bundle_id: Digest384) -> Vec<u8> {
    signing_key(seed.expose()).sign(bundle_id.as_bytes()).encode().as_slice().to_vec()
}

/// One signer's public position in a prospective signer set.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerEntry {
    /// Lowercase hex ML-DSA-44 public key.
    pub public_key_hex: String,
    pub valid_from_sequence: u64,
    pub valid_until_sequence: u64,
}

/// Builds a canonical signer set, sorted by the derived signer identity.
pub fn build_signer_set(
    revision: u32,
    threshold: u16,
    entries: &[SignerEntry],
) -> Result<TrustSignerSetV1, CeremonyError> {
    let mut signers = Vec::with_capacity(entries.len());
    for entry in entries {
        let public_key = decode_hex(&entry.public_key_hex, MAX_TRUST_PUBLIC_KEY_BYTES)?;
        signers.push(TrustSignerV1 {
            signer_id: derive_signer_id(&public_key)?,
            algorithm: TrustSignatureAlgorithmV1::MlDsa44,
            public_key,
            valid_from_sequence: entry.valid_from_sequence,
            valid_until_sequence: entry.valid_until_sequence,
        });
    }
    signers.sort_by_key(|signer| signer.signer_id);
    let set = TrustSignerSetV1 { revision, signers, threshold };
    set.validate().map_err(|_| CeremonyError::InvalidSignerSet)?;
    Ok(set)
}

/// Checkpoint facts read from a real finalized block, never typed by hand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointInputs {
    pub chain_id: Digest384,
    pub genesis_commitment: Digest384,
    pub protocol_revision: u32,
    pub checkpoint_height: u64,
    pub checkpoint_block_id: Digest384,
    pub checkpoint_state_root: Digest384,
    pub checkpoint_finality_commitment: Digest384,
    pub validator_set_root: Digest384,
}

/// Derives every checkpoint-bound bundle field from a finalized block.
///
/// Hand-entered checkpoint identity is the most likely way to produce a bundle
/// that signs cleanly and then rejects every real anchor, so the ceremony reads
/// these values from the same finality bundle and block receipt the verifier
/// consumes.
pub fn checkpoint_inputs(
    finality_envelope: &[u8],
    receipt_envelope: &[u8],
) -> Result<CheckpointInputs, CeremonyError> {
    let finality = decode_envelope::<FinalityCertificateBundle>(finality_envelope)
        .map_err(|_| CeremonyError::Decode)?;
    let receipt =
        decode_envelope::<BlockReceipt>(receipt_envelope).map_err(|_| CeremonyError::Decode)?;
    let header = finality.header();
    let inputs = header.inputs;
    if receipt.height() != inputs.height || receipt.post_state() != inputs.post_state {
        return Err(CeremonyError::MalformedInput);
    }
    let protocol_revision =
        u32::try_from(inputs.protocol_revision).map_err(|_| CeremonyError::MalformedInput)?;
    Ok(CheckpointInputs {
        chain_id: *inputs.chain_id.digest(),
        genesis_commitment: finality.certificate().genesis_commitment(),
        protocol_revision,
        checkpoint_height: inputs.height,
        checkpoint_block_id: receipt.block_id(),
        checkpoint_state_root: inputs.post_state.root(),
        checkpoint_finality_commitment: header.proof_statement_commitment,
        validator_set_root: inputs.validator_set_root,
    })
}

/// The proof-relation values a bundle must pin, emitted by the deployed
/// verifier build rather than chosen during the ceremony.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofBinding {
    pub proof_profile_id_hex: String,
    pub proof_system_revision: u32,
    pub verifier_revision: u32,
    pub risc0_image_id_hex: String,
}

/// Operator decisions that no artifact can supply.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BundleSpec {
    pub bundle_sequence: u64,
    #[serde(default)]
    pub previous_bundle_id_hex: String,
    pub policy_id_hex: String,
    pub policy_revision: u32,
    pub issued_at_ms: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    #[serde(default)]
    pub next_signer_set_id_hex: String,
    #[serde(default)]
    pub next_signer_set_revision: u32,
    #[serde(default)]
    pub next_signer_threshold: u16,
    #[serde(default)]
    pub next_signer_activation_sequence: u64,
}

/// Assembles the unsigned canonical body and fails closed on any violation.
pub fn build_body(
    spec: &BundleSpec,
    checkpoint: &CheckpointInputs,
    proof: &ProofBinding,
    signer_set: &TrustSignerSetV1,
) -> Result<ActumVerifierTrustBundleV1, CeremonyError> {
    let signer_set_id = signer_set.signer_set_id().map_err(|_| CeremonyError::InvalidSignerSet)?;
    let image = decode_hex(&proof.risc0_image_id_hex, 32)?;
    let image: [u8; 32] = image.try_into().map_err(|_| CeremonyError::MalformedInput)?;
    let body = ActumVerifierTrustBundleV1 {
        schema_revision: 1,
        bundle_sequence: spec.bundle_sequence,
        previous_bundle_id: optional_digest(&spec.previous_bundle_id_hex)?,
        chain_id: checkpoint.chain_id,
        genesis_commitment: checkpoint.genesis_commitment,
        protocol_revision: checkpoint.protocol_revision,
        checkpoint_height: checkpoint.checkpoint_height,
        checkpoint_block_id: checkpoint.checkpoint_block_id,
        checkpoint_state_root: checkpoint.checkpoint_state_root,
        checkpoint_finality_commitment: checkpoint.checkpoint_finality_commitment,
        validator_set_root: checkpoint.validator_set_root,
        proof_profile_id: required_digest(&proof.proof_profile_id_hex)?,
        proof_system_revision: proof.proof_system_revision,
        verifier_revision: proof.verifier_revision,
        risc0_image_id: image,
        policy_id: required_digest(&spec.policy_id_hex)?,
        policy_revision: spec.policy_revision,
        issued_at_ms: spec.issued_at_ms,
        not_before_ms: spec.not_before_ms,
        not_after_ms: spec.not_after_ms,
        signer_set_id,
        signer_set_revision: signer_set.revision,
        signer_threshold: signer_set.threshold,
        next_signer_set_id: optional_digest(&spec.next_signer_set_id_hex)?,
        next_signer_set_revision: spec.next_signer_set_revision,
        next_signer_threshold: spec.next_signer_threshold,
        next_signer_activation_sequence: spec.next_signer_activation_sequence,
    };
    body.validate().map_err(|_| CeremonyError::InvalidBundle)?;
    Ok(body)
}

/// Returns the exact value each offline signer authorizes.
pub fn bundle_id_for_signing(
    body: &ActumVerifierTrustBundleV1,
) -> Result<Digest384, CeremonyError> {
    body.bundle_id().map_err(|_| CeremonyError::InvalidBundle)
}

/// One detached signature carried back from an offline signer.
#[derive(Clone, Debug)]
pub struct DetachedSignature {
    pub signer_id: Digest384,
    pub signature: Vec<u8>,
}

/// Recombines detached signatures into a deployable bootstrap bundle.
///
/// The result is verified with the same entry point the verifier host uses, so
/// a bundle that would be rejected on deployment is never written to disk.
pub fn assemble_bootstrap(
    body: ActumVerifierTrustBundleV1,
    signer_set: &TrustSignerSetV1,
    signatures: &[DetachedSignature],
    now_ms: u64,
) -> Result<SignedActumVerifierTrustBundleV1, CeremonyError> {
    let bundle_id = bundle_id_for_signing(&body)?;
    let signer_set_id = signer_set.signer_set_id().map_err(|_| CeremonyError::InvalidSignerSet)?;
    if signatures.len() < usize::from(signer_set.threshold) {
        return Err(CeremonyError::ThresholdNotMet);
    }
    let mut assembled = Vec::with_capacity(signatures.len());
    for detached in signatures {
        if detached.signature.len() != MAX_TRUST_SIGNATURE_BYTES {
            return Err(CeremonyError::MalformedInput);
        }
        if !signer_set.signers.iter().any(|signer| signer.signer_id == detached.signer_id) {
            return Err(CeremonyError::UnknownSigner);
        }
        assembled.push(TrustBundleSignatureV1 {
            signer_set_id,
            signer_id: detached.signer_id,
            algorithm: TrustSignatureAlgorithmV1::MlDsa44,
            signature: detached.signature.clone(),
        });
    }
    assembled.sort_by_key(|signature| (signature.signer_set_id, signature.signer_id));
    if assembled.windows(2).any(|pair| pair[0].signer_id == pair[1].signer_id) {
        return Err(CeremonyError::MalformedInput);
    }
    let bundle = SignedActumVerifierTrustBundleV1 { body, bundle_id, signatures: assembled };
    verify_trust_bundle_bootstrap(&bundle, signer_set, now_ms, &verify_signature)
        .map_err(|_| CeremonyError::Rejected)?;
    Ok(bundle)
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

fn optional_digest(value: &str) -> Result<Digest384, CeremonyError> {
    if value.is_empty() {
        return Ok(Digest384::ZERO);
    }
    required_digest(value)
}

fn required_digest(value: &str) -> Result<Digest384, CeremonyError> {
    let bytes = decode_hex(value, 48)?;
    let bytes: [u8; 48] = bytes.try_into().map_err(|_| CeremonyError::MalformedInput)?;
    Ok(Digest384::new(bytes))
}

/// Decodes exactly `expected` bytes of lowercase hex.
pub fn decode_hex(value: &str, expected: usize) -> Result<Vec<u8>, CeremonyError> {
    if value.len() != expected * 2
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CeremonyError::MalformedInput);
    }
    let mut decoded = Vec::with_capacity(expected);
    for pair in value.as_bytes().chunks_exact(2) {
        decoded.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(decoded)
}

/// Encodes bytes as lowercase hex.
#[must_use]
pub fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

const fn nibble(value: u8) -> Result<u8, CeremonyError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CeremonyError::MalformedInput),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seed: &SignerSeed) -> SignerEntry {
        SignerEntry {
            public_key_hex: encode_hex(&seed.public_key()),
            valid_from_sequence: 1,
            valid_until_sequence: 64,
        }
    }

    fn checkpoint() -> CheckpointInputs {
        CheckpointInputs {
            chain_id: Digest384::new([1; 48]),
            genesis_commitment: Digest384::new([2; 48]),
            protocol_revision: 4,
            checkpoint_height: 12,
            checkpoint_block_id: Digest384::new([3; 48]),
            checkpoint_state_root: Digest384::new([4; 48]),
            checkpoint_finality_commitment: Digest384::new([5; 48]),
            validator_set_root: Digest384::new([6; 48]),
        }
    }

    fn proof() -> ProofBinding {
        ProofBinding {
            proof_profile_id_hex: encode_hex(&[7; 48]),
            proof_system_revision: 1,
            verifier_revision: 1,
            risc0_image_id_hex: encode_hex(&[8; 32]),
        }
    }

    fn spec() -> BundleSpec {
        BundleSpec {
            bundle_sequence: 1,
            previous_bundle_id_hex: String::new(),
            policy_id_hex: encode_hex(&[9; 48]),
            policy_revision: 1,
            issued_at_ms: 1_000,
            not_before_ms: 1_000,
            not_after_ms: 605_000,
            next_signer_set_id_hex: String::new(),
            next_signer_set_revision: 0,
            next_signer_threshold: 0,
            next_signer_activation_sequence: 0,
        }
    }

    #[test]
    fn signer_identity_binds_to_the_public_key() {
        let seed = SignerSeed::generate().expect("seed");
        let other = SignerSeed::generate().expect("seed");
        let key = seed.public_key();
        assert_eq!(key.len(), MAX_TRUST_PUBLIC_KEY_BYTES);
        assert_eq!(derive_signer_id(&key), derive_signer_id(&seed.public_key()));
        assert_ne!(derive_signer_id(&key), derive_signer_id(&other.public_key()));
        assert_eq!(derive_signer_id(&key[..8]), Err(CeremonyError::MalformedInput));
    }

    #[test]
    fn a_single_offline_signer_produces_a_deployable_bootstrap_bundle() {
        let seed = SignerSeed::generate().expect("seed");
        let set = build_signer_set(1, 1, &[entry(&seed)]).expect("signer set");
        let body = build_body(&spec(), &checkpoint(), &proof(), &set).expect("body");
        let bundle_id = bundle_id_for_signing(&body).expect("bundle id");
        let detached = DetachedSignature {
            signer_id: derive_signer_id(&seed.public_key()).expect("signer id"),
            signature: sign_bundle_id(&seed, bundle_id),
        };
        let bundle = assemble_bootstrap(body, &set, &[detached], 2_000).expect("bundle");
        assert_eq!(bundle.bundle_id, bundle_id);
        assert_eq!(bundle.signatures.len(), 1);
    }

    #[test]
    fn threshold_sets_reject_an_incomplete_or_foreign_signature() {
        let first = SignerSeed::generate().expect("seed");
        let second = SignerSeed::generate().expect("seed");
        let third = SignerSeed::generate().expect("seed");
        let outsider = SignerSeed::generate().expect("seed");
        let set = build_signer_set(1, 2, &[entry(&first), entry(&second), entry(&third)])
            .expect("signer set");
        let body = build_body(&spec(), &checkpoint(), &proof(), &set).expect("body");
        let bundle_id = bundle_id_for_signing(&body).expect("bundle id");
        let sign = |seed: &SignerSeed| DetachedSignature {
            signer_id: derive_signer_id(&seed.public_key()).expect("signer id"),
            signature: sign_bundle_id(seed, bundle_id),
        };

        assert_eq!(
            assemble_bootstrap(body.clone(), &set, &[sign(&first)], 2_000).unwrap_err(),
            CeremonyError::ThresholdNotMet
        );
        assert_eq!(
            assemble_bootstrap(body.clone(), &set, &[sign(&first), sign(&outsider)], 2_000)
                .unwrap_err(),
            CeremonyError::UnknownSigner
        );
        assert_eq!(
            assemble_bootstrap(body.clone(), &set, &[sign(&first), sign(&first)], 2_000)
                .unwrap_err(),
            CeremonyError::MalformedInput
        );
        assemble_bootstrap(body, &set, &[sign(&first), sign(&third)], 2_000).expect("bundle");
    }

    #[test]
    fn a_signature_over_a_different_body_is_rejected() {
        let seed = SignerSeed::generate().expect("seed");
        let set = build_signer_set(1, 1, &[entry(&seed)]).expect("signer set");
        let body = build_body(&spec(), &checkpoint(), &proof(), &set).expect("body");
        let mut other_checkpoint = checkpoint();
        other_checkpoint.checkpoint_height = 13;
        let other = build_body(&spec(), &other_checkpoint, &proof(), &set).expect("body");
        let stale = DetachedSignature {
            signer_id: derive_signer_id(&seed.public_key()).expect("signer id"),
            signature: sign_bundle_id(&seed, bundle_id_for_signing(&other).expect("bundle id")),
        };
        assert_eq!(
            assemble_bootstrap(body, &set, &[stale], 2_000).unwrap_err(),
            CeremonyError::Rejected
        );
    }

    #[test]
    fn a_bundle_outside_its_validity_window_is_rejected() {
        let seed = SignerSeed::generate().expect("seed");
        let set = build_signer_set(1, 1, &[entry(&seed)]).expect("signer set");
        let body = build_body(&spec(), &checkpoint(), &proof(), &set).expect("body");
        let bundle_id = bundle_id_for_signing(&body).expect("bundle id");
        let detached = DetachedSignature {
            signer_id: derive_signer_id(&seed.public_key()).expect("signer id"),
            signature: sign_bundle_id(&seed, bundle_id),
        };
        assert_eq!(
            assemble_bootstrap(body, &set, &[detached], 999_999).unwrap_err(),
            CeremonyError::Rejected
        );
    }

    #[test]
    fn malformed_operator_decisions_fail_closed() {
        let seed = SignerSeed::generate().expect("seed");
        let set = build_signer_set(1, 1, &[entry(&seed)]).expect("signer set");
        assert_eq!(build_signer_set(0, 1, &[entry(&seed)]), Err(CeremonyError::InvalidSignerSet));
        assert_eq!(build_signer_set(1, 2, &[entry(&seed)]), Err(CeremonyError::InvalidSignerSet));

        let mut bootstrap_with_previous = spec();
        bootstrap_with_previous.previous_bundle_id_hex = encode_hex(&[1; 48]);
        assert_eq!(
            build_body(&bootstrap_with_previous, &checkpoint(), &proof(), &set),
            Err(CeremonyError::InvalidBundle)
        );

        let mut inverted = spec();
        inverted.not_after_ms = inverted.not_before_ms;
        assert_eq!(
            build_body(&inverted, &checkpoint(), &proof(), &set),
            Err(CeremonyError::InvalidBundle)
        );

        let mut zero_image = proof();
        zero_image.risc0_image_id_hex = encode_hex(&[0; 32]);
        assert_eq!(
            build_body(&spec(), &checkpoint(), &zero_image, &set),
            Err(CeremonyError::InvalidBundle)
        );

        assert_eq!(decode_hex("AA", 1), Err(CeremonyError::MalformedInput));
        assert_eq!(decode_hex("aabb", 1), Err(CeremonyError::MalformedInput));
    }
}
