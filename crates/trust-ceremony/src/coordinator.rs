//! Coordinates a threshold trust ceremony without holding any signing key.
//!
//! A ceremony is a multi-party, multi-session process: a payload is published,
//! signers produce detached signatures independently and at different times,
//! and only then can a bundle be assembled. Something has to track that, and
//! the temptation is to let the operator's tool hold the seeds and simply sign
//! three times.
//!
//! **That would destroy the threshold.** A 2-of-3 whose keys all live in one
//! application is a 1-of-1 wearing a costume: one compromise, one coercion, or
//! one mistake reaches every key at once. The whole point of requiring two
//! independent parties is that they are independent.
//!
//! So this module deliberately cannot sign. Its API accepts public keys and
//! finished signatures; [`crate::SignerSeed`] appears nowhere in it. What it
//! contributes instead is verification at the moment of collection: a bad or
//! foreign signature is rejected against a named signer as it arrives, rather
//! than assembly failing opaquely at the end with nothing to point at.

use crate::{CeremonyError, DetachedSignature, bundle_id_for_signing};
use activechain_application_primitives::{
    ActumVerifierTrustBundleV1, SignedActumVerifierTrustBundleV1, TrustSignatureAlgorithmV1,
    TrustSignerSetV1,
};
use activechain_protocol_types::Digest384;

/// What accepting a signature changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Acceptance {
    /// Recorded, and the threshold is still short.
    Recorded { collected: usize, required: usize },
    /// Recorded, and the ceremony can now be assembled.
    ThresholdMet { collected: usize },
    /// This signer has already signed. Not an error, and not progress either.
    AlreadySigned,
}

/// One ceremony in progress.
#[derive(Clone, Debug)]
pub struct Coordinator {
    signer_set: TrustSignerSetV1,
    bundle_id: Digest384,
    collected: Vec<DetachedSignature>,
}

impl Coordinator {
    /// Begins coordinating a ceremony over the exact body that will be signed.
    ///
    /// # Errors
    /// Returns an error if the signer set is invalid or the body cannot be
    /// committed to.
    pub fn begin(
        signer_set: TrustSignerSetV1,
        body: &ActumVerifierTrustBundleV1,
    ) -> Result<Self, CeremonyError> {
        signer_set.validate().map_err(|_| CeremonyError::InvalidSignerSet)?;
        let bundle_id = bundle_id_for_signing(body)?;
        Ok(Self { signer_set, bundle_id, collected: Vec::new() })
    }

    /// The value each signer signs, published to them out of band.
    #[must_use]
    pub const fn signing_payload(&self) -> Digest384 {
        self.bundle_id
    }

    #[must_use]
    pub fn required(&self) -> usize {
        usize::from(self.signer_set.threshold)
    }

    #[must_use]
    pub fn collected(&self) -> usize {
        self.collected.len()
    }

    #[must_use]
    pub fn threshold_met(&self) -> bool {
        self.collected.len() >= self.required()
    }

    /// Signers who have not yet contributed, so an operator knows who to chase
    /// rather than guessing from a count.
    #[must_use]
    pub fn outstanding(&self) -> Vec<Digest384> {
        self.signer_set
            .signers
            .iter()
            .map(|signer| signer.signer_id)
            .filter(|id| !self.collected.iter().any(|held| held.signer_id == *id))
            .collect()
    }

    /// Records one detached signature, after proving it is what it claims.
    ///
    /// Verification happens here rather than at assembly so a rejection names
    /// the signer responsible. Three things are refused outright: a signer
    /// outside the set, a signature that does not verify against that signer's
    /// public key over this exact payload, and — most importantly — a second
    /// signature from a signer who has already contributed, since counting it
    /// would let one party satisfy a threshold alone.
    ///
    /// # Errors
    /// `UnknownSigner` for a signer outside the set, `Rejected` for a signature
    /// that does not verify.
    pub fn accept(&mut self, signature: DetachedSignature) -> Result<Acceptance, CeremonyError> {
        let signer = self
            .signer_set
            .signers
            .iter()
            .find(|signer| signer.signer_id == signature.signer_id)
            .ok_or(CeremonyError::UnknownSigner)?;

        if self.collected.iter().any(|held| held.signer_id == signature.signer_id) {
            return Ok(Acceptance::AlreadySigned);
        }

        let verified = match signer.algorithm {
            TrustSignatureAlgorithmV1::MlDsa44 => activechain_consensus_verifier::verify_ml_dsa44(
                &signer.public_key,
                self.bundle_id.as_bytes(),
                &signature.signature,
            )
            .is_ok(),
        };
        if !verified {
            return Err(CeremonyError::Rejected);
        }

        self.collected.push(signature);
        if self.threshold_met() {
            Ok(Acceptance::ThresholdMet { collected: self.collected.len() })
        } else {
            Ok(Acceptance::Recorded { collected: self.collected.len(), required: self.required() })
        }
    }

    /// Assembles the signed bundle once enough independent signers have
    /// contributed.
    ///
    /// # Errors
    /// `ThresholdNotMet` before the threshold is reached; assembly errors
    /// otherwise.
    pub fn assemble(
        &self,
        body: ActumVerifierTrustBundleV1,
        now_ms: u64,
    ) -> Result<SignedActumVerifierTrustBundleV1, CeremonyError> {
        if !self.threshold_met() {
            return Err(CeremonyError::ThresholdNotMet);
        }
        crate::assemble_bootstrap(body, &self.signer_set, &self.collected, now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SignerEntry, SignerSeed, build_signer_set, encode_hex, sign_bundle_id};

    struct Party {
        seed: SignerSeed,
        id: Digest384,
    }

    /// Builds a signer set whose seeds stay here, in the test, standing in for
    /// the independent parties that would hold them in reality.
    fn ceremony(threshold: u16, count: usize) -> (TrustSignerSetV1, Vec<Party>) {
        let mut parties = Vec::new();
        let mut entries = Vec::new();
        for _ in 0..count {
            let seed = SignerSeed::generate().expect("seed");
            let public_key = seed.public_key();
            let id = crate::derive_signer_id(&public_key).expect("signer id");
            entries.push(SignerEntry {
                public_key_hex: encode_hex(&public_key),
                valid_from_sequence: 1,
                valid_until_sequence: u64::MAX,
            });
            parties.push(Party { seed, id });
        }
        let set = build_signer_set(1, threshold, &entries).expect("signer set");
        (set, parties)
    }

    fn body(signer_set: &TrustSignerSetV1) -> ActumVerifierTrustBundleV1 {
        let digest = |byte: u8| Digest384::new([byte; 48]);
        let spec = crate::BundleSpec {
            bundle_sequence: 1,
            previous_bundle_id_hex: String::new(),
            policy_id_hex: encode_hex(digest(4).as_bytes()),
            policy_revision: 1,
            issued_at_ms: 0,
            not_before_ms: 0,
            not_after_ms: u64::MAX,
            next_signer_set_id_hex: String::new(),
            next_signer_set_revision: 0,
            next_signer_threshold: 0,
            next_signer_activation_sequence: 0,
        };
        let checkpoint = crate::CheckpointInputs {
            chain_id: digest(1),
            genesis_commitment: digest(2),
            protocol_revision: 1,
            checkpoint_height: 7,
            checkpoint_block_id: digest(5),
            checkpoint_state_root: digest(6),
            checkpoint_finality_commitment: digest(7),
            validator_set_root: digest(8),
        };
        let proof = crate::ProofBinding {
            proof_profile_id_hex: encode_hex(digest(9).as_bytes()),
            proof_system_revision: 1,
            verifier_revision: 1,
            risc0_image_id_hex: encode_hex(&[3_u8; 32]),
        };
        crate::build_body(&spec, &checkpoint, &proof, signer_set).expect("body")
    }

    /// One signer must never be able to satisfy a threshold alone. Counting a
    /// repeated signature would turn a 2-of-3 into a 1-of-1.
    #[test]
    fn one_signer_signing_twice_does_not_meet_a_two_of_three_threshold() {
        let (set, parties) = ceremony(2, 3);
        let body = body(&set);
        let mut coordinator = Coordinator::begin(set, &body).expect("begin");
        let payload = coordinator.signing_payload();

        let first = DetachedSignature {
            signer_id: parties[0].id,
            signature: sign_bundle_id(&parties[0].seed, payload),
        };
        assert_eq!(
            coordinator.accept(first.clone()).unwrap(),
            Acceptance::Recorded { collected: 1, required: 2 }
        );
        assert_eq!(coordinator.accept(first).unwrap(), Acceptance::AlreadySigned);
        assert!(!coordinator.threshold_met(), "a repeat must not advance the threshold");

        // A genuinely independent second signer does.
        let second = DetachedSignature {
            signer_id: parties[1].id,
            signature: sign_bundle_id(&parties[1].seed, payload),
        };
        assert_eq!(coordinator.accept(second).unwrap(), Acceptance::ThresholdMet { collected: 2 });
    }

    /// A signature is verified when it arrives, so the rejection names the
    /// signer rather than surfacing as an opaque assembly failure later.
    #[test]
    fn a_signature_that_does_not_verify_is_refused_at_collection() {
        let (set, parties) = ceremony(2, 3);
        let body = body(&set);
        let mut coordinator = Coordinator::begin(set, &body).expect("begin");
        let payload = coordinator.signing_payload();

        // Signed by party 1 but attributed to party 0.
        let misattributed = DetachedSignature {
            signer_id: parties[0].id,
            signature: sign_bundle_id(&parties[1].seed, payload),
        };
        assert_eq!(coordinator.accept(misattributed), Err(CeremonyError::Rejected));

        // A signature over something other than this ceremony's payload.
        let wrong_payload = DetachedSignature {
            signer_id: parties[0].id,
            signature: sign_bundle_id(&parties[0].seed, Digest384::new([9; 48])),
        };
        assert_eq!(coordinator.accept(wrong_payload), Err(CeremonyError::Rejected));
        assert_eq!(coordinator.collected(), 0);
    }

    #[test]
    fn a_signer_outside_the_set_is_refused() {
        let (set, _) = ceremony(2, 3);
        let (_, strangers) = ceremony(1, 1);
        let body = body(&set);
        let mut coordinator = Coordinator::begin(set, &body).expect("begin");
        let payload = coordinator.signing_payload();
        let outsider = DetachedSignature {
            signer_id: strangers[0].id,
            signature: sign_bundle_id(&strangers[0].seed, payload),
        };
        assert_eq!(coordinator.accept(outsider), Err(CeremonyError::UnknownSigner));
    }

    /// The operator needs to know who is missing, not merely how many are.
    #[test]
    fn outstanding_signers_are_named_and_assembly_waits_for_them() {
        let (set, parties) = ceremony(2, 3);
        let body = body(&set);
        let mut coordinator = Coordinator::begin(set, &body).expect("begin");
        assert_eq!(coordinator.outstanding().len(), 3);
        assert_eq!(coordinator.assemble(body.clone(), 1_000), Err(CeremonyError::ThresholdNotMet));

        let payload = coordinator.signing_payload();
        coordinator
            .accept(DetachedSignature {
                signer_id: parties[0].id,
                signature: sign_bundle_id(&parties[0].seed, payload),
            })
            .unwrap();
        let outstanding = coordinator.outstanding();
        assert_eq!(outstanding.len(), 2);
        assert!(!outstanding.contains(&parties[0].id));
        assert_eq!(coordinator.assemble(body.clone(), 1_000), Err(CeremonyError::ThresholdNotMet));
    }

    /// The end to end path: independent signatures, then a bundle that the
    /// verifier host itself accepts.
    #[test]
    fn independent_signatures_assemble_into_a_deployable_bundle() {
        let (set, parties) = ceremony(2, 3);
        let body = body(&set);
        let mut coordinator = Coordinator::begin(set, &body).expect("begin");
        let payload = coordinator.signing_payload();
        for party in parties.iter().take(2) {
            coordinator
                .accept(DetachedSignature {
                    signer_id: party.id,
                    signature: sign_bundle_id(&party.seed, payload),
                })
                .expect("independent signature");
        }
        let bundle = coordinator.assemble(body.clone(), 1_000).expect("assembled bundle");
        assert_eq!(bundle.signatures.len(), 2);
        assert_eq!(bundle.bundle_id, payload);
    }
}
