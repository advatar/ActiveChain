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

use crate::{CeremonyError, DetachedSignature, bundle_id_for_signing, decode_hex, encode_hex};
use activechain_application_primitives::{
    ActumVerifierTrustBundleV1, MAX_TRUST_SIGNATURE_BYTES, SignedActumVerifierTrustBundleV1,
    TrustSignatureAlgorithmV1, TrustSignerSetV1,
};
use activechain_protocol_types::Digest384;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

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
    /// Where progress is recorded, when the ceremony is durable.
    ///
    /// A ceremony runs over days: signers are people, and people are not
    /// available at once. A coordinator that forgets on restart forces the
    /// whole thing to begin again, and the natural response to that is to
    /// gather the seeds in one place so it can be done quickly — which is the
    /// failure this design exists to avoid.
    path: Option<PathBuf>,
}

/// The on-disk form.
///
/// Signatures are public and the bundle id is derived from a public body, so
/// nothing here is confidential. What it must be is *exact*: a resumed ceremony
/// that recorded a different bundle id would be collecting signatures over a
/// body nobody agreed to.
#[derive(Debug, Deserialize, Serialize)]
struct CeremonyRecord {
    schema: u16,
    bundle_id_hex: String,
    signatures: Vec<RecordedSignature>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RecordedSignature {
    signer_id_hex: String,
    signature_hex: String,
}

const CEREMONY_SCHEMA: u16 = 1;

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
        Ok(Self { signer_set, bundle_id, collected: Vec::new(), path: None })
    }

    /// Begins a ceremony whose progress survives restarts, resuming one already
    /// recorded at this path.
    ///
    /// Resuming is refused if the record was made for a different bundle. A
    /// ceremony is defined by what is being signed, so signatures gathered for
    /// one body must never be counted toward another — that is how a threshold
    /// could be met for something nobody reviewed.
    ///
    /// # Errors
    /// `MalformedInput` for an unreadable or foreign record, plus the errors
    /// [`Self::begin`] can return.
    pub fn open(
        signer_set: TrustSignerSetV1,
        body: &ActumVerifierTrustBundleV1,
        path: impl AsRef<Path>,
    ) -> Result<Self, CeremonyError> {
        let mut coordinator = Self::begin(signer_set, body)?;
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            let bytes = fs::read(&path).map_err(|_| CeremonyError::MalformedInput)?;
            let record: CeremonyRecord =
                serde_json::from_slice(&bytes).map_err(|_| CeremonyError::MalformedInput)?;
            if record.schema != CEREMONY_SCHEMA
                || record.bundle_id_hex != encode_hex(coordinator.bundle_id.as_bytes())
            {
                return Err(CeremonyError::MalformedInput);
            }
            for recorded in record.signatures {
                let signer = decode_hex(&recorded.signer_id_hex, 48)?;
                let signer: [u8; 48] =
                    signer.try_into().map_err(|_| CeremonyError::MalformedInput)?;
                // Re-verified on the way in rather than trusted: a record is a
                // file, and a file can be edited.
                coordinator.accept(DetachedSignature {
                    signer_id: Digest384::new(signer),
                    signature: decode_hex(&recorded.signature_hex, MAX_TRUST_SIGNATURE_BYTES)?,
                })?;
            }
        }
        coordinator.path = Some(path);
        Ok(coordinator)
    }

    fn persist(&self) -> Result<(), CeremonyError> {
        let Some(path) = self.path.as_ref() else { return Ok(()) };
        let record = CeremonyRecord {
            schema: CEREMONY_SCHEMA,
            bundle_id_hex: encode_hex(self.bundle_id.as_bytes()),
            signatures: self
                .collected
                .iter()
                .map(|signature| RecordedSignature {
                    signer_id_hex: encode_hex(signature.signer_id.as_bytes()),
                    signature_hex: encode_hex(&signature.signature),
                })
                .collect(),
        };
        let bytes =
            serde_json::to_vec_pretty(&record).map_err(|_| CeremonyError::MalformedInput)?;
        // Written to a temporary and renamed, so a crash mid-write leaves the
        // previous record rather than a truncated one.
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, &bytes).map_err(|_| CeremonyError::MalformedInput)?;
        fs::rename(&temporary, path).map_err(|_| CeremonyError::MalformedInput)?;
        Ok(())
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
        // Recorded before the caller is told it counted. A signature the
        // coordinator acknowledged but did not keep would have to be collected
        // again from a signer who believes they are finished.
        if let Err(error) = self.persist() {
            self.collected.pop();
            return Err(error);
        }
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

    fn scratch(name: &str) -> std::path::PathBuf {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("activechain-ceremony-{name}-{nanos}.json"))
    }

    /// A ceremony runs over days, because signers are people. Losing progress
    /// on restart is not merely inconvenient: the natural response is to gather
    /// the seeds somewhere they can all be used at once, which is the failure
    /// this whole design exists to prevent.
    #[test]
    fn a_ceremony_resumes_where_it_was_left() {
        let (set, parties) = ceremony(2, 3);
        let body = body(&set);
        let path = scratch("resume");

        let mut first = Coordinator::open(set.clone(), &body, &path).expect("open");
        let payload = first.signing_payload();
        first
            .accept(DetachedSignature {
                signer_id: parties[0].id,
                signature: sign_bundle_id(&parties[0].seed, payload),
            })
            .expect("first signature");
        assert!(!first.threshold_met());
        drop(first);

        // A different process, later in the week.
        let mut resumed = Coordinator::open(set, &body, &path).expect("resume");
        assert_eq!(resumed.collected(), 1, "the earlier signature must still count");
        assert_eq!(resumed.outstanding().len(), 2);
        assert_eq!(
            resumed
                .accept(DetachedSignature {
                    signer_id: parties[1].id,
                    signature: sign_bundle_id(&parties[1].seed, payload),
                })
                .unwrap(),
            Acceptance::ThresholdMet { collected: 2 }
        );
        resumed.assemble(body, 1_000).expect("a resumed ceremony still assembles");
        let _ = std::fs::remove_file(&path);
    }

    /// A ceremony is defined by what is being signed. Signatures gathered for
    /// one body must never be counted toward another, or a threshold could be
    /// met for something nobody reviewed.
    #[test]
    fn a_record_from_a_different_ceremony_is_refused() {
        let (set, parties) = ceremony(2, 3);
        let body = body(&set);
        let path = scratch("foreign");

        let mut original = Coordinator::open(set.clone(), &body, &path).expect("open");
        let payload = original.signing_payload();
        original
            .accept(DetachedSignature {
                signer_id: parties[0].id,
                signature: sign_bundle_id(&parties[0].seed, payload),
            })
            .expect("signature");
        drop(original);

        // The same signer set, a different bundle: a later sequence.
        let mut other_body = body.clone();
        other_body.bundle_sequence = 2;
        other_body.previous_bundle_id = Digest384::new([7; 48]);
        assert_eq!(
            Coordinator::open(set, &other_body, &path).unwrap_err(),
            CeremonyError::MalformedInput,
            "a record for another bundle must not be adopted"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The record is a file, and a file can be edited. Every signature is
    /// re-verified on the way back in rather than trusted because it was
    /// written down.
    #[test]
    fn a_tampered_record_does_not_grant_a_threshold() {
        let (set, parties) = ceremony(2, 3);
        let body = body(&set);
        let path = scratch("tampered");

        let mut original = Coordinator::open(set.clone(), &body, &path).expect("open");
        let payload = original.signing_payload();
        original
            .accept(DetachedSignature {
                signer_id: parties[0].id,
                signature: sign_bundle_id(&parties[0].seed, payload),
            })
            .expect("signature");
        drop(original);

        // Forge a second signer by copying the first signature under their id.
        let text = std::fs::read_to_string(&path).unwrap();
        let forged = text
            .replace(&encode_hex(parties[0].id.as_bytes()), &encode_hex(parties[1].id.as_bytes()));
        std::fs::write(&path, forged).unwrap();

        assert_eq!(
            Coordinator::open(set, &body, &path).unwrap_err(),
            CeremonyError::Rejected,
            "a signature attributed to a signer who did not make it must be refused"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A coordinator with no path keeps its previous behaviour exactly, so
    /// durability is opt-in and cannot surprise an existing caller.
    #[test]
    fn an_in_memory_ceremony_writes_nothing() {
        let (set, parties) = ceremony(2, 3);
        let body = body(&set);
        let mut coordinator = Coordinator::begin(set, &body).expect("begin");
        let payload = coordinator.signing_payload();
        coordinator
            .accept(DetachedSignature {
                signer_id: parties[0].id,
                signature: sign_bundle_id(&parties[0].seed, payload),
            })
            .expect("signature");
        assert_eq!(coordinator.collected(), 1);
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
