//! Production regulated-transfer admission with fixed finalized chain context.

use activechain_application_primitives::{
    ComplianceAdmissionError, ComplianceKeyRegistry, CompliancePersistenceError,
    DurableComplianceReplayJournal, JurisdictionProfileRegistry, admit_regulated_transfer,
    require_selected_profile,
};
use activechain_protocol_types::{
    AssetId, ChainId, ComplianceEvidenceBindingV1, ComplianceReplayWitness,
    ComplianceSignatureEnvelopeV2, Digest384, TransactionId, TravelRuleBindingV1,
};
use std::path::Path;

/// Validator-owned compliance boundary. Callers cannot substitute a signature verifier or chain
/// context per request; the registry, genesis, and protocol revision are fixed at construction.
pub struct RegulatedTransferAdmission {
    chain_id: ChainId,
    genesis: Digest384,
    protocol_revision: u64,
    registry: ComplianceKeyRegistry,
    replay: DurableComplianceReplayJournal,
    /// Absent unless the chain records an activation. Absent is the case that
    /// must stay bit-identical, because it is every network running today.
    activation: Option<JurisdictionProfileRegistry>,
}

impl RegulatedTransferAdmission {
    pub fn open(
        chain_id: ChainId,
        genesis: Digest384,
        protocol_revision: u64,
        registry: ComplianceKeyRegistry,
        replay_path: &Path,
    ) -> Result<Self, CompliancePersistenceError> {
        if genesis == Digest384::ZERO {
            return Err(CompliancePersistenceError::Persistence);
        }
        Ok(Self {
            chain_id,
            genesis,
            protocol_revision,
            registry,
            replay: DurableComplianceReplayJournal::open(replay_path)?,
            activation: None,
        })
    }

    /// Enables profile enforcement against an activation the chain records.
    ///
    /// The root is the argument that matters. A local snapshot decides nothing:
    /// it is a file on one validator's disk, and the canonical envelope carries
    /// no integrity check, so a damaged or edited one still decodes. Requiring
    /// the caller to supply the root the chain carries — and refusing when the
    /// local registry does not reproduce it — is what makes enforcement a
    /// function of consensus state rather than of whatever this host happens to
    /// hold. Two validators that disagree about the registry cannot both admit;
    /// the one whose file drifted refuses to start enforcing at all.
    ///
    /// This is deliberately not an environment variable. A flag controlling
    /// admission would let two validators evaluate the same transfer
    /// differently and fork the chain on a configuration difference.
    ///
    /// # Errors
    /// Refuses a registry bound to another chain or genesis, and one whose
    /// activation root is not the one the chain recorded.
    pub fn with_activation(
        mut self,
        activation: JurisdictionProfileRegistry,
        chain_recorded_root: Digest384,
    ) -> Result<Self, CompliancePersistenceError> {
        if activation.chain_id() != self.chain_id
            || activation.genesis_commitment() != self.genesis
            || chain_recorded_root == Digest384::ZERO
        {
            return Err(CompliancePersistenceError::Persistence);
        }
        let local =
            activation.activation_root().map_err(|_| CompliancePersistenceError::Persistence)?;
        if local != chain_recorded_root {
            return Err(CompliancePersistenceError::Persistence);
        }
        self.activation = Some(activation);
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &mut self,
        evidence: ComplianceEvidenceBindingV1,
        replay_witness: &ComplianceReplayWitness,
        signature: &ComplianceSignatureEnvelopeV2,
        travel: Option<&TravelRuleBindingV1>,
        action: TransactionId,
        asset: Option<AssetId>,
        amount: Option<u128>,
        finalized_height: u64,
    ) -> Result<(), ComplianceAdmissionError> {
        // Before the replay journal, not after. `admit_regulated_transfer`
        // durably consumes the nonce, so refusing afterwards would spend a
        // one-time value on a transfer that was never admitted — the operator
        // would activate the profile, retry, and be told it was a replay.
        if let Some(activation) = &self.activation {
            let selection = activation.selection_at(finalized_height);
            require_selected_profile(&selection, signature.profile())?;
        }
        admit_regulated_transfer(
            &mut self.replay,
            replay_witness,
            evidence,
            signature,
            travel,
            self.chain_id,
            self.genesis,
            self.protocol_revision,
            action,
            asset,
            amount,
            finalized_height,
            &self.registry,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_accumulator::{AccumulatorDomain, ReferenceSet};
    use activechain_application_primitives::compliance_evidence_commitment;
    use activechain_protocol_types::{
        ComplianceReplayKey, CryptoSuiteId, KenyaControlSet, KenyaRegulatedActivity,
        KenyaRegulatedProfileV1, PrincipalId, ProtocolSignature,
    };
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn replay_witness(key: ComplianceReplayKey) -> ComplianceReplayWitness {
        let reference = ReferenceSet::new(AccumulatorDomain::SpentInput);
        let key = key.accumulator_key();
        let witness = reference.non_membership_witness(key.into_bytes()).unwrap();
        ComplianceReplayWitness::new(
            key,
            witness.siblings.into_iter().map(Digest384::new).collect(),
        )
        .unwrap()
    }

    struct Fixture {
        chain_id: ChainId,
        genesis: Digest384,
        evidence: ComplianceEvidenceBindingV1,
        signature: ComplianceSignatureEnvelopeV2,
        keys: ComplianceKeyRegistry,
        action: TransactionId,
        witness: ComplianceReplayWitness,
    }

    fn fixture() -> Fixture {
        let chain_id = ChainId::new(digest(1));
        let genesis = digest(2);
        let provider = PrincipalId::new(digest(3));
        let action = TransactionId::new(digest(5));
        let evidence = ComplianceEvidenceBindingV1::new(
            digest(6),
            chain_id,
            genesis,
            provider,
            digest(7),
            action,
            digest(8),
            digest(9),
            digest(10),
            10,
            20,
            digest(11),
        )
        .unwrap();
        let signing_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([42; 32]));
        let unsigned = ComplianceSignatureEnvelopeV2::new(
            provider,
            evidence.profile(),
            chain_id,
            genesis,
            7,
            evidence.subject(),
            action,
            compliance_evidence_commitment(&evidence).unwrap(),
            evidence.valid_from(),
            evidence.valid_until(),
            evidence.nonce(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        let signature_bytes = signing_key.sign(&unsigned.signing_payload()).encode().to_vec();
        let signature = ComplianceSignatureEnvelopeV2::new(
            unsigned.provider(),
            unsigned.profile(),
            unsigned.chain_id(),
            unsigned.genesis(),
            unsigned.protocol_revision(),
            unsigned.subject(),
            unsigned.action(),
            unsigned.evidence_commitment(),
            unsigned.valid_from(),
            unsigned.valid_until(),
            unsigned.nonce(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature_bytes).unwrap(),
        )
        .unwrap();
        let mut keys = ComplianceKeyRegistry::default();
        keys.register(evidence.profile(), provider, signing_key.verifying_key().encode().to_vec())
            .unwrap();
        let witness = replay_witness(ComplianceReplayKey::new(
            evidence.profile(),
            evidence.operator(),
            action,
            evidence.nonce(),
        ));
        Fixture { chain_id, genesis, evidence, signature, keys, action, witness }
    }

    /// A complete VASP profile carrying a chosen identity and window.
    fn profile(id: Digest384, effective: u64, expires: u64) -> KenyaRegulatedProfileV1 {
        KenyaRegulatedProfileV1::new(
            id,
            PrincipalId::new(digest(200)),
            KenyaRegulatedActivity::VirtualAssetService,
            KenyaControlSet::VASP_REQUIRED,
            digest(31),
            digest(32),
            digest(33),
            digest(34),
            digest(35),
            digest(36),
            digest(37),
            digest(38),
            digest(39),
            digest(40),
            digest(41),
            digest(42),
            Digest384::ZERO,
            Digest384::ZERO,
            Digest384::ZERO,
            Digest384::ZERO,
            effective,
            expires,
            1,
        )
        .unwrap()
    }

    fn activation(
        chain_id: ChainId,
        genesis: Digest384,
        profiles: &[KenyaRegulatedProfileV1],
    ) -> JurisdictionProfileRegistry {
        let mut registry = JurisdictionProfileRegistry::new(chain_id, genesis).unwrap();
        for entry in profiles {
            registry.activate(*entry).unwrap();
        }
        registry
    }

    #[test]
    fn production_boundary_fixes_context_and_persists_replay() {
        let directory = tempfile::tempdir().unwrap();
        let replay_path = directory.path().join("compliance-replay.bin");
        let f = fixture();

        let mut admission = RegulatedTransferAdmission::open(
            f.chain_id,
            f.genesis,
            7,
            f.keys.clone(),
            &replay_path,
        )
        .unwrap();
        assert_eq!(
            admission.admit(f.evidence, &f.witness, &f.signature, None, f.action, None, None, 15),
            Ok(())
        );
        drop(admission);

        let mut restarted =
            RegulatedTransferAdmission::open(f.chain_id, f.genesis, 7, f.keys, &replay_path)
                .unwrap();
        assert_eq!(
            restarted.admit(f.evidence, &f.witness, &f.signature, None, f.action, None, None, 15),
            Err(ComplianceAdmissionError::Replay(CompliancePersistenceError::Replay))
        );
    }

    /// A chain that records no activation must behave exactly as it did before
    /// activation existed. This is every network running today.
    #[test]
    fn without_an_activation_record_nothing_changes() {
        let directory = tempfile::tempdir().unwrap();
        let f = fixture();
        let mut admission = RegulatedTransferAdmission::open(
            f.chain_id,
            f.genesis,
            7,
            f.keys,
            &directory.path().join("replay.bin"),
        )
        .unwrap();
        assert_eq!(
            admission.admit(f.evidence, &f.witness, &f.signature, None, f.action, None, None, 15),
            Ok(())
        );
    }

    #[test]
    fn an_activated_profile_in_force_is_admitted() {
        let directory = tempfile::tempdir().unwrap();
        let f = fixture();
        let active = activation(f.chain_id, f.genesis, &[profile(f.evidence.profile(), 10, 20)]);
        let root = active.activation_root().unwrap();
        let mut admission = RegulatedTransferAdmission::open(
            f.chain_id,
            f.genesis,
            7,
            f.keys,
            &directory.path().join("replay.bin"),
        )
        .unwrap()
        .with_activation(active, root)
        .unwrap();
        assert_eq!(
            admission.admit(f.evidence, &f.witness, &f.signature, None, f.action, None, None, 15),
            Ok(())
        );
    }

    /// Refusing must not spend the nonce. Otherwise an operator activates the
    /// profile, retries the same transfer, and is told it is a replay — the
    /// transfer becomes permanently unadmittable by having been refused once.
    #[test]
    fn a_profile_not_activated_is_refused_without_consuming_its_nonce() {
        let directory = tempfile::tempdir().unwrap();
        let replay_path = directory.path().join("replay.bin");
        let f = fixture();

        let elsewhere = activation(f.chain_id, f.genesis, &[profile(digest(77), 10, 20)]);
        let root = elsewhere.activation_root().unwrap();
        let mut refusing = RegulatedTransferAdmission::open(
            f.chain_id,
            f.genesis,
            7,
            f.keys.clone(),
            &replay_path,
        )
        .unwrap()
        .with_activation(elsewhere, root)
        .unwrap();
        assert_eq!(
            refusing.admit(f.evidence, &f.witness, &f.signature, None, f.action, None, None, 15),
            Err(ComplianceAdmissionError::ProfileNotSelected)
        );
        drop(refusing);

        let now_active =
            activation(f.chain_id, f.genesis, &[profile(f.evidence.profile(), 10, 20)]);
        let root = now_active.activation_root().unwrap();
        let mut admitting =
            RegulatedTransferAdmission::open(f.chain_id, f.genesis, 7, f.keys, &replay_path)
                .unwrap()
                .with_activation(now_active, root)
                .unwrap();
        assert_eq!(
            admitting.admit(f.evidence, &f.witness, &f.signature, None, f.action, None, None, 15),
            Ok(()),
            "a refusal must leave the nonce spendable once the profile is activated"
        );
    }

    /// A profile whose window has closed is not in force, however complete it is.
    #[test]
    fn an_expired_profile_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let f = fixture();
        let expired = activation(f.chain_id, f.genesis, &[profile(f.evidence.profile(), 1, 5)]);
        let root = expired.activation_root().unwrap();
        let mut admission = RegulatedTransferAdmission::open(
            f.chain_id,
            f.genesis,
            7,
            f.keys,
            &directory.path().join("replay.bin"),
        )
        .unwrap()
        .with_activation(expired, root)
        .unwrap();
        assert_eq!(
            admission.admit(f.evidence, &f.witness, &f.signature, None, f.action, None, None, 15),
            Err(ComplianceAdmissionError::ProfileNotSelected)
        );
    }

    /// The root is what ties enforcement to consensus. A local registry that
    /// does not reproduce the chain's root must refuse to start enforcing
    /// rather than enforce its own idea of the activation set.
    #[test]
    fn a_registry_that_does_not_reproduce_the_recorded_root_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let f = fixture();
        let local = activation(f.chain_id, f.genesis, &[profile(f.evidence.profile(), 10, 20)]);
        let other = activation(f.chain_id, f.genesis, &[profile(digest(77), 10, 20)]);
        let foreign_root = other.activation_root().unwrap();
        let opened = RegulatedTransferAdmission::open(
            f.chain_id,
            f.genesis,
            7,
            f.keys,
            &directory.path().join("replay.bin"),
        )
        .unwrap();
        assert!(
            opened.with_activation(local, foreign_root).is_err(),
            "a drifted local registry must not enforce"
        );
    }

    /// An activation from another chain says nothing here.
    #[test]
    fn a_registry_from_another_chain_or_genesis_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let f = fixture();
        let elsewhere = activation(
            ChainId::new(digest(90)),
            digest(91),
            &[profile(f.evidence.profile(), 10, 20)],
        );
        let root = elsewhere.activation_root().unwrap();
        let opened = RegulatedTransferAdmission::open(
            f.chain_id,
            f.genesis,
            7,
            f.keys,
            &directory.path().join("replay.bin"),
        )
        .unwrap();
        assert!(opened.with_activation(elsewhere, root).is_err());
    }
}
