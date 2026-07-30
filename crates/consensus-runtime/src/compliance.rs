//! Production regulated-transfer admission with fixed finalized chain context.

use activechain_application_primitives::{
    ComplianceAdmissionError, ComplianceKeyRegistry, CompliancePersistenceError,
    DurableComplianceReplayJournal, admit_regulated_transfer,
};
use activechain_protocol_types::{
    AssetId, ChainId, ComplianceEvidenceBindingV1, ComplianceSignatureEnvelopeV2, Digest384,
    TransactionId, TravelRuleBindingV1,
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
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &mut self,
        evidence: ComplianceEvidenceBindingV1,
        signature: &ComplianceSignatureEnvelopeV2,
        travel: Option<&TravelRuleBindingV1>,
        action: TransactionId,
        asset: Option<AssetId>,
        amount: Option<u128>,
        finalized_height: u64,
    ) -> Result<(), ComplianceAdmissionError> {
        admit_regulated_transfer(
            &mut self.replay,
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
    use activechain_application_primitives::compliance_evidence_commitment;
    use activechain_protocol_types::{CryptoSuiteId, PrincipalId, ProtocolSignature};
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn production_boundary_fixes_context_and_persists_replay() {
        let directory = tempfile::tempdir().unwrap();
        let replay_path = directory.path().join("compliance-replay.bin");
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
        let mut registry = ComplianceKeyRegistry::default();
        registry
            .register(evidence.profile(), provider, signing_key.verifying_key().encode().to_vec())
            .unwrap();

        let mut admission =
            RegulatedTransferAdmission::open(chain_id, genesis, 7, registry.clone(), &replay_path)
                .unwrap();
        assert_eq!(admission.admit(evidence, &signature, None, action, None, None, 15), Ok(()));
        drop(admission);

        let mut restarted =
            RegulatedTransferAdmission::open(chain_id, genesis, 7, registry, &replay_path).unwrap();
        assert_eq!(
            restarted.admit(evidence, &signature, None, action, None, None, 15),
            Err(ComplianceAdmissionError::Replay(CompliancePersistenceError::Replay))
        );
    }
}
