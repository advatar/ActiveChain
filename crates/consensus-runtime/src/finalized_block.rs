//! Complete typed finalized-block composition boundary.

use activechain_authorization_kernel::{
    AuthorizationCandidate, AuthorizationReplayStore, AuthorizationVerifier,
    verify_authorization_candidate,
};
use activechain_canonical_codec::{EncodeError, decode_envelope, encode_envelope};
use activechain_data_availability::AvailabilityBatch;
use activechain_devnet_kernel::{BlockReceipt, ChainState, DevnetBlock, apply_block};
use activechain_finality_types::commit_parts as commitment;
pub use activechain_finality_types::{FinalizedBlockHeader, ProofPublicInputs};
use activechain_protocol_types::FungibleIssuerApprovalV1;
use activechain_protocol_types::{Digest384, PrincipalId, QuorumCertificate};

#[allow(clippy::too_many_arguments)]
fn derive_proof_public_inputs(
    state: &ChainState,
    block: &DevnetBlock,
    epoch: u64,
    protocol_revision: u64,
    validator_set_root: Digest384,
    pre_supply: u128,
    issuance: u128,
    burn: u128,
    cash_cell_root: Digest384,
    data_shards: usize,
    parity_shards: usize,
) -> Result<(ProofPublicInputs, ChainState, BlockReceipt, Vec<u8>), FinalizedBlockAdmissionError> {
    let encoded =
        encode_envelope(block).map_err(|_| FinalizedBlockAdmissionError::CanonicalBlock)?;
    let output = apply_block(state, block).map_err(|_| FinalizedBlockAdmissionError::Execution)?;
    let mut authorization = Vec::with_capacity(block.actions().len() * 48);
    let mut actions = Vec::with_capacity(block.actions().len() * 48);
    let mut total_fees = 0_u128;
    for (action, receipt) in block.actions().iter().zip(output.receipt().action_receipts()) {
        authorization.extend_from_slice(action.authorization_commitment().as_bytes());
        actions.extend_from_slice(receipt.transaction_id().digest().as_bytes());
        total_fees = total_fees
            .checked_add(receipt.fee_charged())
            .ok_or(FinalizedBlockAdmissionError::Economics)?;
    }
    let post_supply = pre_supply
        .checked_add(issuance)
        .and_then(|v| v.checked_sub(burn))
        .ok_or(FinalizedBlockAdmissionError::Economics)?;
    let availability = AvailabilityBatch::encode(&encoded, data_shards, parity_shards)
        .map_err(|_| FinalizedBlockAdmissionError::Availability)?;
    let da = Digest384::new(
        *availability
            .payload_commitment()
            .map_err(|_| FinalizedBlockAdmissionError::Availability)?
            .as_bytes(),
    );
    Ok((
        ProofPublicInputs {
            chain_id: block.chain_id(),
            epoch,
            height: block.height(),
            protocol_revision,
            validator_set_root,
            parent_block_id: block.parent_block_id(),
            pre_state: block.pre_state(),
            authorization_root: commitment(
                b"ACTIVECHAIN-BLOCK-AUTHORIZATION-V1",
                &[&authorization],
            ),
            action_root: commitment(b"ACTIVECHAIN-BLOCK-ACTIONS-V1", &[&actions]),
            execution_order_root: commitment(b"ACTIVECHAIN-BLOCK-EXECUTION-ORDER-V1", &[&actions]),
            total_fees,
            pre_supply,
            issuance,
            burn,
            post_supply,
            cash_cell_root,
            post_state: output.receipt().post_state(),
            receipt_root: output.receipt_root(),
            data_availability_commitment: da,
        },
        output.state().clone(),
        output.receipt().clone(),
        encoded,
    ))
}

/// A verifier-produced proof statement. Proof bytes are deliberately outside block identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedExecutionProof {
    pub inputs: ProofPublicInputs,
    pub prover: PrincipalId,
    pub proof_system: u16,
    pub proof_bytes: Vec<u8>,
}
impl VerifiedExecutionProof {
    pub const MAX_PROOF_BYTES: usize = 1 << 20;
    pub fn statement_commitment(&self) -> Result<Digest384, EncodeError> {
        let inputs = encode_envelope(&self.inputs)?;
        Ok(commitment(
            b"ACTIVECHAIN-EXECUTION-PROOF-STATEMENT-V1",
            &[&inputs, self.prover.digest().as_bytes(), &self.proof_system.to_be_bytes()],
        ))
    }
}

/// Untrusted material supplied to the authoritative admission path.
pub struct FinalizedBlockCandidate {
    pub encoded_block: Vec<u8>,
    pub authorization_candidates: Vec<AuthorizationCandidate>,
    pub claimed_header: FinalizedBlockHeader,
    pub proof: VerifiedExecutionProof,
    pub certificate: QuorumCertificate,
    pub data_shards: usize,
    pub parity_shards: usize,
}

/// Materialized result after every component has been recomputed and checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedBlock {
    pub header: FinalizedBlockHeader,
    pub block_digest: Digest384,
    pub block: DevnetBlock,
    pub receipt: BlockReceipt,
    pub next_state: ChainState,
    pub post_supply: u128,
    pub availability_payload: Vec<u8>,
    pub proof_statement_commitment: Digest384,
    pub prover: PrincipalId,
}

pub trait ExecutionProofVerifier {
    fn verify(&self, proof_system: u16, statement: Digest384, proof: &[u8]) -> bool;
}

/// External cryptographic observations required by the deterministic composition predicate.
pub trait FinalizedBlockVerifier: ExecutionProofVerifier + AuthorizationVerifier {
    fn verify_certificate(&self, certificate: &QuorumCertificate) -> bool;
    fn verify_issuer_approval(&self, approval: &FungibleIssuerApprovalV1) -> bool;
}
impl<F: Fn(u16, Digest384, &[u8]) -> bool> ExecutionProofVerifier for F {
    fn verify(&self, proof_system: u16, statement: Digest384, proof: &[u8]) -> bool {
        self(proof_system, statement, proof)
    }
}

impl FinalizedBlockCandidate {
    #[allow(clippy::too_many_arguments)]
    pub fn admit<V: FinalizedBlockVerifier>(
        self,
        state: &ChainState,
        chain_genesis_commitment: Digest384,
        epoch: u64,
        protocol_revision: u64,
        validator_set_root: Digest384,
        pre_supply: u128,
        issuance: u128,
        burn: u128,
        cash_cell_root: Digest384,
        authorization_store: &AuthorizationReplayStore,
        verifier: &V,
    ) -> Result<FinalizedBlock, FinalizedBlockAdmissionError> {
        let block: DevnetBlock = decode_envelope(&self.encoded_block)
            .map_err(|_| FinalizedBlockAdmissionError::CanonicalBlock)?;
        if encode_envelope(&block).map_err(|_| FinalizedBlockAdmissionError::CanonicalBlock)?
            != self.encoded_block
        {
            return Err(FinalizedBlockAdmissionError::CanonicalBlock);
        }
        if block.chain_id() != state.chain_id() || block.height() != self.certificate.height() {
            return Err(FinalizedBlockAdmissionError::Context);
        }
        let transfer_count =
            block.actions().iter().filter(|action| action.payload().transfer().is_some()).count();
        if transfer_count != self.authorization_candidates.len() {
            return Err(FinalizedBlockAdmissionError::Authorization);
        }
        let mut verified_authorizations = Vec::with_capacity(transfer_count);
        let mut candidates = self.authorization_candidates.iter();
        for action in block.actions() {
            let Some(transaction) = action.payload().transfer() else {
                let approval = action
                    .payload()
                    .issuer_approval()
                    .ok_or(FinalizedBlockAdmissionError::Authorization)?;
                if action.authorization_commitment() != approval.approval_commitment()
                    || !verifier.verify_issuer_approval(approval)
                {
                    return Err(FinalizedBlockAdmissionError::Authorization);
                }
                continue;
            };
            let candidate = candidates.next().ok_or(FinalizedBlockAdmissionError::Authorization)?;
            let verified = verify_authorization_candidate(
                candidate,
                chain_genesis_commitment,
                epoch,
                block.pre_state().root(),
                verifier,
            )
            .map_err(|_| FinalizedBlockAdmissionError::Authorization)?;
            if verified.actor() != action.sender()
                || verified.envelope_commitment() != action.authorization_commitment()
                || verified.transition_commitment() != action.payload_commitment()
                || candidate.transaction != *transaction
            {
                return Err(FinalizedBlockAdmissionError::Authorization);
            }
            verified_authorizations.push(verified);
        }
        let (inputs, next_state, receipt, _) = derive_proof_public_inputs(
            state,
            &block,
            epoch,
            protocol_revision,
            validator_set_root,
            pre_supply,
            issuance,
            burn,
            cash_cell_root,
            self.data_shards,
            self.parity_shards,
        )?;
        if inputs != self.claimed_header.inputs || inputs != self.proof.inputs {
            return Err(FinalizedBlockAdmissionError::ComponentMismatch);
        }
        let statement =
            self.proof.statement_commitment().map_err(|_| FinalizedBlockAdmissionError::Proof)?;
        if statement != self.claimed_header.proof_statement_commitment
            || self.proof.proof_bytes.is_empty()
            || self.proof.proof_bytes.len() > VerifiedExecutionProof::MAX_PROOF_BYTES
            || !verifier.verify(self.proof.proof_system, statement, &self.proof.proof_bytes)
        {
            return Err(FinalizedBlockAdmissionError::Proof);
        }
        let digest =
            self.claimed_header.digest().map_err(|_| FinalizedBlockAdmissionError::Header)?;
        if self.certificate.genesis_commitment() != chain_genesis_commitment
            || self.certificate.epoch() != epoch
            || self.certificate.protocol_revision() != protocol_revision
            || self.certificate.validator_set_root() != validator_set_root
            || self.certificate.block_digest() != digest
            || !verifier.verify_certificate(&self.certificate)
        {
            return Err(FinalizedBlockAdmissionError::Certificate);
        }
        authorization_store
            .admit_batch(&verified_authorizations)
            .map_err(|_| FinalizedBlockAdmissionError::Authorization)?;
        Ok(FinalizedBlock {
            header: self.claimed_header,
            block_digest: digest,
            block,
            receipt,
            next_state,
            post_supply: inputs.post_supply,
            availability_payload: self.encoded_block,
            proof_statement_commitment: statement,
            prover: self.proof.prover,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalizedBlockAdmissionError {
    CanonicalBlock,
    Context,
    Authorization,
    Execution,
    Economics,
    Availability,
    ComponentMismatch,
    Proof,
    Header,
    Certificate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DurableFinalizedState, DurableProofPipeline, ProofPipelineError};
    use activechain_action_kernel::ResourcePrices;
    use activechain_protocol_types::{ChainId, ConsensusVoteContext};
    use activechain_state_tree::{StateCommitment, commit_objects};
    use activechain_transition::ObjectState;

    struct AcceptAll;
    impl ExecutionProofVerifier for AcceptAll {
        fn verify(&self, system: u16, _statement: Digest384, proof: &[u8]) -> bool {
            system == 1 && proof == b"valid-proof"
        }
    }
    impl FinalizedBlockVerifier for AcceptAll {
        fn verify_certificate(&self, _certificate: &QuorumCertificate) -> bool {
            true
        }
        fn verify_issuer_approval(&self, _approval: &FungibleIssuerApprovalV1) -> bool {
            true
        }
    }
    impl AuthorizationVerifier for AcceptAll {
        fn verify_actor_signature(
            &self,
            _envelope: &activechain_authorization_kernel::AuthorizationEnvelope,
        ) -> bool {
            true
        }
        fn verify_finalized_context(
            &self,
            _envelope: &activechain_authorization_kernel::AuthorizationEnvelope,
        ) -> bool {
            true
        }
        fn verify_credential_signature(
            &self,
            _credential: &activechain_protocol_types::Credential,
        ) -> bool {
            true
        }
        fn verify_credential_status(
            &self,
            _material: &activechain_authorization_kernel::CredentialMaterial,
        ) -> bool {
            true
        }
        fn verify_capability_signature(
            &self,
            _capability: &activechain_protocol_types::CapabilityGrant,
        ) -> bool {
            true
        }
        fn verify_capability_active(
            &self,
            _capability: &activechain_protocol_types::CapabilityGrant,
            _height: u64,
            _state_root: Digest384,
        ) -> bool {
            true
        }
    }

    fn fixture() -> (
        ChainState,
        DevnetBlock,
        ProofPublicInputs,
        VerifiedExecutionProof,
        FinalizedBlockHeader,
        Digest384,
        Digest384,
    ) {
        let chain = ChainId::new(Digest384::new([1; 48]));
        let objects = ObjectState::new(vec![]).unwrap();
        let state =
            ChainState::genesis(chain, objects, vec![], ResourcePrices::new(1, 1, 1, 1, 1, 1))
                .unwrap();
        let pre_state = commit_objects(state.objects().objects()).unwrap();
        let block = DevnetBlock::new(
            chain,
            1,
            Digest384::ZERO,
            pre_state,
            state.commitment().unwrap(),
            vec![],
        )
        .unwrap();
        let root = Digest384::new([2; 48]);
        let genesis = Digest384::new([3; 48]);
        let (inputs, _, _, _) = derive_proof_public_inputs(
            &state,
            &block,
            7,
            4,
            root,
            100,
            3,
            2,
            Digest384::new([6; 48]),
            1,
            1,
        )
        .unwrap();
        let proof = VerifiedExecutionProof {
            inputs,
            prover: PrincipalId::new(Digest384::new([4; 48])),
            proof_system: 1,
            proof_bytes: b"valid-proof".to_vec(),
        };
        let header = FinalizedBlockHeader {
            inputs,
            proof_statement_commitment: proof.statement_commitment().unwrap(),
        };
        (state, block, inputs, proof, header, genesis, root)
    }

    #[test]
    fn typed_finalization_recomputes_every_binding_and_rejects_substitution() {
        let (state, block, _inputs, proof, header, genesis, root) = fixture();
        let authorization_path = std::env::temp_dir().join(format!(
            "activechain-finalization-authorization-{}.snapshot",
            std::process::id()
        ));
        let authorization_store =
            AuthorizationReplayStore::new(authorization_path.clone(), genesis, 7).unwrap();
        let digest = header.digest().unwrap();
        assert_eq!(
            digest,
            Digest384::new([
                36, 172, 138, 9, 83, 100, 172, 1, 41, 192, 222, 157, 127, 238, 98, 227, 250, 200,
                191, 244, 220, 211, 145, 50, 94, 172, 245, 194, 153, 172, 172, 11, 214, 149, 124,
                70, 44, 219, 45, 194, 69, 238, 201, 247, 33, 95, 79, 137,
            ])
        );
        assert_eq!(
            include_str!("../../../testing/vectors/consensus/finalized-block-v1.txt"),
            "header_type_tag=0x0079\nheader_schema_version=2\nproof_inputs_type_tag=0x0078\nproof_inputs_schema_version=2\nheader_digest=24ac8a095364ac0129c0de9d7fee62e3fac8bff4dcd391325eacf5c299acac0bd6957c462cdb2dc245eec9f7215f4f89\n"
        );
        let context = ConsensusVoteContext::new_with_revision(genesis, 7, root, 4).unwrap();
        let certificate = QuorumCertificate::new(
            context,
            1,
            0,
            digest,
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            1,
            1,
        )
        .unwrap();
        let candidate = FinalizedBlockCandidate {
            encoded_block: encode_envelope(&block).unwrap(),
            authorization_candidates: vec![],
            claimed_header: header,
            proof: proof.clone(),
            certificate: certificate.clone(),
            data_shards: 1,
            parity_shards: 1,
        };
        assert_eq!(
            candidate
                .admit(
                    &state,
                    genesis,
                    7,
                    4,
                    root,
                    100,
                    3,
                    2,
                    header.inputs.cash_cell_root,
                    &authorization_store,
                    &AcceptAll,
                )
                .unwrap()
                .block_digest,
            digest
        );

        let wrong = FinalizedBlockCandidate {
            encoded_block: encode_envelope(&block).unwrap(),
            authorization_candidates: vec![],
            claimed_header: FinalizedBlockHeader {
                inputs: ProofPublicInputs { burn: 3, ..header.inputs },
                ..header
            },
            proof: proof.clone(),
            certificate: certificate.clone(),
            data_shards: 1,
            parity_shards: 1,
        };
        assert_eq!(
            wrong.admit(
                &state,
                genesis,
                7,
                4,
                root,
                100,
                3,
                2,
                header.inputs.cash_cell_root,
                &authorization_store,
                &AcceptAll,
            ),
            Err(FinalizedBlockAdmissionError::ComponentMismatch)
        );

        for mutated in [
            ProofPublicInputs { authorization_root: Digest384::new([21; 48]), ..header.inputs },
            ProofPublicInputs { action_root: Digest384::new([22; 48]), ..header.inputs },
            ProofPublicInputs { execution_order_root: Digest384::new([23; 48]), ..header.inputs },
            ProofPublicInputs { receipt_root: Digest384::new([24; 48]), ..header.inputs },
            ProofPublicInputs { cash_cell_root: Digest384::new([27; 48]), ..header.inputs },
            ProofPublicInputs {
                data_availability_commitment: Digest384::new([25; 48]),
                ..header.inputs
            },
            ProofPublicInputs {
                post_state: StateCommitment::new(Digest384::new([26; 48]), 0),
                ..header.inputs
            },
            ProofPublicInputs { protocol_revision: 5, ..header.inputs },
        ] {
            let candidate = FinalizedBlockCandidate {
                encoded_block: encode_envelope(&block).unwrap(),
                authorization_candidates: vec![],
                claimed_header: FinalizedBlockHeader { inputs: mutated, ..header },
                proof: proof.clone(),
                certificate: certificate.clone(),
                data_shards: 1,
                parity_shards: 1,
            };
            assert_eq!(
                candidate.admit(
                    &state,
                    genesis,
                    7,
                    4,
                    root,
                    100,
                    3,
                    2,
                    header.inputs.cash_cell_root,
                    &authorization_store,
                    &AcceptAll,
                ),
                Err(FinalizedBlockAdmissionError::ComponentMismatch)
            );
        }
        let _ = std::fs::remove_file(authorization_path);
    }

    #[test]
    fn proof_pipeline_is_ordered_durable_and_reward_replay_safe() {
        let (state, block, inputs, proof, header, genesis, root) = fixture();
        let authorization_path = std::env::temp_dir()
            .join(format!("activechain-proof-authorization-{}.snapshot", std::process::id()));
        let authorization_store =
            AuthorizationReplayStore::new(authorization_path.clone(), genesis, 7).unwrap();
        let certificate = QuorumCertificate::new(
            ConsensusVoteContext::new_with_revision(genesis, 7, root, 4).unwrap(),
            1,
            0,
            header.digest().unwrap(),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            1,
            1,
        )
        .unwrap();
        let finalized = FinalizedBlockCandidate {
            encoded_block: encode_envelope(&block).unwrap(),
            authorization_candidates: vec![],
            claimed_header: header,
            proof: proof.clone(),
            certificate,
            data_shards: 1,
            parity_shards: 1,
        }
        .admit(
            &state,
            genesis,
            7,
            4,
            root,
            100,
            3,
            2,
            header.inputs.cash_cell_root,
            &authorization_store,
            &AcceptAll,
        )
        .unwrap();
        let mut pipeline = DurableProofPipeline::default();
        let id = pipeline.enqueue(inputs).unwrap();
        assert_eq!(pipeline.enqueue(inputs), Err(ProofPipelineError::Replay));
        pipeline.dispatch(id, 10, 5).unwrap();
        assert_eq!(pipeline.dispatch(id, 12, 5), Err(ProofPipelineError::State));
        pipeline.accept(id, &proof, &AcceptAll).unwrap();
        assert_eq!(
            pipeline.finalize(id, 2, Digest384::new([8; 48])),
            Err(ProofPipelineError::Order)
        );
        let finalized_path = std::env::temp_dir()
            .join(format!("activechain-finalized-state-{}.snapshot", std::process::id()));
        pipeline.commit_finalized(id, &finalized, &finalized_path).unwrap();
        let durable = DurableFinalizedState::load(&finalized_path).unwrap();
        assert_eq!(durable.chain_state, finalized.next_state);
        assert_eq!(durable.post_supply, 101);
        let _ = std::fs::remove_file(finalized_path);
        let path = std::env::temp_dir()
            .join(format!("activechain-proof-pipeline-{}.snapshot", std::process::id()));
        pipeline.save(&path).unwrap();
        let mut restored = DurableProofPipeline::load(&path).unwrap();
        assert_eq!(restored.claim_reward(id).unwrap(), proof.prover);
        assert_eq!(restored.claim_reward(id), Err(ProofPipelineError::Replay));
        restored.save(&path).unwrap();
        let mut corrupt = std::fs::read(&path).unwrap();
        corrupt[10] ^= 1;
        std::fs::write(&path, corrupt).unwrap();
        assert!(DurableProofPipeline::load(&path).is_err());
        let _ = std::fs::remove_file(path);

        let mut retries = DurableProofPipeline::default();
        let retry_id = retries.enqueue(inputs).unwrap();
        retries.dispatch(retry_id, 1, 1).unwrap();
        retries.dispatch(retry_id, 3, 1).unwrap();
        retries.dispatch(retry_id, 5, 1).unwrap();
        assert_eq!(retries.dispatch(retry_id, 7, 1), Err(ProofPipelineError::RetriesExhausted));

        let mut bounded = DurableProofPipeline::default();
        for height in 1..=64 {
            bounded.enqueue(ProofPublicInputs { height, ..inputs }).unwrap();
        }
        assert_eq!(
            bounded.enqueue(ProofPublicInputs { height: 65, ..inputs }),
            Err(ProofPipelineError::Backpressure)
        );
        let _ = std::fs::remove_file(authorization_path);
    }
}
