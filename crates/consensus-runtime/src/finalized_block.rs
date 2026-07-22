//! Complete typed finalized-block composition boundary.

use activechain_action_kernel::ActionEnvelope;
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_data_availability::AvailabilityBatch;
use activechain_devnet_kernel::{BlockReceipt, ChainState, DevnetBlock, apply_block};
use activechain_protocol_types::{ChainId, Digest384, PrincipalId, QuorumCertificate};
use activechain_state_tree::StateCommitment;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

fn commitment(domain: &[u8], parts: &[&[u8]]) -> Digest384 {
    let mut h = Shake256::default();
    h.update(domain);
    for part in parts {
        h.update(&(part.len() as u64).to_be_bytes());
        h.update(part);
    }
    let mut out = [0; 48];
    h.finalize_xof().read(&mut out);
    Digest384::new(out)
}

/// Exact public inputs that an execution proof must bind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofPublicInputs {
    chain_id: ChainId,
    epoch: u64,
    height: u64,
    protocol_revision: u64,
    validator_set_root: Digest384,
    parent_block_id: Digest384,
    pre_state: StateCommitment,
    authorization_root: Digest384,
    action_root: Digest384,
    execution_order_root: Digest384,
    total_fees: u128,
    pre_supply: u128,
    issuance: u128,
    burn: u128,
    post_supply: u128,
    post_state: StateCommitment,
    receipt_root: Digest384,
    data_availability_commitment: Digest384,
}

impl ProofPublicInputs {
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn post_state(&self) -> StateCommitment {
        self.post_state
    }

    #[allow(clippy::too_many_arguments)]
    pub fn derive(
        state: &ChainState,
        block: &DevnetBlock,
        epoch: u64,
        protocol_revision: u64,
        validator_set_root: Digest384,
        pre_supply: u128,
        issuance: u128,
        burn: u128,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<(Self, ChainState, BlockReceipt, Vec<u8>), FinalizedBlockAdmissionError> {
        let encoded =
            encode_envelope(block).map_err(|_| FinalizedBlockAdmissionError::CanonicalBlock)?;
        let output =
            apply_block(state, block).map_err(|_| FinalizedBlockAdmissionError::Execution)?;
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
            Self {
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
                execution_order_root: commitment(
                    b"ACTIVECHAIN-BLOCK-EXECUTION-ORDER-V1",
                    &[&actions],
                ),
                total_fees,
                pre_supply,
                issuance,
                burn,
                post_supply,
                post_state: output.receipt().post_state(),
                receipt_root: output.receipt_root(),
                data_availability_commitment: da,
            },
            output.state().clone(),
            output.receipt().clone(),
            encoded,
        ))
    }
}

impl CanonicalEncode for ProofPublicInputs {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.epoch.encode(e)?;
        self.height.encode(e)?;
        self.protocol_revision.encode(e)?;
        self.validator_set_root.encode(e)?;
        self.parent_block_id.encode(e)?;
        self.pre_state.encode(e)?;
        self.authorization_root.encode(e)?;
        self.action_root.encode(e)?;
        self.execution_order_root.encode(e)?;
        self.total_fees.encode(e)?;
        self.pre_supply.encode(e)?;
        self.issuance.encode(e)?;
        self.burn.encode(e)?;
        self.post_supply.encode(e)?;
        self.post_state.encode(e)?;
        self.receipt_root.encode(e)?;
        self.data_availability_commitment.encode(e)
    }
}
impl CanonicalDecode for ProofPublicInputs {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            chain_id: ChainId::decode(d)?,
            epoch: u64::decode(d)?,
            height: u64::decode(d)?,
            protocol_revision: u64::decode(d)?,
            validator_set_root: Digest384::decode(d)?,
            parent_block_id: Digest384::decode(d)?,
            pre_state: StateCommitment::decode(d)?,
            authorization_root: Digest384::decode(d)?,
            action_root: Digest384::decode(d)?,
            execution_order_root: Digest384::decode(d)?,
            total_fees: u128::decode(d)?,
            pre_supply: u128::decode(d)?,
            issuance: u128::decode(d)?,
            burn: u128::decode(d)?,
            post_supply: u128::decode(d)?,
            post_state: StateCommitment::decode(d)?,
            receipt_root: Digest384::decode(d)?,
            data_availability_commitment: Digest384::decode(d)?,
        })
    }
}
impl CanonicalType for ProofPublicInputs {
    const TYPE_TAG: u16 = 0x0078;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        48 + 8 + 8 + 8 + 48 + 48 + 56 + 48 + 48 + 48 + 16 * 5 + 56 + 48 + 48;
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

/// Canonical header whose digest is the only digest validators may vote for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedBlockHeader {
    pub inputs: ProofPublicInputs,
    pub proof_statement_commitment: Digest384,
}
impl FinalizedBlockHeader {
    pub fn digest(&self) -> Result<Digest384, EncodeError> {
        Ok(commitment(b"ACTIVECHAIN-FINALIZED-BLOCK-HEADER-V1", &[&encode_envelope(self)?]))
    }
}
impl CanonicalEncode for FinalizedBlockHeader {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.inputs.encode(e)?;
        self.proof_statement_commitment.encode(e)
    }
}
impl CanonicalDecode for FinalizedBlockHeader {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            inputs: ProofPublicInputs::decode(d)?,
            proof_statement_commitment: Digest384::decode(d)?,
        };
        if value.inputs.protocol_revision == 0
            || value.inputs.validator_set_root == Digest384::ZERO
            || value.proof_statement_commitment == Digest384::ZERO
        {
            return Err(DecodeError::InvalidValue("unbound finalized block header"));
        }
        Ok(value)
    }
}
impl CanonicalType for FinalizedBlockHeader {
    const TYPE_TAG: u16 = 0x0079;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = ProofPublicInputs::MAX_ENCODED_LEN + 48;
}

/// Untrusted material supplied to the authoritative admission path.
pub struct FinalizedBlockCandidate {
    pub encoded_block: Vec<u8>,
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
pub trait FinalizedBlockVerifier: ExecutionProofVerifier {
    fn verify_authorization(&self, action: &ActionEnvelope) -> bool;
    fn verify_certificate(&self, certificate: &QuorumCertificate) -> bool;
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
        if block.actions().iter().any(|action| !verifier.verify_authorization(action)) {
            return Err(FinalizedBlockAdmissionError::Authorization);
        }
        let (inputs, next_state, receipt, _) = ProofPublicInputs::derive(
            state,
            &block,
            epoch,
            protocol_revision,
            validator_set_root,
            pre_supply,
            issuance,
            burn,
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
    use activechain_protocol_types::ConsensusVoteContext;
    use activechain_state_tree::commit_objects;
    use activechain_transition::ObjectState;

    struct AcceptAll;
    impl ExecutionProofVerifier for AcceptAll {
        fn verify(&self, system: u16, _statement: Digest384, proof: &[u8]) -> bool {
            system == 1 && proof == b"valid-proof"
        }
    }
    impl FinalizedBlockVerifier for AcceptAll {
        fn verify_authorization(&self, _action: &ActionEnvelope) -> bool {
            true
        }
        fn verify_certificate(&self, _certificate: &QuorumCertificate) -> bool {
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
        let block = DevnetBlock::new(chain, 1, Digest384::ZERO, pre_state, vec![]).unwrap();
        let root = Digest384::new([2; 48]);
        let genesis = Digest384::new([3; 48]);
        let (inputs, _, _, _) =
            ProofPublicInputs::derive(&state, &block, 7, 4, root, 100, 3, 2, 1, 1).unwrap();
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
        let digest = header.digest().unwrap();
        assert_eq!(
            digest,
            Digest384::new([
                47, 108, 251, 90, 68, 209, 25, 59, 165, 223, 214, 130, 0, 116, 134, 147, 239, 216,
                109, 205, 217, 49, 158, 138, 196, 207, 215, 228, 163, 166, 46, 145, 101, 120, 226,
                54, 131, 237, 133, 127, 135, 245, 127, 148, 44, 40, 131, 255,
            ])
        );
        assert_eq!(
            include_str!("../../../testing/vectors/consensus/finalized-block-v1.txt"),
            "header_type_tag=0x0079\nheader_schema_version=1\nproof_inputs_type_tag=0x0078\nproof_inputs_schema_version=1\nheader_digest=2f6cfb5a44d1193ba5dfd68200748693efd86dcdd9319e8ac4cfd7e4a3a62e916578e23683ed857f87f57f942c2883ff\n"
        );
        let context = ConsensusVoteContext::new_with_revision(genesis, 7, root, 4).unwrap();
        let certificate =
            QuorumCertificate::new(context, 1, 0, digest, Digest384::new([5; 48]), 1, 1).unwrap();
        let candidate = FinalizedBlockCandidate {
            encoded_block: encode_envelope(&block).unwrap(),
            claimed_header: header,
            proof: proof.clone(),
            certificate: certificate.clone(),
            data_shards: 1,
            parity_shards: 1,
        };
        assert_eq!(
            candidate
                .admit(&state, genesis, 7, 4, root, 100, 3, 2, &AcceptAll)
                .unwrap()
                .block_digest,
            digest
        );

        let wrong = FinalizedBlockCandidate {
            encoded_block: encode_envelope(&block).unwrap(),
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
            wrong.admit(&state, genesis, 7, 4, root, 100, 3, 2, &AcceptAll),
            Err(FinalizedBlockAdmissionError::ComponentMismatch)
        );

        for mutated in [
            ProofPublicInputs { authorization_root: Digest384::new([21; 48]), ..header.inputs },
            ProofPublicInputs { action_root: Digest384::new([22; 48]), ..header.inputs },
            ProofPublicInputs { execution_order_root: Digest384::new([23; 48]), ..header.inputs },
            ProofPublicInputs { receipt_root: Digest384::new([24; 48]), ..header.inputs },
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
                claimed_header: FinalizedBlockHeader { inputs: mutated, ..header },
                proof: proof.clone(),
                certificate: certificate.clone(),
                data_shards: 1,
                parity_shards: 1,
            };
            assert_eq!(
                candidate.admit(&state, genesis, 7, 4, root, 100, 3, 2, &AcceptAll),
                Err(FinalizedBlockAdmissionError::ComponentMismatch)
            );
        }
    }

    #[test]
    fn proof_pipeline_is_ordered_durable_and_reward_replay_safe() {
        let (state, block, inputs, proof, header, genesis, root) = fixture();
        let certificate = QuorumCertificate::new(
            ConsensusVoteContext::new_with_revision(genesis, 7, root, 4).unwrap(),
            1,
            0,
            header.digest().unwrap(),
            Digest384::new([5; 48]),
            1,
            1,
        )
        .unwrap();
        let finalized = FinalizedBlockCandidate {
            encoded_block: encode_envelope(&block).unwrap(),
            claimed_header: header,
            proof: proof.clone(),
            certificate,
            data_shards: 1,
            parity_shards: 1,
        }
        .admit(&state, genesis, 7, 4, root, 100, 3, 2, &AcceptAll)
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
    }
}
