//! Complete typed finalized-block composition boundary.

use activechain_action_kernel::ActionPayloadV2;
use activechain_authorization_kernel::{
    AuthorizationCandidate, AuthorizationReplayStore, AuthorizationVerifier, CredentialMaterial,
    verify_authorization_candidate,
};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_data_availability::AvailabilityBatch;
use activechain_devnet_kernel::{BlockReceipt, ChainState, DevnetBlock, apply_block};
use activechain_finality_types::commit_parts as commitment;
pub use activechain_finality_types::{FinalizedBlockHeader, ProofPublicInputs};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::FungibleIssuerApprovalV1;
use activechain_protocol_types::{
    CapabilityGrant, Credential, Digest384, PrincipalId, QuorumCertificate, ValidatorGenesis,
    ValidatorVote,
};

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
    pre_cash_cell_root: Digest384,
    cash_action_ids: &[activechain_protocol_types::TransactionId],
    cash_cell_root: Digest384,
    data_shards: usize,
    parity_shards: usize,
) -> Result<(ProofPublicInputs, ChainState, BlockReceipt, Vec<u8>), FinalizedBlockAdmissionError> {
    if cash_action_ids.is_empty() != (pre_cash_cell_root == cash_cell_root) {
        return Err(FinalizedBlockAdmissionError::Execution);
    }
    let encoded =
        encode_envelope(block).map_err(|_| FinalizedBlockAdmissionError::CanonicalBlock)?;
    let output = apply_block(state, block).map_err(|_| FinalizedBlockAdmissionError::Execution)?;
    let mut authorization = Vec::with_capacity(block.actions().len() * 48);
    let mut actions = Vec::with_capacity(block.actions().len() * 48);
    let mut total_fees = 0_u128;
    let mut cash_actions = Vec::with_capacity(cash_action_ids.len() * 48);
    for action in cash_action_ids {
        cash_actions.extend_from_slice(action.digest().as_bytes());
    }
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
            pre_cash_cell_root,
            cash_action_root: commitment(b"ACTIVECHAIN-BLOCK-CASH-ACTIONS-V1", &[&cash_actions]),
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

/// Direct-reexecution evidence. The admission path independently reexecutes the block and requires
/// these exact public inputs and receipt, so this proof system needs no trusted prover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectExecutionProofV1 {
    inputs: ProofPublicInputs,
    receipt: BlockReceipt,
    prover: PrincipalId,
}

impl DirectExecutionProofV1 {
    pub const TYPE_TAG: u16 = 0x0192;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const PROOF_SYSTEM: u16 = 0;

    pub fn new(
        inputs: ProofPublicInputs,
        receipt: BlockReceipt,
        prover: PrincipalId,
    ) -> Result<Self, FinalizedBlockAdmissionError> {
        if prover.digest() == &Digest384::ZERO
            || inputs.pre_state != receipt.pre_state()
            || inputs.post_state != receipt.post_state()
            || inputs.receipt_root
                != commit(DomainTag::CANONICAL_VALUE, &receipt)
                    .map_err(|_| FinalizedBlockAdmissionError::Proof)?
        {
            return Err(FinalizedBlockAdmissionError::Proof);
        }
        let fees = receipt
            .action_receipts()
            .iter()
            .try_fold(0_u128, |sum, action| sum.checked_add(action.fee_charged()));
        if fees != Some(inputs.total_fees) {
            return Err(FinalizedBlockAdmissionError::Proof);
        }
        Ok(Self { inputs, receipt, prover })
    }

    pub fn into_verified(self) -> Result<VerifiedExecutionProof, FinalizedBlockAdmissionError> {
        let proof_bytes =
            encode_envelope(&self).map_err(|_| FinalizedBlockAdmissionError::Proof)?;
        Ok(VerifiedExecutionProof {
            inputs: self.inputs,
            prover: self.prover,
            proof_system: Self::PROOF_SYSTEM,
            proof_bytes,
        })
    }
}

impl CanonicalEncode for DirectExecutionProofV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.inputs.encode(encoder)?;
        self.receipt.encode(encoder)?;
        self.prover.encode(encoder)
    }
}
impl CanonicalDecode for DirectExecutionProofV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ProofPublicInputs::decode(decoder)?,
            BlockReceipt::decode(decoder)?,
            PrincipalId::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid direct execution proof"))
    }
}
impl CanonicalType for DirectExecutionProofV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize =
        ProofPublicInputs::MAX_ENCODED_LEN + BlockReceipt::MAX_ENCODED_LEN + 48;
}

/// Production verifier for proof-system zero: deterministic direct reexecution.
pub struct DirectExecutionProofVerifier;
impl ExecutionProofVerifier for DirectExecutionProofVerifier {
    fn verify(&self, proof_system: u16, statement: Digest384, proof: &[u8]) -> bool {
        if proof_system != DirectExecutionProofV1::PROOF_SYSTEM {
            return false;
        }
        let Ok(direct) = decode_envelope::<DirectExecutionProofV1>(proof) else {
            return false;
        };
        let verified = VerifiedExecutionProof {
            inputs: direct.inputs,
            prover: direct.prover,
            proof_system,
            proof_bytes: proof.to_vec(),
        };
        verified.statement_commitment().is_ok_and(|actual| actual == statement)
    }
}

/// Fail-closed verifier used by production cash-only rounds. It accepts only canonical direct
/// execution proofs; any unexpected authorization or issuer action is rejected.
pub struct CashOnlyFinalizedBlockVerifier;

impl ExecutionProofVerifier for CashOnlyFinalizedBlockVerifier {
    fn verify(&self, proof_system: u16, statement: Digest384, proof: &[u8]) -> bool {
        DirectExecutionProofVerifier.verify(proof_system, statement, proof)
    }
}

impl AuthorizationVerifier for CashOnlyFinalizedBlockVerifier {
    fn verify_actor_signature(
        &self,
        _envelope: &activechain_authorization_kernel::AuthorizationEnvelope,
    ) -> bool {
        false
    }

    fn verify_finalized_context(
        &self,
        _envelope: &activechain_authorization_kernel::AuthorizationEnvelope,
    ) -> bool {
        false
    }

    fn verify_credential_signature(&self, _credential: &Credential) -> bool {
        false
    }

    fn verify_credential_status(&self, _material: &CredentialMaterial) -> bool {
        false
    }

    fn verify_capability_signature(&self, _capability: &CapabilityGrant) -> bool {
        false
    }

    fn verify_capability_active(
        &self,
        _capability: &CapabilityGrant,
        _height: u64,
        _state_root: Digest384,
    ) -> bool {
        false
    }
}

impl FinalizedBlockVerifier for CashOnlyFinalizedBlockVerifier {
    fn verify_certificate(
        &self,
        _certificate: &QuorumCertificate,
        _votes: &[ValidatorVote],
    ) -> bool {
        false
    }

    fn verify_issuer_approval(&self, _approval: &FungibleIssuerApprovalV1) -> bool {
        false
    }
}

/// Canonical pre-vote material for a cash round and consensus-native digest anchors. The resulting
/// header is the exact statement validators must sign and `into_candidate` preserves those bytes
/// for post-vote admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedDirectFinalizedBlock {
    encoded_block: Vec<u8>,
    header: FinalizedBlockHeader,
    proof: VerifiedExecutionProof,
    next_state: ChainState,
    receipt: BlockReceipt,
    data_shards: usize,
    parity_shards: usize,
}

impl PreparedDirectFinalizedBlock {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: &ChainState,
        block: &DevnetBlock,
        epoch: u64,
        protocol_revision: u64,
        validator_set_root: Digest384,
        pre_supply: u128,
        issuance: u128,
        burn: u128,
        pre_cash_cell_root: Digest384,
        cash_action_ids: &[activechain_protocol_types::TransactionId],
        cash_cell_root: Digest384,
        data_shards: usize,
        parity_shards: usize,
        prover: PrincipalId,
    ) -> Result<Self, FinalizedBlockAdmissionError> {
        if block.actions().iter().any(|action| {
            let ActionPayloadV2::SubmitAnchor { statement, .. } = action.payload() else {
                return true;
            };
            statement
                .submission_reference()
                .map_or(true, |reference| action.authorization_commitment() != reference)
        }) {
            return Err(FinalizedBlockAdmissionError::Authorization);
        }
        let (inputs, next_state, receipt, encoded_block) = derive_proof_public_inputs(
            state,
            block,
            epoch,
            protocol_revision,
            validator_set_root,
            pre_supply,
            issuance,
            burn,
            pre_cash_cell_root,
            cash_action_ids,
            cash_cell_root,
            data_shards,
            parity_shards,
        )?;
        let proof =
            DirectExecutionProofV1::new(inputs, receipt.clone(), prover)?.into_verified()?;
        let header = FinalizedBlockHeader {
            inputs,
            proof_statement_commitment: proof
                .statement_commitment()
                .map_err(|_| FinalizedBlockAdmissionError::Proof)?,
        };
        Ok(Self { encoded_block, header, proof, next_state, receipt, data_shards, parity_shards })
    }

    pub const fn header(&self) -> &FinalizedBlockHeader {
        &self.header
    }

    pub const fn next_state(&self) -> &ChainState {
        &self.next_state
    }

    pub const fn receipt(&self) -> &BlockReceipt {
        &self.receipt
    }

    pub fn into_candidate(
        self,
        certificate: QuorumCertificate,
        certificate_votes: Vec<ValidatorVote>,
    ) -> FinalizedBlockCandidate {
        FinalizedBlockCandidate {
            encoded_block: self.encoded_block,
            authorization_candidates: Vec::new(),
            claimed_header: self.header,
            proof: self.proof,
            certificate,
            certificate_votes,
            data_shards: self.data_shards,
            parity_shards: self.parity_shards,
        }
    }
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
    pub certificate_votes: Vec<ValidatorVote>,
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
    fn verify_certificate(&self, certificate: &QuorumCertificate, votes: &[ValidatorVote]) -> bool;
    fn verify_issuer_approval(&self, approval: &FungibleIssuerApprovalV1) -> bool;
}

/// Forces real genesis-key and stake verification around an execution/authorization verifier.
pub struct GenesisBackedFinalizedBlockVerifier<V> {
    genesis: ValidatorGenesis,
    inner: V,
}

impl<V> GenesisBackedFinalizedBlockVerifier<V> {
    pub fn new(genesis: ValidatorGenesis, inner: V) -> Self {
        Self { genesis, inner }
    }
}

impl<V: ExecutionProofVerifier> ExecutionProofVerifier for GenesisBackedFinalizedBlockVerifier<V> {
    fn verify(&self, proof_system: u16, statement: Digest384, proof: &[u8]) -> bool {
        self.inner.verify(proof_system, statement, proof)
    }
}

impl<V: AuthorizationVerifier> AuthorizationVerifier for GenesisBackedFinalizedBlockVerifier<V> {
    fn verify_actor_signature(
        &self,
        envelope: &activechain_authorization_kernel::AuthorizationEnvelope,
    ) -> bool {
        self.inner.verify_actor_signature(envelope)
    }
    fn verify_finalized_context(
        &self,
        envelope: &activechain_authorization_kernel::AuthorizationEnvelope,
    ) -> bool {
        self.inner.verify_finalized_context(envelope)
    }
    fn verify_credential_signature(&self, credential: &Credential) -> bool {
        self.inner.verify_credential_signature(credential)
    }
    fn verify_credential_status(&self, material: &CredentialMaterial) -> bool {
        self.inner.verify_credential_status(material)
    }
    fn verify_capability_signature(&self, capability: &CapabilityGrant) -> bool {
        self.inner.verify_capability_signature(capability)
    }
    fn verify_capability_active(
        &self,
        capability: &CapabilityGrant,
        height: u64,
        state_root: Digest384,
    ) -> bool {
        self.inner.verify_capability_active(capability, height, state_root)
    }
}

impl<V: FinalizedBlockVerifier> FinalizedBlockVerifier for GenesisBackedFinalizedBlockVerifier<V> {
    fn verify_certificate(&self, certificate: &QuorumCertificate, votes: &[ValidatorVote]) -> bool {
        if certificate.genesis_commitment() != self.genesis.genesis_commitment()
            || certificate.epoch() != self.genesis.epoch()
            || certificate.protocol_revision() != self.genesis.protocol_revision()
            || certificate.validator_set_root() != self.genesis.validator_set_root()
        {
            return false;
        }
        let Ok(validator_set) = self.genesis.validator_set() else {
            return false;
        };
        let mut keyed_votes = Vec::with_capacity(votes.len());
        for vote in votes {
            let Some(entry) =
                self.genesis.entries().iter().find(|entry| entry.validator() == vote.validator())
            else {
                return false;
            };
            keyed_votes.push((entry.public_key().as_slice(), vote.clone()));
        }
        activechain_crypto_provider::verify_quorum_certificate(
            certificate,
            &validator_set,
            &keyed_votes,
        )
        .is_ok()
    }
    fn verify_issuer_approval(&self, approval: &FungibleIssuerApprovalV1) -> bool {
        self.inner.verify_issuer_approval(approval)
    }
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
        pre_cash_cell_root: Digest384,
        cash_action_ids: &[activechain_protocol_types::TransactionId],
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
            if let ActionPayloadV2::SubmitAnchor { statement, .. } = action.payload() {
                if statement
                    .submission_reference()
                    .map_or(true, |reference| action.authorization_commitment() != reference)
                {
                    return Err(FinalizedBlockAdmissionError::Authorization);
                }
                continue;
            }
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
            let input = transaction
                .commands()
                .first()
                .ok_or(FinalizedBlockAdmissionError::Authorization)?
                .input();
            let expected_control_policy_hash = state
                .objects()
                .find(input.object_id())
                .ok_or(FinalizedBlockAdmissionError::Authorization)?
                .control_policy_hash();
            let verified = verify_authorization_candidate(
                candidate,
                chain_genesis_commitment,
                epoch,
                block.pre_state().root(),
                expected_control_policy_hash,
                verifier,
            )
            .map_err(|_| FinalizedBlockAdmissionError::Authorization)?;
            if !verified.matches_finalized_action_context(
                block.height(),
                action.sender(),
                action.authorization_commitment(),
                action.payload_commitment(),
            ) || candidate.transaction != *transaction
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
            pre_cash_cell_root,
            cash_action_ids,
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
            || !verifier.verify_certificate(&self.certificate, &self.certificate_votes)
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
    use activechain_action_kernel::{
        ACTION_PROTOCOL_VERSION, ActionEnvelope, FeeTicket, NonceChannel, ResourcePrices,
        ResourceVector, ValidityInterval,
    };
    use activechain_application_primitives::DigestAnchorStatementV1;
    use activechain_devnet_kernel::{ActionOutcome, FeeAccount};
    use activechain_protocol_types::{ChainId, ConsensusVoteContext, ObjectId};
    use activechain_state_tree::{StateCommitment, commit_objects};
    use activechain_transition::ObjectState;
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};

    struct AcceptAll;
    impl ExecutionProofVerifier for AcceptAll {
        fn verify(&self, system: u16, _statement: Digest384, proof: &[u8]) -> bool {
            system == 1 && proof == b"valid-proof"
        }
    }
    impl FinalizedBlockVerifier for AcceptAll {
        fn verify_certificate(
            &self,
            _certificate: &QuorumCertificate,
            votes: &[ValidatorVote],
        ) -> bool {
            votes.len() == 1
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
            &[],
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

    fn certificate_vote(certificate: &QuorumCertificate) -> ValidatorVote {
        ValidatorVote::new(
            PrincipalId::new(Digest384::new([31; 48])),
            ConsensusVoteContext::new_with_revision(
                certificate.genesis_commitment(),
                certificate.epoch(),
                certificate.validator_set_root(),
                certificate.protocol_revision(),
            )
            .unwrap(),
            certificate.height(),
            certificate.round(),
            certificate.block_digest(),
            certificate.proposal_commitment(),
            activechain_protocol_types::ProtocolSignature::new(
                activechain_protocol_types::CryptoSuiteId::ML_DSA_44,
                vec![0; 2420],
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn genesis_backed_verifier_requires_real_pq_votes_and_exact_stake_context() {
        use activechain_protocol_types::{
            BlockProposal, ConsensusBlockRef, CryptoSuiteId, ProposalJustification,
            ProtocolSignature, ValidatorGenesisEntry,
        };
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([41; 32]));
        let validator = PrincipalId::new(Digest384::new([42; 48]));
        let genesis = ValidatorGenesis::new_with_revision(
            7,
            1,
            4,
            vec![
                ValidatorGenesisEntry::new(validator, 1, key.verifying_key().encode().into())
                    .unwrap(),
            ],
        )
        .unwrap();
        let context = ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let proposal = BlockProposal::new(
            validator,
            context,
            1,
            0,
            Digest384::new([43; 48]),
            ProposalJustification::Finalized(
                ConsensusBlockRef::new(
                    context.genesis_commitment(),
                    context.genesis_commitment(),
                    0,
                    0,
                )
                .unwrap(),
            ),
            placeholder.clone(),
        )
        .unwrap();
        let unsigned = ValidatorVote::new(
            validator,
            context,
            1,
            0,
            proposal.block_digest(),
            proposal.commitment(),
            placeholder,
        )
        .unwrap();
        let vote = ValidatorVote::new(
            validator,
            context,
            1,
            0,
            proposal.block_digest(),
            proposal.commitment(),
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                key.sign(&unsigned.signing_payload()).encode().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let validator_set = genesis.validator_set().unwrap();
        let mut collector = crate::VoteCollector::new(
            proposal,
            genesis.genesis_commitment(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        );
        collector
            .add_vote(&validator_set, key.verifying_key().encode().as_slice(), vote.clone())
            .unwrap();
        let certificate = collector.finalize(genesis.epoch(), &validator_set).unwrap();
        let verifier = GenesisBackedFinalizedBlockVerifier::new(genesis, AcceptAll);
        assert!(verifier.verify_certificate(&certificate, core::slice::from_ref(&vote)));
        assert!(!verifier.verify_certificate(&certificate, &[]));
        let forged = certificate_vote(&certificate);
        assert!(!verifier.verify_certificate(&certificate, &[forged]));
    }

    #[test]
    fn direct_execution_proof_binds_reexecuted_inputs_receipt_fees_and_prover() {
        let (state, block, inputs, _, _, _, root) = fixture();
        let (_, _, receipt, _) = derive_proof_public_inputs(
            &state,
            &block,
            inputs.epoch,
            inputs.protocol_revision,
            root,
            inputs.pre_supply,
            inputs.issuance,
            inputs.burn,
            inputs.pre_cash_cell_root,
            &[],
            inputs.cash_cell_root,
            1,
            1,
        )
        .unwrap();
        let direct = DirectExecutionProofV1::new(
            inputs,
            receipt.clone(),
            PrincipalId::new(Digest384::new([52; 48])),
        )
        .unwrap()
        .into_verified()
        .unwrap();
        let statement = direct.statement_commitment().unwrap();
        assert!(DirectExecutionProofVerifier.verify(
            direct.proof_system,
            statement,
            &direct.proof_bytes,
        ));
        let mut tampered = direct.proof_bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(!DirectExecutionProofVerifier.verify(direct.proof_system, statement, &tampered));
        let wrong_receipt = BlockReceipt::new(
            receipt.block_id(),
            receipt.height(),
            receipt.pre_state(),
            receipt.post_state(),
            receipt.pre_chain_state(),
            receipt.post_chain_state(),
            vec![activechain_devnet_kernel::ActionReceipt::new(
                activechain_protocol_types::TransactionId::new(Digest384::new([53; 48])),
                activechain_devnet_kernel::ActionOutcome::ResourceLimitExceeded,
                activechain_action_kernel::ResourceVector::default(),
                1,
                0,
                receipt.post_state(),
            )],
        )
        .unwrap();
        assert_eq!(
            DirectExecutionProofV1::new(inputs, wrong_receipt, direct.prover),
            Err(FinalizedBlockAdmissionError::Proof)
        );
    }

    #[test]
    fn prepared_direct_block_preserves_the_exact_pre_vote_admission_material() {
        let (state, block, inputs, _, _, genesis, root) = fixture();
        let prepared = PreparedDirectFinalizedBlock::new(
            &state,
            &block,
            inputs.epoch,
            inputs.protocol_revision,
            root,
            inputs.pre_supply,
            inputs.issuance,
            inputs.burn,
            inputs.pre_cash_cell_root,
            &[],
            inputs.cash_cell_root,
            1,
            1,
            PrincipalId::new(Digest384::new([54; 48])),
        )
        .unwrap();
        assert_eq!(prepared.header().inputs, inputs);
        assert_eq!(prepared.next_state().height(), 1);
        assert_eq!(prepared.receipt().height(), 1);
        let digest = prepared.header().digest().unwrap();
        let certificate = QuorumCertificate::new(
            ConsensusVoteContext::new_with_revision(genesis, 7, root, 4).unwrap(),
            1,
            0,
            digest,
            Digest384::new([55; 48]),
            Digest384::new([56; 48]),
            4,
            4,
        )
        .unwrap();
        let candidate =
            prepared.into_candidate(certificate.clone(), vec![certificate_vote(&certificate)]);
        assert_eq!(candidate.claimed_header.inputs, inputs);
        assert_eq!(candidate.certificate.block_digest(), digest);
        assert_eq!(candidate.proof.proof_system, DirectExecutionProofV1::PROOF_SYSTEM);
    }

    #[test]
    fn prepared_direct_block_executes_only_exactly_bound_native_anchor_actions() {
        let chain = ChainId::new(Digest384::new([61; 48]));
        let sender = PrincipalId::new(Digest384::new([62; 48]));
        let resources = ResourceVector::new(1, 1, 1, 0, 0, 2_048);
        let state = ChainState::genesis_with_fee_accounts(
            chain,
            ObjectState::new(vec![]).unwrap(),
            vec![NonceChannel::new(sender, 0, 0)],
            vec![FeeAccount::new(sender, 10_000, 0)],
            ResourcePrices::new(1, 1, 1, 1, 1, 1),
        )
        .unwrap();
        let statement =
            DigestAnchorStatementV1::new(b"actum.test.anchor".to_vec(), [63; 32]).unwrap();
        let reference = statement.submission_reference().unwrap();
        let payload = ActionPayloadV2::submit_anchor(1, statement);
        let payload_commitment = payload.commitment().unwrap();
        let action = ActionEnvelope::new_payload(
            ACTION_PROTOCOL_VERSION,
            chain,
            sender,
            FeeTicket::new(ObjectId::new(Digest384::new([64; 48])), sender, 2_052, 1, 0, resources)
                .unwrap(),
            0,
            0,
            ValidityInterval::new(1, 1).unwrap(),
            resources,
            payload_commitment,
            payload.clone(),
            reference,
        )
        .unwrap();
        let block = DevnetBlock::new(
            chain,
            1,
            state.head_block_id(),
            commit_objects(state.objects().objects()).unwrap(),
            state.commitment().unwrap(),
            vec![action],
        )
        .unwrap();
        let prepared = PreparedDirectFinalizedBlock::new(
            &state,
            &block,
            7,
            4,
            Digest384::new([65; 48]),
            100,
            0,
            0,
            Digest384::new([66; 48]),
            &[],
            Digest384::new([66; 48]),
            1,
            1,
            sender,
        )
        .unwrap();
        assert!(matches!(
            prepared.receipt().action_receipts()[0].outcome(),
            ActionOutcome::AnchorSubmitted { reference: actual } if actual == reference
        ));

        let unbound = ActionEnvelope::new_payload(
            ACTION_PROTOCOL_VERSION,
            chain,
            sender,
            FeeTicket::new(ObjectId::new(Digest384::new([67; 48])), sender, 2_050, 1, 0, resources)
                .unwrap(),
            0,
            0,
            ValidityInterval::new(1, 1).unwrap(),
            resources,
            payload_commitment,
            payload,
            Digest384::new([68; 48]),
        )
        .unwrap();
        let unbound_block = DevnetBlock::new(
            chain,
            1,
            state.head_block_id(),
            commit_objects(state.objects().objects()).unwrap(),
            state.commitment().unwrap(),
            vec![unbound],
        )
        .unwrap();
        assert_eq!(
            PreparedDirectFinalizedBlock::new(
                &state,
                &unbound_block,
                7,
                4,
                Digest384::new([65; 48]),
                100,
                0,
                0,
                Digest384::new([66; 48]),
                &[],
                Digest384::new([66; 48]),
                1,
                1,
                sender,
            ),
            Err(FinalizedBlockAdmissionError::Authorization)
        );
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
                246, 172, 218, 115, 158, 235, 173, 142, 225, 190, 199, 123, 70, 217, 193, 20, 214,
                249, 208, 183, 180, 84, 105, 132, 251, 39, 230, 11, 198, 252, 216, 3, 56, 144, 72,
                41, 105, 63, 173, 220, 81, 121, 209, 179, 193, 72, 232, 162,
            ])
        );
        assert_eq!(
            include_str!("../../../testing/vectors/consensus/finalized-block-v1.txt"),
            "header_type_tag=0x0079\nheader_schema_version=3\nproof_inputs_type_tag=0x0078\nproof_inputs_schema_version=3\nheader_digest=f6acda739eebad8ee1bec77b46d9c114d6f9d0b7b4546984fb27e60bc6fcd80338904829693faddc5179d1b3c148e8a2\n"
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
            certificate_votes: vec![certificate_vote(&certificate)],
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
                    header.inputs.pre_cash_cell_root,
                    &[],
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
            certificate_votes: vec![certificate_vote(&certificate)],
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
                header.inputs.pre_cash_cell_root,
                &[],
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
            ProofPublicInputs { pre_cash_cell_root: Digest384::new([28; 48]), ..header.inputs },
            ProofPublicInputs { cash_action_root: Digest384::new([29; 48]), ..header.inputs },
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
                certificate_votes: vec![certificate_vote(&certificate)],
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
                    header.inputs.pre_cash_cell_root,
                    &[],
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
            certificate: certificate.clone(),
            certificate_votes: vec![certificate_vote(&certificate)],
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
            header.inputs.pre_cash_cell_root,
            &[],
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
