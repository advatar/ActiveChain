//! PQ-bound consensus message types for the first testnet boundary.

extern crate alloc;
use crate::{CryptoSuiteId, Digest384, Epoch, PrincipalId, ProtocolSignature};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorVote {
    validator: PrincipalId,
    context: ConsensusVoteContext,
    height: u64,
    round: u64,
    block_digest: Digest384,
    proposal_commitment: Digest384,
    signature: ProtocolSignature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusVoteContext {
    genesis_commitment: Digest384,
    epoch: Epoch,
    validator_set_root: Digest384,
    protocol_revision: u64,
}

impl ConsensusVoteContext {
    /// Constructs the initial protocol-revision context.
    pub fn new(
        genesis_commitment: Digest384,
        epoch: Epoch,
        validator_set_root: Digest384,
    ) -> Result<Self, ValidatorVoteError> {
        Self::new_with_revision(
            genesis_commitment,
            epoch,
            validator_set_root,
            INITIAL_PROTOCOL_REVISION,
        )
    }
    pub fn new_with_revision(
        genesis_commitment: Digest384,
        epoch: Epoch,
        validator_set_root: Digest384,
        protocol_revision: u64,
    ) -> Result<Self, ValidatorVoteError> {
        if genesis_commitment == Digest384::ZERO
            || validator_set_root == Digest384::ZERO
            || protocol_revision == 0
        {
            return Err(ValidatorVoteError::UnboundConsensusDomain);
        }
        Ok(Self { genesis_commitment, epoch, validator_set_root, protocol_revision })
    }
    pub const fn genesis_commitment(self) -> Digest384 {
        self.genesis_commitment
    }
    pub const fn epoch(self) -> Epoch {
        self.epoch
    }
    pub const fn validator_set_root(self) -> Digest384 {
        self.validator_set_root
    }
    pub const fn protocol_revision(self) -> u64 {
        self.protocol_revision
    }
}

pub const INITIAL_PROTOCOL_REVISION: u64 = 1;

impl ValidatorVote {
    pub const TYPE_TAG: u16 = 0x0064;
    pub const SCHEMA_VERSION: u16 = 4;
    pub const MAX_ENCODED_LEN: usize =
        48 + 48 + 8 + 48 + 8 + 8 + 8 + 48 + 48 + ProtocolSignature::MAX_ENCODED_LEN;
    /// Constructs a vote bound independently to the payload digest and exact signed proposal.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator: PrincipalId,
        context: ConsensusVoteContext,
        height: u64,
        round: u64,
        block_digest: Digest384,
        proposal_commitment: Digest384,
        signature: ProtocolSignature,
    ) -> Result<Self, ValidatorVoteError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(ValidatorVoteError::InvalidConsensusSuite);
        }
        if block_digest == Digest384::ZERO || proposal_commitment == Digest384::ZERO {
            return Err(ValidatorVoteError::UnboundConsensusDomain);
        }
        Ok(Self { validator, context, height, round, block_digest, proposal_commitment, signature })
    }
    pub const fn validator(&self) -> PrincipalId {
        self.validator
    }
    pub const fn genesis_commitment(&self) -> Digest384 {
        self.context.genesis_commitment()
    }
    pub const fn epoch(&self) -> Epoch {
        self.context.epoch()
    }
    pub const fn validator_set_root(&self) -> Digest384 {
        self.context.validator_set_root()
    }
    pub const fn protocol_revision(&self) -> u64 {
        self.context.protocol_revision()
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn round(&self) -> u64 {
        self.round
    }
    pub const fn block_digest(&self) -> Digest384 {
        self.block_digest
    }
    pub const fn proposal_commitment(&self) -> Digest384 {
        self.proposal_commitment
    }
    pub const fn signature(&self) -> &ProtocolSignature {
        &self.signature
    }
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(18 + 2 + 48 + 8 + 48 + 8 + 48 + 8 + 8 + 48 + 48);
        payload.extend_from_slice(b"ACTIVECHAIN-VOTE-V4");
        payload.extend_from_slice(&Self::SCHEMA_VERSION.to_be_bytes());
        payload.extend_from_slice(self.context.genesis_commitment.as_bytes());
        payload.extend_from_slice(&self.context.epoch.to_be_bytes());
        payload.extend_from_slice(self.context.validator_set_root.as_bytes());
        payload.extend_from_slice(&self.context.protocol_revision.to_be_bytes());
        payload.extend_from_slice(self.validator.digest().as_bytes());
        payload.extend_from_slice(&self.height.to_be_bytes());
        payload.extend_from_slice(&self.round.to_be_bytes());
        payload.extend_from_slice(self.block_digest.as_bytes());
        payload.extend_from_slice(self.proposal_commitment.as_bytes());
        payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorVoteError {
    InvalidConsensusSuite,
    UnboundConsensusDomain,
}

/// Authenticated position of a block in one consensus history.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsensusBlockRef {
    block_digest: Digest384,
    proposal_commitment: Digest384,
    height: u64,
    round: u64,
}

impl ConsensusBlockRef {
    pub fn new(
        block_digest: Digest384,
        proposal_commitment: Digest384,
        height: u64,
        round: u64,
    ) -> Result<Self, BlockProposalError> {
        if block_digest == Digest384::ZERO {
            return Err(BlockProposalError::ZeroBlockDigest);
        }
        if proposal_commitment == Digest384::ZERO {
            return Err(BlockProposalError::ZeroProposalCommitment);
        }
        Ok(Self { block_digest, proposal_commitment, height, round })
    }
    pub const fn block_digest(self) -> Digest384 {
        self.block_digest
    }
    pub const fn proposal_commitment(self) -> Digest384 {
        self.proposal_commitment
    }
    pub const fn height(self) -> u64 {
        self.height
    }
    pub const fn round(self) -> u64 {
        self.round
    }
}

/// Exact safety justification carried by a proposal.
///
/// A finalized anchor is accepted only when it equals the receiver's durable finalized head. A
/// QC is accepted only when its complete value equals a locally verified and durable certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalJustification {
    Finalized(ConsensusBlockRef),
    Quorum(QuorumCertificate),
}

impl ProposalJustification {
    pub const MAX_ENCODED_LEN: usize = 1 + QuorumCertificate::ENCODED_LENGTH;
    pub const fn parent(&self) -> ConsensusBlockRef {
        match self {
            Self::Finalized(parent) => *parent,
            Self::Quorum(certificate) => ConsensusBlockRef {
                block_digest: certificate.block_digest,
                proposal_commitment: certificate.proposal_commitment,
                height: certificate.height,
                round: certificate.round,
            },
        }
    }
    pub const fn certificate(&self) -> Option<&QuorumCertificate> {
        match self {
            Self::Finalized(_) => None,
            Self::Quorum(certificate) => Some(certificate),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockProposal {
    proposer: PrincipalId,
    context: ConsensusVoteContext,
    height: u64,
    round: u64,
    block_digest: Digest384,
    justification: ProposalJustification,
    signature: ProtocolSignature,
}
impl BlockProposal {
    pub const TYPE_TAG: u16 = 0x0068;
    pub const SCHEMA_VERSION: u16 = 3;
    pub const MAX_ENCODED_LEN: usize = 48
        + 48
        + 8
        + 48
        + 8
        + 8
        + 8
        + 48
        + ProposalJustification::MAX_ENCODED_LEN
        + ProtocolSignature::MAX_ENCODED_LEN;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposer: PrincipalId,
        context: ConsensusVoteContext,
        height: u64,
        round: u64,
        block_digest: Digest384,
        justification: ProposalJustification,
        signature: ProtocolSignature,
    ) -> Result<Self, BlockProposalError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(BlockProposalError::InvalidConsensusSuite);
        }
        if block_digest == Digest384::ZERO {
            return Err(BlockProposalError::ZeroBlockDigest);
        }
        let parent = justification.parent();
        if parent.height.checked_add(1) != Some(height) {
            return Err(BlockProposalError::NonConsecutiveHeight);
        }
        match &justification {
            ProposalJustification::Finalized(_) => {
                if parent.height > 0 && round <= parent.round {
                    return Err(BlockProposalError::NonIncreasingRound);
                }
            }
            ProposalJustification::Quorum(certificate) => {
                if certificate.context != context {
                    return Err(BlockProposalError::WrongConsensusContext);
                }
                if round <= parent.round {
                    return Err(BlockProposalError::NonIncreasingRound);
                }
            }
        }
        Ok(Self { proposer, context, height, round, block_digest, justification, signature })
    }
    pub const fn proposer(&self) -> PrincipalId {
        self.proposer
    }
    pub const fn context(&self) -> ConsensusVoteContext {
        self.context
    }
    pub const fn genesis_commitment(&self) -> Digest384 {
        self.context.genesis_commitment()
    }
    pub const fn epoch(&self) -> Epoch {
        self.context.epoch()
    }
    pub const fn validator_set_root(&self) -> Digest384 {
        self.context.validator_set_root()
    }
    pub const fn protocol_revision(&self) -> u64 {
        self.context.protocol_revision()
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn round(&self) -> u64 {
        self.round
    }
    pub const fn block_digest(&self) -> Digest384 {
        self.block_digest
    }
    pub const fn justification(&self) -> &ProposalJustification {
        &self.justification
    }
    pub const fn parent(&self) -> ConsensusBlockRef {
        self.justification.parent()
    }
    pub fn signature(&self) -> &ProtocolSignature {
        &self.signature
    }
    pub fn signing_payload(&self) -> Vec<u8> {
        // Capacity is deliberately not derived from the signature's current wire size: it is a
        // non-consensus optimization and must not couple the signed transcript to one ML-DSA
        // encoding constant.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ACTIVECHAIN-PROPOSAL-V3");
        bytes.extend_from_slice(&Self::SCHEMA_VERSION.to_be_bytes());
        bytes.extend_from_slice(self.proposer.digest().as_bytes());
        bytes.extend_from_slice(self.context.genesis_commitment.as_bytes());
        bytes.extend_from_slice(&self.context.epoch.to_be_bytes());
        bytes.extend_from_slice(self.context.validator_set_root.as_bytes());
        bytes.extend_from_slice(&self.context.protocol_revision.to_be_bytes());
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.round.to_be_bytes());
        bytes.extend_from_slice(self.block_digest.as_bytes());
        append_justification_transcript(&mut bytes, &self.justification);
        bytes
    }
    /// Commitment certified by schema-v4 validator votes in addition to the payload block digest.
    pub fn commitment(&self) -> Digest384 {
        let payload = self.signing_payload();
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-PROPOSAL-COMMITMENT-V3");
        hasher.update(&(payload.len() as u64).to_be_bytes());
        hasher.update(&payload);
        hasher.update(&(self.signature.as_bytes().len() as u64).to_be_bytes());
        hasher.update(self.signature.as_bytes());
        let mut commitment = [0_u8; 48];
        hasher.finalize_xof().read(&mut commitment);
        Digest384::new(commitment)
    }
}

fn append_justification_transcript(bytes: &mut Vec<u8>, justification: &ProposalJustification) {
    match justification {
        ProposalJustification::Finalized(parent) => {
            bytes.push(0);
            bytes.extend_from_slice(parent.block_digest.as_bytes());
            bytes.extend_from_slice(parent.proposal_commitment.as_bytes());
            bytes.extend_from_slice(&parent.height.to_be_bytes());
            bytes.extend_from_slice(&parent.round.to_be_bytes());
        }
        ProposalJustification::Quorum(certificate) => {
            bytes.push(1);
            bytes.extend_from_slice(certificate.genesis_commitment().as_bytes());
            bytes.extend_from_slice(&certificate.epoch().to_be_bytes());
            bytes.extend_from_slice(certificate.validator_set_root().as_bytes());
            bytes.extend_from_slice(&certificate.protocol_revision().to_be_bytes());
            bytes.extend_from_slice(&certificate.height().to_be_bytes());
            bytes.extend_from_slice(&certificate.round().to_be_bytes());
            bytes.extend_from_slice(certificate.block_digest().as_bytes());
            bytes.extend_from_slice(certificate.proposal_commitment().as_bytes());
            bytes.extend_from_slice(certificate.vote_set_root().as_bytes());
            bytes.extend_from_slice(&certificate.total_stake().to_be_bytes());
            bytes.extend_from_slice(&certificate.signer_stake().to_be_bytes());
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockProposalError {
    InvalidConsensusSuite,
    ZeroBlockDigest,
    ZeroProposalCommitment,
    NonConsecutiveHeight,
    NonIncreasingRound,
    WrongConsensusContext,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ValidatorWeight {
    pub validator: PrincipalId,
    pub stake: u128,
}

pub const MAX_VALIDATORS_PER_EPOCH: usize = 256;
pub const ML_DSA44_PUBLIC_KEY_LENGTH: usize = 1312;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorSet {
    validators: Vec<ValidatorWeight>,
    total_stake: u128,
}
impl ValidatorSet {
    pub const MAX_ENCODED_LEN: usize = 1 + MAX_VALIDATORS_PER_EPOCH * (48 + 16);
    pub fn new(validators: Vec<ValidatorWeight>) -> Result<Self, ValidatorSetError> {
        if validators.is_empty() || validators.len() > MAX_VALIDATORS_PER_EPOCH {
            return Err(ValidatorSetError::Bounds);
        }
        if validators.iter().any(|v| v.stake == 0) {
            return Err(ValidatorSetError::ZeroStake);
        }
        let total_stake = validators
            .iter()
            .try_fold(0_u128, |total, validator| total.checked_add(validator.stake))
            .ok_or(ValidatorSetError::StakeOverflow)?;
        if validators.windows(2).any(|pair| pair[0].validator >= pair[1].validator) {
            return Err(ValidatorSetError::NotStrictlyOrdered);
        }
        Ok(Self { validators, total_stake })
    }
    pub fn as_slice(&self) -> &[ValidatorWeight] {
        &self.validators
    }
    pub fn stake_of(&self, validator: &PrincipalId) -> Option<u128> {
        self.validators
            .binary_search_by_key(validator, |entry| entry.validator)
            .ok()
            .map(|index| self.validators[index].stake)
    }
    pub const fn total_stake(&self) -> u128 {
        self.total_stake
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorSetError {
    Bounds,
    ZeroStake,
    StakeOverflow,
    NotStrictlyOrdered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochTransition {
    from_epoch: Epoch,
    to_epoch: Epoch,
    activation_height: u64,
    validator_set_root: Digest384,
}
impl EpochTransition {
    pub const TYPE_TAG: u16 = 0x0067;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const ENCODED_LENGTH: usize = 8 + 8 + 8 + 48;
    pub fn new(
        from_epoch: Epoch,
        to_epoch: Epoch,
        activation_height: u64,
        validator_set_root: Digest384,
    ) -> Result<Self, EpochTransitionError> {
        if from_epoch.checked_add(1) != Some(to_epoch) {
            return Err(EpochTransitionError::NonConsecutiveEpochs);
        }
        if activation_height == 0 {
            return Err(EpochTransitionError::ZeroActivationHeight);
        }
        if validator_set_root == Digest384::ZERO {
            return Err(EpochTransitionError::ZeroValidatorSetRoot);
        }
        Ok(Self { from_epoch, to_epoch, activation_height, validator_set_root })
    }
    pub const fn from_epoch(&self) -> Epoch {
        self.from_epoch
    }
    pub const fn to_epoch(&self) -> Epoch {
        self.to_epoch
    }
    pub const fn activation_height(&self) -> u64 {
        self.activation_height
    }
    pub const fn validator_set_root(&self) -> Digest384 {
        self.validator_set_root
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochTransitionError {
    NonConsecutiveEpochs,
    ZeroActivationHeight,
    ZeroValidatorSetRoot,
}

/// Canonical control-plane authorization committed by a finalized block before activation.
///
/// The authorization may change the validator set, the protocol revision, or both. A validator
/// set change advances exactly one epoch; a revision change is strictly increasing. Runtime code
/// must additionally verify a quorum-certified block whose digest equals [`Self::commitment`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusUpgradeAuthorization {
    authorization_height: u64,
    activation_height: u64,
    from_epoch: Epoch,
    to_epoch: Epoch,
    previous_validator_set_root: Digest384,
    next_validator_set_root: Digest384,
    previous_protocol_revision: u64,
    next_protocol_revision: u64,
}

impl ConsensusUpgradeAuthorization {
    pub const TYPE_TAG: u16 = 0x006d;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const ENCODED_LENGTH: usize = 8 + 8 + 8 + 8 + 48 + 48 + 8 + 8;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization_height: u64,
        activation_height: u64,
        from_epoch: Epoch,
        to_epoch: Epoch,
        previous_validator_set_root: Digest384,
        next_validator_set_root: Digest384,
        previous_protocol_revision: u64,
        next_protocol_revision: u64,
    ) -> Result<Self, ConsensusUpgradeAuthorizationError> {
        if authorization_height == 0 || authorization_height >= activation_height {
            return Err(ConsensusUpgradeAuthorizationError::AuthorizationNotPrior);
        }
        if previous_validator_set_root == Digest384::ZERO
            || next_validator_set_root == Digest384::ZERO
        {
            return Err(ConsensusUpgradeAuthorizationError::ZeroValidatorSetRoot);
        }
        if previous_protocol_revision == 0 || next_protocol_revision == 0 {
            return Err(ConsensusUpgradeAuthorizationError::ZeroProtocolRevision);
        }
        let validator_set_changes = previous_validator_set_root != next_validator_set_root;
        if validator_set_changes {
            if from_epoch.checked_add(1) != Some(to_epoch) {
                return Err(ConsensusUpgradeAuthorizationError::InvalidEpochTransition);
            }
        } else if from_epoch != to_epoch {
            return Err(ConsensusUpgradeAuthorizationError::InvalidEpochTransition);
        }
        if next_protocol_revision < previous_protocol_revision {
            return Err(ConsensusUpgradeAuthorizationError::ProtocolRevisionDowngrade);
        }
        if !validator_set_changes && next_protocol_revision == previous_protocol_revision {
            return Err(ConsensusUpgradeAuthorizationError::NoChange);
        }
        Ok(Self {
            authorization_height,
            activation_height,
            from_epoch,
            to_epoch,
            previous_validator_set_root,
            next_validator_set_root,
            previous_protocol_revision,
            next_protocol_revision,
        })
    }
    pub const fn authorization_height(&self) -> u64 {
        self.authorization_height
    }
    pub const fn activation_height(&self) -> u64 {
        self.activation_height
    }
    pub const fn from_epoch(&self) -> Epoch {
        self.from_epoch
    }
    pub const fn to_epoch(&self) -> Epoch {
        self.to_epoch
    }
    pub const fn previous_validator_set_root(&self) -> Digest384 {
        self.previous_validator_set_root
    }
    pub const fn next_validator_set_root(&self) -> Digest384 {
        self.next_validator_set_root
    }
    pub const fn previous_protocol_revision(&self) -> u64 {
        self.previous_protocol_revision
    }
    pub const fn next_protocol_revision(&self) -> u64 {
        self.next_protocol_revision
    }
    pub fn changes_validator_set(&self) -> bool {
        self.previous_validator_set_root != self.next_validator_set_root
    }
    pub const fn changes_protocol_revision(&self) -> bool {
        self.previous_protocol_revision != self.next_protocol_revision
    }
    pub fn commitment(&self) -> Digest384 {
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-CONSENSUS-UPGRADE-V1");
        hasher.update(&Self::SCHEMA_VERSION.to_be_bytes());
        hasher.update(&self.authorization_height.to_be_bytes());
        hasher.update(&self.activation_height.to_be_bytes());
        hasher.update(&self.from_epoch.to_be_bytes());
        hasher.update(&self.to_epoch.to_be_bytes());
        hasher.update(self.previous_validator_set_root.as_bytes());
        hasher.update(self.next_validator_set_root.as_bytes());
        hasher.update(&self.previous_protocol_revision.to_be_bytes());
        hasher.update(&self.next_protocol_revision.to_be_bytes());
        let mut commitment = [0_u8; 48];
        hasher.finalize_xof().read(&mut commitment);
        Digest384::new(commitment)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusUpgradeAuthorizationError {
    AuthorizationNotPrior,
    ZeroValidatorSetRoot,
    ZeroProtocolRevision,
    InvalidEpochTransition,
    ProtocolRevisionDowngrade,
    NoChange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumCertificate {
    context: ConsensusVoteContext,
    height: u64,
    round: u64,
    block_digest: Digest384,
    proposal_commitment: Digest384,
    vote_set_root: Digest384,
    total_stake: u128,
    signer_stake: u128,
}

impl QuorumCertificate {
    pub const TYPE_TAG: u16 = 0x0065;
    pub const SCHEMA_VERSION: u16 = 3;
    pub const ENCODED_LENGTH: usize = 48 + 8 + 48 + 8 + 8 + 8 + 48 + 48 + 48 + 16 + 16;
    pub fn new(
        context: ConsensusVoteContext,
        height: u64,
        round: u64,
        block_digest: Digest384,
        proposal_commitment: Digest384,
        vote_set_root: Digest384,
        total_stake: u128,
        signer_stake: u128,
    ) -> Result<Self, QuorumCertificateError> {
        if height == 0
            || block_digest == Digest384::ZERO
            || proposal_commitment == Digest384::ZERO
            || vote_set_root == Digest384::ZERO
        {
            return Err(QuorumCertificateError::UnboundCertificate);
        }
        if total_stake == 0 || signer_stake > total_stake {
            return Err(QuorumCertificateError::InvalidStake);
        }
        if signer_stake.checked_mul(3).ok_or(QuorumCertificateError::StakeOverflow)?
            <= total_stake.checked_mul(2).ok_or(QuorumCertificateError::StakeOverflow)?
        {
            return Err(QuorumCertificateError::InsufficientStake);
        }
        Ok(Self {
            context,
            height,
            round,
            block_digest,
            proposal_commitment,
            vote_set_root,
            total_stake,
            signer_stake,
        })
    }
    pub const fn epoch(&self) -> Epoch {
        self.context.epoch()
    }
    pub const fn genesis_commitment(&self) -> Digest384 {
        self.context.genesis_commitment()
    }
    pub const fn validator_set_root(&self) -> Digest384 {
        self.context.validator_set_root()
    }
    pub const fn protocol_revision(&self) -> u64 {
        self.context.protocol_revision()
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn round(&self) -> u64 {
        self.round
    }
    pub const fn total_stake(&self) -> u128 {
        self.total_stake
    }
    pub const fn signer_stake(&self) -> u128 {
        self.signer_stake
    }
    pub const fn block_digest(&self) -> Digest384 {
        self.block_digest
    }
    pub const fn proposal_commitment(&self) -> Digest384 {
        self.proposal_commitment
    }
    pub const fn vote_set_root(&self) -> Digest384 {
        self.vote_set_root
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumCertificateError {
    UnboundCertificate,
    InvalidStake,
    InsufficientStake,
    StakeOverflow,
}

impl CanonicalEncode for ValidatorVote {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.validator.encode(e)?;
        self.context.genesis_commitment.encode(e)?;
        self.context.epoch.encode(e)?;
        self.context.validator_set_root.encode(e)?;
        self.context.protocol_revision.encode(e)?;
        self.height.encode(e)?;
        self.round.encode(e)?;
        self.block_digest.encode(e)?;
        self.proposal_commitment.encode(e)?;
        self.signature.encode(e)
    }
}
impl CanonicalDecode for ValidatorVote {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(d)?,
            ConsensusVoteContext::new_with_revision(
                Digest384::decode(d)?,
                u64::decode(d)?,
                Digest384::decode(d)?,
                u64::decode(d)?,
            )
            .map_err(|_| DecodeError::InvalidValue("validator vote context is unbound"))?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            ProtocolSignature::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("validator vote requires ML-DSA-44"))
    }
}
impl CanonicalType for ValidatorVote {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}
impl CanonicalEncode for ConsensusBlockRef {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.block_digest.encode(encoder)?;
        self.proposal_commitment.encode(encoder)?;
        self.height.encode(encoder)?;
        self.round.encode(encoder)
    }
}
impl CanonicalDecode for ConsensusBlockRef {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid consensus block reference"))
    }
}
impl CanonicalEncode for ProposalJustification {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Finalized(parent) => {
                0_u8.encode(encoder)?;
                parent.encode(encoder)
            }
            Self::Quorum(certificate) => {
                1_u8.encode(encoder)?;
                certificate.encode(encoder)
            }
        }
    }
}
impl CanonicalDecode for ProposalJustification {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Finalized(ConsensusBlockRef::decode(decoder)?)),
            1 => Ok(Self::Quorum(QuorumCertificate::decode(decoder)?)),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ProposalJustification", tag }),
        }
    }
}
impl CanonicalEncode for BlockProposal {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.proposer.encode(e)?;
        self.context.genesis_commitment.encode(e)?;
        self.context.epoch.encode(e)?;
        self.context.validator_set_root.encode(e)?;
        self.context.protocol_revision.encode(e)?;
        self.height.encode(e)?;
        self.round.encode(e)?;
        self.block_digest.encode(e)?;
        self.justification.encode(e)?;
        self.signature.encode(e)
    }
}
impl CanonicalDecode for BlockProposal {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(d)?,
            ConsensusVoteContext::new_with_revision(
                Digest384::decode(d)?,
                u64::decode(d)?,
                Digest384::decode(d)?,
                u64::decode(d)?,
            )
            .map_err(|_| DecodeError::InvalidValue("block proposal context is unbound"))?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            ProposalJustification::decode(d)?,
            ProtocolSignature::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid ML-DSA block proposal"))
    }
}
impl CanonicalType for BlockProposal {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}
impl CanonicalEncode for QuorumCertificate {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.context.genesis_commitment.encode(e)?;
        self.context.epoch.encode(e)?;
        self.context.validator_set_root.encode(e)?;
        self.context.protocol_revision.encode(e)?;
        self.height.encode(e)?;
        self.round.encode(e)?;
        self.block_digest.encode(e)?;
        self.proposal_commitment.encode(e)?;
        self.vote_set_root.encode(e)?;
        self.total_stake.encode(e)?;
        self.signer_stake.encode(e)
    }
}
impl CanonicalDecode for QuorumCertificate {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ConsensusVoteContext::new_with_revision(
                Digest384::decode(d)?,
                u64::decode(d)?,
                Digest384::decode(d)?,
                u64::decode(d)?,
            )
            .map_err(|_| DecodeError::InvalidValue("quorum certificate context is unbound"))?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid quorum certificate"))
    }
}
impl CanonicalType for QuorumCertificate {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}
impl CanonicalEncode for ValidatorSet {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_length(self.validators.len(), MAX_VALIDATORS_PER_EPOCH)?;
        for validator in &self.validators {
            validator.validator.encode(e)?;
            validator.stake.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for ValidatorSet {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let n = d.read_length(MAX_VALIDATORS_PER_EPOCH)?;
        let mut values = Vec::with_capacity(n);
        for _ in 0..n {
            values.push(ValidatorWeight {
                validator: PrincipalId::decode(d)?,
                stake: u128::decode(d)?,
            });
        }
        Self::new(values).map_err(|_| DecodeError::InvalidValue("invalid validator set"))
    }
}
impl CanonicalType for ValidatorSet {
    const TYPE_TAG: u16 = 0x0066;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorGenesisEntry {
    validator: PrincipalId,
    stake: u128,
    public_key: [u8; ML_DSA44_PUBLIC_KEY_LENGTH],
}
impl ValidatorGenesisEntry {
    pub const ENCODED_LENGTH: usize = 48 + 16 + ML_DSA44_PUBLIC_KEY_LENGTH;
    pub fn new(
        validator: PrincipalId,
        stake: u128,
        public_key: [u8; ML_DSA44_PUBLIC_KEY_LENGTH],
    ) -> Result<Self, ValidatorGenesisError> {
        if stake == 0 {
            return Err(ValidatorGenesisError::ZeroStake);
        }
        Ok(Self { validator, stake, public_key })
    }
    pub const fn validator(&self) -> PrincipalId {
        self.validator
    }
    pub const fn stake(&self) -> u128 {
        self.stake
    }
    pub fn public_key(&self) -> &[u8; ML_DSA44_PUBLIC_KEY_LENGTH] {
        &self.public_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorGenesis {
    epoch: Epoch,
    activation_height: u64,
    protocol_revision: u64,
    entries: Vec<ValidatorGenesisEntry>,
}
impl ValidatorGenesis {
    pub const TYPE_TAG: u16 = 0x006b;
    pub const SCHEMA_VERSION: u16 = 2;
    pub const MAX_ENCODED_LEN: usize =
        8 + 8 + 8 + 1 + MAX_VALIDATORS_PER_EPOCH * ValidatorGenesisEntry::ENCODED_LENGTH;
    pub fn new(
        epoch: Epoch,
        activation_height: u64,
        entries: Vec<ValidatorGenesisEntry>,
    ) -> Result<Self, ValidatorGenesisError> {
        Self::new_with_revision(epoch, activation_height, INITIAL_PROTOCOL_REVISION, entries)
    }
    pub fn new_with_revision(
        epoch: Epoch,
        activation_height: u64,
        protocol_revision: u64,
        entries: Vec<ValidatorGenesisEntry>,
    ) -> Result<Self, ValidatorGenesisError> {
        if activation_height == 0 || entries.is_empty() || entries.len() > MAX_VALIDATORS_PER_EPOCH
        {
            return Err(ValidatorGenesisError::Bounds);
        }
        if protocol_revision == 0 {
            return Err(ValidatorGenesisError::ZeroProtocolRevision);
        }
        if entries.windows(2).any(|pair| pair[0].validator >= pair[1].validator) {
            return Err(ValidatorGenesisError::NotStrictlyOrdered);
        }
        Ok(Self { epoch, activation_height, protocol_revision, entries })
    }
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub const fn activation_height(&self) -> u64 {
        self.activation_height
    }
    pub const fn protocol_revision(&self) -> u64 {
        self.protocol_revision
    }
    pub fn entries(&self) -> &[ValidatorGenesisEntry] {
        &self.entries
    }
    pub fn validator_set(&self) -> Result<ValidatorSet, ValidatorSetError> {
        ValidatorSet::new(
            self.entries
                .iter()
                .map(|entry| ValidatorWeight { validator: entry.validator, stake: entry.stake })
                .collect(),
        )
    }
    pub fn validator_set_root(&self) -> Digest384 {
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-VALIDATOR-SET-V1");
        for entry in &self.entries {
            hasher.update(entry.validator.digest().as_bytes());
            hasher.update(&entry.stake.to_be_bytes());
            hasher.update(&entry.public_key);
        }
        let mut root = [0_u8; 48];
        hasher.finalize_xof().read(&mut root);
        Digest384::new(root)
    }
    /// Immutable commitment used to domain-separate consensus signatures.
    /// Identical genesis manifests intentionally identify the same chain.
    pub fn genesis_commitment(&self) -> Digest384 {
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-CONSENSUS-GENESIS-V2");
        hasher.update(&self.epoch.to_be_bytes());
        hasher.update(&self.activation_height.to_be_bytes());
        hasher.update(&self.protocol_revision.to_be_bytes());
        hasher.update(self.validator_set_root().as_bytes());
        let mut commitment = [0_u8; 48];
        hasher.finalize_xof().read(&mut commitment);
        Digest384::new(commitment)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorGenesisError {
    Bounds,
    ZeroStake,
    ZeroProtocolRevision,
    NotStrictlyOrdered,
}
impl CanonicalEncode for ValidatorGenesisEntry {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.validator.encode(e)?;
        self.stake.encode(e)?;
        self.public_key.encode(e)
    }
}
impl CanonicalDecode for ValidatorGenesisEntry {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(d)?,
            u128::decode(d)?,
            <[u8; ML_DSA44_PUBLIC_KEY_LENGTH]>::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid validator genesis entry"))
    }
}
impl CanonicalEncode for ValidatorGenesis {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.epoch.encode(e)?;
        self.activation_height.encode(e)?;
        self.protocol_revision.encode(e)?;
        e.write_length(self.entries.len(), MAX_VALIDATORS_PER_EPOCH)?;
        for entry in &self.entries {
            entry.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for ValidatorGenesis {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let epoch = u64::decode(d)?;
        let activation_height = u64::decode(d)?;
        let protocol_revision = u64::decode(d)?;
        let count = d.read_length(MAX_VALIDATORS_PER_EPOCH)?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(ValidatorGenesisEntry::decode(d)?);
        }
        Self::new_with_revision(epoch, activation_height, protocol_revision, entries)
            .map_err(|_| DecodeError::InvalidValue("invalid validator genesis"))
    }
}
impl CanonicalType for ValidatorGenesis {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}
impl CanonicalEncode for EpochTransition {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.from_epoch.encode(e)?;
        self.to_epoch.encode(e)?;
        self.activation_height.encode(e)?;
        self.validator_set_root.encode(e)
    }
}
impl CanonicalDecode for EpochTransition {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(u64::decode(d)?, u64::decode(d)?, u64::decode(d)?, Digest384::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid epoch transition"))
    }
}
impl CanonicalType for EpochTransition {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}

impl CanonicalEncode for ConsensusUpgradeAuthorization {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.authorization_height.encode(encoder)?;
        self.activation_height.encode(encoder)?;
        self.from_epoch.encode(encoder)?;
        self.to_epoch.encode(encoder)?;
        self.previous_validator_set_root.encode(encoder)?;
        self.next_validator_set_root.encode(encoder)?;
        self.previous_protocol_revision.encode(encoder)?;
        self.next_protocol_revision.encode(encoder)
    }
}

impl CanonicalDecode for ConsensusUpgradeAuthorization {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid consensus upgrade authorization"))
    }
}

impl CanonicalType for ConsensusUpgradeAuthorization {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::vec;
    extern crate alloc;
    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    #[test]
    fn validator_vote_is_round_scoped_and_pq_bound() {
        let vote = ValidatorVote::new(
            PrincipalId::new(digest(1)),
            ConsensusVoteContext::new(digest(10), 3, digest(11)).unwrap(),
            7,
            2,
            digest(3),
            digest(4),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![4; 2420]).unwrap(),
        )
        .unwrap();
        assert_eq!(vote.height(), 7);
        assert_eq!(vote.round(), 2);
        assert_eq!(vote.epoch(), 3);
        assert_eq!(vote.genesis_commitment(), digest(10));
        assert_eq!(vote.validator_set_root(), digest(11));
        assert_eq!(vote.protocol_revision(), INITIAL_PROTOCOL_REVISION);
        assert_eq!(decode_envelope::<ValidatorVote>(&encode_envelope(&vote).unwrap()), Ok(vote));
    }
    #[test]
    fn validator_vote_rejects_other_pq_signature_suites() {
        let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, vec![4; 3309]).unwrap();
        assert_eq!(
            ValidatorVote::new(
                PrincipalId::new(digest(1)),
                ConsensusVoteContext::new(digest(10), 3, digest(11)).unwrap(),
                7,
                2,
                digest(3),
                digest(4),
                signature,
            ),
            Err(ValidatorVoteError::InvalidConsensusSuite)
        );
    }
    #[test]
    fn validator_vote_signature_domain_binds_genesis_epoch_validator_set_and_revision() {
        let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![4; 2420]).unwrap();
        let make = |genesis, epoch, root, revision| {
            ValidatorVote::new(
                PrincipalId::new(digest(1)),
                ConsensusVoteContext::new_with_revision(genesis, epoch, root, revision).unwrap(),
                7,
                2,
                digest(3),
                digest(4),
                signature.clone(),
            )
            .unwrap()
            .signing_payload()
        };
        let baseline = make(digest(10), 3, digest(11), 1);
        assert_ne!(baseline, make(digest(12), 3, digest(11), 1));
        assert_ne!(baseline, make(digest(10), 4, digest(11), 1));
        assert_ne!(baseline, make(digest(10), 3, digest(12), 1));
        assert_ne!(baseline, make(digest(10), 3, digest(11), 2));
    }
    #[test]
    fn proposal_v3_strictly_binds_context_parent_and_canonical_bytes() {
        let context =
            ConsensusVoteContext::new_with_revision(digest(10), 3, digest(11), 2).unwrap();
        let anchor = ProposalJustification::Finalized(
            ConsensusBlockRef::new(
                context.genesis_commitment(),
                context.genesis_commitment(),
                0,
                0,
            )
            .unwrap(),
        );
        let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![4; 2420]).unwrap();
        let proposal = BlockProposal::new(
            PrincipalId::new(digest(1)),
            context,
            1,
            0,
            digest(3),
            anchor,
            signature,
        )
        .unwrap();
        let encoded = encode_envelope(&proposal).unwrap();
        assert_eq!(decode_envelope::<BlockProposal>(&encoded), Ok(proposal.clone()));

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_envelope::<BlockProposal>(&trailing),
            Err(DecodeError::TrailingData { remaining: 1 })
        ));
        let mut wrong_version = encoded;
        wrong_version[2..4].copy_from_slice(&1_u16.to_be_bytes());
        assert!(matches!(
            decode_envelope::<BlockProposal>(&wrong_version),
            Err(DecodeError::UnsupportedSchemaVersion { expected: 3, actual: 1 })
        ));
        assert_ne!(proposal.commitment(), Digest384::ZERO);
    }
    #[test]
    fn proposal_rejects_stale_qc_context_and_non_increasing_parent() {
        let context =
            ConsensusVoteContext::new_with_revision(digest(10), 3, digest(11), 2).unwrap();
        let stale_context =
            ConsensusVoteContext::new_with_revision(digest(10), 3, digest(12), 2).unwrap();
        let stale_qc =
            QuorumCertificate::new(stale_context, 1, 1, digest(4), digest(5), digest(6), 10, 7)
                .unwrap();
        let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![4; 2420]).unwrap();
        assert_eq!(
            BlockProposal::new(
                PrincipalId::new(digest(1)),
                context,
                2,
                2,
                digest(3),
                ProposalJustification::Quorum(stale_qc),
                signature.clone(),
            ),
            Err(BlockProposalError::WrongConsensusContext)
        );
        assert_eq!(
            BlockProposal::new(
                PrincipalId::new(digest(1)),
                context,
                2,
                1,
                digest(3),
                ProposalJustification::Quorum(
                    QuorumCertificate::new(context, 1, 1, digest(4), digest(5), digest(6), 10, 7,)
                        .unwrap(),
                ),
                signature,
            ),
            Err(BlockProposalError::NonIncreasingRound)
        );
    }
    #[test]
    fn quorum_certificate_requires_strict_two_thirds_stake() {
        let context = ConsensusVoteContext::new(digest(10), 1, digest(11)).unwrap();
        assert!(
            QuorumCertificate::new(context, 2, 3, digest(1), digest(2), digest(3), 10, 7).is_ok()
        );
        assert_eq!(
            QuorumCertificate::new(context, 2, 3, digest(1), digest(2), digest(3), 10, 6),
            Err(QuorumCertificateError::InsufficientStake)
        );
    }
    #[test]
    fn quorum_certificate_v3_rejects_old_schema_trailing_and_identity_tamper() {
        let context = ConsensusVoteContext::new(digest(10), 1, digest(11)).unwrap();
        let certificate =
            QuorumCertificate::new(context, 2, 3, digest(1), digest(2), digest(3), 10, 7).unwrap();
        let encoded = encode_envelope(&certificate).unwrap();
        assert_eq!(decode_envelope::<QuorumCertificate>(&encoded), Ok(certificate));

        let mut old_schema = encoded.clone();
        old_schema[2..4].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            decode_envelope::<QuorumCertificate>(&old_schema),
            Err(DecodeError::UnsupportedSchemaVersion { expected: 3, actual: 2 })
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_envelope::<QuorumCertificate>(&trailing),
            Err(DecodeError::TrailingData { remaining: 1 })
        );

        let mut tampered = encoded;
        let body_offset = tampered.len() - QuorumCertificate::ENCODED_LENGTH;
        tampered[body_offset + 176..body_offset + 224].fill(0);
        assert_eq!(
            decode_envelope::<QuorumCertificate>(&tampered),
            Err(DecodeError::InvalidValue("invalid quorum certificate"))
        );
    }
    #[test]
    fn validator_set_rejects_total_stake_overflow() {
        assert_eq!(
            ValidatorSet::new(vec![
                ValidatorWeight { validator: PrincipalId::new(digest(1)), stake: u128::MAX },
                ValidatorWeight { validator: PrincipalId::new(digest(2)), stake: 1 },
            ]),
            Err(ValidatorSetError::StakeOverflow)
        );
    }
    #[test]
    fn frozen_qc_vector_matches_threshold_rules() {
        let vector = include_str!("../../../testing/vectors/consensus/qc-v1.txt");
        let value = |name: &str| {
            vector
                .lines()
                .find_map(|line| {
                    line.split_once('=').and_then(|(key, value)| (key == name).then_some(value))
                })
                .unwrap()
                .parse::<u128>()
                .unwrap()
        };
        let qc = QuorumCertificate::new(
            ConsensusVoteContext::new(digest(10), value("epoch") as u64, digest(11)).unwrap(),
            value("height") as u64,
            value("round") as u64,
            digest(1),
            digest(2),
            digest(3),
            value("total_stake"),
            value("signer_stake"),
        )
        .unwrap();
        assert_eq!(qc.height(), 9);
        assert_eq!(
            QuorumCertificate::new(
                ConsensusVoteContext::new(digest(10), value("epoch") as u64, digest(11),).unwrap(),
                value("height") as u64,
                value("round") as u64,
                digest(1),
                digest(2),
                digest(3),
                value("total_stake"),
                value("under_threshold_signer_stake"),
            ),
            Err(QuorumCertificateError::InsufficientStake)
        );
    }
    #[test]
    fn epoch_transition_requires_consecutive_epochs() {
        let transition = EpochTransition::new(4, 5, 100, digest(9)).unwrap();
        assert_eq!(transition.to_epoch(), 5);
        assert_eq!(
            EpochTransition::new(4, 6, 100, digest(9)),
            Err(EpochTransitionError::NonConsecutiveEpochs)
        );
    }

    #[test]
    fn upgrade_authorization_is_canonical_monotonic_and_commitment_bound() {
        let authorization =
            ConsensusUpgradeAuthorization::new(9, 10, 4, 5, digest(8), digest(9), 2, 3).unwrap();
        let envelope = encode_envelope(&authorization).unwrap();
        assert_eq!(decode_envelope::<ConsensusUpgradeAuthorization>(&envelope), Ok(authorization));
        assert_ne!(authorization.commitment(), Digest384::ZERO);
        let different_revision =
            ConsensusUpgradeAuthorization::new(9, 10, 4, 5, digest(8), digest(9), 2, 4).unwrap();
        assert_ne!(authorization.commitment(), different_revision.commitment());
        assert_eq!(
            ConsensusUpgradeAuthorization::new(9, 10, 4, 5, digest(8), digest(9), 3, 2,),
            Err(ConsensusUpgradeAuthorizationError::ProtocolRevisionDowngrade)
        );
        assert_eq!(
            ConsensusUpgradeAuthorization::new(10, 10, 4, 5, digest(8), digest(9), 2, 3,),
            Err(ConsensusUpgradeAuthorizationError::AuthorizationNotPrior)
        );
    }

    #[test]
    fn validator_genesis_binds_ordered_stake_and_ml_dsa_keys() {
        let first = ValidatorGenesisEntry::new(
            crate::PrincipalId::new(digest(1)),
            4,
            [7; ML_DSA44_PUBLIC_KEY_LENGTH],
        )
        .unwrap();
        let second = ValidatorGenesisEntry::new(
            crate::PrincipalId::new(digest(2)),
            6,
            [8; ML_DSA44_PUBLIC_KEY_LENGTH],
        )
        .unwrap();
        let genesis = ValidatorGenesis::new(3, 1, vec![first, second]).unwrap();
        let encoded = encode_envelope(&genesis).unwrap();
        assert_eq!(decode_envelope::<ValidatorGenesis>(&encoded), Ok(genesis.clone()));
        assert_eq!(genesis.validator_set().unwrap().total_stake(), 10);
        assert_ne!(genesis.validator_set_root(), Digest384::ZERO);
        assert_eq!(genesis.entries()[0].public_key()[0], 7);
        assert_eq!(
            ValidatorGenesis::new(
                3,
                1,
                vec![genesis.entries()[1].clone(), genesis.entries()[0].clone()]
            ),
            Err(ValidatorGenesisError::NotStrictlyOrdered)
        );
    }
}
