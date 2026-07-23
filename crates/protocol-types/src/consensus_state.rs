//! Deterministic consensus-state transition checks for the PQ testnet kernel.

use crate::{
    ConsensusBlockRef, ConsensusUpgradeAuthorization, Digest384, Epoch, INITIAL_PROTOCOL_REVISION,
    QuorumCertificate,
};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};

/// Testnet safety bound. Exhaustion fails closed rather than discarding rollback history.
pub const MAX_RETIRED_VALIDATOR_SET_ROOTS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusState {
    epoch: Epoch,
    finalized_height: u64,
    finalized_round: u64,
    finalized_block_digest: Digest384,
    finalized_proposal_commitment: Digest384,
    certified_handoff: Option<ConsensusBlockRef>,
    validator_set_root: Digest384,
    protocol_revision: u64,
    retired_validator_set_roots: [Digest384; MAX_RETIRED_VALIDATOR_SET_ROOTS],
    retired_validator_set_root_count: u8,
}

impl ConsensusState {
    pub const fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            finalized_height: 0,
            finalized_round: 0,
            finalized_block_digest: Digest384::ZERO,
            finalized_proposal_commitment: Digest384::ZERO,
            certified_handoff: None,
            validator_set_root: Digest384::ZERO,
            protocol_revision: INITIAL_PROTOCOL_REVISION,
            retired_validator_set_roots: [Digest384::ZERO; MAX_RETIRED_VALIDATOR_SET_ROOTS],
            retired_validator_set_root_count: 0,
        }
    }
    pub const fn new_with_validator_set_root(epoch: Epoch, validator_set_root: Digest384) -> Self {
        Self {
            epoch,
            finalized_height: 0,
            finalized_round: 0,
            finalized_block_digest: Digest384::ZERO,
            finalized_proposal_commitment: Digest384::ZERO,
            certified_handoff: None,
            validator_set_root,
            protocol_revision: INITIAL_PROTOCOL_REVISION,
            retired_validator_set_roots: [Digest384::ZERO; MAX_RETIRED_VALIDATOR_SET_ROOTS],
            retired_validator_set_root_count: 0,
        }
    }
    pub fn new_with_consensus_context(
        epoch: Epoch,
        validator_set_root: Digest384,
        protocol_revision: u64,
    ) -> Result<Self, ConsensusStateError> {
        if validator_set_root == Digest384::ZERO || protocol_revision == 0 {
            return Err(ConsensusStateError::InvalidConsensusContext);
        }
        Ok(Self {
            epoch,
            finalized_height: 0,
            finalized_round: 0,
            finalized_block_digest: Digest384::ZERO,
            finalized_proposal_commitment: Digest384::ZERO,
            certified_handoff: None,
            validator_set_root,
            protocol_revision,
            retired_validator_set_roots: [Digest384::ZERO; MAX_RETIRED_VALIDATOR_SET_ROOTS],
            retired_validator_set_root_count: 0,
        })
    }
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }
    pub const fn finalized_round(&self) -> u64 {
        self.finalized_round
    }
    pub const fn finalized_block_digest(&self) -> Digest384 {
        self.finalized_block_digest
    }
    pub const fn finalized_proposal_commitment(&self) -> Digest384 {
        self.finalized_proposal_commitment
    }
    pub const fn certified_handoff(&self) -> Option<ConsensusBlockRef> {
        self.certified_handoff
    }
    /// Resolves the exact proposal-identity anchor used by proposal safety checks.
    ///
    /// The canonical state keeps zero finalized identities before the first commit; this method
    /// maps that state to the one permitted nonzero genesis sentinel so runtime and snapshot
    /// validation cannot choose different anchors.
    pub fn active_anchor(
        &self,
        genesis_commitment: Digest384,
    ) -> Result<ConsensusBlockRef, ConsensusStateError> {
        if genesis_commitment == Digest384::ZERO {
            return Err(ConsensusStateError::InvalidConsensusContext);
        }
        if let Some(handoff) = self.certified_handoff {
            return Ok(handoff);
        }
        let (block_digest, proposal_commitment) = if self.finalized_height == 0 {
            (genesis_commitment, genesis_commitment)
        } else {
            (self.finalized_block_digest, self.finalized_proposal_commitment)
        };
        ConsensusBlockRef::new(
            block_digest,
            proposal_commitment,
            self.finalized_height,
            self.finalized_round,
        )
        .map_err(|_| ConsensusStateError::InvalidConsensusContext)
    }
    pub const fn validator_set_root(&self) -> Digest384 {
        self.validator_set_root
    }
    pub const fn protocol_revision(&self) -> u64 {
        self.protocol_revision
    }
    pub fn retired_validator_set_roots(&self) -> &[Digest384] {
        &self.retired_validator_set_roots[..usize::from(self.retired_validator_set_root_count)]
    }
    /// Applies a QC whose block has already been committed by the consensus commit rule.
    ///
    /// This method does not establish that commitment itself. The authoritative runtime must
    /// first verify the proposal ancestry and a consecutive child QC before calling it. Keeping
    /// that precondition explicit prevents a bare, unparented QC from being mistaken for finality.
    pub fn apply_committed_qc(
        &mut self,
        qc: &QuorumCertificate,
    ) -> Result<(), ConsensusStateError> {
        if qc.epoch() != self.epoch {
            return Err(ConsensusStateError::WrongEpoch);
        }
        if qc.validator_set_root() != self.validator_set_root
            || qc.protocol_revision() != self.protocol_revision
        {
            return Err(ConsensusStateError::InvalidConsensusContext);
        }
        // A committed height is immutable. A later-round QC at that same height must never be
        // allowed to replace the committed digest.
        if qc.height() <= self.finalized_height {
            return Err(ConsensusStateError::NonMonotonicCertificate);
        }
        self.finalized_height = qc.height();
        self.finalized_round = qc.round();
        self.finalized_block_digest = qc.block_digest();
        self.finalized_proposal_commitment = qc.proposal_commitment();
        self.certified_handoff = None;
        Ok(())
    }
    /// Applies an upgrade after an already-verified certified handoff block.
    ///
    /// Two-QC finality commits the authorization's parent while retaining its certified child as
    /// the cross-epoch anchor. The next context therefore starts immediately after that certified
    /// child rather than reusing its height.
    pub fn apply_upgrade_after_certified_block(
        &mut self,
        authorization: &ConsensusUpgradeAuthorization,
        certified_handoff: ConsensusBlockRef,
    ) -> Result<(), ConsensusStateError> {
        if authorization.from_epoch() != self.epoch
            || authorization.previous_validator_set_root() != self.validator_set_root
            || authorization.previous_protocol_revision() != self.protocol_revision
            || authorization.authorization_height() > self.finalized_height
            || self.finalized_height.checked_add(1) != Some(certified_handoff.height())
            || self.finalized_round.checked_add(1) != Some(certified_handoff.round())
            || certified_handoff.height().checked_add(1) != Some(authorization.activation_height())
            || certified_handoff.proposal_commitment() == self.finalized_proposal_commitment
        {
            return Err(ConsensusStateError::InvalidTransition);
        }
        if authorization.changes_validator_set() {
            let next_root = authorization.next_validator_set_root();
            if self.retired_validator_set_roots().contains(&next_root) {
                return Err(ConsensusStateError::RetiredValidatorSet);
            }
            let count = usize::from(self.retired_validator_set_root_count);
            if count == MAX_RETIRED_VALIDATOR_SET_ROOTS {
                return Err(ConsensusStateError::ValidatorSetHistoryFull);
            }
            self.retired_validator_set_roots[count] = self.validator_set_root;
            self.retired_validator_set_root_count += 1;
        }
        self.epoch = authorization.to_epoch();
        self.validator_set_root = authorization.next_validator_set_root();
        self.protocol_revision = authorization.next_protocol_revision();
        self.certified_handoff = Some(certified_handoff);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusStateError {
    WrongEpoch,
    NonMonotonicCertificate,
    InvalidConsensusContext,
    InvalidTransition,
    RetiredValidatorSet,
    ValidatorSetHistoryFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusSnapshot {
    epoch: Epoch,
    finalized_height: u64,
    finalized_round: u64,
    finalized_block_digest: Digest384,
    finalized_proposal_commitment: Digest384,
    certified_handoff: Option<ConsensusBlockRef>,
    validator_set_root: Digest384,
    protocol_revision: u64,
    retired_validator_set_roots: [Digest384; MAX_RETIRED_VALIDATOR_SET_ROOTS],
    retired_validator_set_root_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenesisConfig {
    pub epoch: Epoch,
    pub activation_height: u64,
    pub validator_set_root: Digest384,
}
impl GenesisConfig {
    pub const TYPE_TAG: u16 = 0x006a;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const ENCODED_LENGTH: usize = 8 + 8 + 48;
    pub fn new(
        epoch: Epoch,
        activation_height: u64,
        validator_set_root: Digest384,
    ) -> Result<Self, GenesisConfigError> {
        if activation_height == 0 {
            return Err(GenesisConfigError::ZeroActivationHeight);
        }
        Ok(Self { epoch, activation_height, validator_set_root })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenesisConfigError {
    ZeroActivationHeight,
}
impl CanonicalEncode for GenesisConfig {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.epoch.encode(encoder)?;
        self.activation_height.encode(encoder)?;
        self.validator_set_root.encode(encoder)
    }
}
impl CanonicalDecode for GenesisConfig {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(u64::decode(decoder)?, u64::decode(decoder)?, Digest384::decode(decoder)?)
            .map_err(|_| DecodeError::InvalidValue("invalid genesis configuration"))
    }
}
impl CanonicalType for GenesisConfig {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}

impl ConsensusState {
    pub const fn snapshot(&self) -> ConsensusSnapshot {
        ConsensusSnapshot {
            epoch: self.epoch,
            finalized_height: self.finalized_height,
            finalized_round: self.finalized_round,
            finalized_block_digest: self.finalized_block_digest,
            finalized_proposal_commitment: self.finalized_proposal_commitment,
            certified_handoff: self.certified_handoff,
            validator_set_root: self.validator_set_root,
            protocol_revision: self.protocol_revision,
            retired_validator_set_roots: self.retired_validator_set_roots,
            retired_validator_set_root_count: self.retired_validator_set_root_count,
        }
    }
    pub const fn from_snapshot(snapshot: ConsensusSnapshot) -> Self {
        Self {
            epoch: snapshot.epoch,
            finalized_height: snapshot.finalized_height,
            finalized_round: snapshot.finalized_round,
            finalized_block_digest: snapshot.finalized_block_digest,
            finalized_proposal_commitment: snapshot.finalized_proposal_commitment,
            certified_handoff: snapshot.certified_handoff,
            validator_set_root: snapshot.validator_set_root,
            protocol_revision: snapshot.protocol_revision,
            retired_validator_set_roots: snapshot.retired_validator_set_roots,
            retired_validator_set_root_count: snapshot.retired_validator_set_root_count,
        }
    }
}

impl CanonicalEncode for ConsensusSnapshot {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.epoch.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        self.finalized_round.encode(encoder)?;
        self.finalized_block_digest.encode(encoder)?;
        self.finalized_proposal_commitment.encode(encoder)?;
        self.certified_handoff.encode(encoder)?;
        self.validator_set_root.encode(encoder)?;
        self.protocol_revision.encode(encoder)?;
        let count = usize::from(self.retired_validator_set_root_count);
        encoder.write_length(count, MAX_RETIRED_VALIDATOR_SET_ROOTS)?;
        for root in &self.retired_validator_set_roots[..count] {
            root.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for ConsensusSnapshot {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let epoch = u64::decode(decoder)?;
        let finalized_height = u64::decode(decoder)?;
        let finalized_round = u64::decode(decoder)?;
        let finalized_block_digest = Digest384::decode(decoder)?;
        let finalized_proposal_commitment = Digest384::decode(decoder)?;
        if (finalized_height == 0) != (finalized_block_digest == Digest384::ZERO)
            || (finalized_height == 0) != (finalized_proposal_commitment == Digest384::ZERO)
            || (finalized_height == 0 && finalized_round != 0)
        {
            return Err(DecodeError::InvalidValue("invalid finalized block reference"));
        }
        let certified_handoff = Option::<ConsensusBlockRef>::decode(decoder)?;
        if certified_handoff.is_some_and(|handoff| {
            finalized_height == 0
                || finalized_height.checked_add(1) != Some(handoff.height())
                || finalized_round.checked_add(1) != Some(handoff.round())
                || handoff.proposal_commitment() == finalized_proposal_commitment
        }) {
            return Err(DecodeError::InvalidValue("invalid certified handoff reference"));
        }
        let validator_set_root = Digest384::decode(decoder)?;
        let protocol_revision = u64::decode(decoder)?;
        if protocol_revision == 0 {
            return Err(DecodeError::InvalidValue("zero consensus protocol revision"));
        }
        let count = decoder.read_length(MAX_RETIRED_VALIDATOR_SET_ROOTS)?;
        let mut roots = [Digest384::ZERO; MAX_RETIRED_VALIDATOR_SET_ROOTS];
        for index in 0..count {
            let root = Digest384::decode(decoder)?;
            if root == Digest384::ZERO
                || root == validator_set_root
                || roots[..index].contains(&root)
            {
                return Err(DecodeError::InvalidValue("invalid retired validator-set root"));
            }
            roots[index] = root;
        }
        Ok(Self {
            epoch,
            finalized_height,
            finalized_round,
            finalized_block_digest,
            finalized_proposal_commitment,
            certified_handoff,
            validator_set_root,
            protocol_revision,
            retired_validator_set_roots: roots,
            retired_validator_set_root_count: count as u8,
        })
    }
}

impl CanonicalType for ConsensusSnapshot {
    const TYPE_TAG: u16 = 0x0069;
    const SCHEMA_VERSION: u16 = 4;
    const MAX_ENCODED_LEN: usize = 8
        + 8
        + 8
        + 48
        + 48
        + 1
        + 48
        + 48
        + 8
        + 8
        + 48
        + 8
        + 1
        + MAX_RETIRED_VALIDATOR_SET_ROOTS * 48;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConsensusVoteContext, QuorumCertificate};
    use activechain_canonical_codec::{DecodeError, decode_envelope, encode_envelope};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn qc(epoch: u64, height: u64, root: Digest384, revision: u64) -> QuorumCertificate {
        QuorumCertificate::new(
            ConsensusVoteContext::new_with_revision(digest(5), epoch, root, revision).unwrap(),
            height,
            1,
            digest(1),
            digest(2),
            digest(3),
            10,
            7,
        )
        .unwrap()
    }

    fn authorization(
        authorization_height: u64,
        activation_height: u64,
        previous_root: Digest384,
        next_root: Digest384,
        previous_revision: u64,
        next_revision: u64,
    ) -> ConsensusUpgradeAuthorization {
        ConsensusUpgradeAuthorization::new(
            authorization_height,
            activation_height,
            1,
            if previous_root == next_root { 1 } else { 2 },
            previous_root,
            next_root,
            previous_revision,
            next_revision,
        )
        .unwrap()
    }

    fn finalized_ref(state: &ConsensusState) -> ConsensusBlockRef {
        ConsensusBlockRef::new(
            state.finalized_block_digest(),
            state.finalized_proposal_commitment(),
            state.finalized_height(),
            state.finalized_round(),
        )
        .unwrap()
    }

    #[test]
    fn state_accepts_only_monotonic_qcs() {
        let root = digest(6);
        let mut state = ConsensusState::new_with_validator_set_root(1, root);
        let qc = qc(1, 2, root, 1);
        assert_eq!(state.apply_committed_qc(&qc), Ok(()));
        assert_eq!(
            state.apply_committed_qc(&qc),
            Err(ConsensusStateError::NonMonotonicCertificate)
        );
        let conflicting_same_height = QuorumCertificate::new(
            ConsensusVoteContext::new(digest(5), 1, root).unwrap(),
            2,
            3,
            digest(9),
            digest(10),
            digest(11),
            10,
            7,
        )
        .unwrap();
        assert_eq!(
            state.apply_committed_qc(&conflicting_same_height),
            Err(ConsensusStateError::NonMonotonicCertificate)
        );
        assert_eq!(state.finalized_block_digest(), digest(1));
        assert_eq!(state.finalized_proposal_commitment(), digest(2));
    }

    #[test]
    fn snapshot_v4_strictly_binds_finalized_identity_schema_and_length() {
        let state = ConsensusState::new_with_validator_set_root(1, digest(6));
        let encoded = encode_envelope(&state.snapshot()).unwrap();
        let decoded: ConsensusSnapshot = decode_envelope(&encoded).unwrap();
        assert_eq!(ConsensusState::from_snapshot(decoded), state);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_envelope::<ConsensusSnapshot>(&trailing),
            Err(DecodeError::TrailingData { remaining: 1 })
        );

        let mut wrong_schema = encoded.clone();
        wrong_schema[2..4].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            decode_envelope::<ConsensusSnapshot>(&wrong_schema),
            Err(DecodeError::UnsupportedSchemaVersion { expected: 4, actual: 2 })
        );

        let mut tampered = encoded;
        let body_offset = tampered.len() - (8 + 8 + 8 + 48 + 48 + 1 + 48 + 8 + 1);
        tampered[body_offset + 24] ^= 1;
        assert_eq!(
            decode_envelope::<ConsensusSnapshot>(&tampered),
            Err(DecodeError::InvalidValue("invalid finalized block reference"))
        );
    }

    #[test]
    fn upgrade_requires_exact_next_height_and_persists_history_and_revision() {
        let current_root = digest(8);
        let next_root = digest(9);
        let authorization = authorization(1, 3, current_root, next_root, 1, 2);
        let mut state = ConsensusState::new_with_validator_set_root(1, current_root);
        state.apply_committed_qc(&qc(1, 1, current_root, 1)).unwrap();
        assert_eq!(
            state.apply_upgrade_after_certified_block(&authorization, finalized_ref(&state)),
            Err(ConsensusStateError::InvalidTransition)
        );
        let handoff = ConsensusBlockRef::new(digest(12), digest(13), 2, 2).unwrap();
        assert_eq!(state.apply_upgrade_after_certified_block(&authorization, handoff), Ok(()));
        assert_eq!(state.epoch(), 2);
        assert_eq!(state.validator_set_root(), next_root);
        assert_eq!(state.protocol_revision(), 2);
        assert_eq!(state.retired_validator_set_roots(), &[current_root]);
        assert_eq!(state.certified_handoff(), Some(handoff));

        let restored = ConsensusState::from_snapshot(state.snapshot());
        assert_eq!(restored, state);
        let encoded = encode_envelope(&state.snapshot()).unwrap();
        let decoded: ConsensusSnapshot = decode_envelope(&encoded).unwrap();
        assert_eq!(ConsensusState::from_snapshot(decoded), state);
    }

    #[test]
    fn late_activation_and_retired_set_reactivation_fail_closed() {
        let root_a = digest(7);
        let root_b = digest(8);
        let first = authorization(1, 3, root_a, root_b, 1, 1);
        let mut state = ConsensusState::new_with_validator_set_root(1, root_a);
        state.apply_committed_qc(&qc(1, 1, root_a, 1)).unwrap();
        let first_handoff = ConsensusBlockRef::new(digest(12), digest(13), 2, 2).unwrap();
        state.apply_upgrade_after_certified_block(&first, first_handoff).unwrap();
        state.apply_committed_qc(&qc(2, 3, root_b, 1)).unwrap();

        let reactivation =
            ConsensusUpgradeAuthorization::new(2, 5, 2, 3, root_b, root_a, 1, 1).unwrap();
        let next_handoff = ConsensusBlockRef::new(digest(14), digest(15), 4, 2).unwrap();
        assert_eq!(
            state.apply_upgrade_after_certified_block(&reactivation, next_handoff),
            Err(ConsensusStateError::RetiredValidatorSet)
        );

        let late = ConsensusUpgradeAuthorization::new(1, 4, 2, 3, root_b, digest(9), 1, 1).unwrap();
        assert_eq!(
            state.apply_upgrade_after_certified_block(&late, next_handoff),
            Err(ConsensusStateError::InvalidTransition)
        );
    }

    #[test]
    fn protocol_only_upgrade_keeps_epoch_and_validator_set() {
        let root = digest(6);
        let authorization = authorization(1, 3, root, root, 1, 2);
        let mut state = ConsensusState::new_with_validator_set_root(1, root);
        state.apply_committed_qc(&qc(1, 1, root, 1)).unwrap();
        let handoff = ConsensusBlockRef::new(digest(12), digest(13), 2, 2).unwrap();
        state.apply_upgrade_after_certified_block(&authorization, handoff).unwrap();
        assert_eq!(state.epoch(), 1);
        assert_eq!(state.validator_set_root(), root);
        assert_eq!(state.protocol_revision(), 2);
        assert!(state.retired_validator_set_roots().is_empty());
    }

    #[test]
    fn explicit_context_rejects_zero_revision() {
        assert_eq!(
            ConsensusState::new_with_consensus_context(1, digest(1), 0),
            Err(ConsensusStateError::InvalidConsensusContext)
        );
        assert!(ConsensusVoteContext::new_with_revision(digest(1), 1, digest(2), 0).is_err());
    }
}
