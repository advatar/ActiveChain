//! Deterministic consensus-state transition checks for the PQ testnet kernel.

use crate::{
    ConsensusUpgradeAuthorization, Digest384, Epoch, INITIAL_PROTOCOL_REVISION, QuorumCertificate,
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
    pub const fn validator_set_root(&self) -> Digest384 {
        self.validator_set_root
    }
    pub const fn protocol_revision(&self) -> u64 {
        self.protocol_revision
    }
    pub fn retired_validator_set_roots(&self) -> &[Digest384] {
        &self.retired_validator_set_roots[..usize::from(self.retired_validator_set_root_count)]
    }
    pub fn apply_qc(&mut self, qc: &QuorumCertificate) -> Result<(), ConsensusStateError> {
        if qc.epoch() != self.epoch {
            return Err(ConsensusStateError::WrongEpoch);
        }
        if qc.validator_set_root() != self.validator_set_root
            || qc.protocol_revision() != self.protocol_revision
        {
            return Err(ConsensusStateError::InvalidConsensusContext);
        }
        if qc.height() < self.finalized_height
            || (qc.height() == self.finalized_height && qc.round() <= self.finalized_round)
        {
            return Err(ConsensusStateError::NonMonotonicCertificate);
        }
        self.finalized_height = qc.height();
        self.finalized_round = qc.round();
        Ok(())
    }
    /// Applies a control-plane authorization only at the boundary immediately before its exact
    /// activation height. Cryptographic finality of the authorization is verified by the runtime.
    pub fn apply_upgrade(
        &mut self,
        authorization: &ConsensusUpgradeAuthorization,
    ) -> Result<(), ConsensusStateError> {
        if authorization.from_epoch() != self.epoch
            || authorization.previous_validator_set_root() != self.validator_set_root
            || authorization.previous_protocol_revision() != self.protocol_revision
            || authorization.authorization_height() > self.finalized_height
            || self.finalized_height.checked_add(1) != Some(authorization.activation_height())
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
            validator_set_root,
            protocol_revision,
            retired_validator_set_roots: roots,
            retired_validator_set_root_count: count as u8,
        })
    }
}

impl CanonicalType for ConsensusSnapshot {
    const TYPE_TAG: u16 = 0x0069;
    const SCHEMA_VERSION: u16 = 2;
    const MAX_ENCODED_LEN: usize = 8 + 8 + 8 + 48 + 8 + 1 + MAX_RETIRED_VALIDATOR_SET_ROOTS * 48;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConsensusVoteContext, QuorumCertificate};
    use activechain_canonical_codec::{decode_envelope, encode_envelope};

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

    #[test]
    fn state_accepts_only_monotonic_qcs() {
        let root = digest(6);
        let mut state = ConsensusState::new_with_validator_set_root(1, root);
        let qc = qc(1, 2, root, 1);
        assert_eq!(state.apply_qc(&qc), Ok(()));
        assert_eq!(state.apply_qc(&qc), Err(ConsensusStateError::NonMonotonicCertificate));
    }

    #[test]
    fn upgrade_requires_exact_next_height_and_persists_history_and_revision() {
        let current_root = digest(8);
        let next_root = digest(9);
        let authorization = authorization(1, 3, current_root, next_root, 1, 2);
        let mut state = ConsensusState::new_with_validator_set_root(1, current_root);
        state.apply_qc(&qc(1, 1, current_root, 1)).unwrap();
        assert_eq!(
            state.apply_upgrade(&authorization),
            Err(ConsensusStateError::InvalidTransition)
        );
        state.apply_qc(&qc(1, 2, current_root, 1)).unwrap();
        assert_eq!(state.apply_upgrade(&authorization), Ok(()));
        assert_eq!(state.epoch(), 2);
        assert_eq!(state.validator_set_root(), next_root);
        assert_eq!(state.protocol_revision(), 2);
        assert_eq!(state.retired_validator_set_roots(), &[current_root]);

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
        let first = authorization(1, 2, root_a, root_b, 1, 1);
        let mut state = ConsensusState::new_with_validator_set_root(1, root_a);
        state.apply_qc(&qc(1, 1, root_a, 1)).unwrap();
        state.apply_upgrade(&first).unwrap();
        state.apply_qc(&qc(2, 2, root_b, 1)).unwrap();

        let reactivation =
            ConsensusUpgradeAuthorization::new(2, 3, 2, 3, root_b, root_a, 1, 1).unwrap();
        assert_eq!(
            state.apply_upgrade(&reactivation),
            Err(ConsensusStateError::RetiredValidatorSet)
        );

        let late = ConsensusUpgradeAuthorization::new(1, 2, 2, 3, root_b, digest(9), 1, 1).unwrap();
        assert_eq!(state.apply_upgrade(&late), Err(ConsensusStateError::InvalidTransition));
    }

    #[test]
    fn protocol_only_upgrade_keeps_epoch_and_validator_set() {
        let root = digest(6);
        let authorization = authorization(1, 2, root, root, 1, 2);
        let mut state = ConsensusState::new_with_validator_set_root(1, root);
        state.apply_qc(&qc(1, 1, root, 1)).unwrap();
        state.apply_upgrade(&authorization).unwrap();
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
