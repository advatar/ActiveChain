//! Deterministic consensus-state transition checks for the PQ testnet kernel.

use crate::{Epoch, EpochTransition, QuorumCertificate};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusState {
    epoch: Epoch,
    finalized_height: u64,
    finalized_round: u64,
    validator_set_root: crate::Digest384,
}
impl ConsensusState {
    pub const fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            finalized_height: 0,
            finalized_round: 0,
            validator_set_root: crate::Digest384::ZERO,
        }
    }
    pub const fn new_with_validator_set_root(
        epoch: Epoch,
        validator_set_root: crate::Digest384,
    ) -> Self {
        Self { epoch, finalized_height: 0, finalized_round: 0, validator_set_root }
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
    pub const fn validator_set_root(&self) -> crate::Digest384 {
        self.validator_set_root
    }
    pub fn apply_qc(&mut self, qc: &QuorumCertificate) -> Result<(), ConsensusStateError> {
        if qc.epoch() != self.epoch {
            return Err(ConsensusStateError::WrongEpoch);
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
    pub fn apply_epoch_transition(
        &mut self,
        transition: &EpochTransition,
        activation_height: u64,
    ) -> Result<(), ConsensusStateError> {
        if transition.from_epoch() != self.epoch
            || transition.activation_height() != activation_height
        {
            return Err(ConsensusStateError::InvalidTransition);
        }
        self.epoch = transition.to_epoch();
        self.validator_set_root = transition.validator_set_root();
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusStateError {
    WrongEpoch,
    NonMonotonicCertificate,
    InvalidTransition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusSnapshot {
    pub epoch: Epoch,
    pub finalized_height: u64,
    pub finalized_round: u64,
    pub validator_set_root: crate::Digest384,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenesisConfig {
    pub epoch: Epoch,
    pub activation_height: u64,
    pub validator_set_root: crate::Digest384,
}
impl GenesisConfig {
    pub const TYPE_TAG: u16 = 0x006a;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const ENCODED_LENGTH: usize = 8 + 8 + 48;
    pub fn new(
        epoch: Epoch,
        activation_height: u64,
        validator_set_root: crate::Digest384,
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
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.epoch.encode(e)?;
        self.activation_height.encode(e)?;
        self.validator_set_root.encode(e)
    }
}
impl CanonicalDecode for GenesisConfig {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(u64::decode(d)?, u64::decode(d)?, crate::Digest384::decode(d)?)
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
        }
    }
    pub const fn from_snapshot(snapshot: ConsensusSnapshot) -> Self {
        Self {
            epoch: snapshot.epoch,
            finalized_height: snapshot.finalized_height,
            finalized_round: snapshot.finalized_round,
            validator_set_root: snapshot.validator_set_root,
        }
    }
}
impl CanonicalEncode for ConsensusSnapshot {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.epoch.encode(e)?;
        self.finalized_height.encode(e)?;
        self.finalized_round.encode(e).and_then(|_| self.validator_set_root.encode(e))
    }
}
impl CanonicalDecode for ConsensusSnapshot {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            epoch: u64::decode(d)?,
            finalized_height: u64::decode(d)?,
            finalized_round: u64::decode(d)?,
            validator_set_root: crate::Digest384::decode(d)?,
        })
    }
}
impl CanonicalType for ConsensusSnapshot {
    const TYPE_TAG: u16 = 0x0069;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 72;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Digest384, QuorumCertificate};
    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    #[test]
    fn state_accepts_only_monotonic_qcs() {
        let mut state = ConsensusState::new(1);
        let qc = QuorumCertificate::new(1, 2, 1, digest(1), digest(2), 10, 7).unwrap();
        assert_eq!(state.apply_qc(&qc), Ok(()));
        assert_eq!(state.apply_qc(&qc), Err(ConsensusStateError::NonMonotonicCertificate));
    }

    #[test]
    fn finalized_epoch_transition_activates_and_persists_validator_set_root() {
        let root = digest(9);
        let transition = EpochTransition::new(1, 2, 3, root).unwrap();
        let mut state = ConsensusState::new(1);
        assert_eq!(
            state.apply_epoch_transition(&transition, 2),
            Err(ConsensusStateError::InvalidTransition)
        );
        assert_eq!(state.apply_epoch_transition(&transition, 3), Ok(()));
        assert_eq!(state.validator_set_root(), root);
        let restored = ConsensusState::from_snapshot(state.snapshot());
        assert_eq!(restored.validator_set_root(), root);
    }
}
