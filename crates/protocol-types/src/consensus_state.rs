//! Deterministic consensus-state transition checks for the PQ testnet kernel.

use crate::{Epoch, EpochTransition, QuorumCertificate};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusState {
    epoch: Epoch,
    finalized_height: u64,
    finalized_round: u64,
}
impl ConsensusState {
    pub const fn new(epoch: Epoch) -> Self {
        Self { epoch, finalized_height: 0, finalized_round: 0 }
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
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusStateError {
    WrongEpoch,
    NonMonotonicCertificate,
    InvalidTransition,
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
}
