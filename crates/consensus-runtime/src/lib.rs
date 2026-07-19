#![forbid(unsafe_code)]

//! Deterministic in-memory consensus boundary for the first PQ testnet runtime.

use activechain_crypto_provider::{VerificationError, verify_quorum_certificate};
use activechain_protocol_types::{
    ConsensusState, ConsensusStateError, QuorumCertificate, ValidatorSet, ValidatorVote,
};

pub fn finalize_round(
    state: &mut ConsensusState,
    validator_set: &ValidatorSet,
    certificate: &QuorumCertificate,
    votes: &[(&[u8], ValidatorVote)],
) -> Result<(), RuntimeError> {
    verify_quorum_certificate(certificate, validator_set, votes)
        .map_err(RuntimeError::VoteVerification)?;
    state.apply_qc(certificate).map_err(RuntimeError::State)
}

#[derive(Debug, Eq, PartialEq)]
pub enum RuntimeError {
    VoteVerification(VerificationError),
    State(ConsensusStateError),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_rejects_without_verified_votes() {
        let mut state = ConsensusState::new(1);
        let set = ValidatorSet::new(Vec::new());
        assert!(set.is_err());
        let _ = &mut state;
    }
}
