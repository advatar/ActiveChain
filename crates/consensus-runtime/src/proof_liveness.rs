//! Fail-closed validity-proof deadline, grace, and recovery policy.

/// Consensus safety bound for a configured proof deadline.
pub const MAX_PROOF_DEADLINE_ROUNDS: u16 = 64;
/// Consensus safety bound for re-execution-only proof-pending history.
pub const MAX_PROOF_GRACE_DEPTH: u16 = 64;

/// Bounded liveness parameters activated with mandatory execution proofs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofLivenessProfile {
    proof_deadline_rounds: u16,
    max_grace_depth: u16,
}

impl ProofLivenessProfile {
    /// Initial v1.1 profile. Governance may only replace it through a protocol revision.
    pub const V1_1: Self = Self { proof_deadline_rounds: 2, max_grace_depth: 8 };

    pub const fn new(
        proof_deadline_rounds: u16,
        max_grace_depth: u16,
    ) -> Result<Self, ProofLivenessError> {
        if proof_deadline_rounds == 0
            || proof_deadline_rounds > MAX_PROOF_DEADLINE_ROUNDS
            || max_grace_depth == 0
            || max_grace_depth > MAX_PROOF_GRACE_DEPTH
        {
            return Err(ProofLivenessError::InvalidProfile);
        }
        Ok(Self { proof_deadline_rounds, max_grace_depth })
    }

    pub const fn proof_deadline_rounds(self) -> u16 {
        self.proof_deadline_rounds
    }

    pub const fn max_grace_depth(self) -> u16 {
        self.max_grace_depth
    }

    /// Evaluates one transition without mutating execution or finality state.
    ///
    /// `pending_depth` is the exact consecutive proof-pending prefix. Recovery evidence must cover
    /// that complete prefix; a proof for only the current block cannot skip pending history.
    pub const fn evaluate(
        self,
        input: ProofLivenessInput,
    ) -> Result<ProofLivenessDecision, ProofLivenessError> {
        if input.pending_depth > self.max_grace_depth {
            return Err(ProofLivenessError::InvalidState);
        }
        match input.evidence {
            ProofEvidence::Invalid => Err(ProofLivenessError::InvalidProof),
            ProofEvidence::Mismatched => Err(ProofLivenessError::ProofMismatch),
            ProofEvidence::ValidCurrent => {
                if input.pending_depth == 0 {
                    Ok(ProofLivenessDecision::FinalizeProven)
                } else {
                    Err(ProofLivenessError::MissingPendingHistory)
                }
            }
            ProofEvidence::ValidRecovery { covered_pending_depth } => {
                if input.pending_depth == 0 || covered_pending_depth != input.pending_depth {
                    Err(ProofLivenessError::MissingPendingHistory)
                } else {
                    Ok(ProofLivenessDecision::RecoverPending {
                        cleared_pending_depth: input.pending_depth,
                    })
                }
            }
            ProofEvidence::Missing => {
                if !input.reexecution_valid {
                    return Err(ProofLivenessError::InvalidExecution);
                }
                if input.rounds_waited <= self.proof_deadline_rounds {
                    return Ok(ProofLivenessDecision::AwaitProof);
                }
                if input.pending_depth == self.max_grace_depth {
                    return Ok(ProofLivenessDecision::Halt);
                }
                Ok(ProofLivenessDecision::FinalizeProofPending {
                    pending_depth: input.pending_depth + 1,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofLivenessInput {
    pub pending_depth: u16,
    pub rounds_waited: u16,
    pub reexecution_valid: bool,
    pub evidence: ProofEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofEvidence {
    Missing,
    Invalid,
    Mismatched,
    ValidCurrent,
    ValidRecovery { covered_pending_depth: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofLivenessDecision {
    FinalizeProven,
    AwaitProof,
    FinalizeProofPending { pending_depth: u16 },
    RecoverPending { cleared_pending_depth: u16 },
    Halt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofLivenessError {
    InvalidProfile,
    InvalidState,
    InvalidExecution,
    InvalidProof,
    ProofMismatch,
    MissingPendingHistory,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_bounds_fail_closed() {
        assert_eq!(ProofLivenessProfile::new(0, 8), Err(ProofLivenessError::InvalidProfile));
        assert_eq!(ProofLivenessProfile::new(2, 0), Err(ProofLivenessError::InvalidProfile));
        assert_eq!(
            ProofLivenessProfile::new(MAX_PROOF_DEADLINE_ROUNDS + 1, 8),
            Err(ProofLivenessError::InvalidProfile)
        );
        assert_eq!(ProofLivenessProfile::new(2, 8), Ok(ProofLivenessProfile::V1_1));
    }

    #[test]
    fn frozen_liveness_vectors_execute() {
        let vectors = include_str!("../../../testing/vectors/proof-liveness-v1.tsv");
        assert!(vectors.starts_with(
            "case\tpending_depth\trounds_waited\treexecution_valid\tevidence\tcovered_depth\texpected\treason\n"
        ));
        for line in vectors.lines().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 8, "malformed vector: {line}");
            let pending_depth = fields[1].parse().unwrap();
            let rounds_waited = fields[2].parse().unwrap();
            let reexecution_valid = fields[3].parse().unwrap();
            let covered_depth = fields[5].parse().unwrap();
            let evidence = match fields[4] {
                "missing" => ProofEvidence::Missing,
                "invalid" => ProofEvidence::Invalid,
                "mismatched" => ProofEvidence::Mismatched,
                "valid-current" => ProofEvidence::ValidCurrent,
                "valid-recovery" => {
                    ProofEvidence::ValidRecovery { covered_pending_depth: covered_depth }
                }
                value => panic!("unknown evidence {value}"),
            };
            let actual = ProofLivenessProfile::V1_1.evaluate(ProofLivenessInput {
                pending_depth,
                rounds_waited,
                reexecution_valid,
                evidence,
            });
            let expected = match fields[6] {
                "finalize-proven" => Ok(ProofLivenessDecision::FinalizeProven),
                "await-proof" => Ok(ProofLivenessDecision::AwaitProof),
                "pending-1" => Ok(ProofLivenessDecision::FinalizeProofPending { pending_depth: 1 }),
                "pending-8" => Ok(ProofLivenessDecision::FinalizeProofPending { pending_depth: 8 }),
                "recover-3" => {
                    Ok(ProofLivenessDecision::RecoverPending { cleared_pending_depth: 3 })
                }
                "halt" => Ok(ProofLivenessDecision::Halt),
                "reject-invalid-proof" => Err(ProofLivenessError::InvalidProof),
                "reject-mismatch" => Err(ProofLivenessError::ProofMismatch),
                "reject-history" => Err(ProofLivenessError::MissingPendingHistory),
                "reject-execution" => Err(ProofLivenessError::InvalidExecution),
                value => panic!("unknown expectation {value}"),
            };
            assert_eq!(actual, expected, "vector {}", fields[0]);
        }
    }
}
