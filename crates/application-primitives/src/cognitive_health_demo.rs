//! Narrow PHI-free ProvidEHR demo checkpoint projection into Actum's existing anchor path.
//!
//! The clinical and learning records remain in their authoritative systems. This type carries
//! only fixed-size commitments and constructs `DigestAnchorStatementV1`; consensus, inclusion,
//! state, and finality proofs remain the responsibility of the existing Actum machinery.

use activechain_protocol_types::Digest384;
use sha2::{Digest, Sha256};

use crate::DigestAnchorStatementV1;

pub const PROVIDEHR_DEMO_CHECKPOINT_DOMAIN: &[u8] = b"providehr.transparency.checkpoint.v1";
const CHECKPOINT_COMMITMENT_DOMAIN: &[u8] =
    b"providehr.cognitive-health-demo.checkpoint-commitment.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvidehrDemoCheckpointV1 {
    sequence: u64,
    clinical_decision_commitment: [u8; 32],
    kline_record_commitment: [u8; 32],
    dcn_event_head_commitment: [u8; 32],
    previous_checkpoint: Option<Digest384>,
}

impl ProvidehrDemoCheckpointV1 {
    pub fn new(
        sequence: u64,
        clinical_decision_commitment: [u8; 32],
        kline_record_commitment: [u8; 32],
        dcn_event_head_commitment: [u8; 32],
        previous_checkpoint: Option<Digest384>,
        synthetic: bool,
        contains_raw_health_data: bool,
    ) -> Result<Self, ProvidehrDemoCheckpointError> {
        if sequence == 0
            || clinical_decision_commitment == [0; 32]
            || kline_record_commitment == [0; 32]
            || dcn_event_head_commitment == [0; 32]
            || previous_checkpoint.is_some_and(|digest| digest == Digest384::ZERO)
        {
            return Err(ProvidehrDemoCheckpointError::InvalidCommitment);
        }
        if !synthetic || contains_raw_health_data {
            return Err(ProvidehrDemoCheckpointError::PrivacyBoundary);
        }
        Ok(Self {
            sequence,
            clinical_decision_commitment,
            kline_record_commitment,
            dcn_event_head_commitment,
            previous_checkpoint,
        })
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Deterministic SHA-256 projection used only as the digest carried by the canonical anchor.
    pub fn checkpoint_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CHECKPOINT_COMMITMENT_DOMAIN);
        hasher.update(self.sequence.to_be_bytes());
        hasher.update(self.clinical_decision_commitment);
        hasher.update(self.kline_record_commitment);
        hasher.update(self.dcn_event_head_commitment);
        match self.previous_checkpoint {
            Some(previous) => {
                hasher.update([1]);
                hasher.update(previous.as_bytes());
            }
            None => hasher.update([0]),
        }
        hasher.finalize().into()
    }

    pub fn anchor_statement(
        &self,
    ) -> Result<DigestAnchorStatementV1, ProvidehrDemoCheckpointError> {
        DigestAnchorStatementV1::new(
            PROVIDEHR_DEMO_CHECKPOINT_DOMAIN.to_vec(),
            self.checkpoint_commitment(),
        )
        .map_err(|_| ProvidehrDemoCheckpointError::InvalidCommitment)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvidehrDemoCheckpointError {
    InvalidCommitment,
    PrivacyBoundary,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(sequence: u64) -> ProvidehrDemoCheckpointV1 {
        ProvidehrDemoCheckpointV1::new(sequence, [1; 32], [2; 32], [3; 32], None, true, false)
            .unwrap()
    }

    #[test]
    fn checkpoint_uses_the_existing_canonical_anchor_statement() {
        let value = checkpoint(1);
        let expected = DigestAnchorStatementV1::new(
            PROVIDEHR_DEMO_CHECKPOINT_DOMAIN.to_vec(),
            value.checkpoint_commitment(),
        )
        .unwrap();
        assert_eq!(value.anchor_statement().unwrap(), expected);
        assert_eq!(
            value.anchor_statement().unwrap().submission_reference().unwrap(),
            expected.submission_reference().unwrap()
        );
    }

    #[test]
    fn commitment_is_deterministic_and_binds_sequence() {
        assert_eq!(checkpoint(1).checkpoint_commitment(), checkpoint(1).checkpoint_commitment());
        assert_ne!(checkpoint(1).checkpoint_commitment(), checkpoint(2).checkpoint_commitment());
    }

    #[test]
    fn raw_or_non_synthetic_input_never_reaches_the_anchor_path() {
        assert_eq!(
            ProvidehrDemoCheckpointV1::new(1, [1; 32], [2; 32], [3; 32], None, true, true),
            Err(ProvidehrDemoCheckpointError::PrivacyBoundary)
        );
        assert_eq!(
            ProvidehrDemoCheckpointV1::new(1, [1; 32], [2; 32], [3; 32], None, false, false),
            Err(ProvidehrDemoCheckpointError::PrivacyBoundary)
        );
    }
}
