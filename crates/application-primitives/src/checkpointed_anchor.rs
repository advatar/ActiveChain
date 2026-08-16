use crate::{
    AnchorError, AnchorRecord, AnchorStateRecordV1, AnchorStatus, DigestAnchorStatementV1,
    SignedActumVerifierTrustBundleV1, anchor_state_object,
};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{ChainId, Digest384};
use activechain_state_tree::{StateCommitment, StateProof, StateProofKind, verify_membership};

pub const MAX_GENERIC_ANCHOR_MEMBERSHIP_PROOF_LENGTH: usize = StateProof::MAX_ENCODED_LEN;

/// Generic checkpoint authentication for an already-finalized native digest anchor.
///
/// This is application-neutral. The application supplies the expected
/// `DigestAnchorStatementV1`; the verifier derives the exact immutable anchor
/// state object and checks membership under an operator-accepted checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointedAnchorEvidenceV1 {
    pub finalized_record: AnchorRecord,
    pub checkpoint_bundle_id: Digest384,
    pub checkpoint_height: u64,
    pub checkpoint_block_id: Digest384,
    pub checkpoint_state_root: Digest384,
    pub checkpoint_object_count: u64,
    pub anchor_state_proof: StateProof,
}

impl CheckpointedAnchorEvidenceV1 {
    pub fn new(
        finalized_record: AnchorRecord,
        checkpoint_bundle_id: Digest384,
        checkpoint_height: u64,
        checkpoint_block_id: Digest384,
        checkpoint_state_root: Digest384,
        checkpoint_object_count: u64,
        anchor_state_proof: StateProof,
    ) -> Result<Self, AnchorError> {
        let value = Self {
            finalized_record,
            checkpoint_bundle_id,
            checkpoint_height,
            checkpoint_block_id,
            checkpoint_state_root,
            checkpoint_object_count,
            anchor_state_proof,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), AnchorError> {
        let state_record = AnchorStateRecordV1::from_finalized_record(&self.finalized_record)?;
        let state_object = anchor_state_object(&state_record)?;
        if self.finalized_record.status() != AnchorStatus::Finalized
            || self.checkpoint_bundle_id == Digest384::ZERO
            || self.checkpoint_height == 0
            || self.checkpoint_block_id == Digest384::ZERO
            || self.checkpoint_state_root == Digest384::ZERO
            || self.checkpoint_object_count == 0
            || self.anchor_state_proof.kind() != StateProofKind::Membership
            || self.anchor_state_proof.object_id() != state_object.object_id()
        {
            return Err(AnchorError::InvalidFinalizedEvidence);
        }
        Ok(())
    }
}

impl CanonicalEncode for CheckpointedAnchorEvidenceV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.finalized_record.encode(encoder)?;
        self.checkpoint_bundle_id.encode(encoder)?;
        self.checkpoint_height.encode(encoder)?;
        self.checkpoint_block_id.encode(encoder)?;
        self.checkpoint_state_root.encode(encoder)?;
        self.checkpoint_object_count.encode(encoder)?;
        self.anchor_state_proof.encode(encoder)
    }
}

impl CanonicalDecode for CheckpointedAnchorEvidenceV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AnchorRecord::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            StateProof::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid checkpointed anchor evidence"))
    }
}

impl CanonicalType for CheckpointedAnchorEvidenceV1 {
    const TYPE_TAG: u16 = 0x01C3;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = AnchorRecord::MAX_ENCODED_LEN
        + 48
        + 8
        + 48
        + 48
        + 8
        + StateProof::MAX_ENCODED_LEN;
}

pub fn verify_checkpointed_anchor(
    evidence: &CheckpointedAnchorEvidenceV1,
    expected_statement: &DigestAnchorStatementV1,
    accepted_bundle: &SignedActumVerifierTrustBundleV1,
) -> Result<(), AnchorError> {
    evidence.validate()?;
    accepted_bundle
        .validate()
        .map_err(|_| AnchorError::InvalidFinalizedEvidence)?;
    let body = &accepted_bundle.body;
    let finalized = evidence
        .finalized_record
        .evidence()
        .ok_or(AnchorError::InvalidFinalizedEvidence)?;
    if evidence.finalized_record.statement() != expected_statement
        || finalized.statement() != expected_statement
        || finalized.chain() != ChainId::new(body.chain_id)
        || finalized.genesis() != body.genesis_commitment
        || evidence.checkpoint_bundle_id != accepted_bundle.bundle_id
        || evidence.checkpoint_height != body.checkpoint_height
        || evidence.checkpoint_block_id != body.checkpoint_block_id
        || evidence.checkpoint_state_root != body.checkpoint_state_root
        || finalized.finalized_height() > body.checkpoint_height
    {
        return Err(AnchorError::InvalidFinalizedEvidence);
    }
    let state_record = AnchorStateRecordV1::from_finalized_record(&evidence.finalized_record)?;
    let state_object = anchor_state_object(&state_record)?;
    verify_membership(
        StateCommitment::new(body.checkpoint_state_root, evidence.checkpoint_object_count),
        &state_object,
        &evidence.anchor_state_proof,
    )
    .map_err(|_| AnchorError::InvalidFinalizedEvidence)?;
    Ok(())
}
