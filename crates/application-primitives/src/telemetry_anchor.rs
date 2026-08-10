use crate::{
    ActivityEpochV1, AnchorError, AnchorRecord, AnchorStateRecordV1, AnchorStatus,
    DigestAnchorStatementV1, SignedActumVerifierTrustBundleV1, anchor_state_object,
};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    encode_envelope,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::Digest384;
use activechain_state_tree::{StateCommitment, StateProof, StateProofKind, verify_membership};
use alloc::vec::Vec;
use sha2::{Digest as _, Sha256};

pub const TELEMETRY_EPOCH_ANCHOR_DOMAIN: &[u8] = b"actum.developer-telemetry.epoch.v1";
pub const MAX_ANCHOR_CLIENT_REQUEST_ID: usize = 128;
pub const MAX_CHECKPOINT_MEMBERSHIP_PROOF_LENGTH: usize = StateProof::MAX_ENCODED_LEN;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryEpochAnchorRequestV1 {
    pub chain_id: Digest384,
    pub genesis_commitment: Digest384,
    pub telemetry_schema_revision: u16,
    pub submitter_id: Digest384,
    pub client_request_id: Vec<u8>,
    pub epoch: ActivityEpochV1,
}

impl TelemetryEpochAnchorRequestV1 {
    pub fn new(
        chain_id: Digest384,
        genesis_commitment: Digest384,
        telemetry_schema_revision: u16,
        submitter_id: Digest384,
        client_request_id: Vec<u8>,
        epoch: ActivityEpochV1,
    ) -> Result<Self, AnchorError> {
        if chain_id == Digest384::ZERO
            || genesis_commitment == Digest384::ZERO
            || telemetry_schema_revision == 0
            || submitter_id == Digest384::ZERO
            || client_request_id.is_empty()
            || client_request_id.len() > MAX_ANCHOR_CLIENT_REQUEST_ID
            || client_request_id.iter().any(|byte| {
                !matches!(*byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'-')
            })
            || epoch.validate().is_err()
        {
            return Err(AnchorError::InvalidStatement);
        }
        Ok(Self {
            chain_id,
            genesis_commitment,
            telemetry_schema_revision,
            submitter_id,
            client_request_id,
            epoch,
        })
    }

    pub fn statement(&self) -> Result<DigestAnchorStatementV1, AnchorError> {
        telemetry_epoch_anchor_statement(&self.epoch)
    }

    pub fn request_commitment(&self) -> Result<Digest384, AnchorError> {
        commit(DomainTag::CANONICAL_VALUE, self).map_err(|_| AnchorError::Encoding)
    }
}

impl CanonicalEncode for TelemetryEpochAnchorRequestV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(encoder)?;
        self.genesis_commitment.encode(encoder)?;
        self.telemetry_schema_revision.encode(encoder)?;
        self.submitter_id.encode(encoder)?;
        encoder.write_bytes(&self.client_request_id, MAX_ANCHOR_CLIENT_REQUEST_ID)?;
        self.epoch.encode(encoder)
    }
}

impl CanonicalDecode for TelemetryEpochAnchorRequestV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u16::decode(decoder)?,
            Digest384::decode(decoder)?,
            decoder.read_bytes(MAX_ANCHOR_CLIENT_REQUEST_ID)?.to_vec(),
            ActivityEpochV1::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid telemetry epoch anchor request"))
    }
}

impl CanonicalType for TelemetryEpochAnchorRequestV1 {
    const TYPE_TAG: u16 = 0x01B4;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        48 * 3 + 2 + 2 + MAX_ANCHOR_CLIENT_REQUEST_ID + ActivityEpochV1::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointedTelemetryAnchorEvidenceV1 {
    pub request: TelemetryEpochAnchorRequestV1,
    pub anchor_reference: Digest384,
    pub finalized_record: AnchorRecord,
    pub checkpoint_bundle_id: Digest384,
    pub checkpoint_height: u64,
    pub checkpoint_block_id: Digest384,
    pub checkpoint_state_root: Digest384,
    pub checkpoint_object_count: u64,
    pub anchor_state_proof: StateProof,
}

impl CheckpointedTelemetryAnchorEvidenceV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: TelemetryEpochAnchorRequestV1,
        anchor_reference: Digest384,
        finalized_record: AnchorRecord,
        checkpoint_bundle_id: Digest384,
        checkpoint_height: u64,
        checkpoint_block_id: Digest384,
        checkpoint_state_root: Digest384,
        checkpoint_object_count: u64,
        anchor_state_proof: StateProof,
    ) -> Result<Self, AnchorError> {
        let value = Self {
            request,
            anchor_reference,
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
        let statement = self.request.statement()?;
        let evidence =
            self.finalized_record.evidence().ok_or(AnchorError::InvalidFinalizedEvidence)?;
        let state_record = AnchorStateRecordV1::from_finalized_record(&self.finalized_record)?;
        let state_object = anchor_state_object(&state_record)?;
        if self.anchor_reference != statement.submission_reference()?
            || self.finalized_record.status() != AnchorStatus::Finalized
            || self.finalized_record.statement() != &statement
            || evidence.statement() != &statement
            || evidence.chain() != activechain_protocol_types::ChainId::new(self.request.chain_id)
            || evidence.genesis() != self.request.genesis_commitment
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

impl CanonicalEncode for CheckpointedTelemetryAnchorEvidenceV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.request.encode(encoder)?;
        self.anchor_reference.encode(encoder)?;
        self.finalized_record.encode(encoder)?;
        self.checkpoint_bundle_id.encode(encoder)?;
        self.checkpoint_height.encode(encoder)?;
        self.checkpoint_block_id.encode(encoder)?;
        self.checkpoint_state_root.encode(encoder)?;
        self.checkpoint_object_count.encode(encoder)?;
        self.anchor_state_proof.encode(encoder)
    }
}

impl CanonicalDecode for CheckpointedTelemetryAnchorEvidenceV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            TelemetryEpochAnchorRequestV1::decode(decoder)?,
            Digest384::decode(decoder)?,
            AnchorRecord::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            StateProof::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid checkpointed telemetry anchor evidence"))
    }
}

impl CanonicalType for CheckpointedTelemetryAnchorEvidenceV1 {
    const TYPE_TAG: u16 = 0x01BA;
    const SCHEMA_VERSION: u16 = 2;
    const MAX_ENCODED_LEN: usize = TelemetryEpochAnchorRequestV1::MAX_ENCODED_LEN
        + 48
        + AnchorRecord::MAX_ENCODED_LEN
        + 48
        + 8
        + 48
        + 48
        + 8
        + StateProof::MAX_ENCODED_LEN;
}

pub fn verify_checkpointed_telemetry_anchor(
    evidence: &CheckpointedTelemetryAnchorEvidenceV1,
    expected_request: &TelemetryEpochAnchorRequestV1,
    accepted_bundle: &SignedActumVerifierTrustBundleV1,
) -> Result<(), AnchorError> {
    evidence.validate()?;
    accepted_bundle.validate().map_err(|_| AnchorError::InvalidFinalizedEvidence)?;
    let body = &accepted_bundle.body;
    if &evidence.request != expected_request
        || evidence.checkpoint_bundle_id != accepted_bundle.bundle_id
        || evidence.request.chain_id != body.chain_id
        || evidence.request.genesis_commitment != body.genesis_commitment
        || evidence.request.epoch.policy_id != body.policy_id
        || evidence.checkpoint_height != body.checkpoint_height
        || evidence.checkpoint_block_id != body.checkpoint_block_id
        || evidence.checkpoint_state_root != body.checkpoint_state_root
    {
        return Err(AnchorError::InvalidFinalizedEvidence);
    }
    let finalized =
        evidence.finalized_record.evidence().ok_or(AnchorError::InvalidFinalizedEvidence)?;
    if finalized.finalized_height() > body.checkpoint_height {
        return Err(AnchorError::CheckpointLag);
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

pub fn telemetry_epoch_anchor_statement(
    epoch: &ActivityEpochV1,
) -> Result<DigestAnchorStatementV1, AnchorError> {
    epoch.validate().map_err(|_| AnchorError::InvalidStatement)?;
    let envelope = encode_envelope(epoch).map_err(|_| AnchorError::Encoding)?;
    let digest: [u8; 32] = Sha256::digest(envelope).into();
    DigestAnchorStatementV1::new(TELEMETRY_EPOCH_ANCHOR_DOMAIN.to_vec(), digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActumVerifierTrustBundleV1, AnchorFinalizedEvidenceV1, AnchorRegistry,
        TrustBundleSignatureV1, TrustSignatureAlgorithmV1,
    };
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use activechain_protocol_types::{
        ChainId, Object, ObjectFlags, ObjectId, ObjectOwner, TransactionId,
    };
    use activechain_state_tree::{StateCommitment, commit_objects, prove_object};
    use alloc::vec;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn epoch() -> ActivityEpochV1 {
        ActivityEpochV1 {
            collector_id: digest(1),
            project_id: digest(2),
            first_collector_sequence: 1,
            last_collector_sequence: 2,
            first_project_sequence: 8,
            last_project_sequence: 9,
            event_count: 2,
            wall_start_ms: 100,
            wall_end_ms: 200,
            monotonic_start_ns: 1_000,
            monotonic_end_ns: 2_000,
            event_root: digest(3),
            previous_epoch_id: Digest384::ZERO,
            authorization_revision: 7,
            policy_id: digest(4),
        }
    }

    fn finalized_record(
        request: &TelemetryEpochAnchorRequestV1,
        transaction: TransactionId,
        height: u64,
        block: Digest384,
    ) -> (Digest384, AnchorRecord) {
        let statement = request.statement().unwrap();
        let mut registry = AnchorRegistry::default();
        let reference = registry.submit_action(statement.clone(), transaction).unwrap();
        registry
            .finalize(
                reference,
                AnchorFinalizedEvidenceV1::new(
                    ChainId::new(request.chain_id),
                    request.genesis_commitment,
                    transaction,
                    vec![7],
                    height,
                    block,
                    statement,
                    None,
                    None,
                    1,
                    1,
                    vec![1],
                    vec![2],
                )
                .unwrap(),
            )
            .unwrap();
        (reference, registry.resolve(reference).unwrap().clone())
    }

    fn state_witness(record: &AnchorRecord) -> (Object, StateCommitment, StateProof) {
        let state_record = AnchorStateRecordV1::from_finalized_record(record).unwrap();
        let object = anchor_state_object(&state_record).unwrap();
        let objects = vec![object.clone()];
        let commitment = commit_objects(&objects).unwrap();
        let proof = prove_object(&objects, object.object_id()).unwrap();
        (object, commitment, proof)
    }

    fn signed_bundle(
        request: &TelemetryEpochAnchorRequestV1,
        checkpoint_height: u64,
        checkpoint_block: Digest384,
        checkpoint: StateCommitment,
    ) -> SignedActumVerifierTrustBundleV1 {
        let signer_set_id = digest(30);
        let body = ActumVerifierTrustBundleV1 {
            schema_revision: 1,
            bundle_sequence: 1,
            previous_bundle_id: Digest384::ZERO,
            chain_id: request.chain_id,
            genesis_commitment: request.genesis_commitment,
            protocol_revision: 1,
            checkpoint_height,
            checkpoint_block_id: checkpoint_block,
            checkpoint_state_root: checkpoint.root(),
            checkpoint_finality_commitment: digest(31),
            validator_set_root: digest(32),
            proof_profile_id: digest(33),
            proof_system_revision: 1,
            verifier_revision: 1,
            risc0_image_id: [34; 32],
            policy_id: request.epoch.policy_id,
            policy_revision: 1,
            issued_at_ms: 100,
            not_before_ms: 100,
            not_after_ms: 1_000,
            signer_set_id,
            signer_set_revision: 1,
            signer_threshold: 1,
            next_signer_set_id: Digest384::ZERO,
            next_signer_set_revision: 0,
            next_signer_threshold: 0,
            next_signer_activation_sequence: 0,
        };
        let bundle_id = body.bundle_id().unwrap();
        SignedActumVerifierTrustBundleV1 {
            body,
            bundle_id,
            signatures: vec![TrustBundleSignatureV1 {
                signer_set_id,
                signer_id: digest(35),
                algorithm: TrustSignatureAlgorithmV1::MlDsa44,
                signature: vec![36; TrustBundleSignatureV1::MAX_ENCODED_LEN - 99],
            }],
        }
    }

    fn checkpointed_evidence(
        request: TelemetryEpochAnchorRequestV1,
        reference: Digest384,
        record: AnchorRecord,
        bundle: &SignedActumVerifierTrustBundleV1,
        commitment: StateCommitment,
        proof: StateProof,
    ) -> CheckpointedTelemetryAnchorEvidenceV1 {
        CheckpointedTelemetryAnchorEvidenceV1::new(
            request,
            reference,
            record,
            bundle.bundle_id,
            bundle.body.checkpoint_height,
            bundle.body.checkpoint_block_id,
            bundle.body.checkpoint_state_root,
            commitment.object_count(),
            proof,
        )
        .unwrap()
    }

    #[test]
    fn request_round_trips_and_statement_hashes_exact_epoch_envelope() {
        let request = TelemetryEpochAnchorRequestV1::new(
            digest(5),
            digest(6),
            1,
            digest(7),
            b"anchor-request-1".to_vec(),
            epoch(),
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<TelemetryEpochAnchorRequestV1>(&encode_envelope(&request).unwrap()),
            Ok(request.clone())
        );
        let expected: [u8; 32] = Sha256::digest(encode_envelope(&request.epoch).unwrap()).into();
        assert_eq!(
            request.statement().unwrap().application_domain(),
            TELEMETRY_EPOCH_ANCHOR_DOMAIN
        );
        assert_eq!(*request.statement().unwrap().digest(), expected);
    }

    #[test]
    fn substitutions_change_request_and_epoch_statement_commitments() {
        let request = TelemetryEpochAnchorRequestV1::new(
            digest(5),
            digest(6),
            1,
            digest(7),
            b"anchor-request-1".to_vec(),
            epoch(),
        )
        .unwrap();
        let mut network_substitution = request.clone();
        network_substitution.genesis_commitment = digest(9);
        assert_ne!(
            request.request_commitment().unwrap(),
            network_substitution.request_commitment().unwrap()
        );
        assert_eq!(request.statement().unwrap(), network_substitution.statement().unwrap());
        let mut epoch_substitution = request.clone();
        epoch_substitution.epoch.policy_id = digest(9);
        assert_ne!(request.statement().unwrap(), epoch_substitution.statement().unwrap());
    }

    #[test]
    fn malformed_request_ids_fail_closed() {
        assert!(
            TelemetryEpochAnchorRequestV1::new(
                digest(5),
                digest(6),
                1,
                digest(7),
                b"contains space".to_vec(),
                epoch(),
            )
            .is_err()
        );
    }

    #[test]
    fn checkpointed_state_proof_accepts_earlier_and_same_block_anchors() {
        let request = TelemetryEpochAnchorRequestV1::new(
            digest(5),
            digest(6),
            1,
            digest(7),
            b"anchor-request-1".to_vec(),
            epoch(),
        )
        .unwrap();
        let transaction = TransactionId::new(digest(8));
        let anchor_block = digest(9);
        let (reference, record) = finalized_record(&request, transaction, 10, anchor_block);
        let (object, commitment, proof) = state_witness(&record);
        assert_eq!(object.owner(), ObjectOwner::Immutable);
        assert_eq!(object.flags(), ObjectFlags::SYSTEM);
        let later_bundle = signed_bundle(&request, 12, digest(12), commitment);
        let evidence = checkpointed_evidence(
            request.clone(),
            reference,
            record.clone(),
            &later_bundle,
            commitment,
            proof.clone(),
        );
        assert_eq!(
            verify_checkpointed_telemetry_anchor(&evidence, &request, &later_bundle),
            Ok(())
        );
        assert_eq!(
            decode_envelope::<CheckpointedTelemetryAnchorEvidenceV1>(
                &encode_envelope(&evidence).unwrap()
            ),
            Ok(evidence)
        );
        let same_block_bundle = signed_bundle(&request, 10, anchor_block, commitment);
        let same_block = checkpointed_evidence(
            request.clone(),
            reference,
            record,
            &same_block_bundle,
            commitment,
            proof,
        );
        assert_eq!(
            verify_checkpointed_telemetry_anchor(&same_block, &request, &same_block_bundle),
            Ok(())
        );
    }

    #[test]
    fn checkpointed_state_proof_rejects_substitution_and_reports_lag() {
        let request = TelemetryEpochAnchorRequestV1::new(
            digest(5),
            digest(6),
            1,
            digest(7),
            b"anchor-request-1".to_vec(),
            epoch(),
        )
        .unwrap();
        let transaction = TransactionId::new(digest(8));
        let (reference, record) = finalized_record(&request, transaction, 10, digest(9));
        let (object, commitment, proof) = state_witness(&record);
        let bundle = signed_bundle(&request, 12, digest(12), commitment);
        let evidence = checkpointed_evidence(
            request.clone(),
            reference,
            record.clone(),
            &bundle,
            commitment,
            proof.clone(),
        );

        let mut wrong_anchor = evidence.clone();
        wrong_anchor.anchor_reference = digest(90);
        assert_eq!(
            verify_checkpointed_telemetry_anchor(&wrong_anchor, &request, &bundle),
            Err(AnchorError::InvalidFinalizedEvidence)
        );

        let mut wrong_checkpoint = evidence.clone();
        wrong_checkpoint.checkpoint_block_id = digest(91);
        assert_eq!(
            verify_checkpointed_telemetry_anchor(&wrong_checkpoint, &request, &bundle),
            Err(AnchorError::InvalidFinalizedEvidence)
        );

        let mut unrelated_fields = object.to_fields();
        unrelated_fields.object_id = ObjectId::new(digest(92));
        let unrelated = Object::new(unrelated_fields).unwrap();
        let mut expanded = vec![object, unrelated.clone()];
        expanded.sort_by_key(Object::object_id);
        let expanded_commitment = commit_objects(&expanded).unwrap();
        let expanded_bundle = signed_bundle(&request, 12, digest(12), expanded_commitment);

        let stale = checkpointed_evidence(
            request.clone(),
            reference,
            record.clone(),
            &expanded_bundle,
            expanded_commitment,
            proof,
        );
        assert_eq!(
            verify_checkpointed_telemetry_anchor(&stale, &request, &expanded_bundle),
            Err(AnchorError::InvalidFinalizedEvidence)
        );

        let mut wrong_key = evidence.clone();
        wrong_key.anchor_state_proof = prove_object(&expanded, unrelated.object_id()).unwrap();
        assert_eq!(
            verify_checkpointed_telemetry_anchor(&wrong_key, &request, &bundle),
            Err(AnchorError::InvalidFinalizedEvidence)
        );

        let (_, substituted_record) = finalized_record(&request, transaction, 10, digest(93));
        let wrong_value = checkpointed_evidence(
            request.clone(),
            reference,
            substituted_record,
            &bundle,
            commitment,
            evidence.anchor_state_proof.clone(),
        );
        assert_eq!(
            verify_checkpointed_telemetry_anchor(&wrong_value, &request, &bundle),
            Err(AnchorError::InvalidFinalizedEvidence)
        );

        let (_, newer_record) = finalized_record(&request, transaction, 13, digest(94));
        let (_, newer_commitment, newer_proof) = state_witness(&newer_record);
        let lagging_bundle = signed_bundle(&request, 12, digest(12), newer_commitment);
        let newer = checkpointed_evidence(
            request.clone(),
            reference,
            newer_record,
            &lagging_bundle,
            newer_commitment,
            newer_proof,
        );
        assert_eq!(
            verify_checkpointed_telemetry_anchor(&newer, &request, &lagging_bundle),
            Err(AnchorError::CheckpointLag)
        );
    }
}
