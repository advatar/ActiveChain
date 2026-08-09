use crate::{ActivityEpochV1, AnchorError, DigestAnchorStatementV1};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    encode_envelope,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::Digest384;
use alloc::vec::Vec;
use sha2::{Digest as _, Sha256};

pub const TELEMETRY_EPOCH_ANCHOR_DOMAIN: &[u8] = b"actum.developer-telemetry.epoch.v1";
pub const MAX_ANCHOR_CLIENT_REQUEST_ID: usize = 128;

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
    use activechain_canonical_codec::{decode_envelope, encode_envelope};

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
}
