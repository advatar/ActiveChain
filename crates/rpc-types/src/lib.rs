#![no_std]
#![forbid(unsafe_code)]

//! Canonical bounded wire values shared by ActiveChain RPC servers, clients, and light clients.

extern crate alloc;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{ChainId, Digest384, TransactionId};
use alloc::vec::Vec;

pub const RPC_SCHEMA_REVISION: u32 = 1;
pub const MAX_RPC_BLOB_LENGTH: usize = 256 * 1024;
pub const MAX_RPC_PAGE_SIZE: u16 = 4;
pub const MAX_SUPPORTED_PROOFS: usize = 8;
pub const MAX_ACTIONS_PER_PROOF: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ProofKind {
    StateSparseMerkle = 0,
    FinalityCertificate = 1,
    ReceiptCommitment = 2,
    DataAvailability = 3,
}

impl CanonicalEncode for ProofKind {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for ProofKind {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::StateSparseMerkle),
            1 => Ok(Self::FinalityCertificate),
            2 => Ok(Self::ReceiptCommitment),
            3 => Ok(Self::DataAvailability),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ProofKind", tag }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Health {
    Healthy = 0,
    Stale = 1,
    Degraded = 2,
}

impl CanonicalEncode for Health {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for Health {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Healthy),
            1 => Ok(Self::Stale),
            2 => Ok(Self::Degraded),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "Health", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcStatus {
    chain_id: ChainId,
    genesis_commitment: Digest384,
    protocol_revision: u64,
    rpc_schema_revision: u32,
    finalized_height: u64,
    finalized_at_unix_seconds: u64,
    served_at_unix_seconds: u64,
    maximum_staleness_seconds: u64,
    health: Health,
    supported_proofs: Vec<ProofKind>,
}

impl RpcStatus {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        genesis_commitment: Digest384,
        protocol_revision: u64,
        finalized_height: u64,
        finalized_at_unix_seconds: u64,
        served_at_unix_seconds: u64,
        maximum_staleness_seconds: u64,
        supported_proofs: Vec<ProofKind>,
    ) -> Result<Self, DecodeError> {
        if genesis_commitment == Digest384::ZERO
            || protocol_revision == 0
            || maximum_staleness_seconds == 0
            || supported_proofs.is_empty()
            || supported_proofs.len() > MAX_SUPPORTED_PROOFS
            || supported_proofs.windows(2).any(|pair| pair[0] >= pair[1])
            || finalized_at_unix_seconds > served_at_unix_seconds
        {
            return Err(DecodeError::InvalidValue("invalid RPC status"));
        }
        let age = served_at_unix_seconds - finalized_at_unix_seconds;
        let health = if age > maximum_staleness_seconds { Health::Stale } else { Health::Healthy };
        Ok(Self {
            chain_id,
            genesis_commitment,
            protocol_revision,
            rpc_schema_revision: RPC_SCHEMA_REVISION,
            finalized_height,
            finalized_at_unix_seconds,
            served_at_unix_seconds,
            maximum_staleness_seconds,
            health,
            supported_proofs,
        })
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn genesis_commitment(&self) -> Digest384 {
        self.genesis_commitment
    }
    pub const fn protocol_revision(&self) -> u64 {
        self.protocol_revision
    }
    pub const fn rpc_schema_revision(&self) -> u32 {
        self.rpc_schema_revision
    }
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }
    pub const fn finalized_at_unix_seconds(&self) -> u64 {
        self.finalized_at_unix_seconds
    }
    pub const fn maximum_staleness_seconds(&self) -> u64 {
        self.maximum_staleness_seconds
    }
    pub const fn health(&self) -> Health {
        self.health
    }
    pub fn supported_proofs(&self) -> &[ProofKind] {
        &self.supported_proofs
    }
}

impl CanonicalEncode for RpcStatus {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(encoder)?;
        self.genesis_commitment.encode(encoder)?;
        self.protocol_revision.encode(encoder)?;
        self.rpc_schema_revision.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        self.finalized_at_unix_seconds.encode(encoder)?;
        self.served_at_unix_seconds.encode(encoder)?;
        self.maximum_staleness_seconds.encode(encoder)?;
        self.health.encode(encoder)?;
        encoder.write_length(self.supported_proofs.len(), MAX_SUPPORTED_PROOFS)?;
        for proof in &self.supported_proofs {
            proof.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for RpcStatus {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(decoder)?;
        let genesis = Digest384::decode(decoder)?;
        let protocol = u64::decode(decoder)?;
        let schema = u32::decode(decoder)?;
        let height = u64::decode(decoder)?;
        let finalized_at = u64::decode(decoder)?;
        let served_at = u64::decode(decoder)?;
        let maximum_staleness = u64::decode(decoder)?;
        let claimed_health = Health::decode(decoder)?;
        let count = decoder.read_length(MAX_SUPPORTED_PROOFS)?;
        let mut proofs = Vec::with_capacity(count);
        for _ in 0..count {
            proofs.push(ProofKind::decode(decoder)?);
        }
        if schema != RPC_SCHEMA_REVISION {
            return Err(DecodeError::UnsupportedSchemaVersion {
                expected: RPC_SCHEMA_REVISION as u16,
                actual: u16::try_from(schema).unwrap_or(u16::MAX),
            });
        }
        let value = Self::new(
            chain_id,
            genesis,
            protocol,
            height,
            finalized_at,
            served_at,
            maximum_staleness,
            proofs,
        )?;
        if value.health != claimed_health {
            return Err(DecodeError::InvalidValue("RPC health does not match staleness"));
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum QueryKind {
    State = 0,
    Action = 1,
    Receipt = 2,
}

impl CanonicalEncode for QueryKind {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for QueryKind {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::State),
            1 => Ok(Self::Action),
            2 => Ok(Self::Receipt),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "QueryKind", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcRequest {
    Status,
    Get { kind: QueryKind, key: Digest384 },
    List { kind: QueryKind, after: Option<Digest384>, limit: u16 },
}

impl CanonicalEncode for RpcRequest {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Status => 0_u8.encode(encoder),
            Self::Get { kind, key } => {
                1_u8.encode(encoder)?;
                kind.encode(encoder)?;
                key.encode(encoder)
            }
            Self::List { kind, after, limit } => {
                2_u8.encode(encoder)?;
                kind.encode(encoder)?;
                after.encode(encoder)?;
                limit.encode(encoder)
            }
        }
    }
}
impl CanonicalDecode for RpcRequest {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Status),
            1 => Ok(Self::Get {
                kind: QueryKind::decode(decoder)?,
                key: Digest384::decode(decoder)?,
            }),
            2 => {
                let kind = QueryKind::decode(decoder)?;
                let after = Option::<Digest384>::decode(decoder)?;
                let limit = u16::decode(decoder)?;
                if limit == 0 || limit > MAX_RPC_PAGE_SIZE {
                    return Err(DecodeError::InvalidValue("RPC page limit is out of bounds"));
                }
                Ok(Self::List { kind, after, limit })
            }
            tag => Err(DecodeError::InvalidEnumTag { type_name: "RpcRequest", tag }),
        }
    }
}
impl CanonicalType for RpcRequest {
    const TYPE_TAG: u16 = 0x00a0;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 1 + 1 + 49 + 2;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionSetProof {
    transaction_ids: Vec<TransactionId>,
}
impl ActionSetProof {
    pub const TYPE_TAG: u16 = 0x00a3;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 1 + MAX_ACTIONS_PER_PROOF * 48;

    pub fn new(transaction_ids: Vec<TransactionId>) -> Result<Self, DecodeError> {
        if transaction_ids.is_empty()
            || transaction_ids.len() > MAX_ACTIONS_PER_PROOF
            || transaction_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(DecodeError::InvalidValue(
                "action proof transaction IDs are not a bounded ordered set",
            ));
        }
        Ok(Self { transaction_ids })
    }
    pub fn transaction_ids(&self) -> &[TransactionId] {
        &self.transaction_ids
    }
}
impl CanonicalEncode for ActionSetProof {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.transaction_ids.len(), MAX_ACTIONS_PER_PROOF)?;
        for transaction_id in &self.transaction_ids {
            transaction_id.encode(encoder)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for ActionSetProof {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_ACTIONS_PER_PROOF)?;
        let mut transaction_ids = Vec::with_capacity(count);
        for _ in 0..count {
            transaction_ids.push(TransactionId::decode(decoder)?);
        }
        Self::new(transaction_ids)
    }
}
impl CanonicalType for ActionSetProof {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryRecord {
    kind: QueryKind,
    key: Digest384,
    finalized_height: u64,
    value: Vec<u8>,
    proof: Vec<u8>,
    finality: Vec<u8>,
}

impl QueryRecord {
    pub fn new(
        kind: QueryKind,
        key: Digest384,
        finalized_height: u64,
        value: Vec<u8>,
        proof: Vec<u8>,
        finality: Vec<u8>,
    ) -> Result<Self, DecodeError> {
        if key == Digest384::ZERO
            || value.is_empty()
            || (kind != QueryKind::Receipt && proof.is_empty())
            || finality.is_empty()
            || value.len() > MAX_RPC_BLOB_LENGTH
            || proof.len() > MAX_RPC_BLOB_LENGTH
            || finality.len() > MAX_RPC_BLOB_LENGTH
        {
            return Err(DecodeError::InvalidValue("invalid proof-bearing RPC record"));
        }
        Ok(Self { kind, key, finalized_height, value, proof, finality })
    }
    pub const fn kind(&self) -> QueryKind {
        self.kind
    }
    pub const fn key(&self) -> Digest384 {
        self.key
    }
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
    pub fn finality(&self) -> &[u8] {
        &self.finality
    }
}

impl CanonicalEncode for QueryRecord {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.kind.encode(encoder)?;
        self.key.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        encoder.write_bytes(&self.value, MAX_RPC_BLOB_LENGTH)?;
        encoder.write_bytes(&self.proof, MAX_RPC_BLOB_LENGTH)?;
        encoder.write_bytes(&self.finality, MAX_RPC_BLOB_LENGTH)
    }
}
impl CanonicalDecode for QueryRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            QueryKind::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            decoder.read_bytes(MAX_RPC_BLOB_LENGTH)?.to_vec(),
            decoder.read_bytes(MAX_RPC_BLOB_LENGTH)?.to_vec(),
            decoder.read_bytes(MAX_RPC_BLOB_LENGTH)?.to_vec(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryPage {
    records: Vec<QueryRecord>,
    next: Option<Digest384>,
}
impl QueryPage {
    pub fn new(records: Vec<QueryRecord>, next: Option<Digest384>) -> Result<Self, DecodeError> {
        if records.len() > MAX_RPC_PAGE_SIZE as usize
            || records.windows(2).any(|pair| pair[0].key >= pair[1].key)
            || next.is_some_and(|cursor| records.last().is_none_or(|record| cursor < record.key))
        {
            return Err(DecodeError::InvalidValue("invalid RPC page"));
        }
        Ok(Self { records, next })
    }
    pub fn records(&self) -> &[QueryRecord] {
        &self.records
    }
    pub const fn next(&self) -> Option<Digest384> {
        self.next
    }
}
impl CanonicalEncode for QueryPage {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.records.len(), MAX_RPC_PAGE_SIZE as usize)?;
        for record in &self.records {
            record.encode(encoder)?;
        }
        self.next.encode(encoder)
    }
}
impl CanonicalDecode for QueryPage {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_RPC_PAGE_SIZE as usize)?;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            records.push(QueryRecord::decode(decoder)?);
        }
        Self::new(records, Option::<Digest384>::decode(decoder)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RpcError {
    NotFound = 0,
    Stale = 1,
    UnsupportedProof = 2,
    InvalidRequest = 3,
    DeadlineExceeded = 4,
    Internal = 5,
}
impl CanonicalEncode for RpcError {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for RpcError {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::NotFound),
            1 => Ok(Self::Stale),
            2 => Ok(Self::UnsupportedProof),
            3 => Ok(Self::InvalidRequest),
            4 => Ok(Self::DeadlineExceeded),
            5 => Ok(Self::Internal),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "RpcError", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcResponse {
    Status(RpcStatus),
    Record(QueryRecord),
    Page(QueryPage),
    Error(RpcError),
}
impl CanonicalEncode for RpcResponse {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Status(status) => {
                0_u8.encode(encoder)?;
                status.encode(encoder)
            }
            Self::Record(record) => {
                1_u8.encode(encoder)?;
                record.encode(encoder)
            }
            Self::Page(page) => {
                2_u8.encode(encoder)?;
                page.encode(encoder)
            }
            Self::Error(error) => {
                3_u8.encode(encoder)?;
                error.encode(encoder)
            }
        }
    }
}
impl CanonicalDecode for RpcResponse {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Status(RpcStatus::decode(decoder)?)),
            1 => Ok(Self::Record(QueryRecord::decode(decoder)?)),
            2 => Ok(Self::Page(QueryPage::decode(decoder)?)),
            3 => Ok(Self::Error(RpcError::decode(decoder)?)),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "RpcResponse", tag }),
        }
    }
}
impl CanonicalType for RpcResponse {
    const TYPE_TAG: u16 = 0x00a1;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        1 + 2 + MAX_RPC_PAGE_SIZE as usize * (1 + 48 + 8 + 3 * (4 + MAX_RPC_BLOB_LENGTH)) + 49;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn status_derives_health_and_rejects_substitution() {
        let status = RpcStatus::new(
            ChainId::new(digest(1)),
            digest(2),
            3,
            4,
            100,
            105,
            10,
            alloc::vec![ProofKind::StateSparseMerkle, ProofKind::FinalityCertificate],
        )
        .unwrap();
        assert_eq!(status.health(), Health::Healthy);
        let encoded = {
            let mut encoder = Encoder::new(256);
            status.encode(&mut encoder).unwrap();
            encoder.finish()
        };
        let mut stale = encoded;
        let health = 48 + 48 + 8 + 4 + 8 + 8 + 8 + 8;
        stale[health] = Health::Stale as u8;
        let mut decoder = Decoder::new(&stale);
        assert!(RpcStatus::decode(&mut decoder).is_err());
    }

    #[test]
    fn requests_responses_pages_and_malformed_framing_are_bounded() {
        let request = RpcRequest::List {
            kind: QueryKind::Receipt,
            after: Some(digest(3)),
            limit: MAX_RPC_PAGE_SIZE,
        };
        let request_bytes = encode_envelope(&request).unwrap();
        assert_eq!(decode_envelope::<RpcRequest>(&request_bytes), Ok(request));

        let record = |byte| {
            QueryRecord::new(
                QueryKind::Receipt,
                digest(byte),
                9,
                alloc::vec![byte],
                alloc::vec![byte + 1],
                alloc::vec![byte + 2],
            )
            .unwrap()
        };
        let response = RpcResponse::Page(
            QueryPage::new(alloc::vec![record(4), record(5)], Some(digest(6))).unwrap(),
        );
        let encoded = encode_envelope(&response).unwrap();
        assert_eq!(decode_envelope::<RpcResponse>(&encoded), Ok(response));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_envelope::<RpcResponse>(&trailing).is_err());

        let invalid = RpcRequest::List { kind: QueryKind::State, after: None, limit: 0 };
        let bytes = encode_envelope(&invalid).unwrap();
        assert!(decode_envelope::<RpcRequest>(&bytes).is_err());
    }
}
