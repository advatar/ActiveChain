#![no_std]
#![forbid(unsafe_code)]

//! Canonical bounded wire values shared by ActiveChain RPC servers, clients, and light clients.

extern crate alloc;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{
    ChainId, CryptoSuiteId, Digest384, ProtocolSignature, TransactionId,
};
use alloc::{boxed::Box, vec::Vec};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const RPC_SCHEMA_REVISION: u32 = 1;
pub const MAX_RPC_BLOB_LENGTH: usize = 256 * 1024;
pub const MAX_RPC_PAGE_SIZE: u16 = 4;
pub const MAX_SUPPORTED_PROOFS: usize = 8;
pub const MAX_ACTIONS_PER_PROOF: usize = 32;
pub const ML_DSA_44_PUBLIC_KEY_LENGTH: usize = 1_312;

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
    ApplicationReceipt = 3,
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
            3 => Ok(Self::ApplicationReceipt),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RpcAccessMode {
    Free = 0,
    Allowlist = 1,
    Prepaid = 2,
}
impl CanonicalEncode for RpcAccessMode {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for RpcAccessMode {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Free),
            1 => Ok(Self::Allowlist),
            2 => Ok(Self::Prepaid),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "RpcAccessMode", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcAccessTerms {
    chain_id: ChainId,
    operator_id: Digest384,
    mode: RpcAccessMode,
    operator_public_key: Vec<u8>,
    unit_price: u128,
    settlement_asset: Digest384,
    settlement_recipient: Digest384,
    get_units: u64,
    list_base_units: u64,
    list_item_units: u64,
    quote_valid_until: u64,
    maximum_grant_lifetime: u64,
    operator_signature: Option<ProtocolSignature>,
}
impl RpcAccessTerms {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        operator_id: Digest384,
        mode: RpcAccessMode,
        operator_public_key: Vec<u8>,
        unit_price: u128,
        settlement_asset: Digest384,
        settlement_recipient: Digest384,
        get_units: u64,
        list_base_units: u64,
        list_item_units: u64,
        quote_valid_until: u64,
        maximum_grant_lifetime: u64,
        operator_signature: Option<ProtocolSignature>,
    ) -> Result<Self, DecodeError> {
        let free = mode == RpcAccessMode::Free;
        if operator_id == Digest384::ZERO
            || quote_valid_until == 0
            || maximum_grant_lifetime == 0
            || get_units == 0
            || list_base_units == 0
            || list_item_units == 0
            || (free && (!operator_public_key.is_empty() || unit_price != 0))
            || (free && operator_signature.is_some())
            || (!free && operator_public_key.len() != ML_DSA_44_PUBLIC_KEY_LENGTH)
            || operator_signature
                .as_ref()
                .is_some_and(|signature| signature.suite() != CryptoSuiteId::ML_DSA_44)
            || (mode == RpcAccessMode::Allowlist && unit_price != 0)
            || (mode == RpcAccessMode::Prepaid
                && (unit_price == 0
                    || settlement_asset == Digest384::ZERO
                    || settlement_recipient == Digest384::ZERO))
        {
            return Err(DecodeError::InvalidValue("invalid RPC access terms"));
        }
        Ok(Self {
            chain_id,
            operator_id,
            mode,
            operator_public_key,
            unit_price,
            settlement_asset,
            settlement_recipient,
            get_units,
            list_base_units,
            list_item_units,
            quote_valid_until,
            maximum_grant_lifetime,
            operator_signature,
        })
    }
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn operator_id(&self) -> Digest384 {
        self.operator_id
    }
    pub const fn mode(&self) -> RpcAccessMode {
        self.mode
    }
    pub fn operator_public_key(&self) -> &[u8] {
        &self.operator_public_key
    }
    pub const fn unit_price(&self) -> u128 {
        self.unit_price
    }
    pub const fn quote_valid_until(&self) -> u64 {
        self.quote_valid_until
    }
    pub const fn maximum_grant_lifetime(&self) -> u64 {
        self.maximum_grant_lifetime
    }
    pub fn operator_signature(&self) -> Option<&ProtocolSignature> {
        self.operator_signature.as_ref()
    }
    pub const fn settlement_asset(&self) -> Digest384 {
        self.settlement_asset
    }
    pub const fn settlement_recipient(&self) -> Digest384 {
        self.settlement_recipient
    }
    pub const fn get_units(&self) -> u64 {
        self.get_units
    }
    pub const fn list_base_units(&self) -> u64 {
        self.list_base_units
    }
    pub const fn list_item_units(&self) -> u64 {
        self.list_item_units
    }
    pub fn with_operator_signature(
        mut self,
        signature: ProtocolSignature,
    ) -> Result<Self, DecodeError> {
        if self.mode == RpcAccessMode::Free
            || signature.suite() != CryptoSuiteId::ML_DSA_44
            || self.operator_signature.is_some()
        {
            return Err(DecodeError::InvalidValue("invalid RPC terms signature"));
        }
        self.operator_signature = Some(signature);
        Ok(self)
    }
    pub fn cost(&self, request: &RpcRequest) -> Option<u64> {
        match request {
            RpcRequest::Status => Some(0),
            RpcRequest::Get { .. } => Some(self.get_units),
            RpcRequest::List { limit, .. } => self
                .list_item_units
                .checked_mul(*limit as u64)
                .and_then(|items| self.list_base_units.checked_add(items)),
        }
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let mut encoder = Encoder::new(Self::MAX_ENCODED_LEN);
        self.encode(&mut encoder)?;
        Ok(domain_commitment(b"ACTIVECHAIN-RPC-ACCESS-TERMS-V1", &encoder.finish()))
    }
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Self::MAX_ENCODED_LEN);
        self.encode_unsigned(&mut encoder).expect("validated RPC terms encode");
        let bytes = encoder.finish();
        let mut payload = Vec::with_capacity(35 + bytes.len());
        payload.extend_from_slice(b"ACTIVECHAIN-RPC-ACCESS-TERMS-V1");
        payload.extend_from_slice(&bytes);
        payload
    }
    fn encode_unsigned(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(encoder)?;
        self.operator_id.encode(encoder)?;
        self.mode.encode(encoder)?;
        encoder.write_bytes(&self.operator_public_key, ML_DSA_44_PUBLIC_KEY_LENGTH)?;
        self.unit_price.encode(encoder)?;
        self.settlement_asset.encode(encoder)?;
        self.settlement_recipient.encode(encoder)?;
        self.get_units.encode(encoder)?;
        self.list_base_units.encode(encoder)?;
        self.list_item_units.encode(encoder)?;
        self.quote_valid_until.encode(encoder)?;
        self.maximum_grant_lifetime.encode(encoder)
    }
}
impl CanonicalEncode for RpcAccessTerms {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.encode_unsigned(encoder)?;
        self.operator_signature.encode(encoder)
    }
}
impl CanonicalDecode for RpcAccessTerms {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self::new(
            ChainId::decode(decoder)?,
            Digest384::decode(decoder)?,
            RpcAccessMode::decode(decoder)?,
            decoder.read_bytes(ML_DSA_44_PUBLIC_KEY_LENGTH)?.to_vec(),
            u128::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            Option::<ProtocolSignature>::decode(decoder)?,
        )?;
        if value.mode != RpcAccessMode::Free && value.operator_signature.is_none() {
            return Err(DecodeError::InvalidValue("unsigned non-free RPC access terms"));
        }
        Ok(value)
    }
}
impl CanonicalType for RpcAccessTerms {
    const TYPE_TAG: u16 = 0x00ba;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 4
        + 1
        + 2
        + ML_DSA_44_PUBLIC_KEY_LENGTH
        + 16
        + 8 * 5
        + 1
        + ProtocolSignature::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcAccessGrant {
    terms: RpcAccessTerms,
    grant_id: Digest384,
    client_public_key: Vec<u8>,
    valid_from: u64,
    valid_until: u64,
    purchased_units: u64,
    paid_amount: u128,
    settlement_reference: Digest384,
    operator_signature: ProtocolSignature,
}
impl RpcAccessGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        terms: RpcAccessTerms,
        grant_id: Digest384,
        client_public_key: Vec<u8>,
        valid_from: u64,
        valid_until: u64,
        purchased_units: u64,
        paid_amount: u128,
        settlement_reference: Digest384,
        operator_signature: ProtocolSignature,
    ) -> Result<Self, DecodeError> {
        if terms.mode() == RpcAccessMode::Free
            || grant_id == Digest384::ZERO
            || client_public_key.len() != ML_DSA_44_PUBLIC_KEY_LENGTH
            || valid_from > valid_until
            || purchased_units == 0
            || settlement_reference == Digest384::ZERO
            || operator_signature.suite() != CryptoSuiteId::ML_DSA_44
        {
            return Err(DecodeError::InvalidValue("invalid RPC access grant"));
        }
        Ok(Self {
            terms,
            grant_id,
            client_public_key,
            valid_from,
            valid_until,
            purchased_units,
            paid_amount,
            settlement_reference,
            operator_signature,
        })
    }
    pub const fn terms(&self) -> &RpcAccessTerms {
        &self.terms
    }
    pub const fn chain_id(&self) -> ChainId {
        self.terms.chain_id
    }
    pub const fn operator_id(&self) -> Digest384 {
        self.terms.operator_id
    }
    pub fn terms_commitment(&self) -> Result<Digest384, EncodeError> {
        self.terms.commitment()
    }
    pub const fn grant_id(&self) -> Digest384 {
        self.grant_id
    }
    pub fn client_public_key(&self) -> &[u8] {
        &self.client_public_key
    }
    pub const fn valid_from(&self) -> u64 {
        self.valid_from
    }
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }
    pub const fn purchased_units(&self) -> u64 {
        self.purchased_units
    }
    pub const fn paid_amount(&self) -> u128 {
        self.paid_amount
    }
    pub const fn settlement_reference(&self) -> Digest384 {
        self.settlement_reference
    }
    pub fn operator_signature(&self) -> &ProtocolSignature {
        &self.operator_signature
    }
    #[allow(clippy::too_many_arguments)]
    pub fn signing_payload_for(
        terms: RpcAccessTerms,
        grant_id: Digest384,
        client_public_key: Vec<u8>,
        valid_from: u64,
        valid_until: u64,
        purchased_units: u64,
        paid_amount: u128,
        settlement_reference: Digest384,
    ) -> Result<Vec<u8>, DecodeError> {
        let placeholder =
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, alloc::vec![0; 2_420])
                .map_err(|_| DecodeError::InvalidValue("could not construct grant draft"))?;
        Self::new(
            terms,
            grant_id,
            client_public_key,
            valid_from,
            valid_until,
            purchased_units,
            paid_amount,
            settlement_reference,
            placeholder,
        )
        .map(|grant| grant.signing_payload())
    }
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Self::MAX_ENCODED_LEN);
        self.terms
            .commitment()
            .expect("validated terms encode")
            .encode(&mut encoder)
            .expect("fixed field encodes");
        self.grant_id.encode(&mut encoder).expect("fixed field encodes");
        encoder
            .write_bytes(&self.client_public_key, ML_DSA_44_PUBLIC_KEY_LENGTH)
            .expect("validated key encodes");
        self.valid_from.encode(&mut encoder).expect("fixed field encodes");
        self.valid_until.encode(&mut encoder).expect("fixed field encodes");
        self.purchased_units.encode(&mut encoder).expect("fixed field encodes");
        self.paid_amount.encode(&mut encoder).expect("fixed field encodes");
        self.settlement_reference.encode(&mut encoder).expect("fixed field encodes");
        let bytes = encoder.finish();
        let mut payload = Vec::with_capacity(37 + bytes.len());
        payload.extend_from_slice(b"ACTIVECHAIN-RPC-ACCESS-GRANT-V1");
        payload.extend_from_slice(&bytes);
        payload
    }
}
impl CanonicalEncode for RpcAccessGrant {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.terms.encode(encoder)?;
        self.grant_id.encode(encoder)?;
        encoder.write_bytes(&self.client_public_key, ML_DSA_44_PUBLIC_KEY_LENGTH)?;
        self.valid_from.encode(encoder)?;
        self.valid_until.encode(encoder)?;
        self.purchased_units.encode(encoder)?;
        self.paid_amount.encode(encoder)?;
        self.settlement_reference.encode(encoder)?;
        self.operator_signature.encode(encoder)
    }
}
impl CanonicalDecode for RpcAccessGrant {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            RpcAccessTerms::decode(decoder)?,
            Digest384::decode(decoder)?,
            decoder.read_bytes(ML_DSA_44_PUBLIC_KEY_LENGTH)?.to_vec(),
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u128::decode(decoder)?,
            Digest384::decode(decoder)?,
            ProtocolSignature::decode(decoder)?,
        )
    }
}
impl CanonicalType for RpcAccessGrant {
    const TYPE_TAG: u16 = 0x00bb;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = RpcAccessTerms::MAX_ENCODED_LEN
        + 48 * 2
        + 2
        + ML_DSA_44_PUBLIC_KEY_LENGTH
        + 8 * 3
        + 16
        + ProtocolSignature::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcAccessAuthorization {
    grant: RpcAccessGrant,
    sequence: u64,
    request_commitment: Digest384,
    client_signature: ProtocolSignature,
}
impl RpcAccessAuthorization {
    pub fn new(
        grant: RpcAccessGrant,
        sequence: u64,
        request_commitment: Digest384,
        client_signature: ProtocolSignature,
    ) -> Result<Self, DecodeError> {
        if request_commitment == Digest384::ZERO
            || client_signature.suite() != CryptoSuiteId::ML_DSA_44
        {
            return Err(DecodeError::InvalidValue("invalid RPC access authorization"));
        }
        Ok(Self { grant, sequence, request_commitment, client_signature })
    }
    pub const fn grant(&self) -> &RpcAccessGrant {
        &self.grant
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn request_commitment(&self) -> Digest384 {
        self.request_commitment
    }
    pub fn client_signature(&self) -> &ProtocolSignature {
        &self.client_signature
    }
    pub fn signing_payload(&self) -> Vec<u8> {
        Self::signing_payload_for(self.grant.grant_id(), self.sequence, self.request_commitment)
    }
    pub fn signing_payload_for(
        grant_id: Digest384,
        sequence: u64,
        request_commitment: Digest384,
    ) -> Vec<u8> {
        let mut payload = Vec::with_capacity(92);
        payload.extend_from_slice(b"ACTIVECHAIN-RPC-ACCESS-REQUEST-V1");
        payload.extend_from_slice(grant_id.as_bytes());
        payload.extend_from_slice(&sequence.to_be_bytes());
        payload.extend_from_slice(request_commitment.as_bytes());
        payload
    }
}
impl CanonicalEncode for RpcAccessAuthorization {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.grant.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.request_commitment.encode(encoder)?;
        self.client_signature.encode(encoder)
    }
}
impl CanonicalDecode for RpcAccessAuthorization {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            RpcAccessGrant::decode(decoder)?,
            u64::decode(decoder)?,
            Digest384::decode(decoder)?,
            ProtocolSignature::decode(decoder)?,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcAccessRequest {
    Terms,
    Execute { request: RpcRequest, authorization: Option<Box<RpcAccessAuthorization>> },
}
impl RpcAccessRequest {
    pub fn request_commitment(request: &RpcRequest) -> Result<Digest384, EncodeError> {
        let mut encoder = Encoder::new(RpcRequest::MAX_ENCODED_LEN);
        request.encode(&mut encoder)?;
        Ok(domain_commitment(b"ACTIVECHAIN-RPC-ACCESS-REQUEST-COMMITMENT-V1", &encoder.finish()))
    }
}
impl CanonicalEncode for RpcAccessRequest {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Terms => 0_u8.encode(encoder),
            Self::Execute { request, authorization } => {
                1_u8.encode(encoder)?;
                request.encode(encoder)?;
                if let Some(authorization) = authorization {
                    1_u8.encode(encoder)?;
                    authorization.as_ref().encode(encoder)
                } else {
                    0_u8.encode(encoder)
                }
            }
        }
    }
}
impl CanonicalDecode for RpcAccessRequest {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Terms),
            1 => {
                let request = RpcRequest::decode(decoder)?;
                let authorization = match u8::decode(decoder)? {
                    0 => None,
                    1 => Some(Box::new(RpcAccessAuthorization::decode(decoder)?)),
                    tag => {
                        return Err(DecodeError::InvalidEnumTag {
                            type_name: "RpcAccessAuthorizationOption",
                            tag,
                        });
                    }
                };
                Ok(Self::Execute { request, authorization })
            }
            tag => Err(DecodeError::InvalidEnumTag { type_name: "RpcAccessRequest", tag }),
        }
    }
}
impl CanonicalType for RpcAccessRequest {
    const TYPE_TAG: u16 = 0x00bc;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 2
        + RpcRequest::MAX_ENCODED_LEN
        + RpcAccessGrant::MAX_ENCODED_LEN
        + 8
        + 48
        + ProtocolSignature::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RpcAccessError {
    AuthorizationRequired = 0,
    InvalidGrant = 1,
    Expired = 2,
    Replay = 3,
    BudgetExhausted = 4,
    Persistence = 5,
}
impl CanonicalEncode for RpcAccessError {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for RpcAccessError {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::AuthorizationRequired),
            1 => Ok(Self::InvalidGrant),
            2 => Ok(Self::Expired),
            3 => Ok(Self::Replay),
            4 => Ok(Self::BudgetExhausted),
            5 => Ok(Self::Persistence),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "RpcAccessError", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcAccessResponse {
    Terms(RpcAccessTerms),
    Response { response: RpcResponse, charged_units: u64, remaining_units: Option<u64> },
    Denied(RpcAccessError),
}
impl CanonicalEncode for RpcAccessResponse {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Terms(terms) => {
                0_u8.encode(encoder)?;
                terms.encode(encoder)
            }
            Self::Response { response, charged_units, remaining_units } => {
                1_u8.encode(encoder)?;
                response.encode(encoder)?;
                charged_units.encode(encoder)?;
                remaining_units.encode(encoder)
            }
            Self::Denied(error) => {
                2_u8.encode(encoder)?;
                error.encode(encoder)
            }
        }
    }
}
impl CanonicalDecode for RpcAccessResponse {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Terms(RpcAccessTerms::decode(decoder)?)),
            1 => Ok(Self::Response {
                response: RpcResponse::decode(decoder)?,
                charged_units: u64::decode(decoder)?,
                remaining_units: Option::<u64>::decode(decoder)?,
            }),
            2 => Ok(Self::Denied(RpcAccessError::decode(decoder)?)),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "RpcAccessResponse", tag }),
        }
    }
}
impl CanonicalType for RpcAccessResponse {
    const TYPE_TAG: u16 = 0x00bd;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        1 + RpcAccessTerms::MAX_ENCODED_LEN + RpcResponse::MAX_ENCODED_LEN + 8 + 9;
}

fn domain_commitment(domain: &[u8], bytes: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(bytes);
    let mut output = [0; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
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

    #[test]
    fn access_contract_round_trips_and_rejects_inconsistent_economics() {
        let signature =
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, alloc::vec![7; 2_420]).unwrap();
        let terms = RpcAccessTerms::new(
            ChainId::new(digest(1)),
            digest(2),
            RpcAccessMode::Prepaid,
            alloc::vec![3; ML_DSA_44_PUBLIC_KEY_LENGTH],
            5,
            digest(4),
            digest(5),
            2,
            3,
            4,
            100,
            20,
            Some(signature.clone()),
        )
        .unwrap();
        let grant = RpcAccessGrant::new(
            terms,
            digest(6),
            alloc::vec![8; ML_DSA_44_PUBLIC_KEY_LENGTH],
            10,
            20,
            9,
            45,
            digest(7),
            signature.clone(),
        )
        .unwrap();
        let request = RpcRequest::Get { kind: QueryKind::State, key: digest(8) };
        let authorization = RpcAccessAuthorization::new(
            grant,
            0,
            RpcAccessRequest::request_commitment(&request).unwrap(),
            signature,
        )
        .unwrap();
        let wire =
            RpcAccessRequest::Execute { request, authorization: Some(Box::new(authorization)) };
        let encoded = encode_envelope(&wire).unwrap();
        assert_eq!(decode_envelope::<RpcAccessRequest>(&encoded), Ok(wire));

        assert!(
            RpcAccessTerms::new(
                ChainId::new(digest(1)),
                digest(2),
                RpcAccessMode::Prepaid,
                alloc::vec![3; ML_DSA_44_PUBLIC_KEY_LENGTH],
                0,
                digest(4),
                digest(5),
                1,
                1,
                1,
                100,
                20,
                Some(
                    ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, alloc::vec![7; 2_420],)
                        .unwrap()
                ),
            )
            .is_err()
        );
    }
}
