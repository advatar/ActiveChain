#![no_std]
#![forbid(unsafe_code)]

//! Canonical bounded wire values shared by ActiveChain RPC servers, clients, and light clients.

extern crate alloc;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    encode_envelope,
};
use activechain_protocol_types::{
    AssetId, ChainId, CryptoSuiteId, Digest384, PrincipalId, ProtocolSignature, TransactionId,
};
use alloc::{boxed::Box, vec::Vec};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

// Revision 3: faucet refusals are a typed FaucetRejected response rather than
// a generic InvalidRequest, so a client that does not understand it would
// misread every refusal.
pub const RPC_SCHEMA_REVISION: u32 = 4;
pub const MAX_RPC_BLOB_LENGTH: usize = 256 * 1024;

/// The largest transfer envelope the node will look at.
///
/// Checked before the signature is, because verification is the expensive step
/// and an unbounded submission must be refused before it is ever paid for. The
/// authoritative bound is the envelope's own `MAX_ENCODED_LEN`, enforced when
/// it decodes; this is the cheap gate in front of it.
///
/// Derived rather than picked: `AuthorizedCashTransferV1::MAX_ENCODED_LEN` is
/// 21,222 bytes, dominated by the ML-DSA-44 signatures over the transfer and
/// its session grant. This crate cannot name that constant — wallet-core
/// depends on this one, not the reverse — so the relationship is held by a
/// test in `rpc-server`, which sees both. Rounding to 24 KiB leaves room for a
/// schema revision to add a field without a wire change, and the guard test
/// fails if a revision ever outgrows it, rather than letting valid transfers
/// be refused as malformed.
pub const MAX_TRANSFER_ENVELOPE_LENGTH: usize = 24 * 1024;
pub const MAX_ANCHOR_ACTION_LENGTH: usize = 8 * 1024;
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

    /// Stable commitment to the network identity and wire contract advertised
    /// by this status response. Health and finalized height are deliberately
    /// excluded so the value remains stable across head advancement.
    pub fn identity_commitment(&self) -> Digest384 {
        let mut hasher = sha3::Shake256::default();
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        hasher.update(b"ACTIVECHAIN-RPC-NETWORK-IDENTITY-V1");
        hasher.update(self.chain_id.digest().as_bytes());
        hasher.update(self.genesis_commitment.as_bytes());
        hasher.update(&self.protocol_revision.to_be_bytes());
        hasher.update(&self.rpc_schema_revision.to_be_bytes());
        let mut bytes = [0_u8; 48];
        XofReader::read(&mut hasher.finalize_xof(), &mut bytes);
        Digest384::new(bytes)
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
    CoinCell = 4,
    FungibleCoinCell = 5,
    NonFungibleCoinCell = 6,
    AssetDefinition = 7,
    AssetIssuerRegistration = 8,
    AssetSupplyAttestation = 9,
    AssetCorporateAction = 10,
    AssetSettlementReceipt = 11,
    AssetNftSeries = 12,
    AssetNftTokenRegistry = 13,
    DidEnsAlias = 14,
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
            4 => Ok(Self::CoinCell),
            5 => Ok(Self::FungibleCoinCell),
            6 => Ok(Self::NonFungibleCoinCell),
            7 => Ok(Self::AssetDefinition),
            8 => Ok(Self::AssetIssuerRegistration),
            9 => Ok(Self::AssetSupplyAttestation),
            10 => Ok(Self::AssetCorporateAction),
            11 => Ok(Self::AssetSettlementReceipt),
            12 => Ok(Self::AssetNftSeries),
            13 => Ok(Self::AssetNftTokenRegistry),
            14 => Ok(Self::DidEnsAlias),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "QueryKind", tag }),
        }
    }
}

pub const MAX_FAUCET_PROOF_LENGTH: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FaucetChallengeKind {
    CooldownOnly = 0,
    ProofOfWork = 1,
}
impl CanonicalEncode for FaucetChallengeKind {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for FaucetChallengeKind {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::CooldownOnly),
            1 => Ok(Self::ProofOfWork),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "FaucetChallengeKind", tag }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaucetTermsV1 {
    chain_id: ChainId,
    genesis_commitment: Digest384,
    policy_revision: u64,
    valid_until: u64,
    grant_amount: u128,
    recipient_cooldown_seconds: u64,
    recipient_lifetime_limit: u16,
    source_window_seconds: u64,
    source_window_limit: u16,
    global_window_seconds: u64,
    global_window_limit: u32,
    challenge_kind: FaucetChallengeKind,
    challenge_difficulty: u8,
}
impl FaucetTermsV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        genesis_commitment: Digest384,
        policy_revision: u64,
        valid_until: u64,
        grant_amount: u128,
        recipient_cooldown_seconds: u64,
        recipient_lifetime_limit: u16,
        source_window_seconds: u64,
        source_window_limit: u16,
        global_window_seconds: u64,
        global_window_limit: u32,
        challenge_kind: FaucetChallengeKind,
        challenge_difficulty: u8,
    ) -> Result<Self, DecodeError> {
        if genesis_commitment == Digest384::ZERO
            || policy_revision == 0
            || valid_until == 0
            || grant_amount == 0
            || recipient_cooldown_seconds == 0
            || recipient_lifetime_limit == 0
            || source_window_seconds == 0
            || source_window_limit == 0
            || global_window_seconds == 0
            || global_window_limit == 0
            || challenge_difficulty > 32
            || (challenge_kind == FaucetChallengeKind::CooldownOnly && challenge_difficulty != 0)
            || (challenge_kind == FaucetChallengeKind::ProofOfWork && challenge_difficulty == 0)
        {
            return Err(DecodeError::InvalidValue("invalid faucet terms"));
        }
        Ok(Self {
            chain_id,
            genesis_commitment,
            policy_revision,
            valid_until,
            grant_amount,
            recipient_cooldown_seconds,
            recipient_lifetime_limit,
            source_window_seconds,
            source_window_limit,
            global_window_seconds,
            global_window_limit,
            challenge_kind,
            challenge_difficulty,
        })
    }
    pub const fn chain_id(self) -> ChainId {
        self.chain_id
    }
    pub const fn genesis_commitment(self) -> Digest384 {
        self.genesis_commitment
    }
    pub const fn policy_revision(self) -> u64 {
        self.policy_revision
    }
    pub const fn valid_until(self) -> u64 {
        self.valid_until
    }
    pub const fn grant_amount(self) -> u128 {
        self.grant_amount
    }
    pub const fn challenge_kind(self) -> FaucetChallengeKind {
        self.challenge_kind
    }
    pub const fn challenge_difficulty(self) -> u8 {
        self.challenge_difficulty
    }
}
impl CanonicalEncode for FaucetTermsV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.genesis_commitment.encode(e)?;
        self.policy_revision.encode(e)?;
        self.valid_until.encode(e)?;
        self.grant_amount.encode(e)?;
        self.recipient_cooldown_seconds.encode(e)?;
        self.recipient_lifetime_limit.encode(e)?;
        self.source_window_seconds.encode(e)?;
        self.source_window_limit.encode(e)?;
        self.global_window_seconds.encode(e)?;
        self.global_window_limit.encode(e)?;
        self.challenge_kind.encode(e)?;
        self.challenge_difficulty.encode(e)
    }
}
impl CanonicalDecode for FaucetTermsV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
            u16::decode(d)?,
            u64::decode(d)?,
            u16::decode(d)?,
            u64::decode(d)?,
            u32::decode(d)?,
            FaucetChallengeKind::decode(d)?,
            u8::decode(d)?,
        )
    }
}
impl CanonicalType for FaucetTermsV1 {
    const TYPE_TAG: u16 = 0x00bf;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 2 + 8 * 5 + 16 + 2 * 2 + 4 + 2;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaucetRequestV1 {
    chain_id: ChainId,
    genesis_commitment: Digest384,
    recipient: PrincipalId,
    idempotency_key: Digest384,
    source_commitment: Digest384,
    challenge_nonce: u64,
    challenge_evidence: Vec<u8>,
}

impl FaucetRequestV1 {
    pub fn new(
        chain_id: ChainId,
        genesis_commitment: Digest384,
        recipient: PrincipalId,
        idempotency_key: Digest384,
        source_commitment: Digest384,
        challenge_nonce: u64,
        challenge_evidence: Vec<u8>,
    ) -> Result<Self, DecodeError> {
        if genesis_commitment == Digest384::ZERO
            || idempotency_key == Digest384::ZERO
            || source_commitment == Digest384::ZERO
            || challenge_evidence.len() > MAX_FAUCET_PROOF_LENGTH
        {
            return Err(DecodeError::InvalidValue("invalid faucet request"));
        }
        Ok(Self {
            chain_id,
            genesis_commitment,
            recipient,
            idempotency_key,
            source_commitment,
            challenge_nonce,
            challenge_evidence,
        })
    }
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn genesis_commitment(&self) -> Digest384 {
        self.genesis_commitment
    }
    pub const fn recipient(&self) -> PrincipalId {
        self.recipient
    }
    pub const fn idempotency_key(&self) -> Digest384 {
        self.idempotency_key
    }
    pub const fn source_commitment(&self) -> Digest384 {
        self.source_commitment
    }
    pub const fn challenge_nonce(&self) -> u64 {
        self.challenge_nonce
    }
    pub fn challenge_evidence(&self) -> &[u8] {
        &self.challenge_evidence
    }
    /// Client-computable settlement reference covered by the faucet cash authorization.
    pub fn settlement_reference(&self) -> Result<Digest384, EncodeError> {
        let bytes = encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-TESTNET-FAUCET-REFERENCE-V2");
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
        let mut output = [0; 48];
        hasher.finalize_xof().read(&mut output);
        Ok(Digest384::new(output))
    }
}
impl CanonicalEncode for FaucetRequestV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(encoder)?;
        self.genesis_commitment.encode(encoder)?;
        self.recipient.encode(encoder)?;
        self.idempotency_key.encode(encoder)?;
        self.source_commitment.encode(encoder)?;
        self.challenge_nonce.encode(encoder)?;
        encoder.write_bytes(&self.challenge_evidence, MAX_FAUCET_PROOF_LENGTH)
    }
}
impl CanonicalDecode for FaucetRequestV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(decoder)?,
            Digest384::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            decoder.read_bytes(MAX_FAUCET_PROOF_LENGTH)?.to_vec(),
        )
    }
}
impl CanonicalType for FaucetRequestV1 {
    const TYPE_TAG: u16 = 0x00c0;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 5 + 8 + 2 + MAX_FAUCET_PROOF_LENGTH;
}

/// Faucet request carrying the exact pre-signed cash authorization that must
/// be admitted by validator ingress. The envelope is opaque to the RPC wire
/// but bounded and re-verified by the validator-side settlement boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedFaucetRequestV1 {
    pub request: FaucetRequestV1,
    pub envelope: Vec<u8>,
}
impl CanonicalEncode for AuthorizedFaucetRequestV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.request.encode(encoder)?;
        encoder.write_bytes(&self.envelope, 64 * 1024)
    }
}
impl CanonicalDecode for AuthorizedFaucetRequestV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let request = FaucetRequestV1::decode(decoder)?;
        let envelope = decoder.read_bytes(64 * 1024)?.to_vec();
        if envelope.is_empty() {
            return Err(DecodeError::InvalidValue("empty authorized faucet envelope"));
        }
        Ok(Self { request, envelope })
    }
}
impl CanonicalType for AuthorizedFaucetRequestV1 {
    const TYPE_TAG: u16 = 0x012a;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = FaucetRequestV1::MAX_ENCODED_LEN + 4 + 64 * 1024;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FaucetState {
    Pending = 0,
    Finalized = 1,
    Rejected = 2,
}
impl CanonicalEncode for FaucetState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for FaucetState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Finalized),
            2 => Ok(Self::Rejected),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "FaucetState", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaucetReceiptV1 {
    reference: Digest384,
    recipient: PrincipalId,
    amount: u128,
    state: FaucetState,
    transaction_id: Option<TransactionId>,
    finalized_height: Option<u64>,
    finalized_block: Option<Digest384>,
    proof: Vec<u8>,
}
impl FaucetReceiptV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reference: Digest384,
        recipient: PrincipalId,
        amount: u128,
        state: FaucetState,
        transaction_id: Option<TransactionId>,
        finalized_height: Option<u64>,
        finalized_block: Option<Digest384>,
        proof: Vec<u8>,
    ) -> Result<Self, DecodeError> {
        let finalized_fields = transaction_id.is_some()
            && finalized_height.is_some()
            && finalized_block.is_some()
            && !proof.is_empty();
        if reference == Digest384::ZERO
            || amount == 0
            || proof.len() > MAX_RPC_BLOB_LENGTH
            || (state == FaucetState::Finalized && !finalized_fields)
            || (state != FaucetState::Finalized
                && (finalized_height.is_some() || finalized_block.is_some() || !proof.is_empty()))
        {
            return Err(DecodeError::InvalidValue("invalid faucet receipt"));
        }
        Ok(Self {
            reference,
            recipient,
            amount,
            state,
            transaction_id,
            finalized_height,
            finalized_block,
            proof,
        })
    }
    pub const fn reference(&self) -> Digest384 {
        self.reference
    }
    pub const fn recipient(&self) -> PrincipalId {
        self.recipient
    }
    pub const fn amount(&self) -> u128 {
        self.amount
    }
    pub const fn state(&self) -> FaucetState {
        self.state
    }
    pub const fn transaction_id(&self) -> Option<TransactionId> {
        self.transaction_id
    }
    pub const fn finalized_height(&self) -> Option<u64> {
        self.finalized_height
    }
    pub const fn finalized_block(&self) -> Option<Digest384> {
        self.finalized_block
    }
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
}
impl CanonicalEncode for FaucetReceiptV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.reference.encode(encoder)?;
        self.recipient.encode(encoder)?;
        self.amount.encode(encoder)?;
        self.state.encode(encoder)?;
        self.transaction_id.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        self.finalized_block.encode(encoder)?;
        encoder.write_bytes(&self.proof, MAX_RPC_BLOB_LENGTH)
    }
}
impl CanonicalDecode for FaucetReceiptV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            u128::decode(decoder)?,
            FaucetState::decode(decoder)?,
            Option::<TransactionId>::decode(decoder)?,
            Option::<u64>::decode(decoder)?,
            Option::<Digest384>::decode(decoder)?,
            decoder.read_bytes(MAX_RPC_BLOB_LENGTH)?.to_vec(),
        )
    }
}
impl CanonicalType for FaucetReceiptV1 {
    const TYPE_TAG: u16 = 0x00c1;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 4 + 16 + 1 + 3 + 8 + 2 + MAX_RPC_BLOB_LENGTH;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorActionSubmissionV1 {
    reference: Digest384,
    transaction: TransactionId,
}

impl AnchorActionSubmissionV1 {
    pub fn new(reference: Digest384, transaction: TransactionId) -> Result<Self, DecodeError> {
        if reference == Digest384::ZERO || transaction.digest() == &Digest384::ZERO {
            return Err(DecodeError::InvalidValue("invalid native anchor submission"));
        }
        Ok(Self { reference, transaction })
    }

    pub const fn reference(self) -> Digest384 {
        self.reference
    }

    pub const fn transaction(self) -> TransactionId {
        self.transaction
    }
}

impl CanonicalEncode for AnchorActionSubmissionV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.reference.encode(encoder)?;
        self.transaction.encode(encoder)
    }
}

impl CanonicalDecode for AnchorActionSubmissionV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(Digest384::decode(decoder)?, TransactionId::decode(decoder)?)
    }
}

impl CanonicalType for AnchorActionSubmissionV1 {
    const TYPE_TAG: u16 = 0x01BF;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 96;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorServiceStatusV1 {
    status: RpcStatus,
    accepting_submissions: bool,
}

impl AnchorServiceStatusV1 {
    pub const fn new(status: RpcStatus, accepting_submissions: bool) -> Self {
        Self { status, accepting_submissions }
    }

    pub const fn status(&self) -> &RpcStatus {
        &self.status
    }

    pub const fn accepting_submissions(&self) -> bool {
        self.accepting_submissions
    }
}

impl CanonicalEncode for AnchorServiceStatusV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.status.encode(encoder)?;
        self.accepting_submissions.encode(encoder)
    }
}

impl CanonicalDecode for AnchorServiceStatusV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(RpcStatus::decode(decoder)?, bool::decode(decoder)?))
    }
}

impl CanonicalType for AnchorServiceStatusV1 {
    const TYPE_TAG: u16 = 0x01C0;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 2 + 8 * 5 + 4 + 1 + 2 + MAX_SUPPORTED_PROOFS + 1;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcRequest {
    Status,
    AnchorServiceStatus,
    Get {
        kind: QueryKind,
        key: Digest384,
    },
    List {
        kind: QueryKind,
        after: Option<Digest384>,
        limit: u16,
    },
    SubmitAnchor {
        statement: Vec<u8>,
    },
    SubmitAnchorAction {
        action: Vec<u8>,
    },
    ResolveAnchor {
        reference: Digest384,
    },
    RequestFaucet {
        request: Box<FaucetRequestV1>,
    },
    RequestAuthorizedFaucet {
        request: Box<AuthorizedFaucetRequestV1>,
    },
    ResolveFaucet {
        reference: Digest384,
    },
    FaucetTerms,
    ListOwnerCoinCells {
        owner: PrincipalId,
        after: Option<Digest384>,
        limit: u16,
    },
    ListOwnerFungibleCoinCells {
        owner: PrincipalId,
        asset: AssetId,
        after: Option<Digest384>,
        limit: u16,
    },
    /// Offers a signed transfer for inclusion.
    ///
    /// Acceptance means durably spooled and nothing more; the receipt says so
    /// and makes no claim about the ledger.
    SubmitAuthorizedTransfer {
        envelope: Vec<u8>,
    },
    /// Asks what became of a submission.
    ///
    /// The reference is the canonical commitment over the envelope, so a client
    /// already holds it after submitting and needs nothing handed back to poll
    /// with. Without this a refusal after spooling is unobservable: nothing
    /// changes on chain, and polling cannot separate pending from refused.
    ResolveTransfer {
        reference: Digest384,
    },
}

impl CanonicalEncode for RpcRequest {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Status => 0_u8.encode(encoder),
            Self::AnchorServiceStatus => 12_u8.encode(encoder),
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
            Self::SubmitAnchor { statement } => {
                3_u8.encode(encoder)?;
                encoder.write_bytes(statement, 512)
            }
            Self::SubmitAuthorizedTransfer { envelope } => {
                13_u8.encode(encoder)?;
                encoder.write_bytes(envelope, MAX_TRANSFER_ENVELOPE_LENGTH)
            }
            Self::ResolveTransfer { reference } => {
                14_u8.encode(encoder)?;
                reference.encode(encoder)
            }
            Self::SubmitAnchorAction { action } => {
                11_u8.encode(encoder)?;
                encoder.write_bytes(action, MAX_ANCHOR_ACTION_LENGTH)
            }
            Self::ResolveAnchor { reference } => {
                4_u8.encode(encoder)?;
                reference.encode(encoder)
            }
            Self::RequestFaucet { request } => {
                5_u8.encode(encoder)?;
                request.encode(encoder)
            }
            Self::RequestAuthorizedFaucet { request } => {
                10_u8.encode(encoder)?;
                request.encode(encoder)
            }
            Self::ResolveFaucet { reference } => {
                6_u8.encode(encoder)?;
                reference.encode(encoder)
            }
            Self::FaucetTerms => 7_u8.encode(encoder),
            Self::ListOwnerCoinCells { owner, after, limit } => {
                8_u8.encode(encoder)?;
                owner.encode(encoder)?;
                after.encode(encoder)?;
                limit.encode(encoder)
            }
            Self::ListOwnerFungibleCoinCells { owner, asset, after, limit } => {
                9_u8.encode(encoder)?;
                owner.encode(encoder)?;
                asset.encode(encoder)?;
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
            12 => Ok(Self::AnchorServiceStatus),
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
            3 => Ok(Self::SubmitAnchor { statement: decoder.read_bytes(512)?.to_vec() }),
            13 => Ok(Self::SubmitAuthorizedTransfer {
                envelope: decoder.read_bytes(MAX_TRANSFER_ENVELOPE_LENGTH)?.to_vec(),
            }),
            14 => Ok(Self::ResolveTransfer { reference: Digest384::decode(decoder)? }),
            11 => Ok(Self::SubmitAnchorAction {
                action: decoder.read_bytes(MAX_ANCHOR_ACTION_LENGTH)?.to_vec(),
            }),
            4 => Ok(Self::ResolveAnchor { reference: Digest384::decode(decoder)? }),
            5 => Ok(Self::RequestFaucet { request: Box::new(FaucetRequestV1::decode(decoder)?) }),
            10 => Ok(Self::RequestAuthorizedFaucet {
                request: Box::new(AuthorizedFaucetRequestV1::decode(decoder)?),
            }),
            6 => Ok(Self::ResolveFaucet { reference: Digest384::decode(decoder)? }),
            7 => Ok(Self::FaucetTerms),
            8 => {
                let owner = PrincipalId::decode(decoder)?;
                let after = Option::<Digest384>::decode(decoder)?;
                let limit = u16::decode(decoder)?;
                if limit == 0 || limit > MAX_RPC_PAGE_SIZE {
                    return Err(DecodeError::InvalidValue("RPC page limit is out of bounds"));
                }
                Ok(Self::ListOwnerCoinCells { owner, after, limit })
            }
            9 => {
                let owner = PrincipalId::decode(decoder)?;
                let asset = AssetId::decode(decoder)?;
                let after = Option::<Digest384>::decode(decoder)?;
                let limit = u16::decode(decoder)?;
                if limit == 0 || limit > MAX_RPC_PAGE_SIZE {
                    return Err(DecodeError::InvalidValue("RPC page limit is out of bounds"));
                }
                Ok(Self::ListOwnerFungibleCoinCells { owner, asset, after, limit })
            }
            tag => Err(DecodeError::InvalidEnumTag { type_name: "RpcRequest", tag }),
        }
    }
}
impl CanonicalType for RpcRequest {
    const TYPE_TAG: u16 = 0x0107;
    // Revision 3 adds SubmitAuthorizedTransfer and ResolveTransfer. A client
    // that cannot decode them must not mistake a transfer for something else,
    // so this is a revision bump rather than a quietly additive tag.
    const SCHEMA_VERSION: u16 = 3;
    // The transfer envelope is now the largest a request can carry.
    const MAX_ENCODED_LEN: usize =
        1 + if AuthorizedFaucetRequestV1::MAX_ENCODED_LEN > MAX_TRANSFER_ENVELOPE_LENGTH + 3 {
            AuthorizedFaucetRequestV1::MAX_ENCODED_LEN
        } else {
            MAX_TRANSFER_ENVELOPE_LENGTH + 3
        };
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
            RpcRequest::Status | RpcRequest::AnchorServiceStatus => Some(0),
            RpcRequest::FaucetTerms => Some(0),
            RpcRequest::Get { .. }
            | RpcRequest::SubmitAnchor { .. }
            | RpcRequest::SubmitAnchorAction { .. }
            | RpcRequest::ResolveAnchor { .. }
            | RpcRequest::RequestFaucet { .. }
            | RpcRequest::RequestAuthorizedFaucet { .. }
            | RpcRequest::ResolveFaucet { .. }
            // Charged like any other point operation. Free resolution would
            // make polling cheaper than waiting and invite a client to hammer
            // it; the submission itself is metered for the same reason.
            | RpcRequest::SubmitAuthorizedTransfer { .. }
            | RpcRequest::ResolveTransfer { .. } => Some(self.get_units),
            RpcRequest::List { limit, .. }
            | RpcRequest::ListOwnerCoinCells { limit, .. }
            | RpcRequest::ListOwnerFungibleCoinCells { limit, .. } => self
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
    pub const TYPE_TAG: u16 = 0x010d;
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

/// Why the faucet refused, in terms a client can act on.
///
/// Deliberately bounded and deliberately public. Every operator-side failure —
/// a treasury with too few Coin Cells to construct a transfer, a stale treasury
/// snapshot, a signer problem — collapses into `SettlementUnavailable`, because
/// a client can do nothing with the distinction and the internals are not its
/// business. Kernel errors such as `InvalidTransition` never reach the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FaucetRejectionCode {
    Disabled = 0,
    WrongNetwork = 1,
    InvalidChallenge = 2,
    RecipientCooldown = 3,
    RecipientExhausted = 4,
    SourceLimited = 5,
    GlobalLimited = 6,
    ExistingPendingGrant = 7,
    SettlementUnavailable = 8,
}
impl CanonicalEncode for FaucetRejectionCode {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for FaucetRejectionCode {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::WrongNetwork),
            2 => Ok(Self::InvalidChallenge),
            3 => Ok(Self::RecipientCooldown),
            4 => Ok(Self::RecipientExhausted),
            5 => Ok(Self::SourceLimited),
            6 => Ok(Self::GlobalLimited),
            7 => Ok(Self::ExistingPendingGrant),
            8 => Ok(Self::SettlementUnavailable),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "FaucetRejectionCode", tag }),
        }
    }
}

/// A faucet refusal, with only what the client needs to decide what to do next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaucetRejectionV1 {
    code: FaucetRejectionCode,
    /// When a wait would help. Absent when waiting cannot change the outcome.
    retry_after_seconds: Option<u64>,
    /// The reservation already held for this recipient, for correlation only.
    existing_reference: Option<Digest384>,
}
impl FaucetRejectionV1 {
    pub fn new(
        code: FaucetRejectionCode,
        retry_after_seconds: Option<u64>,
        existing_reference: Option<Digest384>,
    ) -> Result<Self, DecodeError> {
        // A reference is meaningful only for the one code that refers to an
        // existing reservation; carrying it elsewhere would leak references for
        // requests that never produced one.
        if existing_reference.is_some() && code != FaucetRejectionCode::ExistingPendingGrant {
            return Err(DecodeError::InvalidValue("faucet rejection reference is out of place"));
        }
        if existing_reference == Some(Digest384::ZERO) {
            return Err(DecodeError::InvalidValue("faucet rejection reference must not be zero"));
        }
        Ok(Self { code, retry_after_seconds, existing_reference })
    }
    /// A refusal that names nothing beyond "not right now".
    pub const fn unavailable() -> Self {
        Self {
            code: FaucetRejectionCode::SettlementUnavailable,
            retry_after_seconds: None,
            existing_reference: None,
        }
    }
    pub const fn code(&self) -> FaucetRejectionCode {
        self.code
    }
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        self.retry_after_seconds
    }
    pub const fn existing_reference(&self) -> Option<Digest384> {
        self.existing_reference
    }
}
impl CanonicalEncode for FaucetRejectionV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.code.encode(encoder)?;
        self.retry_after_seconds.encode(encoder)?;
        self.existing_reference.encode(encoder)
    }
}
impl CanonicalDecode for FaucetRejectionV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let code = FaucetRejectionCode::decode(decoder)?;
        let retry_after_seconds = Option::<u64>::decode(decoder)?;
        let existing_reference = Option::<Digest384>::decode(decoder)?;
        Self::new(code, retry_after_seconds, existing_reference)
    }
}

/// Where a submitted transfer stands.
///
/// `Pending` means durably spooled and nothing more: not finalized, not
/// executed, and carrying no claim about the ledger. The terminal states are
/// reached once and never regress, because a client that has been told an
/// outcome must not later be told a different one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransferState {
    Pending = 0,
    Finalized = 1,
    Rejected = 2,
    /// Not known here, or no longer retained.
    ///
    /// Deliberately not "definitely evicted": distinguishing a forgotten
    /// outcome from a reference that was never submitted would require keeping
    /// a tombstone for every reference ever asked about, which is unbounded.
    /// A node that has never seen a reference and one that has forgotten it
    /// can say the same true thing.
    ///
    /// What it never means is "still in flight". Reporting `Pending` for a
    /// forgotten outcome would make forgetting look like work in progress and
    /// reintroduce, at the storage boundary, the ambiguity resolution exists
    /// to remove. A client seeing `Unknown` for something it submitted and saw
    /// accepted has learned that the node can no longer answer, which is a
    /// different instruction from "keep waiting".
    Unknown = 3,
}
impl CanonicalEncode for TransferState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for TransferState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Finalized),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Unknown),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "TransferState", tag }),
        }
    }
}

/// Why a transfer was refused.
///
/// Modelled on the faucet taxonomy without inheriting it: a faucet refuses on
/// entitlement, while a transfer refuses on the state of the sender's own
/// cells. `InputAlreadySpent` and `ValidityWindowLapsed` have no faucet
/// equivalent, and the faucet's recipient-quota codes have no meaning here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransferRejectionCode {
    Disabled = 0,
    WrongNetwork = 1,
    /// Failed a size or structural bound. Refused before verification was paid
    /// for, so it says nothing about whether the signature would have held.
    Malformed = 2,
    InvalidAuthorization = 3,
    SessionExpired = 4,
    SessionInvalid = 5,
    /// An input was already consumed, typically by the sender's own earlier
    /// transfer. Terminal: resubmitting the same envelope cannot succeed.
    InputAlreadySpent = 6,
    ValidityWindowLapsed = 7,
    /// The authenticated signer or session exceeded its quota. Transient.
    SignerLimited = 8,
    GlobalLimited = 9,
    /// The spool is at its count or byte bound and refuses rather than drops.
    SpoolFull = 10,
}
impl TransferRejectionCode {
    /// Whether resubmitting the identical envelope could ever succeed later.
    ///
    /// Quota and capacity refusals are about the node's present load; the rest
    /// are about the submission itself and will refuse identically forever.
    #[must_use]
    pub const fn is_transient(self) -> bool {
        matches!(self, Self::SignerLimited | Self::GlobalLimited | Self::SpoolFull)
    }
}
impl CanonicalEncode for TransferRejectionCode {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for TransferRejectionCode {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::WrongNetwork),
            2 => Ok(Self::Malformed),
            3 => Ok(Self::InvalidAuthorization),
            4 => Ok(Self::SessionExpired),
            5 => Ok(Self::SessionInvalid),
            6 => Ok(Self::InputAlreadySpent),
            7 => Ok(Self::ValidityWindowLapsed),
            8 => Ok(Self::SignerLimited),
            9 => Ok(Self::GlobalLimited),
            10 => Ok(Self::SpoolFull),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "TransferRejectionCode", tag }),
        }
    }
}

/// A transfer refusal, carrying only what decides the client's next move.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferRejectionV1 {
    code: TransferRejectionCode,
    /// When a wait would help. Absent when waiting cannot change the outcome.
    retry_after_seconds: Option<u64>,
}
impl TransferRejectionV1 {
    /// # Errors
    /// Rejects a retry hint on a code that will refuse identically forever,
    /// which would invite a client to retry something that cannot succeed.
    pub fn new(
        code: TransferRejectionCode,
        retry_after_seconds: Option<u64>,
    ) -> Result<Self, DecodeError> {
        if retry_after_seconds.is_some() && !code.is_transient() {
            return Err(DecodeError::InvalidValue("retry hint on a permanent transfer refusal"));
        }
        Ok(Self { code, retry_after_seconds })
    }
    #[must_use]
    pub const fn code(&self) -> TransferRejectionCode {
        self.code
    }
    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        self.retry_after_seconds
    }
}
impl CanonicalEncode for TransferRejectionV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.code.encode(encoder)?;
        self.retry_after_seconds.encode(encoder)
    }
}
impl CanonicalDecode for TransferRejectionV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let code = TransferRejectionCode::decode(decoder)?;
        let retry_after_seconds = Option::<u64>::decode(decoder)?;
        Self::new(code, retry_after_seconds)
    }
}

/// What the node can say about one submitted transfer.
///
/// Answers both submission and resolution, so a client polls with the same
/// reference it already holds and reads the same shape it was first given.
/// The reference is the canonical commitment over the submitted envelope,
/// which makes it the deduplication key as well, with no second identifier to
/// keep in step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferReceiptV1 {
    reference: Digest384,
    state: TransferState,
    transaction_id: Option<TransactionId>,
    finalized_height: Option<u64>,
    finalized_block: Option<Digest384>,
    rejection: Option<TransferRejectionV1>,
}
impl TransferReceiptV1 {
    /// # Errors
    /// Refuses any receipt whose fields contradict its state, so an
    /// inconsistent one cannot be encoded and then believed by a client.
    pub fn new(
        reference: Digest384,
        state: TransferState,
        transaction_id: Option<TransactionId>,
        finalized_height: Option<u64>,
        finalized_block: Option<Digest384>,
        rejection: Option<TransferRejectionV1>,
    ) -> Result<Self, DecodeError> {
        if reference == Digest384::ZERO {
            return Err(DecodeError::InvalidValue("transfer receipt without a reference"));
        }
        // Matched state by state rather than counted. Comparing "is finalized"
        // against "has all three evidence fields" agrees whenever both are
        // false, which let a Pending receipt carry a partial finalization it
        // had no business carrying.
        let evidence =
            (transaction_id.is_some(), finalized_height.is_some(), finalized_block.is_some());
        match state {
            TransferState::Pending | TransferState::Unknown => {
                if evidence != (false, false, false) {
                    return Err(DecodeError::InvalidValue(
                        "unsettled transfer cannot carry finalization evidence",
                    ));
                }
                if rejection.is_some() {
                    return Err(DecodeError::InvalidValue(
                        "unsettled transfer cannot carry a refusal",
                    ));
                }
            }
            TransferState::Finalized => {
                if evidence != (true, true, true) {
                    return Err(DecodeError::InvalidValue(
                        "finalized transfer needs its transaction, height and block",
                    ));
                }
                if rejection.is_some() {
                    return Err(DecodeError::InvalidValue("a finalized transfer was not refused"));
                }
            }
            TransferState::Rejected => {
                if rejection.is_none() {
                    return Err(DecodeError::InvalidValue("a refusal must say why"));
                }
                if evidence != (false, false, false) {
                    return Err(DecodeError::InvalidValue(
                        "a refused transfer was never included in a block",
                    ));
                }
            }
        }
        Ok(Self { reference, state, transaction_id, finalized_height, finalized_block, rejection })
    }
    #[must_use]
    pub const fn reference(&self) -> Digest384 {
        self.reference
    }
    #[must_use]
    pub const fn state(&self) -> TransferState {
        self.state
    }
    #[must_use]
    pub const fn finalized_height(&self) -> Option<u64> {
        self.finalized_height
    }
    #[must_use]
    pub const fn transaction_id(&self) -> Option<TransactionId> {
        self.transaction_id
    }
    #[must_use]
    pub const fn finalized_block(&self) -> Option<Digest384> {
        self.finalized_block
    }
    #[must_use]
    pub const fn rejection(&self) -> Option<TransferRejectionV1> {
        self.rejection
    }
}
impl CanonicalEncode for TransferReceiptV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.reference.encode(encoder)?;
        self.state.encode(encoder)?;
        self.transaction_id.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        self.finalized_block.encode(encoder)?;
        self.rejection.encode(encoder)
    }
}
impl CanonicalDecode for TransferReceiptV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let reference = Digest384::decode(decoder)?;
        let state = TransferState::decode(decoder)?;
        let transaction_id = Option::<TransactionId>::decode(decoder)?;
        let finalized_height = Option::<u64>::decode(decoder)?;
        let finalized_block = Option::<Digest384>::decode(decoder)?;
        let rejection = Option::<TransferRejectionV1>::decode(decoder)?;
        Self::new(reference, state, transaction_id, finalized_height, finalized_block, rejection)
    }
}
impl CanonicalType for TransferReceiptV1 {
    const TYPE_TAG: u16 = 0x01c8;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 1 + (1 + 48) + (1 + 8) + (1 + 48) + (1 + 1 + 1 + 8);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcResponse {
    Status(RpcStatus),
    AnchorServiceStatus(AnchorServiceStatusV1),
    Record(QueryRecord),
    Page(QueryPage),
    Error(RpcError),
    AnchorSubmission(Digest384),
    AnchorActionSubmission(AnchorActionSubmissionV1),
    AnchorRecord(Vec<u8>),
    FaucetReceipt(FaucetReceiptV1),
    FaucetTerms(FaucetTermsV1),
    FaucetRejected(FaucetRejectionV1),
    /// Answers both submission and resolution, so a refusal, an accepted
    /// spooling and a finalized outcome all arrive in one shape.
    TransferReceipt(TransferReceiptV1),
}
impl CanonicalEncode for RpcResponse {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Status(status) => {
                0_u8.encode(encoder)?;
                status.encode(encoder)
            }
            Self::AnchorServiceStatus(status) => {
                9_u8.encode(encoder)?;
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
            Self::AnchorSubmission(reference) => {
                4_u8.encode(encoder)?;
                reference.encode(encoder)
            }
            Self::AnchorActionSubmission(submission) => {
                8_u8.encode(encoder)?;
                submission.encode(encoder)
            }
            Self::AnchorRecord(record) => {
                5_u8.encode(encoder)?;
                encoder.write_bytes(record, MAX_RPC_BLOB_LENGTH)
            }
            Self::FaucetReceipt(receipt) => {
                6_u8.encode(encoder)?;
                receipt.encode(encoder)
            }
            Self::FaucetTerms(terms) => {
                7_u8.encode(encoder)?;
                terms.encode(encoder)
            }
            Self::FaucetRejected(rejection) => {
                10_u8.encode(encoder)?;
                rejection.encode(encoder)
            }
            Self::TransferReceipt(receipt) => {
                11_u8.encode(encoder)?;
                receipt.encode(encoder)
            }
        }
    }
}
impl CanonicalDecode for RpcResponse {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Status(RpcStatus::decode(decoder)?)),
            9 => Ok(Self::AnchorServiceStatus(AnchorServiceStatusV1::decode(decoder)?)),
            1 => Ok(Self::Record(QueryRecord::decode(decoder)?)),
            2 => Ok(Self::Page(QueryPage::decode(decoder)?)),
            3 => Ok(Self::Error(RpcError::decode(decoder)?)),
            4 => Ok(Self::AnchorSubmission(Digest384::decode(decoder)?)),
            8 => Ok(Self::AnchorActionSubmission(AnchorActionSubmissionV1::decode(decoder)?)),
            5 => Ok(Self::AnchorRecord(decoder.read_bytes(MAX_RPC_BLOB_LENGTH)?.to_vec())),
            6 => Ok(Self::FaucetReceipt(FaucetReceiptV1::decode(decoder)?)),
            7 => Ok(Self::FaucetTerms(FaucetTermsV1::decode(decoder)?)),
            10 => Ok(Self::FaucetRejected(FaucetRejectionV1::decode(decoder)?)),
            11 => Ok(Self::TransferReceipt(TransferReceiptV1::decode(decoder)?)),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "RpcResponse", tag }),
        }
    }
}
impl CanonicalType for RpcResponse {
    const TYPE_TAG: u16 = 0x010a;
    // Revision 3 added FaucetRejected; revision 4 adds TransferReceipt. A
    // client that cannot decode the new variant must not silently treat an
    // outcome as some other one, so each is a revision bump rather than a
    // quietly additive tag.
    const SCHEMA_VERSION: u16 = 4;
    const MAX_ENCODED_LEN: usize = 1
        + 2
        + MAX_RPC_PAGE_SIZE as usize * (1 + 48 + 8 + 3 * (4 + MAX_RPC_BLOB_LENGTH))
        + FaucetReceiptV1::MAX_ENCODED_LEN;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use activechain_protocol_types::FungibleAssetDefinition;
    use alloc::vec;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn canonical_registry_prevents_cross_type_envelope_substitution() {
        let asset = FungibleAssetDefinition::new(
            AssetId::new(digest(1)),
            PrincipalId::new(digest(2)),
            b"TEST".to_vec(),
            6,
            1_000_000,
            digest(3),
        )
        .unwrap();
        let encoded = encode_envelope(&asset).unwrap();

        assert_ne!(
            <FungibleAssetDefinition as CanonicalType>::TYPE_TAG,
            <RpcRequest as CanonicalType>::TYPE_TAG
        );
        assert!(matches!(
            decode_envelope::<RpcRequest>(&encoded),
            Err(DecodeError::InvalidTypeTag { .. })
        ));
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
    fn anchor_service_status_round_trips_and_is_free() {
        let status = RpcStatus::new(
            ChainId::new(digest(1)),
            digest(2),
            3,
            4,
            100,
            105,
            10,
            alloc::vec![ProofKind::FinalityCertificate],
        )
        .unwrap();
        let request = RpcRequest::AnchorServiceStatus;
        assert_eq!(
            decode_envelope::<RpcRequest>(&encode_envelope(&request).unwrap()),
            Ok(request.clone())
        );
        let response = RpcResponse::AnchorServiceStatus(AnchorServiceStatusV1::new(status, true));
        assert_eq!(
            decode_envelope::<RpcResponse>(&encode_envelope(&response).unwrap()),
            Ok(response)
        );
    }

    #[test]
    fn network_identity_commitment_is_stable_across_head_updates() {
        let first = RpcStatus::new(
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
        let later = RpcStatus::new(
            ChainId::new(digest(1)),
            digest(2),
            3,
            99,
            200,
            205,
            10,
            alloc::vec![ProofKind::StateSparseMerkle, ProofKind::FinalityCertificate],
        )
        .unwrap();
        assert_eq!(first.identity_commitment(), later.identity_commitment());
        let different_revision = RpcStatus::new(
            ChainId::new(digest(1)),
            digest(2),
            4,
            4,
            100,
            105,
            10,
            alloc::vec![ProofKind::StateSparseMerkle, ProofKind::FinalityCertificate],
        )
        .unwrap();
        assert_ne!(first.identity_commitment(), different_revision.identity_commitment());
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

        let nft_request =
            RpcRequest::List { kind: QueryKind::NonFungibleCoinCell, after: None, limit: 1 };
        assert_eq!(
            decode_envelope::<RpcRequest>(&encode_envelope(&nft_request).unwrap()),
            Ok(nft_request)
        );
        for kind in [
            QueryKind::AssetDefinition,
            QueryKind::AssetIssuerRegistration,
            QueryKind::AssetSupplyAttestation,
            QueryKind::AssetCorporateAction,
            QueryKind::AssetSettlementReceipt,
            QueryKind::AssetNftSeries,
            QueryKind::AssetNftTokenRegistry,
        ] {
            let request = RpcRequest::Get { kind, key: digest(7) };
            assert_eq!(
                decode_envelope::<RpcRequest>(&encode_envelope(&request).unwrap()),
                Ok(request)
            );
        }

        let faucet = FaucetRequestV1::new(
            ChainId::new(digest(11)),
            digest(12),
            PrincipalId::new(digest(13)),
            digest(14),
            digest(15),
            1,
            vec![1],
        )
        .unwrap();
        let authorized = RpcRequest::RequestAuthorizedFaucet {
            request: Box::new(AuthorizedFaucetRequestV1 {
                request: faucet,
                envelope: vec![0xaa, 0xbb],
            }),
        };
        let encoded = encode_envelope(&authorized).unwrap();
        assert_eq!(decode_envelope::<RpcRequest>(&encoded), Ok(authorized));
    }

    /// A receipt is the only thing a client ever learns about its transfer, so
    /// every state must survive the wire and every inconsistent combination
    /// must be unconstructible rather than merely unlikely.
    #[test]
    fn transfer_receipt_round_trips_every_state_and_refuses_contradictions() {
        let pending =
            TransferReceiptV1::new(digest(7), TransferState::Pending, None, None, None, None)
                .expect("a pending receipt carries only its reference");
        let wire = encode_envelope(&pending).unwrap();
        assert_eq!(decode_envelope::<TransferReceiptV1>(&wire), Ok(pending));

        let finalized = TransferReceiptV1::new(
            digest(7),
            TransferState::Finalized,
            Some(TransactionId::new(digest(8))),
            Some(41),
            Some(digest(9)),
            None,
        )
        .expect("finalized carries its block evidence");
        assert_eq!(finalized.finalized_height(), Some(41));
        assert_eq!(
            decode_envelope::<TransferReceiptV1>(&encode_envelope(&finalized).unwrap()),
            Ok(finalized)
        );

        let refusal = TransferRejectionV1::new(TransferRejectionCode::InputAlreadySpent, None)
            .expect("a permanent refusal carries no retry hint");
        let rejected = TransferReceiptV1::new(
            digest(7),
            TransferState::Rejected,
            None,
            None,
            None,
            Some(refusal),
        )
        .expect("rejected carries its reason");
        assert_eq!(
            decode_envelope::<TransferReceiptV1>(&encode_envelope(&rejected).unwrap()),
            Ok(rejected)
        );

        // Eviction is reported as its own state. Reporting Pending here would
        // make a forgotten outcome look like work still in progress.
        let unknown =
            TransferReceiptV1::new(digest(7), TransferState::Unknown, None, None, None, None)
                .expect("an evicted receipt still names what it refers to");
        assert_eq!(unknown.state(), TransferState::Unknown);

        assert!(
            TransferReceiptV1::new(Digest384::ZERO, TransferState::Pending, None, None, None, None)
                .is_err(),
            "a receipt nobody can correlate is not a receipt"
        );
        assert!(
            TransferReceiptV1::new(digest(7), TransferState::Rejected, None, None, None, None)
                .is_err(),
            "Rejected without a reason tells a client nothing it can act on"
        );
        assert!(
            TransferReceiptV1::new(
                digest(7),
                TransferState::Pending,
                None,
                None,
                None,
                Some(refusal)
            )
            .is_err(),
            "a reason on a pending receipt claims an outcome that has not happened"
        );
        assert!(
            TransferReceiptV1::new(digest(7), TransferState::Finalized, None, None, None, None)
                .is_err(),
            "Finalized without block evidence is a claim with nothing behind it"
        );
    }

    /// Finalization is three facts that are only true together. Checking that
    /// "is finalized" agrees with "has all three" passes whenever both are
    /// false, which let an unsettled receipt carry a partial finalization it
    /// could never have earned.
    #[test]
    fn no_state_may_carry_partial_finalization_evidence() {
        let transaction = Some(TransactionId::new(digest(8)));
        let height = Some(41_u64);
        let block = Some(digest(9));
        let refusal =
            TransferRejectionV1::new(TransferRejectionCode::InputAlreadySpent, None).unwrap();

        // Every proper subset of the three, against every state that must
        // carry none of them.
        let partials = [
            (transaction, None, None),
            (None, height, None),
            (None, None, block),
            (transaction, height, None),
            (transaction, None, block),
            (None, height, block),
        ];
        for state in [TransferState::Pending, TransferState::Unknown] {
            for (id, at, at_block) in partials {
                assert!(
                    TransferReceiptV1::new(digest(7), state, id, at, at_block, None).is_err(),
                    "{state:?} must carry no finalization evidence, got {id:?}/{at:?}/{at_block:?}"
                );
            }
        }
        for (id, at, at_block) in partials {
            assert!(
                TransferReceiptV1::new(digest(7), TransferState::Finalized, id, at, at_block, None)
                    .is_err(),
                "Finalized needs all three, not {id:?}/{at:?}/{at_block:?}"
            );
            assert!(
                TransferReceiptV1::new(
                    digest(7),
                    TransferState::Rejected,
                    id,
                    at,
                    at_block,
                    Some(refusal)
                )
                .is_err(),
                "a refused transfer was never in a block, so it cannot cite one"
            );
        }

        // A refusal is not an outcome that also finalized.
        assert!(
            TransferReceiptV1::new(
                digest(7),
                TransferState::Finalized,
                transaction,
                height,
                block,
                Some(refusal)
            )
            .is_err(),
            "a finalized transfer was not refused"
        );
        assert!(
            TransferReceiptV1::new(
                digest(7),
                TransferState::Unknown,
                None,
                None,
                None,
                Some(refusal)
            )
            .is_err(),
            "an unanswerable receipt cannot also state a reason"
        );
    }

    /// Unknown is what a node says when it cannot answer, and a client has to
    /// be able to read that off the wire like any other outcome.
    #[test]
    fn an_unknown_outcome_round_trips_like_any_other() {
        let unknown =
            TransferReceiptV1::new(digest(7), TransferState::Unknown, None, None, None, None)
                .expect("an unanswerable receipt still names what it refers to");
        let wire = encode_envelope(&unknown).unwrap();
        let decoded = decode_envelope::<TransferReceiptV1>(&wire).expect("Unknown must survive");
        assert_eq!(decoded.state(), TransferState::Unknown);
        assert_eq!(decoded.reference(), digest(7));
        assert_eq!(decoded.transaction_id(), None);
        assert_eq!(decoded.finalized_block(), None);
        assert_eq!(decoded, unknown);

        let response = RpcResponse::TransferReceipt(unknown);
        assert_eq!(
            decode_envelope::<RpcResponse>(&encode_envelope(&response).unwrap()),
            Ok(response)
        );
    }

    /// A retry hint is an instruction. Offering one where retrying can never
    /// work sends a client into a loop that cannot terminate.
    #[test]
    fn only_a_transient_transfer_refusal_may_carry_a_retry_hint() {
        assert!(TransferRejectionV1::new(TransferRejectionCode::SpoolFull, Some(30)).is_ok());
        assert!(TransferRejectionV1::new(TransferRejectionCode::SignerLimited, Some(30)).is_ok());
        assert!(TransferRejectionV1::new(TransferRejectionCode::GlobalLimited, Some(30)).is_ok());
        for permanent in [
            TransferRejectionCode::InputAlreadySpent,
            TransferRejectionCode::ValidityWindowLapsed,
            TransferRejectionCode::SessionExpired,
            TransferRejectionCode::Malformed,
            TransferRejectionCode::InvalidAuthorization,
        ] {
            assert!(!permanent.is_transient(), "{permanent:?} cannot become acceptable by waiting");
            assert!(
                TransferRejectionV1::new(permanent, Some(30)).is_err(),
                "{permanent:?} must not invite a retry"
            );
            assert!(TransferRejectionV1::new(permanent, None).is_ok());
        }
    }

    /// Submission and resolution are the two halves of observing a transfer,
    /// and both must survive the wire for a refusal after spooling to be
    /// visible at all.
    #[test]
    fn transfer_requests_and_their_receipt_round_trip_on_the_wire() {
        let submit = RpcRequest::SubmitAuthorizedTransfer { envelope: vec![9_u8; 512] };
        assert_eq!(decode_envelope::<RpcRequest>(&encode_envelope(&submit).unwrap()), Ok(submit));

        let resolve = RpcRequest::ResolveTransfer { reference: digest(7) };
        assert_eq!(decode_envelope::<RpcRequest>(&encode_envelope(&resolve).unwrap()), Ok(resolve));

        let receipt =
            TransferReceiptV1::new(digest(7), TransferState::Pending, None, None, None, None)
                .unwrap();
        let response = RpcResponse::TransferReceipt(receipt);
        assert_eq!(
            decode_envelope::<RpcResponse>(&encode_envelope(&response).unwrap()),
            Ok(response)
        );
    }

    /// The size bound exists so an oversized submission is refused before any
    /// signature is verified, since verification is what an attacker would
    /// want to make the node pay for.
    #[test]
    fn an_oversized_transfer_envelope_is_refused_before_verification() {
        let oversized = RpcRequest::SubmitAuthorizedTransfer {
            envelope: vec![0_u8; MAX_TRANSFER_ENVELOPE_LENGTH + 1],
        };
        assert!(
            encode_envelope(&oversized).is_err(),
            "an envelope past the bound must not even encode"
        );
    }

    #[test]
    fn faucet_contract_round_trips_and_requires_finalized_evidence() {
        let terms = FaucetTermsV1::new(
            ChainId::new(digest(1)),
            digest(2),
            3,
            10_000,
            1_000,
            60,
            2,
            60,
            2,
            60,
            100,
            FaucetChallengeKind::ProofOfWork,
            12,
        )
        .unwrap();
        assert_eq!(decode_envelope::<FaucetTermsV1>(&encode_envelope(&terms).unwrap()), Ok(terms));
        let request = FaucetRequestV1::new(
            ChainId::new(digest(1)),
            digest(2),
            PrincipalId::new(digest(3)),
            digest(4),
            digest(5),
            9,
            vec![5, 6],
        )
        .unwrap();
        let wire = encode_envelope(&request).unwrap();
        assert_eq!(decode_envelope::<FaucetRequestV1>(&wire), Ok(request.clone()));
        let reference = request.settlement_reference().unwrap();
        assert_ne!(reference, Digest384::ZERO);
        assert_eq!(request.settlement_reference(), Ok(reference));
        let substituted = FaucetRequestV1::new(
            request.chain_id(),
            request.genesis_commitment(),
            request.recipient(),
            digest(40),
            request.source_commitment(),
            request.challenge_nonce(),
            request.challenge_evidence().to_vec(),
        )
        .unwrap();
        assert_ne!(substituted.settlement_reference().unwrap(), reference);

        let pending = FaucetReceiptV1::new(
            digest(7),
            PrincipalId::new(digest(3)),
            1_000,
            FaucetState::Pending,
            Some(TransactionId::new(digest(8))),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let response = RpcResponse::FaucetReceipt(pending);
        assert_eq!(
            decode_envelope::<RpcResponse>(&encode_envelope(&response).unwrap()),
            Ok(response)
        );
        assert!(
            FaucetReceiptV1::new(
                digest(7),
                PrincipalId::new(digest(3)),
                1_000,
                FaucetState::Finalized,
                Some(TransactionId::new(digest(8))),
                Some(12),
                Some(digest(9)),
                Vec::new(),
            )
            .is_err()
        );
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
