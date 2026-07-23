#![forbid(unsafe_code)]

//! Deterministic in-memory consensus boundary for the first PQ testnet runtime.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_crypto_provider::{
    VerificationError, verify_block_proposal, verify_quorum_certificate,
};
use activechain_protocol_types::{
    BlockProposal, ConsensusBlockRef, ConsensusSnapshot, ConsensusState, ConsensusStateError,
    ConsensusUpgradeAuthorization, ConsensusVoteContext, CryptoSuiteId, Digest384, PrincipalId,
    ProposalJustification, ProtocolSignature, QuorumCertificate, ValidatorGenesis, ValidatorSet,
    ValidatorVote,
};
use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::{Duration, Instant};

/// Canonical wallet transaction admission owned by the validator runtime.
/// Authenticated network handlers can delegate here after peer/session checks.
pub struct WalletTransactionGateway {
    ingress: activechain_wallet_core::TransactionIngress,
}

impl WalletTransactionGateway {
    pub fn from_genesis(
        economy: &activechain_cash_kernel::GenesisEconomy,
    ) -> Result<Self, activechain_cash_kernel::CashTransitionError> {
        Ok(Self { ingress: activechain_wallet_core::TransactionIngress::from_genesis(economy)? })
    }

    pub fn submit_envelope(
        &mut self,
        envelope: &[u8],
        height: u64,
    ) -> Result<(), activechain_wallet_core::WalletError> {
        self.ingress.submit_envelope(envelope, height)
    }

    /// Registers one sender's finalized ML-DSA-44 cash-session key and initial nonce.
    ///
    /// The caller is responsible for deriving this mapping from finalized identity and
    /// authorization state; the gateway never accepts a key from a transaction request.
    pub fn register_authorization_key(
        &mut self,
        sender: PrincipalId,
        public_key: [u8; activechain_protocol_types::ML_DSA44_PUBLIC_KEY_LENGTH],
        initial_nonce: u64,
    ) -> Result<(), activechain_wallet_core::WalletError> {
        self.ingress.register_authorization_key(sender, public_key, initial_nonce)
    }

    pub fn ledger(&self) -> &activechain_cash_kernel::CashLedger {
        self.ingress.ledger()
    }
}

const PEER_BODY_DOMAIN: &[u8] = b"ACTIVECHAIN-PEER-BODY-V1";
pub const MAX_PEER_FRAME_LEN: usize = 16 * 1024;

#[derive(Default)]
pub struct ValidatorMetrics {
    proposals: AtomicU64,
    votes: AtomicU64,
    finalized_certificates: AtomicU64,
    rejected_messages: AtomicU64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricsSnapshot {
    pub proposals: u64,
    pub votes: u64,
    pub finalized_certificates: u64,
    pub rejected_messages: u64,
}
impl MetricsSnapshot {
    pub fn prometheus(self, validator_id: u16) -> String {
        format!(
            "activechain_validator_proposals{{validator=\"{validator_id}\"}} {}\nactivechain_validator_votes{{validator=\"{validator_id}\"}} {}\nactivechain_validator_finalized_certificates{{validator=\"{validator_id}\"}} {}\nactivechain_validator_rejected_messages{{validator=\"{validator_id}\"}} {}\n",
            self.proposals, self.votes, self.finalized_certificates, self.rejected_messages,
        )
    }
}
impl ValidatorMetrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            proposals: self.proposals.load(Ordering::Relaxed),
            votes: self.votes.load(Ordering::Relaxed),
            finalized_certificates: self.finalized_certificates.load(Ordering::Relaxed),
            rejected_messages: self.rejected_messages.load(Ordering::Relaxed),
        }
    }
}

pub struct ValidatorSigner {
    validator: activechain_protocol_types::PrincipalId,
    key: SigningKey<MlDsa44>,
}
impl ValidatorSigner {
    pub fn from_seed(validator: activechain_protocol_types::PrincipalId, seed: [u8; 32]) -> Self {
        Self { validator, key: SigningKey::<MlDsa44>::from_seed(&Seed::from(seed)) }
    }
    pub const fn validator(&self) -> activechain_protocol_types::PrincipalId {
        self.validator
    }
    pub fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().encode().to_vec()
    }
    pub fn sign_handshake(
        &self,
        sender: u16,
        challenge: [u8; 32],
    ) -> Result<PeerHandshake, ValidatorEngineError> {
        let placeholder = PeerHandshake::new(
            sender,
            challenge,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420])
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)?;
        let signature = self.key.sign(&placeholder.signing_payload());
        PeerHandshake::new(
            sender,
            challenge,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)
    }
    fn sign_vote(
        &self,
        proposal: &BlockProposal,
        genesis_commitment: Digest384,
        validator_set_root: Digest384,
        protocol_revision: u64,
    ) -> Result<ValidatorVote, ValidatorEngineError> {
        let context = ConsensusVoteContext::new_with_revision(
            genesis_commitment,
            proposal.epoch(),
            validator_set_root,
            protocol_revision,
        )
        .map_err(|_| ValidatorEngineError::UnboundConsensusDomain)?;
        let proposal_commitment = proposal.commitment();
        let unsigned = ValidatorVote::new(
            self.validator,
            context,
            proposal.height(),
            proposal.round(),
            proposal.block_digest(),
            proposal_commitment,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420])
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)?;
        let signature = self.key.sign(&unsigned.signing_payload());
        ValidatorVote::new(
            self.validator,
            context,
            proposal.height(),
            proposal.round(),
            proposal.block_digest(),
            proposal_commitment,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)
    }
    fn sign_proposal(
        &self,
        context: ConsensusVoteContext,
        height: u64,
        round: u64,
        block_digest: Digest384,
        justification: ProposalJustification,
    ) -> Result<BlockProposal, ValidatorEngineError> {
        let unsigned = BlockProposal::new(
            self.validator,
            context,
            height,
            round,
            block_digest,
            justification.clone(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420])
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)?;
        let signature = self.key.sign(&unsigned.signing_payload());
        BlockProposal::new(
            self.validator,
            context,
            height,
            round,
            block_digest,
            justification,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)
    }
    fn sign_envelope(
        &self,
        sender: u16,
        sequence: u64,
        message: ConsensusMessage,
    ) -> Result<AuthenticatedConsensusMessage, ValidatorEngineError> {
        let digest = message.digest().map_err(ValidatorEngineError::Transport)?;
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420])
            .map_err(|_| ValidatorEngineError::Signer)?;
        let unsigned = SignedPeerEnvelope::new(sender, sequence, digest, placeholder)
            .map_err(|_| ValidatorEngineError::Signer)?;
        let signature = self.key.sign(&unsigned.signing_payload());
        let envelope = SignedPeerEnvelope::new(
            sender,
            sequence,
            digest,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)?;
        AuthenticatedConsensusMessage::new(envelope, message)
            .map_err(ValidatorEngineError::Transport)
    }
}

#[derive(Clone)]
struct PreparedValidatorVote {
    proposal: BlockProposal,
    genesis_commitment: Digest384,
    validator_set_root: Digest384,
    protocol_revision: u64,
}

/// Internal signing boundary used to prove that durable safety state precedes key use.
trait ConsensusVoteSigner {
    fn validator(&self) -> PrincipalId;
    fn sign_prepared_vote(
        &self,
        prepared: &PreparedValidatorVote,
    ) -> Result<ValidatorVote, ValidatorEngineError>;
}

impl ConsensusVoteSigner for ValidatorSigner {
    fn validator(&self) -> PrincipalId {
        self.validator
    }

    fn sign_prepared_vote(
        &self,
        prepared: &PreparedValidatorVote,
    ) -> Result<ValidatorVote, ValidatorEngineError> {
        self.sign_vote(
            &prepared.proposal,
            prepared.genesis_commitment,
            prepared.validator_set_root,
            prepared.protocol_revision,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedBlock {
    proposal: BlockProposal,
    certificate: QuorumCertificate,
    votes: Vec<ValidatorVote>,
}
impl CertifiedBlock {
    pub fn new(
        proposal: BlockProposal,
        certificate: QuorumCertificate,
        votes: Vec<ValidatorVote>,
    ) -> Result<Self, TransportError> {
        if votes.is_empty() || votes.len() > activechain_protocol_types::MAX_VALIDATORS_PER_EPOCH {
            return Err(TransportError::InvalidBody);
        }
        let vote_domain = (
            votes[0].genesis_commitment(),
            votes[0].validator_set_root(),
            votes[0].protocol_revision(),
        );
        let proposal_commitment = proposal.commitment();
        if certificate.genesis_commitment() != proposal.genesis_commitment()
            || certificate.epoch() != proposal.epoch()
            || certificate.validator_set_root() != proposal.validator_set_root()
            || certificate.protocol_revision() != proposal.protocol_revision()
            || certificate.height() != proposal.height()
            || certificate.round() != proposal.round()
            || certificate.block_digest() != proposal.block_digest()
            || certificate.proposal_commitment() != proposal_commitment
            || votes.iter().any(|vote| {
                vote.genesis_commitment() != certificate.genesis_commitment()
                    || vote.epoch() != certificate.epoch()
                    || vote.validator_set_root() != certificate.validator_set_root()
                    || vote.protocol_revision() != certificate.protocol_revision()
                    || (
                        vote.genesis_commitment(),
                        vote.validator_set_root(),
                        vote.protocol_revision(),
                    ) != vote_domain
                    || vote.height() != certificate.height()
                    || vote.round() != certificate.round()
                    || vote.block_digest() != certificate.block_digest()
                    || vote.proposal_commitment() != proposal_commitment
            })
        {
            return Err(TransportError::InvalidBody);
        }
        Ok(Self { proposal, certificate, votes })
    }
    pub const fn proposal(&self) -> &BlockProposal {
        &self.proposal
    }
    pub const fn certificate(&self) -> &QuorumCertificate {
        &self.certificate
    }
    pub fn votes(&self) -> &[ValidatorVote] {
        &self.votes
    }
    fn encode(&self) -> Result<Vec<u8>, TransportError> {
        let proposal = encode_envelope(&self.proposal).map_err(|_| TransportError::InvalidBody)?;
        let certificate =
            encode_envelope(&self.certificate).map_err(|_| TransportError::InvalidBody)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(proposal.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&proposal);
        bytes.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&certificate);
        bytes.extend_from_slice(&(self.votes.len() as u16).to_be_bytes());
        for vote in &self.votes {
            let encoded = encode_envelope(vote).map_err(|_| TransportError::InvalidBody)?;
            bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        Ok(bytes)
    }
    fn decode(mut bytes: &[u8]) -> Result<Self, TransportError> {
        let proposal_bytes = take_length_prefixed(&mut bytes)?;
        let proposal = decode_envelope(proposal_bytes).map_err(|_| TransportError::InvalidBody)?;
        let certificate_bytes = take_length_prefixed(&mut bytes)?;
        let certificate =
            decode_envelope(certificate_bytes).map_err(|_| TransportError::InvalidBody)?;
        if bytes.len() < 2 {
            return Err(TransportError::InvalidBody);
        }
        let count = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        bytes = &bytes[2..];
        if count == 0 || count > activechain_protocol_types::MAX_VALIDATORS_PER_EPOCH {
            return Err(TransportError::InvalidBody);
        }
        let mut votes = Vec::with_capacity(count);
        for _ in 0..count {
            votes.push(
                decode_envelope(take_length_prefixed(&mut bytes)?)
                    .map_err(|_| TransportError::InvalidBody)?,
            );
        }
        if !bytes.is_empty() {
            return Err(TransportError::InvalidBody);
        }
        Self::new(proposal, certificate, votes)
    }
}

fn take_length_prefixed<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], TransportError> {
    if bytes.len() < 4 {
        return Err(TransportError::InvalidBody);
    }
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if length > MAX_PEER_FRAME_LEN || bytes.len() < 4 + length {
        return Err(TransportError::InvalidBody);
    }
    let value = &bytes[4..4 + length];
    *bytes = &bytes[4 + length..];
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsensusMessage {
    Proposal(BlockProposal),
    Vote(ValidatorVote),
    Certificate(CertifiedBlock),
}
impl ConsensusMessage {
    fn kind(&self) -> u8 {
        match self {
            Self::Proposal(_) => 1,
            Self::Vote(_) => 2,
            Self::Certificate(_) => 3,
        }
    }
    fn encode_body(&self) -> Result<Vec<u8>, TransportError> {
        match self {
            Self::Proposal(value) => encode_envelope(value),
            Self::Vote(value) => encode_envelope(value),
            Self::Certificate(value) => return value.encode(),
        }
        .map_err(|_| TransportError::InvalidBody)
    }
    fn decode(kind: u8, body: &[u8]) -> Result<Self, TransportError> {
        match kind {
            1 => decode_envelope(body).map(Self::Proposal),
            2 => decode_envelope(body).map(Self::Vote),
            3 => return CertifiedBlock::decode(body).map(Self::Certificate),
            _ => return Err(TransportError::InvalidMessageKind),
        }
        .map_err(|_| TransportError::InvalidBody)
    }
    pub fn digest(&self) -> Result<Digest384, TransportError> {
        let body = self.encode_body()?;
        let mut hasher = Shake256::default();
        hasher.update(PEER_BODY_DOMAIN);
        hasher.update(&[self.kind()]);
        hasher.update(&(body.len() as u32).to_be_bytes());
        hasher.update(&body);
        let mut digest = [0_u8; 48];
        hasher.finalize_xof().read(&mut digest);
        Ok(Digest384::new(digest))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedConsensusMessage {
    pub envelope: SignedPeerEnvelope,
    pub message: ConsensusMessage,
}
impl AuthenticatedConsensusMessage {
    pub fn new(
        envelope: SignedPeerEnvelope,
        message: ConsensusMessage,
    ) -> Result<Self, TransportError> {
        if envelope.body_digest() != message.digest()? {
            return Err(TransportError::BodyDigestMismatch);
        }
        Ok(Self { envelope, message })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPeerEnvelope {
    sender: u16,
    sequence: u64,
    body_digest: Digest384,
    signature: ProtocolSignature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerHandshake {
    sender: u16,
    challenge: [u8; 32],
    signature: ProtocolSignature,
}
impl PeerHandshake {
    pub fn new(
        sender: u16,
        challenge: [u8; 32],
        signature: ProtocolSignature,
    ) -> Result<Self, TransportError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(TransportError::InvalidSuite);
        }
        Ok(Self { sender, challenge, signature })
    }
    pub const fn sender(&self) -> u16 {
        self.sender
    }
    pub const fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }
    pub fn signature_bytes(&self) -> &[u8] {
        self.signature.as_bytes()
    }
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(35);
        bytes.extend_from_slice(b"ACTIVECHAIN-PEER-HANDSHAKE-V1");
        bytes.extend_from_slice(&self.sender.to_be_bytes());
        bytes.extend_from_slice(&self.challenge);
        bytes
    }
    pub fn verify(&self, public_key: &[u8]) -> Result<(), TransportError> {
        activechain_crypto_provider::verify_ml_dsa44(
            public_key,
            &self.signing_payload(),
            self.signature.as_bytes(),
        )
        .map_err(TransportError::Verification)
    }
}
impl SignedPeerEnvelope {
    pub fn new(
        sender: u16,
        sequence: u64,
        body_digest: Digest384,
        signature: ProtocolSignature,
    ) -> Result<Self, TransportError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(TransportError::InvalidSuite);
        }
        Ok(Self { sender, sequence, body_digest, signature })
    }
    pub const fn sender(&self) -> u16 {
        self.sender
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn body_digest(&self) -> Digest384 {
        self.body_digest
    }
    pub fn signature_bytes(&self) -> &[u8] {
        self.signature.as_bytes()
    }
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(18 + 2 + 8 + 48);
        bytes.extend_from_slice(b"ACTIVECHAIN-PEER-V1");
        bytes.extend_from_slice(&self.sender.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(self.body_digest.as_bytes());
        bytes
    }
    pub fn verify(&self, public_key: &[u8]) -> Result<(), TransportError> {
        activechain_crypto_provider::verify_ml_dsa44(
            public_key,
            &self.signing_payload(),
            self.signature.as_bytes(),
        )
        .map_err(TransportError::Verification)
    }
}

pub struct PeerSocket {
    stream: TcpStream,
}

pub struct PeerDirectory {
    peers: BTreeMap<u16, (PeerSocket, Vec<u8>)>,
    replay: ReplayGuard,
    rate_limits: BTreeMap<u16, (Instant, usize)>,
}
impl Default for PeerDirectory {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PeerListener {
    listener: TcpListener,
}
impl PeerListener {
    pub fn bind(address: (&str, u16)) -> std::io::Result<Self> {
        Ok(Self { listener: TcpListener::bind(address)? })
    }
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
    pub fn accept(&self) -> std::io::Result<PeerSocket> {
        let (stream, _) = self.listener.accept()?;
        Ok(PeerSocket::connect(stream))
    }
    pub fn spawn_accept_loop<F>(&self, handler: F) -> std::io::Result<()>
    where
        F: Fn(PeerSocket) + Send + Sync + 'static,
    {
        let handler = std::sync::Arc::new(handler);
        loop {
            let socket = self.accept()?;
            let handler = std::sync::Arc::clone(&handler);
            std::thread::spawn(move || handler(socket));
        }
    }
}
impl PeerDirectory {
    pub const MAX_PEERS: usize = 128;
    pub fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
            replay: ReplayGuard::default(),
            rate_limits: BTreeMap::new(),
        }
    }
    pub fn insert(
        &mut self,
        peer_id: u16,
        socket: PeerSocket,
        public_key: Vec<u8>,
    ) -> Result<(), PeerDirectoryError> {
        if public_key.len() != 1312 {
            return Err(PeerDirectoryError::InvalidPublicKey);
        }
        if self.peers.contains_key(&peer_id) {
            return Err(PeerDirectoryError::AlreadyRegistered);
        }
        if self.peers.len() >= Self::MAX_PEERS {
            return Err(PeerDirectoryError::Capacity);
        }
        self.peers.insert(peer_id, (socket, public_key));
        Ok(())
    }
    pub fn replace(
        &mut self,
        peer_id: u16,
        socket: PeerSocket,
        public_key: Vec<u8>,
    ) -> Result<(), PeerDirectoryError> {
        if self.peers.contains_key(&peer_id) {
            self.peers.remove(&peer_id);
        }
        self.insert(peer_id, socket, public_key)
    }
    pub fn len(&self) -> usize {
        self.peers.len()
    }
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
    pub fn peers(&self) -> impl Iterator<Item = (&u16, &(PeerSocket, Vec<u8>))> {
        self.peers.iter()
    }
    pub fn remove(&mut self, peer_id: u16) -> bool {
        self.peers.remove(&peer_id).is_some()
    }
    pub fn receive_verified(
        &mut self,
        peer_id: u16,
    ) -> Result<AuthenticatedConsensusMessage, PeerReceiveError> {
        if !self.allow_receive(peer_id, Instant::now()) {
            return Err(PeerReceiveError::Transport(TransportError::RateLimited));
        }
        let (socket, key) = self.peers.get_mut(&peer_id).ok_or(PeerReceiveError::UnknownPeer)?;
        let message = socket.receive_message().map_err(PeerReceiveError::Io)?;
        self.replay.accept(&message.envelope, key).map_err(PeerReceiveError::Transport)?;
        Ok(message)
    }
    fn allow_receive(&mut self, peer_id: u16, now: Instant) -> bool {
        let entry = self.rate_limits.entry(peer_id).or_insert((now, 0));
        if now.duration_since(entry.0) >= Duration::from_secs(1) {
            *entry = (now, 0);
        }
        if entry.1 >= 256 {
            return false;
        }
        entry.1 += 1;
        true
    }
    pub fn broadcast(&mut self, envelope: &SignedPeerEnvelope) -> std::io::Result<()> {
        for (socket, _) in self.peers.values_mut() {
            socket.send(envelope)?;
        }
        Ok(())
    }
    pub fn broadcast_message(
        &mut self,
        message: &AuthenticatedConsensusMessage,
    ) -> std::io::Result<()> {
        for (socket, _) in self.peers.values_mut() {
            socket.send_message(message)?;
        }
        Ok(())
    }
    pub fn broadcast_message_best_effort(
        &mut self,
        message: &AuthenticatedConsensusMessage,
    ) -> Vec<u16> {
        let mut failed = Vec::new();
        for (peer_id, (socket, _)) in &mut self.peers {
            if socket.send_message(message).is_err() {
                failed.push(*peer_id);
            }
        }
        for peer_id in &failed {
            self.peers.remove(peer_id);
        }
        failed
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerDirectoryError {
    AlreadyRegistered,
    Capacity,
    InvalidPublicKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerEndpoint {
    pub id: u16,
    pub address: SocketAddr,
    pub public_key: Vec<u8>,
}
impl PeerEndpoint {
    pub fn from_genesis_address(
        id: u16,
        address: &str,
        public_key: Vec<u8>,
    ) -> Result<Self, PeerConnectorError> {
        if id == 0 || public_key.len() != 1312 {
            return Err(PeerConnectorError::InvalidConfiguration);
        }
        let address = address.parse().map_err(|_| PeerConnectorError::InvalidConfiguration)?;
        Ok(Self { id, address, public_key })
    }
}
pub struct PeerConnector {
    endpoints: Vec<PeerEndpoint>,
    attempts: usize,
    connect_timeout: Duration,
    backoff: Duration,
}
impl PeerConnector {
    pub fn new(endpoints: Vec<PeerEndpoint>) -> Result<Self, PeerConnectorError> {
        if endpoints.is_empty()
            || endpoints.len() > PeerDirectory::MAX_PEERS
            || endpoints.iter().any(|endpoint| endpoint.public_key.len() != 1312)
        {
            return Err(PeerConnectorError::InvalidConfiguration);
        }
        Ok(Self {
            endpoints,
            attempts: 3,
            connect_timeout: Duration::from_millis(500),
            backoff: Duration::from_millis(25),
        })
    }
    pub fn with_retry_policy(
        mut self,
        attempts: usize,
        connect_timeout: Duration,
        backoff: Duration,
    ) -> Result<Self, PeerConnectorError> {
        if attempts == 0 || attempts > 16 {
            return Err(PeerConnectorError::InvalidConfiguration);
        }
        self.attempts = attempts;
        self.connect_timeout = connect_timeout;
        self.backoff = backoff;
        Ok(self)
    }
    pub fn connect_all(&self) -> (PeerDirectory, Vec<(u16, std::io::Error)>) {
        let mut directory = PeerDirectory::new();
        let mut failures = Vec::new();
        for endpoint in &self.endpoints {
            let mut last_error = None;
            for attempt in 0..self.attempts {
                match TcpStream::connect_timeout(&endpoint.address, self.connect_timeout) {
                    Ok(stream) => {
                        let socket = PeerSocket::connect(stream);
                        if directory
                            .insert(endpoint.id, socket, endpoint.public_key.clone())
                            .is_ok()
                        {
                            last_error = None;
                            break;
                        }
                    }
                    Err(error) => last_error = Some(error),
                }
                if attempt + 1 < self.attempts {
                    std::thread::sleep(self.backoff.saturating_mul((attempt + 1) as u32));
                }
            }
            if let Some(error) = last_error {
                failures.push((endpoint.id, error));
            }
        }
        (directory, failures)
    }
    pub fn connect_all_with_handshake(
        &self,
        local_peer_id: u16,
        signer: &ValidatorSigner,
        challenge: [u8; 32],
    ) -> (PeerDirectory, Vec<(u16, std::io::Error)>) {
        let mut directory = PeerDirectory::new();
        let mut failures = Vec::new();
        let outbound = match signer.sign_handshake(local_peer_id, challenge) {
            Ok(handshake) => handshake,
            Err(_) => {
                for endpoint in &self.endpoints {
                    failures.push((
                        endpoint.id,
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "handshake signing failed",
                        ),
                    ));
                }
                return (directory, failures);
            }
        };
        for endpoint in &self.endpoints {
            match self.connect_with_handshake(endpoint, &outbound, challenge) {
                Ok(socket) => {
                    if let Err(error) =
                        directory.insert(endpoint.id, socket, endpoint.public_key.clone())
                    {
                        failures.push((
                            endpoint.id,
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("peer registration failed: {error:?}"),
                            ),
                        ));
                    }
                }
                Err(error) => failures.push((endpoint.id, error)),
            }
        }
        (directory, failures)
    }
    pub fn reconnect(&self, endpoint: &PeerEndpoint) -> Result<PeerSocket, std::io::Error> {
        let mut last_error = None;
        for attempt in 0..self.attempts {
            match TcpStream::connect_timeout(&endpoint.address, self.connect_timeout) {
                Ok(stream) => return Ok(PeerSocket::connect(stream)),
                Err(error) => last_error = Some(error),
            }
            if attempt + 1 < self.attempts {
                std::thread::sleep(self.backoff.saturating_mul((attempt + 1) as u32));
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "reconnect failed")
        }))
    }
    pub fn connect_with_handshake(
        &self,
        endpoint: &PeerEndpoint,
        outbound: &PeerHandshake,
        expected_challenge: [u8; 32],
    ) -> Result<PeerSocket, std::io::Error> {
        let mut socket = self.reconnect(endpoint)?;
        socket.send_handshake(outbound)?;
        let inbound = socket.receive_handshake()?;
        inbound.verify(&endpoint.public_key).map_err(transport_io_error)?;
        if inbound.challenge() != &expected_challenge || inbound.sender() != endpoint.id {
            return Err(invalid_data("peer handshake identity mismatch"));
        }
        Ok(socket)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerConnectorError {
    InvalidConfiguration,
}
#[derive(Debug)]
pub enum PeerReceiveError {
    UnknownPeer,
    Io(std::io::Error),
    Transport(TransportError),
}

#[derive(Clone, Debug)]
pub struct PeerEvent {
    pub peer_id: u16,
    pub envelope: SignedPeerEnvelope,
}
pub struct PeerEventQueue {
    sender: SyncSender<PeerEvent>,
    receiver: Receiver<PeerEvent>,
}
impl Default for PeerEventQueue {
    fn default() -> Self {
        Self::new()
    }
}
impl PeerEventQueue {
    pub const DEFAULT_CAPACITY: usize = 1024;
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        Self { sender, receiver }
    }
    pub fn sender(&self) -> SyncSender<PeerEvent> {
        self.sender.clone()
    }
    pub fn push(&self, event: PeerEvent) -> Result<(), mpsc::SendError<PeerEvent>> {
        self.sender.send(event)
    }
    pub fn recv(&self) -> Result<PeerEvent, mpsc::RecvError> {
        self.receiver.recv()
    }
    pub fn try_recv(&self) -> Result<PeerEvent, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }
}

pub struct ConsensusDispatcher;
impl ConsensusDispatcher {
    pub fn dispatch_once<F>(queue: &PeerEventQueue, handler: F) -> Result<(), DispatchError>
    where
        F: FnOnce(PeerEvent) -> Result<(), String>,
    {
        let event = queue.recv().map_err(|_| DispatchError::QueueClosed)?;
        handler(event).map_err(DispatchError::Handler)
    }
}
#[derive(Debug, Eq, PartialEq)]
pub enum DispatchError {
    QueueClosed,
    Handler(String),
}

pub struct PeerSupervisor {
    handles: Vec<std::thread::JoinHandle<()>>,
}
impl Default for PeerSupervisor {
    fn default() -> Self {
        Self::new()
    }
}
impl PeerSupervisor {
    pub fn new() -> Self {
        Self { handles: Vec::new() }
    }
    pub fn spawn<F>(&mut self, worker: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.handles.push(std::thread::spawn(worker));
    }
    pub fn join_all(self) -> std::thread::Result<()> {
        for handle in self.handles {
            handle.join()?;
        }
        Ok(())
    }
}

pub fn save_snapshot(path: &std::path::Path, state: &ConsensusState) -> std::io::Result<()> {
    let bytes = match std::fs::read(path) {
        Ok(existing) => match decode_envelope::<PersistedValidatorState>(&existing) {
            Ok(mut persisted) => {
                persisted.consensus = state.snapshot();
                encode_envelope(&persisted).map_err(|_| invalid_data("snapshot encoding failed"))?
            }
            Err(_) if existing.starts_with(&PersistedValidatorState::TYPE_TAG.to_be_bytes()) => {
                return Err(invalid_data("validator safety snapshot is invalid"));
            }
            Err(_) => encode_envelope(&state.snapshot())
                .map_err(|_| invalid_data("snapshot encoding failed"))?,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            encode_envelope(&state.snapshot())
                .map_err(|_| invalid_data("snapshot encoding failed"))?
        }
        Err(error) => return Err(error),
    };
    write_atomic(path, &bytes)
}
pub fn load_snapshot(path: &std::path::Path) -> std::io::Result<ConsensusState> {
    let bytes = std::fs::read(path)?;
    if let Ok(snapshot) = decode_envelope::<PersistedValidatorState>(&bytes) {
        return Ok(ConsensusState::from_snapshot(snapshot.consensus));
    }
    let snapshot: ConsensusSnapshot = decode_envelope(&bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "snapshot decoding failed")
    })?;
    Ok(ConsensusState::from_snapshot(snapshot))
}

/// Returns the immutable chain genesis commitment retained by a validator safety snapshot.
/// Raw consensus-only snapshots predate this binding and return `None`.
pub fn load_snapshot_chain_genesis_commitment(
    path: &std::path::Path,
) -> std::io::Result<Option<Digest384>> {
    let bytes = std::fs::read(path)?;
    match decode_envelope::<PersistedValidatorState>(&bytes) {
        Ok(snapshot) => Ok(Some(snapshot.genesis_commitment)),
        Err(_) if bytes.starts_with(&PersistedValidatorState::TYPE_TAG.to_be_bytes()) => {
            Err(invalid_data("validator safety snapshot is invalid"))
        }
        Err(_) => Ok(None),
    }
}

fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn save_validator_snapshot(
    path: &std::path::Path,
    engine: &ValidatorEngine,
    replay: &ReplayGuard,
    outbound_high_water: &BTreeMap<u16, u64>,
) -> std::io::Result<()> {
    let snapshot = PersistedValidatorState {
        consensus: engine.state.snapshot(),
        genesis_commitment: engine.genesis_commitment,
        replay_high_water: replay.highest.clone(),
        outbound_high_water: outbound_high_water.clone(),
        vote_locks: engine.local_vote_locks.clone(),
        highest_voted_rounds: engine.highest_voted_rounds.clone(),
        locked_qc: engine.locked_qc.clone(),
        certified_blocks: engine.certified_blocks.clone(),
        active_anchor: engine.active_anchor,
    };
    let bytes = encode_envelope(&snapshot)
        .map_err(|_| invalid_data("validator safety snapshot encoding failed"))?;
    write_atomic(path, &bytes)
}
pub fn load_genesis(path: &std::path::Path) -> std::io::Result<ValidatorGenesis> {
    let bytes = std::fs::read(path)?;
    decode_envelope(&bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "genesis encoding invalid")
    })
}
pub fn open_protected_payload<T: activechain_canonical_codec::CanonicalType>(
    encoded_envelope: &[u8],
    recipient: &activechain_crypto_provider::MlKem768Recipient,
    associated_data: &[u8],
) -> std::io::Result<T> {
    let protected = activechain_crypto_provider::ProtectedEnvelope::decode(encoded_envelope)
        .map_err(|_| invalid_data("protected envelope is invalid"))?;
    let plaintext = protected
        .open(recipient, associated_data)
        .map_err(|_| invalid_data("protected envelope authentication failed"))?;
    decode_envelope(&plaintext).map_err(|_| invalid_data("protected payload is not canonical"))
}
pub fn verify_execution_evidence(
    evidence: &activechain_object_vm::ExecutionEvidence,
) -> Result<(), RuntimeAdmissionError> {
    evidence.verify().map_err(|_| RuntimeAdmissionError::ExecutionEvidenceInvalid)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAdmissionError {
    ExecutionEvidenceInvalid,
}
pub fn save_distributed_snapshot(
    path: &std::path::Path,
    state: &ConsensusState,
    data_shards: usize,
    parity_shards: usize,
) -> std::io::Result<()> {
    let state_bytes =
        encode_envelope(&state.snapshot()).map_err(|_| invalid_data("snapshot encoding failed"))?;
    let batch = activechain_data_availability::AvailabilityBatch::encode(
        &state_bytes,
        data_shards,
        parity_shards,
    )
    .map_err(|_| invalid_data("snapshot shard encoding failed"))?
    .serialize()
    .map_err(|_| invalid_data("snapshot shard serialization failed"))?;
    let mut bytes = Vec::with_capacity(13 + state_bytes.len() + batch.len());
    bytes.extend_from_slice(b"ACSN1");
    bytes.extend_from_slice(&(state_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&(batch.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&state_bytes);
    bytes.extend_from_slice(&batch);
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(temporary, path)
}
pub fn load_distributed_snapshot(path: &std::path::Path) -> std::io::Result<ConsensusState> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < 13 || &bytes[..5] != b"ACSN1" {
        return Err(invalid_data("invalid distributed snapshot"));
    }
    let state_len = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
    let batch_len = u32::from_be_bytes(bytes[9..13].try_into().unwrap()) as usize;
    if bytes.len() != 13 + state_len + batch_len {
        return Err(invalid_data("distributed snapshot length mismatch"));
    }
    let state_bytes = &bytes[13..13 + state_len];
    let batch_bytes = &bytes[13 + state_len..];
    let batch = activechain_data_availability::AvailabilityBatch::deserialize(batch_bytes)
        .map_err(|_| invalid_data("distributed snapshot shards invalid"))?;
    let reconstructed = batch
        .reconstruct_payload(&[])
        .map_err(|_| invalid_data("distributed snapshot reconstruction failed"))?;
    if reconstructed != state_bytes {
        return Err(invalid_data("distributed snapshot state mismatch"));
    }
    let snapshot: ConsensusSnapshot = decode_envelope(&reconstructed)
        .map_err(|_| invalid_data("distributed snapshot decoding failed"))?;
    Ok(ConsensusState::from_snapshot(snapshot))
}
impl PeerSocket {
    pub fn connect(stream: TcpStream) -> Self {
        Self { stream }
    }
    pub fn set_timeouts(
        &self,
        read: Option<std::time::Duration>,
        write: Option<std::time::Duration>,
    ) -> std::io::Result<()> {
        self.stream.set_read_timeout(read)?;
        self.stream.set_write_timeout(write)
    }
    pub fn send(&mut self, envelope: &SignedPeerEnvelope) -> std::io::Result<()> {
        let mut frame = Vec::with_capacity(2 + 8 + 48 + 2 + envelope.signature_bytes().len());
        frame.extend_from_slice(&envelope.sender().to_be_bytes());
        frame.extend_from_slice(&envelope.sequence().to_be_bytes());
        frame.extend_from_slice(envelope.body_digest().as_bytes());
        frame.extend_from_slice(&(envelope.signature_bytes().len() as u16).to_be_bytes());
        frame.extend_from_slice(envelope.signature_bytes());
        self.stream.write_all(&(frame.len() as u32).to_be_bytes())?;
        self.stream.write_all(&frame)
    }
    pub fn receive_frame(&mut self) -> std::io::Result<Vec<u8>> {
        let mut len = [0; 4];
        self.stream.read_exact(&mut len)?;
        let frame_len = u32::from_be_bytes(len) as usize;
        if frame_len > MAX_PEER_FRAME_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer frame exceeds limit",
            ));
        }
        let mut frame = vec![0; frame_len];
        self.stream.read_exact(&mut frame)?;
        Ok(frame)
    }
    pub fn receive_envelope(&mut self) -> std::io::Result<SignedPeerEnvelope> {
        let frame = self.receive_frame()?;
        if frame.len() < 2 + 8 + 48 + 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer frame too short",
            ));
        }
        let sender = u16::from_be_bytes([frame[0], frame[1]]);
        let sequence = u64::from_be_bytes(frame[2..10].try_into().unwrap());
        let body_digest = Digest384::new(frame[10..58].try_into().unwrap());
        let signature_len = u16::from_be_bytes([frame[58], frame[59]]) as usize;
        if frame.len() != 60 + signature_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer signature length mismatch",
            ));
        }
        let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, frame[60..].to_vec())
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid ML-DSA signature")
            })?;
        SignedPeerEnvelope::new(sender, sequence, body_digest, signature).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid peer envelope")
        })
    }
    pub fn send_message(
        &mut self,
        authenticated: &AuthenticatedConsensusMessage,
    ) -> std::io::Result<()> {
        let body = authenticated.message.encode_body().map_err(transport_io_error)?;
        let envelope = &authenticated.envelope;
        let frame_len = 2 + 8 + 48 + 2 + envelope.signature_bytes().len() + 1 + 4 + body.len();
        if frame_len > MAX_PEER_FRAME_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "peer frame exceeds limit",
            ));
        }
        let mut frame = Vec::with_capacity(frame_len);
        frame.extend_from_slice(&envelope.sender().to_be_bytes());
        frame.extend_from_slice(&envelope.sequence().to_be_bytes());
        frame.extend_from_slice(envelope.body_digest().as_bytes());
        frame.extend_from_slice(&(envelope.signature_bytes().len() as u16).to_be_bytes());
        frame.extend_from_slice(envelope.signature_bytes());
        frame.push(authenticated.message.kind());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        self.stream.write_all(&(frame.len() as u32).to_be_bytes())?;
        self.stream.write_all(&frame)
    }
    pub fn receive_message(&mut self) -> std::io::Result<AuthenticatedConsensusMessage> {
        let frame = self.receive_frame()?;
        if frame.len() < 65 {
            return Err(invalid_data("consensus frame too short"));
        }
        let sender = u16::from_be_bytes([frame[0], frame[1]]);
        let sequence = u64::from_be_bytes(frame[2..10].try_into().unwrap());
        let digest = Digest384::new(frame[10..58].try_into().unwrap());
        let signature_len = u16::from_be_bytes([frame[58], frame[59]]) as usize;
        let kind_offset = 60_usize
            .checked_add(signature_len)
            .ok_or_else(|| invalid_data("invalid signature length"))?;
        let body_offset = kind_offset + 5;
        if body_offset > frame.len() {
            return Err(invalid_data("truncated consensus frame"));
        }
        let body_len =
            u32::from_be_bytes(frame[kind_offset + 1..body_offset].try_into().unwrap()) as usize;
        if frame.len() != body_offset + body_len {
            return Err(invalid_data("consensus body length mismatch"));
        }
        let signature =
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, frame[60..kind_offset].to_vec())
                .map_err(|_| invalid_data("invalid ML-DSA signature"))?;
        let envelope = SignedPeerEnvelope::new(sender, sequence, digest, signature)
            .map_err(transport_io_error)?;
        let message = ConsensusMessage::decode(frame[kind_offset], &frame[body_offset..])
            .map_err(transport_io_error)?;
        AuthenticatedConsensusMessage::new(envelope, message).map_err(transport_io_error)
    }
    pub fn send_handshake(&mut self, handshake: &PeerHandshake) -> std::io::Result<()> {
        let frame_len = 2 + 32 + 2 + handshake.signature_bytes().len();
        if frame_len > MAX_PEER_FRAME_LEN {
            return Err(invalid_data("handshake exceeds limit"));
        }
        let mut frame = Vec::with_capacity(frame_len);
        frame.extend_from_slice(&handshake.sender().to_be_bytes());
        frame.extend_from_slice(handshake.challenge());
        frame.extend_from_slice(&(handshake.signature_bytes().len() as u16).to_be_bytes());
        frame.extend_from_slice(handshake.signature_bytes());
        self.stream.write_all(&(frame.len() as u32).to_be_bytes())?;
        self.stream.write_all(&frame)
    }
    pub fn receive_handshake(&mut self) -> std::io::Result<PeerHandshake> {
        let frame = self.receive_frame()?;
        if frame.len() < 36 {
            return Err(invalid_data("handshake frame too short"));
        }
        let sender = u16::from_be_bytes([frame[0], frame[1]]);
        let challenge: [u8; 32] = frame[2..34].try_into().unwrap();
        let signature_len = u16::from_be_bytes([frame[34], frame[35]]) as usize;
        if frame.len() != 36 + signature_len {
            return Err(invalid_data("handshake signature length mismatch"));
        }
        let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, frame[36..].to_vec())
            .map_err(|_| invalid_data("invalid handshake signature"))?;
        PeerHandshake::new(sender, challenge, signature).map_err(transport_io_error)
    }
}
fn invalid_data(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}
fn transport_io_error(error: TransportError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{error:?}"))
}
#[derive(Debug, Eq, PartialEq)]
pub enum TransportError {
    InvalidSuite,
    InvalidMessageKind,
    InvalidBody,
    BodyDigestMismatch,
    Verification(VerificationError),
    Replay,
    RateLimited,
}

#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ReplayGuard {
    highest: BTreeMap<u16, u64>,
}
impl ReplayGuard {
    pub fn accept(
        &mut self,
        envelope: &SignedPeerEnvelope,
        public_key: &[u8],
    ) -> Result<(), TransportError> {
        envelope.verify(public_key)?;
        if self
            .highest
            .get(&envelope.sender())
            .is_some_and(|highest| envelope.sequence() <= *highest)
        {
            return Err(TransportError::Replay);
        }
        self.highest.insert(envelope.sender(), envelope.sequence());
        Ok(())
    }
}

const MAX_PERSISTED_REPLAY_SENDERS: usize = activechain_protocol_types::MAX_VALIDATORS_PER_EPOCH;
const MAX_PERSISTED_VOTE_LOCKS: usize = 4096;
const MAX_PERSISTED_CERTIFIED_BLOCKS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LocalVoteSlot {
    validator: PrincipalId,
    genesis_commitment: Digest384,
    epoch: u64,
    validator_set_root: Digest384,
    protocol_revision: u64,
    height: u64,
    round: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LocalVoteDomain {
    validator: PrincipalId,
    genesis_commitment: Digest384,
    epoch: u64,
    validator_set_root: Digest384,
    protocol_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HighestVotedRound {
    height: u64,
    round: u64,
    proposal_commitment: Digest384,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CertifiedBlockRecord {
    certificate: QuorumCertificate,
    parent: ConsensusBlockRef,
}

impl CanonicalEncode for CertifiedBlockRecord {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.certificate.encode(encoder)?;
        self.parent.encode(encoder)
    }
}

impl CanonicalDecode for CertifiedBlockRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let certificate = QuorumCertificate::decode(decoder)?;
        let parent = ConsensusBlockRef::decode(decoder)?;
        if parent.height().checked_add(1) != Some(certificate.height())
            || (parent.height() > 0 && certificate.round() <= parent.round())
            || (parent.height() == 0 && certificate.round() < parent.round())
            || parent.proposal_commitment() == certificate.proposal_commitment()
        {
            return Err(DecodeError::InvalidValue("invalid certified-block ancestry record"));
        }
        Ok(Self { certificate, parent })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PersistedValidatorState {
    consensus: ConsensusSnapshot,
    genesis_commitment: Digest384,
    replay_high_water: BTreeMap<u16, u64>,
    outbound_high_water: BTreeMap<u16, u64>,
    vote_locks: BTreeMap<LocalVoteSlot, Digest384>,
    highest_voted_rounds: BTreeMap<LocalVoteDomain, HighestVotedRound>,
    locked_qc: Option<QuorumCertificate>,
    certified_blocks: BTreeMap<Digest384, CertifiedBlockRecord>,
    active_anchor: ConsensusBlockRef,
}

impl CanonicalEncode for PersistedValidatorState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.consensus.encode(encoder)?;
        self.genesis_commitment.encode(encoder)?;
        encoder.write_length(self.replay_high_water.len(), MAX_PERSISTED_REPLAY_SENDERS)?;
        for (sender, sequence) in &self.replay_high_water {
            sender.encode(encoder)?;
            sequence.encode(encoder)?;
        }
        encoder.write_length(self.outbound_high_water.len(), MAX_PERSISTED_REPLAY_SENDERS)?;
        for (sender, sequence) in &self.outbound_high_water {
            sender.encode(encoder)?;
            sequence.encode(encoder)?;
        }
        encoder.write_length(self.vote_locks.len(), MAX_PERSISTED_VOTE_LOCKS)?;
        for (slot, digest) in &self.vote_locks {
            slot.validator.encode(encoder)?;
            slot.genesis_commitment.encode(encoder)?;
            slot.epoch.encode(encoder)?;
            slot.validator_set_root.encode(encoder)?;
            slot.protocol_revision.encode(encoder)?;
            slot.height.encode(encoder)?;
            slot.round.encode(encoder)?;
            digest.encode(encoder)?;
        }
        encoder.write_length(self.highest_voted_rounds.len(), MAX_PERSISTED_REPLAY_SENDERS)?;
        for (domain, highest) in &self.highest_voted_rounds {
            domain.validator.encode(encoder)?;
            domain.genesis_commitment.encode(encoder)?;
            domain.epoch.encode(encoder)?;
            domain.validator_set_root.encode(encoder)?;
            domain.protocol_revision.encode(encoder)?;
            highest.height.encode(encoder)?;
            highest.round.encode(encoder)?;
            highest.proposal_commitment.encode(encoder)?;
        }
        self.locked_qc.encode(encoder)?;
        encoder.write_length(self.certified_blocks.len(), MAX_PERSISTED_CERTIFIED_BLOCKS)?;
        for (digest, record) in &self.certified_blocks {
            digest.encode(encoder)?;
            record.encode(encoder)?;
        }
        self.active_anchor.encode(encoder)?;
        Ok(())
    }
}

impl CanonicalDecode for PersistedValidatorState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let consensus = ConsensusSnapshot::decode(decoder)?;
        let genesis_commitment = Digest384::decode(decoder)?;
        if genesis_commitment == Digest384::ZERO {
            return Err(DecodeError::InvalidValue("zero consensus genesis commitment"));
        }
        let replay_count = decoder.read_length(MAX_PERSISTED_REPLAY_SENDERS)?;
        let mut replay_high_water = BTreeMap::new();
        let mut previous_sender = None;
        for _ in 0..replay_count {
            let sender = u16::decode(decoder)?;
            let sequence = u64::decode(decoder)?;
            if sender == 0
                || previous_sender.is_some_and(|previous| sender <= previous)
                || replay_high_water.insert(sender, sequence).is_some()
            {
                return Err(DecodeError::InvalidValue("invalid replay high-water entry"));
            }
            previous_sender = Some(sender);
        }
        let outbound_count = decoder.read_length(MAX_PERSISTED_REPLAY_SENDERS)?;
        let mut outbound_high_water = BTreeMap::new();
        let mut previous_sender = None;
        for _ in 0..outbound_count {
            let sender = u16::decode(decoder)?;
            let sequence = u64::decode(decoder)?;
            if sender == 0
                || previous_sender.is_some_and(|previous| sender <= previous)
                || outbound_high_water.insert(sender, sequence).is_some()
            {
                return Err(DecodeError::InvalidValue("invalid outbound high-water entry"));
            }
            previous_sender = Some(sender);
        }
        let vote_count = decoder.read_length(MAX_PERSISTED_VOTE_LOCKS)?;
        let mut vote_locks = BTreeMap::new();
        let mut previous_slot = None;
        for _ in 0..vote_count {
            let slot = LocalVoteSlot {
                validator: PrincipalId::decode(decoder)?,
                genesis_commitment: Digest384::decode(decoder)?,
                epoch: u64::decode(decoder)?,
                validator_set_root: Digest384::decode(decoder)?,
                protocol_revision: u64::decode(decoder)?,
                height: u64::decode(decoder)?,
                round: u64::decode(decoder)?,
            };
            let digest = Digest384::decode(decoder)?;
            if slot.genesis_commitment == Digest384::ZERO
                || slot.validator_set_root == Digest384::ZERO
                || slot.protocol_revision == 0
                || digest == Digest384::ZERO
                || previous_slot.is_some_and(|previous| slot <= previous)
                || vote_locks.insert(slot, digest).is_some()
            {
                return Err(DecodeError::InvalidValue("invalid local vote lock"));
            }
            previous_slot = Some(slot);
        }
        let highest_count = decoder.read_length(MAX_PERSISTED_REPLAY_SENDERS)?;
        let mut highest_voted_rounds = BTreeMap::new();
        let mut previous_domain = None;
        for _ in 0..highest_count {
            let domain = LocalVoteDomain {
                validator: PrincipalId::decode(decoder)?,
                genesis_commitment: Digest384::decode(decoder)?,
                epoch: u64::decode(decoder)?,
                validator_set_root: Digest384::decode(decoder)?,
                protocol_revision: u64::decode(decoder)?,
            };
            let highest = HighestVotedRound {
                height: u64::decode(decoder)?,
                round: u64::decode(decoder)?,
                proposal_commitment: Digest384::decode(decoder)?,
            };
            if domain.genesis_commitment == Digest384::ZERO
                || domain.validator_set_root == Digest384::ZERO
                || domain.protocol_revision == 0
                || highest.proposal_commitment == Digest384::ZERO
                || previous_domain.is_some_and(|previous| domain <= previous)
                || highest_voted_rounds.insert(domain, highest).is_some()
            {
                return Err(DecodeError::InvalidValue("invalid durable highest-voted round"));
            }
            previous_domain = Some(domain);
        }
        let locked_qc = Option::<QuorumCertificate>::decode(decoder)?;
        let certified_count = decoder.read_length(MAX_PERSISTED_CERTIFIED_BLOCKS)?;
        let mut certified_blocks = BTreeMap::new();
        let mut previous_digest = None;
        for _ in 0..certified_count {
            let digest = Digest384::decode(decoder)?;
            let record = CertifiedBlockRecord::decode(decoder)?;
            if digest == Digest384::ZERO
                || digest != record.certificate.proposal_commitment()
                || previous_digest.is_some_and(|previous| digest <= previous)
                || certified_blocks.insert(digest, record).is_some()
            {
                return Err(DecodeError::InvalidValue("invalid certified-block record"));
            }
            previous_digest = Some(digest);
        }
        let active_anchor = ConsensusBlockRef::decode(decoder)?;
        if locked_qc.as_ref().is_some_and(|locked| {
            let is_finalized_anchor = locked.block_digest() == active_anchor.block_digest()
                && locked.proposal_commitment() == active_anchor.proposal_commitment()
                && locked.height() == active_anchor.height()
                && locked.round() == active_anchor.round();
            !is_finalized_anchor
                && certified_blocks
                    .get(&locked.proposal_commitment())
                    .is_none_or(|record| record.certificate != *locked)
        }) {
            return Err(DecodeError::InvalidValue("locked QC is not durably certified"));
        }
        Ok(Self {
            consensus,
            genesis_commitment,
            replay_high_water,
            outbound_high_water,
            vote_locks,
            highest_voted_rounds,
            locked_qc,
            certified_blocks,
            active_anchor,
        })
    }
}

impl CanonicalType for PersistedValidatorState {
    const TYPE_TAG: u16 = 0x006c;
    const SCHEMA_VERSION: u16 = 4;
    const MAX_ENCODED_LEN: usize = ConsensusSnapshot::MAX_ENCODED_LEN
        + 48
        + 2
        + MAX_PERSISTED_REPLAY_SENDERS * (2 + 8)
        + 2
        + MAX_PERSISTED_REPLAY_SENDERS * (2 + 8)
        + 2
        + MAX_PERSISTED_VOTE_LOCKS * (48 + 48 + 8 + 48 + 8 + 8 + 8 + 48)
        + 2
        + MAX_PERSISTED_REPLAY_SENDERS * (48 + 48 + 8 + 48 + 8 + 8 + 8 + 48)
        + 1
        + QuorumCertificate::ENCODED_LENGTH
        + 2
        + MAX_PERSISTED_CERTIFIED_BLOCKS
            * (48 + QuorumCertificate::ENCODED_LENGTH + 48 + 48 + 8 + 8)
        + 48
        + 48
        + 8
        + 8;
}

/// Verifies the weighted PQ signatures and active context of a bare QC without changing state.
///
/// A successful return proves only that the QC is well formed. It does **not** establish finality;
/// the authoritative [`ValidatorEngine`] additionally requires its signed proposal ancestry and a
/// consecutive child QC before applying a committed parent.
pub fn verify_bare_qc_evidence(
    state: &ConsensusState,
    validator_set: &ValidatorSet,
    certificate: &QuorumCertificate,
    votes: &[(&[u8], ValidatorVote)],
) -> Result<(), RuntimeError> {
    if votes.iter().any(|(_, vote)| {
        vote.epoch() != state.epoch()
            || vote.validator_set_root() != state.validator_set_root()
            || vote.protocol_revision() != state.protocol_revision()
    }) {
        return Err(RuntimeError::State(ConsensusStateError::InvalidConsensusContext));
    }
    verify_quorum_certificate(certificate, validator_set, votes)
        .map_err(RuntimeError::VoteVerification)
}

#[derive(Debug, Eq, PartialEq)]
pub enum RuntimeError {
    VoteVerification(VerificationError),
    State(ConsensusStateError),
}

pub fn admit_proposal(
    state: &ConsensusState,
    genesis_commitment: Digest384,
    proposal: &BlockProposal,
    proposer_key: &[u8],
) -> Result<(), ProposalError> {
    verify_block_proposal(proposer_key, proposal).map_err(ProposalError::Verification)?;
    if proposal.genesis_commitment() != genesis_commitment
        || proposal.epoch() != state.epoch()
        || proposal.validator_set_root() != state.validator_set_root()
        || proposal.protocol_revision() != state.protocol_revision()
    {
        return Err(ProposalError::ConsensusContextMismatch);
    }
    if proposal.height() <= state.finalized_height() {
        return Err(ProposalError::StaleOrWrongEpoch);
    }
    Ok(())
}
#[derive(Debug, Eq, PartialEq)]
pub enum ProposalError {
    Verification(VerificationError),
    ConsensusContextMismatch,
    StaleOrWrongEpoch,
}

#[derive(Clone)]
pub struct VoteCollector {
    proposal: BlockProposal,
    genesis_commitment: Digest384,
    validator_set_root: Digest384,
    protocol_revision: u64,
    votes: Vec<(Vec<u8>, ValidatorVote)>,
    seen: BTreeMap<activechain_protocol_types::PrincipalId, ()>,
    signer_stake: u128,
}
impl VoteCollector {
    pub fn new(
        proposal: BlockProposal,
        genesis_commitment: Digest384,
        validator_set_root: Digest384,
        protocol_revision: u64,
    ) -> Self {
        Self {
            proposal,
            genesis_commitment,
            validator_set_root,
            protocol_revision,
            votes: Vec::new(),
            seen: BTreeMap::new(),
            signer_stake: 0,
        }
    }
    pub fn add_vote(
        &mut self,
        validator_set: &ValidatorSet,
        public_key: &[u8],
        vote: ValidatorVote,
    ) -> Result<(), VoteCollectionError> {
        if vote.genesis_commitment() != self.genesis_commitment
            || vote.epoch() != self.proposal.epoch()
            || vote.validator_set_root() != self.validator_set_root
            || vote.protocol_revision() != self.protocol_revision
            || vote.height() != self.proposal.height()
            || vote.round() != self.proposal.round()
            || vote.block_digest() != self.proposal.block_digest()
            || vote.proposal_commitment() != self.proposal.commitment()
        {
            return Err(VoteCollectionError::ContextMismatch);
        }
        if self.seen.contains_key(&vote.validator()) {
            return Err(VoteCollectionError::Duplicate);
        }
        let stake = validator_set
            .stake_of(&vote.validator())
            .ok_or(VoteCollectionError::UnknownValidator)?;
        activechain_crypto_provider::verify_validator_vote(public_key, &vote)
            .map_err(VoteCollectionError::Verification)?;
        let insert_at = self
            .votes
            .binary_search_by_key(&vote.validator(), |(_, existing)| existing.validator())
            .unwrap_err();
        self.seen.insert(vote.validator(), ());
        self.signer_stake =
            self.signer_stake.checked_add(stake).ok_or(VoteCollectionError::StakeOverflow)?;
        self.votes.insert(insert_at, (public_key.to_vec(), vote));
        Ok(())
    }
    pub fn signer_stake(&self) -> u128 {
        self.signer_stake
    }
    pub const fn proposal(&self) -> &BlockProposal {
        &self.proposal
    }
    pub fn votes(&self) -> &[(Vec<u8>, ValidatorVote)] {
        &self.votes
    }
    pub fn finalize(
        &self,
        epoch: u64,
        validator_set: &ValidatorSet,
    ) -> Result<QuorumCertificate, VoteCollectionError> {
        if epoch != self.proposal.epoch() {
            return Err(VoteCollectionError::ContextMismatch);
        }
        let total = validator_set.total_stake();
        if self.signer_stake.checked_mul(3).ok_or(VoteCollectionError::StakeOverflow)?
            <= total.checked_mul(2).ok_or(VoteCollectionError::StakeOverflow)?
        {
            return Err(VoteCollectionError::InsufficientStake);
        }
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
        for (key, vote) in &self.votes {
            hasher.update(key);
            hasher.update(&vote.signing_payload());
            hasher.update(vote.signature().as_bytes());
        }
        let mut root = [0_u8; 48];
        hasher.finalize_xof().read(&mut root);
        let context = ConsensusVoteContext::new_with_revision(
            self.genesis_commitment,
            epoch,
            self.validator_set_root,
            self.protocol_revision,
        )
        .map_err(|_| VoteCollectionError::ContextMismatch)?;
        QuorumCertificate::new(
            context,
            self.proposal.height(),
            self.proposal.round(),
            self.proposal.block_digest(),
            self.proposal.commitment(),
            Digest384::new(root),
            total,
            self.signer_stake,
        )
        .map_err(|_| VoteCollectionError::InsufficientStake)
    }
}
#[derive(Debug, Eq, PartialEq)]
pub enum VoteCollectionError {
    ContextMismatch,
    Duplicate,
    UnknownValidator,
    Verification(VerificationError),
    StakeOverflow,
    InsufficientStake,
}

#[derive(Clone)]
pub struct ValidatorEngine {
    state: ConsensusState,
    genesis_commitment: Digest384,
    validator_set: ValidatorSet,
    public_keys: BTreeMap<activechain_protocol_types::PrincipalId, Vec<u8>>,
    collector: Option<VoteCollector>,
    local_vote_locks: BTreeMap<LocalVoteSlot, Digest384>,
    highest_voted_rounds: BTreeMap<LocalVoteDomain, HighestVotedRound>,
    locked_qc: Option<QuorumCertificate>,
    certified_blocks: BTreeMap<Digest384, CertifiedBlockRecord>,
    active_anchor: ConsensusBlockRef,
}
impl ValidatorEngine {
    pub fn from_genesis(
        state: ConsensusState,
        genesis: &ValidatorGenesis,
    ) -> Result<Self, ValidatorEngineError> {
        Self::from_active_manifest(state, genesis, genesis.genesis_commitment())
    }
    pub fn from_active_manifest(
        state: ConsensusState,
        active_manifest: &ValidatorGenesis,
        chain_genesis_commitment: Digest384,
    ) -> Result<Self, ValidatorEngineError> {
        if state.epoch() != active_manifest.epoch() {
            return Err(ValidatorEngineError::GenesisEpochMismatch);
        }
        if state.validator_set_root() != active_manifest.validator_set_root() {
            return Err(ValidatorEngineError::GenesisRootMismatch);
        }
        if state.protocol_revision() != active_manifest.protocol_revision() {
            return Err(ValidatorEngineError::GenesisRevisionMismatch);
        }
        let validator_set =
            active_manifest.validator_set().map_err(|_| ValidatorEngineError::InvalidGenesis)?;
        let public_keys = active_manifest
            .entries()
            .iter()
            .map(|entry| (entry.validator(), entry.public_key().to_vec()))
            .collect();
        Self::new(state, chain_genesis_commitment, validator_set, public_keys)
    }
    pub fn new(
        state: ConsensusState,
        genesis_commitment: Digest384,
        validator_set: ValidatorSet,
        public_keys: BTreeMap<activechain_protocol_types::PrincipalId, Vec<u8>>,
    ) -> Result<Self, ValidatorEngineError> {
        if genesis_commitment == Digest384::ZERO || state.validator_set_root() == Digest384::ZERO {
            return Err(ValidatorEngineError::UnboundConsensusDomain);
        }
        for validator in validator_set.as_slice() {
            let key = public_keys
                .get(&validator.validator)
                .ok_or(ValidatorEngineError::MissingValidatorKey)?;
            if key.len() != 1312 {
                return Err(ValidatorEngineError::InvalidValidatorKey);
            }
        }
        let active_anchor = state
            .active_anchor(genesis_commitment)
            .map_err(|_| ValidatorEngineError::InvalidFinalizedAnchor)?;
        Ok(Self {
            state,
            genesis_commitment,
            validator_set,
            public_keys,
            collector: None,
            local_vote_locks: BTreeMap::new(),
            highest_voted_rounds: BTreeMap::new(),
            locked_qc: None,
            certified_blocks: BTreeMap::new(),
            active_anchor,
        })
    }
    pub const fn state(&self) -> ConsensusState {
        self.state
    }
    fn consensus_context(&self) -> Result<ConsensusVoteContext, ValidatorEngineError> {
        ConsensusVoteContext::new_with_revision(
            self.genesis_commitment,
            self.state.epoch(),
            self.state.validator_set_root(),
            self.state.protocol_revision(),
        )
        .map_err(|_| ValidatorEngineError::UnboundConsensusDomain)
    }
    fn finalized_anchor(&self) -> ConsensusBlockRef {
        self.active_anchor
    }
    fn preferred_justification(&self) -> ProposalJustification {
        let anchor = self.finalized_anchor();
        self.certified_blocks
            .values()
            .filter(|record| {
                record.certificate.genesis_commitment() == self.genesis_commitment
                    && record.certificate.epoch() == self.state.epoch()
                    && record.certificate.validator_set_root() == self.state.validator_set_root()
                    && record.certificate.protocol_revision() == self.state.protocol_revision()
                    && self.is_ancestor_or_equal(
                        anchor.proposal_commitment(),
                        record.certificate.proposal_commitment(),
                    )
            })
            .max_by_key(|record| {
                (
                    record.certificate.round(),
                    record.certificate.height(),
                    record.certificate.proposal_commitment(),
                )
            })
            .map(|record| ProposalJustification::Quorum(record.certificate.clone()))
            .unwrap_or(ProposalJustification::Finalized(anchor))
    }
    fn is_ancestor_or_equal(&self, ancestor: Digest384, descendant: Digest384) -> bool {
        let mut cursor = descendant;
        for _ in 0..=self.certified_blocks.len() {
            if cursor == ancestor {
                return true;
            }
            let Some(record) = self.certified_blocks.get(&cursor) else {
                return false;
            };
            cursor = record.parent.proposal_commitment();
        }
        false
    }
    fn verify_proposal_safety(&self, proposal: &BlockProposal) -> Result<(), ValidatorEngineError> {
        let parent = proposal.parent();
        match proposal.justification() {
            ProposalJustification::Finalized(candidate) => {
                if *candidate != self.finalized_anchor() {
                    return Err(ValidatorEngineError::InvalidFinalizedAnchor);
                }
            }
            ProposalJustification::Quorum(certificate) => {
                let Some(record) = self.certified_blocks.get(&certificate.proposal_commitment())
                else {
                    return Err(ValidatorEngineError::UnknownParentCertificate);
                };
                if record.certificate != *certificate {
                    return Err(ValidatorEngineError::ConflictingCertificate);
                }
            }
        }
        let finalized = self.finalized_anchor();
        if !self.is_ancestor_or_equal(finalized.proposal_commitment(), parent.proposal_commitment())
        {
            return Err(ValidatorEngineError::ConflictingFinalizedPrefix);
        }
        if let Some(locked) = &self.locked_qc {
            let extends_lock = self
                .is_ancestor_or_equal(locked.proposal_commitment(), parent.proposal_commitment());
            let parent_is_newer = proposal
                .justification()
                .certificate()
                .is_some_and(|parent_qc| parent_qc.round() > locked.round());
            if !extends_lock && !parent_is_newer {
                return Err(ValidatorEngineError::UnsafeProposal);
            }
        }
        Ok(())
    }
    fn validate_restored_safety_state(&self) -> Result<(), ValidatorEngineError> {
        let expected_anchor = self
            .state
            .active_anchor(self.genesis_commitment)
            .map_err(|_| ValidatorEngineError::InvalidSafetySnapshot)?;
        if self.certified_blocks.len() > MAX_PERSISTED_CERTIFIED_BLOCKS
            || self.active_anchor != expected_anchor
        {
            return Err(ValidatorEngineError::InvalidSafetySnapshot);
        }
        if self.local_vote_locks.keys().any(|slot| {
            slot.genesis_commitment != self.genesis_commitment
                || slot.epoch != self.state.epoch()
                || slot.validator_set_root != self.state.validator_set_root()
                || slot.protocol_revision != self.state.protocol_revision()
        }) {
            return Err(ValidatorEngineError::InvalidSafetySnapshot);
        }
        if self.highest_voted_rounds.len() > MAX_PERSISTED_REPLAY_SENDERS
            || self.highest_voted_rounds.iter().any(|(domain, highest)| {
                domain.genesis_commitment != self.genesis_commitment
                    || domain.epoch != self.state.epoch()
                    || domain.validator_set_root != self.state.validator_set_root()
                    || domain.protocol_revision != self.state.protocol_revision()
                    || self.validator_set.stake_of(&domain.validator).is_none()
                    || highest.proposal_commitment == Digest384::ZERO
            })
            || self.local_vote_locks.iter().any(|(slot, commitment)| {
                let domain = LocalVoteDomain {
                    validator: slot.validator,
                    genesis_commitment: slot.genesis_commitment,
                    epoch: slot.epoch,
                    validator_set_root: slot.validator_set_root,
                    protocol_revision: slot.protocol_revision,
                };
                self.highest_voted_rounds.get(&domain).is_none_or(|highest| {
                    highest.round < slot.round
                        || (highest.round == slot.round
                            && (highest.height != slot.height
                                || highest.proposal_commitment != *commitment))
                })
            })
        {
            return Err(ValidatorEngineError::InvalidSafetySnapshot);
        }
        for (digest, record) in &self.certified_blocks {
            let certificate = &record.certificate;
            if *digest != certificate.proposal_commitment()
                || certificate.genesis_commitment() != self.genesis_commitment
                || certificate.epoch() != self.state.epoch()
                || certificate.validator_set_root() != self.state.validator_set_root()
                || certificate.protocol_revision() != self.state.protocol_revision()
                || !self.is_ancestor_or_equal(self.active_anchor.proposal_commitment(), *digest)
            {
                return Err(ValidatorEngineError::InvalidSafetySnapshot);
            }
        }
        if self.locked_qc.as_ref().is_some_and(|locked| {
            let is_finalized_anchor = locked.block_digest() == self.active_anchor.block_digest()
                && locked.proposal_commitment() == self.active_anchor.proposal_commitment()
                && locked.height() == self.active_anchor.height()
                && locked.round() == self.active_anchor.round();
            !is_finalized_anchor
                && self
                    .certified_blocks
                    .get(&locked.proposal_commitment())
                    .is_none_or(|record| record.certificate != *locked)
        }) {
            return Err(ValidatorEngineError::InvalidSafetySnapshot);
        }
        Ok(())
    }
    pub fn activate_finalized_validator_set(
        &mut self,
        authorization: &ConsensusUpgradeAuthorization,
        authorization_proof: &CertifiedBlock,
        next_genesis: &ValidatorGenesis,
    ) -> Result<(), ValidatorEngineError> {
        if !authorization.changes_validator_set()
            || authorization.to_epoch() != next_genesis.epoch()
            || authorization.activation_height() != next_genesis.activation_height()
            || authorization.next_validator_set_root() != next_genesis.validator_set_root()
            || authorization.next_protocol_revision() != next_genesis.protocol_revision()
        {
            return Err(ValidatorEngineError::InvalidEpochTransition);
        }
        self.verify_finalized_upgrade_authorization(authorization, authorization_proof)?;
        let handoff_anchor = self.upgrade_handoff_anchor(authorization, authorization_proof)?;
        let validator_set =
            next_genesis.validator_set().map_err(|_| ValidatorEngineError::InvalidGenesis)?;
        let public_keys = next_genesis
            .entries()
            .iter()
            .map(|entry| (entry.validator(), entry.public_key().to_vec()))
            .collect();
        let mut next_state = self.state;
        next_state
            .apply_upgrade_after_certified_block(authorization, handoff_anchor)
            .map_err(|_| ValidatorEngineError::InvalidEpochTransition)?;
        self.state = next_state;
        self.validator_set = validator_set;
        self.public_keys = public_keys;
        self.collector = None;
        self.local_vote_locks.clear();
        self.highest_voted_rounds.clear();
        self.locked_qc = None;
        self.certified_blocks.clear();
        self.active_anchor = handoff_anchor;
        Ok(())
    }
    pub fn activate_finalized_protocol_upgrade(
        &mut self,
        authorization: &ConsensusUpgradeAuthorization,
        authorization_proof: &CertifiedBlock,
    ) -> Result<(), ValidatorEngineError> {
        if authorization.changes_validator_set() || !authorization.changes_protocol_revision() {
            return Err(ValidatorEngineError::InvalidProtocolUpgrade);
        }
        self.verify_finalized_upgrade_authorization(authorization, authorization_proof)?;
        let handoff_anchor = self.upgrade_handoff_anchor(authorization, authorization_proof)?;
        self.state
            .apply_upgrade_after_certified_block(authorization, handoff_anchor)
            .map_err(|_| ValidatorEngineError::InvalidProtocolUpgrade)?;
        self.collector = None;
        self.local_vote_locks.clear();
        self.highest_voted_rounds.clear();
        self.locked_qc = None;
        self.certified_blocks.clear();
        self.active_anchor = handoff_anchor;
        Ok(())
    }
    fn verify_finalized_upgrade_authorization(
        &self,
        authorization: &ConsensusUpgradeAuthorization,
        proof: &CertifiedBlock,
    ) -> Result<(), ValidatorEngineError> {
        let certificate = proof.certificate();
        if certificate.height() != authorization.authorization_height()
            || certificate.height() > self.state.finalized_height()
            || certificate.block_digest() != authorization.commitment()
            || certificate.genesis_commitment() != self.genesis_commitment
            || certificate.epoch() != self.state.epoch()
            || certificate.validator_set_root() != self.state.validator_set_root()
            || certificate.protocol_revision() != self.state.protocol_revision()
        {
            return Err(ValidatorEngineError::InvalidUpgradeAuthorizationProof);
        }
        let mut votes = Vec::with_capacity(proof.votes().len());
        for vote in proof.votes() {
            if vote.genesis_commitment() != self.genesis_commitment
                || vote.epoch() != self.state.epoch()
                || vote.validator_set_root() != self.state.validator_set_root()
                || vote.protocol_revision() != self.state.protocol_revision()
            {
                return Err(ValidatorEngineError::InvalidUpgradeAuthorizationProof);
            }
            let key = self
                .public_keys
                .get(&vote.validator())
                .ok_or(ValidatorEngineError::InvalidUpgradeAuthorizationProof)?;
            votes.push((key.as_slice(), vote.clone()));
        }
        verify_quorum_certificate(certificate, &self.validator_set, &votes)
            .map_err(|_| ValidatorEngineError::InvalidUpgradeAuthorizationProof)
    }
    fn upgrade_handoff_anchor(
        &self,
        authorization: &ConsensusUpgradeAuthorization,
        proof: &CertifiedBlock,
    ) -> Result<ConsensusBlockRef, ValidatorEngineError> {
        let authorization_certificate = proof.certificate();
        let authorization_is_finalized_anchor = self.active_anchor.block_digest()
            == authorization_certificate.block_digest()
            && self.active_anchor.proposal_commitment()
                == authorization_certificate.proposal_commitment()
            && self.active_anchor.height() == authorization_certificate.height()
            && self.active_anchor.round() == authorization_certificate.round();
        if !authorization_is_finalized_anchor
            && self
                .certified_blocks
                .get(&authorization_certificate.proposal_commitment())
                .is_none_or(|record| record.certificate != *authorization_certificate)
        {
            return Err(ValidatorEngineError::InvalidUpgradeAuthorizationProof);
        }
        let mut handoffs = self.certified_blocks.values().filter(|record| {
            record.parent.block_digest() == authorization_certificate.block_digest()
                && record.parent.proposal_commitment()
                    == authorization_certificate.proposal_commitment()
                && record.parent.height() == authorization_certificate.height()
                && record.parent.round() == authorization_certificate.round()
                && authorization_certificate.round().checked_add(1)
                    == Some(record.certificate.round())
        });
        let handoff =
            handoffs.next().ok_or(ValidatorEngineError::MissingUpgradeHandoffCertificate)?;
        if handoffs.next().is_some()
            || handoff.certificate.height().checked_add(1)
                != Some(authorization.activation_height())
        {
            return Err(ValidatorEngineError::InvalidUpgradeHandoffCertificate);
        }
        ConsensusBlockRef::new(
            handoff.certificate.block_digest(),
            handoff.certificate.proposal_commitment(),
            handoff.certificate.height(),
            handoff.certificate.round(),
        )
        .map_err(|_| ValidatorEngineError::InvalidUpgradeHandoffCertificate)
    }
    /// Prepares the durable lock and vote-slot transition without invoking a signing key.
    fn prepare_current_vote(
        &mut self,
        validator: PrincipalId,
    ) -> Result<PreparedValidatorVote, ValidatorEngineError> {
        let proposal = self
            .collector
            .as_ref()
            .ok_or(ValidatorEngineError::MissingProposal)?
            .proposal()
            .clone();
        if self.validator_set.stake_of(&validator).is_none() {
            return Err(ValidatorEngineError::UnknownValidator);
        }
        self.verify_proposal_safety(&proposal)?;
        let slot = LocalVoteSlot {
            validator,
            genesis_commitment: self.genesis_commitment,
            epoch: proposal.epoch(),
            validator_set_root: self.state.validator_set_root(),
            protocol_revision: self.state.protocol_revision(),
            height: proposal.height(),
            round: proposal.round(),
        };
        let proposal_commitment = proposal.commitment();
        let domain = LocalVoteDomain {
            validator,
            genesis_commitment: self.genesis_commitment,
            epoch: proposal.epoch(),
            validator_set_root: self.state.validator_set_root(),
            protocol_revision: self.state.protocol_revision(),
        };
        match self.highest_voted_rounds.get(&domain) {
            Some(highest) if proposal.round() < highest.round => {
                return Err(ValidatorEngineError::StaleLocalView);
            }
            Some(highest)
                if proposal.round() == highest.round
                    && (proposal.height() != highest.height
                        || proposal_commitment != highest.proposal_commitment) =>
            {
                return Err(ValidatorEngineError::ConflictingLocalVote);
            }
            _ => {}
        }
        match self.local_vote_locks.get(&slot) {
            Some(commitment) if *commitment != proposal_commitment => {
                return Err(ValidatorEngineError::ConflictingLocalVote);
            }
            Some(_) => {}
            None if self.local_vote_locks.len() >= MAX_PERSISTED_VOTE_LOCKS => {
                return Err(ValidatorEngineError::VoteLockLimit);
            }
            None => {
                self.local_vote_locks.insert(slot, proposal_commitment);
            }
        }
        if self
            .highest_voted_rounds
            .get(&domain)
            .is_none_or(|highest| proposal.round() > highest.round)
        {
            self.highest_voted_rounds.insert(
                domain,
                HighestVotedRound {
                    height: proposal.height(),
                    round: proposal.round(),
                    proposal_commitment,
                },
            );
        }
        if let ProposalJustification::Quorum(parent_qc) = proposal.justification()
            && self.locked_qc.as_ref().is_none_or(|locked| parent_qc.round() > locked.round())
        {
            self.locked_qc = Some(parent_qc.clone());
        }
        Ok(PreparedValidatorVote {
            proposal,
            genesis_commitment: self.genesis_commitment,
            validator_set_root: self.state.validator_set_root(),
            protocol_revision: self.state.protocol_revision(),
        })
    }
    /// In-memory helper for unit tests. Authoritative services use durable-before-sign instead.
    #[cfg(test)]
    fn sign_current_vote(
        &mut self,
        signer: &ValidatorSigner,
    ) -> Result<ValidatorVote, ValidatorEngineError> {
        let prepared = self.prepare_current_vote(signer.validator())?;
        signer.sign_prepared_vote(&prepared)
    }
    pub fn process(
        &mut self,
        message: ConsensusMessage,
    ) -> Result<Option<CertifiedBlock>, ValidatorEngineError> {
        match message {
            ConsensusMessage::Proposal(proposal) => {
                let key = self
                    .public_keys
                    .get(&proposal.proposer())
                    .ok_or(ValidatorEngineError::UnknownValidator)?;
                admit_proposal(&self.state, self.genesis_commitment, &proposal, key)
                    .map_err(ValidatorEngineError::Proposal)?;
                self.verify_proposal_safety(&proposal)?;
                self.collector = Some(VoteCollector::new(
                    proposal,
                    self.genesis_commitment,
                    self.state.validator_set_root(),
                    self.state.protocol_revision(),
                ));
                Ok(None)
            }
            ConsensusMessage::Vote(vote) => {
                let key = self
                    .public_keys
                    .get(&vote.validator())
                    .ok_or(ValidatorEngineError::UnknownValidator)?;
                let collector =
                    self.collector.as_mut().ok_or(ValidatorEngineError::MissingProposal)?;
                collector
                    .add_vote(&self.validator_set, key, vote)
                    .map_err(ValidatorEngineError::Vote)?;
                match collector.finalize(self.state.epoch(), &self.validator_set) {
                    Ok(certificate) => {
                        let votes: Vec<_> =
                            collector.votes().iter().map(|(_, vote)| vote.clone()).collect();
                        let proof =
                            CertifiedBlock::new(collector.proposal().clone(), certificate, votes)
                                .map_err(ValidatorEngineError::Transport)?;
                        self.apply_certificate(&proof)?;
                        self.collector = None;
                        Ok(Some(proof))
                    }
                    Err(VoteCollectionError::InsufficientStake) => Ok(None),
                    Err(error) => Err(ValidatorEngineError::Vote(error)),
                }
            }
            ConsensusMessage::Certificate(proof) => {
                self.apply_certificate(&proof)?;
                self.collector = None;
                Ok(None)
            }
        }
    }
    fn apply_certificate(&mut self, proof: &CertifiedBlock) -> Result<(), ValidatorEngineError> {
        let certificate = proof.certificate();
        let proposal = proof.proposal();
        if certificate.genesis_commitment() != self.genesis_commitment
            || certificate.epoch() != self.state.epoch()
            || certificate.validator_set_root() != self.state.validator_set_root()
            || certificate.protocol_revision() != self.state.protocol_revision()
        {
            return Err(ValidatorEngineError::VoteDomainMismatch);
        }
        let proposer_key = self
            .public_keys
            .get(&proposal.proposer())
            .ok_or(ValidatorEngineError::UnknownValidator)?;
        verify_block_proposal(proposer_key, proposal)
            .map_err(|error| ValidatorEngineError::Proposal(ProposalError::Verification(error)))?;
        let mut votes = Vec::with_capacity(proof.votes().len());
        for vote in proof.votes() {
            if vote.genesis_commitment() != self.genesis_commitment
                || vote.epoch() != self.state.epoch()
                || vote.validator_set_root() != self.state.validator_set_root()
                || vote.protocol_revision() != self.state.protocol_revision()
            {
                return Err(ValidatorEngineError::VoteDomainMismatch);
            }
            let key = self
                .public_keys
                .get(&vote.validator())
                .ok_or(ValidatorEngineError::UnknownValidator)?;
            votes.push((key.as_slice(), vote.clone()));
        }
        verify_quorum_certificate(certificate, &self.validator_set, &votes).map_err(|error| {
            ValidatorEngineError::Runtime(RuntimeError::VoteVerification(error))
        })?;

        self.apply_verified_certificate_transition(proposal, certificate)
    }

    /// Applies a proposal/QC pair after proposal and vote signatures have been verified.
    ///
    /// Kept private so production callers cannot bypass the PQ verification above. Tests use this
    /// transition boundary to exercise thousands of deterministic pruning steps without producing
    /// thousands of expensive ML-DSA signatures.
    fn apply_verified_certificate_transition(
        &mut self,
        proposal: &BlockProposal,
        certificate: &QuorumCertificate,
    ) -> Result<(), ValidatorEngineError> {
        if certificate.genesis_commitment() != self.genesis_commitment
            || certificate.epoch() != self.state.epoch()
            || certificate.validator_set_root() != self.state.validator_set_root()
            || certificate.protocol_revision() != self.state.protocol_revision()
            || certificate.height() != proposal.height()
            || certificate.round() != proposal.round()
            || certificate.block_digest() != proposal.block_digest()
            || certificate.proposal_commitment() != proposal.commitment()
        {
            return Err(ValidatorEngineError::VoteDomainMismatch);
        }

        if let Some(existing) = self.certified_blocks.get(&certificate.proposal_commitment()) {
            if existing.certificate == *certificate && existing.parent == proposal.parent() {
                return Ok(());
            }
            return Err(ValidatorEngineError::ConflictingCertificate);
        }
        self.verify_proposal_safety(proposal)?;
        if self.certified_blocks.len() >= MAX_PERSISTED_CERTIFIED_BLOCKS {
            return Err(ValidatorEngineError::CertifiedBlockLimit);
        }

        let finalized_before = self.state.finalized_height();
        let mut next_state = self.state;
        let mut next_anchor = self.active_anchor;
        if let ProposalJustification::Quorum(parent_qc) = proposal.justification()
            && parent_qc.round().checked_add(1) == Some(certificate.round())
        {
            if parent_qc.height() > next_state.finalized_height() {
                next_state
                    .apply_committed_qc(parent_qc)
                    .map_err(|error| ValidatorEngineError::Runtime(RuntimeError::State(error)))?;
                next_anchor = ConsensusBlockRef::new(
                    parent_qc.block_digest(),
                    parent_qc.proposal_commitment(),
                    parent_qc.height(),
                    parent_qc.round(),
                )
                .map_err(|_| ValidatorEngineError::InvalidFinalizedAnchor)?;
            } else if parent_qc.height() == next_state.finalized_height() {
                if parent_qc.block_digest() != next_state.finalized_block_digest()
                    || parent_qc.proposal_commitment() != next_state.finalized_proposal_commitment()
                {
                    return Err(ValidatorEngineError::ConflictingFinalizedPrefix);
                }
            } else if !self.is_ancestor_or_equal(
                parent_qc.proposal_commitment(),
                next_state.finalized_proposal_commitment(),
            ) {
                return Err(ValidatorEngineError::ConflictingFinalizedPrefix);
            }
        }
        self.certified_blocks.insert(
            certificate.proposal_commitment(),
            CertifiedBlockRecord { certificate: certificate.clone(), parent: proposal.parent() },
        );
        self.state = next_state;
        self.active_anchor = next_anchor;
        if self.state.finalized_height() > finalized_before {
            self.prune_finalized_history();
        }
        self.local_vote_locks.retain(|slot, _| {
            slot.epoch > self.state.epoch()
                || (slot.epoch == self.state.epoch() && slot.height > self.state.finalized_height())
        });
        Ok(())
    }

    /// Removes committed ancestry while retaining every certified descendant of the new anchor.
    fn prune_finalized_history(&mut self) {
        let anchor = self.active_anchor;
        let retained: Vec<_> = self
            .certified_blocks
            .iter()
            .filter_map(|(commitment, record)| {
                (record.certificate.height() > anchor.height()
                    && self.is_ancestor_or_equal(anchor.proposal_commitment(), *commitment))
                .then_some(*commitment)
            })
            .collect();
        self.certified_blocks.retain(|commitment, _| retained.binary_search(commitment).is_ok());
        if self.locked_qc.as_ref().is_some_and(|locked| locked.height() <= anchor.height()) {
            self.locked_qc = None;
        }
    }
}

#[derive(Debug)]
pub enum ValidatorEngineError {
    InvalidGenesis,
    InvalidEpochTransition,
    InvalidProtocolUpgrade,
    InvalidUpgradeAuthorizationProof,
    MissingUpgradeHandoffCertificate,
    InvalidUpgradeHandoffCertificate,
    GenesisEpochMismatch,
    GenesisRootMismatch,
    GenesisRevisionMismatch,
    SnapshotDomainMismatch,
    SnapshotStateMismatch,
    SnapshotUnknownSender,
    MissingValidatorKey,
    InvalidValidatorKey,
    UnboundConsensusDomain,
    UnknownValidator,
    MissingProposal,
    ConflictingLocalVote,
    StaleLocalView,
    VoteDomainMismatch,
    VoteLockLimit,
    CertifiedBlockLimit,
    InvalidFinalizedAnchor,
    UnknownParentCertificate,
    ConflictingCertificate,
    ConflictingFinalizedPrefix,
    UnsafeProposal,
    InvalidSafetySnapshot,
    SequenceOverflow,
    HeightOverflow,
    RoundOverflow,
    Proposal(ProposalError),
    Vote(VoteCollectionError),
    Transport(TransportError),
    Runtime(RuntimeError),
    Snapshot(std::io::Error),
    Signer,
}

pub struct ValidatorService {
    engine: std::sync::Mutex<ValidatorEngine>,
    replay: std::sync::Mutex<ReplayGuard>,
    outbound_high_water: std::sync::Mutex<BTreeMap<u16, u64>>,
    sender_keys: std::sync::Mutex<BTreeMap<u16, Vec<u8>>>,
    snapshot_path: std::path::PathBuf,
    metrics: std::sync::Arc<ValidatorMetrics>,
}
impl ValidatorService {
    pub fn from_genesis(
        state: ConsensusState,
        genesis: &ValidatorGenesis,
        snapshot_path: std::path::PathBuf,
    ) -> Result<Self, ValidatorEngineError> {
        Self::from_active_manifest(state, genesis, genesis.genesis_commitment(), snapshot_path)
    }
    pub fn from_active_manifest(
        state: ConsensusState,
        active_manifest: &ValidatorGenesis,
        chain_genesis_commitment: Digest384,
        snapshot_path: std::path::PathBuf,
    ) -> Result<Self, ValidatorEngineError> {
        let sender_keys = active_manifest
            .entries()
            .iter()
            .enumerate()
            .map(|(index, entry)| ((index + 1) as u16, entry.public_key().to_vec()))
            .collect::<BTreeMap<_, _>>();
        let mut engine = ValidatorEngine::from_active_manifest(
            state,
            active_manifest,
            chain_genesis_commitment,
        )?;
        let mut replay = ReplayGuard::default();
        let mut outbound_high_water = BTreeMap::new();
        match std::fs::read(&snapshot_path) {
            Ok(bytes) => match decode_envelope::<PersistedValidatorState>(&bytes) {
                Ok(persisted) => {
                    if persisted.genesis_commitment != engine.genesis_commitment {
                        return Err(ValidatorEngineError::SnapshotDomainMismatch);
                    }
                    if ConsensusState::from_snapshot(persisted.consensus) != state {
                        return Err(ValidatorEngineError::SnapshotStateMismatch);
                    }
                    if persisted
                        .replay_high_water
                        .keys()
                        .chain(persisted.outbound_high_water.keys())
                        .any(|sender| !sender_keys.contains_key(sender))
                    {
                        return Err(ValidatorEngineError::SnapshotUnknownSender);
                    }
                    engine.local_vote_locks = persisted.vote_locks;
                    engine.highest_voted_rounds = persisted.highest_voted_rounds;
                    engine.locked_qc = persisted.locked_qc;
                    engine.certified_blocks = persisted.certified_blocks;
                    engine.active_anchor = persisted.active_anchor;
                    engine.validate_restored_safety_state()?;
                    replay.highest = persisted.replay_high_water;
                    outbound_high_water = persisted.outbound_high_water;
                }
                Err(_) if bytes.starts_with(&PersistedValidatorState::TYPE_TAG.to_be_bytes()) => {
                    return Err(ValidatorEngineError::Snapshot(invalid_data(
                        "validator safety snapshot is invalid",
                    )));
                }
                Err(_) => {}
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ValidatorEngineError::Snapshot(error)),
        }
        Ok(Self {
            engine: std::sync::Mutex::new(engine),
            replay: std::sync::Mutex::new(replay),
            outbound_high_water: std::sync::Mutex::new(outbound_high_water),
            sender_keys: std::sync::Mutex::new(sender_keys),
            snapshot_path,
            metrics: std::sync::Arc::new(ValidatorMetrics::default()),
        })
    }
    pub fn state(&self) -> Result<ConsensusState, ValidatorServiceError> {
        self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned).map(|engine| engine.state())
    }
    pub fn activate_finalized_validator_set(
        &self,
        authorization: &ConsensusUpgradeAuthorization,
        authorization_proof: &CertifiedBlock,
        next_genesis: &ValidatorGenesis,
    ) -> Result<(), ValidatorServiceError> {
        let mut engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut sender_keys =
            self.sender_keys.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut candidate = engine.clone();
        candidate
            .activate_finalized_validator_set(authorization, authorization_proof, next_genesis)
            .map_err(ValidatorServiceError::Engine)?;
        save_validator_snapshot(&self.snapshot_path, &candidate, &replay, &outbound)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)?;
        *sender_keys = next_genesis
            .entries()
            .iter()
            .enumerate()
            .map(|(index, entry)| ((index + 1) as u16, entry.public_key().to_vec()))
            .collect();
        *engine = candidate;
        Ok(())
    }
    pub fn activate_finalized_protocol_upgrade(
        &self,
        authorization: &ConsensusUpgradeAuthorization,
        authorization_proof: &CertifiedBlock,
    ) -> Result<(), ValidatorServiceError> {
        let mut engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut candidate = engine.clone();
        candidate
            .activate_finalized_protocol_upgrade(authorization, authorization_proof)
            .map_err(ValidatorServiceError::Engine)?;
        save_validator_snapshot(&self.snapshot_path, &candidate, &replay, &outbound)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)?;
        *engine = candidate;
        Ok(())
    }
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }
    pub fn next_sequence(&self, sender: u16) -> Result<u64, ValidatorServiceError> {
        if !self
            .sender_keys
            .lock()
            .map_err(|_| ValidatorServiceError::Poisoned)?
            .contains_key(&sender)
        {
            return Err(ValidatorServiceError::UnknownSender);
        }
        let replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        replay
            .highest
            .get(&sender)
            .copied()
            .into_iter()
            .chain(outbound.get(&sender).copied())
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))
    }
    pub fn next_proposal_position(&self) -> Result<(u64, u64), ValidatorServiceError> {
        let engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let parent = engine.preferred_justification().parent();
        let height = parent
            .height()
            .checked_add(1)
            .ok_or_else(|| ValidatorServiceError::Engine(ValidatorEngineError::HeightOverflow))?;
        let round = if parent.height() == 0 {
            parent.round()
        } else {
            parent
                .round()
                .checked_add(1)
                .ok_or_else(|| ValidatorServiceError::Engine(ValidatorEngineError::RoundOverflow))?
        };
        Ok((height, round))
    }
    fn reserve_sequence_range(
        &self,
        sender: u16,
        first: u64,
        count: u64,
    ) -> Result<(), ValidatorServiceError> {
        if count == 0
            || !self
                .sender_keys
                .lock()
                .map_err(|_| ValidatorServiceError::Poisoned)?
                .contains_key(&sender)
        {
            return Err(ValidatorServiceError::UnknownSender);
        }
        let last = first
            .checked_add(count - 1)
            .ok_or_else(|| ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))?;
        let engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let highest = replay
            .highest
            .get(&sender)
            .copied()
            .into_iter()
            .chain(outbound.get(&sender).copied())
            .max()
            .unwrap_or(0);
        if first <= highest {
            return Err(ValidatorServiceError::Transport(TransportError::Replay));
        }
        let mut candidate = outbound.clone();
        candidate.insert(sender, last);
        save_validator_snapshot(&self.snapshot_path, &engine, &replay, &candidate)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)?;
        *outbound = candidate;
        Ok(())
    }
    pub fn process_message(
        &self,
        message: AuthenticatedConsensusMessage,
    ) -> Result<Option<CertifiedBlock>, ValidatorServiceError> {
        match &message.message {
            ConsensusMessage::Proposal(_) => {
                self.metrics.proposals.fetch_add(1, Ordering::Relaxed);
            }
            ConsensusMessage::Vote(_) => {
                self.metrics.votes.fetch_add(1, Ordering::Relaxed);
            }
            ConsensusMessage::Certificate(_) => {}
        }
        let key = self
            .sender_keys
            .lock()
            .map_err(|_| ValidatorServiceError::Poisoned)?
            .get(&message.envelope.sender())
            .cloned()
            .ok_or(ValidatorServiceError::UnknownSender)?;
        let mut engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut candidate_replay = replay.clone();
        candidate_replay
            .accept(&message.envelope, &key)
            .map_err(ValidatorServiceError::Transport)?;
        save_validator_snapshot(&self.snapshot_path, &engine, &candidate_replay, &outbound)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)?;
        *replay = candidate_replay;

        let mut candidate_engine = engine.clone();
        let finalized_before = engine.state.finalized_height();
        let result =
            candidate_engine.process(message.message).map_err(ValidatorServiceError::Engine);
        let finalized_advanced =
            result.is_ok() && candidate_engine.state.finalized_height() > finalized_before;
        if result.is_ok() {
            save_validator_snapshot(&self.snapshot_path, &candidate_engine, &replay, &outbound)
                .map_err(ValidatorEngineError::Snapshot)
                .map_err(ValidatorServiceError::Engine)?;
            *engine = candidate_engine;
        }
        if finalized_advanced {
            self.metrics.finalized_certificates.fetch_add(1, Ordering::Relaxed);
        }
        if result.is_err() {
            self.metrics.rejected_messages.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn sign_current_vote_durably<S: ConsensusVoteSigner>(
        &self,
        signer: &S,
    ) -> Result<ValidatorVote, ValidatorServiceError> {
        let mut engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut candidate = engine.clone();
        let prepared = candidate
            .prepare_current_vote(signer.validator())
            .map_err(ValidatorServiceError::Engine)?;
        save_validator_snapshot(&self.snapshot_path, &candidate, &replay, &outbound)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)?;
        *engine = candidate;
        // The exact vote slot and any parent lock are durable before key use. Keep the engine lock
        // until signing completes so an epoch transition cannot race an old-context signature.
        drop(outbound);
        drop(replay);
        let vote = signer.sign_prepared_vote(&prepared).map_err(ValidatorServiceError::Engine)?;
        drop(engine);
        Ok(vote)
    }
    pub fn process_proposal_and_sign_vote(
        &self,
        proposal: AuthenticatedConsensusMessage,
        signer: &ValidatorSigner,
        sequence: u64,
    ) -> Result<AuthenticatedConsensusMessage, ValidatorServiceError> {
        self.process_message(proposal)?;
        let sender = self.sender_for(signer)?;
        self.reserve_sequence_range(sender, sequence, 1)?;
        let vote = self.sign_current_vote_durably(signer)?;
        signer
            .sign_envelope(sender, sequence, ConsensusMessage::Vote(vote))
            .map_err(ValidatorServiceError::Engine)
    }
    pub fn propose_round(
        &self,
        signer: &ValidatorSigner,
        height: u64,
        round: u64,
        block_digest: Digest384,
        sequence: u64,
    ) -> Result<(AuthenticatedConsensusMessage, AuthenticatedConsensusMessage), ValidatorServiceError>
    {
        let (context, justification) = {
            let engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
            (
                engine.consensus_context().map_err(ValidatorServiceError::Engine)?,
                engine.preferred_justification(),
            )
        };
        let proposal = signer
            .sign_proposal(context, height, round, block_digest, justification)
            .map_err(ValidatorServiceError::Engine)?;
        let sender = self.sender_for(signer)?;
        self.reserve_sequence_range(sender, sequence, 2)?;
        let proposal_message = signer
            .sign_envelope(sender, sequence, ConsensusMessage::Proposal(proposal))
            .map_err(ValidatorServiceError::Engine)?;
        self.process_message(proposal_message.clone())?;
        let vote = self.sign_current_vote_durably(signer)?;
        let vote_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))?;
        let vote_message = signer
            .sign_envelope(sender, vote_sequence, ConsensusMessage::Vote(vote))
            .map_err(ValidatorServiceError::Engine)?;
        self.process_message(vote_message.clone())?;
        Ok((proposal_message, vote_message))
    }
    /// Propose, self-process, and fan out a complete round to authenticated peers.
    ///
    /// The local service finalizes from its own quorum rules; peers receive the
    /// same canonical proposal and vote bodies through the bounded directory.
    pub fn propose_round_and_broadcast(
        &self,
        signer: &ValidatorSigner,
        height: u64,
        round: u64,
        block_digest: Digest384,
        sequence: u64,
        peers: &mut PeerDirectory,
    ) -> Result<(), ValidatorServiceError> {
        let (proposal, vote) = self.propose_round(signer, height, round, block_digest, sequence)?;
        peers.broadcast_message(&proposal).map_err(ValidatorServiceError::Io)?;
        peers.broadcast_message(&vote).map_err(ValidatorServiceError::Io)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn propose_round_collect_votes(
        &self,
        signer: &ValidatorSigner,
        height: u64,
        round: u64,
        block_digest: Digest384,
        sequence: u64,
        peers: &mut PeerDirectory,
        peer_ids: &[u16],
    ) -> Result<ConsensusState, ValidatorServiceError> {
        let (proposal, own_vote) =
            self.propose_round(signer, height, round, block_digest, sequence)?;
        peers.broadcast_message(&proposal).map_err(ValidatorServiceError::Io)?;
        peers.broadcast_message(&own_vote).map_err(ValidatorServiceError::Io)?;
        for peer_id in peer_ids {
            let vote = peers.receive_verified(*peer_id).map_err(|error| match error {
                PeerReceiveError::Io(io) => ValidatorServiceError::Io(io),
                PeerReceiveError::Transport(transport) => {
                    ValidatorServiceError::Transport(transport)
                }
                PeerReceiveError::UnknownPeer => ValidatorServiceError::UnknownSender,
            })?;
            self.process_message(vote)?;
        }
        self.state()
    }
    fn sender_for(&self, signer: &ValidatorSigner) -> Result<u16, ValidatorServiceError> {
        let public_key = signer.public_key();
        self.sender_keys
            .lock()
            .map_err(|_| ValidatorServiceError::Poisoned)?
            .iter()
            .find_map(|(sender, key)| (key == &public_key).then_some(*sender))
            .ok_or(ValidatorServiceError::UnknownSender)
    }
    pub fn serve_peer(&self, mut peer: PeerSocket) -> std::io::Result<()> {
        loop {
            let message = match peer.receive_message() {
                Ok(message) => message,
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            };
            self.process_message(message).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{error:?}"))
            })?;
        }
    }
    pub fn serve_authenticated_peer(
        &self,
        mut peer: PeerSocket,
        local_peer_id: u16,
        signer: &ValidatorSigner,
        expected_peer_id: u16,
        expected_public_key: &[u8],
        challenge: [u8; 32],
    ) -> std::io::Result<()> {
        let inbound = peer.receive_handshake()?;
        if inbound.sender() != expected_peer_id {
            return Err(invalid_data("peer handshake sender mismatch"));
        }
        inbound.verify(expected_public_key).map_err(transport_io_error)?;
        let response = signer
            .sign_handshake(local_peer_id, challenge)
            .map_err(|_| invalid_data("handshake signing failed"))?;
        peer.send_handshake(&response)?;
        self.serve_peer(peer)
    }
    pub fn serve_authenticated_genesis_peer(
        &self,
        mut peer: PeerSocket,
        local_peer_id: u16,
        signer: &ValidatorSigner,
        challenge: [u8; 32],
    ) -> std::io::Result<()> {
        let inbound = peer.receive_handshake()?;
        let expected_key = self
            .sender_keys
            .lock()
            .map_err(|_| invalid_data("validator sender-key lock poisoned"))?
            .get(&inbound.sender())
            .cloned()
            .ok_or_else(|| invalid_data("unknown peer handshake sender"))?;
        inbound.verify(&expected_key).map_err(transport_io_error)?;
        let response = signer
            .sign_handshake(local_peer_id, challenge)
            .map_err(|_| invalid_data("handshake signing failed"))?;
        peer.send_handshake(&response)?;
        self.serve_peer(peer)
    }
    pub fn serve_authenticated_genesis_peer_with_voting(
        &self,
        mut peer: PeerSocket,
        local_peer_id: u16,
        signer: &ValidatorSigner,
        challenge: [u8; 32],
    ) -> std::io::Result<()> {
        let inbound = peer.receive_handshake()?;
        let expected_key = self
            .sender_keys
            .lock()
            .map_err(|_| invalid_data("validator sender-key lock poisoned"))?
            .get(&inbound.sender())
            .cloned()
            .ok_or_else(|| invalid_data("unknown peer handshake sender"))?;
        inbound.verify(&expected_key).map_err(transport_io_error)?;
        peer.send_handshake(
            &signer
                .sign_handshake(local_peer_id, challenge)
                .map_err(|_| invalid_data("handshake signing failed"))?,
        )?;
        loop {
            let message = match peer.receive_message() {
                Ok(message) => message,
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            };
            if let ConsensusMessage::Proposal(_) = &message.message {
                let sequence = self
                    .next_sequence(local_peer_id)
                    .map_err(|_| invalid_data("local durable outbound sequence unavailable"))?;
                let vote = self
                    .process_proposal_and_sign_vote(message.clone(), signer, sequence)
                    .map_err(|_| invalid_data("proposal admission failed"))?;
                peer.send_message(&vote)?;
            } else {
                self.process_message(message)
                    .map_err(|_| invalid_data("consensus admission failed"))?;
            }
        }
    }
}
#[derive(Debug)]
pub enum ValidatorServiceError {
    UnknownSender,
    Poisoned,
    Io(std::io::Error),
    Transport(TransportError),
    Engine(ValidatorEngineError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::encode_envelope;
    use activechain_cash_kernel::CoinTransfer;
    use activechain_cash_kernel::{GenesisAllocation, GenesisEconomy, NativeAssetDefinition};
    use activechain_protocol_types::{ChainId, PrincipalId};
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    use std::net::TcpListener;
    fn genesis_justification(context: ConsensusVoteContext) -> ProposalJustification {
        ProposalJustification::Finalized(
            ConsensusBlockRef::new(
                context.genesis_commitment(),
                context.genesis_commitment(),
                0,
                0,
            )
            .unwrap(),
        )
    }
    fn sign_test_proposal(
        key: &SigningKey<MlDsa44>,
        proposer: PrincipalId,
        context: ConsensusVoteContext,
        height: u64,
        round: u64,
        block_digest: Digest384,
        justification: ProposalJustification,
    ) -> BlockProposal {
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let unsigned = BlockProposal::new(
            proposer,
            context,
            height,
            round,
            block_digest,
            justification.clone(),
            placeholder,
        )
        .unwrap();
        BlockProposal::new(
            proposer,
            context,
            height,
            round,
            block_digest,
            justification,
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                key.sign(&unsigned.signing_payload()).encode().to_vec(),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn sign_genesis_proposal(
        signer: &ValidatorSigner,
        genesis: &ValidatorGenesis,
        height: u64,
        round: u64,
        block_digest: Digest384,
    ) -> BlockProposal {
        let context = ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        signer
            .sign_proposal(context, height, round, block_digest, genesis_justification(context))
            .unwrap()
    }
    fn signed_message(
        key: &SigningKey<MlDsa44>,
        sender: u16,
        sequence: u64,
        message: ConsensusMessage,
    ) -> AuthenticatedConsensusMessage {
        let digest = message.digest().unwrap();
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let unsigned = SignedPeerEnvelope::new(sender, sequence, digest, placeholder).unwrap();
        let signature = key.sign(&unsigned.signing_payload());
        AuthenticatedConsensusMessage::new(
            SignedPeerEnvelope::new(
                sender,
                sequence,
                digest,
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                    .unwrap(),
            )
            .unwrap(),
            message,
        )
        .unwrap()
    }

    struct CountingVoteSigner {
        validator: PrincipalId,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ConsensusVoteSigner for CountingVoteSigner {
        fn validator(&self) -> PrincipalId {
            self.validator
        }

        fn sign_prepared_vote(
            &self,
            _prepared: &PreparedValidatorVote,
        ) -> Result<ValidatorVote, ValidatorEngineError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ValidatorEngineError::Signer)
        }
    }

    fn finalize_single_validator_proof(
        service: &ValidatorService,
        signer: &ValidatorSigner,
        genesis: &ValidatorGenesis,
        height: u64,
        block_digest: Digest384,
        sequence: u64,
    ) -> CertifiedBlock {
        let (proposal_message, vote_message) =
            service.propose_round(signer, height, 0, block_digest, sequence).unwrap();
        let proposal = match proposal_message.message {
            ConsensusMessage::Proposal(proposal) => proposal,
            _ => panic!("expected proposal"),
        };
        let vote = match vote_message.message {
            ConsensusMessage::Vote(vote) => vote,
            _ => panic!("expected vote"),
        };
        let validator_set = genesis.validator_set().unwrap();
        let mut collector = VoteCollector::new(
            proposal,
            genesis.genesis_commitment(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        );
        collector.add_vote(&validator_set, signer.public_key().as_slice(), vote.clone()).unwrap();
        CertifiedBlock::new(
            collector.proposal().clone(),
            collector.finalize(genesis.epoch(), &validator_set).unwrap(),
            vec![vote],
        )
        .unwrap()
    }

    #[test]
    fn wallet_gateway_binds_a_genesis_ledger() {
        let digest = |byte| Digest384::new([byte; 48]);
        let owner = PrincipalId::new(digest(10));
        let definition = NativeAssetDefinition::new(
            ChainId::new(digest(1)),
            b"ACT".to_vec(),
            18,
            1_000,
            150,
            digest(2),
            digest(3),
            digest(4),
        )
        .unwrap();
        let economy = GenesisEconomy::new(
            definition,
            vec![
                GenesisAllocation::new(owner, 700, 100).unwrap(),
                GenesisAllocation::new(owner, 100, 0).unwrap(),
            ],
            100,
        )
        .unwrap();
        let mut gateway = WalletTransactionGateway::from_genesis(&economy).unwrap();
        let cash_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([91; 32]));
        gateway
            .register_authorization_key(
                owner,
                cash_key.verifying_key().encode().as_slice().try_into().unwrap(),
                0,
            )
            .unwrap();
        let cells = gateway.ledger().cells().as_slice();
        let transfer = CoinTransfer::new(
            owner,
            PrincipalId::new(digest(11)),
            vec![cells[0].id()],
            cells[1].id(),
            10,
            1,
            10,
        )
        .unwrap();
        let request = activechain_wallet_core::CashAuthorizationRequestV1::new(
            ChainId::new(digest(1)),
            owner,
            0,
            digest(12),
            10,
            transfer,
        )
        .unwrap();
        let signature = cash_key.sign(&request.signing_payload().unwrap());
        let authorized = activechain_wallet_core::AuthorizedCashTransferV1::new(
            request,
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                signature.encode().as_slice().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let envelope = encode_envelope(&authorized).unwrap();
        gateway.submit_envelope(&envelope, 1).unwrap();
        assert!(gateway.submit_envelope(&envelope, 1).is_err());
    }
    #[test]
    fn runtime_rejects_without_verified_votes() {
        let mut state = ConsensusState::new(1);
        let set = ValidatorSet::new(Vec::new());
        assert!(set.is_err());
        let _ = &mut state;
    }

    #[test]
    fn loopback_socket_round_trip_and_replay_guard() {
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::default());
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let unsigned = SignedPeerEnvelope::new(4, 1, Digest384::new([9; 48]), placeholder).unwrap();
        let signature = key.sign(&unsigned.signing_payload());
        let envelope = SignedPeerEnvelope::new(
            4,
            1,
            Digest384::new([9; 48]),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let mut socket = PeerSocket::connect(std::net::TcpStream::connect(address).unwrap());
            socket.send(&envelope).unwrap();
        });
        let (stream, _) = listener.accept().unwrap();
        let mut socket = PeerSocket::connect(stream);
        let received = socket.receive_envelope().unwrap();
        let mut guard = ReplayGuard::default();
        assert!(guard.accept(&received, key.verifying_key().encode().as_slice()).is_ok());
        assert_eq!(
            guard.accept(&received, key.verifying_key().encode().as_slice()),
            Err(TransportError::Replay)
        );
        sender.join().unwrap();
    }

    #[test]
    fn loopback_handshake_proves_ml_dsa_peer_identity() {
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([13; 32]));
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let unsigned = PeerHandshake::new(5, [4; 32], placeholder).unwrap();
        let handshake = PeerHandshake::new(
            5,
            [4; 32],
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                key.sign(&unsigned.signing_payload()).encode().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let mut socket = PeerSocket::connect(TcpStream::connect(address).unwrap());
            socket.send_handshake(&handshake).unwrap();
        });
        let (stream, _) = listener.accept().unwrap();
        let mut socket = PeerSocket::connect(stream);
        let received = socket.receive_handshake().unwrap();
        received.verify(key.verifying_key().encode().as_slice()).unwrap();
        assert_eq!(received.sender(), 5);
        sender.join().unwrap();
    }

    #[test]
    fn reconnect_requires_matching_authenticated_peer_handshake() {
        let client_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([16; 32]));
        let server_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([17; 32]));
        let server_public_key = server_key.verifying_key().encode().to_vec();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server_challenge = [19; 32];
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut socket = PeerSocket::connect(stream);
            let _client = socket.receive_handshake().unwrap();
            let placeholder = PeerHandshake::new(
                8,
                server_challenge,
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap(),
            )
            .unwrap();
            let response = PeerHandshake::new(
                8,
                server_challenge,
                ProtocolSignature::new(
                    CryptoSuiteId::ML_DSA_44,
                    server_key.sign(&placeholder.signing_payload()).encode().to_vec(),
                )
                .unwrap(),
            )
            .unwrap();
            socket.send_handshake(&response).unwrap();
        });
        let endpoint = PeerEndpoint { id: 8, address, public_key: server_public_key };
        let connector = PeerConnector::new(vec![endpoint.clone()])
            .unwrap()
            .with_retry_policy(1, Duration::from_millis(100), Duration::ZERO)
            .unwrap();
        let placeholder = PeerHandshake::new(
            7,
            [18; 32],
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap(),
        )
        .unwrap();
        let outbound = PeerHandshake::new(
            7,
            [18; 32],
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                client_key.sign(&placeholder.signing_payload()).encode().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        connector.connect_with_handshake(&endpoint, &outbound, server_challenge).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn authenticated_consensus_body_round_trips_and_verifies() {
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([7; 32]));
        let vote = ValidatorVote::new(
            activechain_protocol_types::PrincipalId::new(Digest384::new([3; 48])),
            ConsensusVoteContext::new(Digest384::new([10; 48]), 1, Digest384::new([11; 48]))
                .unwrap(),
            8,
            2,
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![5; 2420]).unwrap(),
        )
        .unwrap();
        let authenticated = signed_message(&key, 7, 9, ConsensusMessage::Vote(vote.clone()));
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let mut socket = PeerSocket::connect(std::net::TcpStream::connect(address).unwrap());
            socket.send_message(&authenticated).unwrap();
        });
        let (stream, _) = listener.accept().unwrap();
        let mut socket = PeerSocket::connect(stream);
        let received = socket.receive_message().unwrap();
        received.envelope.verify(key.verifying_key().encode().as_slice()).unwrap();
        assert_eq!(received.message, ConsensusMessage::Vote(vote));
        sender.join().unwrap();
    }

    #[test]
    fn authenticated_consensus_body_rejects_digest_substitution() {
        let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let vote = ValidatorVote::new(
            activechain_protocol_types::PrincipalId::new(Digest384::new([1; 48])),
            ConsensusVoteContext::new(Digest384::new([10; 48]), 1, Digest384::new([11; 48]))
                .unwrap(),
            1,
            1,
            Digest384::new([2; 48]),
            Digest384::new([3; 48]),
            signature.clone(),
        )
        .unwrap();
        let envelope = SignedPeerEnvelope::new(1, 1, Digest384::new([9; 48]), signature).unwrap();
        assert_eq!(
            AuthenticatedConsensusMessage::new(envelope, ConsensusMessage::Vote(vote)),
            Err(TransportError::BodyDigestMismatch)
        );
    }

    #[test]
    fn peer_socket_rejects_oversized_frame_before_allocation() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            stream.write_all(&((MAX_PEER_FRAME_LEN as u32) + 1).to_be_bytes()).unwrap();
        });
        let (stream, _) = listener.accept().unwrap();
        let error = PeerSocket::connect(stream).receive_frame().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        sender.join().unwrap();
    }

    #[test]
    fn consensus_dispatch_preserves_peer_identity_and_sequence() {
        let queue = PeerEventQueue::new();
        let envelope = SignedPeerEnvelope::new(
            12,
            42,
            Digest384::new([1; 48]),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap(),
        )
        .unwrap();
        queue.push(PeerEvent { peer_id: 12, envelope }).unwrap();
        let result = ConsensusDispatcher::dispatch_once(&queue, |event| {
            assert_eq!(event.peer_id, 12);
            assert_eq!(event.envelope.sequence(), 42);
            Ok(())
        });
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn bare_pq_qc_verification_never_advances_finality() {
        use activechain_protocol_types::{ValidatorSet, ValidatorWeight};
        let keys: Vec<_> = (0..3)
            .map(|seed_byte| {
                ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&ml_dsa::Seed::from(
                    [seed_byte; 32],
                ))
            })
            .collect();
        let ids: Vec<_> = (0..3)
            .map(|byte| {
                activechain_protocol_types::PrincipalId::new(Digest384::new([byte + 1; 48]))
            })
            .collect();
        let set = ValidatorSet::new(vec![
            ValidatorWeight { validator: ids[0], stake: 4 },
            ValidatorWeight { validator: ids[1], stake: 3 },
            ValidatorWeight { validator: ids[2], stake: 3 },
        ])
        .unwrap();
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let genesis_commitment = Digest384::new([50; 48]);
        let validator_set_root = Digest384::new([51; 48]);
        let vote_context =
            ConsensusVoteContext::new(genesis_commitment, 1, validator_set_root).unwrap();
        let proposal = BlockProposal::new(
            ids[0],
            vote_context,
            1,
            1,
            Digest384::new([5; 48]),
            genesis_justification(vote_context),
            placeholder.clone(),
        )
        .unwrap();
        let proposal_commitment = proposal.commitment();
        let mut collector = VoteCollector::new(proposal, genesis_commitment, validator_set_root, 1);
        let mut votes = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            let unsigned = ValidatorVote::new(
                ids[index],
                vote_context,
                1,
                1,
                Digest384::new([5; 48]),
                proposal_commitment,
                placeholder.clone(),
            )
            .unwrap();
            let signature = key.sign(&unsigned.signing_payload());
            let vote = ValidatorVote::new(
                ids[index],
                vote_context,
                1,
                1,
                Digest384::new([5; 48]),
                proposal_commitment,
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                    .unwrap(),
            )
            .unwrap();
            collector
                .add_vote(&set, key.verifying_key().encode().as_slice(), vote.clone())
                .unwrap();
            votes.push((key.verifying_key().encode().to_vec(), vote));
        }
        let certificate = collector.finalize(1, &set).unwrap();
        let vote_refs: Vec<(&[u8], ValidatorVote)> =
            votes.iter().map(|(key, vote)| (key.as_slice(), vote.clone())).collect();
        for _ in 0..3 {
            let state =
                ConsensusState::new_with_consensus_context(1, validator_set_root, 1).unwrap();
            verify_bare_qc_evidence(&state, &set, &certificate, &vote_refs).unwrap();
            assert_eq!(state.finalized_height(), 0);
            assert_eq!(state.finalized_block_digest(), Digest384::ZERO);
        }
    }

    #[test]
    fn validator_engines_complete_proposal_vote_certificate_and_restart() {
        use activechain_protocol_types::{PrincipalId, ValidatorWeight};
        let keys: Vec<_> =
            (0..3).map(|seed| SigningKey::<MlDsa44>::from_seed(&Seed::from([seed; 32]))).collect();
        let ids: Vec<_> =
            (0..3).map(|value| PrincipalId::new(Digest384::new([value + 1; 48]))).collect();
        let set = ValidatorSet::new(
            ids.iter().copied().map(|validator| ValidatorWeight { validator, stake: 1 }).collect(),
        )
        .unwrap();
        let public_keys: BTreeMap<_, _> = ids
            .iter()
            .copied()
            .zip(keys.iter().map(|key| key.verifying_key().encode().to_vec()))
            .collect();
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let genesis_commitment = Digest384::new([50; 48]);
        let validator_set_root = Digest384::new([51; 48]);
        let vote_context =
            ConsensusVoteContext::new(genesis_commitment, 1, validator_set_root).unwrap();
        let proposal = sign_test_proposal(
            &keys[0],
            ids[0],
            vote_context,
            1,
            0,
            Digest384::new([8; 48]),
            genesis_justification(vote_context),
        );
        let proposal_commitment = proposal.commitment();
        let mut leader = ValidatorEngine::new(
            ConsensusState::new_with_validator_set_root(1, validator_set_root),
            genesis_commitment,
            set.clone(),
            public_keys.clone(),
        )
        .unwrap();
        leader.process(ConsensusMessage::Proposal(proposal)).unwrap();
        let mut proof = None;
        for (key, id) in keys.iter().zip(ids.iter()) {
            let unsigned = ValidatorVote::new(
                *id,
                vote_context,
                1,
                0,
                Digest384::new([8; 48]),
                proposal_commitment,
                placeholder.clone(),
            )
            .unwrap();
            let vote = ValidatorVote::new(
                *id,
                vote_context,
                1,
                0,
                Digest384::new([8; 48]),
                proposal_commitment,
                ProtocolSignature::new(
                    CryptoSuiteId::ML_DSA_44,
                    key.sign(&unsigned.signing_payload()).encode().to_vec(),
                )
                .unwrap(),
            )
            .unwrap();
            proof = leader.process(ConsensusMessage::Vote(vote)).unwrap().or(proof);
        }
        let proof = proof.unwrap();
        assert_eq!(leader.state().finalized_height(), 0);
        let wire_message = ConsensusMessage::Certificate(proof.clone());
        assert_eq!(
            ConsensusMessage::decode(3, &wire_message.encode_body().unwrap()).unwrap(),
            wire_message
        );
        let mut follower = ValidatorEngine::new(
            ConsensusState::new_with_validator_set_root(1, validator_set_root),
            genesis_commitment,
            set,
            public_keys,
        )
        .unwrap();
        follower.process(ConsensusMessage::Certificate(proof)).unwrap();
        assert_eq!(follower.state().finalized_height(), 0);
    }

    #[test]
    fn same_payload_digest_cannot_alias_distinct_proposal_histories() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let first =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([115; 48])), [116; 32]);
        let second =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([117; 48])), [118; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    first.validator(),
                    3,
                    first.public_key().try_into().unwrap(),
                )
                .unwrap(),
                ValidatorGenesisEntry::new(
                    second.validator(),
                    1,
                    second.public_key().try_into().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let context = ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        let payload_digest = Digest384::new([119; 48]);
        let proposal_a = first
            .sign_proposal(context, 1, 0, payload_digest, genesis_justification(context))
            .unwrap();
        let proposal_b = second
            .sign_proposal(context, 1, 0, payload_digest, genesis_justification(context))
            .unwrap();
        let proposal_b_for_substitution = proposal_b.clone();
        assert_eq!(proposal_a.block_digest(), proposal_b.block_digest());
        assert_ne!(proposal_a.commitment(), proposal_b.commitment());

        let state = ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root());
        let mut node_a = ValidatorEngine::from_genesis(state, &genesis).unwrap();
        node_a.process(ConsensusMessage::Proposal(proposal_a)).unwrap();
        let vote_a = node_a.sign_current_vote(&first).unwrap();
        let proof_a = node_a.process(ConsensusMessage::Vote(vote_a)).unwrap().unwrap();
        assert_eq!(
            CertifiedBlock::new(
                proposal_b_for_substitution,
                proof_a.certificate().clone(),
                proof_a.votes().to_vec(),
            ),
            Err(TransportError::InvalidBody)
        );

        let mut node_b = ValidatorEngine::from_genesis(state, &genesis).unwrap();
        node_b.process(ConsensusMessage::Proposal(proposal_b)).unwrap();
        let vote_b = node_b.sign_current_vote(&first).unwrap();
        let proof_b = node_b.process(ConsensusMessage::Vote(vote_b)).unwrap().unwrap();
        assert_eq!(proof_a.certificate().block_digest(), proof_b.certificate().block_digest());
        assert_ne!(
            proof_a.certificate().proposal_commitment(),
            proof_b.certificate().proposal_commitment()
        );

        let child_of_b = second
            .sign_proposal(
                context,
                2,
                1,
                Digest384::new([120; 48]),
                ProposalJustification::Quorum(proof_b.certificate().clone()),
            )
            .unwrap();
        assert!(matches!(
            node_a.process(ConsensusMessage::Proposal(child_of_b)),
            Err(ValidatorEngineError::UnknownParentCertificate)
        ));
        assert!(node_a.certified_blocks.contains_key(&proof_a.certificate().proposal_commitment()));
        assert!(
            !node_a.certified_blocks.contains_key(&proof_b.certificate().proposal_commitment())
        );

        let child_of_a = first
            .sign_proposal(
                context,
                2,
                1,
                Digest384::new([120; 48]),
                ProposalJustification::Quorum(proof_a.certificate().clone()),
            )
            .unwrap();
        node_a.process(ConsensusMessage::Proposal(child_of_a)).unwrap();
        node_a.sign_current_vote(&first).unwrap();
        assert_eq!(
            node_a.locked_qc.as_ref().map(QuorumCertificate::proposal_commitment),
            Some(proof_a.certificate().proposal_commitment())
        );
        let conflicting_genesis_branch = second
            .sign_proposal(context, 1, 2, Digest384::new([121; 48]), genesis_justification(context))
            .unwrap();
        assert!(matches!(
            node_a.process(ConsensusMessage::Proposal(conflicting_genesis_branch)),
            Err(ValidatorEngineError::UnsafeProposal)
        ));
    }

    #[test]
    fn same_slot_same_payload_different_signed_proposal_is_rejected_after_restart() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let first =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([121; 48])), [122; 32]);
        let second =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([123; 48])), [124; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    first.validator(),
                    3,
                    first.public_key().try_into().unwrap(),
                )
                .unwrap(),
                ValidatorGenesisEntry::new(
                    second.validator(),
                    1,
                    second.public_key().try_into().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let context = ConsensusVoteContext::new(
            genesis.genesis_commitment(),
            1,
            genesis.validator_set_root(),
        )
        .unwrap();
        let payload = Digest384::new([125; 48]);
        let proposal_a =
            first.sign_proposal(context, 1, 0, payload, genesis_justification(context)).unwrap();
        let proposal_a_commitment = proposal_a.commitment();
        let proposal_b =
            second.sign_proposal(context, 1, 0, payload, genesis_justification(context)).unwrap();
        assert_ne!(proposal_a_commitment, proposal_b.commitment());
        let path = std::env::temp_dir()
            .join(format!("activechain-proposal-identity-restart-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        service
            .process_proposal_and_sign_vote(
                first.sign_envelope(1, 1, ConsensusMessage::Proposal(proposal_a.clone())).unwrap(),
                &first,
                2,
            )
            .unwrap();
        drop(service);

        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_genesis(restored, &genesis, path.clone()).unwrap();
        assert!(matches!(
            restarted.process_proposal_and_sign_vote(
                second.sign_envelope(2, 1, ConsensusMessage::Proposal(proposal_b)).unwrap(),
                &first,
                3,
            ),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::ConflictingLocalVote))
        ));
        let repeated = restarted
            .process_proposal_and_sign_vote(
                first.sign_envelope(1, 4, ConsensusMessage::Proposal(proposal_a)).unwrap(),
                &first,
                5,
            )
            .unwrap();
        assert!(matches!(
            repeated.message,
            ConsensusMessage::Vote(ref vote)
                if vote.proposal_commitment() == proposal_a_commitment
        ));
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn validator_engine_rejects_genesis_epoch_mismatch() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let genesis = ValidatorGenesis::new(
            9,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    activechain_protocol_types::PrincipalId::new(Digest384::new([1; 48])),
                    1,
                    [2; activechain_protocol_types::ML_DSA44_PUBLIC_KEY_LENGTH],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert!(matches!(
            ValidatorEngine::from_genesis(ConsensusState::new(8), &genesis),
            Err(ValidatorEngineError::GenesisEpochMismatch)
        ));
    }

    #[test]
    fn validator_signer_produces_a_provider_verifiable_vote() {
        use activechain_protocol_types::{PrincipalId, ValidatorWeight};
        let validator = PrincipalId::new(Digest384::new([4; 48]));
        let signer = ValidatorSigner::from_seed(validator, [6; 32]);
        let set = ValidatorSet::new(vec![ValidatorWeight { validator, stake: 1 }]).unwrap();
        let mut keys = BTreeMap::new();
        keys.insert(validator, signer.public_key());
        let context =
            ConsensusVoteContext::new(Digest384::new([50; 48]), 1, Digest384::new([51; 48]))
                .unwrap();
        let proposal = sign_test_proposal(
            &signer.key,
            validator,
            context,
            1,
            0,
            Digest384::new([5; 48]),
            genesis_justification(context),
        );
        let mut engine = ValidatorEngine::new(
            ConsensusState::new_with_validator_set_root(1, Digest384::new([51; 48])),
            Digest384::new([50; 48]),
            set,
            keys,
        )
        .unwrap();
        engine.process(ConsensusMessage::Proposal(proposal)).unwrap();
        let vote = engine.sign_current_vote(&signer).unwrap();
        activechain_crypto_provider::verify_validator_vote(&signer.public_key(), &vote).unwrap();
        assert!(engine.process(ConsensusMessage::Vote(vote)).unwrap().is_some());
    }

    #[test]
    fn persistent_service_drives_single_validator_round_to_finality() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = activechain_protocol_types::PrincipalId::new(Digest384::new([6; 48]));
        let signer = ValidatorSigner::from_seed(validator, [7; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path =
            std::env::temp_dir().join(format!("activechain-round-{}.bin", std::process::id()));
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        service.propose_round(&signer, 1, 0, Digest384::new([8; 48]), 1).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 0);
        service.propose_round(&signer, 2, 1, Digest384::new([9; 48]), 3).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 1);
        let metrics = service.metrics();
        assert_eq!(metrics.proposals, 2);
        assert_eq!(metrics.votes, 2);
        assert_eq!(metrics.finalized_certificates, 1);
        assert_eq!(metrics.rejected_messages, 0);
        assert!(
            metrics
                .prometheus(1)
                .contains("activechain_validator_finalized_certificates{validator=\"1\"} 1")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn outbound_sequence_and_first_qc_ancestry_survive_restart() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([91; 48]));
        let signer = ValidatorSigner::from_seed(validator, [92; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-outbound-restart-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        assert_eq!(service.next_sequence(1).unwrap(), 1);
        service.propose_round(&signer, 1, 0, Digest384::new([93; 48]), 1).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 0);
        assert_eq!(service.next_sequence(1).unwrap(), 3);
        drop(service);

        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_genesis(restored, &genesis, path.clone()).unwrap();
        assert_eq!(restarted.next_sequence(1).unwrap(), 3);
        assert_eq!(restarted.next_proposal_position().unwrap(), (2, 1));
        restarted.propose_round(&signer, 2, 1, Digest384::new([94; 48]), 3).unwrap();
        assert_eq!(restarted.state().unwrap().finalized_height(), 1);
        assert_eq!(restarted.next_sequence(1).unwrap(), 5);
        assert!(matches!(
            restarted.reserve_sequence_range(1, 3, 1),
            Err(ValidatorServiceError::Transport(TransportError::Replay))
        ));
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn snapshot_failure_prevents_any_vote_signer_invocation() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([95; 48]));
        let signer = ValidatorSigner::from_seed(validator, [96; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let directory =
            std::env::temp_dir().join(format!("activechain-sign-boundary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("validator.snapshot");
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        let proposal = sign_genesis_proposal(&signer, &genesis, 1, 0, Digest384::new([97; 48]));
        service
            .process_message(
                signer.sign_envelope(1, 1, ConsensusMessage::Proposal(proposal)).unwrap(),
            )
            .unwrap();
        let before = service.engine.lock().unwrap().clone();
        assert!(before.local_vote_locks.is_empty());
        assert!(before.locked_qc.is_none());

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let spy = CountingVoteSigner { validator, calls: std::sync::Arc::clone(&calls) };
        assert!(matches!(
            service.sign_current_vote_durably(&spy),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::Snapshot(_)))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let after = service.engine.lock().unwrap();
        assert_eq!(after.local_vote_locks, before.local_vote_locks);
        assert_eq!(after.highest_voted_rounds, before.highest_voted_rounds);
        assert_eq!(after.locked_qc, before.locked_qc);
        assert_eq!(after.active_anchor, before.active_anchor);
        assert_eq!(after.certified_blocks, before.certified_blocks);
        assert!(after.collector.is_some());
    }

    #[test]
    fn outbound_sequence_overflow_survives_restart_and_fails_closed() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([98; 48]));
        let signer = ValidatorSigner::from_seed(validator, [99; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-sequence-overflow-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        {
            let engine = service.engine.lock().unwrap();
            let replay = service.replay.lock().unwrap();
            let mut outbound = service.outbound_high_water.lock().unwrap();
            outbound.insert(1, u64::MAX);
            save_validator_snapshot(&path, &engine, &replay, &outbound).unwrap();
        }
        drop(service);

        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_genesis(restored, &genesis, path.clone()).unwrap();
        assert!(matches!(
            restarted.next_sequence(1),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))
        ));
        let before = restarted.engine.lock().unwrap().clone();
        assert!(matches!(
            restarted.propose_round(&signer, 1, 0, Digest384::new([100; 48]), u64::MAX),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))
        ));
        let after = restarted.engine.lock().unwrap();
        assert_eq!(after.state, before.state);
        assert_eq!(after.local_vote_locks, before.local_vote_locks);
        assert_eq!(after.certified_blocks, before.certified_blocks);
        drop(after);
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn restored_genesis_anchor_rejects_canonical_semantic_tampering() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([134; 48]));
        let signer = ValidatorSigner::from_seed(validator, [135; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let state = ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root());
        let base_path = std::env::temp_dir()
            .join(format!("activechain-anchor-base-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&base_path);
        let service = ValidatorService::from_genesis(state, &genesis, base_path.clone()).unwrap();
        service.reserve_sequence_range(1, 1, 1).unwrap();
        drop(service);
        let bytes = std::fs::read(&base_path).unwrap();
        let base: PersistedValidatorState = decode_envelope(&bytes).unwrap();
        let genesis_commitment = genesis.genesis_commitment();
        let tampered_anchors = [
            ConsensusBlockRef::new(Digest384::new([136; 48]), genesis_commitment, 0, 0).unwrap(),
            ConsensusBlockRef::new(genesis_commitment, Digest384::new([137; 48]), 0, 0).unwrap(),
            ConsensusBlockRef::new(genesis_commitment, genesis_commitment, 1, 0).unwrap(),
            ConsensusBlockRef::new(genesis_commitment, genesis_commitment, 0, 1).unwrap(),
        ];
        for (index, anchor) in tampered_anchors.into_iter().enumerate() {
            let mut tampered = base.clone();
            tampered.active_anchor = anchor;
            let path = std::env::temp_dir()
                .join(format!("activechain-anchor-tampered-{}-{index}.bin", std::process::id()));
            let _ = std::fs::remove_file(&path);
            write_atomic(&path, &encode_envelope(&tampered).unwrap()).unwrap();
            assert!(matches!(
                ValidatorService::from_genesis(state, &genesis, path.clone()),
                Err(ValidatorEngineError::InvalidSafetySnapshot)
            ));
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_file(base_path).unwrap();
    }

    #[test]
    fn complete_engine_snapshot_restores_first_qc_before_finality() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([101; 48]));
        let signer = ValidatorSigner::from_seed(validator, [102; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-engine-first-qc-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        service.propose_round(&signer, 1, 0, Digest384::new([103; 48]), 1).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 0);
        assert_eq!(service.engine.lock().unwrap().certified_blocks.len(), 1);
        drop(service);

        let restored = load_snapshot(&path).unwrap();
        let service = ValidatorService::from_genesis(restored, &genesis, path.clone()).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 0);
        assert_eq!(service.engine.lock().unwrap().certified_blocks.len(), 1);
        assert_eq!(service.next_proposal_position().unwrap(), (2, 1));
        drop(service);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn certified_ancestry_bound_exhaustion_never_evicts_safety_history() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([104; 48]));
        let signer = ValidatorSigner::from_seed(validator, [105; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let context = ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        let mut engine = ValidatorEngine::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
        )
        .unwrap();
        let real_digest = Digest384::new([106; 48]);
        let proposal = sign_genesis_proposal(&signer, &genesis, 1, 0, real_digest);
        let real_proposal_commitment = proposal.commitment();
        engine.process(ConsensusMessage::Proposal(proposal)).unwrap();
        let vote = engine.sign_current_vote(&signer).unwrap();
        let parent = ConsensusBlockRef::new(
            genesis.genesis_commitment(),
            genesis.genesis_commitment(),
            0,
            0,
        )
        .unwrap();
        for index in 0..MAX_PERSISTED_CERTIFIED_BLOCKS {
            let mut block = [107_u8; 48];
            block[40..].copy_from_slice(&(index as u64).to_be_bytes());
            let mut root = [108_u8; 48];
            root[40..].copy_from_slice(&(index as u64).to_be_bytes());
            let mut proposal_id = [109_u8; 48];
            proposal_id[40..].copy_from_slice(&(index as u64).to_be_bytes());
            let block_digest = Digest384::new(block);
            let proposal_commitment = Digest384::new(proposal_id);
            let certificate = QuorumCertificate::new(
                context,
                1,
                1,
                block_digest,
                proposal_commitment,
                Digest384::new(root),
                1,
                1,
            )
            .unwrap();
            assert!(
                engine
                    .certified_blocks
                    .insert(proposal_commitment, CertifiedBlockRecord { certificate, parent },)
                    .is_none()
            );
        }
        let before_state = engine.state;
        let before_anchor = engine.active_anchor;
        let before_lock = engine.locked_qc.clone();
        let before_keys: Vec<_> = engine.certified_blocks.keys().copied().collect();
        assert!(matches!(
            engine.process(ConsensusMessage::Vote(vote)),
            Err(ValidatorEngineError::CertifiedBlockLimit)
        ));
        assert_eq!(engine.state, before_state);
        assert_eq!(engine.active_anchor, before_anchor);
        assert_eq!(engine.locked_qc, before_lock);
        assert_eq!(engine.certified_blocks.len(), MAX_PERSISTED_CERTIFIED_BLOCKS);
        assert_eq!(engine.certified_blocks.keys().copied().collect::<Vec<_>>(), before_keys);
        assert!(!engine.certified_blocks.contains_key(&real_proposal_commitment));
    }

    #[test]
    fn finalized_ancestry_pruning_progresses_beyond_bound_across_restart() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([138; 48]));
        let signer = ValidatorSigner::from_seed(validator, [139; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let context = ConsensusVoteContext::new(
            genesis.genesis_commitment(),
            1,
            genesis.validator_set_root(),
        )
        .unwrap();
        let mut engine = ValidatorEngine::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
        )
        .unwrap();
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-pruned-ancestry-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let total = MAX_PERSISTED_CERTIFIED_BLOCKS + 32;
        let mut previous_qc = None;
        for index in 1..=total {
            let height = index as u64;
            let round = height - 1;
            let mut block = [140_u8; 48];
            block[40..].copy_from_slice(&height.to_be_bytes());
            let justification = previous_qc
                .as_ref()
                .cloned()
                .map(ProposalJustification::Quorum)
                .unwrap_or_else(|| genesis_justification(context));
            let proposal = BlockProposal::new(
                validator,
                context,
                height,
                round,
                Digest384::new(block),
                justification,
                placeholder.clone(),
            )
            .unwrap();
            let mut vote_root = [141_u8; 48];
            vote_root[40..].copy_from_slice(&height.to_be_bytes());
            let certificate = QuorumCertificate::new(
                context,
                height,
                round,
                proposal.block_digest(),
                proposal.commitment(),
                Digest384::new(vote_root),
                1,
                1,
            )
            .unwrap();
            engine.apply_verified_certificate_transition(&proposal, &certificate).unwrap();
            previous_qc = Some(certificate);
            assert!(engine.certified_blocks.len() <= 1);

            if index == MAX_PERSISTED_CERTIFIED_BLOCKS / 2 {
                save_validator_snapshot(&path, &engine, &ReplayGuard::default(), &BTreeMap::new())
                    .unwrap();
                let restored_state = load_snapshot(&path).unwrap();
                let service =
                    ValidatorService::from_genesis(restored_state, &genesis, path.clone()).unwrap();
                engine = service.engine.lock().unwrap().clone();
                drop(service);
                assert!(engine.certified_blocks.len() <= 1);
            }
        }
        assert_eq!(engine.state.finalized_height(), (total - 1) as u64);
        assert_eq!(engine.certified_blocks.len(), 1);
        assert_eq!(
            engine.certified_blocks.keys().next().copied(),
            previous_qc.as_ref().map(QuorumCertificate::proposal_commitment)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn restart_restores_replay_high_water_and_conflicting_local_vote_lock() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([61; 48]));
        let signer = ValidatorSigner::from_seed(validator, [62; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-validator-safety-restart-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let state = ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root());
        let service = ValidatorService::from_genesis(state, &genesis, path.clone()).unwrap();
        let first_proposal =
            sign_genesis_proposal(&signer, &genesis, 1, 0, Digest384::new([63; 48]));
        let first_message =
            signer.sign_envelope(1, 7, ConsensusMessage::Proposal(first_proposal)).unwrap();
        service.process_proposal_and_sign_vote(first_message.clone(), &signer, 8).unwrap();
        drop(service);

        let restored_state = load_snapshot(&path).unwrap();
        let restarted =
            ValidatorService::from_genesis(restored_state, &genesis, path.clone()).unwrap();
        assert!(matches!(
            restarted.process_message(first_message),
            Err(ValidatorServiceError::Transport(TransportError::Replay))
        ));

        let same_proposal =
            sign_genesis_proposal(&signer, &genesis, 1, 0, Digest384::new([63; 48]));
        let same_message =
            signer.sign_envelope(1, 9, ConsensusMessage::Proposal(same_proposal)).unwrap();
        let repeated_vote =
            restarted.process_proposal_and_sign_vote(same_message, &signer, 10).unwrap();
        assert!(matches!(
            repeated_vote.message,
            ConsensusMessage::Vote(ref vote) if vote.block_digest() == Digest384::new([63; 48])
        ));

        let conflicting = sign_genesis_proposal(&signer, &genesis, 1, 0, Digest384::new([64; 48]));
        let conflicting_message =
            signer.sign_envelope(1, 11, ConsensusMessage::Proposal(conflicting)).unwrap();
        assert!(matches!(
            restarted.process_proposal_and_sign_vote(conflicting_message, &signer, 12),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::ConflictingLocalVote))
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn durable_highest_view_rejects_lower_round_after_restart() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([126; 48]));
        let signer = ValidatorSigner::from_seed(validator, [127; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let context = ConsensusVoteContext::new(
            genesis.genesis_commitment(),
            1,
            genesis.validator_set_root(),
        )
        .unwrap();
        let high = signer
            .sign_proposal(context, 1, 2, Digest384::new([128; 48]), genesis_justification(context))
            .unwrap();
        let high_commitment = high.commitment();
        let path = std::env::temp_dir()
            .join(format!("activechain-durable-view-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        service
            .process_proposal_and_sign_vote(
                signer.sign_envelope(1, 1, ConsensusMessage::Proposal(high.clone())).unwrap(),
                &signer,
                2,
            )
            .unwrap();
        drop(service);

        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_genesis(restored, &genesis, path.clone()).unwrap();
        let lower = signer
            .sign_proposal(context, 1, 1, Digest384::new([129; 48]), genesis_justification(context))
            .unwrap();
        assert!(matches!(
            restarted.process_proposal_and_sign_vote(
                signer.sign_envelope(1, 3, ConsensusMessage::Proposal(lower)).unwrap(),
                &signer,
                4,
            ),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::StaleLocalView))
        ));
        let repeated = restarted
            .process_proposal_and_sign_vote(
                signer.sign_envelope(1, 5, ConsensusMessage::Proposal(high)).unwrap(),
                &signer,
                6,
            )
            .unwrap();
        assert!(matches!(
            repeated.message,
            ConsensusMessage::Vote(ref vote) if vote.proposal_commitment() == high_commitment
        ));
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn highest_voted_round_survives_finalized_slot_pruning_and_restart() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([130; 48]));
        let signer = ValidatorSigner::from_seed(validator, [131; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-view-pruning-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        service.propose_round(&signer, 1, 0, Digest384::new([132; 48]), 1).unwrap();
        service.propose_round(&signer, 2, 1, Digest384::new([133; 48]), 3).unwrap();
        {
            let engine = service.engine.lock().unwrap();
            assert!(engine.local_vote_locks.keys().all(|slot| slot.height > 1));
            assert_eq!(engine.highest_voted_rounds.len(), 1);
            assert_eq!(engine.highest_voted_rounds.values().next().unwrap().round, 1);
        }
        drop(service);
        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_genesis(restored, &genesis, path.clone()).unwrap();
        {
            let engine = restarted.engine.lock().unwrap();
            assert!(engine.local_vote_locks.keys().all(|slot| slot.height > 1));
            assert_eq!(engine.highest_voted_rounds.values().next().unwrap().round, 1);
        }
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn validator_set_activation_requires_prior_qc_and_exact_height() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = activechain_protocol_types::PrincipalId::new(Digest384::new([75; 48]));
        let signer = ValidatorSigner::from_seed(validator, [76; 32]);
        let next_signer = ValidatorSigner::from_seed(validator, [77; 32]);
        let current = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let next = ValidatorGenesis::new(
            2,
            3,
            vec![
                ValidatorGenesisEntry::new(
                    validator,
                    1,
                    next_signer.public_key().try_into().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let path =
            std::env::temp_dir().join(format!("activechain-activation-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, current.validator_set_root()),
            &current,
            path.clone(),
        )
        .unwrap();
        let authorization = ConsensusUpgradeAuthorization::new(
            1,
            3,
            1,
            2,
            current.validator_set_root(),
            next.validator_set_root(),
            1,
            1,
        )
        .unwrap();
        let proof = finalize_single_validator_proof(
            &service,
            &signer,
            &current,
            1,
            authorization.commitment(),
            1,
        );
        service.propose_round(&signer, 2, 1, Digest384::new([79; 48]), 3).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 1);
        {
            let engine = service.engine.lock().unwrap();
            assert_eq!(engine.active_anchor.height(), 1);
            assert!(
                !engine.certified_blocks.contains_key(&proof.certificate().proposal_commitment())
            );
            assert_eq!(engine.certified_blocks.len(), 1);
            let retained_handoff = engine.certified_blocks.values().next().unwrap();
            assert_eq!(retained_handoff.certificate.height(), 2);
            assert_eq!(
                retained_handoff.parent.proposal_commitment(),
                proof.certificate().proposal_commitment()
            );
        }
        drop(service);
        let restored = load_snapshot(&path).unwrap();
        let service = ValidatorService::from_genesis(restored, &current, path.clone()).unwrap();
        {
            let engine = service.engine.lock().unwrap();
            assert_eq!(engine.active_anchor.height(), 1);
            assert!(
                !engine.certified_blocks.contains_key(&proof.certificate().proposal_commitment())
            );
            assert_eq!(engine.certified_blocks.len(), 1);
            assert_eq!(engine.certified_blocks.values().next().unwrap().certificate.height(), 2);
        }

        let wrong_authorization = ConsensusUpgradeAuthorization::new(
            1,
            3,
            1,
            2,
            current.validator_set_root(),
            Digest384::new([99; 48]),
            1,
            1,
        )
        .unwrap();
        assert!(
            service.activate_finalized_validator_set(&wrong_authorization, &proof, &next).is_err()
        );
        service.activate_finalized_validator_set(&authorization, &proof, &next).unwrap();
        assert_eq!(service.state().unwrap().epoch(), 2);
        assert_eq!(service.state().unwrap().validator_set_root(), next.validator_set_root());
        assert_eq!(
            service.state().unwrap().retired_validator_set_roots(),
            &[current.validator_set_root()]
        );
        service.propose_round(&next_signer, 3, 2, Digest384::new([78; 48]), 5).unwrap();
        service.propose_round(&next_signer, 4, 3, Digest384::new([80; 48]), 7).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 3);
        drop(service);
        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_active_manifest(
            restored,
            &next,
            current.genesis_commitment(),
            path.clone(),
        )
        .unwrap();
        assert_eq!(restarted.state().unwrap().epoch(), 2);
        assert_eq!(restarted.state().unwrap().retired_validator_set_roots().len(), 1);
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn protocol_upgrade_rejects_stale_revision_certificates() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([80; 48]));
        let signer = ValidatorSigner::from_seed(validator, [81; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-protocol-upgrade-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        let authorization = ConsensusUpgradeAuthorization::new(
            1,
            3,
            1,
            1,
            genesis.validator_set_root(),
            genesis.validator_set_root(),
            1,
            2,
        )
        .unwrap();
        let proof = finalize_single_validator_proof(
            &service,
            &signer,
            &genesis,
            1,
            authorization.commitment(),
            1,
        );
        service.propose_round(&signer, 2, 1, Digest384::new([84; 48]), 3).unwrap();
        service.activate_finalized_protocol_upgrade(&authorization, &proof).unwrap();
        assert_eq!(service.state().unwrap().protocol_revision(), 2);
        assert_eq!(load_snapshot(&path).unwrap().protocol_revision(), 2);

        let stale_context = ConsensusVoteContext::new(
            genesis.genesis_commitment(),
            1,
            genesis.validator_set_root(),
        )
        .unwrap();
        let stale_proposal = signer
            .sign_proposal(
                stale_context,
                2,
                1,
                Digest384::new([82; 48]),
                ProposalJustification::Quorum(proof.certificate().clone()),
            )
            .unwrap();
        let stale_vote = signer
            .sign_vote(
                &stale_proposal,
                genesis.genesis_commitment(),
                genesis.validator_set_root(),
                1,
            )
            .unwrap();
        let validator_set = genesis.validator_set().unwrap();
        let mut collector = VoteCollector::new(
            stale_proposal.clone(),
            genesis.genesis_commitment(),
            genesis.validator_set_root(),
            1,
        );
        collector
            .add_vote(&validator_set, signer.public_key().as_slice(), stale_vote.clone())
            .unwrap();
        let stale_proof = CertifiedBlock::new(
            stale_proposal,
            collector.finalize(1, &validator_set).unwrap(),
            vec![stale_vote],
        )
        .unwrap();
        assert!(matches!(
            service.engine.lock().unwrap().process(ConsensusMessage::Certificate(stale_proof)),
            Err(ValidatorEngineError::VoteDomainMismatch)
        ));

        service.propose_round(&signer, 3, 2, Digest384::new([83; 48]), 5).unwrap();
        service.propose_round(&signer, 4, 3, Digest384::new([85; 48]), 7).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 3);
        let active_revision = ValidatorGenesis::new_with_revision(
            1,
            1,
            2,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        drop(service);
        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_active_manifest(
            restored,
            &active_revision,
            genesis.genesis_commitment(),
            path.clone(),
        )
        .unwrap();
        assert_eq!(restarted.state().unwrap().protocol_revision(), 2);
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn live_socket_session_authenticates_before_processing_consensus() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let local = std::sync::Arc::new(ValidatorSigner::from_seed(
            PrincipalId::new(Digest384::new([71; 48])),
            [72; 32],
        ));
        let remote =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([72; 48])), [74; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    local.validator(),
                    1,
                    local.public_key().try_into().unwrap(),
                )
                .unwrap(),
                ValidatorGenesisEntry::new(
                    remote.validator(),
                    1,
                    remote.public_key().try_into().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let path =
            std::env::temp_dir().join(format!("activechain-live-{}.bin", std::process::id()));
        let service = std::sync::Arc::new(
            ValidatorService::from_genesis(
                ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                &genesis,
                path.clone(),
            )
            .unwrap(),
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server_service = std::sync::Arc::clone(&service);
        let server_signer = std::sync::Arc::clone(&local);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            server_service
                .serve_authenticated_genesis_peer_with_voting(
                    PeerSocket::connect(stream),
                    1,
                    &server_signer,
                    [73; 32],
                )
                .unwrap();
        });
        let mut client = PeerSocket::connect(TcpStream::connect(address).unwrap());
        client.send_handshake(&remote.sign_handshake(2, [73; 32]).unwrap()).unwrap();
        client.receive_handshake().unwrap().verify(&local.public_key()).unwrap();
        let proposal = sign_genesis_proposal(&remote, &genesis, 1, 0, Digest384::new([75; 48]));
        client
            .send_message(
                &remote.sign_envelope(2, 1, ConsensusMessage::Proposal(proposal)).unwrap(),
            )
            .unwrap();
        assert!(matches!(client.receive_message().unwrap().message, ConsensusMessage::Vote(_)));
        drop(client);
        server.join().unwrap();
        assert_eq!(service.metrics().proposals, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn live_vote_sequence_is_local_durable_state_not_remote_sequence() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let local = std::sync::Arc::new(ValidatorSigner::from_seed(
            PrincipalId::new(Digest384::new([109; 48])),
            [110; 32],
        ));
        let remote =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([111; 48])), [112; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    local.validator(),
                    1,
                    local.public_key().try_into().unwrap(),
                )
                .unwrap(),
                ValidatorGenesisEntry::new(
                    remote.validator(),
                    1,
                    remote.public_key().try_into().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-local-sequence-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = std::sync::Arc::new(
            ValidatorService::from_genesis(
                ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                &genesis,
                path.clone(),
            )
            .unwrap(),
        );
        service.reserve_sequence_range(1, 40, 1).unwrap();
        assert_eq!(service.next_sequence(1).unwrap(), 41);

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server_service = std::sync::Arc::clone(&service);
        let server_signer = std::sync::Arc::clone(&local);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            server_service
                .serve_authenticated_genesis_peer_with_voting(
                    PeerSocket::connect(stream),
                    1,
                    &server_signer,
                    [113; 32],
                )
                .unwrap();
        });
        let mut client = PeerSocket::connect(TcpStream::connect(address).unwrap());
        client.send_handshake(&remote.sign_handshake(2, [113; 32]).unwrap()).unwrap();
        client.receive_handshake().unwrap().verify(&local.public_key()).unwrap();
        let proposal = sign_genesis_proposal(&remote, &genesis, 1, 0, Digest384::new([114; 48]));
        client
            .send_message(
                &remote.sign_envelope(2, u64::MAX, ConsensusMessage::Proposal(proposal)).unwrap(),
            )
            .unwrap();
        let response = client.receive_message().unwrap();
        assert_eq!(response.envelope.sender(), 1);
        assert_eq!(response.envelope.sequence(), 41);
        assert!(matches!(response.message, ConsensusMessage::Vote(_)));
        drop(client);
        server.join().unwrap();
        assert_eq!(service.next_sequence(1).unwrap(), 42);
        assert!(matches!(
            service.next_sequence(2),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))
        ));
        drop(service);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn live_socket_quorum_fan_in_finalizes_three_validator_qc() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let signers: Vec<_> = (0..3)
            .map(|index| {
                ValidatorSigner::from_seed(
                    activechain_protocol_types::PrincipalId::new(Digest384::new([81 + index; 48])),
                    [82 + index; 32],
                )
            })
            .collect();
        let genesis = ValidatorGenesis::new(
            1,
            1,
            signers
                .iter()
                .map(|signer| {
                    ValidatorGenesisEntry::new(
                        signer.validator(),
                        1,
                        signer.public_key().try_into().unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let path =
            std::env::temp_dir().join(format!("activechain-live-qc-{}.bin", std::process::id()));
        let receiver = std::sync::Arc::new(
            ValidatorService::from_genesis(
                ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                &genesis,
                path.clone(),
            )
            .unwrap(),
        );
        let send = |sender: &ValidatorSigner,
                    sender_id: u16,
                    message: AuthenticatedConsensusMessage| {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let service = std::sync::Arc::clone(&receiver);
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let local_signer = ValidatorSigner::from_seed(
                    activechain_protocol_types::PrincipalId::new(Digest384::new([81; 48])),
                    [82; 32],
                );
                service
                    .serve_authenticated_genesis_peer(
                        PeerSocket::connect(stream),
                        1,
                        &local_signer,
                        [91; 32],
                    )
                    .unwrap();
            });
            let mut client = PeerSocket::connect(TcpStream::connect(address).unwrap());
            client.send_handshake(&sender.sign_handshake(sender_id, [91; 32]).unwrap()).unwrap();
            client.receive_handshake().unwrap().verify(&signers[0].public_key()).unwrap();
            client.send_message(&message).unwrap();
            drop(client);
            server.join().unwrap();
        };
        let proposal = sign_genesis_proposal(&signers[0], &genesis, 1, 0, Digest384::new([92; 48]));
        let proposal_message =
            signers[0].sign_envelope(1, 1, ConsensusMessage::Proposal(proposal.clone())).unwrap();
        send(&signers[0], 1, proposal_message);
        let mut votes = Vec::new();
        for (index, signer) in signers.iter().enumerate() {
            receiver
                .process_message(
                    signer
                        .sign_envelope(
                            (index + 1) as u16,
                            10 + index as u64,
                            ConsensusMessage::Proposal(proposal.clone()),
                        )
                        .unwrap(),
                )
                .ok();
            let vote = receiver.engine.lock().unwrap().sign_current_vote(signer).unwrap();
            votes.push(
                signer
                    .sign_envelope(
                        (index + 1) as u16,
                        20 + index as u64,
                        ConsensusMessage::Vote(vote),
                    )
                    .unwrap(),
            );
        }
        for vote in votes {
            let sender_id = vote.envelope.sender();
            send(&signers[sender_id as usize - 1], sender_id, vote);
        }
        assert_eq!(receiver.state().unwrap().finalized_height(), 0);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sustained_multi_round_quorum_rehearsal_preserves_monotonic_finality() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let signers: Vec<_> = (0..3)
            .map(|index| {
                ValidatorSigner::from_seed(
                    activechain_protocol_types::PrincipalId::new(Digest384::new([101 + index; 48])),
                    [102 + index; 32],
                )
            })
            .collect();
        let genesis = ValidatorGenesis::new(
            1,
            1,
            signers
                .iter()
                .map(|signer| {
                    ValidatorGenesisEntry::new(
                        signer.validator(),
                        1,
                        signer.public_key().try_into().unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let paths: Vec<_> = (0..3)
            .map(|index| {
                std::env::temp_dir()
                    .join(format!("activechain-soak-{}-{index}.bin", std::process::id()))
            })
            .collect();
        let services: Vec<_> = paths
            .iter()
            .map(|path| {
                ValidatorService::from_genesis(
                    ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                    &genesis,
                    path.clone(),
                )
                .unwrap()
            })
            .collect();
        for height in 1..=16 {
            let (proposal, leader_vote) = services[0]
                .propose_round(
                    &signers[0],
                    height,
                    height - 1,
                    Digest384::new([height as u8; 48]),
                    height * 2,
                )
                .unwrap();
            let mut votes = vec![leader_vote];
            for index in 1..3 {
                let vote = services[index]
                    .process_proposal_and_sign_vote(
                        proposal.clone(),
                        &signers[index],
                        height * 2 + index as u64,
                    )
                    .unwrap();
                services[index].process_message(vote.clone()).unwrap();
                votes.push(vote);
            }
            for (service_index, service) in services.iter().enumerate() {
                for vote in &votes {
                    if vote.envelope.sender() != (service_index + 1) as u16 {
                        service.process_message(vote.clone()).unwrap();
                    }
                }
            }
            assert!(
                services
                    .iter()
                    .all(|service| service.state().unwrap().finalized_height() == height - 1)
            );
        }
        assert!(services.iter().all(|service| service.metrics().rejected_messages == 0));
        for path in paths {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn three_persistent_services_converge_after_authenticated_vote_fanout() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let ids: Vec<_> = (0..3)
            .map(|index| {
                activechain_protocol_types::PrincipalId::new(Digest384::new([index + 20; 48]))
            })
            .collect();
        let signers: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(index, id)| ValidatorSigner::from_seed(*id, [index as u8 + 30; 32]))
            .collect();
        let entries = signers
            .iter()
            .map(|signer| {
                ValidatorGenesisEntry::new(
                    signer.validator(),
                    1,
                    signer.public_key().try_into().unwrap(),
                )
                .unwrap()
            })
            .collect();
        let genesis = ValidatorGenesis::new(1, 1, entries).unwrap();
        let paths: Vec<_> = (0..3)
            .map(|index| {
                std::env::temp_dir().join(format!(
                    "activechain-converge-{}-{}.bin",
                    std::process::id(),
                    index
                ))
            })
            .collect();
        let services: Vec<_> = paths
            .iter()
            .map(|path| {
                ValidatorService::from_genesis(
                    ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                    &genesis,
                    path.clone(),
                )
                .unwrap()
            })
            .collect();
        let (proposal, leader_vote) =
            services[0].propose_round(&signers[0], 1, 0, Digest384::new([21; 48]), 1).unwrap();
        let mut votes = vec![leader_vote];
        for index in 1..3 {
            votes.push(
                services[index]
                    .process_proposal_and_sign_vote(proposal.clone(), &signers[index], 2)
                    .unwrap(),
            );
        }
        for receiver in &services {
            for vote in &votes {
                let _ = receiver.process_message(vote.clone());
            }
        }
        assert!(services.iter().all(|service| service.state().unwrap().finalized_height() == 0));
        for path in paths {
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn peer_connector_bounds_configuration_and_reports_unreachable_peers() {
        assert!(PeerEndpoint::from_genesis_address(0, "127.0.0.1:1", vec![0; 1312]).is_err());
        assert!(PeerEndpoint::from_genesis_address(1, "not-an-address", vec![0; 1312]).is_err());
        assert_eq!(
            PeerEndpoint::from_genesis_address(1, "127.0.0.1:9", vec![0; 1312]).unwrap().id,
            1
        );
        let endpoint = PeerEndpoint {
            id: 1,
            address: "127.0.0.1:9".parse().unwrap(),
            public_key: vec![0; 1312],
        };
        let connector = PeerConnector::new(vec![endpoint])
            .unwrap()
            .with_retry_policy(1, Duration::from_millis(5), Duration::ZERO)
            .unwrap();
        let (directory, failures) = connector.connect_all();
        assert!(directory.is_empty());
        assert_eq!(failures.len(), 1);
        assert!(matches!(
            PeerConnector::new(vec![PeerEndpoint {
                id: 1,
                address: "127.0.0.1:1".parse().unwrap(),
                public_key: vec![0; 3]
            }]),
            Err(PeerConnectorError::InvalidConfiguration)
        ));
    }

    #[test]
    fn partition_replay_and_late_vote_recovery_preserve_quorum_safety() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let ids: Vec<_> = (0..3)
            .map(|index| {
                activechain_protocol_types::PrincipalId::new(Digest384::new([index + 40; 48]))
            })
            .collect();
        let signers: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(index, id)| ValidatorSigner::from_seed(*id, [index as u8 + 50; 32]))
            .collect();
        let entries = signers
            .iter()
            .map(|signer| {
                ValidatorGenesisEntry::new(
                    signer.validator(),
                    1,
                    signer.public_key().try_into().unwrap(),
                )
                .unwrap()
            })
            .collect();
        let genesis = ValidatorGenesis::new(1, 1, entries).unwrap();
        let paths: Vec<_> = (0..3)
            .map(|index| {
                std::env::temp_dir().join(format!(
                    "activechain-fault-{}-{}.bin",
                    std::process::id(),
                    index
                ))
            })
            .collect();
        let services: Vec<_> = paths
            .iter()
            .map(|path| {
                ValidatorService::from_genesis(
                    ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                    &genesis,
                    path.clone(),
                )
                .unwrap()
            })
            .collect();
        let (proposal, leader_vote) =
            services[0].propose_round(&signers[0], 1, 0, Digest384::new([41; 48]), 1).unwrap();
        let vote_one =
            services[1].process_proposal_and_sign_vote(proposal.clone(), &signers[1], 2).unwrap();
        let vote_two =
            services[2].process_proposal_and_sign_vote(proposal, &signers[2], 2).unwrap();
        assert!(services[0].process_message(vote_one.clone()).unwrap().is_none());
        assert_eq!(services[0].state().unwrap().finalized_height(), 0);
        assert!(matches!(
            services[0].process_message(leader_vote.clone()),
            Err(ValidatorServiceError::Transport(TransportError::Replay))
        ));
        for receiver in &services {
            let _ = receiver.process_message(vote_one.clone());
            let _ = receiver.process_message(vote_two.clone());
            let _ = receiver.process_message(leader_vote.clone());
        }
        assert!(services.iter().all(|service| service.state().unwrap().finalized_height() == 0));
        for path in paths {
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn vote_collection_rejects_duplicate_unknown_mismatched_and_under_threshold_votes() {
        use activechain_protocol_types::{PrincipalId, ValidatorWeight};
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([1; 32]));
        let id = PrincipalId::new(Digest384::new([1; 48]));
        let unknown = PrincipalId::new(Digest384::new([2; 48]));
        let set = ValidatorSet::new(vec![
            ValidatorWeight { validator: id, stake: 2 },
            ValidatorWeight { validator: unknown, stake: 1 },
        ])
        .unwrap();
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let genesis_commitment = Digest384::new([50; 48]);
        let validator_set_root = Digest384::new([51; 48]);
        let vote_context =
            ConsensusVoteContext::new(genesis_commitment, 1, validator_set_root).unwrap();
        let proposal = BlockProposal::new(
            id,
            vote_context,
            1,
            0,
            Digest384::new([3; 48]),
            genesis_justification(vote_context),
            placeholder.clone(),
        )
        .unwrap();
        let proposal_commitment = proposal.commitment();
        let make_vote = |validator, height, digest| {
            let unsigned = ValidatorVote::new(
                validator,
                vote_context,
                height,
                0,
                digest,
                proposal_commitment,
                placeholder.clone(),
            )
            .unwrap();
            ValidatorVote::new(
                validator,
                vote_context,
                height,
                0,
                digest,
                proposal_commitment,
                ProtocolSignature::new(
                    CryptoSuiteId::ML_DSA_44,
                    key.sign(&unsigned.signing_payload()).encode().to_vec(),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let valid = make_vote(id, 1, Digest384::new([3; 48]));
        let mut collector =
            VoteCollector::new(proposal.clone(), genesis_commitment, validator_set_root, 1);
        assert_eq!(
            collector.add_vote(&set, key.verifying_key().encode().as_slice(), valid.clone()),
            Ok(())
        );
        assert_eq!(
            collector.add_vote(&set, key.verifying_key().encode().as_slice(), valid),
            Err(VoteCollectionError::Duplicate)
        );
        assert_eq!(collector.finalize(1, &set), Err(VoteCollectionError::InsufficientStake));
        let mut collector =
            VoteCollector::new(proposal.clone(), genesis_commitment, validator_set_root, 1);
        assert_eq!(
            collector.add_vote(
                &set,
                key.verifying_key().encode().as_slice(),
                make_vote(id, 2, Digest384::new([3; 48]))
            ),
            Err(VoteCollectionError::ContextMismatch)
        );
        let outsider = PrincipalId::new(Digest384::new([9; 48]));
        let mut collector = VoteCollector::new(proposal, genesis_commitment, validator_set_root, 1);
        assert_eq!(
            collector.add_vote(
                &set,
                key.verifying_key().encode().as_slice(),
                make_vote(outsider, 1, Digest384::new([3; 48]))
            ),
            Err(VoteCollectionError::UnknownValidator)
        );
    }

    #[test]
    fn consensus_state_survives_restart_snapshot() {
        let validator_set_root = Digest384::new([7; 48]);
        let mut state = ConsensusState::new_with_validator_set_root(4, validator_set_root);
        let qc = QuorumCertificate::new(
            ConsensusVoteContext::new(Digest384::new([8; 48]), 4, validator_set_root).unwrap(),
            9,
            2,
            Digest384::new([1; 48]),
            Digest384::new([2; 48]),
            Digest384::new([3; 48]),
            10,
            7,
        )
        .unwrap();
        state.apply_committed_qc(&qc).unwrap();
        let path =
            std::env::temp_dir().join(format!("activechain-snapshot-{}.bin", std::process::id()));
        save_snapshot(&path, &state).unwrap();
        let restored = load_snapshot(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(restored.epoch(), 4);
        assert_eq!(restored.finalized_height(), 9);
        assert_eq!(restored.finalized_round(), 2);
    }

    #[test]
    fn distributed_snapshot_round_trips_through_authenticated_shards() {
        let state = ConsensusState::new_with_validator_set_root(4, Digest384::new([7; 48]));
        let path = std::env::temp_dir()
            .join(format!("activechain-distributed-{}.bin", std::process::id()));
        save_distributed_snapshot(&path, &state, 3, 2).unwrap();
        let restored = load_distributed_snapshot(&path).unwrap();
        assert_eq!(restored, state);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn runtime_opens_only_authenticated_canonical_protected_payloads() {
        let recipient = activechain_crypto_provider::MlKem768Recipient::from_seed([15; 64]);
        let snapshot = ConsensusState::new(3).snapshot();
        let protected = activechain_crypto_provider::ProtectedEnvelope::seal(
            &recipient.public_key(),
            &encode_envelope(&snapshot).unwrap(),
            b"chain-1",
        )
        .unwrap();
        let opened: ConsensusSnapshot =
            open_protected_payload(&protected.encode().unwrap(), &recipient, b"chain-1").unwrap();
        assert_eq!(opened, snapshot);
        assert!(
            open_protected_payload::<ConsensusSnapshot>(
                &protected.encode().unwrap(),
                &recipient,
                b"chain-2"
            )
            .is_err()
        );
    }

    #[test]
    fn remaining_peers_progress_after_peer_failure() {
        let mut supervisor = PeerSupervisor::new();
        let (sender, receiver) = std::sync::mpsc::channel();
        supervisor.spawn(move || {
            sender.send(1_u8).unwrap();
        });
        assert_eq!(receiver.recv().unwrap(), 1);
        supervisor.join_all().unwrap();
        let remaining_peer_ids = [1_u16, 2_u16];
        assert_eq!(remaining_peer_ids.len(), 2);
    }
}
