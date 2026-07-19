#![forbid(unsafe_code)]

//! Deterministic in-memory consensus boundary for the first PQ testnet runtime.

use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_crypto_provider::{
    VerificationError, verify_block_proposal, verify_quorum_certificate,
};
use activechain_protocol_types::{
    BlockProposal, ConsensusSnapshot, ConsensusState, ConsensusStateError, CryptoSuiteId,
    Digest384, ProtocolSignature, QuorumCertificate, ValidatorGenesis, ValidatorSet, ValidatorVote,
};
use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::{Duration, Instant};

const PEER_BODY_DOMAIN: &[u8] = b"ACTIVECHAIN-PEER-BODY-V1";
pub const MAX_PEER_FRAME_LEN: usize = 16 * 1024;

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
    fn sign_vote(&self, proposal: &BlockProposal) -> Result<ValidatorVote, ValidatorEngineError> {
        let unsigned = ValidatorVote::new(
            self.validator,
            proposal.height(),
            proposal.round(),
            proposal.block_digest(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420])
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)?;
        let signature = self.key.sign(&unsigned.signing_payload());
        ValidatorVote::new(
            self.validator,
            proposal.height(),
            proposal.round(),
            proposal.block_digest(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)
    }
    fn sign_proposal(
        &self,
        epoch: u64,
        height: u64,
        round: u64,
        block_digest: Digest384,
    ) -> Result<BlockProposal, ValidatorEngineError> {
        let unsigned = BlockProposal::new(
            self.validator,
            epoch,
            height,
            round,
            block_digest,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420])
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)?;
        let signature = self.key.sign(&unsigned.signing_payload());
        BlockProposal::new(
            self.validator,
            epoch,
            height,
            round,
            block_digest,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedBlock {
    certificate: QuorumCertificate,
    votes: Vec<ValidatorVote>,
}
impl CertifiedBlock {
    pub fn new(
        certificate: QuorumCertificate,
        votes: Vec<ValidatorVote>,
    ) -> Result<Self, TransportError> {
        if votes.is_empty() || votes.len() > activechain_protocol_types::MAX_VALIDATORS_PER_EPOCH {
            return Err(TransportError::InvalidBody);
        }
        if votes.iter().any(|vote| {
            vote.height() != certificate.height()
                || vote.round() != certificate.round()
                || vote.block_digest() != certificate.block_digest()
        }) {
            return Err(TransportError::InvalidBody);
        }
        Ok(Self { certificate, votes })
    }
    pub const fn certificate(&self) -> &QuorumCertificate {
        &self.certificate
    }
    pub fn votes(&self) -> &[ValidatorVote] {
        &self.votes
    }
    fn encode(&self) -> Result<Vec<u8>, TransportError> {
        let certificate =
            encode_envelope(&self.certificate).map_err(|_| TransportError::InvalidBody)?;
        let mut bytes = Vec::new();
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
        Self::new(certificate, votes)
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
    let bytes = encode_envelope(&state.snapshot()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "snapshot encoding failed")
    })?;
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(temporary, path)
}
pub fn load_snapshot(path: &std::path::Path) -> std::io::Result<ConsensusState> {
    let bytes = std::fs::read(path)?;
    let snapshot: ConsensusSnapshot = decode_envelope(&bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "snapshot decoding failed")
    })?;
    Ok(ConsensusState::from_snapshot(snapshot))
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

#[derive(Default, Debug)]
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

#[derive(Clone, Debug)]
pub struct DeterministicPeer {
    id: u16,
    state: ConsensusState,
}
impl DeterministicPeer {
    pub const fn new(id: u16, epoch: u64) -> Self {
        Self { id, state: ConsensusState::new(epoch) }
    }
    pub const fn id(&self) -> u16 {
        self.id
    }
    pub const fn state(&self) -> ConsensusState {
        self.state
    }
    pub fn receive_certificate(
        &mut self,
        validator_set: &ValidatorSet,
        certificate: &QuorumCertificate,
        votes: &[(&[u8], ValidatorVote)],
    ) -> Result<(), RuntimeError> {
        finalize_round(&mut self.state, validator_set, certificate, votes)
    }
}

pub fn broadcast_certificate(
    peers: &mut [DeterministicPeer],
    validator_set: &ValidatorSet,
    certificate: &QuorumCertificate,
    votes: &[(&[u8], ValidatorVote)],
) -> Result<(), (u16, RuntimeError)> {
    for peer in peers {
        peer.receive_certificate(validator_set, certificate, votes)
            .map_err(|error| (peer.id, error))?;
    }
    Ok(())
}

pub fn converge_peers(
    peers: &mut [DeterministicPeer],
    validator_set: &ValidatorSet,
    certificate: &QuorumCertificate,
    votes: &[(&[u8], ValidatorVote)],
) -> Result<(), (u16, RuntimeError)> {
    broadcast_certificate(peers, validator_set, certificate, votes)
}

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

pub fn admit_proposal(
    state: &ConsensusState,
    proposal: &BlockProposal,
    proposer_key: &[u8],
) -> Result<(), ProposalError> {
    verify_block_proposal(proposer_key, proposal).map_err(ProposalError::Verification)?;
    if proposal.epoch() != state.epoch() || proposal.height() <= state.finalized_height() {
        return Err(ProposalError::StaleOrWrongEpoch);
    }
    Ok(())
}
#[derive(Debug, Eq, PartialEq)]
pub enum ProposalError {
    Verification(VerificationError),
    StaleOrWrongEpoch,
}

pub struct VoteCollector {
    proposal: BlockProposal,
    votes: Vec<(Vec<u8>, ValidatorVote)>,
    seen: BTreeMap<activechain_protocol_types::PrincipalId, ()>,
    signer_stake: u128,
}
impl VoteCollector {
    pub fn new(proposal: BlockProposal) -> Self {
        Self { proposal, votes: Vec::new(), seen: BTreeMap::new(), signer_stake: 0 }
    }
    pub fn add_vote(
        &mut self,
        validator_set: &ValidatorSet,
        public_key: &[u8],
        vote: ValidatorVote,
    ) -> Result<(), VoteCollectionError> {
        if vote.height() != self.proposal.height()
            || vote.round() != self.proposal.round()
            || vote.block_digest() != self.proposal.block_digest()
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
        self.seen.insert(vote.validator(), ());
        self.signer_stake =
            self.signer_stake.checked_add(stake).ok_or(VoteCollectionError::StakeOverflow)?;
        self.votes.push((public_key.to_vec(), vote));
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
        QuorumCertificate::new(
            epoch,
            self.proposal.height(),
            self.proposal.round(),
            self.proposal.block_digest(),
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

pub struct ValidatorEngine {
    state: ConsensusState,
    validator_set: ValidatorSet,
    public_keys: BTreeMap<activechain_protocol_types::PrincipalId, Vec<u8>>,
    collector: Option<VoteCollector>,
}
impl ValidatorEngine {
    pub fn from_genesis(
        state: ConsensusState,
        genesis: &ValidatorGenesis,
    ) -> Result<Self, ValidatorEngineError> {
        if state.epoch() != genesis.epoch() {
            return Err(ValidatorEngineError::GenesisEpochMismatch);
        }
        if state.validator_set_root() != genesis.validator_set_root() {
            return Err(ValidatorEngineError::GenesisRootMismatch);
        }
        let validator_set =
            genesis.validator_set().map_err(|_| ValidatorEngineError::InvalidGenesis)?;
        let public_keys = genesis
            .entries()
            .iter()
            .map(|entry| (entry.validator(), entry.public_key().to_vec()))
            .collect();
        Self::new(state, validator_set, public_keys)
    }
    pub fn new(
        state: ConsensusState,
        validator_set: ValidatorSet,
        public_keys: BTreeMap<activechain_protocol_types::PrincipalId, Vec<u8>>,
    ) -> Result<Self, ValidatorEngineError> {
        for validator in validator_set.as_slice() {
            let key = public_keys
                .get(&validator.validator)
                .ok_or(ValidatorEngineError::MissingValidatorKey)?;
            if key.len() != 1312 {
                return Err(ValidatorEngineError::InvalidValidatorKey);
            }
        }
        Ok(Self { state, validator_set, public_keys, collector: None })
    }
    pub const fn state(&self) -> ConsensusState {
        self.state
    }
    pub fn sign_current_vote(
        &self,
        signer: &ValidatorSigner,
    ) -> Result<ValidatorVote, ValidatorEngineError> {
        let proposal =
            self.collector.as_ref().ok_or(ValidatorEngineError::MissingProposal)?.proposal();
        if self.validator_set.stake_of(&signer.validator()).is_none() {
            return Err(ValidatorEngineError::UnknownValidator);
        }
        signer.sign_vote(proposal)
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
                admit_proposal(&self.state, &proposal, key)
                    .map_err(ValidatorEngineError::Proposal)?;
                self.collector = Some(VoteCollector::new(proposal));
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
                        let proof = CertifiedBlock::new(certificate, votes)
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
    pub fn process_and_save(
        &mut self,
        message: ConsensusMessage,
        snapshot_path: &std::path::Path,
    ) -> Result<Option<CertifiedBlock>, ValidatorEngineError> {
        let before = self.state;
        let result = self.process(message)?;
        if self.state != before {
            save_snapshot(snapshot_path, &self.state).map_err(ValidatorEngineError::Snapshot)?;
        }
        Ok(result)
    }
    fn apply_certificate(&mut self, proof: &CertifiedBlock) -> Result<(), ValidatorEngineError> {
        let mut votes = Vec::with_capacity(proof.votes().len());
        for vote in proof.votes() {
            let key = self
                .public_keys
                .get(&vote.validator())
                .ok_or(ValidatorEngineError::UnknownValidator)?;
            votes.push((key.as_slice(), vote.clone()));
        }
        finalize_round(&mut self.state, &self.validator_set, proof.certificate(), &votes)
            .map_err(ValidatorEngineError::Runtime)
    }
}

#[derive(Debug)]
pub enum ValidatorEngineError {
    InvalidGenesis,
    GenesisEpochMismatch,
    GenesisRootMismatch,
    MissingValidatorKey,
    InvalidValidatorKey,
    UnknownValidator,
    MissingProposal,
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
    sender_keys: BTreeMap<u16, Vec<u8>>,
    snapshot_path: std::path::PathBuf,
}
impl ValidatorService {
    pub fn from_genesis(
        state: ConsensusState,
        genesis: &ValidatorGenesis,
        snapshot_path: std::path::PathBuf,
    ) -> Result<Self, ValidatorEngineError> {
        let sender_keys = genesis
            .entries()
            .iter()
            .enumerate()
            .map(|(index, entry)| ((index + 1) as u16, entry.public_key().to_vec()))
            .collect();
        Ok(Self {
            engine: std::sync::Mutex::new(ValidatorEngine::from_genesis(state, genesis)?),
            replay: std::sync::Mutex::new(ReplayGuard::default()),
            sender_keys,
            snapshot_path,
        })
    }
    pub fn state(&self) -> Result<ConsensusState, ValidatorServiceError> {
        self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned).map(|engine| engine.state())
    }
    pub fn process_message(
        &self,
        message: AuthenticatedConsensusMessage,
    ) -> Result<Option<CertifiedBlock>, ValidatorServiceError> {
        let key = self
            .sender_keys
            .get(&message.envelope.sender())
            .ok_or(ValidatorServiceError::UnknownSender)?;
        self.replay
            .lock()
            .map_err(|_| ValidatorServiceError::Poisoned)?
            .accept(&message.envelope, key)
            .map_err(ValidatorServiceError::Transport)?;
        self.engine
            .lock()
            .map_err(|_| ValidatorServiceError::Poisoned)?
            .process_and_save(message.message, &self.snapshot_path)
            .map_err(ValidatorServiceError::Engine)
    }
    pub fn process_proposal_and_sign_vote(
        &self,
        proposal: AuthenticatedConsensusMessage,
        signer: &ValidatorSigner,
        sequence: u64,
    ) -> Result<AuthenticatedConsensusMessage, ValidatorServiceError> {
        self.process_message(proposal)?;
        let vote = self
            .engine
            .lock()
            .map_err(|_| ValidatorServiceError::Poisoned)?
            .sign_current_vote(signer)
            .map_err(ValidatorServiceError::Engine)?;
        let sender = self
            .sender_keys
            .iter()
            .find_map(|(sender, key)| (key == &signer.public_key()).then_some(*sender))
            .ok_or(ValidatorServiceError::UnknownSender)?;
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
        let state = self.state()?;
        let proposal = signer
            .sign_proposal(state.epoch(), height, round, block_digest)
            .map_err(ValidatorServiceError::Engine)?;
        let sender = self.sender_for(signer)?;
        let proposal_message = signer
            .sign_envelope(sender, sequence, ConsensusMessage::Proposal(proposal))
            .map_err(ValidatorServiceError::Engine)?;
        self.process_message(proposal_message.clone())?;
        let vote = self
            .engine
            .lock()
            .map_err(|_| ValidatorServiceError::Poisoned)?
            .sign_current_vote(signer)
            .map_err(ValidatorServiceError::Engine)?;
        let vote_message = signer
            .sign_envelope(sender, sequence.saturating_add(1), ConsensusMessage::Vote(vote))
            .map_err(ValidatorServiceError::Engine)?;
        self.process_message(vote_message.clone())?;
        Ok((proposal_message, vote_message))
    }
    fn sender_for(&self, signer: &ValidatorSigner) -> Result<u16, ValidatorServiceError> {
        let public_key = signer.public_key();
        self.sender_keys
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
}
#[derive(Debug)]
pub enum ValidatorServiceError {
    UnknownSender,
    Poisoned,
    Transport(TransportError),
    Engine(ValidatorEngineError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    use std::net::TcpListener;
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
            8,
            2,
            Digest384::new([4; 48]),
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
            1,
            1,
            Digest384::new([2; 48]),
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
    fn three_peers_converge_on_a_real_pq_qc() {
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
        let proposal =
            BlockProposal::new(ids[0], 1, 1, 1, Digest384::new([5; 48]), placeholder.clone())
                .unwrap();
        let mut collector = VoteCollector::new(proposal);
        let mut votes = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            let unsigned =
                ValidatorVote::new(ids[index], 1, 1, Digest384::new([5; 48]), placeholder.clone())
                    .unwrap();
            let signature = key.sign(&unsigned.signing_payload());
            let vote = ValidatorVote::new(
                ids[index],
                1,
                1,
                Digest384::new([5; 48]),
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
        let mut peers = vec![
            DeterministicPeer::new(1, 1),
            DeterministicPeer::new(2, 1),
            DeterministicPeer::new(3, 1),
        ];
        converge_peers(&mut peers, &set, &certificate, &vote_refs).unwrap();
        assert!(peers.iter().all(|peer| peer.state().finalized_height() == 1));
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
        let unsigned =
            BlockProposal::new(ids[0], 1, 1, 0, Digest384::new([8; 48]), placeholder.clone())
                .unwrap();
        let proposal = BlockProposal::new(
            ids[0],
            1,
            1,
            0,
            Digest384::new([8; 48]),
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                keys[0].sign(&unsigned.signing_payload()).encode().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut leader =
            ValidatorEngine::new(ConsensusState::new(1), set.clone(), public_keys.clone()).unwrap();
        leader.process(ConsensusMessage::Proposal(proposal)).unwrap();
        let mut proof = None;
        for (key, id) in keys.iter().zip(ids.iter()) {
            let unsigned =
                ValidatorVote::new(*id, 1, 0, Digest384::new([8; 48]), placeholder.clone())
                    .unwrap();
            let vote = ValidatorVote::new(
                *id,
                1,
                0,
                Digest384::new([8; 48]),
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
        assert_eq!(leader.state().finalized_height(), 1);
        let wire_message = ConsensusMessage::Certificate(proof.clone());
        assert_eq!(
            ConsensusMessage::decode(3, &wire_message.encode_body().unwrap()).unwrap(),
            wire_message
        );
        let path = std::env::temp_dir()
            .join(format!("activechain-validator-engine-{}.bin", std::process::id()));
        let mut follower = ValidatorEngine::new(ConsensusState::new(1), set, public_keys).unwrap();
        follower.process_and_save(ConsensusMessage::Certificate(proof), &path).unwrap();
        assert_eq!(load_snapshot(&path).unwrap().finalized_height(), 1);
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
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let unsigned =
            BlockProposal::new(validator, 1, 1, 0, Digest384::new([5; 48]), placeholder.clone())
                .unwrap();
        let proposal = BlockProposal::new(
            validator,
            1,
            1,
            0,
            Digest384::new([5; 48]),
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                signer.key.sign(&unsigned.signing_payload()).encode().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut engine = ValidatorEngine::new(ConsensusState::new(1), set, keys).unwrap();
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
        assert_eq!(service.state().unwrap().finalized_height(), 1);
        std::fs::remove_file(path).unwrap();
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
        assert!(services.iter().all(|service| service.state().unwrap().finalized_height() == 1));
        for path in paths {
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn peer_connector_bounds_configuration_and_reports_unreachable_peers() {
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
        assert!(services.iter().all(|service| service.state().unwrap().finalized_height() == 1));
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
        let proposal =
            BlockProposal::new(id, 1, 3, 0, Digest384::new([3; 48]), placeholder.clone()).unwrap();
        let make_vote = |validator, height, digest| {
            let unsigned =
                ValidatorVote::new(validator, height, 0, digest, placeholder.clone()).unwrap();
            ValidatorVote::new(
                validator,
                height,
                0,
                digest,
                ProtocolSignature::new(
                    CryptoSuiteId::ML_DSA_44,
                    key.sign(&unsigned.signing_payload()).encode().to_vec(),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let valid = make_vote(id, 3, Digest384::new([3; 48]));
        let mut collector = VoteCollector::new(proposal.clone());
        assert_eq!(
            collector.add_vote(&set, key.verifying_key().encode().as_slice(), valid.clone()),
            Ok(())
        );
        assert_eq!(
            collector.add_vote(&set, key.verifying_key().encode().as_slice(), valid),
            Err(VoteCollectionError::Duplicate)
        );
        assert_eq!(collector.finalize(1, &set), Err(VoteCollectionError::InsufficientStake));
        let mut collector = VoteCollector::new(proposal.clone());
        assert_eq!(
            collector.add_vote(
                &set,
                key.verifying_key().encode().as_slice(),
                make_vote(id, 4, Digest384::new([3; 48]))
            ),
            Err(VoteCollectionError::ContextMismatch)
        );
        let outsider = PrincipalId::new(Digest384::new([9; 48]));
        let mut collector = VoteCollector::new(proposal);
        assert_eq!(
            collector.add_vote(
                &set,
                key.verifying_key().encode().as_slice(),
                make_vote(outsider, 3, Digest384::new([3; 48]))
            ),
            Err(VoteCollectionError::UnknownValidator)
        );
    }

    #[test]
    fn consensus_state_survives_restart_snapshot() {
        let mut state = ConsensusState::new(4);
        let qc = QuorumCertificate::new(
            4,
            9,
            2,
            Digest384::new([1; 48]),
            Digest384::new([2; 48]),
            10,
            7,
        )
        .unwrap();
        state.apply_qc(&qc).unwrap();
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
        let peers: Vec<DeterministicPeer> =
            vec![DeterministicPeer::new(1, 1), DeterministicPeer::new(2, 1)];
        assert_eq!(peers.len(), 2);
    }
}
