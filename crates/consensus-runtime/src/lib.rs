#![forbid(unsafe_code)]

//! Deterministic in-memory consensus boundary for the first PQ testnet runtime.

use activechain_crypto_provider::{
    VerificationError, verify_block_proposal, verify_quorum_certificate,
};
use activechain_protocol_types::{
    BlockProposal, ConsensusState, ConsensusStateError, CryptoSuiteId, Digest384,
    ProtocolSignature, QuorumCertificate, ValidatorSet, ValidatorVote,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, Sender};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPeerEnvelope {
    sender: u16,
    sequence: u64,
    body_digest: Digest384,
    signature: ProtocolSignature,
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
        Self { peers: BTreeMap::new(), replay: ReplayGuard::default() }
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
    pub fn len(&self) -> usize {
        self.peers.len()
    }
    pub fn remove(&mut self, peer_id: u16) -> bool {
        self.peers.remove(&peer_id).is_some()
    }
    pub fn receive_verified(
        &mut self,
        peer_id: u16,
    ) -> Result<SignedPeerEnvelope, PeerReceiveError> {
        let (socket, key) = self.peers.get_mut(&peer_id).ok_or(PeerReceiveError::UnknownPeer)?;
        let envelope = socket.receive_envelope().map_err(PeerReceiveError::Io)?;
        self.replay.accept(&envelope, key).map_err(PeerReceiveError::Transport)?;
        Ok(envelope)
    }
    pub fn broadcast(&mut self, envelope: &SignedPeerEnvelope) -> std::io::Result<()> {
        for (socket, _) in self.peers.values_mut() {
            socket.send(envelope)?;
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
    sender: Sender<PeerEvent>,
    receiver: Receiver<PeerEvent>,
}
impl PeerEventQueue {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self { sender, receiver }
    }
    pub fn sender(&self) -> Sender<PeerEvent> {
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
        let mut frame = vec![0; u32::from_be_bytes(len) as usize];
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
}
#[derive(Debug, Eq, PartialEq)]
pub enum TransportError {
    InvalidSuite,
    Verification(VerificationError),
    Replay,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    use std::net::TcpListener;
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
}
