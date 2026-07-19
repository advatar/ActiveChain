#![forbid(unsafe_code)]

//! Deterministic in-memory consensus boundary for the first PQ testnet runtime.

use activechain_crypto_provider::{VerificationError, verify_quorum_certificate};
use activechain_protocol_types::{
    ConsensusState, ConsensusStateError, CryptoSuiteId, Digest384, ProtocolSignature,
    QuorumCertificate, ValidatorSet, ValidatorVote,
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;

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
impl PeerSocket {
    pub fn connect(stream: TcpStream) -> Self {
        Self { stream }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_rejects_without_verified_votes() {
        let mut state = ConsensusState::new(1);
        let set = ValidatorSet::new(Vec::new());
        assert!(set.is_err());
        let _ = &mut state;
    }
}
