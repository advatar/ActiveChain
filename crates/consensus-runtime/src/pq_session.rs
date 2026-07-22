use super::{MAX_PEER_FRAME_LEN, PeerSocket, ValidatorSigner, invalid_data};
use activechain_crypto_provider::{MlKem768Recipient, ml_kem768_encapsulate, verify_ml_dsa44};
use activechain_protocol_types::Digest384;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{collections::BTreeMap, io::Write, path::Path};

const DOMAIN: &[u8] = b"ACTIVECHAIN-PQ-SESSION-V1";
const KDF_DOMAIN: &[u8] = b"ACTIVECHAIN-PQ-SESSION-KDF-V1";
const CONFIRM_DOMAIN: &[u8] = b"ACTIVECHAIN-PQ-SESSION-CONFIRM-V1";
const DSA_SUITE: u16 = 0x0101;
const KEM_SUITE: u16 = 0x0201;
const KEM_PUBLIC_KEY_LEN: usize = 1184;
const KEM_CIPHERTEXT_LEN: usize = 1088;
const SIGNATURE_LEN: usize = 2420;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PqSessionContext {
    pub chain: Digest384,
    pub epoch: u64,
    pub initiator: u16,
    pub responder: u16,
    pub client_nonce: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqPeerSession {
    pub id: [u8; 32],
    pub peer: u16,
    key: [u8; 32],
}
impl PqPeerSession {
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

fn client_payload(context: PqSessionContext, kem_public_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + kem_public_key.len());
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(context.chain.as_bytes());
    out.extend_from_slice(&context.epoch.to_be_bytes());
    out.extend_from_slice(&context.initiator.to_be_bytes());
    out.extend_from_slice(&context.responder.to_be_bytes());
    out.extend_from_slice(&DSA_SUITE.to_be_bytes());
    out.extend_from_slice(&KEM_SUITE.to_be_bytes());
    out.extend_from_slice(&context.client_nonce);
    out.extend_from_slice(kem_public_key);
    out
}
fn expand(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Shake256::default();
    h.update(domain);
    for part in parts {
        h.update(&((*part).len() as u32).to_be_bytes());
        h.update(part);
    }
    let mut out = [0; 32];
    h.finalize_xof().read(&mut out);
    out
}
fn derive(shared: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    expand(KDF_DOMAIN, &[shared, transcript])
}
fn confirmation(key: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    expand(CONFIRM_DOMAIN, &[key, transcript])
}

impl PeerSocket {
    /// Establishes a transcript-bound ML-KEM-768/ML-DSA-44 session as initiator.
    pub fn initiate_pq_session(
        &mut self,
        context: PqSessionContext,
        signer: &ValidatorSigner,
        responder_key: &[u8],
        kem_seed: [u8; 64],
    ) -> std::io::Result<PqPeerSession> {
        if context.initiator == 0
            || context.responder == 0
            || context.initiator == context.responder
            || context.chain == Digest384::ZERO
        {
            return Err(invalid_data("invalid PQ session context"));
        }
        let recipient = MlKem768Recipient::from_seed(kem_seed);
        let kem_public = recipient.public_key();
        let payload = client_payload(context, &kem_public);
        let signature = signer.sign_session_payload(&payload);
        let mut hello = payload.clone();
        hello.extend_from_slice(&signature);
        self.stream.write_all(&(hello.len() as u32).to_be_bytes())?;
        self.stream.write_all(&hello)?;
        let finish = self.receive_frame()?;
        let expected = 32 + KEM_CIPHERTEXT_LEN + 32 + SIGNATURE_LEN;
        if finish.len() != expected {
            return Err(invalid_data("invalid PQ server finish length"));
        }
        let session_id: [u8; 32] = finish[..32].try_into().unwrap();
        let ciphertext = &finish[32..32 + KEM_CIPHERTEXT_LEN];
        let confirm: [u8; 32] =
            finish[32 + KEM_CIPHERTEXT_LEN..64 + KEM_CIPHERTEXT_LEN].try_into().unwrap();
        let mut transcript = payload;
        transcript.extend_from_slice(&signature);
        transcript.extend_from_slice(&session_id);
        transcript.extend_from_slice(ciphertext);
        verify_ml_dsa44(responder_key, &transcript, &finish[64 + KEM_CIPHERTEXT_LEN..])
            .map_err(|_| invalid_data("invalid PQ responder signature"))?;
        let shared = recipient
            .decapsulate(ciphertext)
            .map_err(|_| invalid_data("PQ decapsulation failed"))?;
        let key = derive(&shared, &transcript);
        if confirmation(&key, &transcript) != confirm {
            return Err(invalid_data("PQ key confirmation failed"));
        }
        Ok(PqPeerSession { id: session_id, peer: context.responder, key })
    }

    /// Accepts and authenticates a transcript-bound PQ session.
    pub fn accept_pq_session(
        &mut self,
        chain: Digest384,
        epoch: u64,
        responder: u16,
        signer: &ValidatorSigner,
        peer_keys: &BTreeMap<u16, Vec<u8>>,
        server_nonce: [u8; 32],
    ) -> std::io::Result<PqPeerSession> {
        let hello = self.receive_frame()?;
        let payload_len = DOMAIN.len() + 48 + 8 + 2 + 2 + 2 + 2 + 32 + KEM_PUBLIC_KEY_LEN;
        if hello.len() != payload_len + SIGNATURE_LEN || !hello.starts_with(DOMAIN) {
            return Err(invalid_data("invalid PQ client hello"));
        }
        let mut at = DOMAIN.len();
        let got_chain = Digest384::new(hello[at..at + 48].try_into().unwrap());
        at += 48;
        let got_epoch = u64::from_be_bytes(hello[at..at + 8].try_into().unwrap());
        at += 8;
        let initiator = u16::from_be_bytes(hello[at..at + 2].try_into().unwrap());
        at += 2;
        let got_responder = u16::from_be_bytes(hello[at..at + 2].try_into().unwrap());
        at += 2;
        let dsa = u16::from_be_bytes(hello[at..at + 2].try_into().unwrap());
        at += 2;
        let kem = u16::from_be_bytes(hello[at..at + 2].try_into().unwrap());
        at += 2 + 32;
        if got_chain != chain
            || got_epoch != epoch
            || got_responder != responder
            || initiator == 0
            || dsa != DSA_SUITE
            || kem != KEM_SUITE
        {
            return Err(invalid_data("PQ session context or suite mismatch"));
        }
        let peer_key =
            peer_keys.get(&initiator).ok_or_else(|| invalid_data("unknown PQ initiator"))?;
        verify_ml_dsa44(peer_key, &hello[..payload_len], &hello[payload_len..])
            .map_err(|_| invalid_data("invalid PQ initiator signature"))?;
        let kem_public = &hello[at..at + KEM_PUBLIC_KEY_LEN];
        let (ciphertext, shared) = ml_kem768_encapsulate(kem_public)
            .map_err(|_| invalid_data("invalid PQ KEM public key"))?;
        let session_id = expand(
            b"ACTIVECHAIN-PQ-SESSION-ID-V1",
            &[
                chain.as_bytes(),
                &epoch.to_be_bytes(),
                &initiator.to_be_bytes(),
                &responder.to_be_bytes(),
                &server_nonce,
                &hello,
            ],
        );
        let mut transcript = hello;
        transcript.extend_from_slice(&session_id);
        transcript.extend_from_slice(&ciphertext);
        let key = derive(&shared, &transcript);
        let confirm = confirmation(&key, &transcript);
        let response_signature = signer.sign_session_payload(&transcript);
        let mut finish = Vec::with_capacity(32 + ciphertext.len() + 32 + response_signature.len());
        finish.extend_from_slice(&session_id);
        finish.extend_from_slice(&ciphertext);
        finish.extend_from_slice(&confirm);
        finish.extend_from_slice(&response_signature);
        if finish.len() > MAX_PEER_FRAME_LEN {
            return Err(invalid_data("PQ server finish exceeds limit"));
        }
        self.stream.write_all(&(finish.len() as u32).to_be_bytes())?;
        self.stream.write_all(&finish)?;
        Ok(PqPeerSession { id: session_id, peer: initiator, key })
    }
}

/// Durable accepted-session and protected-message sequence high-water state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PqSessionStore {
    sessions: BTreeMap<[u8; 32], (u16, u64, u64)>,
}
impl PqSessionStore {
    pub fn accept(&mut self, session: &PqPeerSession) -> std::io::Result<()> {
        if self.sessions.contains_key(&session.id) {
            return Err(invalid_data("PQ session replay"));
        }
        self.sessions.insert(session.id, (session.peer, 0, 0));
        Ok(())
    }
    pub fn accept_receive_sequence(&mut self, id: [u8; 32], sequence: u64) -> std::io::Result<()> {
        let state = self.sessions.get_mut(&id).ok_or_else(|| invalid_data("unknown PQ session"))?;
        if sequence <= state.2 {
            return Err(invalid_data("protected message replay"));
        }
        state.2 = sequence;
        Ok(())
    }
    pub fn next_send_sequence(&mut self, id: [u8; 32]) -> std::io::Result<u64> {
        let state = self.sessions.get_mut(&id).ok_or_else(|| invalid_data("unknown PQ session"))?;
        state.1 =
            state.1.checked_add(1).ok_or_else(|| invalid_data("protected sequence exhausted"))?;
        Ok(state.1)
    }
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ACPQSS1\0");
        bytes.extend_from_slice(&(self.sessions.len() as u16).to_be_bytes());
        for (id, (peer, send, receive)) in &self.sessions {
            bytes.extend_from_slice(id);
            bytes.extend_from_slice(&peer.to_be_bytes());
            bytes.extend_from_slice(&send.to_be_bytes());
            bytes.extend_from_slice(&receive.to_be_bytes());
        }
        let tag = expand(b"ACTIVECHAIN-PQ-SESSION-STORE-V1", &[&bytes]);
        bytes.extend_from_slice(&tag);
        super::write_atomic(path, &bytes)
    }
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < 42 || &bytes[..8] != b"ACPQSS1\0" {
            return Err(invalid_data("invalid PQ session store"));
        }
        let body_len = bytes.len() - 32;
        if expand(b"ACTIVECHAIN-PQ-SESSION-STORE-V1", &[&bytes[..body_len]]) != bytes[body_len..] {
            return Err(invalid_data("corrupt PQ session store"));
        }
        let count = u16::from_be_bytes(bytes[8..10].try_into().unwrap()) as usize;
        if body_len != 10 + count * 50 {
            return Err(invalid_data("invalid PQ session store length"));
        }
        let mut sessions = BTreeMap::new();
        let mut at = 10;
        for _ in 0..count {
            let id = bytes[at..at + 32].try_into().unwrap();
            at += 32;
            let peer = u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap());
            at += 2;
            let send = u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
            at += 8;
            let receive = u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
            at += 8;
            if peer == 0 || sessions.insert(id, (peer, send, receive)).is_some() {
                return Err(invalid_data("non-canonical PQ session store"));
            }
        }
        Ok(Self { sessions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::PrincipalId;
    use std::net::{TcpListener, TcpStream};
    #[test]
    fn pq_session_agrees_and_binds_context() {
        let a = ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([1; 48])), [1; 32]);
        let b = ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([2; 48])), [2; 32]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let ak = a.public_key();
        let bk = b.public_key();
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut p = PeerSocket::connect(s);
            let keys = BTreeMap::from([(1, ak)]);
            p.accept_pq_session(Digest384::new([9; 48]), 7, 2, &b, &keys, [4; 32]).unwrap()
        });
        let mut p = PeerSocket::connect(TcpStream::connect(address).unwrap());
        let client = p
            .initiate_pq_session(
                PqSessionContext {
                    chain: Digest384::new([9; 48]),
                    epoch: 7,
                    initiator: 1,
                    responder: 2,
                    client_nonce: [3; 32],
                },
                &a,
                &bk,
                [5; 64],
            )
            .unwrap();
        let server = server.join().unwrap();
        assert_eq!(client.id, server.id);
        assert_eq!(client.key(), server.key());
    }
    #[test]
    fn pq_session_rejects_context_alias_and_freezes_suites() {
        assert_eq!(
            include_str!("../../../testing/vectors/consensus/pq-session-v1.txt"),
            "domain=ACTIVECHAIN-PQ-SESSION-V1\ndsa_suite=0x0101\nkem_suite=0x0201\nkem_public_key_len=1184\nkem_ciphertext_len=1088\nsignature_len=2420\n"
        );
        let a = ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([1; 48])), [11; 32]);
        let b = ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([2; 48])), [12; 32]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let ak = a.public_key();
        let bk = b.public_key();
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut p = PeerSocket::connect(s);
            p.accept_pq_session(
                Digest384::new([9; 48]),
                7,
                2,
                &b,
                &BTreeMap::from([(1, ak)]),
                [4; 32],
            )
        });
        let mut p = PeerSocket::connect(TcpStream::connect(address).unwrap());
        assert!(
            p.initiate_pq_session(
                PqSessionContext {
                    chain: Digest384::new([8; 48]),
                    epoch: 7,
                    initiator: 1,
                    responder: 2,
                    client_nonce: [3; 32],
                },
                &a,
                &bk,
                [5; 64],
            )
            .is_err()
        );
        assert!(server.join().unwrap().is_err());
    }
    #[test]
    fn durable_sequences_reject_replay_and_corruption() {
        let dir = std::env::temp_dir().join(format!("activechain-pq-{}", std::process::id()));
        let path = dir.with_extension("state");
        let session = PqPeerSession { id: [8; 32], peer: 2, key: [7; 32] };
        let mut store = PqSessionStore::default();
        store.accept(&session).unwrap();
        assert_eq!(store.next_send_sequence(session.id).unwrap(), 1);
        store.accept_receive_sequence(session.id, 1).unwrap();
        store.save(&path).unwrap();
        let mut loaded = PqSessionStore::load(&path).unwrap();
        assert!(loaded.accept(&session).is_err());
        assert!(loaded.accept_receive_sequence(session.id, 1).is_err());
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[10] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(PqSessionStore::load(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
}
