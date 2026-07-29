use super::{
    AuthenticatedConsensusMessage, MAX_PEER_FRAME_LEN, PeerSocket, ValidatorSigner, invalid_data,
};
use activechain_crypto_provider::{MlKem768Recipient, ml_kem768_encapsulate, verify_ml_dsa44};
use activechain_protocol_types::Digest384;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{collections::BTreeMap, io::Write, path::Path};

const DOMAIN: &[u8] = b"ACTIVECHAIN-PQ-SESSION-V2";
const KDF_DOMAIN: &[u8] = b"ACTIVECHAIN-PQ-SESSION-KDF-V2";
const CONFIRM_DOMAIN: &[u8] = b"ACTIVECHAIN-PQ-SESSION-CONFIRM-V2";
const SESSION_ID_DOMAIN: &[u8] = b"ACTIVECHAIN-PQ-SESSION-ID-V2";
const PROTECTED_DOMAIN: &[u8] = b"ACTIVECHAIN-PQ-PROTECTED-V2";
const PROTECTED_STREAM_DOMAIN: &[u8] = b"ACTIVECHAIN-PQ-PROTECTED-STREAM-V2";
const PROTECTED_TAG_DOMAIN: &[u8] = b"ACTIVECHAIN-PQ-PROTECTED-TAG-V2";
const STORE_DOMAIN: &[u8] = b"ACTIVECHAIN-PQ-SESSION-STORE-V2";
const STORE_MAGIC: &[u8; 8] = b"ACPQSS2\0";
const PROTECTED_MAGIC: &[u8; 8] = b"ACPQPF2\0";
const CLIENT_HELLO: u8 = 1;
const SERVER_CHALLENGE: u8 = 2;
const CLIENT_FINISH: u8 = 3;
const SERVER_FINISH: u8 = 4;
const DSA_SUITE: u16 = 0x0101;
const KEM_SUITE: u16 = 0x0201;
const KEM_PUBLIC_KEY_LEN: usize = 1184;
const KEM_CIPHERTEXT_LEN: usize = 1088;
const SIGNATURE_LEN: usize = 2420;
const MAX_SESSIONS: usize = 256;
pub const SESSION_TTL_SECS: u64 = 120;
const MAX_CLOCK_SKEW_SECS: u64 = 5;
const SESSION_ID_OFFSET: usize = DOMAIN.len() + 1 + 72 + 32 + 32 + 8 + 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PqSessionContext {
    pub chain: Digest384,
    pub epoch: u64,
    pub protocol_revision: u64,
    pub initiator: u16,
    pub responder: u16,
}
impl PqSessionContext {
    fn validate(self) -> std::io::Result<()> {
        if self.chain == Digest384::ZERO
            || self.epoch == 0
            || self.protocol_revision == 0
            || self.initiator == 0
            || self.responder == 0
            || self.initiator == self.responder
        {
            return Err(invalid_data("invalid PQ session context"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqPeerSession {
    pub id: [u8; 32],
    pub peer: u16,
    pub expires_at: u64,
    context: PqSessionContext,
    local_is_initiator: bool,
    key: [u8; 32],
}
impl PqPeerSession {
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
    pub fn local_peer(&self) -> u16 {
        if self.local_is_initiator { self.context.initiator } else { self.context.responder }
    }
    fn remote_peer(&self) -> u16 {
        if self.local_is_initiator { self.context.responder } else { self.context.initiator }
    }
    fn associated_data(&self, sender: u16, receiver: u16, sequence: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROTECTED_DOMAIN.len() + 32 + 12);
        out.extend_from_slice(PROTECTED_DOMAIN);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&sender.to_be_bytes());
        out.extend_from_slice(&receiver.to_be_bytes());
        out.extend_from_slice(&sequence.to_be_bytes());
        out
    }
}

fn now_secs() -> std::io::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| invalid_data("system clock precedes Unix epoch"))
}

fn fill_random<const N: usize>() -> std::io::Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| invalid_data("PQ session randomness failed"))?;
    Ok(bytes)
}

fn append_context(out: &mut Vec<u8>, context: PqSessionContext) {
    out.extend_from_slice(context.chain.as_bytes());
    out.extend_from_slice(&context.epoch.to_be_bytes());
    out.extend_from_slice(&context.protocol_revision.to_be_bytes());
    out.extend_from_slice(&context.initiator.to_be_bytes());
    out.extend_from_slice(&context.responder.to_be_bytes());
    out.extend_from_slice(&DSA_SUITE.to_be_bytes());
    out.extend_from_slice(&KEM_SUITE.to_be_bytes());
}

fn read_context(bytes: &[u8], at: &mut usize) -> std::io::Result<PqSessionContext> {
    let end = at.checked_add(72).ok_or_else(|| invalid_data("PQ context overflow"))?;
    if end > bytes.len() {
        return Err(invalid_data("truncated PQ session context"));
    }
    let context = PqSessionContext {
        chain: Digest384::new(bytes[*at..*at + 48].try_into().unwrap()),
        epoch: u64::from_be_bytes(bytes[*at + 48..*at + 56].try_into().unwrap()),
        protocol_revision: u64::from_be_bytes(bytes[*at + 56..*at + 64].try_into().unwrap()),
        initiator: u16::from_be_bytes(bytes[*at + 64..*at + 66].try_into().unwrap()),
        responder: u16::from_be_bytes(bytes[*at + 66..*at + 68].try_into().unwrap()),
    };
    let dsa = u16::from_be_bytes(bytes[*at + 68..*at + 70].try_into().unwrap());
    let kem = u16::from_be_bytes(bytes[*at + 70..end].try_into().unwrap());
    *at = end;
    context.validate()?;
    if dsa != DSA_SUITE || kem != KEM_SUITE {
        return Err(invalid_data("PQ session suite mismatch"));
    }
    Ok(context)
}

fn expand(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    for part in parts {
        hasher.update(&((*part).len() as u32).to_be_bytes());
        hasher.update(part);
    }
    let mut out = [0; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

fn stream(key: &[u8; 32], associated_data: &[u8], len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(PROTECTED_STREAM_DOMAIN);
    hasher.update(key);
    hasher.update(&(associated_data.len() as u32).to_be_bytes());
    hasher.update(associated_data);
    let mut out = vec![0; len];
    hasher.finalize_xof().read(&mut out);
    out
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right).fold(0_u8, |difference, (a, b)| difference | (a ^ b)) == 0
}

fn client_hello(context: PqSessionContext, client_nonce: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN.len() + 105);
    out.extend_from_slice(DOMAIN);
    out.push(CLIENT_HELLO);
    append_context(&mut out, context);
    out.extend_from_slice(&client_nonce);
    out
}

fn parse_client_hello(bytes: &[u8]) -> std::io::Result<(PqSessionContext, [u8; 32])> {
    if !bytes.starts_with(DOMAIN) || bytes.get(DOMAIN.len()) != Some(&CLIENT_HELLO) {
        return Err(invalid_data("invalid PQ client hello"));
    }
    let mut at = DOMAIN.len() + 1;
    let context = read_context(bytes, &mut at)?;
    if bytes.len() != at + 32 {
        return Err(invalid_data("invalid PQ client hello length"));
    }
    Ok((context, bytes[at..].try_into().unwrap()))
}

#[allow(clippy::too_many_arguments)]
fn server_challenge(
    context: PqSessionContext,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    session_id: [u8; 32],
    kem_public_key: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN.len() + 1280);
    out.extend_from_slice(DOMAIN);
    out.push(SERVER_CHALLENGE);
    append_context(&mut out, context);
    out.extend_from_slice(&client_nonce);
    out.extend_from_slice(&server_nonce);
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    out.extend_from_slice(&session_id);
    out.extend_from_slice(kem_public_key);
    out
}

struct ParsedChallenge {
    context: PqSessionContext,
    client_nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    session_id: [u8; 32],
    kem_public_key: Vec<u8>,
    unsigned: Vec<u8>,
}

fn parse_server_challenge(bytes: &[u8]) -> std::io::Result<ParsedChallenge> {
    if !bytes.starts_with(DOMAIN) || bytes.get(DOMAIN.len()) != Some(&SERVER_CHALLENGE) {
        return Err(invalid_data("invalid PQ server challenge"));
    }
    if bytes.len() < SIGNATURE_LEN {
        return Err(invalid_data("truncated PQ server challenge"));
    }
    let unsigned_len = bytes.len() - SIGNATURE_LEN;
    let unsigned = &bytes[..unsigned_len];
    let mut at = DOMAIN.len() + 1;
    let context = read_context(unsigned, &mut at)?;
    let expected = at + 32 + 32 + 8 + 8 + 32 + KEM_PUBLIC_KEY_LEN;
    if unsigned.len() != expected {
        return Err(invalid_data("invalid PQ server challenge length"));
    }
    let client_nonce = unsigned[at..at + 32].try_into().unwrap();
    at += 64;
    let issued_at = u64::from_be_bytes(unsigned[at..at + 8].try_into().unwrap());
    at += 8;
    let expires_at = u64::from_be_bytes(unsigned[at..at + 8].try_into().unwrap());
    at += 8;
    let session_id = unsigned[at..at + 32].try_into().unwrap();
    at += 32;
    Ok(ParsedChallenge {
        context,
        client_nonce,
        issued_at,
        expires_at,
        session_id,
        kem_public_key: unsigned[at..].to_vec(),
        unsigned: unsigned.to_vec(),
    })
}

fn validate_server_challenge(
    challenge: &ParsedChallenge,
    expected_context: PqSessionContext,
    expected_client_nonce: [u8; 32],
    now: u64,
) -> std::io::Result<()> {
    if challenge.context != expected_context
        || challenge.client_nonce != expected_client_nonce
        || challenge.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS)
        || challenge.expires_at <= now
        || challenge.expires_at.saturating_sub(challenge.issued_at) > SESSION_TTL_SECS
    {
        return Err(invalid_data("stale or mismatched PQ server challenge"));
    }
    Ok(())
}

fn derive(shared: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    expand(KDF_DOMAIN, &[shared, transcript])
}

fn confirmation(key: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    expand(CONFIRM_DOMAIN, &[key, transcript])
}

impl PeerSocket {
    pub fn initiate_pq_session(
        &mut self,
        context: PqSessionContext,
        signer: &ValidatorSigner,
        responder_key: &[u8],
    ) -> std::io::Result<PqPeerSession> {
        context.validate()?;
        let client_nonce = fill_random::<32>()?;
        let hello = client_hello(context, client_nonce);
        self.write_session_frame(&hello)?;

        let challenge_bytes = self.receive_frame()?;
        let challenge = parse_server_challenge(&challenge_bytes)?;
        let now = now_secs()?;
        validate_server_challenge(&challenge, context, client_nonce, now)?;
        verify_ml_dsa44(
            responder_key,
            &challenge.unsigned,
            &challenge_bytes[challenge.unsigned.len()..],
        )
        .map_err(|_| invalid_data("invalid PQ responder challenge signature"))?;
        let expected_session_id = expand(
            SESSION_ID_DOMAIN,
            &[&hello, &challenge.unsigned[..SESSION_ID_OFFSET], &challenge.kem_public_key],
        );
        if challenge.session_id != expected_session_id {
            return Err(invalid_data("invalid PQ session identifier"));
        }
        let (ciphertext, shared) = ml_kem768_encapsulate(&challenge.kem_public_key)
            .map_err(|_| invalid_data("invalid PQ responder KEM key"))?;
        let mut transcript = hello;
        transcript.extend_from_slice(&challenge_bytes);
        transcript.extend_from_slice(&ciphertext);
        let signature = signer.sign_session_payload(&transcript);
        let mut finish = Vec::with_capacity(1 + 32 + ciphertext.len() + signature.len());
        finish.push(CLIENT_FINISH);
        finish.extend_from_slice(&challenge.session_id);
        finish.extend_from_slice(&ciphertext);
        finish.extend_from_slice(&signature);
        self.write_session_frame(&finish)?;

        let key = derive(&shared, &transcript);
        let expected_confirmation = confirmation(&key, &transcript);
        let server_finish = self.receive_frame()?;
        if server_finish.len() != 1 + 32 + 32 + SIGNATURE_LEN
            || server_finish[0] != SERVER_FINISH
            || server_finish[1..33] != challenge.session_id
            || server_finish[33..65] != expected_confirmation
        {
            return Err(invalid_data("invalid PQ server finish"));
        }
        let mut signed_finish = transcript;
        signed_finish.extend_from_slice(&expected_confirmation);
        verify_ml_dsa44(responder_key, &signed_finish, &server_finish[65..])
            .map_err(|_| invalid_data("invalid PQ server finish signature"))?;
        Ok(PqPeerSession {
            id: challenge.session_id,
            peer: context.responder,
            expires_at: challenge.expires_at,
            context,
            local_is_initiator: true,
            key,
        })
    }

    pub fn accept_pq_session(
        &mut self,
        chain: Digest384,
        epoch: u64,
        protocol_revision: u64,
        responder: u16,
        signer: &ValidatorSigner,
        peer_keys: &BTreeMap<u16, Vec<u8>>,
    ) -> std::io::Result<PqPeerSession> {
        let hello = self.receive_frame()?;
        let (context, client_nonce) = parse_client_hello(&hello)?;
        if context.chain != chain
            || context.epoch != epoch
            || context.protocol_revision != protocol_revision
            || context.responder != responder
        {
            return Err(invalid_data("PQ session context mismatch"));
        }
        let peer_key = peer_keys
            .get(&context.initiator)
            .ok_or_else(|| invalid_data("unknown PQ session initiator"))?;
        let server_nonce = fill_random::<32>()?;
        let kem_seed = fill_random::<64>()?;
        let recipient = MlKem768Recipient::from_seed(kem_seed);
        let kem_public_key = recipient.public_key();
        let issued_at = now_secs()?;
        let expires_at = issued_at
            .checked_add(SESSION_TTL_SECS)
            .ok_or_else(|| invalid_data("PQ session expiry overflow"))?;
        let challenge_prefix = server_challenge(
            context,
            client_nonce,
            server_nonce,
            issued_at,
            expires_at,
            [0; 32],
            &kem_public_key,
        );
        let session_id = expand(
            SESSION_ID_DOMAIN,
            &[&hello, &challenge_prefix[..SESSION_ID_OFFSET], &kem_public_key],
        );
        let unsigned = server_challenge(
            context,
            client_nonce,
            server_nonce,
            issued_at,
            expires_at,
            session_id,
            &kem_public_key,
        );
        let challenge_signature = signer.sign_session_payload(&unsigned);
        let mut challenge = unsigned;
        challenge.extend_from_slice(&challenge_signature);
        self.write_session_frame(&challenge)?;

        let finish = self.receive_frame()?;
        if finish.len() != 1 + 32 + KEM_CIPHERTEXT_LEN + SIGNATURE_LEN
            || finish[0] != CLIENT_FINISH
            || finish[1..33] != session_id
        {
            return Err(invalid_data("invalid PQ client finish"));
        }
        let ciphertext = &finish[33..33 + KEM_CIPHERTEXT_LEN];
        let mut transcript = hello;
        transcript.extend_from_slice(&challenge);
        transcript.extend_from_slice(ciphertext);
        verify_ml_dsa44(peer_key, &transcript, &finish[33 + KEM_CIPHERTEXT_LEN..])
            .map_err(|_| invalid_data("invalid PQ initiator finish signature"))?;
        let shared = recipient
            .decapsulate(ciphertext)
            .map_err(|_| invalid_data("PQ decapsulation failed"))?;
        let key = derive(&shared, &transcript);
        let confirm = confirmation(&key, &transcript);
        let mut signed_finish = transcript;
        signed_finish.extend_from_slice(&confirm);
        let response_signature = signer.sign_session_payload(&signed_finish);
        let mut server_finish = Vec::with_capacity(1 + 32 + 32 + response_signature.len());
        server_finish.push(SERVER_FINISH);
        server_finish.extend_from_slice(&session_id);
        server_finish.extend_from_slice(&confirm);
        server_finish.extend_from_slice(&response_signature);
        self.write_session_frame(&server_finish)?;
        Ok(PqPeerSession {
            id: session_id,
            peer: context.initiator,
            expires_at,
            context,
            local_is_initiator: false,
            key,
        })
    }

    fn write_session_frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
        if frame.len() > MAX_PEER_FRAME_LEN {
            return Err(invalid_data("PQ session frame exceeds limit"));
        }
        self.stream.write_all(&(frame.len() as u32).to_be_bytes())?;
        self.stream.write_all(frame)
    }

    pub fn send_protected_message(
        &mut self,
        session: &PqPeerSession,
        sequence: u64,
        message: &AuthenticatedConsensusMessage,
    ) -> std::io::Result<()> {
        if sequence == 0 || session.expires_at <= now_secs()? {
            return Err(invalid_data("expired PQ session"));
        }
        let plaintext = message.wire_bytes()?;
        let sender = session.local_peer();
        let receiver = session.remote_peer();
        let associated_data = session.associated_data(sender, receiver, sequence);
        let keystream = stream(&session.key, &associated_data, plaintext.len());
        let ciphertext =
            plaintext.iter().zip(keystream).map(|(byte, mask)| byte ^ mask).collect::<Vec<_>>();
        let tag = expand(PROTECTED_TAG_DOMAIN, &[&session.key, &associated_data, &ciphertext]);
        let frame_len = 8 + 32 + 2 + 2 + 8 + 4 + ciphertext.len() + 32;
        if frame_len > MAX_PEER_FRAME_LEN {
            return Err(invalid_data("protected peer frame exceeds limit"));
        }
        let mut frame = Vec::with_capacity(frame_len);
        frame.extend_from_slice(PROTECTED_MAGIC);
        frame.extend_from_slice(&session.id);
        frame.extend_from_slice(&sender.to_be_bytes());
        frame.extend_from_slice(&receiver.to_be_bytes());
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        frame.extend_from_slice(&ciphertext);
        frame.extend_from_slice(&tag);
        self.write_session_frame(&frame)
    }

    pub fn receive_protected_message(
        &mut self,
        session: &PqPeerSession,
    ) -> std::io::Result<(u64, AuthenticatedConsensusMessage)> {
        if session.expires_at <= now_secs()? {
            return Err(invalid_data("expired PQ session"));
        }
        let frame = self.receive_frame()?;
        if frame.len() < 88 || &frame[..8] != PROTECTED_MAGIC || frame[8..40] != session.id {
            return Err(invalid_data("invalid protected peer frame"));
        }
        let sender = u16::from_be_bytes(frame[40..42].try_into().unwrap());
        let receiver = u16::from_be_bytes(frame[42..44].try_into().unwrap());
        let sequence = u64::from_be_bytes(frame[44..52].try_into().unwrap());
        let ciphertext_len = u32::from_be_bytes(frame[52..56].try_into().unwrap()) as usize;
        if sequence == 0
            || sender != session.remote_peer()
            || receiver != session.local_peer()
            || frame.len() != 56 + ciphertext_len + 32
        {
            return Err(invalid_data("protected peer context mismatch"));
        }
        let ciphertext = &frame[56..56 + ciphertext_len];
        let associated_data = session.associated_data(sender, receiver, sequence);
        let expected_tag =
            expand(PROTECTED_TAG_DOMAIN, &[&session.key, &associated_data, ciphertext]);
        if !constant_time_equal(&expected_tag, &frame[56 + ciphertext_len..]) {
            return Err(invalid_data("protected peer authentication failed"));
        }
        let keystream = stream(&session.key, &associated_data, ciphertext.len());
        let plaintext =
            ciphertext.iter().zip(keystream).map(|(byte, mask)| byte ^ mask).collect::<Vec<_>>();
        Ok((sequence, AuthenticatedConsensusMessage::from_wire_bytes(&plaintext)?))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoredSession {
    peer: u16,
    expires_at: u64,
    send: u64,
    receive: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqSessionStore {
    chain: Digest384,
    epoch: u64,
    protocol_revision: u64,
    sessions: BTreeMap<[u8; 32], StoredSession>,
}
impl PqSessionStore {
    pub fn new(chain: Digest384, epoch: u64, protocol_revision: u64) -> std::io::Result<Self> {
        if chain == Digest384::ZERO || epoch == 0 || protocol_revision == 0 {
            return Err(invalid_data("invalid PQ session store context"));
        }
        Ok(Self { chain, epoch, protocol_revision, sessions: BTreeMap::new() })
    }

    pub fn load_or_new(
        path: &Path,
        chain: Digest384,
        epoch: u64,
        protocol_revision: u64,
    ) -> std::io::Result<Self> {
        match Self::load(path) {
            Ok(store)
                if store.chain == chain
                    && store.epoch == epoch
                    && store.protocol_revision == protocol_revision =>
            {
                Ok(store)
            }
            Ok(_) => {
                let store = Self::new(chain, epoch, protocol_revision)?;
                store.save(path)?;
                Ok(store)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Self::new(chain, epoch, protocol_revision)
            }
            Err(error) => Err(error),
        }
    }

    fn prune(&mut self, now: u64) {
        self.sessions.retain(|_, state| state.expires_at > now);
    }

    pub fn accept_and_save(&mut self, session: &PqPeerSession, path: &Path) -> std::io::Result<()> {
        let now = now_secs()?;
        self.prune(now);
        if session.context.chain != self.chain
            || session.context.epoch != self.epoch
            || session.context.protocol_revision != self.protocol_revision
            || session.expires_at <= now
            || self.sessions.contains_key(&session.id)
        {
            return Err(invalid_data("PQ session replay or domain mismatch"));
        }
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(invalid_data("PQ session store capacity exceeded"));
        }
        self.sessions.insert(
            session.id,
            StoredSession {
                peer: session.peer,
                expires_at: session.expires_at,
                send: 0,
                receive: 0,
            },
        );
        self.save(path)
    }

    pub fn reserve_send_and_save(&mut self, id: [u8; 32], path: &Path) -> std::io::Result<u64> {
        let now = now_secs()?;
        self.prune(now);
        let state = self.sessions.get_mut(&id).ok_or_else(|| invalid_data("unknown PQ session"))?;
        state.send = state
            .send
            .checked_add(1)
            .ok_or_else(|| invalid_data("protected sequence exhausted"))?;
        let sequence = state.send;
        self.save(path)?;
        Ok(sequence)
    }

    pub fn accept_receive_and_save(
        &mut self,
        id: [u8; 32],
        sequence: u64,
        path: &Path,
    ) -> std::io::Result<()> {
        let now = now_secs()?;
        self.prune(now);
        let state = self.sessions.get_mut(&id).ok_or_else(|| invalid_data("unknown PQ session"))?;
        if sequence <= state.receive {
            return Err(invalid_data("protected message replay"));
        }
        state.receive = sequence;
        self.save(path)
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if self.sessions.len() > MAX_SESSIONS {
            return Err(invalid_data("PQ session store capacity exceeded"));
        }
        let mut bytes = Vec::with_capacity(96 + self.sessions.len() * 58);
        bytes.extend_from_slice(STORE_MAGIC);
        bytes.extend_from_slice(self.chain.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.protocol_revision.to_be_bytes());
        bytes.extend_from_slice(&(self.sessions.len() as u16).to_be_bytes());
        for (id, state) in &self.sessions {
            bytes.extend_from_slice(id);
            bytes.extend_from_slice(&state.peer.to_be_bytes());
            bytes.extend_from_slice(&state.expires_at.to_be_bytes());
            bytes.extend_from_slice(&state.send.to_be_bytes());
            bytes.extend_from_slice(&state.receive.to_be_bytes());
        }
        let tag = expand(STORE_DOMAIN, &[&bytes]);
        bytes.extend_from_slice(&tag);
        super::write_atomic(path, &bytes)
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        const HEADER: usize = 8 + 48 + 8 + 8 + 2;
        const ENTRY: usize = 32 + 2 + 8 + 8 + 8;
        if bytes.len() < HEADER + 32 || &bytes[..8] != STORE_MAGIC {
            return Err(invalid_data("invalid PQ session store"));
        }
        let body_len = bytes.len() - 32;
        if !constant_time_equal(&expand(STORE_DOMAIN, &[&bytes[..body_len]]), &bytes[body_len..]) {
            return Err(invalid_data("corrupt PQ session store"));
        }
        let chain = Digest384::new(bytes[8..56].try_into().unwrap());
        let epoch = u64::from_be_bytes(bytes[56..64].try_into().unwrap());
        let protocol_revision = u64::from_be_bytes(bytes[64..72].try_into().unwrap());
        let count = u16::from_be_bytes(bytes[72..74].try_into().unwrap()) as usize;
        if chain == Digest384::ZERO
            || epoch == 0
            || protocol_revision == 0
            || count > MAX_SESSIONS
            || body_len != HEADER + count * ENTRY
        {
            return Err(invalid_data("invalid PQ session store context or length"));
        }
        let mut sessions = BTreeMap::new();
        let mut at = HEADER;
        for _ in 0..count {
            let id = bytes[at..at + 32].try_into().unwrap();
            at += 32;
            let state = StoredSession {
                peer: u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap()),
                expires_at: u64::from_be_bytes(bytes[at + 2..at + 10].try_into().unwrap()),
                send: u64::from_be_bytes(bytes[at + 10..at + 18].try_into().unwrap()),
                receive: u64::from_be_bytes(bytes[at + 18..at + 26].try_into().unwrap()),
            };
            at += 26;
            if id == [0; 32]
                || state.peer == 0
                || state.expires_at == 0
                || sessions.insert(id, state).is_some()
            {
                return Err(invalid_data("non-canonical PQ session store"));
            }
        }
        Ok(Self { chain, epoch, protocol_revision, sessions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::PrincipalId;
    use std::net::{TcpListener, TcpStream};

    fn context() -> PqSessionContext {
        PqSessionContext {
            chain: Digest384::new([9; 48]),
            epoch: 7,
            protocol_revision: 1,
            initiator: 1,
            responder: 2,
        }
    }

    #[test]
    fn pq_session_agrees_and_binds_complete_context() {
        let initiator =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([1; 48])), [1; 32]);
        let responder =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([2; 48])), [2; 32]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let initiator_key = initiator.public_key();
        let responder_key = responder.public_key();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut peer = PeerSocket::connect(stream);
            peer.accept_pq_session(
                context().chain,
                context().epoch,
                context().protocol_revision,
                2,
                &responder,
                &BTreeMap::from([(1, initiator_key)]),
            )
            .unwrap()
        });
        let mut peer = PeerSocket::connect(TcpStream::connect(address).unwrap());
        let client = peer.initiate_pq_session(context(), &initiator, &responder_key).unwrap();
        let server = server.join().unwrap();
        assert_eq!(client.id, server.id);
        assert_eq!(client.key(), server.key());
        assert_eq!(client.local_peer(), 1);
        assert_eq!(server.local_peer(), 2);
    }

    #[test]
    fn pq_session_rejects_wrong_responder_identity() {
        let initiator =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([21; 48])), [21; 32]);
        let responder =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([22; 48])), [22; 32]);
        let impostor =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([23; 48])), [23; 32]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let initiator_key = initiator.public_key();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            PeerSocket::connect(stream).accept_pq_session(
                context().chain,
                context().epoch,
                context().protocol_revision,
                2,
                &responder,
                &BTreeMap::from([(1, initiator_key)]),
            )
        });
        let mut peer = PeerSocket::connect(TcpStream::connect(address).unwrap());
        assert!(peer.initiate_pq_session(context(), &initiator, &impostor.public_key()).is_err());
        drop(peer);
        assert!(server.join().unwrap().is_err());
    }

    #[test]
    fn session_store_is_bounded_durable_and_rejects_replay() {
        let path =
            std::env::temp_dir().join(format!("activechain-pq-session-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let now = now_secs().unwrap();
        let session = PqPeerSession {
            id: [8; 32],
            peer: 2,
            expires_at: now + 60,
            context: context(),
            local_is_initiator: true,
            key: [7; 32],
        };
        let mut store =
            PqSessionStore::new(context().chain, context().epoch, context().protocol_revision)
                .unwrap();
        store.accept_and_save(&session, &path).unwrap();
        assert_eq!(store.reserve_send_and_save(session.id, &path).unwrap(), 1);
        store.accept_receive_and_save(session.id, 1, &path).unwrap();
        let mut loaded = PqSessionStore::load(&path).unwrap();
        assert!(loaded.accept_and_save(&session, &path).is_err());
        assert!(loaded.accept_receive_and_save(session.id, 1, &path).is_err());
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[10] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(PqSessionStore::load(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn session_messages_reject_reflection_cross_domain_and_malformed_lengths() {
        let hello = client_hello(context(), [3; 32]);
        assert!(parse_server_challenge(&hello).is_err());

        let mut other = context();
        other.protocol_revision += 1;
        let parsed = parse_client_hello(&client_hello(other, [4; 32])).unwrap();
        assert_ne!(parsed.0, context());

        let mut truncated = client_hello(context(), [5; 32]);
        truncated.pop();
        assert!(parse_client_hello(&truncated).is_err());

        let mut wrong_suite = client_hello(context(), [6; 32]);
        let suite_offset = DOMAIN.len() + 1 + 68;
        wrong_suite[suite_offset] ^= 1;
        assert!(parse_client_hello(&wrong_suite).is_err());
    }

    #[test]
    fn server_challenge_rejects_replay_cross_domain_and_expiry() {
        let now = now_secs().unwrap();
        let nonce = [10; 32];
        let recipient = MlKem768Recipient::from_seed([11; 64]);
        let mut bytes = server_challenge(
            context(),
            nonce,
            [12; 32],
            now,
            now + SESSION_TTL_SECS,
            [13; 32],
            &recipient.public_key(),
        );
        bytes.extend_from_slice(&[0; SIGNATURE_LEN]);
        let challenge = parse_server_challenge(&bytes).unwrap();
        validate_server_challenge(&challenge, context(), nonce, now).unwrap();
        assert!(validate_server_challenge(&challenge, context(), [14; 32], now).is_err());

        let mut cross_domain = context();
        cross_domain.chain = Digest384::new([15; 48]);
        assert!(validate_server_challenge(&challenge, cross_domain, nonce, now).is_err());
        assert!(
            validate_server_challenge(&challenge, context(), nonce, now + SESSION_TTL_SECS)
                .is_err()
        );
    }

    #[test]
    fn protected_frame_rejects_mutation_and_expired_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let now = now_secs().unwrap();
        let sender_session = PqPeerSession {
            id: [16; 32],
            peer: 2,
            expires_at: now + 60,
            context: context(),
            local_is_initiator: true,
            key: [17; 32],
        };
        let receiver_session =
            PqPeerSession { peer: 1, local_is_initiator: false, ..sender_session.clone() };
        let writer = std::thread::spawn(move || {
            let socket_stream = TcpStream::connect(address).unwrap();
            let mut peer = PeerSocket::connect(socket_stream);
            let plaintext = [18; 80];
            let associated_data = sender_session.associated_data(1, 2, 1);
            let keystream = stream(&sender_session.key, &associated_data, plaintext.len());
            let ciphertext =
                plaintext.iter().zip(keystream).map(|(byte, mask)| byte ^ mask).collect::<Vec<_>>();
            let mut tag =
                expand(PROTECTED_TAG_DOMAIN, &[&sender_session.key, &associated_data, &ciphertext]);
            tag[0] ^= 1;
            let mut frame = Vec::new();
            frame.extend_from_slice(PROTECTED_MAGIC);
            frame.extend_from_slice(&sender_session.id);
            frame.extend_from_slice(&1_u16.to_be_bytes());
            frame.extend_from_slice(&2_u16.to_be_bytes());
            frame.extend_from_slice(&1_u64.to_be_bytes());
            frame.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
            frame.extend_from_slice(&ciphertext);
            frame.extend_from_slice(&tag);
            peer.write_session_frame(&frame).unwrap();
        });
        let (stream, _) = listener.accept().unwrap();
        let mut receiver = PeerSocket::connect(stream);
        assert!(receiver.receive_protected_message(&receiver_session).is_err());
        writer.join().unwrap();

        let expired = PqPeerSession { expires_at: now, ..receiver_session };
        assert!(receiver.receive_protected_message(&expired).is_err());
    }

    #[test]
    fn session_store_rolls_over_atomically_on_domain_change() {
        let path = std::env::temp_dir()
            .join(format!("activechain-pq-session-domain-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let old = PqSessionStore::new(context().chain, context().epoch, 1).unwrap();
        old.save(&path).unwrap();

        let rolled =
            PqSessionStore::load_or_new(&path, context().chain, context().epoch, 2).unwrap();
        assert_eq!(rolled.protocol_revision, 2);
        assert!(rolled.sessions.is_empty());
        assert_eq!(PqSessionStore::load(&path).unwrap(), rolled);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pq_session_v2_constants_match_canonical_vector() {
        let expected = format!(
            "domain={}\nkdf_domain={}\nconfirmation_domain={}\nsession_id_domain={}\n\
             protected_domain={}\nstore_domain={}\ndsa_suite=0x{DSA_SUITE:04x}\n\
             kem_suite=0x{KEM_SUITE:04x}\nkem_public_key_len={KEM_PUBLIC_KEY_LEN}\n\
             kem_ciphertext_len={KEM_CIPHERTEXT_LEN}\nsignature_len={SIGNATURE_LEN}\n\
             session_ttl_seconds={SESSION_TTL_SECS}\nmax_clock_skew_seconds={MAX_CLOCK_SKEW_SECS}\n\
             first_protected_sequence=1\nmax_sessions={MAX_SESSIONS}\n",
            std::str::from_utf8(DOMAIN).unwrap(),
            std::str::from_utf8(KDF_DOMAIN).unwrap(),
            std::str::from_utf8(CONFIRM_DOMAIN).unwrap(),
            std::str::from_utf8(SESSION_ID_DOMAIN).unwrap(),
            std::str::from_utf8(PROTECTED_DOMAIN).unwrap(),
            std::str::from_utf8(STORE_DOMAIN).unwrap(),
        );
        assert_eq!(include_str!("../../../testing/vectors/consensus/pq-session-v2.txt"), expected);
    }
}
