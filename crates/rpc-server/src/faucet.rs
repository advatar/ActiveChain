use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{ChainId, Digest384, PrincipalId, TransactionId};
use activechain_rpc_types::{FaucetReceiptV1, FaucetRequestV1, FaucetState};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

const MAX_FAUCET_RECORDS: usize = 65_535;
const SNAPSHOT_TAG_LENGTH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SybilPolicy {
    CooldownOnly,
    ProofOfWork { leading_zero_bits: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaucetPolicy {
    pub chain_id: ChainId,
    pub genesis_commitment: Digest384,
    pub enabled: bool,
    pub grant_amount: u128,
    pub recipient_cooldown_seconds: u64,
    pub recipient_lifetime_limit: u16,
    pub source_window_seconds: u64,
    pub source_window_limit: u16,
    pub global_window_seconds: u64,
    pub global_window_limit: u32,
    pub sybil_policy: SybilPolicy,
}

impl FaucetPolicy {
    pub fn validate(&self) -> Result<(), FaucetError> {
        let difficulty = match self.sybil_policy {
            SybilPolicy::CooldownOnly => 0,
            SybilPolicy::ProofOfWork { leading_zero_bits } => leading_zero_bits,
        };
        if self.genesis_commitment == Digest384::ZERO
            || self.grant_amount == 0
            || self.recipient_cooldown_seconds == 0
            || self.recipient_lifetime_limit == 0
            || self.source_window_seconds == 0
            || self.source_window_limit == 0
            || self.global_window_seconds == 0
            || self.global_window_limit == 0
            || difficulty > 32
        {
            return Err(FaucetError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaucetError {
    Disabled,
    WrongNetwork,
    InvalidPolicy,
    InvalidChallenge,
    RecipientCooldown,
    RecipientExhausted,
    SourceLimited,
    GlobalLimited,
    NotFound,
    InvalidTransition,
    Persistence,
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Admission {
    Accept,
    RecipientCooldown,
    RecipientExhausted,
    SourceLimited,
    GlobalLimited,
}

#[allow(clippy::too_many_arguments)]
fn admission(
    recipient_count: usize,
    seconds_since_recipient: Option<u64>,
    source_count: usize,
    global_count: usize,
    recipient_lifetime_limit: u16,
    recipient_cooldown_seconds: u64,
    source_window_limit: u16,
    global_window_limit: u32,
) -> Admission {
    if recipient_count >= usize::from(recipient_lifetime_limit) {
        Admission::RecipientExhausted
    } else if seconds_since_recipient.is_some_and(|age| age < recipient_cooldown_seconds) {
        Admission::RecipientCooldown
    } else if source_count >= usize::from(source_window_limit) {
        Admission::SourceLimited
    } else if global_count >= usize::try_from(global_window_limit).unwrap_or(usize::MAX) {
        Admission::GlobalLimited
    } else {
        Admission::Accept
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FaucetRecord {
    idempotency_key: Digest384,
    source_commitment: Digest384,
    created_at: u64,
    receipt: FaucetReceiptV1,
}

pub struct DurableFaucet {
    policy: FaucetPolicy,
    path: PathBuf,
    records: Vec<FaucetRecord>,
}

impl DurableFaucet {
    pub fn create(policy: FaucetPolicy, path: PathBuf) -> Result<Self, FaucetError> {
        policy.validate()?;
        if path.exists() {
            return Err(FaucetError::Persistence);
        }
        let service = Self { policy, path, records: Vec::new() };
        service.save()?;
        Ok(service)
    }

    pub fn open(policy: FaucetPolicy, path: PathBuf) -> Result<Self, FaucetError> {
        policy.validate()?;
        let records = load_records(&path)?;
        if records.iter().any(|record| {
            record.receipt.amount() != policy.grant_amount
                || record.receipt.recipient().into_digest() == Digest384::ZERO
        }) {
            return Err(FaucetError::Persistence);
        }
        Ok(Self { policy, path, records })
    }

    pub const fn policy(&self) -> FaucetPolicy {
        self.policy
    }

    pub fn request<F>(
        &mut self,
        request: &FaucetRequestV1,
        source_commitment: Digest384,
        now: u64,
        submit: F,
    ) -> Result<FaucetReceiptV1, FaucetError>
    where
        F: FnOnce(PrincipalId, u128, Digest384) -> Result<TransactionId, FaucetError>,
    {
        if !self.policy.enabled {
            return Err(FaucetError::Disabled);
        }
        if request.chain_id() != self.policy.chain_id
            || request.genesis_commitment() != self.policy.genesis_commitment
        {
            return Err(FaucetError::WrongNetwork);
        }
        if source_commitment == Digest384::ZERO {
            return Err(FaucetError::InvalidChallenge);
        }
        if let Some(existing) =
            self.records.iter().find(|record| record.idempotency_key == request.idempotency_key())
        {
            if existing.receipt.recipient() == request.recipient()
                && existing.source_commitment == source_commitment
            {
                return Ok(existing.receipt.clone());
            }
            return Err(FaucetError::InvalidChallenge);
        }
        self.verify_challenge(request, source_commitment)?;

        let recipient_records: Vec<_> = self
            .records
            .iter()
            .filter(|record| record.receipt.recipient() == request.recipient())
            .collect();
        let seconds_since_recipient =
            recipient_records.iter().map(|record| now.saturating_sub(record.created_at)).min();
        let source_count = self
            .records
            .iter()
            .filter(|record| {
                record.source_commitment == source_commitment
                    && now.saturating_sub(record.created_at) < self.policy.source_window_seconds
            })
            .count();
        let global_count = self
            .records
            .iter()
            .filter(|record| {
                now.saturating_sub(record.created_at) < self.policy.global_window_seconds
            })
            .count();
        match admission(
            recipient_records.len(),
            seconds_since_recipient,
            source_count,
            global_count,
            self.policy.recipient_lifetime_limit,
            self.policy.recipient_cooldown_seconds,
            self.policy.source_window_limit,
            self.policy.global_window_limit,
        ) {
            Admission::Accept => {}
            Admission::RecipientCooldown => return Err(FaucetError::RecipientCooldown),
            Admission::RecipientExhausted => return Err(FaucetError::RecipientExhausted),
            Admission::SourceLimited => return Err(FaucetError::SourceLimited),
            Admission::GlobalLimited => return Err(FaucetError::GlobalLimited),
        }
        if self.records.len() >= MAX_FAUCET_RECORDS {
            return Err(FaucetError::Capacity);
        }

        let reference = faucet_reference(request, source_commitment);
        let transaction_id = submit(request.recipient(), self.policy.grant_amount, reference)?;
        let receipt = FaucetReceiptV1::new(
            reference,
            request.recipient(),
            self.policy.grant_amount,
            FaucetState::Pending,
            Some(transaction_id),
            None,
            None,
            Vec::new(),
        )
        .map_err(|_| FaucetError::InvalidTransition)?;
        self.records.push(FaucetRecord {
            idempotency_key: request.idempotency_key(),
            source_commitment,
            created_at: now,
            receipt: receipt.clone(),
        });
        if self.save().is_err() {
            self.records.pop();
            return Err(FaucetError::Persistence);
        }
        Ok(receipt)
    }

    pub fn resolve(&self, reference: Digest384) -> Option<&FaucetReceiptV1> {
        self.records
            .iter()
            .find(|record| record.receipt.reference() == reference)
            .map(|record| &record.receipt)
    }

    pub fn finalize(
        &mut self,
        reference: Digest384,
        height: u64,
        block: Digest384,
        proof: Vec<u8>,
    ) -> Result<FaucetReceiptV1, FaucetError> {
        let index = self
            .records
            .iter()
            .position(|record| record.receipt.reference() == reference)
            .ok_or(FaucetError::NotFound)?;
        let current = &self.records[index].receipt;
        let transaction = current.transaction_id().ok_or(FaucetError::InvalidTransition)?;
        let finalized = FaucetReceiptV1::new(
            reference,
            current.recipient(),
            current.amount(),
            FaucetState::Finalized,
            Some(transaction),
            Some(height),
            Some(block),
            proof,
        )
        .map_err(|_| FaucetError::InvalidTransition)?;
        let previous = std::mem::replace(&mut self.records[index].receipt, finalized.clone());
        if self.save().is_err() {
            self.records[index].receipt = previous;
            return Err(FaucetError::Persistence);
        }
        Ok(finalized)
    }

    fn verify_challenge(
        &self,
        request: &FaucetRequestV1,
        source_commitment: Digest384,
    ) -> Result<(), FaucetError> {
        let SybilPolicy::ProofOfWork { leading_zero_bits } = self.policy.sybil_policy else {
            return Ok(());
        };
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-TESTNET-FAUCET-POW-V1");
        hasher.update(self.policy.genesis_commitment.as_bytes());
        hasher.update(request.recipient().into_digest().as_bytes());
        hasher.update(request.idempotency_key().as_bytes());
        hasher.update(source_commitment.as_bytes());
        hasher.update(&request.challenge_nonce().to_be_bytes());
        hasher.update(request.challenge_evidence());
        let mut output = [0_u8; 32];
        XofReader::read(&mut hasher.finalize_xof(), &mut output);
        if leading_zero_count(&output) < u32::from(leading_zero_bits) {
            return Err(FaucetError::InvalidChallenge);
        }
        Ok(())
    }

    fn save(&self) -> Result<(), FaucetError> {
        save_records(&self.path, &self.records)
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn accepted_admission_is_strictly_within_every_limit() {
        let recipient_count: usize = kani::any();
        let recipient_age: Option<u64> = kani::any();
        let source_count: usize = kani::any();
        let global_count: usize = kani::any();
        let recipient_limit: u16 = kani::any();
        let cooldown: u64 = kani::any();
        let source_limit: u16 = kani::any();
        let global_limit: u32 = kani::any();
        kani::assume(recipient_limit > 0);
        kani::assume(cooldown > 0);
        kani::assume(source_limit > 0);
        kani::assume(global_limit > 0);

        if admission(
            recipient_count,
            recipient_age,
            source_count,
            global_count,
            recipient_limit,
            cooldown,
            source_limit,
            global_limit,
        ) == Admission::Accept
        {
            assert!(recipient_count < usize::from(recipient_limit));
            assert!(recipient_age.is_none_or(|age| age >= cooldown));
            assert!(source_count < usize::from(source_limit));
            assert!(global_count < usize::try_from(global_limit).unwrap_or(usize::MAX));
        }
    }

    #[kani::proof]
    fn increasing_usage_cannot_turn_a_rejection_into_acceptance() {
        let recipient_count: u16 = kani::any();
        let source_count: u16 = kani::any();
        let global_count: u32 = kani::any();
        let recipient_limit: u16 = kani::any();
        let source_limit: u16 = kani::any();
        let global_limit: u32 = kani::any();
        kani::assume(recipient_count < u16::MAX);
        kani::assume(source_count < u16::MAX);
        kani::assume(global_count < u32::MAX);

        let before = admission(
            usize::from(recipient_count),
            None,
            usize::from(source_count),
            usize::try_from(global_count).unwrap_or(usize::MAX),
            recipient_limit,
            1,
            source_limit,
            global_limit,
        );
        let after = admission(
            usize::from(recipient_count + 1),
            None,
            usize::from(source_count + 1),
            usize::try_from(global_count + 1).unwrap_or(usize::MAX),
            recipient_limit,
            1,
            source_limit,
            global_limit,
        );
        if before != Admission::Accept {
            assert!(after != Admission::Accept);
        }
    }
}

fn faucet_reference(request: &FaucetRequestV1, source: Digest384) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-TESTNET-FAUCET-REFERENCE-V1");
    hasher.update(request.chain_id().into_digest().as_bytes());
    hasher.update(request.genesis_commitment().as_bytes());
    hasher.update(request.recipient().into_digest().as_bytes());
    hasher.update(request.idempotency_key().as_bytes());
    hasher.update(source.as_bytes());
    let mut output = [0; 48];
    XofReader::read(&mut hasher.finalize_xof(), &mut output);
    Digest384::new(output)
}

fn leading_zero_count(bytes: &[u8]) -> u32 {
    let mut count = 0;
    for byte in bytes {
        let zeros = byte.leading_zeros();
        count += zeros;
        if zeros != 8 {
            break;
        }
    }
    count
}

impl CanonicalEncode for FaucetRecord {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.idempotency_key.encode(encoder)?;
        self.source_commitment.encode(encoder)?;
        self.created_at.encode(encoder)?;
        self.receipt.encode(encoder)
    }
}
impl CanonicalDecode for FaucetRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            idempotency_key: Digest384::decode(decoder)?,
            source_commitment: Digest384::decode(decoder)?,
            created_at: u64::decode(decoder)?,
            receipt: FaucetReceiptV1::decode(decoder)?,
        })
    }
}

fn save_records(path: &Path, records: &[FaucetRecord]) -> Result<(), FaucetError> {
    let mut encoder = Encoder::new(4 + records.len() * (104 + FaucetReceiptV1::MAX_ENCODED_LEN));
    encoder.write_length(records.len(), MAX_FAUCET_RECORDS).map_err(|_| FaucetError::Capacity)?;
    for record in records {
        record.encode(&mut encoder).map_err(|_| FaucetError::Persistence)?;
    }
    let bytes = encoder.finish();
    let tag = snapshot_tag(&bytes);
    let temporary = path.with_extension("tmp");
    let mut file = File::create(&temporary).map_err(|_| FaucetError::Persistence)?;
    file.write_all(&bytes).map_err(|_| FaucetError::Persistence)?;
    file.write_all(&tag).map_err(|_| FaucetError::Persistence)?;
    file.sync_all().map_err(|_| FaucetError::Persistence)?;
    std::fs::rename(&temporary, path).map_err(|_| FaucetError::Persistence)?;
    let parent =
        path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| FaucetError::Persistence)
}

fn load_records(path: &Path) -> Result<Vec<FaucetRecord>, FaucetError> {
    let bytes = std::fs::read(path).map_err(|_| FaucetError::Persistence)?;
    if bytes.len() < SNAPSHOT_TAG_LENGTH {
        return Err(FaucetError::Persistence);
    }
    let body_len = bytes.len() - SNAPSHOT_TAG_LENGTH;
    if snapshot_tag(&bytes[..body_len]) != bytes[body_len..] {
        return Err(FaucetError::Persistence);
    }
    let mut decoder = Decoder::new(&bytes[..body_len]);
    let count = decoder.read_length(MAX_FAUCET_RECORDS).map_err(|_| FaucetError::Persistence)?;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(FaucetRecord::decode(&mut decoder).map_err(|_| FaucetError::Persistence)?);
    }
    decoder.finish().map_err(|_| FaucetError::Persistence)?;
    Ok(records)
}

fn snapshot_tag(bytes: &[u8]) -> [u8; SNAPSHOT_TAG_LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-FAUCET-SNAPSHOT-V1");
    hasher.update(bytes);
    let mut output = [0; SNAPSHOT_TAG_LENGTH];
    XofReader::read(&mut hasher.finalize_xof(), &mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }
    fn policy() -> FaucetPolicy {
        FaucetPolicy {
            chain_id: ChainId::new(digest(1)),
            genesis_commitment: digest(2),
            enabled: true,
            grant_amount: 1_000,
            recipient_cooldown_seconds: 60,
            recipient_lifetime_limit: 2,
            source_window_seconds: 60,
            source_window_limit: 2,
            global_window_seconds: 60,
            global_window_limit: 3,
            sybil_policy: SybilPolicy::CooldownOnly,
        }
    }
    fn request(recipient: u8, key: u8) -> FaucetRequestV1 {
        FaucetRequestV1::new(
            ChainId::new(digest(1)),
            digest(2),
            principal(recipient),
            digest(key),
            0,
            Vec::new(),
        )
        .unwrap()
    }
    fn path(name: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("activechain-faucet-{name}-{nonce}.snapshot"))
    }

    #[test]
    fn idempotency_and_limits_survive_restart() {
        let path = path("limits");
        let mut faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
        let receipt = faucet
            .request(&request(3, 4), digest(9), 100, |_, _, _| Ok(TransactionId::new(digest(10))))
            .unwrap();
        assert_eq!(
            faucet.request(&request(3, 4), digest(9), 101, |_, _, _| panic!()),
            Ok(receipt.clone())
        );
        assert_eq!(
            faucet.request(&request(3, 5), digest(9), 101, |_, _, _| panic!()),
            Err(FaucetError::RecipientCooldown)
        );
        drop(faucet);
        let faucet = DurableFaucet::open(policy(), path.clone()).unwrap();
        assert_eq!(faucet.resolve(receipt.reference()), Some(&receipt));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn wrong_network_and_source_reuse_are_rejected() {
        let path = path("network");
        let mut faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
        let wrong = FaucetRequestV1::new(
            ChainId::new(digest(8)),
            digest(2),
            principal(3),
            digest(4),
            0,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            faucet.request(&wrong, digest(9), 100, |_, _, _| panic!()),
            Err(FaucetError::WrongNetwork)
        );
        faucet
            .request(&request(3, 4), digest(9), 100, |_, _, _| Ok(TransactionId::new(digest(10))))
            .unwrap();
        assert_eq!(
            faucet.request(&request(4, 4), digest(9), 200, |_, _, _| panic!()),
            Err(FaucetError::InvalidChallenge)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn finalized_receipt_carries_chain_evidence() {
        let path = path("finalize");
        let mut faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
        let pending = faucet
            .request(&request(3, 4), digest(9), 100, |_, _, _| Ok(TransactionId::new(digest(10))))
            .unwrap();
        let finalized =
            faucet.finalize(pending.reference(), 12, digest(11), vec![1, 2, 3]).unwrap();
        assert_eq!(finalized.state(), FaucetState::Finalized);
        assert_eq!(finalized.finalized_height(), Some(12));
        drop(faucet);
        assert_eq!(
            DurableFaucet::open(policy(), path.clone()).unwrap().resolve(pending.reference()),
            Some(&finalized)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn corrupted_snapshot_is_rejected() {
        let path = path("corrupt");
        let faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
        drop(faucet);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            DurableFaucet::open(policy(), path.clone()),
            Err(FaucetError::Persistence)
        ));
        std::fs::remove_file(path).unwrap();
    }
}
