use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_cash_kernel::{
    CashLedger, CashPaymasterPolicyV1, CashPaymasterRequestV1, CoinTransfer,
};
use activechain_protocol_commitment::cash_transition_id;
use activechain_protocol_types::{Digest384, Height, PrincipalId, TransactionId};
use sha2::{Digest, Sha384};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SponsoredCashPersistenceError {
    InvalidState,
    InvalidTransfer,
    Persistence,
}

/// One canonical crash-consistency unit for sponsored cash execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SponsoredCashSnapshotV1 {
    ledger: CashLedger,
    paymaster: CashPaymasterPolicyV1,
}

impl SponsoredCashSnapshotV1 {
    pub const TYPE_TAG: u16 = 0x0179;

    pub fn new(
        ledger: CashLedger,
        paymaster: CashPaymasterPolicyV1,
    ) -> Result<Self, SponsoredCashPersistenceError> {
        ledger.verify_invariants().map_err(|_| SponsoredCashPersistenceError::InvalidState)?;
        Ok(Self { ledger, paymaster })
    }

    pub const fn ledger(&self) -> &CashLedger {
        &self.ledger
    }

    pub const fn paymaster(&self) -> &CashPaymasterPolicyV1 {
        &self.paymaster
    }

    pub fn commitment(&self) -> Result<Digest384, SponsoredCashPersistenceError> {
        let bytes =
            encode_envelope(self).map_err(|_| SponsoredCashPersistenceError::InvalidState)?;
        let mut hasher = Sha384::new();
        hasher.update(b"ACTIVECHAIN-SPONSORED-CASH-SNAPSHOT-V1");
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
        let output: [u8; 48] = hasher.finalize().into();
        Ok(Digest384::new(output))
    }
}

impl CanonicalEncode for SponsoredCashSnapshotV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.ledger.encode(encoder)?;
        self.paymaster.encode(encoder)
    }
}

impl CanonicalDecode for SponsoredCashSnapshotV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(CashLedger::decode(decoder)?, CashPaymasterPolicyV1::decode(decoder)?)
            .map_err(|_| DecodeError::InvalidValue("invalid sponsored cash snapshot"))
    }
}

impl CanonicalType for SponsoredCashSnapshotV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        CashLedger::MAX_ENCODED_LEN + CashPaymasterPolicyV1::MAX_ENCODED_LEN;
}

/// Offline-verifiable result emitted only after durable sponsored execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SponsoredCashReceiptV1 {
    transfer: TransactionId,
    sponsor: PrincipalId,
    sender: PrincipalId,
    fee: u128,
    height: Height,
    pre_state: Digest384,
    post_state: Digest384,
}

impl SponsoredCashReceiptV1 {
    pub const TYPE_TAG: u16 = 0x017a;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transfer: TransactionId,
        sponsor: PrincipalId,
        sender: PrincipalId,
        fee: u128,
        height: Height,
        pre_state: Digest384,
        post_state: Digest384,
    ) -> Result<Self, SponsoredCashPersistenceError> {
        if transfer.digest() == &Digest384::ZERO
            || sponsor.digest() == &Digest384::ZERO
            || sender.digest() == &Digest384::ZERO
            || fee == 0
            || pre_state == Digest384::ZERO
            || post_state == Digest384::ZERO
            || pre_state == post_state
        {
            return Err(SponsoredCashPersistenceError::InvalidState);
        }
        Ok(Self { transfer, sponsor, sender, fee, height, pre_state, post_state })
    }

    pub const fn transfer(&self) -> TransactionId {
        self.transfer
    }

    pub const fn pre_state(&self) -> Digest384 {
        self.pre_state
    }

    pub const fn post_state(&self) -> Digest384 {
        self.post_state
    }

    pub fn binds(
        &self,
        before: &SponsoredCashSnapshotV1,
        after: &SponsoredCashSnapshotV1,
        transfer: &CoinTransfer,
        request: &CashPaymasterRequestV1,
        height: Height,
    ) -> bool {
        cash_transition_id(transfer).is_ok_and(|id| id == self.transfer)
            && request.transfer() == *self.transfer.digest()
            && request.sponsor() == self.sponsor
            && request.sender() == self.sender
            && request.fee() == self.fee
            && height == self.height
            && before.commitment().is_ok_and(|value| value == self.pre_state)
            && after.commitment().is_ok_and(|value| value == self.post_state)
    }
}

impl CanonicalEncode for SponsoredCashReceiptV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.transfer.encode(encoder)?;
        self.sponsor.encode(encoder)?;
        self.sender.encode(encoder)?;
        self.fee.encode(encoder)?;
        self.height.encode(encoder)?;
        self.pre_state.encode(encoder)?;
        self.post_state.encode(encoder)
    }
}

impl CanonicalDecode for SponsoredCashReceiptV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            TransactionId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            u128::decode(decoder)?,
            Height::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid sponsored cash receipt"))
    }
}

impl CanonicalType for SponsoredCashReceiptV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 5 + 16 + 8;
}

/// Write-before-acknowledgement sponsored cash state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableSponsoredCash {
    path: PathBuf,
    snapshot: SponsoredCashSnapshotV1,
}

impl DurableSponsoredCash {
    pub fn create(
        path: impl AsRef<Path>,
        snapshot: SponsoredCashSnapshotV1,
    ) -> Result<Self, SponsoredCashPersistenceError> {
        let path = path.as_ref().to_path_buf();
        save_atomic(&snapshot, &path)?;
        Ok(Self { path, snapshot })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, SponsoredCashPersistenceError> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path).map_err(|_| SponsoredCashPersistenceError::Persistence)?;
        let snapshot =
            decode_envelope(&bytes).map_err(|_| SponsoredCashPersistenceError::Persistence)?;
        Ok(Self { path, snapshot })
    }

    pub const fn snapshot(&self) -> &SponsoredCashSnapshotV1 {
        &self.snapshot
    }

    pub fn execute(
        &mut self,
        request: &CashPaymasterRequestV1,
        transfer: &CoinTransfer,
        height: Height,
    ) -> Result<SponsoredCashReceiptV1, SponsoredCashPersistenceError> {
        let pre_state = self.snapshot.commitment()?;
        let mut next = self.snapshot.clone();
        next.ledger
            .apply_sponsored_transfer(&mut next.paymaster, request, transfer, height)
            .map_err(|_| SponsoredCashPersistenceError::InvalidTransfer)?;
        let post_state = next.commitment()?;
        let receipt = SponsoredCashReceiptV1::new(
            cash_transition_id(transfer)
                .map_err(|_| SponsoredCashPersistenceError::InvalidTransfer)?,
            request.sponsor(),
            request.sender(),
            request.fee(),
            height,
            pre_state,
            post_state,
        )?;
        save_atomic(&next, &self.path)?;
        self.snapshot = next;
        Ok(receipt)
    }
}

fn save_atomic(
    snapshot: &SponsoredCashSnapshotV1,
    path: &Path,
) -> Result<(), SponsoredCashPersistenceError> {
    let bytes =
        encode_envelope(snapshot).map_err(|_| SponsoredCashPersistenceError::Persistence)?;
    let parent = path.parent().ok_or(SponsoredCashPersistenceError::Persistence)?;
    std::fs::create_dir_all(parent).map_err(|_| SponsoredCashPersistenceError::Persistence)?;
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)
        .map_err(|_| SponsoredCashPersistenceError::Persistence)?;
    file.write_all(&bytes).map_err(|_| SponsoredCashPersistenceError::Persistence)?;
    file.sync_all().map_err(|_| SponsoredCashPersistenceError::Persistence)?;
    std::fs::rename(&temporary, path).map_err(|_| SponsoredCashPersistenceError::Persistence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_cash_kernel::{GenesisAllocation, GenesisEconomy, NativeAssetDefinition};
    use activechain_protocol_commitment::cash_transition_id;
    use activechain_protocol_types::{ChainId, Digest384, PrincipalId};
    use std::vec;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }

    fn fixture() -> (SponsoredCashSnapshotV1, CashPaymasterRequestV1, CoinTransfer) {
        let definition = NativeAssetDefinition::new(
            ChainId::new(digest(1)),
            b"ACT".to_vec(),
            18,
            1_000_000,
            150,
            digest(2),
            digest(3),
            digest(4),
        )
        .unwrap();
        let economy = GenesisEconomy::new(
            definition,
            vec![
                GenesisAllocation::new(principal(10), 700_000, 100_000).unwrap(),
                GenesisAllocation::new(principal(12), 100_000, 0).unwrap(),
            ],
            100_000,
        )
        .unwrap();
        let ledger = CashLedger::from_genesis(&economy).unwrap();
        let sender_input = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(10))
            .unwrap()
            .id();
        let sponsor_reserve = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(12))
            .unwrap()
            .id();
        let transfer = CoinTransfer::new(
            principal(10),
            principal(20),
            vec![sender_input],
            sponsor_reserve,
            500,
            7,
            100,
        )
        .unwrap();
        let policy =
            CashPaymasterPolicyV1::new(principal(12), vec![principal(10)], 10, 100, 0, 1, 0, 100)
                .unwrap();
        let request = CashPaymasterRequestV1::new(
            principal(12),
            principal(10),
            *cash_transition_id(&transfer).unwrap().digest(),
            policy.commitment().unwrap(),
            digest(90),
            7,
            0,
            1,
            0,
            100,
        )
        .unwrap();
        (SponsoredCashSnapshotV1::new(ledger, policy).unwrap(), request, transfer)
    }

    #[test]
    fn sponsored_execution_survives_restart_and_replay_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sponsored-cash.bin");
        let (snapshot, request, transfer) = fixture();
        let before = snapshot.clone();
        let mut durable = DurableSponsoredCash::create(&path, snapshot).unwrap();
        let receipt = durable.execute(&request, &transfer, 10).unwrap();
        assert!(receipt.binds(&before, durable.snapshot(), &transfer, &request, 10));
        assert!(!receipt.binds(&before, durable.snapshot(), &transfer, &request, 11));
        assert_eq!(
            decode_envelope::<SponsoredCashReceiptV1>(&encode_envelope(&receipt).unwrap()).unwrap(),
            receipt
        );
        assert_eq!(durable.snapshot().paymaster().spent(), 7);
        assert_eq!(durable.snapshot().paymaster().next_nonce(), 1);
        let mut restarted = DurableSponsoredCash::open(&path).unwrap();
        assert_eq!(restarted.snapshot(), durable.snapshot());
        assert_eq!(
            restarted.execute(&request, &transfer, 10),
            Err(SponsoredCashPersistenceError::InvalidTransfer)
        );
        assert_eq!(restarted.snapshot(), durable.snapshot());
    }

    #[test]
    fn corrupt_restart_and_failed_write_leave_state_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let corrupt = directory.path().join("corrupt.bin");
        std::fs::write(&corrupt, b"not canonical").unwrap();
        assert_eq!(
            DurableSponsoredCash::open(&corrupt),
            Err(SponsoredCashPersistenceError::Persistence)
        );

        let path = directory.path().join("sponsored-cash.bin");
        let (snapshot, request, transfer) = fixture();
        let mut durable = DurableSponsoredCash::create(&path, snapshot).unwrap();
        let before = durable.snapshot().clone();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            durable.execute(&request, &transfer, 10),
            Err(SponsoredCashPersistenceError::Persistence)
        );
        assert_eq!(durable.snapshot(), &before);
    }
}
