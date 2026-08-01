use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_cash_kernel::{
    CashLedger, CashPaymasterPolicyV1, CashPaymasterRequestV1, CoinTransfer,
};
use activechain_protocol_types::Height;
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
    ) -> Result<(), SponsoredCashPersistenceError> {
        let mut next = self.snapshot.clone();
        next.ledger
            .apply_sponsored_transfer(&mut next.paymaster, request, transfer, height)
            .map_err(|_| SponsoredCashPersistenceError::InvalidTransfer)?;
        save_atomic(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
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
        let mut durable = DurableSponsoredCash::create(&path, snapshot).unwrap();
        durable.execute(&request, &transfer, 10).unwrap();
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
