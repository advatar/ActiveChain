use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_cash_kernel::{
    FungibleBurnV1, FungibleCoinCellSet, FungibleMintV1, FungibleRedemptionV1, FungibleTransferV1,
};
use activechain_protocol_types::{
    FungibleAssetPolicyV1, FungibleHolderControlStateV1, FungibleIssuerApprovalV1, Height,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FungibleTransferPersistenceError {
    InvalidTransfer,
    InvalidState,
    Persistence,
}

/// Complete fungible state for one policy, with unrelated asset cells retained in the set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FungibleAssetLedgerSnapshotV1 {
    cells: FungibleCoinCellSet,
    policy: FungibleAssetPolicyV1,
}

impl FungibleAssetLedgerSnapshotV1 {
    pub const TYPE_TAG: u16 = 0x017f;

    pub fn new(
        cells: FungibleCoinCellSet,
        policy: FungibleAssetPolicyV1,
    ) -> Result<Self, FungibleTransferPersistenceError> {
        let issued = cells
            .as_slice()
            .iter()
            .filter(|record| record.cell().asset_id() == policy.asset_id())
            .try_fold(0_u128, |sum, record| sum.checked_add(record.cell().amount()))
            .ok_or(FungibleTransferPersistenceError::InvalidState)?;
        if issued != policy.supply_issued() {
            return Err(FungibleTransferPersistenceError::InvalidState);
        }
        Ok(Self { cells, policy })
    }

    pub const fn cells(&self) -> &FungibleCoinCellSet {
        &self.cells
    }

    pub const fn policy(&self) -> &FungibleAssetPolicyV1 {
        &self.policy
    }
}

impl CanonicalEncode for FungibleAssetLedgerSnapshotV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.cells.encode(encoder)?;
        self.policy.encode(encoder)
    }
}

impl CanonicalDecode for FungibleAssetLedgerSnapshotV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(FungibleCoinCellSet::decode(decoder)?, FungibleAssetPolicyV1::decode(decoder)?)
            .map_err(|_| DecodeError::InvalidValue("invalid fungible asset ledger snapshot"))
    }
}

impl CanonicalType for FungibleAssetLedgerSnapshotV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        FungibleCoinCellSet::MAX_ENCODED_LEN + FungibleAssetPolicyV1::MAX_ENCODED_LEN;
}

/// Write-before-acknowledgement Coin Cell and policy-supply state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableFungibleAssetLedger {
    path: PathBuf,
    snapshot: FungibleAssetLedgerSnapshotV1,
}

impl DurableFungibleAssetLedger {
    pub fn create(
        path: impl AsRef<Path>,
        snapshot: FungibleAssetLedgerSnapshotV1,
    ) -> Result<Self, FungibleTransferPersistenceError> {
        let path = path.as_ref().to_path_buf();
        save_asset_atomic(&snapshot, &path)?;
        Ok(Self { path, snapshot })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, FungibleTransferPersistenceError> {
        let path = path.as_ref().to_path_buf();
        let bytes =
            std::fs::read(&path).map_err(|_| FungibleTransferPersistenceError::Persistence)?;
        let snapshot =
            decode_envelope(&bytes).map_err(|_| FungibleTransferPersistenceError::Persistence)?;
        Ok(Self { path, snapshot })
    }

    pub const fn snapshot(&self) -> &FungibleAssetLedgerSnapshotV1 {
        &self.snapshot
    }

    pub fn transfer(
        &mut self,
        transfer: &FungibleTransferV1,
        holder_state: &FungibleHolderControlStateV1,
        height: Height,
    ) -> Result<(), FungibleTransferPersistenceError> {
        let cells = self
            .snapshot
            .cells
            .apply_transfer(transfer, &self.snapshot.policy, holder_state, height)
            .map_err(|_| FungibleTransferPersistenceError::InvalidTransfer)?;
        self.persist(FungibleAssetLedgerSnapshotV1::new(cells, self.snapshot.policy.clone())?)
    }

    pub fn mint(
        &mut self,
        mint: &FungibleMintV1,
        approval: &FungibleIssuerApprovalV1,
        height: Height,
    ) -> Result<(), FungibleTransferPersistenceError> {
        let (cells, policy) = self
            .snapshot
            .cells
            .apply_mint(mint, &self.snapshot.policy, approval, height)
            .map_err(|_| FungibleTransferPersistenceError::InvalidTransfer)?;
        self.persist(FungibleAssetLedgerSnapshotV1::new(cells, policy)?)
    }

    pub fn burn(
        &mut self,
        burn: &FungibleBurnV1,
        approval: &FungibleIssuerApprovalV1,
        height: Height,
    ) -> Result<(), FungibleTransferPersistenceError> {
        let (cells, policy) = self
            .snapshot
            .cells
            .apply_burn(burn, &self.snapshot.policy, approval, height)
            .map_err(|_| FungibleTransferPersistenceError::InvalidTransfer)?;
        self.persist(FungibleAssetLedgerSnapshotV1::new(cells, policy)?)
    }

    pub fn redeem(
        &mut self,
        redemption: &FungibleRedemptionV1,
        approval: &FungibleIssuerApprovalV1,
        height: Height,
    ) -> Result<(), FungibleTransferPersistenceError> {
        let (cells, policy) = self
            .snapshot
            .cells
            .apply_redemption(redemption, &self.snapshot.policy, approval, height)
            .map_err(|_| FungibleTransferPersistenceError::InvalidTransfer)?;
        self.persist(FungibleAssetLedgerSnapshotV1::new(cells, policy)?)
    }

    fn persist(
        &mut self,
        next: FungibleAssetLedgerSnapshotV1,
    ) -> Result<(), FungibleTransferPersistenceError> {
        save_asset_atomic(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }
}

/// Write-before-acknowledgement authoritative fungible Coin Cell set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableFungibleTransferLedger {
    path: PathBuf,
    cells: FungibleCoinCellSet,
}

impl DurableFungibleTransferLedger {
    pub fn create(
        path: impl AsRef<Path>,
        cells: FungibleCoinCellSet,
    ) -> Result<Self, FungibleTransferPersistenceError> {
        let path = path.as_ref().to_path_buf();
        save_atomic(&cells, &path)?;
        Ok(Self { path, cells })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, FungibleTransferPersistenceError> {
        let path = path.as_ref().to_path_buf();
        let bytes =
            std::fs::read(&path).map_err(|_| FungibleTransferPersistenceError::Persistence)?;
        let cells =
            decode_envelope(&bytes).map_err(|_| FungibleTransferPersistenceError::Persistence)?;
        Ok(Self { path, cells })
    }

    pub const fn cells(&self) -> &FungibleCoinCellSet {
        &self.cells
    }

    pub fn apply(
        &mut self,
        transfer: &FungibleTransferV1,
        policy: &FungibleAssetPolicyV1,
        holder_state: &FungibleHolderControlStateV1,
        height: Height,
    ) -> Result<(), FungibleTransferPersistenceError> {
        let next = self
            .cells
            .apply_transfer(transfer, policy, holder_state, height)
            .map_err(|_| FungibleTransferPersistenceError::InvalidTransfer)?;
        save_atomic(&next, &self.path)?;
        self.cells = next;
        Ok(())
    }
}

fn save_atomic(
    cells: &FungibleCoinCellSet,
    path: &Path,
) -> Result<(), FungibleTransferPersistenceError> {
    let bytes =
        encode_envelope(cells).map_err(|_| FungibleTransferPersistenceError::Persistence)?;
    let parent = path.parent().ok_or(FungibleTransferPersistenceError::Persistence)?;
    std::fs::create_dir_all(parent).map_err(|_| FungibleTransferPersistenceError::Persistence)?;
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)
        .map_err(|_| FungibleTransferPersistenceError::Persistence)?;
    file.write_all(&bytes).map_err(|_| FungibleTransferPersistenceError::Persistence)?;
    file.sync_all().map_err(|_| FungibleTransferPersistenceError::Persistence)?;
    std::fs::rename(temporary, path).map_err(|_| FungibleTransferPersistenceError::Persistence)
}

fn save_asset_atomic(
    snapshot: &FungibleAssetLedgerSnapshotV1,
    path: &Path,
) -> Result<(), FungibleTransferPersistenceError> {
    let bytes =
        encode_envelope(snapshot).map_err(|_| FungibleTransferPersistenceError::Persistence)?;
    let parent = path.parent().ok_or(FungibleTransferPersistenceError::Persistence)?;
    std::fs::create_dir_all(parent).map_err(|_| FungibleTransferPersistenceError::Persistence)?;
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)
        .map_err(|_| FungibleTransferPersistenceError::Persistence)?;
    file.write_all(&bytes).map_err(|_| FungibleTransferPersistenceError::Persistence)?;
    file.sync_all().map_err(|_| FungibleTransferPersistenceError::Persistence)?;
    std::fs::rename(temporary, path).map_err(|_| FungibleTransferPersistenceError::Persistence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_cash_kernel::{CoinCellOrigin, FungibleCoinCell, FungibleCoinCellRecord};
    use activechain_protocol_commitment::coin_cell_id;
    use activechain_protocol_types::{
        AssetId, Digest384, FungibleAssetLifecycle, FungibleIssuerOperation, PrincipalId,
        TransactionId,
    };
    use std::vec;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn fixture() -> (
        FungibleCoinCellSet,
        FungibleTransferV1,
        FungibleAssetPolicyV1,
        FungibleHolderControlStateV1,
    ) {
        let asset = AssetId::new(digest(1));
        let owner = PrincipalId::new(digest(2));
        let recipient = PrincipalId::new(digest(3));
        let origin = CoinCellOrigin::new(TransactionId::new(digest(4)), 0);
        let cell = FungibleCoinCell::new(origin, asset, owner, 50, 5).unwrap();
        let cells = FungibleCoinCellSet::new(vec![FungibleCoinCellRecord::new(
            coin_cell_id(&origin).unwrap(),
            cell,
        )])
        .unwrap();
        let transfer = FungibleTransferV1::new(asset, owner, recipient, vec![cell], 50).unwrap();
        let policy = FungibleAssetPolicyV1::new(
            asset,
            owner,
            digest(5),
            digest(6),
            digest(7),
            digest(8),
            100,
            50,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap();
        let state = FungibleHolderControlStateV1::new(asset, owner).unwrap();
        (cells, transfer, policy, state)
    }

    #[test]
    fn transfer_survives_restart_and_replay_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fungible-ledger.bin");
        let (cells, transfer, policy, state) = fixture();
        let mut durable = DurableFungibleTransferLedger::create(&path, cells).unwrap();
        durable.apply(&transfer, &policy, &state, 10).unwrap();
        let root = durable.cells().root();
        let mut restarted = DurableFungibleTransferLedger::open(&path).unwrap();
        assert_eq!(restarted.cells().root(), root);
        assert_eq!(
            restarted.apply(&transfer, &policy, &state, 10),
            Err(FungibleTransferPersistenceError::InvalidTransfer)
        );
        assert_eq!(restarted.cells().root(), root);
    }

    #[test]
    fn corruption_and_failed_write_do_not_advance_root() {
        let directory = tempfile::tempdir().unwrap();
        let corrupt = directory.path().join("corrupt.bin");
        std::fs::write(&corrupt, b"not canonical").unwrap();
        assert_eq!(
            DurableFungibleTransferLedger::open(&corrupt),
            Err(FungibleTransferPersistenceError::Persistence)
        );
        let path = directory.path().join("fungible-ledger.bin");
        let (cells, transfer, policy, state) = fixture();
        let mut durable = DurableFungibleTransferLedger::create(&path, cells).unwrap();
        let root = durable.cells().root();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            durable.apply(&transfer, &policy, &state, 10),
            Err(FungibleTransferPersistenceError::Persistence)
        );
        assert_eq!(durable.cells().root(), root);
    }

    #[test]
    fn combined_asset_ledger_mint_survives_restart_with_exact_supply() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fungible-asset-ledger.bin");
        let (cells, _, policy, _) = fixture();
        let snapshot = FungibleAssetLedgerSnapshotV1::new(cells, policy).unwrap();
        let mut durable = DurableFungibleAssetLedger::create(&path, snapshot).unwrap();
        let mint = FungibleMintV1::new(
            durable.snapshot().policy().asset_id(),
            durable.snapshot().policy().issuer(),
            PrincipalId::new(digest(9)),
            10,
            50,
            100,
        )
        .unwrap();
        let approval = FungibleIssuerApprovalV1::new(
            durable.snapshot().policy().asset_id(),
            durable.snapshot().policy().commitment().unwrap(),
            durable.snapshot().policy().authority_set(),
            digest(10),
            FungibleIssuerOperation::Mint,
            10,
            50,
            5,
            10,
        )
        .unwrap();
        durable.mint(&mint, &approval, 5).unwrap();
        assert_eq!(durable.snapshot().policy().supply_issued(), 60);
        assert_eq!(durable.snapshot().cells().as_slice().len(), 2);
        let restarted = DurableFungibleAssetLedger::open(&path).unwrap();
        assert_eq!(restarted.snapshot(), durable.snapshot());
    }

    #[test]
    fn combined_asset_ledger_rejects_supply_mismatch_and_failed_burn_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fungible-asset-ledger.bin");
        let (cells, _, policy, _) = fixture();
        let mismatched = FungibleAssetPolicyV1::new(
            policy.asset_id(),
            policy.issuer(),
            digest(5),
            digest(6),
            digest(7),
            digest(8),
            100,
            49,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap();
        assert_eq!(
            FungibleAssetLedgerSnapshotV1::new(cells.clone(), mismatched),
            Err(FungibleTransferPersistenceError::InvalidState)
        );
        let cell = cells.as_slice()[0].cell();
        let snapshot = FungibleAssetLedgerSnapshotV1::new(cells, policy).unwrap();
        let mut durable = DurableFungibleAssetLedger::create(&path, snapshot).unwrap();
        let burn = FungibleBurnV1::new(
            durable.snapshot().policy().asset_id(),
            durable.snapshot().policy().issuer(),
            vec![cell],
            50,
        )
        .unwrap();
        let approval = FungibleIssuerApprovalV1::new(
            durable.snapshot().policy().asset_id(),
            durable.snapshot().policy().commitment().unwrap(),
            durable.snapshot().policy().authority_set(),
            digest(10),
            FungibleIssuerOperation::Burn,
            50,
            50,
            5,
            10,
        )
        .unwrap();
        let before = durable.snapshot().clone();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            durable.burn(&burn, &approval, 5),
            Err(FungibleTransferPersistenceError::Persistence)
        );
        assert_eq!(durable.snapshot(), &before);
    }
}
