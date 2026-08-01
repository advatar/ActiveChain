use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_cash_kernel::{FungibleCoinCellSet, FungibleTransferV1};
use activechain_protocol_types::{FungibleAssetPolicyV1, FungibleHolderControlStateV1, Height};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FungibleTransferPersistenceError {
    InvalidTransfer,
    Persistence,
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

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_cash_kernel::{CoinCellOrigin, FungibleCoinCell, FungibleCoinCellRecord};
    use activechain_protocol_commitment::coin_cell_id;
    use activechain_protocol_types::{
        AssetId, Digest384, FungibleAssetLifecycle, PrincipalId, TransactionId,
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
}
