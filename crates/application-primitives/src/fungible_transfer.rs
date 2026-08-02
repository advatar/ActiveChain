use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_cash_kernel::{
    FungibleBurnV1, FungibleCoinCellSet, FungibleMintV1, FungibleRedemptionV1, FungibleTransferV1,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    AssetId, Digest384, FungibleAssetPolicyV1, FungibleHolderControlStateV1,
    FungibleIssuerApprovalV1, Height,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    vec::Vec,
};

pub const MAX_FUNGIBLE_ASSET_POLICIES: usize = 4096;

/// Canonical public state-tree value authenticating one complete multi-asset ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssetLedgerAnchorV1 {
    finalized_height: Height,
    ledger_commitment: Digest384,
}

impl AssetLedgerAnchorV1 {
    pub const TYPE_TAG: u16 = 0x018E;

    pub fn new(
        finalized_height: Height,
        ledger_commitment: Digest384,
    ) -> Result<Self, FungibleTransferPersistenceError> {
        if finalized_height == 0 || ledger_commitment == Digest384::ZERO {
            return Err(FungibleTransferPersistenceError::InvalidState);
        }
        Ok(Self { finalized_height, ledger_commitment })
    }

    pub fn from_ledger(
        finalized_height: Height,
        ledger: &MultiAssetLedgerSnapshotV1,
    ) -> Result<Self, FungibleTransferPersistenceError> {
        let ledger_commitment = commit(DomainTag::CANONICAL_VALUE, ledger)
            .map_err(|_| FungibleTransferPersistenceError::InvalidState)?;
        Self::new(finalized_height, ledger_commitment)
    }

    pub const fn finalized_height(self) -> Height {
        self.finalized_height
    }
    pub const fn ledger_commitment(self) -> Digest384 {
        self.ledger_commitment
    }

    pub fn commitment(&self) -> Result<Digest384, FungibleTransferPersistenceError> {
        commit(DomainTag::CANONICAL_VALUE, self)
            .map_err(|_| FungibleTransferPersistenceError::InvalidState)
    }
}

impl CanonicalEncode for AssetLedgerAnchorV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.finalized_height.encode(encoder)?;
        self.ledger_commitment.encode(encoder)
    }
}

impl CanonicalDecode for AssetLedgerAnchorV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(u64::decode(decoder)?, Digest384::decode(decoder)?)
            .map_err(|_| DecodeError::InvalidValue("invalid asset ledger anchor"))
    }
}

impl CanonicalType for AssetLedgerAnchorV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 56;
}

#[must_use]
pub const fn asset_ledger_anchor_type_id() -> Digest384 {
    let mut bytes = [0_u8; 48];
    bytes[46] = 0x01;
    bytes[47] = 0x8E;
    Digest384::new(bytes)
}

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
        self.persist(FungibleAssetLedgerSnapshotV1::new(cells, self.snapshot.policy)?)
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

/// Complete fungible state whose sorted policies govern every cell in the set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiAssetLedgerSnapshotV1 {
    cells: FungibleCoinCellSet,
    policies: Vec<FungibleAssetPolicyV1>,
}

impl MultiAssetLedgerSnapshotV1 {
    pub const TYPE_TAG: u16 = 0x0180;

    pub fn new(
        cells: FungibleCoinCellSet,
        policies: Vec<FungibleAssetPolicyV1>,
    ) -> Result<Self, FungibleTransferPersistenceError> {
        if policies.len() > MAX_FUNGIBLE_ASSET_POLICIES
            || policies.windows(2).any(|pair| pair[0].asset_id() >= pair[1].asset_id())
        {
            return Err(FungibleTransferPersistenceError::InvalidState);
        }
        for record in cells.as_slice() {
            if policy_index(&policies, record.cell().asset_id()).is_none() {
                return Err(FungibleTransferPersistenceError::InvalidState);
            }
        }
        for policy in &policies {
            let issued = cells
                .as_slice()
                .iter()
                .filter(|record| record.cell().asset_id() == policy.asset_id())
                .try_fold(0_u128, |sum, record| sum.checked_add(record.cell().amount()))
                .ok_or(FungibleTransferPersistenceError::InvalidState)?;
            if issued != policy.supply_issued() {
                return Err(FungibleTransferPersistenceError::InvalidState);
            }
        }
        Ok(Self { cells, policies })
    }

    pub const fn cells(&self) -> &FungibleCoinCellSet {
        &self.cells
    }
    pub fn policies(&self) -> &[FungibleAssetPolicyV1] {
        &self.policies
    }
    pub fn policy(&self, asset_id: AssetId) -> Option<&FungibleAssetPolicyV1> {
        policy_index(&self.policies, asset_id).map(|index| &self.policies[index])
    }
}

impl CanonicalEncode for MultiAssetLedgerSnapshotV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.cells.encode(encoder)?;
        encoder.write_length(self.policies.len(), MAX_FUNGIBLE_ASSET_POLICIES)?;
        for policy in &self.policies {
            policy.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for MultiAssetLedgerSnapshotV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let cells = FungibleCoinCellSet::decode(decoder)?;
        let count = decoder.read_length(MAX_FUNGIBLE_ASSET_POLICIES)?;
        let mut policies = Vec::with_capacity(count);
        for _ in 0..count {
            policies.push(FungibleAssetPolicyV1::decode(decoder)?);
        }
        Self::new(cells, policies)
            .map_err(|_| DecodeError::InvalidValue("invalid multi-asset ledger snapshot"))
    }
}

impl CanonicalType for MultiAssetLedgerSnapshotV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = FungibleCoinCellSet::MAX_ENCODED_LEN
        + 3
        + MAX_FUNGIBLE_ASSET_POLICIES * FungibleAssetPolicyV1::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableMultiAssetLedger {
    path: PathBuf,
    snapshot: MultiAssetLedgerSnapshotV1,
}

impl DurableMultiAssetLedger {
    pub fn create(
        path: impl AsRef<Path>,
        snapshot: MultiAssetLedgerSnapshotV1,
    ) -> Result<Self, FungibleTransferPersistenceError> {
        let path = path.as_ref().to_path_buf();
        save_multi_asset_atomic(&snapshot, &path)?;
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
    pub const fn snapshot(&self) -> &MultiAssetLedgerSnapshotV1 {
        &self.snapshot
    }

    pub fn transfer(
        &mut self,
        transfer: &FungibleTransferV1,
        holder_state: &FungibleHolderControlStateV1,
        height: Height,
    ) -> Result<(), FungibleTransferPersistenceError> {
        let policy = self
            .snapshot
            .policy(transfer.asset_id())
            .ok_or(FungibleTransferPersistenceError::InvalidTransfer)?;
        let cells = self
            .snapshot
            .cells
            .apply_transfer(transfer, policy, holder_state, height)
            .map_err(|_| FungibleTransferPersistenceError::InvalidTransfer)?;
        self.persist(MultiAssetLedgerSnapshotV1::new(cells, self.snapshot.policies.clone())?)
    }
    pub fn mint(
        &mut self,
        mint: &FungibleMintV1,
        approval: &FungibleIssuerApprovalV1,
        height: Height,
    ) -> Result<(), FungibleTransferPersistenceError> {
        self.apply_policy_transition(mint.asset_id(), |cells, policy| {
            cells.apply_mint(mint, policy, approval, height)
        })
    }
    pub fn burn(
        &mut self,
        burn: &FungibleBurnV1,
        approval: &FungibleIssuerApprovalV1,
        height: Height,
    ) -> Result<(), FungibleTransferPersistenceError> {
        self.apply_policy_transition(burn.asset_id(), |cells, policy| {
            cells.apply_burn(burn, policy, approval, height)
        })
    }
    pub fn redeem(
        &mut self,
        redemption: &FungibleRedemptionV1,
        approval: &FungibleIssuerApprovalV1,
        height: Height,
    ) -> Result<(), FungibleTransferPersistenceError> {
        self.apply_policy_transition(redemption.asset_id(), |cells, policy| {
            cells.apply_redemption(redemption, policy, approval, height)
        })
    }
    fn apply_policy_transition(
        &mut self,
        asset_id: AssetId,
        transition: impl FnOnce(
            &FungibleCoinCellSet,
            &FungibleAssetPolicyV1,
        ) -> Result<
            (FungibleCoinCellSet, FungibleAssetPolicyV1),
            activechain_cash_kernel::NativeMoneyError,
        >,
    ) -> Result<(), FungibleTransferPersistenceError> {
        let index = policy_index(&self.snapshot.policies, asset_id)
            .ok_or(FungibleTransferPersistenceError::InvalidTransfer)?;
        let (cells, policy) = transition(&self.snapshot.cells, &self.snapshot.policies[index])
            .map_err(|_| FungibleTransferPersistenceError::InvalidTransfer)?;
        let mut policies = self.snapshot.policies.clone();
        policies[index] = policy;
        self.persist(MultiAssetLedgerSnapshotV1::new(cells, policies)?)
    }
    fn persist(
        &mut self,
        next: MultiAssetLedgerSnapshotV1,
    ) -> Result<(), FungibleTransferPersistenceError> {
        save_multi_asset_atomic(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }
}

fn policy_index(policies: &[FungibleAssetPolicyV1], asset_id: AssetId) -> Option<usize> {
    policies.binary_search_by_key(&asset_id, |policy| policy.asset_id()).ok()
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

fn save_multi_asset_atomic(
    snapshot: &MultiAssetLedgerSnapshotV1,
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

    fn multi_asset_fixture() -> (MultiAssetLedgerSnapshotV1, AssetId, AssetId, PrincipalId) {
        let asset_a = AssetId::new(digest(21));
        let asset_b = AssetId::new(digest(22));
        let issuer = PrincipalId::new(digest(23));
        let cell_a = FungibleCoinCell::new(
            CoinCellOrigin::new(TransactionId::new(digest(24)), 0),
            asset_a,
            issuer,
            50,
            1,
        )
        .unwrap();
        let cell_b = FungibleCoinCell::new(
            CoinCellOrigin::new(TransactionId::new(digest(25)), 0),
            asset_b,
            issuer,
            70,
            1,
        )
        .unwrap();
        let mut records = vec![cell_a, cell_b]
            .into_iter()
            .map(|cell| FungibleCoinCellRecord::new(coin_cell_id(&cell.origin()).unwrap(), cell))
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record.id());
        let cells = FungibleCoinCellSet::new(records).unwrap();
        let make_policy = |asset, supply| {
            FungibleAssetPolicyV1::new(
                asset,
                issuer,
                digest(26),
                digest(27),
                digest(28),
                digest(29),
                200,
                supply,
                FungibleAssetLifecycle::Registered,
            )
            .unwrap()
        };
        let mut policies = vec![make_policy(asset_b, 70), make_policy(asset_a, 50)];
        policies.sort_by_key(|policy| policy.asset_id());
        (MultiAssetLedgerSnapshotV1::new(cells, policies).unwrap(), asset_a, asset_b, issuer)
    }

    #[test]
    fn multi_asset_mint_is_isolated_restarts_and_replay_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("multi-asset-ledger.bin");
        let (snapshot, asset_a, asset_b, issuer) = multi_asset_fixture();
        let before_b = snapshot.policy(asset_b).unwrap().clone();
        let policy_a = snapshot.policy(asset_a).unwrap();
        let mint = FungibleMintV1::new(asset_a, issuer, PrincipalId::new(digest(30)), 10, 50, 200)
            .unwrap();
        let approval = FungibleIssuerApprovalV1::new(
            asset_a,
            policy_a.commitment().unwrap(),
            policy_a.authority_set(),
            digest(31),
            FungibleIssuerOperation::Mint,
            10,
            50,
            5,
            10,
        )
        .unwrap();
        let mut durable = DurableMultiAssetLedger::create(&path, snapshot).unwrap();
        durable.mint(&mint, &approval, 5).unwrap();
        assert_eq!(durable.snapshot().policy(asset_a).unwrap().supply_issued(), 60);
        assert_eq!(durable.snapshot().policy(asset_b), Some(&before_b));
        assert_eq!(
            durable
                .snapshot()
                .cells()
                .as_slice()
                .iter()
                .filter(|record| record.cell().asset_id() == asset_b)
                .map(|record| record.cell().amount())
                .sum::<u128>(),
            70
        );
        let restarted = DurableMultiAssetLedger::open(&path).unwrap();
        assert_eq!(restarted.snapshot(), durable.snapshot());
        let before_replay = durable.snapshot().clone();
        assert_eq!(
            durable.mint(&mint, &approval, 5),
            Err(FungibleTransferPersistenceError::InvalidTransfer)
        );
        assert_eq!(durable.snapshot(), &before_replay);
    }

    #[test]
    fn multi_asset_snapshot_rejects_unknown_unsorted_and_mismatched_policies() {
        let (snapshot, asset_a, asset_b, _) = multi_asset_fixture();
        assert_eq!(
            MultiAssetLedgerSnapshotV1::new(
                snapshot.cells().clone(),
                vec![snapshot.policy(asset_a).unwrap().clone()]
            ),
            Err(FungibleTransferPersistenceError::InvalidState)
        );
        assert_eq!(
            MultiAssetLedgerSnapshotV1::new(
                snapshot.cells().clone(),
                vec![
                    snapshot.policy(asset_b).unwrap().clone(),
                    snapshot.policy(asset_a).unwrap().clone()
                ]
            ),
            Err(FungibleTransferPersistenceError::InvalidState)
        );
        let mismatched = FungibleAssetPolicyV1::new(
            asset_a,
            snapshot.policy(asset_a).unwrap().issuer(),
            digest(26),
            digest(27),
            digest(28),
            digest(29),
            200,
            49,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap();
        let mut policies = vec![mismatched, snapshot.policy(asset_b).unwrap().clone()];
        policies.sort_by_key(|policy| policy.asset_id());
        assert_eq!(
            MultiAssetLedgerSnapshotV1::new(snapshot.cells().clone(), policies),
            Err(FungibleTransferPersistenceError::InvalidState)
        );
    }

    #[test]
    fn multi_asset_failed_write_does_not_advance_memory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("multi-asset-ledger.bin");
        let (snapshot, asset_a, _, issuer) = multi_asset_fixture();
        let cell = snapshot
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().asset_id() == asset_a)
            .unwrap()
            .cell();
        let policy = snapshot.policy(asset_a).unwrap();
        let burn = FungibleBurnV1::new(asset_a, issuer, vec![cell], 50).unwrap();
        let approval = FungibleIssuerApprovalV1::new(
            asset_a,
            policy.commitment().unwrap(),
            policy.authority_set(),
            digest(32),
            FungibleIssuerOperation::Burn,
            50,
            50,
            5,
            10,
        )
        .unwrap();
        let mut durable = DurableMultiAssetLedger::create(&path, snapshot).unwrap();
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
