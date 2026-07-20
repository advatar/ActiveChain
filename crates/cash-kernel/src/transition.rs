use alloc::vec::Vec;

use activechain_protocol_commitment::{
    cash_transition_id, coin_cell_id, coin_cell_set_root, genesis_allocation_root, native_asset_id,
    supply_root,
};
use activechain_protocol_types::{
    CoinCellId, CoinCellSetRoot, GenesisAllocationRoot, Height, SupplyRoot, TransactionId,
};

use crate::types::{
    CoinBurnTransition, CoinCell, CoinCellOrigin, CoinCellRecord, CoinCellSet, CoinMintTransition,
    CoinTransfer, EpochEconomicsTransition, GenesisEconomy, NativeAssetDefinition,
    NativeMoneyError, NativeSupply,
};
use crate::{RewardRedemption, RewardSettlement};

/// Atomic bounded native-money ledger used by the semantic and process kernels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashLedger {
    definition: NativeAssetDefinition,
    supply: NativeSupply,
    cells: CoinCellSet,
}

impl CashLedger {
    pub fn redeem_reward(
        &mut self,
        settlement: &RewardSettlement,
        redemption: &RewardRedemption,
    ) -> Result<(), CashTransitionError> {
        if redemption.settlement != settlement.assignment || settlement.reward == 0 {
            return Err(CashTransitionError::Invalid(NativeMoneyError::ZeroAmount));
        }
        let transfer = CoinTransfer::new(
            redemption.pool_owner,
            settlement.verifier,
            alloc::vec![redemption.pool_cell],
            redemption.fee_reserve,
            settlement.reward,
            0,
            redemption.height,
        )
        .map_err(CashTransitionError::Invalid)?;
        self.apply_transfer(&transfer, redemption.height)
    }
    /// Creates a ledger from a validated one-time genesis economy.
    pub fn from_genesis(economy: &GenesisEconomy) -> Result<Self, CashTransitionError> {
        let mut records = Vec::new();
        for (index, allocation) in economy.allocations().iter().enumerate() {
            if allocation.liquid_amount() == 0 {
                continue;
            }
            let origin = CoinCellOrigin::new(
                TransactionId::new(economy_root_digest(economy)?),
                u16::try_from(index)
                    .map_err(|_| CashTransitionError::Invariant(NativeMoneyError::TooManyCells))?,
            );
            let cell = CoinCell::new(origin, allocation.recipient(), allocation.liquid_amount(), 0)
                .map_err(CashTransitionError::Invalid)?;
            let id = coin_cell_id(&origin).map_err(CashTransitionError::Encoding)?.into_digest();
            records.push(CoinCellRecord::new(CoinCellId::new(id), cell));
        }
        records.sort_by_key(|record| record.id());
        let cells = CoinCellSet::new(records).map_err(CashTransitionError::Invalid)?;
        let locked = economy
            .allocations()
            .iter()
            .map(|allocation| allocation.locked_amount())
            .try_fold(0_u128, |sum, amount| sum.checked_add(amount))
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        let supply = NativeSupply::genesis(
            economy.definition().genesis_supply(),
            economy.security_reserve(),
            locked,
        )
        .map_err(CashTransitionError::Invalid)?;
        let ledger = Self { definition: economy.definition().clone(), supply, cells };
        ledger.verify_invariants()?;
        Ok(ledger)
    }

    #[must_use]
    pub const fn definition(&self) -> &NativeAssetDefinition {
        &self.definition
    }
    #[must_use]
    pub const fn supply(&self) -> NativeSupply {
        self.supply
    }
    #[must_use]
    pub const fn cells(&self) -> &CoinCellSet {
        &self.cells
    }

    /// Applies a deterministic epoch-security mint from the declared issuance authority.
    pub fn apply_mint(
        &mut self,
        mint: &CoinMintTransition,
        settlement: &EpochEconomicsTransition,
    ) -> Result<CoinCellId, CashTransitionError> {
        if mint.issuance_policy_hash() != self.definition.issuance_policy_hash() {
            return Err(CashTransitionError::Invalid(NativeMoneyError::MintAuthorityMismatch));
        }
        if mint.sequence() != settlement.epoch()
            || mint.sequence()
                != self
                    .supply
                    .last_settled_epoch()
                    .checked_add(1)
                    .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?
        {
            return Err(CashTransitionError::Invalid(NativeMoneyError::MintSequenceMismatch));
        }
        if settlement.pre_supply() != self.supply.current_total_supply()
            || settlement.burned_amount() != 0
            || settlement.authorized_issuance() != mint.amount()
        {
            return Err(CashTransitionError::Invalid(NativeMoneyError::IssuanceFormulaMismatch));
        }
        let next_total = settlement.post_supply();
        if next_total < self.supply.current_total_supply() {
            return Err(CashTransitionError::Invalid(NativeMoneyError::IssuanceCapExceeded));
        }
        let transition_id = cash_transition_id(mint).map_err(CashTransitionError::Encoding)?;
        let origin = CoinCellOrigin::new(transition_id, 0);
        let cell = CoinCell::new(origin, mint.recipient(), mint.amount(), mint.height())
            .map_err(CashTransitionError::Invalid)?;
        let id = coin_cell_id(&origin).map_err(CashTransitionError::Encoding)?;
        self.insert_new_cell(CoinCellRecord::new(id, cell))?;
        let issuance = self
            .supply
            .cumulative_security_issuance()
            .checked_add(mint.amount())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        self.supply = NativeSupply::new(
            self.supply.genesis_supply(),
            issuance,
            self.supply.cumulative_burn(),
            next_total,
            self.supply
                .circulating_supply()
                .checked_add(mint.amount())
                .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?,
            self.supply.locked_vesting_supply(),
            self.supply.staked_supply(),
            self.supply.security_reserve_balance(),
            mint.sequence(),
        )
        .map_err(CashTransitionError::Invalid)?;
        self.verify_invariants()?;
        Ok(CoinCellId::new(id.into_digest()))
    }

    /// Applies a fixed public transfer, charging its explicit fee reserve.
    pub fn apply_transfer(
        &mut self,
        transfer: &CoinTransfer,
        height: Height,
    ) -> Result<(), CashTransitionError> {
        if height > transfer.valid_until() {
            return Err(CashTransitionError::Invalid(NativeMoneyError::Expired));
        }
        let mut total = 0_u128;
        let mut records = Vec::new();
        for id in transfer.inputs() {
            let record = self
                .find(*id)
                .ok_or(CashTransitionError::Invalid(NativeMoneyError::MissingCell))?;
            if record.cell().owner() != transfer.sender() {
                return Err(CashTransitionError::Invalid(NativeMoneyError::WrongOwner));
            }
            total = total
                .checked_add(record.cell().amount())
                .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
            records.push(record);
        }
        let reserve = self
            .find(transfer.fee_reserve())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::MissingCell))?;
        if reserve.cell().owner() != transfer.sender() {
            return Err(CashTransitionError::Invalid(NativeMoneyError::WrongOwner));
        }
        total = total
            .checked_add(reserve.cell().amount())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        let required = transfer
            .amount()
            .checked_add(transfer.fee())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        if total < required {
            return Err(CashTransitionError::Invalid(NativeMoneyError::InsufficientValue));
        }
        records.push(reserve);
        let change = total - required;
        let transition_id = cash_transition_id(transfer).map_err(CashTransitionError::Encoding)?;
        let mut next = self
            .cells
            .as_slice()
            .iter()
            .copied()
            .filter(|record| !records.iter().any(|spent| spent.id() == record.id()))
            .collect::<Vec<_>>();
        let recipient = CoinCell::new(
            CoinCellOrigin::new(transition_id, 0),
            transfer.recipient(),
            transfer.amount(),
            height,
        )
        .map_err(CashTransitionError::Invalid)?;
        let recipient_id =
            coin_cell_id(&recipient.origin()).map_err(CashTransitionError::Encoding)?;
        next.push(CoinCellRecord::new(recipient_id, recipient));
        if change > 0 {
            let change_cell = CoinCell::new(
                CoinCellOrigin::new(transition_id, 1),
                transfer.sender(),
                change,
                height,
            )
            .map_err(CashTransitionError::Invalid)?;
            let change_id =
                coin_cell_id(&change_cell.origin()).map_err(CashTransitionError::Encoding)?;
            next.push(CoinCellRecord::new(change_id, change_cell));
        }
        next.sort_by_key(|record| record.id());
        self.cells = CoinCellSet::new(next).map_err(CashTransitionError::Invalid)?;
        let fee_pool = self
            .supply
            .security_reserve_balance()
            .checked_add(transfer.fee())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        let circulating = self
            .supply
            .circulating_supply()
            .checked_sub(transfer.fee())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        self.supply = NativeSupply::new(
            self.supply.genesis_supply(),
            self.supply.cumulative_security_issuance(),
            self.supply.cumulative_burn(),
            self.supply.current_total_supply(),
            circulating,
            self.supply.locked_vesting_supply(),
            self.supply.staked_supply(),
            fee_pool,
            self.supply.last_settled_epoch(),
        )
        .map_err(CashTransitionError::Invalid)?;
        self.verify_invariants()
    }

    /// Applies a permanent burn and returns any unburned change to the owner.
    pub fn apply_burn(
        &mut self,
        burn: &CoinBurnTransition,
        height: Height,
    ) -> Result<(), CashTransitionError> {
        if height > burn.valid_until() {
            return Err(CashTransitionError::Invalid(NativeMoneyError::Expired));
        }
        let mut total = 0_u128;
        let mut spent = Vec::new();
        for id in burn.inputs() {
            let record = self
                .find(*id)
                .ok_or(CashTransitionError::Invalid(NativeMoneyError::MissingCell))?;
            if record.cell().owner() != burn.owner() {
                return Err(CashTransitionError::Invalid(NativeMoneyError::WrongOwner));
            }
            total = total
                .checked_add(record.cell().amount())
                .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
            spent.push(record);
        }
        if total < burn.amount() {
            return Err(CashTransitionError::Invalid(NativeMoneyError::BurnExceedsInputs));
        }
        let transition_id = cash_transition_id(burn).map_err(CashTransitionError::Encoding)?;
        let mut next = self
            .cells
            .as_slice()
            .iter()
            .copied()
            .filter(|r| !spent.iter().any(|s| s.id() == r.id()))
            .collect::<Vec<_>>();
        let change = total - burn.amount();
        if change > 0 {
            let cell =
                CoinCell::new(CoinCellOrigin::new(transition_id, 0), burn.owner(), change, height)
                    .map_err(CashTransitionError::Invalid)?;
            let id = coin_cell_id(&cell.origin()).map_err(CashTransitionError::Encoding)?;
            next.push(CoinCellRecord::new(id, cell));
        }
        next.sort_by_key(|r| r.id());
        self.cells = CoinCellSet::new(next).map_err(CashTransitionError::Invalid)?;
        let burned = self
            .supply
            .cumulative_burn()
            .checked_add(burn.amount())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        let current = self
            .supply
            .current_total_supply()
            .checked_sub(burn.amount())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        let circulating = self
            .supply
            .circulating_supply()
            .checked_sub(burn.amount())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        self.supply = NativeSupply::new(
            self.supply.genesis_supply(),
            self.supply.cumulative_security_issuance(),
            burned,
            current,
            circulating,
            self.supply.locked_vesting_supply(),
            self.supply.staked_supply(),
            self.supply.security_reserve_balance(),
            self.supply.last_settled_epoch(),
        )
        .map_err(CashTransitionError::Invalid)?;
        self.verify_invariants()
    }

    pub fn verify_invariants(&self) -> Result<(), CashTransitionError> {
        let mut cell_total = 0_u128;
        for record in self.cells.as_slice() {
            let expected =
                coin_cell_id(&record.cell().origin()).map_err(CashTransitionError::Encoding)?;
            if expected != record.id() {
                return Err(CashTransitionError::Invariant(NativeMoneyError::OutputCollision));
            }
            cell_total = cell_total
                .checked_add(record.cell().amount())
                .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        }
        let accounted = cell_total
            .checked_add(self.supply.security_reserve_balance())
            .and_then(|v| v.checked_add(self.supply.locked_vesting_supply()))
            .and_then(|v| v.checked_add(self.supply.staked_supply()))
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        let expected = self.supply.current_total_supply();
        if accounted != expected {
            return Err(CashTransitionError::Invariant(NativeMoneyError::SupplyPartitionMismatch));
        }
        Ok(())
    }

    pub fn cell_set_root(&self) -> Result<CoinCellSetRoot, CashTransitionError> {
        coin_cell_set_root(&self.cells).map_err(CashTransitionError::Encoding)
    }
    pub fn supply_root(&self) -> Result<SupplyRoot, CashTransitionError> {
        supply_root(&self.supply).map_err(CashTransitionError::Encoding)
    }
    pub fn genesis_root(
        economy: &GenesisEconomy,
    ) -> Result<GenesisAllocationRoot, CashTransitionError> {
        genesis_allocation_root(economy).map_err(CashTransitionError::Encoding)
    }
    pub fn asset_id(&self) -> Result<activechain_protocol_types::AssetId, CashTransitionError> {
        native_asset_id(&self.definition).map_err(CashTransitionError::Encoding)
    }
    fn find(&self, id: CoinCellId) -> Option<CoinCellRecord> {
        self.cells
            .as_slice()
            .binary_search_by_key(&id, |r| r.id())
            .ok()
            .map(|i| self.cells.as_slice()[i])
    }
    fn insert_new_cell(&mut self, record: CoinCellRecord) -> Result<(), CashTransitionError> {
        if self.find(record.id()).is_some() {
            return Err(CashTransitionError::Invalid(NativeMoneyError::OutputCollision));
        }
        let mut next = self.cells.as_slice().to_vec();
        next.push(record);
        next.sort_by_key(|r| r.id());
        self.cells = CoinCellSet::new(next).map_err(CashTransitionError::Invalid)?;
        Ok(())
    }
}

fn economy_root_digest(
    economy: &GenesisEconomy,
) -> Result<activechain_protocol_types::Digest384, CashTransitionError> {
    genesis_allocation_root(economy)
        .map(|root| root.into_digest())
        .map_err(CashTransitionError::Encoding)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashTransitionError {
    Invalid(NativeMoneyError),
    Encoding(activechain_canonical_codec::EncodeError),
    Invariant(NativeMoneyError),
}
