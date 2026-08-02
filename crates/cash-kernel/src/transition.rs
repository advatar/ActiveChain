use alloc::vec::Vec;

use activechain_accumulator::{
    AccumulatorDomain, NonMembershipWitness, ReferenceSet, SetCommitment,
};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_privacy_kernel::{
    PrivacyError, ShieldIntent, ShieldedCashState, UnshieldIntent, VerifiedPrivacyProof,
};
use activechain_protocol_commitment::{
    DomainTag, cash_transition_id, coin_cell_id, coin_cell_set_root, commit,
    genesis_allocation_root, native_asset_id, supply_root,
};
use activechain_protocol_types::{
    CoinCellId, CoinCellSetRoot, GenesisAllocationRoot, Height, SupplyRoot, TransactionId,
};

use crate::types::{
    CoinBurnTransition, CoinCell, CoinCellOrigin, CoinCellRecord, CoinCellSet, CoinMintTransition,
    CoinTransfer, EpochEconomicsTransition, GenesisEconomy, NativeAssetDefinition,
    NativeMoneyError, NativeSupply, basis_points_amount, effective_stake_basis_points,
    epoch_security_budget, issuance_window_index,
};
use crate::{
    CashPaymasterPolicyV1, CashPaymasterRequestV1, EconomicsError, RewardRedemption,
    RewardSettlement,
};

/// Atomic bounded native-money ledger used by the semantic and process kernels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashLedger {
    definition: NativeAssetDefinition,
    supply: NativeSupply,
    cells: CoinCellSet,
    shielded: ShieldedCashState,
    redeemed_reward_root: activechain_protocol_types::Digest384,
    redeemed_reward_count: u64,
}

pub const LEGACY_MAX_REDEEMED_REWARDS: usize = 4_096;

impl CashLedger {
    pub fn redeem_reward(
        &mut self,
        settlement: &RewardSettlement,
        redemption: &RewardRedemption,
    ) -> Result<(), CashTransitionError> {
        if redemption.settlement != settlement.assignment
            || redemption.replay_witness.assignment() != settlement.assignment
            || settlement.reward == 0
        {
            return Err(CashTransitionError::Invalid(NativeMoneyError::ZeroAmount));
        }
        let commitment = SetCommitment {
            domain: AccumulatorDomain::SpentInput,
            root: self.redeemed_reward_root.into_bytes(),
            count: self.redeemed_reward_count,
        };
        let witness = NonMembershipWitness {
            key: settlement.assignment.into_bytes(),
            siblings: redemption
                .replay_witness
                .siblings()
                .iter()
                .map(|sibling| sibling.into_bytes())
                .collect(),
        };
        let next_commitment =
            commitment.insert(settlement.assignment.into_bytes(), &witness).map_err(|_| {
                CashTransitionError::Invalid(NativeMoneyError::InvalidRewardReplayWitness)
            })?;
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
        let mut next = self.clone();
        next.apply_transfer_inner(&transfer, redemption.height)?;
        next.redeemed_reward_root =
            activechain_protocol_types::Digest384::new(next_commitment.root);
        next.redeemed_reward_count = next_commitment.count;
        next.verify_invariants()?;
        *self = next;
        Ok(())
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
        let ledger = Self {
            definition: economy.definition().clone(),
            supply,
            cells,
            shielded: ShieldedCashState::default(),
            redeemed_reward_root: activechain_protocol_types::Digest384::new(
                SetCommitment::empty(AccumulatorDomain::SpentInput).root,
            ),
            redeemed_reward_count: 0,
        };
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
    #[must_use]
    pub const fn shielded_state(&self) -> &ShieldedCashState {
        &self.shielded
    }
    #[must_use]
    pub const fn redeemed_reward_root(&self) -> activechain_protocol_types::Digest384 {
        self.redeemed_reward_root
    }
    #[must_use]
    pub const fn redeemed_reward_count(&self) -> u64 {
        self.redeemed_reward_count
    }

    /// Atomically consumes public Coin Cells and credits the shielded native-value partition.
    pub fn apply_shield(
        &mut self,
        intent: &ShieldIntent,
        proof: VerifiedPrivacyProof,
        height: Height,
    ) -> Result<(), CashTransitionError> {
        let mut next = self.clone();
        next.apply_shield_inner(intent, proof, height)?;
        *self = next;
        Ok(())
    }

    fn apply_shield_inner(
        &mut self,
        intent: &ShieldIntent,
        proof: VerifiedPrivacyProof,
        height: Height,
    ) -> Result<(), CashTransitionError> {
        self.verify_privacy_context(
            intent.chain_id(),
            intent.asset_id(),
            intent.valid_until(),
            height,
        )?;
        let proof_commitment = verify_privacy_proof(intent, proof)?;
        let mut total = 0_u128;
        let mut spent = Vec::new();
        for id in intent.inputs() {
            let record = self
                .find(*id)
                .ok_or(CashTransitionError::Invalid(NativeMoneyError::MissingCell))?;
            if record.cell().owner() != intent.owner() {
                return Err(CashTransitionError::Invalid(NativeMoneyError::WrongOwner));
            }
            total = total
                .checked_add(record.cell().amount())
                .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
            spent.push(record);
        }
        let reserve = self
            .find(intent.fee_reserve())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::MissingCell))?;
        if reserve.cell().owner() != intent.owner() {
            return Err(CashTransitionError::Invalid(NativeMoneyError::WrongOwner));
        }
        total = total
            .checked_add(reserve.cell().amount())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        spent.push(reserve);
        let required = intent
            .amount()
            .checked_add(intent.fee())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        if total < required {
            return Err(CashTransitionError::Invalid(NativeMoneyError::InsufficientValue));
        }
        let transition_id = cash_transition_id(intent).map_err(CashTransitionError::Encoding)?;
        let mut cells = self
            .cells
            .as_slice()
            .iter()
            .copied()
            .filter(|record| !spent.iter().any(|item| item.id() == record.id()))
            .collect::<Vec<_>>();
        let change = total - required;
        if change > 0 {
            let cell = CoinCell::new(
                CoinCellOrigin::new(transition_id, 0),
                intent.owner(),
                change,
                height,
            )
            .map_err(CashTransitionError::Invalid)?;
            let id = coin_cell_id(&cell.origin()).map_err(CashTransitionError::Encoding)?;
            cells.push(CoinCellRecord::new(id, cell));
        }
        cells.sort_by_key(|record| record.id());
        self.cells = CoinCellSet::new(cells).map_err(CashTransitionError::Invalid)?;
        self.shielded
            .credit(intent.amount(), proof_commitment)
            .map_err(CashTransitionError::Privacy)?;
        self.move_fee_to_reserve(intent.fee())?;
        self.verify_invariants()
    }

    /// Atomically consumes shielded nullifiers and creates one public Coin Cell.
    pub fn apply_unshield(
        &mut self,
        intent: &UnshieldIntent,
        proof: VerifiedPrivacyProof,
        height: Height,
    ) -> Result<CoinCellId, CashTransitionError> {
        let mut next = self.clone();
        let output = next.apply_unshield_inner(intent, proof, height)?;
        *self = next;
        Ok(output)
    }

    fn apply_unshield_inner(
        &mut self,
        intent: &UnshieldIntent,
        proof: VerifiedPrivacyProof,
        height: Height,
    ) -> Result<CoinCellId, CashTransitionError> {
        self.verify_privacy_context(
            intent.chain_id(),
            intent.asset_id(),
            intent.valid_until(),
            height,
        )?;
        if intent.anchor() != self.shielded.anchor() {
            return Err(CashTransitionError::Privacy(PrivacyError::WrongAnchor));
        }
        let proof_commitment = verify_privacy_proof(intent, proof)?;
        let debit = intent
            .amount()
            .checked_add(intent.fee())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        self.shielded
            .debit(debit, intent.nullifiers(), intent.nullifier_witnesses(), proof_commitment)
            .map_err(CashTransitionError::Privacy)?;
        let transition_id = cash_transition_id(intent).map_err(CashTransitionError::Encoding)?;
        let cell = CoinCell::new(
            CoinCellOrigin::new(transition_id, 0),
            intent.recipient(),
            intent.amount(),
            height,
        )
        .map_err(CashTransitionError::Invalid)?;
        let id = coin_cell_id(&cell.origin()).map_err(CashTransitionError::Encoding)?;
        self.insert_new_cell(CoinCellRecord::new(id, cell))?;
        self.move_fee_to_reserve(intent.fee())?;
        self.verify_invariants()?;
        Ok(id)
    }

    fn verify_privacy_context(
        &self,
        chain_id: activechain_protocol_types::ChainId,
        asset_id: activechain_protocol_types::AssetId,
        valid_until: Height,
        height: Height,
    ) -> Result<(), CashTransitionError> {
        if chain_id != self.definition.chain_id() {
            return Err(CashTransitionError::Privacy(PrivacyError::WrongChain));
        }
        if asset_id != self.asset_id()? {
            return Err(CashTransitionError::Privacy(PrivacyError::PublicInputMismatch));
        }
        if height > valid_until {
            return Err(CashTransitionError::Privacy(PrivacyError::Expired));
        }
        Ok(())
    }

    fn move_fee_to_reserve(&mut self, fee: u128) -> Result<(), CashTransitionError> {
        self.supply = NativeSupply::new(
            self.supply.genesis_supply(),
            self.supply.cumulative_security_issuance(),
            self.supply.cumulative_burn(),
            self.supply.current_total_supply(),
            self.supply
                .circulating_supply()
                .checked_sub(fee)
                .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?,
            self.supply.locked_vesting_supply(),
            self.supply.staked_supply(),
            self.supply
                .security_reserve_balance()
                .checked_add(fee)
                .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?,
            self.supply.last_settled_epoch(),
            self.supply.issuance_window(),
            self.supply.issuance_window_opening_supply(),
            self.supply.issuance_in_window(),
        )
        .map_err(CashTransitionError::Invalid)?;
        Ok(())
    }

    /// Applies a deterministic epoch-security mint from the declared issuance authority.
    pub fn apply_mint(
        &mut self,
        mint: &CoinMintTransition,
        settlement: &EpochEconomicsTransition,
    ) -> Result<CoinCellId, CashTransitionError> {
        let mut next = self.clone();
        let output = next.apply_mint_inner(mint, settlement)?;
        *self = next;
        Ok(output)
    }

    fn apply_mint_inner(
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
        let effective_stake_bps = effective_stake_basis_points(
            self.supply.staked_supply(),
            self.supply.current_total_supply(),
        )
        .map_err(CashTransitionError::Invalid)?;
        if settlement.pre_supply() != self.supply.current_total_supply()
            || settlement.burned_amount() != 0
            || settlement.authorized_issuance() != mint.amount()
            || settlement.effective_stake_bps() != effective_stake_bps
            || settlement.target_security_budget()
                != epoch_security_budget(self.supply.current_total_supply(), effective_stake_bps)
                    .map_err(CashTransitionError::Invalid)?
        {
            return Err(CashTransitionError::Invalid(NativeMoneyError::IssuanceFormulaMismatch));
        }
        let next_window =
            issuance_window_index(mint.sequence()).map_err(CashTransitionError::Invalid)?;
        let (window_opening_supply, issued_before) = if self.supply.last_settled_epoch() == 0
            || next_window == self.supply.issuance_window()
        {
            (self.supply.issuance_window_opening_supply(), self.supply.issuance_in_window())
        } else {
            (self.supply.current_total_supply(), 0)
        };
        let annual_cap = basis_points_amount(
            window_opening_supply,
            self.definition.maximum_ordinary_annual_issuance_bps(),
        )
        .map_err(CashTransitionError::Invalid)?;
        let remaining_cap = annual_cap
            .checked_sub(issued_before)
            .ok_or(CashTransitionError::Invariant(NativeMoneyError::IssuanceCapExceeded))?;
        if settlement.issuance_cap() != remaining_cap || mint.amount() > remaining_cap {
            return Err(CashTransitionError::Invalid(NativeMoneyError::IssuanceCapExceeded));
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
        let issued_in_window = issued_before
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
            next_window,
            window_opening_supply,
            issued_in_window,
        )
        .map_err(CashTransitionError::Invalid)?;
        self.verify_invariants()?;
        Ok(CoinCellId::new(id.into_digest()))
    }

    /// Advances one economics epoch without creating a Coin Cell when fees and reserve cover the
    /// complete derived security budget. This also permits fail-closed legacy state to reach the
    /// next issuance window without reopening capacity in the current one.
    pub fn apply_zero_issuance_settlement(
        &mut self,
        settlement: &EpochEconomicsTransition,
    ) -> Result<(), CashTransitionError> {
        let mut next = self.clone();
        next.apply_zero_issuance_settlement_inner(settlement)?;
        *self = next;
        Ok(())
    }

    fn apply_zero_issuance_settlement_inner(
        &mut self,
        settlement: &EpochEconomicsTransition,
    ) -> Result<(), CashTransitionError> {
        let next_epoch = self
            .supply
            .last_settled_epoch()
            .checked_add(1)
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        if settlement.epoch() != next_epoch {
            return Err(CashTransitionError::Invalid(NativeMoneyError::MintSequenceMismatch));
        }
        let effective_stake_bps = effective_stake_basis_points(
            self.supply.staked_supply(),
            self.supply.current_total_supply(),
        )
        .map_err(CashTransitionError::Invalid)?;
        let target = epoch_security_budget(self.supply.current_total_supply(), effective_stake_bps)
            .map_err(CashTransitionError::Invalid)?;
        if settlement.pre_supply() != self.supply.current_total_supply()
            || settlement.post_supply() != self.supply.current_total_supply()
            || settlement.burned_amount() != 0
            || settlement.authorized_issuance() != 0
            || settlement.effective_stake_bps() != effective_stake_bps
            || settlement.target_security_budget() != target
        {
            return Err(CashTransitionError::Invalid(NativeMoneyError::IssuanceFormulaMismatch));
        }
        let next_window =
            issuance_window_index(settlement.epoch()).map_err(CashTransitionError::Invalid)?;
        let (window_opening_supply, issued_in_window) = if self.supply.last_settled_epoch() == 0
            || next_window == self.supply.issuance_window()
        {
            (self.supply.issuance_window_opening_supply(), self.supply.issuance_in_window())
        } else {
            (self.supply.current_total_supply(), 0)
        };
        let annual_cap = basis_points_amount(
            window_opening_supply,
            self.definition.maximum_ordinary_annual_issuance_bps(),
        )
        .map_err(CashTransitionError::Invalid)?;
        let remaining_cap = annual_cap
            .checked_sub(issued_in_window)
            .ok_or(CashTransitionError::Invariant(NativeMoneyError::IssuanceCapExceeded))?;
        if settlement.issuance_cap() != remaining_cap {
            return Err(CashTransitionError::Invalid(NativeMoneyError::IssuanceCapExceeded));
        }
        self.supply = NativeSupply::new(
            self.supply.genesis_supply(),
            self.supply.cumulative_security_issuance(),
            self.supply.cumulative_burn(),
            self.supply.current_total_supply(),
            self.supply.circulating_supply(),
            self.supply.locked_vesting_supply(),
            self.supply.staked_supply(),
            self.supply.security_reserve_balance(),
            settlement.epoch(),
            next_window,
            window_opening_supply,
            issued_in_window,
        )
        .map_err(CashTransitionError::Invalid)?;
        self.verify_invariants()
    }

    /// Applies a fixed public transfer, charging its explicit fee reserve.
    pub fn apply_transfer(
        &mut self,
        transfer: &CoinTransfer,
        height: Height,
    ) -> Result<(), CashTransitionError> {
        let mut next = self.clone();
        next.apply_transfer_inner(transfer, height)?;
        *self = next;
        Ok(())
    }

    fn apply_transfer_inner(
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
            self.supply.issuance_window(),
            self.supply.issuance_window_opening_supply(),
            self.supply.issuance_in_window(),
        )
        .map_err(CashTransitionError::Invalid)?;
        self.verify_invariants()
    }

    /// Applies a transfer whose value inputs belong to the sender while its
    /// distinct fee reserve belongs to an authorized paymaster. Ledger and
    /// paymaster state advance atomically.
    pub fn apply_sponsored_transfer(
        &mut self,
        policy: &mut CashPaymasterPolicyV1,
        request: &CashPaymasterRequestV1,
        transfer: &CoinTransfer,
        height: Height,
    ) -> Result<(), CashTransitionError> {
        if request.sender() != transfer.sender() || request.fee() != transfer.fee() {
            return Err(CashTransitionError::Economics(EconomicsError::PaymasterUnauthorized));
        }
        let transition_id = cash_transition_id(transfer).map_err(CashTransitionError::Encoding)?;
        if request.transfer() != *transition_id.digest() {
            return Err(CashTransitionError::Economics(EconomicsError::PaymasterUnauthorized));
        }
        let next_policy = policy
            .authorize(request, *transition_id.digest(), transfer.fee(), height)
            .map_err(CashTransitionError::Economics)?;
        let mut next = self.clone();
        next.apply_sponsored_transfer_inner(request.sponsor(), transfer, transition_id, height)?;
        *self = next;
        *policy = next_policy;
        Ok(())
    }

    fn apply_sponsored_transfer_inner(
        &mut self,
        sponsor: activechain_protocol_types::PrincipalId,
        transfer: &CoinTransfer,
        transition_id: TransactionId,
        height: Height,
    ) -> Result<(), CashTransitionError> {
        if height > transfer.valid_until() {
            return Err(CashTransitionError::Invalid(NativeMoneyError::Expired));
        }
        let mut input_total = 0_u128;
        let mut spent = Vec::new();
        for id in transfer.inputs() {
            let record = self
                .find(*id)
                .ok_or(CashTransitionError::Invalid(NativeMoneyError::MissingCell))?;
            if record.cell().owner() != transfer.sender() {
                return Err(CashTransitionError::Invalid(NativeMoneyError::WrongOwner));
            }
            input_total = input_total
                .checked_add(record.cell().amount())
                .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
            spent.push(record);
        }
        if input_total < transfer.amount() {
            return Err(CashTransitionError::Invalid(NativeMoneyError::InsufficientValue));
        }
        let reserve = self
            .find(transfer.fee_reserve())
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::MissingCell))?;
        if reserve.cell().owner() != sponsor {
            return Err(CashTransitionError::Invalid(NativeMoneyError::WrongOwner));
        }
        if reserve.cell().amount() < transfer.fee() {
            return Err(CashTransitionError::Invalid(NativeMoneyError::InsufficientValue));
        }
        spent.push(reserve);
        let mut cells = self
            .cells
            .as_slice()
            .iter()
            .copied()
            .filter(|record| !spent.iter().any(|spent| spent.id() == record.id()))
            .collect::<Vec<_>>();
        let recipient = CoinCell::new(
            CoinCellOrigin::new(transition_id, 0),
            transfer.recipient(),
            transfer.amount(),
            height,
        )
        .map_err(CashTransitionError::Invalid)?;
        cells.push(CoinCellRecord::new(
            coin_cell_id(&recipient.origin()).map_err(CashTransitionError::Encoding)?,
            recipient,
        ));
        let sender_change = input_total - transfer.amount();
        if sender_change > 0 {
            let change = CoinCell::new(
                CoinCellOrigin::new(transition_id, 1),
                transfer.sender(),
                sender_change,
                height,
            )
            .map_err(CashTransitionError::Invalid)?;
            cells.push(CoinCellRecord::new(
                coin_cell_id(&change.origin()).map_err(CashTransitionError::Encoding)?,
                change,
            ));
        }
        let sponsor_change = reserve.cell().amount() - transfer.fee();
        if sponsor_change > 0 {
            let change = CoinCell::new(
                CoinCellOrigin::new(transition_id, 2),
                sponsor,
                sponsor_change,
                height,
            )
            .map_err(CashTransitionError::Invalid)?;
            cells.push(CoinCellRecord::new(
                coin_cell_id(&change.origin()).map_err(CashTransitionError::Encoding)?,
                change,
            ));
        }
        cells.sort_by_key(|record| record.id());
        self.cells = CoinCellSet::new(cells).map_err(CashTransitionError::Invalid)?;
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
            self.supply.issuance_window(),
            self.supply.issuance_window_opening_supply(),
            self.supply.issuance_in_window(),
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
        // Apply to a candidate and swap only once every check has passed, as every other
        // transition does. Assigning `self.cells` before the supply arithmetic and the
        // invariant check would let a later failure leave cells destroyed with supply intact.
        let mut candidate = self.clone();
        candidate.cells = CoinCellSet::new(next).map_err(CashTransitionError::Invalid)?;
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
        candidate.supply = NativeSupply::new(
            self.supply.genesis_supply(),
            self.supply.cumulative_security_issuance(),
            burned,
            current,
            circulating,
            self.supply.locked_vesting_supply(),
            self.supply.staked_supply(),
            self.supply.security_reserve_balance(),
            self.supply.last_settled_epoch(),
            self.supply.issuance_window(),
            self.supply.issuance_window_opening_supply(),
            self.supply.issuance_in_window(),
        )
        .map_err(CashTransitionError::Invalid)?;
        candidate.verify_invariants()?;
        *self = candidate;
        Ok(())
    }

    pub fn verify_invariants(&self) -> Result<(), CashTransitionError> {
        if self.redeemed_reward_root == activechain_protocol_types::Digest384::ZERO {
            return Err(CashTransitionError::Invariant(
                NativeMoneyError::InvalidRewardReplayWitness,
            ));
        }
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
            .checked_add(self.shielded.pool_balance())
            .and_then(|v| v.checked_add(self.supply.security_reserve_balance()))
            .and_then(|v| v.checked_add(self.supply.locked_vesting_supply()))
            .and_then(|v| v.checked_add(self.supply.staked_supply()))
            .ok_or(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))?;
        let expected = self.supply.current_total_supply();
        if accounted != expected {
            return Err(CashTransitionError::Invariant(NativeMoneyError::SupplyPartitionMismatch));
        }
        let annual_cap = basis_points_amount(
            self.supply.issuance_window_opening_supply(),
            self.definition.maximum_ordinary_annual_issuance_bps(),
        )
        .map_err(CashTransitionError::Invalid)?;
        if self.supply.issuance_in_window() > annual_cap {
            return Err(CashTransitionError::Invariant(NativeMoneyError::IssuanceCapExceeded));
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

impl CanonicalEncode for CashLedger {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.definition.encode(e)?;
        self.supply.encode(e)?;
        self.cells.encode(e)?;
        self.shielded.encode(e)?;
        self.redeemed_reward_root.encode(e)?;
        self.redeemed_reward_count.encode(e)
    }
}

impl CanonicalDecode for CashLedger {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let definition = NativeAssetDefinition::decode(d)?;
        let supply = NativeSupply::decode(d)?;
        let cells = CoinCellSet::decode(d)?;
        let shielded = ShieldedCashState::decode(d)?;
        let redeemed_reward_root = activechain_protocol_types::Digest384::decode(d)?;
        let redeemed_reward_count = u64::decode(d)?;
        let ledger = Self {
            definition,
            supply,
            cells,
            shielded,
            redeemed_reward_root,
            redeemed_reward_count,
        };
        ledger.verify_invariants().map_err(|_| DecodeError::InvalidValue("invalid cash ledger"))?;
        Ok(ledger)
    }
}

impl CashLedger {
    fn encode_legacy_v1_fields(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.definition.encode(e)?;
        self.supply.genesis_supply().encode(e)?;
        self.supply.cumulative_security_issuance().encode(e)?;
        self.supply.cumulative_burn().encode(e)?;
        self.supply.current_total_supply().encode(e)?;
        self.supply.circulating_supply().encode(e)?;
        self.supply.locked_vesting_supply().encode(e)?;
        self.supply.staked_supply().encode(e)?;
        self.supply.security_reserve_balance().encode(e)?;
        self.supply.last_settled_epoch().encode(e)?;
        self.cells.encode(e)?;
        self.shielded.encode_legacy_v1(e)
    }

    /// Encodes the schema-v1 body for explicit bounded snapshot migration tooling.
    #[doc(hidden)]
    pub fn encode_legacy_v1(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.encode_legacy_v1_fields(e)?;
        if self.redeemed_reward_count != 0 {
            return Err(EncodeError::LengthLimitExceeded {
                length: usize::try_from(self.redeemed_reward_count).unwrap_or(usize::MAX),
                maximum: 0,
            });
        }
        e.write_length(0, LEGACY_MAX_REDEEMED_REWARDS)
    }

    #[cfg(test)]
    pub(crate) fn encode_legacy_v1_with_rewards_for_test(
        &self,
        e: &mut Encoder,
        assignments: &[activechain_protocol_types::Digest384],
    ) -> Result<(), EncodeError> {
        self.encode_legacy_v1_fields(e)?;
        e.write_length(assignments.len(), LEGACY_MAX_REDEEMED_REWARDS)?;
        for assignment in assignments {
            assignment.encode(e)?;
        }
        Ok(())
    }

    /// Decodes the bounded schema-v1 ledger used by transaction-ingress snapshot v2.
    pub fn decode_legacy_v1(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let definition = NativeAssetDefinition::decode(d)?;
        let supply =
            NativeSupply::decode_legacy_v1(d, definition.maximum_ordinary_annual_issuance_bps())?;
        let cells = CoinCellSet::decode(d)?;
        let shielded = ShieldedCashState::decode_legacy_v1(d)?;
        let commitment = decode_legacy_reward_commitment(d)?;
        let ledger = Self {
            definition,
            supply,
            cells,
            shielded,
            redeemed_reward_root: activechain_protocol_types::Digest384::new(commitment.root),
            redeemed_reward_count: commitment.count,
        };
        ledger
            .verify_invariants()
            .map_err(|_| DecodeError::InvalidValue("invalid legacy cash ledger"))?;
        Ok(ledger)
    }

    #[doc(hidden)]
    pub fn encode_legacy_v2(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        if self.redeemed_reward_count != 0 {
            return Err(EncodeError::LengthLimitExceeded {
                length: usize::try_from(self.redeemed_reward_count).unwrap_or(usize::MAX),
                maximum: 0,
            });
        }
        self.definition.encode(e)?;
        self.supply.encode(e)?;
        self.cells.encode(e)?;
        self.shielded.encode_legacy_v1(e)?;
        e.write_length(0, LEGACY_MAX_REDEEMED_REWARDS)
    }

    pub fn decode_legacy_v2(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let definition = NativeAssetDefinition::decode(d)?;
        let supply = NativeSupply::decode(d)?;
        let cells = CoinCellSet::decode(d)?;
        let shielded = ShieldedCashState::decode_legacy_v1(d)?;
        let commitment = decode_legacy_reward_commitment(d)?;
        let ledger = Self {
            definition,
            supply,
            cells,
            shielded,
            redeemed_reward_root: activechain_protocol_types::Digest384::new(commitment.root),
            redeemed_reward_count: commitment.count,
        };
        ledger
            .verify_invariants()
            .map_err(|_| DecodeError::InvalidValue("invalid legacy cash ledger"))?;
        Ok(ledger)
    }
}

fn decode_legacy_reward_commitment(d: &mut Decoder<'_>) -> Result<SetCommitment, DecodeError> {
    let count = d.read_length(LEGACY_MAX_REDEEMED_REWARDS)?;
    let mut reference = ReferenceSet::new(AccumulatorDomain::SpentInput);
    let mut previous = None;
    for _ in 0..count {
        let assignment = activechain_protocol_types::Digest384::decode(d)?;
        if previous.is_some_and(|prior| prior >= assignment) {
            return Err(DecodeError::InvalidValue(
                "legacy reward replay set is not strictly ordered",
            ));
        }
        reference
            .insert(assignment.into_bytes())
            .map_err(|_| DecodeError::InvalidValue("invalid legacy reward replay set"))?;
        previous = Some(assignment);
    }
    Ok(reference.commitment())
}

impl CanonicalType for CashLedger {
    const TYPE_TAG: u16 = 0x0102;
    const SCHEMA_VERSION: u16 = 3;
    const MAX_ENCODED_LEN: usize = NativeAssetDefinition::MAX_ENCODED_LEN
        + NativeSupply::MAX_ENCODED_LEN
        + CoinCellSet::MAX_ENCODED_LEN
        + ShieldedCashState::MAX_ENCODED_LEN
        + 48
        + 8;
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
    Privacy(PrivacyError),
    Economics(EconomicsError),
}

fn verify_privacy_proof<T: activechain_canonical_codec::CanonicalType>(
    intent: &T,
    proof: VerifiedPrivacyProof,
) -> Result<activechain_protocol_types::Digest384, CashTransitionError> {
    if !proof.verified {
        return Err(CashTransitionError::Privacy(PrivacyError::ProofNotVerified));
    }
    let expected =
        commit(DomainTag::PRIVACY_PUBLIC_INPUTS, intent).map_err(CashTransitionError::Encoding)?;
    if expected != proof.public_inputs_commitment {
        return Err(CashTransitionError::Privacy(PrivacyError::PublicInputMismatch));
    }
    Ok(expected)
}
