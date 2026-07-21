#![no_std]
#![forbid(unsafe_code)]

//! Canonical native-money values and pure Coin Cell transitions.
//!
//! The cash kernel is deliberately independent of ObjectVM. It accepts only
//! fixed-semantics native-money transitions and publishes total deterministic
//! failures before mutating ledger state.

extern crate alloc;

mod economics;
mod transition;
mod types;

pub use economics::{
    ChallengeAssignment, DutyAssignment, DutyReceipt, EconomicsError, FeeMarket, FeeQuote,
    ObjectiveFault, RewardRedemption, RewardSettlement, SecurityPoolAllocation, SlashSplit,
    VerifierRole, assign_challenge, register_assignment, resolve_challenge, settle_duty,
};
pub use transition::{CashLedger, CashTransitionError};
pub use types::{
    CashTransferV1, CoinBurnTransition, CoinCell, CoinCellOrigin, CoinCellRecord, CoinCellSet,
    CoinMintTransition, CoinTransfer, EpochEconomicsTransition, GenesisAllocation, GenesisEconomy,
    MAX_COIN_CELLS, MAX_TRANSFER_INPUTS, NativeAssetDefinition, NativeMoneyError, NativeSupply,
};

#[cfg(test)]
mod tests {
    extern crate alloc;

    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use activechain_privacy_kernel::{ShieldIntent, UnshieldIntent, VerifiedPrivacyProof};
    use activechain_protocol_commitment::{DomainTag, commit};
    use activechain_protocol_types::{ChainId, CoinCellId, Digest384, PrincipalId};
    use alloc::vec;
    use proptest::prelude::*;

    use super::{
        CashLedger, CashTransferV1, CashTransitionError, CoinBurnTransition, CoinMintTransition,
        CoinTransfer, EpochEconomicsTransition, GenesisAllocation, GenesisEconomy,
        NativeAssetDefinition, NativeMoneyError, NativeSupply,
    };

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }
    fn economy() -> GenesisEconomy {
        let definition = NativeAssetDefinition::new(
            ChainId::new(digest(1)),
            b"ACT".to_vec(),
            18,
            1_000,
            150,
            digest(2),
            digest(3),
            digest(4),
        )
        .unwrap();
        GenesisEconomy::new(
            definition,
            vec![
                GenesisAllocation::new(principal(10), 700, 100).unwrap(),
                GenesisAllocation::new(principal(12), 100, 0).unwrap(),
            ],
            100,
        )
        .unwrap()
    }

    fn settlement(pre_supply: u128, issuance: u128, epoch: u64) -> EpochEconomicsTransition {
        EpochEconomicsTransition::new(
            epoch,
            pre_supply,
            5_000,
            0,
            0,
            issuance,
            issuance,
            issuance * 2,
            0,
            digest(20),
            digest(21),
            digest(22),
            digest(23),
            pre_supply + issuance,
        )
        .unwrap()
    }

    #[test]
    fn cash_transfer_batch_is_ordered_and_fixed_costed() {
        let first = CoinTransfer::new(
            principal(10),
            principal(12),
            vec![CoinCellId::new(digest(1))],
            CoinCellId::new(digest(2)),
            10,
            1,
            20,
        )
        .unwrap();
        let second = CoinTransfer::new(
            principal(10),
            principal(12),
            vec![CoinCellId::new(digest(3))],
            CoinCellId::new(digest(4)),
            11,
            1,
            20,
        )
        .unwrap();
        let batch = CashTransferV1::new(vec![first, second]).unwrap();
        assert_eq!(batch.resource_units(), 72);
        assert!(CashTransferV1::new(batch.transfers().iter().cloned().rev().collect()).is_err());
    }

    #[test]
    fn native_definition_round_trips_and_rejects_discretionary_shape() {
        let definition = NativeAssetDefinition::new(
            ChainId::new(digest(1)),
            b"ACT".to_vec(),
            18,
            1_000,
            150,
            digest(2),
            digest(3),
            digest(4),
        )
        .unwrap();
        let bytes = encode_envelope(&definition).unwrap();
        assert_eq!(decode_envelope::<NativeAssetDefinition>(&bytes), Ok(definition));
        assert_eq!(
            NativeAssetDefinition::new(
                ChainId::new(digest(1)),
                b"act".to_vec(),
                18,
                1_000,
                150,
                digest(2),
                digest(3),
                digest(4)
            ),
            Err(NativeMoneyError::InvalidSymbol)
        );
    }

    #[test]
    fn genesis_supply_is_reproducible_and_partitioned() {
        let economy = economy();
        let ledger = CashLedger::from_genesis(&economy).unwrap();
        assert_eq!(ledger.supply().current_total_supply(), 1_000);
        assert_eq!(ledger.supply().locked_vesting_supply(), 100);
        assert_eq!(ledger.supply().security_reserve_balance(), 100);
        assert_eq!(ledger.cells().as_slice().len(), 2);
        assert_eq!(ledger.cell_set_root().unwrap(), ledger.cell_set_root().unwrap());
        assert_eq!(
            CashLedger::genesis_root(&economy).unwrap(),
            CashLedger::genesis_root(&economy).unwrap()
        );
    }

    #[test]
    fn mint_requires_policy_hash_and_epoch_sequence() {
        let economy = economy();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        let recipient = principal(20);
        let mint = CoinMintTransition::new(digest(2), recipient, 50, 1, 9).unwrap();
        assert!(ledger.apply_mint(&mint, &settlement(1_000, 50, 1)).is_ok());
        assert_eq!(ledger.supply().cumulative_security_issuance(), 50);
        assert_eq!(
            ledger.apply_mint(&mint, &settlement(1_050, 50, 1)),
            Err(CashTransitionError::Invalid(NativeMoneyError::MintSequenceMismatch))
        );
        let wrong = CoinMintTransition::new(digest(99), recipient, 1, 2, 10).unwrap();
        assert_eq!(
            ledger.apply_mint(&wrong, &settlement(1_050, 1, 2)),
            Err(CashTransitionError::Invalid(NativeMoneyError::MintAuthorityMismatch))
        );
    }

    #[test]
    fn transfer_charges_owned_fee_reserve_and_rejects_replay() {
        let economy = economy();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        let minted = ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(10), 50, 1, 1).unwrap(),
                &settlement(1_000, 50, 1),
            )
            .unwrap();
        let first = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(10) && record.id() != minted)
            .unwrap()
            .id();
        let second = minted;
        let transfer =
            CoinTransfer::new(principal(10), principal(20), vec![first], second, 500, 7, 10)
                .unwrap();
        ledger.apply_transfer(&transfer, 1).unwrap();
        assert_eq!(ledger.supply().security_reserve_balance(), 107);
        assert_eq!(
            ledger.apply_transfer(&transfer, 1),
            Err(CashTransitionError::Invalid(NativeMoneyError::MissingCell))
        );
    }

    #[test]
    fn burn_reduces_supply_without_recreating_value() {
        let economy = economy();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        let input = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(10))
            .unwrap()
            .id();
        let burn = CoinBurnTransition::new(principal(10), vec![input], 100, 10).unwrap();
        ledger.apply_burn(&burn, 1).unwrap();
        assert_eq!(ledger.supply().current_total_supply(), 900);
        assert_eq!(ledger.supply().cumulative_burn(), 100);
        ledger.verify_invariants().unwrap();
    }

    #[test]
    fn shield_and_unshield_are_supply_conserving_atomic_and_replay_safe() {
        let economy = economy();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        let minted = ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(10), 50, 1, 1).unwrap(),
                &settlement(1_000, 50, 1),
            )
            .unwrap();
        let input = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(10) && record.id() != minted)
            .unwrap()
            .id();
        let shield = ShieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            principal(10),
            vec![input],
            minted,
            400,
            7,
            vec![digest(60)],
            20,
        )
        .unwrap();
        let shield_proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &shield).unwrap(),
            verified: true,
        };
        ledger.apply_shield(&shield, shield_proof, 2).unwrap();
        assert_eq!(ledger.shielded_state().pool_balance(), 400);
        assert_eq!(ledger.supply().current_total_supply(), 1_050);
        assert_eq!(ledger.supply().security_reserve_balance(), 107);

        let unshield = UnshieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            ledger.shielded_state().anchor(),
            principal(12),
            100,
            3,
            vec![digest(70)],
            vec![digest(80)],
            30,
        )
        .unwrap();
        let unshield_proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &unshield).unwrap(),
            verified: true,
        };
        let output = ledger.apply_unshield(&unshield, unshield_proof, 3).unwrap();
        assert_eq!(ledger.shielded_state().pool_balance(), 297);
        assert_eq!(ledger.supply().security_reserve_balance(), 110);
        assert_eq!(ledger.supply().current_total_supply(), 1_050);
        assert_eq!(
            ledger
                .cells()
                .as_slice()
                .iter()
                .find(|record| record.id() == output)
                .unwrap()
                .cell()
                .amount(),
            100
        );

        let snapshot = ledger.clone();
        assert_eq!(
            ledger.apply_unshield(&unshield, unshield_proof, 3),
            Err(CashTransitionError::Privacy(
                activechain_privacy_kernel::PrivacyError::WrongAnchor
            ))
        );
        assert_eq!(ledger, snapshot);

        let rebound_replay = UnshieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            ledger.shielded_state().anchor(),
            principal(12),
            100,
            3,
            vec![digest(70)],
            vec![digest(81)],
            30,
        )
        .unwrap();
        let rebound_proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &rebound_replay)
                .unwrap(),
            verified: true,
        };
        assert_eq!(
            ledger.apply_unshield(&rebound_replay, rebound_proof, 4),
            Err(CashTransitionError::Privacy(
                activechain_privacy_kernel::PrivacyError::NullifierAlreadySpent
            ))
        );
        assert_eq!(ledger, snapshot);
    }

    #[test]
    fn rejected_shield_proof_consumes_no_public_cells() {
        let economy = economy();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        let owned = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(10))
            .unwrap()
            .id();
        let intent = ShieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            principal(10),
            vec![owned],
            CoinCellId::new(digest(99)),
            1,
            0,
            vec![digest(60)],
            20,
        )
        .unwrap();
        let before = ledger.clone();
        let proof = VerifiedPrivacyProof { public_inputs_commitment: digest(98), verified: false };
        assert_eq!(
            ledger.apply_shield(&intent, proof, 2),
            Err(CashTransitionError::Privacy(
                activechain_privacy_kernel::PrivacyError::ProofNotVerified
            ))
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn malformed_inputs_are_rejected_before_mutation() {
        let id = CoinCellId::new(digest(1));
        assert_eq!(
            CoinTransfer::new(principal(1), principal(2), vec![id, id], id, 1, 0, 1),
            Err(NativeMoneyError::InputsNotOrdered)
        );
        assert_eq!(
            CoinBurnTransition::new(principal(1), vec![], 1, 1),
            Err(NativeMoneyError::InvalidInputs)
        );
    }

    #[test]
    fn frozen_native_money_vector_matches_supply_and_issuance_rules() {
        let vector = include_str!("../../../testing/vectors/cash/native-money-v1.txt");
        let value = |name: &str| -> u128 {
            vector
                .lines()
                .find_map(|line| {
                    line.split_once('=').and_then(|(key, value)| (key == name).then_some(value))
                })
                .unwrap()
                .parse()
                .unwrap()
        };
        assert_eq!(
            value("genesis_supply"),
            value("circulating_supply")
                + value("locked_vesting_supply")
                + value("security_reserve_balance")
        );
        assert_eq!(
            value("authorized_issuance"),
            value("target_security_budget") - value("security_fee_revenue") - value("reserve_draw")
        );
        assert_eq!(
            value("post_supply_after_epoch"),
            value("genesis_supply") + value("authorized_issuance")
        );
        assert_eq!(
            value("post_supply_after_burn"),
            value("post_supply_after_epoch") - value("burned_amount")
        );
    }

    proptest::proptest! {
        #[test]
        fn supply_equation_is_checked_for_bounded_values(
            genesis in 1_u128..1_000_000,
            issuance in 0_u128..1_000_000,
            burned in 0_u128..1_000_000,
        ) {
            let total = genesis.checked_add(issuance).and_then(|value| value.checked_sub(burned));
            if let Some(total) = total {
                let supply = NativeSupply::new(total + burned - issuance, issuance, burned, total, total, 0, 0, 0, 0);
                prop_assert!(supply.is_ok());
            }
        }
    }
}
