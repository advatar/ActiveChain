#![no_std]
#![forbid(unsafe_code)]

//! Canonical native-money values and pure Coin Cell transitions.
//!
//! The cash kernel is deliberately independent of ObjectVM. It accepts only
//! fixed-semantics native-money transitions and publishes total deterministic
//! failures before mutating ledger state.

extern crate alloc;

mod air;
mod authenticated;
mod economics;
mod partitioned;
mod transition;
mod types;

pub use air::{
    AuthenticatedCashAirProofV1, CashAirError, CashAirProof, CashAirPublicInputs, CashAirRow,
    prove_authenticated_cash_air, prove_cash_air, verify_authenticated_cash_air, verify_cash_air,
};
pub use authenticated::{
    AUTHENTICATED_CASH_DEPTH, AuthenticatedCoinCellRoot, CoinCellMutationError,
    CoinCellMutationWitness, CoinCellTransitionWitness, MAX_AUTHENTICATED_CASH_MUTATIONS,
    authenticated_coin_cell_count_root_hash, authenticated_coin_cell_leaf_hash,
    authenticated_coin_cell_leaf_transcript, authenticated_coin_cell_node_hash,
    authenticated_coin_cell_node_transcript, authenticated_coin_cell_root,
    authenticated_coin_cell_root_transcript, authenticated_empty_coin_cell_leaf_hash,
    authenticated_empty_coin_cell_leaf_transcript, prove_coin_cell_mutation,
    prove_coin_cell_transition, verify_coin_cell_mutation, verify_coin_cell_transition,
};
pub use economics::{
    ChallengeAssignment, DutyAssignment, DutyReceipt, EconomicsError, FeeMarket, FeeQuote,
    ObjectiveFault, RewardRedemption, RewardSettlement, SecurityPoolAllocation, SlashSplit,
    VerifierRole, assign_challenge, register_assignment, resolve_challenge, settle_duty,
};
pub use partitioned::{MAX_CASH_PARTITIONS, PartitionedCashPlan, PartitionedCashReceipt};
pub use transition::{CashLedger, CashTransitionError, MAX_REDEEMED_REWARDS};
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
        NativeAssetDefinition, NativeMoneyError, NativeSupply, PartitionedCashPlan,
        RewardRedemption, RewardSettlement,
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

    fn partitioned_fixture() -> (CashLedger, CashTransferV1) {
        let mut ledger = CashLedger::from_genesis(&economy()).unwrap();
        ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(10), 50, 1, 1).unwrap(),
                &settlement(1_000, 50, 1),
            )
            .unwrap();
        ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(12), 50, 2, 2).unwrap(),
                &settlement(1_050, 50, 2),
            )
            .unwrap();
        let mut transfers = [principal(10), principal(12)]
            .into_iter()
            .map(|owner| {
                let ids = ledger
                    .cells()
                    .as_slice()
                    .iter()
                    .filter(|record| record.cell().owner() == owner)
                    .map(|record| record.id())
                    .collect::<alloc::vec::Vec<_>>();
                CoinTransfer::new(owner, principal(30), vec![ids[0]], ids[1], 25, 1, 20).unwrap()
            })
            .collect::<alloc::vec::Vec<_>>();
        transfers.sort_by_key(|transfer| transfer.inputs()[0]);
        (ledger, CashTransferV1::new(transfers).unwrap())
    }

    #[test]
    fn partitioned_execution_matches_serial_for_disjoint_transfers() {
        let (ledger, batch) = partitioned_fixture();
        let mut serial = ledger.clone();
        for transfer in batch.transfers() {
            serial.apply_transfer(transfer, 3).unwrap();
        }
        let mut partitioned = ledger.clone();
        let receipt = partitioned.apply_partitioned_batch(&batch, 3, 16).unwrap();
        assert_eq!(receipt.applied(), 2);
        assert_eq!(receipt.rejected(), 0);
        assert_eq!(receipt.plan().parallel(), &[0, 1]);
        assert!(receipt.plan().fallback().is_empty());
        assert_eq!(partitioned, serial);
        assert!(receipt.plan().locks().windows(2).all(|pair| pair[0] < pair[1]));
        assert!(receipt.plan().partition_for(receipt.plan().locks()[0]) < 16);
        let batch_bytes = encode_envelope(&batch).unwrap();
        assert_eq!(decode_envelope::<CashTransferV1>(&batch_bytes), Ok(batch.clone()));
        let receipt_bytes = encode_envelope(&receipt).unwrap();
        assert_eq!(decode_envelope::<super::PartitionedCashReceipt>(&receipt_bytes), Ok(receipt));
        for partitions in 1..=super::MAX_CASH_PARTITIONS {
            let mut candidate = ledger.clone();
            candidate.apply_partitioned_batch(&batch, 3, partitions).unwrap();
            assert_eq!(candidate, serial);
        }
    }

    #[test]
    fn conflicting_inputs_have_one_ordered_winner_and_release_all_runtime_locks() {
        let (mut ledger, _) = partitioned_fixture();
        let owner = principal(10);
        let ids = ledger
            .cells()
            .as_slice()
            .iter()
            .filter(|record| record.cell().owner() == owner)
            .map(|record| record.id())
            .collect::<alloc::vec::Vec<_>>();
        let mut transfers = vec![
            CoinTransfer::new(owner, principal(31), vec![ids[0]], ids[1], 25, 1, 20).unwrap(),
            CoinTransfer::new(owner, principal(32), vec![ids[1]], ids[0], 25, 1, 20).unwrap(),
        ];
        transfers.sort_by_key(|transfer| transfer.inputs()[0]);
        let batch = CashTransferV1::new(transfers).unwrap();
        let plan = PartitionedCashPlan::build(&batch, 8).unwrap();
        assert_eq!(plan.parallel(), &[0]);
        assert_eq!(plan.fallback(), &[1]);
        let pre = ledger.clone();
        let receipt = ledger.apply_partitioned_batch(&batch, 3, 8).unwrap();
        assert_eq!((receipt.applied(), receipt.rejected()), (1, 1));
        // A fresh plan can acquire the same identifiers: locks are not persistent ledger state.
        assert_eq!(PartitionedCashPlan::build(&batch, 8).unwrap(), plan);
        let encoded = encode_envelope(&ledger).unwrap();
        assert_eq!(decode_envelope::<CashLedger>(&encoded), Ok(ledger));
        let (air, _) = super::prove_cash_air(&pre, &batch, 3, 8).unwrap();
        assert!(air.rows()[0].accepted());
        assert!(!air.rows()[1].accepted());
        assert_eq!(
            (air.rows()[1].input_value(), air.rows()[1].output_value(), air.rows()[1].fee()),
            (0, 0, 0)
        );
    }

    #[test]
    fn invalid_partition_count_and_all_failed_work_are_atomic() {
        let (mut ledger, batch) = partitioned_fixture();
        let snapshot = ledger.clone();
        assert!(PartitionedCashPlan::build(&batch, 0).is_err());
        let receipt = ledger.apply_partitioned_batch(&batch, 99, 4).unwrap();
        assert_eq!((receipt.applied(), receipt.rejected()), (0, 2));
        assert_eq!(ledger, snapshot);
    }

    #[test]
    fn transparent_cash_air_matches_direct_reexecution_and_binds_context() {
        let (ledger, batch) = partitioned_fixture();
        let (proof, expected_post) = super::prove_cash_air(&ledger, &batch, 3, 16).unwrap();
        for row in proof.rows() {
            assert_eq!(row.input_value(), row.output_value() + row.fee());
        }
        assert_eq!(
            super::verify_cash_air(&ledger, &batch, &proof, 3, 16),
            Ok(expected_post.clone())
        );
        assert_eq!(
            super::verify_cash_air(&ledger, &batch, &proof, 4, 16),
            Err(super::CashAirError::InvalidProof)
        );
        assert_eq!(
            super::verify_cash_air(&ledger, &batch, &proof, 3, 8),
            Err(super::CashAirError::InvalidProof)
        );
        assert!(super::verify_cash_air(&expected_post, &batch, &proof, 3, 16).is_err());
        let bytes = encode_envelope(&proof).unwrap();
        assert_eq!(decode_envelope::<super::CashAirProof>(&bytes), Ok(proof.clone()));
        assert_eq!(proof.commitment().unwrap(), proof.commitment().unwrap());
        assert_eq!(
            proof.commitment().unwrap().as_bytes(),
            &[
                14, 105, 213, 198, 196, 18, 68, 61, 208, 82, 78, 154, 147, 13, 131, 187, 223, 248,
                125, 87, 82, 105, 104, 139, 213, 39, 210, 60, 183, 75, 142, 131, 226, 171, 154, 12,
                18, 144, 5, 83, 185, 114, 129, 4, 150, 25, 62, 42,
            ]
        );
        assert!(include_str!("../../../testing/vectors/cash/cash-air-v1.txt")
            .contains("proof_commitment_hex=0e69d5c6c412443dd0524e9a930d83bbdff87d575269688bd527d23cb74b8e83e2ab9a0c12900553b972810496193e2a"));
    }

    #[test]
    fn authenticated_cash_air_chains_exact_membership_and_consumption_updates() {
        let (ledger, batch) = partitioned_fixture();
        let (proof, expected_post) =
            super::prove_authenticated_cash_air(&ledger, &batch, 3, 16).unwrap();
        assert_eq!(
            super::verify_authenticated_cash_air(&ledger, &batch, &proof, 3, 16),
            Ok(expected_post.clone())
        );
        assert_eq!(proof.pre_root(), super::authenticated_coin_cell_root(ledger.cells()).unwrap());
        assert_eq!(
            proof.post_root(),
            super::authenticated_coin_cell_root(expected_post.cells()).unwrap()
        );
        for (row, mutation) in proof.execution().rows().iter().zip(proof.mutations()) {
            assert_eq!(mutation.is_some(), row.accepted());
        }
        let encoded = encode_envelope(&proof).unwrap();
        assert_eq!(
            decode_envelope::<super::AuthenticatedCashAirProofV1>(&encoded),
            Ok(proof.clone())
        );
        assert_eq!(
            super::verify_authenticated_cash_air(&ledger, &batch, &proof, 3, 8),
            Err(super::CashAirError::InvalidProof)
        );
        assert!(
            super::verify_authenticated_cash_air(&expected_post, &batch, &proof, 3, 16).is_err()
        );
    }

    #[test]
    fn every_decodable_single_byte_cash_air_substitution_fails_reexecution() {
        let (ledger, batch) = partitioned_fixture();
        let (proof, _) = super::prove_cash_air(&ledger, &batch, 3, 16).unwrap();
        let encoded = encode_envelope(&proof).unwrap();
        for index in 8..encoded.len() {
            let mut tampered = encoded.clone();
            tampered[index] ^= 1;
            if let Ok(candidate) = decode_envelope::<super::CashAirProof>(&tampered) {
                assert_eq!(
                    super::verify_cash_air(&ledger, &batch, &candidate, 3, 16),
                    Err(super::CashAirError::InvalidProof),
                    "substitution at byte {index} was accepted"
                );
            }
        }
        assert!(decode_envelope::<super::CashAirProof>(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn cash_air_rejects_values_outside_its_non_wrapping_field_range() {
        let large = u128::from(u64::MAX) + 1;
        let definition = NativeAssetDefinition::new(
            ChainId::new(digest(1)),
            b"ACT".to_vec(),
            18,
            large + 1,
            150,
            digest(2),
            digest(3),
            digest(4),
        )
        .unwrap();
        let economy = GenesisEconomy::new(
            definition,
            vec![
                GenesisAllocation::new(principal(10), large, 0).unwrap(),
                GenesisAllocation::new(principal(12), 1, 0).unwrap(),
            ],
            0,
        )
        .unwrap();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        let minted = ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(10), 1, 1, 1).unwrap(),
                &settlement(large + 1, 1, 1),
            )
            .unwrap();
        let genesis = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(10) && record.id() != minted)
            .unwrap()
            .id();
        let batch = CashTransferV1::new(vec![
            CoinTransfer::new(principal(10), principal(20), vec![genesis], minted, 1, 0, 20)
                .unwrap(),
        ])
        .unwrap();
        assert_eq!(
            super::prove_cash_air(&ledger, &batch, 2, 8),
            Err(super::CashAirError::UnsupportedRange)
        );
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
    fn reward_and_shield_sources_are_one_shot_and_atomic_across_paths() {
        let economy = economy();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        let fee_reserve = ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(10), 50, 1, 1).unwrap(),
                &settlement(1_000, 50, 1),
            )
            .unwrap();
        let pool_cell = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(10) && record.id() != fee_reserve)
            .unwrap()
            .id();
        let reward = RewardSettlement {
            assignment: digest(90),
            verifier: principal(12),
            reward: 100,
            bond_return: 0,
            slash_amount: 0,
        };
        let redemption = RewardRedemption {
            settlement: reward.assignment,
            pool_owner: principal(10),
            pool_cell,
            fee_reserve,
            height: 2,
        };
        let supply_before = ledger.supply().current_total_supply();
        ledger.redeem_reward(&reward, &redemption).unwrap();
        assert_eq!(ledger.supply().current_total_supply(), supply_before);
        assert_eq!(ledger.redeemed_rewards(), &[reward.assignment]);

        let paid = ledger.clone();
        assert_eq!(
            ledger.redeem_reward(&reward, &redemption),
            Err(CashTransitionError::Invalid(NativeMoneyError::RewardAlreadyRedeemed))
        );
        assert_eq!(ledger, paid);

        let mut restarted: CashLedger =
            decode_envelope(&encode_envelope(&ledger).unwrap()).unwrap();
        assert_eq!(restarted.redeemed_rewards(), &[reward.assignment]);
        assert_eq!(
            restarted.redeem_reward(&reward, &redemption),
            Err(CashTransitionError::Invalid(NativeMoneyError::RewardAlreadyRedeemed))
        );
        assert_eq!(restarted, ledger);

        let spent_shield = ShieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            principal(10),
            vec![pool_cell],
            fee_reserve,
            100,
            0,
            vec![digest(91)],
            20,
        )
        .unwrap();
        let spent_proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &spent_shield)
                .unwrap(),
            verified: true,
        };
        assert_eq!(
            ledger.apply_shield(&spent_shield, spent_proof, 3),
            Err(CashTransitionError::Invalid(NativeMoneyError::MissingCell))
        );
        assert_eq!(ledger, paid);

        let mut shield_first = CashLedger::from_genesis(&economy).unwrap();
        let shield_fee = shield_first
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(10), 50, 1, 1).unwrap(),
                &settlement(1_000, 50, 1),
            )
            .unwrap();
        let shield_input = shield_first
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(10) && record.id() != shield_fee)
            .unwrap()
            .id();
        let shield = ShieldIntent::new(
            economy.definition().chain_id(),
            shield_first.asset_id().unwrap(),
            principal(10),
            vec![shield_input],
            shield_fee,
            400,
            0,
            vec![digest(92)],
            20,
        )
        .unwrap();
        let shield_proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &shield).unwrap(),
            verified: true,
        };
        shield_first.apply_shield(&shield, shield_proof, 2).unwrap();
        let shielded = shield_first.clone();
        let unavailable = RewardRedemption {
            settlement: reward.assignment,
            pool_owner: principal(10),
            pool_cell: shield_input,
            fee_reserve: shield_fee,
            height: 3,
        };
        assert_eq!(
            shield_first.redeem_reward(&reward, &unavailable),
            Err(CashTransitionError::Invalid(NativeMoneyError::MissingCell))
        );
        assert!(shield_first.redeemed_rewards().is_empty());
        assert_eq!(shield_first, shielded);
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

        #[test]
        fn every_reward_amount_moves_value_once_without_changing_total_supply(
            reward_amount in 1_u128..=500,
        ) {
            let economy = economy();
            let mut ledger = CashLedger::from_genesis(&economy).unwrap();
            let fee_reserve = ledger
                .apply_mint(
                    &CoinMintTransition::new(digest(2), principal(10), 50, 1, 1).unwrap(),
                    &settlement(1_000, 50, 1),
                )
                .unwrap();
            let pool_cell = ledger
                .cells()
                .as_slice()
                .iter()
                .find(|record| record.cell().owner() == principal(10) && record.id() != fee_reserve)
                .unwrap()
                .id();
            let reward = RewardSettlement {
                assignment: digest(93),
                verifier: principal(12),
                reward: reward_amount,
                bond_return: 0,
                slash_amount: 0,
            };
            let redemption = RewardRedemption {
                settlement: reward.assignment,
                pool_owner: principal(10),
                pool_cell,
                fee_reserve,
                height: 2,
            };
            let supply = ledger.supply().current_total_supply();
            ledger.redeem_reward(&reward, &redemption).unwrap();
            prop_assert_eq!(ledger.supply().current_total_supply(), supply);
            let paid = ledger.clone();
            prop_assert_eq!(
                ledger.redeem_reward(&reward, &redemption),
                Err(CashTransitionError::Invalid(NativeMoneyError::RewardAlreadyRedeemed))
            );
            prop_assert_eq!(ledger, paid);
        }
    }
}
