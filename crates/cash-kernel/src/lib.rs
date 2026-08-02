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
    AUTHENTICATED_CASH_DEPTH, AuthenticatedCoinCellPartitionRoots, AuthenticatedCoinCellRoot,
    CoinCellMembershipProof, CoinCellMutationError, CoinCellMutationWitness,
    CoinCellPartitionMutationWitness, CoinCellPartitionTransitionWitness,
    CoinCellTransitionWitness, MAX_AUTHENTICATED_CASH_MUTATIONS,
    authenticated_coin_cell_count_root_hash, authenticated_coin_cell_leaf_hash,
    authenticated_coin_cell_leaf_transcript, authenticated_coin_cell_node_hash,
    authenticated_coin_cell_node_transcript, authenticated_coin_cell_partition_roots,
    authenticated_coin_cell_partition_roots_hash,
    authenticated_coin_cell_partition_roots_transcript, authenticated_coin_cell_root,
    authenticated_coin_cell_root_transcript, authenticated_empty_coin_cell_leaf_hash,
    authenticated_empty_coin_cell_leaf_transcript, prove_coin_cell_membership,
    prove_coin_cell_mutation, prove_coin_cell_partition_transition, prove_coin_cell_transition,
    verify_coin_cell_membership, verify_coin_cell_mutation, verify_coin_cell_partition_transition,
    verify_coin_cell_transition,
};
pub use economics::{
    CapacityReservationV1, CapacitySettlementV1, CashPaymasterPolicyV1, CashPaymasterRequestV1,
    ChallengeAssignment, ChallengeCommitmentV1, DutyAssignment, DutyReceipt, EconomicsError,
    FeeMarket, FeeQuote, ObjectiveFault, RewardRedemption, RewardReplayWitness, RewardSettlement,
    SecurityPoolAllocation, SlashSplit, VerifierRole, assign_challenge, challenge_commitment,
    register_assignment, resolve_challenge, select_auditor, settle_duty,
};
pub use partitioned::{
    MAX_CASH_PARTITIONS, PartitionedCashPlan, PartitionedCashReceipt, cash_partition_for,
};
pub use transition::{CashLedger, CashTransitionError, LEGACY_MAX_REDEEMED_REWARDS};
pub use types::{
    CashTransferV1, CoinBurnTransition, CoinCell, CoinCellOrigin, CoinCellRecord, CoinCellSet,
    CoinMintTransition, CoinTransfer, EpochEconomicsTransition, FungibleBurnV1, FungibleCoinCell,
    FungibleCoinCellMembershipProof, FungibleCoinCellRecord, FungibleCoinCellSet, FungibleMintV1,
    FungibleRedemptionV1, FungibleSettlementReceiptV1, FungibleTransferV1, GenesisAllocation,
    GenesisEconomy, ISSUANCE_EPOCHS_PER_YEAR, MAX_COIN_CELLS, MAX_TRANSFER_INPUTS,
    NativeAssetDefinition, NativeMoneyError, NativeSupply, NonFungibleCoinCell,
    NonFungibleCoinCellRecord, annual_security_budget_bps, basis_points_amount,
    effective_stake_basis_points, epoch_security_budget, issuance_window_index,
};

#[cfg(kani)]
mod nft_kani_proofs {
    use super::*;
    use activechain_protocol_types::{AssetId, Digest384, PrincipalId, TransactionId};

    #[kani::proof]
    fn nft_transfer_preserves_identity_and_rejects_non_owner() {
        let owner = PrincipalId::new(Digest384::new([4; 48]));
        let destination = PrincipalId::new(Digest384::new([5; 48]));
        let cell = NonFungibleCoinCell::new(
            CoinCellOrigin::new(TransactionId::new(Digest384::new([1; 48])), 0),
            AssetId::new(Digest384::new([2; 48])),
            Digest384::new([3; 48]),
            owner,
            Digest384::new([6; 48]),
            7,
        )
        .unwrap();
        assert!(cell.transfer(destination, owner).is_err());
        let moved = cell.transfer(owner, destination).unwrap();
        assert_eq!(moved.asset_id(), cell.asset_id());
        assert_eq!(moved.token_id(), cell.token_id());
        assert_eq!(moved.metadata_commitment(), cell.metadata_commitment());
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use activechain_accumulator::{AccumulatorDomain, ReferenceSet};
    use activechain_canonical_codec::{
        CanonicalType, Decoder, Encoder, decode_envelope, encode_envelope,
    };
    use activechain_privacy_kernel::{
        NullifierWitness, PrivacyError, ShieldIntent, UnshieldIntent, VerifiedPrivacyProof,
    };
    use activechain_protocol_commitment::{DomainTag, cash_transition_id, commit};
    use activechain_protocol_types::{
        AssetId, ChainId, CoinCellId, Digest384, PrincipalId, TransactionId,
    };
    use alloc::{format, string::String, vec, vec::Vec};
    use proptest::prelude::*;

    use super::{
        CashLedger, CashPaymasterPolicyV1, CashPaymasterRequestV1, CashTransferV1,
        CashTransitionError, CoinBurnTransition, CoinMintTransition, CoinTransfer,
        EpochEconomicsTransition, FungibleCoinCell, GenesisAllocation, GenesisEconomy,
        NativeAssetDefinition, NativeMoneyError, NativeSupply, NonFungibleCoinCell,
        NonFungibleCoinCellRecord, PartitionedCashPlan, RewardRedemption, RewardReplayWitness,
        RewardSettlement,
    };

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn nullifier_witnesses(nullifiers: &[Digest384]) -> Vec<NullifierWitness> {
        let mut reference = ReferenceSet::new(AccumulatorDomain::Nullifier);
        nullifiers
            .iter()
            .map(|nullifier| {
                let witness = reference.non_membership_witness(nullifier.into_bytes()).unwrap();
                reference.insert(nullifier.into_bytes()).unwrap();
                NullifierWitness::new(
                    *nullifier,
                    witness.siblings.into_iter().map(Digest384::new).collect(),
                )
                .unwrap()
            })
            .collect()
    }

    fn reward_replay_witness(assignment: Digest384) -> RewardReplayWitness {
        let reference = ReferenceSet::new(AccumulatorDomain::SpentInput);
        let witness = reference.non_membership_witness(assignment.into_bytes()).unwrap();
        RewardReplayWitness::new(
            assignment,
            witness.siblings.into_iter().map(Digest384::new).collect(),
        )
        .unwrap()
    }

    #[test]
    fn reward_replay_witness_is_canonical_and_exactly_bounded() {
        let witness = reward_replay_witness(digest(90));
        let encoded = encode_envelope(&witness).unwrap();
        assert_eq!(decode_envelope::<RewardReplayWitness>(&encoded), Ok(witness));
        assert_eq!(RewardReplayWitness::MAX_ENCODED_LEN, 48 * 385);
        assert_eq!(
            RewardReplayWitness::new(
                digest(90),
                vec![Digest384::ZERO; activechain_accumulator::KEY_BITS - 1],
            ),
            Err(activechain_canonical_codec::DecodeError::InvalidValue(
                "invalid reward replay witness"
            ))
        );
    }

    #[test]
    fn nft_coin_cell_binds_identity_and_owner() {
        let origin = super::CoinCellOrigin::new(TransactionId::new(digest(1)), 0);
        let cell = NonFungibleCoinCell::new(
            origin,
            AssetId::new(digest(2)),
            digest(3),
            principal(4),
            digest(5),
            7,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<NonFungibleCoinCell>(&encode_envelope(&cell).unwrap()),
            Ok(cell)
        );
        assert_eq!(cell.transfer(principal(9), principal(10)), Err(NativeMoneyError::WrongOwner));
        assert_eq!(cell.transfer(principal(4), principal(10)).unwrap().owner(), principal(10));
        let record = NonFungibleCoinCellRecord::new(CoinCellId::new(digest(8)), cell);
        assert_eq!(
            decode_envelope::<NonFungibleCoinCellRecord>(&encode_envelope(&record).unwrap()),
            Ok(record)
        );
        assert_eq!(
            NonFungibleCoinCell::new(
                origin,
                AssetId::new(Digest384::ZERO),
                digest(3),
                principal(4),
                digest(5),
                7,
            ),
            Err(NativeMoneyError::InvalidInputs)
        );
        assert_eq!(
            FungibleCoinCell::new(
                origin,
                AssetId::new(digest(2)),
                PrincipalId::new(Digest384::ZERO),
                1,
                7
            ),
            Err(NativeMoneyError::InvalidInputs)
        );
    }
    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }
    fn economy() -> GenesisEconomy {
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
        GenesisEconomy::new(
            definition,
            vec![
                GenesisAllocation::new(principal(10), 700_000, 100_000).unwrap(),
                GenesisAllocation::new(principal(12), 100_000, 0).unwrap(),
            ],
            100_000,
        )
        .unwrap()
    }

    fn settlement(pre_supply: u128, issuance: u128, epoch: u64) -> EpochEconomicsTransition {
        settlement_with_window(
            pre_supply,
            issuance,
            epoch,
            0,
            1_000_000,
            issuance * u128::from(epoch - 1),
        )
    }

    fn settlement_with_window(
        pre_supply: u128,
        issuance: u128,
        epoch: u64,
        effective_stake_bps: u16,
        opening_supply: u128,
        issued_before: u128,
    ) -> EpochEconomicsTransition {
        let target = crate::types::epoch_security_budget(pre_supply, effective_stake_bps).unwrap();
        let cap = crate::types::basis_points_amount(opening_supply, 150).unwrap() - issued_before;
        EpochEconomicsTransition::new(
            epoch,
            pre_supply,
            effective_stake_bps,
            target - issuance,
            0,
            target,
            issuance,
            cap,
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
                &CoinMintTransition::new(digest(2), principal(10), 20, 1, 1).unwrap(),
                &settlement(1_000_000, 20, 1),
            )
            .unwrap();
        ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(12), 20, 2, 2).unwrap(),
                &settlement(1_000_020, 20, 2),
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
                102, 127, 210, 7, 27, 3, 232, 109, 247, 147, 47, 11, 103, 225, 212, 134, 200, 86,
                16, 203, 52, 100, 215, 232, 134, 155, 152, 144, 106, 202, 9, 5, 239, 162, 218, 93,
                165, 96, 74, 237, 71, 114, 41, 10, 191, 97, 109, 170,
            ]
        );
        assert!(include_str!("../../../testing/vectors/cash/cash-air-v1.txt")
            .contains("proof_commitment_hex=667fd2071b03e86df7932f0b67e1d486c85610cb3464d7e8869b98906aca0905efa2da5da5604aed4772290abf616daa"));
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
        assert_eq!(
            proof.pre_root(),
            super::authenticated_coin_cell_partition_roots(ledger.cells(), 16)
                .unwrap()
                .global_root()
        );
        assert_eq!(
            proof.post_root(),
            super::authenticated_coin_cell_partition_roots(expected_post.cells(), 16)
                .unwrap()
                .global_root()
        );
        for (row, mutation) in proof.execution().rows().iter().zip(proof.mutations()) {
            assert_eq!(mutation.is_some(), row.accepted());
            if let Some(mutation) = mutation {
                assert_eq!(mutation.partitions(), 16);
                assert!(!mutation.mutations().is_empty());
            }
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
                &settlement_with_window(large + 1, 1, 1, 0, large + 1, 0),
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
        assert_eq!(ledger.supply().current_total_supply(), 1_000_000);
        assert_eq!(ledger.supply().locked_vesting_supply(), 100_000);
        assert_eq!(ledger.supply().security_reserve_balance(), 100_000);
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
        let mint = CoinMintTransition::new(digest(2), recipient, 20, 1, 9).unwrap();
        assert!(ledger.apply_mint(&mint, &settlement(1_000_000, 20, 1)).is_ok());
        assert_eq!(ledger.supply().cumulative_security_issuance(), 20);
        assert_eq!(
            ledger.apply_mint(&mint, &settlement(1_000_020, 20, 1)),
            Err(CashTransitionError::Invalid(NativeMoneyError::MintSequenceMismatch))
        );
        let wrong = CoinMintTransition::new(digest(99), recipient, 1, 2, 10).unwrap();
        assert_eq!(
            ledger.apply_mint(&wrong, &settlement(1_000_020, 1, 2)),
            Err(CashTransitionError::Invalid(NativeMoneyError::MintAuthorityMismatch))
        );
    }

    #[test]
    fn mint_derives_target_and_annual_cap_from_committed_state_atomically() {
        let mut ledger = CashLedger::from_genesis(&economy()).unwrap();
        let mint = CoinMintTransition::new(digest(2), principal(20), 20, 1, 9).unwrap();
        let valid = settlement(1_000_000, 20, 1);

        let wrong_target = EpochEconomicsTransition::new(
            1,
            1_000_000,
            0,
            1,
            0,
            21,
            20,
            15_000,
            0,
            digest(20),
            digest(21),
            digest(22),
            digest(23),
            1_000_020,
        )
        .unwrap();
        let before = ledger.clone();
        assert_eq!(
            ledger.apply_mint(&mint, &wrong_target),
            Err(CashTransitionError::Invalid(NativeMoneyError::IssuanceFormulaMismatch))
        );
        assert_eq!(ledger, before);

        let caller_claimed_stake = EpochEconomicsTransition::new(
            1,
            1_000_000,
            5_000,
            0,
            0,
            20,
            20,
            15_000,
            0,
            digest(20),
            digest(21),
            digest(22),
            digest(23),
            1_000_020,
        )
        .unwrap();
        assert_eq!(
            ledger.apply_mint(&mint, &caller_claimed_stake),
            Err(CashTransitionError::Invalid(NativeMoneyError::IssuanceFormulaMismatch))
        );
        assert_eq!(ledger, before);

        let wrong_cap = EpochEconomicsTransition::new(
            valid.epoch(),
            valid.pre_supply(),
            valid.effective_stake_bps(),
            valid.security_fee_revenue(),
            valid.reserve_draw(),
            valid.target_security_budget(),
            valid.authorized_issuance(),
            valid.issuance_cap() + 1,
            valid.burned_amount(),
            digest(20),
            digest(21),
            digest(22),
            digest(23),
            valid.post_supply(),
        )
        .unwrap();
        assert_eq!(
            ledger.apply_mint(&mint, &wrong_cap),
            Err(CashTransitionError::Invalid(NativeMoneyError::IssuanceCapExceeded))
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn annual_issuance_accounting_survives_restart_and_rolls_over_once() {
        let mut ledger = CashLedger::from_genesis(&economy()).unwrap();
        let opening_supply = ledger.supply().current_total_supply();
        let mut issued = 0_u128;
        for epoch in 1..=365 {
            let pre_supply = ledger.supply().current_total_supply();
            let amount = crate::types::epoch_security_budget(pre_supply, 0).unwrap();
            ledger
                .apply_mint(
                    &CoinMintTransition::new(digest(2), principal(20), amount, epoch, epoch)
                        .unwrap(),
                    &settlement_with_window(pre_supply, amount, epoch, 0, opening_supply, issued),
                )
                .unwrap();
            issued += amount;
            if epoch == 180 {
                ledger = decode_envelope(&encode_envelope(&ledger).unwrap()).unwrap();
            }
        }
        let cap = crate::types::basis_points_amount(opening_supply, 150).unwrap();
        assert!(ledger.supply().issuance_in_window() <= cap);
        assert_eq!(ledger.supply().issuance_window(), 0);

        let next_opening = ledger.supply().current_total_supply();
        let amount = crate::types::epoch_security_budget(next_opening, 0).unwrap();
        ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(20), amount, 366, 366).unwrap(),
                &settlement_with_window(next_opening, amount, 366, 0, next_opening, 0),
            )
            .unwrap();
        assert_eq!(ledger.supply().issuance_window(), 1);
        assert_eq!(ledger.supply().issuance_window_opening_supply(), next_opening);
        assert_eq!(ledger.supply().issuance_in_window(), amount);
    }

    #[test]
    fn legacy_ledger_migration_exhausts_current_window_but_can_advance_without_minting() {
        let mut ledger = CashLedger::from_genesis(&economy()).unwrap();
        ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(20), 20, 1, 1).unwrap(),
                &settlement(1_000_000, 20, 1),
            )
            .unwrap();
        let mut encoder = Encoder::new(CashLedger::MAX_ENCODED_LEN);
        ledger.encode_legacy_v1(&mut encoder).unwrap();
        let body = encoder.finish();
        let mut decoder = Decoder::new(&body);
        let mut migrated = CashLedger::decode_legacy_v1(&mut decoder).unwrap();
        decoder.finish().unwrap();
        assert_eq!(migrated.supply().issuance_window(), 0);
        assert_eq!(
            migrated.supply().issuance_window_opening_supply(),
            migrated.supply().current_total_supply()
        );
        let migrated_cap = crate::types::basis_points_amount(
            migrated.supply().issuance_window_opening_supply(),
            150,
        )
        .unwrap();
        assert_eq!(migrated.supply().issuance_in_window(), migrated_cap);
        migrated.verify_invariants().unwrap();

        for epoch in 2..=365 {
            let supply = migrated.supply().current_total_supply();
            let target = crate::types::epoch_security_budget(supply, 0).unwrap();
            let zero = EpochEconomicsTransition::new(
                epoch,
                supply,
                0,
                target,
                0,
                target,
                0,
                0,
                0,
                digest(20),
                digest(21),
                digest(22),
                digest(23),
                supply,
            )
            .unwrap();
            migrated.apply_zero_issuance_settlement(&zero).unwrap();
        }
        let next_opening = migrated.supply().current_total_supply();
        let amount = crate::types::epoch_security_budget(next_opening, 0).unwrap();
        migrated
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(20), amount, 366, 366).unwrap(),
                &settlement_with_window(next_opening, amount, 366, 0, next_opening, 0),
            )
            .unwrap();
        assert_eq!(migrated.supply().issuance_window(), 1);
        assert_eq!(migrated.supply().issuance_in_window(), amount);
    }

    #[test]
    fn legacy_reward_history_migrates_to_the_spent_input_root() {
        let ledger = CashLedger::from_genesis(&economy()).unwrap();
        let assignments = [digest(80), digest(81)];
        let mut encoder = Encoder::new(CashLedger::MAX_ENCODED_LEN);
        ledger.encode_legacy_v1_with_rewards_for_test(&mut encoder, &assignments).unwrap();
        let body = encoder.finish();
        let mut decoder = Decoder::new(&body);
        let migrated = CashLedger::decode_legacy_v1(&mut decoder).unwrap();
        decoder.finish().unwrap();

        let mut reference = ReferenceSet::new(AccumulatorDomain::SpentInput);
        for assignment in assignments {
            reference.insert(assignment.into_bytes()).unwrap();
        }
        assert_eq!(migrated.redeemed_reward_count(), 2);
        assert_eq!(migrated.redeemed_reward_root().into_bytes(), reference.commitment().root);
    }

    #[test]
    fn transfer_charges_owned_fee_reserve_and_rejects_replay() {
        let economy = economy();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        let minted = ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(10), 20, 1, 1).unwrap(),
                &settlement(1_000_000, 20, 1),
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
        assert_eq!(ledger.supply().security_reserve_balance(), 100_007);
        assert_eq!(
            ledger.apply_transfer(&transfer, 1),
            Err(CashTransitionError::Invalid(NativeMoneyError::MissingCell))
        );
    }

    #[test]
    fn sponsored_transfer_separates_value_and_fee_change_atomically() {
        let mut ledger = CashLedger::from_genesis(&economy()).unwrap();
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
        let mut policy =
            CashPaymasterPolicyV1::new(principal(12), vec![principal(10)], 10, 100, 0, 1, 0, 100)
                .unwrap();
        let transfer_id = cash_transition_id(&transfer).unwrap();
        let request = CashPaymasterRequestV1::new(
            principal(12),
            principal(10),
            *transfer_id.digest(),
            policy.commitment().unwrap(),
            digest(90),
            7,
            0,
            1,
            0,
            100,
        )
        .unwrap();
        ledger.apply_sponsored_transfer(&mut policy, &request, &transfer, 10).unwrap();
        assert_eq!(policy.spent(), 7);
        assert_eq!(policy.next_nonce(), 1);
        assert_eq!(ledger.supply().security_reserve_balance(), 100_007);
        assert!(ledger.cells().as_slice().iter().any(|record| {
            record.cell().owner() == principal(20) && record.cell().amount() == 500
        }));
        assert!(ledger.cells().as_slice().iter().any(|record| {
            record.cell().owner() == principal(10) && record.cell().amount() == 699_500
        }));
        assert!(ledger.cells().as_slice().iter().any(|record| {
            record.cell().owner() == principal(12) && record.cell().amount() == 99_993
        }));
        ledger.verify_invariants().unwrap();
    }

    #[test]
    fn failed_sponsorship_mutates_neither_ledger_nor_paymaster() {
        let mut ledger = CashLedger::from_genesis(&economy()).unwrap();
        let before = ledger.clone();
        let sender_input = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(10))
            .unwrap()
            .id();
        let wrong_reserve = ledger
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
            wrong_reserve,
            500,
            7,
            100,
        )
        .unwrap();
        let mut policy =
            CashPaymasterPolicyV1::new(principal(10), vec![principal(10)], 10, 100, 0, 1, 0, 100)
                .unwrap();
        let policy_before = policy.clone();
        let transfer_id = cash_transition_id(&transfer).unwrap();
        let request = CashPaymasterRequestV1::new(
            principal(10),
            principal(10),
            *transfer_id.digest(),
            policy.commitment().unwrap(),
            digest(90),
            7,
            0,
            1,
            0,
            100,
        )
        .unwrap();
        assert_eq!(
            ledger.apply_sponsored_transfer(&mut policy, &request, &transfer, 10),
            Err(CashTransitionError::Invalid(NativeMoneyError::WrongOwner))
        );
        assert_eq!(ledger, before);
        assert_eq!(policy, policy_before);
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
        assert_eq!(ledger.supply().current_total_supply(), 999_900);
        assert_eq!(ledger.supply().cumulative_burn(), 100);
        ledger.verify_invariants().unwrap();
    }

    #[test]
    fn shield_and_unshield_are_supply_conserving_atomic_and_replay_safe() {
        let economy = economy();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        let minted = ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(10), 20, 1, 1).unwrap(),
                &settlement(1_000_000, 20, 1),
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
        assert_eq!(ledger.supply().current_total_supply(), 1_000_020);
        assert_eq!(ledger.supply().security_reserve_balance(), 100_007);

        let unshield = UnshieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            ledger.shielded_state().anchor(),
            principal(12),
            100,
            3,
            vec![digest(70)],
            nullifier_witnesses(&[digest(70)]),
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
        assert_eq!(ledger.supply().security_reserve_balance(), 100_010);
        assert_eq!(ledger.supply().current_total_supply(), 1_000_020);
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
            unshield.nullifier_witnesses().to_vec(),
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
                activechain_privacy_kernel::PrivacyError::InvalidNullifierWitness
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
                &CoinMintTransition::new(digest(2), principal(10), 20, 1, 1).unwrap(),
                &settlement(1_000_000, 20, 1),
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
            replay_witness: reward_replay_witness(reward.assignment),
            pool_owner: principal(10),
            pool_cell,
            fee_reserve,
            height: 2,
        };
        let supply_before = ledger.supply().current_total_supply();
        let replay_root_before = ledger.redeemed_reward_root();
        ledger.redeem_reward(&reward, &redemption).unwrap();
        assert_eq!(ledger.supply().current_total_supply(), supply_before);
        assert_eq!(ledger.redeemed_reward_count(), 1);
        assert_ne!(ledger.redeemed_reward_root(), replay_root_before);

        let paid = ledger.clone();
        assert_eq!(
            ledger.redeem_reward(&reward, &redemption),
            Err(CashTransitionError::Invalid(NativeMoneyError::InvalidRewardReplayWitness))
        );
        assert_eq!(ledger, paid);

        let mut restarted: CashLedger =
            decode_envelope(&encode_envelope(&ledger).unwrap()).unwrap();
        assert_eq!(restarted.redeemed_reward_count(), 1);
        assert_eq!(restarted.redeemed_reward_root(), ledger.redeemed_reward_root());
        assert_eq!(
            restarted.redeem_reward(&reward, &redemption),
            Err(CashTransitionError::Invalid(NativeMoneyError::InvalidRewardReplayWitness))
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
                &CoinMintTransition::new(digest(2), principal(10), 20, 1, 1).unwrap(),
                &settlement(1_000_000, 20, 1),
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
            replay_witness: reward_replay_witness(reward.assignment),
            pool_owner: principal(10),
            pool_cell: shield_input,
            fee_reserve: shield_fee,
            height: 3,
        };
        assert_eq!(
            shield_first.redeem_reward(&reward, &unavailable),
            Err(CashTransitionError::Invalid(NativeMoneyError::MissingCell))
        );
        assert_eq!(shield_first.redeemed_reward_count(), 0);
        assert_eq!(shield_first, shielded);
    }

    #[test]
    fn rust_cash_lifecycle_matches_frozen_lean_refinement_table() {
        fn row(name: &str, accepted: bool, ledger: &CashLedger) -> String {
            format!(
                "{name},{},{},{},{}\n",
                if accepted { "accept" } else { "reject" },
                ledger.supply().current_total_supply(),
                ledger.shielded_state().pool_balance(),
                ledger.redeemed_reward_count()
            )
        }

        let economy = economy();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        let mut output = row("genesis", true, &ledger);
        let fee_reserve = ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(10), 20, 1, 1).unwrap(),
                &settlement(1_000_000, 20, 1),
            )
            .unwrap();
        output.push_str(&row("issuance", true, &ledger));

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
            replay_witness: reward_replay_witness(reward.assignment),
            pool_owner: principal(10),
            pool_cell,
            fee_reserve,
            height: 2,
        };
        ledger.redeem_reward(&reward, &redemption).unwrap();
        output.push_str(&row("reward", true, &ledger));
        let reward_state = ledger.clone();
        assert!(ledger.redeem_reward(&reward, &redemption).is_err());
        assert_eq!(ledger, reward_state);
        output.push_str(&row("reward_replay", false, &ledger));

        ledger = decode_envelope(&encode_envelope(&ledger).unwrap()).unwrap();
        output.push_str(&row("restart", true, &ledger));
        let mut owner_cells = ledger
            .cells()
            .as_slice()
            .iter()
            .filter(|record| record.cell().owner() == principal(12))
            .collect::<Vec<_>>();
        owner_cells.sort_by_key(|record| record.cell().amount());
        let shield_fee = owner_cells[0].id();
        let shield_input = owner_cells.last().unwrap().id();
        let shield = ShieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            principal(12),
            vec![shield_input],
            shield_fee,
            400,
            7,
            vec![digest(92)],
            20,
        )
        .unwrap();
        let shield_proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &shield).unwrap(),
            verified: true,
        };
        ledger.apply_shield(&shield, shield_proof, 3).unwrap();
        output.push_str(&row("shield", true, &ledger));

        let unshield = UnshieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            ledger.shielded_state().anchor(),
            principal(12),
            100,
            3,
            vec![digest(70)],
            nullifier_witnesses(&[digest(70)]),
            vec![digest(80)],
            30,
        )
        .unwrap();
        let unshield_proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &unshield).unwrap(),
            verified: true,
        };
        ledger.apply_unshield(&unshield, unshield_proof, 4).unwrap();
        output.push_str(&row("unshield", true, &ledger));
        let unshielded = ledger.clone();
        assert!(ledger.apply_unshield(&unshield, unshield_proof, 4).is_err());
        assert_eq!(ledger, unshielded);
        output.push_str(&row("unshield_replay", false, &ledger));

        assert_eq!(
            output,
            include_str!("../../../testing/vectors/cash/cash-lifecycle-model-table.txt")
        );
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
        assert_eq!(value("issuance_epochs_per_year"), 365);
        assert_eq!(
            value("issuance_cap"),
            value("issuance_window_opening_supply") * value("maximum_ordinary_annual_issuance_bps")
                / 10_000
                - value("issuance_in_window_before")
        );
        assert_eq!(
            value("issuance_in_window_after"),
            value("issuance_in_window_before") + value("authorized_issuance")
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

    #[test]
    fn checked_stake_ratio_handles_zero_fractional_and_u128_max_boundaries() {
        assert_eq!(crate::types::effective_stake_basis_points(0, u128::MAX), Ok(0));
        assert_eq!(crate::types::effective_stake_basis_points(u128::MAX, u128::MAX), Ok(10_000));
        assert_eq!(crate::types::effective_stake_basis_points(1, 3), Ok(3_333));
        assert_eq!(
            crate::types::effective_stake_basis_points(4, 3),
            Err(NativeMoneyError::SupplyPartitionMismatch)
        );
    }

    // ============ adversarial regression tests (issue #14) ============
    //
    // Each test pins a defence against a concrete attack on the native cash
    // plane. All of them were first run as exploit attempts against the
    // production API and were refused; they exist so that the refusal stays.

    fn minted_fixture() -> (GenesisEconomy, CashLedger, CoinCellId, CoinCellId) {
        let economy = economy();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        let minted = ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(10), 20, 1, 1).unwrap(),
                &settlement(1_000_000, 20, 1),
            )
            .unwrap();
        let owned = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(10) && record.id() != minted)
            .unwrap()
            .id();
        (economy, ledger, owned, minted)
    }

    fn shielded_fixture() -> (GenesisEconomy, CashLedger) {
        let (economy, mut ledger, input, fee_reserve) = minted_fixture();
        let shield = ShieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            principal(10),
            vec![input],
            fee_reserve,
            400,
            0,
            vec![digest(60)],
            20,
        )
        .unwrap();
        let proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &shield).unwrap(),
            verified: true,
        };
        ledger.apply_shield(&shield, proof, 2).unwrap();
        (economy, ledger)
    }

    fn multi_cell_fixture() -> (CashLedger, Vec<CoinCellId>) {
        let mut ledger = CashLedger::from_genesis(&economy()).unwrap();
        let mut issued = 0_u128;
        for epoch in 1..=3_u64 {
            let pre = ledger.supply().current_total_supply();
            let amount = crate::types::epoch_security_budget(pre, 0).unwrap();
            ledger
                .apply_mint(
                    &CoinMintTransition::new(digest(2), principal(10), amount, epoch, epoch)
                        .unwrap(),
                    &settlement_with_window(pre, amount, epoch, 0, 1_000_000, issued),
                )
                .unwrap();
            issued += amount;
        }
        let ids = ledger
            .cells()
            .as_slice()
            .iter()
            .filter(|record| record.cell().owner() == principal(10))
            .map(|record| record.id())
            .collect::<Vec<_>>();
        (ledger, ids)
    }

    /// Attack: forge wire bytes for a transfer or shield whose fee reserve is
    /// also a value input, or whose inputs repeat, so the kernel counts the
    /// same Coin Cell twice and mints the duplicate as change. The decoders
    /// must refuse what the constructors refuse.
    #[test]
    fn canonical_decoding_refuses_double_counted_inputs_and_nullifiers() {
        use activechain_canonical_codec::{CanonicalDecode, CanonicalEncode};
        let first = CoinCellId::new(digest(1));
        let second = CoinCellId::new(digest(2));

        let transfer_body = |inputs: &[CoinCellId], reserve: CoinCellId| {
            let mut encoder = Encoder::new(CoinTransfer::MAX_ENCODED_LEN);
            principal(10).encode(&mut encoder).unwrap();
            principal(20).encode(&mut encoder).unwrap();
            encoder.write_length(inputs.len(), super::MAX_TRANSFER_INPUTS).unwrap();
            for id in inputs {
                id.encode(&mut encoder).unwrap();
            }
            reserve.encode(&mut encoder).unwrap();
            100_u128.encode(&mut encoder).unwrap();
            1_u128.encode(&mut encoder).unwrap();
            10_u64.encode(&mut encoder).unwrap();
            encoder.finish()
        };
        let control = transfer_body(&[first], second);
        assert!(CoinTransfer::decode(&mut Decoder::new(&control)).is_ok());
        assert!(
            CoinTransfer::decode(&mut Decoder::new(&transfer_body(&[first, first], second)))
                .is_err()
        );
        assert!(CoinTransfer::decode(&mut Decoder::new(&transfer_body(&[first], first))).is_err());

        let shield_body = |inputs: &[CoinCellId], reserve: CoinCellId| {
            let mut encoder = Encoder::new(<ShieldIntent as CanonicalType>::MAX_ENCODED_LEN);
            ChainId::new(digest(1)).encode(&mut encoder).unwrap();
            AssetId::new(digest(2)).encode(&mut encoder).unwrap();
            principal(10).encode(&mut encoder).unwrap();
            encoder
                .write_length(inputs.len(), activechain_privacy_kernel::MAX_SHIELDED_ITEMS)
                .unwrap();
            for id in inputs {
                id.encode(&mut encoder).unwrap();
            }
            reserve.encode(&mut encoder).unwrap();
            100_u128.encode(&mut encoder).unwrap();
            1_u128.encode(&mut encoder).unwrap();
            encoder.write_length(1, activechain_privacy_kernel::MAX_SHIELDED_ITEMS).unwrap();
            digest(60).encode(&mut encoder).unwrap();
            20_u64.encode(&mut encoder).unwrap();
            encoder.finish()
        };
        assert!(ShieldIntent::decode(&mut Decoder::new(&shield_body(&[first], second))).is_ok());
        assert!(ShieldIntent::decode(&mut Decoder::new(&shield_body(&[first], first))).is_err());
        assert!(
            ShieldIntent::decode(&mut Decoder::new(&shield_body(&[first, first], second))).is_err()
        );

        let witnesses = nullifier_witnesses(&[digest(70)]);
        let mut encoder = Encoder::new(<UnshieldIntent as CanonicalType>::MAX_ENCODED_LEN);
        ChainId::new(digest(1)).encode(&mut encoder).unwrap();
        AssetId::new(digest(2)).encode(&mut encoder).unwrap();
        digest(50).encode(&mut encoder).unwrap();
        principal(12).encode(&mut encoder).unwrap();
        100_u128.encode(&mut encoder).unwrap();
        0_u128.encode(&mut encoder).unwrap();
        encoder.write_length(2, activechain_privacy_kernel::MAX_SHIELDED_ITEMS).unwrap();
        digest(70).encode(&mut encoder).unwrap();
        digest(70).encode(&mut encoder).unwrap();
        witnesses[0].encode(&mut encoder).unwrap();
        witnesses[0].encode(&mut encoder).unwrap();
        encoder.write_length(0, activechain_privacy_kernel::MAX_SHIELDED_ITEMS).unwrap();
        30_u64.encode(&mut encoder).unwrap();
        let duplicated = encoder.finish();
        assert!(UnshieldIntent::decode(&mut Decoder::new(&duplicated)).is_err());
    }

    /// Attack: mint value through the reward path by pointing the pool cell and
    /// the fee reserve at the same Coin Cell, by redeeming a reward larger than
    /// the pool, or by draining a pool cell the redeemer does not own.
    #[test]
    fn reward_redemption_cannot_create_value() {
        let reward = |amount| RewardSettlement {
            assignment: digest(90),
            verifier: principal(12),
            reward: amount,
            bond_return: 0,
            slash_amount: 0,
        };
        let redemption = |pool_owner, pool_cell, fee_reserve| RewardRedemption {
            settlement: digest(90),
            replay_witness: reward_replay_witness(digest(90)),
            pool_owner,
            pool_cell,
            fee_reserve,
            height: 2,
        };

        let (_, mut ledger, pool_cell, fee_reserve) = minted_fixture();
        let before = ledger.clone();
        assert_eq!(
            ledger.redeem_reward(&reward(100), &redemption(principal(10), pool_cell, pool_cell)),
            Err(CashTransitionError::Invalid(NativeMoneyError::FeeReserveAlsoInput))
        );
        assert_eq!(ledger, before);
        assert_eq!(
            ledger.redeem_reward(
                &reward(10_000_000),
                &redemption(principal(10), pool_cell, fee_reserve)
            ),
            Err(CashTransitionError::Invalid(NativeMoneyError::InsufficientValue))
        );
        assert_eq!(ledger, before);
        assert_eq!(
            ledger.redeem_reward(&reward(100), &redemption(principal(12), pool_cell, fee_reserve)),
            Err(CashTransitionError::Invalid(NativeMoneyError::WrongOwner))
        );
        assert_eq!(ledger, before);
    }

    /// Attack: pay a transfer fee from someone else's Coin Cell, or leave the
    /// declared fee reserve unspent. The reserve must be owned by the sender
    /// and must actually be consumed into the security reserve.
    #[test]
    fn transfer_fee_reserve_must_be_owned_and_is_consumed() {
        let (_, mut ledger, owned, reserve) = minted_fixture();
        let foreign = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(12))
            .unwrap()
            .id();
        let before = ledger.clone();
        let stolen =
            CoinTransfer::new(principal(10), principal(20), vec![owned], foreign, 500, 7, 10)
                .unwrap();
        assert_eq!(
            ledger.apply_transfer(&stolen, 1),
            Err(CashTransitionError::Invalid(NativeMoneyError::WrongOwner))
        );
        assert_eq!(ledger, before);

        let overflowing =
            CoinTransfer::new(principal(10), principal(20), vec![owned], reserve, u128::MAX, 1, 10)
                .unwrap();
        assert_eq!(
            ledger.apply_transfer(&overflowing, 1),
            Err(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))
        );
        assert_eq!(ledger, before);

        let reserve_before = ledger.supply().security_reserve_balance();
        let circulating_before = ledger.supply().circulating_supply();
        let transfer =
            CoinTransfer::new(principal(10), principal(20), vec![owned], reserve, 500, 7, 10)
                .unwrap();
        ledger.apply_transfer(&transfer, 1).unwrap();
        assert!(ledger.cells().as_slice().iter().all(|record| record.id() != reserve));
        assert!(ledger.cells().as_slice().iter().all(|record| record.id() != owned));
        assert_eq!(ledger.supply().security_reserve_balance(), reserve_before + 7);
        assert_eq!(ledger.supply().circulating_supply(), circulating_before - 7);
        ledger.verify_invariants().unwrap();
    }

    /// Attack: have an authorized paymaster sponsor a fee larger than the
    /// balance of the reserve cell it offers, so the ledger credits an
    /// unfunded fee to the security reserve.
    #[test]
    fn sponsored_transfer_rejects_an_underfunded_sponsor_reserve() {
        let mut ledger = CashLedger::from_genesis(&economy()).unwrap();
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
            200_000,
            100,
        )
        .unwrap();
        let mut policy = CashPaymasterPolicyV1::new(
            principal(12),
            vec![principal(10)],
            200_000,
            1_000_000,
            0,
            1,
            0,
            100,
        )
        .unwrap();
        let transfer_id = cash_transition_id(&transfer).unwrap();
        let request = CashPaymasterRequestV1::new(
            principal(12),
            principal(10),
            *transfer_id.digest(),
            policy.commitment().unwrap(),
            digest(90),
            200_000,
            0,
            1,
            0,
            100,
        )
        .unwrap();
        let before = ledger.clone();
        let policy_before = policy.clone();
        assert_eq!(
            ledger.apply_sponsored_transfer(&mut policy, &request, &transfer, 10),
            Err(CashTransitionError::Invalid(NativeMoneyError::InsufficientValue))
        );
        assert_eq!(ledger, before);
        assert_eq!(policy, policy_before);
    }

    /// Attack: burn more than the declared inputs hold, burn a cell owned by
    /// someone else, or replay a burn (in memory and after a restart) so the
    /// same value leaves the supply twice.
    #[test]
    fn burn_accounting_is_bounded_owned_and_not_replayable() {
        let (_, mut ledger, owned, _) = minted_fixture();
        let before = ledger.clone();
        let too_much = CoinBurnTransition::new(principal(10), vec![owned], 10_000_000, 10).unwrap();
        assert_eq!(
            ledger.apply_burn(&too_much, 1),
            Err(CashTransitionError::Invalid(NativeMoneyError::BurnExceedsInputs))
        );
        assert_eq!(ledger, before);

        let not_owned = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(12))
            .unwrap()
            .id();
        let foreign = CoinBurnTransition::new(principal(10), vec![not_owned], 10, 10).unwrap();
        assert_eq!(
            ledger.apply_burn(&foreign, 1),
            Err(CashTransitionError::Invalid(NativeMoneyError::WrongOwner))
        );
        assert_eq!(ledger, before);

        let burn = CoinBurnTransition::new(principal(10), vec![owned], 100, 10).unwrap();
        let supply_before = ledger.supply().current_total_supply();
        ledger.apply_burn(&burn, 1).unwrap();
        assert_eq!(ledger.supply().current_total_supply(), supply_before - 100);
        assert_eq!(ledger.supply().cumulative_burn(), 100);
        let burned = ledger.clone();
        assert_eq!(
            ledger.apply_burn(&burn, 1),
            Err(CashTransitionError::Invalid(NativeMoneyError::MissingCell))
        );
        assert_eq!(ledger, burned);

        let mut restarted: CashLedger =
            decode_envelope(&encode_envelope(&ledger).unwrap()).unwrap();
        assert_eq!(restarted, ledger);
        assert_eq!(restarted.supply().cumulative_burn(), 100);
        assert_eq!(
            restarted.apply_burn(&burn, 1),
            Err(CashTransitionError::Invalid(NativeMoneyError::MissingCell))
        );
        assert_eq!(restarted, ledger);
    }

    /// Attack: replay a settled transfer against a ledger restored from its own
    /// canonical snapshot, in the hope that the spent-input evidence did not
    /// survive encoding.
    #[test]
    fn transfer_replay_finds_no_input_after_a_restart() {
        let (_, mut ledger, owned, reserve) = minted_fixture();
        let transfer =
            CoinTransfer::new(principal(10), principal(20), vec![owned], reserve, 500, 7, 10)
                .unwrap();
        ledger.apply_transfer(&transfer, 1).unwrap();
        let mut restarted: CashLedger =
            decode_envelope(&encode_envelope(&ledger).unwrap()).unwrap();
        assert_eq!(restarted, ledger);
        assert_eq!(
            restarted.apply_transfer(&transfer, 1),
            Err(CashTransitionError::Invalid(NativeMoneyError::MissingCell))
        );
        assert_eq!(restarted, ledger);
    }

    /// Attack: spend one Coin Cell twice inside a single batch, either as the
    /// value input of two transfers, as a shared fee reserve, or as a shared
    /// secondary input that the first-input batch ordering does not compare.
    #[test]
    fn batched_transfers_cannot_spend_one_cell_twice() {
        let (mut ledger, ids) = multi_cell_fixture();
        assert!(ids.len() >= 4);

        let repeated = vec![
            CoinTransfer::new(principal(10), principal(30), vec![ids[0]], ids[1], 10, 1, 20)
                .unwrap(),
            CoinTransfer::new(principal(10), principal(31), vec![ids[0]], ids[2], 10, 1, 20)
                .unwrap(),
        ];
        assert_eq!(CashTransferV1::new(repeated), Err(NativeMoneyError::InputsNotOrdered));

        let shared_reserve = {
            let mut transfers = vec![
                CoinTransfer::new(principal(10), principal(30), vec![ids[0]], ids[2], 10, 1, 20)
                    .unwrap(),
                CoinTransfer::new(principal(10), principal(31), vec![ids[1]], ids[2], 10, 1, 20)
                    .unwrap(),
            ];
            transfers.sort_by_key(|transfer| transfer.inputs()[0]);
            CashTransferV1::new(transfers).unwrap()
        };
        let supply = ledger.supply().current_total_supply();
        let receipt = ledger.apply_partitioned_batch(&shared_reserve, 5, 8).unwrap();
        assert_eq!((receipt.applied(), receipt.rejected()), (1, 1));
        assert_eq!(ledger.supply().current_total_supply(), supply);
        ledger.verify_invariants().unwrap();

        let (mut ledger, ids) = multi_cell_fixture();
        let shared_input = {
            let mut first = vec![ids[0], ids[3]];
            first.sort_unstable();
            let mut second = vec![ids[1], ids[3]];
            second.sort_unstable();
            let mut transfers = vec![
                CoinTransfer::new(principal(10), principal(30), first, ids[2], 10, 1, 20).unwrap(),
                CoinTransfer::new(principal(10), principal(31), second, ids[2], 10, 1, 20).unwrap(),
            ];
            transfers.sort_by_key(|transfer| transfer.inputs()[0]);
            CashTransferV1::new(transfers).unwrap()
        };
        let supply = ledger.supply().current_total_supply();
        let receipt = ledger.apply_partitioned_batch(&shared_input, 5, 8).unwrap();
        assert_eq!((receipt.applied(), receipt.rejected()), (1, 1));
        assert_eq!(ledger.supply().current_total_supply(), supply);
        ledger.verify_invariants().unwrap();
    }

    /// Attack: unshield more than the shielded pool holds, hide the excess in
    /// the fee, or overflow `amount + fee` so the debit wraps. Also pins that a
    /// fully drained pool with a zero anchor cannot be unshielded again.
    #[test]
    fn unshield_cannot_drain_more_than_the_shielded_pool() {
        let (economy, ledger) = shielded_fixture();
        let pool = ledger.shielded_state().pool_balance();
        let intent = |amount, fee, nullifier, change| {
            UnshieldIntent::new(
                economy.definition().chain_id(),
                ledger.asset_id().unwrap(),
                ledger.shielded_state().anchor(),
                principal(12),
                amount,
                fee,
                vec![nullifier],
                nullifier_witnesses(&[nullifier]),
                vec![change],
                30,
            )
            .unwrap()
        };
        for (amount, fee, expected) in [
            (pool + 1, 0_u128, CashTransitionError::Privacy(PrivacyError::ZeroValue)),
            (pool, 1, CashTransitionError::Privacy(PrivacyError::ZeroValue)),
            (u128::MAX, 1, CashTransitionError::Invalid(NativeMoneyError::AmountOverflow)),
        ] {
            let mut candidate = ledger.clone();
            let intent = intent(amount, fee, digest(70), digest(80));
            let proof = VerifiedPrivacyProof {
                public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &intent)
                    .unwrap(),
                verified: true,
            };
            assert_eq!(candidate.apply_unshield(&intent, proof, 3), Err(expected));
            assert_eq!(candidate, ledger);
        }

        let mut drained = ledger.clone();
        let full = intent(pool, 0, digest(70), digest(80));
        let proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &full).unwrap(),
            verified: true,
        };
        drained.apply_unshield(&full, proof, 3).unwrap();
        assert_eq!(drained.shielded_state().pool_balance(), 0);
        assert_eq!(drained.shielded_state().anchor(), Digest384::ZERO);
        let empty = drained.clone();
        let after = UnshieldIntent::new(
            economy.definition().chain_id(),
            drained.asset_id().unwrap(),
            drained.shielded_state().anchor(),
            principal(12),
            1,
            0,
            vec![digest(71)],
            nullifier_witnesses(&[digest(71)]),
            vec![digest(82)],
            30,
        )
        .unwrap();
        let proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &after).unwrap(),
            verified: true,
        };
        assert_eq!(
            drained.apply_unshield(&after, proof, 4),
            Err(CashTransitionError::Privacy(PrivacyError::ZeroValue))
        );
        assert_eq!(drained, empty);
    }

    /// Attack: spend a shielded note twice by replaying its nullifier against a
    /// ledger restored from a snapshot, with a witness freshly derived from an
    /// empty accumulator, or by presenting a witness from another accumulator
    /// domain.
    #[test]
    fn spent_nullifiers_cannot_be_replayed_across_restart_or_domains() {
        let (economy, mut ledger) = shielded_fixture();
        let intent = UnshieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            ledger.shielded_state().anchor(),
            principal(12),
            100,
            0,
            vec![digest(70)],
            nullifier_witnesses(&[digest(70)]),
            vec![digest(80)],
            30,
        )
        .unwrap();
        let proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &intent).unwrap(),
            verified: true,
        };
        ledger.apply_unshield(&intent, proof, 3).unwrap();

        let mut restarted: CashLedger =
            decode_envelope(&encode_envelope(&ledger).unwrap()).unwrap();
        assert_eq!(restarted, ledger);
        let replay = UnshieldIntent::new(
            economy.definition().chain_id(),
            restarted.asset_id().unwrap(),
            restarted.shielded_state().anchor(),
            principal(12),
            100,
            0,
            vec![digest(70)],
            nullifier_witnesses(&[digest(70)]),
            vec![digest(81)],
            30,
        )
        .unwrap();
        let replay_proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &replay).unwrap(),
            verified: true,
        };
        assert_eq!(
            restarted.apply_unshield(&replay, replay_proof, 4),
            Err(CashTransitionError::Privacy(PrivacyError::InvalidNullifierWitness))
        );
        assert_eq!(restarted, ledger);

        let cross_domain = {
            let reference = ReferenceSet::new(AccumulatorDomain::SpentInput);
            let witness = reference.non_membership_witness(digest(72).into_bytes()).unwrap();
            NullifierWitness::new(
                digest(72),
                witness.siblings.into_iter().map(Digest384::new).collect(),
            )
            .unwrap()
        };
        let borrowed = UnshieldIntent::new(
            economy.definition().chain_id(),
            restarted.asset_id().unwrap(),
            restarted.shielded_state().anchor(),
            principal(12),
            100,
            0,
            vec![digest(72)],
            vec![cross_domain],
            vec![digest(83)],
            30,
        )
        .unwrap();
        let borrowed_proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &borrowed).unwrap(),
            verified: true,
        };
        assert_eq!(
            restarted.apply_unshield(&borrowed, borrowed_proof, 4),
            Err(CashTransitionError::Privacy(PrivacyError::InvalidNullifierWitness))
        );
        assert_eq!(restarted, ledger);
    }

    /// Attack: reuse a verified privacy proof for a different statement, or
    /// replay a shield across chains and assets. The kernel must bind the proof
    /// to the exact intent it verified.
    #[test]
    fn privacy_proofs_bind_chain_asset_and_amount() {
        let (economy, ledger) = shielded_fixture();
        let honest = UnshieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            ledger.shielded_state().anchor(),
            principal(12),
            100,
            0,
            vec![digest(70)],
            nullifier_witnesses(&[digest(70)]),
            vec![digest(80)],
            30,
        )
        .unwrap();
        let proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &honest).unwrap(),
            verified: true,
        };
        let inflated = UnshieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            ledger.shielded_state().anchor(),
            principal(12),
            300,
            0,
            vec![digest(70)],
            nullifier_witnesses(&[digest(70)]),
            vec![digest(80)],
            30,
        )
        .unwrap();
        let mut candidate = ledger.clone();
        assert_eq!(
            candidate.apply_unshield(&inflated, proof, 3),
            Err(CashTransitionError::Privacy(PrivacyError::PublicInputMismatch))
        );
        assert_eq!(candidate, ledger);

        let (_, mut public_ledger, owned, reserve) = minted_fixture();
        let before = public_ledger.clone();
        let shield = |chain, asset| {
            ShieldIntent::new(
                chain,
                asset,
                principal(10),
                vec![owned],
                reserve,
                100,
                0,
                vec![digest(60)],
                20,
            )
            .unwrap()
        };
        let foreign_chain = shield(ChainId::new(digest(99)), public_ledger.asset_id().unwrap());
        let proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &foreign_chain)
                .unwrap(),
            verified: true,
        };
        assert_eq!(
            public_ledger.apply_shield(&foreign_chain, proof, 3),
            Err(CashTransitionError::Privacy(PrivacyError::WrongChain))
        );
        assert_eq!(public_ledger, before);

        let foreign_asset = shield(public_ledger.definition().chain_id(), AssetId::new(digest(98)));
        let proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &foreign_asset)
                .unwrap(),
            verified: true,
        };
        assert_eq!(
            public_ledger.apply_shield(&foreign_asset, proof, 3),
            Err(CashTransitionError::Privacy(PrivacyError::PublicInputMismatch))
        );
        assert_eq!(public_ledger, before);
    }

    /// Attack: shield more value than the declared inputs hold, or shield a
    /// Coin Cell owned by another principal, to credit the shielded pool with
    /// value that never left the public partition.
    #[test]
    fn shield_requires_owned_and_sufficient_public_inputs() {
        let (economy, mut ledger, owned, reserve) = minted_fixture();
        let before = ledger.clone();
        let intent = ShieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            principal(10),
            vec![owned],
            reserve,
            10_000_000,
            0,
            vec![digest(60)],
            20,
        )
        .unwrap();
        let proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &intent).unwrap(),
            verified: true,
        };
        assert_eq!(
            ledger.apply_shield(&intent, proof, 3),
            Err(CashTransitionError::Invalid(NativeMoneyError::InsufficientValue))
        );
        assert_eq!(ledger, before);

        let foreign_input = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(12))
            .unwrap()
            .id();
        let intent = ShieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            principal(10),
            vec![foreign_input],
            reserve,
            100,
            0,
            vec![digest(60)],
            20,
        )
        .unwrap();
        let proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &intent).unwrap(),
            verified: true,
        };
        assert_eq!(
            ledger.apply_shield(&intent, proof, 3),
            Err(CashTransitionError::Invalid(NativeMoneyError::WrongOwner))
        );
        assert_eq!(ledger, before);
    }

    /// Attack: replay an expired transfer, burn, or shield at a later height.
    #[test]
    fn expired_transitions_are_refused_at_every_entry_point() {
        let (economy, mut ledger, owned, reserve) = minted_fixture();
        let before = ledger.clone();
        let transfer =
            CoinTransfer::new(principal(10), principal(20), vec![owned], reserve, 100, 1, 5)
                .unwrap();
        assert_eq!(
            ledger.apply_transfer(&transfer, 6),
            Err(CashTransitionError::Invalid(NativeMoneyError::Expired))
        );
        assert_eq!(ledger, before);

        let burn = CoinBurnTransition::new(principal(10), vec![owned], 100, 5).unwrap();
        assert_eq!(
            ledger.apply_burn(&burn, 6),
            Err(CashTransitionError::Invalid(NativeMoneyError::Expired))
        );
        assert_eq!(ledger, before);

        let shield = ShieldIntent::new(
            economy.definition().chain_id(),
            ledger.asset_id().unwrap(),
            principal(10),
            vec![owned],
            reserve,
            100,
            0,
            vec![digest(60)],
            5,
        )
        .unwrap();
        let proof = VerifiedPrivacyProof {
            public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, &shield).unwrap(),
            verified: true,
        };
        assert_eq!(
            ledger.apply_shield(&shield, proof, 6),
            Err(CashTransitionError::Privacy(PrivacyError::Expired))
        );
        assert_eq!(ledger, before);
    }

    /// Attack (defect class #678): hand-assemble a canonical ledger snapshot
    /// that pairs a modest supply commitment with a richer Coin Cell set, or an
    /// inflated shielded pool, so that decoding restores value the transition
    /// rules never issued. Every decoder, including the legacy migration paths,
    /// must re-check the supply partition.
    #[test]
    fn forged_ledger_snapshots_cannot_restore_unissued_value() {
        use activechain_canonical_codec::{CanonicalDecode, CanonicalEncode};
        use activechain_privacy_kernel::{NullifierSet, ShieldedCashState};

        let (_, rich, _, _) = minted_fixture();
        let poor = CashLedger::from_genesis(&economy()).unwrap();

        let current = |supply_source: &CashLedger, cell_source: &CashLedger| {
            let mut encoder = Encoder::new(<CashLedger as CanonicalType>::MAX_ENCODED_LEN);
            supply_source.definition().encode(&mut encoder).unwrap();
            supply_source.supply().encode(&mut encoder).unwrap();
            cell_source.cells().encode(&mut encoder).unwrap();
            supply_source.shielded_state().encode(&mut encoder).unwrap();
            supply_source.redeemed_reward_root().encode(&mut encoder).unwrap();
            supply_source.redeemed_reward_count().encode(&mut encoder).unwrap();
            encoder.finish()
        };
        assert_eq!(CashLedger::decode(&mut Decoder::new(&current(&poor, &poor))).unwrap(), poor);
        assert_eq!(
            CashLedger::decode(&mut Decoder::new(&current(&poor, &rich))),
            Err(activechain_canonical_codec::DecodeError::InvalidValue("invalid cash ledger"))
        );

        let legacy_v2 = |supply_source: &CashLedger, cell_source: &CashLedger| {
            let mut encoder = Encoder::new(<CashLedger as CanonicalType>::MAX_ENCODED_LEN);
            supply_source.definition().encode(&mut encoder).unwrap();
            supply_source.supply().encode(&mut encoder).unwrap();
            cell_source.cells().encode(&mut encoder).unwrap();
            supply_source.shielded_state().encode_legacy_v1(&mut encoder).unwrap();
            encoder.write_length(0, super::LEGACY_MAX_REDEEMED_REWARDS).unwrap();
            encoder.finish()
        };
        assert_eq!(
            CashLedger::decode_legacy_v2(&mut Decoder::new(&legacy_v2(&poor, &poor))).unwrap(),
            poor
        );
        assert!(CashLedger::decode_legacy_v2(&mut Decoder::new(&legacy_v2(&poor, &rich))).is_err());

        let legacy_v1 = |supply_source: &CashLedger, cell_source: &CashLedger| {
            let mut encoder = Encoder::new(<CashLedger as CanonicalType>::MAX_ENCODED_LEN);
            let supply = supply_source.supply();
            supply_source.definition().encode(&mut encoder).unwrap();
            supply.genesis_supply().encode(&mut encoder).unwrap();
            supply.cumulative_security_issuance().encode(&mut encoder).unwrap();
            supply.cumulative_burn().encode(&mut encoder).unwrap();
            supply.current_total_supply().encode(&mut encoder).unwrap();
            supply.circulating_supply().encode(&mut encoder).unwrap();
            supply.locked_vesting_supply().encode(&mut encoder).unwrap();
            supply.staked_supply().encode(&mut encoder).unwrap();
            supply.security_reserve_balance().encode(&mut encoder).unwrap();
            supply.last_settled_epoch().encode(&mut encoder).unwrap();
            cell_source.cells().encode(&mut encoder).unwrap();
            supply_source.shielded_state().encode_legacy_v1(&mut encoder).unwrap();
            encoder.write_length(0, super::LEGACY_MAX_REDEEMED_REWARDS).unwrap();
            encoder.finish()
        };
        assert!(CashLedger::decode_legacy_v1(&mut Decoder::new(&legacy_v1(&poor, &poor))).is_ok());
        assert!(CashLedger::decode_legacy_v1(&mut Decoder::new(&legacy_v1(&poor, &rich))).is_err());

        let inflated = ShieldedCashState::new(1_000, digest(77), NullifierSet::empty()).unwrap();
        let mut encoder = Encoder::new(<CashLedger as CanonicalType>::MAX_ENCODED_LEN);
        poor.definition().encode(&mut encoder).unwrap();
        poor.supply().encode(&mut encoder).unwrap();
        poor.cells().encode(&mut encoder).unwrap();
        inflated.encode(&mut encoder).unwrap();
        poor.redeemed_reward_root().encode(&mut encoder).unwrap();
        poor.redeemed_reward_count().encode(&mut encoder).unwrap();
        let forged = encoder.finish();
        assert!(CashLedger::decode(&mut Decoder::new(&forged)).is_err());
    }

    /// Attack: create value outside the issuance path by settling an epoch that
    /// declares issuance through the zero-issuance route, by minting to the
    /// zero principal, or by declaring genesis allocations that exceed the
    /// genesis supply.
    #[test]
    fn value_creation_outside_the_issuance_path_is_refused() {
        let mut ledger = CashLedger::from_genesis(&economy()).unwrap();
        let before = ledger.clone();
        assert_eq!(
            ledger.apply_zero_issuance_settlement(&settlement(1_000_000, 20, 1)),
            Err(CashTransitionError::Invalid(NativeMoneyError::IssuanceFormulaMismatch))
        );
        assert_eq!(ledger, before);

        let mint = CoinMintTransition::new(digest(2), PrincipalId::new(Digest384::ZERO), 20, 1, 1)
            .unwrap();
        assert_eq!(
            ledger.apply_mint(&mint, &settlement(1_000_000, 20, 1)),
            Err(CashTransitionError::Invalid(NativeMoneyError::InvalidInputs))
        );
        assert_eq!(ledger, before);

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
        assert_eq!(
            GenesisEconomy::new(
                definition,
                vec![GenesisAllocation::new(principal(10), 900_000, 0).unwrap()],
                100_001,
            ),
            Err(NativeMoneyError::GenesisSupplyMismatch)
        );
    }

    /// Pins that every applied transfer keeps the four supply partitions and
    /// the Coin Cell set summing to exactly the committed total supply.
    #[test]
    fn value_is_conserved_across_a_transfer_walk() {
        let (mut ledger, _) = multi_cell_fixture();
        let total = ledger.supply().current_total_supply();
        let mut recipients =
            [principal(10), principal(20), principal(21), principal(22)].into_iter().cycle();
        for (height, step) in (10_u64..).zip(0..12_u64) {
            let cells = ledger
                .cells()
                .as_slice()
                .iter()
                .filter(|record| record.cell().amount() > 10)
                .map(|record| (record.id(), record.cell().owner(), record.cell().amount()))
                .collect::<Vec<_>>();
            let Some(&(_, owner, _)) = cells.first() else { break };
            let mine =
                cells.iter().filter(|(_, candidate, _)| *candidate == owner).collect::<Vec<_>>();
            if mine.len() < 2 {
                break;
            }
            let transfer = CoinTransfer::new(
                owner,
                recipients.next().unwrap(),
                vec![mine[0].0],
                mine[1].0,
                (mine[0].2 / 2).max(1),
                u128::from((step % 3) + 1),
                1_000,
            )
            .unwrap();
            ledger.apply_transfer(&transfer, height).unwrap();
            ledger.verify_invariants().unwrap();
            let held: u128 =
                ledger.cells().as_slice().iter().map(|record| record.cell().amount()).sum();
            assert_eq!(
                held + ledger.shielded_state().pool_balance()
                    + ledger.supply().security_reserve_balance()
                    + ledger.supply().locked_vesting_supply()
                    + ledger.supply().staked_supply(),
                total
            );
            assert_eq!(ledger.supply().current_total_supply(), total);
        }
    }

    /// Attack (defect class #683): drive value arithmetic to the `u128`
    /// boundary and check that no addition wraps and no subtraction saturates
    /// into a conservation break.
    #[test]
    fn supply_arithmetic_is_checked_at_the_u128_boundary() {
        let definition = NativeAssetDefinition::new(
            ChainId::new(digest(1)),
            b"ACT".to_vec(),
            18,
            u128::MAX,
            150,
            digest(2),
            digest(3),
            digest(4),
        )
        .unwrap();
        let economy = GenesisEconomy::new(
            definition,
            vec![
                GenesisAllocation::new(principal(10), u128::MAX - 6, 1).unwrap(),
                GenesisAllocation::new(principal(10), 2, 0).unwrap(),
                GenesisAllocation::new(principal(12), 1, 0).unwrap(),
            ],
            2,
        )
        .unwrap();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        ledger.verify_invariants().unwrap();
        let big = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().amount() == u128::MAX - 6)
            .unwrap()
            .id();
        let small = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().owner() == principal(10) && record.id() != big)
            .unwrap()
            .id();

        let before = ledger.clone();
        let overflowing =
            CoinTransfer::new(principal(10), principal(20), vec![big], small, u128::MAX, 1, 10)
                .unwrap();
        assert_eq!(
            ledger.apply_transfer(&overflowing, 1),
            Err(CashTransitionError::Invalid(NativeMoneyError::AmountOverflow))
        );
        assert_eq!(ledger, before);

        let transfer =
            CoinTransfer::new(principal(10), principal(20), vec![big], small, u128::MAX - 6, 1, 10)
                .unwrap();
        ledger.apply_transfer(&transfer, 1).unwrap();
        ledger.verify_invariants().unwrap();
        assert_eq!(ledger.supply().current_total_supply(), u128::MAX);

        let huge = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().amount() == u128::MAX - 6)
            .unwrap()
            .id();
        let burn = CoinBurnTransition::new(principal(20), vec![huge], u128::MAX - 6, 10).unwrap();
        ledger.apply_burn(&burn, 1).unwrap();
        ledger.verify_invariants().unwrap();
        assert_eq!(ledger.supply().cumulative_burn(), u128::MAX - 6);
        assert_eq!(ledger.supply().current_total_supply(), 6);
        let restarted: CashLedger = decode_envelope(&encode_envelope(&ledger).unwrap()).unwrap();
        assert_eq!(restarted, ledger);
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
                let genesis = total + burned - issuance;
                let supply = NativeSupply::new(
                    genesis, issuance, burned, total, total, 0, 0, 0, 0, 0, genesis, 0,
                );
                prop_assert!(supply.is_ok());
            }
        }

        #[test]
        fn derived_stake_ratio_matches_wide_bounded_arithmetic(
            total in 1_u64..=u64::MAX,
            raw_staked in 0_u64..=u64::MAX,
        ) {
            let staked = raw_staked % total;
            let expected = ((u128::from(staked) * 10_000) / u128::from(total)) as u16;
            prop_assert_eq!(
                crate::types::effective_stake_basis_points(
                    u128::from(staked),
                    u128::from(total),
                ),
                Ok(expected),
            );
        }

        #[test]
        fn every_reward_amount_moves_value_once_without_changing_total_supply(
            reward_amount in 1_u128..=500,
        ) {
            let economy = economy();
            let mut ledger = CashLedger::from_genesis(&economy).unwrap();
            let fee_reserve = ledger
                .apply_mint(
                    &CoinMintTransition::new(digest(2), principal(10), 20, 1, 1).unwrap(),
                    &settlement(1_000_000, 20, 1),
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
                replay_witness: reward_replay_witness(reward.assignment),
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
                Err(CashTransitionError::Invalid(
                    NativeMoneyError::InvalidRewardReplayWitness
                ))
            );
            prop_assert_eq!(ledger, paid);
        }
    }
}
