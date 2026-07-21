#![forbid(unsafe_code)]

use activechain_cash_kernel::{
    EpochEconomicsTransition, FeeMarket, FeeQuote, NativeMoneyError, NativeSupply,
};
use activechain_protocol_types::{
    ConsensusVoteContext, Digest384, QuorumCertificate, QuorumCertificateError,
};

#[path = "../../vectors.rs"]
mod vectors;

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn main() {
    let fee = FeeQuote {
        base: vectors::FEE_BASE,
        resource_units: vectors::FEE_UNITS,
        resource_price: vectors::FEE_PRICE,
        congestion_price: vectors::FEE_CONGESTION,
    };
    assert_eq!(fee.total(), Some(vectors::FEE_TOTAL));
    assert_eq!(
        FeeQuote {
            base: 0,
            resource_units: u64::MAX,
            resource_price: u128::MAX,
            congestion_price: 0,
        }
        .total(),
        None
    );
    assert_eq!(
        FeeQuote { base: u128::MAX, resource_units: 1, resource_price: 1, congestion_price: 0 }
            .total(),
        None
    );

    let market =
        FeeMarket::new(vectors::MARKET_BASE, vectors::MARKET_TARGET, vectors::MARKET_CHANGE_BPS)
            .expect("frozen market is valid");
    assert_eq!(
        market.next(vectors::MARKET_USED_HIGH).expect("high-use adjustment fits").base_fee,
        vectors::MARKET_NEXT_HIGH
    );
    assert_eq!(
        market.next(vectors::MARKET_USED_LOW).expect("low-use adjustment fits").base_fee,
        vectors::MARKET_NEXT_LOW
    );
    assert_eq!(
        FeeMarket::new(1, 1, 10_000)
            .expect("minimum market is valid")
            .next(0)
            .expect("minimum decrease remains defined")
            .base_fee,
        1
    );
    assert_eq!(
        FeeMarket::new(u128::MAX, 1, 10_000)
            .expect("constructor admits checked runtime arithmetic")
            .next(1),
        None
    );
    assert_eq!(
        FeeMarket::new(u128::MAX, 1, 1)
            .expect("constructor admits checked runtime arithmetic")
            .next(2),
        None
    );

    let context = ConsensusVoteContext::new(digest(1), 1, digest(2))
        .expect("frozen consensus context is bound");
    assert!(
        QuorumCertificate::new(
            context,
            1,
            0,
            digest(3),
            digest(4),
            vectors::QUORUM_TOTAL,
            vectors::QUORUM_ACCEPTED_SIGNERS,
        )
        .is_ok()
    );
    assert_eq!(
        QuorumCertificate::new(
            context,
            1,
            0,
            digest(3),
            digest(4),
            vectors::QUORUM_TOTAL,
            vectors::QUORUM_REJECTED_SIGNERS,
        ),
        Err(QuorumCertificateError::InsufficientStake)
    );
    assert_eq!(
        QuorumCertificate::new(context, 1, 0, digest(3), digest(4), u128::MAX, u128::MAX,),
        Err(QuorumCertificateError::StakeOverflow)
    );

    let supply = NativeSupply::new(
        vectors::SUPPLY_PRE,
        vectors::SUPPLY_ISSUANCE,
        vectors::SUPPLY_BURN,
        vectors::SUPPLY_POST,
        vectors::PARTITION_CIRCULATING,
        vectors::PARTITION_VESTING,
        vectors::PARTITION_STAKED,
        vectors::PARTITION_RESERVE,
        1,
    )
    .expect("frozen supply equations hold");
    assert_eq!(supply.current_total_supply(), vectors::SUPPLY_POST);
    assert_eq!(
        NativeSupply::new(u128::MAX, 1, 0, 0, 0, 0, 0, 0, 1),
        Err(NativeMoneyError::AmountOverflow)
    );
    assert_eq!(NativeSupply::new(0, 0, 1, 0, 0, 0, 0, 0, 1), Err(NativeMoneyError::AmountOverflow));
    assert_eq!(
        NativeSupply::new(u128::MAX, 0, 0, u128::MAX, u128::MAX, 1, 0, 0, 1),
        Err(NativeMoneyError::SupplyPartitionMismatch)
    );

    let settlement = EpochEconomicsTransition::new(
        1,
        vectors::SUPPLY_PRE,
        5_000,
        vectors::SECURITY_FEES,
        vectors::SECURITY_RESERVE,
        vectors::SECURITY_TARGET,
        vectors::SECURITY_ISSUANCE,
        vectors::SECURITY_CAP,
        vectors::SUPPLY_BURN,
        digest(10),
        digest(11),
        digest(12),
        digest(13),
        vectors::SUPPLY_POST,
    )
    .expect("frozen issuance and supply equations hold");
    assert_eq!(settlement.authorized_issuance(), vectors::SECURITY_ISSUANCE);
    assert_eq!(settlement.post_supply(), vectors::SUPPLY_POST);
    assert_eq!(
        EpochEconomicsTransition::new(
            1,
            100,
            5_000,
            u128::MAX,
            1,
            100,
            0,
            100,
            0,
            digest(10),
            digest(11),
            digest(12),
            digest(13),
            100,
        ),
        Err(NativeMoneyError::AmountOverflow)
    );
    assert_eq!(
        EpochEconomicsTransition::new(
            1,
            100,
            5_000,
            0,
            0,
            100,
            100,
            99,
            0,
            digest(10),
            digest(11),
            digest(12),
            digest(13),
            200,
        ),
        Err(NativeMoneyError::IssuanceFormulaMismatch)
    );
}
