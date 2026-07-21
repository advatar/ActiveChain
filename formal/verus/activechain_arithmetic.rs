use vstd::arithmetic::div_mod::lemma_multiply_divide_le;
use vstd::arithmetic::mul::{lemma_mul_inequality, lemma_mul_is_commutative};
use vstd::prelude::*;

verus! {

pub open spec fn fee_total_math(
    base: u128,
    resource_units: u64,
    resource_price: u128,
    congestion_price: u128,
) -> int {
    base as int
        + (resource_units as int) * (resource_price as int)
        + congestion_price as int
}

/// Mirrors `FeeQuote::total`: every intermediate checked operation succeeds
/// exactly when the mathematical, non-negative total fits in `u128`.
pub fn fee_total_checked(
    base: u128,
    resource_units: u64,
    resource_price: u128,
    congestion_price: u128,
) -> (result: Option<u128>)
    ensures
        match result {
            Some(value) => {
                fee_total_math(base, resource_units, resource_price, congestion_price)
                    <= u128::MAX as int
                && value as int
                    == fee_total_math(base, resource_units, resource_price, congestion_price)
            },
            None => fee_total_math(base, resource_units, resource_price, congestion_price)
                > u128::MAX as int,
        },
{
    match (resource_units as u128).checked_mul(resource_price) {
        None => None,
        Some(resource_cost) => match base.checked_add(resource_cost) {
            None => None,
            Some(subtotal) => subtotal.checked_add(congestion_price),
        },
    }
}

pub open spec fn strict_quorum_math(signer_stake: u128, total_stake: u128) -> bool {
    3 * signer_stake as int > 2 * total_stake as int
}

/// Division-free strict two-thirds comparison with the same checked-overflow
/// behavior as `QuorumCertificate::new`.
pub fn strict_quorum_checked(
    signer_stake: u128,
    total_stake: u128,
) -> (result: Option<bool>)
    requires
        total_stake > 0,
        signer_stake <= total_stake,
    ensures
        match result {
            Some(accepted) => {
                3 * signer_stake as int <= u128::MAX as int
                && 2 * total_stake as int <= u128::MAX as int
                && accepted == strict_quorum_math(signer_stake, total_stake)
            },
            None => {
                3 * signer_stake as int > u128::MAX as int
                || 2 * total_stake as int > u128::MAX as int
            },
        },
{
    match signer_stake.checked_mul(3) {
        None => None,
        Some(signer_tripled) => match total_stake.checked_mul(2) {
            None => None,
            Some(total_doubled) => Some(signer_tripled > total_doubled),
        },
    }
}

pub open spec fn fee_delta_math(base_fee: u128, max_change_bps: u16) -> int {
    (base_fee as int * max_change_bps as int) / 10_000
}

pub open spec fn next_base_fee_math(
    base_fee: u128,
    target_units: u64,
    max_change_bps: u16,
    used_units: u64,
) -> int {
    let delta = fee_delta_math(base_fee, max_change_bps);
    if used_units > target_units {
        base_fee as int + delta
    } else if used_units < target_units {
        if base_fee as int - delta < 1 {
            1
        } else {
            base_fee as int - delta
        }
    } else {
        base_fee as int
    }
}

pub open spec fn next_base_fee_overflows(
    base_fee: u128,
    target_units: u64,
    max_change_bps: u16,
    used_units: u64,
) -> bool {
    base_fee as int * max_change_bps as int > u128::MAX as int
    || (
        base_fee as int * max_change_bps as int <= u128::MAX as int
        && used_units > target_units
        && next_base_fee_math(base_fee, target_units, max_change_bps, used_units)
            > u128::MAX as int
    )
}

/// Mirrors `FeeMarket::next` for states admitted by `FeeMarket::new`.
pub fn next_base_fee_checked(
    base_fee: u128,
    target_units: u64,
    max_change_bps: u16,
    used_units: u64,
) -> (result: Option<u128>)
    requires
        base_fee > 0,
        target_units > 0,
        max_change_bps <= 10_000,
    ensures
        match result {
            Some(value) => {
                !next_base_fee_overflows(base_fee, target_units, max_change_bps, used_units)
                && value as int
                    == next_base_fee_math(base_fee, target_units, max_change_bps, used_units)
                && value >= 1
            },
            None => next_base_fee_overflows(
                base_fee,
                target_units,
                max_change_bps,
                used_units,
            ),
        },
{
    match base_fee.checked_mul(max_change_bps as u128) {
        None => None,
        Some(product) => {
            let delta = product / 10_000;
            proof {
                lemma_mul_inequality(
                    max_change_bps as int,
                    10_000,
                    base_fee as int,
                );
                lemma_mul_is_commutative(base_fee as int, max_change_bps as int);
                assert(base_fee as int * max_change_bps as int
                    <= 10_000 * base_fee as int);
                lemma_multiply_divide_le(
                    base_fee as int * max_change_bps as int,
                    10_000,
                    base_fee as int,
                );
                assert(delta as int <= base_fee as int);
            }
            if used_units > target_units {
                match base_fee.checked_add(delta) {
                    None => None,
                    Some(next) => Some(next),
                }
            } else if used_units < target_units {
                let reduced = base_fee - delta;
                if reduced < 1 {
                    Some(1)
                } else {
                    Some(reduced)
                }
            } else {
                Some(base_fee)
            }
        },
    }
}

pub open spec fn post_supply_math(pre_supply: u128, issuance: u128, burned: u128) -> int {
    pre_supply as int + issuance as int - burned as int
}

/// Checked supply equation used by epoch settlement.
pub fn post_supply_checked(
    pre_supply: u128,
    issuance: u128,
    burned: u128,
) -> (result: Option<u128>)
    ensures
        match result {
            Some(value) => {
                pre_supply as int + issuance as int <= u128::MAX as int
                && burned as int <= pre_supply as int + issuance as int
                && value as int == post_supply_math(pre_supply, issuance, burned)
            },
            None => {
                pre_supply as int + issuance as int > u128::MAX as int
                || burned as int > pre_supply as int + issuance as int
            },
        },
{
    match pre_supply.checked_add(issuance) {
        None => None,
        Some(pre_issuance) => pre_issuance.checked_sub(burned),
    }
}

pub open spec fn partition_total_math(
    circulating: u128,
    vesting: u128,
    staked: u128,
    reserve: u128,
) -> int {
    circulating as int + vesting as int + staked as int + reserve as int
}

/// Checked total for the native-supply partition equation.
pub fn partition_total_checked(
    circulating: u128,
    vesting: u128,
    staked: u128,
    reserve: u128,
) -> (result: Option<u128>)
    ensures
        match result {
            Some(value) => {
                partition_total_math(circulating, vesting, staked, reserve)
                    <= u128::MAX as int
                && value as int == partition_total_math(circulating, vesting, staked, reserve)
            },
            None => partition_total_math(circulating, vesting, staked, reserve)
                > u128::MAX as int,
        },
{
    match circulating.checked_add(vesting) {
        None => None,
        Some(first) => match first.checked_add(staked) {
            None => None,
            Some(second) => second.checked_add(reserve),
        },
    }
}

pub open spec fn issuance_gap_math(
    security_fees: u128,
    reserve_draw: u128,
    target_budget: u128,
) -> int {
    let covered = security_fees as int + reserve_draw as int;
    if covered >= target_budget as int {
        0
    } else {
        target_budget as int - covered
    }
}

/// Mirrors the checked coverage sum, saturating target gap, and issuance cap
/// checks in `EpochEconomicsTransition::new`.
pub fn authorized_issuance_checked(
    security_fees: u128,
    reserve_draw: u128,
    target_budget: u128,
    issuance_cap: u128,
) -> (result: Option<u128>)
    ensures
        match result {
            Some(value) => {
                security_fees as int + reserve_draw as int <= u128::MAX as int
                && issuance_gap_math(security_fees, reserve_draw, target_budget)
                    <= issuance_cap as int
                && value as int == issuance_gap_math(security_fees, reserve_draw, target_budget)
                && value <= target_budget
            },
            None => {
                security_fees as int + reserve_draw as int > u128::MAX as int
                || issuance_gap_math(security_fees, reserve_draw, target_budget)
                    > issuance_cap as int
            },
        },
{
    match security_fees.checked_add(reserve_draw) {
        None => None,
        Some(covered) => {
            let gap = target_budget.saturating_sub(covered);
            if gap > issuance_cap {
                None
            } else {
                Some(gap)
            }
        },
    }
}

fn frozen_production_vectors() {
    let fee = fee_total_checked(3, 4, 5, 2);
    assert(fee == Some(25));
    let fee_product_overflow = fee_total_checked(0, u64::MAX, u128::MAX, 0);
    assert(fee_product_overflow == None);
    let fee_sum_overflow = fee_total_checked(u128::MAX, 1, 1, 0);
    assert(fee_sum_overflow == None);
    let accepted_quorum = strict_quorum_checked(3, 3);
    assert(accepted_quorum == Some(true));
    let rejected_quorum = strict_quorum_checked(2, 3);
    assert(rejected_quorum == Some(false));
    let quorum_overflow = strict_quorum_checked(u128::MAX, u128::MAX);
    assert(quorum_overflow == None);
    let higher_fee = next_base_fee_checked(100, 10, 1_000, 20);
    assert(higher_fee == Some(110));
    let lower_fee = next_base_fee_checked(100, 10, 1_000, 1);
    assert(lower_fee == Some(90));
    let minimum_fee = next_base_fee_checked(1, 1, 10_000, 0);
    assert(minimum_fee == Some(1));
    let fee_product_overflow = next_base_fee_checked(u128::MAX, 1, 10_000, 1);
    assert(fee_product_overflow == None);
    let fee_increase_overflow = next_base_fee_checked(u128::MAX, 1, 1, 2);
    assert(fee_increase_overflow == None);
    let post_supply = post_supply_checked(1_000, 50, 10);
    assert(post_supply == Some(1_040));
    let supply_add_overflow = post_supply_checked(u128::MAX, 1, 0);
    assert(supply_add_overflow == None);
    let supply_burn_underflow = post_supply_checked(0, 0, 1);
    assert(supply_burn_underflow == None);
    let partition = partition_total_checked(800, 100, 50, 90);
    assert(partition == Some(1_040));
    let partition_overflow = partition_total_checked(u128::MAX, 1, 0, 0);
    assert(partition_overflow == None);
    let issuance = authorized_issuance_checked(35, 15, 100, 60);
    assert(issuance == Some(50));
    let covered_overflow = authorized_issuance_checked(u128::MAX, 1, 100, 100);
    assert(covered_overflow == None);
    let cap_failure = authorized_issuance_checked(0, 0, 100, 99);
    assert(cap_failure == None);
}

fn main() {
    frozen_production_vectors();
}

} // verus!
