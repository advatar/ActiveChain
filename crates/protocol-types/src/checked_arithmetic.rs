//! Shared checked arithmetic used by consensus and native economics.

#[must_use]
pub fn fee_total(base: u128, units: u64, price: u128, congestion: u128) -> Option<u128> {
    let resource = (units as u128).checked_mul(price)?;
    base.checked_add(resource)?.checked_add(congestion)
}

#[must_use]
pub fn strict_two_thirds(signer: u128, total: u128) -> Option<bool> {
    Some(signer.checked_mul(3)? > total.checked_mul(2)?)
}

#[must_use]
pub fn next_base_fee(base: u128, target: u64, change_bps: u16, used: u64) -> Option<u128> {
    let delta = base.checked_mul(change_bps as u128)?.checked_div(10_000)?;
    if used > target {
        base.checked_add(delta)
    } else if used < target {
        Some(base.saturating_sub(delta).max(1))
    } else {
        Some(base)
    }
}

#[must_use]
pub fn post_supply(pre: u128, issuance: u128, burned: u128) -> Option<u128> {
    pre.checked_add(issuance)?.checked_sub(burned)
}

#[must_use]
pub fn partition_total(a: u128, b: u128, c: u128, d: u128) -> Option<u128> {
    a.checked_add(b)?.checked_add(c)?.checked_add(d)
}

#[must_use]
pub fn authorized_issuance(fees: u128, reserve: u128, target: u128) -> Option<u128> {
    Some(target.saturating_sub(fees.checked_add(reserve)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn shared_operations_match_independent_checked_expressions(
            a: u128, b: u128, c: u128, d: u128, units: u64, target: u64,
            bps in 0_u16..=10_000, used: u64,
        ) {
            prop_assert_eq!(fee_total(a, units, b, c), (units as u128).checked_mul(b).and_then(|x| a.checked_add(x)).and_then(|x| x.checked_add(c)));
            prop_assert_eq!(strict_two_thirds(a, b), a.checked_mul(3).and_then(|x| b.checked_mul(2).map(|y| x > y)));
            let expected_fee = a.checked_mul(bps as u128).and_then(|x| x.checked_div(10_000)).and_then(|delta| if used > target { a.checked_add(delta) } else if used < target { Some(a.saturating_sub(delta).max(1)) } else { Some(a) });
            prop_assert_eq!(next_base_fee(a, target, bps, used), expected_fee);
            prop_assert_eq!(post_supply(a, b, c), a.checked_add(b).and_then(|x| x.checked_sub(c)));
            prop_assert_eq!(partition_total(a, b, c, d), a.checked_add(b).and_then(|x| x.checked_add(c)).and_then(|x| x.checked_add(d)));
            prop_assert_eq!(authorized_issuance(a, b, c), a.checked_add(b).map(|x| c.saturating_sub(x)));
        }
    }
}
