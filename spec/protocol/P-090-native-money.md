# P-090 Native money and protocol issuance

Status: draft implementation tranche

This specification defines the first native-money boundary from `CASH.md` and
`MINT.md`. Native money is a fixed-semantics protocol path and is never routed
through ObjectVM.

## Monetary constitution

`NativeAssetDefinition` is immutable and contains the chain binding, canonical
symbol, decimal precision, genesis supply, policy commitments, and a bounded
ordinary annual issuance ceiling. It contains no administrator, foundation,
validator, proposer, multisignature, bridge, or reusable native mint key.

Native creation has exactly two protocol paths:

1. the one-time `GenesisEconomy` allocation, and
2. an `EpochEconomicsTransition` whose issuance is deterministically computed
   from the target security budget, security-directed fees, and reserve draw.

The epoch transition must satisfy:

```text
authorized_issuance = max(target_security_budget
                           - security_fee_revenue
                           - reserve_draw, 0)
authorized_issuance <= issuance_cap
post_supply = pre_supply + authorized_issuance - burned_amount
```

No caller-provided authority signature can substitute for these checks.

## Supply accounting

`NativeSupply` records genesis supply, cumulative security issuance, cumulative
burn, current total supply, circulating supply, locked vesting supply, staked
supply, security-reserve balance, and the last settled epoch. The following
partition is checked with checked arithmetic:

```text
current_total_supply = circulating_supply
                      + locked_vesting_supply
                      + staked_supply
                      + security_reserve_balance
```

Genesis allocations must sum with the initial reserve to the declared genesis
supply. Locked allocation value is not spendable until a later vesting layer is
implemented; it remains part of total supply.

## Coin Cells and transitions

Each unspent `CoinCell` has a deterministic `(transition_id, output_index)`
origin, owner, positive amount, and creation height. A `CoinTransfer` requires
strictly ordered, duplicate-free inputs and a distinct fee-reserve cell owned by
the sender. It creates a recipient cell and optional sender change, moves the
fee into the protocol security reserve, and consumes all inputs atomically.

`CoinBurnTransition` consumes owner cells and reduces total supply exactly once;
it may create only unburned change. Replaying consumed inputs, using a wrong
owner, exceeding checked sums, or violating a deadline is rejected before state
mutation.

## Post-quantum boundary

This tranche defines value conservation and issuance accounting only. Payment
authorization witnesses and compact ML-DSA sessions are specified by the next
cash tranche; no classical signature suite may be added to native validation.
