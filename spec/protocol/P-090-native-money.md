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

Authoritative transaction ingress accepts only a strict canonical
`AuthorizedCashTransferV1` envelope (type `0x008b`, schema version `1`). Its
embedded `CashAuthorizationRequestV1` (type `0x008a`, schema version `1`) binds:

- the immutable chain ID and sender principal;
- the sender-local nonce, one-shot session ID, and session expiry;
- a recomputed recipient commitment; and
- the complete canonical `CoinTransfer`, including all input cells, fee reserve,
  amount, fee, and validity height.

The signature transcript is the domain-separated, length-prefixed canonical
request envelope and MUST use ML-DSA-44. The node obtains the sender's public key
from finalized authorization state; a request can never supply or replace that
key. Strict decoding rejects a wrong type or version, malformed lengths,
trailing bytes, a recipient mismatch, an expiry outside the transfer validity
window, or any non-ML-DSA signature suite.

Admission checks the exact next nonce and rejects reused session IDs or any
already-consumed payment/fee input. The ledger transition, nonce increment,
session consumption, and input replay barriers are constructed on a private
next-state value and become visible together only after every ledger check
succeeds. The current implementation provides this atomicity in memory. Before
public value-bearing operation, finalized identity/key provenance and the joint
ledger/authorization state MUST be persisted by one crash-atomic commit. The
legacy unkeyed `PaymentSession` helper is local wallet compatibility code and is
not a network authorization mechanism.

No classical signature suite may be added to native validation.
