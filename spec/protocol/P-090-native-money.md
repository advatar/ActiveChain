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

### Constitutional issuance derivation

Version 2 divides the monotonically increasing economics-settlement sequence into fixed windows of
365 epochs. Epochs 1–365 are window 0, epochs 366–730 are window 1, and boundaries use checked
integer arithmetic. Each window commits its opening total supply and cumulative charged issuance in
`NativeSupply`; those fields are therefore included in the canonical supply root.

The annual constitutional cap is
`floor(window_opening_supply * maximum_ordinary_annual_issuance_bps / 10_000)`. Multiplication is
evaluated by quotient/remainder decomposition so a valid `u128` result cannot fail because of an
overflowing intermediate. The remaining allowance is that cap minus issuance already charged in
the window. Underflow is an invalid state.

Effective stake is itself derived as
`floor(staked_supply * 10_000 / current_total_supply)` from committed `NativeSupply`; a transition's
caller-supplied observation must equal it. The annual target security-budget rate is then derived
from effective stake by piecewise-linear
interpolation of the constitutional research curve: 150 bps at or below 30% stake, 100 bps at 40%,
75 bps at 50%, 50 bps at 60%, and 40 bps at or above 70%. The per-epoch target is
`floor(pre_supply * annual_rate_bps / 10_000 / 365)`. Floor rounding ensures the 365 epoch targets
cannot exceed the corresponding annual rate through rounding alone. The executed mint boundary
requires the transition's target and remaining-cap fields to equal these derived values before any
cell or supply mutation. It then charges the exact minted amount to both cumulative lifetime
issuance and the current window.

`NativeSupply` schema version 2 and `CashLedger` schema version 2 persist this accounting.
`TransactionIngress` snapshot version 3 accepts bounded legacy version-2 snapshots once. Migration
conservatively exhausts the current window because legacy state cannot identify when issuance
occurred; the next atomic save rewrites version 3. A zero-issuance economics transition, whose
derived budget is fully covered by fees/reserve and which creates no Coin Cell, advances consecutive
epochs without reopening current-window capacity. This lets migrated state reach the next window
without either minting or remaining frozen forever. Malformed, non-canonical, wrong-chain,
over-cap, or arithmetically invalid state fails closed.

`WalletTransactionGateway::settle_epoch_durable` is the validator-owned production entry point. It
delegates to `TransactionIngress::settle_epoch_durable`, applies mint or zero-issuance settlement to
a private next state, crash-atomically saves the complete ingress snapshot, and only then publishes
the in-memory successor. There is no separate mutable mint path around this boundary.

## Supply accounting

`NativeSupply` records genesis supply, cumulative security issuance, cumulative
burn, current total supply, circulating supply, locked vesting supply, staked
supply, security-reserve balance, the last settled epoch, and the committed
issuance-window opening supply and cumulative charge. The following
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

The complete ordered Coin Cell set has a domain-separated authenticated sparse-tree root. Finalized
proof public inputs revision 2 commit that root alongside supply and object state. A wallet
discovery result is valid only when each canonical `CoinCellRecord` has a full membership path to
that exact finalized root and its embedded owner equals the requested principal. RPC filtering is
not a proof: wallets independently verify finality, chain genesis, the cell identifier, owner,
membership path, and root before treating value as spendable.

### Partitioned batch execution

`CashTransferV1` (type `0x0091`, schema version `1`) is a bounded batch of at
most 64 transfers ordered by first input identifier. `PartitionedCashPlan`
(type `0x0092`) maps every locked input and fee-reserve identifier to one of
1–256 logical partitions using the first two digest bytes modulo the configured
partition count. The mapping affects scheduling only and cannot change ownership,
authorization, transition identifiers, or the committed Coin Cell set.

The planner acquires identifiers in strict byte order. Transfers whose complete
input sets are disjoint form the parallel lane. Any transfer intersecting an
earlier lock is retained in original batch order in the conflict-fallback lane.
The reference kernel applies the parallel lane followed by fallback and returns
a canonical `PartitionedCashReceipt` (type `0x0093`). Because every later
parallel transfer is disjoint from every earlier transfer, this ordering is
equivalent to serial batch execution. Each transfer remains individually atomic:
an invalid or losing conflict publishes no scratch state, while earlier valid
transfers remain committed. Planning locks are ephemeral and are never encoded
inside `CashLedger`; restart therefore reconstructs them from the canonical batch.

### Transparent CashAIR tranche

The specialized version-1 cash trace consists of `CashAirPublicInputs` (type
`0x0094`), bounded `CashAirRow` values (type `0x0095`), and `CashAirProof`
(type `0x0096`). Public inputs bind the complete batch commitment, pre/post Coin
Cell roots, pre/post supply roots, height, partition count, and accepted/rejected
counts. Each row binds its transfer index, adjacent cell and supply roots, and
outcome. Row order is exactly the partition plan's disjoint lane followed by its
canonical conflict fallback.

Verification regenerates the complete expected trace by direct execution from
the supplied pre-ledger and batch and requires exact equality of the proof,
including all intermediate roots and outcomes. The expected height and partition
count are caller-supplied context, so a trace cannot be replayed under another
execution context. A frozen vector commits the complete proof envelope.

The `activechain-cash-air` companion crate proves the first algebraic subset with
a Winterfell transparent STARK at a minimum 95-bit conjectured security policy:
row progression, boolean activity/outcomes, one-way padding, accepted/rejected
counts, failed-row root atomicity, exact pre/post Coin Cell root binding, and
per-row input = output + fee conservation. Rejected rows constrain all three
value columns to zero. Version 1 deliberately bounds each trace-row total and fee
to `u64`; proof construction rejects a larger value instead of reducing it modulo
the STARK field. The
STARK verifier and direct-reexecution oracle are independent gates; both must pass.

This tranche is not zero knowledge. It also does not yet arithmetize SHAKE,
ML-DSA, authenticated membership, successful value/fee transitions, session
budgets, authenticated partition-root updates, or recursive aggregation. Those
remain explicit CashAIR completion gates and no proof-finalized throughput claim
is permitted until they are implemented and benchmarked.

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
