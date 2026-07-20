The **native coin must never be minted by an administrator, validator, proposer, foundation, or multisignature**. It should be minted only by deterministic protocol transitions that every node can recompute and that the global transition proof verifies.

For mainnet, there should be exactly two native-coin creation paths:

1. **Genesis issuance:** a one-time, publicly committed initial allocation.
2. **Security issuance:** bounded minting at epoch boundaries to fund consensus and protocol assurance.

A development-network faucet can exist, but its transition type must be rejected on every mainnet chain ID.

# 1. Native-coin supply state

The native asset definition should be immutable:

```text
NativeAssetDefinition {
    asset_id
    symbol
    decimals

    genesis_supply
    maximum_ordinary_annual_issuance_rate

    issuance_policy_hash
    burn_policy_hash
    reward_policy_hash

    freeze_authority = None
    discretionary_mint_authority = None
    upgrade_authority = None
}
```

The ledger tracks a supply object:

```text
NativeSupplyState {
    genesis_supply

    cumulative_security_issuance
    cumulative_burn

    current_total_supply
    circulating_supply
    locked_vesting_supply
    staked_supply
    security_reserve_balance

    last_settled_epoch
}
```

The core invariant is:

\[
S_e
=
S_{\text{genesis}}
+
\sum_{i=1}^{e} I_i
-
\sum_{i=1}^{e} B_i
\]

where:

- \(S_e\) is current native supply;
- \(I_i\) is authorized protocol issuance;
- \(B_i\) is permanently burned native coin.

Locking coins for staking, vesting, channels, escrow, or bonds does not change total supply.

# 2. Genesis minting

The genesis file contains:

```text
GenesisEconomy {
    native_asset_definition
    genesis_supply
    genesis_allocation_root
    vesting_schedule_root
    initial_security_reserve
}
```

The genesis transition creates:

- ordinary Coin Cells for liquid allocations;
- vesting objects for locked allocations;
- an on-chain security-reserve vault;
- any public-goods endowment objects;
- no reusable native mint capability.

The allocation must be reproducible from a published machine-readable file. Every client independently verifies:

\[
\sum \text{genesis allocations}
=
\text{genesis supply}
\]

Locked contributor and treasury allocations should be represented as explicit vesting objects rather than an off-chain promise.

A reasonable distribution can be debated separately, but the technical rule is absolute: **no undisclosed allocation and no post-genesis foundation mint key**.

# 3. Ongoing minting happens at epoch settlement

Validators do not individually mint their rewards. The block proposer does not select the amount.

During an epoch, the system records:

- completed validator duties;
- DA sampling duties;
- audit-verifier assignments;
- objective penalties;
- security-fee revenue;
- congestion burns;
- active stake;
- validator-seat backing;
- reward recipients.

At the epoch boundary, all nodes deterministically calculate one `EpochEconomicsTransition`:

```text
EpochEconomicsTransition {
    epoch

    pre_supply
    effective_stake
    security_fee_revenue
    reserve_draw

    target_security_budget
    authorized_issuance
    burned_amount

    validator_reward_root
    audit_reward_root
    challenge_reward_root
    public_goods_reward_root

    post_supply
}
```

The transition proof establishes that:

1. the issuance formula was applied correctly;
2. issuance remained under the constitutional cap;
3. reward recipients performed the required duties;
4. every penalty was derived from valid evidence;
5. rewards sum exactly to the authorized budget;
6. no reward was paid twice;
7. burns were properly accounted for;
8. the resulting supply is correct.

The resulting block is finalized with PQ validator signatures, and its state transition is verified through the transparent PQ proof system.

There is no P-256, ECDSA, Ed25519, BLS, or administrator signature in this minting path.

# 4. Reward credits rather than thousands of tiny outputs

Creating one Coin Cell for every tiny service payment would unnecessarily fragment state.

Epoch settlement should create aggregated reward credits:

```text
RewardCredit {
    owner_principal
    amount
    source_epochs
    reward_categories
    accounting_proof_root
}
```

The credit is supply-bearing as soon as the epoch transition finalizes.

The owner may later redeem it into one or more Coin Cells:

```text
RewardCredit
    ↓ redeem
Public Coin Cells
```

or:

```text
RewardCredit
    ↓ shield
Private shielded note
```

Redemption does not mint again. It only changes the representation of already-issued value.

# 5. Recommended inflation policy

I would not use either:

- a permanently fixed annual inflation rate; or
- a hard supply cap that assumes transaction fees will always fund sufficient security.

Instead, use a **bounded adaptive security budget**.

The protocol chooses how much security expenditure it needs. Fees pay part of that expenditure. The protocol mints only the shortfall.

## Security-budget curve

Let:

- \(S_e\) be supply at the start of epoch \(e\);
- \(q_e\) be the effective staked fraction;
- \(r(q_e)\) be the annual security-budget rate;
- \(E\) be epochs per year.

Then:

\[
T_e
=
\frac{S_e \cdot r(q_e)}{E}
\]

where \(T_e\) is the target security budget for the epoch.

The rate rises when effective stake is dangerously low and falls when participation is comfortably high.

Illustrative starting values for economic simulation:

| Effective staked supply | Annual target security budget |
|---:|---:|
| 30% or lower | 1.50% of supply |
| 40% | 1.00% |
| 50% | 0.75% |
| 60% | 0.50% |
| 70% or higher | 0.40% |

Interpolate smoothly between the points.

These are test parameters, not values to freeze before simulation.

## Actual issuance

Let:

- \(F_e\) be security-directed fee revenue;
- \(D_e\) be an automatically permitted security-reserve draw;
- \(I_{e,\max}\) be the epoch’s issuance cap.

Then:

\[
I_e
=
\operatorname{clamp}
\left(
0,\,
I_{e,\max},\,
T_e-F_e-D_e
\right)
\]

This has several useful consequences:

- if fees fund the entire security budget, issuance can fall to zero;
- if fees are low, issuance maintains baseline security;
- issuance cannot exceed its constitutional ceiling;
- no fiat-price oracle is required;
- the rule cannot be manipulated by reporting an external coin price.

I would initially study:

| Parameter | Starting research value |
|---|---:|
| Normal target at 50% effective stake | 0.75% annual security budget |
| Maximum ordinary annual issuance | 1.50% |
| Minimum annual issuance | 0% |
| Security-reserve target | 180 days of target security spending |
| Issuance adjustment smoothing | 90–180 days |
| Maximum change per epoch | Very small and protocol-bounded |

# 6. Gross issuance and net inflation are different

Gross issuance pays for security.

Net supply change also includes burns:

\[
\Delta S_e=I_e-B_e
\]

Therefore the network may be:

- inflationary;
- nearly supply-neutral;
- or net deflationary;

depending on actual issuance and burns.

It should not promise permanent deflation. The objective is sustainable security with predictable dilution, not a marketing slogan.

## Illustrative example

Suppose:

- total supply is 10 billion coins;
- target annual security budget is 0.75%, or 75 million;
- security-directed fees contribute 30 million;
- the reserve contributes 5 million;
- the protocol mints 40 million;
- congestion and penalty burns destroy 25 million.

Then:

```text
Gross issuance:     40 million
Burns:              25 million
Net supply increase: 15 million
Net inflation:       0.15%
```

The actual figures would emerge from usage and the deterministic policy.

# 7. Why some inflation is appropriate for a cash network

Low transaction fees and a strong security budget do not appear from nowhere.

Security is ultimately funded by some combination of:

- transaction users;
- coin holders through dilution;
- congestion rents;
- application-specific service buyers;
- accumulated reserves.

For a cash-oriented network, requiring every small payment to fund the full validator-security budget would make fees unnecessarily high.

The better split is:

```text
Bounded issuance
    → baseline consensus and assurance security

Cash and contract fees
    → marginal DA, proof, state, and ordering costs

Congestion rent
    → burn and/or replenish security reserve

Application escrows
    → AI workers, optional verifiers, and special assurance services
```

This lets a coffee payment pay principally for the marginal resources it consumes rather than an arbitrary share of the network’s total security expenditure.

Inflation is therefore a transparent security expenditure. It must remain bounded, predictable, and auditable.

# 8. Who receives newly issued coins?

A proposed starting allocation of the security budget is:

| Recipient | Share | Purpose |
|---|---:|---|
| Validator seats | 70% | Consensus, finality, PQ voting, required DA sampling |
| Independent execution auditors | 15% | Re-execution and proof-system defense in depth |
| Challenge and liveness reserve | 10% | Objective challenges, emergency fallback proving, incident response |
| Independent clients and formal assurance | 5% | Client diversity, formal verification, conformance infrastructure |

Direct economic services should primarily be user-funded:

- DA storage from DA fees;
- proof production from proof fees;
- state custody from state rent;
- AI computation from job escrows;
- optional application verification from assurance escrows.

Issuance should not subsidize unlimited commercial AI work or storage.

# 9. Rewards should not simply be proportional to stake

A purely linear reward system creates compounding concentration: the biggest validator attracts more stake, earns more rewards, and grows further.

The preferred system is **equalized stake-backed validator seats**:

- each active validator seat requires approximately one target amount of backing;
- excess stake does not give that seat unlimited additional voting weight;
- equal fulfilled duties earn approximately equal seat rewards;
- delegators behind a seat divide that reward;
- underbacked competent validators offer a higher reward per delegated coin.

Conceptually:

\[
R_j
=
R_{\text{seat}}
\cdot
\text{duty performance}_j
\]

rather than:

\[
R_j
\propto
\text{unlimited stake backing}_j
\]

Stake still provides economic security, but the reward system does not unnecessarily amplify operator concentration.

# 10. Fee burns

Not every fee should be burned. Providers must be paid.

A fee should be decomposed into:

\[
\text{Fee}
=
\text{service payment}
+
\text{security contribution}
+
\text{scarcity rent}
\]

| Fee component | Destination |
|---|---|
| DA service cost | DA publishers and custodians |
| Proof-generation cost | Accepted provers |
| State-rent cost | State custodians |
| Protected-ordering cost | Beacon and decryption participants |
| Consensus-security component | Security pool, reducing required issuance |
| Scarcity or congestion rent | Burn or security reserve |
| Optional priority payment | Mostly epoch-wide validator pool |

Burning only the scarcity component avoids pretending infrastructure providers can operate without compensation.

# 11. Slashing and supply

Slashing does not automatically mean all penalized coins are burned.

A valid slash can be divided:

```text
40% → valid challenger or reporter
40% → security reserve
20% → permanent burn
```

The exact percentages are policy parameters.

Only the burned portion reduces total supply. Redistribution does not.

Correlated, objectively malicious validator behavior may warrant much larger burn fractions than an ordinary service-bond failure.

# 12. Custom-token minting

The native coin has no mint capability. User-issued assets do.

A custom asset is controlled through a linear `MintCapability`:

```text
MintCapability {
    asset_id

    holder_policy
    remaining_mint_limit
    rate_limit
    valid_until

    required_credentials
    required_reserve_evidence
    delegation_depth

    revocation_policy
}
```

A token mint transaction:

1. consumes the current mint capability;
2. creates new Coin Cells or shielded notes;
3. creates a replacement capability with a reduced remaining limit;
4. updates the asset supply;
5. proves compliance with the mint policy.

For example:

```text
Old mint limit:      1,000,000
Minted now:             25,000
New mint limit:        975,000
```

A fixed-supply token permanently consumes and destroys its mint capability after initial issuance.

A stablecoin may retain an ongoing mint capability controlled by:

- a threshold organization;
- proof-of-reserve attestations;
- rate limits;
- explicit freeze and redemption policies.

The ledger can prove that the declared policy was followed. It cannot prove that an off-chain bank account contains the claimed funds unless it accepts external evidence providers.

# 13. Bridged tokens are not native issuance

A bridge may mint a representation of an external token only after verifying a corresponding lock or burn on the source chain.

That token receives a route-specific asset identifier:

```text
ExternalAssetId = H(
    source_chain
    source_asset
    bridge_channel
    security_profile
)
```

A bridge can never mint the native ActiveChain coin.

Wrapped-asset minting therefore has no effect on native inflation.

# 14. Private minting and private rewards

Private transfers can coexist with public supply auditing.

A mint transition may create a shielded output:

```text
Public:
    asset_id
    amount minted
    shielded commitment
    mint-policy proof

Private:
    recipient
    spending secret
    note randomness
    private metadata
```

For the native coin, epoch issuance remains publicly auditable. The recipient may be hidden or may immediately shield an aggregated reward.

The proof establishes that the hidden note contains exactly the authorized minted amount.

Thus:

- total supply remains public;
- reward ownership can be private;
- the mint policy remains verifiable;
- there is no hidden inflation.

# 15. Economic parameters must not be a governance mint switch

Economic parameters should live in a versioned `EconomicConstitution`:

```text
EconomicConstitution {
    target_stake_curve
    maximum_annual_issuance
    reserve_policy

    reward_allocation
    fee_allocation
    burn_policy
    slashing_distribution

    adjustment_limits
    smoothing_windows
}
```

A protocol upgrade may replace this constitution only with:

- a published specification;
- independent-client implementations;
- formal and economic simulations;
- a long activation delay;
- prospective effect only.

No on-chain vote or administrator should be able to mint an arbitrary one-off amount.

# 16. Required formal invariants

Before incentive testnet, the implementation should prove or mechanically check:

### Supply

- Only genesis and `EpochEconomicsTransition` can mint native coins.
- Native issuance never exceeds the configured cap.
- Reward outputs sum exactly to authorized issuance.
- A reward is paid no more than once.
- Burns reduce supply exactly once.
- Shielding and unshielding do not change supply.
- Staking and unbonding do not change supply.
- Bridge operations cannot alter native supply.

### Rewards

- Rewards correspond to fulfilled duties or an authorized public-goods allocation.
- Validator reward calculation is deterministic.
- Excess backing does not create excess seat rewards.
- Penalties are tied to objective evidence.
- Service fees cannot be paid twice.

### Governance

- No key possesses native mint authority.
- No emergency action can alter supply.
- Parameter changes cannot apply retroactively.
- The annual issuance ceiling cannot be exceeded by ordinary block production.

# 17. Concrete implementation order

Given the developer’s reported status, I would implement this next:

## Milestone 1 — Native supply

```text
NativeAssetDefinition
NativeSupplyState
GenesisAllocationRoot
CoinCell
SupplyRoot
```

## Milestone 2 — Protocol mint transition

```text
EpochEconomicsTransition
RewardAccumulator
RewardCredit
RewardClaim
BurnTransition
```

## Milestone 3 — Incentive accounting

```text
ValidatorDutyLedger
DADutyLedger
AuditDutyLedger
PenaltyLedger
SecurityFeePool
SecurityReserve
```

## Milestone 4 — Staking economy

```text
ValidatorCandidate
StakePosition
DelegationBasket
EqualizedBackingElection
UnbondingQueue
RewardDistribution
```

## Milestone 5 — Slashing

```text
EquivocationEvidence
FalseDAEvidence
InvalidShareEvidence
RoleSpecificServiceBond
SlashDistribution
```

## Milestone 6 — Economic simulation

Test:

- 20%, 40%, 50%, 60%, and 80% effective stake;
- low, medium, and high fee demand;
- coin-price shocks without using a price oracle in protocol;
- validator-cost changes;
- prolonged prover or DA shortages;
- stake concentration;
- mass unbonding;
- security-reserve depletion;
- maximum issuance-cap conditions;
- varying burn rates.

# Recommended monetary constitution

The clearest initial policy is:

> **A fixed and transparent genesis supply, no discretionary mint authority, a deterministic security budget, bounded adaptive issuance that fills only the gap not covered by fees and reserves, and public supply proofs for every epoch.**

In compact form:

\[
\boxed{
\text{Native minting}
=
\text{Genesis}
+
\text{Bounded protocol security issuance}
}
\]

\[
\boxed{
\text{Net supply change}
=
\text{Security issuance}
-
\text{Permanent burns}
}
\]

This gives ActiveChain low marginal cash fees without making security dependent on permanently high transaction fees, while preventing any validator, foundation, governance committee, or bridge from creating native coins at will.
