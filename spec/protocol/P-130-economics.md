# P-130 — ActiveChain v1 economic security model

Status: normative decision for the v1 protocol family.

## Decision

ActiveChain v1 uses a native staked asset for validator security. Validator seats are backed by
native stake, and protocol rewards are paid by a bounded, deterministic security budget.
Stablecoin-collateralised validator bonds are not the v1 consensus security model; stablecoins
remain application assets that may be used for fees, settlement, or regulated operator collateral
without becoming the chain's security root.

## Security and issuance

- Genesis issuance is explicit, reproducible, and immutable after genesis.
- Epoch settlement computes validator, availability, audit, and public-goods rewards
  deterministically from recorded duties and objective evidence.
- Issuance is limited to the epoch security-budget shortfall and the constitutional annual cap.
  Fees and burns reduce the shortfall; no administrator, validator, proposer, or foundation key
  can mint the native asset.
- Staking, vesting, escrow, and bonds change ownership or liquidity, not total supply.
- Reward credits are redeemable representations of already-issued value and cannot mint again.

## Validator admission and penalties

Validator admission requires native stake and the protocol's post-quantum identity and
availability requirements. Stake weight influences quorum safety and seat backing; reward amounts
are based on fulfilled assigned duties, not delegated stake gathered by an operator. Missed duties
lose rewards. Equivocation, false availability attestations, and signing an objectively invalid
finalized result are slashable under the evidence rules.

## Storage resources

P-070 fixes deterministic charged-byte accounting, pressure bands, prepaid active leases, and paid
renewable cold retention. Storage service payments go only to providers that satisfy assigned
custody and retrieval duties. Scarcity rent is burned or transferred to the security reserve so a
provider cannot capture the complete benefit of withholding its own capacity.

At critical storage pressure the protocol rejects non-system net state expansion. Governance and
operators cannot override that admission result by reporting different filesystem allocation.
Changing the logical charge schedule or qualified physical ceiling requires a new protocol profile
and fresh decentralisation qualification.

## Stablecoins and regulated profiles

Stablecoins may provide application-level payment and collateral rails, subject to issuer policy
and regulated admission profiles. A stablecoin issuer, custodian, or operator cannot acquire
consensus mint authority or alter validator-set safety by controlling redemption or freeze policy.

## Compatibility and rejected branch

The previously described stablecoin-secured-validator design is retained only as a rejected
research alternative. It is not a v1 configuration switch. Any future change to the security
asset requires a new protocol version, a new genesis commitment, and a fresh decentralisation and
capture-risk analysis; it cannot reinterpret v1 staking bytes.
