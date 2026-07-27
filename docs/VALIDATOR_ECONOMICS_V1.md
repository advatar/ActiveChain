# Validator economics v1

The v1 development network uses the native ActiveChain asset for stake weighting. A validator's
effective weight is the finalized stake recorded in the validator set; application balances,
stablecoins, and off-chain collateral do not influence consensus weight.

## Invariants

- Stake weights are nonnegative and bounded by checked arithmetic.
- Quorum certificates use the exact finalized stake snapshot named by the epoch.
- A validator-set transition is authorized at one exact height and binds the next genesis
  commitment, ordered validator keys, and stake weights.
- Slashing and reward settlement are deterministic, one-shot, and cannot create native supply.
- A restart restores the same stake snapshot and replay state before accepting votes.

## Stablecoin collateral

Stablecoins may be native application assets, but v1 does not silently treat them as validator
security. A future stablecoin-secured profile must specify oracle/finality dependencies, reserve
haircuts, depeg handling, liquidation, cross-asset quorum arithmetic, and a governed activation
height. Until then, only native finalized stake is consensus-authoritative.

Any change to the weighting asset is a protocol upgrade, not an operator configuration toggle.
