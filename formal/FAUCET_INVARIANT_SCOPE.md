# Faucet invariant proof scope

The faucet model proves state-transition properties; it does not prove Sybil resistance of any
external challenge provider or the legal status of a testnet asset.

Required invariants:

- **Testnet identity:** every accepted grant carries the configured chain and genesis commitment.
- **Supply conservation:** cumulative grants never exceed the operator budget or the test asset's
  declared faucet allocation.
- **Exactly once:** a request reference and grant nonce can produce at most one accepted issuance.
- **Monotonic limits:** cooldown, lifetime, and global budget counters never decrease across a
  successful transition or restart.
- **Atomic restart:** replaying a durable journal from its last atomic record yields the same
  accepted/rejected state and next nonce.
- **Receipt binding:** a finalized receipt is accepted only when its transaction, owner, amount,
  asset, genesis, and finalized-height proof match the original grant.

Out of scope: availability, external identity uniqueness, challenge-provider honesty, and
production-value claims. Those remain explicit operational assumptions and launch gates.
