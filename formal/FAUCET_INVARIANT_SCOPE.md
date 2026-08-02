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

`formal/lean/ActiveChain/Faucet.lean` now machine-checks the pure transition core for testnet and
genesis binding, the faucet-allocation bound, exact issued-counter advancement, durable reference
consumption, replay rejection, and exact finalized-receipt binding. The executable runtime vectors
live in `testing/vectors/faucet-invariants-v1.tsv`, `faucet-finalized-funding-v1.tsv`, and
`faucet-funding-admission-v2.tsv`.

The model deliberately does not equate an in-memory `State` with a durable filesystem image.
Atomic replacement, checksum validation, restart recovery, and failpoint behavior remain runtime
properties until a refinement from the journal codec and write protocol is proved. Likewise,
`certificateVerified` represents the result of the separately qualified finality verifier rather
than assuming that a caller-set Boolean is sufficient in production.

The targeted runtime qualification covers every journal publication failpoint, replay and
concurrent duplicate submission, exact cooldown edges, recipient/source/global exhaustion, policy
tightening across restart, expiry, snapshot corruption, raw abuse-identifier non-persistence, and
the live Kanalen finalized owner Coin Cell proof. This is evidence for the composed implementation,
not a claim that the external assumptions above have been eliminated.

Out of scope: availability, external identity uniqueness, challenge-provider honesty, and
production-value claims. Those remain explicit operational assumptions and launch gates.
