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

## Where the implementation has outrun this model

`admit` models issuance as one atomic step: check admissibility, advance `issued`, record the
reference. The runtime no longer works that way, and the model has no counterpart for the states it
now passes through:

- **Reservation before settlement.** A durable record exists before any transfer is attempted, so a
  grant can be *taken* without being *issued*. `Admissible` has no notion of a reservation, and
  `issued` advances only in the model's single step.
- **Multi-cell grants.** A grant delivers `cells_per_grant` Coin Cells as separate transfers under
  derived per-cell references. The model has one reference and one amount per accepted issuance.
- **Completion.** Quota is consumed only once every owed cell has settled. The model has no
  incomplete state, so it cannot express the property that a half-delivered grant spends nothing.
- **Recovery.** Startup reconciliation replays or closes open grants. The model has no restart.

Two consequences worth stating plainly. First, `exactly once` still holds at the grant reference:
per-cell references are consumed by the operator settlement journal, not by `acceptedReferences`.
Second, `monotonic limits` survives an upgrade only because records written before multi-cell grants
migrate as complete single-cell grants (`required_cells = 1`, `delivered = [transaction]`). Were
they migrated as incomplete, a counter that had advanced would retreat across a restart, violating
the invariant. That migration is therefore load-bearing for a proven property and must not be
removed as mere compatibility code.

Extending the model to cover reservation, partial delivery, and completion is outstanding work; the
runtime behaviour is currently defended by tests rather than proof.

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
