# Kani testnet-faucet proof scope

The production `activechain-rpc-server::faucet` admission helper has two Kani harnesses.
For arbitrary counters, limits, cooldown ages, and platform-sized counts they prove:

1. an accepted request is strictly below the recipient lifetime, source-window, and global-window
   limits and is outside the recipient cooldown; and
2. increasing every usage counter cannot turn an already rejected request into an accepted one.

Run the bounded proofs with:

```bash
cargo kani -p activechain-rpc-server --harness accepted_admission_is_strictly_within_every_limit
cargo kani -p activechain-rpc-server --harness increasing_usage_cannot_turn_a_rejection_into_acceptance
```

These are compositional arithmetic/control-flow results over the exact production helper. SHAKE256
collision and preimage resistance, trusted wall-clock progression, filesystem and `fsync` crash
semantics, transaction-ingress correctness, validator finality, and proof-system soundness remain
explicit external assumptions. Production RPC derives the abuse-control identity from the accepted
peer address rather than the request's client-selected challenge commitment. Runtime tests cover
every reservation and receipt write interruption, before/after-settlement uncertainty, atomic
snapshot replacement, checksum rejection, restart reconciliation, concurrent idempotency,
wrong-network rejection, cooldowns, and finalized receipt structure.

This proof does **not** establish end-to-end supply conservation or exactly-one finalized Coin Cell
issuance by itself. The runtime now writes a transcript-bound reservation before settlement and the
wallet/validator adapters make exact transaction submission idempotent, while finalized receipt
verification remains a separate requirement tracked by issue #167. The public faucet and in-app
funding control must remain disabled until all of that issue's proof obligations are discharged.
