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
collision and preimage resistance, trusted wall-clock progression, source-commitment provenance,
filesystem and `fsync` crash semantics, transaction-ingress correctness, validator finality, and
proof-system soundness remain explicit external assumptions. Runtime tests cover atomic snapshot
replacement, checksum rejection, restart equivalence, idempotency, wrong-network rejection,
cooldowns, and finalized receipt structure.

This proof does **not** yet establish end-to-end supply conservation or exactly-one finalized Coin
Cell issuance. Those require the faucet-authorized cash transition and finalized receipt verifier
that are still tracked by issue #167. The public faucet and in-app funding control must remain
disabled until those links exist and their proof obligations are discharged.
