# ActiveChain work-proof verifier

This crate is the stateful verification boundary for `pow.actum.network` work claims.

It verifies a canonical `WorkProofReceiptEnvelopeV1` against an operator-pinned RISC Zero image,
connects the exact telemetry epoch anchor to finalized Actum state through an accepted chained
trust bundle, and then atomically registers every class-neutral usage nullifier. A claim is verified
only when relation, anchor, and usage verification all succeed.

`actum-work-proof-verifier` is the bounded stateless subprocess used for relation verification. It
does not manage trust bundles, verify finality, or mutate the usage registry. The parent service
enforces request and response limits, a hard timeout, and fail-closed child handling.

The durable registry is a single-writer service resource. Deploy exactly one stateful admission
service for each registry file. Multiple stateless relation-verifier subprocesses may run in
parallel. Exact retries of the same derived claim are idempotent; reuse by another claim rejects the
entire nullifier set.

See `docs/POW_APP_INTEGRATION_V1.md` for the application-facing contract and Preview rules.
