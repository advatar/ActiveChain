# ActiveChain work-proof verifier

This crate is the stateful verification boundary for `pow.actum.network` work claims.

It verifies a canonical `WorkProofReceiptEnvelopeV1` against an operator-pinned RISC Zero image,
connects the exact telemetry epoch anchor to finalized Actum state through an accepted chained
trust bundle, and then atomically registers every class-neutral usage nullifier. A claim is verified
only when relation, anchor, and usage verification all succeed.

`actum-work-proof-verifier` is the bounded stateless subprocess used for relation verification. It
does not manage trust bundles, verify finality, or mutate the usage registry. The parent service
enforces request and response limits, a hard timeout, and fail-closed child handling.

`actum-work-proof-json-verifier` is the external compatibility adapter for applications such as
ProofOfWork. It accepts one bounded `actum.work-proof.verify.request.v1` JSON object on stdin and
returns one `actum.work-proof.verify.result.v1` object. The request carries lowercase-hex canonical
public-claim and proof envelopes. Its closed result codes are `VERIFIED`, `INVALID`, `UNSUPPORTED`,
and `MALFORMED`; caller-provided trust or success fields are rejected.

The durable registry uses a dedicated OS-level lock file and reloads durable state under that lock,
so multiple admission-service processes may safely share one registry file. Multiple stateless
relation-verifier subprocesses may also run in parallel. Exact retries of the same derived claim are
idempotent; reuse by another claim rejects the entire nullifier set.

See `docs/POW_APP_INTEGRATION_V1.md` for the application-facing contract and Preview rules.
