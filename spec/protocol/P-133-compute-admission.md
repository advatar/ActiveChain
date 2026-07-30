# P-133 — Compute-job admission boundary

Status: normative v1 scope decision.

General AI and compute jobs are **not** consensus-state semantics in v1. A job result cannot be
made true merely by putting it in a block, and the base layer cannot canonically prove that an AI
answer is useful, safe, or beneficial. Making such claims consensus-critical would fail the
architecture admission test for bounded evaluation, deterministic refinement, and independent
review.

## v1 treatment

Applications may use ordinary escrowed objects and attestations for compute requests. The base
layer may commit:

- a canonical job identifier and input commitment;
- an escrow and expiry;
- a provider principal and capability scope;
- an output commitment;
- signed assurance claims with an explicit assurance class.

Those records settle payment and provenance. They do not make the output a protocol truth, and
consensus does not execute arbitrary model code or judge its quality.

The application-layer `ComputeEscrowV1` binds the job, chain, requester, provider, delegated
capability, input, asset, amount, expiry, and requester refund. `ComputeAssuranceStatementV1`
binds the exact escrow, evidence, output, provider, assurance class, optional verifier profile,
and attestation height. Its ML-DSA-44 envelope authenticates the provider claim; it does not prove
that the output is useful, safe, or correct.

## Future admission gate

A future compute version may add bounded job objects only after it publishes canonical encoding,
resource limits, deterministic execution semantics, compatibility/migration rules, positive and
negative vectors, a formal refinement model, and an independently implementable verifier. Each
assurance tier must state exactly what is proven (for example, reproducible execution) and what is
not proven (for example, usefulness or safety of an answer).

The reserved compute tags in P-131 remain rejected by v1 clients and cannot become active through
configuration alone.

The application crate exposes a `FutureComputeVerifier` interface only to freeze the eventual
independent boundary. Every invocation must carry explicit proof-byte and verifier-unit ceilings;
v1 consensus provides no implementation or dispatch path for this interface.
