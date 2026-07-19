# ActiveChain implementation status

This file tracks executable work derived from `BLUEPRINT.md` and `STACK.md`.

## Phase 0 — protocol foundation

- [x] Establish a pinned stable-Rust workspace with consensus-kernel quality gates.
- [x] Draft the initial normative specifications (`P-000`, `P-001`, and `P-010`).
- [x] Define the first canonical schema for protocol primitives and principals.
- [x] Implement `no_std`, safe-Rust protocol primitive types.
- [x] Implement a bounded canonical binary codec with strict trailing-data rejection.
- [x] Implement SHAKE256/384 domain-separated commitments.
- [x] Publish deterministic codec and commitment test vectors.
- [x] Add unit and property tests for round trips, malformed input, bounds, and domain separation.
- [x] Document the workspace layout and local verification commands.

Phase 0 bootstrap is tracked by [GitHub issue #1](https://github.com/advatar/ActiveChain/issues/1).

## Active milestone — local CI and authority kernel

Tracked by [GitHub issue #2](https://github.com/advatar/ActiveChain/issues/2).

- [x] Register a dedicated repo-scoped self-hosted runner on this Mac.
- [x] Route CI exclusively to the `activechain-ci` runner label and harden checkout behavior.
- [ ] Verify the full CI workflow completes on the local runner.
- [ ] Draft `P-020` principal lifecycle and `P-022` capability semantics.
- [ ] Add canonical authenticator and capability schemas.
- [ ] Implement bounded authenticator descriptors and validation.
- [ ] Implement pure principal lifecycle transitions for creation, rotation, freeze, and recovery initiation.
- [ ] Implement canonical capability grants and mechanically checked attenuation.
- [ ] Publish deterministic authority vectors.
- [ ] Add unit and property tests for lifecycle invariants and non-escalation.

## Queued authority-kernel milestones

- Define and implement the bounded APL policy kernel.
- Add a Lean reference model and differential vectors for authority semantics.
- Implement versioned objects, access manifests, and the reference transition function.

## Deferred until the semantic kernel is stable

- ObjectVM and bytecode verifier.
- Single-node semantic devnet.
- PQ transport, consensus, and data availability.
- Proof-carrying execution and privacy profiles.
- Protected ordering and the external compute plane.
