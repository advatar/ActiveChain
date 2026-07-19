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

## Completed milestone — local CI and authority kernel

Tracked by [GitHub issue #2](https://github.com/advatar/ActiveChain/issues/2).

- [x] Register a dedicated repo-scoped self-hosted runner on this Mac.
- [x] Route CI exclusively to the `activechain-ci` runner label and harden checkout behavior.
- [x] Verify the full CI workflow completes on the local runner.
- [x] Draft `P-020` principal lifecycle and `P-022` capability semantics.
- [x] Add canonical authenticator and capability schemas.
- [x] Implement bounded authenticator descriptors and validation.
- [x] Implement pure principal lifecycle transitions for creation, rotation, freeze, and recovery initiation.
- [x] Implement canonical capability grants and mechanically checked attenuation.
- [x] Publish deterministic authority vectors.
- [x] Add unit and property tests for lifecycle invariants and non-escalation.

## Active milestone — typed ObjectVM verifier and metered interpreter

Tracked by [GitHub issue #6](https://github.com/advatar/ActiveChain/issues/6).

- [ ] Draft the normative `P-050` ObjectVM instruction, typing, resource, control-flow, and metering semantics.
- [ ] Define bounded canonical bytecode-program, instruction, value-type, event, and execution-result schemas.
- [ ] Implement a `no_std` verifier for instruction/register bounds, forward-only targets, reachability, and complete returns.
- [ ] Enforce static register typing, definite initialization, and exact state agreement at control-flow merges.
- [ ] Enforce copyable scalars, affine capabilities, and exactly preserved linear objects.
- [ ] Implement a deterministic `no_std` reference interpreter with explicit inputs, checked arithmetic, and prepaid fixed gas.
- [ ] Return bounded typed outputs/events and total structural, verification, and execution failures.
- [ ] Add an executable Lean instruction/resource model and Rust differential fixture.
- [ ] Publish deterministic bytecode/execution vectors and comprehensive unit/property tests.
- [ ] Pass the full local-runner CI matrix.

## Completed milestone — bounded APL policy kernel

Tracked by [GitHub issue #3](https://github.com/advatar/ActiveChain/issues/3).

- [x] Draft the normative `P-023` Authorization Policy Language specification.
- [x] Define canonical policy, predicate, effect, and obligation schemas.
- [x] Implement bounded policy and authorization-request validation.
- [x] Implement a total `no_std` evaluator with default deny and forbid precedence.
- [x] Meter every rule and predicate without data-dependent short-circuiting.
- [x] Return bounded deterministic state-update and audit obligations.
- [x] Add an executable Lean reference model with core decision theorems.
- [x] Publish a deterministic APL policy/request/decision vector.
- [x] Add unit, property, and Rust-versus-model truth-table tests.
- [x] Pass the full local-runner CI matrix.

## Completed milestone — canonical sparse state tree and witnesses

Tracked by [GitHub issue #5](https://github.com/advatar/ActiveChain/issues/5).

- [x] Draft the normative `P-031` state-tree and witness specification.
- [x] Define domain-separated leaf, empty, internal-node, and final-root transcripts.
- [x] Implement the fixed-depth 16-way sparse SHAKE256/384 reference tree.
- [x] Bind the 4,096 logical partitions to the first 12 object-ID bits.
- [x] Define canonical state commitments and compressed proof schemas.
- [x] Generate and verify membership and non-membership proofs.
- [x] Reject malformed, non-canonical, wrong-kind, wrong-object, and tampered proofs.
- [x] Add an executable Lean path/fold model and Rust differential fixture.
- [x] Publish deterministic state-root and proof vectors.
- [x] Add unit and property tests for determinism, updates, proofs, tampering, encoding, and bounds.
- [x] Pass the full local-runner CI matrix.

## Completed milestone — versioned objects and atomic transitions

Tracked by [GitHub issue #4](https://github.com/advatar/ActiveChain/issues/4).

- [x] Draft `P-030` object semantics and refine the executable `P-010` boundary.
- [x] Define canonical object, owner, flags, version-reference, access-manifest, command, and receipt schemas.
- [x] Implement bounded object validation and exact checked one-step version updates.
- [x] Implement canonical sorted, duplicate-free access-manifest validation.
- [x] Implement bounded transfer transaction inputs and deterministic receipts.
- [x] Integrate committed APL control policies with access-confined atomic transfer execution.
- [x] Add an executable Lean version/atomicity model and cross-check fixtures.
- [x] Publish deterministic object, manifest, transfer, and receipt vectors.
- [x] Add unit and property tests for canonical encoding, confinement, authorization, versioning, and atomic abort.
- [x] Pass the full local-runner CI matrix.

## Deferred until the semantic kernel is stable

- Single-node semantic devnet.
- PQ transport, consensus, and data availability.
- Proof-carrying execution and privacy profiles.
- Protected ordering and the external compute plane.
