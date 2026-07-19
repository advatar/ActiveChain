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

## Completed milestone — typed ObjectVM verifier and metered interpreter

Tracked by [GitHub issue #6](https://github.com/advatar/ActiveChain/issues/6).

- [x] Draft the normative `P-050` ObjectVM instruction, typing, resource, control-flow, and metering semantics.
- [x] Define bounded canonical bytecode-program, instruction, value-type, event, and execution-result schemas.
- [x] Implement a `no_std` verifier for instruction/register bounds, forward-only targets, reachability, and complete returns.
- [x] Enforce static register typing, definite initialization, and exact state agreement at control-flow merges.
- [x] Enforce copyable scalars, affine capabilities, and exactly preserved linear objects.
- [x] Implement a deterministic `no_std` reference interpreter with explicit inputs, checked arithmetic, and prepaid fixed gas.
- [x] Return bounded typed outputs/events and total structural, verification, and execution failures.
- [x] Add an executable Lean instruction/resource model and Rust differential fixture.
- [x] Publish deterministic bytecode/execution vectors and comprehensive unit/property tests.
- [x] Pass the full local-runner CI matrix.

## Completed milestone — P-040 admission and single-node semantic devnet

Tracked by [GitHub issue #7](https://github.com/advatar/ActiveChain/issues/7).

- [x] Draft the public-development `P-040` envelope, fee-ticket, resource, validity, and nonce semantics.
- [x] Define bounded canonical action-envelope, fee-ticket, block, action-receipt, and block-receipt schemas.
- [x] Bind envelopes to chain, sender, payload commitment, validity, resources, fees, nonce channel, and authorization evidence.
- [x] Implement exact nonce advancement, replay/gap rejection, and one-shot fee-ticket consumption.
- [x] Apply canonically ordered admitted transfers with total receipts and no partial semantic effects.
- [x] Derive deterministic action IDs, block IDs, receipt roots, resource charges, and state-tree post roots.
- [x] Implement a pure `no_std` devnet chain kernel plus a minimal host executable.
- [x] Add an executable Lean nonce/replay model and Rust differential fixture.
- [x] Publish deterministic action/block vectors and comprehensive unit/property tests.
- [x] Pass the full local-runner CI matrix.

## Completed milestone — P-021 credentials and status-aware presentations

Tracked by [GitHub issue #8](https://github.com/advatar/ActiveChain/issues/8).

- [x] Draft credential, acceptance-policy, issuer, status, freshness, and presentation semantics.
- [x] Define bounded canonical credential, registry, and acceptance-policy schemas.
- [x] Add strict canonical Rust credential and registry types.
- [x] Implement a pure `no_std` verifier over explicitly preverified issuer and status evidence.
- [x] Bind subject, issuer, schema, time, issuance log, registry root, sequence, and freshness.
- [x] Produce typed facts safe to inject into the current APL request boundary.
- [x] Add an executable Lean acceptance model and Rust differential fixture.
- [x] Publish deterministic credential and status vectors.
- [x] Add comprehensive unit, property, and boundary tests.
- [x] Pass the full dedicated local-runner CI matrix.

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

- PQ transport, consensus, and data availability.
- Proof-carrying execution and privacy profiles.
- Protected ordering and the external compute plane.

## Active milestone — full PQ migration boundary

Tracked by [GitHub issue #10](https://github.com/advatar/ActiveChain/issues/10).

- [ ] Add explicit PQ-only validation for consensus-critical suite positions.
- [ ] Define suite activation and deprecation boundaries before live testnet use.
- [ ] Specify migration behavior for validator, principal, credential, transport, and protected-envelope keys.
- [ ] Add deterministic migration vectors and rejection tests.
- [ ] Do not describe consensus, threshold encryption, or clients as quantum-safe until their implementations pass these gates.
- [x] Add a canonical height-bounded PQ migration window primitive and boundary tests.
- [x] Add a canonical ML-DSA-44-bound validator vote primitive for the future BFT boundary.

ActiveChain is PQ-by-construction from its first protocol release. Migration windows exist for
algorithm versioning and deprecation, never as permission to ship a classical safety dependency.

## Active milestone — PQ validator epochs and quorum certificates

Tracked by [GitHub issue #11](https://github.com/advatar/ActiveChain/issues/11).

- [x] Define bounded canonical validator sets and epoch identity.
- [x] Bind quorum certificates to a Merkleized raw ML-DSA vote-set root.
- [x] Enforce overflow-safe two-thirds stake thresholds.
- [ ] Add canonical vectors and malformed/under-threshold rejection tests.

## Active milestone — deterministic multi-validator PQ runtime

Tracked by [GitHub issue #12](https://github.com/advatar/ActiveChain/issues/12).

- [x] Build an in-memory deterministic proposal and vote-collection runtime.
- [x] Form quorum certificates only after provider-backed vote verification.
- [x] Advance consensus state on finalized certificates.
- [x] Exercise duplicate, unknown, mismatched, and under-threshold adversarial cases.
- [x] Add canonical consensus snapshots for validator restart recovery.
- [x] Add canonical genesis configuration binding epoch, activation height, and validator-set root.

## Active milestone — PQ testnet launch readiness

Tracked by [GitHub issue #13](https://github.com/advatar/ActiveChain/issues/13).

- [x] Carry canonically encoded proposal, vote, and quorum-certificate bodies in authenticated peer frames.
- [x] Define canonical validator genesis entries binding ordered stake and fixed ML-DSA-44 public keys.
- [x] Bind the persistent validator service to genesis, authenticate sender-indexed peer messages, and save finalized snapshots.
- [x] Add a reviewed ML-DSA validator signer and authenticated local vote production from admitted proposals.
- [x] Broadcast complete authenticated consensus messages and enforce bounded peer event queues.
- [x] Run the complete proposal → vote → QC → finalization loop in the validator process and persist finalized state.
- [ ] Add configured peer discovery, authenticated connection handshakes, reconnects, bounded queues, rate limits, and backpressure.
  - [x] Add bounded endpoint configuration, retry/backoff connection attempts, per-peer receive rate limits, and unreachable-peer reporting.
  - [x] Add challenge-based ML-DSA peer handshakes with bounded framing and loopback verification.
  - [x] Add partition, replay, dropped-vote, and late-recovery multi-validator rehearsal evidence.
  - [x] Add bounded reconnect retry and peer-directory replacement APIs.
  - [x] Require a matching authenticated handshake during reconnect before accepting the socket.
  - [x] Provide an authenticated round helper that fans out canonical proposal and vote messages through the peer directory.
- [ ] Activate validator-set and staking transitions only through finalized consensus state.
  - [x] Bind the active validator-set root into finalized epoch transitions and durable consensus snapshots.
- [ ] Implement erasure-coded data availability, commitments, sampling, and authenticated snapshot distribution.
  - [x] Add bounded Reed–Solomon shard construction/reconstruction with SHAKE commitments and deterministic sampling.
  - [x] Add authenticated distributed snapshot serialization, reconstruction, and restart tests.
- [ ] Add ML-KEM protected transaction submission without classical confidentiality dependencies.
  - [x] Add reviewed RustCrypto ML-KEM-768 encapsulation/decapsulation boundary and tamper tests.
  - [x] Bind protected payload confidentiality and integrity to ML-KEM shared keys and associated data.
  - [x] Add canonical protected-envelope serialization and runtime admission of authenticated payloads.
- [ ] Integrate transparent proof-carrying ObjectVM execution into block admission and finalization.
  - [x] Add canonical replay-verifiable execution evidence with program verification and result matching.
  - [x] Add consensus-runtime admission validation for replay-verifiable execution evidence.
- [ ] Ship genesis, validator, and wallet CLIs plus an indexer, metrics, alerts, and operator documentation.
  - [x] Add a canonical genesis generator CLI for reproducible validator manifests.
  - [x] Add thread-safe validator proposal/vote/finality/rejection metrics snapshots for local readiness checks.
  - [x] Expose metrics snapshots in stable Prometheus text format for operator alerts.
  - [x] Add deterministic `validator-node ... <index> --once` execution for process-level round rehearsals.
  - [x] Publish the operator runbook and release-gate thresholds in `docs/testnet-operations.md`.
- [ ] Pass multi-process Byzantine, restart, partition, and sustained-load testnet rehearsals on the local runner.
  - [x] Launch three genesis-bound validator-node processes and verify deterministic signer derivation, metrics, and persisted snapshots.
  - [x] Require ML-DSA verification on inbound validator socket sessions before accepting consensus frames.
  - [x] Wire genesis-bound authenticated session handling into the validator-node accept loop.
  - [x] Return a signed vote from authenticated proposal-serving sessions for scheduled fan-in.
  - [x] Add proposer-side round coordination that broadcasts, receives, and admits peer votes.
  - [x] Validate peer ID/address/key tuples through a canonical endpoint constructor.
  - [x] Make peer discovery return only sockets that completed the authenticated ML-DSA handshake.
  - [x] Exercise a live TCP handshake and consensus frame end-to-end before service admission.
  - [x] Prove three independently signed validator votes reach a receiver over authenticated TCP and finalize a QC.
  - [x] Run a 16-round sustained quorum rehearsal with monotonic leader finality and zero leader rejections.
  - [x] Remove failed sockets during best-effort broadcast so one dead peer cannot stall remaining fan-out.
- [ ] Update and push the landing page at each completed launch milestone.

## Planned milestone — P-051 immutable ObjectVM packages and upgrade model

Tracked by [GitHub issue #9](https://github.com/advatar/ActiveChain/issues/9).

- [x] Define bounded immutable package and module manifests around verified ObjectVM programs.
- [x] Bind package identity to canonical bytecode and manifest commitments.
- [x] Validate entry-point, import, and upgrade constraints without ambient state.
- [ ] Publish deterministic package vectors and unit/property tests.
- [ ] Pass the full local-runner CI matrix.
- [ ] Update the landing page to reflect the completed milestone and next testnet gate.
