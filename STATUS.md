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

- [x] Add explicit PQ-only validation for consensus-critical suite positions.
- [x] Define suite activation and deprecation boundaries before live testnet use.
- [x] Document the day-one PQ-only admission policy and bounded future-suite migration process.
- [x] Specify migration behavior for validator, principal, credential, transport, and protected-envelope keys.
- [x] Specify the day-one suite and bounded migration requirement for each key class in the PQ policy matrix.
- [x] Add deterministic migration vectors and rejection tests.
- [x] Freeze a PQ migration-window vector and test half-open activation/deprecation boundaries.
- [x] Do not describe consensus, threshold encryption, or clients as quantum-safe until their implementations pass these gates.
- [x] Add a canonical height-bounded PQ migration window primitive and boundary tests.
- [x] Add a canonical ML-DSA-44-bound validator vote primitive for the future BFT boundary.

ActiveChain is PQ-by-construction from its first protocol release. Migration windows exist for
algorithm versioning and deprecation, never as permission to ship a classical safety dependency.

## Active milestone — PQ validator epochs and quorum certificates

Tracked by [GitHub issue #11](https://github.com/advatar/ActiveChain/issues/11).

- [x] Define bounded canonical validator sets and epoch identity.
- [x] Bind quorum certificates to a Merkleized raw ML-DSA vote-set root.
- [x] Enforce overflow-safe two-thirds stake thresholds.
- [x] Add canonical vectors and malformed/under-threshold rejection tests.
- [x] Add a frozen QC stake-threshold vector with deterministic acceptance and rejection coverage.

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
- [x] Add configured peer discovery, authenticated connection handshakes, reconnects, bounded queues, rate limits, and backpressure.
  - [x] Add bounded endpoint configuration, retry/backoff connection attempts, per-peer receive rate limits, and unreachable-peer reporting.
  - [x] Add challenge-based ML-DSA peer handshakes with bounded framing and loopback verification.
  - [x] Add partition, replay, dropped-vote, and late-recovery multi-validator rehearsal evidence.
  - [x] Add bounded reconnect retry and peer-directory replacement APIs.
  - [x] Require a matching authenticated handshake during reconnect before accepting the socket.
  - [x] Provide an authenticated round helper that fans out canonical proposal and vote messages through the peer directory.
- [x] Activate validator-set and staking transitions only through finalized consensus state.
  - [x] Bind the active validator-set root into finalized epoch transitions and durable consensus snapshots.
  - [x] Gate validator-set replacement on a finalized activation height and atomically update the engine root/key set.
- [x] Implement erasure-coded data availability, commitments, sampling, and authenticated snapshot distribution.
  - [x] Add bounded Reed–Solomon shard construction/reconstruction with SHAKE commitments and deterministic sampling.
  - [x] Add authenticated distributed snapshot serialization, reconstruction, and restart tests.
- [x] Add ML-KEM protected transaction submission without classical confidentiality dependencies.
  - [x] Add reviewed RustCrypto ML-KEM-768 encapsulation/decapsulation boundary and tamper tests.
  - [x] Bind protected payload confidentiality and integrity to ML-KEM shared keys and associated data.
  - [x] Add canonical protected-envelope serialization and runtime admission of authenticated payloads.
- [x] Integrate transparent proof-carrying ObjectVM execution into block admission and finalization.
  - [x] Add canonical replay-verifiable execution evidence with program verification and result matching.
  - [x] Add consensus-runtime admission validation for replay-verifiable execution evidence.
- [x] Ship genesis, validator, and wallet CLIs plus an indexer, metrics, alerts, and operator documentation.
  - [x] Add a canonical genesis generator CLI for reproducible validator manifests.
  - [x] Add thread-safe validator proposal/vote/finality/rejection metrics snapshots for local readiness checks.
  - [x] Expose metrics snapshots in stable Prometheus text format for operator alerts.
  - [x] Add deterministic `validator-node ... <index> --once` execution for process-level round rehearsals.
  - [x] Publish the operator runbook and release-gate thresholds in `docs/testnet-operations.md`.
  - [x] Add a deterministic ML-DSA-44 wallet identity CLI for local testnet operators.
  - [x] Add a deterministic finalized-snapshot indexer CLI for operator state ingestion.
- [x] Pass multi-process Byzantine, restart, partition, and sustained-load testnet rehearsals on the local runner.
  - [x] Launch three genesis-bound validator-node processes and verify deterministic signer derivation, metrics, and persisted snapshots.
  - [x] Require ML-DSA verification on inbound validator socket sessions before accepting consensus frames.
  - [x] Wire genesis-bound authenticated session handling into the validator-node accept loop.
  - [x] Return a signed vote from authenticated proposal-serving sessions for scheduled fan-in.
  - [x] Add proposer-side round coordination that broadcasts, receives, and admits peer votes.
  - [x] Validate peer ID/address/key tuples through a canonical endpoint constructor.
  - [x] Run a spawned three-process authenticated quorum round with returned votes and finalized height.
  - [x] Restart a live validator from its persisted snapshot and verify listener recovery.
  - [x] Inject an oversized Byzantine frame into a live validator and prove quorum still finalizes.
  - [x] Probe live partition (socket refusal), restart the validator, and verify reconnect reachability.
  - [x] Sustain a 32-connection oversized-frame burst without disrupting authenticated quorum finality.
  - [x] Make peer discovery return only sockets that completed the authenticated ML-DSA handshake.
  - [x] Exercise a live TCP handshake and consensus frame end-to-end before service admission.
  - [x] Prove three independently signed validator votes reach a receiver over authenticated TCP and finalize a QC.
  - [x] Run a 16-round sustained quorum rehearsal with monotonic leader finality and zero leader rejections.
  - [x] Remove failed sockets during best-effort broadcast so one dead peer cannot stall remaining fan-out.
- [x] Update and push the landing page at each completed launch milestone.

## Planned milestone — P-051 immutable ObjectVM packages and upgrade model

Tracked by [GitHub issue #9](https://github.com/advatar/ActiveChain/issues/9).

- [x] Define bounded immutable package and module manifests around verified ObjectVM programs.
- [x] Bind package identity to canonical bytecode and manifest commitments.
- [x] Validate entry-point, import, and upgrade constraints without ambient state.
- [x] Publish deterministic package vectors and unit/property tests.
  - [x] Freeze a canonical package-manifest vector with malformed entry-point rejection coverage.
- [x] Pass the full local-runner CI matrix.
- [x] Update the landing page to reflect the completed milestone and next testnet gate.

## Active milestone — native PQ cash plane and accountable verifier economy

Tracked by [GitHub issue #14](https://github.com/advatar/ActiveChain/issues/14).

- [x] Implement canonical native-asset, genesis-allocation, Coin Cell, transfer, mint, burn, and supply schemas.
- [x] Restrict native creation to one-time deterministic genesis allocation and bounded epoch security issuance; reject discretionary mint paths.
- [x] Track genesis supply, cumulative security issuance, cumulative burn, circulating supply, locked/staked supply, security reserve, and last settled epoch.
- [ ] Ensure reward credits/redemptions and shielding/unshielding never mint native value twice.
- [x] Route verifier reward redemption through an explicit pool-owned Coin Cell transfer intent.
- [x] Derive domain-separated Coin Cell identifiers, Coin Cell set roots, supply roots, and genesis allocation roots.
- [x] Implement a pure `no_std` native-money transition kernel outside ObjectVM.
- [x] Prove no double spend, checked value conservation, issuance-only minting, explicit burn accounting, and fee-reserve ownership.
- [x] Publish a frozen native-money vector and unit/malformed-input tests.
- [ ] Implement `CashTransferV1` and deterministic cash batches with fixed resource charging.
- [ ] Add PQ payment sessions and compact authorization-key references.
- [ ] Separate persistent canonical payment intents from short-lived PQ authorization witnesses.
- [ ] Add partitioned Coin Cell state, input locks, parallel execution, and conflict fallback.
- [ ] Implement the transparent specialized CashAIR and direct-reexecution comparison.
- [ ] Add the cash-specific capacity and fee market, refundable deposits, sponsorship, and paymasters.
- [x] Implement the first accountable verifier-duty kernel: role-scoped bond lots, one-shot assignments, fixed rewards, receipt validation, and bounded objective penalties.
- [ ] Add random audit assignments and commit/reveal challenge rewards without passive-verifier inflation.
- [x] Add deterministic one-shot challenge assignments and bounded challenge reward resolution.
- [x] Add deterministic fee quotes from base, resource, and congestion components.
- [ ] Build a reproducible proof-finalized cash throughput benchmark with real PQ, DA, state, and proof work.
- [ ] Pass the full local-runner CI matrix.
- [ ] Update and push the landing-page roadmap at each completed major milestone.

## Planned milestone — `did:activechain` identity method

- [x] Freeze the method-specific identifier, PQ verification methods, resolver boundary, and
  finalized lifecycle operations in `spec/protocol/P-095-activechain-did-method.md`.
- [ ] Implement canonical DID controller records and resolver responses.
- [ ] Add ML-DSA rotation, ML-KEM agreement, SLH-DSA recovery, deactivation, and DID test vectors.
- [ ] Add ENS alias records without treating ENS control as protocol authorization.
- [ ] Add EUDI Wallet interoperability for OpenID4VCI/OpenID4VP and mdoc/VC presentations.

## Active milestone — OpenWallet-aligned ActiveChain wallet

- [x] Add `activechain-wallet-core` with policy-gated Coin Cell intents and deterministic fee checks.
- [x] Add a deterministic ML-DSA testnet wallet CLI for operator/genesis identity derivation.
- [ ] Add encrypted PQ keystore, ML-DSA/ML-KEM key lifecycle, DID resolution, and recovery.
- [ ] Add CLI adapter for testnet transfer, verifier bonding, duty receipts, and reward redemption.
- [ ] Add OpenWallet credential and application-session adapters.
- [x] Freeze the first-testnet wallet/operator contract in `spec/protocol/P-100-testnet-wallet-operator.md`.
- [x] Publish the first-testnet release checklist and explicit transaction-ingress blockers.

## Planned milestone — mobile wallet shells

- [x] Freeze the shared-core/native-shell boundary in `docs/mobile-wallet.md`.
- [ ] Publish versioned Rust FFI types and golden vectors.
- [ ] Build iOS and Android local three-validator prototypes.
- [ ] Complete secure-storage, recovery, and mobile signing audits.

## Active milestone — dBrowser verifier compatibility

- [x] Freeze envelope type/version/body-length/trailing-byte rules in `P-110`.
- [x] Publish the machine-readable `testing/vectors/manifest-v1.json` index.
- [ ] Add complete envelope/commitment hashes for every published vector.
- [ ] Implement a bounded language-neutral verifier API and structured failure codes.
- [ ] Add malformed/tampered/wrong-version/trailing-byte fixtures to CI.
- [ ] Freeze light-client finality, checkpoint, state-sync, DA, and upgrade requirements.
- [x] Add a local manifest checker for vector hashes and malformed fixtures.
