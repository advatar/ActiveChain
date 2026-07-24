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

## Active release fix — Apple app icon catalogs

Tracked by [GitHub issue #147](https://github.com/advatar/ActiveChain/issues/147).

- [x] Add complete asset-catalog app icons for ActiveChain Wallet and Amber.
- [x] Configure both iOS targets to emit `CFBundleIconName = AppIcon`.
- [x] Add submission-oriented bundle validation that catches missing icon metadata.
- [x] Pass Wallet and Amber iOS/macOS builds and tests.
- [x] Commit, push, merge, and leave generated/user-specific files out of the change.

## Active developer setup — iOS wallet XCFramework

Tracked by [GitHub issue #129](https://github.com/advatar/ActiveChain/issues/129).

- [x] Document that the generated Xcode project requires an exact-HEAD Apple distribution.
- [x] Build and verify the local wallet XCFramework and arm64 simulator app from a clean checkout.
- [x] Preserve the shared Apple development-team ID in `project.yml` while keeping certificates,
  private keys, Xcode user data, and build state local.

## Active implementation — native macOS wallet

Tracked by [GitHub issue #132](https://github.com/advatar/ActiveChain/issues/132).

- [x] Audit and adapt shared SwiftUI wallet sources for macOS.
- [x] Add an XcodeGen macOS application target linked to the exact-HEAD wallet XCFramework.
- [x] Extend local build qualification to cover both macOS and iOS.
- [x] Add platform-aware tests and document macOS build, run, and signing behavior.
- [x] Pass formatting, script syntax, Swift tests, and both application builds.

## Active fix — universal macOS wallet distribution

Tracked by [GitHub issue #143](https://github.com/advatar/ActiveChain/issues/143).

- [x] Package arm64 and x86_64 Rust FFI code in each macOS XCFramework slice.
- [x] Require both macOS architectures in Apple distribution qualification.
- [x] Qualify the wallet with a generic unsigned macOS Archive.
- [x] Declare the generated iOS launch screen and pass iOS Archive validation.
- [x] Pass distribution consumers, app tests, and iOS/macOS build qualification.

## Active fix — wallet App Store version metadata

Tracked by [GitHub issue #145](https://github.com/advatar/ActiveChain/issues/145).

- [x] Define valid marketing and build versions for both wallet application targets.
- [x] Regenerate the Xcode project from the canonical XcodeGen source.
- [x] Verify iOS and macOS archives contain valid bundle version metadata.

## Active implementation — wallet Receive flow

Tracked by [GitHub issue #135](https://github.com/advatar/ActiveChain/issues/135).

- [x] Present receiving details from the shared macOS and iOS wallet interface.
- [x] Bind the receiving payload to the selected ActiveChain network.
- [x] Add QR, copy, share, and dismissal behavior.
- [x] Add unit coverage and pass macOS tests plus both application builds.

## Active deployment — Kanalen developmental RPC

Tracked by [GitHub issue #137](https://github.com/advatar/ActiveChain/issues/137).

- [x] Build and checksum a release bundle pinned to the deployed `main` revision.
- [x] Install a revisioned deployment on the Kanalen Mac without disturbing unrelated services.
- [x] Configure `rpc.kanalen.activechain.dev` with TLS 1.3 and automatic certificate renewal.
- [x] Keep validator, faucet, and metrics ports private.
- [x] Verify DNS, certificate identity, public TLS, existing HTTPS routing, and exposed ports.
- [x] Add a canonical operator path from genesis/finalized validator state to the durable RPC index,
  then start the backend, verify a framed status request, and rehearse restart recovery.

## Active deployment — persistent Kanalen chain

Tracked by [GitHub issue #154](https://github.com/advatar/ActiveChain/issues/154).

- [x] Run a persistent three-validator quorum from one immutable Kanalen genesis.
- [x] Ingest finalized validator state monotonically into the durable RPC index.
- [x] Manage validator, ingestion, and RPC processes with restart-safe LaunchAgents.
- [x] Reset only disposable Kanalen state and verify public RPC finality advances after restart.
- [ ] Connect Amber content retrieval and bonded submission only after verified finality is live.

## Active investigation — Aztec billboard parity

Tracked by [GitHub issue #17](https://github.com/advatar/ActiveChain/issues/17).

- [x] Inventory the Aztec billboard's functional, privacy, moderation, bridge, UX, test, and proof properties.
- [x] Map each property to the current ActiveChain implementation and identify missing protocol/runtime primitives.
- [x] Publish an ActiveChain-native architecture, feasibility verdict, implementation stages, and verification gates.
- [x] Verify the investigation artifacts, commit them on the isolated worktree branch, and push the branch.

## Active specification — Amber private imageboard

Tracked by [GitHub issue #53](https://github.com/advatar/ActiveChain/issues/53).

- [x] Extract Emerald's protocol ambitions, security boundaries, and unresolved areas as a benchmark.
- [x] Define an independent ActiveChain-native architecture with equivalent outcome-level goals.
- [x] Specify normative lifecycle, privacy, availability, moderation, economics, client, and recovery requirements.
- [x] Publish measurable formal-verification, adversarial-test, performance, audit, and launch gates.
- [x] Map the current vertical slice to staged implementation milestones and honest public claims.

## Active implementation — Amber native Apple application

Tracked by [GitHub issue #138](https://github.com/advatar/ActiveChain/issues/138).

- [x] Establish Amber as the product name while retaining Emerald only as a research benchmark.
- [x] Add one shared SwiftUI source set with native iOS and macOS application targets.
- [x] Implement bounded board, thread, and post presentation models plus an adaptive retro imageboard shell.
- [x] Add unit coverage for identifiers, bounds, ordering, and platform-neutral view state.
- [x] Feature Amber honestly as the first reference application on the ActiveChain landing page.
- [x] Document and pass reproducible iOS Simulator and macOS builds.

## Active implementation — Amber live RPC health

Tracked by [GitHub issue #149](https://github.com/advatar/ActiveChain/issues/149).

- [x] Add a native TLS-framed status client for the configured Kanalen RPC endpoint.
- [x] Strictly decode bounded status responses and reject incompatible protocol or schema revisions.
- [x] Present checking, verified, stale, degraded, unavailable, and incompatible states.
- [x] Refresh status on launch and on demand without blocking the Amber interface.
- [x] Add deterministic codec/state tests and pass native iOS and macOS builds.

## Active release fix — Amber iPad app icons

Tracked by [GitHub issue #150](https://github.com/advatar/ActiveChain/issues/150).

- [x] Add the required iPhone and iPad AppIcon renditions, including the 152×152 iPad icon.
- [x] Extend local release validation to reject bundles missing the compiled iPad icon metadata.
- [x] Pass native builds and validate the generated iOS application bundle.

## Active implementation — Amber bonded posting

Tracked by [GitHub issue #141](https://github.com/advatar/ActiveChain/issues/141).

- [x] Freeze distinct post-fee, refundable-bond, maximum-slash, and terminal-outcome semantics.
- [x] Add a fail-closed client quote and moderation settlement model with conservation tests.
- [x] Present the locked bond, moderation risk, and refund conditions in the native composer.
- [x] Keep emergency hiding separate from final economic slashing and document appeal requirements.
- [x] Pass native iOS and macOS tests, commit, push, and merge the qualified change.

## Active fix — Amber network refresh feedback

Tracked by [GitHub issue #152](https://github.com/advatar/ActiveChain/issues/152).

- [x] Make network-status refresh activity immediately visible.
- [x] Prevent overlapping status requests and report completed checks.
- [x] Add refresh-state unit coverage and pass Amber Apple qualification.

## Active fix — Amber composer board selection

Tracked by [GitHub issue #158](https://github.com/advatar/ActiveChain/issues/158).

- [x] Add an explicit board picker to the bonded-post composer.
- [x] Preserve an existing board selection and expose the live-submission gate.
- [x] Add readiness tests and pass native iOS and macOS qualification.

## Active implementation — private billboard native-token vertical slice

- [x] Make the live-process quorum rehearsal wait for validator readiness and exercise two-chain finality instead of relying on fixed startup sleeps (GitHub issue #45).

Tracked by [GitHub issue #27](https://github.com/advatar/ActiveChain/issues/27).

- [x] Specify canonical billboard configuration, permit, post, moderation, and proof statements.
- [x] Implement bounded cooldown, save-up, screening, penalty, dummy-post, and withdrawal semantics.
- [x] Add verifier-issued evidence and atomic senderless action, nullifier, successor, fee, and public-output admission.
- [x] Add encrypted permit delivery plus wallet discovery, spend tracking, and restart recovery.
- [x] Exercise the complete shield, discover, post, restart, and withdraw lifecycle with adversarial tests.
- [x] Pass repository quality gates, commit the isolated changes, push, and open a draft PR.

## Active implementation — ActiveChain PQ-ZK v1

Tracked by [GitHub issue #31](https://github.com/advatar/ActiveChain/issues/31).

- [x] Freeze a transparent STARK/FRI profile, transcript, parameters, proof envelope, and security assumptions.
- [x] Implement and verify the first real witness-hiding preimage relation with a pinned guest image,
  no trusted setup, no Groth16 receipt, and development receipts disabled.
- [x] Compile the complete private-billboard post and withdrawal relations into pinned guest images
  with canonical private inputs and public journals; tracked by GitHub issue #64.
- [x] Stabilize guest release builds so unrelated workspace changes cannot move pinned image IDs;
  tracked by GitHub issue #67.
- [x] Differentially test the proof relation against the private billboard reference verifier,
  including valid, invalid, substituted-image, substituted-journal, and replay cases.
- [x] Publish deterministic vectors, malformed/substitution/replay tests, and reproducible performance evidence.
- [x] Machine-check exact image/journal binding, fail-closed admission, and one-shot nullifier admission.
- [x] Machine-check billboard conservation, successor, cooldown/penalty, and admission-composition invariants.
- [x] Publish qualified formal-verification evidence and third-party-audit-pending status on an
  isolated landing-page branch and draft PR.
- [x] Pass all repository gates, commit, push, and open an isolated stacked draft PR.

## Active communication — why ActiveChain is a new L1

Tracked by [GitHub issue #42](https://github.com/advatar/ActiveChain/issues/42).

- [x] Publish a primary-source comparison with Ethereum, Aztec, Logos, Solana, Starknet,
  Cosmos SDK, and Polkadot.
- [x] Explain which combined protocol requirements motivate a coherent new L1 rather than an
  unchanged deployment on an existing chain, rollup, or appchain framework.
- [x] Publish the engineering, security, ecosystem, liquidity, and interoperability costs of that
  choice without superiority or first-to-market claims.
- [x] Pass the landing-page production build, changed-file lint/format checks, and responsive CSS review.
- [ ] Complete screenshot-based mobile and desktop review; the in-app browser runtime failed to
  initialize in the implementation session, so this remains an explicit PR review gate.

## Active launch gate — whole-system formal verification

Tracked by [GitHub issue #16](https://github.com/advatar/ActiveChain/issues/16).

- [x] Prove the initial wallet-agent HITL and replay properties in Tamarin.
- [ ] Prove consensus QC, chain-prefix finality, replay, equivocation, view-change, reconfiguration,
  and crash-recovery properties.
  - [x] Prove bounded authentication, replay, non-equivocation, quorum-intersection, and frontier-finality component lemmas.
  - [x] Prove arbitrary weighted-quorum intersection and the conditional no-conflicting-QCs
    composition theorem in Lean.
  - [x] Exhaustively model-check bounded parent/QC binding, durable locks, cross-view prefix
    finality, crash/restart, and one validator-root transition in TLA+.
  - [x] Implement and model parent/QC binding plus safe-vote, lock, and commit rules across rounds.
    - [x] Bind every non-genesis proposal to its parent digest and justifying QC in the canonical signed payload ([#25](https://github.com/advatar/ActiveChain/issues/25)).
    - [x] Enforce locked-branch safe voting and persist the highest locked QC across validator restart.
    - [x] Apply consecutive chained-QC commit rules and reject conflicting finalized prefixes.
    - [x] Cover valid chains, malformed/stale/conflicting proposals, serialization, and restart recovery with tests.
  - [ ] Prove any two finalized histories are prefix-comparable, including view changes, epoch
    changes, and restart recovery.
  - [x] Verify canonical signer ordering, vote-set-root recomputation, and checked stake arithmetic
    at the Rust QC boundary.
- [x] Prove abstract cash conservation, authorized issuance, burn, and reward no-double-mint properties in Lean.
- [ ] Refine the cash proof to signed, chain-bound intents, input authorization, atomic batches,
  one-shot sessions/nonces, finalized issuance, reward proofs, shielding, and crash-safe replay.
  - [x] Prove the target chain/sender/intent/signature/nonce/session/input admission predicate and
    atomic replay barriers in Lean.
  - [x] Replace authoritative bare-transfer ingress with a strict ML-DSA-44 envelope bound to the
    chain, sender, exact transfer, recipient, nonce, session, expiry, and consumed inputs.
  - [x] Derive authorization keys from finalized identity state and persist the cash ledger, nonce,
    session, and input-replay barriers in one crash-atomic state transition. The unkeyed legacy
    `PaymentSession` remains a local compatibility helper and is not accepted by network ingress.
    - [x] Require verified finalized principal/authenticator provenance for authoritative cash keys ([#29](https://github.com/advatar/ActiveChain/issues/29)).
    - [x] Canonically snapshot the ledger, key provenance, nonces, sessions, and input barriers.
    - [x] Persist successful authoritative admission atomically before acknowledgement and fail closed on corrupt state.
    - [x] Test rotation/provenance rejection, restart replay safety, corruption, and failed-write atomicity.
- [x] Prove DA reconstruction bounds and fail-closed light-client trust transitions in Lean.
- [x] Prove canonical envelope rejection, commitment binding, and FFI precondition invariants in Lean.
- [x] Prove bounded principal rotation/recovery/deactivation and direct-delegation attenuation properties.
- [x] Prove exact epoch/revision activation and retired-validator-set rejection in the abstract Lean model.
- [x] Implement and prove conformance for finalized epoch/revision authorization, exact activation,
  retired-set history, and revision-bound certificate admission.
  - [x] Implement canonical finalized upgrade authorizations, exact-height activation,
    revision-bound votes/QCs, bounded retired-root persistence, stale-certificate rejection, and
    atomic validator key/root replacement in Rust.
  - [x] Add an implementation trace or differential refinement from the Rust upgrade path to the
    Lean transition model, including the bounded retired-root exhaustion case.
    - [x] Emit matching Rust and Lean traces for unchanged, validator-set, protocol, combined, and rejected transitions ([#33](https://github.com/advatar/ActiveChain/issues/33)).
    - [x] Include exact-height, stale-context, retired-root, and bounded history-exhaustion cases.
    - [x] Freeze the trace and enforce byte-for-byte Rust/Lean comparisons in CI.
- [x] Prove the scoped PQ-session downgrade, context, key-confirmation, and bounded replay target in Tamarin.
- [x] Implement the modeled PQ transcript/session boundary and prove full agreement, secrecy under
  stated compromise assumptions, durable sequence handling, and parser conformance.
  - [x] Prove exact prior-event peer correspondence, first-message origin, and honest-session
    symbolic secrecy, and bind the session KDF to the complete signed transcript after a discovered
    cross-session alias counterexample.
  - [x] Implement that transcript/KDF/key-confirmation state machine in Rust with durable sequences
    and canonical parser/vector conformance.
    - [x] Replace the live challenge-only handshake with canonical chain/epoch/peer/suite/KEM transcript messages ([#35](https://github.com/advatar/ActiveChain/issues/35)).
    - [x] Derive keys from the complete transcript, authenticate both finishes, and verify responder confirmation.
    - [x] Persist accepted session IDs and protected-message sequences atomically across restart.
    - [x] Freeze parser/transcript vectors and test downgrade, alias, replay, corruption, and peer mismatch.
- [x] Prove canonical finalized-block composition: decode, authorization, execution, fees/supply,
  post-state root, DA commitment, proof evidence, and protocol revision all bind the same block.
  - [x] Prove the fail-closed composition contract, deterministic finalization, component mismatch
    rejection, and collision-conditional state/proof uniqueness in Lean.
  - [x] Exhaustively model-check the bounded proof-job pipeline with exact public-input binding,
    invalid/cross-job proof rejection, retry/timeout/backpressure, stale cleanup, deterministic
    sequential finalization, and one-time prover rewards in TLA+.
  - [x] Implement the typed Rust block/header and validator admission path that refines the complete
    predicate instead of finalizing an opaque digest, and persist proof jobs, acceptance, finality,
    and reward replay protection crash-atomically.
    - [x] Define canonical bounded block/header, proof statement, proof job, and finalized-block values ([#37](https://github.com/advatar/ActiveChain/issues/37)).
    - [x] Recompute authorization, execution, economics, state, DA, proof-input, revision, and header commitments at the admission boundary.
    - [x] Add a typed production proposal entry point and require the QC digest to equal the admitted canonical header digest.
    - [x] Persist jobs, retries/timeouts, accepted proofs, ordered finality, finalized block digests, and prover-reward replay state atomically.
    - [x] Freeze vectors and test every component mismatch, cross-job proof, restart, corruption, backpressure, and duplicate reward.
- [x] Prove the PQ-authenticated credential/capability/state-proof to APL decision to transition
  authorization chain, including multi-hop attenuation, revocation, budgets, and concurrency.
  - [x] Define canonical joined authorization evidence and verified-fact adapters ([#41](https://github.com/advatar/ActiveChain/issues/41)).
  - [x] Verify PQ actor/credential signatures, finalized issuance/status/state evidence, multi-hop attenuation, holder binding, and revocation.
  - [x] Derive the exact APL request from verified facts and bind its permit/obligations to the exact transition.
  - [x] Crash-atomically consume invocation replay, use/money/compute/rate budgets, and transition state under concurrent admission.
  - [x] Freeze vectors and test stale/revoked/amplified/substituted evidence, exhaustion, concurrent replay, restart, and corruption.
- [x] Complete APL evaluator, ObjectVM verifier/interpreter, state-tree, and codec refinement proofs;
  the current executable Lean tables cover only bounded semantic slices.
  - [x] Route each production boundary through an explicit pure semantic kernel and document the
    refinement relation ([#44](https://github.com/advatar/ActiveChain/issues/44)).
  - [x] Replace table-only APL evidence with general evaluator theorems and production differential tests.
  - [x] Prove verifier/interpreter agreement, whole-run determinism, gas accounting, and failure atomicity
    for ObjectVM, with executable conformance witnesses.
    - [x] Carry verifier-produced register/event certificates into production execution and reject any
      per-instruction runtime disagreement before charging or mutation ([#44](https://github.com/advatar/ActiveChain/issues/44)).
  - [x] Generalize state-tree path, membership, non-membership, and root-update proofs and compare them
    against the production implementation.
  - [x] Generalize canonical envelope and minimal-length decoding proofs and bind them to production
    encoder/decoder traces across every published schema.
  - [x] Freeze cross-language witnesses, publish the exact remaining assumptions, and pass all formal,
    workspace, lint, and applicable bounded-checking gates.
  - [x] Add seven compositional Kani harnesses over the production bytecode-verifier and ObjectVM
    helpers for bounded register/target admission, the complete resource-class table, prepaid gas,
    checked addition, and forward branch selection. Full verifier-to-interpreter composition and
    whole-run determinism remain outside this bounded result after the corresponding 180-second
    Kani queries timed out without a counterexample.
- [ ] Add TLA+ consensus/reconfiguration/crash models, Verus refinement proofs, and Kani bounded
  checks for decoders, arithmetic, persistence, FFI, and network admission.
  - [x] Pin TLA+ tools and exhaustively check the first finite consensus safety model on the local
    runner.
  - [x] Add a second finite TLA+ model for hostile proof-pipeline scheduling and exact proof-input
    binding; liveness remains excluded until honest-prover, delivery, and fairness assumptions are
    specified.
  - [x] Generalize reconfiguration to membership churn and multiple transitions, and add a fair
    timed liveness model before making liveness claims.
    - [x] Model two authorized membership transitions with validator joins, departures, and
      rejection of certificates from retired sets; tracked by GitHub issue #52.
    - [x] Preserve durable locks, quorum-certificate safety, and committed-prefix safety across
      view changes, crashes, restarts, and membership activation.
    - [x] Specify clocks, timeouts, honest-leader rotation, delivery/readiness assumptions, and
      explicit fairness sufficient for a bounded progress property.
    - [x] Freeze the safety and liveness configurations, publish the exact proof scope, and run
      both configurations in the formal CI gate.
  - [x] Add Verus refinement and Kani bounded-checking gates for the concrete Rust boundaries.
    - [x] Add the first Kani gate over the production canonical codec: seven bounded harnesses for
      strict round trips, truncation, trailing bytes, adversarial decode, length prefixes, raw
      reads, and bounded encoder writes.
    - [x] Add five Kani harnesses over the production verifier C ABI for null and oversized pointer
      rejection, exact safe-API refinement on inputs through nine bytes, strict error codes, and
      commitment-pointer preconditions; arbitrary foreign readable-memory validity and SHAKE256
      internals remain outside this bounded proof.
      - [x] Keep the verifier-FFI Kani shadow workspace synchronized with every production verifier
        API dependency and reject future manifest/source drift in preflight
        ([GitHub issue #117](https://github.com/advatar/ActiveChain/issues/117)).
    - [x] Add seven Kani harnesses over actual private production bytecode-verifier/ObjectVM
      predicates for exact bounded register and target checks, resource classification, gas
      prepayment, checked addition, and forward branch selection, backed by whole-entry-point Rust
      tests and an explicit record of the unproved full-interpreter timeout boundary.
    - [x] Prove checked fee totals, strict-quorum arithmetic, base-fee adjustment, supply equations,
      partition accounting, and capped issuance in Verus, with a locked finite parity executable
      against the production cash and consensus crates.
      - [x] Keep the isolated Verus production-parity lockfile synchronized and validate it
        offline before proof execution
        ([GitHub issue #119](https://github.com/advatar/ActiveChain/issues/119)).
    - [x] Move the verified arithmetic behind a shared production implementation or add an
      all-input refinement bridge, and extend Kani coverage to larger production schemas,
      persistence, commitment internals, and network admission.
      - [x] Centralize the cash/consensus checked arithmetic in a shared production module and
        add arbitrary-input property comparisons to an independent checked oracle; tracked by
        issue #56.
      - [x] Bound a representative larger canonical production schema with strict round-trip,
        truncation, substitution, and trailing-byte Kani harnesses.
      - [x] Bound durable snapshot framing/checksum/fail-closed behavior and commitment
        domain/input binding, retaining hash internals as an explicit assumption.
      - [x] Bound authenticated network frame length/layout and sequence admission, retain
        peer/version binding in production integration tests, and pin every new harness in CI.
- [x] Add implementation-trace and differential conformance checks for every proof domain.
  - [x] Inventory each formal artifact and bind it to a production trace, differential oracle, or
    explicit external-only boundary; tracked by GitHub issue #58.
  - [x] Freeze a canonical trace schema and reject missing, duplicate, reordered, or substituted
    inputs, decisions, state transitions, and commitments.
  - [x] Replay representative positive and negative traces across consensus, economics,
    authorization, execution, state, codec, identity, privacy, and availability domains.
  - [x] Pin the trace-conformance matrix and executable gate in self-hosted CI.
- [x] Run every Lean and Tamarin model on the self-hosted CI runner.
  - [x] Audit that every Lean source is reachable from the build root and every Tamarin theory is
    discovered by the formal gate; tracked by GitHub issue #60.
  - [x] Require every declared Tamarin lemma to be selected exactly once or listed as explicitly
    unproved, rejecting missing, duplicate, overlapping, and stale classifications.
- [x] Publish proof scopes, assumptions, counterexamples, and explicit unverified boundaries.
  - [x] Index every conformance-matrix domain to a published scope record; tracked by GitHub
    issue #62.
  - [x] Fail CI on missing or stale scope artifacts and require every explicit unproved target to
    remain discoverable from the index.
- [ ] Obtain independent external formal-methods review before any non-developmental launch claim.

## Completed milestone — local CI and authority kernel

Tracked by [GitHub issue #2](https://github.com/advatar/ActiveChain/issues/2).

- [x] Register a dedicated repo-scoped self-hosted runner on this Mac.
- [x] Route CI exclusively to the `activechain-ci` runner label and harden checkout behavior.
- [x] Verify the full CI workflow completes on the local runner.
- [x] Keep the Kanalen deployment workflow dispatch-only and startup-valid, pin its artifact action,
  and remove its temporary SSH key on every exit path.
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
- [x] Add and prove the initial Tamarin wallet-agent model: biometric-bound HITL approval, delegation sessions, and single-accept replay safety.
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

## Active milestone — Phase 4 privacy and protected ordering foundations

Tracked by [GitHub issue #18](https://github.com/advatar/ActiveChain/issues/18).

- [x] Implement the first bounded privacy-kernel slice.
  - [x] Define canonical shielded-note commitments, nullifiers, viewing capabilities, and
    shielded-transfer public inputs.
  - [x] Enforce fail-closed admission binding chain, anchor, asset, balance, nullifiers, outputs,
    fees, expiry, and proof public inputs.
  - [x] Reject duplicate and previously spent nullifiers with atomic application semantics.
  - [x] Publish deterministic vectors and unit, property, and malformed-input tests.
- [x] Add persistent nullifier storage and atomic shield/unshield cash-ledger integration.
- [x] Add domain pseudonym and private-credential presentation statements.
- [x] Add private-object transition statements and scoped disclosure semantics.
- [x] Add protected-envelope, committee, ordering, forced-inclusion, and public-lane isolation.
  - [x] Define bounded ML-KEM protected-submission and decryption/beacon committee values.
  - [x] Enforce post-lock commitment-only ordering and forced-inclusion deadlines.
  - [x] Prove by executable tests that protected-lane failure cannot block public-lane draining.
  - [x] Integrate threshold decryption shares, builder bids/bonds, networking, and persistence.
    - [x] Wrap Shamir shares for committee members with real ML-KEM-768 and require the declared
      threshold to reconstruct and authenticate protected payloads.
    - [x] Add bounded builder bids, locked bonds, objective settlement, and penalty accounting.
    - [x] Carry protected submissions, locks, shares, and ordered sets over authenticated peers,
      with canonical bounds, ML-DSA sender authentication, replay protection, and finalized
      chain/epoch/set validation.
    - [x] Persist protected queues, locks, shares, settlements, and replay barriers atomically with
      canonical cross-state validation and fail-closed restart loading.

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
  - [x] Re-ran both process-level and live TCP quorum rehearsals after the wallet/DA integration changes; finalized height and restart recovery remained stable.
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
  - [x] Exercise a funded canonical wallet transfer through the validator gateway with replay rejection.
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
- [x] Ensure reward credits/redemptions and shielding/unshielding never mint native value twice.
  - [x] Bind reward redemption and shield/unshield movements to one-shot source identifiers.
  - [x] Prove duplicate and cross-path replay rejection preserves supply and all owned state.
- [x] Route verifier reward redemption through an explicit pool-owned Coin Cell transfer intent.
- [x] Derive domain-separated Coin Cell identifiers, Coin Cell set roots, supply roots, and genesis allocation roots.
- [x] Implement a pure `no_std` native-money transition kernel outside ObjectVM.
- [x] Prove no double spend, checked value conservation, issuance-only minting, explicit burn accounting, and fee-reserve ownership.
- [x] Publish a frozen native-money vector and unit/malformed-input tests.
- [x] Implement `CashTransferV1` and deterministic cash batches with fixed resource charging.
- [x] Add PQ payment sessions and compact authorization-key references.
- [x] Separate persistent canonical payment intents from short-lived PQ authorization witnesses.
- [x] Add partitioned Coin Cell state, input locks, parallel execution, and conflict fallback
  ([GitHub issue #66](https://github.com/advatar/ActiveChain/issues/66)).
- [ ] Implement the transparent specialized CashAIR and direct-reexecution comparison
  ([GitHub issue #69](https://github.com/advatar/ActiveChain/issues/69)).
  - [x] Reproduce the private-billboard guest image IDs and keep the published relation fixtures
    valid against both reference and guest execution
    ([GitHub issue #120](https://github.com/advatar/ActiveChain/issues/120)).
    - [x] Prevent repeated reproducible guest builds from depending on a blocking Docker desktop
      credential helper
      ([GitHub issue #121](https://github.com/advatar/ActiveChain/issues/121)).
    - [x] Make Apple distribution qualification honor the exact configured Cargo target directory
      instead of reading stale default-target libraries
      ([GitHub issue #123](https://github.com/advatar/ActiveChain/issues/123)).
    - [x] Enforce the anchor RPC size invariant without failing workspace-wide strict Clippy
      ([GitHub issue #124](https://github.com/advatar/ActiveChain/issues/124)).
  - [x] Freeze canonical bounded public inputs, execution rows, partition-plan binding, trace
    commitment, malformed/substitution tests, and exact direct-reexecution comparison.
  - [x] Add a dedicated transparent STARK prover/verifier for row progression, outcome booleanity,
    failed-row atomicity, accepted/rejected counts, and pre/post Coin Cell root binding.
  - [ ] Add specialized SHAKE, ML-DSA, membership, consumption, value/fee arithmetic,
    session-budget, and authenticated partition-root transition constraints.
    - [x] Arithmetize bounded per-row input/output/fee conservation and rejected-row zeroing.
      - [ ] Arithmetize SHAKE, ML-DSA, authenticated membership/consumption, session budgets,
        and authenticated partition-root transitions.
        - [ ] Add authenticated Coin Cell membership, one-time consumption, and partition/global
          root transition constraints
          ([GitHub issue #76](https://github.com/advatar/ActiveChain/issues/76)).
          - [x] Define canonical count-bound per-partition authenticated roots and an ordered,
            partition-count-bound global partition root using the existing partition mapping.
          - [x] Add canonical row-level partition transition witnesses carrying the complete
            pre-root vector plus sorted local authenticated transitions for exactly touched
            partitions, with recomputed pre/post global roots.
          - [x] Replace whole-set-only evidence with a canonical sparse Coin Cell accumulator and
            locally verifiable membership/non-membership mutation witnesses.
          - [x] Arithmetize ordered mutation paths and bind their chained pre/post roots into
            CashAIR public inputs.
            - [x] Add authenticated-mode pre/post root public inputs and trace columns to the
              parent CashAIR STARK, with rejected-row stability and exact mutation-chain rows.
            - [x] Compose the authenticated parent proof with exactly one bounded SHAKE proof set
              per accepted row and reject missing, extra, or rejected-row SHAKE evidence.
            - [x] Add a bit-constrained SHAKE256/Keccak table for leaf, node, and root transcripts
              ([GitHub issue #78](https://github.com/advatar/ActiveChain/issues/78)).
              - [x] Add public-input-bound Keccak-f permutation proofs, SHAKE padding/absorption
                chaining, and differential leaf/node/root transcript tests.
              - [x] Batch path permutations and connect their exported digest tuples to ordered
                mutation-path rows with a sound cross-table argument.
                - [x] Commit one Keccak trace and bind every 24-row slot to its verifier-derived,
                  ordered pre/post state tuple through committed preprocessed columns; bind padded
                  slots to the zero-state permutation and reject tuple/order substitution.
                - [x] Derive the exact pre-leaf/path/root and post-leaf/path/root transcript sequence
                  from every ordered accepted mutation and verify it through the batched table.
                - [x] Benchmark and cap full-depth multi-mutation prover memory/time before enabling
                  authenticated SHAKE proofs at validator ingress.
                  - [x] Split authenticated paths into deterministic ordered STARK chunks with a
                    hard per-chunk Keccak-permutation cap before allocating traces.
                  - [x] Run the full two-row authenticated composite in optimized mode on the local
                    ARM64 release runner: 88.58 s proof/verification, 661,585,920-byte maximum RSS,
                    no swaps (2026-07-22).
                  - [x] Reject composites exceeding a fixed total Keccak-permutation budget before
                    parent or chunk proving begins.
      - [x] Complete bounded-session enforcement and its CashAIR binding
        ([GitHub issue #72](https://github.com/advatar/ActiveChain/issues/72)).
        - [x] Add canonical ML-DSA session-grant envelopes, persistent spend budgets, strict
          validator ingress, and crash-atomic budget consumption with transfer admission.
        - [x] Bind the exact runtime pre/post session-budget witness into specialized AIR range and
          monotonic-spend constraints
          ([GitHub issue #74](https://github.com/advatar/ActiveChain/issues/74)).
  - [ ] Add recursive microbatch, partition, cash-slot, and global-transition aggregation.
- [ ] Add the cash-specific capacity and fee market, refundable deposits, sponsorship, and paymasters.
- [x] Implement the first accountable verifier-duty kernel: role-scoped bond lots, one-shot assignments, fixed rewards, receipt validation, and bounded objective penalties.
- [ ] Add random audit assignments and commit/reveal challenge rewards without passive-verifier inflation.
- [x] Add deterministic one-shot challenge assignments and bounded challenge reward resolution.
- [x] Add deterministic fee quotes from base, resource, and congestion components.
- [ ] Build a reproducible proof-finalized cash throughput benchmark with real PQ, DA, state, and proof work.
- [x] Pass the full local-runner CI matrix.
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
- [x] Add the versioned OpenWallet credential and application-session adapter boundary (interoperability conformance remains).
- [x] Freeze the first-testnet wallet/operator contract in `spec/protocol/P-100-testnet-wallet-operator.md`.
- [x] Publish the first-testnet release checklist and explicit transaction-ingress blockers.

## Planned milestone — mobile wallet shells

- [x] Add compile-checked iOS and Android shell prototypes over the shared wallet core.
- [x] Scaffold testable iOS and Android wallet shells with local bridge mocks.
- [x] Expose a platform-neutral mobile bridge that keeps policy, transfer construction, and opaque keystore slots in Rust.

- [x] Freeze the shared-core/native-shell boundary in `docs/mobile-wallet.md`.
- [ ] Publish versioned Rust FFI types and golden vectors.
- [ ] Build iOS and Android local three-validator prototypes.
- [ ] Complete secure-storage, recovery, and mobile signing audits.
  - [ ] Replace local string-based bridge mocks with the versioned wallet ABI and exact canonical
    transfer review/sign/submit flows.
  - [x] Add production-quality native navigation, portfolio, activity, transfer review, agent
    approvals, identity, network health, empty/error/loading states, and accessibility coverage.
  - [ ] Bind iOS Keychain and Android Keystore callback providers without exposing plaintext keys.
  - [x] Compile, unit-test, launch, and screenshot-review both native applications against fixed
    device profiles.
  - [ ] Implement OpenWallet issuance/presentation request parsing, consent-bound sessions,
    credential selection, replay protection, and deterministic conformance vectors.
  - [x] Run the seven-step wallet acceptance rehearsal through three persistent validators,
    transaction ingress, faucet, RPC finality, replay rejection, and validator restart.
  - [x] Ship enforceable agent management across wallet core and native shells.
    - [x] Model agents as independently authenticated principals with bounded capabilities,
      budgets, expiry, pause, and finalized revocation state.
    - [x] Persist the local agent registry and replay state durably without storing agent or wallet
      secret keys.
    - [x] Distinguish same-team app-group transports, third-party protocol clients, remote agents,
      and device-managed network controls in the UI and documentation.
    - [x] Add native agent inventory, detail, pause/resume, revoke, pending-request, and risk-state
      flows with unit coverage.
    - [x] Document that arbitrary third-party app behavior is outside wallet authority; enforce
      ActiveChain actions at approval/signing and consensus boundaries instead of claiming OS-wide
      interception.
    - [x] Expose durable agent lifecycle/request operations through the wallet ABI and replace the
      native demonstration stores with that shared implementation.
      - [x] Link the generated Apple XCFramework into the iOS shell and persist lifecycle
        transitions through the canonical Rust registry ABI.
      - [x] Link the Android shell through a reproducible JNI/NDK bridge and replace its
        demonstration registry.
    - [x] Add safe iOS App Intents for agent discovery and navigation; keep capability grants,
      approvals, budget increases, revocation, and signing inside authenticated wallet flows.

## Active milestone — dBrowser verifier compatibility

- [x] Complete external digest anchor finalization and client verification
  ([GitHub issue #131](https://github.com/advatar/ActiveChain/issues/131)).
  - [x] Add bounded operator finalization and rejection operations without exposing public
    finalization authority over RPC.
  - [x] Bind finalized evidence to the existing offline verifier boundary.
  - [x] Expose a language-neutral verifier ABI and conformance coverage.
  - [x] Verify pending, finalized, rejected, tampered, wrong-network, and restart behavior.
- [x] Expose an idempotent, proof-bearing external digest-anchoring contract for MadeMark,
  including canonical single and Merkle-batch statements, durable submit/resolve state,
  independently verifiable finalized evidence, RPC operations, and deterministic vectors
  ([GitHub issue #122](https://github.com/advatar/ActiveChain/issues/122)).
- [x] Freeze envelope type/version/body-length/trailing-byte rules in `P-110`.
- [x] Publish the machine-readable `testing/vectors/manifest-v1.json` index.
- [x] Add complete envelope/commitment hashes for every published vector
  ([GitHub issue #116](https://github.com/advatar/ActiveChain/issues/116)).
- [x] Verify the checked-in DA proof and payload commitment fixture directly through the DA kernel.
- [x] Implement a bounded language-neutral verifier API and structured failure codes.
  - [x] Return canonical body metadata, required output length, commitment, failure offset, and
    machine-readable detail through a null-safe caller-owned C result descriptor.
  - [x] Add positive, short-buffer, malformed framing, type/version, null-pointer, and oversized
    conformance coverage without changing the legacy verifier entry points.
- [x] Add malformed/tampered/wrong-version/trailing-byte fixtures to CI.
- [x] Freeze light-client finality, checkpoint, state-sync, DA, and upgrade requirements.
- [x] Add a local manifest checker for vector hashes and malformed fixtures.
- [ ] Deliver the stable downstream integration contract required by dBrowser
  ([GitHub epic #86](https://github.com/advatar/ActiveChain/issues/86)).
  - [ ] Build a versioned verifier SDK for principals, capabilities, APL decisions, state
    witnesses, finalized blocks, receipts, and authorization chains
    ([GitHub issue #88](https://github.com/advatar/ActiveChain/issues/88)).
    - [x] Publish ABI, schema, and protocol revision queries plus an exact semantic Principal
      envelope verifier through matching Rust and C result codes.
    - [x] Add exact CapabilityGrant envelope and parent-child attenuation verification through
      matching Rust and C result codes.
    - [x] Add exact APL PolicyDecision envelope verification through matching Rust and C result
      codes.
    - [x] Add exact state membership and non-membership witness verification through matching Rust
      and C result codes.
    - [x] Add finalized-block header/QC verification against the exact validator genesis and
      ordered signed vote set through matching Rust and C result codes.
      - [x] Extract canonical execution-proof inputs and finalized-block headers from the
        validator runtime into the bounded shared `activechain-finality-types` crate without
        changing their registered tags, schemas, encoding, or digest domains.
    - [ ] Add receipt and joined authorization-chain verifiers with complete positive and
      malformed vectors.
      - [x] Verify canonical block receipts against a cryptographically verified finality bundle,
        exact receipt commitment, height, and pre/post state transition through matching Rust and
        C result codes.
      - [ ] Verify joined authorization chains.
        - [x] Publish bounded canonical whole-chain attenuation, finalized-height validity, root
          linkage, and leaf actor-binding verification through matching Rust and C result codes.
        - [ ] Join capability and actor signatures to principal controller keys proven against the
          finalized state root.
  - [x] Expose Coin Cell discovery, policy evaluation, canonical intents, approval-bound signing,
    secure-key callbacks, and submission through the wallet ABI
    ([GitHub issue #87](https://github.com/advatar/ActiveChain/issues/87)).
    - [x] Expose deterministic Coin Cell selection from a canonical bounded cell-set envelope
      through a null-safe C ABI with distinct payment and fee-reserve outputs.
    - [x] Expose pure spending-policy evaluation with exact 128-bit limits, daily accounting, and
      optional recipient pinning through the C ABI.
    - [x] Construct the exact canonical cash authorization request and intent identifier through a
      size-query C ABI without exposing secret material.
    - [x] Invoke opaque secure-key callbacks only over the canonical approval-bound signing
      transcript and verify the returned ML-DSA-44 signature before publishing an authorized
      envelope.
    - [x] Reverify authorized envelopes before forwarding their exact canonical bytes through an
      opaque caller-owned transport callback.
  - [x] Publish a proof-bearing development-network query/RPC contract
    ([GitHub issue #91](https://github.com/advatar/ActiveChain/issues/91)).
    - [x] Freeze canonical bounded RPC status, query, proof, page, and typed-error schemas.
    - [x] Expose chain identity, immutable genesis commitment, protocol/schema revisions,
      finalized height, supported proof kinds, health, and staleness.
    - [x] Serve proof-bearing state, action, and receipt queries over a bounded local network
      protocol with deadlines and pagination.
    - [x] Persist indexed finalized query material atomically and verify restart recovery.
    - [x] Add malformed/oversized/stale vectors and an end-to-end client query verified against
      finalized state.
    - [x] Add configurable operator RPC access economics
      ([GitHub issue #110](https://github.com/advatar/ActiveChain/issues/110)).
      - [x] Publish bounded canonical access terms, grants, authenticated requests, and typed
        access failures without changing proof semantics.
      - [x] Support backward-compatible free, operator-allowlisted, and prepaid metered modes.
      - [x] Bind grants and requests to the chain, operator, client PQ key, exact request,
        validity window, monotonic sequence, settlement reference, and purchased unit budget.
      - [x] Persist usage atomically before serving paid work and fail closed on replay,
        exhaustion, restart corruption, or failed persistence.
      - [x] Document operator configuration and settlement adapters, and test malformed, tampered,
        expired, wrong-context, replay, budget, restart, and free-mode vectors.
  - [x] Package an embeddable persistent light client
    ([GitHub issue #92](https://github.com/advatar/ActiveChain/issues/92)).
    - [x] Add fail-closed trusted-checkpoint bootstrap with explicit chain identity and
      weak-subjectivity bounds.
    - [x] Verify monotonic parent-linked finalized headers against the active validator set and
      immutable chain genesis.
    - [x] Verify finalized validator-set transitions and protocol upgrades while rejecting retired
      set reactivation and wrong revisions.
    - [x] Verify state, receipt, action, and data-availability proofs against the current finalized
      header.
    - [x] Persist all trust state crash-safely and cover stale, forked, corrupt, restart, bad-proof,
      bad-DA, retired-set, and wrong-revision vectors.
  - [x] Ship reproducible Apple artifacts and a machine-readable compatibility manifest
    ([GitHub issue #90](https://github.com/advatar/ActiveChain/issues/90)).
    - [x] Generate and drift-check the verifier and wallet C headers from their Rust ABI exports.
    - [x] Build macOS, iOS-device, and iOS-simulator static-library slices and package versioned
      verifier and wallet XCFrameworks.
    - [x] Emit deterministic artifact hashes and compatibility metadata covering source, ABI,
      schemas, protocols, slices, certification status, and upgrade policy.
    - [x] Add a clean Swift consumer smoke test and fail-closed compatibility validation.
    - [x] Document reproducible local and CI distribution qualification without implying an
      independent security audit.
  - [x] Stabilize browser/agent jobs, artifacts, evidence, manifests, and receipts
    ([GitHub issue #89](https://github.com/advatar/ActiveChain/issues/89)).
    - [x] Publish bounded canonical schemas for application manifests, artifacts, jobs,
      delegated actions, execution evidence, and application receipts.
    - [x] Bind every lifecycle value to chain identity, requester/executor authority, resources,
      fees, provenance, result commitments, validity windows, and replay domains.
    - [x] Implement deterministic job lifecycle validation covering acceptance, cancellation,
      timeout, completion, and exactly-once fee settlement.
    - [x] Add verifier-facing receipt validation and finalized RPC lookup bindings.
    - [x] Freeze positive and malformed vectors for substitution, authority amplification,
      duplicate/replay, invalid lifecycle, timeout, and settlement failures.
    - [x] Document the downstream integration boundary and compatibility revisions.
  - [ ] Pass downstream conformance against dBrowser while retaining the developmental and
    unaudited release status until the external security gate completes.
  - [ ] Consolidate verified release branches into `main`, retire superseded branches, and enforce
    a single active implementation branch per issue
    ([GitHub issue #125](https://github.com/advatar/ActiveChain/issues/125)).

## Planned milestone — external pre-launch security audit

No audit has been completed; requirements and scope are frozen in `docs/SECURITY_AUDIT.md`. The
wallet and all testnets remain explicitly developmental until this milestone completes.

- [x] Publish the pre-launch audit scope, auditor requirements, and launch gate in
  `docs/SECURITY_AUDIT.md`.
- [ ] Select an independent external blockchain/security firm with post-quantum and mobile
  expertise and freeze the audit commit.
- [ ] Audit Rust consensus, cash economics, replay protection, and state transitions.
- [ ] Audit PQ cryptography and ML-DSA/ML-KEM usage.
- [ ] Audit C ABI/FFI memory safety and native wallet integration.
- [ ] Audit iOS Keychain/Secure Enclave and Android Keystore handling.
- [ ] Audit OpenWallet interoperability and protocol conformance.
- [ ] Audit threat model, fuzzing, property tests, and validator/network abuse resistance.
- [ ] Remediate all findings or document explicitly accepted risks.
- [ ] Complete the firm's re-review of every fix.
- [ ] Publish the final report and remediation log in this repository.
