# ActiveChain implementation status

This file tracks executable work derived from `BLUEPRINT.md` and `STACK.md`.

## Kanalen integrator onboarding

Tracked by [GitHub issue #815](https://github.com/advatar/ActiveChain/issues/815).

- [x] Publish one self-contained guide for pinning and probing the TLS RPC, building and creating
  the developmental wallet, requesting faucet funding, verifying balance/finality, and respecting
  the current spending, access, framing, and rate-limit boundaries.
- [x] Link the guide from the documentation index and Track 0 plan, then validate its paths, links,
  exact public-network constants, and focused onboarding commands.
- [ ] Publish a signed external wallet distribution and a public ordinary-transfer submission path
  before claiming that an outside developer can install and spend unaided; the onboarding audit
  confirmed both remain unavailable in the current reference surfaces.

## ActiveBridge Thunes connector qualification

Tracked by [GitHub issue #803](https://github.com/advatar/ActiveChain/issues/803).

- [x] Implement and locally qualify the Thunes connector and connector-host policy integration.
- [x] Isolate the formal-model TLA+ Docker invocation from the macOS runner keychain without
  initializing the unrelated RISC0 builder.
- [ ] Pass one new exact-SHA full deterministic-kernel gate before moving PR #804 out of draft.

## Active gate recovery — Republished TLA+ 1.8.0 asset

Tracked by [GitHub issue #797](https://github.com/advatar/ActiveChain/issues/797).

- [x] Align both TLA runners and both proof-scope records with the current official v1.8.0
  release-asset digest while preserving the four-location drift regression.
- [x] Pass both TLA suites and the exact complete deterministic-kernel gate on `0ae3ae67`
  ([run 31515122255](https://github.com/advatar/ActiveChain/actions/runs/31515122255)).
- [ ] Merge to `main` and verify reachability from `origin/main`.

## Reusable finalized-payment verifier service

Tracked by [GitHub issue #786](https://github.com/advatar/ActiveChain/issues/786).

- [x] Define a bounded, versioned application authorization request that composes canonical payment
  intent, finalized settlement, finality bundle, and block receipt verification.
- [x] Implement an authenticated HTTP verifier service with trusted-genesis configuration,
  application/audience/context binding, health/readiness, and fail-closed errors.
- [x] Add malformed, substitution, finality, replay-binding, and transport qualification tests plus
  a Docker-local service image for dependent applications.
- [x] Integrate the service with ZeroK and pass targeted service, Docker, and end-to-end gates.
- [x] Pass the complete deterministic-kernel gate locally against `150bf56d` and merge to
  `main`, and verify reachability from `origin/main`.

## Active initiative — Verifiable developer telemetry

- [ ] Deliver the protocol and integration contract promised by `pow.actum.network`
  ([GitHub initiative #771](https://github.com/advatar/ActiveChain/issues/771)).
  - [ ] Freeze canonical event, epoch, policy, proof, disclosure, and verification contracts plus
    app-developer documentation and vectors
    ([GitHub issue #772](https://github.com/advatar/ActiveChain/issues/772)).
    - [x] Publish the normative boundary, threat model, app integration guide, JSON schema, fixture,
      implementation-status matrix, and deterministic CI consistency check.
    - [x] Add generated canonical binary/signature vectors with the implementing collector/proof
      crates, then pass the exact full deterministic-kernel gate before integration.
  - [x] Implement the permissioned local collector and trust layer (#773; qualified candidate
    `daf2b499` in split deterministic-kernel run `31346478760`).
    - [x] Add shared no-std canonical event/epoch primitives and frozen Merkle domains.
    - [x] Replace JSON commitments with canonical envelopes, monotonic duration, durable sequence allocation, and prior-epoch linkage.
    - [x] Publish deterministic canonical/signature vectors.
    - [x] Pass the exact full gate.
  - [x] Package telemetry, attribution, prove-work, and verify-work plugin/MCP capabilities (#774;
    qualified candidate `91abacd0` in split deterministic-kernel run `31350660653`).
    - [x] Add portable Agent Plugins 1.0.0 and Codex manifests plus the telemetry skill.
    - [x] Add bounded, capability-scoped telemetry and work MCP tools with durable idempotency.
    - [x] Add adversarial authorization, race, replay, wrong-chain, timeout, malformed-response, and redaction tests.
    - [x] Pass the exact full gate after #773 merges.
  - [x] Anchor and resolve finalized activity epochs through the existing digest boundary (#775;
    qualified in run `31447336017` and merged to `main` as `7095a337`).
    - [x] Expose fail-closed anchor-service health that checks the finalized RPC view, operator
      fee/nonce state, registry, and proposal-spool capacity before reporting submission readiness.
    - [x] Add the canonical network-bound epoch anchor request and exact frozen epoch statement derivation.
    - [x] Add chained signed verifier trust bundles.
    - [x] Bind the exact anchor statement to canonical transaction/state inclusion evidence before
      reporting finality.
      - [x] Derive the native action from operator-owned finalized fee/nonce state and persist one
        crash-atomic, idempotent proposal per round.
      - [x] Include only exact-reference-bound `SubmitAnchor` actions in the validator proposal,
        commit their receipts under finality, and archive action/receipt/finality together.
      - [x] Reconcile archives through the independent finalized-anchor verifier before the
        durable `submitted -> finalized` registry transition.
      - [x] Wire the Kanalen testnet operator bootstrap and document the production lifecycle.
    - [x] Add the authenticated idempotent anchor service, recovery rehearsals, vectors, and exact gate.
      - [x] Add the bounded bearer-authenticated telemetry anchor gateway and freeze its developer contract.
      - [x] Add gateway recovery/adversarial rehearsals and deterministic canonical vectors.
      - [x] Rebase onto merged #773 and pass the exact full gate.
    - [x] Regenerate the affected RPC/client anchor vectors and manifest hashes.
    - [x] Pass the exact full gate for the corrected binding and merge it to `main`.
    - [x] Authenticate accepted finalized anchor records under the canonical checkpoint state root.
      - [x] Freeze domain-separated registry-object key/type/value encoding and replacement rules.
      - [x] Make only the canonical `SubmitAnchor` transition create the authenticated state object.
      - [x] Verify the exact record with the existing bounded canonical `StateProof`, without callbacks.
      - [x] Add wrong-root/key/value/anchor/checkpoint, stale-proof, duplicate, replacement, and
        unadmitted-anchor adversarial tests and vectors.
      - [x] Pass affected checks and one exact full gate, then merge the follow-up into `main`.
  - [x] Implement work claims and zero-knowledge non-overlap proofs (#776; claimed on `feat/776-work-proof-zk`).
    - [x] Freeze tagged raw telemetry measurements and policy-pinned class aggregates.
    - [x] Implement class-specific Attention, Compute, and Contribution arithmetic.
    - [x] Add class-neutral usage nullifiers and adversarial relation coverage.
    - [x] Regenerate proof/image/receipt vectors and pass the exact full gate.
  - [x] Expose bounded verification APIs, SDKs, and explorer DTOs (#777; qualified in run
    `31455861662` and merged to `main` as `797687a8`).
    - [x] Replace anchor/checkpoint equality with canonical checkpoint state membership,
      retryable checkpoint-lag/unavailable outcomes, and substitution/adversarial tests.
    - [x] Enforce cross-process all-or-nothing usage-nullifier admission with reload-under-lock,
      crash-safe persistence, and real multiprocess race/restart tests.
    - [x] Document the complete-file registry as bounded Preview storage and qualify explicit
      entry/file-size limits plus 10k/100k/500k/1m admission latency.
    - [x] Rebase onto merged #775, compile first, pass affected tests, and run one exact full gate.
    - [x] Implement bounded in-process and subprocess RISC Zero relation verification.
    - [x] Bind operator-selected chained trust bundles and exact finalized-anchor inclusion.
    - [x] Implement durable all-or-nothing class-neutral usage admission and exact-claim retries.
    - [x] Add bounded explorer DTOs, pagination, error taxonomy, offline Rust API, and C FFI.
    - [x] Ship the authenticated bounded stateful HTTP verification/explorer adapter and real
      ML-DSA trust-bootstrap tooling; requests cannot select trust.
    - [x] Document the `pow.actum.network` verifier, trust, subprocess, and storage boundaries.
    - [x] Pass compile-first and affected-crate qualification for the direct finalized-anchor
      verifier boundary without rebuilding the frozen guest image.
    - [x] Pass the exact full deterministic-kernel gate with the pinned guest image.
  - [x] Build the offline verifier trust-bundle ceremony that #778 provisioning requires
    ([GitHub issue #793](https://github.com/advatar/ActiveChain/issues/793); merged as `0258749e`).
    - [x] Add threshold-capable keygen, signer-set, and prepare/inspect/sign/assemble tooling that
      keeps the signing key off every verifier host and derives checkpoint identity from a real
      finalized block.
    - [x] Emit the deployed build's proof binding instead of transcribing it into bundle
      specifications.
    - [x] Pass the exact full deterministic-kernel gate.
  - [ ] Qualify and document the complete `pow.actum.network` integration (#778; claimed on `feat/778-pow-e2e-qualification`).
    - [x] Assemble checkpointed anchor evidence from a live RPC node. Nothing built
      `CheckpointedTelemetryAnchorEvidenceV1`, so every claim failed retryable
      `CheckpointUnavailable` and no production case was reachable.
    - [x] Deploy the qualified revision to Kanalen and serve the verifier publicly. The
      bring-up exposed a missing bundle binary, a faucet source that breaks after the first
      grant, a receipt the ingest pipeline never indexes, a Lima-only container host name,
      a loopback bind the containerised gateway cannot dial, and an ALPN mismatch.
    - [ ] Capture the real exact-revision lifecycle evidence on the Kanalen host.
    - [x] Add deterministic delivery, anchor, verifier, replay, restart, concurrency, and privacy rehearsals.
    - [x] Emit exact-revision deterministic evidence from the split runtime gate.
    - [x] Bundle the stateless verifier, stateful admission API, and trust-bootstrap tools for Kanalen deployment.
    - [x] Freeze the native telemetry-anchor action/receipt/finality/trust consumer fixture.
    - [x] Route plugin `work.verify` through authenticated stateful admission while preserving an
      explicit relation-only fallback.
    - [x] Publish the stateful HTTP JSON Schema and binding-validating server-side TypeScript client.
    - [x] Package and provision the fail-closed stateful verifier service, durable stores, private
      bearer token, launchd unit, and Kanalen TLS route.
    - [x] Automate checksum-verified, revision-addressed Mac mini activation and TLS gateway refresh
      for explicit deploys.
    - [x] Split formal proofs from Verus/vector conformance into independently rerunnable,
      fail-closed qualification jobs.
    - [ ] Exercise real deployed delivery, anchoring, finality, and stateful usage admission.
    - [ ] Pass the exact full gate and publish production qualification evidence.
    - [ ] Promote the deployed testnet and update landing-page capabilities proven by that evidence.

## Verifier C header and Apple distribution reconciliation

Tracked by [GitHub issue #745](https://github.com/advatar/ActiveChain/issues/745).

- [x] Regenerate and audit the verifier C header against the exported production ABI.
- [x] Pass header validation, Apple distribution reproducibility, and the exact aggregate
  deterministic-kernel gate; merge the dependency chain to `main` and verify reachability.

## Light-client devnet vector hash reconciliation

Tracked by [GitHub issue #743](https://github.com/advatar/ActiveChain/issues/743).

- [x] Align the stale light-client devnet-block requirement hash with the generated canonical vector
  and primary verifier manifest.
- [x] Pass complete verifier-manifest/proof-conformance checks and the exact aggregate
  deterministic-kernel gate; merge the dependency chain to `main` and verify reachability.

## Proof-of-funds guest image identity reconciliation

Tracked by [GitHub issue #741](https://github.com/advatar/ActiveChain/issues/741).

- [x] Trace the proof-of-funds guest ELF/image change and reconcile every canonical image-ID and
  vector consumer with the intended reproducible guest.
- [x] Pass PQ-ZK tests, canonical vector reproduction, and the exact aggregate deterministic-kernel
  gate; merge the dependency chain to `main` and verify reachability.

## Verus parity lockfile reconciliation

Tracked by [GitHub issue #739](https://github.com/advatar/ActiveChain/issues/739).

- [x] Regenerate and audit the isolated Verus parity lockfile against its pinned manifest and
  production dependency graph.
- [x] Pass all Verus contracts and the exact aggregate deterministic-kernel gate; merge the
  dependency chain to `main` and verify reachability.

## Protocol-types asset Kani proof recovery

Tracked by [GitHub issue #737](https://github.com/advatar/ActiveChain/issues/737).

- [x] Repair the reachable NFT registry proof panic and bound the two timed-out asset rejection
  harnesses without weakening their production invariants.
- [x] Pass all protocol-types Kani harnesses and the exact aggregate deterministic-kernel gate;
  merge the dependency chain to `main` and verify reachability.

## Verifier-FFI Kani workspace graph reconciliation

Tracked by [GitHub issue #735](https://github.com/advatar/ActiveChain/issues/735).

- [x] Mirror the production `activechain-payment-types` dependency in the verifier-FFI Kani
  workspace without weakening graph-drift validation.
- [x] Pass the targeted verifier-FFI Kani gate and the exact aggregate deterministic-kernel gate;
  merge the dependency chain to `main` and verify reachability.

## Active release fix — Hardened crypto dependencies in Kani mirrors

- [ ] Reconcile hardened crypto-provider dependencies in every production-source Kani mirror
  ([GitHub issue #769](https://github.com/advatar/ActiveChain/issues/769)).
  - [x] Mirror the exact resolved `ring` and `zeroize` dependencies used by production crypto.
  - [x] Extend the fast verifier-FFI preflight to reject external dependency-name drift.
  - [x] Reconcile the isolated RISC Zero guest lock with the hardened crypto dependency closure.
  - [ ] Pass targeted Kani verification and the exact full deterministic-kernel gate before merge.

## Published TLA+ 1.8.0 tool pin recovery

Tracked by [GitHub issue #733](https://github.com/advatar/ActiveChain/issues/733).

- [x] Repin both TLA runners and proof-scope records to the official published v1.8.0 release
  asset digest, with an alignment regression.
- [x] Pass both TLA model suites and the exact aggregate deterministic-kernel gate; merge the
  dependency chain to `main` and verify reachability.

## Independent-client baseline identity reconciliation

Tracked by [GitHub issue #731](https://github.com/advatar/ActiveChain/issues/731).

- [x] Reconcile the two merged canonical identities with the P-134 machine-readable and published
  cumulative counts without changing staffing estimates or gates.
- [x] Pass registry/budget validation, strict workspace Clippy, and the deterministic-kernel gate;
  merge the dependency chain to `main` and verify reachability.

## Consensus canonical fixture drift recovery

Tracked by [GitHub issue #729](https://github.com/advatar/ActiveChain/issues/729).

- [x] Reconcile the finalized-block canonical digest vector with the current schema-three proof
  inputs and document the source of the change.
- [x] Generate a structurally valid empty-history schema-four snapshot fixture and retain
  fail-closed malformed/non-empty legacy rejection.
- [x] Pass the consensus-runtime suite, strict workspace Clippy, and the deterministic-kernel gate;
  merge the dependency chain to `main` and verify reachability.

## Fungible transfer test strict-Clippy recovery

Tracked by [GitHub issue #727](https://github.com/advatar/ActiveChain/issues/727).

- [x] Replace redundant cloning of copyable fungible-asset policies without changing test
  semantics.
- [x] Pass application-primitives tests, strict workspace Clippy, and the deterministic-kernel
  gate; merge the dependency chain to `main` and verify reachability.

## Consensus runtime strict-Clippy recovery

Tracked by [GitHub issue #725](https://github.com/advatar/ActiveChain/issues/725).

- [x] Remove superseded validator helpers, preserve staged-cash recovery semantics, and eliminate
  redundant test clones flagged by strict Clippy.
- [x] Pass consensus-runtime tests, strict workspace Clippy, and the deterministic-kernel gate;
  merge the dependency chain to `main` and verify reachability.

## MCP canonical RPC query-kind coverage

Tracked by [GitHub issue #719](https://github.com/advatar/ActiveChain/issues/719).

- [x] Map every canonical RPC `QueryKind` to a stable MCP snake-case name.
- [x] Add exhaustive regression coverage for all current query variants.
- [x] Pass MCP tests, strict workspace Clippy, and the deterministic-kernel gate; merge to `main`
  and verify reachability.

## External credential adapter strict-Clippy recovery

Tracked by [GitHub issue #721](https://github.com/advatar/ActiveChain/issues/721).

- [x] Resolve the five behavior-preserving strict-Clippy findings in SD-JWT parsing and time
  validation.
- [x] Pass adapter tests, strict workspace Clippy, and the deterministic-kernel gate; merge to
  `main` and verify reachability.

## External credential admission error representation

Tracked by [GitHub issue #723](https://github.com/advatar/ActiveChain/issues/723).

- [x] Preserve typed rejected admission receipts while resolving the oversized `Result` error
  representation under strict Clippy.
- [x] Pass admission tests, strict workspace Clippy, and the deterministic-kernel gate; merge to
  `main` and verify reachability.

## Open-source documentation and community health

Tracked by [GitHub issue #659](https://github.com/advatar/ActiveChain/issues/659).

- [x] Replace the stale Phase 0 README with accurate architecture, maturity, quick-start,
  verification, repository-map, contribution, security, support, and license guidance.
- [x] Add an indexed documentation map and standard contribution, conduct, security, support,
  governance, license, issue-template, and pull-request-template files.
- [x] Validate relative links, documented paths, and focused onboarding commands without running
  the full workspace build or CI.

## Bounded validator storage and decentralized archives

Tracked by [GitHub issue #397](https://github.com/advatar/ActiveChain/issues/397), with the first
normative and measurement slice in [#398](https://github.com/advatar/ActiveChain/issues/398).

- [x] Fix the development storage contract at a qualified 1 TiB physical validator ceiling, a
  deterministic charged-byte schedule, automatic pressure bands, 30-day assigned hot retention,
  two certified snapshots, 8-of-12 archives, and renewable hibernation.
- [x] Add overflow-safe executable storage accounting and a drift-checked machine-readable profile.
- [x] Implement persistent partition state, immutable ledger segments, and certified snapshots
  ([GitHub issue #403](https://github.com/advatar/ActiveChain/issues/403)).
  - [x] Add sealed, chain-linked ledger segments and crash-safe two-generation partition manifests.
  - [x] Persist content-addressed partition payloads and atomically activate only complete snapshots.
  - [x] Bind snapshot certification to finalized state through the checkpoint verifier boundary.
- [ ] Implement paid archive assignment, challenges, reconstruction, and crash-safe pruning
  ([GitHub issue #405](https://github.com/advatar/ActiveChain/issues/405)).
  - [x] Add permissionless 8-of-12 archive assignments, custody receipts, retrieval proofs, and
    exact reconstruction with failure-domain bounds.
  - [x] Add a monotonic, authenticated pruning watermark that requires complete retention,
    snapshot, grace-period, checkpoint, and archive evidence before idempotent deletion
    ([GitHub issue #407](https://github.com/advatar/ActiveChain/issues/407)).
  - [ ] Integrate objective payment/slashing settlement and finalized certificate ingestion.
    - [x] Add manifest-bound archive escrow, rewards, and objective missed-challenge slashing
      ([GitHub issue #418](https://github.com/advatar/ActiveChain/issues/418)).
    - [ ] Wire finalized settlement outputs into the native token ledger after #167/#180 land.
- [ ] Implement prepaid leases, hibernation/restoration, and accumulator-backed replay history
  ([GitHub issue #409](https://github.com/advatar/ActiveChain/issues/409)).
  - [x] Add checked byte-epoch quotes, pressure admission, bounded endowments, archive-certified
    hibernation, and owner-copy restoration.
  - [x] Integrate rent and hibernation commands with authenticated global state transitions.
    - [x] Add proof-authenticated canonical object renew, hibernate, and restore transitions
      ([GitHub issue #420](https://github.com/advatar/ActiveChain/issues/420)).
    - [ ] Route storage commands through finalized transaction ingress after #167/#180 land.
  - [x] Add stateless witnessed sparse replay sets and append-only header history commitments
    ([GitHub issue #411](https://github.com/advatar/ActiveChain/issues/411)).
  - [ ] Migrate bounded production replay collections to the witnessed accumulator roots.
    - [x] Replace the privacy kernel's stored nullifier vector with a constant-size witnessed root
      and canonical non-membership updates
      ([GitHub issue #424](https://github.com/advatar/ActiveChain/issues/424)).
    - [x] Replace the cash ledger's redeemed-reward vector with a constant-size witnessed root
      ([GitHub issue #426](https://github.com/advatar/ActiveChain/issues/426)).
    - [x] Replace durable compliance replay vectors with constant-size witnessed roots
      ([GitHub issue #428](https://github.com/advatar/ActiveChain/issues/428)).
- [x] Qualify checkpoint snapshot sync, light clients, operator metrics, and sustained 1 TiB bounds.
  - [x] Add bounded checkpoint sync and light-client checkpoint verification
    ([GitHub issue #414](https://github.com/advatar/ActiveChain/issues/414)).
  - [x] Add bounded operator telemetry and deterministic multi-year capacity qualification
    ([GitHub issue #416](https://github.com/advatar/ActiveChain/issues/416)).
  - [x] Run a production-like physical disk soak with crash/restart and archive-loss injection
    ([GitHub issue #422](https://github.com/advatar/ActiveChain/issues/422)).
    - [x] Add a configurable production-API filesystem soak harness and versioned report.
    - [x] Qualify interrupted activation, corruption, archive loss, and pruning fail-closed behavior.
    - [x] Record a production-like local run with measured peak and final physical usage.

## Active bounded-storage landing publication

Tracked by [GitHub issue #430](https://github.com/advatar/ActiveChain/issues/430).

- [x] Publish accurately qualified bounded validator storage and decentralized archive functionality
  to `activechain-display/main`, with dedicated claim regression coverage, lint, production build,
  and route smoke verification.
- [x] Advance the parent landing-page submodule pointer to landing merge `b419a12`; merge it to
  `main` as `589da93` and confirm both landing and parent revisions are reachable from their
  respective `origin/main` branches.

## Non-interactive Docker authentication isolation

Tracked by [GitHub issue #433](https://github.com/advatar/ActiveChain/issues/433).

- [x] Keep every deterministic-kernel Docker and nested RISC0 BuildKit invocation on an explicit,
  anonymous configuration that cannot fall back to the macOS login-keychain credential helper.
- [x] Add a fail-closed regression check for the effective Docker configuration.
- [x] Pass the complete deterministic-kernel gate, merge to `main`, and verify reachability; merge
  commit `1c278e7` is reachable from `origin/main`.

## Independent-client budget gate repair

Tracked by [GitHub issue #401](https://github.com/advatar/ActiveChain/issues/401).

- [x] Reconcile the published per-version active canonical identity counts with the registry after
  merged protocol additions, without changing the approved staffing ranges or release gates.
- [x] Reconcile the Apple compatibility manifest and C/Swift consumers with wallet ABI revision 4.
- [x] Give each authorization-chain lemma a bounded 15-minute proof window so normal ARM64 runner
  variance cannot kill a valid source-saturation proof at the old 10-minute limit.
- [x] Pass the deterministic-kernel gate and merge the repair to `main`; merge commit `28fab4a` is
  reachable from `origin/main`.

## Active landing-page rebrand — Actum

Tracked by [GitHub issue #391](https://github.com/advatar/ActiveChain/issues/391).

- [x] Rebrand the public landing-page copy and metadata from ActiveChain to Actum while retaining
  compatibility-sensitive protocol, repository, RPC, and network identifiers for a later phase.
- [x] Add a regression check for the public brand surface and pass landing-page lint and production
  build verification.
- [x] Merge the unit-tested landing-page revision and parent submodule update into `main`.

## Landing-page information architecture

Tracked by [GitHub issue #366](https://github.com/advatar/ActiveChain/issues/366), readiness
cross-reference [#343](https://github.com/advatar/ActiveChain/issues/343), and native-assets
readability issue [#191](https://github.com/advatar/ActiveChain/issues/191).

- [x] Replace the single long-form landing route with a focused home page and dedicated content
  pages grouped under clear top-level categories and subcategories.
- [x] Add shared desktop and mobile navigation with active-page context, category menus, and
  direct links to every page.
- [x] Preserve the existing visual language and substantive content while improving page-level
  hierarchy, orientation, and cross-page discovery.
- [x] Pass the landing unit-test suite, publish the display revision, and merge the
  parent-repository pointer to `main`; browser, CI, and full-build qualification were explicitly
  skipped for this integration at operator request.

## Critical incident — deterministic validator key compromise

Tracked by [GitHub issue #326](https://github.com/advatar/ActiveChain/issues/326).

- [x] Replace public-parameter-derived validator seeds with CSPRNG-generated, operator-provisioned
  key files whose ownership, permissions, encoding, manifest identity, and legacy-key status are
  checked fail-closed before startup.
- [x] Remove production validator seed reconstruction and keep deterministic identities confined to
  explicit test fixtures.
- [x] Add secure provisioning, mismatch, permissions, legacy-key, restart, and rotation tests.
- [x] Publish and rehearse a recoverable three-validator identity rotation before changing Kanalen.
- [x] Archive the compromised Kanalen state, rotate every validator identity, restore quorum/RPC
  health, and record the new immutable chain identity without trusting prior certificates.
- [x] Remove deterministic CLI wallet identities and track native platform key custody separately
  ([GitHub issue #327](https://github.com/advatar/ActiveChain/issues/327)).

## Critical wallet approvals — one canonical signed request

Tracked by [GitHub issue #339](https://github.com/advatar/ActiveChain/issues/339).

- [x] Inventory and remove platform-local unsigned/defaulted approval encodings and developer
  transaction bridges.
- [x] Expose one bounded canonical approval transcript and human-readable fields from Rust through
  the C/JNI boundaries, bound to the exact intent commitment.
- [x] Require immediate platform authentication before native custody signs that exact transcript;
  reject mutation, substitution, replay, and alternate encodings.
- [x] Add shared cross-language vectors plus Rust, FFI, Apple, Android, and end-to-end submission
  tests.
- [x] Pass targeted Rust, Android, and Apple builds/tests, merge to `main`, and verify
  reachability before closing #339. The exhaustive deterministic-kernel CI gate was explicitly
  skipped during issue reconciliation in favor of the normal affected-platform test suites.

## Critical wallet recovery — hardware-wrapped post-quantum custody

Tracked by [GitHub issue #327](https://github.com/advatar/ActiveChain/issues/327).

- [x] Define a versioned native custody contract with honest hardware capability reporting,
  explicit user-presence policy, finalized-state rollback protection, rotation, revocation, and
  independently encrypted recovery envelopes.
- [x] Implement Apple Keychain/Secure Enclave wrapping for backup-excluded ML-DSA-44 slots, keeping
  plaintext secret bytes transient inside the native provider and zeroizing them after signing.
  - [x] Replace the Apple test-only ML-DSA engine with the wire-compatible Rust implementation,
    deriving public keys and producing self-verified signatures from transient unwrapped seeds.
- [x] Implement Android Keystore/StrongBox wrapping with user authentication and backup exclusion,
  keeping plaintext secret bytes transient inside the native provider and zeroizing them after
  signing.
  - [x] Connect the Keystore wrapping cipher to a real AndroidX `BiometricPrompt.CryptoObject`,
    with fail-closed cancellation, lockout, unavailable-hardware, and duplicate-callback handling.
- [x] Keep secret key material behind opaque native handles across the Rust FFI, reverify every
  returned ML-DSA-44 signature, and add locked-device, cancelled-authentication, rollback, wrong-key,
  revoked-key, recovery, rotation, and migration-failure tests.
- [x] Correct mobile custody and recovery claims. Targeted Rust (13), macOS (26), and Android
  unit/build qualification passes on the merged implementation candidate.
- [ ] Complete physical-device qualification and the independent platform/PQ review gates tracked
  by #578, #579, and #580; these external evidence gates do not reopen the completed #327
  implementation scope.
- [x] Merge the implementation to `main` and verify reachability. The queued full deterministic
  kernel run is skipped in favor of normal tests during issue reconciliation.

## Critical consensus recovery — bounded views and leader rotation

Tracked by [GitHub issue #329](https://github.com/advatar/ActiveChain/issues/329).

- [x] Define canonical, domain-separated timeout votes and quorum-backed view-change certificates.
- [x] Enforce deterministic proposer eligibility and reject unjustified, stale, or unbounded round
  advances before collector or durable vote state changes.
- [x] Retain vote collectors by consensus slot so competing traffic cannot discard quorum progress.
- [x] Persist and validate the active view, timeout-vote locks, and accepted view-change proof across
  restart with a bounded snapshot migration.
- [x] Authenticate timeout votes and view-change certificates inside the existing sender-bound peer
  envelope, persist replay high-water state before admission, and expose durable timeout/publish APIs.
- [x] Exercise three-validator timeout quorum, deterministic leader rotation, snapshot restart,
  replay rejection, forged timeout signatures, and rotating-leader sustained finality in unit tests.
- [x] Add adversarial unit/model/process tests for `u64::MAX`, skipped rounds, replay, restart,
  absent/malicious leaders, and continued finality after leader rotation.
- [x] Pass the complete deterministic-kernel gate, merge to `main`, and verify reachability before
  closing #329.

## Critical monetary recovery — constitutional issuance ceiling

Tracked by [GitHub issue #331](https://github.com/advatar/ActiveChain/issues/331).

- [x] Define a deterministic issuance-year window, stake-sensitive target-budget curve, rounding,
  boundary, and checked-overflow semantics in the native-money specification.
- [x] Derive the target security budget and remaining annual issuance allowance from committed
  ledger state at the executed mint boundary; reject caller-controlled substitutes before mutation.
- [x] Persist bounded window opening supply and cumulative issuance in canonical consensus state,
  with an explicit fail-closed migration for legacy snapshots.
- [x] Enforce the cumulative ceiling in ledger invariants so split transactions and restarts cannot
  reopen issuance capacity.
- [x] Add boundary, overflow, multi-mint, rollover, restart, legacy-migration, and adversarial
  property tests; align formal arithmetic and frozen vectors.
- [x] Pass the deterministic-kernel gate, merge to `main`, and verify reachability before closing
  #331.

## Critical cash recovery — durable replay protection

Tracked by [GitHub issue #332](https://github.com/advatar/ActiveChain/issues/332).

- [x] Route every production wallet and faucet mutation through one write-before-acknowledgement
  durable ingress boundary.
- [x] Derive admission height from the live finalized RPC state instead of immutable startup input.
- [x] Specify crash outcomes for each atomic-publication boundary and fail closed after uncertain
  publication.
- [x] Prune expired session records and redundant spent-input markers without reopening nonce,
  session, or Coin Cell replay windows.
- [x] Add restart, duplicate, corruption, publish-failure, pruning, and live RPC-process tests.
- [x] Pass the deterministic-kernel gate, merge to `main`, and verify reachability before closing
  #332.

## Critical codec recovery — canonical type-tag registry

Tracked by [GitHub issue #333](https://github.com/advatar/ActiveChain/issues/333).

- [x] Inventory every production canonical type in one machine-readable registry and distinguish
  intentional aliases from independent protocol types.
- [x] Assign a unique v1 `(type tag, schema version)` identity to every live type without consuming
  reserved v1.1/v1.2 extension ranges.
- [x] Migrate or reject legacy collided envelopes explicitly and regenerate every affected vector,
  manifest, header, and external-verifier fixture.
- [x] Bind an unambiguous registered type identity into canonical value commitments and signatures.
- [x] Add CI enforcement for registry completeness, uniqueness, allowed ranges, and cross-type
  decode/commitment rejection, including the demonstrated asset/RPC collision.
- [x] Pass the deterministic-kernel gate, merge to `main`, and verify reachability before closing
  #333.

## Critical authorization recovery — authenticated transfer facts

Tracked by [GitHub issue #334](https://github.com/advatar/ActiveChain/issues/334).

Follow-up availability fix tracked by
[GitHub issue #705](https://github.com/advatar/ActiveChain/issues/705).

Adversarial context-binding follow-up tracked by
[GitHub issue #706](https://github.com/advatar/ActiveChain/issues/706).

- [x] Add a constant-size finalized capability-revocation registry and carry its authenticated
  object/state proof plus per-capability non-membership paths through signed-chain verification.
- [x] Reject missing, revoked, stale, substituted-registry, and malformed revocation evidence with
  targeted adversarial verifier tests.
- [x] Run targeted accumulator/protocol/verifier tests plus affected strict Clippy, merge the #706
  revocation slice to `main`, prove reachability, and delete its feature branch.
- [x] Bind authorization-layer APL evaluation to the finalized input object's control-policy
  commitment and reject policy substitution before producing `VerifiedAuthorization`
  ([GitHub issue #753](https://github.com/advatar/ActiveChain/issues/753)).
- [x] Advance capability grants to a v2 issuer-signing transcript that commits the trusted chain
  genesis, so byte-identical authority cannot move between devnet, testnet, and mainnet.
- [x] Refresh canonical authority vectors and add real ML-DSA verification proving same-chain
  acceptance and cross-chain rejection.
- [x] Run targeted protocol-types and verifier tests plus affected strict Clippy, merge the #706
  chain-binding slice to `main`, prove reachability, and delete its feature branch.
- [x] Bind every opaque verified authorization to the exact finalized block height at production
  admission, matching the existing P-110 verifier contract.
- [x] Add a targeted stale-height regression proving an otherwise valid authorization cannot use
  an expired capability or manipulate a rate window by declaring another height.
- [x] Run targeted authorization-kernel and consensus-runtime tests plus affected strict Clippy,
  merge the #706 height slice to `main`, prove reachability, and delete its feature branch.

- [x] Replace the permanently capped invocation replay map with a constant-size witnessed
  accumulator commitment, preserving fail-closed replay rejection across restart while allowing
  more than 4,096 valid authorizations.
- [x] Add targeted adversarial unit tests for the 4,096/4,097 boundary, duplicate and stale
  witnesses, sequential batch witnesses, and snapshot restart behavior.
- [x] Run targeted authorization-kernel and accumulator tests plus affected strict Clippy, merge
  #705 to `main`, verify patch-equivalent reachability, and delete the feature branch.

- [x] Replace publicly mintable asserted-verification values with opaque results produced only by
  concrete cryptographic and finalized-state verification.
- [x] Bind authorization to the exact canonical transaction, chain genesis, epoch, finalized state
  root, actor, policy, credential, capability, and replay context.
- [x] Route the production finalized-transfer admission graph through `authorization-kernel`; remove
  the commitment-only/test-only authorization bypass.
- [x] Persist authorization replay/budget state before acknowledgement and fail closed on
  publication uncertainty.
- [x] Add forgery, substitution, stale-state, cross-transaction, serialization, restart, and
  production caller-graph regression tests.
- [x] Pass the deterministic-kernel gate, merge to `main`, and verify reachability before closing
  #334.

## Critical compliance recovery — canonical provider attestations

Tracked by [GitHub issue #335](https://github.com/advatar/ActiveChain/issues/335).

- [x] Define a versioned, domain-separated canonical transcript covering the complete evidence,
  subject, provider, policy/profile, validity, chain genesis, and protocol revision.
- [x] Verify provider signatures and exact finalized context on every production compliance
  admission; reject unknown, ambiguous, stale, and cross-network material.
- [x] Define and enforce a fail-closed migration/reissuance policy for legacy attestations.
- [x] Add field-substitution, omission, replay, expiry, cross-network, canonical-vector, and
  production caller-graph regressions.
- [x] Pass the deterministic-kernel gate, merge to `main`, and verify reachability before closing
  #335.

## Critical faucet recovery — durable settlement reservations

Tracked by [GitHub issue #336](https://github.com/advatar/ActiveChain/issues/336).

- [x] Persist a bounded, canonical grant reservation before invoking settlement and retain every
  possibly-settled record across persistence failures.
- [x] Make retry and operator reconciliation idempotent across crashes before, during, and after
  settlement and receipt publication.
- [x] Derive abuse-control identities at the authenticated server boundary rather than trusting a
  client-selected source commitment.
- [x] Add fault-injection, restart, duplicate, concurrent-request, and uncertain-settlement tests.
- [x] Pass the deterministic-kernel gate, merge to `main`, and verify reachability before closing
  #336.

## Critical fee recovery — bounded economically backed tickets

Tracked by [GitHub issue #337](https://github.com/advatar/ActiveChain/issues/337).

- [x] Define canonical ticket backing, issuer authority, uniqueness, validity, and replay-window
  semantics with an explicit consensus state-growth bound.
- [x] Verify and atomically consume backing with each charged action before state execution.
- [x] Replace permanent ticket history with consensus-safe expiry pruning and bounded snapshot
  migration while preserving replay rejection.
- [x] Add forged, duplicate, expired, future, restart, pruning-boundary, saturation, property, and
  sustained-hostile-traffic tests.
- [x] Raise the deterministic-kernel job timeout so the exact candidate can complete the full
  formal, model-checking, test, release, rehearsal, and vector gate without a deterministic
  120-minute cancellation.
- [x] Pass the deterministic-kernel gate, merge to `main`, and verify reachability before closing
  #337.

## Critical transport recovery — mutually authenticated peer sessions

Tracked by [GitHub issue #330](https://github.com/advatar/ActiveChain/issues/330).

- [x] Replace the replayable challenge-only handshake with the proved server-challenge, signed
  client-finish, and signed key-confirmation state machine using fresh CSPRNG nonces.
- [x] Bind the complete transcript to chain genesis, epoch, protocol revision, both peer identities,
  and the pinned ML-DSA-44/ML-KEM-768 suites.
- [x] Authenticate every consensus frame under the negotiated session key with durable, bounded,
  write-before-admission send/receive sequence state and expiry.
- [x] Remove unauthenticated and challenge-only production paths; bind each admitted socket to the
  configured peer identity and session before consensus parsing.
- [x] Cover capture/replay, reflection, wrong identity, cross-genesis/protocol use, expiry, restart,
  corruption, and protected-frame mutation in unit and live process tests.
- [x] Align the Rust implementation, Tamarin model, canonical vectors, operations guidance, and
  observability; pass the deterministic-kernel gate and merge #330 to `main`.

## Critical ingress recovery — bounded authenticated network service

Tracked by [GitHub issue #338](https://github.com/advatar/ActiveChain/issues/338).

- [x] Replace the unbounded thread-per-connection listener with a fixed worker set, bounded socket
  queue, and immediate overload shedding whose resource ceilings are operator-visible.
- [x] Enforce absolute handshake, frame read/write, authenticated-session idle, lifetime, and
  message-count limits so byte-drip and stalled peers cannot retain workers indefinitely.
- [x] Put bounded pre-authentication limits on the server-observed source address and
  service-level limits on the authenticated validator identity before expensive message decoding.
- [x] Expose accepted, active, queued, shed, timed-out, rate-limited, malformed, and recovered
  traffic metrics with structured operator diagnostics.
- [x] Add slow-drip, connection-flood, oversized/expensive-invalid-frame, reachable-rate-limit,
  recovery, and healthy-peer-under-hostile-load tests.
- [x] Pass the deterministic-kernel gate, merge to `main`, and verify reachability before closing
  #338.

## Deterministic-kernel CI baseline

### Tiered verification cadence

Tracked by [GitHub issue #345](https://github.com/advatar/ActiveChain/issues/345).

- [x] Document targeted implementation checks, touched-crate checkpoints, consolidated pushes,
  and one full deterministic-kernel run for the exact final merge candidate in `AGENTS.md`.
- [x] Preserve mandatory exhaustive qualification for substantive executable, formal, vector,
  build, workflow, dependency, packaging, and release-input changes.
- [x] Avoid redundant full-system reruns for documentation-only completion bookkeeping after the
  underlying exact implementation revision has already qualified.

- [x] Restore the clean-checkout `cargo fmt --all --check` gate
  ([GitHub issue #320](https://github.com/advatar/ActiveChain/issues/320)).
- [x] Reconcile `Cargo.lock` with current workspace manifests and pass the exact locked,
  all-target, all-feature workspace Clippy gate used by CI.
- [x] Capture Tamarin stderr in the formal evidence file so derivation completion and warnings are
  checked rather than bypassing the gate.
- [x] Run each unchanged authorization lemma in an independently bounded prover process so the
  complete eighteen-lemma manifest finishes while retaining timeout-as-failure behavior.
- [x] Give the authorization executability witnesses a deterministic bounded proof strategy; the
  default search reached the per-lemma limit on `exists_complete_authorized_transition` after the
  first thirteen manifest lemmas completed.
- [x] Remove redundant attacker-delivery premises for credential, capability, and state-proof
  records that are already bound into the authoritative snapshot; retain adversarial delivery for
  signed action requests and re-prove every authorization lemma.
- [x] Model signed action submission as an explicit canonical envelope rather than a destructured
  transport tuple, while retaining public request/signature visibility and replayability.
- [x] Install the pinned Kani toolchain in the deterministic-kernel job instead of relying on
  mutable self-hosted runner state, then run every bounded-model harness on that exact version.
- [x] Reconcile the isolated verifier-FFI Kani workspace with the production dependency closure so
  application primitives, the crypto provider, and RPC types cannot bypass ABI proofs.
- [x] Keep the supply-attestation Kani claim structural and compositional by factoring exact policy
  binding from the separately tested SHA3 commitment path; retain unwinding assertions as hard
  failures and prove the production helper rather than a copied model.
- [x] Make the isolated Verus arithmetic gate reproducible from a clean runner instead of requiring
  an uncached `libc` crate while invoking Cargo in offline mode.
- [x] Update the finite Verus/Rust parity bridge for the production quorum certificate's added
  commitment field and retain accepted, threshold-rejected, and overflow vectors.
- [x] Repair the stale finalized-header negative schema test so it actually substitutes an
  unsupported version after the production schema moved to version 2.
- [x] Regenerate the checked-in verifier and wallet C headers after their public safety contracts
  and declaration order changed, restoring the Apple distribution reproducibility gate.
- [x] Correct the standalone validator restart rehearsal to retain zero finality without a quorum,
  while proving durable progress separately from the three-process quorum rehearsal.
- [x] Verify the repaired baseline through the required deterministic-kernel CI job.

## Active protocol decision — P-130 economics

- [x] Record the v1 native-staked-asset decision and reject stablecoin-secured validators as a
  consensus-security alternative in `spec/protocol/P-130-economics.md`.
- [x] Make `MINT.md`, `REWARDS.md`, and `CASH.md` explicitly subordinate to P-130 and remove any
  implication that stablecoin collateral is a selectable v1 validator-security profile.
- [x] Recompute the decentralisation scorecard for native-stake security, show the weighted
  arithmetic and assumptions, and record the rejected branch's issuer capture penalty.

## Active protocol decision — P-131 version series

- [x] Publish the ordered v1.0–v2 launch contract and reserve extension surfaces in
  `spec/protocol/P-131-version-series.md`.
- [x] Add a bounded protocol-version profile that rejects unknown revisions and exposes explicit
  feature activation/requirement gates for the complete v1.0–v2 series.
- [x] Assign named deferred-feature tags inside the reserved v1.1/v1.2 ranges and reject every
  unassigned reserved tag even after activation.
- [x] Freeze executable reserved-tag/header-slot vectors and wire them into touched-crate tests.

## Active protocol decision — P-132 proof liveness

- [x] Define validator re-execution fallback, bounded proof grace depth, proof-pending state, and
  recovery behavior in `spec/protocol/P-132-proof-liveness.md`.
- [x] Encode a bounded proof deadline/grace profile and fail-closed liveness transition policy.
- [x] Freeze executable normal, outage, recovery, and exhaustion vectors and split validity from
  prover-liveness concentration in the decentralization scorecard.

## Active protocol decision — P-133 compute admission

- [x] Demote general compute jobs and AI-result claims out of v1 consensus semantics; define the
  escrow/attestation boundary in `spec/protocol/P-133-compute-admission.md`.
- [x] Add canonical application-layer compute escrow and assurance-attestation types and vectors.
- [x] Reserve a future bounded compute verifier interface without activating compute semantics in
  v1 consensus.

## Active protocol decision — P-134 independent client

- [x] Publish a bounded v1.0 conformance surface and Go verifier milestones in
  `spec/protocol/P-134-independent-client.md`.
- [x] Publish a machine-counted per-version conformance budget, required staffing allocation, and
  delivery estimate for the independent Go verifier.
- [x] Correct the current TSV smoke reader to M0 status and qualify independent-verification
  claims until semantic M2 differential replay passes.
- [ ] Freeze the language-neutral semantic vectors and implement the independent verifier through
  M2 without importing Rust implementation code.
  - [ ] Implement M1 semantic verification families independently in Go.
    - [x] Decode and validate canonical envelope framing, minimal length encoding, exact
          tag/schema, bounds, truncation, and trailing-data rejection (#618).
    - [x] Independently decode Principal v1 bodies and reject invalid kind/freeze tags,
          temporal inversion, truncation, and trailing bytes (#620).
    - [x] Independently decode AuthenticatorDescriptor v1, registered suites, exact key sizes,
          purpose compatibility, and validity/revocation ordering (#622).
    - [x] Independently decode CapabilityGrant v1 and verify complete parent/child attenuation,
          including scopes, ceilings, validity, delegation, revocation, and signature framing (#624).
    - [x] Independently decode and evaluate the bounded APL v1 policy/request/decision family in Go
          against language-neutral positive and adversarial semantic vectors
          ([GitHub issue #755](https://github.com/advatar/ActiveChain/issues/755)).
    - [x] Reconcile the independent CapabilityGrant decoder with current schema v2 chain-genesis
          binding and adversarial attenuation vectors
          ([GitHub issue #757](https://github.com/advatar/ActiveChain/issues/757)).
    - [x] Independently decode and verify the credential/status v1 semantic family in Go against
          language-neutral positive and adversarial vectors
          ([GitHub issue #759](https://github.com/advatar/ActiveChain/issues/759)); implementation
          candidate `a3dcfc63` passed exact full qualification run `31399064101`.

## Active milestone — P-060 execution proof system

- [x] Publish the P-060 selection/security specification and explicit re-execution transition gate.
- [x] Implement a standalone Gate-1 transparent STARK reference prover and verifier with protocol-bound receipts.
- [x] Add strict decoding, public-input binding, mutation, malformed-input, determinism, and totality tests.
- [x] Publish a deterministic positive receipt vector and benchmark metadata with honest soundness caveats.
- [x] Publish a deterministic malformed receipt vector and exercise it through the verifier test suite.
- [x] Add a CLI vector-check command that validates positive acceptance and malformed rejection.
- [x] Reconcile the normative P-060 status with the shipped Gate-1 reference and its explicit
  accumulator-only scope.
- [x] Add an independent no-STARK model verifier and CLI cross-check for canonical vectors.
- [x] Add a negative model-verifier regression for mutated post-state commitments.

## CashAIR P-060 hardening

- [x] Register explicit parent, SHAKE permutation, and composite suite identifiers.
- [x] Replace Plonky3 benchmark FRI defaults with pinned protocol parameters and a documented
  100-bit-plus conjectured-security target.
- [x] Raise Winterfell CashAIR and session acceptance floors to 100 bits and enable grinding.
- [x] Reject out-of-range value columns before trace construction.
- [x] Make digest-to-f128 conversion reject non-canonical limbs instead of reducing them.
- [x] Name the structural verifier explicitly while retaining a compatibility alias.
- [x] Declare CashAIR's internal Blake3, SHA-256, and Keccak assumptions in P-060.
- [x] Add strict parent CashAIR proof byte-envelope decoding with suite binding and trailing-byte rejection.
- [x] Add strict authenticated composite proof byte-envelope decoding with suite, row-count, and
  per-proof bounds; full-depth happy-path qualification remains an explicit benchmark gate.
- [ ] Resolve the remaining CashAIR review gates ([#323](https://github.com/advatar/ActiveChain/issues/323)): wire amount range constraints into the AIR and
  replace the ignored composite happy-path with a bounded CI fixture. The SHAKE FRI set is now
  explicit, pinned at log_blowup=3, 32 queries, and 16 grinding bits (112-bit conjectured floor).
  As of 2026-07-27, `cargo test -p activechain-cash-air --offline` passes 22 tests with one
  intentionally ignored full-depth timing gate; no FRI-parameter mismatch remains. The two
  outstanding items are implementation work, not release claims.
  - [x] Constrain every native input, output, and fee trace value to an in-AIR 64-bit boolean
    decomposition; host-side trace construction checks are defense in depth only.
  - [x] Replace the ignored full composite proof with a bounded accepted-row fixture that runs in
    ordinary CI and retains the separate full-depth benchmark gate.
  - [x] Qualify and integrate the completed CashAIR hardening work.
    - [x] Pass focused CashAIR tests and Clippy (25 tests passed, one explicit full-depth
          benchmark gate ignored; targeted all-target/all-feature Clippy passed on 2026-08-02).
    - [x] Verify the amount-constraint and bounded-receipt commits are reachable from
          `origin/main`; the full deterministic-kernel gate was explicitly skipped in favor of
          targeted tests during issue reconciliation.
- [x] Redesign authenticated CashAIR receipt aggregation to fit the existing bounded ingress
  ceiling instead of enlarging it; add compact accepted-row encode/decode/verify qualification
  ([#379](https://github.com/advatar/ActiveChain/issues/379)).
  - [x] Aggregate a full authenticated mutation path into bounded large batches so FRI query
    openings are not repeated once per 64 permutations, while preserving the pinned security
    parameters and ordered transcript binding.
  - [x] Replace the JSON proof representation with strict bounded binary encoding and reject
    trailing, truncated, oversized, and allocation-amplifying inputs before proof decoding.
  - [x] Prove, canonically encode, decode, and verify the accepted-row release fixture below the
    8 MiB ingress ceiling; record size, verification time, and peak-memory measurements.
    The 2026-07-30 Apple M5 Max release run produced a 3,591,727-byte logical proof and a
    3,750,254-byte receipt in four canonical segments, verified in 2,545 ms, and reported a
    3,087,925,248-byte maximum resident set for the combined prove/verify process (54,526,624-byte
    peak physical footprint). Two encoded receipts fit an 8 MiB byte-admission budget; three do not.
- [x] Cover authenticated envelope round-trip and suite mutation rejection without running the
  full SHAKE proving benchmark.
- [x] Make the reference package independently testable outside the root workspace.
- [x] Exercise the standalone P-060 verifier package and protocol vectors: 14 unit/integration
  tests pass, including deterministic positive proofs, malformed fixtures, strict codec bounds,
  suite binding, and independent model verification.
- [ ] Refine the AIR against P-050 ObjectVM semantics and publish an independent second verifier.
- [ ] Qualify proof parameters against the required soundness and verifier-cost gates before consensus activation.

## Kanalen snapshot compatibility gate

- [x] Publish the persisted validator snapshot schema marker through the read-only indexer.
- [x] Make the preflight script reject snapshots with an unexpected schema marker.

## Kanalen recoverable clean rebuild

- [x] Add an explicit-confirmation tool that archives incompatible state before rebuilding genesis.
- [x] Cover validator, RPC, and PQ-session artifacts without touching launch configuration.

## Workspace strict-Clippy qualification

- [x] Resolve the current dead-code and argument-count diagnostics under `-D warnings`.
- [x] Pass the exact workspace all-target/all-feature Clippy gate with `RISC0_SKIP_BUILD=1` (the CI qualification mode).

## Clippy follow-up: regulated admission

- [x] Clear the newly surfaced argument-count and nested-condition diagnostics in regulated transfer admission.

## Clippy follow-up: agent enrollment

- [x] Preserve the canonical enrollment constructor shape while clearing its argument-count diagnostic.

## Clippy follow-up: consensus runtime feature build

- [x] Disambiguate SHAKE reader calls when all workspace features are enabled.

## Clippy follow-up: consensus runtime lint cleanup

- [x] Document the intentional consensus message size and simplify constant error paths.

## Clippy follow-up: vector generator API drift

- [x] Keep the frozen epoch-upgrade table consumable while the runtime upgrade model evolves.

## Clippy follow-up: verifier fixture API drift

- [x] Update finality verifier fixtures for explicit proposal commitments in votes and certificates.

## Clippy follow-up: light-client fixture API drift

- [x] Update light-client finality and upgrade fixtures for explicit proposal commitments.

## Clippy follow-up: verifier/RPC fixture API drift

- [x] Update verifier API and RPC finality fixtures for explicit proposal commitments.

## Kanalen reset/recovery automation

- [x] Bootstrap the RPC index automatically when a testnet is reset to a new genesis.
- [x] Rehearse a genesis reset end-to-end and verify the public RPC health response (fresh genesis finalized at height 7; RPC healthy).

## Faucet RPC exposure

- [x] Expose operator-configured faucet terms and persisted receipt resolution through the RPC server.
- [x] Keep funding submission disabled until a validator-backed settlement adapter is attached.

## Release branch hygiene

- [x] Remove merged implementation branches while preserving intentional archive branches.
- [x] Verify `origin/main` is the only active implementation branch after cleanup.

## Active fix — Kanalen wallet app compatibility

Tracked by [GitHub issue #318](https://github.com/advatar/ActiveChain/issues/318).

- [x] Pin the native wallet clients to Kanalen's immutable chain identity, genesis commitment,
  protocol revision, and RPC schema revision 2.
- [x] Fix Apple wallet status and owner-page decoding, then refresh owner state only through a
  cryptographic verifier bound to the trusted device profile.
- [x] Replace Android's fabricated wallet/network state with a bounded live TLS status client and
  explicit unavailable states for balances, activity, approvals, identity, funding, and transfers.
- [x] Make the live Kanalen probe verify the full canonical status, immutable identity, health
  consistency, proof ordering, frame bounds, and trailing-data rejection.
- [x] Regenerate the managed wallet C header after integrating the restored `main` baseline, so
  owner-proof documentation and constant layout remain pinned-cbindgen reproducible.
- [x] Remove the deprecated Android system-bar color assignments exposed by the clean exact-head
  rebuild; the edge-to-edge root already paints the intended system-bar background.
- [x] Add the missing Android Gradle wrapper pinned to AGP 8.6's supported/default Gradle 8.7,
  preventing host Gradle 9/10 drift and its plugin deprecation path.
- [x] Extend the verifier-FFI Kani shadow workspace with the production cash/privacy dependency
  closure introduced by owner Coin Cell verification, then re-prove every ABI harness.
- [x] Pass Apple, Android, Rust, and live Kanalen qualification.

Qualification on 2026-07-28 passed 21 tests on each Apple target, the exact-revision iOS build and
universal macOS archive, the checksum-pinned Gradle 8.7 Android JVM tests and debug APK build, the
complete locked all-feature Rust workspace suite, strict all-target/all-feature Clippy, and the four
adversarial Python probe tests. The live TLS 1.3 probe verified the exact Kanalen identity at healthy
finalized height 7,052. The final merge and reachability check are tracked in issue #318.

## Phase 0 — protocol foundation

- [x] Establish a pinned stable-Rust workspace with consensus-kernel quality gates.
- [x] Draft the initial normative specifications (`P-000`, `P-001`, and `P-010`).
- [x] Define the first canonical schema for protocol primitives and principals.
- [x] Implement `no_std`, safe-Rust protocol primitive types.
- [x] Implement a bounded canonical binary codec with strict trailing-data rejection.
- [x] Qualify canonical codec behavior: all 10 tests pass for minimal length prefixes, bounded
  byte strings, exact envelope layout, type/schema/trailing-data rejection, option tags, and
  arbitrary round-trips.
- [x] Implement SHAKE256/384 domain-separated commitments.
- [x] Qualify protocol commitments: all four tests pass for published principal/package vectors,
  complete-manifest binding, domain separation, and type separation.
- [x] Publish deterministic codec and commitment test vectors.
- [x] Add unit and property tests for round trips, malformed input, bounds, and domain separation.
- [x] Document the workspace layout and local verification commands.

Phase 0 bootstrap is tracked by [GitHub issue #1](https://github.com/advatar/ActiveChain/issues/1).

## Active testnet fix — verified wallet state discovery

- [x] Pin the Apple wallet and Amber status clients to the deployed Kanalen chain and genesis,
  reject substituted network identities, and pass targeted unit plus live TLS tests
  ([GitHub issue #634](https://github.com/advatar/ActiveChain/issues/634)). Three Amber and two
  wallet identity/codec XCTest cases pass serially on macOS, and each app's own Swift network client
  independently accepts the healthy live Kanalen endpoint with the exact pinned identity.
- [x] Qualify the wallet-core/OpenWallet and agent-management primitives: all 36 library tests
  pass, including deterministic selection, PQ authorization, durable replay barriers, OpenWallet
  consent/nonces, agent enrollment/revocation, and malformed-vector rejection.

Tracked by [GitHub issue #180](https://github.com/advatar/ActiveChain/issues/180).

- [x] Define a bounded owner-scoped Coin Cell query and finalized proof-bearing response.
- [x] Expose wallet-facing verification helpers that bind native and fungible owner queries to
  the requested owner, asset (where applicable), finalized membership proof, and trusted genesis.
- [x] Bind the finalized cash-record publisher to the configured validator genesis before RPC
  indexing.
- [x] Persist and serve owner indexes without leaking unrelated owner state.
- [x] Verify exact owner, finalized cash-root membership, cell commitment, and root binding in
  wallet code; chain/genesis binding remains enforced by the RPC finality verifier.
- [x] Persist and restore the authenticated wallet ledger with an explicit chain-id binding.
- [x] Export finalized Coin Cell membership proofs from validator execution into the RPC index;
  wallet snapshots without a matching finalized cash-cell root remain in-process only.
- [x] Add a validator-service API that emits proof-bearing RPC records only after exact finality,
  height, genesis, and cash-root verification.
- [x] Add a verified snapshot constructor for execution adapters, preventing unverified cash state
  from entering the validator-to-RPC publication boundary.
- [x] Reject cash/finality ingestion when the supplied finality bundle is not bound to the
  validator snapshot's immutable chain genesis.
- [x] Route the validator-to-RPC ingest command through the chain-genesis-bound cash-record
  publisher.
- [x] Wire the proof-bearing Coin Cell record builder into the validator finalization publisher;
  publication now consumes evidence-bearing persisted cash state.
- [x] Add a validator publication method that requires the exact finalized certificate to match
  the persisted cash root, height, and immutable chain genesis.
- [x] Add an execution-side snapshot materializer from the authenticated wallet ledger; certificate
  binding remains mandatory before RPC publication.
- [x] Add a validator-bound wallet-to-RPC publication helper that derives genesis and finalized
  height from consensus state rather than caller input.
- [x] Cover execution snapshot root/identity behavior with a validator-runtime regression test.
- [x] Make durable RPC replacement independently verify every proof-bearing record against the
  configured genesis and exact finalized height before persistence.
- [x] Persist finalized cash cells with the exact finalized certificate and reject height, genesis,
  root, checksum, and malformed-evidence mismatches on restart.
- [x] Add an atomic snapshot/finality verification boundary binding cash root, height, and genesis
  before RPC publication.
- [x] Expose a validator-service persistence boundary that accepts cash snapshots only at the
  exact finalized height and immutable chain genesis.
- [x] Enable the Kanalen ingestion runner to publish finalized cash snapshots when validator
  output and its matching finality bundle are available; retain metadata-only ingestion until
  then.
- [x] Make the production validator round execute or load the authoritative cash transition,
  verify it through the non-test finalized-block verifier, and atomically emit the matching
  finalized cash snapshot plus certificate bundle; metadata consensus alone is insufficient.
  - [x] Stage bounded authorized cash batches against durable validator ingress, certify the exact
    successor root, and publish the complete successor only after quorum finality; rejected or
    duplicate batches leave the authoritative ingress unchanged.
  - [x] Make finalized-block admission carry the exact signed vote set and provide a genesis-backed
    verifier that checks ML-DSA signatures, canonical vote commitments, and stake quorum instead
    of permitting a production caller to validate a bare quorum-certificate commitment.
  - [x] Bind the exact pre/post cash roots and ordered authorized cash-action root into typed proof
    public inputs, then make finalized admission recompute those values from staged ingress.
  - [x] Provide a production draft builder for canonical cash-only execution blocks so validator
    rounds vote over the exact header later consumed by typed finalized-block admission.
  - [x] Route the validator's published cash round through durable canonical execution state,
    direct-reexecution proof verification, and genesis-backed post-vote admission before emission.
  - [x] Commit admitted execution state, authorized cash ingress, finality artifacts, and action
    archival through one write-ahead journal with idempotent partial-materialization recovery.
  - [x] Recover a precommitted round when consensus persisted its certificate before the artifact
    journal was promoted, closing the final certification-to-publication crash window.
- [x] Require finalized-cash publication to load a canonical invariant-checked, chain-bound cash
  ledger instead of synthesizing an empty Coin Cell set.
- [x] Make a fresh Kanalen reset provision the genesis cash state consumed by that execution path,
  then prove the first and restarted rounds publish matching cash/finality artifacts.
  - [x] Rehearse first and restarted round publication from the exact reset-provisioned cash ledger,
    retaining authoritative state while regenerating only derived publication artifacts.
  - [x] Bootstrap an absent execution snapshot for the existing metadata-only Kanalen history at
    the exact next-proposal predecessor height and finalized anchor digest without resetting chain
    identity, then persist that base before any staged vote.
- [x] Provision a canonical chain-bound cash ledger during reset from an explicit operator treasury
  principal and validated supply/reserve parameters.
- [x] Make the Kanalen proposer certify the exact finalized cash root and emit the verifier-ready
  cash snapshot plus quorum finality bundle consumed by the fail-closed ingestion runner.
- [x] Load a real device wallet profile and remove the hard-coded unavailable dashboard path;
  balances remain fail-closed until the linked verifier accepts finalized owner proofs.
- [x] Extend Kanalen ingestion/rehearsal, add adversarial tests, deploy, and verify the public RPC.
  - [x] Repair canonical schema-5 validator safety-snapshot migration so the live chain can retain
    its consensus state while adopting schema-6 view-change and timeout fields.
  - [x] Run all three validator listeners and make round orchestration rotate through candidates,
    preserving full-quorum voting while accepting only the consensus-selected proposer.
  - [x] Raise the bounded consensus peer frame to 32 KiB so a three-validator ML-DSA view-change
    certificate and its successor certified block fit without relaxing oversized-frame rejection.
  - [x] Make RPC ingestion consume the canonical crash-journal cash snapshot and independently
    verify it against the separately published quorum finality bundle.
  - [x] Update the public TLS probe to the current canonical RPC request and response type tags.
- [x] Verify the currently deployed Kanalen testnet independently over localhost on the host:
  chain/genesis identity matches, finalized height advances to 4168, and health reports `Healthy`.
- [x] Deploy the schema-2 RPC binary and matching probe without changing validator binaries or
  snapshots; the host-local probe reports the same chain/genesis identity and `Healthy` at height
  4182 while both legacy-compatible validators remain running.
- [x] Re-run the complete seven-stage wallet/testnet rehearsal after validator certificate
  propagation changes: genesis-bound funding, replay rejection, three-validator finality,
  restart, and durable recovery all pass locally.
- [x] Complete the local seven-stage wallet acceptance rehearsal: genesis-bound faucet grant,
  authorized ingress/replay checks, three-validator quorum, finalized-certificate propagation,
  restart, and durable snapshot recovery all pass.
- [x] Correct the local three-validator rehearsal's authenticated peer identity/signature wiring;
  the first live round now finalizes with three votes and zero rejections.
- [x] Preserve and advertise the finalized parent certificate across the second proposer/restart
  round; the live rehearsal now reaches finalized height 1 with three votes after restart.
  - [x] Verify the public TLS edge with a protocol-level status probe; validator/RPC health is
    observed independently of the HTTP landing service.

## Active recovery — abandoned checkout reconciliation

Tracked by [GitHub issue #178](https://github.com/advatar/ActiveChain/issues/178).

- [x] Inventory the canonical checkout, remaining worktrees, local commits, and remote reachability.
- [x] Separate intentional shared Xcode configuration from machine-local user state.
- [x] Classify the stale billboard reassessment and consensus/authorization recovery against current
  `origin/main`.
- [x] Port and verify only current substantive changes; preserve or remove obsolete branches only
  after reachability checks.
- [x] Reconcile canonical `main`, run qualification gates, publish the result, and clean obsolete
  worktrees.

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
- [x] Keep the agent enrollment UI compatible with the currently packaged wallet XCFramework;
  use the stable registration ABI until the pending-enrollment symbol is included in a rebuilt
  signed distribution.

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

## Active release fix — live wallet state

Tracked by [GitHub issue #162](https://github.com/advatar/ActiveChain/issues/162).

- [x] Remove fabricated balances, assets, conversion values, network claims, activity, approvals,
  credentials, identities, agent records, fees, and validity heights from the native wallet.
- [x] Populate Kanalen finality and health from a bounded canonical TLS-framed RPC request.
- [x] Render persisted wallet and agent records only when they actually exist.
- [x] Fail honestly with empty, unavailable, or unsupported states where no live query exists.
- [x] Add no-placeholder regression tests and pass iOS plus macOS test/build gates.

## Active implementation — testnet wallet faucet

Tracked by [GitHub issue #167](https://github.com/advatar/ActiveChain/issues/167).

- [x] Freeze canonical, testnet-bound faucet request, challenge, decision, and receipt/status types.
- [x] Add operator-configurable grant amounts, global budgets, recipient cooldown/lifetime limits,
  idempotency, optional escalating Sybil challenges, and durable restart-safe accounting.
- [x] Add bounded canonical request/response framing for the validator RPC bridge, with strict
  length checks and malformed-frame regression vectors.
- [x] Add a versioned `RequestAuthorizedFaucet` RPC schema carrying the exact signed envelope;
  canonical round-trip and empty-envelope rejection are covered by RPC-type tests.
- [x] Advance the advertised RPC schema revision to 2 so clients cannot silently interpret the
  new authorized-faucet request as an older wire shape.
- [x] Bind bridge settlement responses to the exact admitted faucet reference and expose a typed
  request-to-response helper.
- [x] Freeze canonical pending/finalized/rejected settlement status responses with state-consistent
  optional evidence and malformed vectors.
- [x] Add a fail-closed finalization path that verifies certificate evidence against the faucet
  genesis, exact finalized height, and block digest before funding is marked final.
- [x] Submit faucet-authorized Coin Cell transitions through real transaction ingress and expose
  pending/finalized/rejected proof-bearing status through the Kanalen gateway.
  - [x] Admit the atomic operator session-plus-transfer envelope in consensus batch preparation,
    reload the authoritative ingress before signing, and spool immutable framed actions for the
    locked Kanalen round runner without publishing an RPC-local ledger successor.
  - [x] Archive the matching finality bundle beside each consumed cash-action batch, verify its
    exact committed cash-action root, and durably reconcile matching pending faucet receipts.
  - [x] Verify the finalized recipient Coin Cell membership as part of reconciliation and deploy
    the treasury-controlled signer configuration on Kanalen.
  - [x] Add a pristine-genesis-only ML-DSA treasury authorization bootstrap and derive the
    Kanalen treasury principal from a newly generated, permission-restricted faucet operator key.
  - [x] Perform the authorized Kanalen reset, update pinned client genesis, and qualify live funding.
- [x] Qualify the current RPC/faucet boundary with 27 server tests covering finalized ingestion,
  owner scoping, cross-chain rejection, durable restart, faucet limits, malformed evidence, and
  typed adapter installation.
- [x] Upgrade the canonical cash authorization to schema v2 with a signed optional settlement
  reference, and require the exact faucet reference, recipient, amount, and admission height before
  validator transaction ingress.
- [x] Add a strict validator-RPC bridge entry point that decodes the signed envelope and checks its
  intent identifier, recipient, and amount before handing bytes to an authoritative backend.
- [x] Add a typed production faucet settlement adapter boundary for validator-backed ingress.
- [x] Add an opt-in RPC authorized-settlement callback that receives the exact signed envelope
  after faucet policy admission; absent this callback, the new request remains fail-closed.
- [x] Expose a typed authorized-settlement adapter API for validator implementations and qualify
  its installation through the RPC server test suite.
- [x] Provide a validator-runtime adapter backed by the real `WalletTransactionGateway`; it uses
  the consensus-owned finalized height and fail-closes malformed ingress (qualified in runtime
  tests).
- [x] Add a direct `TransactionIngress`-backed RPC adapter for deployments that host wallet
  admission in the RPC process, with chain, intent, recipient, amount, and height checks.
- [x] Add optional `ACTIVECHAIN_WALLET_INGRESS_SNAPSHOT` and
  `ACTIVECHAIN_FINALIZED_HEIGHT` startup wiring to `activechain-rpc-node`; unset variables keep
  the node fail-closed and metadata-only.
- [x] Publish the end-to-end funding admission contract and adversarial reference-substitution
  vectors before public faucet deployment.
- [x] Freeze the validator-bridge authorized-settlement request envelope with strict canonical
  round-trip, trailing-byte, empty, malformed, and intent/recipient/amount-binding vectors.
- [x] Add bounded length-prefixed bridge framing for authorized settlement requests with strict
  truncation and trailing-byte rejection.
- [x] Freeze executable faucet invariant vectors for failed-settlement atomicity, source/global
  limits, restart equivalence, and exactly-once idempotency.
- [x] Add bounded Kani proofs for admission limit monotonicity and cooldown precedence; these do
  not yet prove validator ingress or end-to-end issuance.
- [x] Require an explicit testnet-only faucet deployment profile; production/regulated profiles
  fail closed before durable faucet state is created.
- [x] Formally verify testnet-only validity, supply conservation, exactly-once issuance,
  rate-limit monotonicity, atomic restart equivalence, and receipt-to-finalized-transition binding;
  publish the proof scope and every remaining assumption or gap.
- [x] Freeze the faucet invariant model and executable conformance vectors before formal proof
  integration.
- [x] Add an iOS/macOS testnet funding flow that never credits optimistic or local-only balances.
- [x] Pass replay, concurrency, forged-chain, exhaustion, restart, privacy, and end-to-end tests.

## Active protocol design — multi-asset Coin Cells

Tracked by [GitHub issue #163](https://github.com/advatar/ActiveChain/issues/163).

- [x] Bind fungible Coin Cells and all transitions, authorizations, proofs, and receipts to `AssetId`.
- [x] Expose an explicit canonical asset-bound fungible transfer commitment for proof/receipt
  consumers; dedicated fungible AIR remains open.
- [x] Freeze canonical fungible AIR public inputs with asset/registry bindings and per-asset
  supply/transfer conservation checks; arithmetization remains open.
- [x] Factor fungible conservation into a checked arithmetic kernel shared by runtime validation
  and future formal/AIR refinement.
- [x] Add canonical u128-to-16-bit-limb decomposition/recomposition for fungible AIR range checks.
- [x] Expose all fungible public amount columns through the canonical limb view used by AIR
  refinement.
- [x] Add checked reconstruction of fungible AIR amount limbs with a bounded Kani round-trip
  proof and malformed-conservation rejection.
- [x] Add a proof-system-independent fungible public-statement verifier with commitment and
  conservation mismatch rejection.
- [x] Bind wallet-side fungible membership verification to the exact owner, `AssetId`, record,
  and authenticated finalized root.
- [x] Bind fungible transfer admission to the finalized asset policy and lifecycle.
- [x] Bind fungible settlement receipts to the exact redemption asset, amount, and settlement
  reference.
- [x] Add the backward-compatible canonical `FungibleCoinCellRecord` wire type before migrating
  authenticated roots and wallet/RPC APIs.
- [x] Add an ordered fungible-cell set and domain-separated authenticated root.
- [x] Add fungible-cell membership proofs bound to the asset record and set root.
- [x] Freeze the canonical multi-asset binding rules and positive/malformed vectors before
  changing execution or wallet surfaces.
- [x] Specify a finalized issuer-controlled asset metadata and supply registry, including reserve,
  redemption, jurisdiction, authority, lifecycle, and bounded supply commitments.
- [x] Add proof-bearing owner-and-asset RPC discovery with bounded pagination.
- [x] Extend the versioned wallet ABI for multi-asset balances, selection, signing, and submission.
- [x] Add wallet transfer construction that requires the finalized asset policy and rejects paused,
  retired, stale, or cross-asset policy state.
- [x] Add deterministic wallet selection over `FungibleCoinCellSet` with explicit asset identity.
- [x] Qualify native, test-EUR, and test-USD assets with cross-asset adversarial vectors.

## Regulated-profile assurance plan and screening semantics

The dependency-ordered assurance implementation plan tracked by
[GitHub issue #213](https://github.com/advatar/ActiveChain/issues/213) is complete. Later operating
evidence, jurisdiction activation, independent review, and regulated-deployment decisions remain
separate release gates and are not implied by completing the plan.

- [x] Qualify canonical protocol-type coverage: all 75 library tests pass across assets, issuer
  lifecycle, consensus/QC, credentials, DID, compliance evidence, travel-rule bindings, and
  strict canonical/malformed vectors.

- [x] Validate the current compliance-provider registry and credential-predicate admission
  implementation: four focused application-primitive tests pass, including durable replay and
  malformed provider-key rejection.

- [x] Specify versioned sanctions/KYC screening inputs, freshness, matching, overrides, and
  privacy-preserving evidence handling with deterministic vectors.
- [x] Freeze the commitment-only screening decision envelope, bounded validity, outcomes, and
  malformed vectors; private list matches and analyst evidence remain provider-held.
- [x] Add explicit idempotent compliance-provider key revocation and replacement semantics;
  cryptographic verification remains ML-DSA-44 and profile-scoped.
- [x] Reject jurisdiction-profile inheritance manifests with missing parent references; cycles,
  non-stricter edges, ambiguity, and inactive candidates remain fail-closed.
- [x] Reject duplicate, self-referential, or zero-identity inheritance edges before profile
  expansion, preventing first-match ambiguity in the selector.
- [x] Persist the bounded provider-key registry through canonical atomic snapshots and restore it
  fail-closed on malformed, duplicate, or invalid-length records.
- [x] Add the versioned screening policy boundary for list authority, parameter commitments,
  freshness, and clear-only admission.
- [x] Bind screening acceptance to the exact regulated chain and transaction context.
- [x] Enforce `require_provider_signature` through a decision commitment and exact profile,
  chain, and action signature envelope.
- [x] Add commitment-only, dual-control screening overrides with reviewer quorum, reason
  commitment, profile/decision binding, expiry, and deterministic positive/malformed vectors.
- [x] Provide ML-DSA-44 verification wiring for compliance signature envelopes; key registry
  selection remains an operator-controlled boundary.
- [x] Add a bounded profile-scoped provider key registry with strict key shape and unknown-profile
  rejection.

## Active dBrowser development RPC contract

Tracked by [GitHub issue #91](https://github.com/advatar/ActiveChain/issues/91).

- [x] Freeze chain identity, genesis, protocol revision, finality/health, supported proofs, and
  proof-bearing state/action/receipt query semantics with deterministic vectors; `RpcStatus`,
  bounded `QueryRecord`/page types, canonical decoding, and malformed substitution vectors now
  enforce this contract.
- [x] Add a stable network identity commitment over chain, genesis, protocol, and RPC schema
  revisions; head height and health are intentionally excluded.

## Active Kanalen deployment compatibility gate

- [x] Refresh the frozen devnet semantic vector for canonical action-envelope schema v2 and its
      derived action/block/receipt commitments ([GitHub issue #616](https://github.com/advatar/ActiveChain/issues/616)).

- [x] Add snapshot schema and immutable genesis compatibility checks before
  promoting new validator binaries; the 2026-07-25 canary was rolled back after snapshot decode
  failure.
- [x] Publish an operator migration/rebuild procedure for incompatible snapshots.

## Active EUDI/TLSNotary credential pipeline

Tracked by [GitHub issue #169](https://github.com/advatar/ActiveChain/issues/169).

- [x] Freeze credential-to-ZK predicate boundaries, issuer/status freshness, holder binding,
  audience/action binding, and selective-disclosure vectors; canonical predicate and malformed
  credential/status-registry vectors exercise each binding.
- [x] Add the canonical commitment-only predicate boundary with holder, audience, action, policy,
  nonce, expiry, and hidden-value bindings.
- [x] Add application admission that enforces predicate chain/audience/action/expiry before handing
  hidden-value verification to the ZK circuit boundary.
- [x] Add credential temporal validity and issuer/schema/status-registry freshness admission
  helpers with exact finalized-height binding.
- [x] Add one canonical acceptance-policy evaluator combining allowlists, validity, status
  requirement, and finalized-height freshness.
- [x] Reject malformed credential-status snapshots (zero roots or zero sequence) before they can
  satisfy registry freshness admission.
- [x] Reject malformed credential-status snapshots during canonical decoding, not only at
  downstream policy admission.
- [x] Add a canonical TLS-derived credential evidence envelope that preserves notary/server,
  holder, freshness/status, disclosure, and assurance provenance without source transcripts.
- [x] Bind predicate admission to the exact evidence commitment and minimum assurance class so a
  holder/self-issued credential can never be promoted to issuer-upgraded or regulated assurance.
- [x] Publish positive and substitution vectors and qualify the ActiveChain boundary with 108
  normal affected tests, strict Clippy, and the canonical registry check; merge commit `9f42789`
  is reachable from `origin/main`.
- [x] Add the cross-repository TLSNotary producer envelope and EUWallet authenticated-ingestion
  boundary: `advatar/tlsn` PR #1 and `advatar/EUWallet` PR #76 are merged, preserve explicit
  assurance, reject unauthorized promotion, and keep TLS-derived evidence outside PID namespaces.
- [x] Publish and consume the byte-identical 17-case portable-evidence TSV across ActiveChain,
  TLSNotary, and EUWallet, covering version, commitment, freshness, assurance, and issuer-upgrade
  failures with a closed decision table.
- [x] Consume receipt nullifiers through the canonical accumulator and persist the updated root
  atomically before acknowledgement, rejecting replay, stale witnesses, and corrupt restart state.
- [x] Complete wallet consent/assurance UX, lifecycle and recovery coverage, and offline-proof
  conformance.
- [ ] Complete physical-device key qualification and independent review under #569 and its
  dedicated children #578, #579, and #580; these external gates do not reopen the completed #169
  implementation scope.

## Active independent-client qualification

- [x] Build the standard-library-only Go M0 vector reader and publish the v1.0 launch-gate
  complexity decision in P-134; semantic verification remains required for M1/M2.

- [x] Publish a bounded conformance surface and second-client milestone for the selected launch
  contract, with canonical vectors and no dependency on Rust implementation internals.
- [x] Add a language-independent TSV conformance smoke client that verifies the published
  positive/malformed case matrix without importing Rust implementation crates.
- [x] Publish the implementation-independent v1 conformance surface, required proof/asset/
  credential boundaries, and second-client qualification gates.

## Active proof-liveness qualification

- [x] Specify explicit v1.0 re-execution authority, mandatory-proof admission states, outage
  behavior, upgrade activation, and fail-closed qualification requirements.

## Active ordered protocol-version qualification

- [x] Publish the ordered v1.0/v1.1/v1.2 mandatory/deferred feature contract, additive encoding
  rule, activation bindings, and atomic upgrade gate.

## Active validator-economics qualification

- [x] Specify native-stake authority, quorum/slash/reward invariants, restart behavior, and the
  governed transition requirements for any future stablecoin-secured profile.

## Active compute-job boundary qualification

- [x] Specify compute jobs as application objects with commitment-only execution evidence,
  finalized receipts, pending/failure/dispute states, and no consensus-special execution primitive.

## ActiveBridge qualification

- [x] Define the v1 application settlement boundary for native payments, atomic swaps, merchant
  receipts, cross-network finality states, timeout refunds, and privacy-preserving commitments.

## Active implementation — ActiveBridge connector and settlement platform

Tracked by [GitHub issue #189](https://github.com/advatar/ActiveChain/issues/189).

- [x] Freeze canonical quotes, intents, provider observations, lifecycle records, evidence classes,
  and idempotency bindings.
  - [x] Persist a bounded per-intent lifecycle journal atomically across creation and every exact
    successor, retaining external, submitted, and finalized evidence semantics on restart.
- [x] Add crash-safe provider observation journaling and deterministic connector simulation.
- [x] Add a fail-closed operator connector-host policy for identity, HTTPS origins, opaque secrets,
  supported rail/asset pairs, amount ceilings, and request deadlines.
- [x] Implement the sandbox nTZS connector for quote, collection, payout, conversion, status, and
  reconciliation mappings without partnership or regulated-asset claims.
- [x] Integrate finalized native settlement, refunds/disputes, fee sponsorship, treasury controls,
  authenticated APIs/SDKs/webhooks, formal refinement, and local operations drills.
  - [x] Publish a transport-agnostic Rust SDK with canonical authenticated requests, correlated
    responses, and mandatory proof material for finalized/refunded lifecycle results.
  - [x] Prove cumulative refund conservation and sequencing, treasury budget/nonce safety, and
    retained-intent webhook cursor admission in the executable payment model.
  - [x] Bind each finalized payment successor to one canonical intent, exact native asset/amount,
    transaction, finalized height/block, receipt commitment, and proof commitment, and persist it
    through the joined request-state boundary.
    - [x] Cryptographically verify the trusted-genesis finality bundle and canonical block receipt,
      including exact action-transaction inclusion and evidence commitments, before finalization.
      - [x] Persist the full verified settlement evidence, joined request lifecycle, and initialized
        exact refund accounting as one atomic aggregate successor.
      - [x] Apply refund requests through the complete settlement state, atomically joining the
        first `Finalized` to `RefundPending` edge with cumulative amount and sequence accounting.
      - [x] Persist dispute opening and exact successors inside that same complete settlement
        aggregate without promoting external resolution to ActiveChain finality.
      - [x] Persist treasury policy registration and exact debit authorization inside the complete
        settlement aggregate so budget and nonce state cannot diverge from payment evidence.
      - [x] Consume authenticated API replay state inside the complete settlement aggregate so an
        acknowledged authorization cannot diverge from retained payment evidence.
      - [x] Persist exact webhook delivery cursors inside the complete settlement aggregate and
        reject delivery for events whose payment intent is not retained there.
      - [x] Add canonical paymaster sponsorship policy and exact authorization, then persist its
        fee budget and nonce successors inside the complete settlement aggregate.
      - [x] Cryptographically verify and persist exact full-refund evidence before advancing
        `RefundPending` to `Refunded`; partial or external-only refunds remain pending.
  - [x] Qualify deterministic local operations without promoting sandbox evidence.
    - [x] Run one deterministic ActiveBridge recovery drill covering exact retry, ambiguous
          provider dispatch, forced reconciliation, restart, replay, and failed-write atomicity.
    - [x] Add validated, crash-safe export and restoration for the complete joined payment
          settlement aggregate, rejecting corrupt backups without mutating live state.
    - [x] Complete sustained soak/chaos qualification.
      - [x] Run a bounded deterministic multi-intent persistence soak with exact retries,
            lifecycle and webhook mutation, and periodic complete-aggregate restart verification.
      - [x] Run time-based multi-process load, outage, partition, and resource-exhaustion chaos.
        - [x] Exercise concurrent process-level load/restart, simulated provider outage,
              partition/reordering, and failed-write pressure for a bounded wall-clock duration.
        - [x] Complete kernel-level memory, disk, and file-descriptor exhaustion qualification.
          - [x] Prove real file-descriptor exhaustion cannot advance live or durable aggregate
                state.
          - [x] Prove real disk-write exhaustion cannot advance durable aggregate state.
          - [x] Prove real Linux/cgroup memory exhaustion cannot advance live or durable aggregate
                state, then restart-decode the byte-identical pre-state outside the constrained child.
    - [ ] Complete operator-led incident exercises, independent review, and staged external-rail
          pilots; these external evidence gates do not reopen the completed local implementation
          scope.
- [x] Add canonical exact-once partial-refund requests and cumulative settlement-bound accounting.
  - [x] Persist a bounded per-intent refund-state journal atomically across settlement registration
    and every accepted partial refund, rejecting replay and corrupt restart state.
- [x] Add a canonical dispute request and monotonic lifecycle that keeps external resolution
  strictly distinct from ActiveChain-finalized settlement.
  - [x] Persist a bounded exact-dispute lifecycle journal atomically across opening and every
    validated successor, retaining external-versus-finalized evidence semantics on restart.
- [x] Add canonical treasury debit policy and exact-once payout/conversion/refund/fee/settlement
  authorization with operator, asset, ceiling, period-budget, nonce, and expiry controls.
  - [x] Persist a bounded per-treasury policy journal atomically across registration and every
    authorized debit, preserving exact budget and nonce successors across restart.
- [x] Add canonical webhook events and exact-sequence subscriber cursors that reject duplicate,
  skipped, cross-subscription, cross-intent, and expired delivery without promoting evidence.
- [x] Persist canonically ordered webhook subscriber cursors atomically so acknowledged delivery
  survives restart and failed or corrupt storage cannot advance in-memory state.
- [x] Bind authenticated API calls to exact caller, audience, operation, request, idempotency,
  optional intent, sequence, validity, and authenticator commitments with replay-safe client state.
  - [x] Persist exact caller/idempotency-key request bindings atomically, returning the original
    intent for identical retries and rejecting conflicting reuse across restart.
- [x] Persist authenticated API replay state atomically per caller and audience before request
  acknowledgement, rejecting corrupt snapshots without advancing memory.
  - [x] Persist create-intent idempotency binding, immutable canonical intent, and initial/current
    lifecycle as one atomic request-state snapshot with exact-retry reconstruction.
    - [x] Advance each lifecycle by atomically replacing that same joined request-state snapshot,
      preventing intent, idempotency, and lifecycle durability from diverging.
- [x] Verify canonical API authorization envelopes with committed ML-DSA-44 caller keys before
  consuming replay state, including negative proofs that invalid signatures cannot advance it.
- [x] Verify canonical webhook envelopes with their committed ML-DSA-44 subscriber keys before
  durably advancing delivery cursors, without promoting provider evidence to chain finality.

## Active EUDI/TLSNotary/ZK qualification

- [x] Freeze the off-chain evidence, selective-disclosure predicate, holder/action/policy binding,
  finalized status, privacy, and fail-closed boundary for EU Wallet/TLSNotary integration.

## Active faucet ingress qualification

- [x] Specify real testnet faucet transaction ingress, durable pending/finalized/rejected status,
  exact finality/Coin Cell proof binding, replay safety, and wallet no-optimism requirements.
- [x] Add ingress-specific deterministic vectors for submission, replay, finalized membership, and
  forged-proof rejection.

## Active testnet release qualification

- [ ] Promote the qualified hardened Kanalen release, reconcile the public immutable genesis probe,
  verify public finality and network exposure after restart, and publish the live developmental
  status to the landing-page `main` branch
  ([GitHub issue #765](https://github.com/advatar/ActiveChain/issues/765)).

- [ ] Replace bespoke protected-envelope, consensus-frame, and wallet-keystore cryptography with
  reviewed AEAD boundaries, direction-bound traffic keys, zeroizing secret lifecycles, explicit
  fail-closed format revisions, and hardened-candidate Kanalen qualification
  ([GitHub issue #763](https://github.com/advatar/ActiveChain/issues/763)).
  - [x] Import and review the supplied patch, correct its fixed-size zeroizing-key integration,
    format the result, and update the frozen protected-session domain vector.
  - [x] Pass 73 consensus-runtime library tests and its binary/doc tests, 7 crypto-provider tests,
    72 wallet-core tests and its wallet/issuer/doc tests, plus strict affected-crate Clippy.
  - [x] Pass the complete hardened local Kanalen qualification: release build, verifier checks,
    fail-closed finalized cash, signed faucet/transfer and replay rejection, three-validator
    authenticated finality with zero rejected messages, durable restart, and release packaging.
  - [ ] Pass the exact aggregate deterministic-kernel gate, merge to `origin/main`, and verify
    reachability before closing the issue.

- [x] Qualify a reproducible local Kanalen developmental release from `origin/main`: provide one
  operator entry point that builds the exact release components, exercises three-validator PQ
  finality, finalized-cash publication, wallet funding/transfer/replay rejection, snapshot restart,
  and records the remaining security gates without making production-readiness claims
  ([GitHub issue #761](https://github.com/advatar/ActiveChain/issues/761)).
  - [x] Add and document `scripts/qualify-kanalen-local.sh`, with a command-plan regression test in
    the deterministic-kernel workflow.
  - [x] Pass the complete local qualification: release build, verifier manifest, 16 verifier API
    tests, fail-closed finalized-cash publication, signed faucet and transfer admission, replay
    rejection, three-validator authenticated finality with zero rejected messages, durable restart,
    and local release packaging.
  - [x] Pass the exact aggregate deterministic-kernel gate on implementation revision `440bc49d`;
    integration and `origin/main` reachability are tracked by pull request #762.

- [x] Align the Kanalen promotion preflight with validator snapshot schema 6 and bounded execution
  snapshot migration, preserve explicit migration overrides and chain/genesis mismatch rejection,
  then deploy and smoke-test the exact merged revision
  ([GitHub issue #630](https://github.com/advatar/ActiveChain/issues/630)). Targeted shell,
  devnet-migration, validator, and indexer tests passed; Kanalen was promoted to merge revision
  `b9f25c6`, migrated execution schema 3 to schema 5 atomically, retained schema-6 validator state,
  advanced public finality from height 10,231 through 10,233, and reported
  `proposals=1 votes=3 rejected=0` over TLS 1.3.
- [x] Publish a fail-closed development testnet release gate covering validator finality, Coin Cell
  extraction, RPC, faucet ingress, wallet funding, independent-client conformance, and claims.
- [x] Publish genesis-reset vectors rejecting old proposals, certificates, snapshots, and faucet
  receipts after a Kanalen development-network reset.

## Active native issuer operations

- [x] Add deterministic offline inspection and dry-run for canonical threshold-approved issuer
  supply operations before submission.
- [x] Add an issuer-console review surface derived from canonical policy and approval envelopes,
  including exact supply pre/post-state and approval-window binding.

Tracked by [GitHub issue #164](https://github.com/advatar/ActiveChain/issues/164).

- [x] Persist the complete multi-asset Coin Cell set and canonically sorted policy registry
  atomically, requiring every cell to resolve to one policy and every policy supply to equal its
  checked cell total.
- [x] Define issuer registration, threshold-controlled mint/burn, redemption, pause/recovery,
  and supply-attestation lifecycle semantics with deterministic vectors.
- [x] Add a canonical commitment-only fungible supply attestation binding asset, issuer, policy,
  exact issued supply, finalized height, and approval evidence.
- [x] Publish deterministic positive/malformed supply-attestation vectors for external issuer
  and wallet conformance.
- [x] Add canonical issuer-registration envelopes with strict authority/policy bindings and
  half-open activation windows.
- [x] Add an exact registration-to-policy binding predicate for issuer, authority set, asset, and
  policy commitment substitution resistance.
- [x] Add a Kani proof boundary for supply-attestation identity and exact-supply preservation.
- [x] Freeze canonical bounded pause/resume/retire lifecycle actions with policy, authority,
  reason, and activation/expiry bindings.
- [x] Bind lifecycle actions to a concrete threshold-approval commitment.
- [x] Add canonical threshold-approval envelopes for mint, burn, and redemption with exact policy,
  authority, amount, pre-supply, operation, and validity bindings.
- [x] Specify confidential evidence retention, deletion, access, breach handling, and offline
  verification boundaries with deterministic vectors.
- [x] Add a commitment-only retention policy for evidence class, jurisdiction, access, breach,
  deletion mode, retention deadline, and offline verifier; raw evidence remains off-chain.
- [x] Publish the regulated screening profile boundary for list/provider commitments, refresh and
  matching parameters, outcomes, bounded overrides, freeze decisions, and privacy/audit handling.
- [x] Publish the privacy-preserving off-chain Travel Rule profile binding exact chain/action,
  asset/amount, parties, policy, nonce, expiry, and counterparty acknowledgement.
- [x] Specify transaction-monitoring population reconciliation, versioned rules, case lifecycle,
  freeze/escalation controls, FIU reporting boundaries, and stale-system fail-closed behavior.
- [x] Specify confidential evidence lifecycle, least-privilege access, retention/deletion/legal
  hold, breach response, offline verification, and jurisdiction ambiguity handling.
- [x] Specify release assurance evidence, operating-period records, independent engagement
  requirements, claim restrictions, exceptions, and residual-risk ownership.
- [x] Specify reproducible Apple artifact formats, generated interfaces, compatibility manifests,
  revision reporting, and fail-closed upgrade/migration policy.
- [x] Specify proof-bearing native-asset RPC query families and bindings for definitions, supply,
  owners, NFT records, actions, receipts, attestations, and empty/unsupported responses.

## Active launch sequencing — versioned feature contract

- [x] Reserve future type-tag ranges and publish fail-closed unknown-tag vectors for deferred
  v1.1/v1.2 dispatch; header/envelope extension qualification remains a release gate.

## Active epic — native asset tokenization

Tracked by [GitHub issue #164](https://github.com/advatar/ActiveChain/issues/164).

- [x] Freeze native fungible, non-fungible, and series asset definitions and lifecycle actions.
- [x] Reject fungible definitions with zero asset, issuer, or policy identities before registry
  admission; malformed identity vectors are deterministic.
- [x] Add a canonical native NFT token record with nonzero metadata commitment and owner-bound
  transfer semantics; series assets and full issuer authorization remain separate gates.
- [x] Add bounded NFT series definitions with metadata-schema commitments and checked mint
  reservation accounting; issuer authorization remains enforced by the action layer.
- [x] Bind every NFT series mint reservation to the exact issuer, authority set, pre-state series
  commitment, minted count, quantity, approval commitment, and finalized execution window.
- [x] Bind approved NFT minting to a bounded canonical manifest of exact token IDs, recipients,
  and metadata commitments, then derive the reserved series state and token records atomically.
- [x] Reject NFT token-ID reuse across mint batches with a canonical per-asset registry whose
  pre/post cardinality must equal the exact series supply transition.
- [x] Reject NFT token and series definitions with zero asset, issuer, or owner identities before
  metadata and supply admission.
- [x] Add an immutable-identity NFT Coin Cell carrying asset/token/metadata commitments and
  owner-bound transfer semantics in the cash kernel.
- [x] Reject cash-layer fungible and NFT Coin Cells with zero asset or owner identities before
  authenticated-root admission.
- [x] Reject native monetary constitutions with zero chain or policy commitments before genesis
  allocation and supply partitioning.
- [x] Add a Kani proof boundary for NFT transfer identity preservation and non-owner rejection.
- [x] Prove approved NFT manifest minting advances exact supply, preserves series/token identity,
      and rejects every substituted approval, manifest, pre-state, or execution-height binding.
- [x] Prove the NFT token-registry successor preserves existing identities, inserts each approved
      token exactly once in canonical order, and matches finalized minted supply.
- [x] Add a canonical NFT Coin Cell record wrapper for proof-bearing RPC/indexing integration.
- [x] Reserve an explicit RPC query kind for NFT Coin Cells; proof verification remains
  fail-closed until an authenticated NFT membership tree is published.
- [x] Add canonical request round-trip coverage for the NFT query tag and retain unsupported
  proof rejection until the finalized root schema is extended.
- [x] Enforce issuer/controller authority, supply conservation, declared controls, and corporate
  actions in consensus, persistence, authorization, and formal proofs.
  - [x] Admit exact policy/authority/window-bound corporate actions as validator payloads and
    commit their replay-safe registry successor in consensus asset-ledger state.
  - [x] Admit issuer- and approval-bound pause, resume, and retirement actions as exact consensus
    policy successors, including the zero-supply retirement rule.
  - [x] Persist each accepted controller rotation as one atomic policy/controller-state successor,
    revalidating exact commitments and revision bindings on restart.
  - [x] Execute controller rotation through validator action admission and commit the exact policy
    and controller-revision successor in consensus asset-ledger state.
  - [x] Authenticate the complete policy/Cell ledger through a canonical state-tree anchor proven
    against finalized post-state, and reverify the joined evidence on restart.
  - [x] Admit threshold-approved fungible mint, burn, and redemption as versioned validator action
    payloads that atomically advance the consensus multi-asset ledger.
  - [x] Prove controller rotation preserves immutable policy economics, advances revision exactly
        once, and rejects every substituted pre-state binding or invalid execution height.
  - [x] Prove lifecycle controls preserve immutable policy economics and reject substituted
        bindings, invalid heights, illegal transitions, and nonzero-supply retirement.
  - [x] Prove exceptional holder controls enforce declared powers, preserve identity, advance the
        exact revision once, and reject substitution, replay, invalid height, and overflow.
  - [x] Prove an authorized clawback changes only Coin Cell ownership while preserving origin,
        asset, amount, and creation height, with malformed cell/action bindings rejected.
- [x] Define canonical corporate-action envelopes for distributions, splits/consolidations,
  coupons, maturity, record-date voting, and redemption offers.
  - [x] Add bounded exact-once corporate-action admission bound to the finalized asset policy,
    authority set, and half-open execution window.
- [x] Add canonical mint and burn supply-state transitions with exact pre-state, issuer, lifecycle,
  cap, overflow, and conservation checks.
- [x] Add bounded Kani proofs for mint cap/conservation and burn non-underflow invariants.
- [x] Add consensus-facing approved mint/burn boundaries that bind issuer, authority set, asset,
  policy commitment, operation, amount, pre-state, and activation height.
- [x] Require a nonzero authority-set commitment when constructing fungible asset policy state;
  unbound policy state cannot enter lifecycle or supply transitions.
- [x] Add replay-safe controller rotation that binds the exact policy/controller pre-state,
  current and replacement authority sets, monotonic revision, approval, and execution window.
- [x] Expose proof-bearing asset, supply, owner, action, receipt, and attestation RPC contracts.
- [x] Specify the proof-bearing native-asset RPC families and fail-closed empty/unsupported
  semantics in `docs/NATIVE_ASSET_RPC_V1.md`; authenticated server wiring remains a gate.
  - [x] Wire finalized state-proof verification for asset definitions, issuer registrations,
    supply attestations, corporate actions, and settlement receipts.
  - [x] Expose NFT series supply and minted-token registries as exact-type, finalized
    object-membership RPC records while keeping unsupported NFT Coin Cell proofs fail closed.
  - [x] Verify NFT series and token-registry records locally through the versioned wallet ABI,
    binding exact query kind, canonical value, finalized membership, height, and trusted genesis.
- [x] Ship native issuer CLI and console workflows with threshold approval and recovery initiation
      as currently specified by P-020; challenge, cancellation, and completion remain future
      protocol extensions.
- [x] Ship a deterministic issuer CLI for policy commitments and threshold-approval envelopes;
  malformed hex, operations, amounts, and validity windows fail closed.
- [x] Extend the issuer CLI with deterministic, strict supply-attestation envelope generation.
- [x] Extend the issuer CLI with deterministic issuer-registration envelope generation and
  inverted-window rejection.
- [x] Extend the issuer CLI with strict canonical asset-definition and pause/resume/retire
  lifecycle-action generation.
- [x] Extend the issuer CLI with deterministic NFT series, exact mint-manifest, threshold-approval,
  and replay-protected offline dry-run workflows.
- [x] Extend the issuer CLI with canonical controller-state, rotation-envelope, and exact offline
  policy/controller post-state dry-run workflows.
- [x] Add a P-020-scoped issuer recovery-initiation CLI that binds the exact issuer principal,
      recovery authority, challenge window, evidence/bond, and post-challenge controller rotation.
- [x] Add an issuer-console recovery-initiation review reconstructed from the canonical principal,
      exact recovery request, challenge window, and first-post-challenge controller rotation.
- [x] Add an issuer-console controller-rotation review derived from exact canonical pre/post
  policy and controller state, authorities, revision, approval, and finalized execution window.
- [x] Add an issuer-console review surface derived from the exact approved NFT manifest, series,
  minted-token registry, authority, validity window, and replay-protected post-state transition.
- [x] Extend the issuer CLI with canonical distribution, split/consolidation, coupon, maturity,
  record-date vote, and redemption-offer generation.
- [x] Add exact-once corporate-action CLI preflight and an issuer-console review derived from the
  accepted policy, action, and registry transition.
- [x] Persist accepted corporate-action identities atomically before acknowledgement and restore
  replay protection fail-closed across restart or corrupt storage.
- [x] Prove the production corporate-action admission predicate requires the exact asset, policy,
  authority set, and half-open finalized execution window.
- [x] Declare holder freeze and clawback powers immutably at asset creation, then enforce exact,
  revisioned, authority-approved exceptional controls without changing Coin Cell value or identity.
- [x] Add deterministic issuer CLI workflows to declare, construct, and dry-run freeze, unfreeze,
  and clawback actions against exact holder state and Coin Cell inputs.
- [x] Add an issuer-console review reconstructed from the accepted declared-control transition,
  including holder, destination, amount, revision, freeze state, approval, reason, and window.
- [x] Persist canonically sorted per-holder freeze/unfreeze revisions before acknowledgement,
  rejecting replay, cross-binding, corrupt restart state, and state-only clawback execution.
- [x] Persist an exact clawback Coin Cell and its matching holder-control revision as one atomic
  snapshot, preserving value and identity while rejecting replay and partial failure.
- [x] Persist the complete authoritative fungible Coin Cell set and matching holder revision in one
  clawback snapshot, preserving the target record identity and all unrelated cells.
- [x] Execute canonical fungible transfers against the authoritative set by consuming exact
  origin-derived input records and creating one deterministic policy- and freeze-gated output.
- [x] Persist the authoritative fungible set successor before acknowledging an ordinary transfer,
  restoring replay protection fail-closed across restart, corruption, and failed writes.
- [x] Join threshold-approved fungible minting to one authoritative successor containing both the
  deterministic new Coin Cell and the exact advanced policy supply state.
- [x] Join threshold-approved fungible burns to one authoritative successor containing both exact
  input removal and the identically reduced policy supply state.
- [x] Join threshold-approved redemptions to exact authoritative input removal and supply reduction
  while retaining the external settlement reference for separately finalized receipt evidence.
- [x] Persist fungible policy supply and the complete authoritative Coin Cell set as one canonical
  ledger, requiring exact checked supply equality on create, restart, and every transition.
- [x] Publish deterministic issuer-registration vectors for activation boundaries and malformed
  authority/policy bindings.
- [x] Keep the workspace lockfile synchronized with the canonical payment-types cryptographic
  dependencies so targeted issuer/payment tests leave a reproducible clean checkout.
- [x] Complete wallet ABI compatibility, adversarial transition, and migration implementation
  gates for the #164 native-asset scope.
  - [x] Expose verifier ABI, canonical schema, and protocol revisions through the native wallet
        ABI so shells can negotiate proof-bearing native-asset compatibility before verification.
  - [x] Reject supply-inconsistent and ambiguous partially upgraded legacy asset snapshots during
        standalone-ledger and chain-state migration.
- [ ] Complete independent wallet/native-asset audit and external interoperability qualification;
  these evidence gates do not reopen the completed #164 implementation scope.

## Active design — privacy-preserving tokenization identity

Tracked by [GitHub issue #165](https://github.com/advatar/ActiveChain/issues/165).

- [x] Accept bounded OpenID4VP-derived SD-JWT VC and mdoc presentations through separate,
  versioned external verifier adapters with a closed format/profile allowlist.
- [x] Reject credential-status registries with zero registry, issuer, schema, root, or sequence
  identities before status/freshness admission.
- [x] Bind minimal selective-disclosure and ZK attribute proofs to asset, action, audience, nonce,
  policy revision, holder key, expiry, and finalized credential-status evidence.
- [x] Compose asset-specific identity policies with APL and authorization without global KYC.
- [x] Add wallet consent/disclosure controls, pinned issuer/profile policy tooling,
  cross-repository interoperability vectors, privacy analysis, and replay/correlation tests.
- [x] Complete the #165 ActiveChain implementation scope and retain commitment-only identity facts
  without raw credential material or global KYC state.
- [ ] Complete independent interoperability, privacy, and security review gates under #569 and
  #579; these external evidence gates do not reopen the completed #165 implementation scope.

## Active integration — TLS evidence, wallet credentials, and ZK predicates

Tracked by [GitHub issue #169](https://github.com/advatar/ActiveChain/issues/169).

Detailed remaining implementation slices:

- [x] Production OpenID4VP transport and live trust/status adapters
  ([GitHub issue #562](https://github.com/advatar/ActiveChain/issues/562)).
- [x] TLS evidence proof-of-funds predicate circuits
  ([GitHub issue #563](https://github.com/advatar/ActiveChain/issues/563)).
- [x] Private age, residency, and jurisdiction predicate proofs
  ([GitHub issue #564](https://github.com/advatar/ActiveChain/issues/564)).
- [x] Assurance-preserving ML-DSA companion credentials
  ([GitHub issue #565](https://github.com/advatar/ActiveChain/issues/565)).
  - [x] Freeze the separate native companion, governed assurance transition, dual-status, and
    provenance-preserving admission contract; reject relabeling external ES256/COSE credentials.
  - [x] Add substitution, escalation, revocation disagreement, replay, and authority-boundary unit
    vectors, then merge the targeted-test-qualified implementation to `main`.
- [x] Evidence-to-credential-to-APL refinement and non-escalation proofs
  ([GitHub issue #568](https://github.com/advatar/ActiveChain/issues/568)).
- [ ] Cross-device VCIssuer/EUWallet interoperability qualification
  ([GitHub issue #569](https://github.com/advatar/ActiveChain/issues/569)).
  - [x] Add a fail-closed cross-repository digest, privacy and evidence-schema qualification harness
    plus an honest supported/blocked compatibility matrix.
  - [ ] Complete physical Android qualification ([#578](https://github.com/advatar/ActiveChain/issues/578)),
    independent review ([#579](https://github.com/advatar/ActiveChain/issues/579)), and physical Apple
    end-to-end qualification ([#580](https://github.com/advatar/ActiveChain/issues/580)).

## Active dBrowser downstream qualification

- [x] Publish the stable verifier SDK, wallet ABI, RPC/light-client, artifact-readiness, and
  honest-development-state contract for downstream dBrowser integration.
- [x] Re-run the downstream verifier API qualification: all 10 principal, capability, policy,
  authorization-chain, state-witness, receipt, finality-bundle, and finalized-anchor tests pass
  with strict version/framing and real PQ vote checks.

## Active PQ-ZK/CashAIR qualification

- [x] Specify proof public-input bindings, PQ authorization ordering, typed failure behavior,
  formal-assumption disclosure, and v1.0 CashAIR re-execution fallback.
- [x] Publish executable proof-admission vectors for verified, missing, malformed, substituted,
  and unknown proof states.

- [x] Freeze cross-repository schemas and deterministic vectors from TLSNotary evidence through
  self-issued or issuer-upgraded VC claims to ActiveChain circuit public inputs and receipts.
- [x] Preserve explicit provenance and assurance classes: notarized TLS evidence and holder
  self-issuance must never be silently promoted to EUDI PID, (Q)EAA, regulated KYC, or bank attestation.
- [x] Specify proof-of-funds predicates for currency/asset, threshold/range, institution membership,
  observation freshness, aggregation rules, units/decimals, and holder binding.
  - [x] Add a canonical proof-of-funds public-input envelope binding currency/asset units,
    threshold/range, institution set, observation window, holder, and exact action context.
- [x] Add privacy-preserving age/range and nationality/jurisdiction membership or non-membership
  predicates with canonical registry/set commitments and inference-risk consent warnings.
- [x] Integrate EUWallet custody, validation, provenance UI, consent, presentation, deletion,
  recovery, and audit with ActiveChain-bound audience/action/policy/nonce requests.
- [x] Verify only minimal commitments, predicates, status/freshness, assurance, and pairwise/nullifier
  replay controls on ActiveChain; keep transcripts, account identifiers, and full balances off-chain.
  - [x] Add a canonical finalized predicate receipt preserving the exact evidence and assurance,
    predicate, verifier/proof version, status, policy, nullifier, and finalized-height bindings.
  - [x] Consume receipt nullifiers through the canonical accumulator and persist the updated root
    atomically before acknowledgement, rejecting replay, stale witnesses, and corrupt restart state.
  - [x] Persist admitted transcript-free receipts and the corresponding nullifier accumulator as
    one canonical atomic ledger so restart preserves both replay protection and receipt evidence.
- [x] Formally prove the evidence-to-claim-to-circuit-to-APL refinement, no provenance escalation,
  predicate soundness, action/audience binding, replay resistance, and declared unlinkability.
- [x] Pass cross-repository malformed/adversarial vectors, device-key integration unit coverage,
  and offline receipt-verification gates.
- [ ] Complete physical-device, privacy-review, and independent-audit evidence under #569,
  #578, #579, and #580.

## Active communication — first-class protocol primitives

Tracked by [GitHub issue #172](https://github.com/advatar/ActiveChain/issues/172).

- [x] Explain why assets, verified attributes, policies, and receipts are consensus-native types.
- [x] Distinguish the implemented APL typed AST/evaluator from its planned authoring syntax/compiler.
- [x] Distinguish ObjectVM contract bytecode from RISC Zero private proof guests and generic RISC-V.
- [ ] Pass responsive browser verification.
- [x] Pass the production landing-page build (`npm run build`) after the native-asset and
  regulated-profile content updates.

## Active documentation — whole-system architecture and agent keys

Tracked by [GitHub issue #174](https://github.com/advatar/ActiveChain/issues/174).

- [x] Publish one guide joining principals, wallet and agent keys, capabilities, credentials,
  policies, assets, execution, proofs, networking, receipts, recovery, and formal verification.
- [x] Specify agent enrollment, custody, session separation, rotation, compromise, revocation,
  recovery, migration, multi-device, remote-agent, and third-party-application behavior.
- [x] Mark implemented, developmental, planned, unaudited, and formally unproved boundaries.

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
- [x] Update Amber's RPC client to schema revision 2 and qualify its status decoder against the
  deployed Kanalen RPC; unsigned CLI test installation remains an expected local signing gate.

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

## Active release fix — Amber bundle versions

Tracked by [GitHub issue #160](https://github.com/advatar/ActiveChain/issues/160).

- [x] Define canonical marketing and build versions for every Amber application target.
- [x] Preserve Apple development team `L2AF8KFX35` when regenerating the Xcode project.
- [x] Validate built iOS and macOS Info.plists and pass native Apple qualification.

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
- [x] Restore the pinned guest lockfile and targeted PQ-ZK/private-billboard unit-test reproducibility
  after workspace dependency updates.

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

- [x] Recover and reconcile the unpublished consensus-safety and authorization-chain proof work
  against current `origin/main`
  ([GitHub issue #127](https://github.com/advatar/ActiveChain/issues/127)).
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
    - [x] Prove the abstract history-lifting theorem: consensus-supplied comparable finalized tips
          yield prefix-comparable full histories, durable restart preserves the exact history, and
          an epoch change remains a parent-bound extension; production trace refinement remains.
    - [x] Add a byte-identical Rust/Lean executable refinement trace covering skipped-view
          finalization, durable restart, exact epoch activation, and post-activation finalization;
          the unbounded production trace theorem remains open.
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
  - [x] Add a byte-identical Rust/Lean cash-lifecycle refinement trace for authorized issuance,
        one-shot reward redemption, shield/unshield conservation, replay rejection, and canonical
        restart; broader unbounded and block-finality refinement remains open.
  - [x] Prove one-shot verifier duty settlement, exact bond conservation
        (`bond_return + slash = bond`), bounded slashing, and rejected-settlement state
        preservation in Lean, with a byte-identical Rust/Lean refinement trace over the production
        `register_assignment`/`settle_duty` kernel; cryptographic receipt authorization, principal
        identity, and Coin Cell custody of bonds and rewards remain production-boundary
        assumptions.
  - [x] Prove OpenWallet consent-bound issuance in Lean: `issuanceRequiresConsent` (an accepted
        `completeIssuance` in any reachable state implies the trace contains an `authorizeIssuance`
        step carrying exactly the offer's consent digest), `preAuthorizedOffersAreRejected` (the
        [#678](https://github.com/advatar/ActiveChain/issues/678) regression: an offer decoded in
        any state other than `offered` is refused and the step is a no-op), `grantNonceIsOneShot`,
        `disclosureAnswersTheRequest` (no over-disclosure and no unanswered requested schema), and
        `rejectedTransitionsPreserveState`, with a byte-identical 14-step Rust/Lean refinement trace
        over the production `OpenWalletAdapterV1` (`testing/vectors/credential/openwallet-consent-model-table.txt`,
        `scripts/check-openwallet-consent-refinement.sh`); canonical decoding, cryptographic issuer
        authentication, credential-content validity, and digest collision resistance remain
        production-boundary assumptions recorded in `formal/OPENWALLET_CONSENT_PROOF_SCOPE.md`.
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
- [x] Add TLA+ consensus/reconfiguration/crash models, Verus refinement proofs, and Kani bounded
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

- [x] Qualify the bytecode verifier boundary: all 10 tests pass for linear-resource ownership,
  branch merge safety, declared u8 destinations, initialization/event bounds, forward reachability,
  malformed-byte rejection, canonical body bounds, and runtime entry certificates.

- [x] Qualify ObjectVM execution: all 12 tests pass for deterministic execution, exhaustive
  small-gas oracle agreement, full instruction-set refinement, checked arithmetic failure,
  evidence substitution rejection, gas-before-failure accounting, and exact result bounds.

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
- [x] Qualify the action kernel: all seven tests pass for resource-dimension charging, fee/nonce
  bounds, replay-gap-exhaustion distinctions, exact envelope commitments, published lengths, and
  nonce advancement.
- [x] Define bounded canonical action-envelope, fee-ticket, block, action-receipt, and block-receipt schemas.
- [x] Qualify the generic transition kernel: all eight tests pass for atomic receipt publication,
  scratch-state rollback, ordered/nonempty commands, typed semantic failures, canonical
  round-trips, and exactly-once object advancement.
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

- [x] Qualify the policy kernel: all 15 tests pass for bounded AST/request validation, strict
  canonical envelopes, default-deny/forbid precedence, deterministic obligations, exact fact and
  approval lookup, metering independence, and general-effect-fold refinement.

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

- [x] Qualify the state-tree implementation: all 11 tests pass for deterministic roots, bounded
  canonical proofs, membership/non-membership verification, path/default rejection, key/version
  binding, authenticated updates, and independent nibble/partition oracle refinement.

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

- [x] Qualify the privacy-kernel implementation: all 23 tests pass for protected ordering,
  ML-KEM/ML-DSA boundaries, forced inclusion, public-lane isolation, nullifier atomicity,
  scoped disclosure, builder settlement/slashing, authenticated networking, and durable state.

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
- [x] Qualify the cryptographic provider boundary: all five tests pass for real ML-DSA-44
  signatures, ML-KEM-768 round-trips/tamper rejection, associated-data-bound protected envelopes,
  consensus vote payloads, and canonical quorum transcripts.

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
- [x] Qualify the Kanalen current-main consensus recovery fix
  ([GitHub issue #262](https://github.com/advatar/ActiveChain/issues/262)).
  - [x] Persist each retained certified block as its complete verified proposal, quorum
    certificate, and ordered signed vote proof; migrate the bounded schema-v4 snapshot format.
  - [x] Authenticate request and response consensus traffic and persist inbound/outbound replay
    barriers before accepting or emitting a sequence.
  - [x] Cover restart, replay, malformed authenticated response, and missing certified-history
    behavior with focused regression tests.
  - [x] Pass local and remote-compatible three-validator qualification, merge the fix to `main`,
    and verify its commits are reachable from `origin/main` before closing #262.
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
- [x] Qualify the data-availability kernel: three unit tests, one checked-in fixture test, and
  serialized reconstruction coverage pass for parity-loss recovery, commitment tamper detection,
  deterministic bounded sampling, and distributed payload reconstruction.
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

- [x] Add exact-once refundable cash-capacity reservations with bounded resource prepayment and
  deterministic unused-balance refunds.
- [x] Add front-running-resistant commit/reveal admission for objective verifier challenges.
- [x] Add unbiased deterministic audit assignment from finalized randomness and a canonical
  eligible-verifier set.
- [x] Add canonical paymaster policy authorization with exact fee, epoch-budget, nonce, expiry,
  sender, transfer, and policy-revision binding.
- [x] Apply sponsored cash transfers atomically with separate sender value and paymaster fee
  reserves, exact change, and paymaster budget/nonce advancement.
- [x] Persist the combined CashLedger and paymaster budget/nonce state atomically before
  acknowledging sponsored execution, with fail-closed restart and write-failure behavior.
- [x] Emit a canonical sponsored-execution receipt only after persistence, binding the exact
  transfer, sponsor, sender, fee, height, and combined pre/post state commitments.

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
- [x] Implement the transparent specialized CashAIR and direct-reexecution comparison
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
- [x] Reject reordered CashAIR rows and nonzero value/fee columns on rejected rows during
  canonical decoding, before direct re-execution.
- [x] Enforce CashAIR applied/rejected counters and contiguous pre/post cell and supply-root
  chains against the public inputs during canonical decoding.
- [x] Reject accepted CashAIR rows whose bounded output-plus-fee arithmetic overflows or exceeds
  the input value before direct re-execution.
- [x] Reject accepted CashAIR rows with zero input value at canonical decode time.
- [x] Reject CashAIR public inputs with zero batch, Coin Cell, or supply commitments before trace
  admission.
  - [x] Add a dedicated transparent STARK prover/verifier for row progression, outcome booleanity,
    failed-row atomicity, accepted/rejected counts, and pre/post Coin Cell root binding.
  - [x] Add specialized SHAKE, ML-DSA, membership, consumption, value/fee arithmetic,
    session-budget, and authenticated partition-root transition constraints.
    - [x] Arithmetize bounded per-row input/output/fee conservation and rejected-row zeroing.
      - [x] Arithmetize SHAKE, ML-DSA, authenticated membership/consumption, session budgets,
        and authenticated partition-root transitions.
        - [x] Complete the ML-DSA-44 verifier tables and their cross-table composition.
          - [x] Constrain and publicly bind the exact FIPS 204 forward NTT butterfly schedule over
                q=8,380,417; inverse NTT, matrix products, hints, norms, decoding, and challenge
                composition remain separate subgates.
          - [x] Constrain and publicly bind FIPS 204 coefficient-wise `MultiplyNTT` modular
                products; vector dot-product accumulation remains a separate subgate.
          - [x] Constrain FIPS 204 inverse-NTT butterflies and compose the mandatory
                `256^-1 mod q` scaling through the `MultiplyNTT` table.
          - [x] Compose four `MultiplyNTT` proofs with coefficient-wise modular accumulation for
                the fixed ML-DSA-44 matrix-row/vector dot product.
          - [x] Compose four proven matrix-row dot products into the complete fixed 4x4
                ML-DSA-44 matrix-vector multiplication.
          - [x] Constrain the decoded 10-bit `t1` range, multiply all four polynomials by `2^13`
                modulo q, and compose their forward NTT proofs for verifier precomputation.
          - [x] Validate the exact ML-DSA-44 `tau=39` sparse challenge polynomial and compose its
                NTT with all four `c_hat * t1_2d_hat` product proofs.
          - [x] Compose the complete verifier reconstruction `UseHint(InvNTT(A_hat*z_hat -
                c_hat*t1_2d_hat), h)` across all four ML-DSA-44 polynomials.
          - [x] Extend the specialized SHAKE256 AIR to bounded variable-length XOF output,
                constraining every absorption and squeeze permutation needed by ML-DSA sampling.
          - [x] Prove bounded SHAKE128 XOF output and bind all 16 ML-DSA-44 `ExpandA(rho)`
                rejection-sampled NTT polynomials, including the rejection fallback path.
          - [x] Prove bounded SHAKE256 output and bind ML-DSA-44 `SampleInBall(c_tilde)` to the
                exact Algorithm 29 rejection, swap, and sign-bit procedure.
          - [x] Bind canonical ML-DSA-44 `w1Encode` and prove the final
                `c_tilde = SHAKE256(mu || w1Encode(w1), 32)` verifier equality.
          - [x] Compose decoding, `tr`/`mu` hashing, `ExpandA`, reconstruction, and final challenge
                equality against one canonical ML-DSA-44 key, signature, and cash payload.
          - [x] Constrain ML-DSA-44 public-key/signature bit unpacking, `z` infinity-norm range,
                and canonical hint decoding, exposing exact decoded verifier inputs.
          - [x] Constrain ML-DSA-44 `UseHint` decomposition, signed low bits, adjustment branches,
                and modulo-44 wraparound for all four verifier polynomials.
        - [x] Bind the exact authorized-transfer envelope and ML-DSA-44 verification key into the
          session STARK public inputs, then compose real signature verification at proof admission;
          this binding does not replace the remaining in-circuit ML-DSA arithmetic gate.
        - [x] Replace external session signature verification with the composed ML-DSA-44 table
          proof over the exact authorization payload and committed verification key.
        - [x] Add authenticated Coin Cell membership, one-time consumption, and partition/global
          root transition constraints
          ([GitHub issue #76](https://github.com/advatar/ActiveChain/issues/76)).
          - [x] Carry canonical per-row partition transition witnesses through CashAIR, bind their
            global roots in the parent STARK, and prove every touched partition's SHAKE paths.
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
  - [x] Add recursive microbatch, partition, cash-slot, and global-transition aggregation.
    - [x] Derive every proof-leaf field from one verified authorized payment, its composed
      session/ML-DSA proof, and its authenticated partition-aware CashAIR receipt.
    - [x] Define canonical bounded aggregation statements and a composed verifier that binds
      ordered child-proof commitments, partition ownership, resource totals, and contiguous
      pre/post roots at every level.
    - [x] Add pinned RISC Zero leaf, microbatch, partition, cash-slot, and global-transition guests;
      each aggregation guest verifies exact child image IDs and canonical journals through resolved
      receipt assumptions, and the host accepts only unconditional succinct receipts.
- [x] Add the cash-specific capacity and fee market, refundable deposits, sponsorship, and paymasters.
  - [x] Adjust deterministic base fees from bounded target-capacity utilization and quote exact
        base, resource, and congestion charges.
  - [x] Require exact prepaid capacity deposits, settle reservations once, and refund every unused
        unit while rejecting underfunding, expiry, overuse, and arithmetic overflow.
  - [x] Bind paymaster authorization to the sponsor policy, allowed sender, exact transfer and fee,
        epoch budget, monotonic nonce, and expiry window.
  - [x] Apply sponsored value transfer, sender change, sponsor fee change, and paymaster budget
        advancement atomically so a rejected sponsorship mutates no state.
- [x] Implement the first accountable verifier-duty kernel: role-scoped bond lots, one-shot assignments, fixed rewards, receipt validation, and bounded objective penalties.
- [x] Add random audit assignments and commit/reveal challenge rewards without passive-verifier inflation.
  - [x] Select one auditor from a canonical eligible set using finalized randomness, target binding,
        and rejection sampling without modulo bias.
  - [x] Seal challenge evidence behind a commitment bound to the challenger and duty, enforce reveal
        and resolution deadlines, and settle the assigned reward at most once.
- [x] Add deterministic one-shot challenge assignments and bounded challenge reward resolution.
- [x] Add deterministic fee quotes from base, resource, and congestion components.
- [x] Build a reproducible proof-finalized cash throughput benchmark with real PQ, DA, state, and
      proof work.
  - [x] Measure deterministic ML-DSA authorization, authenticated Coin Cell execution, CashAIR
        proving and verification, and Reed-Solomon availability reconstruction in one pipeline.
  - [x] Emit machine-readable stage timings, verified throughput, and proof/availability sizes,
        with a bounded real-pipeline smoke test.
- [x] Pass the full local-runner CI matrix.
- [x] Update and push the landing-page roadmap at each completed major milestone.
  - [x] Advertise the proof-aware ActiveBridge Rust SDK and reconcile implemented versus
    externally qualified identity claims (activechain-display#17).
  - [x] Advertise the reproducible proof-finalized cash benchmark with explicit local-measurement
        and non-production caveats (activechain-display#19).
  - [x] Advertise PQ-native payments and VCIssuer identity integrations directly on the homepage,
        retaining pre-testnet, device-qualification, independent-review, and pilot caveats
        (activechain-display#21).

## Planned milestone — `did:activechain` identity method

Detailed remaining implementation slices:

- [x] Post-quantum key lifecycle and deterministic DID vectors
  ([GitHub issue #566](https://github.com/advatar/ActiveChain/issues/566)).
  - [x] Add canonical ML-DSA control/SLH-DSA recovery and ML-KEM agreement method documents,
    exact record commitments, role-bound lifecycle transitions, and terminal deactivation tests.
  - [x] Verify network-bound lifecycle authorizations with real ML-DSA-65/87 and
    SLH-DSA-SHAKE-192s signatures without suite fallback.
  - [x] Connect lifecycle signing payloads to opaque native custody callbacks.
  - [x] Publish deterministic create/rotate/recover/deactivate/resolution vectors and migration
    coverage, including wrong-key, rollback, suite-confusion, and post-deactivation failures.
- [x] Non-authoritative ENS aliases
  ([GitHub issue #567](https://github.com/advatar/ActiveChain/issues/567)).

- [x] Freeze the method-specific identifier, PQ verification methods, resolver boundary, and
  finalized lifecycle operations in `spec/protocol/P-095-activechain-did-method.md`.
- [x] Implement canonical DID controller records and resolver responses; strict constructors,
  lifecycle binding, canonical round-trip, and malformed zero-identity vectors are covered in
  `protocol-types` tests.
- [x] Add a canonical commitment-only `DidControllerRecordV1` with monotonic, previous-commitment
  bound updates and explicit deactivation-safe lifecycle semantics.
- [x] Add canonical `DidResolutionV1` responses binding a nonzero method DID to finalized height
  and an optional public controller record.
- [x] Add canonical create/update/recover/deactivate DID operations with authorization and
  previous-record commitment binding.
- [x] Implement the domain-separated SHAKE method-specific DID derivation from `PrincipalId` and
  method version; reject zero principals and key/name-derived aliases.
- [x] Enforce active-state semantics for DID update/recovery operations and require inactive
  records exclusively for deactivation operations.
- [x] Publish deterministic DID controller lifecycle vectors covering create, update, deactivation,
  zero identities, previous-commitment, and authorization failures.
- [x] Prove DID controller lifecycle safety in Lean: `createRequiresFreshIdentity` (an accepted
  create carries no previous commitment, starts at sequence 1, and applies only to an unregistered
  principal), `sequenceIsStrictlyMonotone` (every accepted update/recover/deactivate strictly
  increases the record sequence; the model's sequences are unbounded `Nat`, so the `u64` ceiling
  stays covered by the [#683](https://github.com/advatar/ActiveChain/issues/683) `checked_add`
  regression test rather than by the model),
  `operationBindsPreviousCommitment` and `staleOrForeignCommitmentIsRejected`,
  `deactivationIsTerminal` (also proved under an arbitrary trace),
  `controlCannotAuthorizeRecovery`/`recoveryCannotAuthorizeUpdateOrDeactivate`, and
  `rejectedOperationsPreserveState`, with a byte-identical 17-step Rust/Lean refinement trace over
  the production `DidControllerOperationV1::new` and
  `DidControllerRecordV1::apply_document_operation`
  (`testing/vectors/did-lifecycle-model-table.txt`,
  `scripts/check-did-lifecycle-refinement.sh`); commitment collision resistance, ML-DSA/SLH-DSA
  signature unforgeability, canonical encoding, authenticator validity windows, and finalized
  registry storage remain production-boundary assumptions
  ([#700](https://github.com/advatar/ActiveChain/issues/700)).
- [x] Add domain-separated operation commitments for replay-safe DID lifecycle indexing.
- [x] Add ML-DSA rotation, ML-KEM agreement, SLH-DSA recovery, deactivation, and DID test vectors.
- [x] Add ENS alias records without treating ENS control as protocol authorization.
- [x] Freeze the VCIssuer-to-ActiveChain handoff for OpenID4VCI-issued SD-JWT VC and mdoc
  presentations as a bounded commitment-only, assurance-preserving, action-bound canonical value.
- [x] Implement the governed `ExternalIssuerBindingV1` and finalized bounded registry: stable
  issuer principals, explicit ordered profile allowlists, previous-bound lifecycle transitions,
  collision rejection, finalized lookup, and cross-network/rollback failure are unit tested.
- [x] Freeze EUDI/VCIssuer profile-to-schema derivation and consume byte-identical vectors in
  ActiveChain and VCIssuer; arbitrary caller-provided schema identifiers must fail closed (#439).
- [x] Implement account-bound, pairwise, private-proof, and device-bound external subject
  association profiles with wallet authorization, scoped derivation, rotation/recovery, and replay
  rejection (#440).
- [x] Implement governed mirrored external status and issuance-transparency snapshots with
  monotonic anchoring, bounded freshness, source migration, publisher authorization, and offline
  lookup evidence (#444).
- [x] Implement the bounded external SD-JWT VC/OpenID4VP verifier with pinned issuer, schema,
  holder, request, trust, and status inputs plus typed fail-closed rejection behavior (#441).
- [x] Implement the separately versioned bounded mdoc/COSE/OpenID4VP verifier with canonical CBOR,
  issuer/device authentication, namespace digests, session binding, and typed rejection codes
  (#442).
- [x] Admit opaque outputs from registered external credential adapters through P-021 policy and
  derive only bounded schema facts for P-023, with non-leaking context-bound receipts (#443).
- [x] Implement wallet-owned external presentation display, explicit consent/user presence,
  minimal disclosure, cancellation, replay-safe audit, and rollback-aware recovery (#445).
- [x] Publish and consume a digest-locked synthetic identity bridge corpus across ActiveChain,
  VCIssuer, and EUWallet with positive and named-boundary negative vectors (#446).
- [x] Prove bounded external identity authenticity, schema/holder/status/context/replay safety,
  authority separation, assurance monotonicity, minimization, and Rust/model parity (#447).
- [x] Complete wallet OpenID4VP transport, consent UX, live trust/status adapters, and
  cross-repository vectors.
- [ ] Complete physical-device qualification and independent interoperability/privacy/security
  review ([#569](https://github.com/advatar/ActiveChain/issues/569)).

## Active milestone — OpenWallet-aligned ActiveChain wallet

- [x] Add `activechain-wallet-core` with policy-gated Coin Cell intents and deterministic fee checks.
- [x] Add a deterministic ML-DSA testnet wallet CLI for operator/genesis identity derivation.
- [ ] Add encrypted PQ keystore, ML-DSA/ML-KEM key lifecycle, DID resolution, and recovery.
- [x] Add CLI adapter for testnet transfer, verifier bonding, duty receipts, and reward redemption.
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
    - [x] Add a canonical secret-free agent authenticator registry with provenance, enrollment,
      monotonic rotation, compromise deactivation, durable restart safety, and formal properties
      ([GitHub issue #176](https://github.com/advatar/ActiveChain/issues/176)).

## Active milestone — dBrowser verifier compatibility

### Apple external digest-anchor client boundary

Tracked by [GitHub issue #387](https://github.com/advatar/ActiveChain/issues/387).

- [x] Construct bounded canonical `DigestAnchorStatementV1` envelopes and deterministic
  submission references through the shipped Apple verifier ABI.
- [x] Encode submit/resolve RPC request envelopes and decode bounded anchor RPC responses without
  requiring Swift to reimplement the consensus codec.
- [x] Publish generated C declarations, deterministic vectors, and Swift/URLSession integration
  guidance while retaining explicit-trust finalized-evidence verification.
- [x] Pass affected-crate and reproducible Apple distribution qualification; merge the
  implementation and verify it is reachable from `origin/main`. The queued full deterministic
  kernel run was explicitly skipped in favor of normal tests during issue reconciliation.

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
- [x] Qualify the embeddable light-client implementation: all four library tests pass for
  wrong-genesis/signature rejection, finalized validator-set upgrades, stale/fork restart safety,
  corruption rejection, and data-availability reconstruction binding.
- [x] Add a local manifest checker for vector hashes and malformed fixtures.
- [x] Deliver the stable downstream integration contract required by dBrowser
  - [x] Make Apple linkage readiness machine-readable and fail closed: distributions must
    distinguish a contract-ready artifact from a signed, independently audited release.
  ([GitHub epic #86](https://github.com/advatar/ActiveChain/issues/86)).
  - [x] Build a versioned verifier SDK for principals, capabilities, APL decisions, state
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
    - [x] Add receipt and joined authorization-chain verifiers with complete positive and
      malformed vectors.
      - [x] Verify canonical block receipts against a cryptographically verified finality bundle,
        exact receipt commitment, height, and pre/post state transition through matching Rust and
        C result codes.
      - [x] Verify joined authorization chains.
        - [x] Publish bounded canonical whole-chain attenuation, finalized-height validity, root
          linkage, and leaf actor-binding verification through matching Rust and C result codes.
        - [x] Join capability and actor signatures to principal controller keys proven against the
          finalized state root ([GitHub issue #626](https://github.com/advatar/ActiveChain/issues/626)).
          - [x] Canonicalize object-backed finalized principal and authenticator-set witnesses
            ([GitHub issue #627](https://github.com/advatar/ActiveChain/issues/627)).
  - [x] Expose Coin Cell discovery, policy evaluation, canonical intents, approval-bound signing,
    secure-key callbacks, and submission through the wallet ABI
    ([GitHub issue #87](https://github.com/advatar/ActiveChain/issues/87)).
    - [x] Expose deterministic Coin Cell selection from a canonical bounded cell-set envelope
      through a null-safe C ABI with distinct payment and fee-reserve outputs.
    - [x] Expose pure spending-policy evaluation with exact 128-bit limits, daily accounting, and
      optional recipient pinning through the C ABI.
    - [x] Construct the exact canonical cash authorization request and intent identifier through a
      size-query C ABI without exposing secret material.
  - [x] Complete validator-backed owner-scoped Coin Cell/state extraction before serving wallet
    balances on Kanalen, including proof-bearing public owner queries (issue #180).
    - [x] Make the Kanalen round publisher fail closed unless the exact finalized cash snapshot and
      certificate bundle are both present, so a metadata-only height cannot be advertised as a
      wallet-ready finalized state.
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
  - [x] Pass downstream conformance against dBrowser while retaining the developmental and
    unaudited release status until the external security gate completes.
  - [x] Consolidate verified release branches into `main`, retire superseded branches, and enforce
    a single active implementation branch per issue
    ([GitHub issue #125](https://github.com/advatar/ActiveChain/issues/125)).

## Planned initiative — Kenya VASP and stablecoin regulatory profile

- [ ] Implement fail-closed Kenya VASP and stablecoin regulatory support aligned to the 2025 Act
  and 2026 Regulations without representing protocol capability as legal approval
  ([GitHub issue #369](https://github.com/advatar/ActiveChain/issues/369)).
  - [ ] Publish a regulation-by-regulation Kenya control register and source/version metadata.
  - [ ] Replace the Kenya design placeholder with versioned VASP and stablecoin-issuer manifests.
  - [ ] Add canonical activation validation for mandatory controls, approvals, validity, and policy
    commitments.
  - [ ] Add deterministic positive, negative, expiry, ambiguity, inheritance, and cross-border
    conformance vectors and unit tests.
  - [ ] Document deployment gates for licensing, regulator approval, counsel, reserves, custody,
    audits, reporting, and operating-period evidence.

## Planned milestone — external pre-launch security audit

- [x] Publish the exact audit scope, evidence requests, exclusions, and release-blocking
  acceptance criteria in `docs/SECURITY_AUDIT_SCOPE.md`.

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

## Planned initiative — MCP interoperability and constrained A2UI approvals

## Active implementation — Portable Actum Agent Plugin

- [ ] Package Actum node fluency and plugin-owned lifecycle operations as an Agent Plugins v1.0.0
  package ([GitHub issue #767](https://github.com/advatar/ActiveChain/issues/767)).
  - [x] Publish schema-valid portable and Codex manifests, Actum skills, and the existing MCP
    server configuration.
  - [x] Bound start, stop, status, logs, and queries to explicit plugin-owned data and processes.
  - [x] Add deterministic lifecycle and conformance tests plus installation documentation.
  - [ ] Pass affected checks and the exact full deterministic-kernel gate before integration.

- [x] Deliver MCP agent interoperability and constrained A2UI approval surfaces without making
  either transport or presentation an authority boundary
  ([GitHub issue #355](https://github.com/advatar/ActiveChain/issues/355)).
  - [x] Freeze versioned schemas, trust boundaries, and the threat model
    ([GitHub issue #356](https://github.com/advatar/ActiveChain/issues/356)).
    - [x] Add a host-only bounded MCP/A2UI DTO crate outside the consensus trusted base.
    - [x] Publish machine-readable schemas, normative boundaries, threats, and conformance vectors.
    - [x] Integrate the verified implementation into `origin/main`; the exhaustive
      deterministic-kernel gate was explicitly skipped during issue reconciliation.
  - [x] Implement proof-bearing read-only MCP tools and resources
    ([GitHub issue #361](https://github.com/advatar/ActiveChain/issues/361)).
    - [x] Implement stable MCP lifecycle, deterministic tool discovery, bounded stdio framing, and
      typed proof-verifying RPC adapters on a branch stacked above #356.
    - [x] Pass touched-crate tests, strict Clippy, formatting, and canonical type-registry checks
      after integrating #356 and current `origin/main`.
    - [x] Merge the verified candidate into `origin/main`; the exhaustive deterministic-kernel
      gate was explicitly skipped during issue reconciliation.
  - [x] Implement a proposal-only MCP intent and capability gateway
    ([GitHub issue #357](https://github.com/advatar/ActiveChain/issues/357)).
    - [x] Define a canonical, request-bound transfer `ActionIntent` and deterministic commitment.
    - [x] Enforce exact agent/capability/chain/wallet/resource/recipient/expiry/budget bindings before
      durable proposal admission.
    - [x] Persist idempotency and lifecycle state atomically across restart and emit non-secret audit
      events without exposing signing, submission, or arbitrary forwarding.
    - [x] Add policy-specific anchor proposals using the canonical bounded statement envelope and
      exact domain/reference binding. Normal touched-crate qualification replaces the queued full
      deterministic-kernel run during issue reconciliation; integrate the candidate into
      `origin/main`.
  - [x] Route MCP proposals through canonical native wallet approval
    ([GitHub issue #358](https://github.com/advatar/ActiveChain/issues/358)).
    - [x] Decode the canonical proposal intent at the shared wallet boundary and derive every
      review field and the exact approval commitment without trusting MCP display labels.
    - [x] Require the existing authenticated native signing callback to sign only the reviewed
      proposal commitment, with expiry and substitution checks.
    - [x] Expose equivalent Apple and Android proposal review paths and persist bounded lifecycle
      transitions across restart, rejection, approval, submission, finality, expiry, and failure.
    - [x] Add Rust and platform tests for equivalence, spoofing, substitution, stale/concurrent
      review, replay, restart/background-resume recovery, and finality resolution. Normal affected
      Rust, Android, Swift-package, and exact-head Apple distribution/macOS suites replace the
      explicitly skipped exhaustive CI gate during issue reconciliation; integrate and verify the
      candidate in `origin/main`.
  - [x] Render approvals and results through a constrained, fail-closed A2UI layer
    ([GitHub issue #360](https://github.com/advatar/ActiveChain/issues/360)).
    - [x] Add a host-only renderer that reconstructs verified approval facts, separates untrusted
      explanations, binds actions to the canonical intent, and emits a deterministic native fallback.
    - [x] Add bounded A2UI component/data fixtures and adversarial tests for deceptive content,
      action substitution, accessibility labels, and unsupported surfaces.
    - [x] Add transfer receipt, capability grant, agent enrollment, credential disclosure, and
      job/proof DTOs; reconstruct transfer facts directly from the canonical proposal intent and
      allow commitment-bound actions only to begin #358's authenticated native-wallet flow or
      persist rejection. Normal touched-crate tests and strict Clippy replace the explicitly
      skipped exhaustive CI gate during issue reconciliation; integrate into `origin/main`.
  - [x] Rehearse an end-to-end MCP transfer proposal, approval, finality, and verified receipt
    ([GitHub issue #362](https://github.com/advatar/ActiveChain/issues/362)).
    - [x] Add a deterministic three-validator local rehearsal harness with bounded setup/teardown
      and no persistent custody secrets.
    - [x] Correlate the MCP request, canonical proposal, reviewed commitment, authorization,
      transaction, finalized record, and independently verified receipt.
    - [x] Exercise happy-path, denial, expiry, failure, and idempotent reconnect/retry lifecycle
      outcomes without treating MCP transport or A2UI presentation as authority.
    - [x] Document every trust boundary and developmental/unaudited status; normal affected
      integration tests and strict Clippy are green, and merge commit `e8c3928` is reachable from
      `origin/main`.
  - [x] Complete adversarial security, compatibility, and operational qualification
    ([GitHub issue #359](https://github.com/advatar/ActiveChain/issues/359)).
    - [x] Consolidate prompt-injection, substitution, replay, lifecycle, malformed payload, and
      deceptive A2UI cases into an automated qualification suite.
    - [x] Publish the supported MCP/A2UI compatibility matrix and fail-closed version policy.
    - [x] Add incident-disable, privacy/telemetry, audit-log, and resource-exhaustion operator
      guidance plus an external security-audit scope update.
    - [x] Normal affected tests and strict Clippy are green, merge commit `fed7927` is reachable
      from `origin/main`, and the exhaustive deterministic-kernel gate was explicitly skipped.
  - [x] Announce the planned MCP and constrained A2UI interfaces on the public landing page
    without presenting them as shipped or audited
    ([GitHub issue #364](https://github.com/advatar/ActiveChain/issues/364)).

## Active release fix — CashAIR proof segmentation across build profiles

- [x] Make authenticated receipt segmentation tests enforce the size-derived wire contract rather
  than a debug-build-specific segment count
  ([GitHub issue #747](https://github.com/advatar/ActiveChain/issues/747)).
  - [x] Derive the expected segment count from each encoded proof length and the canonical maximum
    segment size while retaining losslessness, ordering, and bound checks.
  - [x] Pass affected debug and release tests, strict Clippy, and the exact full deterministic-kernel
    gate before integrating the stacked recovery branches into `origin/main`.

## Active release fix — Semantic-devnet empty-block vector drift

- [x] Reconcile the canonical empty-block fixture with the deterministic semantic-devnet generator
  ([GitHub issue #749](https://github.com/advatar/ActiveChain/issues/749)).
  - [x] Confirm the changed block ID and receipt root are stable consequences of current canonical
    inputs, then update only the directly coupled vector material.
  - [x] Pass semantic-devnet tests, exact vector reproduction, strict affected Clippy, and the exact
    full deterministic-kernel gate before integrating the stacked recovery branches into
    `origin/main`.
# Resumable deterministic-kernel qualification

Tracked by [GitHub issue #788](https://github.com/advatar/ActiveChain/issues/788).

- [x] Split the monolithic ARM64 gate into independently visible and rerunnable stages without
  dropping any existing final-candidate command or exact-revision binding.
- [x] Add a lightweight affected-change lane for ordinary development commits and an explicit
  full-qualification trigger for final merge candidates, `main`, and release contexts.
- [x] Add a fail-closed aggregate result and workflow-policy regression coverage so a candidate
  cannot appear qualified when a mandatory stage was skipped or failed.
- [x] Document the maintainer workflow and qualify synchronization-aware candidate `3000f6a6` in
  split run `31340339674`; merge to `main` and reachability remain.
- [x] Make force-push synchronization classification detect an unreachable `before` SHA and
  conservatively fall back to the complete PR-base diff; candidate `c6e0f01a` passed split run
  `31354777749`.
