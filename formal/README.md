# ActiveChain formal-verification program

Formal verification is a launch gate. These artifacts are scoped models with explicit assumptions;
they are not a certificate that the complete implementation is correct.

## Tooling

- Lean 4 models executable semantics and algebraic invariants.
- Tamarin models adversarial protocol traces, authentication, replay, compromise, and ordering.
- TLA+ exhaustively explores bounded consensus, reconfiguration, and crash interleavings.
- Kani bounded-model-checks selected concrete Rust safety and canonicality boundaries.
- Verus proves selected checked-arithmetic contracts and compiles the verified target.
- Rust differential fixtures compare selected executable Lean tables with the implementation.

## Current proof domains

| Domain | Tool | Primary artifact | Mechanically checked result | Implementation refinement |
| --- | --- | --- | --- | --- |
| APL, credentials, objects, ObjectVM, state tree, nonce | Lean 4 | `formal/lean/ActiveChain/` | bounded semantic slices and six finite differential tables | incomplete; these are not full evaluator, VM, tree, or codec proofs |
| APL effect refinement | Lean 4 + Rust | `formal/lean/ActiveChain/Apl.lean`, `policy-kernel::eval` | arbitrary-list permit/forbid theorem plus exhaustive production differential enumeration through six rules | predicate-to-observation mapping remains a Rust-tested refinement boundary |
| state-tree refinement | Lean 4 + Rust | `formal/lean/ActiveChain/StateTree.lean`, `state-tree` | arbitrary proof folds and authenticated replacement roots, with production insert/update/delete differential recomputation | SHAKE256 and Rust-to-Lean compiler correspondence remain assumptions |
| wallet-agent HITL and replay | Tamarin | `formal/tamarin/activechain_wallet.spthy` | scoped biometric approval and one-shot acceptance lemmas | not connected to the mobile mock bridges or secure storage |
| bounded consensus traces | Tamarin | `formal/tamarin/activechain_consensus.spthy` | authentication, replay, non-equivocation, quorum intersection, and frontier lemmas | partial; no cross-round chain-prefix finality refinement |
| weighted consensus arithmetic | Lean 4 | `formal/lean/ActiveChain/WeightedConsensus.lean` | arbitrary-weight intersection and conditional conflicting-QC exclusion | vote-lock and signer-set premises require Rust conformance |
| checked consensus/economics arithmetic | Verus + Rust | `formal/verus/activechain_arithmetic.rs`, `protocol-types::checked_arithmetic` | eight no-cheating obligations for fee, strict-quorum, base-fee, supply, partition, and capped-issuance arithmetic; cash and consensus now call one shared production implementation with arbitrary-input property comparison against independent checked expressions | Verus compiler correspondence to the shared Rust source remains an assumption; the former duplicated production arithmetic and finite-vector-only bridge are removed |
| cross-view consensus safety | TLA+ / TLC | `formal/tla/ActiveChainConsensus.tla` | 936,652-state bounded exhaustive check of parent/QC binding, durable locks, prefix finality, crash/restart, and one root transition | Rust uses a conservative linear refinement with signed parent QCs, durable highest-QC/lock state, and consecutive two-QC commits; unbounded and reconfiguration-wide prefix proof remains open |
| membership churn and timed progress | TLA+ / TLC | `formal/tla/ActiveChainReconfiguration.tla` | two join/leave transitions, exact epoch/set certificate admission, retired-set rejection, durable crash snapshots, bounded deadlines/leader rotation, and progress under explicit weak fairness | quorum/signature formation and the distributed vote table are abstracted; liveness excludes crashes, permanent partitions, unfair scheduling, and unbounded delay; see `RECONFIGURATION_LIVENESS_TLA_PROOF_SCOPE.md` |
| proof-carrying block pipeline | TLA+ / TLC | `formal/tla/ActiveChainProofPipeline.tla` | 15,664-state bounded exhaustive check of exact proof-input binding, hostile/failing/withholding provers, retries, backpressure, stale cleanup, deterministic finalization, and one-time rewards | incomplete; proof-system soundness is assumed, crashes/liveness are excluded, and the Rust scheduler/finality/reward path has no refinement mapping |
| finalized-block composition | Lean 4 + Rust | `formal/lean/ActiveChain/BlockComposition.lean`, `consensus-runtime::finalized_block` | fail-closed binding and mismatch rejection across context, authorization, deterministic execution, economics, state, DA, proof inputs, and QC/header digest, with a typed proposal entry point and durable proof pipeline | implemented; cryptographic verifier soundness remains an explicit external assumption |
| joined authorization chain | Lean 4 + Rust | `formal/lean/ActiveChain/AuthorizationChain.lean`, `authorization-kernel` | PQ/finality evidence conjunction, credential freshness/revocation, multi-hop capability attenuation, exactly derived APL facts, transition binding, atomic budgets/replay/state, and serialized concurrent duplicate safety | implemented; cryptographic and finalized-proof soundness remain explicit boundary assumptions |
| native cash and rewards | Lean 4 | `formal/lean/ActiveChain/Cash.lean`, `CashAuthorization.lean` | abstract conservation, issuance, burn, no-double-redemption, and chain-bound one-shot spend-admission target | authoritative Rust ingress verifies exact ML-DSA-44 requests, finalized principal/authenticator provenance, and crash-atomically persists the ledger and replay barriers; the external finality-verifier refinement and issuance/reward refinement remain open |
| identity lifecycle and delegation | Tamarin | `formal/tamarin/activechain_identity.spthy` | bounded lifecycle, direct attenuation, revocation, and replay lemmas | upstream signature/state-proof provenance and multi-hop budgets are open |
| DA reconstruction and light-client trust | Lean 4 | `formal/lean/ActiveChain/DA.lean` | abstract reconstruction bounds and fail-closed trust transition | DA arithmetic and Rust state-machine refinement are open |
| canonical envelopes and FFI gates | Lean 4 | `formal/lean/ActiveChain/Envelope.lean` | abstract strict-decode, binding, and pointer/length preconditions | framing is production-linked below; schema-body and arbitrary foreign-memory refinement remain incomplete |
| canonical framing refinement | Lean 4 + Kani + Rust | `formal/lean/ActiveChain/Envelope.lean`, `canonical-codec`, `vector-generator` | unique all-`u32` length widths, shared production framing parser, eight Kani harnesses, and strict audit of all published envelope vectors | schema-body semantics and compiler correspondence remain separate boundaries |
| concrete canonical codec | Kani | `crates/canonical-codec/src/kani_proofs.rs` | seven bounded production-code harnesses over a two-byte body and adversarial inputs up to nine bytes | deliberately bounded; larger production schemas, allocation failure, DoS limits, persistence, and FFI remain open |
| verifier C ABI | Kani | `crates/verifier-ffi/src/kani_proofs.rs` | five production-wrapper harnesses for null/oversized rejection, exact safe-API refinement, strict status codes, and commitment pointer gates | deliberately bounded to envelope inputs through nine bytes; arbitrary foreign readable memory and SHAKE256 internals are assumptions, not proved claims |
| bytecode verifier and ObjectVM helpers | Kani | `crates/bytecode-verifier/src/verify.rs`, `crates/object-vm/src/execute/kani_proofs.rs` | seven production-helper harnesses over bounded registers/targets, the complete resource-class table, gas prepayment, checked addition, and forward branch selection | compositional only; full `verify`-to-`execute` and whole-interpreter queries timed out at 180 seconds and are not proved |
| production QC schema and shared quorum arithmetic | Kani | `protocol-types::consensus::kani_proofs` | arbitrary numeric QC strict round-trip, every fixed-QC truncation rejected, and all-input checked strict-quorum equivalence | digest contents are fixed; signature/hash internals, allocation failure, and other schemas remain outside the bounded claim; see `KANI_PROTOCOL_TYPES_PROOF_SCOPE.md` |
| commitment transcript binding | Kani | `protocol-commitment::kani_proofs` | production preimage construction binds every header field, exact length, and bodies through four symbolic bytes | SHAKE256 internals and collision resistance remain assumptions |
| network and durable-state admission | Kani + Rust | `protocol-types::admission`, `consensus-runtime` | all-input checked frame ranges/layouts and replay monotonicity; protected snapshots add atomic versioned exact-length checksum framing and restart/corruption tests | filesystem crash semantics and SHAKE256 internals remain assumptions |
| epoch and protocol upgrades | Lean 4 | `formal/lean/ActiveChain/EpochUpgrade.lean` | exact activation, monotonic revision, retired-set, and stale-context rejection | Rust now enforces signed prior authorization, exact activation, revision-bound QCs, and bounded retired-root persistence; trace/differential refinement remains open |
| PQ peer sessions | Tamarin | `formal/tamarin/activechain_pq_session.spthy` | 11 symbolic suite/context/replay, exact peer-correspondence, first-message-origin, and honest-session-secrecy lemmas | transcript-bound KDF and session state are not implemented in the current Rust handshake |

“Mechanically checked” means that the stated theorem holds in the named model. It does not imply
that arbitrary production Rust executions refine that model. A domain becomes implementation-level
evidence only after a trace, extraction, or differential conformance layer connects the concrete
code and serialized values to the formal state and assumptions.

## Local reproduction

```bash
bash scripts/check-formal-models.sh
bash scripts/check-proof-conformance.sh
bash scripts/check-tla-proof-pipeline.sh
bash scripts/check-kani-codec.sh
bash scripts/check-kani-verifier-ffi.sh
bash scripts/check-kani-object-vm.sh
bash scripts/check-kani-protocol-types.sh
bash scripts/check-kani-commitment.sh
formal/verus/verify.sh
```

The gates pin Lean through `formal/lean/lean-toolchain`, require Tamarin 1.12.0, require
`cargo-kani` 0.67.0 with its bundled Rust 1.93 nightly and CBMC 6.8.0, and checksum-pin official
Verus `0.2026.05.24.ecee80a`. A proof run is
preceded by `scripts/check-formal-coverage.py`, which accounts for all 24 Lean
targets/modules and all 42 lemmas in four Tamarin theories. Selectors must be
complete and unique; the timed-out `no_conflicting_qcs_for_one_slot` composition
is retained in the theory and explicitly classified in
`formal/tamarin/activechain_consensus.unproved` rather than silently skipped. A run is accepted
only when each CI-selected lemma is `verified`, all well-formedness checks pass, and the
proof-scope document records assumptions, implementation mapping, and deliberately excluded
properties. The bounded consensus model retains one expensive composition target outside its
selected lemma list; the corresponding weighted arithmetic and conditional composition are proved
in Lean. The proof-pipeline model is a finite safety result and makes no liveness or proof-system
soundness claim. The Kani claim is limited to the exact finite bounds in
`formal/KANI_CODEC_PROOF_SCOPE.md`; the C ABI claim is likewise limited to the exact bounds and
foreign-memory precondition in `formal/KANI_VERIFIER_FFI_PROOF_SCOPE.md`. The ObjectVM claim is the
compositional production-helper result in `formal/KANI_OBJECT_VM_PROOF_SCOPE.md`, not a whole-run
interpreter theorem. The Verus target is
connected to production by finite parity vectors, not an all-input refinement proof. Falsified
lemmas and counterexample traces are evidence to fix the model, specification, or code; they must
never be hidden by weakening a property without documenting the change.

## Unverified boundary

The program does not yet establish end-to-end correctness of the Rust implementation. In
particular, it does not prove unbounded chain-prefix finality across rounds and reconfiguration,
implementation refinement of canonical finalized-block composition, durable finalized cash-key
provenance and replay state, the full
credential/capability/APL authorization chain, complete ObjectVM metatheory, cryptographic
primitive security, liveness under arbitrary scheduling, mobile OS security, production FFI memory
safety, or deployment correctness. The complete launch-gate backlog is tracked in `STATUS.md` and
GitHub issue #16. Independent formal-methods and security review remains mandatory before any
non-developmental or value-bearing launch.
