# ActiveChain formal-verification program

Formal verification is a launch gate. These artifacts are scoped models with explicit assumptions;
they are not a certificate that the complete implementation is correct.

## Tooling

- Lean 4 models executable semantics and algebraic invariants.
- Tamarin models adversarial protocol traces, authentication, replay, compromise, and ordering.
- Rust differential fixtures compare selected executable Lean tables with the implementation.

## Current proof domains

| Domain | Tool | Primary artifact | Mechanically checked result | Implementation refinement |
| --- | --- | --- | --- | --- |
| APL, credentials, objects, ObjectVM, state tree, nonce | Lean 4 | `formal/lean/ActiveChain/` | bounded semantic slices and six finite differential tables | incomplete; these are not full evaluator, VM, tree, or codec proofs |
| wallet-agent HITL and replay | Tamarin | `formal/tamarin/activechain_wallet.spthy` | scoped biometric approval and one-shot acceptance lemmas | not connected to the mobile mock bridges or secure storage |
| bounded consensus traces | Tamarin | `formal/tamarin/activechain_consensus.spthy` | authentication, replay, non-equivocation, quorum intersection, and frontier lemmas | partial; no cross-round chain-prefix finality refinement |
| weighted consensus arithmetic | Lean 4 | `formal/lean/ActiveChain/WeightedConsensus.lean` | arbitrary-weight intersection and conditional conflicting-QC exclusion | vote-lock and signer-set premises require Rust conformance |
| native cash and rewards | Lean 4 | `formal/lean/ActiveChain/Cash.lean`, `CashAuthorization.lean` | abstract conservation, issuance, burn, no-double-redemption, and chain-bound one-shot spend-admission target | incomplete; Rust still admits bare transfers, and finalized issuance/reward proof refinement is open |
| identity lifecycle and delegation | Tamarin | `formal/tamarin/activechain_identity.spthy` | bounded lifecycle, direct attenuation, revocation, and replay lemmas | upstream signature/state-proof provenance and multi-hop budgets are open |
| DA reconstruction and light-client trust | Lean 4 | `formal/lean/ActiveChain/DA.lean` | abstract reconstruction bounds and fail-closed trust transition | DA arithmetic and Rust state-machine refinement are open |
| canonical envelopes and FFI gates | Lean 4 | `formal/lean/ActiveChain/Envelope.lean` | abstract strict-decode, binding, and pointer/length preconditions | only bounded concrete tests currently connect to Rust/C ABI |
| epoch and protocol upgrades | Lean 4 | `formal/lean/ActiveChain/EpochUpgrade.lean` | exact activation, monotonic revision, retired-set, and stale-context rejection | Rust conformance is in progress |
| PQ peer sessions | Tamarin | `formal/tamarin/activechain_pq_session.spthy` | scoped suite, context, key-confirmation, and bounded replay target | target protocol is stronger than the current Rust handshake |

“Mechanically checked” means that the stated theorem holds in the named model. It does not imply
that arbitrary production Rust executions refine that model. A domain becomes implementation-level
evidence only after a trace, extraction, or differential conformance layer connects the concrete
code and serialized values to the formal state and assumptions.

## Local reproduction

```bash
bash scripts/check-formal-models.sh
```

The gate pins Lean through `formal/lean/lean-toolchain` and requires Tamarin 1.12.0. A proof run is
accepted only when each CI-selected lemma is `verified`, all well-formedness checks pass, and the
proof-scope document records assumptions, implementation mapping, and deliberately excluded
properties. The bounded consensus model retains one expensive composition target outside its
selected lemma list; the corresponding weighted arithmetic and conditional composition are proved
in Lean. Falsified lemmas and counterexample traces are evidence to fix the model, specification, or
code; they must never be hidden by weakening a property without documenting the change.

## Unverified boundary

The program does not yet establish end-to-end correctness of the Rust implementation. In
particular, it does not prove chain-prefix finality across rounds and reconfiguration, canonical
finalized-block composition, cryptographically authorized cash spending, the full
credential/capability/APL authorization chain, complete ObjectVM metatheory, cryptographic
primitive security, liveness under arbitrary scheduling, mobile OS security, production FFI memory
safety, or deployment correctness. The complete launch-gate backlog is tracked in `STATUS.md` and
GitHub issue #16. Independent formal-methods and security review remains mandatory before any
non-developmental or value-bearing launch.
