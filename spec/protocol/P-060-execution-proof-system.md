# P-060: Execution proof system and proving-machine selection

- Status: Draft 0.2 (Gate-1 reference implementation)
- Protocol version: Development
- Issue: not yet filed
- Supersedes: the "purpose-specific transparent STARK VM" sketch in `PQVM.md`

## 1. Scope

This document specifies the component that produces and verifies **execution validity proofs** for
the authoritative state transition: the proof system, its security profile, the verifier contract,
and the process by which the proving machine is selected.

It does **not** specify the private-relation proof path. That is `P-111`, which pins RISC Zero and
serves application-level private actions. The two paths are distinct: `P-111` proves that an
approved private relation holds; this document proves that the public transition function was
executed correctly.

`P-050` defines what is executed. This document defines what proves it.

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

## 2. Why this component exists

`P-000` §2 requires that independent clients reproduce every accepted transition, and `PQVM.md`
fixes the governing principle:

> No classical primitive may be sufficient to authorize state, establish finality, decrypt protected
> transactions, commit data availability, or validate execution.

Two consequences follow, and only the first is a requirement.

**Requirement.** If execution validity is established by proof rather than by universal
re-execution, that proof MUST be transparent and hash-based. Pairing-based commitments, KZG,
Groth16, and curve-committed PLONK are excluded because a quantum adversary that breaks the
commitment scheme can forge a validity proof, which is a soundness failure, not a privacy failure.

**Not a requirement.** That a *new instruction set* must be designed. `PQVM.md` reaches a
purpose-built machine by elimination — RISC Zero's Groth16 wrapping path is not PQ, therefore build
a bespoke VM — but the eliminated object is a *compression path*, not an instruction set. The
inference does not carry. §4 therefore treats the machine as an open selection with explicit
criteria, rather than a settled design.

This distinction is the reason this specification exists as a selection document. The proof-system
requirements in §5–§9 are binding regardless of which machine is chosen; the machine choice is
deferred to a gated decision in §4 and §11.

## 3. Non-goals

This component does not:

- replace `P-050` ObjectVM semantics as the definition of correct execution;
- provide privacy — execution proofs are validity proofs, not zero-knowledge proofs of hidden
  state, and MUST NOT be described as privacy-providing;
- prove anything about jobs, AI computation, or external evidence;
- establish finality, which is a consensus property;
- justify a general-purpose developer-facing zkVM.

## 4. Candidate architectures

Exactly one of the following MUST be selected before the proving path becomes consensus-required.
Each is evaluated against the criteria in §10.

### 4.1 Option A — prove `P-050` traces with an existing transparent STARK

An off-the-shelf transparent prover (Stwo, Plonky3, Winterfell class) generates an AIR for the
existing ObjectVM execution trace. No new instruction set. `P-050` semantics, its verifier, its
vectors, and its Lean models are preserved unchanged.

- Cost: constrained by ObjectVM's design, which was optimized for verification and determinism
  rather than for arithmetization. Trace width and instruction cost may be unfavourable.
- Risk: lowest. Failure mode is proving inefficiency, which is a performance problem, not a
  correctness or schedule problem.

### 4.2 Option B — fork a general transparent zkVM and remove non-PQ modes

Take an existing zkVM, delete Groth16/PLONK compression and every curve-based commitment, and pin
the transparent receipt mode only.

- Cost: inherits a large unowned codebase and its audit surface; the removed compression path is
  usually the one that makes proofs small enough for on-chain verification, so recursion must be
  rebuilt anyway.
- Risk: medium. Fork maintenance against upstream is indefinite.

### 4.3 Option C — purpose-built instruction set co-designed with the AIR

A compact machine whose instructions are chosen for cheap arithmetization: object reads and writes,
integer computation, policy evaluation, capability consumption, hashing, state-tree updates.

- Cost: highest. This is a multi-year cryptography and compiler programme, and it duplicates the
  semantic, verifier, vector, and formal-model work already completed for `P-050`.
- Risk: highest, and it is schedule risk on the critical path rather than performance risk.
- Benefit: potentially large constant-factor gains in proving cost, and a single semantic object
  rather than a semantics/AIR pair to keep in refinement.

### 4.4 Default

Option A is the default and MUST be treated as the selected architecture until Option B or C is
justified against §10 with measured evidence. A bespoke machine MUST NOT be adopted on the grounds
that RISC Zero's compression path is non-PQ; that argument selects a *receipt mode*, not an ISA.

## 5. Proof-system security profile

A conforming proof system MUST:

1. be transparent — no trusted setup, no structured reference string, no ceremony;
2. derive soundness only from hash-function assumptions and the soundness of the low-degree test;
3. use no elliptic curve, pairing, KZG commitment, or discrete-log assumption anywhere in the
   authoritative verification path, including in recursion and aggregation;
4. publish its claimed soundness in bits, and state explicitly whether that figure is provable or
   conjectured;
5. state its Fiat–Shamir assumption, including whether it is analysed in the quantum random-oracle
   model;
6. fix blowup factor, query count, grinding bits, and field, and treat every one of them as a
   protocol-versioned consensus parameter.

Post-quantum security is a **conditional claim** under these assumptions. Following `P-111`, this
specification MUST NOT be represented as unconditional security or as NIST certification.

Claimed soundness for the authoritative path MUST be at least 100 bits, and the parameter set
achieving it MUST be reproducible from published values alone.

## 6. Field and hash selection

The field and the AIR-internal hash MUST be fixed per protocol version and registered like a
cryptographic suite under `P-002`.

A tension MUST be resolved explicitly rather than silently:

- `P-001`/`P-002` use SHAKE256 with 384-bit output for all canonical commitments;
- SHAKE256 is expensive to arithmetize, and algebraic hashes (Poseidon2 class) are dramatically
  cheaper inside a trace but younger and less cryptanalysed.

The conforming resolution is:

- every commitment that crosses a protocol boundary — state roots, action identifiers, block
  identifiers, receipts — MUST remain SHAKE256/384 per `P-001`;
- an algebraic hash MAY be used **internally** to the proof system for Merkle commitments to the
  trace and for the FRI transcript;
- if an algebraic hash is used, its selection, parameters, and cryptanalytic status MUST be recorded
  as a named security assumption in `P-000` §4, and it MUST NOT be reused for any protocol-boundary
  commitment.

## 7. Verifier contract

The verifier is the security boundary and MUST be independently implementable from this document.

A conforming verifier MUST:

1. accept only the receipt kind and proof-system version registered for the protocol version in
   force, rejecting all others including development and fake receipt modes;
2. bind the proof to the exact program or AIR identity, the pre-state root, the canonical block, the
   post-state root, and the protocol and verifier versions;
3. strictly decode public inputs, rejecting unknown versions, malformed lengths, and trailing bytes;
4. be total, allocation-bounded, and free of unbounded recursion, consistent with `P-000` §6;
5. reach a decision within published, protocol-versioned resource bounds;
6. never accept a proof whose parameters differ from the registered set, even where the parameters
   would be individually valid.

Published bounds MUST include maximum proof size in bytes, maximum verifier memory, and maximum
verifier time on a named reference machine.

### 7.1 Verifier cost budget

`DECENTRALIZATION.md` rates cheap independent verification as the design's strongest property. That
rating is only meaningful if a bound exists, so the bound is normative:

- a proof-verifying light client MUST be operable on commodity consumer hardware;
- verification of one block's execution proof MUST NOT exceed the cost of verifying an Ethereum
  consensus light-client update by more than one order of magnitude;
- proof size MUST be small enough that a light client can retrieve one per block over a mobile
  network without exceeding published bandwidth limits.

If recursion is required to meet these bounds, the recursive verifier is part of the authoritative
path and inherits every requirement in §5.

## 8. Determinism and reproducibility

Proving MUST be reproducible: the same pre-state, block, and witness MUST yield a proof that the
same verifier accepts, under a pinned toolchain, with no dependence on clock, filesystem ordering,
locale, thread scheduling, or hardware accelerator availability.

Prover nondeterminism that changes proof bytes but not the verification outcome is permitted and
MUST be documented as such. Prover nondeterminism that can change the verification outcome is a
consensus fault.

Proving hardware MUST NOT be a validity authority. A GPU-, FPGA-, or ASIC-produced proof MUST be
verifiable by the same verifier and MUST NOT receive any protocol privilege.

## 9. Relationship to re-execution

Until the proving path meets §7 bounds and passes its gates, validator re-execution remains the
authoritative validity mechanism, consistent with `BLUEPRINT.md` §1.2's "validator re-execution as
defense in depth: initially yes."

The transition from re-execution-authoritative to proof-authoritative is a protocol-version change
and MUST be sequenced explicitly (see #314). The block header MUST reserve the proof field from
genesis even while proofs are not consensus-required, so that enabling them does not reinterpret
bytes accepted under an earlier version, which `P-000` §9 prohibits.

Prover unavailability behaviour MUST be specified before proofs become consensus-required
(see #316). Absent that specification, a concentrated prover market becomes a liveness dependency
even though it is correctly not a validity authority.

## 10. Selection criteria

The Option A/B/C decision MUST be made against measured evidence on all of:

| Criterion | Measurement |
|---|---|
| Proving cost | Prover seconds and peak memory per block at a stated workload profile |
| Proof size | Bytes, before and after recursion |
| Verification cost | Milliseconds and memory on the named reference machine |
| Soundness | Claimed bits, provable or conjectured, with parameters |
| Audit surface | Lines of consensus-path code that must be independently reviewed |
| Semantic duplication | Whether `P-050` semantics, vectors, and Lean models are preserved or duplicated |
| Second-client cost | Incremental conforming-verifier implementation effort (see #317) |
| Schedule risk | Whether failure is a performance problem or a critical-path problem |

A selection that improves proving cost while duplicating `P-050`'s semantic and formal-model work
MUST account for that duplication as a cost, including its permanent refinement-maintenance burden.

## 11. Decision gates

This component is plausibly the largest single engineering item in the programme. It therefore
carries explicit abandonment criteria rather than open-ended commitment.

**Gate 1 — feasibility.** A standalone Option-A reference package is implemented with a bounded
accumulator AIR and measured on the §10 criteria. It is deliberately a harness for the proof,
receipt, and verifier gates, not yet a claim that the AIR implements `P-050` ObjectVM. The gate
remains open until the same verifier boundary is refined against `P-050` and independently
reimplemented. If that refinement meets §7 bounds, the selection is closed at Option A and Options
B and C are not pursued.

**Gate 2 — justification.** Option B or C may be opened only if Gate 1 measurements show Option A
missing a §7 bound by a stated margin, and only with a written estimate of the full cost including
new semantics, new verifier, new vectors, new formal models, and second-client impact.

**Gate 3 — exit.** If no option meets §7 bounds by the milestone at which proofs are scheduled to
become consensus-required, the correct outcome is to defer the proof-authoritative transition to a
later protocol version and remain re-execution-authoritative, not to relax §5 or §7. Relaxing the
security profile to make a schedule is prohibited.

## 12. Test vectors and formal properties

Before the proving path may become consensus-required:

1. deterministic positive vectors binding pre-state, block, post-state, and accepted proof;
2. deterministic negative vectors for wrong program identity, wrong pre-state, wrong post-state,
   mutated public inputs, trailing bytes, unregistered parameter sets, unregistered receipt kinds,
   and development/fake receipt modes;
3. an independent verifier implementation reproducing every vector, per `P-000` §4;
4. a stated refinement claim joining the AIR or program semantics to `P-050`, with its assumptions
   published;
5. published cryptographic, toolchain, and platform assumptions per `P-000` §4.

A proof system with no independent verifier implementation MUST NOT be described as providing
independently verifiable validity.

## 13. Compatibility

Proof-system version, parameter set, field, hash, and receipt kind are jointly a registered suite.
A later protocol version MAY register a new suite but MUST NOT reinterpret a proof accepted under an
earlier suite. Historical verification MUST retain the original rules, per `P-000` §9.

## 14. Open questions

- Whether ObjectVM's instruction set, designed for verification rather than arithmetization, is
  workable as an AIR without modification, and what a minimal arithmetization-friendly revision of
  `P-050` would cost relative to Option C.
- Whether recursion is required at genesis-scale block sizes or only at target throughput.
- Whether the algebraic hash of §6 is acceptable in a consensus-path security assumption, given its
  cryptanalytic maturity relative to SHAKE256.
- Whether `P-111`'s pinned RISC Zero path and this path can share a verifier surface, or whether two
  independent proof verifiers are a permanent cost.
- The named reference machine for §7 bounds.

## 15. Implementation notes (non-normative)

The `p060-execution-proof` package contains the Gate-1 reference: a transparent Winterfell STARK,
strict protocol-bound receipts, deterministic positive and malformed vectors, a CLI vector checker,
and mutation/totality tests. It intentionally proves only an accumulator transition until the
`P-050` refinement is complete. `P-111` remains a separate private-relation proof path and does
not provide execution validity for public blocks.

The CashAIR crate is a separate specialized Option-A demonstration for the cash lane. Its
authenticated composite is registered as one suite identifier composed of the pinned Winterfell
parent and SHAKE permutation suite; it is not a general ObjectVM execution proof and does not
close the P-050 refinement gate.

The cheapest next step is Gate 1: arithmetize the existing `P-050` interpreter and measure. That
produces the evidence §10 requires and is useful work under every option, because a `P-050` AIR is
needed for Option A, is a baseline for Option B, and is the comparison Option C must beat.
