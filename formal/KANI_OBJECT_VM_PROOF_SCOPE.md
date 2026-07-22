# ObjectVM Kani Proof Scope

Status: compositional bounded verification slice implemented and passing on 2026-07-21.

This artifact is deliberately **not** an end-to-end Kani proof of `verify(program)` followed by
`execute(&VerifiedProgram, ...)`. It checks seven small, actual production predicates and semantic
helpers with Kani, then uses ordinary exhaustive, differential, property, and fixture tests for the
allocation-heavy whole-verifier/whole-interpreter composition. Claims must preserve that boundary.

## Pinned verifier and production-source preflight

- `cargo-kani 0.67.0`
- Kani driver `0.67.0`
- Kani release bundle `kani-0.67.0-aarch64-apple-darwin`
- bundled CBMC `6.8.0`
- bundled Rust `nightly-2025-11-21-aarch64-apple-darwin`
- bundled `rustc 1.93.0-nightly (53732d5e0 2025-11-20)`

Kani 0.67.0 cannot load the main workspace's Rust 1.97.1 package metadata. The verification-only
workspace under `crates/object-vm/kani-workspace` declares Rust 1.93 metadata while its library
targets point to the production source files. Before every run, the gate rejects any target that
does not resolve to these exact files:

- `crates/bytecode-verifier/src/lib.rs`
- `crates/canonical-codec/src/lib.rs`
- `crates/object-vm/src/lib.rs`
- `crates/protocol-types/src/lib.rs`

The preflight also requires every external package version, source, and checksum in the proof lock
to occur in the production `Cargo.lock`. No verifier, interpreter, value type, or codec is copied
into the proof workspace.

Run both proof packages with:

```sh
./scripts/check-kani-object-vm.sh
```

For each of `activechain-bytecode-verifier` and `activechain-object-vm`, the exact Kani options are:

```sh
cargo kani \
  --manifest-path crates/object-vm/kani-workspace/Cargo.toml \
  --package <package> \
  --lib \
  --target-dir "${TMPDIR:-/tmp}/activechain-kani-object-vm" \
  --jobs 2 \
  --output-format terse \
  --default-unwind 8 \
  -Z unstable-options \
  --harness-timeout 180s
```

Default memory-safety, undefined-behavior, arithmetic-overflow, assertion, and unwinding checks stay
enabled. The loop-free proof helpers fit the unwind bound; an insufficient bound would fail an
unwinding assertion. Each package process has a 300-second process-group timeout and runs Cargo
offline after the locked preflight. Resource settings can be changed with
`ACTIVECHAIN_KANI_OBJECT_VM_PROCESS_TIMEOUT`, `ACTIVECHAIN_KANI_OBJECT_VM_HARNESS_TIMEOUT`,
`ACTIVECHAIN_KANI_OBJECT_VM_JOBS`, and `ACTIVECHAIN_KANI_OBJECT_VM_TARGET_DIR`. Changing a timeout
does not enlarge the state space or turn a timeout into a proof.

## Production refinement structure

The bytecode verifier now routes every register lookup through private `register_index`, while
every jump and branch still routes through private `require_target`. The interpreter routes every
instruction prepayment, `AddU64`, and `BranchIf` through private `prepay_gas`, `checked_add`, and
`select_branch_target` respectively.

Successful verification now also publishes an immutable `VerifiedInstructionState` for every
program counter. Each certificate contains the exact register-presence vector and the maximum
prior-event count obtained from the verifier's flow merge. `execute(&VerifiedProgram, ...)` passes
its concrete register presence and event count through the certificate's pure
`admits_runtime_state` predicate before every instruction. A mismatch fails closed as an invariant
violation before that instruction is charged or executed. An unchecked program still cannot cross
the public interpreter boundary.

The Lean model independently defines the same list-equality/event-bound certificate predicate and
proves its exact iff characterization for arbitrary register lists and event counts. It also proves
exact unit gas for arbitrary resource-action lists. This is a general semantic theorem, but not a
compiler proof that Rust execution refines Lean.

## Mechanically checked properties

The bytecode-verifier invocation reported:

```text
Manual Harness Summary:
Complete - 3 successfully verified harnesses, 0 failures, 3 total.
```

It establishes:

1. For every `u8` register and every register count from zero through 32, `register_index` returns
   that index exactly when it is declared and otherwise returns no index.
2. For every `u16` target, every instruction count from one through 256, and every current program
   counter within that program, `require_target` accepts exactly targets that are in bounds and
   strictly forward. Out-of-bounds targets and self/back edges return their exact structured error.
3. Across the complete five-value P-050 type table, only `U64`, `Bool`, and `Digest` are copyable
   event scalars; `Object` alone is linear; and `Capability` alone is affine. These are the same
   production predicates used by copy, emit, return, and capability verification.

The ObjectVM invocation reported:

```text
Manual Harness Summary:
Complete - 4 successfully verified harnesses, 0 failures, 4 total.
```

It establishes:

4. For every `u64` gas-used value, instruction cost, and gas limit at program counters zero through
   255, prepayment succeeds exactly when checked addition does not overflow and the complete next
   cost is within the limit. Every other case returns `GasExhausted` carrying the unchanged prior
   gas, exact cost, counter, and limit.
5. For every pair of `u64` operands at counters zero through 255, ObjectVM checked addition agrees
   with an `overflowing_add` oracle: a non-overflowing sum is exact and overflow returns the exact
   `ArithmeticOverflow` counter.
6. For every Boolean condition and every program counter/target within the 256-instruction bound,
   branch selection chooses the target exactly when true and exact fallthrough `pc + 1` when false.
7. Under verifier premises that both the explicit target and fallthrough exist and are strictly
   later, either selected branch edge remains strictly forward and in bounds; the selected value is
   the explicit target or exact fallthrough according to the condition.

Kani reports `caller_location` and a foreign-function construct elsewhere in the compiled
dependency graph. Kani fails a harness if an unsupported construct is reachable. All seven
harnesses completed, so those constructs do not block the checked paths.

## Executable whole-boundary evidence

Ordinary production tests remain essential to the compositional argument:

- all 256 possible `u8` destinations are passed through a real two-instruction `VmProgram` and the
  full `verify` entry point; only declared register zero succeeds;
- resource copy rejection, linear return preservation, forward/in-bounds targets, branch-state
  merges, event limits, unreachable code, and canonical malformed/trailing bytes exercise the full
  verifier;
- a verified gas fixture exhaustively tests limits zero through seven and proves failure is reported
  before the unaffordable instruction, while six or more gas produces the exact event/result;
- the verifier's complete eight-instruction resource fixture publishes exact entry certificates at
  every program counter; each correct concrete state is admitted while every single-bit presence
  substitution, event overflow, and wrong register-vector length is rejected;
- public execution checks those certificates on every visited instruction and repeated execution
  of an identical verified invocation produces an identical result;
- verified resource, addition, branch, overflow, input mismatch, evidence replay, and canonical
  result fixtures exercise the full interpreter; and
- a property test runs identical verified addition invocations twice over bounded `u32`-range
  operands and requires identical complete results.

At the recorded checkpoint, `activechain-bytecode-verifier` passes 10 tests and
`activechain-object-vm` passes 11 tests.

## Tested but unproved whole-program boundary

Two stronger Kani formulations were attempted without disabling checks:

1. one concrete verified three-instruction program through full `verify` and `execute`; and
2. the same concrete program through the private vector/register interpreter loop after separating
   it from verification.

Each exceeded the fixed 180-second per-harness budget while expanding allocation and enum dispatch.
Neither produced a counterexample. A timeout is not evidence of correctness, so neither formulation
is included in the seven passing claims. The whole-program refinement from arbitrary accepted
`VmProgram` to `VmExecutionResult` remains open for a more scalable model checker, contracts whose
premises are independently proved, or an unbounded theorem-prover refinement.

## Deliberate limitations

- This slice proves production helper obligations compositionally; it does not mechanically prove
  in one Kani query that full `verify` establishes every premise consumed by every interpreter
  instruction. The production certificate check makes disagreement explicit and fail-closed, but
  absence of disagreement for every possible accepted program remains an open theorem.
- It does not Kani-prove whole-run determinism. Determinism currently has executable branch,
  arithmetic, evidence-replay, differential, and property-test coverage.
- Version 1 uses immediate `LoadU64`, `LoadBool`, and `LoadDigest` operands, not a constant pool, so
  there is no constant index to validate. Future indexed constants require new verifier and Kani
  obligations before activation.
- The Lean model independently fixes resource classification and the six-row copy/move/consume cost
  table. This slice does not formally prove Rust/Lean compiler or table equivalence.
- Allocation failure, denial-of-service behavior at maximum protocol sizes, canonical codec
  correctness, object semantics, cryptographic evidence, consensus integration, and optimized
  backend refinement remain outside this artifact.

Claims derived from this artifact must use **compositional bounded verification** and must mention
that **whole verify-to-execute composition and whole-run determinism are not Kani-proved**.
