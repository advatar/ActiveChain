# P-050: ObjectVM bytecode and execution semantics

- Status: Draft 0.1
- Protocol version: Development
- Issue: <https://github.com/advatar/ActiveChain/issues/6>

## 1. Scope

This revision defines the first typed ObjectVM bytecode, its consensus security verifier, and a deterministic reference interpreter. It is deliberately a single-entry, single-program kernel. P-051 will add immutable packages, modules, imports, calls, and upgrades without weakening these local instruction guarantees.

The compiler is untrusted. Only bytecode accepted by the verifier is executable. Optimized interpreters and future native backends MUST refine the result of this reference semantics.

## 2. Consensus boundary

ObjectVM receives only an explicit program, typed input values, and a gas limit. It has no ambient caller, global-state lookup, clock, filesystem, network, floating point, reflection, runtime loading, or nondeterministic collection operation.

Version 1 bounds are:

```text
registers       1..32
inputs          0..16, occupying the register prefix
output types    0..16
instructions    1..256
events          0..16
```

All registers have one statically declared type and one of three verifier states: `Uninitialized`, `Available`, or `Moved`. Destinations MUST be uninitialized, making version-1 bytecode SSA-like. A moved register is never reusable.

## 3. Value and resource types

```text
U64         copyable scalar
Bool        copyable scalar
Digest      copyable 384-bit scalar
Capability  affine CapabilityId
Object      linear canonical Object
```

Copyable values MAY be read or copied any number of times. Capabilities MUST NOT be copied and MAY be explicitly consumed, returned, moved, or omitted at return. Objects MUST NOT be copied or consumed. Every available linear object at a return MUST occur exactly once in the declared outputs. Because move invalidates its source and every control-flow merge requires identical register states, verification preserves exactly one live representative of each input object.

## 4. Instructions

The registered version-1 instruction set is:

```text
LoadU64(dst, value)          cost 1
LoadBool(dst, value)         cost 1
LoadDigest(dst, value)       cost 2
Copy(dst, src)               cost 1
Move(dst, src)               cost 1
AddU64(dst, left, right)     cost 2
EqU64(dst, left, right)      cost 1
Jump(target)                 cost 1
BranchIf(condition, target)  cost 1
ConsumeCapability(src)       cost 1
Emit(src)                    cost 4
Return(sources)              cost 1 + number of sources
```

`AddU64` uses checked unsigned arithmetic and execution fails on overflow. `EqU64` compares unsigned values. `Emit` accepts only `U64`, `Bool`, or `Digest` and copies that scalar into the ordered event list. `Return` is terminal and its source types MUST exactly equal the program output types.

## 5. Control flow and termination

Program counters and jump targets are zero-based `u16` instruction indexes. Every jump target MUST be strictly greater than the current counter and less than the instruction count. Conditional fallthrough MUST also exist. Back edges and self edges are invalid, so recursion and loops are absent in this first slice.

Every instruction MUST be reachable. Every reachable path MUST terminate in `Return`; falling beyond the instruction list is invalid. When two paths reach one instruction, all register availability states MUST be identical. The verifier tracks the maximum event count across incoming paths and rejects any path exceeding the program declaration or the protocol maximum.

These rules bound verification and execution by 256 iterations plus bounded state merges over 32 registers.

## 6. Static verification

The verifier rejects:

- an out-of-range register or target;
- a non-forward control-flow edge;
- an unavailable source or already-initialized destination;
- any operand or destination type mismatch;
- copying an affine or linear value;
- consuming a non-capability;
- emitting a resource value;
- different register states at a merge;
- an unreachable instruction or non-returning path;
- a duplicate return register or output signature mismatch;
- an available linear object omitted from return; or
- a statically possible event count above the declared bound.

Successful verification returns an opaque `VerifiedProgram`. The interpreter accepts no unverified program.

## 7. Execution

Inputs MUST exactly match the declared input prefix in count and type. Before each instruction changes VM state, the interpreter computes its registered cost and requires that the cumulative value not exceed the caller gas limit. Gas exhaustion therefore never partially executes the failing instruction.

The reference interpreter uses a vector of optional typed values corresponding exactly to the verified registers. Loads initialize, copies clone only scalars, moves take the source, and capability consumption takes and discards only the affine identifier. Branch selection depends only on a typed Boolean register. Execution returns on the first reached `Return` with exact gas, step count, ordered outputs, and ordered scalar events.

For verified bytecode with matching inputs, structural register/type failures are unreachable implementation-invariant errors. Arithmetic overflow and insufficient gas remain deterministic execution failures.

## 8. Canonical types

```text
VmProgramV1          type 0x0060, schema 1, max body  12,854 bytes
VmExecutionResultV1  type 0x0061, schema 1, max body 270,508 bytes
```

Program encoding includes the input count, complete register type vector, output signature, instruction vector, and maximum event count. Instruction and value discriminants are one byte. Lists use P-001 minimal bounded lengths. Execution results encode gas, steps, outputs, and events in field order.

## 9. Required properties

Implementations MUST test:

```text
same verified program + inputs + gas -> identical result
copy(linear or affine)                -> verifier rejection
return without every live object      -> verifier rejection
inconsistent branch resource state    -> verifier rejection
backward/out-of-range target           -> verifier rejection
insufficient gas                       -> failure before the instruction
u64 overflow                           -> deterministic execution failure
malformed/trailing canonical bytes     -> decoding failure
```

The Lean model fixes the copy/move/consume resource algebra and instruction costs independently. Rust and Lean produce one frozen differential table. Canonical vectors publish a verified program, its typed inputs, and exact execution result.

## 10. Deferred refinements

P-051 defines packages, modules, imports, entry functions, immutable code commitments, synchronous calls, call-depth limits, and upgrades. Later P-050 revisions add object field operations, policy and cryptographic host calls, compute-job creation, proof traces, and richer bounded integer types. None may introduce hidden state or make an existing verified program nondeterministic.
