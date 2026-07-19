# P-000: System goals, terminology, and security assumptions

- Status: Draft 0.1
- Protocol version: Development
- Issue: <https://github.com/advatar/ActiveChain/issues/1>

## 1. Scope

ActiveChain is a proof-carrying object ledger whose validity kernel combines a principal, credentials, capabilities, policies, objects, jobs, and proofs or receipts. This document fixes the boundary of the first implementation. It does not specify networking, consensus, data availability, a virtual machine, or proof-system parameters.

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

## 2. Goals

The protocol kernel MUST:

1. give every accepted value one canonical binary representation;
2. make authority explicit and deny operations without a complete authorization derivation;
3. keep deterministic execution independent of clocks, networks, filesystems, locale, and operating-system state;
4. use explicit protocol versions and cryptographic domains;
5. bound parsing, allocation, and execution before consuming attacker-controlled data;
6. preserve enough evidence for independent clients to reproduce every accepted transition.

The protocol MUST NOT treat a key as a principal, execute external computation inside consensus, infer real-world truth from credential validity, or permit governance to override an invalid transition.

## 3. Terms

- **Principal:** a stable protocol identity controlled by a versioned authorization policy.
- **Credential:** an issuer-signed claim normally held off chain.
- **Capability:** holder-bound, attenuable authority to perform bounded actions.
- **Policy:** a total, deterministic rule that may further restrict authority.
- **Object:** versioned state with explicit ownership and policy commitments.
- **Job:** an asynchronous request for externally executed computation.
- **Canonical value:** a typed value with exactly one accepted byte encoding.
- **Transition:** the deterministic mapping from a committed pre-state and canonical inputs to a committed result or a specified failure receipt.

## 4. Security assumptions

Initial kernel correctness assumes:

- SHAKE256 behaves as a collision- and preimage-resistant extendable-output function at the selected 384-bit output length;
- the pinned Rust compiler correctly implements safe Rust and fixed-width integer operations;
- independent clients implement this specification rather than importing the Rust transition function;
- host resource exhaustion can stop a node but cannot cause it to accept a different canonical value;
- future signature, proof, and consensus assumptions are suite- and version-specific and are not silently inherited by this draft.

The kernel MUST NOT depend on Python, Kubernetes, Wasmtime, PostgreSQL, RocksDB iteration order, a builder, a prover, or an AI worker for validity.

## 5. State-machine boundary

Conceptually, a protocol-version dispatcher invokes:

```text
transition(pre_state, canonical_block, witness, protocol_version)
    -> TransitionOutput | TransitionError
```

The function MUST be pure. All accepted failure paths MUST be represented by deterministic errors or receipts; malformed input MUST NOT produce partial state changes.

## 6. Resource bounds

Every consensus type MUST publish a maximum canonical body length. A decoder MUST validate lengths before allocation. Collections, recursion, call depth, and execution resources MUST have protocol-versioned limits before they are admitted to the transition function.

## 7. Required properties

The project SHALL progressively establish codec injectivity, deterministic transition output, default denial, capability attenuation, budget safety, replay freedom, object-version uniqueness, resource conservation, atomicity, and proof binding. P-001 starts the executable refinement chain with codec injectivity and strict decoding.

## 8. Test vectors

Versioned vectors live under `testing/vectors/`. A vector is normative only for the protocol version and type tag named by its manifest. Implementations MUST reproduce its body bytes, envelope bytes, and commitments exactly.

## 9. Compatibility

No draft is mainnet-compatible. A future protocol may add a type tag or schema version, but MUST NOT reinterpret bytes accepted under an earlier tag and version. Historical verification MUST retain the original rules.

## 10. Implementation notes (non-normative)

The reference kernel is split into small `no_std` Rust crates. Formal Lean models and independently implemented Go vectors will be added before distributed consensus work begins.
