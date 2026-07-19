Agreed. **Post-quantum security should be a genesis invariant, not a migration promise.**

That means Logos Execution Zone cannot be the protocol foundation unless its entire authoritative path is replaced or proven PQ-safe. LEZ may still be useful as prior art for explicit state inputs and unified public/private execution, but we should not inherit its cryptographic security model.

The corrected principle is:

> **No classical primitive may be sufficient to authorize state, establish finality, decrypt protected transactions, commit data availability, or validate execution.**

## Why LEZ is not acceptable as the base

LEZ currently relies on RISC Zero as its proving substrate. RISC Zero’s transparent STARK receipts can remain quantum-resistant under their hash-based assumptions, but its commonly used compact Groth16 wrapping path relies on BN254 and is explicitly not quantum-safe. RISC Zero itself distinguishes its quantum-resistant STARK receipts from its non-quantum-safe STARK-to-SNARK compression path.  [oai_citation:0‡RISC Zero](https://dev.risczero.com/api/security-model?utm_source=chatgpt.com)

More importantly, using LEZ would require auditing every inherited dependency in its full trust path:

- account signatures;
- sequencer authentication;
- consensus or settlement;
- state commitments;
- proof receipts;
- networking identity;
- wallet authentication;
- private-state encryption;
- upgrade authorization.

Even where the execution proof is a STARK, a classical signature or settlement layer elsewhere can still invalidate a claim of day-one PQ security.

So the correct position is:

> **Borrow LEZ’s ideas, not its trust root.**

---

# Revised architecture

We should build a **PQ-native Authority Object Runtime** with pluggable execution backends.

```text
Post-quantum principals and signatures
                    │
Post-quantum capabilities and credentials
                    │
Deterministic policy and object semantics
                    │
       Canonical execution representation
             ┌──────┴────────┐
             ▼               ▼
   Native interpreter   PQ STARK prover
             │               │
             └──────┬────────┘
                    ▼
       PQ consensus and finality
```

The authoritative implementation must not depend on:

- ECDSA;
- Ed25519;
- BLS;
- pairing-based commitments;
- KZG;
- Groth16;
- PLONK with curve-based commitments;
- classical VRFs;
- classical settlement chains.

NIST has finalized ML-KEM, ML-DSA, and SLH-DSA as its principal post-quantum standards, so these can anchor encryption, ordinary signatures, and independent hash-based recovery or checkpoint signatures from genesis.  [oai_citation:1‡NIST](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards?utm_source=chatgpt.com)

## Genesis cryptographic profile

| Function | Day-one choice |
|---|---|
| User authorization | ML-DSA-65 |
| Validator votes | ML-DSA-44 or ML-DSA-65 after benchmarking |
| Credential issuance | ML-DSA-65 |
| High-value recovery | ML-DSA plus SLH-DSA |
| Long-lived checkpoints | SLH-DSA |
| Network key establishment | ML-KEM-768 |
| Protected transaction encryption | ML-KEM-768 plus symmetric encryption |
| State commitments | SHAKE256-based Merkle commitments |
| DA commitments | Hash-based Merkle commitments |
| Execution proofs | Transparent hash-based STARKs |
| Proof recursion | Transparent STARK recursion |
| Randomness | PQ-signed commit–reveal and recover protocol |
| Quorum certificates | Merkleized ML-DSA vote sets, optionally STARK-compressed |

The system may support classical signatures as optional compatibility factors, but they must never be sufficient alone.

---

# What to use instead of RISC Zero

RISC Zero is not entirely unsuitable. Its **STARK-only receipt modes** could be used as an experimental or external compute backend. The unacceptable part is making its Groth16 compression or existing security profile a mandatory consensus dependency.

However, for the authoritative ledger transition, I would now prefer one of two approaches.

## Preferred path: a purpose-specific transparent STARK VM

Build a small execution machine designed together with the proof system.

This does not mean inventing a large general CPU. It means defining a compact instruction set for:

- object reads and writes;
- integer computation;
- policy evaluation;
- capability consumption;
- signature verification;
- hashing;
- contract calls;
- state-tree updates;
- job and receipt creation.

The VM should be optimized for:

- formal semantics;
- predictable execution;
- compact traces;
- explicit effects;
- linear resources;
- parallel conflict analysis;
- efficient STARK constraints.

This restores a reason for having a custom runtime: not novelty, but **PQ proof efficiency and semantic assurance**.

## Alternative path: PQ-only general zkVM fork

Fork an existing transparent STARK VM and remove all non-PQ proof modes.

Requirements:

- only hash-based commitments;
- no pairing wrapper;
- no elliptic-curve recursion;
- PQ-oriented soundness parameters;
- explicit quantum-security analysis;
- frozen verifier;
- independent verifier implementation;
- no development receipt bypass in production;
- formal mapping from the VM semantics to proof constraints.

Stwo is a more promising foundation than a Groth16-oriented stack because Circle STARKs are transparent and hash-based. STARKWare describes STARK security as relying on minimal, post-quantum-secure assumptions.  [oai_citation:2‡StarkWare](https://starkware.co/blog/s-two-prover/?utm_source=chatgpt.com)

But Stwo is a proof framework, not a complete blockchain VM. We would still need to build the execution semantics and recursion profile around it.

---

# The new role of the Authority Object Runtime

The earlier “ObjectVM” name can now be retained, but with a more precise definition:

> **ObjectVM is a small PQ-STARK-native machine implementing the canonical semantics of principals, capabilities, policies, objects, contracts, and jobs.**

It is not another EVM clone and not intended to emulate Linux.

## Native state operations

```text
READ_OBJECT
BORROW_OBJECT
WRITE_OBJECT
CREATE_OBJECT
DELETE_OBJECT
HIBERNATE_OBJECT
RESTORE_OBJECT
```

## Authority operations

```text
AUTHENTICATE_PRINCIPAL
VERIFY_CREDENTIAL
VERIFY_CAPABILITY_CHAIN
EVALUATE_POLICY
CONSUME_CAPABILITY
DECREMENT_BUDGET
CONSUME_NULLIFIER
REQUIRE_APPROVAL
```

## Contract operations

```text
CALL
RETURN
EMIT_EVENT
CREATE_JOB
ACCEPT_RECEIPT
ABORT
```

## PQ cryptographic operations

```text
VERIFY_ML_DSA
VERIFY_SLH_DSA
HASH_SHAKE
VERIFY_MERKLE_PATH
VERIFY_STARK
```

## Bounded computation

```text
integer arithmetic
bit operations
bounded memory
bounded loops
typed collections
deterministic control flow
```

The high-level contract language can still look Move-like, but compilation targets ObjectVM rather than general RISC-V.

---

# Why this is better for PQ than using RISC-V directly

A generic RISC-V zkVM proves millions of low-level instructions needed to emulate ordinary software. A purpose-specific VM can treat important operations as native trace tables.

For example, capability attenuation should not require proving a Rust program instruction by instruction. It should have a dedicated constraint:

\[
A_{\text{child}}\subseteq A_{\text{parent}}
\]

Likewise:

- ML-DSA verification can use a specialized proof component;
- state-tree updates can use a Merkle coprocessor;
- APL policy evaluation can use a policy trace table;
- matrix operations can use an AI coprocessor;
- nullifier checks can use a set-membership table.

This produces:

- smaller traces;
- faster proofs;
- easier formal correspondence;
- more predictable costs;
- fewer hidden behaviors;
- a smaller trusted semantic surface.

A general RISC-V backend can still exist for asynchronous compute jobs, but it need not define canonical ledger execution.

---

# Full-PQ consensus without BLS

The largest immediate engineering challenge is vote aggregation.

BLS provides convenient constant-size quorum certificates but is not post-quantum. We should not adopt it temporarily.

At genesis:

1. Validators sign votes using ML-DSA.
2. Votes are stored in a Merkleized availability batch.
3. The QC includes a signer bitmap, stake sum, and vote-set root.
4. Validators verify the relevant raw signatures.
5. A STARK may prove the full QC verification for light clients.

The proof states:

```text
Every included signature is a valid ML-DSA signature.
Every signer belongs to the committed validator set.
No signer is counted twice.
All votes reference the same block, epoch, and round.
The signed stake exceeds two thirds.
```

This costs more bandwidth than BLS but preserves the security invariant.

Later, hash-based PQ multisignatures may reduce overhead, but they should be introduced only after maturity and audit. Research on hash-based post-quantum multisignatures exists, but it should be treated as an optimization rather than a genesis dependency.  [oai_citation:3‡cic.iacr.org](https://cic.iacr.org/p/2/1/13?utm_source=chatgpt.com)

---

# Full-PQ protected transactions

We should also avoid assuming a mature PQ threshold-encryption standard.

The conservative genesis construction remains:

1. Generate a random symmetric transaction key \(K\).
2. Encrypt the transaction payload under \(K\).
3. Split \(K\) into Shamir shares.
4. Encrypt each share to a committee member using ML-KEM.
5. Commit all encrypted shares into the transaction envelope.
6. After order lock, committee members reveal signed shares.
7. Reconstruct \(K\) after reaching the threshold.
8. Charge the sender even if the decrypted payload is malformed.

This is bulky but honestly PQ.

The public transaction lane remains available if the committee fails.

---

# Privacy proofs must also remain PQ

We should not use pairing-based credential systems such as BBS signatures as the mandatory private credential mechanism, even though they offer elegant selective disclosure.

Instead:

1. Credentials are signed with ML-DSA.
2. The holder proves inside a transparent STARK that:
   - the ML-DSA signature is valid;
   - the issuer is accepted by the policy;
   - required claim predicates hold;
   - the credential is not expired;
   - the relevant status root shows it is not revoked;
   - the capability chain and policy permit the action.
3. Only selected claims, pseudonyms, and nullifiers become public.

This is less compact than pairing-based systems but preserves a coherent PQ assumption.

The same method applies to:

- private identities;
- private authorization;
- shielded assets;
- private contract state;
- AI data rights;
- private organizational approval.

---

# Day-one PQ acceptance policy

Every cryptographic artifact should be classified.

```text
PQ_CORE
    Valid for consensus, authorization, and state finality

PQ_EXPERIMENTAL
    Allowed for noncritical compute receipts with explicit policy approval

CLASSICAL_COMPATIBILITY
    Allowed only for external systems and bridges

DEVELOPMENT_ONLY
    Rejected by every production node
```

Examples:

| Artifact | Classification |
|---|---|
| ML-DSA signature | `PQ_CORE` |
| SLH-DSA signature | `PQ_CORE` |
| ML-KEM ciphertext | `PQ_CORE` |
| Transparent SHAKE-based STARK | `PQ_CORE` |
| RISC Zero STARK receipt after parameter review | Potentially `PQ_EXPERIMENTAL` or `PQ_CORE` |
| RISC Zero Groth16 receipt | `CLASSICAL_COMPATIBILITY` |
| Aztec proof relying on curve commitments | `CLASSICAL_COMPATIBILITY` |
| Ethereum finality proof | `CLASSICAL_COMPATIBILITY` |
| Fake or development receipt | `DEVELOPMENT_ONLY` |

A classical bridge may be supported later, but the wallet must say clearly:

> This asset inherits a classical external security dependency.

It must not contaminate the security classification of native assets.

---

# Revised implementation stack

| Layer | Revised choice |
|---|---|
| Normative semantics | Lean 4 |
| Distributed models | TLA+ |
| Main implementation | Stable Rust |
| Contract language | Move-inspired resource language |
| Canonical ledger VM | Custom small ObjectVM |
| Proof framework | Customized transparent Stwo/Circle STARK stack |
| Recursion | Hash-based STARK recursion only |
| User signatures | ML-DSA |
| Recovery/checkpoints | ML-DSA plus SLH-DSA |
| Encryption | ML-KEM plus AES-256-GCM-SIV |
| State and DA commitments | SHAKE256 Merkle structures |
| QC representation | Raw Merkleized ML-DSA votes plus optional STARK compression |
| Private credentials | ML-DSA verified inside STARK |
| Private state | Hash commitments, encryption, nullifiers, STARK proofs |
| General AI compute | External workers with explicit evidence tiers |
| Exact AI proofs | ObjectVM/TensorIR STARK components |
| RISC Zero | Optional external compute backend, STARK receipts only |
| Logos | Architectural reference or nonauthoritative prototype only |
| Aztec | Privacy-design reference and classical interoperability domain |

---

# Practical consequence

This makes the implementation harder.

We lose:

- immediate access to a mature general zkVM stack;
- very small Groth16 proof wrappers;
- easy Ethereum verification;
- BLS-style compact quorum certificates;
- mature pairing-based credential systems.

We gain:

- one coherent security claim;
- no mandatory quantum-vulnerable migration debt;
- no “PQ except for settlement” qualification;
- no “PQ except for proof compression” qualification;
- no “PQ except for validator aggregation” qualification;
- no forced identity or asset migration later;
- a protocol whose long-lived state begins under the intended cryptographic assumptions.

That is the correct tradeoff for this project.

The concise architectural statement should now be:

> **We use existing systems as prior art, but no inherited component enters the authoritative path unless its complete security dependency graph is post-quantum. The native path—from principal authentication through authorization, execution, privacy proofs, data availability, consensus, and finality—is PQ from genesis.**
