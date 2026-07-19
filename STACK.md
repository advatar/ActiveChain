# Recommended technology stack

I would build this as **two deliberately different systems**:

1. A **small, consensus-grade trust kernel** written primarily in stable Rust, with formal specifications and no dynamic dependencies.
2. An **elastic compute ecosystem** for provers, AI workers, builders, indexers and archives, where Python, GPUs, containers and Kubernetes are acceptable because their outputs are independently verified.

Trying to use one homogeneous stack for both would either make the consensus kernel dangerously complex or make the AI and proving ecosystem unnecessarily rigid.

## Stack at a glance

| Layer | Primary choice |
|---|---|
| Normative semantics | Lean 4 |
| Distributed protocol models | TLA+ |
| Production kernel | Stable Rust |
| Selected Rust verification | Verus |
| Bounded model checking | Kani |
| Independent full client | Go |
| Async runtime | Tokio |
| Validator networking | Quinn/QUIC |
| Discovery and relays | Restricted libp2p |
| Canonical encoding | Custom schema compiler and binary codec |
| PQ algorithms | ML-DSA, ML-KEM, SLH-DSA, SHAKE |
| PQ implementations | Multiple replaceable providers; initially RustCrypto plus libcrux differential testing |
| Consensus | Custom Jolteon/Ditto-style BFT |
| Data availability | Two-dimensional Reed–Solomon plus SHAKE Merkle commitments |
| Active state | Custom Merkle radix tree over RocksDB |
| Immutable ledger data | Append-only segment files |
| Authorization | Frozen, consensus-safe Cedar-derived language |
| Contract language | Move-derived resource language |
| Contract VM | Custom typed ObjectVM |
| Native execution optimization | Optional Cranelift backend outside the canonical path |
| Base validity proof | Customized Stwo Circle STARK |
| Recursion | Dedicated transparent STARK recursion layer |
| AI artifact interchange | Safetensors plus ONNX/StableHLO import |
| Verifiable AI execution | Canonical deterministic TensorIR |
| AI and prover orchestration | Rust workers, Python SDK, Kubernetes, NATS JetStream |
| Operational metadata | PostgreSQL |
| Large artifact storage | S3-compatible object storage |
| Tool plugins | Wasm components under Wasmtime, outside consensus |
| Node APIs | Tonic gRPC, Axum HTTP, WebSocket/WebTransport |
| Query APIs | Dedicated PostgreSQL-backed GraphQL/indexer service |
| Wallet core | Rust compiled through UniFFI and WebAssembly |
| Observability | `tracing`, OpenTelemetry, Prometheus and Grafana |
| Builds | Cargo plus Nix |
| Testing | nextest, proptest, cargo-fuzz, Miri, Loom, Kani and differential simulators |

---

# 1. Core implementation language: stable Rust

The main implementation should be Rust, with a strict architectural separation between deterministic logic and operating-system integration.

```text
┌───────────────────────────────────────────┐
│ node shell                                │
│ Tokio · Quinn · RocksDB · RPC · telemetry │
└─────────────────────┬─────────────────────┘
                      │ typed commands/events
┌─────────────────────▼─────────────────────┐
│ deterministic protocol kernel             │
│ no clocks · no network · no filesystem    │
│ no async · no floating point · no serde   │
└─────────────────────┬─────────────────────┘
                      │ execution trace
┌─────────────────────▼─────────────────────┐
│ proof witness and verifier                │
└───────────────────────────────────────────┘
```

The deterministic kernel should compile with:

```rust
#![no_std]
extern crate alloc;
#![forbid(unsafe_code)]
```

Where possible, its top-level interface should look conceptually like:

```rust
pub fn transition(
    pre_state: StateCommitment,
    block: &CanonicalBlock,
    witness: &StateWitness,
    protocol: ProtocolVersion,
) -> Result<TransitionOutput, TransitionError>;
```

This function must not know whether it is running:

- in a validator;
- in an executor;
- inside a test harness;
- under a prover;
- in a light-client verifier;
- in an independent client.

All operating-system behavior belongs in adapters around this kernel.

## Rust boundaries

Use stable Rust for:

- canonical types;
- codecs;
- policy evaluation;
- state transition;
- ObjectVM interpreter;
- consensus state machine;
- DA verification;
- proof verifier;
- light client;
- wallet core.

Permit pinned nightly Rust only in the isolated prover image if SIMD or proof-system dependencies require it. The validator binary itself should not inherit the prover’s toolchain risk.

Unsafe code should be permitted only in separately audited crates for:

- cryptographic SIMD;
- database FFI;
- zero-copy networking;
- specialized proof arithmetic.

Every unsafe crate receives its own fuzzing, Miri and Kani gates.

---

# 2. Independent implementation: Go

The first independent full client should be written in Go and maintained in a separate repository by a separate team.

It should independently implement:

- canonical decoding;
- block and transaction validation;
- consensus;
- state-tree updates;
- fee accounting;
- authorization;
- proof verification;
- state sync.

Suggested Go components:

| Function | Choice |
|---|---|
| Networking | `quic-go` |
| State persistence | Pebble |
| APIs | ConnectRPC or gRPC |
| Metrics | Prometheus Go client |
| Canonical protocol types | Generated from the protocol schema |
| Proof verifier | Native Go implementation, not Rust FFI |

The Go client must **not** call the Rust transition function through FFI. That would produce deployment diversity without semantic diversity.

A third client could later use Java or Kotlin, but a primary Rust client and independent Go client are the minimum useful combination.

---

# 3. Formal-methods stack

No single verification system is ideal for every layer.

## Lean 4: normative semantic source

Use Lean for:

- canonical type definitions;
- principal and capability semantics;
- policy evaluation;
- capability attenuation;
- object transitions;
- asset conservation;
- fee arithmetic;
- recovery semantics;
- ObjectVM instruction semantics;
- proof public-input definition;
- protocol upgrade compatibility.

Lean should contain an executable reference transition model. It should generate test cases that are run against the Rust and Go clients.

Lean is a particularly appropriate choice for authorization because Cedar uses a similar pattern: a Lean formal model, a safe-Rust production evaluator and differential testing between them.  [oai_citation:0‡Cedar Policy Language Reference Guide](https://docs.cedarpolicy.com/other/security.html)

## TLA+: consensus and distributed lifecycle

Use TLA+ for:

- consensus locking and voting;
- view changes;
- epoch transitions;
- one-unproved-block backpressure;
- DA certificate lifecycle;
- protected-envelope decryption;
- forced inclusion;
- proof failure and recovery;
- state snapshot activation;
- weak-subjectivity checkpoints.

TLA+ is designed for concurrent and distributed-system modeling and is valuable precisely where state-machine logic spans multiple actors and message schedules.  [oai_citation:1‡Leslie Lamport's Home Page](https://lamport.azurewebsites.net/tla/tla.html)

## Verus: selected production Rust

Use Verus for the parts of the actual Rust kernel where functional correctness has especially high value:

- canonical integer arithmetic;
- fee calculation;
- capability attenuation;
- capability budget consumption;
- object-version transitions;
- state-tree insertion and deletion;
- Merkle proof verification;
- codec bounds;
- authorization decision combination;
- replay and nonce handling.

Verus is designed to verify functional correctness of low-level Rust systems code, while retaining Rust’s ownership and linearity model.  [oai_citation:2‡verus-lang.github.io](https://verus-lang.github.io/verus/guide/)

Do not attempt to convert the entire node into Verus code. Network adapters, telemetry, databases and RPC layers are poor targets. Verify the small semantic kernel.

## Kani: bit-precise edge cases

Use Kani for:

- integer overflow;
- panic freedom;
- parser behavior;
- malformed bytecode;
- malformed proofs;
- unsafe wrappers;
- boundary values;
- finite state-machine harnesses;
- cryptographic encoding edge cases.

Kani is useful for safety and correctness properties but does not support every Rust feature, including general concurrency, so it is complementary to TLA+ and Verus rather than a replacement for them.  [oai_citation:3‡model-checking.github.io](https://model-checking.github.io/kani/)

---

# 4. Canonical schema and serialization

Do not use Protobuf, JSON, CBOR, Borsh, SCALE or `bincode` as the normative consensus representation.

Create a small protocol schema language, for example:

```text
struct Principal {
    principal_id: PrincipalId;
    kind: PrincipalKind;
    controller_policy: Digest384;
    recovery_policy: Digest384;
    authenticators_root: Digest384;
    sequence: u64;
}

enum PrincipalKind : u8 {
    Human = 0;
    Organization = 1;
    Device = 2;
    Service = 3;
    Agent = 4;
    Pseudonym = 5;
}
```

The schema compiler generates:

- Rust types and codecs;
- Go types and codecs;
- TypeScript signing types;
- Swift and Kotlin wallet types;
- Lean definitions;
- test-vector encoders;
- Wireshark dissectors;
- fuzzing dictionaries.

The encoding rules should require:

- fixed field order;
- explicit type tag;
- explicit schema version;
- minimally encoded lengths;
- bounded collections;
- rejection of unknown fields in consensus objects;
- no duplicate map keys;
- no unordered map encoding;
- no trailing data;
- no floating-point values;
- explicit byte-ordering;
- explicit normalization rules.

`serde` can be used for RPC and configuration. It should not be involved in transaction IDs, signatures, state roots or proof public inputs.

---

# 5. Post-quantum cryptographic stack

The **algorithms** should be frozen early. The **implementations** should remain replaceable.

NIST’s finalized core PQ standards are ML-KEM, ML-DSA and SLH-DSA, and NIST currently describes them as the foundation for PQ deployment.  [oai_citation:4‡csrc.nist.gov](https://csrc.nist.gov/projects/post-quantum-cryptography)

## Proposed cryptographic profile

| Use | Primitive |
|---|---|
| Validator votes | ML-DSA-44 |
| Principal control | ML-DSA-65 |
| Credential issuance | ML-DSA-65 |
| Organization and high-value control | ML-DSA-65 or ML-DSA-87 by policy |
| Recovery | ML-DSA-65 plus optional SLH-DSA |
| Epoch checkpoints | SLH-DSA-SHAKE-192s |
| Session key establishment | ML-KEM-768 |
| Protected transaction shares | ML-KEM-768 |
| Protocol hash | SHAKE256 with 384-bit output |
| Transaction and object IDs | 384-bit domain-separated SHAKE output |
| Symmetric encryption | AES-256-GCM-SIV |
| KDF and domain expansion | KMAC256 or domain-separated SHAKE256 |
| Transparent proofs | Hash-based STARK |
| Classical curves | No required security dependency |

## Crypto-provider abstraction

Consensus code should call a narrow internal API:

```rust
pub trait CryptoProvider {
    fn verify_mldsa(
        suite: MlDsaSuite,
        public_key: &[u8],
        context: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;

    fn encapsulate_mlkem(
        suite: MlKemSuite,
        public_key: &[u8],
        randomness: &mut dyn SecureRandom,
    ) -> Result<KemOutput, CryptoError>;

    fn decapsulate_mlkem(
        suite: MlKemSuite,
        secret_key: &SecretBytes,
        ciphertext: &[u8],
    ) -> Result<SecretBytes, CryptoError>;
}
```

For the development network, use at least two backends:

- RustCrypto;
- libcrux;
- optionally liboqs as a differential test oracle, not as the primary consensus dependency.

RustCrypto provides pure-Rust ML-KEM, ML-DSA, SHA-3 and symmetric cryptography implementations. Libcrux provides high-assurance implementations and verification work, but its own repository currently labels the project pre-release and advises prospective production users to consult the maintainers; its maintainers also document that not every component is formally verified. It should therefore not be the sole implementation on which the system depends.  [oai_citation:5‡GitHub](https://github.com/rustcrypto)

Before mainnet:

- pin exact source commits;
- reproduce NIST known-answer tests;
- run cross-architecture vectors;
- test x86-64 and AArch64;
- run portable and SIMD implementations against each other;
- commission an independent review;
- keep a shadow verifier using another implementation;
- make the suite identifier part of every key and signature.

## Transport security

Use Quinn and rustls with the available X25519+ML-KEM hybrid transport profile, but do not treat the TLS certificate as the protocol identity.

Instead:

1. QUIC establishes an encrypted transport.
2. Both sides perform an application handshake signed with ML-DSA.
3. The ML-DSA identity is bound to the QUIC connection and protocol role.
4. Every consensus-critical message is independently signed.

The hybrid rustls profile combines X25519 and ML-KEM; the application authentication prevents the protocol from depending on classical certificates for validator identity.  [oai_citation:6‡Rustls](https://rustls.dev/perf/2024-12-17-pq-kx/)

---

# 6. Networking stack

## Quinn for validator traffic

Use Quinn directly for:

- consensus;
- DA samples;
- state synchronization;
- proof distribution;
- encrypted transaction shares;
- validator control messages.

Quinn exposes reliable streams and datagrams, while `quinn-proto` separates deterministic QUIC protocol logic from actual networking. That deterministic core is useful for a reproducible network simulator.  [oai_citation:7‡docs.rs](https://docs.rs/quinn-proto)

Use separate endpoints or strict stream classes:

```text
UDP/4100  consensus and quorum traffic
UDP/4101  randomness and decryption shares
UDP/4102  proof traffic
UDP/4103  DA samples and small shares
UDP/4104  bulk DA and state synchronization
```

This makes operating-system queueing and denial-of-service isolation much easier than multiplexing everything through one unprioritized peer connection.

## Libp2p only for discovery

Use libp2p for:

- Kademlia-based peer discovery;
- relay discovery;
- AutoNAT;
- hole punching;
- peer identify;
- browser and mobile relay support.

Do not use gossipsub as the canonical consensus transport. Libp2p is valuable for discovery, NAT traversal and cross-language connectivity, but the validator hot path should remain a small, explicitly controlled protocol.  [oai_citation:8‡libp2p](https://libp2p.io/docs/)

## Wire protocol

Each message frame should include:

```text
protocol_id
protocol_version
message_type
epoch
sequence
payload_length
payload
sender_signature
```

Hard limits must be known before allocation. A peer that advertises a 4 GiB message should be rejected before a buffer is created.

---

# 7. Consensus implementation

Build consensus specifically for this protocol rather than integrating CometBFT, Substrate or another general application framework.

The consensus crate should be split into:

```text
consensus-core/
    pure deterministic state machine
    vote validation
    lock and commit rules
    timeout transitions
    epoch transitions

consensus-node/
    timers
    QUIC connections
    vote aggregation tree
    storage
    telemetry
```

The core receives events:

```rust
enum ConsensusInput {
    Proposal(VerifiedProposal),
    Vote(VerifiedVote),
    Timeout(VerifiedTimeout),
    LocalDeadline(Round),
    EpochActivation(EpochConfig),
}
```

and emits commands:

```rust
enum ConsensusEffect {
    BroadcastVote(Vote),
    BroadcastProposal(Proposal),
    ScheduleDeadline(Deadline),
    FinalizeOrderSet(OrderSet),
    ActivateEpoch(EpochConfig),
}
```

This design makes the consensus algorithm independently runnable in:

- TLA+ trace comparisons;
- deterministic simulation;
- fuzzing;
- a real validator;
- the independent Go client.

Raw ML-DSA vote sets are canonical. A STARK-compressed quorum certificate can be added later as an optimization, but the raw votes remain reconstructible and independently verifiable.

---

# 8. Data availability stack

## Erasure coding

Use:

- `reed-solomon-simd` as the optimized implementation;
- a separate scalar/reference implementation for testing;
- custom two-dimensional coding and matrix layout.

`reed-solomon-simd` provides pure-Rust runtime SIMD implementations across x86-64 and AArch64; the more established `reed-solomon-erasure` crate provides useful GF(2⁸) and GF(2¹⁶) reference behavior.  [oai_citation:9‡docs.rs](https://docs.rs/reed-solomon-simd)

Do not expose either crate’s API as the protocol specification. Define the exact matrix, padding and reconstruction semantics independently.

## DA implementation crates

```text
da-codec/
    systematic 2D encoding
    canonical padding
    share coordinates
    reconstruction

da-commitment/
    row roots
    column roots
    namespace roots
    batch root

da-sampler/
    private sample selection
    sample requests
    response verification

da-proof/
    encoding-validity AIR
```

Every share has:

```text
batch_root
row
column
share_length
share_bytes
Merkle path
```

The encoding proof is generated with the same STARK family as execution proofs.

---

# 9. State storage

Use three separate storage forms.

## Immutable ledger log

Store finalized blocks, receipts and state deltas in append-only segment files:

```text
ledger/
    blocks-00000000.seg
    blocks-00000001.seg
    receipts-00000000.seg
    deltas-00000000.seg
```

Each segment has:

- fixed header;
- record offsets;
- record checksums;
- Merkle root;
- previous-segment root;
- optional Zstandard compression;
- immutable finalization footer.

Sequential immutable data should not be forced through an LSM key-value database.

## Active state

Use a custom canonical Merkle radix tree, persisted in RocksDB.

Suggested column families:

```text
object_leaf
tree_node
partition_root
state_metadata
lease_index
hibernation_record
nullifier
capability_budget
credential_status
snapshot_metadata
```

RocksDB is persistence, not consensus. Tree shape, root computation and traversal order are defined by the protocol, not by RocksDB iteration.

RocksDB supports consistent checkpoints, which makes it suitable for producing snapshot material, but every exported checkpoint must still be checked against the protocol state root.  [oai_citation:10‡RocksDB](https://rocksdb.org/blog/2015/11/10/use-checkpoints-for-efficient-snapshots.html)

Define a storage interface:

```rust
pub trait StateStore {
    fn get_node(&self, key: NodeKey) -> Result<Option<NodeBytes>, StoreError>;
    fn apply_batch(&mut self, batch: CanonicalStateBatch) -> Result<(), StoreError>;
    fn checkpoint(&self, destination: &Path) -> Result<(), StoreError>;
}
```

The Go client should use Pebble behind the same logical interface, providing storage-engine diversity.

## Archive and snapshot storage

Use an S3-compatible object layer for:

- full snapshots;
- partition snapshots;
- old DA batches;
- model artifacts;
- datasets;
- proof traces;
- generated content.

The content root in the ledger, not the object-store URI, identifies the artifact.

---

# 10. Identity and authorization stack

## Cedar-derived, not Cedar-dependent

Use Cedar as the semantic foundation for APL, the Authorization Policy Language, but freeze a consensus-specific subset.

Cedar’s current security design combines a Lean model, a safe-Rust evaluator and differential tests. It also uses default-deny and forbid-overrides-permit semantics. Those are exactly the implementation patterns to retain.  [oai_citation:11‡Cedar Policy Language Reference Guide](https://docs.cedarpolicy.com/other/security.html)

However, do not use an automatically updating Cedar crate directly in consensus.

APL should make the following changes:

| Cedar behavior | APL behavior |
|---|---|
| General application entity model | Protocol principals, capabilities and objects |
| Extensible functions | Only versioned protocol-defined functions |
| Evaluation error can be skipped | Any relevant error yields deny |
| General string-heavy policy data | Canonical typed protocol values |
| External mutable entity store | State-root-bound authorization context |
| Runtime library upgrades | Policy version fixed by protocol version |

The APL runtime should be:

- `no_std`;
- total;
- deterministic;
- bounded;
- schema-validated;
- free of network, clock and external storage access.

Use the same policy evaluator in:

- object execution;
- wallet simulation;
- credential presentation;
- agent sessions;
- tool gateways;
- compute-job settlement;
- viewing-capability checks.

## Credential interoperability

Keep the consensus credential format canonical and binary.

Provide edge adapters for:

- W3C Verifiable Credentials;
- enterprise PKI credentials;
- hardware attestations;
- government credentials;
- application-specific issuer formats.

No JSON-LD canonicalization should occur inside consensus.

## Wallet authorization engine

The wallet should run the same APL evaluator locally and show:

```text
Principal:       Agent-42
Action:          Purchase
Resource:        TravelBudget
Amount:          420 EUR
Capability:      TravelBooking-7
Remaining limit: 500 EUR/day
Credentials:     Employee, TravelApprover
Human approval:  Required
Data disclosed:  Destination country, not itinerary
```

This is much safer than presenting users with a hex-encoded contract call.

---

# 11. Smart-contract stack

## Contract language

Use a **Move-derived language dialect**, preserving:

- resources;
- affine and linear values;
- modules;
- capabilities;
- explicit ownership;
- bytecode verification;
- specification clauses.

Move was specifically designed around resource types that cannot be implicitly copied or discarded, making it a strong starting point for asset and capability semantics.  [oai_citation:12‡move-language.github.io](https://move-language.github.io/move/)

I would reuse or fork parts of the Move frontend, but not use MoveVM unchanged.

The compiler pipeline should be:

```text
Move-derived source
        ↓
typed high-level IR
        ↓
capability and effect checking
        ↓
object-access inference
        ↓
bounded middle IR
        ↓
ObjectVM bytecode
        ↓
bytecode verifier
```

## ObjectVM

ObjectVM should be a small typed register machine, not EVM and not general WebAssembly.

The instruction set should include:

- bounded integer operations;
- resource moves;
- object reads and writes;
- capability consumption;
- policy invocation;
- contract calls;
- event creation;
- hashing;
- PQ signature verification;
- proof verification;
- compute-job creation.

It should exclude:

- floating point;
- filesystem access;
- networking;
- clocks;
- unrestricted dynamic dispatch;
- reflection;
- runtime code loading;
- hidden global state access.

## Execution implementations

Maintain three execution paths:

1. **Reference interpreter:** simple Rust, always available.
2. **Optimized interpreter:** Rust with specialized dispatch.
3. **Optional Cranelift executor:** for high-performance execution nodes.

Cranelift output is never canonical by itself. Every optimized result is either rechecked by the reference interpreter during hardening or covered by the transition proof.

## Wasm is for tools, not contracts

Use Wasm components for off-chain tool plugins and connectors, where language interoperability is valuable.

Do not put Wasmtime in the consensus trusted base. Wasmtime has strong security practices but, like any large sandbox runtime, continues to receive security advisories; keeping it outside consensus means a sandbox failure cannot fabricate ledger state.  [oai_citation:13‡Bytecode Alliance](https://bytecodealliance.org/articles/wasmtime-security-advisories)

---

# 12. Proof-system stack

This is the one component I would subject to a formal six-month bake-off before permanently freezing.

## Lead choice: customized Stwo

Use Stwo as the base prover and verifier because its current implementation is a production-grade, modular Circle STARK system in Rust with a small `no_std` verifier.  [oai_citation:14‡GitHub](https://github.com/starkware-libs/stwo/blob/dev/README.md)

Create a vendored fork:

```text
pcl-stark/
    field/
    channel/
    commitments/
    fri/
    verifier/
    prover/
    recursion/
    zero-knowledge/
```

Do not consume the moving upstream repository directly in consensus.

## Required modifications

Stwo is not a drop-in solution for this design. Its published Cairo profile currently describes a default configuration targeting approximately 96 bits of conjectured soundness and states that it is not zero knowledge by default. Our fork must therefore change the profile before mainnet.  [oai_citation:15‡GitHub](https://github.com/starkware-libs/stwo-cairo)

The mainnet proof profile must add:

- at least a 128-bit PQ-oriented soundness target;
- SHAKE256-based 384-bit transcript and commitment hashing;
- deterministic protocol serialization;
- witness masking and trace randomization for ZK;
- a dedicated recursive verifier;
- domain-separated proof types;
- independent verifier implementations;
- public parameter-generation scripts;
- exhaustive test vectors;
- formal correspondence to ObjectVM semantics.

## Recursion path

The practical implementation should be staged:

### Development path

Use the Stwo-Cairo recursive-verifier architecture to prove end-to-end aggregation early.

### Mainnet path

Generate a dedicated recursive verifier for the exact ObjectVM proof profile, avoiding the overhead of interpreting the whole ledger transition in Cairo.

The AIR definition should originate from one declarative source that generates:

- Rust witness code;
- Rust verifier constraints;
- recursive-verifier constraints;
- Lean-side constraint descriptions;
- test-vector code.

## What not to use for the core proof

Plonky3 should remain a benchmark and research implementation initially. Its recursive STARK repository currently states that it is under active development, unaudited and not recommended for production.  [oai_citation:16‡GitHub](https://github.com/Plonky3/Plonky3-recursion)

Winterfell is useful as a reference implementation and differential test target, but its own documentation labels it a research project, warns that it is not production-ready and notes that its current implementation does not provide perfect zero knowledge.  [oai_citation:17‡GitHub](https://github.com/facebook/winterfell)

RISC Zero and SP1 can be supported as external compute-job receipt adapters. Their curve-based SNARK wrappers must not qualify as the protocol’s full-PQ Tier A evidence; only their transparent STARK receipt forms should be eligible for that classification. SP1’s documented architecture includes a STARK-to-SNARK wrapping layer, while RISC Zero exposes both recursive STARK and Groth16 receipt forms.  [oai_citation:18‡docs.succinct.xyz](https://docs.succinct.xyz/docs/sp1/what-is-a-zkvm)

---

# 13. Privacy stack

Use the same transparent proof family for:

- private credentials;
- policy satisfaction;
- shielded assets;
- private objects;
- private compute-job inputs;
- selective disclosure;
- viewing-capability proofs.

This avoids introducing a second unrelated proof system into the consensus trusted base.

## Privacy crates

```text
privacy-credential/
    ML-DSA credential verification
    issuer-set membership
    status and revocation
    selective claims
    domain nullifiers

privacy-policy/
    committed APL evaluation
    capability-chain proof
    private approval proof

privacy-asset/
    note membership
    nullifiers
    value conservation
    viewing capabilities

privacy-object/
    committed state
    private transition
    encrypted state
```

## Wallet proving

Create one Rust proving library that supports:

- desktop native;
- iOS and Android through UniFFI;
- browsers through WebAssembly;
- local hardware acceleration where available;
- remote proving only for witnesses encrypted under a user-controlled policy.

The wallet should never send raw credential witnesses to an ordinary RPC endpoint.

## Protected transaction encryption

Use:

- ML-KEM-768 for recipient share encryption;
- AES-256-GCM-SIV for payload encryption;
- protocol-specific Shamir sharing implemented in a small independently verified crate;
- signed, post-lock share release.

Protected envelopes and shielded state remain separate features. One hides a transaction before ordering; the other hides persistent ledger state.

---

# 14. AI and general compute stack

The AI plane should have a strict Rust control layer and a flexible Python execution layer.

```text
Ledger and policy kernel
           │
           │ authorized ComputeJob
           ▼
Rust compute coordinator
           │
           ├── deterministic proof worker
           ├── replicated worker
           ├── optimistic worker
           ├── confidential-compute worker
           └── human/evaluator workflow
```

## AI artifact formats

Use:

- **Safetensors** for weight storage;
- **ONNX** and **StableHLO** as import formats;
- a protocol-defined **TensorIR** as the canonical deterministic computation representation;
- OCI manifests for packaging;
- S3-compatible storage for chunks;
- SHAKE-based content roots in the ledger.

ONNX provides a common model representation and operator model, StableHLO is a standardized MLIR dialect used as an OpenXLA interface, and Safetensors is designed as a tensor-storage format that avoids pickle-style executable deserialization.  [oai_citation:19‡OpenXLA Project](https://openxla.org/xla/terminology)

Neither ONNX nor StableHLO should be consensus-canonical directly. Both allow evolving operator sets and implementation freedom. Import them into a frozen TensorIR.

## TensorIR

TensorIR should specify:

- exact tensor shape;
- exact integer or fixed-point representation;
- rounding mode;
- overflow behavior;
- quantization;
- lookup-table contents;
- tokenization;
- random-seed derivation;
- sampling algorithm;
- operator version;
- memory layout.

For example:

```text
TensorIRProgram {
    ir_version
    input_schema
    output_schema
    constant_roots
    operations[]
    numeric_profile
    randomness_profile
}
```

Exact proofs establish execution of TensorIR, not arbitrary Python or arbitrary CUDA kernels.

## Worker implementation

### General AI workers

Use:

- Python;
- PyTorch or JAX;
- CUDA or other accelerator runtimes;
- pinned OCI images;
- a Rust worker supervisor;
- signed artifact manifests.

This path supports fast development but is verified by replication, challenge or attestation rather than exact proof unless it normalizes into TensorIR.

### Exact proof workers

Use:

- Rust witness generator;
- deterministic integer TensorIR runtime;
- specialized matrix, lookup and attention AIR components;
- Stwo-based proof generation;
- CPU baseline;
- CUDA acceleration later;
- no arbitrary Python during the proven computation.

### Tool gateway

Implement the agent tool gateway in Rust with:

- APL authorization;
- one-use capabilities;
- signed action intents;
- Wasm Component Model plugins;
- WIT interfaces;
- Wasmtime sandboxing;
- host-owned credentials;
- signed tool receipts.

The model never receives the underlying banking, cloud or enterprise API credential. It receives only an invocation capability interpreted by the gateway.

## AI worker infrastructure

Use:

| Component | Technology |
|---|---|
| Work queue | NATS JetStream |
| Job metadata | PostgreSQL |
| Artifact and trace storage | S3-compatible object storage |
| Cluster scheduling | Kubernetes |
| GPU scheduling | Kubernetes device plugins and queueing |
| HPC integration | Slurm adapter |
| Worker supervisor | Rust |
| User and research SDK | Python |
| Model execution | Python framework or deterministic TensorIR runtime |
| Tool plugins | Wasm components |
| Evidence settlement | Rust verifier service plus on-chain contract |

JetStream provides persistent, replayable streams and work-queue behavior, making it suitable for off-chain prover and compute coordination. It must not be part of consensus correctness: duplicate or lost queue deliveries are handled idempotently by `JobId`.  [oai_citation:20‡docs.nats.io](https://docs.nats.io/nats-concepts/jetstream)

---

# 15. API stack

## Validator and node APIs

Use:

- `tonic` for gRPC;
- `axum` for REST and health endpoints;
- `tower` middleware;
- WebSocket for subscriptions;
- WebTransport for browser-native high-throughput sessions;
- Unix-domain sockets for local administration and remote-signer communication.

Separate endpoints:

```text
Public query API
Transaction submission API
Validator administration API
Proof-provider API
DA-provider API
Compute-worker API
Remote-signer API
```

A validator’s administration interface must not be exposed through the public RPC server.

## Indexing and queries

Do not turn the consensus state database into a general query engine.

A dedicated indexer consumes finalized:

- state deltas;
- receipts;
- events;
- identity changes;
- credential-status roots;
- compute receipts.

It writes PostgreSQL tables and exposes:

- GraphQL;
- REST;
- event subscriptions;
- analytics exports.

Indexers are replaceable and untrusted. Every query response can optionally include the ledger root and membership proof needed to verify the relevant object.

## SDKs

Create:

- Rust protocol SDK;
- TypeScript SDK;
- Swift SDK;
- Kotlin SDK;
- Python compute and AI SDK;
- Go infrastructure SDK.

The Rust wallet core is compiled through:

- UniFFI for Swift/Kotlin;
- `wasm-bindgen` for browsers;
- native Rust for desktop and hardware integrations.

Canonical signing bytes are always produced by the shared protocol core, not reconstructed manually in JavaScript.

---

# 16. Operational data stack

## PostgreSQL

Use PostgreSQL for:

- indexer data;
- prover bids;
- job-market metadata;
- artifact catalogues;
- operational identity metadata;
- billing;
- support tooling.

Never use PostgreSQL to determine canonical ledger state.

## NATS JetStream

Use JetStream for:

- proof component jobs;
- witness-generation jobs;
- AI compute assignments;
- snapshot construction;
- archive replication;
- event delivery to indexers.

Every consumer must be idempotent. “Exactly once” is not relied upon for correctness.

## Object storage

Use S3-compatible storage for:

- model weights;
- datasets;
- proof traces;
- block snapshots;
- DA archives;
- generated artifacts;
- reproducible-build artifacts.

Use content roots and signed manifests rather than trusting bucket paths.

---

# 17. Observability

Use Rust’s `tracing` ecosystem with OpenTelemetry export.

Instrument every end-to-end transaction with identifiers such as:

```text
transaction_id
order_set_root
block_height
proof_job_id
batch_root
principal_pseudonym
compute_job_id
```

Privacy-sensitive values must be explicitly excluded or redacted.

OpenTelemetry provides a vendor-neutral framework for traces, metrics and logs and supports correlating those signals across services.  [oai_citation:21‡OpenTelemetry](https://opentelemetry.io/docs/)

Recommended operational stack:

| Signal | Stack |
|---|---|
| Metrics | Prometheus |
| Dashboards | Grafana |
| Traces | OpenTelemetry Collector plus Tempo or equivalent |
| Logs | Structured JSON through OpenTelemetry or Loki |
| Profiling | `pprof`, `perf`, eBPF tooling |
| Alerts | Prometheus Alertmanager |
| Security events | Separate append-only audit sink |

Consensus decisions must never depend on telemetry availability.

---

# 18. Build and release stack

## Builds

Use:

- Cargo workspaces;
- `rust-toolchain.toml`;
- vendored dependencies;
- Nix flakes for reproducible developer environments;
- reproducible release containers;
- separate stable and proof-worker toolchains.

Avoid introducing Bazel initially. Cargo plus Nix is sufficient until the multi-language build graph actually warrants additional complexity.

## Rust quality gates

Every change should run:

```text
cargo fmt
cargo clippy --all-targets --all-features
cargo nextest run
cargo test --doc
cargo miri test
cargo kani
verus verification
cargo fuzz smoke corpus
cargo deny
cargo vet
cargo audit
reproducible-build comparison
```

Additional tools:

- `proptest` for semantic properties;
- `cargo-fuzz`/libFuzzer for parsers;
- Loom for concurrency schedules;
- Criterion for microbenchmarks;
- deterministic network simulation;
- cross-client state-root comparison;
- proof-versus-reexecution comparison.

## Release artifacts

Every release should publish:

- source commit;
- exact dependency lock;
- Nix derivation;
- OCI image digest;
- SBOM;
- audit status;
- test report;
- deterministic build hashes;
- ML-DSA release signature;
- SLH-DSA checkpoint signature for major releases.

Do not rely only on contemporary classical software-signing infrastructure.

---

# 19. Deployment topology

## Validators

Run validators as a small number of native processes under systemd:

```text
validator-node
remote-signer
optional local sentry
OpenTelemetry collector
```

Do not require Kubernetes for validators. Validator operation should remain understandable to an operator with one or two Linux machines.

The remote signer should preferably communicate over:

- Unix-domain socket;
- `vsock`;
- physically isolated local network;
- hardware or HSM plugin when PQ support is suitable.

## Provers and AI workers

Run elastic workers under Kubernetes:

```text
prover-coordinator
witness-workers
recursive-provers
AI-workers
tool-gateways
artifact-cache
NATS
PostgreSQL
object-store gateway
```

This plane benefits from:

- horizontal scaling;
- GPU assignment;
- preemption;
- queue-based retries;
- heterogeneous machines;
- large temporary storage.

Its failure can delay finality or jobs, but it cannot fabricate valid state.

## Archive nodes

Archive nodes may use:

- local object storage;
- cloud object storage;
- tape or cold storage;
- content-distribution networks;
- erasure-coded multi-region storage.

Their integrity is checked by content roots.

---

# 20. Repository structure

I would begin with one primary monorepo and separate repositories for independent clients.

```text
pcl/
├── spec/
│   ├── lean/
│   ├── tla/
│   ├── protocol/
│   └── threat-model/
│
├── schema/
│   ├── pcl-idl/
│   ├── generator/
│   └── vectors/
│
├── crates/
│   ├── protocol-types/
│   ├── canonical-codec/
│   ├── crypto-provider/
│   ├── principal/
│   ├── credential/
│   ├── capability/
│   ├── policy-kernel/
│   ├── object-kernel/
│   ├── state-tree/
│   ├── object-vm/
│   ├── bytecode-verifier/
│   ├── transition/
│   ├── consensus-core/
│   ├── da-core/
│   ├── proof-verifier/
│   ├── light-client/
│   └── wallet-core/
│
├── node/
│   ├── validator/
│   ├── full-node/
│   ├── archive/
│   ├── remote-signer/
│   └── rpc/
│
├── lang/
│   ├── parser/
│   ├── compiler/
│   ├── package-manager/
│   ├── lsp/
│   └── standard-library/
│
├── proof/
│   ├── pcl-stark/
│   ├── objectvm-air/
│   ├── policy-air/
│   ├── privacy-air/
│   ├── recursion/
│   ├── witness/
│   └── prover-worker/
│
├── compute/
│   ├── coordinator/
│   ├── worker/
│   ├── tensor-ir/
│   ├── artifact/
│   ├── receipts/
│   └── tool-gateway/
│
├── services/
│   ├── indexer/
│   ├── explorer-api/
│   ├── artifact-registry/
│   └── prover-market/
│
├── sdk/
│   ├── rust/
│   ├── typescript/
│   ├── swift/
│   ├── kotlin/
│   └── python/
│
└── testing/
    ├── simulation/
    ├── fuzz/
    ├── interoperability/
    ├── adversarial/
    └── benchmarks/
```

Separate repositories:

```text
pcl-go-client
pcl-java-client
pcl-spec-review
pcl-proof-audit
```

Independent clients should consume published specifications and vectors, not import code from the primary monorepo.

---

# 21. Choices to freeze now versus prototype

## Freeze immediately

These decisions are foundational and expensive to reverse:

| Decision | Freeze |
|---|---|
| Rust primary implementation | Yes |
| Go independent client | Yes |
| Lean semantic model | Yes |
| TLA+ distributed model | Yes |
| Custom canonical codec | Yes |
| Principal/capability/policy/object model | Yes |
| Move-derived resource language | Yes |
| Custom ObjectVM | Yes |
| NIST PQ algorithm families | Yes |
| 384-bit protocol commitments | Yes |
| QUIC validator transport | Yes |
| Storage abstraction and custom state root | Yes |
| Separate validator and worker planes | Yes |

## Prototype before freezing

| Decision | Reason |
|---|---|
| Exact Stwo fork and parameter profile | Must benchmark custom SHAKE, ZK and recursion |
| Recursive-verifier architecture | Main remaining proof-system risk |
| State-tree arity and path compression | Requires real workload measurements |
| DA matrix dimensions | Network and reconstruction benchmarks |
| ML-DSA vote propagation topology | PQ signature bandwidth measurements |
| TensorIR operator set | Must remain small and deterministic |
| Browser privacy-prover profile | Hardware and memory constraints |
| Protected-mempool committee size | Ciphertext and liveness trade-off |

## Explicitly defer

Do not put these on the mainnet critical path:

- novel PQ aggregate signatures;
- novel PQ threshold signatures;
- arbitrary private contract code;
- real-time proofs for frontier-scale LLMs;
- universal external-chain bridging;
- GPU-only fallback proving;
- validator dependence on Kubernetes;
- tool or AI plugins in consensus;
- classical curve-based proof wrappers.

---

# Bottom line

The stack should be **custom where semantics and trust matter, standard where infrastructure is replaceable**.

Own and formally specify:

- principal semantics;
- capability delegation;
- authorization policies;
- object state;
- canonical encoding;
- ObjectVM;
- state roots;
- consensus;
- DA certification;
- proof statement;
- fee accounting;
- privacy statements.

Reuse or adapt:

- Rust and Go;
- Lean, TLA+, Verus and Kani;
- Quinn and limited libp2p;
- RocksDB and Pebble;
- Cedar’s formal-development methodology;
- Move’s resource-language concepts;
- Stwo’s Circle STARK implementation;
- PostgreSQL, NATS and S3;
- Kubernetes for elastic workers;
- Python, ONNX, StableHLO and Safetensors for AI tooling;
- Wasm components for off-chain plugins.

The most important boundary is that **Python, Kubernetes, Wasmtime, databases, AI frameworks, builders and provers can all be buggy or malicious without gaining the ability to authorize an action or fabricate valid ledger state**.
