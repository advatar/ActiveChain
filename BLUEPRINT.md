# Detailed implementation plan

This plan treats the system as a greenfield protocol rather than a retrofit. Its central artifact is not a blockchain client; it is a formally specified state-transition system built around:

\[
\boxed{
\text{Principal}
+\text{Credential}
+\text{Capability}
+\text{Policy}
+\text{Object}
+\text{Job}
+\text{Proof or Receipt}
}
\]

Consensus, data availability, smart contracts, privacy, and AI computation are separate implementation planes that must all refine this same semantic core.

The intended end state is:

> A fully post-quantum, proof-carrying global object ledger with native smart contracts, private credentials, capability-based authorization, protected transaction ordering, and an asynchronous compute plane for AI and other expensive workloads.

The build should borrow responsive BFT from HotStuff/Jolteon/Ditto and the separation of data dissemination from ordering demonstrated by Narwhal, but it should not inherit their transaction or account semantics unchanged.  [oai_citation:0‡arXiv](https://arxiv.org/abs/1803.05069)

---

# 1. Program strategy

## 1.1 Build order

The project must be implemented in this order:

```text
Normative semantics
        ↓
Canonical types and encoding
        ↓
Principal, capability and policy kernel
        ↓
Object state and deterministic VM
        ↓
Single-node reference execution
        ↓
PQ networking, consensus and DA
        ↓
Proof-carrying execution
        ↓
Private authorization and shielded state
        ↓
Protected ordering
        ↓
AI and general compute jobs
        ↓
Independent clients and adversarial testnets
        ↓
Conservative mainnet
        ↓
Stateless-validator mode
```

Starting with consensus would produce a fast network with no stable definition of identity, authority, privacy, or execution. Starting with a smart-contract VM would cause every application to reinvent those concepts inconsistently.

## 1.2 Launch contract

The following features are mandatory for protocol version 1.0:

| Feature | Required at genesis |
|---|---|
| Fully post-quantum state authorization | Yes |
| Post-quantum validator consensus signatures | Yes |
| Principal and recovery objects | Yes |
| Capability delegation and attenuation | Yes |
| Native deterministic policy engine | Yes |
| Private credential presentation | Yes |
| Resource-safe object smart contracts | Yes |
| Multidimensional fees and state rent | Yes |
| Mandatory execution validity proofs | Yes |
| Validator re-execution as defense in depth | Initially yes |
| Shielded payments and private objects | At least the standard shielded profiles |
| AI and general compute-job objects | Yes |
| Multiple compute assurance tiers | Yes |
| Protected transaction lane | Yes, initially optional |
| Public transaction lane | Yes, always |
| Light clients | Yes |
| External bridges | No; added only after core launch |
| Fully private arbitrary contract code | Not required for genesis |
| Real-time ZK proofs for frontier LLMs | Not required |
| Stateless active validators | Enabled only after dual-execution hardening |

## 1.3 Explicit non-goals

The protocol will not attempt to:

- define one global legal or human identity;
- treat a wallet key as an identity;
- execute large AI models inside consensus;
- prove that an AI answer is true or beneficial;
- make credential issuers inherently trustworthy;
- eliminate all MEV;
- guarantee permanent storage without payment;
- make external chains post-quantum through bridging;
- use governance to override invalid state transitions;
- promise semantic parallelism for highly contended shared state.

---

# 2. Workstreams and ownership

The project should be divided into independently accountable workstreams.

| Workstream | Primary responsibility |
|---|---|
| Protocol semantics | Normative state-transition function and invariants |
| Formal methods | Lean models, TLA+ models, refinement proofs and verified implementation components |
| Cryptography | PQ suites, randomness, encrypted transactions, proof-system security |
| Identity and authorization | Principals, credentials, capabilities, policies, recovery and organizations |
| Object state and storage | State tree, snapshots, leases, hibernation and state sync |
| Smart contracts and VM | Bytecode, verifier, source language, execution and developer tooling |
| Consensus and networking | BFT, epochs, validator lifecycle, transport and peer management |
| Data availability | Erasure coding, sampling, retention and reconstruction |
| Execution and proving | Parallel execution, trace generation, STARKs, recursion and proof market |
| Privacy | Shielded objects, credential proofs, private policies and metadata protections |
| AI and compute | Jobs, artifacts, receipts, tool gateways, attestation and AI SDK |
| Economics | Fees, staking, issuance, rent and capacity control |
| Client diversity | Independent full-node implementations |
| Wallets and SDKs | User authorization, simulation, credentials and agent controls |
| Testnet and SRE | Simulators, chaos testing, telemetry, releases and incident exercises |
| Security assurance | Audits, red teams, bug bounties and supply-chain security |

No team should own both a normative specification and the only implementation used to test that specification.

---

# 3. Normative specification package

Before production client development, create the following versioned specifications.

| Identifier | Specification |
|---|---|
| `P-000` | System goals, terminology and security assumptions |
| `P-001` | Canonical data types and binary encoding |
| `P-002` | Cryptographic suites and domain separation |
| `P-010` | Global state-transition function |
| `P-020` | Principal lifecycle and controller authentication |
| `P-021` | Credential schemas, presentations and status |
| `P-022` | Capabilities, delegation and revocation |
| `P-023` | Authorization Policy Language |
| `P-024` | Recovery, freeze and key rotation |
| `P-030` | Object model, ownership and versioning |
| `P-031` | State tree, witnesses, snapshots and hibernation |
| `P-040` | Action envelopes, fee tickets and nonce channels |
| `P-041` | Protected envelopes and canonical ordering |
| `P-050` | ObjectVM bytecode and execution semantics |
| `P-051` | Contract package and upgrade model |
| `P-060` | Consensus and validator reconfiguration |
| `P-061` | Randomness and beacon protocol |
| `P-070` | Data availability and batch certificates |
| `P-080` | Execution proof statement and recursive aggregation |
| `P-081` | Shielded-object proof statements |
| `P-090` | Fee vector, staking, rewards and rent |
| `P-100` | Compute jobs, artifacts and evidence |
| `P-101` | AI agent and tool authorization profiles |
| `P-110` | Light clients, state sync and weak-subjectivity checkpoints |
| `P-120` | External interoperability and bridge trust classes |
| `P-130` | Upgrade process and protocol-version transitions |
| `P-140` | Telemetry, conformance and performance measurement |

Each specification must contain:

1. normative data structures;
2. state-machine pseudocode;
3. error and abort behavior;
4. resource bounds;
5. security assumptions;
6. test vectors;
7. formal properties;
8. backward-compatibility rules;
9. implementation notes clearly separated from normative behavior.

Specifications use “MUST,” “MUST NOT,” “SHOULD,” and “MAY” consistently. Consensus behavior must never depend on an informal diagram or prose example.

---

# 4. Repository and implementation structure

## 4.1 Reference monorepo

The primary implementation repository should have this structure:

```text
/spec/
    architecture/
    protocol/
    wire/
    threat-model/
    economics/

/formal/
    lean/
    tla/
    verus/
    kani/

/core/
    types/
    codec/
    crypto/
    state/
    transition/

/authority/
    principal/
    credential/
    capability/
    policy/
    recovery/

/execution/
    object-vm/
    bytecode-verifier/
    scheduler/
    runtime/
    contract-sdk/

/network/
    transport/
    peer-manager/
    consensus/
    data-availability/
    protected-mempool/

/proof/
    trace/
    stark/
    recursion/
    verifier/
    prover-market/
    privacy-circuits/

/compute/
    artifacts/
    jobs/
    receipts/
    ai-profiles/
    tool-gateway/

/node/
    validator/
    full-node/
    light-client/
    archive/
    indexer/

/wallet/
    core/
    credential-store/
    policy-ui/
    agent-console/

/sdk/
    rust/
    typescript/
    kotlin/
    swift/
    python/

/testing/
    vectors/
    simulator/
    adversarial/
    fuzz/
    benchmarks/
    interoperability/
```

## 4.2 Languages

Use:

- **Rust** for the primary full node, VM, execution engine and prover orchestration;
- **Lean** for normative executable models and theorem proving;
- **TLA+** for distributed protocol behavior;
- **Verus** for functional verification of selected Rust components;
- **Kani** for bit-precise model checking, parser safety and unsafe-code verification;
- **Go** for the first independent full client;
- **Java or Kotlin** for a second independently implemented full client;
- **TypeScript, Kotlin and Swift** for user-facing SDKs.

Verus is specifically intended for functional verification of low-level Rust systems code, while Kani provides bit-precise model checking for safety and correctness properties.  [oai_citation:1‡verus-lang.github.io](https://verus-lang.github.io/verus/guide/)

## 4.3 Dependency policy

Consensus-critical modules must follow these rules:

- no unbounded parser allocation;
- no runtime reflection;
- no hidden network access;
- no locale-sensitive behavior;
- no floating-point arithmetic;
- no platform-dependent integer behavior;
- no unchecked arithmetic unless formally justified;
- no `unsafe` Rust outside isolated, audited modules;
- no dynamically fetched code;
- reproducible builds;
- complete software bill of materials;
- pinned compiler and dependency versions;
- at least two independent implementations of every cryptographic verifier used for consensus.

---

# 5. Canonical data model

## 5.1 Primitive types

Use fixed, explicit types:

```text
Digest384       = 48 bytes
ObjectId        = Digest384
PrincipalId     = Digest384
CapabilityId    = Digest384
CredentialId    = Digest384
PackageId       = Digest384
JobId           = Digest384
TransactionId   = Digest384

Height          = unsigned 64-bit integer
Epoch           = unsigned 64-bit integer
Round           = unsigned 64-bit integer
Amount          = unsigned 128-bit integer
ResourceUnits   = unsigned 128-bit integer
Timestamp       = unsigned 64-bit Unix seconds
```

A 48-byte hash output provides a larger margin for collision-sensitive commitments under quantum attack than conventional 32-byte roots.

All hashes use explicit domain separation:

```text
H(
    protocol_domain,
    type_tag,
    schema_version,
    canonical_length,
    canonical_bytes
)
```

The same byte string must never be interpreted as two cryptographically interchangeable object types.

## 5.2 Canonical encoding

Create a schema-generated canonical binary encoding with:

- fixed field order;
- explicit version and type tags;
- fixed integer widths where practical;
- minimally encoded length prefixes;
- no unordered maps;
- no duplicate fields;
- no NaN or floating-point types;
- bounded vectors;
- strict rejection of trailing data;
- strict normalization before hashing or signing.

JSON, generic CBOR and protobuf may be used at RPC boundaries, but they are not consensus encodings.

Every client must pass an injectivity test:

\[
\operatorname{encode}(x)=\operatorname{encode}(y)\implies x=y
\]

and a round-trip test:

\[
\operatorname{decode}(\operatorname{encode}(x))=x
\]

---

# 6. Core protocol objects

## 6.1 Principal

```text
Principal {
    principal_id: PrincipalId
    principal_kind: Human | Organization | Device | Service | Agent | Pseudonym

    controller_policy_hash: Digest384
    recovery_policy_hash: Digest384
    authenticator_set_root: Digest384

    sequence: u64
    freeze_state: Active | RecoveryPending | Frozen
    metadata_commitment: Digest384

    anchor_deposit: Amount
    created_at: Height
    last_updated_at: Height
}
```

The principal identifier is random or transaction-derived, not key-derived. Key rotation therefore does not change identity.

The principal object contains no public list of personal credentials.

## 6.2 Authenticator

```text
AuthenticatorDescriptor {
    authenticator_id: Digest384
    scheme: CryptoSuiteId
    verification_key: bytes
    purpose:
        Control
        Recovery
        Session
        Validator
        CredentialIssuance
        ToolReceipt
    valid_from: Height
    valid_until: Height?
    revoked_at: Height?
}
```

A principal’s controller policy decides which authenticators are sufficient.

## 6.3 Credential

Credentials normally remain off-chain.

```text
Credential {
    format_version: u16
    issuer: PrincipalId
    subject_binding: Digest384
    schema_id: Digest384
    claims_commitment: Digest384

    issuance_height: Height
    valid_from: Timestamp
    valid_until: Timestamp?
    status_registry: ObjectId?
    issuance_log_root: Digest384?

    terms_commitment: Digest384?
    issuer_signature: Signature
}
```

The external adapter should support W3C Verifiable Credentials 2.0, but the consensus representation remains canonical binary. W3C VC 2.0 defines an issuer–holder–verifier model and is a stable Recommendation; the W3C quantum-resistant credential cryptosuite work published in June 2026 remains a draft and should be treated as an interoperability target rather than the protocol’s normative cryptography.  [oai_citation:2‡W3C](https://www.w3.org/TR/vc-data-model-2.0/)

## 6.4 Capability

```text
CapabilityGrant {
    capability_id: CapabilityId

    issuer: PrincipalId
    holder_binding: PrincipalId | Digest384
    parent_capability: CapabilityId?

    permitted_actions: BoundedSet<ActionId>
    resource_scope: ResourceSelector
    data_scope: DataSelector

    monetary_limit: Amount?
    compute_limit: ResourceUnits?
    rate_limit: RateLimit?
    use_limit: u64?

    valid_from: Height
    valid_until: Height?

    delegation_depth_remaining: u8
    delegation_allowed: bool

    revocation_registry: ObjectId?
    constraint_hash: Digest384
    issuer_signature: Signature
}
```

Capabilities are holder-bound by default. Unbound bearer capabilities must be explicitly marked and discouraged by wallets.

Mutable budgets are represented by an on-chain `CapabilityBudget` object so concurrent spending cannot exceed the grant.

## 6.5 Object

```text
Object {
    object_id: ObjectId
    object_version: u64
    type_id: Digest384

    owner:
        Principal(PrincipalId)
        Shared
        Immutable
        CapabilityControlled(CapabilityId)
        Shielded(Digest384)

    control_policy_hash: Digest384
    use_policy_hash: Digest384
    disclosure_policy_hash: Digest384
    upgrade_policy_hash: Digest384

    package_id: PackageId?
    value_root: Digest384
    public_value: bytes?

    lease_expiry_epoch: Epoch
    storage_deposit: Amount
    flags: ObjectFlags
}
```

## 6.6 Compute job

```text
ComputeJob {
    job_id: JobId
    requester: PrincipalId

    program_manifest: Digest384
    model_manifest: Digest384?
    input_commitments: Vec<Digest384>
    output_schema: Digest384

    data_capabilities: Vec<CapabilityId>
    tool_capabilities: Vec<CapabilityId>

    resource_ceiling: ResourceVector
    payment_escrow: Amount
    deadline: Height

    privacy_policy: Digest384
    verification_policy: VerificationPolicy
    settlement_policy: Digest384

    state: Open | Assigned | Completed | Expired | Disputed
}
```

---

# 7. The authorization kernel

## 7.1 Unified authorization request

Every state-changing operation is reduced to:

```text
AuthorizationRequest {
    actor: PrincipalId | PrivatePrincipalCommitment
    action: ActionId
    resource: ObjectId | ResourceSelector

    block_context: {
        height
        epoch
        timestamp_bounds
        chain_id
    }

    transaction_context: {
        transaction_id
        fee_payer
        value
        resource_limits
        declared_purpose
    }

    credentials: PresentedFacts
    capabilities: CapabilityChain
    approvals: ApprovalSet
    attestation_results: AttestationFacts
}
```

Contracts never parse arbitrary wallet signatures themselves. The kernel produces a verified `AuthorizationContext` and passes that context to contract code.

## 7.2 Authorization equation

An operation may proceed only when:

\[
\begin{aligned}
\operatorname{Allow}={}&
\operatorname{AuthenticatedActor}\\
&\land \operatorname{ValidCapabilityChain}\\
&\land \operatorname{CapabilityWithinBudget}\\
&\land \operatorname{CredentialPredicatesSatisfied}\\
&\land \operatorname{ObjectPolicyAllows}\\
&\land \operatorname{ContractPolicyAllows}\\
&\land \operatorname{RequiredApprovalsPresent}\\
&\land \neg\operatorname{ExplicitForbid}
\end{aligned}
\]

The final authorization rule is an intersection. A contract can impose additional restrictions but cannot expand authority that the object or capability did not grant.

## 7.3 Capability attenuation

Capability delegation uses a deliberately restricted attenuation algebra rather than arbitrary policy code.

A child capability must satisfy:

\[
\begin{aligned}
A_c &\subseteq A_p\\
R_c &\subseteq R_p\\
D_c &\subseteq D_p\\
B_c &\le B_p\\
U_c &\le U_p\\
[t_c^0,t_c^1] &\subseteq [t_p^0,t_p^1]\\
d_c &<d_p
\end{aligned}
\]

where:

- \(A\) is the action set;
- \(R\) is the resource scope;
- \(D\) is the data scope;
- \(B\) is the monetary or compute budget;
- \(U\) is the use count;
- \(d\) is remaining delegation depth.

The verifier should reject any delegation it cannot mechanically prove to be narrower.

## 7.4 Authorization Policy Language

Create a protocol-native Authorization Policy Language, or APL, inspired by the verification-guided design of Cedar rather than embedding a general-purpose contract interpreter in authorization. Cedar demonstrates that a useful authorization language can have a formal model, typed validation, differential testing and mechanized correspondence between model and implementation.  [oai_citation:3‡Lean Language](https://lean-lang.org/use-cases/cedar/)

APL has:

- default deny;
- explicit `permit` and `forbid`;
- `forbid` overrides `permit`;
- no loops;
- no recursion;
- no user-defined I/O;
- no mutable state during evaluation;
- bounded collections;
- typed schemas;
- deterministic evaluation cost;
- total evaluation;
- explicit policy versioning.

Example:

```text
permit(
    principal,
    action == Transfer,
    resource
)
when {
    principal has_capability Transfer(resource);
    capability.remaining_amount >= request.amount;
    credential(
        schema = TreasuryOperator,
        issuer in organization.accepted_issuers
    );
    request.amount < 10_000
        || approval_count(role = HumanDirector) >= 2;
    request.destination in organization.approved_counterparties;
};

forbid(principal, action, resource)
when {
    principal.is_frozen
        || capability.is_revoked
        || request.destination.risk_flag == Blocked;
};
```

## 7.5 Policy obligations

A policy may return bounded obligations:

```text
AuthorizationDecision {
    result: Permit | Deny
    required_state_updates: Vec<Obligation>
    audit_commitment: Digest384?
}
```

Valid obligations include:

- decrement capability budget;
- consume a single-use capability;
- emit an audit commitment;
- require a named approval receipt;
- create a delayed settlement;
- restrict output disclosure.

Policies may not directly perform arbitrary contract calls.

## 7.6 Private authorization

A private authorization proof has public inputs:

```text
policy_hash
request_commitment
accepted_issuer_root
credential_status_root
capability_revocation_root
decision = Permit
required_budget_delta
domain_nullifier
```

The private witness may contain:

- credential;
- credential signature;
- credential claims;
- subject secret;
- capability chain;
- policy source;
- private approvals;
- membership and non-revocation paths.

The proof establishes authorization without disclosing those values.

## 7.7 Credential status and revocation

An issuer maintains:

```text
CredentialStatusRegistry {
    issuer: PrincipalId
    schema_id: Digest384
    status_root: Digest384
    sequence: u64
    effective_height: Height
}
```

A presentation proof must bind to a status root no older than the policy’s maximum staleness window.

Policies decide:

- which issuers are trusted;
- which schemas are accepted;
- maximum revocation-data age;
- whether issuance-log inclusion is required;
- whether a unique-use nullifier is required.

The protocol verifies who issued a claim and whether the relevant policy accepts the issuer. It does not claim the issuer’s real-world statement is true.

## 7.8 Pairwise pseudonyms and nullifiers

For privacy-preserving identity:

\[
P_{\text{domain}}=
H(s_{\text{subject}}\parallel\text{application domain})
\]

For bounded uniqueness:

\[
N=
H(
s_{\text{subject}}
\parallel\text{application domain}
\parallel\text{epoch}
\parallel\text{purpose}
)
\]

A zero-knowledge proof links the pseudonym or nullifier to an accepted credential without exposing a global identifier.

## 7.9 Recovery

Recovery is a protocol state machine:

```text
Active
  ↓ initiate recovery
RecoveryPending
  ↓ notice period
Challenged ──────→ Cancelled
  ↓ sufficient recovery authorization
Recovered
```

A recovery request contains:

- principal;
- proposed controller policy;
- recovery evidence;
- initiation height;
- challenge deadline;
- recovery bond.

Policies may require:

- guardian threshold;
- institution-issued recovery credential;
- hardware recovery key;
- time delay;
- old-key veto;
- proof of recent account activity;
- temporary spending freeze after recovery.

No application should invent a separate recovery system for the same principal.

---

# 8. Full post-quantum cryptographic profile

NIST states that ML-KEM, ML-DSA and SLH-DSA form the foundation of current PQ deployments and can be put into use now. By contrast, NIST’s threshold-cryptography process only published its first formal call in January 2026 and is still gathering and analyzing reference schemes. The implementation therefore uses standardized single-party PQ primitives in the core and avoids requiring a novel PQ threshold signature for safety.  [oai_citation:4‡NIST Computer Security Resource Center](https://csrc.nist.gov/projects/post-quantum-cryptography)

## 8.1 Genesis suite

| Purpose | Algorithm |
|---|---|
| High-frequency validator vote | ML-DSA-44 |
| User and organization controller | ML-DSA-65 |
| Long-term recovery | ML-DSA-65 plus optional SLH-DSA |
| Epoch checkpoint diversity signature | SLH-DSA |
| Network key establishment | ML-KEM-768 |
| Protected-envelope share encryption | ML-KEM-768 |
| Hashes and Merkle trees | SHAKE256, 48-byte output |
| Key derivation | KMAC256 or a domain-separated SHA-3 KDF |
| Symmetric payload encryption | AES-256-GCM or versioned 256-bit AEAD |
| Execution proofs | Transparent hash-based STARK |
| DA commitments | SHAKE256 Merkle commitments |
| Polynomial commitments | None in the core |
| Pairing-based cryptography | None in the core |
| Classical elliptic-curve security dependency | None in the core |

ML-DSA-44 is used for short-lived, high-frequency votes because validator keys rotate and the vote bandwidth is substantial. More conservative suites are used for long-lived principal control and recovery.

## 8.2 Crypto-suite registry

Every key, signature, ciphertext, proof and commitment carries:

```text
CryptoSuiteId {
    family
    parameter_set
    encoding_version
    security_profile
}
```

An algorithm upgrade follows:

1. register new suite;
2. support old and new verification;
3. permit dual authorization;
4. make new suite the default;
5. reject creation of new old-suite keys;
6. retain historical verification;
7. sunset old-suite authorization after a declared height.

NIST’s current guidance explicitly emphasizes cryptographic agility as part of PQ migration planning.  [oai_citation:5‡NIST Computer Security Resource Center](https://csrc.nist.gov/Projects/post-quantum-cryptography/publications)

## 8.3 Validator quorum certificates

A quorum certificate is:

```text
QuorumCertificate {
    epoch: Epoch
    round: Round
    block_id: Digest384

    signer_bitmap: bytes
    vote_set_root: Digest384
    signed_stake: u128

    vote_data_locator: DataLocator
}
```

The raw ML-DSA vote set is available through the DA network.

Active validators verify the raw signatures before extending a certificate. A recursively proven QC may be provided for mobile light clients and bandwidth compression, but consensus safety does not depend on accepting a compressed proof without access to the raw votes.

This avoids making a new PQ aggregate-signature construction part of the safety-critical trusted base.

## 8.4 PQ transport

Network transport should use QUIC framing with a TLS or protocol-security profile that includes ML-KEM and ML-DSA. As of July 2026, the corresponding IETF TLS specifications are still work in progress, so consensus validity must remain independent of transport confidentiality.  [oai_citation:6‡IETF Datatracker](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/)

Application-layer signatures authenticate every consensus-critical message even if a transport session is compromised.

## 8.5 PQ randomness beacon

Because a mature standardized PQ VRF is not assumed, implement a commit-and-recover beacon.

At epoch setup:

1. A rotating beacon committee is selected.
2. Each member creates an epoch seed.
3. It commits to a Merkle tree of per-slot pseudorandom values.
4. It Shamir-shares the epoch seed.
5. Each share is encrypted to its recipient using ML-KEM.
6. The encrypted shares and commitments are DA-published.
7. Complaints or consistency failures exclude the member before activation.

For slot \(s\):

1. transaction set \(O_s\) is locked;
2. members reveal their committed slot values;
3. withheld values are reconstructed from encrypted shares;
4. randomness is:

\[
R_s =
H(
O_s
\parallel
r_{1,s}
\parallel\cdots\parallel
r_{n,s}
)
\]

If at least one contributing member was honest and kept its value secret until set lock, the builder could not predict the result while selecting the set.

Beacon failure must not compromise consensus safety. It may cause the system to use a documented, less-fair deterministic ordering fallback.

## 8.6 Protected transaction encryption

The genesis protected lane uses a conservative multi-recipient construction:

1. client creates random 256-bit payload key \(K\);
2. payload is encrypted with \(K\);
3. \(K\) is divided into \(t\)-of-\(n\) Shamir shares;
4. each share is encrypted to a committee member with ML-KEM;
5. encrypted payload and shares are DA-published;
6. after set lock, members reveal signed shares;
7. the first canonical set of \(t\) valid shares reconstructs \(K\);
8. malformed or inconsistent envelopes abort and pay their reserved fees.

This has substantial ciphertext overhead. It should initially be an opt-in lane for economically sensitive transactions.

Batched threshold encryption is promising and can greatly reduce communication, but the current research literature also documents setup, malformed-ciphertext and privacy pitfalls. It should replace the conservative construction only after a PQ-compatible scheme has matured and passed independent review.  [oai_citation:7‡USENIX](https://www.usenix.org/conference/usenixsecurity24/presentation/choudhuri)

---

# 9. State and storage architecture

## 9.1 Partitioned global state

The global state is divided into 4,096 logical partitions based on the first 12 bits of the object identifier.

```text
GlobalRoot
    ├── PartitionRoot[0]
    ├── PartitionRoot[1]
    ├── ...
    └── PartitionRoot[4095]
```

Each partition uses a canonical hash-only radix tree. The global root commits to every partition root.

Physical partitioning supports:

- parallel storage;
- parallel witness generation;
- independent execution subproofs;
- partial state sync;
- bounded database compaction.

It does not create independent consensus domains.

## 9.2 State-tree requirements

The tree must support:

- deterministic shape;
- insertion-order independence;
- membership proofs;
- non-membership proofs;
- compact batch multiproofs;
- efficient version updates;
- partition snapshots;
- canonical empty roots;
- proof-friendly traversal;
- hash-only security.

A 16-ary sparse radix tree with canonical path compression is a reasonable initial design. A benchmark phase should compare it with a Merkleized B-tree before the state format is frozen.

## 9.3 Object versioning

Every mutable object update consumes:

```text
(object_id, version = v)
```

and creates:

```text
(object_id, version = v + 1)
```

A transaction using a stale version aborts deterministically.

No two successful transactions can create the same object version.

## 9.4 Access manifests

A transaction declares:

```text
AccessManifest {
    exact_reads: Vec<(ObjectId, Version)>
    exact_writes: Vec<(ObjectId, Version)>

    immutable_reads: Vec<ObjectId>

    creation_namespaces: Vec<NamespaceGrant>
    maximum_created_objects: u32

    maximum_dynamic_reads: u32
    dynamic_read_policy: Digest384?
}
```

Access outside the manifest aborts.

Overly broad write declarations are charged because they reduce available parallelism.

## 9.5 Leases and hibernation

Each active object pays for byte-epochs of storage.

When a lease expires:

1. the object becomes non-mutable;
2. its full value leaves the active database;
3. a hibernation record remains committed;
4. the owner retains a resurrection witness;
5. the object can be restored by proving the old value and paying a new lease.

```text
HibernationRecord {
    object_id
    version
    type_id
    owner_commitment
    value_root
    policy_roots
    hibernated_at
}
```

Ownership is not extinguished.

Small principal anchors and base-asset ownership records should receive a permanent or endowment-funded storage class so loss of wallet activity does not erase identity or ownership.

## 9.6 Snapshots and state sync

Create:

- partition deltas every block;
- incremental snapshots every hour;
- full certified snapshots at least daily;
- two complete snapshot generations in mandatory hot retention.

A new node syncs by:

1. obtaining a recent weak-subjectivity checkpoint;
2. verifying the snapshot root against the checkpoint;
3. downloading erasure-coded partition snapshots;
4. applying certified deltas;
5. verifying the current state root.

---

# 10. Smart-contract platform

## 10.1 ObjectVM

Implement a small typed register VM with Move-like resource semantics.

Move provides useful precedent for representing assets as resources that cannot be implicitly copied or discarded, and object-oriented transaction models make dependencies visible. Block-STM demonstrates deterministic speculative execution against a preset transaction order.  [oai_citation:8‡diem-developers-components.netlify.app](https://diem-developers-components.netlify.app/papers/diem-move-a-language-with-programmable-resources/2020-05-26.pdf)

The VM must support:

- affine and linear values;
- modules and packages;
- immutable code by default;
- explicit object inputs and outputs;
- typed capabilities;
- bounded call depth;
- deterministic integer arithmetic;
- fixed resource metering;
- typed events;
- synchronous intra-transaction contract calls;
- asynchronous compute-job submission;
- versioned cryptographic host functions.

It must not support:

- floating point;
- wall-clock access;
- network access;
- implicit global storage access;
- runtime code loading;
- reflection;
- unbounded recursion;
- nondeterministic iteration;
- ambient caller authority.

## 10.2 Source language

Develop a resource-oriented source language with:

- familiar Rust- or Move-like syntax;
- explicit `resource` declarations;
- explicit ownership and capability parameters;
- specification clauses;
- preconditions and postconditions;
- loop invariants for bounded loops;
- package manifests;
- automatic access-manifest generation where possible.

Example:

```text
public entry fun transfer(
    auth: &AuthorizationContext,
    coin: Coin<Currency>,
    recipient: PrincipalId,
    amount: u128
): Coin<Currency>
requires auth.permits(
    action = Transfer,
    resource = coin.id,
    value = amount
)
ensures old(coin.value) ==
    result.remaining.value + result.sent.value
{
    ...
}
```

## 10.3 Bytecode verifier

The on-chain bytecode verifier checks:

- type safety;
- linear-resource use;
- absence of unbounded recursion;
- call-depth bounds;
- valid package imports;
- deterministic instruction set;
- no hidden object access;
- valid access declarations;
- bounded event and object creation;
- absence of invalid control-flow targets;
- metering instrumentation.

Compiler correctness is not trusted. The bytecode verifier is the security boundary.

## 10.4 Transaction command graph

A transaction may contain multiple commands:

```text
TransactionBody {
    commands: Vec<Command>
    access_manifest: AccessManifest
    authorization_bundle: AuthorizationBundle
    output_disclosure: DisclosurePolicy
}
```

Results from one command may be passed to later commands. The entire graph commits atomically.

## 10.5 Reentrancy

Reentrancy is avoided structurally:

- a mutable object handle cannot be duplicated;
- contracts receive explicit object capabilities;
- a called contract cannot discover unrelated caller state;
- callbacks require explicit continuation objects;
- the command graph fixes control flow and object ownership.

## 10.6 Contract upgrades

An upgrade requires:

```text
UpgradeProposal {
    package_id
    current_code_hash
    proposed_code_hash
    schema_migration_hash
    migration_proof
    authorization_proof
    activation_height
    user_exit_deadline?
}
```

The migration proof establishes that the proposed state transformation is valid under the declared migration program.

Applications that advertise immutability must have no upgrade policy.

## 10.7 Contract verification tooling

The SDK should provide:

- unit testing;
- property-based testing;
- symbolic execution;
- formal specifications;
- invariant checking;
- transaction simulation;
- policy simulation;
- capability-flow visualization;
- bytecode decompilation;
- reproducible package builds;
- source-to-bytecode translation validation.

---

# 11. Deterministic parallel execution

## 11.1 Execution stages

For every ordered set:

1. parse and classify transactions;
2. resolve object versions;
3. validate access manifests;
4. build conflict graph;
5. schedule disjoint components;
6. execute components in parallel;
7. resolve speculative conflicts using canonical order;
8. verify postconditions;
9. update object versions;
10. create state-delta and proof traces.

## 11.2 Conflict graph

Transactions \(T_i\) and \(T_j\) conflict when:

\[
W_i\cap(W_j\cup R_j)\ne\varnothing
\quad\lor\quad
W_j\cap R_i\ne\varnothing
\]

Disjoint connected components execute independently.

Within a connected component, a Block-STM-style speculative scheduler may be used, but the final result must be equivalent to sequential execution in canonical transaction order.

## 11.3 Determinism rule

For a fixed:

- pre-state root;
- protocol version;
- ordered transaction set;
- beacon randomness;
- decryption result;
- block context;

every conforming client must produce exactly the same:

- post-state root;
- receipt root;
- event root;
- fee accounting;
- capability-budget updates;
- nullifier set.

## 11.4 Hot objects

The runtime should expose contention metrics to developers.

Applications should be encouraged to use:

- partitioned liquidity;
- batch auctions;
- commutative counters;
- accumulator objects;
- sharded queues;
- per-user positions;
- asynchronous jobs.

The protocol must not hide that a single semantically shared object serializes its updates.

---

# 12. Transaction and block pipeline

## 12.1 Fee ticket

Before submitting an encrypted transaction, the user creates or owns a fee ticket:

```text
FeeTicket {
    ticket_id: ObjectId
    payer: PrincipalId
    reserved_amount: Amount
    valid_until: Height
    nonce: u64
    permitted_resource_vector: ResourceVector
}
```

The public envelope references the ticket. Mempool workers can therefore reject unpaid encrypted spam without seeing the private payload.

The ticket is consumed once, even if the encrypted payload later proves malformed.

## 12.2 Action envelope

```text
ActionEnvelope {
    version
    chain_id

    fee_ticket
    fee_bucket
    maximum_fee_vector
    resource_limits

    validity_interval
    public_nonce_channel
    public_sequence?

    protected_mode
    payload_commitment
    encrypted_payload | public_payload

    encrypted_key_shares?
    submission_signature
}
```

The fee payer may differ from the actor.

The actor may be represented by a private principal commitment if authorization is proved in zero knowledge.

## 12.3 One-block proof pipeline

Block \(h\) performs two operations:

1. finalizes the proven transition for order set \(O_{h-1}\);
2. locks the next transaction set \(O_h\).

```text
Block[h] {
    parent
    consensus_qc

    finalized_transition {
        order_set_root: O[h-1]
        pre_state_root
        post_state_root
        receipt_root
        event_root
        execution_proof
    }

    next_order_set {
        batch_certificate_roots
        envelope_set_root: O[h]
        inclusion_queue_commitment
    }

    resource_base_fees
    randomness_commitment
    validator_set_root
}
```

After \(O_h\) is locked:

1. protected transactions decrypt;
2. canonical ordering is derived;
3. execution occurs;
4. proof is generated;
5. block \(h+1\) finalizes the resulting state root.

There may be exactly one unproven order set.

## 12.4 Total transition semantics

Every well-formed envelope must have a provable result, including failure.

Receipt outcomes are:

```text
Success
MalformedProtectedPayload
AuthenticationFailed
AuthorizationDenied
CredentialExpired
CapabilityRevoked
StaleObjectVersion
AccessManifestViolation
ContractAbort
ResourceLimitExceeded
FeeLimitExceeded
```

This prevents one bad transaction from making an order set unprovable.

---

# 13. Consensus implementation

## 13.1 Initial parameters

Proposed conservative genesis parameters:

| Parameter | Initial value |
|---|---:|
| Active validators | 1,024 |
| Target after scaling tests | 4,096 |
| BFT threshold | More than two-thirds active stake |
| Byzantine safety assumption | Less than one-third active stake |
| Target slot duration | 3 seconds |
| Target order finality | 3–6 seconds |
| Target state finality | 6–12 seconds |
| Validator-set reconfiguration | Once per day |
| Unbonding period | 90 days |
| Weak-subjectivity checkpoint interval | 7 days |

The active validator count should be increased only after PQ signature and network benchmarks demonstrate that the target hardware can sustain it.

## 13.2 Consensus protocol

Implement:

- Jolteon-style responsive two-chain fast path;
- Ditto-style asynchronous fallback;
- stake-weighted voting;
- deterministic locking rules;
- epoch-boundary reconfiguration;
- objective equivocation evidence;
- separate consensus and withdrawal keys.

The implementation sequence is:

1. formal single-epoch safety model;
2. four-node deterministic simulator;
3. static 16-node testnet;
4. stake weighting;
5. timeouts and view changes;
6. epoch transitions;
7. asynchronous fallback;
8. adversarial network simulator;
9. 1,024-node geographic testbed.

## 13.3 Slashing

Slash only for cryptographically provable behavior:

- double proposal in the same round;
- conflicting vote;
- invalid epoch transition signature;
- conflicting checkpoint;
- invalid signed decryption share;
- invalid signed DA attestation.

Downtime receives lost rewards and bounded inactivity penalties.

## 13.4 Epoch transitions

The old validator set finalizes:

```text
EpochTransition {
    next_epoch
    next_validator_set_root
    next_stake_root
    next_crypto_keys_root
    next_beacon_committee_root
    next_decryption_committee_root
    activation_checkpoint
}
```

The new set cannot begin independently of a certificate from the old set.

## 13.5 Weak subjectivity

A long-offline node obtains a recent checkpoint from multiple independent sources and verifies:

- validator-set root;
- state root;
- protocol version;
- epoch;
- ML-DSA quorum;
- SLH-DSA checkpoint diversity signature.

The software must display checkpoint age and provenance rather than silently embedding one opaque trusted endpoint.

---

# 14. Data-availability implementation

## 14.1 Batch production

Multiple DA producers operate concurrently. A batch contains:

```text
DataBatch {
    publisher
    namespace
    source_size
    share_dimensions
    source_data_root
    encoded_matrix_root
    transaction_envelope_root
    expiry_epoch
    encoding_validity_proof
}
```

## 14.2 Initial coding profile

A reasonable prototype profile is:

- source matrix: \(128\times128\);
- source share: 256 bytes;
- source batch: 4 MiB;
- extended matrix: \(256\times256\);
- encoded batch: 16 MiB;
- two-dimensional Reed–Solomon extension;
- row and column Merkle commitments.

These are benchmark parameters, not immutable protocol constants.

## 14.3 Encoding-validity proof

The publisher provides a STARK establishing that:

- the source shares match the source-data commitment;
- each extended row is a valid codeword;
- each extended column is a valid codeword;
- the encoded matrix matches its root.

Without this proof, a producer could commit to malformed coded data that appears sampled but cannot be reconstructed.

## 14.4 Sampling

Validators receive deterministic and random sample assignments.

A DA attestation states:

```text
AvailabilityAttestation {
    batch_root
    validator
    assigned_samples_root
    successful_retrieval_bitmap
    retention_commitment
    signature
}
```

A batch certificate requires more than two-thirds of active stake attesting successful sampling and assigned retention.

Light clients independently select samples using private randomness.

Data-availability sampling allows verification without every light node downloading all data; separating dissemination from consensus also removes the consensus leader’s uplink as the only throughput source.  [oai_citation:9‡Celestia](https://celestia.org/glossary/data-availability-sampling/)

## 14.5 Network separation

Use distinct priority classes:

1. consensus votes and proposals;
2. decryption and randomness shares;
3. state-transition proofs;
4. DA samples and batch certificates;
5. full batch propagation;
6. archive traffic;
7. RPC and indexer traffic.

Bulk DA traffic may never starve consensus traffic.

## 14.6 Retention

Initial policy:

- transaction and witness data: 30 days;
- encrypted rejected envelopes: 7 days;
- current and previous complete state snapshot: mandatory;
- older snapshots: market-provided;
- finalized headers and state roots: permanent;
- archival content: permissionless paid storage.

---

# 15. Ordering, builders and censorship resistance

## 15.1 Builders

A builder proposes:

```text
BuilderBid {
    order_set_root
    included_batch_roots
    resource_vector
    proposer_payment
    builder_bond
    builder_signature
}
```

The payload is already DA-certified. No trusted relay is necessary.

The proposer can always construct a local candidate.

## 15.2 Builders select sets, not arbitrary sequence

The protocol determines order after set lock using:

1. eligibility age;
2. coarse fee bucket;
3. required dependency order;
4. post-lock randomness.

```text
order_key(tx) = (
    eligibility_round,
    fee_bucket,
    dependency_rank,
    H(randomness || transaction_id)
)
```

Exact priority fees are not used for fine-grained sequencing.

## 15.3 Forced inclusion queue

Every DA-certified, fee-backed envelope receives an eligibility round.

After a configured age, the envelope enters the forced-inclusion queue.

A valid proposal must consume the oldest eligible envelopes up to each relevant resource limit. It may omit an envelope only if:

- it expired;
- its fee cap is below the current base fee;
- its fee ticket is already consumed;
- a prerequisite is invalid;
- including it would exceed a specific resource dimension.

The proposal includes a proof of the queue prefix it consumed.

Inclusion-list research similarly treats transaction inclusion as part of block validity rather than leaving it entirely to builders.  [oai_citation:10‡Ethereum Improvement Proposals](https://eips.ethereum.org/EIPS/eip-7547)

## 15.4 Ordering guarantees

Do not describe the system as providing perfect first-seen ordering. There is no globally objective arrival time in an asynchronous network.

The protocol offers:

- bounded inclusion after DA certification;
- builder-independent post-lock tie-breaking;
- coarse rather than continuous priority classes;
- hidden transaction contents before set lock;
- application-level batch auctions for order-sensitive markets.

---

# 16. Proof-carrying execution

## 16.1 Proof architecture

Use a transparent, hash-based recursive STARK with no trusted setup and no pairing-based final wrapper.

STARKs were designed as transparent proof systems with verification much cheaper than replaying the underlying computation and with security based on hash-oriented assumptions suitable for post-quantum deployment.  [oai_citation:11‡ePrint archive](https://eprint.iacr.org/2018/046)

The proof tree is:

```text
Per-transaction proof fragments
            ↓
Per-conflict-component proofs
            ↓
Per-state-partition proofs
            ↓
Authorization and credential proof aggregation
            ↓
Fee, rent and receipt proof
            ↓
Global recursive transition proof
```

## 16.2 Public proof statement

The final proof states:

```text
Given:
    chain_id
    protocol_version
    prior_state_root
    ordered_envelope_set_root
    data_availability_roots
    decryption_result_root
    canonical_ordering_randomness
    resource_base_fee_vector

Prove:
    all referenced data was decoded as specified;
    protected envelopes were decrypted or deterministically failed;
    canonical transaction order was derived correctly;
    all authentication proofs were valid;
    all capability chains were valid and non-escalating;
    all policies evaluated correctly;
    ObjectVM execution followed canonical semantics;
    object versions and access manifests were respected;
    assets and capability budgets were conserved;
    rent and fees were charged correctly;
    receipts and events match execution;
    the transition produced the claimed post-state root.
```

## 16.3 Proof-system implementation stages

### Stage A: trace-only prototype

- deterministic ObjectVM;
- complete execution traces;
- trace replay tool;
- no proof requirement.

### Stage B: non-recursive proofs

- prove one transaction;
- prove one contract call;
- prove state-tree updates;
- prove ML-DSA verification in a dedicated circuit;
- prove APL evaluation.

### Stage C: recursion

- aggregate transaction proofs;
- aggregate partition proofs;
- prove proof verification recursively;
- produce one global transition proof.

Recursive proof systems already demonstrate constant-size aggregation and composition as a practical architecture, although the production implementation here must retain a purely transparent PQ profile rather than using a curve-based final wrapper.  [oai_citation:12‡RISC Zero](https://dev.risczero.com/api/1.0/recursion)

### Stage D: dual execution

For every testnet block:

- all validators re-execute;
- all validators verify the proof;
- clients compare the two roots;
- any mismatch automatically stops admission of new order sets.

### Stage E: proof-primary operation

After extended production hardening:

- validators may verify proofs without retaining all state;
- randomly selected validators continue full re-execution;
- archival and execution nodes remain permissionless;
- the raw state-transition witness remains available during retention.

## 16.4 Prover market

A block’s proving plan is deterministic:

```text
ProvingPlan {
    order_set_root
    component_ranges
    partition_assignments
    expected_public_inputs
    maximum_trace_units
}
```

Anyone may prove a component.

Rewards are paid only for proofs accepted into the final aggregate.

Provers have no exclusive assignment. A failed prover is replaced without changing transaction order.

## 16.5 Fallback prover

Maintain an open-source CPU-capable fallback prover.

The block-capacity rule must ensure a worst-case block can be proved on commodity hardware within a bounded emergency interval, proposed initially as 15–30 minutes.

Specialized proving hardware should improve latency, not become a prerequisite for eventual progress.

## 16.6 Proof backpressure

If the current order set has no valid proof:

- consensus may finalize empty maintenance blocks;
- it may process validator and liveness metadata;
- it may not lock another user order set.

This keeps the unproved backlog at exactly one.

---

# 17. Privacy implementation

## 17.1 Privacy layers

Implement privacy separately for:

| Layer | Protection |
|---|---|
| Pre-order transaction contents | Protected envelopes |
| Principal identity | Pairwise pseudonyms and ZK credentials |
| Authorization policy | Policy commitments and ZK evaluation |
| Asset ownership and amount | Shielded objects |
| Contract state | Private committed state |
| AI inputs and outputs | Encrypted jobs, ZK or attested execution |
| Network identity | Optional relays and mix network |
| Selective audit | Scoped viewing capabilities |

## 17.2 Shielded note profile

A standard shielded asset object contains:

```text
ShieldedNotePlaintext {
    asset_id
    amount
    owner_secret
    policy_hash
    disclosure_descriptor
    randomness
}
```

Public state contains:

```text
note_commitment
encrypted_note
nullifier_tree_root
note_tree_root
```

A spend proof establishes:

- note membership;
- owner authorization;
- unspent nullifier;
- accepted policy;
- input-output value conservation;
- correct fee payment;
- correctly formed output commitments.

## 17.3 Private general object

A private object contains:

```text
PrivateObject {
    object_id
    version
    state_commitment
    encrypted_state
    owner_commitment
    policy_commitment
    disclosure_commitment
}
```

A transition proof establishes correct execution against the committed code and state.

## 17.4 Viewing capabilities

Viewing authority is a capability:

```text
ViewCapability {
    holder
    object_scope
    field_scope
    time_scope
    permitted_purpose
    onward_disclosure
    expiry
}
```

There is no universal decryption or compliance key.

## 17.5 Metadata protection

Provide:

- fixed envelope-size classes;
- optional message padding;
- batched relay submission;
- delayed transaction release;
- pairwise fee-payer accounts;
- privacy relays;
- optional mix-network integration.

Wallets must distinguish:

- hidden state;
- hidden transaction contents;
- hidden principal identity;
- hidden network identity.

They are not equivalent.

---

# 18. AI-native compute plane

## 18.1 Architectural boundary

AI inference and training are not synchronous smart-contract calls.

The chain handles:

- authorization;
- job definition;
- data rights;
- payments;
- commitments;
- verification evidence;
- receipts;
- dispute state;
- settlement.

External workers handle expensive computation.

This borrows the useful `refine → accumulate` separation from JAM while retaining a native transaction, identity and authorization kernel. JAM’s official model similarly distinguishes mostly stateless refinement from stateful accumulation, but its services generally define their own user-facing semantics.  [oai_citation:13‡wiki.polkadot.network](https://wiki.polkadot.network/docs/learn-jam-chain)

## 18.2 Generic artifact object

```text
ArtifactManifest {
    artifact_id
    artifact_type:
        Model
        Dataset
        Runtime
        PromptTemplate
        Tool
        Evaluation
        GeneratedContent

    content_root
    chunk_root
    size
    media_type

    publisher
    license_policy
    data_classification
    provenance_root
    dependency_roots

    creation_receipt?
    evaluation_credentials[]
}
```

## 18.3 Model manifest

```text
ModelManifest {
    artifact_id
    architecture_id
    weights_root
    tokenizer_root
    quantization_profile
    numeric_semantics
    inference_runtime_root

    publisher
    license_policy
    intended_use_commitment
    evaluation_credentials
}
```

Exact proofs require deterministic numeric semantics, including:

- fixed-point representation;
- rounding mode;
- tokenizer version;
- tensor layout;
- sampling algorithm;
- random seed derivation;
- overflow behavior.

## 18.4 Dataset manifest

```text
DatasetManifest {
    artifact_id
    data_root
    schema_root
    lineage_root

    license_policy
    consent_policy
    permitted_purposes
    prohibited_purposes
    retention_policy
    derived_artifact_policy

    privacy_classification
    compensation_policy
}
```

## 18.5 Verification policies

```text
VerificationPolicy =
    ExactStark {
        program_hash
        proof_profile
    }
  | ReplicatedExecution {
        executor_count
        agreement_rule
        executor_credential_policy
    }
  | Optimistic {
        challenge_window
        challenger_bond
        adjudication_program
    }
  | TeeAttestation {
        accepted_platforms
        accepted_measurements
        minimum_security_version
        verifier_policy
    }
  | NamedEvaluator {
        credential_policy
        threshold
    }
  | AllOf(Vec<VerificationPolicy>)
  | AnyOf(Vec<VerificationPolicy>)
```

The assurance type is part of the result and must be displayed to users.

## 18.6 Compute receipt

```text
ComputeReceipt {
    job_id
    executor_principal

    program_root
    model_root?
    runtime_root

    input_root
    output_root
    randomness_commitment

    data_capabilities_used
    tool_capabilities_used
    resource_usage

    evidence:
        StarkProof
        ReplicationCertificate
        OptimisticResult
        AttestationEvidence
        EvaluatorSignatures

    started_at_bound
    completed_at_bound
}
```

## 18.7 Job lifecycle

```text
Create job
   ↓
Authorize data, tools and budget
   ↓
Escrow payment
   ↓
Select executor or open market
   ↓
Execute
   ↓
Submit output commitment and evidence
   ↓
Verify required policy
   ↓
Optional challenge period
   ↓
Settle payment and publish receipt
```

## 18.8 Agent principals

An AI agent is a principal controlled by another principal or organization.

```text
AgentPrincipalMetadata {
    agent_principal
    controller_principal
    agent_class
    default_model_policy
    default_tool_policy
    maximum_session_duration
}
```

The model is not the principal. The agent may change models only within its controller policy.

## 18.9 Agent session

```text
AgentSession {
    agent_principal
    session_authenticator

    allowed_tools
    data_read_scope
    data_write_scope
    data_egress_scope

    monetary_budget
    compute_budget
    action_rate_limit

    high_risk_approval_policy
    valid_until
    delegation_allowed = false
}
```

Prompt text cannot expand this authority.

## 18.10 Propose–authorize–execute–settle

For external side effects:

1. agent produces an `ActionIntent`;
2. deterministic policy classifies the action;
3. required approvals are collected;
4. a one-use capability is issued;
5. tool gateway verifies the capability;
6. tool performs the action;
7. gateway produces a signed receipt;
8. the chain verifies and settles.

Example:

```text
ActionIntent {
    agent
    tool = BankTransferGateway
    action = CreateTransfer
    amount = 420
    currency = EUR
    destination_commitment
    justification_commitment
    expiry
}
```

The model never receives a reusable unrestricted banking credential.

## 18.11 Tool gateway

Every external tool gateway implements:

```text
authorize(capability, action_intent, state_proof)
execute(action_intent)
produce_receipt(external_result)
```

The receipt should include:

- gateway principal;
- tool version;
- action commitment;
- external identifier commitment;
- timestamp bounds;
- result;
- authorization capability consumed;
- PQ signature;
- optional hardware attestation.

## 18.12 Attestation and provenance interoperability

Use adapters for:

- IETF RATS architecture;
- Entity Attestation Tokens;
- SCITT transparency statements;
- C2PA content manifests.

RATS separates attesters, verifiers and relying parties; EAT defines a standard claims container for attestation; SCITT provides transparent signed supply-chain statements; C2PA provides content provenance structures.  [oai_citation:14‡IETF Datatracker](https://datatracker.ietf.org/doc/rfc9334/)

Attestation is evidence about a measured environment. It is not equivalent to a proof of exact computation.

## 18.13 ZK inference roadmap

### Initial support

Prove:

- linear and logistic models;
- decision trees;
- small neural networks;
- deterministic embedding models;
- narrow quantized transformers;
- safety or classification predicates over private data.

### Intermediate support

Add optimized chips for:

- matrix multiplication;
- lookup tables;
- activation approximations;
- attention;
- quantization;
- tokenization;
- deterministic sampling.

### Large-model support

Frontier models initially use:

- replicated execution;
- hardware attestation;
- optimistic challenge;
- specialized proof systems where economically practical.

Research such as zkLLM has demonstrated complete proofs for models up to 13 billion parameters, but reported proof generation times of up to roughly 15 minutes. This is evidence that verifiable LLM inference is feasible, not that frontier per-token real-time proving is solved.  [oai_citation:15‡Hongyang Zhang's Homepage](https://hongyanz.github.io/publications/CCS_zkLLM.pdf)

## 18.14 AI safety boundary

The protocol can prove:

- which model and runtime executed;
- which committed inputs were used;
- which seed was used;
- which tools were authorized;
- which budgets were consumed;
- which output was produced.

It cannot prove merely from computation that the output is:

- factually true;
- socially beneficial;
- unbiased;
- lawful in every jurisdiction;
- aligned with the user’s unstated intention.

Those properties require credentials, evaluations, external facts and human judgment.

---

# 19. Multidimensional fees and economics

## 19.1 Resource vector

```text
ResourceVector {
    consensus_bytes
    data_availability_bytes
    execution_steps
    memory_units
    proof_trace_units
    active_state_byte_epochs
    protected_encryption_recipients
    protected_payload_bytes
}
```

Each dimension has:

- target;
- hard maximum;
- current base fee;
- adjustment denominator;
- minimum fee.

## 19.2 Base-fee update

Use deterministic integer arithmetic:

\[
p_{i,h+1}
=
\max
\left(
p_{i,\min},
p_{i,h}
+
\frac{
p_{i,h}(u_{i,h}-t_i)
}{
t_i d_i
}
\right)
\]

where:

- \(u_i\) is actual usage;
- \(t_i\) is target usage;
- \(d_i\) controls adjustment speed.

Research on multidimensional blockchain fee markets provides strong support for independently pricing non-fungible resource constraints rather than compressing everything into one gas number.  [oai_citation:16‡arXiv](https://arxiv.org/abs/2402.08661)

## 19.3 Transaction payment

\[
\text{charge}
=
\sum_i
p_i \cdot r_i
+
\text{priority fee}
\]

The user submits a maximum price vector.

Unused fee-ticket value is refunded after execution, minus mandatory DA and validation costs.

## 19.4 Prover payment

Prover rewards are determined by a separate market:

- protocol publishes proving plan;
- provers submit proof and requested reward;
- first valid proof within acceptable price wins;
- fallback reward increases over time;
- duplicate valid proofs may receive a small redundancy reward during hardening.

## 19.5 State rent

State rent is charged in byte-epochs.

A storage deposit funds an initial lease. Renewal may be:

- automatic from a sponsor;
- manual;
- paid by the object;
- paid by an application;
- capped by owner policy.

Wallets warn users well before hibernation.

## 19.6 Staking

Separate:

- validator operator principal;
- consensus key;
- withdrawal principal;
- delegated stake pool;
- reward destination.

Stake delegation must not give the operator authority over delegator funds.

## 19.7 Slashing distribution

Slashed capital is divided among:

- reporter reward;
- security reserve;
- burn.

The proposer should not capture all slashing proceeds.

## 19.8 Economic simulation

Before testnet incentives, build an agent-based simulator covering:

- validator concentration;
- builder concentration;
- prover concentration;
- encrypted-lane demand;
- state-rent abandonment;
- DA spam;
- low-fee forced-inclusion attacks;
- stake borrowing;
- censorship bribery;
- proof withholding;
- archive-provider failure.

Economic parameters are not frozen until simulated under both rational and adversarial actors.

---

# 20. Formal-verification program

## 20.1 Verification chain

The intended refinement chain is:

\[
\text{Lean specification}
\Longrightarrow
\text{executable reference model}
\Longrightarrow
\text{production transition code}
\Longrightarrow
\text{ObjectVM trace}
\Longrightarrow
\text{STARK constraints}
\]

The proof system is only useful if it proves the same machine specified by the protocol.

## 20.2 Required theorem set

| Property | Formal statement |
|---|---|
| Policy totality | Every bounded policy request returns exactly one result |
| Policy determinism | Identical request and state produce identical decision |
| Authorization soundness | Every successful write has a valid authorization derivation |
| Default denial | Absence of a valid permit cannot authorize |
| Capability attenuation | Child authority is a subset of parent authority |
| Budget safety | Concurrent uses cannot exceed capability budget |
| Replay freedom | A nonce, ticket or nullifier cannot be successfully consumed twice |
| Recovery safety | Controller replacement requires the declared recovery policy |
| Object uniqueness | One object version has at most one successful successor |
| Resource conservation | Linear resources cannot be created or duplicated except by authorized mint rules |
| Deterministic execution | All conforming executions produce the same output |
| Parallel serializability | Parallel output equals canonical sequential output |
| Atomicity | A multi-command transaction commits all effects or none |
| Access confinement | Execution cannot access undeclared objects |
| Fee correctness | Charged fees equal canonical resource accounting |
| Rent ownership safety | Hibernation does not transfer or destroy ownership |
| Job settlement soundness | Payment occurs only when the declared evidence policy accepts |
| Agent authority bound | An agent action is within its controller-derived capability |
| Proof binding | Proof public inputs uniquely bind pre-state, order set and post-state |
| Consensus safety | Conflicting state roots cannot both finalize under the fault bound |
| Reconfiguration safety | Epoch transition does not create two valid validator-set histories |
| DA reconstruction | Certified data reconstructs under the stated share assumptions |
| Codec injectivity | Distinct values do not share one canonical encoding |

## 20.3 Tool allocation

Use:

- **Lean:** semantic kernel, policies, capabilities, state transition and theorem statements;
- **TLA+:** consensus, reconfiguration, proof pipeline, DA certificates, protected-envelope lifecycle;
- **Verus:** codec, state tree, capability verifier, fee arithmetic and selected consensus logic;
- **Kani:** parsers, integer edge cases, memory safety, unsafe blocks and bounded protocol handlers;
- **property testing:** cross-client equivalence;
- **translation validation:** source language to ObjectVM bytecode;
- **differential proving:** reference interpreter versus proof trace.

## 20.4 Formal model of APL

The APL model must prove:

- termination;
- deterministic `permit`/`forbid` semantics;
- schema-safe field access;
- type preservation;
- `forbid` precedence;
- equivalence between formal evaluator and production evaluator;
- safe compilation into private authorization circuits.

## 20.5 Formal model of parallelism

Prove that:

- disjoint components commute;
- optimistic validation detects stale reads;
- final commit order follows canonical order;
- retries cannot change transaction semantics;
- no partial object updates survive an abort.

## 20.6 Trusted computing base

The smallest unavoidable trusted base includes:

- cryptographic primitive implementations;
- canonical decoding;
- consensus lock and commit rules;
- ObjectVM semantics;
- proof verifier;
- state-root computation;
- protocol-version dispatcher.

Wallets, builders, provers, indexers, archives, tool gateways and AI workers are outside the validity trusted base.

---

# 21. Testing and security program

## 21.1 Continuous integration

Every change runs:

- formatting and static analysis;
- reproducible build check;
- unit tests;
- property tests;
- parser fuzzing;
- canonical-vector tests;
- cross-client differential tests;
- Lean proof checking;
- Verus and Kani suites;
- ObjectVM execution-versus-reference comparison;
- proof-versus-reexecution comparison;
- deterministic simulation;
- benchmark regression tests;
- dependency vulnerability scan;
- SBOM and provenance generation.

## 21.2 Deterministic network simulator

The simulator must model:

- message delay;
- packet loss;
- duplication;
- reordering;
- partitions;
- clock skew;
- Byzantine equivocation;
- validator crashes;
- leader censorship;
- invalid DA shares;
- malformed erasure coding;
- proof withholding;
- incorrect proofs;
- decryption-share withholding;
- early private-share collusion;
- archive loss;
- validator-set churn.

A test should be reproducible from one seed.

## 21.3 Fuzz targets

Fuzz:

- every wire decoder;
- every cryptographic envelope parser;
- policy parser and evaluator;
- bytecode verifier;
- state witness verifier;
- DA sample verifier;
- proof public-input parser;
- credential presentation parser;
- block and QC parser;
- snapshot importer;
- bridge proof parser;
- wallet transaction decoder.

## 21.4 Adversarial testnets

Run dedicated testnets for:

1. consensus equivocation;
2. sustained 20–30% packet loss;
3. one-third validator outage;
4. leader denial-of-service;
5. DA withholding;
6. corrupted snapshots;
7. proof-producer outage;
8. encrypted-transaction spam;
9. builder censorship;
10. credential issuer compromise;
11. mass principal recovery;
12. AI tool prompt-injection attempts;
13. state-rent expiry spikes;
14. client implementation divergence.

## 21.5 Audit sequence

Commission independent reviews of:

1. threat model and architecture;
2. PQ cryptographic profile;
3. consensus and epoch transition;
4. canonical codec;
5. state tree;
6. authorization and recovery;
7. ObjectVM and bytecode verifier;
8. STARK protocol and verifier;
9. private credential and shielded circuits;
10. protected transaction lane;
11. wallet and hardware-key flows;
12. AI tool-gateway model;
13. economics and slashing;
14. build and release supply chain.

No firm should perform every audit.

## 21.6 Supply-chain transparency

Every release publishes:

- source commit;
- reproducible-build instructions;
- compiler and dependency hashes;
- SBOM;
- test results;
- audit status;
- signed release statement;
- transparency-log inclusion receipt.

SCITT’s signed-statement transparency architecture is an appropriate interoperability format for these release attestations.  [oai_citation:17‡IETF Datatracker](https://datatracker.ietf.org/doc/rfc9943/)

---

# 22. Roadmap and milestones

The phases overlap. The month ranges describe a credible engineering program rather than a guaranteed deadline.

## Phase 0 — Protocol foundation  
**Months 0–6**

### Deliverables

- `P-000` through `P-030` draft specifications;
- threat model;
- canonical type system;
- crypto-suite profile;
- Lean model of principals, capabilities, policies and objects;
- first APL evaluator;
- state-tree benchmark prototypes;
- ObjectVM instruction-set prototype;
- deterministic event simulator;
- project repository and supply-chain controls.

### Exit criteria

- security assumptions approved by independent reviewers;
- canonical encoding test vectors frozen for development;
- capability attenuation theorem proved;
- policy totality and determinism proved;
- state-transition reference model executes basic object transfers;
- ML-DSA and ML-KEM benchmarks completed on target hardware;
- no unresolved architectural contradiction among privacy, authorization and execution.

## Phase 1 — Semantic devnet  
**Months 4–12**

### Deliverables

- single-node deterministic chain;
- principal creation and key rotation;
- recovery state machine;
- credentials and status registries;
- capability creation and delegation;
- APL object policies;
- fee tickets and nonce channels;
- initial ObjectVM;
- source-language compiler;
- package deployment and contract calls;
- compute-job and agent object schemas;
- CLI wallet;
- reference indexer.

### Demonstration scenario

1. Alice creates a PQ principal.
2. An organization issues her a private credential.
3. Alice creates an AI agent principal.
4. She delegates a €500/day travel capability.
5. The agent invokes a travel contract.
6. A policy requires human approval above €300.
7. The transaction is denied without approval.
8. Alice adds a one-time approval.
9. The transaction succeeds.
10. The agent’s remaining budget decreases.
11. Replaying the same capability use fails.
12. Reference model and Rust client produce the same state root.

### Exit criteria

- one million randomized transitions without divergence;
- bytecode verifier rejects all generated invalid programs;
- resource conservation proved for standard asset module;
- policy model and production evaluator pass differential testing;
- no network consensus yet required.

## Phase 2 — PQ consensus and DA testnet  
**Months 10–22**

### Deliverables

- peer discovery and authenticated transport;
- ML-DSA consensus votes;
- static-set Jolteon fast path;
- Ditto-style fallback;
- validator staking and epoch transitions;
- raw PQ quorum certificates;
- multi-producer DA workers;
- erasure coding;
- DA sampling;
- snapshot and state sync;
- public transaction mempool;
- full validator re-execution.

### Network stages

```text
4 nodes
→ 16 nodes
→ 64 nodes
→ 256 nodes
→ 1,024-node controlled testbed
```

### Exit criteria

- formal consensus safety proof for implemented locking rules;
- 30-day test with no state divergence;
- recovery after repeated network partitions;
- validator-set transition exercised at least 100 times;
- reconstruction succeeds under the target withholding model;
- validator resource use remains within target hardware bounds;
- independent Go client imports and verifies every block.

## Phase 3 — Proof-carrying execution  
**Months 16–32**

### Deliverables

- ObjectVM trace specification;
- non-recursive transaction STARKs;
- state-tree update proof;
- APL evaluation proof;
- ML-DSA verification proof component;
- recursive partition aggregation;
- global transition proof;
- prover-job protocol;
- fallback CPU prover;
- proof telemetry;
- one-unproved-set backpressure.

### Exit criteria

- 90 consecutive days in which proof root equals re-execution root for every block;
- proof verifier implemented independently in at least two languages;
- no trusted setup;
- proof public inputs bind all state-transition context;
- fallback prover successfully proves maximum-capacity blocks;
- no proof backlog exceeding one order set;
- all known proof-system critical findings resolved.

## Phase 4 — Privacy and protected ordering  
**Months 22–38**

### Deliverables

- private credential presentations;
- domain pseudonyms and nullifiers;
- shielded asset module;
- private policy proofs;
- private-object SDK;
- ML-KEM multi-recipient protected envelopes;
- decryption committee;
- beacon committee;
- post-lock randomized ordering;
- forced-inclusion queue;
- builder bids and bonds;
- privacy relay prototype.

### Exit criteria

- no cross-domain identity link in protocol transcripts absent holder action;
- credential revocation honored within declared freshness bound;
- shielded asset conservation formally specified and audited;
- malformed encrypted transactions cannot block other transactions;
- public lane remains live during complete protected-lane failure;
- front-running simulations show builders cannot inspect protected payloads before set lock under the stated committee assumption.

## Phase 5 — AI and general compute plane  
**Months 24–40**

### Deliverables

- artifact manifests;
- model and dataset profiles;
- compute-job marketplace;
- verification-policy interpreter;
- exact STARK job receipts;
- replicated-execution receipts;
- optimistic challenge receipts;
- RATS/EAT attestation adapter;
- SCITT and C2PA adapters;
- tool gateway;
- agent session capability SDK;
- human-approval workflow;
- deterministic small-model proof profiles.

### Exit criteria

- end-to-end job settlement for every assurance tier;
- wallet displays assurance tier correctly;
- an agent cannot exceed monetary, data, tool or compute capabilities;
- prompt injection cannot bypass the tool gateway;
- exact computation jobs settle only with matching proofs;
- attested jobs clearly expose attestation issuer and accepted measurements;
- data key release is conditional on job authorization and evidence policy.

## Phase 6 — Multi-client adversarial network  
**Months 30–48**

### Deliverables

- Rust, Go and third full client;
- independent state-transition implementations;
- mobile light clients;
- public testnet;
- staking and validator onboarding;
- state rent;
- protocol upgrade mechanism;
- formal theorem completion;
- external audits;
- large bug bounty;
- economic attack simulations;
- disaster-recovery exercises.

### Exit criteria

- no client controls more than 50% of testnet stake;
- at least two minority clients each carry meaningful stake;
- 180 days without unexplained consensus divergence;
- 90 days without proof/re-execution mismatch;
- all critical and high audit findings resolved;
- successful state recovery from certified snapshots;
- successful operation during major prover outage;
- successful recovery from decryption-committee outage;
- reproducible builds verified by independent parties.

## Phase 7 — Mainnet candidate  
**Months 42–54**

### Mainnet-candidate configuration

- 1,024 active validators;
- mandatory execution proof;
- mandatory validator re-execution;
- protected lane optional;
- public lane always available;
- standard shielded assets;
- private credential authorization;
- AI compute objects and labeled assurance tiers;
- no external bridges initially;
- conservative capacity limits;
- long upgrade notice periods.

### Genesis gates

Mainnet does not launch unless:

1. three full clients are production-ready;
2. formal consensus-safety obligations are complete;
3. authorization and capability theorems are complete;
4. proof verifier has multiple independent implementations;
5. all critical cryptography reviews are complete;
6. privacy circuits have been audited;
7. validator hardware targets are met;
8. fallback proving is demonstrated;
9. six months of adversarial testnet history exists;
10. no unresolved high-severity finding remains;
11. genesis allocation is reproducible and publicly inspectable;
12. emergency procedures cannot alter balances or bypass proofs.

## Phase 8 — Stateless-validator transition  
**After stable mainnet operation**

The transition requires:

- at least 12 months of proof-versus-reexecution agreement;
- two independent execution clients;
- proof-system upgrade process tested in production;
- robust state-custodian and snapshot markets;
- emergency fallback proving proven;
- light-client QC compression mature;
- no unresolved circuit-equivalence questions.

Re-execution becomes optional for active validators only after those gates.

---

# 23. First 180 days

## Month 1: charter and threat model

Deliver:

- architectural decision record template;
- threat model;
- security invariants;
- trusted-base inventory;
- protocol terminology;
- initial specification repository;
- dependency and supply-chain policy;
- target hardware profiles.

The threat model must include compromised AI agents, dishonest credential issuers, colluding protected-mempool committees and proof-producer concentration—not only Byzantine validators.

## Month 2: canonical kernel

Deliver:

- canonical IDL;
- binary codec;
- domain-separated hash API;
- primitive types;
- object identifier derivation;
- state-transition input/output schema;
- cross-language test-vector generator.

Acceptance test:

- Rust, Go and Lean decode and re-encode the same corpus byte-for-byte.

## Month 3: principals and authority

Deliver:

- principal object;
- authenticator set;
- key rotation;
- capability grant;
- attenuation verifier;
- revocation registry;
- APL grammar;
- APL formal semantics;
- first policy evaluator.

Acceptance test:

- randomly generated child capabilities can never increase rights;
- formal and production evaluators agree on all generated policies.

## Month 4: object state and VM

Deliver:

- prototype state trees;
- object versions;
- access manifests;
- transaction command graph;
- ObjectVM interpreter;
- bytecode verifier;
- standard asset module;
- deterministic fee accounting.

Acceptance test:

- asset conservation and object-version uniqueness hold under randomized concurrent workloads.

## Month 5: credentials, recovery and jobs

Deliver:

- credential format;
- issuer registry;
- status registry;
- private-presentation proof statement;
- principal recovery;
- compute-job object;
- agent principal;
- agent session capability;
- standard tool-receipt schema.

Acceptance test:

- agent action succeeds only when credential, capability, policy and budget all pass.

## Month 6: semantic devnet

Deliver:

- single-node chain;
- block production;
- CLI wallet;
- contract deployment;
- principal dashboard;
- capability dashboard;
- credential wallet;
- AI agent authorization demo;
- deterministic replay tool;
- first formal assurance report.

The six-month milestone is successful only if the entire principal-to-agent-to-contract authorization path exists before distributed consensus is added.

---

# 24. Staffing plan

## Months 0–12

Approximately 40–50 core contributors:

| Area | People |
|---|---:|
| Protocol architecture and specification | 6 |
| Formal methods | 7 |
| Identity and policy | 7 |
| VM, state and contracts | 9 |
| PQ cryptography and proof research | 8 |
| SDK, wallet and developer tooling | 5 |
| Test infrastructure and release engineering | 4 |

## Months 12–30

Approximately 75–95 contributors:

- consensus and networking expands;
- DA team becomes independent;
- proof-system team grows;
- first independent client team begins;
- AI compute and privacy teams become separate;
- dedicated economics and SRE functions begin.

## Months 30–54

Approximately 100–130 contributors across independent organizations:

| Area | Approximate peak |
|---|---:|
| Protocol and formal methods | 16 |
| Consensus, network and DA | 18 |
| VM, state and contracts | 16 |
| Cryptography, ZK and privacy | 22 |
| Identity, wallet and policy | 14 |
| AI and compute plane | 12 |
| Primary client and SRE | 15 |
| Two independent client teams | 24 |
| Economics and governance | 5 |
| Security assurance and testing | 10 |

External academic reviewers, auditors and cryptographers are additional to these numbers.

---

# 25. Performance and reliability targets

These are engineering gates, not promised production results.

| Metric | Mainnet-candidate target |
|---|---:|
| Order finality, p50 | ≤ 3 seconds |
| Order finality, p95 | ≤ 6 seconds |
| Proof-backed state finality, p95 | ≤ 12 seconds |
| Unproved transaction sets | Exactly 0 or 1 |
| Simple object transfers | ≥ 10,000/second on test profile |
| Mixed policy-rich calls | ≥ 2,000/second on test profile |
| Validator CPU | 16 cores or less under ordinary load |
| Validator memory | 64 GB or less |
| Validator sustained bandwidth | 100 Mbps or less |
| Validator disk | 2 TB commodity NVMe |
| Full snapshot sync | Under 6 hours on target connection |
| Ordinary authorization proof on laptop | Under 3 seconds |
| Shielded transfer proof on laptop | Under 5 seconds |
| Global transition proof | Within one block interval on competitive prover cluster |
| Commodity fallback proof | Under 30 minutes |
| DA false-accept bound | Below \(2^{-80}\) under specified model |
| Hot-data reconstruction | Successful with one-third assigned nodes unavailable |
| Client divergence | Zero unexplained divergences |
| Proof/re-execution mismatch | Zero |

Capacity is reduced rather than weakening cryptographic or validator requirements when a target is missed.

---

# 26. Risk register and mandatory responses

| Risk | Required response |
|---|---|
| PQ vote bandwidth exceeds target | Increase slot duration or reduce active set; do not introduce classical aggregation |
| ML-DSA verifier bug | Maintain independent implementations and suite agility |
| STARK proving is too slow | Lower block capacity and optimize; retain proof requirement |
| STARK verifier disagreement | Halt new order sets before finalizing mismatched state |
| General private contracts are too complex | Launch audited private profiles first; do not claim arbitrary privacy |
| Protected lane is unreliable | Keep public lane live and make protected lane opt-in |
| Protected lane ciphertext is too large | Limit to high-value transactions until a mature PQ batch scheme exists |
| Credential issuer compromise | Key history, status roots, issuance transparency and explicit issuer trust policies |
| Recovery is abused | Delays, challenges, notifications and scoped recovery policies |
| Policy language becomes too expressive | Remove features until totality and analyzability are restored |
| Builder concentration | Forced inclusion, local building and set-only builder authority |
| Prover concentration | Permissionless proving, deterministic chunks and CPU fallback |
| Archive market fails | Mandatory recent snapshots and owner-retained resurrection proofs |
| AI agent prompt injection | Tool gateway enforces capabilities independently of prompts |
| TEE attestation is overstated | Label it as attestation, expose root trust and accepted measurements |
| ZK AI is not economical | Use labeled replication, optimistic or attested tiers |
| Validator operator concentration | Transparent operator principals, client diversity and stake-distribution monitoring |
| State rent harms users | Automatic renewal, long notices and ownership-preserving hibernation |
| Protocol scope grows uncontrollably | Freeze the semantic kernel and move optional schemas into application standards |

---

# 27. Mainnet operational model

## 27.1 Emergency behavior

There is no emergency state-edit key.

Validators may coordinate a temporary `SafetyHalt` that:

- stops admission of new order sets;
- permits evidence and recovery messages;
- cannot change balances;
- cannot replace contract code;
- cannot bypass execution proofs;
- expires automatically unless renewed through the normal validator quorum.

## 27.2 Invalid proof

An invalid proof is ignored.

Repeated invalid proofs result in loss of prover bonds but do not affect state.

## 27.3 No proof available

The chain stops admitting new user order sets and opens the proving reward to all participants. Consensus may continue maintenance blocks.

## 27.4 Client divergence

On detecting divergent proposed state roots:

1. stop voting for state finalization;
2. publish full diagnostic traces;
3. retain the last proven state;
4. identify which implementation diverged;
5. release a patched client through the normal signed release process;
6. resume without rewriting previously finalized state.

## 27.5 Finalized semantic bug

There is no hidden technical mechanism that can make an already finalized invalid semantic rule disappear.

Any exceptional fork is an explicit social action, visible as a new protocol history.

---

# 28. Definition of completion

The implementation is complete only when the following end-to-end statement is true:

> A user can create a post-quantum principal, privately prove an accepted credential, delegate a narrowly scoped capability to an AI agent, have that agent submit a protected action or compute job, enforce deterministic object and contract policies, execute or verify the work under a declared assurance tier, settle the result atomically, and allow an ordinary node to verify data availability, a PQ consensus certificate, authorization correctness and one succinct state-transition proof without trusting the builder, prover, AI worker, credential holder, tool gateway or storage provider beyond the assumptions explicitly declared by policy.

The most important early deliverable is therefore not a high-throughput testnet. It is a small executable kernel in which authority cannot be implicit, delegation cannot amplify rights, policy evaluation cannot diverge, assets cannot be duplicated, AI agents cannot escape their capabilities, and every accepted transition has one canonical meaning.
