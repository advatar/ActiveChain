I reviewed the repository as an end-to-end security-critical system rather than judging it by the number of crates, tests, or formal artifacts. The overall architecture is strong and unusually disciplined for a project at this stage, but I would **not move toward a value-bearing public network yet**. The largest remaining risks are not basic Rust quality; they are cryptographic composition, consensus proof completeness, wallet key custody, network/adversarial testing, proof-system qualification, and the sheer amount of protocol surface that has accumulated.

A particularly important point: the repo itself is candid about this. `README.md:36–38` explicitly says checked milestones do not imply end-to-end completeness, `README.md:59–63` lists major unfinished security work, and `SECURITY.md:5–7` says there is no production-ready release or independent security audit. That assessment is correct.

## Overall assessment

I would rate the project approximately:

| Area                         | Assessment                              | Main issue                                                |
| ---------------------------- | --------------------------------------- | --------------------------------------------------------- |
| Protocol architecture        | **Very strong**                         | Too much v1 surface                                       |
| Rust kernel design           | **Strong**                              | Composition harder to reason about than individual crates |
| Canonicalization/determinism | **Very strong**                         | Need independent verifier completion                      |
| Consensus safety             | **Promising but not closed**            | Whole-history/refinement theorem still open               |
| Consensus networking         | **Needs work**                          | Bespoke secure channel                                    |
| PQ crypto integration        | **Needs external review**               | Custom constructions around standardized primitives       |
| Cash/accounting              | **Strong kernel**                       | Full finality/replay refinement incomplete                |
| Proof systems                | **Experimental**                        | Soundness/parameter qualification not finished            |
| Wallet                       | **Not production ready**                | Secure PQ keystore and mobile hardware binding unfinished |
| FFI                          | **High-risk boundary**                  | Large unsafe C surface                                    |
| Storage/archive              | **Advanced**                            | Economics/finalized settlement wiring incomplete          |
| Agent/MCP layer              | **Good direction**                      | Keep it subordinate to authorization kernel               |
| Formal verification          | **Excellent direction**                 | Several key composition theorems remain bounded/abstract  |
| Fuzz/adversarial testing     | **Weak relative to project complexity** | I found no proper fuzz harness                            |
| Operational security         | **Early**                               | No stable supported release/audit/incident maturity       |
| Decentralization             | **Architecturally thoughtful**          | Complexity and prover concentration remain major risks    |

The project is closer to an **advanced research/testnet implementation** than a production L1. That isn't criticism of the quality—it is mainly a consequence of how ambitious the design is.

# Critical / high-priority findings

### 1. Replace the bespoke cryptography around ML-KEM

This is my strongest concrete code-level objection.

`crates/crypto-provider/src/lib.rs:29–125` implements `ProtectedEnvelope` as:

```text
ML-KEM shared secret
      ↓
SHAKE-generated XOR stream
      +
SHAKE-generated authentication tag
```

Specifically:

* `xor_stream()` at approximately `107–118`
* `envelope_tag()` at approximately `119+`

The validator PQ session does essentially the same thing independently in:

`crates/consensus-runtime/src/pq_session.rs:148–175`

and:

`crates/consensus-runtime/src/pq_session.rs:457–...`

where the code does:

```rust
let keystream = stream(&session.key, &associated_data, plaintext.len());

let ciphertext =
    plaintext.iter().zip(keystream)
        .map(|(byte, mask)| byte ^ mask)
        .collect::<Vec<_>>();

let tag =
    expand(PROTECTED_TAG_DOMAIN,
           &[&session.key, &associated_data, &ciphertext]);
```

I don't see an obvious trivial break in that construction. Domain separation and unique sequence-bound associated data are clearly being considered.

But that is not a sufficient reason to deploy it.

You are effectively defining an ActiveChain-specific authenticated encryption protocol. That means you inherit questions around:

* key separation;
* misuse resistance;
* multi-user security;
* nonce reuse;
* transcript binding;
* KEM/DEM composition;
* chosen-ciphertext behavior;
* side channels;
* session rollover;
* key compromise;
* rekeying;
* truncation/security bounds;
* cross-protocol key use.

There is very little upside.

I would instead make the PQ channel:

```text
ML-KEM-768
   │
   ▼
shared secret
   │
   ▼
HKDF-SHA-384 / SHAKE-based standardized KDF
   │
   ├── client→server AEAD key
   ├── server→client AEAD key
   ├── exporter key
   └── confirmation key

AEAD:
AES-256-GCM
or
ChaCha20-Poly1305
```

with explicit transcript hashing.

Even better, use a standardized/hardened hybrid handshake framework where feasible rather than designing another transport protocol.

**Priority: P0 before security audit.**

---

### 2. The same custom crypto exists in two places

This compounds finding #1.

You have one protected-envelope construction in `crypto-provider` and another in `consensus-runtime::pq_session`.

Even if both are sound, two related cryptographic constructions mean:

```text
ProtectedEnvelope semantics
        ≠
PQ session semantics
```

and therefore two things auditors need to prove.

Consolidate into one cryptographic channel abstraction.

Something like:

```rust
trait ProtectedChannel {
    fn seal(
        key: &TrafficKey,
        sequence: u64,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Ciphertext>;

    fn open(...) -> Result<Plaintext>;
}
```

The consensus layer should not know how encryption works.

---

### 3. Session secrets aren't visibly lifecycle-hardened enough

You already use `zeroize` elsewhere in `consensus-runtime`, which is good.

But:

```rust
pub struct PqPeerSession {
    ...
    key: [u8; 32],
}
```

is `Clone`.

That makes secret lifetime harder to reason about.

For session secrets I would use:

```rust
Zeroizing<[u8; 32]>
```

or a dedicated non-`Clone` secret type implementing `ZeroizeOnDrop`.

The same applies wherever:

* ML-KEM shared secrets;
* deterministic signing seeds;
* decrypted wallet keys;
* ephemeral traffic keys

exist in ordinary `Vec<u8>` or arrays.

I'd make this structural rather than relying on developers remembering to call `zeroize()`.

---

### 4. Consensus formal verification isn't finished at exactly the most important level

`STATUS.md` is explicit here.

The project has already done a lot:

* quorum intersection;
* authentication;
* non-equivocation;
* QC composition;
* safe voting;
* locks;
* chained QC commit;
* bounded TLA+ checking;
* crash/restart cases;
* epoch transition traces.

That's excellent work.

But this item remains open:

> Prove any two finalized histories are prefix-comparable, including view changes, epoch changes, and restart recovery.

And the existing result is described as:

> production trace refinement remains

or

> unbounded production trace theorem remains open.

That distinction matters.

You have shown something like:

```text
model satisfies safety
+
selected Rust executions correspond to model
```

but the ideal end state is:

```text
ALL production executions
       ↓ refinement
formal transition relation
       ↓ theorem
prefix-comparable finalized histories
```

Without the refinement step, a bug in Rust that falls outside the modeled transition relation can invalidate the theorem while all formal proofs remain true.

For an ordinary application I'd call this ambitious optional verification.

For a novel consensus implementation holding value, I'd treat it as a major launch gate.

**P0 before mainnet.**

---

### 5. Cash formal verification has the same model-to-production gap

The repo says:

> broader unbounded and block-finality refinement remains open.

The abstract accounting model is good, and you have gone surprisingly far into:

* chain-bound intents;
* authenticated sender;
* one-shot sessions;
* nonce replay;
* input authorization;
* issuance;
* reward redemption;
* shielding;
* restart safety.

But cash correctness doesn't end at the cash kernel.

The real property is approximately:

[
\forall H:
\operatorname{Finalized}(H)
\Rightarrow
\operatorname{Conservation}(H)
\land
\operatorname{Authorization}(H)
\land
\operatorname{NoReplay}(H)
]

across:

```text
RPC
→ admission
→ authorization
→ mempool/order
→ block application
→ storage
→ crash
→ recovery
→ consensus finalization
→ RPC proof
```

That composition is a harder theorem than conservation inside `cash-kernel`.

It remains one of the principal launch blockers.

---

### 6. Proof-system security qualification is incomplete

This is another area where STATUS is correctly cautious.

The repository still says:

> Refine the AIR against P-050 ObjectVM semantics and publish an independent second verifier.

and:

> Qualify proof parameters against the required soundness and verifier-cost gates before consensus activation.

Those should remain hard blockers.

Do not let:

```text
STARK verifies
```

become equivalent in documentation to:

```text
the proof demonstrates the ActiveChain transition semantics
```

until the refinement relationship is explicit.

The security claim must be:

[
\operatorname{VerifyProof}(P)=1
\Rightarrow
S_{i+1} = T(S_i,A_i)
]

not merely:

[
\operatorname{VerifyProof}(P)=1
\Rightarrow
\text{AIR constraints were satisfied}
]

The second statement only becomes useful once the AIR faithfully represents `T`.

---

### 7. Independent verifier work needs to become a first-class release criterion

Your architecture depends heavily on the claim:

> independent verification is cheap and doesn't require trusting the validator implementation.

Excellent.

But STATUS still includes unfinished independent semantic verification work in Go.

This is not just “client diversity.”

For this architecture it is a core security mechanism.

At minimum I'd require:

```text
Rust implementation
        │
canonical vectors
        ▼
Go verifier

AND

Rust implementation
        │
canonical vectors
        ▼
a second implementation
```

with no shared serialization implementation or copied state-transition code.

I would probably make:

**2 independent verifier implementations + canonical vector corpus**

a mainnet requirement.

---

### 8. There is effectively no serious fuzzing programme visible

I searched the repository and CI for the usual fuzz infrastructure and did not find meaningful:

* `cargo-fuzz`;
* libFuzzer harnesses;
* AFL;
* honggfuzz.

Yet your own audit scope correctly calls out fuzzing of:

* canonical codec;
* bytecode verifier;
* ObjectVM;
* envelope parsing;
* FFI.

This needs to become real code, not an audit wish.

For a project with hostile byte inputs almost everywhere, I'd create a `fuzz/` workspace with at least:

```text
codec_decode
codec_roundtrip

protocol_envelope
peer_frame
pq_session_frame

objectvm_bytecode
objectvm_execute

credential_sdjwt
credential_mdoc

rpc_request
rpc_response

wallet_ffi_inputs
verifier_ffi_inputs

state_witness
cash_transaction

archive_manifest
snapshot_decoder
```

And persistent OSS-Fuzz style corpora.

Your property tests and malformed fixtures are useful, but fuzzing discovers a different class of problem.

**This is one of the biggest engineering gaps I found.**

---

### 9. The wallet FFI is too large for comfort

`crates/wallet-ffi/src/lib.rs` begins with:

```rust
#![allow(unsafe_code)]
```

which is unavoidable for a C ABI.

But the file exposes a large number of raw-pointer entry points and callback functions.

The design generally appears careful about:

* null pointers;
* explicit lengths;
* bounded inputs;
* fixed-size output structures.

Still, the amount of unsafe boundary code is substantial.

The FFI should be minimized aggressively.

Rather than exposing dozens of semantic operations via C, I would prefer a much narrower ABI:

```text
wallet_create
wallet_destroy

wallet_request(...)
wallet_response_free(...)

sign_callback
secure_storage_callback
network_callback
```

with canonical serialized requests crossing the boundary.

In other words:

```text
rich Rust API
        ↓
very thin C ABI
        ↓
Swift/Kotlin
```

rather than mirroring the Rust feature surface in C.

This materially reduces audit surface.

---

### 10. The mobile wallet is still missing the actual production key-security boundary

STATUS says the following are still unfinished:

* encrypted PQ keystore;
* ML-DSA/ML-KEM key lifecycle;
* recovery;
* physical-device qualification;
* binding Keychain/Android Keystore callbacks;
* eliminating plaintext-key exposure;
* secure-storage audit.

That means the native UI can look polished while the most important wallet property is not yet complete.

The rule should be:

```text
signing key plaintext
NEVER
crosses the Rust/native interface
```

and ideally never exists as a long-lived plaintext object at all.

For algorithms not directly supported by Secure Enclave/Android StrongBox, I'd use the hardware key to wrap a PQ secret:

```text
hardware-bound key
       │
       ▼
unwrap encrypted ML-DSA key
       │
short-lived protected memory
       ▼
sign
       │
zeroize
```

plus anti-rollback storage and recovery semantics.

Until this exists, the wallet is a prototype regardless of UI completeness.

# Significant architectural gaps

### 11. The v1 protocol surface has grown too large

This may be the largest strategic weakness.

You now have first-class machinery for:

* native cash;
* multi-assets;
* DID;
* VC;
* capabilities;
* policies;
* ObjectVM;
* RISC Zero guests;
* PQ ZK;
* archive economics;
* rent;
* MCP;
* A2UI;
* AI/agent authorization;
* payment connectors;
* external credentials;
* compliance;
* private proofs;
* mobile wallets.

All of those are individually defensible.

Together they create:

[
\text{security complexity}
\gg
\sum \text{individual feature complexity}
]

because interaction terms grow rapidly.

I would strongly consider a **Mainnet Core profile** containing only:

```text
Principal
Authenticator
Capability
Policy
Object
Native Asset
Canonical Action
State Transition
Consensus
DA
Finality
Light Verification
```

Everything else becomes a profile or application layer.

For example:

```text
Actum Core
├── Cash Profile
├── Identity Profile
├── Regulated Asset Profile
├── Agent Profile
├── Private Proof Profile
└── Archive Market Profile
```

This gives auditors a smaller trusted computing base.

---

### 12. APL needs authoring tooling before it becomes broadly usable

The security model is quite good:

`ARCHITECTURE_GUIDE.md:193–214` describes a total evaluator with:

* default deny;
* forbid-over-permit;
* bounded facts;
* no I/O;
* no recursion;
* fixed work;
* atomic obligation settlement.

Excellent.

But the architecture guide also says:

> The friendly textual policy syntax/compiler remains planned.

This will matter quickly.

Nobody should hand-author serialized `PolicySetV1` structures at scale.

You need:

```text
human policy
    ↓
typed policy DSL
    ↓
canonical APL IR
    ↓
static analysis
    ↓
simulation
    ↓
compiled PolicySetV1
```

and tooling that answers:

```text
Why was this denied?
Why was this allowed?
What authority was actually used?
What changes if fact X disappears?
Can this capability ever authorize Y?
```

Otherwise policy becomes correct but operationally unusable.

---

### 13. ObjectVM is intentionally tiny—but you don't yet have the developer layer above it

`ARCHITECTURE_GUIDE.md:233–244` makes the right security choice: ObjectVM is small, typed, bounded and forward-only.

The missing piece is the safe compilation ecosystem.

You will eventually need:

```text
high-level language / DSL
        ↓
typed IR
        ↓
ObjectVM
        ↓
bytecode verifier
```

with compiler correctness treated as desirable but **not trusted**.

This is where your earlier Capsulang/Authority-IR ideas actually fit very naturally.

ObjectVM should stay boring.

Do not “improve usability” by turning ObjectVM itself into a general smart-contract VM.

---

### 14. Archive economics aren't fully connected to finalized economics

STATUS still records:

> Wire finalized settlement outputs into the native token ledger

and related archive/rent ingress work.

This matters because otherwise you've proved mechanics but not the economic game.

The full archive property needs to encompass:

```text
assignment
→ escrow
→ challenge
→ response
→ finality
→ reward/slash
→ token accounting
→ archive reassignment
```

under reorg/crash/restart conditions.

Archive availability cannot depend on an economic subsystem whose payment semantics aren't part of the finalized ledger state.

---

### 15. Storage operations still need full finalized-transaction ingress

Likewise, storage commands being implemented internally isn't equivalent to them being safely exposed on the network.

You already acknowledge this with:

> Route storage commands through finalized transaction ingress

Keep that separation.

Every state-mutating protocol surface should enter through one canonical path:

```text
AuthenticatedAction
     ↓
Admission
     ↓
Authorization
     ↓
Resource accounting
     ↓
Execution
     ↓
Proof/receipt
     ↓
Consensus
```

Avoid special operator paths.

---

### 16. Network DoS/eclipsing needs much more adversarial qualification

There is good defensive engineering already:

* bounded peer frame size;
* ingress worker limits;
* bounded queues;
* pre-auth rate limits;
* source tracking;
* session expiration;
* authenticated peers;
* replay tracking.

That's solid.

But I would still add a dedicated adversarial network harness covering:

```text
slowloris
partial-frame stalls
signature verification floods
ML-KEM handshake floods
connection churn
IP rotation
validator impersonation
stale epoch keys
massive reconnect storms
peer eclipse
asymmetric partitions
clock skew
replay floods
certificate amplification
malformed-frame CPU asymmetry
```

The important metric isn't merely:

```text
bad message rejected
```

but:

[
\frac{\text{attacker cost}}
{\text{validator cost}}
]

You want that ratio to be favorable before expensive PQ verification.

---

### 17. PQ signatures radically increase bandwidth—model this globally

ML-DSA signatures are large.

You are carrying them in:

* consensus votes;
* peer authentication;
* identities;
* transactions;
* possibly credential/controller operations.

A system that looks efficient under Ed25519 assumptions can behave very differently under ML-DSA.

I would create a formal bandwidth budget:

[
B =
B_{\text{transactions}}
+
B_{\text{votes}}
+
B_{\text{DA}}
+
B_{\text{proofs}}
+
B_{\text{PQ-auth}}
]

for:

* 100 validators;
* 500 validators;
* 1,024 validators.

Then simulate:

* normal operation;
* view changes;
* validator-set transition;
* network degradation.

Signature aggregation is harder in the PQ setting, so this deserves explicit architectural treatment rather than ordinary benchmarking.

---

### 18. Consensus topology is still fairly static

I found genesis-address-based peer configuration and a `PeerConnector` constructing authenticated connections to configured validator endpoints.

That's appropriate for a developmental BFT network.

It isn't yet what I'd call a robust decentralized networking layer.

Longer term you'll need explicit designs for:

* peer discovery;
* endpoint rotation;
* NAT;
* DDoS-resilient topology;
* validator address privacy;
* multi-homing;
* sentry nodes;
* gossip fanout;
* eclipse resistance.

Don't blur:

```text
consensus algorithm decentralization
```

with:

```text
network topology decentralization.
```

They're separate.

# Code quality observations

### 19. The Rust kernels are generally defensive

I saw quite a lot I like:

* `unsafe_code = "forbid"` as workspace policy;
* release overflow checks;
* canonical encodings;
* bounded collections;
* checked arithmetic;
* explicit domain separation;
* type tags and schema revisions;
* resource ceilings;
* fail-closed decoding;
* restart/corruption tests;
* deterministic vectors.

This is substantially better than the average experimental chain.

There are many `unwrap()` calls in the repository, but the raw count is misleading because a large number are inside embedded `#[cfg(test)]` modules and fixed-size parsing where length has already been checked.

I would **not** prioritize a blind "`unwrap()` elimination" campaign.

Prioritize attacker-reachable panics instead.

---

### 20. Some source files are too large

Examples include approximately:

* `consensus-runtime/src/lib.rs` — >300 KB
* `payment-connector-host/src/lib.rs` — >160 KB
* `protocol-types/src/asset.rs` — ~148 KB
* `payment-types/src/lib.rs` — ~144 KB
* `wallet-ffi/src/lib.rs` — ~120 KB
* `rpc-server/src/lib.rs` — ~116 KB

Large files aren't intrinsically insecure.

But in security-sensitive systems, they make it harder to establish clear invariants.

`consensus-runtime/src/lib.rs` in particular should probably become modules such as:

```text
consensus/
  proposer.rs
  voting.rs
  locking.rs
  commit.rs
  view_change.rs
  reconfiguration.rs

network/
  frame.rs
  handshake.rs
  secure_channel.rs
  ingress.rs
  peer_directory.rs

persistence/
  safety_state.rs
  round_journal.rs
  recovery.rs
```

A reviewer should be able to understand a security boundary without loading 300 KB of unrelated code.

---

### 21. The STATUS file is impressive but has become a second project

`STATUS.md` is extremely detailed and useful historically.

But it is thousands of lines and mixes:

```text
past implementation narrative
current status
GitHub issue history
CI results
launch gates
future roadmap
```

At this size, it becomes difficult to answer:

> What blocks mainnet **today**?

I would split it:

```text
STATUS.md
    1–2 page live status only

ROADMAP.md
    future milestones

LAUNCH_GATES.md
    binary release requirements

docs/history/
    completed issue narratives
```

And make `LAUNCH_GATES.md` machine readable.

For example:

```yaml
mainnet:
  external_audit: false
  consensus_refinement: false
  cash_refinement: false
  proof_soundness_review: false
  independent_verifiers: 1/2
  fuzzing_gate: false
  ios_secure_keystore: false
  android_secure_keystore: false
```

That prevents accidental claim inflation.

# What I would build next

I would **stop adding protocol features temporarily**.

The next programme should be a security-convergence milestone:

1. **Eliminate bespoke symmetric cryptography.** Standardize KEM→KDF→AEAD and zeroize all secret-key types.

2. **Finish consensus production refinement.** Prove Rust traces implement the model across view change, reconfiguration, restart, and finalization.

3. **Finish cash-to-finality refinement.** The theorem should span authenticated ingress through finalized state.

4. **Finish proof-semantic refinement and soundness qualification.** Especially CashAIR/ObjectVM and the second verifier.

5. **Build fuzz infrastructure.** Run continuously against parsers, VM, FFI, protocol envelopes and network frames.

6. **Shrink the launch TCB.** Define an explicit Actum Core mainnet profile and move optional functionality behind protocol profiles.

7. **Complete mobile custody.** Hardware-bound wrapping, encrypted PQ keystore, recovery, zeroization and real-device testing.

8. **Reduce the FFI.** Turn it into a minimal serialized-command ABI.

9. **Build realistic adversarial networking tests.** Include eclipse, flood, PQ-verification asymmetry and multi-validator chaos.

10. **Then freeze the protocol and commission the external audit.** Don't begin the expensive audit while core semantics are still moving.

## The most important architectural recommendation

I would resist the temptation to keep turning ActiveChain/Actum into the place where every interesting concept becomes a native consensus primitive.

The strongest part of this project is becoming:

[
\boxed{
\text{Authenticated authority}
+
\text{deterministic transition}
+
\text{proof}
+
\text{finality}
}
]

That is the kernel.

Things such as agents, identity credentials, regulated assets, AI computation, archive markets, payments and applications should increasingly look like **composable profiles over that kernel**, not new kernel concepts.

That would make Actum far easier to audit, standardize and eventually implement independently.

And it fits the rebrand unusually well: an **Act** can essentially become

[
A =
(
S_{\mathrm{pre}},
I,
Auth,
P,
E,
S_{\mathrm{post}},
R
)
]

where:

* (S_{\mathrm{pre}}) is the authenticated prior state,
* (I) is intent,
* (Auth) is authority,
* (P) is policy/proof,
* (E) is deterministic execution,
* (S_{\mathrm{post}}) is resulting state,
* (R) is the independently verifiable receipt.

Everything else becomes vocabulary layered onto this object.

So my conclusion is: **the fundamental architecture is worth continuing, and much of the implementation is unusually rigorous. But the project has reached the point where adding more features will lower rather than raise its chance of success. The next phase should be reduction, composition proofs, fuzzing, custody, independent implementations and audit.**

