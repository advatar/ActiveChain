# ActiveChain architecture guide

Status: living integration guide. Normative protocol specifications take precedence. Production
security and independent audit are incomplete.

## 1. The system in one sentence

ActiveChain lets independently authenticated principals act on canonical assets and objects through
attenuated capabilities and total policies, optionally prove private credential predicates, execute
bounded public programs or pinned private proof guests, and leave a finalized receipt that an
independent verifier can check.

```text
person / organization
  └─ wallet principal and secure keys
       ├─ credentials and private witnesses
       ├─ agent registry
       │    └─ public agent principals + attenuated capabilities
       └─ approved canonical intent
              ↓
authenticated actor + capability chain + verified facts + APL decision
              ↓
native cash / typed transition / ObjectVM / verified private-proof journal
              ↓
consensus + finalized state, inclusion evidence, and receipt
```

## 2. First-class protocol values

Assets, objects, principals, credentials, capabilities, policies, actions, proofs, and receipts are
versioned canonical values rather than application conventions. This gives wallets, applications,
validators, indexers, and offline verifiers one meaning for:

- which asset or object is affected;
- who authenticated and under which key provenance;
- which authority was delegated and how it was attenuated;
- which credential predicate was verified and at what assurance;
- which policy revision decided the action;
- which state, nonce, budget, fee, and validity interval were bound;
- which effects finalized.

The cost is a larger consensus surface. New first-class semantics require canonical encoding,
bounded evaluation, compatibility rules, deterministic vectors, formal refinement, migration, and
independent review. Features that cannot justify that burden belong above consensus.

## 3. Principals and key roles

A principal identifier is stable across controller-key rotation. A principal may represent a
person, organization, agent, validator, issuer, application, or service. Do not use one key for all
roles.

| Key or secret | Owner | Purpose | Expected custody |
| --- | --- | --- | --- |
| Wallet controller/signing key | User or organization | Principal lifecycle and approved actions | Secure Enclave, Android Keystore, hardware wallet, or audited signer |
| Recovery authority | User-designated recovery policy | Freeze/recovery and controller replacement | Separate device, social/organizational threshold, or offline hardware |
| Credential holder key | Credential subject | Holder binding and presentations | Wallet secure hardware; distinct by profile where required |
| Agent controller key | Agent operator/process | Authenticate the independent agent principal | Agent device HSM/secure hardware or isolated service signer |
| Device/app-instance key | One installation | Enroll and attest a particular instance | Platform secure storage; replaceable without changing the principal |
| Transport/session key | Wallet, app, or agent session | Encrypt/authenticate one bounded channel | Ephemeral; short-lived; never treated as chain authority |
| Action/session signing authority | Delegated agent session | Sign a bounded sequence/budget of canonical requests | Short-lived and capability/policy constrained |
| Validator/operator keys | Node operator | Consensus, RPC terms, deployment operations | Separate role-specific operational custody |

No App Group, relay, push notification, App Intent, log, analytics event, or backup may contain a
plaintext signing key or reusable bearer capability.

## 4. Agent keys

### 4.1 What an agent is

An agent is an independently authenticated ActiveChain principal. It is not synonymous with an
installed app, an App Intent, a cloud process, or a model. Several processes may operate one agent
principal under an explicit multi-device or rotation policy; one app may operate several agents.

The wallet does **not** store the agent secret key. The durable wallet registry stores the public
agent principal, label, connection kind, capability identifiers, budget, expiry, lifecycle, and
consumed request identifiers. Agent secret material remains with the agent.

### 4.2 Enrollment

1. The agent creates its controller key and principal outside the wallet.
2. The agent presents its public principal, supported protocol/version, connection metadata, and
   available key-provenance or device-attestation evidence.
3. The wallet verifies the enrollment channel and shows the user exactly what entity is being
   enrolled. Platform attestation strengthens provenance but is not the principal itself.
4. The wallet creates a new, narrowly attenuated capability: exact actions/resources, recipients,
   value and fee limits, use count, validity, delegation depth, purpose, and approval policy.
5. The user approves the grant with wallet authentication. The finalized capability, not the local
   contact record, is the authority.

An agent never receives the wallet controller key or an unrestricted “sign anything” API.

### 4.3 Requests and signing

Each request binds:

```text
chain + genesis + agent principal + capability chain
+ exact action, resources, recipients and effects
+ value, fee, budget and validity
+ nonce/session/request identifier
+ policy and credential-proof commitments
```

The agent signs the canonical request with its own authorized key. The wallet may reject it locally,
require biometric/human approval, contribute a separate authorization, or merely display it,
depending on policy. Validators recheck actor authentication, capability attenuation, revocation,
APL, budgets, replay barriers, state versions, and obligations. Wallet approval is not a substitute
for validator authorization.

### 4.4 Pause, revoke, rotate, and recover

- **Pause** is immediate local refusal by this wallet. It is reversible and not global chain state.
- **Revocation pending** means the wallet refuses locally while the revocation transaction awaits
  finality.
- **Finalized revocation** invalidates the named capability for every conforming verifier.
- **Agent-key rotation** changes the controller/authenticator under an authorized principal
  lifecycle operation; it must not silently widen existing capabilities.
- **Compromise response** pauses locally, submits revocation, rotates or deactivates the principal
  as policy permits, invalidates sessions, and audits actions since the last trusted checkpoint.
- **Recovery** uses a separately authorized recovery policy. The recovery key must not be the same
  secret as the compromised controller key.

Removing an app does not revoke a remote capability. Losing one device does not justify treating
unfinalized local state as global revocation.

### 4.5 Local, third-party, and remote agents

- Same-team apps and extensions may use an Apple App Group only as a bounded request/receipt inbox.
- Third-party apps use universal links, QR/document handoff, browser integration, or an
  authenticated encrypted relay. They cannot join the wallet App Group.
- Remote agents use the same principal/capability protocol and should normally receive shorter
  validity and lower budgets.
- App Intents navigate or invoke a flow; they are not credentials and cannot grant, approve,
  revoke, sign, or submit authority changes by themselves.
- Network extensions may observe/control flows under platform policy but cannot infer encrypted
  semantic intent and must not become the authorization root.

The wallet can control what its keys authorize and what ActiveChain capabilities allow. It cannot
intercept unrelated behavior inside a third-party app.

## 5. Wallet custody

The native wallet is a thin shell over the shared Rust core:

- platform code owns UI, lifecycle, secure-storage handles, and transport;
- Rust owns canonical intents, policy decisions, Coin Cell selection, replay-safe session rules,
  and signature verification;
- secure-key callbacks sign only an already approved, domain-separated payload;
- Rust verifies the returned signature before an envelope can reach transport.

The current design supports opaque encrypted key slots and hardware-backed callback boundaries.
Independent iOS Keychain/Secure Enclave and Android Keystore audit remains a launch gate. Backups
must be encrypted, versioned, integrity protected, and explicit about which keys are device-bound
and therefore not recoverable from ciphertext alone.

## 6. Credentials, identity, and private attributes

EUWallet is the natural custody and consent surface for EUDI credentials and TLSNotary-derived
credentials. ActiveChain consumes only versioned verifier results and proof public inputs.

Assurance must not be upgraded:

```text
TLS-notarized evidence
  ≠ holder self-issued identity assertion
  ≠ authorized issuer credential
  ≠ EUDI PID or (Q)EAA unless the applicable trust framework says so
```

Zero knowledge proves predicates without hiding provenance. Examples include:

- age is at least 18 without birth date or exact age;
- funds exceed a threshold without exact balance or account history;
- nationality is not in a denied set without revealing nationality.

Proofs bind credential commitment, assurance, issuer/notary authorization, status/freshness, holder,
chain/genesis, asset/application, action, policy revision, audience, purpose, nonce, expiry, proof
version, and a policy-scoped nullifier or pairwise identity. Raw credentials, TLS transcripts,
account identifiers, exact balances, and stable global identifiers stay off-chain.

Repeated queries can still cause inference. Wallet consent must identify tiny sets, unusual
predicates, retention, and intersection/correlation risks.

## 7. Capabilities and APL

A capability says what authority a principal possesses. Delegation is accepted only when the child
is mechanically no broader than the parent across action, resource, data, budget, use count,
validity, and remaining delegation depth. Delegated bearer capabilities are rejected in version 1.

APL decides whether verified request facts satisfy policy. Implemented APL v1 is a canonical typed
AST and total evaluator with:

- default deny and `forbid` overriding `permit`;
- bounded rules, predicates, facts, and obligations;
- no I/O, mutation, recursion, dynamic dispatch, or nondeterministic facts;
- fixed work metering independent of predicate truth;
- atomic settlement of returned obligations by the enclosing transition.

The friendly textual policy syntax/compiler remains planned authoring tooling. Consensus consumes
only validated `PolicySetV1`, not source text or an ambient parser.

Authorization is an intersection:

```text
authenticated actor
AND verified request and credential facts
AND valid non-revoked attenuated authority
AND APL permit
AND no protocol forbid
AND atomic obligation settlement
```

## 8. Assets, cash, and tokenization

Native ACT uses Coin Cells, explicit payment and fee inputs, canonical intents, signed sessions,
and conservation-checked transitions. Native multi-asset Coin Cells, issuer registries, stablecoins,
and the full tokenization lifecycle remain active protocol work.

The target is first-class fungible, non-fungible, and series assets with declared issuer/controller
authority, supply, issuance/redemption/burn rules, optional declared controls, corporate actions,
attestations, asset-specific identity policy, proof-bearing discovery, and wallet support. An
application must not be able to reinterpret an asset identifier or bypass its protocol policy.

## 9. Execution and proof systems

The three programming boundaries are intentionally different:

| Boundary | Role | Current reality |
| --- | --- | --- |
| APL | Authorization decision | Typed AST and evaluator implemented; authoring compiler planned |
| ObjectVM | Deterministic public state transition | Small typed forward-only bytecode and verifier; richer packages/calls/upgrades planned |
| RISC Zero | Private computation proof | Pinned application-specific guests and verified journals; not the consensus contract VM |

ObjectVM v1 has explicit typed inputs, at most 32 registers and 256 instructions, forward-only
control flow, prepaid gas, affine capabilities, linear objects, and no ambient storage, time,
filesystem, network, floating point, recursion, or runtime loading.

Arbitrary programs are not accepted merely because a language compiles to generic RISC-V or targets
RISC Zero. Future languages may compile to ObjectVM, but the ObjectVM bytecode verifier and
canonical effects—not the compiler or source language—remain the security boundary. RISC Zero
guests are pinned proof programs with exact image identifiers and public journals.

## 10. Networking, RPC, faucet, and receipts

Authenticated consensus and protected-submission networking are distinct from public query RPC.
RPC status is live on Kanalen; proof-bearing owner-scoped Coin Cell discovery and several downstream
queries remain incomplete.

The faucet foundation has canonical terms/requests/receipts, durable idempotency, configurable
limits, proof-of-work escalation, and bounded formal admission proofs. It remains disabled publicly
until a pre-funded pool-owned Coin Cell transfer reaches real authenticated ingress and produces
finalized inclusion/state evidence. Wallets must never credit optimistic faucet balances.

A finalized result should identify network/genesis, protocol and verifier versions, transaction or
action, block height/hash, exact commitment, and inclusion/state/finality evidence sufficient for
offline verification.

## 11. Formal verification and release truth

Formal methods are scoped claims, not a certificate for the whole system. Each critical path needs:

1. a canonical semantic specification;
2. bounded and malformed vectors;
3. executable implementation tests;
4. model or production-code proof harnesses;
5. refinement/conformance evidence joining model to implementation;
6. explicit cryptographic, compiler, filesystem, clock, platform, and operational assumptions;
7. independent review of a frozen release.

Open compositions include end-to-end agent key provenance, secure hardware custody, recovery
completion, multi-device convergence, native multi-asset tokenization, credential-to-ZK-to-APL
refinement, faucet-to-finalized-cash binding, complete ObjectVM packages, and production finality.

## 12. Current status legend

- **Implemented** means code and local tests exist; it does not imply deployment or audit.
- **Deployed developmental** means exercised on Kanalen without a production-security claim.
- **Formally checked slice** means only the published theorem/harness scope and assumptions.
- **Planned** means architecture or issue text exists but the end-to-end feature does not.
- **Production ready** requires all release gates and independent audit; ActiveChain is not there.

## 13. Open decisions

- Agent controller-key profile and hardware-attestation requirements by connection kind.
- Safe multi-device agent control without turning an exported seed into ambient authority.
- Recovery completion, challenge/cancellation, and threshold/social/organizational profiles.
- Whether agent action sessions use dedicated derived signing keys or capability-bound controller
  signatures in each protocol profile.
- Human-readable APL syntax, compiler, translation validation, and policy migration UX.
- ObjectVM package/call/upgrade semantics and supported source-language toolchains.
- Credential circuit registry, proof aggregation, correlation budgets, and verifier governance.
- Multi-asset Coin Cell and issuer/controller registry schemas.
- Trustworthy privacy-preserving Sybil provenance at the public faucet gateway.

## 14. Implementer checklist

Before adding an integration, answer:

1. Which principal acts, and which key role authenticates it?
2. Who controls and can rotate/recover that key?
3. What exact capability authorizes the action, and how is it revoked?
4. Which policy and verified facts are evaluated?
5. What private data is disclosed, committed, or proven?
6. What chain, state, nonce, audience, purpose, budget, and expiry are bound?
7. Which VM or proof boundary executes the logic?
8. What is persisted locally, transported, placed on-chain, and returned in the receipt?
9. How do replay, compromise, crash, reordering, and upgrade fail?
10. Which tests, formal claims, assumptions, and independent reviews support the result?

## 15. Normative and detailed references

- `spec/protocol/P-020-principal-lifecycle.md`
- `spec/protocol/P-022-capabilities.md`
- `spec/protocol/P-023-authorization-policy-language.md`
- `spec/protocol/P-050-object-vm.md`
- `spec/protocol/P-090-native-money.md`
- `spec/protocol/P-111-post-quantum-zero-knowledge.md`
- `docs/wallet-agent-management.md`
- `docs/mobile-wallet.md`
- `docs/implementation/vc-proof-pipeline.md`
- `docs/implementation/browser-agent-primitives.md`
- `docs/SECURITY_AUDIT.md`
