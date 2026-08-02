# ACTS — a unified concept design for verifiable act provenance

This document unifies three threads:

- **MadeMark/AuditFinder** (`../MadeMark`): a shipping local-first provenance recorder — per-root
  append-only feeds of hash-chained signed events, signed checkpoints, an independent witness
  service, sealed portable evidence dossiers (`.mmevidence`), transparent STARK/FRI policy proofs,
  conservative multi-party merges that preserve conflicts, and signed release ceremonies.
- **MM2ACTUM.md**: the analysis of what Actum should adopt from MadeMark's epistemology — and what
  it must not absorb into consensus.
- **Actum/ActiveChain**: the settlement and verification substrate — PQ-only principals with
  rotation/recovery, issuer-signed credentials with explicit assurance classes, attenuated
  capabilities, deterministic APL policy evaluation, canonical intents, witnessed accumulators,
  and finality receipts.

The organizing shift: MadeMark proves the **history of a file**; Actum proves the **finality of a
transaction**. The unified system proves the **history of an act** — every consequential state
transition becomes explainable, attributable, and independently verifiable. That is the substrate
AI agents, autonomous workflows, and regulated processes actually need: trustworthy execution
histories, not merely trustworthy documents or trustworthy ledger entries.

## 1. The defining abstraction

> A **verifiable act** is a canonical claim that an authenticated principal, acting under
> specified authority and policy, transformed committed inputs into declared effects, with
> independently checkable evidence linking intent, authorization, execution, and finality.

Neither system alone provides this. MadeMark can say *what happened around an artifact and who
signed the history*, but its identity model is local and self-declared. Actum can say *what
finalized and under which authority*, but a receipt answers "what executed", not "why". The act
record joins them.

## 2. Asymmetric strengths — who teaches whom

| Capability | MadeMark has | Actum has | Unified direction |
|---|---|---|---|
| Identity, keys, recovery | local self-declared directory | protocol principals, rotation, recovery | MadeMark **adopts** Actum principals |
| Credential assurance | — | issuer classes, EUDI ladder, no silent upgrade | Actum model applies to *all* evidence, not just identity |
| History representation | hash-chained signed feeds, stable event IDs, checkpoints | ordered transactions | Actum **adopts** feed/checkpoint semantics for act graphs |
| Portable verification | sealed `.mmevidence` dossiers, offline verifier, no-account verification | proof-bearing RPC | Act Bundle v1 generalizes the dossier |
| Multi-party truth | independently signed participant feeds, explicit conflict records | consensus ordering | conflicts stay signed branches; consensus orders, never rewrites |
| Policy proof | STARK/FRI policy proofs over local history | deterministic APL decisions, PQ-ZK profile | one policy-proof discipline, two deployment points |
| Approval semantics | approvals as evidence-bearing events | wallet HITL approval transcripts | approval becomes its own act binding the exact presented action |
| Finality | external witness/anchor | consensus finality receipts | Actum is the anchor of last resort; witnesses remain distinct |

The flow of adoption runs both ways, but never wholesale: each side takes the other's *discipline*,
not its *schemas*.

## 3. Unified architecture — five planes

```
┌────────────────────────────────────────────────────────────┐
│ 5. Domain profiles                                         │
│    AI-agent action · payment · release · clinical decision │
├────────────────────────────────────────────────────────────┤
│ 4. Offline verifier                                        │
│    structured assurance vector, no account required        │
├────────────────────────────────────────────────────────────┤
│ 3. Actum consensus core (anchor + settlement)              │
│    act commitment · authority · policy commitment ·        │
│    effects · receipt · finality                            │
├────────────────────────────────────────────────────────────┤
│ 2. Act provenance protocol (canonical, off-consensus)      │
│    ActRecordV1 · causal graph · epistemic types ·          │
│    approvals · agent manifests · Act Bundle v1             │
├────────────────────────────────────────────────────────────┤
│ 1. Local-first recorders (MadeMark and successors)         │
│    append-only signed feeds · checkpoints · witnesses ·    │
│    evidence adapters · selective disclosure                │
└────────────────────────────────────────────────────────────┘
```

High-volume local observation stays local (plane 1). Only signed checkpoints, selective proofs,
and consequential transitions ascend. Consensus (plane 3) receives commitments and effects, never
raw logs, prompts, or private reasoning. This is MM2ACTUM's hierarchy made structural:

```
local observations → signed checkpoints → selective proofs/approvals
                   → consequential Actum action → finalized receipt
```

## 4. Core object model (plane 2)

**ActRecordV1** — act ID; actor principal; acting device/application/agent; authority and
capability chain; declared, interpreted, and authorized intent; policy and policy decision;
input/prior-state commitments; approvals; computation/model execution manifest; resulting
effects; supporting evidence; parent and caused acts; finalization receipt.

**Causal edges** (what turns a list into provenance): `requestedBy`, `interpretedFrom`,
`authorizedBy`, `approvedBy`, `evaluatedUnder`, `executedBy`, `produced`, `supersedes`,
`compensatesFor`, `dependsOn`.

**Epistemic types** — every assertion is typed: *fact* (protocol-verified), *attestation*
(issuer-signed), *observation* (device/oracle/witness), *declaration* (self-claimed), *inference*
(software/model-derived), *decision* (policy output), *effect* (finalized transition). Evidence
never silently upgrades its type. This is MadeMark's conservatism applied system-wide.

**Assurance vector** — the verifier returns structured conclusions per dimension (actor
authentication, human identity, agent identity, model identity, policy execution, human approval,
execution finality, intent fidelity), never one green badge.

**Intent transformation chain** — expressed → interpreted → authorized → executed, with each
transformation preserved. The system proves what was expressed, how software interpreted it, what
was presented for approval, what was authorized, and what executed. It never claims to prove
internal mental intention.

**Act Bundle v1** — the portable, offline-verifiable package: act records, principal states,
credential presentations, capability chains, policy commitments and evaluation receipts, I/O
commitments, approvals, execution receipts, inclusion/state/finality proofs, revocation status,
verifier version requirements. Direct generalization of MadeMark's `.mmevidence` dossier: sealed
resources, exact candidate binding, hostile-input rejection, verification without the
originating application or any account.

## 5. Concrete component mapping

| MadeMark mechanism (shipping today) | Unified role |
|---|---|
| Per-root hash-chained signed event feeds | per-context act feeds (events → acts concerning state) |
| Signed feed checkpoints | act-graph checkpoints; digest anchored into Actum |
| Independent witness service | witness observation — kept distinct from author signature and consensus finality (three-way separation) |
| `.mmevidence` sealed dossier + standalone validator | Act Bundle v1 format + offline verifier |
| STARK/FRI policy proofs over history | policy-result proofs over act graphs (shares Actum's PQ-ZK transparent-proof profile: no trusted setup, no EC dependency) |
| Conservative two-parent merges / conflict records | multi-party act feeds with preserved, attributable disagreement |
| Evidence adapters (Mail/Messages, C2PA sidecars) | interop profiles: C2PA → transformation evidence, VC/EUDI → actor assurance, in-toto/SLSA → supply-chain evidence, SCITT → transparency, OTel → operational observation |
| Signed release-tag ceremony + release dossier | the "software release" domain profile — already a working vertical slice of act provenance |
| MCP read/query server | act-graph query surface for AI tools (read-only, assurance-typed results) |

What stays out of the unified core, per MM2ACTUM: filesystem paths, local self-declared identity,
free-form detail maps, application action enums, raw workflow logs, C2PA parsing in consensus,
model prompts and private reasoning, and any universal ontology of human action.

## 6. Consensus boundary discipline

Only plane-3 primitives that multiple unrelated domain profiles independently require may
graduate into consensus, and each graduation carries the full canonical-encoding, boundedness,
compatibility, formal-modeling, migration, and audit obligations. The consensus core stays
minimal: act commitment, actor/authority, policy commitment, input-state commitment, declared
effects, execution result, receipt, optional parent-provenance commitment. An Actum finalization
proves a commitment entered finalized state — it does not promote the off-chain claims inside
that commitment to truth. Verifier language must preserve this ("this bundle existed in this
form, signed by these principals, containing these attestations"), never "everything inside is
true".

## 7. Delivery plan

1. **Specify Act Bundle v1 and ActRecordV1** off-chain: canonical encodings, epistemic typing,
   causal edges, assurance vector, bounded sizes, frozen vectors, malformed-input rejection.
   No consensus change.
2. **MadeMark emits and verifies Act Bundles.** Map feed events + checkpoints + dossier into the
   bundle format behind an adapter; MadeMark adopts Actum principals/credentials for new
   enrollments while keeping its local directory for legacy feeds.
3. **Actum anchors and verifies.** Add digest anchoring for act-feed checkpoints and an offline
   verifier that returns the assurance vector; expose read-only act-graph queries via the
   existing MCP surface.
4. **One end-to-end vertical slice** (MM2ACTUM's recommended first move): human request → agent
   interpretation → capability check → APL decision → exact human approval → Actum cash action →
   finalized effect → portable bundle. Use a real testnet payment with an externally issued
   identity credential; make every assurance boundary visible in the verifier output.
5. **Domain profiles** from proven need: AI-agent action and software release first (the latter
   already exists in MadeMark's release ceremony), then payment/mortgage/clinical as partners
   materialize.
6. **Promotion review**: after two unrelated profiles ship, evaluate which bundle fields have
   earned consensus-core status.

The slice in step 4 is the demonstration that matters: identity, intent, delegation, policy, AI
agency, execution, and finality in one independently verifiable artifact. The product question
stops being "is this object authentic?" and becomes "what caused this state to exist, who had
authority to cause it, what evidence and policy justified it — and can I verify the answer after
the originating application is gone?"
