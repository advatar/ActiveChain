# Amber: ActiveChain private imageboard specification

Status: engineering target; not yet implemented in full  
Tracking: [GitHub issue #53](https://github.com/advatar/ActiveChain/issues/53)  
Benchmark: [*Emerald: A Decentralized Imageboard Protocol*](https://alex.sellstrom.me/papers/Emerald.pdf), April 29, 2026

**Product naming:** ActiveChain's native private-imageboard application and protocol profile are
called **Amber**. Emerald is an independent research benchmark only. User-facing applications,
network identifiers, schemas, and public claims MUST use Amber naming and MUST NOT imply Emerald
compatibility, endorsement, or shared implementation.

## 1. Purpose and interpretation

This specification defines what ActiveChain must build before its private billboard can credibly
claim the same level of *system ambition* as Emerald. It does not require source compatibility,
Aztec contracts, ETH bonds, BLAKE3 identifiers, JPEG XL, KZG commitments, Symbiotic Relay, or any
other Emerald-specific implementation choice.

Ambition parity means that a user and an adversary encounter comparable outcome-level properties:

1. anonymous bonded posting and reporting at the public-ledger boundary;
2. one globally consistent, bounded active-board view;
3. exact off-chain content bound to compact ordered state;
4. stake-backed availability before content becomes live;
5. punishable custody obligations after positive availability votes;
6. economically coherent spam, report, moderation, refund, and reward paths;
7. practical retrieval without granting a service provider authority over board state;
8. explicit privacy limits covering fees, timing, networking, wallets, and content; and
9. independently reproducible security, performance, and recovery evidence.

ActiveChain SHOULD exceed the benchmark where its native architecture permits it, particularly in
post-quantum cryptography, atomic private-native-asset accounting, deterministic object access,
formal refinement evidence, and validator-enforced canonical transitions. It MUST NOT describe a
prototype component as satisfying the whole-system goal.

The terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

## 2. Benchmark boundary

Emerald's central architectural goal is anonymous, ephemeral, bounded-state discussion with
globally consistent ordering and moderation state, off-chain media, and economically backed data
availability. Its paper explicitly leaves moderation selection, custody sampling and slashing,
peer-discovery bootstrapping, service-node payment, exact content schema, and some claim mechanics
open. ActiveChain ambition parity therefore does not mean reproducing unresolved choices. It means
closing them—or documenting an equally explicit, safe launch boundary—within an independent design.

| Outcome | Emerald ambition | ActiveChain target |
|---|---|---|
| Public identity | No poster or reporter address in public records | Senderless actions; no principal, fee ticket, stable pseudonym, or claim owner in board records |
| Active state | Fixed reusable thread slots and capped threads | Bounded board object with reusable slots, stable generations, capped posts and reports |
| Content | Exact off-chain blob named by a compact hash | Canonical versioned blob named by a SHAKE256/384 commitment and erasure-layout root |
| Inclusion | Stake-weighted availability gate | Epoch-bound ML-DSA availability certificate before ordered activation |
| Custody | Unpredictable post-vote challenges and penalties | Consensus-random sampled shard challenges with objective response verification and native slashing |
| Bonds | Anonymous post/report escrow and private claims | Shielded native-token bond notes, one-shot nullifiers, write-once terminal entitlements |
| Moderation | Durable report keys and authorized final outcome | Capability-scoped policy with a separately specified adjudicator set, quorum, appeal, and emergency path |
| Access | Swarms plus optional paid service nodes | Board/shard swarms, verifiable content, multi-provider discovery, self-hosting, optional private metering |
| Cryptography | Aztec private execution; KZG discussed for DA | Pinned transparent PQ-ZK profile, ML-DSA authentication, hash/Merkle/FRI-compatible DA proofs |
| Assurance | Security model with explicit open problems | Executable spec, formal models, differential tests, network rehearsals, reproducible benchmarks, external audit |

## 3. Non-goals

The first conforming release does not need an unbounded social graph, persistent user profiles,
follows, reactions, private messages, permanent archival, arbitrary user-created boards, a token
bridge, or compatibility with Emerald state. It does not promise protection against self-identifying
content, a compromised client, a global passive network adversary, endpoint compromise, traffic
analysis outside the specified transport profile, or cryptographic breaks.

## 4. Roles and trust boundaries

The protocol MUST define these roles independently even when one operator performs several:

- **Poster** creates a private bonded submission and retains private claim material.
- **Reporter** creates a private bonded accusation against one stable post/rule tuple.
- **Reader** derives board state and verifies retrieved content without trusting a gateway.
- **Validator** orders canonical actions, verifies PQ proofs and certificates, and advances state.
- **Content node** stores and serves selected board/shard blobs without deciding canonical state.
- **Availability operator** signs retrievability attestations and accepts sampled custody liability.
- **Adjudicator** resolves reports under a board policy but cannot rewrite unrelated state.
- **Service provider** offers indexed retrieval and optional paid access without consensus authority.
- **Wallet/client** constructs proofs, discovers notes, normalizes fee and network behavior, and
  verifies chain, content, and policy evidence.

No content node, service provider, relayer, availability operator, or adjudicator acting alone MAY
make a pending post live, alter its canonical number, fabricate a claim, or redefine board history.

## 5. Canonical identifiers and commitments

All fields MUST have bounded canonical encodings and domain-separated commitments. The frozen
schema MUST include at least:

- `BoardId = H(chain_id, board_config_commitment)`;
- `ThreadId = (board_id, monotonically increasing thread_number)`;
- `SlotRef = (board_id, slot_index, slot_generation)`;
- `PostId = (board_id, thread_number, post_number)` plus a random public anti-correlation nonce;
- `ReportId = (post_id, rule_id, policy_revision)`;
- `BlobId = H(blob_profile, exact_blob_bytes)`;
- `LayoutRoot = MerkleRoot(encoding_profile, indexed shard commitments)`;
- `SubmissionId = H(board, target, blob_id, layout_root, bond_commitment, randomizer)`;
- `AvailabilityId = H(submission_id, operator_epoch, deadline)`; and
- domain-separated nullifiers for post, report, refund, reward, appeal, and withdrawal paths.

`slot_index` MUST NOT be a durable thread identity. Slot reuse MUST increment a generation and
assign a never-reused thread number. Old posts, reports, terminal outcomes, and claims MUST remain
unambiguous after reuse.

## 6. Bounded public state

Each board configuration MUST freeze maximum active threads, posts per thread, report references
per live thread, blob bytes, attachment count, rules, pending submissions, pending reports, and
challenge windows. Every transition MUST have statically bounded reads, writes, proof bytes, and
execution cost.

The minimum public state is:

- `BoardConfig`: limits, bond schedule, bump policy, content/DA profiles, policy commitment,
  adjudication profile, fee class, retention window, and upgrade rules;
- `ThreadSlot`: slot generation, stable thread number, creation/bump heights, post count, active
  report-reference count, state, and terminal marker for the prior generation;
- `PendingSubmission`: exact target, blob/layout commitments, availability epoch/deadline, and
  bond amount commitment without poster identity;
- `PostRecord`: stable post key, blob/layout commitments, activation height, lifecycle state,
  policy revision, and terminal entitlement commitments without author identity;
- `ReportRecord`: stable post/rule key, lifecycle state, policy revision, and terminal entitlement
  commitments without reporter identity;
- `ReportRef`: a dense, bounded live-thread index into stable report records;
- `AvailabilityCertificate`: epoch, operator-set root, yes-stake, total stake, signer-set root,
  deadline, and exact submission commitment;
- `CustodyChallenge`: unpredictable sample commitment, operator, response deadline, and result;
- write-once `ThreadTerminal`, `PostOutcome`, `ReportOutcome`, and `ClaimEntitlement` facts; and
- consumed nullifier sets and current commitment roots.

Live board reconstruction MUST require only bounded canonical state plus referenced blobs. Durable
terminal facts MAY be accumulated in authenticated state trees, but their keys and proofs MUST be
bounded and independently verifiable.

## 7. Canonical content profile

The initial content profile MUST specify exact bytes, not an interpreted object. It MUST define:

- a versioned envelope with MIME/profile identifier, UTF-8 text bounds, attachment descriptors,
  declared dimensions and lengths, and exact payload bytes;
- canonical rejection of duplicate fields, ambiguous normalization, trailing bytes, decompression
  bombs, oversized dimensions, malformed metadata, and unsupported codecs;
- a domain-separated content commitment and deterministic test vectors;
- an erasure coding profile with `k` data and `m` parity shards, indexed shard commitments, a
  layout root, reconstruction rules, and maximum expansion ratio;
- verified preview behavior: a client MUST NOT render unverified bytes as canonical content; and
- explicit retention: live blobs carry availability obligations, while pruned blobs MAY expire
  after the configured claim/challenge window.

The first profile MAY use a conservative image format plus separately encoded text instead of
Emerald's proposed JPEG XL metadata. Format selection MUST be based on decoder safety, browser and
mobile support, deterministic validation, progressive delivery needs, and auditability. A future
format requires a versioned protocol upgrade.

## 8. Private bonded action protocol

### 8.1 Post submission

A post proof MUST establish, without revealing the poster:

1. ownership and one-shot consumption of a valid shielded native-token permit;
2. sufficient unlocked value for the post bond and normalized fee class;
3. membership of the target live thread generation, or valid deterministic slot replacement for a
   new thread;
4. compliance with cooldown, saved-capacity, size, policy revision, and expiry rules;
5. binding to the exact `BlobId`, `LayoutRoot`, content profile, target, and randomizer;
6. correct successor permit, bond-note, claim-note, and change commitments;
7. distinct domain-bound nullifiers; and
8. equality of private debits and public escrow/fee effects.

Admission creates `PendingSubmission`; it MUST NOT immediately increment the live post count or
assign a final post number. Failure MUST atomically revert private notes, nullifiers, fees, escrow,
and public state.

### 8.2 Availability activation

Only a valid availability certificate received before expiry MAY activate a pending submission.
Activation MUST recheck the target generation. If it remains live, activation atomically assigns
the next post number, advances bump metadata under the frozen policy, inserts the post, and removes
the pending entry. If the target was pruned or replaced, the submission MUST enter a deterministic
non-penalized terminal refund path rather than attach to the replacement thread.

### 8.3 Reporting

A report proof MUST anonymously lock the configured report bond and bind a claim note to one exact
`ReportId`. The public transition MUST prove the post exists under the stable thread number, is
reportable, and has no report for the same rule and policy revision. It MUST append one bounded
`ReportRef` only while the thread is live.

### 8.4 Claims and withdrawals

Claims MUST use private authorization notes, write-once public entitlement amounts, and one-shot
nullifiers. No public claim record may contain the claimant address. Refund, residual bond, reward,
and forfeiture paths MUST be mutually exclusive and value conserving. Withdrawal MAY produce a
public native Coin Cell; operational guidance MUST warn that doing so can correlate the claimant.

## 9. Availability and custody protocol

### 9.1 Operator epochs

Availability operators MUST be selected from epoch-bound staked identities with an authenticated
operator-set root, weights, service endpoints, supported profiles, and slashable native stake.
Operator authentication MUST use an approved PQ signature suite. Set activation and retirement
MUST be finalized by consensus and protected from stale-certificate reuse.

### 9.2 Positive availability certificate

Before signing yes, an operator MUST retrieve enough committed shards to reconstruct the exact
blob, verify `BlobId` and `LayoutRoot`, and advertise the configured serving obligation. A compact
certificate MUST bind submission, blob, layout, board/shard, operator epoch, decision deadline,
signer-set root, yes stake, and total stake. Activation requires a frozen strict threshold and MUST
reject duplicate signers, unknown operators, overflow, stale epochs, substituted layouts, and
certificates formed after expiry.

The aggregation format MUST preserve post-quantum security. A classical BLS or KZG dependency MUST
NOT be introduced into the conforming PQ profile. Initial certificates MAY carry a bounded canonical
ML-DSA signer set; later compression requires a separately reviewed PQ construction.

### 9.3 Custody challenges

Challenge randomness MUST be unpredictable until positive voting closes and MUST derive from
finalized consensus randomness plus the availability ID and operator identity. Sampling MUST be
unbiased within a quantified bound and select both operators and shard/chunk positions.

A response MUST provide the exact sampled bytes and an authentication path to `LayoutRoot`, or a
transparent PQ proof of equivalent knowledge. It MUST bind operator, epoch, challenge, position,
and deadline. Validators MUST deterministically verify success, lateness, malformed paths, replay,
and substitution.

The economic parameters MUST satisfy a published inequality under the threat model: expected loss
from lazy yes-voting exceeds its maximum saved retrieval/storage cost plus attainable reward. A
failed response MUST cause objective slashing and temporary exclusion; repeated or correlated
failures SHOULD escalate. Challenges MUST be rate bounded so attackers cannot exhaust honest
operators.

### 9.4 Availability safety boundary

The protocol guarantees a stake-backed, time-bounded retrievability claim—not permanent archival.
The spec MUST quantify the assumed honest/available stake, reconstruction threshold, sampling
probability, challenge frequency, response window, network delay, and residual probability of a
live blob becoming unrecoverable.

## 10. Content distribution and service access

Content nodes MUST be able to join selected board or shard swarms, discover multiple independent
peers, request indexed shards/blobs, resume transfers, verify every returned unit, and reconstruct
live content. The network MUST support at least two bootstrap mechanisms with no single mandatory
gateway. A client MUST be able to switch providers or run a node without changing canonical state.

The reader API MUST return finalized board proofs, post records, provider candidates, and content
proofs. Service providers MAY offer indexing, previews, and paid bandwidth, but clients MUST verify
state and content locally. Payment SHOULD be off-chain or amortized, use a normalized privacy
profile, and avoid a unique on-chain event per read. Non-service proofs are not required for the
first release; provider diversity, verifiable bytes, and exit are required.

A fresh client MUST reconstruct the complete live board from a finalized checkpoint plus bounded
state proofs, discover all live blob commitments, fetch from multiple providers, and recover wallet
notes from its viewing material without having observed historical events live.

## 11. Moderation and governance

The protocol MUST freeze a board rule registry and policy revision. An adjudication specification
MUST define:

- eligibility and selection of adjudicators;
- capability scope by board, rule, action, amount, and validity height;
- quorum and conflict-of-interest rules;
- private or public evidence handling and what is deliberately not put on-chain;
- decision deadline, abstention, unavailable quorum, and orphaned-report behavior;
- appeal count, appeal authority, supersession, and finality;
- emergency removal powers, transparency log, expiry, and retrospective review;
- collusion, bribery, capture, censorship, and compromised-key assumptions; and
- governance for policy changes without retroactively altering settled claims.

An upheld report MUST delete or hide the post in canonical board state, return the report bond,
award only the configured portion of the post bond, and create the poster's residual entitlement.
A rejected report MUST preserve the post and deterministically forfeit or route the report bond.
A thread pruned before judgment MUST return the base report bond without a violation reward. Every
report finalizes at most once, and no later report may extract another penalty from a deleted post.

Moderation authority SHOULD use ActiveChain capability attenuation and APL forbid precedence, but
those mechanisms do not themselves solve adjudicator selection or collusion. Launch claims MUST
name the chosen trust model.

## 12. Economics and conservation

The native-token accounting specification MUST define all sources, sinks, escrow accounts, reward
limits, rounding, overflow behavior, and terminal cases. For every accepted trace:

`inputs + minted_rewards = outputs + fees + burned_or_slashed_value + live_escrow`.

No transition may mint a reporter reward independently of the offending bond or an explicitly
governed reward pool. A report cannot claim more than one penalty. A post bond cannot be withdrawn
before all applicable terminal conditions. Expired pending submissions, unavailable blobs, pruned
threads, rejected reports, upheld reports, appeals, operator failures, and governance shutdown MUST
each have a total, non-blocking settlement rule.

Parameter selection MUST publish spam-cost, honest-user-cost, false-report, lazy-DA, and griefing
simulations across native-token price ranges. Governance MUST use bounded rate changes and delayed
activation so existing notes remain settleable.

## 13. Privacy specification

### 13.1 Required ledger privacy

Public post, report, availability, moderation, and claim state MUST contain no poster or reporter
principal, address, authorization key, stable user pseudonym, public fee ticket, bond owner, or
linkable change identifier. Proof journals MUST reveal only the minimum canonical transition
statement. Nullifiers for different purposes MUST be domain separated and computationally
unlinkable absent the witness.

The prover/verifier path MUST use the pinned transparent PQ-ZK profile, disable development
receipts, bind the guest image and journal exactly, and reject alternate receipt kinds. Complete
post, report, activation, claim, and withdrawal relations—not merely a preimage demo—must execute
inside pinned guest images.

### 13.2 Operational privacy

The official client MUST define a uniform fee class, transaction envelope size buckets, batching
window, retry behavior, relay selection, content-upload path, proof-generation fingerprint policy,
and wallet note-discovery behavior. At least one deployable privacy transport profile MUST separate
the user's network address from both validators and first-hop content operators. Cover traffic or
mixing MAY be staged, but the absence and resulting correlation risk MUST be explicit.

The privacy analysis MUST cover chain observers, validators, relays, content peers, availability
operators, service providers, adjudicators, wallet infrastructure, compromised endpoints, and
colluding subsets. It MUST state visible fields, linkability, retained logs, timing resolution,
active attacks, and user mitigations. No claim stronger than the analyzed observer model is allowed.

## 14. Security properties

At minimum, the implementation and evidence MUST address:

- **Safety:** canonical clients never disagree on finalized thread order, numbering, deletion, or
  report outcome at the same finalized height.
- **Boundedness:** no valid trace exceeds configured live slots, posts, reports, pending items,
  proof sizes, state accesses, or arithmetic bounds.
- **Generation separation:** actions and claims for an old slot generation cannot affect its reuse.
- **Authorization privacy:** valid public traces do not require a public poster/reporter identity.
- **Sound admission:** no post activates without a valid private action and availability certificate.
- **DA accountability:** a false or lazy positive vote creates quantifiable slash risk under the
  sampling assumptions.
- **Conservation:** all bonds, fees, rewards, refunds, residuals, and slashes balance atomically.
- **One-shot settlement:** each nullifier, entitlement, report decision, and penalty is consumed or
  initialized at most once.
- **Moderation isolation:** authority for one board/rule cannot affect another scope.
- **Atomicity:** failed proofs, stale targets, unavailable content, and partial subsystem failures
  publish no inconsistent state or private notes.
- **Recovery:** validator, content node, and wallet restart cannot erase locks, replay guards,
  obligations, claim rights, or finalized board state.
- **Censorship escape:** no single service or content provider is necessary to derive state and
  retrieve an otherwise available live blob.
- **Upgrade safety:** revisions cannot reinterpret old identifiers, proofs, bonds, or claims.

## 15. Formal verification and refinement obligations

The formal program MUST model the whole bounded lifecycle, not only isolated arithmetic. Required
artifacts are:

1. Lean definitions and proofs for canonical state transitions, bounds, slot-generation separation,
   conservation, mutually exclusive outcomes, one-shot claims, and deterministic numbering;
2. Tamarin models for anonymous action authorization, replay/nullifier resistance, note delivery,
   fee-path linkability assumptions, availability certificates, custody challenge freshness,
   adjudication authorization, and recovery;
3. TLA+ or an equivalent temporal model for pending-to-live activation, two-chain finality,
   concurrent prune/report/availability races, appeals, operator epoch changes, and liveness under
   stated quorum assumptions;
4. bounded model checks of canonical decoders, proof journals, FFI/verifier boundaries, arithmetic,
   and maximum object-access manifests;
5. differential tests proving the Rust reference transition and every PQ-ZK guest relation agree
   on accepted outputs and typed failures; and
6. trace-conformance tests replaying generated model traces against production Rust.

The evidence index MUST distinguish theorem assumptions, executable code, refinement links,
trusted computing base, unverified dependencies, and externally audited components. Formal results
MUST NOT be advertised as a proof that the zkVM, compiler, cryptographic primitives, operating
system, network, or implementation is bug-free.

## 16. Test and rehearsal gates

A conforming release requires deterministic unit/property/fuzz tests plus multi-process rehearsals
covering:

- maximum-capacity slot reuse and stable-key claims;
- simultaneous post, prune, report, appeal, and availability expiry races;
- malformed, substituted, replayed, stale, oversized, and cross-chain proofs/certificates;
- withheld blobs, corrupt shards, insufficient reconstruction, dishonest yes votes, missed and
  replayed challenges, epoch rollover, and slashing;
- duplicate reports, conflicting decisions, adjudicator loss, compromised capabilities, and
  emergency-action expiry;
- wallet restart, multi-device synchronization, note rollback/reorg, duplicate delivery, and
  withdrawal correlation warnings;
- validator crash/restart, partitions, delayed finality, snapshot restore, and upgrade activation;
- content-node churn, bootstrap failure, provider censorship, partial shards, and fresh-client sync;
- exact economic conservation under every terminal branch; and
- privacy regression snapshots that enumerate every public field and network endpoint.

At least one public adversarial testnet MUST run long enough to include multiple operator epochs,
board saturation/pruning cycles, custody samples, report appeals, wallet recoveries, and deliberate
provider failures.

## 17. Performance and usability acceptance criteria

Before implementation begins, maintainers MUST freeze a reproducible benchmark environment and
numeric service-level objectives. The initial targets SHOULD include:

- bounded proof generation on a documented consumer laptop and supported phone-class device;
- verifier cost small enough to sustain the target block load with explicit worst-case proof bytes;
- pending-to-live latency measured at p50/p95/p99 under the finalized DA threshold;
- first board render and progressive/thumbnail render latency from a cold client;
- successful reconstruction at the configured maximum tolerated missing shards;
- fresh-client state sync without replaying unbounded history;
- wallet recovery and note discovery across the retention horizon;
- maximum board-state proof size independent of historical post count; and
- quantified operator bandwidth, storage, challenge load, and honest-user bond/fee cost.

Results MUST include hardware, software revisions, dataset, network conditions, failures, and raw
machine-readable output. A single warm local run is not a product performance claim.

## 18. Audit and launch gates

The public production claim requires independent review of:

- all PQ-ZK guest relations, journals, image pinning, host verification, and trusted dependencies;
- canonical content and state codecs;
- private note, nullifier, fee, escrow, claim, and wallet recovery flows;
- availability certificate construction, sampling, shard proofs, and slashing economics;
- moderation capabilities, adjudication and appeal state machines;
- networking/privacy threat model and logging defaults;
- formal models, refinement evidence, and claimed coverage; and
- reproducible builds, dependency provenance, release signing, and incident response.

Critical/high findings MUST be fixed and retested. The report, scope, revision, exclusions, and
residual risks MUST be public. Until then, every public description MUST say “prototype” or
“third-party audit pending,” as applicable.

## 19. Implementation milestones

### M0 — Freeze requirements and adversary model

- Resolve content profile, board limits, observer model, DA assumptions, adjudication trust model,
  economics, upgrade policy, and numeric performance targets.
- Publish canonical schemas, transition tables, threat matrix, and test vectors.

Exit: independent design review finds no undefined terminal state or unbounded input.

### M1 — Complete private application relations

- Move post, report, terminal claim, and withdrawal relations into pinned PQ-ZK guests.
- Add production commitment trees, wallet witnesses, multi-device discovery, normalized fees, and
  atomic public adapters.

Exit: differential tests cover every reference branch; real proofs pass substitution, replay,
malformed-journal, and restart tests.

### M2 — Bounded board lifecycle

- Implement boards, reusable thread slots, stable generations/numbers, pending submissions,
  report references, prune markers, terminal outcomes, and upgrade-safe state proofs.

Exit: saturation and concurrency rehearsals preserve all Section 14 safety properties.

### M3 — Content network

- Freeze canonical blobs and erasure layout; implement authenticated board/shard swarms,
  multi-source retrieval, verified previews, provider discovery, and fresh-client sync.

Exit: clients reconstruct and verify live boards through churn with no mandatory gateway.

### M4 — Stake-backed DA and custody

- Implement operator epochs, ML-DSA availability certificates, activation gate, consensus-random
  challenges, Merkle shard responses, slashing/exclusion, metrics, and economic simulations.

Exit: adversarial testnet demonstrates quantified availability and catches deliberately lazy voters.

### M5 — Moderation and claims

- Freeze adjudicator selection, scoped capabilities, report evidence, decisions, appeal/emergency
  paths, bond outcomes, and private claims.

Exit: collusion/failure assumptions are explicit and every outcome conserves value and finalizes once.

### M6 — Product privacy and usability

- Ship official wallet/client, privacy transport, normalized submission/fee behavior, provider exit,
  recovery, accessibility, moderation views, and operator tools.

Exit: usability/performance SLOs and operational privacy tests pass on supported devices.

### M7 — Assurance and launch

- Complete formal artifacts and refinement evidence, public testnet, audit, remediation, reproducible
  release, monitoring, incident response, and governance ceremony.

Exit: the audited revision meets every mandatory acceptance criterion and publishes residual risks.

## 20. Current gap assessment

The current `activechain-private-billboard` vertical slice already demonstrates native shielding,
encrypted permit discovery, senderless protected actions, bounded cooldown/penalty semantics,
nullifier and successor admission, atomic fees/escrow, restart recovery, moderation-dependent
withdrawal, and adversarial lifecycle tests. ActiveChain PQ-ZK v1 supplies a pinned transparent
hash-based proving profile and initial formal application evidence. The DA crate supplies bounded
Reed-Solomon encoding, SHAKE commitments, deterministic sampling, reconstruction, and tamper tests.

Those are foundations, not ambition parity. The principal missing deliverables are:

- complete billboard relations inside real pinned PQ-ZK guests;
- production commitment trees, witnesses, wallet synchronization, and privacy transport;
- multi-board reusable thread lifecycle with stable identifiers and report enumeration;
- pending submission and stake-certified activation;
- a production content schema and multi-provider swarm;
- operator epochs, compact PQ certificates, unpredictable custody challenges, and slashing;
- a resolved moderation/adjudication and appeal model;
- complete anonymous bond/report/reward/refund economics;
- fresh-client reconstruction and paid-provider exit;
- whole-lifecycle formal refinement, performance evidence, adversarial testnet, and external audit.

## 21. Honest public claim ladder

Public language MUST follow the highest completed gate:

1. **Reference vertical slice:** executable private lifecycle; reference verifier may see witnesses.
2. **PQ-ZK application prototype:** complete relations use real pinned proofs; audit pending.
3. **Networked private billboard testnet:** bounded board, content network, DA/custody, moderation,
   wallet, and recovery run across independent nodes; economics and audit still experimental.
4. **Emerald-ambition protocol candidate:** all M0–M6 gates and whole-system evidence are public;
   external audit may still be pending.
5. **Audited production candidate:** M7 audit and remediation apply to the exact release revision.

“On par with Emerald's ambitions” is appropriate only at level 4 or 5 and MUST link to this matrix,
benchmark results, formal-evidence scope, audit status, and residual-risk statement.
