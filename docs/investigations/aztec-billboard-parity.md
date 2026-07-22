# Aztec billboard parity on ActiveChain — Phase 4 reassessment

- Original investigation: [#17](https://github.com/advatar/ActiveChain/issues/17)
- Reassessment issue: [#24](https://github.com/advatar/ActiveChain/issues/24)
- Original ActiveChain baseline: `56d2f6345e9bb6add4dab4da2cdd2292a7d7dd28`
- Reassessment ActiveChain baseline: `47109c6c9dbe91dca203304917c4c58c940722f2`
- Aztec experiment baseline: `1849967d15d96ab96234091f2fa47d8762a6c06a`
- Original assessment: 2026-07-21
- Reassessment: 2026-07-22

## Verdict

The verdict has improved from “privacy primitives unimplemented” to “privacy statement and state
foundations implemented, end-to-end privacy still unimplemented.” A public billboard prototype
remains possible. ActiveChain now also has bounded canonical shielded notes, nullifiers, viewing
capabilities, domain pseudonyms, shielded-transfer inputs, private-object transition and disclosure
statements, atomic shield/unshield accounting, and protected-ordering transport and persistence.
Those are concrete reusable Phase 4 foundations rather than blueprint-only designs.

They do not yet make the billboard anonymous. The privacy kernel explicitly implements no proof
system and makes no privacy claim. Its admission APIs accept a caller-produced
`VerifiedPrivacyProof { verified: bool, ... }`; there is no configured circuit/prover/verifier
that establishes note ownership, membership, conservation, billboard cooldown, screening, or
successor-state correctness. The general public action envelope still contains a public sender and
fee ticket, and wallet code has no encrypted-note discovery, spend construction, nullifier
tracking, backup, or recovery flow. Protected ordering hides payloads before ordering but does not
hide persistent state or replace the public action admission path.

Full parity therefore remains a protocol-and-application vertical slice, but it can now build on
implemented canonical boundaries and atomic accounting instead of starting from specifications.
The largest remaining blockers are real proof verification and circuits, private action/fee
admission, encrypted note delivery and wallet synchronization, billboard-specific transitions and
clients, end-to-end integration, privacy measurement, and independent audit.

“Same properties” should mean equivalent externally observable guarantees on ActiveChain. It
should not require copying Aztec-specific L1 inbox/outbox, Noir note APIs, Ethereum Fee Juice, or
PXE internals. ActiveChain-native value escrow and redemption can preserve the economic invariant.
Exact ETH round trips would additionally require an audited Ethereum bridge, which ActiveChain
explicitly excludes from its initial scope.

## Source property baseline

The experiment combines the following into one demo:

1. A public append-only message feed whose post call exposes neither an Aztec sender address nor a
   public link between a user's posts.
2. A public Ethereum deposit which becomes a private L2 note. The deposit amount determines a
   private cooldown: `base_cooldown * minimum_deposit / amount`.
3. A bounded save-up rule allowing limited bursts without changing the long-run post rate.
4. Constant-cost screening of at most two linked post notes per post, a censor window, dummy posts
   to finish screening, and withdrawal only after every real post is screened.
5. A transferable censor role, public flag records and responses, an on-chain text policy, hidden-by-
   default flagged posts, and a `K-1` cooldown penalty for each screened flag.
6. Deposit/claim/post/withdraw/claim flows across an Ethereum portal and Aztec, plus deployer, user,
   censor, CLI, and fee-funding applications.
7. A local-LLM moderation daemon that reads the public policy/feed and invokes the censor CLI.
8. Noir tests, local-network integration checks, daemon tests, a security review, and partial Lean /
   Verity models.

The source security material is evidence, not a completed audit. `SECURITY_PROPERTIES.md` records
review provenance at source commit `086abfc...`, while this investigation targets `1849967...`.
The current README also lists end-to-end proof stubs and untested browser paths. Those claims must
be revalidated rather than imported as assumptions.

## Property-by-property mapping

Status meanings:

- **Now**: an existing executable ActiveChain primitive directly supports the property.
- **Prototype**: the behavior can be demonstrated publicly with bounded application work, but not
  with complete source privacy/security parity.
- **Foundation**: reusable executable privacy/state machinery now exists, but a missing proof,
  admission, wallet, or application integration prevents the property itself.
- **Blocked**: no current ActiveChain path can honestly provide the property.

| Property | Status | ActiveChain mapping and gap |
|---|---|---|
| Canonical bounded data and deterministic commitments | Now | Canonical codec, typed objects, SHAKE256/384 domain separation, state witnesses, and bounded decoding are implemented. |
| Atomic state transitions and replay rejection | Now | Versioned objects, exact access manifests, action nonces, one-shot fee tickets, receipts, and atomic transfer semantics are implemented. |
| PQ validator authentication, finality, and DA | Now | The current runtime has ML-DSA-bound validator flows, quorum certificates, persistent snapshots, and erasure-coded DA. This is stronger than the demo's stated platform baseline, subject to ActiveChain's open launch-gate proofs. |
| Public append-only feed | Prototype | A shared object plus versioned post objects/public values can represent a feed, but the current action payload is a typed transfer and ObjectVM is a small scalar interpreter; arbitrary package-governed mutation is not yet wired end to end. |
| Transferable censor authority | Prototype | Capabilities and attenuation plus APL forbid precedence provide the right authority model. Billboard-specific flag, transfer, and policy transitions still need implementation. |
| Public moderation policy and flag responses | Prototype | Bounded object public values can store these. Schema, size limits, canonical text encoding, history, and application queries are missing. |
| Hidden-by-default flagged-post UX | Prototype | This is an indexer/client presentation rule and can be built once the feed schema and query API exist. It is not censorship at consensus or DA level; flagged content remains retrievable. |
| Local-LLM moderation daemon | Prototype | The daemon pattern is portable and should remain outside consensus. It needs an ActiveChain query/submit adapter, scoped censor capability handling, durable cursoring, and adversarial-output tests. |
| Deposit-proportional cooldown arithmetic | Prototype | Checked `u128` arithmetic and deterministic execution can express the formula. ActiveChain currently lacks a billboard transition and a normative consensus-time source for an exact posts-per-hour statement; a height/slot-based rule is safer until time semantics are specified. |
| Save-up, censor-window, dummy-post, screening, and penalty state machine | Prototype | These are deterministic bounded transitions and do not inherently require privacy. The link/state schemas, access sets, transition execution, and model proofs are absent. |
| Public sender anonymity | Foundation | Domain pseudonym statements and encrypted protected submissions now exist. They do not replace `ActionEnvelope` version 1, which still publishes `sender` and `fee_ticket`, and no proof-backed private actor admission path invokes them. |
| Unlinkable ownership and post chains | Foundation | Canonical shielded notes, nullifier openings/sets, private-object transition statements, disclosure capabilities, and atomic replay checks now exist. There is still no proof system, membership tree verifier, encrypted private-object store, or billboard successor transition wired into finalized execution. |
| Private deposit amount and cooldown | Foundation | The cash ledger now atomically shields/unshields native value, persists a bounded pool/nullifier state, conserves supply, and rejects replay. It trusts preverified evidence, has no encrypted note delivery, and does not prove or execute the billboard's private amount/cooldown state machine. |
| Anonymous fee payment | Foundation | Shielded public inputs and shield/unshield intents account for fees, and protected ordering can conceal a submission before ordering. The production action path still exposes a sender and fee ticket; no relayed, sponsored, or shielded-fee private action is admitted end to end. |
| Exact ETH deposit and withdrawal | Blocked | ActiveChain has native cash conservation work but no audited Ethereum light client/bridge, inbox/outbox, relayer economics, or finality/reorg policy. The blueprint says no external bridges initially. |
| Native-token escrow and redemption | Foundation | Atomic shield/unshield transitions now conserve native supply, bind exact public inputs, and reject spent nullifiers. Billboard escrow/terminal-screening authorization is absent, and proof soundness is delegated to a verifier that is not implemented. |
| Selective private wallet discovery | Blocked | A canonical scoped `ViewingCapability` exists, but there is still no encrypted note delivery, trial decryption, witness maintenance, spend construction, nullifier tracking, backup/recovery, or multi-device synchronization in wallet code. |
| Pre-order payload confidentiality and ordering fairness | Foundation | ML-KEM protected submissions, bounded committees, post-lock ordering, forced inclusion, public-lane isolation, authenticated messages, threshold shares, builder bonds, and crash-atomic persistence are implemented. This reduces mempool leakage but does not itself provide sender, state, fee, timing, or network unlinkability. |
| Formal parity evidence | Blocked | ActiveChain has component models and executable malformed-input/replay tests, but no billboard model, privacy circuit, circuit-to-Rust refinement, end-to-end trace conformance, transcript linkability study, or independent review. The source's partial models cannot prove a different implementation. |

## Phase 4 delta since the original assessment

The following original blockers have moved into executable foundation work:

- Shielded note commitments, one-shot nullifier derivation, bounded persistent nullifier state, and
  deterministic privacy vectors are implemented in `activechain-privacy-kernel`.
- Public-to-shielded and shielded-to-public native-cash transitions are atomic, supply conserving,
  fee accounting, anchor bound, expiry bound, and replay rejecting.
- Private-object transitions bind pre/post roots, object class, authorization, policy, program,
  access manifest, disclosure root, and expiry into an exact public statement.
- Scoped viewing and disclosure capabilities plus domain pseudonym and private-credential
  statements are canonical and fail closed at their statement boundary.
- Protected ordering includes bounded encrypted submissions, committee configuration, lock-before-
  order rules, forced inclusion, public-lane isolation, threshold decryption-share transport,
  authenticated peer messages, builder bond settlement, and crash-atomic restart state.

The following original blockers remain:

- The repository has no privacy circuit implementation, proving stack, or cryptographic verifier.
  A boolean preverification result is a trust boundary, not proof-system evidence.
- No consensus action variant atomically combines a private-object/billboard transition, shielded
  fee payment, nullifier update, public post output, and finalized state-root update.
- No encrypted-note ciphertext format, note commitment tree/witness service, recipient discovery,
  wallet prover, recovery protocol, or multi-device synchronization exists.
- No billboard package, schemas, ObjectVM transition, indexer/API, CLI/web/mobile flow, or censor
  daemon adapter exists.
- No traffic-analysis defense or evidence shows that sender, fee payer, deposit, post chain,
  network origin, timing, and withdrawal are unlinkable.
- Exact ETH deposit/withdrawal still requires a separately specified and audited Ethereum bridge.

## ActiveChain-native design

### Public objects

- `BillboardConfig`: immutable minimum stake, cooldown unit, maximum save-up, penalty multiplier,
  screening window, post-size limit, and package/revision identifiers.
- `ModerationAuthority`: capability-controlled object holding the current censor capability and
  canonical transfer history.
- `ModerationPolicy`: versioned shared object containing bounded UTF-8 policy bytes.
- `Post`: immutable public content, consensus slot/height, and a public random post identifier. It
  contains no principal, deposit, fee payer, cooldown, or chain-link identifier.
- `ModerationDecision`: immutable flag, response, policy version, censor-capability authorization,
  and target post identifier.

Indexers derive the feed and flagged view from immutable objects/events. Clients hide flagged
content by default, while raw data remains available and DA-verifiable.

### Private state

A shielded `BillboardPermit` replaces the Aztec `DepositNote`:

```text
BillboardPermit {
    asset_id,
    amount,
    refund_commitment,
    next_allowed_slot,
    chain_head_commitment,
    last_screened_commitment,
    last_real_post_commitment,
    policy_revision,
    randomness
}
```

Its commitment is public; its plaintext is encrypted to scoped viewing keys. A post proof consumes
one permit nullifier and creates exactly one successor permit commitment. Public outputs contain
only the post and the commitments/nullifier required by consensus. The proof establishes:

- ownership authorization without revealing a principal;
- membership and non-spend of the old permit;
- input/output amount conservation;
- correct slot-based cooldown and bounded save-up calculation;
- correct child/grandchild link openings and screening-window eligibility;
- correct lookup of finalized moderation decisions;
- exact flag penalty and successor state;
- correct real or dummy post behavior;
- binding to chain ID, application/package revision, config object version, state root, and action
  validity window.

A withdrawal proof consumes the permit, proves the terminal screening condition, and creates a
shielded native coin for the refund commitment. No value is minted. A separate, future Ethereum
bridge may redeem to ETH, but is not part of billboard privacy correctness.

### Submission and metadata

Private posting requires a new private-action envelope whose actor and payload are commitments,
plus a verifier-recognized proof statement. Fees must be shielded, capability-sponsored, or paid by
a relay in a way that does not identify the permit owner. Fixed size classes, batching, delayed
release, and privacy relays are needed to avoid turning cryptographic anonymity into trivial network
linkability. The anonymity claim must state which of sender, deposit, fee payer, IP address, timing,
and withdrawal are hidden; these are distinct properties in the blueprint.

### Time semantics

Use consensus slots or heights for the first implementation. “One post per hour” should be stated
as a bound over a protocol-defined slot duration and tested across missed/late slots. Wall-clock
timestamps should only be used after consensus specifies their validity bounds, monotonicity, and
behavior under reconfiguration. Arithmetic must be checked before narrowing and must reject zero
parameters.

## Implementation sequence

### Stage 0 — public semantics prototype

1. Specify canonical billboard config, post, policy, authority, and decision schemas.
2. Add billboard state transitions with checked arithmetic and exact object access manifests.
3. Add an ActiveChain-native escrow/redemption transition using transparent ownership.
4. Build CLI/indexer support and port the moderation daemon adapter.
5. Add unit, property, differential-model, restart, reorg/finality, and multi-validator tests.

This stage validates application semantics only. Every UI must label posts and deposits public and
linkable.

### Stage 1 — shielded permit vertical slice

Phase 4 has completed the generic note/nullifier encodings, shielded-cash accounting, private-object
public statement, scoped disclosure statement, and protected-ordering foundation. The remaining
vertical slice is:

1. Define the billboard circuit statement as a specialization of the current shielded-transfer and
   private-object statements, including config/policy revisions, post public output, cooldown,
   bounded save-up, screening, penalties, and terminal withdrawal.
2. Select and integrate a proof system, implement the circuit and verifier, and replace
   caller-asserted `VerifiedPrivacyProof` construction at every network boundary.
3. Add a commitment tree and witness API plus encrypted note delivery, wallet discovery, proving,
   nullifier tracking, backup, and recovery.
4. Add private action admission that commits atomically to the proof, permit nullifier/successor,
   shielded fee, public post/decision reads, and finalized pre/post roots.
5. Prove permit conservation, one-successor state evolution, replay resistance, cooldown safety,
   screening correctness, withdrawal liveness bounds, and no double redemption.

### Stage 2 — privacy and production UX

1. Add relays, fixed-size padded submissions, scoped viewing capabilities, multi-device recovery,
   and privacy-preserving observability.
2. Build user/censor web or mobile flows, moderation-policy warnings, and explicit censored-content
   controls.
3. Run transcript linkability experiments and adversarial traffic-analysis simulations.
4. Obtain independent circuit, wallet, cryptography, and application audits.

### Stage 3 — optional Ethereum bridge

Specify and audit Ethereum header/finality verification, deposits, withdrawals, message inclusion
and non-consumption, reorg handling, relayers, emergency controls, accounting, and bridge-specific
privacy leakage. Do not make bridge availability a precondition for native escrow withdrawal.

## Required acceptance gates

Full parity requires all of the following, not merely a working UI:

- Every real post is retrievable from finalized state; dummy posts reveal no content.
- Stake conservation and refund correctness hold across failures, replay, restart, and concurrent
  actions; a permit cannot post or withdraw twice.
- For amount `minimum * n`, the protocol-defined long-run rate is at most `n` base units per
  cooldown interval, including split deposits, save-up bursts, and withdraw/redeposit attempts.
- Screening work is constant and bounded; flags inside the window are included exactly once; the
  penalty is exact; an honest user can eventually withdraw after censorship stops.
- Only the current censor capability can flag, set policy, or transfer authority; old capabilities
  and stale policy revisions fail.
- Public action, proof, fee, object, indexer, and network transcripts do not contain a stable user or
  deposit identifier. Same-user and different-user post transcript distributions are tested under
  the stated cryptographic assumptions.
- Malformed proofs, nullifiers, commitments, encrypted notes, oversized messages/policies, stale
  roots, wrong chain/revision, and arithmetic boundaries fail closed.
- Wallet backup/recovery neither loses spendability nor enables double use, and scoped viewing does
  not become a universal decryption key.
- Rust execution, the circuit/model, and canonical fixtures pass differential conformance checks;
  the full workspace, multi-node rehearsal, and independent security review pass.

## Recommendation

Proceed with Stage 0 if it is explicitly presented as a public semantics prototype. In parallel,
use the billboard as the first proof-backed Phase 4 application profile: the new generic kernel is
strong enough to define its canonical public statement and atomic ledger boundary, while the
billboard forces completion of the still-missing proof, private action, shielded fee, note-delivery,
wallet, and transcript-privacy paths. Do not market the generic Phase 4 foundation or protected
ordering as anonymous billboard parity.

The most valuable next milestone is one end-to-end native-token lifecycle on a local multi-validator
network: shield a public coin into an encrypted permit, discover it in a wallet, submit one proved
post through the protected lane without a public principal/fee link, update the permit/nullifier and
publish the post atomically, then prove terminal withdrawal and recover native value after restart.
That is a sharper readiness gate than adding more standalone statement types.

Defer an Ethereum bridge until this native shielded lifecycle is correct and independently reviewed;
a bridge adds a separate consensus, accounting, reorg, relayer, and privacy threat model without
closing the current proof or wallet gaps.

## Validation performed

Original investigation validation on 2026-07-21:

- `cargo fmt --all -- --check`: passed.
- `cargo test --workspace --all-targets`: passed.
- Aztec source `censor-daemon/run_tests.sh`: passed (23 moderation unit tests and 14 daemon
  integration tests).

Phase 4 reassessment validation on 2026-07-22:

- Static evidence review covered the privacy kernel, shielded cash integration, protected ordering,
  authenticated network messages, threshold encryption, builder settlement, persistence, action
  envelope, wallet code, current status, and the Phase 4 commit series merged by PR #19.
- `cargo fmt --all -- --check`: passed.
- `cargo test -p activechain-privacy-kernel -p activechain-cash-kernel -p activechain-consensus-runtime`:
  passed (23 privacy, 17 current cash, and 30 consensus-runtime tests; the targeted suites were
  rerun across the baseline update).
- `cargo test --workspace --all-targets`: passed.
- The Aztec/Noir and local-network suites were not rerun because this reassessment changes only the
  ActiveChain baseline; their prior coverage remains source evidence rather than fresh validation.
