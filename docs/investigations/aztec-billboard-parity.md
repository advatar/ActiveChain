# Aztec billboard parity on ActiveChain

- Investigation issue: [#17](https://github.com/advatar/ActiveChain/issues/17)
- ActiveChain baseline: `56d2f6345e9bb6add4dab4da2cdd2292a7d7dd28`
- Aztec experiment baseline: `1849967d15d96ab96234091f2fa47d8762a6c06a`
- Date: 2026-07-21

## Verdict

The billboard can be built as an ActiveChain application, but it cannot currently be built with
all of the Aztec demo's security and privacy properties. A public, non-anonymous prototype can be
built from today's object, policy, capability, state-tree, ObjectVM, cash, consensus, DA, wallet,
and indexer foundations. The defining property—unlinkable posts backed by a private deposit and a
privately updated rate-limit state—is blocked on the Phase 4 shielded asset/private-object proof
system and private action admission described in `BLUEPRINT.md` but not implemented in the
workspace.

Full parity is therefore feasible as a planned protocol vertical slice, not as an application-only
change. It should not be described as anonymous or parity-complete until the privacy circuits,
nullifier rules, shielded fee path, proving/wallet integration, and transcript-level unlinkability
tests have shipped and been audited.

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
- **Blocked**: a missing consensus-critical or cryptographic primitive prevents an honest parity
  claim.

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
| Public sender anonymity | Blocked | `ActionEnvelope` version 1 contains a public `sender`, and construction requires every command actor to be that public principal. Pairwise pseudonyms and private actors are blueprint items, not an admission path. |
| Unlinkable ownership and post chains | Blocked | `ObjectOwner::Shielded` is currently a commitment-shaped reserved owner mode; there is no membership/ownership/nullifier proof verifier or encrypted private-object transition path. |
| Private deposit amount and cooldown | Blocked | The blueprint specifies shielded notes, but the cash kernel and action kernel do not implement shield/unshield proofs, encrypted notes, private values, or a private rate-limit state transition. |
| Anonymous fee payment | Blocked | Public envelopes expose the sender and fee ticket. A shielded or sponsored/relayed fee path that cannot relink posts is required. |
| Exact ETH deposit and withdrawal | Blocked | ActiveChain has native cash conservation work but no audited Ethereum light client/bridge, inbox/outbox, relayer economics, or finality/reorg policy. The blueprint says no external bridges initially. |
| Native-token escrow and redemption | Prototype | An ActiveChain-native locked deposit can preserve “stake is recoverable and cannot be withdrawn twice,” but application escrow, authorization, and redemption transitions are not present. Privacy still depends on shielded assets. |
| Selective private wallet discovery | Blocked | No PXE-equivalent note discovery, encrypted note delivery, nullifier tracking, scoped viewing capability implementation, backup/recovery, or multi-device synchronization exists. |
| Formal parity evidence | Blocked | ActiveChain has Lean/Tamarin component models, but no billboard model, circuit refinement proof, end-to-end trace conformance, or independent review. The source's partial models cannot prove a different implementation. |

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

1. Finish the shielded-note/nullifier specification and proof public-input statement.
2. Implement note commitments, encrypted note delivery, membership and nullifier trees, proof
   verification, and atomic shielded state updates.
3. Add private action admission, anonymous authorization, fee sponsorship/shielding, and wallet note
   discovery/recovery.
4. Prove permit conservation, one-successor state evolution, replay resistance, cooldown safety,
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

Proceed with Stage 0 only if it is explicitly presented as a public semantics prototype. Treat the
billboard as a concrete Phase 4 driver for private actions and shielded objects, because it exercises
identity hiding, private mutable state, anonymous fees, public outputs, moderation lookups, and
eventual redemption in one bounded application. Defer an Ethereum bridge until the native shielded
flow is correct; it adds substantial trust and reorg risk without resolving the core privacy gap.

## Validation performed

- `cargo fmt --all -- --check`: passed.
- `cargo test --workspace --all-targets`: passed.
- Aztec source `censor-daemon/run_tests.sh`: passed (23 moderation unit tests and 14 daemon
  integration tests).
- The Aztec/Noir and local-network suites were not rerun because the `aztec` CLI is not installed in
  this environment. Their README coverage counts are treated as source claims, not fresh results.
