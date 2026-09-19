# Emerald on Actum

Status: new integration track  
Tracking: #859

## Purpose

This track makes Actum an alternative substrate for **Emerald** without turning Amber into a competing product and without pretending that application-level equivalence requires cloning Aztec.

Amber remains the ActiveChain-native reference imageboard and a source of reusable implementation, proof, wallet, moderation, and network components. Emerald remains an independent protocol/product. Any compatibility claim must be tied to an explicit compatibility matrix and tested outcome-level guarantees.

## Invariants

1. **Emerald identity is preserved.** User-facing Emerald deployments remain Emerald.
2. **Substrate choice is explicit.** An Emerald deployment identifies its substrate profile and the security/finality/privacy assumptions that follow.
3. **Equivalent outcomes, not identical internals.** Actum does not need Aztec wire formats, Noir contracts, PXE APIs, Ethereum Fee Juice, or identical commitments unless Emerald explicitly depends on them.
4. **No anonymity regression for convenience.** Posting, reporting, fee payment, bonds, claims, RPC admission, ordering, receipts, logs, and wallet recovery are part of the privacy transcript.
5. **Moderation and anonymity are independent requirements.** Moderation must not require public poster/reporter identity.
6. **Implemented and target guarantees remain separate.** Existing Amber/ActiveChain components may be reused only with their current assurance boundaries.

## EOA-M0: compatibility and unlinkable private state

The first technical blocker is the current private-billboard proof statement. Today a post exposes a successor commitment in its public inputs while the following proof journal exposes the consumed prior permit commitment. Consecutive uses can therefore disclose a direct predecessor/successor equality even though the permit witness itself is private.

The replacement relation MUST prove, without revealing the consumed permit commitment:

- membership of an eligible permit commitment in an accepted application commitment root;
- authorization to consume that permit;
- a correctly derived one-shot nullifier;
- the exact permitted successor private state;
- value conservation across fee, bond/escrow, change, refund/reward and successor notes;
- chain, application, policy revision, target state root and validity-window binding;
- bounded cooldown/rate-limit and moderation-dependent state transitions where applicable.

The public statement SHOULD expose only what consensus and the Emerald application require: accepted root(s), nullifier(s), new commitment(s), exact public application effects, policy/revision bindings, and proof-profile identifiers.

Deleting the current journal field alone is not a fix. Validators need a sound hidden-membership relation. The normative v2 target is now frozen in [`spec/protocol/P-EMERALD-POST-V2.md`](../../spec/protocol/P-EMERALD-POST-V2.md): root-bound hidden membership, one-shot nullification, exact successor/economic effects, and a public journal containing only the v2 domain, public-input commitment, and nullifier.

### M0 regression baseline

The branch now contains `legacy_billboard_post_transcript_links_consecutive_permits` in
`crates/pq-zk/src/lib.rs`. It constructs two valid consecutive v1 posts and demonstrates the
privacy defect directly: the first post's public `successor_commitment` equals the second proof's
publicly journaled consumed `permit_commitment`.

This is a characterization/regression test for the legacy v1 statement, not an acceptance of that
statement. The replacement relation must make this equality unavailable to a public transcript
observer while preserving membership, authorization, nullifier, successor-state, policy and
conservation checks inside the proof.

## Claims and exits

Emerald-on-Actum SHOULD settle refunds, rewards and residual bonds into private notes. A later public Actum withdrawal MAY be supported as an explicit user choice and MUST be presented as a possible correlation boundary.

## Moderation

Emerald's moderation architecture is preserved as the application semantic baseline. The Actum adapter supplies authenticated state transitions, scoped authority/capabilities, private report bonds and settlement primitives; it does not redefine Emerald's policy by default.

Qualification MUST cover:

- report admission without reporter identity disclosure;
- urgent restriction/hiding semantics separately from irreversible economic settlement;
- ordinary adjudication, review/appeal and terminal outcomes as specified by the selected Emerald revision;
- stale/conflicting/replayed decisions;
- provider/cache behavior after a canonical restriction/removal;
- availability/custody obligations after removal so honest operators are not punished for policy compliance;
- harmless synthetic fixtures for abuse-handling tests.

No test requires possession or redistribution of illegal abusive material.

## Availability and custody

Ledger DA is not automatically Emerald content availability. The adapter MUST map Emerald's off-chain blob commitment, pre-activation availability threshold, post-vote custody obligation, challenge randomness, response proof and penalty semantics onto Actum components or preserve Emerald's own mechanism behind an adapter.

The mapping must distinguish:

- existing Actum DA primitives;
- application-specific availability certificates;
- operator epochs and stake;
- unpredictable challenge selection;
- shard/blob response verification;
- slashing/exclusion;
- retention and terminal removal semantics.

## Compatibility matrix

M0 will freeze a matrix for at least:

- anonymous posting;
- anonymous reporting;
- private fee/bond funding;
- private claim/refund/reward;
- bounded canonical board state;
- content commitment and retrieval;
- availability activation;
- custody challenges;
- moderation decisions and appeals;
- pruning/slot reuse;
- restart/recovery;
- provider exit;
- observer/linkability model;
- finality and settlement assumptions.

Each row is classified as **equivalent**, **different but acceptable**, **missing**, or **out of scope**, with executable evidence where available.

## Differential conformance

The track will define substrate-neutral lifecycle vectors. Given equivalent initial state and actions, Emerald/Aztec and Emerald/Actum should agree on the semantic outcome defined by the compatibility matrix: board visibility/order, moderation state, bond/claim rights and terminal economics.

The test does not require identical hashes, proof bytes, block numbers or substrate-specific receipts.

## Claim ladder

1. **Design track** — compatibility matrix and replacement relations specified.
2. **Private lifecycle prototype** — unlinkable private post/report/claim relations execute with real proofs.
3. **Emerald/Actum testnet profile** — complete board, content, moderation, availability/custody and recovery operate across independent nodes.
4. **Compatibility candidate** — differential lifecycle suite and adversarial privacy/network tests pass.
5. **Audited deployment profile** — independent review and remediation apply to the exact release revision.

Until the relevant gate is met, do not describe Actum as a drop-in Aztec replacement or claim complete Emerald compatibility.
