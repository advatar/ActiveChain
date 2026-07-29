# TODO — concept-level blockers

Scope: unresolved **design and strategy** contradictions, not implementation work. Feature
progress is tracked in `STATUS.md`; remaining feature surface is summarised in `GAPS.md`.

Each item below is blocking in the specific sense that other documents already depend on an answer
that has not been given, or give two incompatible answers. Nothing here is fixed by writing more
code.

---

## P0 — must be resolved before further protocol work compounds the problem

### 1. The economic model is currently two mutually exclusive designs — #313

**Contradiction.** `MINT.md`, `REWARDS.md`, and `DECENTRALIZATION.md` specify a permissionless
network secured by a native staked asset: bounded security issuance (`MINT.md` §5, §16), bonded
verifier roles with slashing (`REWARDS.md` §1, §9, §10), issuance funding baseline security
(`CASH.md` §10), and an explicit claim that "token distribution determines whether the design
succeeds" (`DECENTRALIZATION.md` §9).

`ANTISPECULATION.md` (deleted in `3dda60d`, recoverable from `098c784`) concludes the opposite: no
freely traded native token, stablecoin-collateralised validator bonds, identified professional
validators, non-transferable governance credentials, fees denominated in stablecoins.

These are not two configurations of one protocol. They are two networks with different security
sources, different validator admission rules, different decentralisation ceilings, and different
legal exposure.

**Why it blocks.** Who pays for security, in what asset, and who may validate determines the
staking model, the fee market, the reward accounting in `MINT.md` §3–4, the entire verifier economy
in `REWARDS.md`, the genesis scorecard in `DECENTRALIZATION.md` §1, and the regulatory posture in
`docs/audits/AUDITOR_ASSURANCE_PROTOCOL.md`. Every one of those documents is currently written
against an assumption the project has not actually made.

**Unpriced risk in the no-token branch.** Stablecoin-collateralised security makes the chain's
security budget a derivative of an off-chain issuer's solvency and freeze authority. That is a
larger capture and censorship vector than the prover concentration `DECENTRALIZATION.md` §3 spends
several pages on, and it is not analysed anywhere.

**Done when:** one branch is chosen and written up as a normative economics specification
(`P-130` or similar); `MINT.md`, `REWARDS.md`, `CASH.md` §10, and `DECENTRALIZATION.md` are
reconciled to it or explicitly marked as describing the rejected branch; the decentralisation
scorecard is recomputed for the chosen branch.

---

### 2. The v1.0 launch contract collapses the build order into a single release — #314

**No scope is being dropped. This item is about sequencing only.** Every feature in `BLUEPRINT.md`
§1.2 stays in the programme; the question is which protocol version makes it *mandatory*.

**Contradiction.** `BLUEPRINT.md` §1.1 sets a disciplined dependency-ordered build order.
`BLUEPRINT.md` §1.2 then requires nearly all of it at genesis simultaneously: PQ consensus,
capability delegation, APL, private credential presentation, shielded payments, mandatory execution
validity proofs, AI and general compute-job objects, multiple compute assurance tiers, protected
ordering, multidimensional fees plus state rent, and light clients.

That set is five to seven independent research programmes shipping in one release. Comparable
individual components have each absorbed a team-decade elsewhere: the shielded pool (Zcash), a PQ
proving VM (`PQVM.md`'s own Stwo-fork path), DA sampling (Celestia), the policy kernel (Cedar).
§1.2 therefore nullifies §1.1 — an ordered build order whose every stage is due on the same day is
not an order.

**Why it blocks.** A genesis contract that cannot be met either slips indefinitely or gets met
nominally, and the second outcome destroys the project's main asset — the refusal to overclaim
documented in `docs/ARCHITECTURE_GUIDE.md` §12 and the auditor protocol §2.

**Resolution already available in-repo.** `spec/protocol/P-000` §9 forbids reinterpreting bytes
accepted under an earlier tag and version, and §5 dispatches the transition function on an explicit
protocol version. Full scope can therefore ship across an ordered version series with no
compatibility damage and no feature abandoned — *provided the genesis encoding reserves the space
for it*.

**Proposed sequencing** (feature set unchanged; only the mandatory-at version moves):

| Version | Mandatory | Rationale |
|---|---|---|
| v1.0 | PQ state authorization, PQ consensus signatures, principals and recovery, capability attenuation, APL, ObjectVM, multidimensional fees and state rent, public lane, light clients, validator re-execution | The authorization kernel and object semantics — the parts that cannot be added later without reinterpreting authority |
| v1.1 | Mandatory execution validity proofs become consensus-required | Header field present and reserved from genesis; re-execution is authoritative until proofs are qualified, which §1.2 already contemplates |
| v1.2 | Private credential presentation, shielded payments and private objects | Note, viewing-capability, and nullifier boundaries already exist as reference types (`README.md`); reserve their tags at genesis |
| v1.3 | Protected transaction lane required rather than optional | §1.2 already marks it initially optional |
| v1.4 | Compute-job objects and assurance tiers | Depends on item 3's admission decision, not on genesis |
| v2 | Stateless active validators, external bridges | Already post-genesis in §1.2 |

**The hard requirement that makes this safe.** Deferral is only free if genesis reserves what later
versions will need: type tags, block-header fields, envelope extension points, and version-dispatch
seams for every deferred feature, plus deterministic negative vectors proving v1.0 clients reject
unknown tags cleanly rather than ignoring them. Without that, adding a deferred feature later forces
exactly the byte reinterpretation `P-000` §9 prohibits. This reservation work is itself a genesis
deliverable.

**Done when:** §1.2 is restated as a version series covering the full feature set; every deferred
feature has a reserved type tag, a reserved encoding slot, and a named target version; and the
genesis vector suite includes unknown-tag rejection cases for each reservation.

---

### 3. The AI and compute plane fails the project's own admission test — #315

**Contradiction.** `docs/ARCHITECTURE_GUIDE.md` §2 sets the bar: new first-class semantics must
justify canonical encoding, bounded evaluation, compatibility rules, deterministic vectors, formal
refinement, migration, and independent review — and anything that cannot belongs above consensus.

Capabilities, credentials, and assets pass that test explicitly. Compute jobs never have it applied.
`BLUEPRINT.md` §1.3 simultaneously rules out proving that an AI answer is true or beneficial, which
leaves unstated what base-layer job objects provide over escrowed attestation implemented as an
application.

**Done when:** either a written justification that survives the §2 test is added to the job
specification, or jobs are demoted out of the consensus surface and out of the genesis contract.

---

### 4. Mandatory validity proofs create an unanalysed liveness dependency — #316

**Gap.** `DECENTRALIZATION.md` §3 scores prover decentralisation 5.5 at genesis and argues correctly
that a non-authoritative supplier cannot corrupt validity. It does not address the separate
consequence: if every block requires a proof and proving is expensive, concentrated, and subject to
recursion economies of scale, then **liveness** depends on a small supplier set even though validity
does not.

Combined with item 2, `PQVM.md`'s purpose-specific PQ STARK VM plus `CashAIR` plus recursion is
plausibly the single largest engineering item in the plan, against a fast-moving external field.

**Done when:** the design states what happens when the prover market is unavailable, degraded, or
hostile — fallback to validator re-execution, a proving grace period, a liveness-only degraded mode,
or an explicit accepted dependency — and `DECENTRALIZATION.md` distinguishes validity concentration
from liveness concentration in the scorecard.

---

### 5. The strongest claim depends on a second client that current scope makes implausible — #317

**Tension.** Independent verification is rated top tier throughout (`DECENTRALIZATION.md` §2,
"Overall ranking"). That rating assumes independent implementations actually exist.
`spec/protocol/P-000` §4 requires that independent clients implement the specification rather than
importing the Rust transition function, and `BLUEPRINT.md` §2 forbids one team owning both a
normative spec and its only implementation. Meanwhile `DECENTRALIZATION.md` §3 concedes protocol
complexity is itself centralising and ranks social auditability below Bitcoin and Ethereum.

With all of §1.2 mandatory in one release, the cost of a conforming second client is very likely
prohibitive, which would silently downgrade the project's best property to a claim. Item 2's version
series helps directly: a second client tracks a v1.0 surface and grows with the series, rather than
having to implement seven planes before it can validate a single block.

**Done when:** a complexity budget exists — an explicit estimate of the conforming-client surface
per protocol version under item 2's sequencing, and a decision on whether the Go client is funded as
a v1.0 launch gate or as a fast-follow with a named version target.

---

## P1 — should be fixed, does not block protocol decisions

### 6. Strategy documents have not caught up to what the project is actually betting on

`docs/ARCHITECTURE_GUIDE.md` §4 (agents as independently authenticated principals holding
attenuated, budgeted, revocable capabilities, with the wallet never holding the agent secret) is the
most differentiated material in the corpus and the clearest case of something that genuinely needs
consensus-level semantics. It is presented as an integration detail.

Meanwhile the anti-speculation stance forgoes every conventional bootstrapping lever, which means
adoption has to come from specific counterparties rather than network effects.

**Done when:** the positioning material states the actual bet — provable validity, explicit
delegable authority for machine actors, private provable identity, PQ survivability — and names the
counterparties it is for, rather than leading with general-purpose L1 framing.

### 7. Removed business documents left a dangling contradiction

`3dda60d` removed `ACTIVECOIN.md`, `ANTISPECULATION.md`, and `REGULATION.md` from the repository,
but the positions they took still contradict `MINT.md` and `REWARDS.md`, which remain. Either the
economics decision from item 1 supersedes them, or their absence reads as the contradiction having
been resolved when it has not.

**Done when:** item 1 lands and this file records which branch won.

### 8. Compliance work is outpacing the permissionless core

`GAPS.md` shows the regulated profile substantially specified and partially implemented while
multi-asset transitions, issuer operations, faucet funding, and consensus qualification remain open.
The auditor protocol §2 draws the boundaries between permissionless base layer and regulated
operator correctly, so this is a resourcing signal rather than a design fault — but sustained, it
converts the project into a compliance platform with a permissionless story attached.

**Done when:** the sequencing is deliberate and stated, rather than emergent.
