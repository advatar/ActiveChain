# Operator surfaces build plan v1

Detailed build plan for the three operator surfaces, structured so that none of
it competes with making the testnet fully usable. Companion to
[OPERATOR_SURFACES_PLAN_V1.md](OPERATOR_SURFACES_PLAN_V1.md), which establishes
what already exists.

The organising principle: **Track 0 owns the testnet and the release train.
Tracks A–C may not touch either without an explicit, scheduled handover.**

---

## Track 0 — testnet fully usable (protected)

"Fully usable" means an outside developer can, unaided: install the wallet,
create it, get funded, see a verified balance, **spend**, and integrate against
a stable RPC — while an operator can keep it running without hand-surgery.

Two structural ceilings block that today. Both are the same root cause as the
faucet incident, and neither is a UI problem.

### 0.1 A wallet with one Coin Cell cannot spend — **blocker** ([#799](https://github.com/advatar/ActiveChain/issues/799))

`CoinTransfer` refuses a fee reserve that is also an input, so spending needs
at least two cells. A transfer creates exactly one recipient cell, so one grant
delivers one cell. With `RECIPIENT_COOLDOWN=86400` and `RECIPIENT_LIMIT=3`, a
new integrator waits **24 hours between grants and cannot transact at all until
the second one**, then falls back to one cell after their first spend.

Pinned by `a_sender_of_n_cells_can_make_exactly_n_minus_one_ordinary_transfers`.

Options, to be decided:

- **(a)** Faucet issues two transfers per grant — two treasury cells per
  recipient, no kernel change, halves treasury runway.
- **(b)** Kernel allows multiple recipient outputs in one transfer — the
  general fix; touches consensus, AIR, and proofs. Not a testnet-timescale
  change.
- **(c)** A self-split operation available to any holder — needs the same
  multi-output capability as (b).

Recommendation: **(a) now**, behind faucet policy, with (b) evaluated under
[#799](https://github.com/advatar/ActiveChain/issues/799) as the durable answer.

**(a) is only safe as one grant, not two fire-and-forget transfers.** If
transfer A finalizes and B does not, the recipient holds a single cell they
still cannot spend, while the faucet may consider the grant delivered and start
a cooldown — reintroducing exactly the partial-settlement class just removed
from the reservation path. Freeze the semantics first:

```text
FaucetGrantSettlementV1
  success  = every recipient cell finalized
  partial  = not success, and still reconcilable
  cooldown = begins only on complete grant settlement
```

Preferably both transfers ride one consensus operation or batch. Where that
cannot be guaranteed, the durable faucet state machine tracks **both**
transaction ids and reconciles partial completion through the existing recovery
path, which already replays what was authorized and refuses to close what it
cannot establish.

### 0.2 The chain caps at ~130 Coin Cells in total — **fixed** ([#800](https://github.com/advatar/ActiveChain/issues/800))

`activechain-rpc-ingest` publishes **every cell in the finalized cash snapshot**
as an index record carrying its own copy of the finality bundle. Measured at
32,260 bytes per record against `RpcIndex::MAX_ENCODED_LEN` of 4 MiB, that is
about 130 records **chain-wide, across all owners**. The chain currently holds
96. Exceeding it does not degrade: the round fails with `Invalid` and the index
stops publishing entirely.

This is a hard ceiling on how many wallets and cells the testnet can host, and
integrators will reach it quickly.

Options:

- **(a)** Stop republishing the finality bundle per record; carry one shared
  proof per index page and reference it. Attacks the 32 KiB rather than the
  4 MiB, so it is the larger win.
- **(b)** Raise `MAX_RPC_FRAME` — buys a small multiple and moves the wall
  without removing it. Rejected as a standalone answer.
- **(c)** Paginate the durable index so no single frame must hold every record.

Recommendation: **(a) and (c) together** — one snapshot/checkpoint proof per
page, with bounded paginated records beneath it. Deduplication solves today's
size explosion; pagination supplies a structural bound so the next global
ceiling is not rediscovered later at a larger scale.

**Status: fixed, and it needed no schema revision.** The 4 MiB bound was always
on the *stored* snapshot, while responses are separately capped at four records
per page — so this was a persistence change with no wire impact and no client
rebuild. Records now reference a shared finality table, and the index is stored
as a header chunk plus bounded page chunks, each encoded independently. An index
written before pagination still loads and is rewritten paged on the next
publication, so a node upgrading does not crash-loop on the file it already has.
The plannable treasury moves from 110 cells to 4,304, and what bounds it now is
an operational budget on memory and round time rather than a frame.

### 0.3 Faucet source limit collides with shared egress

Abuse identity is derived from the peer address, so an entire office behind one
NAT shares `SOURCE_LIMIT=5` per hour. Confirmed during the rehearsal. Needs a
policy decision before external integrators arrive: raise the limit, or admit a
per-recipient challenge that does not key on network position.

### 0.5 The wallet can only ever see one network — **fixed** ([#801](https://github.com/advatar/ActiveChain/issues/801))

`WalletKanalen` fixes host, chain id, and genesis as compile-time constants, so
a rebuilt chain currently requires a source change and a new build — as it did
three times in one day during the faucet work. Once several testnets run in
parallel this stops being an inconvenience and becomes a wall: a developer
cannot point the wallet at their own network at all.

The change is a wallet-side network registry: a selected network, a list of
known ones, each carrying host, chain id, and genesis, with the current
constants as the built-in default. The existing superseded-profile path already
handles the consequence correctly — a wallet bound to a genesis the chain does
not report is detected and offered a replacement — so the identity model needs
no change, only the source of the pin.

Two properties must survive: the pin stays a *pin* (a wallet still refuses a
chain it was not bound to, rather than following whatever a server claims), and
per-network wallets stay separate, since a key provisioned for one network's
genesis has no meaning on another.

This belongs to Track 0 because it is also what lets integrators use the
testnet at all, but it is the same work Track A needs, so build it once.

**Status: built.** `WalletNetwork` carries the pin and `WalletNetworkRegistry`
holds the known networks and the selection. Both properties are enforced and
tested: an unconfigured wallet still falls back to the built-in pin rather than
accepting whichever chain answers first, and the custody slot and profile
account are scoped per network so a wallet from one chain cannot appear while
another is selected. Removing a network does not delete its wallet.

### 0.4 Routine, already understood

| Item | State |
|---|---|
| Deploy the accumulated commits (anchor sweep, paged index, treasury cap, wallet fixes) | deployed from `412b8e70` |
| Qualification gate green on the exact SHA | complete: [full gate `31838029089`](https://github.com/advatar/ActiveChain/actions/runs/31838029089) passed on `412b8e70` |
| macOS wallet lifecycle UI test | blocked: needs the Mac unlocked (XCUITest cannot foreground; provisioning needs Touch ID) |
| Treasury pool maintenance | [#799](https://github.com/advatar/ActiveChain/issues/799) — 94 grants of runway remain |
| Integrator onboarding doc: endpoint, genesis pin, funding, limits | drafted in [KANALEN_INTEGRATOR_ONBOARDING_V1.md](KANALEN_INTEGRATOR_ONBOARDING_V1.md); signed distribution and public ordinary-transfer submission remain open |
| Android parity | [#795](https://github.com/advatar/ActiveChain/issues/795), only if integrators need it |

### Track 0 exit criteria

1. A fresh wallet can be funded and can **spend** without waiting a day.
2. The chain can host the intended integrator population without the index
   ceiling being reachable by ordinary use.
3. Gate green on the deployed SHA; lifecycle test green on hardware.
4. An integrator can onboard from a document without asking us anything.

*Status: 1 and 2 are fixed in main but **not deployed**. The live release predates both, so the
testnet still hands out one unspendable Coin Cell per grant and its RPC index sits at roughly 74% of
the 4 MiB ceiling — about seventeen two-cell grants of headroom. The deployed wallet cannot reach the
node at all, since it pins RPC schema revision 3 against a node serving 2.*

*The deploy is ready and blocked on one thing: main is red on three qualification jobs, all fixed by
[#804](https://github.com/advatar/ActiveChain/pull/804), which is draft pending its author's own
checklist. Every other precondition is verified — deploy secrets present, LAN ssh open, the
activation script defaults to `kanalen`, and the live chain id and genesis commitment match the
wallet's pins byte for byte, so the upgrade migrates in place without a reset.*

---

## The interference contract

Six resources are shared. Tracks A–C respect these rules or they stall Track 0.

| Resource | Rule |
|---|---|
| **Mac mini** | Hosts the chain *and* the serial CI runner. Tracks A–C run no CI on it while a Track 0 gate or rehearsal is running. |
| **Release train** | One `current` symlink. Tracks A–C never deploy to Kanalen. |
| **Kanalen genesis** | Never reset by Tracks A–C. A reset repins every wallet. |
| **RPC schema revision** | One scheduled window per change, owned by Track 0. Tracks A–C queue behind it. |
| **Treasury runway** | 94 grants. Tracks A–C use their own network, never Kanalen's faucet. |
| **Host ports** | Allocated per network by the planner; no track hand-picks a port. |
| **`consensus-runtime`** | Chain-critical. Track B changes are inert without a consensus-visible activation record, and are exercised only on the dev network. |

**The enabling move: several testnets in parallel.** Tracks A–C target their own
chain from day one. This is not overhead and not merely isolation — running
many networks concurrently *is* the point of Track A, and using one for this
work simply proves it. Kanalen is then never the test subject.

The system is closer to this than it looks. Already parameterised:

- `deployment_root` is `${ACTIVECHAIN_KANALEN_ROOT:-$HOME/activechain-deploy/kanalen}`
- launchd labels are namespaced by network name (`dev.activechain.kanalen.*`)
- the gateway routes by hostname SNI, so networks separate cleanly by hostname
- `network.env` is already per-deployment

Three things genuinely block it, and they are all mechanical:

1. **Ports are hardcoded** in the launch agents — 49151 RPC, 49153–49155
   validators, 49156–49157. Needs a per-network base port allocated by the
   planner, with collision detection across networks already on the host.
2. **The network name is literal** in plist filenames, labels, script names,
   and paths. Needs templating from one value.
3. **The wallet pins exactly one network at compile time** — `WalletKanalen`
   fixes host, chain id, and genesis as constants. This is the client-side
   blocker and the one with real design content (see 0.5).

None of that is deep work. It is the difference between a deployment script and
a fleet, and it converts "spin up a network to test the admin UI" from a
special case into the ordinary path.

---

## Track A — network admin

Delivers the ability to stand up a network from a declarative manifest, and is
what makes Tracks B and C safe by giving them somewhere else to run.

### A1. Plan compiler and host preflight *(no deploy, no Kanalen contact)*

Two layers, because they have different determinism guarantees and conflating
them would make the plan unreproducible.

**A1a. `PlanCompiler` — genuinely pure.** Manifest in, `NetworkPlan` or refusal
out. No DNS, no sockets, no filesystem inspection, no clock. It validates
topology, names, port *ranges*, cell budgets, thresholds, derived paths and
labels, and the expected artifact set. The same manifest must compile to the
same plan in Stockholm, in CI, and on the target host — that property is what
later lets us prove a manifest produced the network it claims to have produced.

Preflights at this layer encode the incidents already paid for:

- treasury cells against the index budget *and* against 0.2's outcome
- minimum spendable cells for the treasury, per 0.1
- grants that would leave a recipient unable to spend, per 0.1
- signer threshold satisfiable by the signer set
- port ranges that do not overlap between the networks being planned together
- a network name safe as a launchd label, a filesystem path, and a hostname

**The signed artifact is the plan digest**, taken over the canonically encoded
plan object. Human-readable output is *rendered from* that object and is never
itself the thing signed.

**A1b. `HostPreflight` — explicitly environmental.** Everything that needs the
world: DNS resolution, certificate reachability, ports already occupied,
networks already installed, disk space, launchd availability. It produces an
`EnvironmentAssessment` against a compiled plan and is never mistaken for part
of the plan.

```text
network manifest ──▶ PlanCompiler ──▶ NetworkPlan (deterministic, digest-signed)
                                          │
                                          ▼
                            HostPreflight ──▶ EnvironmentAssessment
```

*Exit: the plan for Kanalen's topology reproduces its real configuration — ports,
labels, paths — and each known incident is rejected by a compiler test. The
compiler has no I/O in its dependency surface.*

**Status: A1a and A1b are built** (`crates/network-planner`, 15 tests).

- The compiler is pure: no I/O anywhere in its dependency surface.
- `NetworkPlan` has a canonical encoding and `digest()` over it, so the signed
  artifact is the plan object rather than rendered text. Advisories are
  excluded from the commitment — wording is guidance for a reader, not part of
  what a deployment is.
- `preflight::assess` is the separate environmental layer, returning an
  `EnvironmentAssessment` and never touching the plan. A test pins that
  assessing does not change the plan's digest.
- Planning `deploy/networks/kanalen.json` reproduces the live layout exactly:
  rpc 49151, validators 49153–49155, anchor 49156, work-proof 49157.
- Two manifests planned together allocate without collision and are refused
  when their reservations overlap.

**Status: built.** `crates/network-planner`, 27 tests.

### A2. Apply

- `activechain-network-apply`: idempotent execution of a plan, emitting an
  evidence record of each step.
- Absorbs the launchd bootout/bootstrap retry and PATH resolution already fixed
  in `activate-kanalen-release.sh`, plus the cross-genesis artefact sweep.

*Exit: a second network stood up end to end from a manifest, twice,
byte-identical, running concurrently with Kanalen on the same host without
touching it. A third, started while both run, allocates cleanly.*

**Status: built.** `render::materialize` is pure — a plan and a home directory
in, the exact bytes of `network.env` and every launch agent out. `apply::apply`
is the thin effectful layer: preflight, write, never overwrite, and stop where
custody begins. Two networks were applied side by side on one host with distinct
derived chain ids, ten launch agents passing `plutil -lint`, and a refusal on
re-apply.

The chain id is derived rather than configured —
`SHAKE256-384("ACTIVECHAIN-CHAIN-ID-V1" || domain)`, verified against the value
Kanalen runs — so it can no longer be mistyped or hand-carried between tools.

Apply records its plan into the deployment, which is what makes A3 possible.

### A3. Operator UI

- Native macOS app, reusing the wallet's custody architecture. **Not a browser
  application** — this surface handles validator keys, the faucet operator
  seed, and trust ceremony coordination and signatures. Private threshold key
  shares never enter it; see A4.
- Manifest editor, plan review with preflight results, apply progress, evidence
  view.

*Exit: an operator who has never used the CLI can stand up a network, and can
see every network on the host with its ports, hostnames, and health.*

**Status: half built.** `activechain-network-status` delivers the fleet view —
every deployment on a host, read from the plan it recorded, with each port
probed so intention and reality can be compared. A bound port reports as
"listening" and nothing stronger, and a directory with no recorded plan is
listed as unaccounted rather than omitted.

The graphical shell is **not** built. What exists is the operator surface as a
command line tool; calling that a UI would be a claim about usability nobody has
tested. The functions beneath it are all testable without it, which is the
condition that makes the shell a presentation layer rather than a rewrite.

### A4. Trust ceremony orchestration

A network is not usable without its verifier trust bundle, so the operator app
should drive the ceremony — **workflow integration, not custody consolidation**.

The app may: prepare the ceremony, show the signer set, produce the signing
payload, collect independently produced signatures, verify the threshold,
assemble the bundle, and activate the result.

The app must not: hold the signing keys. A 2-of-3 ceremony whose three keys live
in one macOS application is 1-of-1 wearing a costume, and the entire value of
the threshold is gone.

**Status: built.** `trust_ceremony::coordinator` tracks a ceremony without
holding a key: `SignerSeed` appears nowhere in its API. It verifies each
signature at collection against that signer's public key over the exact payload,
so a rejection names the responsible party, and it reports who is outstanding.
One signer submitting twice does not advance a 2-of-3 — pinned by test, because
counting a repeat would let a single party satisfy a threshold alone.

The same distinction applies to "sharing the wallet's Secure Enclave custody":
reuse the custody **architecture and interaction patterns**, but keep the
security domains separate. Wallet keys, validator keys, treasury authority, and
trust roots are four different domains and a compromise of one must not imply
the others.

---

## Track B — jurisdiction profile enforcement, then selection

Two phases, in this order, for the reason established in the study: a selector
over an unenforced profile asserts a regulatory posture the system does not
hold.

### B1. Make a profile mean something *(dev network only; no activation record on Kanalen)*

*Status: 1, 3 and 4 built and in review — the durable registry
([#807](https://github.com/advatar/ActiveChain/pull/807)), admission enforcement gated on a
chain-recorded activation root ([#810](https://github.com/advatar/ActiveChain/pull/810)), and the
selection vectors ([#808](https://github.com/advatar/ActiveChain/pull/808)). Obligation
composition, which 3 also calls for, is
[#811](https://github.com/advatar/ActiveChain/pull/811) and has no consumer yet. **2 remains**:
activation is expressible but the canonical activation record a chain carries — genesis feature
set or transition at a stated height — is undesigned, and nothing should enforce against a local
file alone.*

1. **Registry** — durable jurisdiction profile store in the shape of the
   existing durable registries: canonical snapshot, atomic replace, fail-closed
   restart, refusing cross-genesis records.
2. **Activation transition** — refuses activation unless every `REQUIRED`
   commitment resolves to a signed nonzero digest and the full control mask is
   present. This rule is already written in the manifests; make it executable.
3. **Admission** — `RegulatedTransferAdmission` consults the active profile set
   and applies `require_selected_profile`, composing obligations by intersection
   per the conflict algorithm already specified.

   **Activation is consensus-visible state, never local process configuration.**
   An environment variable controlling admission would let two validators
   evaluate the same transaction differently and fork the chain on a
   configuration difference. Enforcement is therefore gated on a canonical
   activation record — a genesis feature set, or an activation transition at a
   stated height — from which every validator derives the same answer:

   ```text
   enforcement = f(consensus state)      not      f(process environment)
   ```

   Kanalen stays bit-identical by simply carrying no activation record. A
   compile-time or dev-harness flag remains fine for making the code reachable
   in tests, but must not reach the validator transition path.
4. **Vectors** — deterministic tests for inheritance without weakening,
   conflict resolution, expiry, non-retroactivity.

*Exit: on the dev network, a transfer under an activated profile is admitted; the same
transfer with an expired, incomplete, or unselected profile fails closed.
Kanalen carries no activation record, so nothing there changes.*

This completes stage 4 of `docs/compliance/JURISDICTION_PROFILE_PLAN.md`.

### B2. Control register UI

*Status: built and in review ([#809](https://github.com/advatar/ActiveChain/pull/809)). Every row
reads outstanding because no evidence store exists; the page says so rather than presenting an
empty register as a clean bill.*

- One row per control family, showing which commitment is present, which is
  outstanding, and who is accountable.
- Activation state **computed, never asserted**.
- The code's existing disclaimer surfaced prominently: the bits commit to
  accountable off-chain controls and are not a licence, approval, reserve
  balance, or legal conclusion.
- Absent `legal_review` shown as loudly as any other gap.

No jurisdiction dropdown. The interaction is evidence collection.

*Exit: a compliance owner can see exactly what is missing before Kenya
activation, and cannot cause the UI to claim readiness that the mask does not
support.*

### B3. Cross-network movement is where a profile escapes

Assets can already move between networks. `ActiveBridge` is an application
protocol over native asset actions — payment intents bind a recipient network,
swap intents bind both legs — and `crates/payment-types`, `payment-sdk` and
`payment-connector-host` implement parts of it.

**None of those crates contain any compliance or jurisdiction concept.** The
bridge design document does not mention profiles, jurisdictions, or regulated
activity anywhere.

This does not void regulatory obligations. It concentrates them. A bridge is
exactly where a regulated instrument leaves the profile that made it lawful,
and an unbound one is a regulatory arbitrage device rather than a payment
route: if a Kenya-profile stablecoin can be moved to a network that enforces
nothing, then the profile was advisory all along.

The governing rule should be that **a profile binds the asset, not the
network it currently sits on**:

- Moving a profile-bound asset carries its obligations with it, or the move
  fails closed. Silently dropping them is the one outcome that must be
  impossible.
- The destination must be able to enforce a compatible profile. Obligations
  compose by intersection under the existing conflict algorithm, so a
  destination enforcing less cannot receive.
- A payment intent's recipient network is therefore subject to profile
  applicability, not merely to route availability.
- Unprofiled assets on unprofiled networks are unaffected. This constrains
  regulated instruments only.

Parallel testnets are unaffected: they carry unlabelled test assets. What this
constrains is C3.

**C3 therefore requires B3 as well as B1.** A Kenyan stablecoin that can be
bridged to a network with no enforcement is not a regulated instrument, whatever
the issuing network enforces.

---

## Track C — issuer console

Runs in parallel with B, against an **unlabelled test asset**, and only adopts
a jurisdiction label after B1 lands.

### C1. Issuer surface over existing primitives

*Status: the reserve attestation is built and in review
([#812](https://github.com/advatar/ActiveChain/pull/812)) — typed, signed, with no reachable state
that asserts reserves were verified. The register, issue/redeem through
`FungibleIssuerApprovalV1`, and holder controls are not started.*

Reuse rather than rebuild. Issuance approvals flow through the **existing
wallet approval path** so they inherit Secure Enclave custody, canonical
approval review, and one-shot signing.

- Register: definition, decimals, supply cap, reserve/redemption policy
  commitments, threshold authority set.
- Issue / redeem via `FungibleIssuerApprovalV1`, with
  `dry-run-corporate-action` preflight before any approval is requested.
- Holder controls and halt, bounded and expiring.
- Reserve attestation as a **typed, signed attestation** — issuer, asset,
  period, reserve scope, the liability or supply figure it is claimed against,
  the evidence provider or auditor, and an expiry — whose commitment is then
  anchored. The anchor establishes integrity, time, and provenance; it does not
  establish reserves. A UI must never read "reserves verified" from the mere
  existence of an anchored digest, which is the same principle as computing
  balance state from evidence rather than asserting it.

### C2. A2UI surface

`crates/a2ui-renderer` already renders issuer approvals from wallet-reconstructed
facts over `A2uiSurfaceV1`. Extend that rather than introducing a second
rendering path.

### C3. Kenya labelling — gated

*Status: **must not be started.** Its preconditions — B1 deployed and enabled, both Kenya
manifests resolved, counsel review — are unmet, and building ahead of them would produce exactly
the thing this section forbids.*

Requires B1 deployed and enabled, both Kenya manifests fully resolved, and
counsel review. **Nothing before this point may present as a Kenyan
instrument.**

---

## Sequencing

```
Track 0  ├── 0.1 spendability ──┬── 0.4 deploy ── gate ── onboarding doc ──▶ usable
         └── 0.2 index ceiling ─┘        (schema window, Track 0 owns)

Track A  ── A1 planner ── A2 apply ── 2nd net up ─┬── A3 UI ── A4 ceremony
                                                  │
Track B                                           ├── B1 enforcement ── B2 UI
                                                  │
Track C                                           └── C1 console ── C2 A2UI ── C3 label
                                                                        (needs B1)
```

A1 is safe to start immediately: it is a pure planner, touches nothing live, and
its preflight checks are where the testnet's own lessons get written down. A2
must complete before B and C begin, because a second network is what keeps them
off Kanalen.

0.5 (wallet network selection) is shared: Track 0 needs it so integrators can
reach the testnet, Track A needs it so anyone can reach a network they just
created. Build it once, in Track 0, early.

Two hard cross-track dependencies: **C3 requires B1** (enforcement exists) and
**C3 requires B3** (enforcement cannot be escaped by moving the asset).

## Risk register

| Risk | Mitigation |
|---|---|
| Validators diverging on locally-configured admission | Enforcement gated on consensus-visible activation only; no environment flag reaches the transition path |
| A partially settled two-cell grant leaving a recipient unable to spend | One grant lifecycle with both transaction ids tracked; cooldown only on complete settlement |
| A threshold ceremony collapsing into single-operator custody | The operator app orchestrates and verifies; it never holds the signing keys |
| An anchored digest being read as proof of reserves | Typed signed attestation with scope and expiry; UI computes from the evidence, never from the anchor's existence |
| Index ceiling reached during integration | 0.2 before external integrators; monitor cell count as an operational metric |
| Schema churn forcing repeated wallet rebuilds | Track 0 owns a single window; B1 and 0.2 ride it together if timing allows |
| Profile work destabilising consensus | Consensus-visible activation absent on Kanalen; dev network only; no activation record until vectors pass |
| CI starving the chain | Tracks A–C hold CI while Track 0 runs; longer term, move the runner off the chain host |
| A "Kenya" label outrunning enforcement | C3 gated on B1, B3 and counsel; no jurisdiction naming in C1/C2 |
| A regulated asset bridged to a network that enforces nothing | B3: the profile binds the asset, not its location; cross-network movement carries obligations or fails closed |
| Operator UI handling keys in a browser | A3 is native; browser variants may only author and sign plans |

## Amendment record

Reviewed and amended before adoption:

1. B1 enforcement moved from an environment flag to consensus-bound activation.
2. A1 split into a deterministic `PlanCompiler` and an environmental
   `HostPreflight`; the signed artifact is the plan digest, not rendered text.
3. The two-cell grant specified as one atomic, reconcilable lifecycle.
4. A4 orchestrates the trust ceremony without consolidating custody; security
   domains stay separate.
5. Reserve attestations are typed evidence; anchoring gives integrity, time and
   provenance, not proof of reserves.
6. The index fix is shared proof per page **plus** pagination, not deduplication
   alone.

Unchanged, and deliberately so: the track ordering, Track 0's protection, the
move to independent networks, and the hard boundary that **C3 requires B1**.

## Out of scope

Reserve banking, licence applications, KES on/off-ramp and M-Pesa integration,
and any assessment of legal sufficiency. Each needs a named owner outside
engineering.
