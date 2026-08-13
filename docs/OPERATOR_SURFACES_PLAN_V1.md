# Operator surfaces plan v1

Planning study for three requested surfaces: starting a network, selecting a
regulatory profile, and issuing a Kenya stablecoin. This is a plan, not a
commitment, and it deliberately builds on what already exists rather than
proposing anything parallel to it.

## Summary of the starting position

The three requests sit at very different distances from working software. That
gradient, not the UI design, is what should drive sequencing.

| Surface | Protocol primitives | Wired into runtime | Docs/design | UI |
|---|---|---|---|---|
| Start a network | complete | yes (CLI) | partial | none |
| Pick regulation | complete | **no** | extensive | none |
| Issue a stablecoin | complete | yes | extensive | none |

The load-bearing finding is the middle row, below.

## The gap that governs everything: profiles are defined but inert

`KenyaRegulatedProfileV1` exists in `crates/protocol-types/src/compliance.rs`
with 18 control families derived from Kenya Legal Notice No. 134 of 2026, 18
policy commitment digests, validity heights, and a revision. Two activation
manifests exist: `docs/compliance/profiles/ke.virtual-asset-service.v2.json`
and `ke.stablecoin-issuer.v1.json`, both `activation_gated` with a
`required_control_mask` of `0x0003ffff` that matches
`KenyaControlSet::STABLECOIN_REQUIRED` exactly.

**Nothing consumes any of it.** `KenyaRegulatedProfileV1` appears only in its
own definition and the crate re-export — no constructor, no registry, no
storage, no admission check. `require_selected_profile` is exported from
`application-primitives` and never called. The runtime compliance path that
*is* wired, `RegulatedTransferAdmission` in `crates/consensus-runtime/src/compliance.rs`,
validates evidence, provider signatures, travel-rule bindings, and replay — but
never consults a jurisdiction profile.

This is delivery stage 4 of `docs/compliance/JURISDICTION_PROFILE_PLAN.md`
("integrate profile-set selection into admission and replay barriers"), and it
has not been started. Stages 1–3 largely have.

**Consequence for the request as posed:** a UI that lets someone "pick Kenya"
today would change nothing at runtime. It would produce a screen asserting a
regulatory posture the system does not enforce — the same class of defect as
the wallet's funding card claiming no balance had been credited when one had,
except that here the false claim is about regulatory compliance. The
enforcement path must exist before the selector does, or the selector must be
explicitly labelled as configuration authoring with no runtime effect.

## 1. Admin UI to start a new network

### What exists

Every step is implemented as a tool; none of them are orchestrated:

- `genesis-tool` — validator set and `genesis.bin`, returns the genesis commitment
- `cash-genesis-tool` — treasury ledger, operator seed, returns the cash owner
- `crates/trust-ceremony` — keygen, signer set, prepare, sign, assemble
- `deploy/kanalen/scripts/reset-kanalen-state.sh` — archive and rebuild state
- `deploy/kanalen/scripts/activate-kanalen-release.sh` — install, launchd, gateway
- `network.env` — the manifest that binds chain id, genesis commitment, treasury owner

The operator currently threads derived values between these by hand: chain id
into the cash tool, cash owner into the RPC plist, genesis commitment into the
wallet's pin.

### What the recent incidents say about the design

This session produced four failures that a wizard-style UI would have
reproduced faithfully, because they are all *planning* errors rather than
execution errors:

- a treasury sized beyond what the RPC index frame can publish (silent until a
  round fails with `Invalid`)
- a treasury of two cells, which buys exactly one grant
- cross-genesis anchor artefacts surviving a rebuild
- a launchd bootout/bootstrap race taking a validator offline mid-deploy

The lesson is that the valuable artefact is **a validated plan**, not a
sequence of buttons. A UI that merely calls the tools in order inherits every
one of these.

### Proposed shape

Manifest-first, UI-second:

1. **`network.toml`** — one declarative description: chain identity, validator
   count and endpoints, treasury sizing, faucet policy, trust signer set and
   threshold, gateway hostnames.
2. **`activechain-network-plan`** — reads the manifest, resolves derived values,
   and refuses impossible configurations *before* anything is created. This is
   where the incident lessons become preflight checks: treasury cells against
   the index frame, minimum spendable cells, hostname/DNS reachability, signer
   threshold sanity.
3. **`activechain-network-apply`** — executes the plan, idempotently, emitting a
   signed record of what it did.
4. **UI** — an editor over the manifest plus a progress and evidence view over
   the plan. It never becomes the source of truth.

**Key constraint: this surface handles key material** — validator keys, the
faucet operator seed, trust ceremony shares. It must not be a browser
application. Options, in order of preference:

- a native macOS operator app reusing the wallet's custody *architecture* —
  though wallet keys, validator keys, treasury authority and trust roots stay
  in separate security domains, and a threshold ceremony's signers must never
  all live in one application
- a local TUI over the same planner
- a browser UI that can only *author and sign a plan*, executed by an
  operator-side agent that holds the keys

### Open questions

- Does "new network" mean a new chain id, or a new deployment of Kanalen? The
  activation script currently refuses a chain-id substitution, deliberately.
- Multi-host validators, or the current single-host three-validator topology?

## 2. UI to pick regulation, starting with Kenya

### What exists

Considerably more than the request assumes. `docs/compliance/JURISDICTION_PROFILE_PLAN.md`
already fixes the semantics: profiles are scoped, versioned, signed, and
non-retroactive; obligations compose by intersection; conflicts fail closed;
profile authority is separated from validator authority. `KenyaRegulatedProfileV1`
is the canonical activation record, and `KENYA_VASP_CONTROL_REGISTER_V1.md`
enumerates the control families.

### What is missing

The enforcement path (see above), and only then a UI.

### Proposed shape

**Phase A — make a profile mean something.** Before any UI:

1. A durable jurisdiction profile registry, in the shape of the existing
   durable registries (`DurableComplianceReplayJournal`,
   `DurableControllerLedger`): canonical snapshot, atomic replace, fail-closed
   restart.
2. Profile activation as an explicit transition, refusing activation unless
   every `REQUIRED` commitment resolves to a signed nonzero digest and the full
   control mask is present — the rule the manifests already state.
3. `RegulatedTransferAdmission` consults the active profile set and applies
   `require_selected_profile`, composing obligations by intersection per the
   existing conflict algorithm. Activation is a **consensus-visible record**,
   never a local environment flag: two validators configured differently must
   not be able to evaluate the same transfer differently.

**Phase B — the UI.** Its job is *evidence collection*, not selection. The
honest interaction is a control register checklist:

- one row per control family, showing which commitment is present, which is
  outstanding, and who is accountable
- an activation state that is computed, never asserted: a profile activates
  only when the mask is complete
- explicit display of the disclaimer already in the code — the bits commit to
  accountable off-chain controls and are not a licence, an approval, a reserve
  balance, or a legal conclusion

A dropdown reading "Jurisdiction: Kenya" is the wrong primitive. It invites
exactly the inference the code comments take care to forbid.

### Non-goals and a caution

I am not qualified to give legal advice, and this plan does not evaluate
whether the 18 control families correctly capture Legal Notice No. 134 of 2026.
The schema already anticipates this: `legal_review` is a first-class commitment
field, and the plan document requires qualified local counsel before any
production claim. The UI should surface that field's absence as prominently as
any other.

## 3. UI to issue a Kenya stablecoin

### What exists

This is the best-provisioned of the three. `docs/implementation/native-issuer-operations-v1.md`
specifies the full lifecycle — register, issue, transfer, redeem, pause/recover,
retire — with separated attenuated roles and threshold authority. The
primitives are wired into the kernels: `FungibleAssetDefinition`,
`FungibleAssetPolicyV1`, `FungibleIssuerApprovalV1`,
`FungibleIssuerOperation::{Mint, Burn, Redemption}`, `DurableFungibleAssetLedger`,
`DurableMultiAssetLedger`, holder control, clawback, corporate actions, and
controller rotation. `dry-run-corporate-action` already provides preflight.

`crates/a2ui-renderer` renders issuer approvals from wallet-reconstructed facts
over the `A2uiSurfaceV1` declarative protocol, and the wallet already has an
Approvals tab.

### Proposed shape

Reuse rather than build: the issuer console should be an **A2UI surface whose
approvals are signed through the existing wallet path**, so issuance inherits
Secure Enclave custody, the canonical approval review, and the one-shot signing
session the wallet already enforces. Concretely:

1. Asset registration: definition, decimals, supply cap, reserve/redemption
   policy commitments, jurisdiction profile binding, threshold authority set.
2. Issue and redeem against `FungibleIssuerApprovalV1`, with
   `dry-run-corporate-action` preflight before any approval is requested.
3. Reserve attestation as typed, signed evidence — issuer, asset, period,
   scope, the liability it is claimed against, the provider or auditor, and an
   expiry — whose commitment is anchored. Anchoring supplies integrity, time
   and provenance; it does not prove reserves, and no UI may imply that it
   does.
4. Holder controls and halt, bounded and expiring, per the existing
   exceptional-control policy.

### The sequencing decision

**A stablecoin can ship on the existing kernel without item 2 — but it would be
an unregulated one.** The Kenya stablecoin control bits
(`STABLECOIN_WHITE_PAPER`, `STABLECOIN_ISSUANCE_AND_REDEMPTION`,
`STABLECOIN_RESERVES_AND_CUSTODY`, `STABLECOIN_AUDIT_REPORTING_AND_HALT`) live
in the profile that nothing enforces.

This is the decision worth taking deliberately:

- **Ship issuance first, regulated later** — fastest to a demonstrable asset;
  risks a stablecoin whose "Kenya" label is presentational.
- **Wire profiles first** — slower; the first issued asset is genuinely
  profile-bound.

My recommendation is to wire profile activation and admission (Phase A of item
2) before the issuer console ships anything labelled Kenyan, and to build the
issuer console meanwhile against an unlabelled test asset. The two workstreams
are independent until the moment of labelling.

## Suggested order

1. **Item 1, planner and preflight** — immediately useful, encodes the
   incidents, no UI required to be valuable.
2. **Item 2, Phase A** — the enforcement path; unblocks any honest regulatory
   claim.
3. **Item 3, issuer console** — against a test asset, in parallel with 2.
4. **Item 2, Phase B** — the control register UI.
5. **Item 3, Kenya labelling** — only after 2 completes and counsel review.

## Deliberately out of scope here

Reserve banking arrangements, licence applications, M-Pesa or KES on/off-ramp
integration, and any assessment of legal sufficiency. Each needs a named owner
outside engineering.
