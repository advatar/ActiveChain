# Emerald on Actum — private post relation v2

Status: **EOA-M0 normative target; implementation pending**  
Tracking: #859

## 1. Purpose

Version 2 replaces the legacy billboard post proof statement for Emerald-on-Actum. Its primary
privacy requirement is that a public observer cannot learn which previously committed permit is
being consumed merely by inspecting the proof journal or public application transcript.

The legacy v1 relation is retained for compatibility and characterization only. It MUST NOT be used
to claim unlinkable Emerald posting.

## 2. Required state commitment

The application maintains an authenticated **permit commitment tree** whose finalized root is part
of the accepted Emerald/Actum application state. A wallet spending a permit supplies, as private
witness data:

- the complete prior permit opening;
- its position or canonical leaf locator;
- an authentication path proving the permit commitment is a member of the accepted permit root;
- private authorization/nullifier material;
- the complete successor permit opening; and
- any bounded moderation inputs required by the rate-limit/screening state machine.

The membership path and consumed permit commitment MUST NOT appear in the public journal.

The production tree profile, append/update semantics, witness refresh rules, and root transition are
separate consensus-critical work. V2 MUST NOT fake membership by accepting an arbitrary root beside
an unrelated witness.

## 3. Public post statement

The v2 public statement MUST bind at least:

```text
PostPublicInputsV2 {
    chain_id
    asset_id
    application_revision
    policy_revision
    accepted_permit_root
    accepted_nullifier_root
    nullifier
    successor_commitment
    post_id
    content_or_blob_commitment
    target
    height_or_slot
    fee_effect
    bond_effect
    dummy_or_action_kind
    validity_window
}
```

Exact field types and bounds are frozen before the v2 guest image ID is published.

The public statement MUST NOT contain:

- the consumed permit commitment;
- the consumed permit position;
- a stable owner/principal identifier;
- a public fee ticket identifying the wallet;
- the private membership path;
- private authorization material.

## 4. Private witness

```text
PostWitnessV2 {
    prior_permit
    prior_position
    prior_membership_path
    nullifier_key
    successor_permit
    moderation_witness
}
```

The proof relation MUST establish all of the following atomically:

1. `commit(prior_permit)` is a member of `accepted_permit_root`.
2. The witness is authorized to consume the prior permit.
3. The public nullifier is derived from the prior permit, private nullifier material, chain and
   application domain exactly once.
4. The nullifier was absent from the accepted nullifier state used by admission; consensus
   admission atomically inserts it.
5. The successor commitment opens to the exact successor derived by the bounded Emerald policy,
   including cooldown/save-up/screening semantics where enabled.
6. Chain, asset, application revision, policy revision, target, slot/height and validity window
   match the public statement.
7. Fees, post/report bonds, change and successor private value conserve exactly.
8. Moderation facts consumed by the relation are authenticated to the accepted application state
   and cannot be substituted across policy revisions.
9. Dummy and real actions obey their distinct content and economic rules.

## 5. Journal v2

The post guest journal is versioned independently from v1:

```text
ACTIVECHAIN-EMERALD-POST-RISC0-STARK-V2
|| public_inputs_commitment
|| nullifier
```

The journal MUST NOT append the prior permit commitment.

The `public_inputs_commitment` commits to the complete canonical `PostPublicInputsV2`, including
the accepted permit root, nullifier root, successor commitment and all public economic/application
effects. The explicit nullifier is repeated in the journal so admission can bind one-shot
consumption without parsing private witness data.

Removing the v1 permit field without adding the root-bound membership proof is explicitly
non-conforming.

## 6. Admission

Validator admission MUST compose these checks:

1. verify the exact pinned v2 guest image and journal;
2. verify that the public accepted roots equal the roots authorized for the action's finalized
   state/version;
3. reject an already-spent nullifier and atomically update nullifier state;
4. apply the public Emerald state transition and economic effects;
5. insert/append the successor private commitment according to the frozen permit-tree transition;
6. commit all effects together or none of them.

Proof validity alone MUST NOT authorize stale-root admission.

## 7. Privacy acceptance tests

Before v2 can replace v1 for Emerald:

- two consecutive posts from the same evolving permit MUST NOT expose an exact
  predecessor/successor commitment equality in their public journals;
- the consumed permit commitment and leaf position MUST be absent from serialized public inputs,
  proof journals, RPC envelopes, receipts and ordinary logs;
- changing the accepted permit root while retaining the same witness MUST fail;
- changing any membership-path element MUST fail;
- changing the successor commitment, nullifier, policy revision, chain, target or public economic
  effect MUST fail;
- replaying the same proof/nullifier MUST fail at admission;
- a valid proof against an old but once-finalized root MUST fail when that root is outside the
  allowed admission window;
- same-user and different-user transcript distributions MUST be tested for stable identifiers
  outside the cryptographic statement, including fee/RPC/order metadata.

These tests establish bounded properties only; they do not claim protection from timing, IP-level
traffic analysis, endpoint compromise or self-identifying content.

## 8. Migration

V1 and v2 use distinct relation identifiers, journal domains and guest image IDs. Existing v1
receipts remain verifiable under their historical profile but MUST NOT be silently interpreted as
v2. An Emerald deployment advertises the minimum accepted relation version and rejects downgrade
where unlinkable posting is required.

## 9. Next implementation slice

The smallest correct implementation slice is:

1. add a bounded canonical permit-tree membership witness and deterministic vectors; **implemented as the reusable append-only `HiddenHistoryMembershipWitness` plus `testing/vectors/emerald/permit-membership-v1.txt`; production root-transition/admission wiring remains pending**
2. implement `PostPublicInputsV2` / `PostWitnessV2`;
3. add the reference v2 verifier and negative membership/root tests;
4. add a separate pinned `billboard_post_v2`/Emerald post guest;
5. publish a v2 journal vector containing only the domain, public-input commitment and nullifier;
6. add admission composition only after root transition semantics are frozen.

Until all six are present, this document is a target specification rather than an implemented
privacy guarantee.
