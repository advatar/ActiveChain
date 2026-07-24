# Abandoned work reconciliation — 2026-07-24

Tracking issue: [#178](https://github.com/advatar/ActiveChain/issues/178)

This audit classifies the clean canonical checkout and the three worktrees left by the previous
developer. It compares every unique commit with `origin/main` at `44d4312`. No uncommitted source
edits remained at the start of the audit.

## Canonical `main`: `8d8d6e0` (`XCode stuff`)

Disposition: **do not merge; superseded plus machine-local state**.

- `mobile/apple/AmberApp/project.yml` on current main already declares
  `DEVELOPMENT_TEAM = L2AF8KFX35`, and the generated project already contains that shared setting.
  Replaying the local project-file edit would add no missing configuration.
- `UserInterfaceState.xcuserstate` is personal Xcode window/editor state and is not a source or
  release artifact.
- Changing the generated Amber product reference from `lastKnownFileType` to `explicitFileType`
  is Xcode normalization noise not represented in the authoritative XcodeGen input.

The personal-state path is now ignored repository-wide. The local commit remains reachable from
the archival branch until canonical-main reconciliation is complete.

## Billboard reassessment: `9edcc51`

Disposition: **historically valid, now superseded; do not merge as current documentation**.

The reassessment accurately described the Phase 4 foundation at baseline `47109c6`, but it
explicitly listed the billboard circuit, atomic senderless admission, encrypted permit delivery,
wallet discovery, and end-to-end lifecycle as missing. Current main records and implements those
items in the private-billboard vertical slice. Merging the old reassessment would therefore publish
obsolete blockers and contradict current executable status.

The closed PR retains review provenance. The unique commit should be kept only as historical
evidence, not merged into current documentation.

## Consensus and authorization recovery: `9fb97ce`

Disposition: **preserve as a recovery source; never merge or cherry-pick wholesale**.

The recovery commit is a 3,857-line WIP patch over an old baseline. A trial application to current
main conflicts in:

- `crates/consensus-runtime/src/bin/validator-node.rs`
- `crates/consensus-runtime/src/lib.rs`
- `crates/crypto-provider/src/lib.rs`
- `crates/protocol-types/src/consensus.rs`
- `formal/AUTHORIZATION_CHAIN_PROOF_SCOPE.md`

Current main has since merged chained-QC safety, durable vote/replay state, finalized-block
composition, epoch authorization, and a joined authorization-kernel Lean proof. Consequently,
conflicting Rust changes require invariant-by-invariant review against the current engine; conflict
resolution by selecting either side would be unsafe.

Two Tamarin artifacts remain unique and potentially valuable:

- `formal/tamarin/activechain_authorization_chain.spthy`
- `formal/tamarin/activechain_authorization_chain.lemmas`

The recovered proof-scope file cannot replace the current file of the same name: current main uses
it for the joined authorization-chain Lean model, while the recovered text scopes a separate
Tamarin model. A future port must retain the Lean scope and publish the Tamarin scope under a
distinct name. It must then adapt the formal gate, run the full derivation preflight and all
eighteen lemma checks, and establish trace correspondence with the current authorization kernel.

The recovered consensus additions also contain proposal/QC transcript binding, durable local
sequence and highest-vote state, ancestry retention, pruning, and restart tests whose names are not
present verbatim on current main. Names alone are not proof of a missing invariant: several have
newer implementations under different structures. Each property must be mapped to a current test
and proof before any minimal port is attempted under issue
[#127](https://github.com/advatar/ActiveChain/issues/127).

## Safe cleanup rule

Only the Xcode and billboard worktrees/branches may be retired after their unique commits are made
archivally reachable. The consensus recovery branch and PR must remain until issue #127 has either
ported the unique Tamarin proof and any demonstrated missing current invariant, or explicitly
rejected each item with test/proof evidence.
