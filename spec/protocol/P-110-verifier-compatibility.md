# P-110: Stable verifier compatibility contract

- Status: Draft 0.3
- Protocol revision: `activechain-v1-dev`

This contract is the boundary for network-disabled local verifiers such as dBrowser.

## Canonical envelope

Every accepted value is encoded as:

```text
type_tag:       u16, big-endian
schema_version: u16, big-endian
body_length:    canonical unsigned varint (maximum four bytes)
body:           canonical schema bytes
```

The body length MUST equal the remaining byte count exactly. Decoders MUST reject unknown type or
schema pairs, non-minimal lengths, malformed bodies, and every trailing byte. Commitment functions
MUST operate on the canonical body, never on a caller-provided digest.

## Machine-readable vectors

`testing/vectors/manifest-v1.json` is the compatibility index. Each entry contains a vector ID,
protocol revision, type tag, schema version, envelope hex, expected commitment(s), and SHA-256 hash.
Malformed, tampered, wrong-version, and trailing-byte cases are first-class entries with structured
expected failures.

## Stable verifier surface

The first implementation surface is language-neutral:

```text
verify_envelope(bytes, expected_type, expected_version)
  -> { canonical_body, commitments[] } | { code, offset, detail }
```

The C ABI MUST preserve this result shape, use caller-owned buffers, require explicit output
lengths, and never panic or allocate without a published bound.

The checked-in header `crates/verifier-api/include/activechain_verifier.h` freezes the adapter
function signatures and numeric result codes. Bindings MUST reject null pointers, lengths above the
published bound, and integer truncation before calling the Rust implementation.

## Light-client requirements

Before a light client trusts state it MUST verify a consecutive two-QC proposal chain that commits
the parent, including the complete canonical signed-vote transcript for both QCs. It MUST also
verify the validator-set root active at that height, a checkpoint binding the state root and
protocol revision, state-tree membership/non-membership proofs, and data-availability evidence.
A bare QC is certified evidence, not finality, and MUST NOT advance trusted state. Validator-set
changes require a committed authorization block and its retained certified child as the handoff
anchor. Upgrades require an explicit version gate and retained historical rules.

### Epoch and revision activation

Validator-set and protocol-revision changes MUST be represented by canonical
`ConsensusUpgradeAuthorization` (`type_tag = 0x006d`, `schema_version = 1`). The authorization
commits the authorization and activation heights, previous and next epochs, previous and next
validator-set roots, and previous and next protocol revisions under
`ACTIVECHAIN-CONSENSUS-UPGRADE-V1`.

An authorization is actionable only when all of the following hold:

- a strict-quorum `CertifiedBlock` certifies the authorization commitment as its block digest, and
  a consecutive child `CertifiedBlock` commits that authorization block;
- every included ML-DSA vote is bound to the immutable genesis commitment, active epoch, active
  validator-set root, and active protocol revision;
- the committed authorization is the active finalized anchor;
- the certified child is retained durably after committed-history pruning, is exactly one height
  and one round after the committed authorization, and is immediately before the activation
  height;
- a validator-set change advances exactly one epoch and binds a `ValidatorGenesis` with the exact
  next epoch, activation height, validator-set root, and protocol revision;
- a protocol revision is unchanged or increases strictly; and
- a next validator-set root has never appeared in the durable retired-root history.

Nodes MUST reject early, missed, or late activation. They MUST reject certificates from a stale
epoch, a non-active validator-set root, or a non-active protocol revision. A schema-v3 QC binds the
complete consensus context, payload block digest, exact signed-proposal commitment, and vote-set
root, but a QC summary alone is not proof of its signer set and MUST NOT be treated as authoritative
without its canonical signed votes. Every vote MUST bind the same payload digest and exact proposal
commitment as its QC. Validators in the signed vote set
MUST be strictly ordered by principal ID. Verifiers MUST recompute `vote_set_root` from
`ACTIVECHAIN-VOTE-SET-V1 || public_key || vote_signing_payload || signature` for each ordered vote
and reject duplicate, reordered, omitted, substituted, or otherwise mismatched transcripts.

The activation boundary uses these schema revisions:

| Type | Type tag | Schema |
| --- | --- | --- |
| `ValidatorVote` | `0x0064` | `4` |
| `QuorumCertificate` | `0x0065` | `3` |
| `BlockProposal` | `0x0068` | `3` |
| `ConsensusSnapshot` | `0x0069` | `4` |
| `ValidatorGenesis` | `0x006b` | `2` |
| persisted validator safety state | `0x006c` | `4` |
| `ConsensusUpgradeAuthorization` | `0x006d` | `1` |

Older votes, QCs, proposals, snapshots, and validator-safety snapshots omit required proposal
identity, context, handoff, or rollback-history fields and MUST fail closed rather than be silently
upgraded. The persisted safety state MUST be made durable before invoking a vote signer and MUST
retain exact vote slots, the highest voted round per consensus domain, the locked QC, replay and
outbound sequence high-water marks, the active finalized anchor, and all still-live certified
descendants.
