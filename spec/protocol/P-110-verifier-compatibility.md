# P-110: Stable verifier compatibility contract

- Status: Draft 0.2
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

`testing/vectors/manifest-v1.json` is the compatibility index. It identifies each vector source,
protocol revision, type tag, schema version, and source-file SHA-256, and links
`envelope-manifest-v1.json`. The linked manifest enumerates every envelope field with its exact
envelope SHA-256 and expected canonical-value commitment. Malformed, tampered, wrong-version, and
trailing-byte cases are first-class entries with structured expected failures.

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

`activechain_verify_envelope_v1` implements this boundary with a caller-owned canonical-body
buffer and `ActivechainVerifierResult`. A zero-capacity null body pointer performs a size query.
Success returns the exact type, schema, required body length, canonical body, and the P-001
canonical-value commitment. Failures return a stable primary code, byte offset, and decode detail:

| Detail | Meaning |
| ---: | --- |
| 0 | no decode subcategory |
| 1 | unexpected end |
| 2 | non-minimal length |
| 3 | length overflow |
| 4 | declared length exceeds the bound |
| 5 | invalid Boolean |
| 6 | invalid enum discriminant |
| 7 | schema invariant violation |
| 8 | trailing data |

Offsets identify the start of the failing envelope field where it is statically knowable: type at
0, schema at 2, length at 4, and body at 5. Unexpected-end points to the end of input and
trailing-data points to the first trailing byte. No error string crosses the ABI.

## Light-client requirements

Before a light client trusts state it MUST verify a finalized quorum certificate, the validator-set
root active at that height, a checkpoint binding the state root and protocol revision, state-tree
membership/non-membership proofs, and data-availability evidence. Validator-set changes require a
finalized activation height. Upgrades require an explicit version gate and retained historical rules.

### Epoch and revision activation

Validator-set and protocol-revision changes MUST be represented by canonical
`ConsensusUpgradeAuthorization` (`type_tag = 0x006d`, `schema_version = 1`). The authorization
commits the authorization and activation heights, previous and next epochs, previous and next
validator-set roots, and previous and next protocol revisions under
`ACTIVECHAIN-CONSENSUS-UPGRADE-V1`.

An authorization is actionable only when all of the following hold:

- a strict-quorum `CertifiedBlock` finalizes the authorization commitment as its block digest;
- every included ML-DSA vote is bound to the immutable genesis commitment, active epoch, active
  validator-set root, and active protocol revision;
- the authorization height is finalized before the activation height;
- the node is at the boundary immediately before the declared activation height;
- a validator-set change advances exactly one epoch and binds a `ValidatorGenesis` with the exact
  next epoch, activation height, validator-set root, and protocol revision;
- a protocol revision is unchanged or increases strictly; and
- a next validator-set root has never appeared in the durable retired-root history.

Nodes MUST reject early, missed, or late activation. They MUST reject certificates from a stale
epoch, a non-active validator-set root, or a non-active protocol revision. A schema-v2 QC binds the
complete consensus context, but a QC summary alone is not proof of its signer set and MUST NOT be
treated as authoritative without its canonical signed votes. Validators in the signed vote set
MUST be strictly ordered by principal ID. Verifiers MUST recompute `vote_set_root` from
`ACTIVECHAIN-VOTE-SET-V1 || public_key || vote_signing_payload || signature` for each ordered vote
and reject duplicate, reordered, omitted, substituted, or otherwise mismatched transcripts.

The activation boundary uses these schema revisions:

| Type | Type tag | Schema |
| --- | --- | --- |
| `ValidatorVote` | `0x0064` | `3` |
| `QuorumCertificate` | `0x0065` | `2` |
| `ConsensusSnapshot` | `0x0069` | `2` |
| `ValidatorGenesis` | `0x006b` | `2` |
| `ConsensusUpgradeAuthorization` | `0x006d` | `1` |

Older snapshots and validator manifests omit required revision or rollback-history fields and MUST
fail closed rather than be silently upgraded.
