# P-110: Stable verifier compatibility contract

- Status: Draft 0.1
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

An eventual C ABI MUST preserve this result shape, use caller-owned buffers, require explicit output
lengths, and never panic or allocate without a published bound.

## Light-client requirements

Before a light client trusts state it MUST verify a finalized quorum certificate, the validator-set
root active at that height, a checkpoint binding the state root and protocol revision, state-tree
membership/non-membership proofs, and data-availability evidence. Validator-set changes require a
finalized activation height. Upgrades require an explicit version gate and retained historical rules.
