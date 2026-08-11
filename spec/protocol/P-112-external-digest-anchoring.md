# P-112: External digest anchoring

- Status: Draft 0.1
- Protocol version: Development

External applications MAY submit a digest without disclosing the material from which it was
derived. ActiveChain accepts only a bounded application domain and an exact 32-byte SHA-256
digest. MadeMark uses `mademark.external-anchor.statement.v1`. Files, paths, users, audit events,
and other application metadata are outside this protocol.

## Submission and resolution

`submit(applicationDomain, digest)` canonically encodes `DigestAnchorStatementV1` (`0x00c6`,
revision 1). The body is a minimally length-prefixed ASCII application domain followed by exactly
32 digest bytes. Domains contain only lowercase ASCII letters, digits, period, and hyphen and are
at most 128 bytes.

The submission reference is the ActiveChain canonical-value commitment to that exact statement.
Repeated exact submissions MUST return the same reference and MUST NOT create another action.
`resolve(reference)` returns `pending`, `finalized`, or `rejected`; an unknown, malformed, or
network-mismatched reference is `invalid` to the application.

A finalized record MUST contain `AnchorFinalizedEvidenceV1` (`0x00ca`, revision 2), binding the
chain ID, genesis commitment, transaction ID, finalized block height and hash, exact statement,
protocol revision, verifier revision, action inclusion/state proof, and finality proof. Offline
verification checks every trusted-network field and then verifies both proofs against the trusted
ActiveChain light-client parameters. A status cannot become finalized without this evidence.

## Consensus-authenticated registry

The canonical `SubmitAnchor` transition creates exactly one immutable `SYSTEM` object for the
statement reference. Its key is `commit(OBJECT_ID_DERIVATION, AnchorRegistryKeyV1(reference))`;
the key type is `0x01c1`, revision 1. Its public value is `AnchorStateRecordV1` (`0x01c2`, revision
1), which binds the reference, exact statement, transaction ID, admission height, and admission
block. The object type is the zero-extended record type tag, and `value_root` is the canonical-value
commitment to the record. All policy commitments are zero, the owner is immutable, the lease is
unbounded, and only the `SYSTEM` flag is set.

The mapping is append-only. A duplicate key is an invalid block transition; no action may replace,
transfer, expire, or delete an admitted anchor record. Host lifecycle registries remain operational
indexes and MUST NOT substitute for this consensus state fact.

`anchor_verified` requires both independent native finality for anchor block A and canonical sparse
state membership of the exact derived object under the operator-pinned finalized checkpoint C,
where A.height is less than or equal to C.height. The checkpoint proof carries the object count
needed to reconstruct the already-pinned state root; that count is not trusted independently.
Anchors newer than C are retryable checkpoint lag, not invalid anchors. The fixed 96-level proof is
bounded by `StateProof::MAX_ENCODED_LEN`; no host callback or unverified ancestry tuple is accepted.

## Batch commitments

Batch leaves are:

`SHA-256(0x00 || domain_length_u16_be || domain || digest)`

Internal nodes are:

`SHA-256(0x01 || left || right)`

The tree is a complete binary tree with a power-of-two leaf count. A batch proof (`0x00c9`,
revision 1) contains the zero-based
leaf index, leaf count, and bottom-up sibling list. Left/right order is derived from each index bit.
Callers pad smaller logical batches with application-defined dummy statements before submission;
v1 proofs always contain `log2(leaf_count)` siblings.

Anchoring is optional for MadeMark. Submission, resolution, RPC, or network failure MUST NOT block
or invalidate MadeMark's local operation.
