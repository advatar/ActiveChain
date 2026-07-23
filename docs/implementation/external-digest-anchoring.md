# External digest anchoring

ActiveChain issue #122 provides the optional external anchor used by MadeMark's
`ActiveChainExternalAnchorProvider`. The application submits the SHA-256 digest of its canonical
`MadeMarkAnchorStatementV1`, never the statement's source material or local metadata.

## Client flow

1. Construct `DigestAnchorStatementV1` with domain
   `mademark.external-anchor.statement.v1` and the 32-byte MadeMark digest.
2. Canonically envelope-encode it and send `RpcRequest::SubmitAnchor`.
3. Persist the returned `AnchorSubmission` reference locally. Repeating step 2 is safe and returns
   the same reference.
4. Poll `RpcRequest::ResolveAnchor`. `NotFound`, malformed responses, network errors, and
   trusted-network mismatches map to MadeMark's `invalid`/failure result and never affect local
   operation.
5. Treat `finalized` as valid only after decoding `AnchorFinalizedEvidenceV1` and calling
   `verify_anchor_evidence` with the expected statement, trusted chain ID, trusted genesis
   commitment, exact protocol/verifier revisions, and a light-client verifier for both the action
   inclusion/state proof and finality proof.

The RPC registry persists an accepted statement before returning its reference. Snapshot decoding
recomputes every reference and fails closed on corruption or substitution. `pending` may transition
once to `rejected`, or to `finalized` only with evidence for the exact statement.
Operators enable the registry by setting `ACTIVECHAIN_ANCHOR_SNAPSHOT` for
`activechain-rpc-node`, or by passing its optional final positional argument. Omitting it disables
all mutation endpoints while leaving the proof-query RPC unchanged.

Batch clients submit the Merkle root as the statement digest and retain
`AnchorBatchProofV1` for each MadeMark leaf. The canonical tree hashing and frozen vector are in
`P-112` and `testing/vectors/application/external-anchor-v1.txt`.
