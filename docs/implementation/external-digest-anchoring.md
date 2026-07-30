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

Finalization is deliberately not a public RPC mutation. After the anchor action is included in a
finalized block, an operator installs its canonical `AnchorFinalizedEvidenceV1` with:

```text
activechain-anchor-admin finalize <anchor-snapshot> <reference-hex> <evidence-envelope> \
  <trusted-chain-hex> <trusted-genesis-hex> <protocol-revision> <verifier-revision>
```

The command runs the production finality-bundle and block-receipt verifier, requires the declared
anchor transaction to occur in the verified receipt, and only then performs the durable one-shot
`pending -> finalized` transition. Operators may terminally reject a pending request with
`activechain-anchor-admin reject <anchor-snapshot> <reference-hex>`.

Language-neutral clients call
`activechain_verify_anchor_finalized_evidence_code` with the evidence, exact statement, and
explicit trusted network parameters. This API does not accept a caller-provided success callback.
ActiveChain remains developmental; successful verification proves consistency with the configured
development-network trust roots, not production-network security.

Batch clients submit the Merkle root as the statement digest and retain
`AnchorBatchProofV1` for each MadeMark leaf. The canonical tree hashing and frozen vector are in
`P-112` and `testing/vectors/application/external-anchor-v1.txt`.

## Apple client boundary

`ActiveChainVerifier.xcframework` exposes the complete codec/verifier boundary needed by an Apple
application without asking Swift to reproduce ActiveChain's canonical encoding:

- `activechain_anchor_statement_v1` validates the application domain, constructs the canonical
  `DigestAnchorStatementV1` envelope, and returns its deterministic 48-byte submission reference;
- `activechain_anchor_submit_request_v1` and `activechain_anchor_resolve_request_v1` produce exact
  canonical `RpcRequest` envelopes;
- `activechain_anchor_decode_response_v1` accepts only anchor submission, anchor record, or RPC
  error variants. It returns the record status and emits the canonical finalized-evidence envelope
  when the record is finalized; and
- `activechain_verify_anchor_finalized_evidence_code` verifies that evidence against the original
  statement plus caller-pinned chain ID, genesis commitment, protocol revision, and verifier
  revision.

All variable outputs use a two-call, caller-owned-buffer convention. Call first with a null output
and zero capacity, allocate `required_output_length`, then call again. A size query with non-empty
output returns `ACTIVECHAIN_VERIFY_BUFFER_TOO_SMALL`; malformed domains, statements, responses, or
record envelopes fail closed.

The RPC service is a bounded TCP service, not HTTP. Prefix each generated request envelope with its
four-byte unsigned big-endian length and send it over the authenticated endpoint selected by the
deployment; read the response using the same framing and pass the response body (without the
length prefix) to the decoder. Apple applications should implement that transport with
`Network.framework` or an application-owned HTTPS gateway. They must not connect to an undocumented
LAN address, disable TLS validation, or infer trusted chain parameters from the response.

`testing/vectors/application/apple-anchor-client-v1.txt` freezes statement, reference, submit, and
resolve bytes. The shipped C and Swift consumers compile and exercise statement/request creation in
every Apple distribution slice.
