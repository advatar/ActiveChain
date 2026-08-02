# P-095: `did:activechain` method

- Status: Draft 0.1
- Protocol version: Development

`did:activechain` is the DID method for ActiveChain principals. It is a resolver and lifecycle
profile over finalized ActiveChain state; it is not a second identity ledger.

## Method-specific identifier

The identifier is the lowercase multibase encoding of the domain-separated SHAKE256 commitment of
the canonical `PrincipalId` and method version. It MUST NOT be derived from a classical key or an
ENS name. The same principal commitment always resolves to the same method-specific identifier.

## DID Document

Resolution returns only the current public controller record: ML-DSA authentication methods,
ML-KEM key-agreement methods, optional SLH-DSA recovery methods, verification relationships, and
service endpoints. Credentials, attributes, transaction history, and private state MUST NOT be
embedded in the document.

The canonical `DidDocumentV1` is ordered and bounded. It contains one stable `PrincipalId`, one to
eight public authentication descriptors, one to four ML-KEM-768 agreement methods, and an optional
service-set commitment. Authentication and agreement method identifiers MUST be strictly increasing
and MUST be unique across both sets.

Only ML-DSA-65 or ML-DSA-87 methods may have the control role. Recovery methods use the recovery
role and may use ML-DSA-65, ML-DSA-87, or SLH-DSA-SHAKE-192s. Agreement methods MUST use exactly
ML-KEM-768 and its 1,184-byte public encapsulation-key encoding. A KEM method cannot authorize a
signature, and a signature method cannot appear in the key-agreement relationship.

`DidControllerRecordV1` commits independently to the complete canonical document, authentication
methods, agreement methods, recovery methods, and services. A resolver or lifecycle transition
MUST recompute all five bindings; accepting caller-provided section commitments is forbidden.

## Operations

Creation, rotation, recovery, service updates, and deactivation are finalized state transitions.
Every operation is versioned, replay-protected, bound to the previous document commitment, and
authorized by the current controller policy. Recovery requires the explicitly configured recovery
policy; there is no implicit administrator key.

`DidOperationAuthorizationV1` binds the immutable chain-genesis commitment, exact canonical
operation commitment, authorizer method identifier, suite, and signature. Update and deactivation
require a current active control method. Recovery requires a current active recovery method.
Verification MUST dispatch by the method suite and MUST NOT fall back between ML-DSA and SLH-DSA.
The next record increments the sequence exactly once and must commit to the supplied next document.

Deactivation produces an inactive record. Inactive records reject update, recovery, and repeated
deactivation before signature processing. Resolution after deactivation returns the stable DID and
finalized height with no public controller document; no later operation may resurrect it.

Light clients persist `DidResolutionCheckpointV1`, containing the stable DID, last finalized
height, sequence, exact record commitment, and terminal deactivation flag. A checkpoint rejects a
lower height or sequence, a different record at the same sequence, a different DID, and every
resolution after deactivation. The new document, authorization, and checkpoint envelopes are
additive v1 types; existing `DidControllerRecordV1` bytes retain their schema and decode unchanged.

Native wallets sign only the `DidOperationAuthorizationV1` payload through an opaque custody
callback. The callback receives no operation alternatives and returns only a suite-exact
signature. Rust re-verifies that signature under the supplied public method before releasing the
canonical authorization envelope; private key material never crosses the FFI boundary.

## Interoperability

Resolvers MUST expose the W3C DID 1.1 data model and JSON representation while retaining the
canonical binary document as the consensus representation. ENS names MAY reference an ActiveChain
DID as an alias, but ENS ownership alone MUST NOT authorize an ActiveChain transition.
