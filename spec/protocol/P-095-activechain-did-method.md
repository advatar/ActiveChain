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

## Operations

Creation, rotation, recovery, service updates, and deactivation are finalized state transitions.
Every operation is versioned, replay-protected, bound to the previous document commitment, and
authorized by the current controller policy. Recovery requires the explicitly configured recovery
policy; there is no implicit administrator key.

## Interoperability

Resolvers MUST expose the W3C DID 1.1 data model and JSON representation while retaining the
canonical binary document as the consensus representation. ENS names MAY reference an ActiveChain
DID as an alias, but ENS ownership alone MUST NOT authorize an ActiveChain transition.
