# EUDI / TLSNotary / ZK credential boundary v1

EU Wallet and TLSNotary components produce and custody credentials off-chain. ActiveChain
receives a versioned presentation or zero-knowledge predicate, not raw identity documents,
TLS transcripts, or unnecessary attributes.

## Binding

Every admitted predicate commits to the credential issuer and schema, holder binding, chain ID,
audience, action/asset, policy revision, nonce, expiry, and a finalized status-registry snapshot.
The verifier rejects missing, stale, revoked, cross-chain, cross-action, or replayed bindings.

## Selective disclosure

Predicates disclose only the minimum claim needed by policy: for example `over_18`, `not_us`, or
`not_north_korea`, without revealing age or nationality. The circuit proves the predicate against
the hidden claims commitment and issuer/status commitments. No KYC payload is written to chain.

## Failure and privacy

Unsupported credential formats, unknown issuers/schemas, stale status, malformed proofs, and
ambiguous jurisdiction fail closed. A verifier returns a typed rejection reason without exposing
the hidden value. Consent, retention, deletion, and off-chain evidence access remain governed by
the wallet/provider policy rather than consensus state.
