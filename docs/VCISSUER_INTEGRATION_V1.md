# VCIssuer integration profile v1

`VCIssuer` is the credential-issuance edge; ActiveChain is the authorization and settlement
boundary. The issuer speaks OpenID4VCI and produces profiled SD-JWT VC or mdoc credentials. Those
portable credentials stay in the holder wallet and are not submitted to consensus.

## Native identity model

ActiveChain natively supports:

- `Principal`: stable identities for people, organizations, devices, services, pseudonyms, and
  agents, independent of rotating controller keys;
- `did:activechain`: a finalized resolver view of a principal's public controller lifecycle;
- `Credential`: an issuer-signed, off-chain claim whose canonical statement binds issuer, subject,
  schema, claims commitment, validity, status registry, issuance log, and terms;
- `Capability`: scoped authority that may be delegated only by attenuation;
- APL policy: deterministic default-deny authorization over verified credential and capability
  facts;
- private/pairwise holder bindings, predicate proofs, nullifiers, and assurance-preserving receipts.

A principal is not automatically a legal identity. A DID is not a credential. A credential is not
authority unless the action's policy accepts its issuer, schema, status, assurance, holder binding,
and predicate.

## Adapter flow

1. The wallet obtains a VCIssuer offer and completes OpenID4VCI issuance.
2. For an action, the wallet consents to an OpenID4VP disclosure or zero-knowledge predicate.
3. A profiled verifier validates format signatures, issuer authorization/trust lists, holder proof,
   status, freshness, and the exact disclosure/predicate.
4. The verifier constructs `VcIssuerPresentationV1`. It contains commitments only and embeds a
   `CredentialPredicateV1` bound to chain, audience, action, nonce, policy revision, and expiry.
5. APL consumes the verified fact. The receipt records format, assurance, verifier/proof versions,
   policy commitment, and outcome without recording raw PID, mdoc, SD-JWT claims, or a stable
   cross-context subject identifier.

The v1 format allowlist is closed to SD-JWT VC and mdoc. Unknown formats, zero evidence,
self-issued assurance, stale predicates, and substituted chain/audience/action contexts fail
closed. VCIssuer's experimental hybrid-PQ wrapper is not an EUDI credential and is not accepted by
this profile until separately standardized and registered.

## Deployment boundary

This profile implements the canonical ActiveChain handoff and unit-tested rejection boundary. A
production deployment still requires pinned VCIssuer profiles and trust lists, wallet consent UX,
OpenID4VP transport, status operations, cross-repository vectors, device qualification, data
protection review, and independent security/interoperability review.
