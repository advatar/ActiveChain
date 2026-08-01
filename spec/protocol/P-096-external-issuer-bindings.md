# P-096: External issuer bindings

## 1. Boundary

An external credential issuer is accountable on ActiveChain through a stable `PrincipalId`, but
that principal is not itself an EUDI legal identity. `ExternalIssuerBindingV1` binds the principal
to commitments over a normalized external issuer identifier, trust-list or certificate identity,
and an explicit ordered allowlist of credential profiles. Consensus never parses URLs, OAuth
metadata, JSON, X.509, SD-JWT, COSE, mdoc, or rulebook documents.

## 2. Normalization and commitments

External adapters MUST normalize issuer URLs and profile identifiers under their registered
profile before hashing them. The protocol consumes only nonzero `Digest384` commitments. Each
profile commits its credential-configuration identifier, credential type, rulebook identifier and
positive version, rulebook digest, and signing certificate/key identity. There is no wildcard,
prefix, fallback, display-name, or caller-supplied schema admission.

## 3. Lifecycle

Sequence 1 has no previous commitment and enters `Active`. Every successor increments the sequence
by exactly one, commits the complete previous binding, and preserves chain, genesis, issuer
principal, and external issuer identity. `Active` may rotate in place, suspend, supersede, or
retire. `Suspended` may resume, rotate, supersede, or retire. `Superseded` and `Retired` are
terminal. Trust/profile/signing changes are therefore explicit versioned transitions; a changed
legal external identity requires a separate binding.

## 4. Registry

`ExternalIssuerRegistryV1` stores at most 64 current bindings in strict `PrincipalId` order and
rejects duplicate external identities. Updates advance finalized height, reject rollback, and
validate the lifecycle. Resolution returns a binding only at or below the registry's finalized
height and while its half-open validity interval is active.

## 5. Security and privacy

Bindings contain no certificate bodies, credentials, attributes, personal data, OAuth metadata,
or status lists. A bound issuer principal may issue only profiles in its explicit allowlist.
External presentation verification, status proofs, and profile-to-schema mapping remain separate
bounded adapters. Cross-network, previous-state, issuer, external-identity, trust, rulebook,
profile, signing-key, lifecycle, and finalized-height substitution fail closed.
