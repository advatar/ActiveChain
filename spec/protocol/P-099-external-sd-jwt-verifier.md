# P-099: External SD-JWT VC presentation verifier

## 1. Isolation boundary

The SD-JWT VC/OpenID4VP adapter runs outside consensus and performs no network access. Every
verification call receives bounded presentation bytes and pinned issuer, trust, schema, subject,
status, chain, action, audience, nonce, purpose, response-URI, time, and policy inputs. Consensus
receives only `VcIssuerPresentationV1`; it never parses JSON, JWT, OAuth metadata, certificates,
disclosures, or personal attributes.

## 2. Closed profile

The initial profile is VCIssuer `dc+sd-jwt` using ES256, SHA-256 disclosure digests, and an ES256
`kb+jwt`. The verifier rejects unknown algorithms, types, critical extensions, duplicate JSON
keys, malformed base64url/JSON/compact framing, excess bytes/depth/counts, and profiles absent
from the finalized `ExternalIssuerBindingV1`. The issuer URL and pinned signing JWK MUST commit to
the binding's exact external and trust identities.

## 3. Verification order

The verifier authenticates the issuer JWS and validity interval; validates every disclosure digest
and rejects duplicate/injected disclosures; authenticates the holder JWK from `cnf`; validates the
key-binding JWS, `sd_hash`, nonce, audience, purpose, response URI, and time; then validates the
exact finalized external status root and issuance-log policy. Only then may it create the
schema-selected, action-bound predicate and handoff.

Certificate and trust-list processing occurs before this deterministic API. Its result is the
pinned JWK whose commitment is checked here; unavailable, stale, conflicting, substituted, or
revoked trust material therefore supplies no admissible input.

## 4. Privacy and diagnostics

Logs expose only `SdJwtRejection` codes and request correlation data generated outside credential
content. Raw credentials, salts, disclosures, claim names/values, holder keys, and identifiers MUST
not enter logs or consensus state. Commitments domain-separate the unchanged issuer JWT,
disclosure set, holder JWK, predicate value, nonce, issuer authorization, and status snapshot.

## 5. Replay and recovery

`SdJwtReplayCache` consumes a presentation commitment only after full success. Its sorted bounded
entries are persisted atomically and revalidated on restart. Replays fail closed. Trust/status
refresh, cache persistence, outage grace, monitoring, and key recovery are operator procedures;
none may silently relax the pinned inputs or policy limits.
