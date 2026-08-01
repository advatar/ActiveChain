# P-100: External mdoc presentation verifier

## 1. Separate closed profile

The mdoc adapter is distinct from the SD-JWT adapter and has no fallback parser. It accepts only
bounded base64url-encoded CBOR matching the VCIssuer ISO mdoc issuance shape: issuer-signed
namespaces, tag-24 issuer items and MSO, COSE_Sign1 tag 18, SHA-256 value digests, COSE ES256
algorithm `-7`, P-256 device keys, and explicitly admitted document types and namespaces.

## 2. Deterministic CBOR policy

The envelope is at most 96 KiB, with at most eight namespaces, 64 items per namespace, 4 KiB per
item, and nesting depth 16. Definite-length shortest-form CBOR is required by decode/re-encode
identity. Duplicate map keys, duplicate digest identifiers, unknown tags, indefinite-length or
non-shortest framing, excess collections, and unsupported algorithms fail closed. Verification
uses typed keys and never depends on map order or display strings.

## 3. Authentication pipeline

The verifier checks the finalized issuer/profile binding and pinned trust-key commitment, verifies
the COSE issuer signature over the exact `Signature1` structure, validates MSO version, document
type, validity, namespace and every disclosed issuer-item digest, and extracts the device key. It
then verifies device authentication over the exact session transcript, document type, disclosure
digest, nonce, audience, purpose, and response URI. Finally it checks the exact recent anchored
status/issuance roots and emits one `VcIssuerPresentationV1` bound to the requested chain action.

Certificate-chain and trust-list validation precede the deterministic API and provide the pinned
issuer JWK whose commitment is checked here. Stale, conflicting, substituted, or revoked trust
material cannot produce an admissible input.

## 4. Privacy and operations

Raw CBOR, certificates, namespaces, issuer items, device keys, session transcripts, and attribute
values remain outside consensus and redacted telemetry. Only typed rejection codes and
domain-separated commitments cross the adapter boundary. Operators persist replay state at the
OpenID4VP request layer and publish trust/status refresh, outage, recovery, and equivocation
procedures.
