# Independent Go verifier (v1.0 M0 plus identity M1 slices)

This module is intentionally standard-library-only and does not import the Rust
workspace. It validates the published v1 TSV contract: strict headers, bounded
records, unique case identifiers, explicit accept/reject outcomes, and the
independence negative case. Run from this directory with:

```sh
go test ./...
go run . -vectors ../../testing/vectors
```

The verifier now independently implements strict canonical-envelope framing: exact type/schema,
minimal bounded ULEB128 lengths, exact bodies, and fail-closed truncation/trailing-data handling.
It also independently decodes the fixed Principal v1 body and enforces its closed kind/freeze
enums and creation/update ordering. AuthenticatorDescriptor v1 additionally enforces the closed PQ
suite registry, exact public-key sizes, purpose compatibility, and temporal bounds. These are
joined by complete CapabilityGrant v1 structural decoding and parent/child attenuation checks for
holders, actions, scopes, ceilings, validity, delegation, revocation, constraints, and signature
suite/length framing. These are partial M1 semantic families, not completion of M1.
It still does not decode other schema bodies,
verify ML-DSA signatures, execute transitions, or replay finalized roots, and is not M2 evidence.
The v1.0 complexity budget, staffing requirement, and launch decision are recorded in P-134.
