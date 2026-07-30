# Independent Go verifier (v1.0 M0 reader)

This module is intentionally standard-library-only and does not import the Rust
workspace. It validates the published v1 TSV contract: strict headers, bounded
records, unique case identifiers, explicit accept/reject outcomes, and the
independence negative case. Run from this directory with:

```sh
go test ./...
go run . -vectors ../../testing/vectors
```

This is an M0 parser/independence smoke check only. It does not decode canonical envelopes,
verify ML-DSA signatures, execute transitions, or replay finalized roots, and therefore is not M1
or M2 evidence. The v1.0 complexity budget, required staffing, and launch decision are recorded in
`spec/protocol/P-134-independent-client.md`.
