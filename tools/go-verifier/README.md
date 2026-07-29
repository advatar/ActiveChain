# Independent Go verifier (v1.0 M2 gate)

This module is intentionally standard-library-only and does not import the Rust
workspace. It validates the published v1 TSV contract: strict headers, bounded
records, unique case identifiers, explicit accept/reject outcomes, and the
independence negative case. Run from this directory with:

```sh
go test ./...
go run . -vectors ../../testing/vectors
```

This is the conformance-surface gate for M2, not a claim that Go already
reimplements every consensus plane. The v1.0 complexity budget and funding
decision are recorded in `spec/protocol/P-134-independent-client.md`.
