# Independent Go verifier (v1.0 M0 plus canonical-codec M1 slice)

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
That is one M1 semantic family, not completion of M1. It still does not decode schema bodies,
verify ML-DSA signatures, execute transitions, or replay finalized roots, and is not M2 evidence.
The v1.0 complexity budget, staffing requirement, and launch decision are recorded in P-134.
