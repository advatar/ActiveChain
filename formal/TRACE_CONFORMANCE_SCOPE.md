# Implementation-trace conformance scope

`testing/proof-conformance-v1.tsv` is the canonical inventory connecting every
in-repository Lean, Tamarin, TLA+, Verus, and Kani proof domain to a production
witness. Its classifications have precise meanings:

- `differential` means an executable production observation is compared with
  a frozen independent table, checked expression, or strict round-trip oracle.
- `trace` means a deterministic positive/negative production trace exercises
  the modeled boundary, but no compiler-level refinement theorem is claimed.
- `external-boundary` means the formal property has no honest executable
  production witness. The fair timed liveness result is classified this way
  because scheduler fairness and eventual delivery are environment assumptions.

The gate validates canonical matrix order and uniqueness, existence of both
artifacts in every row, allowed classifications, vector-manifest uniqueness and
SHA-256 integrity, malformed-vector presence, all generator↔frozen-vector and
Rust↔Lean table tests, arbitrary checked-arithmetic comparison, and durable
snapshot mutation tests. It also audits that duplicate, missing-field,
reordered, and substituted metadata would be rejected.

This matrix is coverage evidence, not a universal refinement proof. Frozen
traces cover selected executions; Tamarin cryptographic abstractions, TLA+
fairness, cryptographic primitive internals, compiler correspondence, operating
system durability, and external review remain separate assumptions or gates.
