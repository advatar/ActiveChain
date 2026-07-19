# ActiveChain

ActiveChain is being built as a formally specified, proof-carrying object ledger with explicit principals, credentials, capabilities, policies, objects, jobs, and verification evidence.

The implementation is deliberately starting below networking and consensus. The current Phase 0 slice establishes one deterministic meaning for protocol values before any distributed system is allowed to depend on them.

## What exists now

- draft system-boundary, canonical-encoding, and transition specifications under `spec/protocol/`;
- an initial canonical schema in `schema/activechain.idl`;
- distinct 384-bit protocol identifier types;
- a `no_std`, unsafe-free, allocation-bounded canonical codec;
- strict rejection of wrong tags, unsupported versions, malformed lengths, invalid values, and trailing bytes;
- SHAKE256 commitments with 384-bit output and registered domain separation;
- a deterministic principal test-vector generator and published vector;
- unit and property tests for round trips, bounds, malformed input, semantic validation, and domain/type separation.

## Workspace

```text
crates/canonical-codec       consensus binary encoding
crates/protocol-types        primitive IDs and Principal v1
crates/protocol-commitment   SHAKE256/384 commitment transcript
schema/                      canonical schema source
spec/protocol/               normative protocol drafts
testing/vectors/             cross-implementation fixtures
tools/vector-generator/      deterministic vector producer
```

The three protocol crates compile with `#![no_std]` and `#![forbid(unsafe_code)]`. The vector generator is ordinary host tooling and is outside the consensus kernel.

## Verify locally

The repository pins Rust 1.97.1. Run:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo test --locked --workspace --doc
cargo run --locked --quiet -p activechain-vector-generator
```

Implementation progress is tracked in `STATUS.md` and [GitHub issue #1](https://github.com/advatar/ActiveChain/issues/1).
