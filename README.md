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
- versioned post-quantum suite identifiers, exact key/signature structure, and bounded authenticators;
- pure principal creation, rotation, freeze, and recovery-initiation transitions;
- signed capability grants and conservative multi-dimensional delegation attenuation;
- deterministic principal and authority test-vector generation;
- unit and property tests for codec safety, lifecycle binding, and capability non-escalation.

## Workspace

```text
crates/canonical-codec       consensus binary encoding
crates/protocol-types        canonical IDs, principals, authenticators, capabilities
crates/protocol-commitment   SHAKE256/384 commitment transcript
crates/principal             pure principal lifecycle state machine
crates/capability            mechanical delegation attenuation
schema/                      canonical schema source
spec/protocol/               normative protocol drafts
testing/vectors/             cross-implementation fixtures
tools/vector-generator/      deterministic vector producer
```

All five protocol and authority crates compile with `#![no_std]` and `#![forbid(unsafe_code)]`. The vector generator is ordinary host tooling and is outside the consensus kernel.

## Verify locally

The repository pins Rust 1.97.1. Run:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo check --locked --target aarch64-apple-ios --lib -p activechain-canonical-codec -p activechain-protocol-types -p activechain-protocol-commitment -p activechain-principal -p activechain-capability
cargo test --locked --workspace --all-features
cargo test --locked --workspace --doc
cargo run --locked --quiet -p activechain-vector-generator -- principal-v1
cargo run --locked --quiet -p activechain-vector-generator -- authority-v1
```

Implementation progress is tracked in `STATUS.md`, [bootstrap issue #1](https://github.com/advatar/ActiveChain/issues/1), and [authority-kernel issue #2](https://github.com/advatar/ActiveChain/issues/2).

CI runs on the repository's dedicated macOS ARM64 self-hosted runner. Its pinned installation, operations, and security boundary are documented in `docs/ci/self-hosted-runner.md`.
