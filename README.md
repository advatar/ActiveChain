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
- a bounded, total APL evaluator with default deny, forbid precedence, fixed metering, and atomic obligations;
- an executable Lean APL effect model with proved decision properties and a Rust differential check;
- deterministic principal, authority, and APL test-vector generation;
- unit and property tests for codec safety, lifecycle binding, capability non-escalation, and policy semantics.

## Workspace

```text
crates/canonical-codec       consensus binary encoding
crates/protocol-types        canonical IDs, principals, authenticators, capabilities
crates/protocol-commitment   SHAKE256/384 commitment transcript
crates/principal             pure principal lifecycle state machine
crates/capability            mechanical delegation attenuation
crates/policy-kernel         bounded APL AST, requests, evaluation, decisions
formal/lean/                 executable APL effect model and proofs
schema/                      canonical schema source
spec/protocol/               normative protocol drafts
testing/vectors/             cross-implementation fixtures
tools/vector-generator/      deterministic vector producer
```

All six protocol, authority, and policy crates compile with `#![no_std]` and `#![forbid(unsafe_code)]`. The vector generator and Lean model are host verification tooling outside the consensus kernel.

## Verify locally

The repository pins Rust 1.97.1. Run:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo check --locked --target aarch64-apple-ios --lib -p activechain-canonical-codec -p activechain-protocol-types -p activechain-protocol-commitment -p activechain-principal -p activechain-capability -p activechain-policy-kernel
cargo test --locked --workspace --all-features
cargo test --locked --workspace --doc
cargo run --locked --quiet -p activechain-vector-generator -- principal-v1
cargo run --locked --quiet -p activechain-vector-generator -- authority-v1
cargo run --locked --quiet -p activechain-vector-generator -- apl-v1
cd formal/lean && lake build
```

Implementation progress is tracked in `STATUS.md` and the linked milestone issues, including [APL issue #3](https://github.com/advatar/ActiveChain/issues/3).

CI runs on the repository's dedicated macOS ARM64 self-hosted runner. Its pinned installation, operations, and security boundary are documented in `docs/ci/self-hosted-runner.md`.
