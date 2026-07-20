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
- canonical off-chain credentials with issuer-bound signatures and status-registry snapshots;
- a pure status/freshness-aware credential verifier that derives bounded APL schema facts;
- a bounded, total APL evaluator with default deny, forbid precedence, fixed metering, and atomic obligations;
- an executable Lean APL effect model with proved decision properties and a Rust differential check;
- versioned objects, bounded disjoint access manifests, and atomic APL-authorized transfer batches;
- executable Lean models for APL effects, object versioning, and atomic publication;
- a canonical fixed-depth sparse state tree with compressed membership and non-membership witnesses;
- executable Lean models for state-key paths and abstract 16-way proof folding;
- bounded typed ObjectVM bytecode, a static resource/control-flow verifier, and a prepaid-gas interpreter;
- executable Lean models for ObjectVM copy/move/consume resource semantics and instruction costs;
- public action envelopes with exact nonce channels, one-shot fee tickets, and six-dimensional resource ceilings;
- a pure deterministic block kernel with canonical action/block identifiers, receipts, charges, and post-state roots;
- a minimal semantic-devnet host and an executable Lean nonce/replay model;
- an executable Lean credential-status model with required/future/stale/revoked precedence;
- deterministic principal, authority, credential, APL, transition, state-tree, ObjectVM, action, and block vectors;
- unit and property tests for codec safety, authority, policy, transitions, proofs, bytecode, execution, admission, and block application.

## Workspace

```text
crates/canonical-codec       consensus binary encoding
crates/action-kernel         public action admission values and replay semantics
crates/cash-kernel           native Coin Cell money and deterministic issuance
crates/bytecode-verifier     typed ObjectVM bytecode and static verification
crates/protocol-types        canonical IDs, principals, authenticators, capabilities
crates/protocol-commitment   SHAKE256/384 commitment transcript
crates/principal             pure principal lifecycle state machine
crates/capability            mechanical delegation attenuation
crates/credential            issuer/status-aware credential presentation verification
crates/policy-kernel         bounded APL AST, requests, evaluation, decisions
crates/object                exact one-step object ownership transitions
crates/object-vm             deterministic metered reference interpreter
crates/transition            access-confined atomic transfer reference kernel
crates/state-tree            canonical sparse state commitment and witnesses
crates/wallet-core           OpenWallet-aligned PQ wallet intents and Coin Cell selection
crates/devnet-kernel         pure deterministic single-node block application
formal/lean/                 executable APL/object/state-tree models and proofs
node/semantic-devnet/        minimal host shell around the pure block kernel
schema/                      canonical schema source
spec/protocol/               normative protocol drafts
testing/vectors/             cross-implementation fixtures
tools/vector-generator/      deterministic vector producer
```

All fourteen protocol and semantic-kernel crates compile with `#![no_std]` and `#![forbid(unsafe_code)]`. The semantic-devnet executable, vector generator, and Lean models are host tooling outside the consensus kernel.

### Testnet wallet POC

Derive a deterministic post-quantum wallet identity for local testnet genesis and operator
rehearsals:

```sh
cargo run -p activechain-wallet-core --bin activechain-wallet -- derive 0 1 0
```

The command prints the ML-DSA suite, principal commitment, and public key. Secret material is not
printed or persisted by the CLI; production keystore encryption and node submission are separate
wallet milestones.

## Verify locally

The repository pins Rust 1.97.1. Run:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo check --locked --target aarch64-apple-ios --lib -p activechain-action-kernel -p activechain-bytecode-verifier -p activechain-canonical-codec -p activechain-credential -p activechain-devnet-kernel -p activechain-protocol-types -p activechain-protocol-commitment -p activechain-principal -p activechain-capability -p activechain-cash-kernel -p activechain-policy-kernel -p activechain-object -p activechain-object-vm -p activechain-transition -p activechain-state-tree
cargo test --locked --workspace --all-features
cargo test --locked --workspace --doc
cargo run --locked --quiet -p activechain-vector-generator -- principal-v1
cargo run --locked --quiet -p activechain-vector-generator -- authority-v1
cargo run --locked --quiet -p activechain-vector-generator -- credential-v1
cargo run --locked --quiet -p activechain-vector-generator -- apl-v1
cargo run --locked --quiet -p activechain-vector-generator -- object-transition-v1
cargo run --locked --quiet -p activechain-vector-generator -- state-tree-v1
cargo run --locked --quiet -p activechain-vector-generator -- object-vm-v1
cargo run --locked --quiet -p activechain-vector-generator -- devnet-block-v1
cargo run --locked --quiet -p activechain-semantic-devnet -- empty-block
cd formal/lean && lake build
```

Implementation progress is tracked in `STATUS.md` and the linked milestone issues, including [credential verification issue #8](https://github.com/advatar/ActiveChain/issues/8).

CI runs on the repository's dedicated macOS ARM64 self-hosted runner. Its pinned installation, operations, and security boundary are documented in `docs/ci/self-hosted-runner.md`.
