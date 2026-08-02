# ActiveChain

[![Deterministic kernel](https://github.com/advatar/ActiveChain/actions/workflows/kernel.yml/badge.svg?branch=main)](https://github.com/advatar/ActiveChain/actions/workflows/kernel.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.97.1](https://img.shields.io/badge/rust-1.97.1-orange.svg)](rust-toolchain.toml)

ActiveChain is an experimental, proof-carrying object ledger for post-quantum payments,
verifiable identity, explicit authorization, bounded computation, and independently verifiable
state transitions. The public-facing protocol is presented as **Actum**; crate and repository names
retain the `activechain` prefix while that naming transition is completed.

The project treats principals, credentials, capabilities, policies, assets, objects, actions,
proofs, and receipts as canonical protocol values. Deterministic Rust kernels, cross-implementation
vectors, executable formal models, and explicit security boundaries are developed together.

> [!WARNING]
> ActiveChain is developmental software. No independent security audit has been completed. The
> wallet, testnet, cryptography integration, proof systems, and APIs may change and must not be used
> to protect real value. See [Security status](#security-status) and [SECURITY.md](SECURITY.md).

## Why ActiveChain?

- **Post-quantum authorization:** versioned ML-DSA, ML-KEM, and SLH-DSA roles with explicit
  downgrade and lifecycle boundaries.
- **Native identity semantics:** stable principals, rotating control, issuer/status-aware
  credentials, selective disclosure inputs, and attenuating capabilities.
- **Proof-carrying execution:** deterministic kernels, transparent proof profiles, proof admission,
  and independently checkable receipts.
- **Native payments and assets:** Coin Cell accounting, fee and issuance rules, multi-asset
  lifecycle operations, and proof-aware payment integration.
- **Bounded systems:** canonical encodings, total policy evaluation, metered ObjectVM execution,
  authenticated storage, and explicit resource ceilings.
- **Verification-first development:** Rust tests, malformed-input vectors, Lean and Tamarin models,
  Kani harnesses, and independent Go verifier components.

The design is intentionally ambitious. A checked box in [STATUS.md](STATUS.md) means a bounded
repository milestone was implemented; it does not imply production readiness, external audit, or
completion of every end-to-end composition gate.

## Current maturity

Implemented repository surfaces include:

- canonical protocol types, domain-separated commitments, principals, credentials, capabilities,
  APL authorization, objects, transitions, ObjectVM, sparse state witnesses, and action admission;
- authenticated post-quantum consensus/finality components, data availability, light-client and
  verifier APIs, deterministic vectors, and formal refinement artifacts;
- native cash and multi-asset kernels, wallet and FFI boundaries, payment SDK/connector surfaces,
  faucet and developmental testnet operations;
- VCIssuer/OpenID4VCI presentation handoff, external SD-JWT VC and mdoc verification boundaries,
  private credential predicates, and assurance-preserving policy facts;
- transparent PQ-ZK and CashAIR components, including authenticated SHAKE, NTT arithmetic tables,
  bounded aggregation statements, and proof-admission boundaries;
- bounded validator storage, archive, pruning, rent, checkpoint synchronization, replay
  accumulators, and storage qualification tools;
- constrained MCP/A2UI agent interfaces, a private-billboard reference application, and native
  Apple/Android wallet shells.

Important unfinished work remains. In particular, production security review, complete ML-DSA
cross-table composition inside CashAIR, production interoperability qualification, deployment
hardening, and several launch gates remain open. The authoritative implementation ledger is
[STATUS.md](STATUS.md); security claims are bounded by
[docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).

## Architecture at a glance

```text
wallet / application / agent
        │ canonical intent + authenticated authority + private proof inputs
        ▼
principal + credential + capability + APL authorization
        │ bounded action and declared state access
        ▼
cash / asset / object / ObjectVM / application transition kernels
        │ receipts + state commitments + proof obligations
        ▼
consensus + data availability + authenticated storage
        │ finalized evidence
        ▼
wallet, light client, verifier API, RPC, and independent clients
```

Start with the [architecture guide](docs/ARCHITECTURE_GUIDE.md). Normative protocol drafts live in
[`spec/protocol/`](spec/protocol/); implementation notes and operational evidence do not override
those specifications. The [documentation index](docs/README.md) explains the distinction.

## Quick start

### Prerequisites

- Git with submodule support;
- the Rust toolchain pinned in [`rust-toolchain.toml`](rust-toolchain.toml) (rustup installs it
  automatically);
- optional: Lean/Elan, Tamarin, Kani, Go, Docker, Xcode, and Android Studio for their respective
  verification or platform surfaces.

Clone the repository and its landing-page submodule:

```sh
git clone --recurse-submodules https://github.com/advatar/ActiveChain.git
cd ActiveChain
cargo metadata --locked --no-deps >/dev/null
```

Run a small deterministic kernel test:

```sh
cargo test --locked -p activechain-canonical-codec
```

Generate a canonical principal vector:

```sh
cargo run --locked --quiet -p activechain-vector-generator -- principal-v1
```

Derive a deterministic developmental wallet identity:

```sh
cargo run --locked -p activechain-wallet-core --bin activechain-wallet -- derive 0 1 0
```

The wallet command prints public test identity material only. Production keystore and network
submission requirements are separate launch gates.

## Repository map

| Path | Purpose |
| --- | --- |
| [`crates/`](crates/) | Consensus-safe kernels, protocol types, proof systems, storage, wallet, verifier, RPC, payment, and application libraries |
| [`node/semantic-devnet/`](node/semantic-devnet/) | Host executable around deterministic protocol kernels |
| [`connectors/`](connectors/) | Bounded external payment connector implementations |
| [`spec/protocol/`](spec/protocol/) | Normative, versioned protocol drafts |
| [`schema/`](schema/) | Canonical schema source |
| [`formal/`](formal/) | Lean and Tamarin models, proof scope, and refinement artifacts |
| [`testing/vectors/`](testing/vectors/) | Deterministic valid, malformed, and cross-implementation fixtures |
| [`tools/`](tools/) | Vector generation, distribution, benchmarking, and independent verifier tools |
| [`mobile/`](mobile/) | Shared mobile guidance and native Apple/Android clients |
| [`deploy/kanalen/`](deploy/kanalen/) | Developmental Kanalen testnet configuration and operations |
| [`LandingPage/`](LandingPage/) | Public website submodule |

Most protocol crates are `#![no_std]` and forbid unsafe Rust. Host, FFI, platform, operational, and
tooling crates have different constraints; check each crate before assuming a kernel guarantee.

## Development workflow

Choose checks proportional to your change while iterating:

```sh
cargo fmt --all --check
cargo test --locked -p <affected-package>
cargo clippy --locked -p <affected-package> --all-targets --all-features -- -D warnings
```

Changes to canonical encodings or protocol behavior should also update deterministic vectors,
malformed fixtures, normative specifications, and applicable formal/refinement evidence. The final
merge candidate is qualified by the repository's deterministic kernel gate; contributors do not
need to run every expensive proof and platform job for each small edit.

See [CONTRIBUTING.md](CONTRIBUTING.md) for branch, issue, test, documentation, commit, and pull
request expectations.

## Documentation

- [Documentation index](docs/README.md)
- [Architecture guide](docs/ARCHITECTURE_GUIDE.md)
- [Implementation status](STATUS.md)
- [Protocol specifications](spec/protocol/)
- [Formal models and proof scope](formal/README.md)
- [Testnet release boundary](docs/TESTNET_RELEASE.md)
- [Security audit requirement](docs/SECURITY_AUDIT.md)
- [VCIssuer integration](docs/VCISSUER_INTEGRATION_V1.md)
- [Mobile overview](mobile/README.md)

## Security status

No independent audit has been completed. Internal review, tests, formal models, and proof artifacts
are evidence inputs—not substitutes for the external audit and remediation process described in
[docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md). Testnets are developmental and may reset or change
incompatibly.

Please report suspected vulnerabilities privately according to [SECURITY.md](SECURITY.md). Do not
open a public issue for an unpatched vulnerability.

## Community and governance

- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Support](SUPPORT.md)
- [Governance](GOVERNANCE.md)

Project decisions currently use a maintainer-led, issue-and-PR process. Protocol changes require an
explicit specification and compatibility/security analysis; repository activity or a merged draft
does not itself establish a production network governance right.

## License

Licensed under the [Apache License 2.0](LICENSE).
