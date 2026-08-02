# Contributing to ActiveChain

Thank you for helping build ActiveChain. Contributions are welcome across protocol design, Rust,
formal verification, independent clients, wallets, documentation, testing, and operations.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues
must follow [SECURITY.md](SECURITY.md), not the public issue tracker.

## Before you start

1. Read the [README](README.md), [architecture guide](docs/ARCHITECTURE_GUIDE.md), and relevant
   normative documents under [`spec/protocol/`](spec/protocol/).
2. Search existing issues and pull requests. Use one issue and one implementation branch for one
   coherent scope.
3. For substantial protocol, compatibility, security, or architecture changes, open an issue before
   implementation. Explain the problem, invariants, alternatives, migration impact, and evidence
   needed for acceptance.
4. Keep readiness claims narrow. Implemented, tested, formally modeled, audited, deployed, and
   production-ready are different states.

Good first contributions are focused documentation corrections, malformed-input fixtures,
cross-implementation vector checks, isolated tests, and small implementation gaps already described
by an issue.

## Set up the repository

```sh
git clone --recurse-submodules https://github.com/advatar/ActiveChain.git
cd ActiveChain
cargo metadata --locked --no-deps >/dev/null
```

Rust is pinned by [`rust-toolchain.toml`](rust-toolchain.toml). Optional surfaces require their own
toolchains: Lean/Elan and Tamarin for formal models, Kani for bounded model checking, Go for the
independent verifier, and Apple/Android tooling for native clients.

## Make a change

- Branch from current `origin/main` using a descriptive name such as `feat/123-short-scope`,
  `fix/123-short-scope`, or `docs/123-short-scope`.
- Avoid drive-by formatting, generated files, editor state, credentials, build outputs, or unrelated
  changes.
- Preserve `no_std`, allocation bounds, canonical encodings, domain separation, and
  `#![forbid(unsafe_code)]` where the affected crate requires them.
- Add unit tests for new behavior and negative tests for malformed, substituted, replayed,
  out-of-range, or downgraded inputs.
- Update specifications, vectors, formal artifacts, status, and documentation when their claims or
  contracts change.
- Never silently weaken a verifier, security boundary, assurance level, or fail-closed condition to
  make a test pass.

## Verify locally

During development, run focused checks for the changed boundary:

```sh
cargo fmt --all --check
cargo test --locked -p <affected-package>
cargo clippy --locked -p <affected-package> --all-targets --all-features -- -D warnings
```

Run the relevant script or model check when changing vectors, formal artifacts, FFI, protocol tags,
or compatibility contracts. The complete deterministic kernel gate is expensive and maintainer
controlled; it runs on the exact merge candidate. A narrow check may support iteration but cannot
justify a broad production or protocol-completion claim.

Documentation-only changes should validate links, paths, examples, and any commands they publish.
The repository's focused community-documentation check is:

```sh
python3 scripts/check-community-docs.py
```

## Commit and pull request guidance

- Use clear imperative commit messages with a useful scope, for example
  `feat(cash): reject replayed reward receipts`.
- Keep the pull request small enough to review as one argument.
- Link the issue and describe the user-visible or protocol-visible outcome.
- List exact verification commands and results, including intentionally skipped gates.
- Call out compatibility, migration, security, privacy, performance, and operational effects.
- Identify generated artifacts and how they were reproduced.
- Respond to review with additional commits on the same branch.

Maintainers may request that large proposals first become a versioned specification or design note.
Acceptance is based on correctness, scope, evidence, maintainability, and alignment with documented
protocol boundaries—not only on passing tests.

## Documentation conventions

- Use repository-relative links and name the authoritative source for a claim.
- Mark normative requirements clearly; implementation notes must not silently redefine a protocol.
- Include status and maturity language for developmental or unaudited surfaces.
- Prefer concise examples that can be checked locally.
- Update [`docs/README.md`](docs/README.md) when adding a new major document family.

## Developer Certificate of Origin

By contributing, you certify that you have the right to submit the work under this repository's
[Apache-2.0 license](LICENSE). Add a `Signed-off-by` trailer if a maintainer or automation policy
requests it. The project does not currently require a separate contributor license agreement.
