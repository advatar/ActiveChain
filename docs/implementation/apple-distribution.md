# Reproducible Apple distribution

ActiveChain’s Apple distribution contains two binary products:

- `ActiveChainVerifier.xcframework`
- `ActiveChainWallet.xcframework`

Each contains arm64 macOS, iOS-device, and iOS-simulator slices. The accompanying `Package.swift`
exposes both as local SwiftPM binary targets. This is a developmental integration artifact, not an
independent security certification or a production-wallet endorsement.

## Exact-source build

On a clean macOS checkout with Xcode and the pinned Rust toolchain:

```text
scripts/build-apple-distribution.sh dist/ActiveChainKit "$(git rev-parse HEAD)"
scripts/check-apple-distribution.sh dist/ActiveChainKit
```

The build refuses a revision other than checked-out `HEAD` and refuses a dirty worktree. CI installs
the pinned `aarch64-apple-ios` and `aarch64-apple-ios-sim` targets before invoking it.

`scripts/check-apple-reproducibility.sh` builds the distribution twice from the same clean revision,
compares every byte, and then runs the consumer qualification.

## Generated headers

`activechain-apple-distribution` runs pinned `cbindgen` against the verifier and wallet FFI crates.
The checked-in headers are generated outputs:

```text
cargo run --locked -p activechain-apple-distribution -- sync-headers .
cargo run --locked -p activechain-apple-distribution -- check-headers .
```

CI runs the drift check. Callback declarations receive one deterministic C ABI normalization
because Rust represents nullable function pointers as `Option<extern "C" fn>` while C represents
the same ABI as a nullable function-pointer typedef. Any unexpected cbindgen shape fails
generation.

## Compatibility manifest

`activechain-compatibility.json` records:

- the full source revision;
- verifier, wallet, RPC, light-client, and protocol revisions;
- every downstream verifier/wallet canonical schema and type tag;
- the exact Apple target slices;
- SHA-256 for every packaged file;
- a fail-closed upgrade policy; and
- `developmental-unaudited` / `independently_audited: false`.

The verifier rejects unknown manifest formats, changed ABI/schema/protocol revisions, altered
release status, missing slices, unsorted or malformed hashes, and any artifact substitution.
Manifest verification does not replace signature verification on a release channel; consumers
must obtain the manifest and archive hash from the intended release source.

## Consumer qualification

The qualification script:

1. verifies every manifest hash;
2. compiles, links, and runs clean C and Swift macOS consumers;
3. compiles and links clean Swift consumers against both iOS-device libraries;
4. compiles and links clean Swift consumers against both iOS-simulator libraries; and
5. asks SwiftPM to load the packaged binary-target manifest.

The consumers query ABI/schema/protocol revisions before accepting the library. Application code
must likewise fail closed on an unsupported revision.

## Publication

The `Apple distribution` workflow runs on version tags and manual dispatch. It builds the exact
GitHub revision, repeats consumer qualification, uploads the distribution archive, and publishes
its SHA-256 as workflow artifacts. Independent audit completion remains a separate external launch
gate documented in `docs/SECURITY_AUDIT.md`.
