# Validation and delivery record

Date: 2026-09-09. Host: Apple Silicon macOS, Swift 6.3.3, Xcode-selected Apple SDKs. Rust compiler and rustdoc: rustup 1.97.1, explicitly selected by scripts to avoid Homebrew/rustup mixing.

## Executed checks

| Check | Result |
|---|---|
| Locked Rust unit tests and doc-test invocation | 17 unit tests passed; zero doc tests; command succeeded |
| Rust clippy for all targets with warnings denied | Passed |
| Swift Testing macOS integration suite | 11 tests passed |
| Independent cryptographic check | Rust-produced action signature verified by Apple's CryptoKit |
| Native distribution build | All five architectures compiled; three-slice XCFramework created |
| Xcode generic iOS Simulator build | Passed, unsigned |
| Xcode generic iOS device build | Passed, unsigned |
| AuthorityDemo | Two independent synthetic roots accepted, delegated action accepted, replay rejected, pairwise keys differ |

Xcode builds were serial. No simulator test session or disposable XCTest simulator clone set was created, so XCTest clone cleanup was not applicable. The iOS checks establish compilation, not runtime behavior on a device. Runtime FFI tests ran on arm64 macOS; Intel and iOS runtime execution were not tested.

Regression coverage includes RFC 8032 and SHA-256 vectors; malformed C requests; typed signature contexts; proof-of-possession challenges; forged/misbound/stale/revoked identity evidence; duplicate roots; policy claims and hardware requirements; normal rotation; threshold recovery; revoked guardians; epoch rollback; exact audience/resource/operation/amount/currency/merchant checks; child attenuation; ancestor revocation; no-redelegation; signature tampering; JSON round trips; key lifetime/import/export; replay capacity and clock rollback; and concurrent duplicate submissions.

The Swift suite exposed optional JSON omission changing parent/revocation hashes. Digest operations now normalize the payload schema before hashing and verify its signature. A Rust regression test and Swift revocation/subdelegation tests cover the fix. SwiftPM also retained previously linked static code after copying an updated XCFramework; the build script now cleans the generated SwiftPM cache after replacing the native artifact.

## Reproduce

```sh
./scripts/test.sh
xcodebuild -scheme AnyIdentity -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath .build/xcode CODE_SIGNING_ALLOWED=NO build
xcodebuild -scheme AnyIdentity -destination 'generic/platform=iOS' \
  -derivedDataPath .build/xcode CODE_SIGNING_ALLOWED=NO build
```

Run these sequentially. `scripts/test.sh` rebuilds the full XCFramework and invalidates this package's SwiftPM cache before testing. It does not launch simulator tests. `--host` can be used for faster macOS-only development, but does not produce the full distribution artifact.

## Delivery boundaries

- This is a reference core, not a production identity network. Native government credential adapters, cryptographic same-person convergence, anonymous inherited-assurance proofs, hardware signing, distributed/persistent status and replay infrastructure, and complete device-loss recovery of pairwise accounts are not implemented. See PROTOCOL.md.
- No formal cryptographic review, fuzzer campaign, vulnerability audit, platform identity certification, or live issuer interoperability test was completed.
- Patent research is preliminary. Official grant/dossier, SE/UK territorial status, prosecution history and full-system claim analysis remain open. See FTO_AND_PATENTS.md.
- The supplied directory initially contained only BRIEF1.md and PATENT.md, with no Git repository/remote. A local source repository was initialized for the implementation. Original briefs remain unchanged and outside the implementation commit.
- A GitHub destination was requested but not supplied. The issue exists as Documentation/TRACKING_ISSUE.md; no remote issue, push or hosted SwiftPM binary release was created.
- The generated XCFramework is available in this workspace and ignored by Git; source checkouts require the documented bootstrap build before SwiftPM resolution.
