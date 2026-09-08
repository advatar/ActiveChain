# ActiveChain Wallet Apple apps

The generated Xcode project references the exact-HEAD Rust binary at
`dist/apple/current/ActiveChainWallet.xcframework`. From the repository root, prepare that
distribution, regenerate the project, and build the current developer wallets with:

```bash
scripts/build-ios-wallet-app.sh
scripts/build-macos-wallet-app.sh
```

Run the real iOS fresh-wallet faucet acceptance test from a clean, committed checkout:

```bash
scripts/test-ios-wallet-e2e.sh
```

The runner requires a healthy pinned public Kanalen RPC, builds the exact revision's Rust
distribution, and creates a new iPhone 17 Pro simulator on iOS 26.5. Override
`ACTIVECHAIN_IOS_E2E_RUNTIME` or `ACTIVECHAIN_IOS_E2E_DEVICE_TYPE` with installed simulator
identifiers if needed. It runs the dedicated `ActiveChainWalletLiveE2E` scheme serially, with
separate DerivedData and an `.xcresult` under `tmp/ios-wallet-e2e.*`. The normal unit-test scheme
does not issue live faucet requests.

The test requires fresh onboarding, acknowledges the disposable identity's recovery key, proves
an initial zero balance, requests the real faucet, refreshes until the receipt finalizes at a
new height, requires positive owner-proof-verified Coin Cells, and checks persistence after
relaunch. A stale network, existing wallet, rejected/disabled faucet, timeout, zero balance, or
unverified proof fails the test. Recovery secrets are never deliberately attached or copied.
Treat local XCTest diagnostics as private, since automatic UI failure capture can include the
recovery screen.

The runner prints and retains the dedicated simulator UUID and its wallet for inspection, then
shuts it down. Reopen it with `xcrun simctl boot <UUID>` and Simulator. Each invocation creates
a new identity; remove only that UUID with `xcrun simctl delete <UUID>` when finished. Disposable
XCTest clones are cleaned only when no other `xcodebuild` is active; existing interactive
simulators and wallets are preserved. This qualifies the live iOS application/network path;
physical-device user-presence and recovery qualification remains separate because simulator
custody already omits the user-presence gate at compile time.

`project.yml` is the source of truth and preserves the ActiveChain Apple development-team ID across
regeneration. Certificates, private keys, Xcode user data, and build state remain local and must not
be committed. If Xcode reports that `ActiveChainWallet.xcframework` is missing, close it and rerun
the appropriate script from a clean checkout.

Before uploading an archive, run
`scripts/validate-apple-app-icon.sh /path/to/ActiveChainWallet.app`. The validator requires a
compiled asset catalog and `CFBundleIcons.CFBundlePrimaryIcon.CFBundleIconName = AppIcon`.

Both targets use the shared Keychain Access Group
`$(AppIdentifierPrefix)dev.activechain.wallet.shared`. The macOS target uses the Data Protection
Keychain for compatible access-group behavior. Items remain device-bound by default; callers must
explicitly request iCloud Keychain synchronization for non-authorizing wallet metadata. Secure
Enclave and transaction-authorization records must remain device-specific.

The custody implementation stores a versioned ML-DSA-44 slot record as
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. A user-presence-gated Secure Enclave P-256 key is
used only to wrap the ML-DSA-44 seed; P-256 is never ActiveChain transaction authority. Rotation,
revocation, finalized-height rollback protection, and an independently encrypted recovery envelope
are covered by the macOS-hosted unit suite. The canonical approval callback is one-shot, recomputes
the Rust-owned review before custody access, and requests user presence only for the exact signing
payload. Production signing remains disabled until the wire-compatible native ML-DSA-44 engine is
connected and physical-device recovery/user-presence qualification passes.

The dashboard obtains Kanalen health and finalized height from the canonical TLS-framed status RPC
at `rpc.kanalen.actum.network`. It pins the immutable chain ID, genesis commitment, protocol
revision, and RPC schema before reporting health. It does not synthesize balances, assets,
activity, approvals, credentials, identities, agents, fees, or finality. Persisted agent
registrations are displayed only when they exist.

Kanalen exposes bounded proof-bearing owner-scoped Coin Cell discovery. When a real device profile
is already present, the app queries its exact owner and publishes records only after the linked Rust
verifier binds their canonical key, owner, authenticated cash root, finalized height, validator
certificate, and trusted genesis. Balance aggregation and transfers remain disabled until the
wallet has verified spendable inputs, a distinct fee reserve, and production signing material.
Multi-asset Coin Cells and native asset tokenization are tracked in issues #163 and #164.
