# ActiveChain Wallet Apple apps

The generated Xcode project references the exact-HEAD Rust binary at
`dist/apple/current/ActiveChainWallet.xcframework`. From the repository root, prepare that
distribution, regenerate the project, and build the current developer wallets with:

```bash
scripts/build-ios-wallet-app.sh
scripts/build-macos-wallet-app.sh
```

`project.yml` is the source of truth and preserves the ActiveChain Apple development-team ID across
regeneration. Certificates, private keys, Xcode user data, and build state remain local and must not
be committed. If Xcode reports that `ActiveChainWallet.xcframework` is missing, close it and rerun
the appropriate script from a clean checkout.

Both targets use the shared Keychain Access Group
`$(AppIdentifierPrefix)dev.activechain.wallet.shared`. The macOS target uses the Data Protection
Keychain for compatible access-group behavior. Items remain device-bound by default; callers must
explicitly request iCloud Keychain synchronization for non-authorizing wallet metadata. Secure
Enclave and transaction-authorization keys must remain device-specific.

The app exercises policy-gated transfer preview/approval and OpenWallet credential/session
replay rules. It uses deterministic local adapters until the Rust FFI library is linked into the
Xcode target. No production signing or key material is present in this developer build.
