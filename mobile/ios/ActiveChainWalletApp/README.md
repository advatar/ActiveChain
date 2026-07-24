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

Before uploading an archive, run
`scripts/validate-apple-app-icon.sh /path/to/ActiveChainWallet.app`. The validator requires a
compiled asset catalog and `CFBundleIcons.CFBundlePrimaryIcon.CFBundleIconName = AppIcon`.

Both targets use the shared Keychain Access Group
`$(AppIdentifierPrefix)dev.activechain.wallet.shared`. The macOS target uses the Data Protection
Keychain for compatible access-group behavior. Items remain device-bound by default; callers must
explicitly request iCloud Keychain synchronization for non-authorizing wallet metadata. Secure
Enclave and transaction-authorization keys must remain device-specific.

The dashboard obtains Kanalen health and finalized height from the canonical TLS-framed status RPC
at `rpc.kanalen.activechain.dev`. It does not synthesize balances, assets, activity, approvals,
credentials, identities, agents, fees, or finality. Persisted agent registrations are displayed
only when they exist.

Kanalen does not yet expose proof-bearing owner-scoped Coin Cell discovery, so the wallet reports
balance and assets as unavailable and keeps transfers disabled. Multi-asset Coin Cells and native
asset tokenization are tracked in issues #163 and #164. The app exercises policy-gated transfer
preview/approval and OpenWallet credential/session replay rules, but no production signing or key
material is present in this developer build.
