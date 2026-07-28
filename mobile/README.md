# ActiveChain mobile wallets

This directory contains testable iOS, macOS, and Android shells over `activechain-wallet-core`.
The Apple agent-management flow uses the versioned Rust FFI registry and atomically persists its
canonical snapshot. Build the exact-HEAD XCFramework and app project from a clean checkout with:

```text
scripts/build-ios-wallet-app.sh
scripts/build-macos-wallet-app.sh
```

The Android shell builds its arm64 JNI library as a Gradle prerequisite and persists the same
canonical registry format. The shipping apps do not expose the deterministic `LocalWalletBridge`
integration paths. Transfers, funding, agent submission/revocation, and other authority-changing
network operations remain unavailable until validator ingress, verified finality, and platform
keystore callback providers are connected.

Amber, ActiveChain's first native reference application, lives in `apple/AmberApp`. It uses one
shared SwiftUI source set for iOS and macOS and is deliberately separate from the wallet shell.
