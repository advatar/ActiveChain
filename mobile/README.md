# ActiveChain mobile wallets

This directory contains testable iOS and Android shells over `activechain-wallet-core`.
The iOS agent-management flow uses the versioned Rust FFI registry and atomically persists its
canonical snapshot. Build its exact-HEAD XCFramework and app project from a clean checkout with:

```text
scripts/build-ios-wallet-app.sh
```

The Android shell builds its arm64 JNI library as a Gradle prerequisite and persists the same
canonical registry format. Other `LocalWalletBridge` paths remain deterministic integration mocks;
they do not claim production cryptography or secure storage. Platform keystore callback providers
remain a separate release gate.
