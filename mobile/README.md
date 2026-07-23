# ActiveChain mobile wallets

This directory contains testable iOS and Android shells over `activechain-wallet-core`.
The iOS agent-management flow uses the versioned Rust FFI registry and atomically persists its
canonical snapshot. Build its exact-HEAD XCFramework and app project from a clean checkout with:

```text
scripts/build-ios-wallet-app.sh
```

Other `LocalWalletBridge` paths and the Android agent registry remain deterministic integration
mocks; they do not claim production cryptography or secure storage. The remaining work is the
Android JNI/NDK bridge and platform keystore callback providers.
