# ActiveChain mobile wallets

This directory contains testable iOS and Android shells over `activechain-wallet-core`.
The current `LocalWalletBridge` implementations are deterministic mocks for UI and integration
testing. They do not claim production cryptography or secure storage. The next step is replacing
the mock with the versioned Rust FFI bridge and platform keystore adapters.
