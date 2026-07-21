# ActiveChain Wallet Android shell

The Kotlin shell in `ActiveChainWallet/src/main` is a deterministic local developer wallet. It
exercises the same policy preview and approval contract as iOS. Wire it into an Android Studio
Gradle application target, then replace `LocalWalletBridge` with the versioned Rust FFI library
before handling real keys or funds.
