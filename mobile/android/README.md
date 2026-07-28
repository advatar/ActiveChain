# ActiveChain Wallet for Android

The app queries the canonical TLS RPC endpoint at `rpc.kanalen.activechain.dev:443` and accepts
network status only when the returned chain ID, genesis commitment, protocol revision, and schema
revision exactly match Kanalen. Status decoding is bounded and canonical; malformed, stale,
unavailable, or incompatible responses are shown explicitly.

Balances, assets, activity, approvals, identity, credentials, transfers, and funding remain
unavailable until Android has proof-bearing owner queries, secure profile provisioning, and a
signing/submission path. The UI never substitutes sample or optimistic wallet data. Persisted agent
authority is decoded through the versioned Rust FFI, and an empty registry stays empty.

Gradle invokes `scripts/build-android-wallet-library.sh`, builds the exact checkout for `arm64-v8a`
with NDK 28.2, and packages the resulting shared library without checking it into Git.

From `mobile/android`, run:

```text
ANDROID_HOME="$ANDROID_SDK_ROOT" gradle testDebugUnitTest assembleDebug
ANDROID_HOME="$ANDROID_SDK_ROOT" gradle connectedDebugAndroidTest
```

The first command validates the canonical RPC codec and builds the APK. The second verifies that an
empty device registry does not create or persist sample agent authority on an arm64 emulator or
device. `LocalWalletBridge` transaction paths remain deterministic developer integrations until
Android Keystore callbacks are connected; this app must not handle production keys or funds yet.
