# ActiveChain Wallet for Android

The app queries the canonical TLS RPC endpoint at `rpc.kanalen.activechain.dev:443` and accepts
network status only when the returned chain ID, genesis commitment, protocol revision, and schema
revision exactly match Kanalen. Status decoding is bounded and canonical; malformed, stale,
unavailable, or incompatible responses are shown explicitly.

The app loads a device-local, backup-excluded owner profile and performs the same bounded,
owner-scoped Coin Cell query as the Apple wallet. Records reach the UI only after the linked Rust
verifier binds the canonical key, owner, finalized height, proof, finality bundle, and live Kanalen
genesis. Empty or rejected proof sets never become an optimistic zero balance. Testnet funding uses
the canonical faucet terms/request/receipt protocol and exposes honest unavailable, requesting,
pending, finalized, and rejected states; only a subsequent verified owner query can affect wallet
state.

Android also mirrors the Apple receive-request binding, OpenWallet credential/session replay seam,
canonical agent-enrollment validation, and one-shot platform routes for agent management and
approval review. Persisted agent authority is decoded through the versioned Rust FFI, and an empty
registry stays empty. Transfers, assets, activity, and credentials remain visibly unavailable when
their finalized evidence is absent; the UI never substitutes sample or optimistic wallet data.

The checked-in Gradle 8.7 wrapper invokes `scripts/build-android-wallet-library.sh`, builds the
exact checkout for `arm64-v8a` with NDK 28.2, and packages the resulting shared library without
checking it into Git. Gradle 8.7 and JDK 17 are the supported defaults for Android Gradle Plugin
8.6; use the wrapper instead of a host-installed Gradle.

From `mobile/android`, run:

```text
ANDROID_HOME="$ANDROID_SDK_ROOT" ./gradlew testDebugUnitTest assembleDebug
ANDROID_HOME="$ANDROID_SDK_ROOT" ./gradlew connectedDebugAndroidTest
```

The first command validates canonical status, owner-page, faucet, receive, OpenWallet, enrollment,
routing, custody, and approval behavior and builds the APK. The second
also exercises the shared approval vector through JNI, native ML-DSA-44 custody, one-shot signing,
and Rust submission verification on an arm64 emulator or device.

The custody implementation writes its versioned ML-DSA-44 slot record under `noBackupFilesDir` and
wraps the seed with a per-use authenticated Android Keystore AES-GCM key. StrongBox is preferred;
hardware-isolated TEE is the explicit fallback. The AES key never signs an ActiveChain transaction.
Rotation, revocation, finalized-height rollback protection, recovery metadata binding, wrong-key
failure, and plaintext-buffer clearing have host unit coverage. The canonical approval session
rechecks the Rust-owned human review, consumes authorization before signing, and sends only the
Rust-derived payload into custody. `BiometricPromptAuthorizer` authenticates that exact Keystore
cipher through an AndroidX `BiometricPrompt.CryptoObject` on a custody worker, maps cancellation,
lockout, and unavailable hardware to fail-closed custody results, and permits only the first
terminal callback to complete an attempt. Production transfers remain disabled until physical-
device StrongBox/TEE/backup qualification and independent review pass; this app must not handle
production keys or funds yet.
