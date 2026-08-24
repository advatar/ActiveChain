# ActiveChain Wallet for Android

The app queries the canonical TLS RPC endpoint at `rpc.kanalen.actum.network:443` and accepts
network status only when the returned chain ID, genesis commitment, protocol revision, and schema
revision exactly match Kanalen. Status decoding is bounded and canonical; malformed, stale,
unavailable, or incompatible responses are shown explicitly.

Balances, assets, activity, approvals, identity, credentials, transfers, and funding remain
unavailable until Android has proof-bearing owner queries, secure profile provisioning, and a
signing/submission path. The UI never substitutes sample or optimistic wallet data. Persisted agent
authority is decoded through the versioned Rust FFI, and an empty registry stays empty.

The checked-in Gradle 8.7 wrapper invokes `scripts/build-android-wallet-library.sh`, builds the
exact checkout for `arm64-v8a` with NDK 28.2, and packages the resulting shared library without
checking it into Git. Gradle 8.7 and JDK 17 are the supported defaults for Android Gradle Plugin
8.6; use the wrapper instead of a host-installed Gradle.

From `mobile/android`, run:

```text
ANDROID_HOME="$ANDROID_SDK_ROOT" ./gradlew testDebugUnitTest assembleDebug
ANDROID_HOME="$ANDROID_SDK_ROOT" ./gradlew connectedDebugAndroidTest
```

The first command validates the canonical RPC and approval codecs and builds the APK. The second
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
