# ActiveChain Wallet Android shell

The Kotlin shell uses the versioned Rust FFI library for agent lifecycle and durable canonical
registry state. Gradle invokes `scripts/build-android-wallet-library.sh`, builds the exact checkout
for `arm64-v8a` with NDK 28.2, and packages the resulting shared library without checking it into
Git.

From `mobile/android`, run:

```text
ANDROID_HOME="$ANDROID_SDK_ROOT" gradle testDebugUnitTest assembleDebug
ANDROID_HOME="$ANDROID_SDK_ROOT" gradle connectedDebugAndroidTest
```

The first command runs JVM tests and builds the APK. The second proves JNI lifecycle transitions
and snapshot reload on an arm64 emulator or device. `LocalWalletBridge` transaction paths remain
deterministic developer integrations until Android Keystore callbacks are connected; this shell
must not handle production keys or funds yet.
