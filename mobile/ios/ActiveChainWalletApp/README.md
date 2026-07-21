# ActiveChain Wallet iOS app

Build and run the current developer wallet in the simulator:

```bash
xcodegen generate
xcodebuild -project ActiveChainWallet.xcodeproj -scheme ActiveChainWallet \
  -sdk iphonesimulator CODE_SIGNING_ALLOWED=NO build
```

The app exercises policy-gated transfer preview/approval and OpenWallet credential/session
replay rules. It uses deterministic local adapters until the Rust FFI library is linked into the
Xcode target. No production signing or key material is present in this developer build.
