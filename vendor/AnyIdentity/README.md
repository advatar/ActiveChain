# AnyIdentity

A Swift 6 package backed by a Rust cryptographic protocol core through a versioned C FFI. It implements the portable person-authority primitives described in BRIEF1.md: identity evidence bound to user keys, multi-root assurance, continuity, pairwise keys, and constrained action/delegation signatures.

**Reference implementation, not a production identity service.** Native government credential verification, same-person biometric linkage, anonymous identity proofs and distributed status/recovery infrastructure are integration or research boundaries. See [protocol and security model](Documentation/PROTOCOL.md). The [patent/FTO investigation](Documentation/FTO_AND_PATENTS.md) finds substantial prior art and does not establish legal clearance.

## Build and run

Requirements: macOS, Xcode with macOS/iOS SDKs, Swift 6+, and rustup. `rust-toolchain.toml` pins Rust 1.97.1. No Swift package dependencies are fetched; Rust dependencies are locked in `rust/Cargo.lock`.

```sh
# Once, if the pinned toolchain is not already installed:
rustup toolchain install 1.97.1 --profile minimal --component rustfmt --component clippy

# Build universal macOS, iOS device and universal iOS Simulator static libraries:
./scripts/build-rust.sh --all

swift test
swift run AuthorityDemo

# Full Rust lint/test, Apple artifact rebuild, Swift tests and example:
./scripts/test.sh
```

A faster local build is `./scripts/build-rust.sh --host`; it replaces the artifact with a host-only macOS slice. Use `--all` before iOS integration or distribution. Build and test this package serially. The builder invalidates this package's SwiftPM build cache so changed native code is relinked.

The generated `Artifacts/CAnyIdentity.xcframework` is deliberately excluded from source control. **Build it before opening the package or resolving it as a local dependency.** This checkout uses a local SwiftPM binary target. To distribute through a Git-based SwiftPM URL without a bootstrap step, publish the XCFramework as a versioned release archive and change the binary target to its URL and checksum, or vendor the artifact. No release hosting/remote repository has been configured.

```swift
.package(path: "/path/to/AnyIdentity")
// Consumer target:
.product(name: "AnyIdentity", package: "AnyIdentity")
```

Supported deployment targets: macOS 13+, iOS 16+. The Rust build produces arm64/x86_64 macOS, arm64 iOS and arm64/x86_64 Simulator slices. No simulator is needed for the macOS tests.

## Integrating into `../../ActiveChain`

These instructions match the sibling checkout inspected on 2026-09-09. They describe integration work for ActiveChain; this package does not already install an ActiveChain adapter or change its protocol.

### Add the dependency

From the **ActiveChain repository root**, bootstrap the Apple artifact first:

```sh
(cd ../Packages/AnyIdentity && ./scripts/build-rust.sh --all)
```

The shipping iOS/macOS apps are defined in `mobile/ios/ActiveChainWalletApp/project.yml`. They compile `../ActiveChainWallet/Sources/ActiveChainWallet` directly; updating the standalone wallet package alone does **not** add this dependency to the apps. Add the following entries to the existing XcodeGen configuration, merging the dependency entries into each existing target:

```yaml
packages:
  AnyIdentity:
    path: ../../../../Packages/AnyIdentity

targets:
  ActiveChainWallet:
    dependencies:
      - package: AnyIdentity
        product: AnyIdentity
  ActiveChainWalletMac:
    dependencies:
      - package: AnyIdentity
        product: AnyIdentity
```

Retain the existing `ActiveChainWallet.xcframework` dependency and all other target settings/sources. SwiftPM supplies `CAnyIdentity` transitively; do not add its archive a second time. Regenerate the project from the ActiveChain root:

```sh
xcodegen generate \
  --spec mobile/ios/ActiveChainWalletApp/project.yml \
  --project mobile/ios/ActiveChainWalletApp
```

For code also built through **`mobile/ios/ActiveChainWallet/Package.swift`**, its manifest should additionally declare the dependency. This is the complete replacement for that checkout's current minimal manifest:

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ActiveChainWallet",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "ActiveChainWallet", targets: ["ActiveChainWallet"])],
    dependencies: [.package(path: "../../../../Packages/AnyIdentity")],
    targets: [
        .target(name: "ActiveChainWallet", dependencies: [
            .product(name: "AnyIdentity", package: "AnyIdentity")
        ]),
        .testTarget(name: "ActiveChainWalletTests", dependencies: ["ActiveChainWallet"])
    ]
)
```

Both relative paths resolve to this checkout from their respective configuration directories. Use a **Swift 6+ compiler**, even with the consumer manifest/language mode at 5.9. The apps' existing iOS 17/macOS 14 deployment targets already meet this package's minimums. CI must check out both repositories in the same layout and build the ignored XCFramework before dependency resolution. After rebuilding Rust, clean the **consumer's** build products/DerivedData before relinking; the script only cleans AnyIdentity's own SwiftPM cache.

### Place the identity check before native signing

For MCP proposals, the existing app boundary is `RustCanonicalApproval.reviewProposal(_:finalizedHeight:)` in `ActiveChainWalletApp/Sources/RustCanonicalApproval.swift`. Its result is `CanonicalMcpProposalApproval`; its public Swift initializer alone is not proof that Rust validated the bytes.

Use this sequence:

1. Review the canonical intent with ActiveChain's Rust reviewer and authenticated finalized height. Check the expected chain, wallet, native principal/capability and application policy using ActiveChain's existing path.
2. Load the person's pinned AnyIdentity state, trusted attestor roots, policy and authenticated fresh revocation snapshot. Issue and persist an unpredictable, single-use identity challenge bound to this proposal and the intended verifier audience.
3. Build the expected AnyIdentity action from the reviewed **exact intent bytes** and stored challenge metadata. Have the person's enrolled AnyIdentity key approve it after displaying the native proposal details.
4. Verify the signed action and trusted identity evidence with a long-lived `AuthorityVerifier`. Stop on any error. Record durable acceptance/idempotency before a retryable side effect.
5. Continue through `CanonicalMcpProposalApprovalSession.sign(with:slotID:minimumVersion:finalizedHeight:)` and the existing native lifecycle/submission path. Require the identity result to remain within `AuthorizedAction.validUntil`; revalidate identity state/status if execution is delayed. Recheck native expiry and policy at signing/submission time. The existing session re-reviews the intent and enforces one-shot signing.

AnyIdentity is an **additional application identity-policy gate**, using classical Ed25519 rather than post-quantum identity signatures. ActiveChain's native signatures, finalized proofs, capabilities, replay checks and admission rules still determine native authority. An `AuthorizedAction` is a local result, not an ActiveChain credential or consensus proof. The current `RustAgentRegistryStore.prepareEnrollment` unavailable-submission boundary also needs its own implementation; identity approval does not complete agent enrollment.

### Typed proposal-binding example

The following helper compiles against the two public packages. In the shipping app, omit `import ActiveChainWallet`: those types are compiled directly into `ActiveChainWalletApp`. The operation/resource names below define an example application profile; use the same versioned mapping at the signer and verifier.

```swift
import Foundation
import AnyIdentity
import ActiveChainWallet

enum IdentityApprovalError: Error {
    case invalidWindow
    case oversizedEnvelope
}

func identityAction(
    for approval: CanonicalMcpProposalApproval,
    state: AuthorityState,
    audience: String,
    nonce: String,
    issuedAt: UInt64,
    expiresAt: UInt64
) throws -> Action {
    // Metadata comes from the verifier's stored challenge, not the reply.
    guard expiresAt > issuedAt, expiresAt - issuedAt <= 120 else {
        throw IdentityApprovalError.invalidWindow
    }
    let operation: String
    switch approval.action {
    case .transfer: operation = "activechain.mcp.v1.transfer"
    case .submitAnchor: operation = "activechain.mcp.v1.submitAnchor"
    }
    let proposalHex = approval.proposalID.map { String(format: "%02x", $0) }.joined()
    return Action(
        authorityId: state.authorityId,
        epoch: state.epoch,
        audience: audience,
        nonce: nonce,
        operation: operation,
        resource: "activechain:proposal:" + proposalHex,
        payloadDigest: try AnyIdentity.sha256(approval.intent),
        issuedAt: issuedAt,
        expiresAt: expiresAt
    )
}

// Holder side: expected must describe the proposal the person reviewed.
func signIdentityApproval(expected: Action, personKey: IdentityKey) throws -> Data {
    try AnyIdentity.encode(AnyIdentity.sign(expected, key: personKey))
}

// Verifier side: reuse the actor for this pinned authority across requests.
func checkIdentityApproval(
    verifier: AuthorityVerifier,
    expected: Action,
    signedJSON: Data,
    evidence: [Signed<Evidence>],
    now: UInt64
) async throws -> AuthorizedAction {
    guard signedJSON.count <= 1_048_576 else {
        throw IdentityApprovalError.oversizedEnvelope
    }
    let signed = try AnyIdentity.decode(Signed<Action>.self, from: signedJSON)
    return try await verifier.verifyAndConsume(
        action: signed, expected: expected, evidence: evidence, now: now
    )
}
```

Construct and retain the actor with `AuthorityVerifier(state:roots:policy:revocations:)` from authenticated configuration. Obtain `expected` by calling `identityAction` with a Rust-reviewed proposal, pinned state and the **original stored** audience/nonce/issuedAt/expiresAt. The verifier reconstructs it independently; never use `signed.payload` as `expected`. Use current trusted Unix seconds for verification `now`, not the stored issuance time. Choose a stable audience specific to the service/environment; the intent digest binds the native chain, wallet, recipient, amounts and agent fields. ActiveChain's agent-supplied `requestNonce` remains bound through the intent bytes but does not replace the verifier-owned challenge.

This example uses direct holder signing (`chain: []` by default). For delegated signing, supply the verified root-to-leaf `[Signed<Delegation>]` chain to `verifyAndConsume`; use the same operation/resource/audience profile and `AnyIdentity.digest(parent)` for parent references. Native ActiveChain agent registration/capability authorization remains a separate requirement, including an authenticated binding if an AnyIdentity delegate key is associated with a native principal.

### Values that must stay distinct

| Concern | AnyIdentity | ActiveChain integration rule |
|---|---|---|
| Signing keys | Software Ed25519; 32-byte public key represented as 64 hex characters | ActiveChain uses native ML-DSA-44 custody. Maintain separate keys and records; never reuse its seed or treat an identity signature as native authorization. |
| Identifiers and commitments | SHA-256 digests represented as 64 hex characters | Native proposal/principal commitments here are 48 bytes. Preserve them; `sha256(approval.intent)` is only the additional identity transcript binding. |
| Expiry | `UInt64` Unix seconds | `expiresAtHeight` is a block height. Enforce both clocks independently; never cast height into an identity timestamp. |
| Amounts | Optional `UInt64` minor units, paired with a three-uppercase-letter currency | Native proposal amount/fee use `Unsigned128Words`. The example omits identity monetary fields and relies on native policy for amount/fee limits. No implicit truncation or invented fiat conversion. |
| Serialization | Versioned signed JSON and Rust schema normalization | Preserve ActiveChain canonical bytes. Use `AnyIdentity.encode/decode` for transport and `digest` for signed-envelope references; hashing JSON transport is not an equivalent envelope digest. |
| Lifecycle evidence | Signed identity envelopes and local assurance result | `McpProposalLifecycleStore.transition` expects 48-byte native evidence. Do not put identity JSON or a 32-byte digest there. Store an associated identity audit record separately until an explicit native mapping is designed. |

Identity delegation amount limits, when used, apply **per action**, not cumulatively. A missing optional bound is not a spending budget. Operations, resources and audiences match exactly; there is no wildcard interpretation.

### Application responsibilities before deployment

- **Enrollment and attestors:** provision a separate `IdentityKey`, create/pin its authority once, then obtain evidence bound to that authority/current key. Implement `IdentityEvidenceAdapter` with real issuer signature, holder-binding, status and freshness checks before `attest`. Validate enrollment against a stored one-use challenge. The core does not verify raw passports/mdoc/SD-JWT credentials or prove same-person convergence. Never ship the demo's synthetic roots as trust configuration.
- **Trust configuration:** pin roots and independence groups outside claimant input; choose required claims and assurance levels for the actual action. Each counted independent root must support the required claims. Authenticate revocation snapshots at ingestion; do not make an empty snapshot with a fresh timestamp to simulate a status check. Unsigned `Assurance` is not portable evidence.
- **Custody:** persist AnyIdentity's own seed only under an explicitly separate Keychain service/tag and access policy, with authentication as required. `IdentityKey(seed:)`/`exportSeed()` are storage hooks, not a Keychain implementation. This FFI signs in software and has no external hardware-signer callback. Secure Enclave wrapping does not make Ed25519 signing hardware-backed. Pairwise keys do not inherit identity evidence automatically.
- **Durability:** the verifier actor's replay cache and authority transitions are process-local. Persist consumed challenges, pinned epochs and status freshness across restarts/replicas; coordinate them with proposal lifecycle/idempotent submission. A successful `verifyAndConsume` consumes the challenge even if later native signing fails. Recovery/retry requires recorded state or a newly issued challenge, not a bypass. Rotation/recovery needs atomic state persistence and fresh evidence/delegations for the new key/epoch.
- **Transport and failures:** bound all incoming envelopes/evidence/chains before decoding; the FFI also caps each JSON request at 1 MiB. Fail closed on `AnyIdentityError`, stale evidence/status, replay, clock rollback and cache capacity errors. Log error codes and proposal references without credentials, seeds or unnecessary personal claims.

Before shipping the ActiveChain integration, verify both Rust libraries link together in the actual iOS/macOS apps. Exercise mismatched intent, chain/wallet/audience, expired height/time, revoked or rotated keys, missing assurance, delegated scope violations, replay across restart and a native-signing failure after identity acceptance. The helper was compiled against both public packages; the shipping app integration and these end-to-end checks are still consumer work. Package-level checks are recorded in [validation](Documentation/VALIDATION.md).

For a runnable standalone flow, `swift run AuthorityDemo` demonstrates two **synthetic** identity roots, an agent's bounded booking authority and replay rejection. See [protocol and security model](Documentation/PROTOCOL.md) for exact signing, delegation and transition rules.

## Tanzanian identity

See [Tanzanian digital identity research](Documentation/TANZANIA_IDENTITY.md) for NIDA access routes, Jamii Namba/Pocket findings, provider candidates and a proposed backend attestor using `IdentityEvidenceAdapter`. It identifies access prerequisites, holder-to-key binding, data handling and the work needed for an ActiveChain pilot. No Tanzanian verification adapter or live provider connection is implemented yet.

## API map

| Swift API | Purpose |
|---|---|
| `IdentityKey` | OS-random keys; seed import/export; exact-audience HKDF derivation; native key ownership |
| `createAuthority`, `enroll` | Genesis state and holder-signed enrollment challenge |
| `IdentityEvidenceAdapter`, `attest` | External credential-verification boundary and signed normalized evidence |
| `assess` | Trusted-root, independence, claim, assurance, freshness and revocation policy |
| `approveTransition`, `applyTransition` | Rotation or pinned-quorum recovery, replacement-key possession, monotonic epoch |
| `delegate`, `sign`, `verifyAction` | Delegation chains and signed actions with exact scope, audience, time and request binding |
| `AuthorityVerifier.verifyAndConsume` | Combined identity/authority validation with actor-isolated in-process replay prevention |
| `encode`, `decode`, `digest`, `evidenceReference` | Wire transport and normalized revocation/parent references |

Rust owns private keys and signature/policy logic. Swift never holds a seed unless explicitly importing/exporting it. Returned FFI JSON is freed immediately after decoding; immutable native keys support concurrent reads and are freed when the Swift owner deinitializes.

## Project contents

- `rust/src`: cryptography, protocol validation, FFI and negative tests.
- `Sources/AnyIdentity`: typed public models, safe FFI ownership and verifier actor.
- `Sources/CAnyIdentity/include`: public C header/module map used by the XCFramework.
- `Tests/AnyIdentityTests`: integration tests, independent CryptoKit verification and concurrent replay checks.
- `Documentation`: protocol/security model, preliminary patent report, search log, dependency notices and delivery status.

The project has no public-source licence selected. Third-party licences remain applicable; no patent licence is granted by this repository.
