# Composite identity proofs in the Apple wallet

The shared wallet and the iOS/macOS application targets use AnyIdentity from the requested
`/Users/johansellstrom/dev/advatar/Packages/AnyIdentity` package. The unchanged source snapshot is
vendored at `vendor/AnyIdentity`, revision `0d59e583a8641dccc08c6eb19ffe2c77696c7587`.
`distribution/anyidentity/source.json` pins every source file by SHA-256. Local paths are provenance;
CI builds the vendored snapshot and does not require that workstation checkout. Uncommitted work
in the original package was not copied. To update, deliberately replace the snapshot and manifest,
review the effective dependency change, rebuild, and run the full kernel gate.

Run `scripts/build-anyidentity.sh` before opening the generated Xcode project. It validates the pin
and builds the upstream Rust library for device, simulator, and universal macOS slices. App build
and live acceptance scripts call it automatically. Artifacts and build caches are not committed.
The wrapper packages the generated library as a static framework so its module map cannot collide
with the native wallet library in Xcode. The root Rust workspace excludes the independent vendored crate. Its formatting check uses upstream
Rust 2021 defaults, separate from ActiveChain's Rust 2024 formatting configuration.

## Profile and trust configuration

`CompositeIdentityProfile` holds public authority state and signed issuer evidence and supports
Codable persistence by the caller. `assess` requires a policy with at least two independent roots.
The caller supplies authenticated authority state, trusted issuer keys and independence groups,
assurance/claim requirements, a fresh revocation snapshot, and Unix time. Holder-provided roots
must never become trusted merely because they accompany a proof. Evidence revocation references
use `AnyIdentity.evidenceReference(issuer:id:)`, not the signed evidence digest.

No production issuer roots or credential adapters were provided. Consequently the faucet and normal
wallet onboarding do not require identity. The package integration provides profile assessment and
an optional approval gate; it does not claim that synthetic test credentials establish a real-world
identity. Production enrollment, issuer transport, authority rotation/recovery configuration, and
identity UI remain application policy work. Test seeds occur only in tests.

## Native approval integration

Application policy can create `CanonicalMcpProposalApprovalSession.requiringIdentity` with the
canonical intent, verified finalized block height, expected audience, and a configured
`CompositeIdentityApprovalVerifier`. The factory first obtains the actual native review from Rust.
Its returned `identityChallenge` can be sent to the holder, who signs `challenge.expected` with
AnyIdentity and returns `CompositeIdentityProof(action:evidence:delegation:)` encoded as JSON.

The verifier owns the random 256-bit challenge, expected audience, operation, native proposal ID,
and SHA-256 of the exact reviewed intent bytes. The holder cannot choose the expected action.
Challenge lifetimes are at most 120 seconds. Unix-time identity expiry and native block-height
expiry are checked independently. Delegation scope, claims, issuer independence, authority epoch,
signatures, and revocation freshness are verified by AnyIdentity. Proof input is capped at 1 MiB.

Call the session's asynchronous `sign(...identityProof:)` overload. The ordinary signing overload
rejects an identity-required session. Identity verification durably consumes the challenge before
native custody is accessed. The existing native review, ML-DSA signature, custody authentication,
and native admission checks still apply. The signature is discarded if identity authorization
expires during custody authentication. Identity SHA-256 audit digests are never substituted for
ActiveChain's 48-byte native commitments or finalized lifecycle evidence.

A failed or cancelled native signing attempt consumes the identity challenge. Issue and approve a
new challenge to retry. Successful identity verification alone does not authorize a transaction on
chain or credit a wallet balance.

## Durable replay boundary

Use a private app-support journal URL, scoped to the trusted authority and policy. The journal
persists expected challenges and consumption metadata, not personal evidence or identity seeds.
An OS lock plus reload and compare-under-lock prevents independent verifier instances from consuming
the same challenge. Atomic writes, file and directory fsync, bounded records, corruption checks,
and symlink rejection fail closed. Consumption survives an ordinary process restart.

The journal binds the authority, roots, and policy and refuses configuration mismatch. A newer
revocation snapshot can reopen the same journal; older instances and rollback to an earlier
`checkedAt` value fail closed. Persisted monotonic observation of Unix time rejects clock rollback.
Configuration rotation needs an authenticated migration policy; deleting the journal is not a
supported migration. This file-based journal assumes integrity of the app's private storage; it
is not protection against a privileged attacker restoring an entire earlier device backup.

## Verification

`scripts/test-wallet-identity.sh <verified Apple distribution>` validates the source pin, runs
upstream Rust formatting/Clippy/tests and Swift tests, runs shared-wallet contract tests, and
serially links the actual iOS and macOS apps. The full deterministic-kernel gate invokes it while
its exact-revision Apple distribution is available. App unit tests also exercise Rust-reviewed
challenge creation, refusal to bypass identity, and durable consumption after native custody fails.

Negative tests cover missing/forged evidence, non-independent issuers, required claims, revoked
keys/credentials, stale revocations, wrong holder, audience, nonce, intent/proposal substitution,
delegation scope, both expiry domains, oversized input, replay, concurrent consumers, process
restart, configuration freshness rollback, clock rollback, and corrupt persistence.
