# Protocol v1 and security boundaries

## Trust model

The core verifies cryptographic assertions; it does not discover who is trustworthy. Applications supply pinned `AuthorityState`, `TrustedRoot` entries, `AssurancePolicy`, a trusted `RevocationSnapshot`, trusted time and the expected action. Never accept these from the claimant as authoritative. Authenticate and protect their storage and updates.

A signature proves possession of a key and integrity of a message. It does not prove that a statement is true, that a human is present, that a key is non-exportable or that two identity documents describe the same biological person. Trusted adapters must perform those checks before issuing evidence. Two people can intentionally bind their credentials to one shared key; the core cannot detect that attack.

## Requirements mapping

| BRIEF1 concept | Implemented behavior | Boundary |
|---|---|---|
| Heterogeneous roots | Signed evidence with issuer, kind, holder key, authority ID, facts, level and time; async adapter protocol | No native mDL, passport/NFC, SD-JWT/VC, EUDI, UK wallet, banking or national-ID verifier |
| Identity-to-key binding | Enrollment proof signs audience, challenge, key, ID and validity; attestation checks the expected challenge and exact binding | Attestor owns one-use challenge state, source trust-chain validation, liveness and same-person checks |
| Persistent authority | Hash-derived genesis ID stays fixed across accepted key changes; credential replacement reattests the same ID/key | State must be pinned; a serialized state is not self-authenticating |
| Multi-root assurance | Distinct configured issuer independence groups; per-root ceilings/kinds; required facts, age, liveness/hardware policy | Group independence and assurance meanings are deployment policy, not automatically inferred or mapped to eIDAS/NIST |
| Key rotation/recovery | Old+new signatures for rotation; preconfigured distinct guardian quorum+new signature for recovery; epoch increments | Guardians may perform external re-proofing; arbitrary new evidence alone cannot take over an authority; no secret reconstruction or distributed fork consensus |
| Pairwise authorities | HKDF-derived Ed25519 keys separated by audience | No ZK proof transferring master identity assurance, no unlinkable revocation proof, no automatic pairwise-key continuity after master-secret loss |
| Statements/actions/artifacts | Generic operation, resource and payload hash in signed action | The application supplies semantics and verifies the payload bytes; a signed “present”/“adult” claim is not evidence of physical presence/age by itself |
| Bounded agent authority | Parent-bound chain; exact operation/resource/audience, time, monetary and merchant bounds, depth attenuation | Amount is per action, not a cumulative budget. External atomic accounting is necessary for cumulative spend or rate limits |
| Offline verification/status | Local signature checks against a fresh trusted status snapshot | Offline status cannot reveal revocation after the snapshot; no network status service or signed status-download format is supplied |

## Keys and encoding

- Ed25519 from ed25519-dalek 2.2, using strict verification and rejection of weak public keys. SHA-256 hashes; HKDF-SHA-256 derives pairwise 32-byte signing seeds.
- OS randomness fills a 32-byte seed. Rust uses `Zeroizing` for temporary seeds and dalek's zeroize support for key destruction. This reduces ordinary secret lifetime; it is not a promise against process dumps, compiler/register copies or hostile in-process code. Swift `Data` copies of exported seeds are caller-owned.
- Software keys only. `hardwareBound` is an attestor statement checked as a policy input; the software `IdentityKey` implementation cannot substantiate it. A native hardware-backed signer would need a separately specified algorithm/FFI integration.
- Public keys/signatures/digests are lowercase hex, respectively 32/64/32 bytes. Exact audience strings are case-sensitive and not URL-normalized. The application must define canonical audience identifiers and separate tenants/environments where needed.
- Pairwise KDF: HKDF-SHA-256 with salt UTF-8 `AnyIdentity/pairwise/v1`, input key material the master seed and info the exact UTF-8 audience. Never use the public key as input key material or share the derivation seed with verifiers.
- Genesis ID: SHA-256 of UTF-8 `AnyIdentity/authority/v1`, NUL, and lowercase hex genesis public key. Recovery configuration is pinned alongside this ID, not committed by the ID itself.

Every signed envelope has `version`, `kind`, `signer`, `payload`, and `signature`. Signature input is UTF-8 JSON of an object with `protocol: "AnyIdentity"`, `version: 1`, kind, signer and the typed payload. Unknown versions/kinds fail verification. Signing is domain-separated by kind; enrollment signatures cannot be reused as actions.

The **restricted JSON v1 profile is not RFC 8785/JCS, JOSE or COSE**. Rust normalizes typed schemas, recursively lexicographically sorts object keys via serde_json maps, sorts/deduplicates set-valued fields, retains sequence-valued arrays, restores optional values as explicit nulls, then emits compact JSON. Types are unsigned integers, strings, booleans, arrays, objects and null; no floats or arbitrary extension fields. Current timestamps/amounts support UInt64 without passing through a JavaScript number. Future interoperating implementations must reproduce this profile, including serde_json string escaping and set normalization, and use version changes for changed semantics.

Envelope reference: SHA-256 of UTF-8 `AnyIdentity/envelope/v1`, NUL, then the canonical complete signed envelope. `digest` parses the kind's schema, verifies its self-signature and restores omitted optionals before hashing. This matters because Swift omits nil JSON properties. Always obtain parent/revocation references through `digest`; hashing a Swift JSON encoding directly is not equivalent.

Evidence revocation reference: SHA-256 of the canonical JSON array `["AnyIdentity/evidence-reference/v1", issuer, evidenceID]`. Namespacing prevents different issuers' local identifiers from colliding. Obtain it with `evidenceReference`.

## Enrollment and assurance

1. Attestor generates an unpredictable single-use challenge and stores its intended audience, holder/session and expiry.
2. Holder signs `Enrollment` with the proposed subject key.
3. External adapter validates source credential authenticity, issuer trust/status, native holder binding, freshness and the person relationship. An NFC authenticity check alone is insufficient evidence that the presenter is the passport subject.
4. Attestor calls `attest` with its **stored** expected challenge/audience and signed facts. It atomically consumes the challenge in its own service. The core does not keep enrollment replay state.
5. Relying party pins the holder's authority state and configured attestor roots. It validates each binding and applies its own policy.

Each qualifying evidence record must independently contain **all required claims** and meet minimum assurance, age and requested liveness/hardware conditions. Root configuration limits permitted credential kinds and maximum level. Distinct accepted groups count once regardless of how many credentials or keys they issue. The same public key cannot be configured as separate roots. Unknown issuers are ignored; bad signatures or wrong-key bindings from recognized issuers reject the assessment. Expired, revoked or nonqualifying records do not count. Duplicate `(issuer,id)` records reject input. Evidence count is capped at 64.

The resulting `claims` field is the union of facts in accepted records; only the policy's `requiredClaims` are guaranteed to have the full independent-root support. Re-run assessment with additional facts in the policy if their assurance matters. There is no hidden PII database; normalized facts and identifiers are nevertheless linkable and potentially personal data.

Validity is half-open `[issuedAt, expiresAt)`, with no implicit clock-skew allowance. Evidence freshness expires exactly at `issuedAt + maximumAgeSeconds` and the result's `validUntil` is the earliest applicable accepted evidence/status bound. No currently valid evidence means no identity-assured authorization, even though a persistent key can still sign an unassured assertion.

## Continuity and recovery

`Transition` commits to authority ID, previous/new public keys, next epoch, bounded time and recovery mode. Every approval signs identical fields. Normal rotation requires the current and replacement keys; recovery requires the configured number of distinct, nonrevoked guardian keys and replacement-key proof. A revoked current key may be recovered through guardians, but a revoked authority cannot. Guardians cannot double-count or become the new operational key. Recovery configuration is immutable in v1.

Only apply a transition to the locally pinned current state, and atomically persist the updated key/epoch and history. Old transitions cannot apply again to the advanced state. However, restoring an old snapshot or accepting a claimant-provided snapshot defeats this guarantee. There is no global resolver, witness log, fork choice or device synchronization protocol in this package.

Old-key identity evidence and delegations stop qualifying after a transition. Obtain fresh attestations for the new current key. The stable authority ID survives this reattestation; existing evidence is not silently transferred to a recovered key. Guardians should require an appropriate re-proofing ceremony before signing. If the master derivation seed is lost, deriving from the replacement creates different pairwise keys; preserving those site accounts requires separate site recovery/rotation or a securely retained derivation root.

## Delegations and actions

A root delegation is signed by the pinned authority key and has no parent. Every child commits to the complete parent's envelope digest and is signed by the parent's delegate. All nodes must match the current authority ID/epoch/audience, be valid now and unrevoked. Cycles and excessive chain length reject. `remainingDepth` ranges from 0 to 8 and strictly decreases: at most nine delegation nodes including the root.

Child scopes must be subsets of operations/resources and must retain or tighten parent amount/currency/merchant conditions and validity. Strings use exact equality; there are no wildcard, URL-prefix, regex or Unicode-normalization permission rules. Nil monetary bound means unlimited money under that dimension. A monetary bound requires a matching currency and an action amount. Merchant category is an exact application-defined string. Fields such as merchant category, currency and amount must be independently checked against the intended transaction rather than blindly trusted from agent input.

The final agent proves possession by signing the whole action. `verifyAction` requires an independently supplied expected action, including audience, unpredictable nonce, payload digest and all transaction fields. Verification does not execute the action. A valid action must fit wholly inside every delegation's validity window, and ancestor revocation invalidates descendants. Omitting a required chain or signing with another key fails.

`AuthorityVerifier` adds assurance checking and an actor-isolated replay cache. It consumes a nonce only after successful verification; concurrent copies have one winner. It rejects backwards time and fails closed when the cache is full rather than evicting live challenges. Nonces are remembered until the signed action expires. Do not reuse an old challenge for a newly issued request.

This replay protection is **in-process only**. Services must atomically persist challenge consumption and transaction/idempotency effects across restarts and replicas. A successful cryptographic check is not a guarantee of exactly-once payment execution. The actor's roots/policy are fixed, state may transition, and status may be refreshed. The trusted provider must enforce its status freshness ceiling; the core only checks the snapshot's supplied window. A newer snapshot is trusted configuration, so its authenticity and retention of revoked identifiers are provider responsibilities.

## Privacy and non-goals

A master public key or persistent authority ID shown at multiple sites is a correlation handle. Derived public keys do not expose that handle cryptographically, but a master-signed link, common evidence identifier, rare disclosed claims, issuer observations, network data or shared authority ID can reconnect them. Do not send master evidence and claim that a pairwise presentation is unlinkable.

A separately enrolled pairwise authority can receive minimal signed facts from an attestor. That attestor can still correlate enrollments; this is not anonymous credential re-randomization. The package intentionally makes no ZK, predicate-proof or privacy-preserving inherited-assurance claim. It also makes no eIDAS qualified-signature, NIST assurance certification, mDL/ICAO conformance or Secure Enclave attestation claim.

## FFI ownership and resource limits

C ABI version 1 exposes opaque immutable key handles and an input-length-delimited JSON operation call. Requests are limited to 1 MiB. Identifiers are bounded to 4096 bytes, nonblank and free of control characters. Rust JSON parsing has its normal recursion limit. Invalid signatures, schemas, times, bindings, permissions and status yield structured errors. Panics in key operations and request dispatch are caught before crossing the ABI; allocation failure or invalid pointers are outside this recoverable-error guarantee.

The caller must provide valid pointers and lengths and free each returned string/key exactly once using this library. Swift encapsulates these contracts and holds key references through calls. FFI is not a sandbox against a malicious native caller. Build on platforms with unwind-capable Rust; changing to panic=abort removes panic recovery.
