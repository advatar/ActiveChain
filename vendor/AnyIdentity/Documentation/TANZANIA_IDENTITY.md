# Adding Tanzanian digital identity

Research date: **9 September 2026**. Scope: AnyIdentity's Swift/Rust package and its proposed ActiveChain integration. This is an implementation recommendation based on public primary sources, not a completed provider integration or legal clearance. No provider accounts were created, personal data submitted or organizations contacted. The operating entity is still unspecified, so both direct institutional access and a verification partner are considered.

## Recommendation

Add a **Tanzanian identity attestor service** behind the existing `IdentityEvidenceAdapter` boundary. Prefer direct NIDA access where the operating institution can obtain it; evaluate an authorized local provider for a first pilot. Keep provider credentials and identity proofing on the backend, and return a minimal `Signed<Evidence>` bound to the holder's AnyIdentity key. ActiveChain then applies its existing identity-policy gate before native signing, as described in the [README](../README.md).

The design can use the existing evidence/enrollment protocol. The substantial new work is the approved upstream connection, a trustworthy holder-verification ceremony, the attestor service, and persistent status/challenge management. A national ID number alone is not an authentication credential. A successful lookup must not become a claim that the person holding the phone is the record's subject.

## What is available, and what is not established

### NIDA institutional access

NIDA publishes three routes: the Common Interface Gateway (CIG), using NIN/fingerprints/questions; an institutional secure portal using questions; and offline chip-card reading with NIDA-provided SAM access and card readers. Its onboarding calls for an application to the Director General, business/regulatory registration licence, TIN, server/network design and API description, followed by review, technical consultation, contract, testing and billing. The published table lists TZS 500 for citizens and USD 1 for listed foreign-person categories; confirm the billable unit, current tariff and failed/retried-query charges. The page leaves its connection-time estimate blank. [NIDA data-sharing procedure](https://www.nida.go.tz/Ushirikishanaji-Taarifa).

**Assessment:** CIG is the direct integration candidate; the secure portal suits an assisted pilot. SAM/card-reader access requires a separately validated hardware workflow. Obtain the current API specification and access terms before implementing transport or promising phone-only verification. Foreign-entity eligibility, detailed authentication, biometrics, response signatures, entitlements and service levels remain unconfirmed.

NIDA describes coverage of citizens, resident foreigners and refugees across mainland Tanzania and Zanzibar, and use of NIN before card delivery. Therefore, do not equate “NIDA record verified” with Tanzanian citizenship, or require a physical card if the approved verification route supports a NIN-only presentation. [NIDA's explanation of its identification role](https://www.nida.go.tz/index.php/Habari-Maelezo?value=10).

The public self-service NIN recovery page is distinct from stakeholder verification. Do not scrape it or treat a recovered number as holder proof. [NIDA service categories](https://services.nida.go.tz/default).

### Jamii Namba and Jamii Pocket

The 2026/27 Home Affairs budget, paragraphs 158–160, describes planned registration from birth under Jamii Namba and additions of face/iris recognition. This supports tracking the programme, but does not establish that those verification methods are enabled for our application today. [Official 2026/27 budget, printed page 68](https://www.parliament.go.tz/uploads/documents/sw-1779711628-HOTUBA%20YA%20BAJETI%20YA%20WIZARA%20YA%20MAMBO%20YA%20NDANI%20YA%20NCHI%20KWA%20MWAKA%202026-2027_compressed.pdf).

The ministry-hosted JamiiStack site describes Jamii Pocket as a verifiable identity/document locker and advertises Jamii Sandbox. However, the public pages inspected did not provide a usable issuer trust list, credential schema, verifier registration procedure or presentation protocol. Its journey page also marks metrics as awaiting validation and a brochure as a placeholder. Treat these as discovery leads, even where the site displays a live-status label. [JamiiStack ecosystem](https://jamiistack.mawasiliano.go.tz/), [journey and publication status](https://jamiistack.mawasiliano.go.tz/dpi-journey).

**Assessment:** reserve a future adapter for authenticated wallet presentations. Do not assume OpenID4VP, SD-JWT VC, mdoc, a public OIDC login or Apple Wallet interoperability without the programme's actual specifications. Jamii Namba and NIDA are not automatically two independent identity roots. Begin the proposed pilot with adults; child identity and guardian authority require a separate product and policy design.

### Provider shortlist

| Candidate | Primary-source evidence | Decision for this project |
|---|---|---|
| **SelcomID** | Its site advertises NIDA registry checks, document/face comparison, liveness, assisted fingerprint capture, REST/webhooks and sandbox access. It describes Tanzanian processing. [SelcomID](https://identity.selcommobile.com/) | First local candidate to evaluate. These are provider claims, not verified entitlements or a tested SLA. Obtain the production specification, authorized data-source relationship, hosting/subprocessors, matching provenance and commercial terms. |
| **Prembly** | An August 2024 update announced upcoming Tanzanian national-ID endpoints. Separate developer documentation provides a Tanzanian document-with-face example. [Product announcement](https://blog.prembly.com/explore-new-features-zambia-kenya/), [document-with-face documentation](https://docs.prembly.com/docs/document-verification-with-face-copy-6) | Second discovery candidate. A historical announcement or document image check does not establish current NIDA registry access. Request the exact live product, supported population and holder-proof method. |
| **Smile ID** | Its inspected government-ID-number coverage table does not list Tanzania, while its product guidance distinguishes government checks from document verification. [ID-number coverage](https://docs.usesmileid.com/supported-id-types/for-individuals-kyc/backed-by-id-authority), [product distinctions](https://docs.usesmileid.com/getting-started/choose-a-product) | Do not select as a confirmed NIDA lookup provider from general Africa/global document coverage. Ask for written Tanzania-specific support if evaluating it. |

This is a capability shortlist, not a vendor endorsement. No provider was tested, and no complete per-verification commercial quote was obtained. Ask every provider whether face comparison uses a **registry portrait, an authenticated chip portrait, or only the submitted card image**; these yield different assurance. The SelcomID public description specifically mentions selfie-to-document comparison, so registry-face matching must not be inferred from a combined success flag. [SelcomID capabilities](https://identity.selcommobile.com/).

## Proposed enrollment and attestation flow

The following is our proposed application protocol, not a published NIDA API:

1. **Create a wallet key.** The Swift app creates an `IdentityKey` and genesis authority, or loads a previously pinned authority. Protect this separate Ed25519 seed; it is not the ActiveChain ML-DSA-44 key.
2. **Start a server-owned session.** The attestor creates an unpredictable nonce, a fixed enrollment audience and a short expiry. Persist the session's intended holder key/authority, requested claims, relying-party context and consent/purpose record. Authenticate existing accounts and their current epoch when reattesting.
3. **Prove possession.** The holder signs `Enrollment` using `AnyIdentity.enroll`. Validate that signature and the stored audience/nonce/window before spending upstream queries. This proves control of the proposed key, not ownership of a NIDA identity.
4. **Verify the person in the same session.** Use the approved upstream ceremony. Persist an immutable association between our session, the provider job, the source identity and the holder key. Require an adequate presenter-to-record match. Liveness without a trusted identity comparison proves neither the name nor the NIN. Protect assisted enrollment from an operator substituting a different key.
5. **Accept only authenticated results.** Validate the provider's documented response authentication and freshness, and retrieve final status server-to-server where required. Correlate the job with the stored session. Ignore client-submitted `verified` flags; reject callback replay, swapped jobs, mismatched subjects and contradictory results. Pending/timeouts remain pending or fail closed.
6. **Issue evidence.** The attestor derives only justified claims, then signs evidence bound to the exact `authorityId` and `subjectKey`. Use `attest` with the stored expected challenge. Atomically consume the enrollment challenge and persist the issued envelope/job reference. An idempotent retry returns the same issuance result rather than issuing to another key.
7. **Use it in ActiveChain.** The wallet transports the envelope. The relying verifier pins the attestor root and applies `assess`/`AuthorityVerifier.verifyAndConsume` to the canonical-proposal binding. Native ActiveChain authorization, capability checks and signatures still govern execution.
8. **Refresh and recover.** Define evidence lifetime and upstream rechecks from the actual status service/contract. Publish an authenticated attestor revocation feed for relying parties. After key rotation or guardian recovery, obtain fresh key-bound evidence; repeating a NIN lookup alone must not take over an existing authority.

The attestor signature is **our attestation of an approved verification process**. It is not a NIDA-issued AnyIdentity signature. Preserve upstream verification provenance in protected audit storage; accurately identify our signing entity in `Evidence.issuer`.

### Evidence profile

These names and levels are proposed application conventions, not government or NIST/eIDAS assurance levels:

| Existing field | Proposed use |
|---|---|
| `issuer` | Stable identifier controlled by the attestor, with a separately pinned signing key; never impersonate `nida.go.tz`. |
| `credentialKind` | A versioned profile such as `tz.nida.holder.v1`. Use a distinct profile for document-only or assisted methods if their assurance differs. |
| `id` | Random opaque issuance identifier. Keep any provider transaction/NIN mapping only in protected backend storage. |
| `authorityId`, `subjectKey` | Values from the validated enrollment and pinned current authority. Never derive keys or authority IDs from NIN. |
| `claims` | Minimal predicates such as `identity.holder_verified` and `tz.nida.record_verified`. Add `age.over_18` or `citizenship.tz` only when verified source attributes justify them. |
| `assuranceLevel` | A versioned local policy value approved for the actual ceremony. A record-only match does not qualify for this holder profile, regardless of the provider's numerical score. |
| `liveness` | True only when a supported live-presence check actually succeeded in this identity-bound session. Questions and device unlock alone do not justify it. |
| `hardwareBound` | False for the current software `IdentityKey`, even if biometric authentication protects seed access. |
| `issuedAt`, `expiresAt` | Trusted server Unix seconds and a bounded policy lifetime, not card lifetime or ActiveChain block height. |
| `TrustedRoot.independenceGroup` | A conservative shared group such as `tz-nida` for NIDA-derived attestations through any intermediary. Two vendors querying NIDA do not supply two independent identity roots. |

A NIDA-backed bank attestation is not automatically independent either; assess its underlying proofing. AnyIdentity currently has one independence-group label per configured root, not a full model of shared issuers, operators and data sources. Avoid multi-root claims that exceed that model. Each root counted by `AssurancePolicy` must independently satisfy all `requiredClaims`; names in the returned claims union alone do not provide that guarantee. See [the current protocol](PROTOCOL.md).

### Swift, Rust and service boundaries

- **Swift client:** a proposed `TanzaniaIdentityAdapter` can implement `IdentityEvidenceAdapter`. Its `credential: Data` should be a bounded reference to an authenticated backend verification session, with the signed enrollment; it must not contain an API secret or a locally asserted verification decision. The adapter transports the resulting signed evidence; the relying verifier checks it against pinned trust. Camera/consent/localization UI belongs in the consuming app, with an approved SDK or assisted capture route.
- **Rust backend:** reuse this crate's validation/encoding rather than implementing a second signing format. The crate builds an `rlib` and exposes `model`/`protocol`, but high-level enrollment/evidence signing currently lives in a private dispatcher/crypto module and the public C ABI. A production Rust service should first expose and test a narrow typed attestation API, or deliberately wrap the existing ABI. No HTTP attestor, NIDA client or Linux deployment has been supplied or validated here.
- **Signing infrastructure:** the current core signs with an in-process Ed25519 key. An HSM/KMS signer requires an explicit signing abstraction and canonical-message tests; configuration alone cannot provide that feature. Keep issuer keys out of the app and separate them from provider connection credentials.
- **Raw evidence:** upload images/biometrics only through the approved capture/service path, outside the AnyIdentity FFI. The FFI's JSON request ceiling is 1 MiB; it is not a document-processing API. Normalize successful checks into minimal facts.
- **iPhone biometrics:** Touch ID data cannot be exported or matched against another fingerprint database. Apps receive Face ID authentication success, not the enrolled face data. Consequently, native device authentication cannot implement NIDA fingerprint/portrait verification; use the approved capture/matching workflow. [Apple Touch ID security](https://support.apple.com/en-ie/105095), [Apple Face ID security](https://support.apple.com/en-ie/102381).

Preserve NIN as a **string**, with normalization specified by the contracted interface. An e-GA dictionary describes it as a varchar with maximum size 20; do not parse it into `UInt64`, infer a birth date from digits, or invent a check-digit rule. [e-GA institutional data dictionary, NIN entry](https://www.ega.go.tz/pdf-viewer?file=https%3A%2F%2Fwww.ega.go.tz%2Fuploads%2Fstandarddocuments%2Fsw-1640950814-Final+Institutional+Data+Dictionary+Technical+Standards+and+Guidelines-EDITED+%281%29.pdf).

## Data handling and operating prerequisites

PDPC states that controllers/processors must register and describes organizational documentation and DPO submission. Establish which entity holds each role before a real-data pilot. Its cross-border guidance describes a permit application and safeguards; do not assume user consent alone makes offshore processing permissible. Biometric data is included in the Act's sensitive-personal-data definition. Confirm the applicable legal basis, biometric conditions, retention, registration and transfer arrangements with Tanzanian counsel/PDPC, including territorial questions for a Zanzibar deployment. [PDPC registration](https://pdpc.go.tz/services/registration/), [cross-border permits](https://pdpc.go.tz/services/cross-border-data-transfer-permit/), [Act, section 3 definitions](https://www.pdpc.go.tz/media/media/THE_PERSONAL_DATA_PROTECTION_ACT.pdf).

**Our design recommendation:** use a Tanzanian processing boundary for the initial proofing service where feasible, subject to the approved arrangements. Inventory external SDKs, cloud backups, telemetry, support access and subprocessors; local hosting alone does not describe every transfer. Sending a key-bound attestation abroad can still disclose personal data. Classify that flow explicitly rather than assuming that removal of a name makes it anonymous.

Keep NIN, names, birth dates, card images, biometrics and raw provider responses out of public ActiveChain records and routine logs. Use an encrypted, access-controlled audit store with a defined deletion schedule. Plain hashes of NIN are predictable correlation handles; do not publish them. Opaque or keyed references remain potentially personal data and are not an automatic legal exemption. Disclose minimal predicates to the relying party. Existing AnyIdentity evidence is not selectively disclosable or zero-knowledge; a shared authority ID remains linkable.

## Work packages and decision gates

| Work package | Concrete output | Dependency / acceptance |
|---|---|---|
| 1. Access and scope | Choose operating entity, adult population/use case, direct CIG versus provider, required verification method and permitted disclosures | Written eligibility/data-source confirmation, current technical pack, test access, pricing and data-processing terms. No invented onboarding-duration estimate. |
| 2. Service contract and local fixtures | Versioned challenge/session/result contract, method-specific evidence profile, deterministic synthetic upstream fixtures | Explicit lookup-versus-holder distinction, session/key binding, failure mapping and conservative root grouping. Can be built before live access. |
| 3. Attestor/backend | Tested typed Rust signing entry point, upstream adapter, durable session/idempotency store, issuer-key custody and authenticated status feed | Contract tests against the approved sandbox; authenticated callbacks/results and retention controls. |
| 4. Wallet and ActiveChain | Swift remote adapter, approved capture/assisted flow, protected identity-key storage, trusted-root provisioning and canonical-proposal gate | Build/link in the real apps; the existing package's macOS tests do not validate an upstream NIDA connection. |
| 5. Controlled pilot | Adult users enrolled through the approved process, operational support, measured success/latency/cost and false-rejection handling | Access/data-processing requirements satisfied, security review and end-to-end rejection tests completed. |

**Required negative cases:** known NIN presented by another person; liveness without a matching trusted identity; invalid or replayed enrollment signature; substituted key/authority/provider job; forged, duplicated or delayed callback; provider timeout/missing fields; invalid source status; stale/revoked evidence; two vendors attempting to count the same NIDA source twice; app restart/retry; and rotation/recovery followed by an old-key presentation. For any biometric method, evaluate capture injection/replay resistance and accessibility/fallback handling with the provider.

### Questions for NIDA or the shortlisted provider

These are prepared questions, not sent requests:

1. Can our operating entity and use case access the service directly, or must we contract through an approved Tanzanian institution? Are downstream key-bound attestations to ActiveChain relying parties permitted?
2. Which checks are enabled for us: NIN lookup, questions, fingerprints, registry portrait comparison, document comparison or another holder-verification ceremony? Which population and record/status categories are covered?
3. Supply the current API/schema, authentication and network requirements, response/callback verification, test data, error semantics, entitlements and certificate/key rotation procedure.
4. How are match quality, liveness, fraud handling, unavailable biometrics and assisted verification evidenced? What exactly does each success/status field mean?
5. What are current fees, minimums, retry/failed-query charges, sandbox limitations, service levels and expected onboarding steps?
6. Which fields may be retained or disclosed, for how long, and under which controller/processor/transfer arrangements? Where do capture SDKs, subprocessors, backups and support staff process data?
7. Are change/revocation notifications available, or must status be polled? What should happen when a record changes, a card is replaced or a person is deceased?
8. Is Jamii Pocket accepting third-party verifiers? If so, supply the presentation protocol, issuer keys/trust registry, holder binding, status checks, schemas and production onboarding requirements.

## Research limits and verification record

Official NIDA procedures, ministry/Parliament programme material, PDPC guidance and provider-owned documentation were prioritized. Public provider claims were distinguished from demonstrated access. The PDPC Act/regulations PDF fetches were unreliable; the Act definition was checked against its indexed official text and the practical prerequisites against accessible PDPC service pages. This is not a complete statutory analysis. Historical or unofficial API-schema reposts were not used to specify an implementation.

No current public NIDA/Jamii wallet-verifier specification or working sandbox session was established in this research. Absence from the inspected public material is not proof that an institutional/private interface is unavailable. Provider access and product coverage must be reconfirmed before selection.

Local code review confirmed the evidence adapter, enrollment/attestation boundary, private Rust signing dispatcher, assurance grouping and the package's documented ActiveChain hook. Only research/documentation changes were made. Build and documentation validation are recorded in [STATUS.md](../STATUS.md).
