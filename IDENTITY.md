
• ActiveChain already has a strong native identity model, but it deliberately does not model “a person” or “an organization” as intrinsic protocol types.
  VCIssuer should supply real-world attestations about a principal, while ActiveChain supplies stable identifiers, controller lifecycle, authorization,
  delegation, status commitments, and policy enforcement.

  ## Native identity concepts

  ActiveChain currently supports:

  - Stable principals. PrincipalId is key-independent, so controller rotation does not change identity.
  - Controller and recovery authority. Each principal has controller and recovery policies, an authenticator-set commitment, replay-protected sequence numbers,
    freeze state, and challenge-based recovery.

  - did:activechain. A DID projection over finalized principal state, with post-quantum authentication, key agreement, recovery commitments, and services. It is
    not a separate identity ledger.

  - Public and private actors. Policies can use an explicit principal or a commitment representing a private actor.
  - Off-chain credentials. ActiveChain defines signed credentials with:
      - issuer principal
      - opaque subject binding
      - schema commitment
      - claims commitment
      - validity interval
      - optional status registry
      - optional issuance-log root
      - optional terms commitment

  - Credential-derived authorization facts. A verified credential contributes a schema commitment to the Authorization Policy Language; raw claims are not
    exposed to consensus.

  - Capabilities and delegation. Principals can issue mechanically attenuated, holder-bound or bearer capabilities with action/resource/data scopes, limits,
    expiry, budgets, revocation, and bounded delegation depth.

  - Agent identities. Apps, services, devices, and autonomous agents can have their own principals and narrowly delegated capabilities.
  - Approval roles. Authorization can require independently verified role-and-threshold approval facts.
  - Generic identity semantics. “Person,” “company,” “government issuer,” “device,” and “AI agent” are credential schemas and policy roles, not distinct base-
    layer account classes.

  The key specifications are spec/protocol/P-020-principal-lifecycle.md, spec/protocol/P-021-credentials.md, spec/protocol/P-023-authorization-policy-
  language.md, and spec/protocol/P-095-activechain-did-method.md.

  ## Recommended integration

  The clean boundary is:

  VCIssuer / EUDI trust domain
          │
          │ SD-JWT VC or mdoc presentation
          ▼
  External presentation verifier
    - validates EUDI issuer trust
    - validates ES256/COSE signatures
    - validates holder/device binding
    - validates disclosures and status
    - maps the credential profile
          │
          │ bounded preverified evidence
          ▼
  ActiveChain credential adapter
    - binds external issuer → PrincipalId
    - binds holder → subject commitment
    - maps credential type → schema Digest384
    - commits claims without publishing them
    - emits VerifiedCredentialFact
          │
          ▼
  APL authorization
    authenticated actor
    AND accepted issuer/schema
    AND current active credential
    AND capability/approval requirements
    AND protocol-specific constraints

  This follows ActiveChain’s existing trust boundary: W3C conversion, signature verification, status proofs, and private presentations are explicitly external-
  verifier responsibilities.

  ### 1. Give the issuer an ActiveChain principal

  The deployed VCIssuer operator should control an ActiveChain principal and optionally publish a did:activechain document.

  That principal represents the accountable issuer operation—not necessarily the legal EUDI identifier itself. Maintain a governed binding between:

  - ActiveChain PrincipalId
  - EUDI issuer URL
  - issuer certificate/trust-list identity
  - permitted credential configurations
  - profile/rulebook digests
  - signing-key or certificate commitments

  Controller rotation then changes operational keys without changing the issuer identity.

  ### 2. Add an EUDI-to-ActiveChain verification adapter

  Do not teach consensus to parse SD-JWT, JSON, OAuth metadata, X.509, or mdoc. Build a bounded verifier adapter outside consensus that accepts a presentation
  and produces exact preverified evidence.

  For each accepted VCIssuer profile, define a canonical mapping such as:

  schema_id = SHAKE256(
      "ACTIVECHAIN-EUDI-SCHEMA-V1" ||
      credential_configuration_id ||
      credential_type ||
      rulebook_id ||
      rulebook_version ||
      rulebook_digest
  )

  The adapter must use a pinned mapping table. It must never accept an arbitrary caller-supplied schema_id.

  ### 3. Bind the holder carefully

  Use different subject bindings depending on the privacy requirement:

  - Account-bound credential: commit the ActiveChain PrincipalId, credential holder key, and binding version.
  - Pseudonymous credential: derive a verifier- or purpose-specific commitment so the same credential cannot be correlated globally.
  - Private proof: expose only a commitment and resulting verified schema/predicate facts.
  - Device-bound EUDI credential: bind both the wallet holder key and the intended ActiveChain principal, rather than assuming those identities are automatically
    identical.

  A wallet should explicitly authorize the association between its EUDI holder key and its ActiveChain principal.

  ### 4. Keep credentials and personal data off-chain

  Do not store PID attributes, learning records, portraits, SD-JWT disclosures, mdoc namespaces, or complete credentials on ActiveChain.

  On-chain state should contain only what is needed for deterministic trust and authorization:

  - issuer/profile binding commitments
  - credential schema commitments
  - status roots and sequences
  - issuance-log or transparency roots
  - optional audit commitments
  - policy and terms commitments

  The holder retains the credential. Verifiers receive only the required disclosures.

  ### 5. Bridge status and revocation

  VCIssuer uses EUDI/IETF status mechanisms, while ActiveChain has CredentialStatusRegistryV1. These should not become two independently authoritative revocation
  systems.

  Use one of two explicit profiles:

  - Mirrored status: periodically commit the externally authoritative EUDI status-list root and metadata to an ActiveChain registry snapshot.
  - Native companion status: issue an ActiveChain-specific companion attestation whose status is managed natively.

  For EUDI credentials, I recommend mirrored status: the adapter verifies the original status mechanism and proves that it corresponds to a recent anchored root.
  ActiveChain policy then enforces a maximum root age.

  ### 6. Use credentials to unlock capabilities, not as capabilities themselves

  A credential should establish facts such as:

  - PID verified
  - over an age threshold
  - resident in an allowed jurisdiction
  - qualified representative of an organization
  - holder of a learning qualification
  - regulated issuer/operator role

  APL should combine that fact with normal authentication and capabilities. For example:

  authenticated principal
  AND verified PID schema
  AND verified organization-representative schema
  AND capability permits action X on resource Y
  AND credential status is current
  AND transaction value is below the policy limit

  Possessing a PID must not automatically grant spending, administration, or delegation authority.

  ## Important compatibility issue

  VCIssuer currently issues standards-oriented ES256 SD-JWT VC and COSE/mdoc credentials. ActiveChain’s native CredentialV1 currently accepts only ML-DSA-65 or
  ML-DSA-87 issuance signatures.

  Therefore, an EUDI credential cannot simply be decoded as an ActiveChain native credential today.

  The safest initial design is:

  1. Preserve the original EUDI credential unchanged.
  2. Verify it externally under its native trust framework.
  3. Produce a bounded ExternalCredentialEvidenceV1.
  4. Convert that evidence into an internal VerifiedCredentialFact.
  5. Optionally let the ActiveChain issuer principal issue a separate ML-DSA companion credential committing to the original credential and verification profile.

  That avoids falsely representing ES256 EUDI credentials as native ML-DSA credentials.

  ## Suggested implementation order

  1. Define an ExternalIssuerBindingV1 mapping EUDI trust identities and profiles to an ActiveChain issuer principal.
  2. Define canonical EUDI profile-to-schema mappings with frozen cross-repository vectors.
  3. Define subject-binding profiles for account-bound and unlinkable presentations.
  4. Implement an external SD-JWT verifier adapter first.
  5. Add mdoc verification as a separate adapter.
  6. Connect verified facts to P-021 acceptance policies and P-023 requests.
  7. Anchor status and issuance-log roots.
  8. Add wallet presentation UX and consent.
  9. Add end-to-end vectors shared by both repositories.
  10. Formally model issuer substitution, holder-key mismatch, stale status, replay, correlation, and schema-confusion attacks.

  The conceptual rule should be: ActiveChain identifies and authorizes principals; VCIssuer attests externally governed facts about them.

