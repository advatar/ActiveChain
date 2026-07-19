# P-021: Credentials, status registries, and presentation facts

- Status: Draft 0.1
- Protocol version: Development
- Issue: <https://github.com/advatar/ActiveChain/issues/8>

## 1. Scope and trust boundary

Credentials normally remain off-chain. This revision defines their canonical signed form, deterministic acceptance policy, issuer/status evidence boundary, and the exact facts that the public semantic devnet may inject into P-023 authorization requests.

ML-DSA verification, status-tree inclusion proofs, issuance-log inclusion proofs, W3C VC conversion, and private zero-knowledge presentation are external-verifier responsibilities in this revision. The consensus-safe kernel consumes explicit preverified evidence and MUST bind it back to the exact canonical values. It MUST NOT treat an arbitrary schema identifier supplied by a caller as a verified credential fact.

## 2. Canonical credential

The canonical `CredentialStatementV1` committed by the issuer signature contains, in order:

```text
format_version = 1
issuer: PrincipalId
subject_binding: Digest384
schema_id: Digest384
claims_commitment: Digest384
issuance_height: Height
valid_from: Timestamp
valid_until: Option<Timestamp>
status_registry: Option<ObjectId>
issuance_log_root: Option<Digest384>
terms_commitment: Option<Digest384>
```

`CredentialV1` contains that statement followed by `issuer_signature: ProtocolSignature`. The validity end, when present, MUST be greater than or equal to the validity start. The issuance signature suite MUST be ML-DSA-65 or ML-DSA-87. Claims are committed; this public profile does not decode application claims inside consensus.

The issuer signs the canonical statement under domain `CREDENTIAL_ISSUANCE = 0x0008`. The `CredentialId` is the commitment to the complete signed credential under domain `CREDENTIAL_ID = 0x0007`. Changing the signature therefore changes the credential identifier without changing the issuance message.

## 3. Status registry

```text
CredentialStatusRegistryV1 {
    registry_id: ObjectId
    issuer: PrincipalId
    schema_id: Digest384
    status_root: Digest384
    sequence: u64
    effective_height: Height
}
```

The root commits to issuer-defined credential status. A preverified status-evidence item binds the exact registry identifier, credential identifier, status root, registry sequence, and one of `Active`, `Revoked`, or `Suspended`.

If a credential names a registry, a presentation MUST provide the matching registry snapshot and status evidence even when policy does not otherwise require status. This prevents callers from discarding declared revocation semantics.

## 4. Acceptance policy

`CredentialAcceptancePolicyV1` contains strictly increasing, duplicate-free issuer and schema allowlists, each bounded to 32 entries, plus:

```text
maximum_status_age: u64
require_status: bool
require_issuance_log: bool
```

An empty allowlist accepts nothing. Status age is measured in finalized block heights as `presentation_height - effective_height`. Future registry snapshots and ages greater than the configured maximum are rejected.

## 5. Presentation verification

The deterministic verifier receives a credential, acceptance policy, expected subject binding, finalized height and timestamp, preverified issuer evidence, and optional registry/status evidence. It checks in fixed order:

1. issuance height and timestamp validity;
2. exact subject binding;
3. issuer and schema allowlists;
4. issuer evidence against the issuance commitment, issuer, and signature suite;
5. required issuance-log evidence;
6. declared or policy-required status material;
7. registry identifier, issuer, schema, height, and freshness;
8. status-evidence credential, root, sequence, and active state.

Every error returns no verified fact. Success returns a `VerifiedCredentialFact` whose fields are not publicly constructible. The fact exposes the accepted schema for the existing P-023 request boundary; adapters MUST sort, deduplicate, and enforce P-023's 32-fact bound.

## 6. Total failure classes

Failures include not-yet-issued, not-yet-valid, expired, subject mismatch, unaccepted issuer/schema, issuer-evidence mismatch, missing or mismatched issuance-log evidence, missing or unexpected status material, registry mismatch, future or stale registry, status-evidence mismatch, revoked, suspended, commitment encoding, and too many derived APL facts.

Verification is pure. Failure cannot mutate registry, credential, policy, or chain state.

## 7. Canonical types and bounds

```text
CredentialStatementV1        type 0x0023, schema 1, max body    366 bytes
CredentialV1                 type 0x0024, schema 1, max body  5,001 bytes
CredentialStatusRegistryV1   type 0x0025, schema 1, max body    208 bytes
CredentialAcceptancePolicyV1 type 0x0026, schema 1, max body  3,084 bytes
```

## 8. Required properties

```text
same signed credential                    -> same CredentialId
unsigned field or signature change        -> different CredentialId
signature-only change                      -> same issuance commitment
wrong issuer/subject/schema/transcript     -> rejection
timestamp outside inclusive validity       -> rejection
declared registry without proof            -> rejection
future/stale/non-active status              -> rejection
accepted result                            -> canonical bounded APL schema fact
```

The Lean development model fixes status-required, future, stale, and non-active precedence. Rust MUST reproduce its frozen table.

## 9. Compatibility

Changing field order, bounds, signature suites, commitment domains, interval inclusivity, status freshness, evidence precedence, or fact derivation requires a protocol/schema version change.
