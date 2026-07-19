# P-002: Cryptographic suites and domain separation

- Status: Draft 0.1
- Protocol version: Development
- Issue: <https://github.com/advatar/ActiveChain/issues/2>

## 1. Scope

This revision specifies canonical cryptographic-suite identifiers and structural key/signature validation. It does not yet specify provider APIs, signature verification, key generation, KEM operations, secret-key storage, or proof-system parameters.

## 2. Suite identifier

Every key, signature, ciphertext, proof, and commitment MUST identify a complete suite tuple:

```text
CryptoSuiteId {
    family: u8
    parameter_set: u16
    encoding_version: u16
    security_profile: u8
}
```

All integers use P-001 big-endian encoding. A decoder MUST reject a tuple not present in the protocol-version registry even when its individual fields are known.

## 3. Development registry

| Name | Family | Parameter set | Encoding | Profile |
|---|---:|---:|---:|---:|
| ML-DSA-44 | 1 | 44 | 1 | 2 |
| ML-DSA-65 | 1 | 65 | 1 | 3 |
| ML-DSA-87 | 1 | 87 | 1 | 5 |
| SLH-DSA-SHAKE-192s | 2 | `0x0192` | 1 | 3 |
| ML-KEM-768 | 3 | 768 | 1 | 3 |
| SHAKE256/384 | 4 | 384 | 1 | 5 |

The numeric profile is a registry value, not an assertion that two distinct families provide identical concrete security.

## 4. Canonical public sizes

Signature-suite keys and signatures MUST have exactly these byte lengths:

| Suite | Verification key | Signature |
|---|---:|---:|
| ML-DSA-44 | 1,312 | 2,420 |
| ML-DSA-65 | 1,952 | 3,309 |
| ML-DSA-87 | 2,592 | 4,627 |
| SLH-DSA-SHAKE-192s | 48 | 16,224 |

ML-KEM and SHAKE suite identifiers MUST be rejected where a signature or public verification key is required.

`ProtocolSignature` is the six-byte suite identifier followed by a P-001 bounded byte string. The development schema admits at most 20,000 signature bytes and has a conservative maximum canonical size of 20,011 bytes.

## 5. Authenticator profiles

`AuthenticatorDescriptor` contains an identifier, suite, bounded verification key, purpose, validity start, optional validity end, and optional revocation height. The following suite-purpose pairs are admitted:

| Purpose | Suites |
|---|---|
| Control | ML-DSA-65, ML-DSA-87 |
| Recovery | ML-DSA-65, ML-DSA-87, SLH-DSA-SHAKE-192s |
| Session | ML-DSA-44, ML-DSA-65 |
| Validator | ML-DSA-44 |
| Credential issuance | ML-DSA-65, ML-DSA-87 |
| Tool receipt | ML-DSA-44, ML-DSA-65 |

The optional validity end MUST NOT precede `valid_from`. A revocation height MUST NOT precede `valid_from`. An authenticator is active at height `h` exactly when:

```text
valid_from <= h
and (valid_until is absent or h <= valid_until)
and (revoked_at is absent or h < revoked_at)
```

## 6. Domain separation

P-001 defines the development SHAKE256/384 transcript and registered commitment-domain tags. A cryptographic provider MUST receive the intended domain through a typed API. Raw bytes valid in one domain MUST NOT be accepted as a signature or commitment in another domain.

## 7. Error and abort behavior

Unknown suite tuples, non-signature suites in signature positions, incorrect key/signature lengths, disallowed purpose profiles, inverted validity, and pre-validity revocation MUST be rejected before cryptographic work. Structural rejection never modifies state.

Cryptographic verification failure is a separate deterministic authorization failure and MUST NOT be confused with malformed encoding.

## 8. Resource bounds

Verification keys are length-bounded by 4,096 bytes before allocation. Signatures are length-bounded by 20,000 bytes before allocation. `AuthenticatorDescriptorV1.MAX_ENCODED_LEN` is 4,179 bytes.

## 9. Security assumptions

Structural validation does not establish possession of a secret key or signature validity. Consensus acceptance additionally assumes a conforming, independently tested implementation of the selected NIST primitive, correct context binding, and an authorization policy which admits the authenticator purpose.

## 10. Test vectors and formal properties

Authority vectors under `testing/vectors/authority/` bind suite identifiers, keys, signatures, canonical envelopes, and P-001 commitments. Implementations MUST reproduce them byte-for-byte.

Required properties include registry totality for known tuples, rejection of unknown tuples, exact key/signature lengths, deterministic activity at each height, and cross-provider agreement on future verification vectors.

## 11. Compatibility

Adding a suite requires a protocol-version registry change. Historical tuples retain their exact sizes and encodings. A new implementation provider MAY replace an old provider only when it reproduces all vectors and verification results; it MUST NOT change canonical bytes.

## 12. Implementation notes (non-normative)

The current Rust code implements only types and structural validation. A later `crypto-provider` crate will connect independently replaceable ML-DSA, SLH-DSA, ML-KEM, and SHAKE implementations.
