# P-001: Canonical data types and binary encoding

- Status: Draft 0.1
- Protocol version: Development
- Issue: <https://github.com/advatar/ActiveChain/issues/1>

## 1. Primitive types

The following widths are normative:

| Type | Representation |
|---|---|
| `Digest384` | exactly 48 bytes |
| protocol identifier newtypes | exactly one `Digest384` |
| `u8`, `u16`, `u32`, `u64`, `u128` | unsigned fixed-width integer |
| `Height`, `Epoch`, `Round`, `Timestamp` | `u64` |
| `Amount`, `ResourceUnits` | `u128` |

Identifier types are distinct even when their physical representations match. Implementations MUST NOT implicitly interchange a `PrincipalId` and an `ObjectId`.

## 2. Integer and scalar encoding

Fixed-width integers MUST use big-endian byte order. A Boolean MUST be one byte: `00` for false and `01` for true. Other Boolean tags MUST be rejected. Enum discriminants use their declared fixed-width integer representation; unknown discriminants MUST be rejected.

Floating-point values, native-width integers, locale-sensitive strings, and unordered collections MUST NOT occur in a consensus type.

## 3. Lengths and byte strings

Variable lengths use unsigned LEB128 restricted to a `u32`. The shortest representation MUST be used. Decoders MUST reject:

- more than five length bytes;
- values greater than `u32::MAX`;
- a fifth byte greater than `0f`;
- multi-byte encodings whose final payload group is zero;
- lengths greater than the field or type maximum;
- input that ends before the declared length.

A byte string is its minimal length followed by exactly that many bytes. The maximum MUST be checked before copying or allocating.

## 4. Top-level envelope

Every top-level consensus value is encoded as:

```text
type_tag       : u16 big-endian
schema_version : u16 big-endian
body_length    : minimal u32 ULEB128
body           : body_length bytes
```

Type tag `0x0020` is `Principal`. Its development schema version is `1`. Tags not registered for the expected type, unsupported versions, trailing bytes after the envelope, and trailing bytes inside the body MUST be rejected.

Fields in a body occur exactly once in schema order. There are no field names or field numbers on the wire. Schema evolution therefore requires a new schema version.

## 5. Principal version 1

`Principal` uses the exact field order declared in `schema/activechain.idl`. Its body is 282 bytes. A decoded principal MUST satisfy `last_updated_at >= created_at`.

## 6. Commitment transcript

The development commitment is the first 48 bytes produced by SHAKE256 over this transcript:

```text
ASCII "ACTIVECHAIN-COMMITMENT"
transcript_version : u16 big-endian = 1
domain_tag         : u16 big-endian
type_tag           : u16 big-endian
schema_version     : u16 big-endian
body_length        : u64 big-endian
canonical_body
```

Registered development domain tags are:

| Tag | Meaning |
|---:|---|
| `0x0001` | canonical value commitment |
| `0x0002` | object identifier derivation |
| `0x0003` | signing payload |
| `0x0004` | state leaf |

The envelope is not hashed as `canonical_body`; its type and version are already explicit transcript fields. A caller MUST select the domain for the intended protocol use.

## 7. Errors and abort behavior

Decoding returns a typed error and no value. An implementation MUST distinguish at least: truncation, invalid type, unsupported version, non-minimal or overflowing length, limit violation, invalid scalar or enum, invalid semantic value, and trailing data. A decoding error MUST NOT modify protocol state.

Encoding fails before exceeding the type limit. Arithmetic used to compute buffer lengths MUST be checked.

## 8. Resource bounds

Each `CanonicalType` publishes `MAX_ENCODED_LEN` for its body. The envelope length is additionally bounded by `u32::MAX`. `PrincipalV1.MAX_ENCODED_LEN` is 282. Future collection fields MUST publish field-specific limits.

## 9. Formal properties

For a fixed type tag and schema version, implementations MUST satisfy:

```text
decode(encode(x)) = x
encode(x) = encode(y) implies x = y
```

Strict decoding MUST ensure that appending bytes, substituting a non-minimal length, or changing a type/version tag never yields the same accepted value.

## 10. Test vectors

The initial principal vector is `testing/vectors/canonical/principal-v1.txt`. Future Rust, Go, TypeScript, Swift, Kotlin, and Lean implementations MUST reproduce it byte-for-byte.

## 11. Compatibility

A decoder for one type and schema version MUST reject every other tag and version. A new version MAY define a migration, but MUST NOT alter version 1 decoding. Unknown fields are impossible in a fixed body and MUST NOT be simulated by accepting trailing bytes.

## 12. Implementation notes (non-normative)

The Rust codec uses caller-visible bounds and borrowed slices during decoding. Serialization frameworks used by RPC layers are deliberately excluded from consensus encoding.
