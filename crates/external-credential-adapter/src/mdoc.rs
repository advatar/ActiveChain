//! Closed ISO mdoc/COSE verification profile for VCIssuer-issued credentials.

use crate::{commitment, verify_es256_with_jwk};
use activechain_protocol_types::{
    ChainId, CredentialAssuranceClassV1, CredentialPredicateKind, CredentialPredicateV1, Digest384,
    ExternalCredentialStatusSnapshotV1, ExternalIssuerBindingV1, PrincipalId, TransactionId,
    VcIssuerFormatV1, VcIssuerPresentationV1,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::value::Value;
use serde_json::Value as JsonValue;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const MAX_MDOC_BYTES: usize = 96 * 1024;
pub const MAX_NAMESPACES: usize = 8;
pub const MAX_ITEMS_PER_NAMESPACE: usize = 64;
pub const MAX_ITEM_BYTES: usize = 4 * 1024;
pub const MAX_CBOR_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdocRejection {
    Oversize,
    MalformedBase64Url,
    MalformedCbor,
    NonCanonicalCbor,
    DuplicateMapKey,
    UnsupportedTag,
    UnsupportedAlgorithm,
    IssuerNotActive,
    ProfileNotAdmitted,
    IssuerTrustMismatch,
    InvalidIssuerSignature,
    DocumentTypeMismatch,
    NamespaceMismatch,
    DigestMismatch,
    ValidityInvalid,
    DeviceKeyInvalid,
    InvalidDeviceSignature,
    SessionBindingMismatch,
    RequiredClaimMissing,
    PredicateNotSatisfied,
    StatusNotAdmissible,
    StatusEvidenceMismatch,
    InvalidOutput,
}

pub struct MdocVerificationContext<'a> {
    pub issuer_signed: &'a str,
    pub issuer_jwk: &'a JsonValue,
    pub issuer_binding: &'a ExternalIssuerBindingV1,
    pub configuration_commitment: Digest384,
    pub expected_doc_type: &'a str,
    pub expected_namespace: &'a str,
    pub device_signature: &'a [u8],
    pub session_transcript: Digest384,
    pub expected_nonce: &'a str,
    pub expected_audience: &'a str,
    pub expected_purpose: &'a str,
    pub expected_response_uri: &'a str,
    pub now_unix: i64,
    pub status_snapshot: &'a ExternalCredentialStatusSnapshotV1,
    pub status_root: Digest384,
    pub issuance_log_root: Option<Digest384>,
    pub verified_height: u64,
    pub maximum_root_age: u64,
    pub require_issuance_log: bool,
    pub chain_id: ChainId,
    pub audience: PrincipalId,
    pub action: TransactionId,
    pub predicate_kind: CredentialPredicateKind,
    pub predicate_element: &'a str,
    pub policy_revision: u64,
    pub expires_height: u64,
}

pub fn verify_mdoc(
    context: &MdocVerificationContext<'_>,
) -> Result<VcIssuerPresentationV1, MdocRejection> {
    if context.issuer_signed.len() > MAX_MDOC_BYTES.saturating_mul(2) {
        return Err(MdocRejection::Oversize);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(context.issuer_signed)
        .map_err(|_| MdocRejection::MalformedBase64Url)?;
    if bytes.len() > MAX_MDOC_BYTES {
        return Err(MdocRejection::Oversize);
    }
    let root = decode_canonical(&bytes)?;
    if cbor_depth(&root) > MAX_CBOR_DEPTH {
        return Err(MdocRejection::Oversize);
    }
    if !context.issuer_binding.active_at(context.verified_height) {
        return Err(MdocRejection::IssuerNotActive);
    }
    if !context.issuer_binding.admits_profile(context.configuration_commitment) {
        return Err(MdocRejection::ProfileNotAdmitted);
    }
    let trust = commitment(
        b"ACTIVECHAIN-EXTERNAL-ISSUER-JWK-V1",
        &serde_json::to_vec(context.issuer_jwk).map_err(|_| MdocRejection::IssuerTrustMismatch)?,
    );
    if trust != context.issuer_binding.trust_identity_commitment() {
        return Err(MdocRejection::IssuerTrustMismatch);
    }

    let root_map = map(&root)?;
    ensure_unique_text_keys(root_map)?;
    let namespaces = field(root_map, "nameSpaces")?;
    let issuer_auth = field(root_map, "issuerAuth")?;
    let mso = verify_issuer_auth(issuer_auth, context.issuer_jwk)?;
    let mso_map = map(&mso)?;
    ensure_unique_text_keys(mso_map)?;
    if text(field(mso_map, "version")?)? != "1.0"
        || text(field(mso_map, "digestAlgorithm")?)? != "SHA-256"
    {
        return Err(MdocRejection::UnsupportedAlgorithm);
    }
    if text(field(mso_map, "docType")?)? != context.expected_doc_type {
        return Err(MdocRejection::DocumentTypeMismatch);
    }
    validate_validity(field(mso_map, "validityInfo")?, context.now_unix)?;
    let device_jwk = device_jwk(field(mso_map, "deviceKeyInfo")?)?;
    let disclosed = verify_namespaces(
        namespaces,
        field(mso_map, "valueDigests")?,
        context.expected_namespace,
        context.predicate_element,
    )?;
    if !predicate_satisfied(context.predicate_kind, &disclosed) {
        return Err(MdocRejection::PredicateNotSatisfied);
    }
    let device_input = device_authentication_bytes(context, namespaces)?;
    verify_es256_with_jwk(&device_jwk, &device_input, context.device_signature)
        .map_err(|_| MdocRejection::InvalidDeviceSignature)?;
    if !context.status_snapshot.admissible_at(
        context.verified_height,
        context.maximum_root_age,
        context.require_issuance_log,
    ) {
        return Err(MdocRejection::StatusNotAdmissible);
    }
    if !context.status_snapshot.binds_evidence(context.status_root, context.issuance_log_root) {
        return Err(MdocRejection::StatusEvidenceMismatch);
    }

    let credential_commitment = commitment(b"ACTIVECHAIN-MDOC-CREDENTIAL-V1", &bytes);
    let claims_commitment = commitment(
        b"ACTIVECHAIN-MDOC-DISCLOSURES-V1",
        &encode(namespaces).map_err(|_| MdocRejection::MalformedCbor)?,
    );
    let holder_binding = commitment(
        b"ACTIVECHAIN-MDOC-DEVICE-KEY-V1",
        &serde_json::to_vec(&device_jwk).map_err(|_| MdocRejection::DeviceKeyInvalid)?,
    );
    let value_bytes = encode(&disclosed).map_err(|_| MdocRejection::MalformedCbor)?;
    let predicate = CredentialPredicateV1::new(
        context.status_snapshot.schema_id(),
        claims_commitment,
        holder_binding,
        context.chain_id,
        context.audience,
        context.action,
        commitment(b"ACTIVECHAIN-MDOC-NONCE-V1", context.expected_nonce.as_bytes()),
        context.policy_revision,
        context.expires_height,
        context.predicate_kind,
        commitment(b"ACTIVECHAIN-MDOC-PREDICATE-VALUE-V1", &value_bytes),
    )
    .map_err(|_| MdocRejection::InvalidOutput)?;
    VcIssuerPresentationV1::new(
        context.issuer_binding.issuer(),
        VcIssuerFormatV1::Mdoc,
        credential_commitment,
        context.status_snapshot.commitment().map_err(|_| MdocRejection::InvalidOutput)?,
        context.issuer_binding.commitment().map_err(|_| MdocRejection::InvalidOutput)?,
        CredentialAssuranceClassV1::RegulatedAttestation,
        predicate,
        context.verified_height,
        context.chain_id,
        context.audience,
        context.action,
    )
    .map_err(|_| MdocRejection::InvalidOutput)
}

fn verify_issuer_auth(value: &Value, jwk: &JsonValue) -> Result<Value, MdocRejection> {
    let Value::Tag(18, cose) = value else {
        return Err(MdocRejection::UnsupportedTag);
    };
    let array = cose.as_array().ok_or(MdocRejection::MalformedCbor)?;
    if array.len() != 4 {
        return Err(MdocRejection::MalformedCbor);
    }
    let protected = bytes(&array[0])?;
    let protected_value = decode_canonical(protected)?;
    let protected_map = map(&protected_value)?;
    ensure_unique_integer_keys(protected_map)?;
    if integer(integer_field(protected_map, 1)?)? != -7 {
        return Err(MdocRejection::UnsupportedAlgorithm);
    }
    let payload = bytes(&array[2])?;
    let signature = bytes(&array[3])?;
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    verify_es256_with_jwk(
        jwk,
        &encode(&sig_structure).map_err(|_| MdocRejection::MalformedCbor)?,
        signature,
    )
    .map_err(|_| MdocRejection::InvalidIssuerSignature)?;
    let Value::Tag(24, embedded) = decode_canonical(payload)? else {
        return Err(MdocRejection::UnsupportedTag);
    };
    let mso_bytes = bytes(&embedded)?;
    decode_canonical(mso_bytes)
}

fn verify_namespaces(
    namespaces: &Value,
    digests: &Value,
    expected_namespace: &str,
    claim: &str,
) -> Result<Value, MdocRejection> {
    let namespace_map = map(namespaces)?;
    if namespace_map.len() > MAX_NAMESPACES {
        return Err(MdocRejection::Oversize);
    }
    ensure_unique_text_keys(namespace_map)?;
    if namespace_map.len() != 1 {
        return Err(MdocRejection::NamespaceMismatch);
    }
    let items =
        field(namespace_map, expected_namespace)?.as_array().ok_or(MdocRejection::MalformedCbor)?;
    if items.len() > MAX_ITEMS_PER_NAMESPACE {
        return Err(MdocRejection::Oversize);
    }
    let digest_namespace = field(map(digests)?, expected_namespace)?;
    let digest_map = map(digest_namespace)?;
    ensure_unique_integer_keys(digest_map)?;
    let mut ids = BTreeSet::new();
    let mut result = None;
    for tagged in items {
        let encoded_tagged = encode(tagged).map_err(|_| MdocRejection::MalformedCbor)?;
        if encoded_tagged.len() > MAX_ITEM_BYTES {
            return Err(MdocRejection::Oversize);
        }
        let Value::Tag(24, item_bytes) = tagged else {
            return Err(MdocRejection::UnsupportedTag);
        };
        let item = decode_canonical(bytes(item_bytes)?)?;
        let item_map = map(&item)?;
        ensure_unique_text_keys(item_map)?;
        let id = integer(field(item_map, "digestID")?)?;
        if id < 0 || !ids.insert(id) {
            return Err(MdocRejection::DuplicateMapKey);
        }
        let expected = bytes(integer_field(digest_map, id)?)?;
        if Sha256::digest(&encoded_tagged).as_slice() != expected {
            return Err(MdocRejection::DigestMismatch);
        }
        if text(field(item_map, "elementIdentifier")?)? == claim {
            result = Some(field(item_map, "elementValue")?.clone());
        }
    }
    result.ok_or(MdocRejection::RequiredClaimMissing)
}

fn device_authentication_bytes(
    context: &MdocVerificationContext<'_>,
    namespaces: &Value,
) -> Result<Vec<u8>, MdocRejection> {
    let disclosed = encode(namespaces).map_err(|_| MdocRejection::MalformedCbor)?;
    encode(&Value::Array(vec![
        Value::Text("DeviceAuthentication".into()),
        Value::Bytes(context.session_transcript.as_bytes().to_vec()),
        Value::Text(context.expected_doc_type.into()),
        Value::Bytes(Sha256::digest(&disclosed).to_vec()),
        Value::Text(context.expected_nonce.into()),
        Value::Text(context.expected_audience.into()),
        Value::Text(context.expected_purpose.into()),
        Value::Text(context.expected_response_uri.into()),
    ]))
    .map_err(|_| MdocRejection::MalformedCbor)
}

fn validate_validity(value: &Value, now: i64) -> Result<(), MdocRejection> {
    let map = map(value)?;
    let from = datetime(field(map, "validFrom")?)?;
    let until = datetime(field(map, "validUntil")?)?;
    if from > now || until < now || until <= from {
        return Err(MdocRejection::ValidityInvalid);
    }
    Ok(())
}
fn datetime(value: &Value) -> Result<i64, MdocRejection> {
    let Value::Tag(0, text_value) = value else {
        return Err(MdocRejection::UnsupportedTag);
    };
    OffsetDateTime::parse(text(text_value)?, &Rfc3339)
        .map(|v| v.unix_timestamp())
        .map_err(|_| MdocRejection::ValidityInvalid)
}
fn device_jwk(value: &Value) -> Result<JsonValue, MdocRejection> {
    let info = map(value)?;
    let key = map(field(info, "deviceKey")?)?;
    ensure_unique_integer_keys(key)?;
    if integer(integer_field(key, 1)?)? != 2 || integer(integer_field(key, -1)?)? != 1 {
        return Err(MdocRejection::DeviceKeyInvalid);
    }
    let x = bytes(integer_field(key, -2)?)?;
    let y = bytes(integer_field(key, -3)?)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(MdocRejection::DeviceKeyInvalid);
    }
    Ok(
        serde_json::json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(x),"y":URL_SAFE_NO_PAD.encode(y)}),
    )
}
fn predicate_satisfied(kind: CredentialPredicateKind, value: &Value) -> bool {
    match kind {
        CredentialPredicateKind::AgeAtLeast => value == &Value::Bool(true),
        CredentialPredicateKind::JurisdictionNotIn => {
            value.as_text().is_some_and(|v| !v.is_empty())
        }
        CredentialPredicateKind::AssetAmountAtLeast => value
            .as_integer()
            .and_then(|v| i128::from(v).try_into().ok())
            .is_some_and(|v: u64| v > 0),
    }
}
fn decode_canonical(bytes: &[u8]) -> Result<Value, MdocRejection> {
    let value: Value =
        ciborium::de::from_reader(bytes).map_err(|_| MdocRejection::MalformedCbor)?;
    if encode(&value).map_err(|_| MdocRejection::MalformedCbor)? != bytes {
        return Err(MdocRejection::NonCanonicalCbor);
    }
    Ok(value)
}
fn encode(value: &Value) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)?;
    Ok(out)
}
fn map(value: &Value) -> Result<&[(Value, Value)], MdocRejection> {
    value.as_map().map(Vec::as_slice).ok_or(MdocRejection::MalformedCbor)
}
fn text(value: &Value) -> Result<&str, MdocRejection> {
    value.as_text().ok_or(MdocRejection::MalformedCbor)
}
fn bytes(value: &Value) -> Result<&[u8], MdocRejection> {
    value.as_bytes().map(Vec::as_slice).ok_or(MdocRejection::MalformedCbor)
}
fn integer(value: &Value) -> Result<i128, MdocRejection> {
    value.as_integer().map(i128::from).ok_or(MdocRejection::MalformedCbor)
}
fn field<'a>(map: &'a [(Value, Value)], key: &str) -> Result<&'a Value, MdocRejection> {
    map.iter()
        .find_map(|(k, v)| (k.as_text() == Some(key)).then_some(v))
        .ok_or(MdocRejection::MalformedCbor)
}
fn integer_field(map: &[(Value, Value)], key: i128) -> Result<&Value, MdocRejection> {
    map.iter()
        .find_map(|(k, v)| (k.as_integer().map(i128::from) == Some(key)).then_some(v))
        .ok_or(MdocRejection::MalformedCbor)
}
fn ensure_unique_text_keys(map: &[(Value, Value)]) -> Result<(), MdocRejection> {
    let mut keys = BTreeSet::new();
    for (k, _) in map {
        if !keys.insert(text(k)?.to_owned()) {
            return Err(MdocRejection::DuplicateMapKey);
        }
    }
    Ok(())
}
fn ensure_unique_integer_keys(map: &[(Value, Value)]) -> Result<(), MdocRejection> {
    let mut keys = BTreeSet::new();
    for (k, _) in map {
        if !keys.insert(integer(k)?) {
            return Err(MdocRejection::DuplicateMapKey);
        }
    }
    Ok(())
}
fn cbor_depth(value: &Value) -> usize {
    match value {
        Value::Array(v) => 1 + v.iter().map(cbor_depth).max().unwrap_or(0),
        Value::Map(v) => {
            1 + v.iter().flat_map(|(k, v)| [cbor_depth(k), cbor_depth(v)]).max().unwrap_or(0)
        }
        Value::Tag(_, v) => 1 + cbor_depth(v),
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{
        ExternalCredentialStatusSnapshotV1, ExternalIssuerBindingStatusV1, ExternalIssuerProfileV1,
        ExternalStatusSnapshotStateV1,
    };
    use ciborium::value::Integer;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use serde_json::json;

    fn d(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    fn principal(n: u8) -> PrincipalId {
        PrincipalId::new(d(n))
    }
    fn int(n: i64) -> Value {
        Value::Integer(Integer::from(n))
    }
    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes((&[n; 32]).into()).unwrap()
    }
    fn jwk(key: &SigningKey) -> JsonValue {
        let point = key.verifying_key().to_encoded_point(false);
        json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())})
    }
    fn sign(key: &SigningKey, bytes: &[u8]) -> Vec<u8> {
        let signature: Signature = key.sign(bytes);
        signature.to_bytes().to_vec()
    }
    struct Fixture {
        encoded: String,
        issuer_jwk: JsonValue,
        binding: ExternalIssuerBindingV1,
        status: ExternalCredentialStatusSnapshotV1,
        device_key: SigningKey,
        device_signature: Vec<u8>,
    }
    fn fixture() -> Fixture {
        let issuer_key = key(1);
        let device_key = key(2);
        let device_point = device_key.verifying_key().to_encoded_point(false);
        let item = Value::Map(vec![
            (Value::Text("digestID".into()), int(0)),
            (Value::Text("random".into()), Value::Bytes(vec![7; 32])),
            (Value::Text("elementIdentifier".into()), Value::Text("age_over_18".into())),
            (Value::Text("elementValue".into()), Value::Bool(true)),
        ]);
        let tagged_item = Value::Tag(24, Box::new(Value::Bytes(encode(&item).unwrap())));
        let tagged_bytes = encode(&tagged_item).unwrap();
        let namespace = "eu.europa.ec.eudi.pid.1";
        let device_cose_key = Value::Map(vec![
            (int(1), int(2)),
            (int(-1), int(1)),
            (int(-2), Value::Bytes(device_point.x().unwrap().to_vec())),
            (int(-3), Value::Bytes(device_point.y().unwrap().to_vec())),
        ]);
        let mso = Value::Map(vec![
            (Value::Text("version".into()), Value::Text("1.0".into())),
            (Value::Text("digestAlgorithm".into()), Value::Text("SHA-256".into())),
            (
                Value::Text("valueDigests".into()),
                Value::Map(vec![(
                    Value::Text(namespace.into()),
                    Value::Map(vec![(
                        int(0),
                        Value::Bytes(Sha256::digest(&tagged_bytes).to_vec()),
                    )]),
                )]),
            ),
            (
                Value::Text("deviceKeyInfo".into()),
                Value::Map(vec![(Value::Text("deviceKey".into()), device_cose_key)]),
            ),
            (Value::Text("docType".into()), Value::Text("eu.europa.ec.eudi.pid.1".into())),
            (
                Value::Text("validityInfo".into()),
                Value::Map(vec![
                    (
                        Value::Text("signed".into()),
                        Value::Tag(0, Box::new(Value::Text("1970-01-01T00:01:40Z".into()))),
                    ),
                    (
                        Value::Text("validFrom".into()),
                        Value::Tag(0, Box::new(Value::Text("1970-01-01T00:01:40Z".into()))),
                    ),
                    (
                        Value::Text("validUntil".into()),
                        Value::Tag(0, Box::new(Value::Text("1970-01-01T00:03:20Z".into()))),
                    ),
                ]),
            ),
        ]);
        let mso_payload =
            encode(&Value::Tag(24, Box::new(Value::Bytes(encode(&mso).unwrap())))).unwrap();
        let protected = encode(&Value::Map(vec![
            (int(1), int(-7)),
            (int(4), Value::Bytes(b"issuer-1".to_vec())),
        ]))
        .unwrap();
        let sig_structure = Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(mso_payload.clone()),
        ]);
        let issuer_auth = Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(vec![]),
                Value::Bytes(mso_payload),
                Value::Bytes(sign(&issuer_key, &encode(&sig_structure).unwrap())),
            ])),
        );
        let namespaces =
            Value::Map(vec![(Value::Text(namespace.into()), Value::Array(vec![tagged_item]))]);
        let root = Value::Map(vec![
            (Value::Text("nameSpaces".into()), namespaces),
            (Value::Text("issuerAuth".into()), issuer_auth),
        ]);
        let issuer_jwk = jwk(&issuer_key);
        let trust = commitment(
            b"ACTIVECHAIN-EXTERNAL-ISSUER-JWK-V1",
            &serde_json::to_vec(&issuer_jwk).unwrap(),
        );
        let profile = ExternalIssuerProfileV1::new(d(20), d(21), d(22), 1, d(23), d(24)).unwrap();
        let binding = ExternalIssuerBindingV1::new(
            ChainId::new(d(1)),
            d(2),
            principal(3),
            d(4),
            trust,
            vec![profile],
            1,
            None,
            1,
            None,
            d(6),
            ExternalIssuerBindingStatusV1::Active,
        )
        .unwrap();
        let status = ExternalCredentialStatusSnapshotV1::new(
            ChainId::new(d(1)),
            d(2),
            binding.commitment().unwrap(),
            d(20),
            d(21),
            d(25),
            1,
            d(26),
            d(27),
            1,
            100,
            10,
            10,
            30,
            None,
            principal(7),
            d(28),
            d(29),
            Some(d(30)),
            ExternalStatusSnapshotStateV1::Published,
        )
        .unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(encode(&root).unwrap());
        let mut result =
            Fixture { encoded, issuer_jwk, binding, status, device_key, device_signature: vec![] };
        let input = device_authentication_bytes(
            &context(&result),
            field(map(&root).unwrap(), "nameSpaces").unwrap(),
        )
        .unwrap();
        result.device_signature = sign(&result.device_key, &input);
        result
    }
    fn context<'a>(f: &'a Fixture) -> MdocVerificationContext<'a> {
        MdocVerificationContext {
            issuer_signed: &f.encoded,
            issuer_jwk: &f.issuer_jwk,
            issuer_binding: &f.binding,
            configuration_commitment: d(20),
            expected_doc_type: "eu.europa.ec.eudi.pid.1",
            expected_namespace: "eu.europa.ec.eudi.pid.1",
            device_signature: &f.device_signature,
            session_transcript: d(31),
            expected_nonce: "nonce-1",
            expected_audience: "aud-1",
            expected_purpose: "age-check",
            expected_response_uri: "https://verifier.example/cb",
            now_unix: 110,
            status_snapshot: &f.status,
            status_root: d(27),
            issuance_log_root: Some(d(30)),
            verified_height: 10,
            maximum_root_age: 5,
            require_issuance_log: true,
            chain_id: ChainId::new(d(1)),
            audience: principal(8),
            action: TransactionId::new(d(9)),
            predicate_kind: CredentialPredicateKind::AgeAtLeast,
            predicate_element: "age_over_18",
            policy_revision: 1,
            expires_height: 20,
        }
    }

    #[test]
    fn vcissuer_mdoc_emits_action_bound_evidence() {
        let f = fixture();
        let verified = verify_mdoc(&context(&f)).unwrap();
        assert_eq!(verified.format(), VcIssuerFormatV1::Mdoc);
        assert!(verified.predicate().binds_action(
            ChainId::new(d(1)),
            principal(8),
            TransactionId::new(d(9))
        ));
    }
    #[test]
    fn document_session_status_and_cbor_substitution_fail_closed() {
        let f = fixture();
        let mut wrong_doc = context(&f);
        wrong_doc.expected_doc_type = "org.iso.18013.5.1.mDL";
        assert_eq!(verify_mdoc(&wrong_doc), Err(MdocRejection::DocumentTypeMismatch));
        let mut wrong_session = context(&f);
        wrong_session.session_transcript = d(40);
        assert_eq!(verify_mdoc(&wrong_session), Err(MdocRejection::InvalidDeviceSignature));
        let mut stale = context(&f);
        stale.verified_height = 16;
        assert_eq!(verify_mdoc(&stale), Err(MdocRejection::StatusNotAdmissible));
        let mut bytes = URL_SAFE_NO_PAD.decode(&f.encoded).unwrap();
        bytes.push(0);
        let malformed = URL_SAFE_NO_PAD.encode(bytes);
        let mut bad = context(&f);
        bad.issuer_signed = &malformed;
        assert!(matches!(
            verify_mdoc(&bad),
            Err(MdocRejection::MalformedCbor | MdocRejection::NonCanonicalCbor)
        ));
    }

    #[test]
    fn duplicate_keys_unknown_algorithm_and_resource_limits_fail_closed() {
        let duplicate = vec![
            (Value::Text("docType".into()), Value::Text("a".into())),
            (Value::Text("docType".into()), Value::Text("b".into())),
        ];
        assert_eq!(ensure_unique_text_keys(&duplicate), Err(MdocRejection::DuplicateMapKey));

        let protected = encode(&Value::Map(vec![(int(1), int(-8))])).unwrap();
        let auth = Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(vec![]),
                Value::Bytes(vec![0]),
                Value::Bytes(vec![0; 64]),
            ])),
        );
        assert_eq!(verify_issuer_auth(&auth, &json!({})), Err(MdocRejection::UnsupportedAlgorithm));

        let too_many = Value::Map(
            (0..=MAX_NAMESPACES)
                .map(|n| (Value::Text(format!("n{n}")), Value::Array(vec![])))
                .collect(),
        );
        let digests = Value::Map(vec![]);
        assert_eq!(
            verify_namespaces(&too_many, &digests, "n0", "claim"),
            Err(MdocRejection::Oversize)
        );
    }
}
