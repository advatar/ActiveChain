//! Bounded, network-isolated verification of VCIssuer SD-JWT VC presentations.

pub mod mdoc;

use activechain_protocol_types::{
    ChainId, CredentialAssuranceClassV1, CredentialPredicateKind, CredentialPredicateV1, Digest384,
    ExternalCredentialStatusSnapshotV1, ExternalIssuerBindingV1, PrincipalId, TransactionId,
    VcIssuerFormatV1, VcIssuerPresentationV1,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::collections::BTreeSet;

pub const MAX_PRESENTATION_BYTES: usize = 64 * 1024;
pub const MAX_JWT_BYTES: usize = 24 * 1024;
pub const MAX_DISCLOSURES: usize = 64;
pub const MAX_DISCLOSURE_BYTES: usize = 4 * 1024;
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_REPLAY_ENTRIES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdJwtRejection {
    Oversize,
    MalformedCompact,
    MalformedBase64Url,
    MalformedJson,
    DuplicateJsonKey,
    UnsupportedAlgorithm,
    UnsupportedType,
    InvalidIssuerSignature,
    InvalidHolderKey,
    InvalidKeyBindingSignature,
    IssuerMismatch,
    IssuerNotActive,
    ProfileNotAdmitted,
    TimeInvalid,
    RequestBindingMismatch,
    DisclosureDigestMismatch,
    DuplicateDisclosure,
    RequiredClaimMissing,
    PredicateNotSatisfied,
    StatusNotAdmissible,
    StatusEvidenceMismatch,
    InvalidOutput,
    Replay,
    ReplayCacheFull,
}

/// Non-deserializable proof that a registered adapter completed verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedExternalPresentation {
    presentation: VcIssuerPresentationV1,
    configuration_commitment: Digest384,
    subject_binding: Digest384,
    purpose_commitment: Digest384,
    status_anchor_height: u64,
    status_age: u64,
    has_issuance_log: bool,
    verifier_version: u16,
    proof_version: u16,
    replay_nullifier: Digest384,
}
impl VerifiedExternalPresentation {
    pub const fn presentation(&self) -> VcIssuerPresentationV1 {
        self.presentation
    }
    pub const fn configuration_commitment(&self) -> Digest384 {
        self.configuration_commitment
    }
    pub const fn subject_binding(&self) -> Digest384 {
        self.subject_binding
    }
    pub const fn purpose_commitment(&self) -> Digest384 {
        self.purpose_commitment
    }
    pub const fn status_anchor_height(&self) -> u64 {
        self.status_anchor_height
    }
    pub const fn status_age(&self) -> u64 {
        self.status_age
    }
    pub const fn has_issuance_log(&self) -> bool {
        self.has_issuance_log
    }
    pub const fn verifier_version(&self) -> u16 {
        self.verifier_version
    }
    pub const fn proof_version(&self) -> u16 {
        self.proof_version
    }
    pub const fn replay_nullifier(&self) -> Digest384 {
        self.replay_nullifier
    }
}
#[cfg(feature = "test-support")]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn testing_verified_external_presentation(
    presentation: VcIssuerPresentationV1,
    configuration_commitment: Digest384,
    subject_binding: Digest384,
    purpose_commitment: Digest384,
    status_anchor_height: u64,
    status_age: u64,
    has_issuance_log: bool,
    verifier_version: u16,
    proof_version: u16,
    replay_nullifier: Digest384,
) -> VerifiedExternalPresentation {
    VerifiedExternalPresentation {
        presentation,
        configuration_commitment,
        subject_binding,
        purpose_commitment,
        status_anchor_height,
        status_age,
        has_issuance_log,
        verifier_version,
        proof_version,
        replay_nullifier,
    }
}

/// Bounded replay state. Persist `entries()` atomically and restore it with `from_entries`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SdJwtReplayCache {
    entries: BTreeSet<Digest384>,
}
impl SdJwtReplayCache {
    pub fn from_entries(entries: Vec<Digest384>) -> Result<Self, SdJwtRejection> {
        if entries.len() > MAX_REPLAY_ENTRIES
            || entries.iter().any(|entry| *entry == Digest384::ZERO)
            || !entries.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(SdJwtRejection::ReplayCacheFull);
        }
        Ok(Self { entries: entries.into_iter().collect() })
    }
    pub fn entries(&self) -> Vec<Digest384> {
        self.entries.iter().copied().collect()
    }
    fn consume(&mut self, key: Digest384) -> Result<(), SdJwtRejection> {
        if self.entries.contains(&key) {
            return Err(SdJwtRejection::Replay);
        }
        if self.entries.len() >= MAX_REPLAY_ENTRIES {
            return Err(SdJwtRejection::ReplayCacheFull);
        }
        self.entries.insert(key);
        Ok(())
    }
}

pub struct SdJwtVerificationContext<'a> {
    pub presentation: &'a str,
    pub expected_issuer: &'a str,
    /// Pinned issuer signing JWK obtained from the authenticated trust input.
    pub issuer_jwk: &'a Value,
    pub configuration_commitment: Digest384,
    pub issuer_binding: &'a ExternalIssuerBindingV1,
    pub status_snapshot: &'a ExternalCredentialStatusSnapshotV1,
    pub status_root: Digest384,
    pub issuance_log_root: Option<Digest384>,
    pub verified_height: u64,
    pub maximum_root_age: u64,
    pub require_issuance_log: bool,
    pub now: u64,
    pub maximum_clock_skew: u64,
    pub expected_nonce: &'a str,
    pub expected_audience: &'a str,
    pub expected_purpose: &'a str,
    pub expected_response_uri: &'a str,
    pub chain_id: ChainId,
    pub audience: PrincipalId,
    pub action: TransactionId,
    pub predicate_kind: CredentialPredicateKind,
    pub predicate_claim: &'a str,
    pub policy_revision: u64,
    pub expires_height: u64,
}

/// Verifies only pinned inputs and performs no network or filesystem access.
pub fn verify_sd_jwt_vc(
    context: &SdJwtVerificationContext<'_>,
) -> Result<VerifiedExternalPresentation, SdJwtRejection> {
    if context.presentation.len() > MAX_PRESENTATION_BYTES {
        return Err(SdJwtRejection::Oversize);
    }
    reject_duplicate_json_keys_in_segments(context.presentation)?;
    let mut parts: Vec<&str> = context.presentation.split('~').collect();
    if parts.last() == Some(&"") {
        parts.pop();
    }
    if parts.len() < 2 || parts.len() > MAX_DISCLOSURES + 2 {
        return Err(SdJwtRejection::MalformedCompact);
    }
    let issuer_jwt = parts[0];
    let kb_jwt = *parts.last().ok_or(SdJwtRejection::MalformedCompact)?;
    if !kb_jwt.contains('.') {
        return Err(SdJwtRejection::MalformedCompact);
    }
    let disclosures = &parts[1..parts.len() - 1];
    let (issuer_header, issuer_payload, issuer_input, issuer_signature) = parse_jwt(issuer_jwt)?;
    exact_header(&issuer_header, "dc+sd-jwt")?;
    let issuer = string(&issuer_payload, "iss")?;
    let issuer_identity = commitment(b"ACTIVECHAIN-EXTERNAL-ISSUER-URL-V1", issuer.as_bytes());
    let trust_identity = commitment(
        b"ACTIVECHAIN-EXTERNAL-ISSUER-JWK-V1",
        serde_json::to_vec(context.issuer_jwk)
            .map_err(|_| SdJwtRejection::MalformedJson)?
            .as_slice(),
    );
    if issuer != context.expected_issuer
        || issuer_identity != context.issuer_binding.external_issuer_identity()
        || trust_identity != context.issuer_binding.trust_identity_commitment()
    {
        return Err(SdJwtRejection::IssuerMismatch);
    }
    if !context.issuer_binding.active_at(context.verified_height) {
        return Err(SdJwtRejection::IssuerNotActive);
    }
    if !context.issuer_binding.admits_profile(context.configuration_commitment) {
        return Err(SdJwtRejection::ProfileNotAdmitted);
    }
    verify_es256_with_jwk(context.issuer_jwk, issuer_input, &issuer_signature)
        .map_err(|_| SdJwtRejection::InvalidIssuerSignature)?;
    validate_times(&issuer_payload, context.now, context.maximum_clock_skew)?;

    let sd_alg = string(&issuer_payload, "_sd_alg")?;
    if sd_alg != "sha-256" {
        return Err(SdJwtRejection::UnsupportedAlgorithm);
    }
    let expected_digests =
        issuer_payload.get("_sd").and_then(Value::as_array).ok_or(SdJwtRejection::MalformedJson)?;
    let expected: BTreeSet<&str> = expected_digests
        .iter()
        .map(|v| v.as_str().ok_or(SdJwtRejection::MalformedJson))
        .collect::<Result<_, _>>()?;
    if expected.len() != expected_digests.len() {
        return Err(SdJwtRejection::DuplicateDisclosure);
    }
    let mut names = BTreeSet::new();
    let mut disclosed = None;
    for encoded in disclosures {
        if encoded.len() > MAX_DISCLOSURE_BYTES {
            return Err(SdJwtRejection::Oversize);
        }
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes()));
        if !expected.contains(digest.as_str()) {
            return Err(SdJwtRejection::DisclosureDigestMismatch);
        }
        let value = decode_json(encoded)?;
        let fields =
            value.as_array().filter(|v| v.len() == 3).ok_or(SdJwtRejection::MalformedJson)?;
        let name = fields[1].as_str().ok_or(SdJwtRejection::MalformedJson)?;
        if !names.insert(name.to_owned()) {
            return Err(SdJwtRejection::DuplicateDisclosure);
        }
        if name == context.predicate_claim {
            disclosed = Some(fields[2].clone());
        }
    }
    let predicate_value = disclosed.ok_or(SdJwtRejection::RequiredClaimMissing)?;
    if !predicate_satisfied(context.predicate_kind, &predicate_value) {
        return Err(SdJwtRejection::PredicateNotSatisfied);
    }

    let (kb_header, kb_payload, kb_input, kb_signature) = parse_jwt(kb_jwt)?;
    exact_header(&kb_header, "kb+jwt")?;
    let holder_jwk = issuer_payload.pointer("/cnf/jwk").ok_or(SdJwtRejection::InvalidHolderKey)?;
    verify_es256_with_jwk(holder_jwk, kb_input, &kb_signature)
        .map_err(|_| SdJwtRejection::InvalidKeyBindingSignature)?;
    validate_times(&kb_payload, context.now, context.maximum_clock_skew)?;
    for (field, expected_value) in [
        ("nonce", context.expected_nonce),
        ("aud", context.expected_audience),
        ("purpose", context.expected_purpose),
        ("response_uri", context.expected_response_uri),
    ] {
        if string(&kb_payload, field)? != expected_value {
            return Err(SdJwtRejection::RequestBindingMismatch);
        }
    }
    let sd_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(
        context.presentation
            [..context.presentation.rfind(kb_jwt).ok_or(SdJwtRejection::MalformedCompact)?]
            .as_bytes(),
    ));
    if string(&kb_payload, "sd_hash")? != sd_hash {
        return Err(SdJwtRejection::RequestBindingMismatch);
    }
    if !context.status_snapshot.admissible_at(
        context.verified_height,
        context.maximum_root_age,
        context.require_issuance_log,
    ) {
        return Err(SdJwtRejection::StatusNotAdmissible);
    }
    if !context.status_snapshot.binds_evidence(context.status_root, context.issuance_log_root) {
        return Err(SdJwtRejection::StatusEvidenceMismatch);
    }

    let credential_commitment =
        commitment(b"ACTIVECHAIN-SD-JWT-CREDENTIAL-V1", issuer_jwt.as_bytes());
    let claims_commitment =
        commitment(b"ACTIVECHAIN-SD-JWT-DISCLOSURES-V1", disclosures.join("~").as_bytes());
    let holder_binding = commitment(
        b"ACTIVECHAIN-SD-JWT-HOLDER-JWK-V1",
        serde_json::to_vec(holder_jwk).map_err(|_| SdJwtRejection::MalformedJson)?.as_slice(),
    );
    let value_commitment = commitment(
        b"ACTIVECHAIN-SD-JWT-PREDICATE-VALUE-V1",
        serde_json::to_vec(&predicate_value).map_err(|_| SdJwtRejection::MalformedJson)?.as_slice(),
    );
    let nonce = commitment(b"ACTIVECHAIN-OPENID4VP-NONCE-V1", context.expected_nonce.as_bytes());
    let predicate = CredentialPredicateV1::new(
        context.status_snapshot.schema_id(),
        claims_commitment,
        holder_binding,
        context.chain_id,
        context.audience,
        context.action,
        nonce,
        context.policy_revision,
        context.expires_height,
        context.predicate_kind,
        value_commitment,
    )
    .map_err(|_| SdJwtRejection::InvalidOutput)?;
    let presentation = VcIssuerPresentationV1::new(
        context.issuer_binding.issuer(),
        VcIssuerFormatV1::SdJwtVc,
        credential_commitment,
        context.status_snapshot.commitment().map_err(|_| SdJwtRejection::InvalidOutput)?,
        context.issuer_binding.commitment().map_err(|_| SdJwtRejection::InvalidOutput)?,
        CredentialAssuranceClassV1::IssuerUpgraded,
        predicate,
        context.verified_height,
        context.chain_id,
        context.audience,
        context.action,
    )
    .map_err(|_| SdJwtRejection::InvalidOutput)?;
    Ok(VerifiedExternalPresentation {
        presentation,
        configuration_commitment: context.configuration_commitment,
        subject_binding: holder_binding,
        purpose_commitment: commitment(
            b"ACTIVECHAIN-OPENID4VP-PURPOSE-V1",
            context.expected_purpose.as_bytes(),
        ),
        status_anchor_height: context.status_snapshot.anchor_height(),
        status_age: context.verified_height.saturating_sub(context.status_snapshot.anchor_height()),
        has_issuance_log: context.issuance_log_root.is_some(),
        verifier_version: 1,
        proof_version: 1,
        replay_nullifier: commitment(
            b"ACTIVECHAIN-SD-JWT-OPENID4VP-REPLAY-V1",
            context.presentation.as_bytes(),
        ),
    })
}

/// Verifies first and consumes the request-bound presentation only after successful verification.
pub fn verify_sd_jwt_vc_once(
    cache: &mut SdJwtReplayCache,
    context: &SdJwtVerificationContext<'_>,
) -> Result<VerifiedExternalPresentation, SdJwtRejection> {
    let verified = verify_sd_jwt_vc(context)?;
    let replay_key =
        commitment(b"ACTIVECHAIN-SD-JWT-OPENID4VP-REPLAY-V1", context.presentation.as_bytes());
    cache.consume(replay_key)?;
    Ok(verified)
}

fn parse_jwt(token: &str) -> Result<(Value, Value, &[u8], Vec<u8>), SdJwtRejection> {
    if token.len() > MAX_JWT_BYTES {
        return Err(SdJwtRejection::Oversize);
    }
    let mut segments = token.split('.');
    let h = segments.next().ok_or(SdJwtRejection::MalformedCompact)?;
    let p = segments.next().ok_or(SdJwtRejection::MalformedCompact)?;
    let s = segments.next().ok_or(SdJwtRejection::MalformedCompact)?;
    if segments.next().is_some() || [h, p, s].iter().any(|v| v.is_empty()) {
        return Err(SdJwtRejection::MalformedCompact);
    }
    let signature = URL_SAFE_NO_PAD.decode(s).map_err(|_| SdJwtRejection::MalformedBase64Url)?;
    let input_len = h.len() + 1 + p.len();
    Ok((decode_json(h)?, decode_json(p)?, &token.as_bytes()[..input_len], signature))
}

fn decode_json(encoded: &str) -> Result<Value, SdJwtRejection> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| SdJwtRejection::MalformedBase64Url)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| SdJwtRejection::MalformedJson)?;
    if json_depth(&value) > MAX_JSON_DEPTH {
        return Err(SdJwtRejection::Oversize);
    }
    Ok(value)
}
fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(v) => 1 + v.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(v) => 1 + v.values().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}
fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str, SdJwtRejection> {
    value.get(field).and_then(Value::as_str).ok_or(SdJwtRejection::MalformedJson)
}
fn exact_header(value: &Value, typ: &str) -> Result<(), SdJwtRejection> {
    if string(value, "alg")? != "ES256" {
        return Err(SdJwtRejection::UnsupportedAlgorithm);
    }
    if string(value, "typ")? != typ {
        return Err(SdJwtRejection::UnsupportedType);
    }
    if value.get("crit").is_some() {
        return Err(SdJwtRejection::UnsupportedAlgorithm);
    }
    Ok(())
}
fn validate_times(value: &Value, now: u64, skew: u64) -> Result<(), SdJwtRejection> {
    let iat = value.get("iat").and_then(Value::as_u64).ok_or(SdJwtRejection::TimeInvalid)?;
    if iat > now.saturating_add(skew) {
        return Err(SdJwtRejection::TimeInvalid);
    }
    if let Some(nbf) = value.get("nbf").and_then(Value::as_u64) {
        if nbf > now.saturating_add(skew) {
            return Err(SdJwtRejection::TimeInvalid);
        }
    }
    if let Some(exp) = value.get("exp").and_then(Value::as_u64) {
        if exp.saturating_add(skew) < now {
            return Err(SdJwtRejection::TimeInvalid);
        }
    }
    Ok(())
}
pub(crate) fn verify_es256_with_jwk(
    jwk: &Value,
    input: &[u8],
    signature: &[u8],
) -> Result<(), SdJwtRejection> {
    if string(jwk, "kty")? != "EC" || string(jwk, "crv")? != "P-256" {
        return Err(SdJwtRejection::InvalidHolderKey);
    }
    let x = URL_SAFE_NO_PAD
        .decode(string(jwk, "x")?)
        .map_err(|_| SdJwtRejection::MalformedBase64Url)?;
    let y = URL_SAFE_NO_PAD
        .decode(string(jwk, "y")?)
        .map_err(|_| SdJwtRejection::MalformedBase64Url)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(SdJwtRejection::InvalidHolderKey);
    }
    let mut point = Vec::with_capacity(65);
    point.push(4);
    point.extend(x);
    point.extend(y);
    let key =
        VerifyingKey::from_sec1_bytes(&point).map_err(|_| SdJwtRejection::InvalidHolderKey)?;
    let sig = Signature::from_slice(signature).map_err(|_| SdJwtRejection::InvalidHolderKey)?;
    key.verify(input, &sig).map_err(|_| SdJwtRejection::InvalidHolderKey)
}
fn predicate_satisfied(kind: CredentialPredicateKind, value: &Value) -> bool {
    match kind {
        CredentialPredicateKind::AgeAtLeast => value == &Value::Bool(true),
        CredentialPredicateKind::JurisdictionNotIn => value.as_str().is_some_and(|v| !v.is_empty()),
        CredentialPredicateKind::AssetAmountAtLeast => value.as_u64().is_some_and(|v| v > 0),
    }
}
pub(crate) fn commitment(domain: &[u8], bytes: &[u8]) -> Digest384 {
    let mut h = Shake256::default();
    Update::update(&mut h, domain);
    Update::update(&mut h, bytes);
    let mut out = [0; 48];
    XofReader::read(&mut h.finalize_xof(), &mut out);
    Digest384::new(out)
}

fn reject_duplicate_json_keys_in_segments(presentation: &str) -> Result<(), SdJwtRejection> {
    // A conservative lexical guard catches duplicate keys before serde_json can collapse them.
    for token in presentation.split(['~', '.']) {
        if token.is_empty() {
            continue;
        }
        let Ok(bytes) = URL_SAFE_NO_PAD.decode(token) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if !text.starts_with(['{', '[']) {
            continue;
        }
        let mut keys = BTreeSet::new();
        for fragment in text.split(',') {
            if let Some((key, _)) = fragment.split_once(':') {
                let key = key.trim().trim_start_matches('{').trim().trim_matches('"');
                if !key.is_empty() && !keys.insert(key.to_owned()) {
                    return Err(SdJwtRejection::DuplicateJsonKey);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{
        ExternalCredentialStatusSnapshotV1, ExternalIssuerBindingStatusV1, ExternalIssuerProfileV1,
        ExternalStatusSnapshotStateV1,
    };
    use p256::ecdsa::{SigningKey, signature::Signer};
    use serde_json::json;

    fn d(value: u8) -> Digest384 {
        Digest384::new([value; 48])
    }
    fn principal(value: u8) -> PrincipalId {
        PrincipalId::new(d(value))
    }
    fn signing_key(value: u8) -> SigningKey {
        SigningKey::from_bytes((&[value; 32]).into()).unwrap()
    }
    fn jwk(key: &SigningKey) -> Value {
        let point = key.verifying_key().to_encoded_point(false);
        json!({
            "kty": "EC", "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())
        })
    }
    fn jwt(header: &Value, payload: &Value, key: &SigningKey) -> String {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        let input = format!("{header}.{payload}");
        let signature: Signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
    struct Fixture {
        presentation: String,
        issuer_jwk: Value,
        binding: ExternalIssuerBindingV1,
        status: ExternalCredentialStatusSnapshotV1,
    }
    fn fixture() -> Fixture {
        let issuer_key = signing_key(1);
        let holder_key = signing_key(2);
        let disclosure = URL_SAFE_NO_PAD.encode(br#"["salt","age_over_18",true]"#);
        let disclosure_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()));
        let issuer_payload = json!({
            "iss":"https://issuer.example", "iat":100, "nbf":100, "exp":200,
            "vct":"eu.europa.ec.eudi.pid.1", "cnf":{"jwk":jwk(&holder_key)},
            "_sd_alg":"sha-256", "_sd":[disclosure_digest]
        });
        let issuer_jwt = jwt(
            &json!({"alg":"ES256","typ":"dc+sd-jwt","kid":"issuer-1"}),
            &issuer_payload,
            &issuer_key,
        );
        let prefix = format!("{issuer_jwt}~{disclosure}~");
        let kb_payload = json!({
            "iat":100, "exp":200, "nonce":"nonce-1", "aud":"aud-1",
            "purpose":"age-check", "response_uri":"https://verifier.example/cb",
            "sd_hash":URL_SAFE_NO_PAD.encode(Sha256::digest(prefix.as_bytes()))
        });
        let kb = jwt(&json!({"alg":"ES256","typ":"kb+jwt"}), &kb_payload, &holder_key);
        let profile = ExternalIssuerProfileV1::new(d(20), d(21), d(22), 1, d(23), d(24)).unwrap();
        let issuer_jwk = jwk(&issuer_key);
        let issuer_identity =
            commitment(b"ACTIVECHAIN-EXTERNAL-ISSUER-URL-V1", b"https://issuer.example");
        let trust_identity = commitment(
            b"ACTIVECHAIN-EXTERNAL-ISSUER-JWK-V1",
            &serde_json::to_vec(&issuer_jwk).unwrap(),
        );
        let binding = ExternalIssuerBindingV1::new(
            ChainId::new(d(1)),
            d(2),
            principal(3),
            issuer_identity,
            trust_identity,
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
        Fixture { presentation: format!("{prefix}{kb}"), issuer_jwk, binding, status }
    }
    fn context<'a>(f: &'a Fixture) -> SdJwtVerificationContext<'a> {
        SdJwtVerificationContext {
            presentation: &f.presentation,
            expected_issuer: "https://issuer.example",
            issuer_jwk: &f.issuer_jwk,
            configuration_commitment: d(20),
            issuer_binding: &f.binding,
            status_snapshot: &f.status,
            status_root: d(27),
            issuance_log_root: Some(d(30)),
            verified_height: 10,
            maximum_root_age: 5,
            require_issuance_log: true,
            now: 110,
            maximum_clock_skew: 5,
            expected_nonce: "nonce-1",
            expected_audience: "aud-1",
            expected_purpose: "age-check",
            expected_response_uri: "https://verifier.example/cb",
            chain_id: ChainId::new(d(1)),
            audience: principal(8),
            action: TransactionId::new(d(9)),
            predicate_kind: CredentialPredicateKind::AgeAtLeast,
            predicate_claim: "age_over_18",
            policy_revision: 1,
            expires_height: 20,
        }
    }

    #[test]
    fn vcissuer_sd_jwt_produces_one_action_bound_handoff() {
        let f = fixture();
        let verified = verify_sd_jwt_vc(&context(&f)).unwrap();
        assert_eq!(verified.presentation().format(), VcIssuerFormatV1::SdJwtVc);
        assert!(verified.presentation().predicate().binds_action(
            ChainId::new(d(1)),
            principal(8),
            TransactionId::new(d(9))
        ));
    }

    #[test]
    fn nonce_status_and_disclosure_substitution_fail_closed() {
        let f = fixture();
        let mut replay = context(&f);
        replay.expected_nonce = "other";
        assert_eq!(verify_sd_jwt_vc(&replay), Err(SdJwtRejection::RequestBindingMismatch));
        let mut stale = context(&f);
        stale.verified_height = 16;
        stale.maximum_root_age = 5;
        assert_eq!(verify_sd_jwt_vc(&stale), Err(SdJwtRejection::StatusNotAdmissible));
        let mut tampered = f.presentation.clone();
        let position = tampered.find("~").unwrap() + 1;
        tampered.insert(position, 'A');
        let mut bad = context(&f);
        bad.presentation = &tampered;
        assert_eq!(verify_sd_jwt_vc(&bad), Err(SdJwtRejection::DisclosureDigestMismatch));
    }

    #[test]
    fn replay_cache_is_consumed_only_after_success_and_survives_restart() {
        let f = fixture();
        let mut cache = SdJwtReplayCache::default();
        verify_sd_jwt_vc_once(&mut cache, &context(&f)).unwrap();
        let mut restored = SdJwtReplayCache::from_entries(cache.entries()).unwrap();
        assert_eq!(verify_sd_jwt_vc_once(&mut restored, &context(&f)), Err(SdJwtRejection::Replay));

        let mut invalid = context(&f);
        invalid.expected_nonce = "wrong";
        let mut empty = SdJwtReplayCache::default();
        assert_eq!(
            verify_sd_jwt_vc_once(&mut empty, &invalid),
            Err(SdJwtRejection::RequestBindingMismatch)
        );
        assert!(empty.entries().is_empty());
    }

    #[test]
    fn duplicate_keys_and_algorithm_confusion_are_typed_rejections() {
        let duplicated =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","alg":"none","typ":"dc+sd-jwt"}"#);
        let presentation = format!("{duplicated}.e30.AA~e30~e30.e30.AA");
        assert_eq!(
            reject_duplicate_json_keys_in_segments(&presentation),
            Err(SdJwtRejection::DuplicateJsonKey)
        );
        assert_eq!(
            exact_header(&json!({"alg":"none","typ":"dc+sd-jwt"}), "dc+sd-jwt"),
            Err(SdJwtRejection::UnsupportedAlgorithm)
        );
        assert_eq!(
            exact_header(&json!({"alg":"ES256","typ":"dc+sd-jwt","crit":["x"]}), "dc+sd-jwt"),
            Err(SdJwtRejection::UnsupportedAlgorithm)
        );
    }
}
