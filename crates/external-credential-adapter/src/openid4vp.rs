//! Standard SD-JWT+KB handoff used by EUWallet. Unlike the legacy adapter profile, a standard
//! holder signs `iat`, `aud`, `nonce` and `sd_hash`, not application-specific claims. The verifier
//! commits the complete application request into the nonce before sending its signed request.
//!
//! Persist this request and its exact trusted context before launching the wallet. Neither a
//! callback nor a presenter-supplied context may recreate a pending request. Successful verification
//! consumes the request nonce (not the potentially re-signed presentation bytes).

use crate::{
    SdJwtRejection, SdJwtReplayCache, SdJwtVerificationContext, VerifiedExternalPresentation,
    commitment, parse_jwt, string, verify_sd_jwt_profile,
};
use activechain_protocol_types::{Digest384, PrincipalId};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;

pub const MAX_REQUEST_LIFETIME_SECONDS: u64 = 120;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PresentationResponse {
    Presented(String),
    Declined,
}

/// Parse the actual form-encoded OpenID4VP `direct_post` envelope emitted by EUWallet. The
/// returned compact presentation is untrusted until `verify_openid4vp_sd_jwt_once` succeeds.
/// A redirect back to the app carries no verification authority.
pub fn parse_direct_post(
    body: &[u8],
    expected_state: &str,
) -> Result<PresentationResponse, SdJwtRejection> {
    if body.is_empty() || body.len() > 3 * crate::MAX_PRESENTATION_BYTES + 2048 {
        return Err(SdJwtRejection::Oversize);
    }
    let mut index = 0;
    while index < body.len() {
        if body[index] == b'%' {
            if index + 2 >= body.len()
                || !body[index + 1].is_ascii_hexdigit()
                || !body[index + 2].is_ascii_hexdigit()
            {
                return Err(SdJwtRejection::MalformedCompact);
            }
            index += 3;
        } else {
            if !body[index].is_ascii() {
                return Err(SdJwtRejection::MalformedCompact);
            }
            index += 1;
        }
    }
    let mut fields = BTreeMap::new();
    for (key, value) in form_urlencoded::parse(body) {
        if !matches!(key.as_ref(), "state" | "vp_token" | "error" | "error_description")
            || fields.insert(key.into_owned(), value.into_owned()).is_some()
        {
            return Err(SdJwtRejection::MalformedCompact);
        }
    }
    if expected_state.len() < 32 || fields.get("state").map(String::as_str) != Some(expected_state)
    {
        return Err(SdJwtRejection::RequestBindingMismatch);
    }
    if fields.contains_key("error") {
        if fields.contains_key("vp_token")
            || fields.get("error").map(String::as_str) != Some("access_denied")
        {
            return Err(SdJwtRejection::MalformedCompact);
        }
        return Ok(PresentationResponse::Declined);
    }
    if fields.contains_key("error_description") {
        return Err(SdJwtRejection::MalformedCompact);
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Token {
        identity: Vec<String>,
    }
    let raw = fields.get("vp_token").ok_or(SdJwtRejection::MalformedCompact)?;
    // The request asks for one credential under one DCQL id. Reject extra credentials, duplicate
    // query ids, and bare legacy tokens rather than accidentally accepting a different selection.
    let token: Token = serde_json::from_str(raw).map_err(|_| SdJwtRejection::MalformedJson)?;
    if token.identity.len() != 1 {
        return Err(SdJwtRejection::MalformedCompact);
    }
    let compact = token.identity.into_iter().next().ok_or(SdJwtRejection::MalformedCompact)?;
    if compact.is_empty() || compact.len() > crate::MAX_PRESENTATION_BYTES {
        return Err(SdJwtRejection::Oversize);
    }
    Ok(PresentationResponse::Presented(compact))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenId4VpRequest {
    wallet: PrincipalId,
    wallet_audience: String,
    entropy: Digest384,
    issued_at: u64,
    expires_at: u64,
    credential_type: String,
    nonce: String,
}

impl OpenId4VpRequest {
    /// `entropy` must come from the verifier's cryptographically secure random generator, once
    /// per request. It must not be provided by the presenting wallet. The native wallet principal
    /// is separate from the verifier audience and will still require its own signing-key consent.
    pub fn new(
        context: &SdJwtVerificationContext<'_>,
        wallet: PrincipalId,
        entropy: Digest384,
        wallet_audience: &str,
        credential_type: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, SdJwtRejection> {
        if *wallet.digest() == Digest384::ZERO
            || entropy == Digest384::ZERO
            || wallet_audience.is_empty()
            || wallet_audience.len() > 512
            || credential_type.is_empty()
            || credential_type.len() > 512
            || expires_at <= issued_at
            || expires_at - issued_at > MAX_REQUEST_LIFETIME_SECONDS
            || context.expected_audience.is_empty()
            || context.expected_purpose.is_empty()
            || context.expected_response_uri.is_empty()
            || context.expected_audience.len() > 2048
            || context.expected_purpose.len() > 2048
            || context.expected_response_uri.len() > 2048
            || context.maximum_clock_skew > 30
        {
            return Err(SdJwtRejection::RequestBindingMismatch);
        }
        let mut request = Self {
            wallet,
            wallet_audience: wallet_audience.to_owned(),
            entropy,
            issued_at,
            expires_at,
            credential_type: credential_type.to_owned(),
            nonce: String::new(),
        };
        request.nonce = request.context_nonce(context)?;
        Ok(request)
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub const fn wallet(&self) -> PrincipalId {
        self.wallet
    }

    /// Exact JWS signing input for EUWallet's existing OpenID4VP loader and consent machine.
    /// The service appends an ES256 signature made by its registered RP key. Certificate bytes are
    /// transport material only: EUWallet validates them against its own signed trust registration.
    pub fn authorization_signing_input(
        &self,
        context: &SdJwtVerificationContext<'_>,
        state: &str,
        certificate_chain: &[Vec<u8>],
    ) -> Result<String, SdJwtRejection> {
        if self.context_nonce(context)? != self.nonce
            || state.len() < 32
            || state.len() > 128
            || !state
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            || certificate_chain.is_empty()
            || certificate_chain.len() > 8
            || certificate_chain
                .iter()
                .any(|certificate| certificate.is_empty() || certificate.len() > 16 * 1024)
            || certificate_chain.iter().map(Vec::len).sum::<usize>() > 64 * 1024
        {
            return Err(SdJwtRejection::RequestBindingMismatch);
        }
        let header = json!({"alg":"ES256", "typ":"oauth-authz-req+jwt",
            "x5c":certificate_chain.iter().map(|certificate| STANDARD.encode(certificate)).collect::<Vec<_>>()});
        let payload = json!({
            "iss":context.expected_audience, "client_id":context.expected_audience,
            "aud":self.wallet_audience, "response_type":"vp_token", "response_mode":"direct_post",
            "response_uri":context.expected_response_uri, "nonce":self.nonce, "state":state,
            "iat":self.issued_at, "exp":self.expires_at, "purpose":context.expected_purpose,
            "dcql_query":{"credentials":[{"id":"identity", "format":"dc+sd-jwt",
                "meta":{"vct_values":[self.credential_type]}, "claims":[{"path":[context.predicate_claim]}]}]}
        });
        let encoded_header =
            serde_json::to_vec(&header).map_err(|_| SdJwtRejection::InvalidOutput)?;
        let encoded_payload =
            serde_json::to_vec(&payload).map_err(|_| SdJwtRejection::InvalidOutput)?;
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(encoded_header),
            URL_SAFE_NO_PAD.encode(encoded_payload)
        ))
    }

    fn context_nonce(
        &self,
        context: &SdJwtVerificationContext<'_>,
    ) -> Result<String, SdJwtRejection> {
        // JSON arrays are unambiguous and length-delimited; object member order is not involved.
        // The issuer binding commitment includes its chain/genesis and governance revision.
        let binding =
            context.issuer_binding.commitment().map_err(|_| SdJwtRejection::InvalidOutput)?;
        let bytes = serde_json::to_vec(&json!([
            "ACTIVECHAIN-EUWALLET-REQUEST-V1",
            URL_SAFE_NO_PAD.encode(self.wallet.digest().as_bytes()),
            URL_SAFE_NO_PAD.encode(self.entropy.as_bytes()),
            self.issued_at,
            self.expires_at,
            self.credential_type,
            self.wallet_audience,
            URL_SAFE_NO_PAD.encode(context.chain_id.digest().as_bytes()),
            URL_SAFE_NO_PAD.encode(context.audience.digest().as_bytes()),
            URL_SAFE_NO_PAD.encode(context.action.digest().as_bytes()),
            URL_SAFE_NO_PAD.encode(binding.as_bytes()),
            URL_SAFE_NO_PAD.encode(context.configuration_commitment.as_bytes()),
            context.expected_issuer,
            context.expected_audience,
            context.expected_purpose,
            context.expected_response_uri,
            context.predicate_kind as u8,
            context.predicate_claim,
            context.policy_revision,
            context.expires_height
        ]))
        .map_err(|_| SdJwtRejection::InvalidOutput)?;
        Ok(URL_SAFE_NO_PAD
            .encode(commitment(b"ACTIVECHAIN-OPENID4VP-REQUEST-NONCE-V1", &bytes).as_bytes()))
    }
}

/// Returns the same opaque, governance/status-checked native admission evidence as the original
/// adapter, but only for a verifier-created, request-committed standard SD-JWT+KB presentation.
/// Replay entries must be committed durably before returning success to the application.
pub fn verify_openid4vp_sd_jwt_once(
    cache: &mut SdJwtReplayCache,
    context: &SdJwtVerificationContext<'_>,
    request: &OpenId4VpRequest,
) -> Result<VerifiedExternalPresentation, SdJwtRejection> {
    if context.expected_nonce != request.nonce
        || request.context_nonce(context)? != request.nonce
        || context.now < request.issued_at
        || context.now >= request.expires_at
        || context.maximum_clock_skew > 30
    {
        return Err(SdJwtRejection::RequestBindingMismatch);
    }
    if context.presentation.len() > crate::MAX_PRESENTATION_BYTES {
        return Err(SdJwtRejection::Oversize);
    }
    let issuer = context.presentation.split('~').next().ok_or(SdJwtRejection::MalformedCompact)?;
    let (_, issuer_payload, _, _) = parse_jwt(issuer)?;
    if string(&issuer_payload, "vct")? != request.credential_type {
        return Err(SdJwtRejection::ProfileNotAdmitted);
    }
    // A missing or mistyped expiry must not turn a short-lived credential into perpetual evidence.
    let expiry = issuer_payload
        .get("exp")
        .and_then(serde_json::Value::as_u64)
        .ok_or(SdJwtRejection::TimeInvalid)?;
    if context.now >= expiry {
        return Err(SdJwtRejection::TimeInvalid);
    }
    let kb = context.presentation.rsplit('~').next().ok_or(SdJwtRejection::MalformedCompact)?;
    let (_, holder_payload, _, _) = parse_jwt(kb)?;
    for payload in [&issuer_payload, &holder_payload] {
        for field in ["iat", "nbf", "exp"] {
            if payload.get(field).is_some_and(|value| value.as_u64().is_none()) {
                return Err(SdJwtRejection::TimeInvalid);
            }
        }
    }
    let issued = holder_payload
        .get("iat")
        .and_then(serde_json::Value::as_u64)
        .ok_or(SdJwtRejection::TimeInvalid)?;
    if issued.saturating_add(context.maximum_clock_skew) < request.issued_at {
        return Err(SdJwtRejection::TimeInvalid);
    }
    let verified = verify_sd_jwt_profile(context, false)?;
    cache.consume(commitment(
        b"ACTIVECHAIN-OPENID4VP-CONSUMED-REQUEST-V1",
        request.nonce.as_bytes(),
    ))?;
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(fields: &[(&str, &str)]) -> Vec<u8> {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish()
            .into_bytes()
    }

    #[test]
    fn direct_post_is_bound_to_one_state_and_one_dcql_credential() {
        let state = "s".repeat(32);
        let token = r#"{"identity":["issuer.payload.signature~holder.payload.signature"]}"#;
        assert!(matches!(
            parse_direct_post(&form(&[("state", &state), ("vp_token", token)]), &state),
            Ok(PresentationResponse::Presented(_))
        ));
        for fields in [
            vec![("state", "other"), ("vp_token", token)],
            vec![("state", &state), ("state", &state), ("vp_token", token)],
            vec![("state", &state), ("vp_token", token), ("error", "access_denied")],
        ] {
            assert!(parse_direct_post(&form(&fields), &state).is_err());
        }
        for substituted in [
            r#"{"identity":["one","two"]}"#,
            r#"{"identity":["one"],"identity":["two"]}"#,
            r#"{"identity":["one"],"other":["two"]}"#,
            r#"{"identity":"one"}"#,
            "bare.jwt",
        ] {
            assert!(
                parse_direct_post(&form(&[("state", &state), ("vp_token", substituted)]), &state)
                    .is_err()
            );
        }
    }

    #[test]
    fn decline_is_not_a_successful_presentation_and_bad_encoding_is_refused() {
        let state = "s".repeat(32);
        assert_eq!(
            parse_direct_post(&form(&[("state", &state), ("error", "access_denied")]), &state),
            Ok(PresentationResponse::Declined)
        );
        for body in [b"state=%".as_slice(), b"state=%GG", b"state=\xff"] {
            assert!(parse_direct_post(body, &state).is_err());
        }
    }
}
