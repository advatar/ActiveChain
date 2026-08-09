use activechain_payment_verifier_service::{
    MAX_PAYMENT_EVIDENCE_BYTES, VerificationPolicy, VerifyRequestV1, verify_development_fixture,
    verify_finalized_payment,
};
use activechain_protocol_types::{ChainId, Digest384, PrincipalId};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Serialize;
use std::{
    env,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;

#[derive(Clone)]
struct AppState {
    bearer_token: Arc<Vec<u8>>,
    profile: Profile,
}

#[derive(Clone)]
enum Profile {
    Production(VerificationPolicy),
    Development { audience: String },
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    profile: &'static str,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen = env::var("ACTIVECHAIN_PAYMENT_VERIFIER_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let bearer_token = required("ACTIVECHAIN_PAYMENT_VERIFIER_BEARER_TOKEN")?.into_bytes();
    if bearer_token.len() < 32 {
        return Err("verifier bearer token must contain at least 32 bytes".into());
    }
    let audience = required("ACTIVECHAIN_PAYMENT_VERIFIER_AUDIENCE")?;
    let development = env::var("ACTIVECHAIN_PAYMENT_VERIFIER_ALLOW_DEV_FIXTURES")
        .is_ok_and(|value| value == "true");
    let profile = if development {
        if !is_loopback_or_unspecified(&listen)? {
            return Err(
                "development fixtures may only bind loopback or a container interface".into()
            );
        }
        eprintln!("WARNING: ActiveChain payment verifier is accepting development fixtures");
        Profile::Development { audience }
    } else {
        Profile::Production(VerificationPolicy {
            audience,
            chain: ChainId::new(Digest384::new(required_digest("ACTIVECHAIN_TRUSTED_CHAIN_B64")?)),
            genesis: Digest384::new(required_digest("ACTIVECHAIN_TRUSTED_GENESIS_B64")?),
            merchant: PrincipalId::new(Digest384::new(required_digest(
                "ACTIVECHAIN_PAYMENT_MERCHANT_B64",
            )?)),
        })
    };
    let state = AppState { bearer_token: Arc::new(bearer_token), profile };
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(health))
        .route("/v1/verify-inference-authorization", post(verify))
        .layer(DefaultBodyLimit::max(MAX_PAYMENT_EVIDENCE_BYTES * 2))
        .with_state(state);
    let listener = TcpListener::bind(&listen).await?;
    eprintln!("ActiveChain payment verifier listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        profile: match &state.profile {
            Profile::Production(_) => "production",
            Profile::Development { .. } => "local-development-only",
        },
    })
}

async fn verify(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !authorized(&headers, &state.bearer_token) {
        return (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "unauthorized" }))
            .into_response();
    }
    let request: VerifyRequestV1 = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse { error: "malformed_request" }),
            )
                .into_response();
        }
    };
    let result = match &state.profile {
        Profile::Production(policy) => verify_finalized_payment(&request, policy, unix_time()),
        Profile::Development { audience } => verify_development_fixture(&request, audience),
    };
    match result {
        Ok(response) => Json(response).into_response(),
        Err(error) => {
            (StatusCode::UNPROCESSABLE_ENTITY, Json(ErrorResponse { error: error.code() }))
                .into_response()
        }
    }
}

fn authorized(headers: &HeaderMap, expected: &[u8]) -> bool {
    let Some(value) = headers.get("authorization").and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    token.len() == expected.len() && bool::from(token.as_bytes().ct_eq(expected))
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn required_digest(name: &str) -> Result<[u8; 48], Box<dyn std::error::Error>> {
    BASE64
        .decode(required(name)?)?
        .try_into()
        .map_err(|_| format!("{name} must decode to 48 bytes").into())
}

fn unix_time() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

fn is_loopback_or_unspecified(listen: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let address: std::net::SocketAddr = listen.parse()?;
    Ok(address.ip().is_loopback() || address.ip().is_unspecified())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn bearer_auth_requires_exact_scheme_and_value() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer exact-secret"));
        assert!(authorized(&headers, b"exact-secret"));
        assert!(!authorized(&headers, b"exact-secret-extra"));
        headers.insert("authorization", HeaderValue::from_static("Basic exact-secret"));
        assert!(!authorized(&headers, b"exact-secret"));
    }

    #[test]
    fn development_bind_policy_is_bounded_to_local_interfaces() {
        assert!(is_loopback_or_unspecified("127.0.0.1:8080").unwrap());
        assert!(is_loopback_or_unspecified("0.0.0.0:8080").unwrap());
        assert!(!is_loopback_or_unspecified("192.0.2.1:8080").unwrap());
    }
}
