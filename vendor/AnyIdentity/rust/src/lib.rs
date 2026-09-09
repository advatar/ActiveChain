mod crypto;
mod ffi;
pub mod model;
pub mod protocol;
#[cfg(test)]
mod tests;

use ed25519_dalek::SigningKey;
use model::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Serialize)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
}
impl Error {
    pub fn new(code: &'static str, message: &str) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn invalid(message: &str) -> Self {
        Self::new("invalid_input", message)
    }
    fn json(_: serde_json::Error) -> Self {
        Self::invalid("malformed JSON or schema mismatch")
    }
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    PublicKey,
    CreateAuthority {
        recovery_keys: BTreeSet<String>,
        recovery_threshold: usize,
    },
    Enroll {
        enrollment: Enrollment,
    },
    Attest {
        enrollment: Signed<Enrollment>,
        evidence: Evidence,
        expected_audience: String,
        expected_nonce: String,
        now: u64,
    },
    Assess {
        state: AuthorityState,
        evidence: Vec<Signed<Evidence>>,
        roots: Vec<TrustedRoot>,
        policy: AssurancePolicy,
        revocations: RevocationSnapshot,
        now: u64,
    },
    ApproveTransition {
        transition: Transition,
    },
    ApplyTransition {
        state: AuthorityState,
        approvals: Vec<Signed<Transition>>,
        revocations: RevocationSnapshot,
        now: u64,
    },
    Delegate {
        delegation: Delegation,
    },
    SignAction {
        action: Action,
    },
    VerifyAction {
        state: AuthorityState,
        chain: Vec<Signed<Delegation>>,
        action: Box<Signed<Action>>,
        expected: Box<Action>,
        revocations: RevocationSnapshot,
        now: u64,
    },
    EnvelopeDigest {
        envelope: Value,
    },
    EvidenceReference {
        issuer: String,
        id: String,
    },
}
fn dispatch(key: Option<&SigningKey>, input: &[u8]) -> Result<Value> {
    let request: Request = serde_json::from_slice(input).map_err(Error::json)?;
    let need_key = || key.ok_or_else(|| Error::invalid("operation requires a key"));
    match request {
        Request::PublicKey => Ok(json!(crypto::public_key(need_key()?))),
        Request::CreateAuthority {
            recovery_keys,
            recovery_threshold,
        } => {
            let current_key = crypto::public_key(need_key()?);
            let state = AuthorityState {
                authority_id: crypto::authority_id(&current_key)?,
                current_key,
                epoch: 0,
                recovery_keys,
                recovery_threshold,
            };
            protocol::validate_state(&state)?;
            Ok(json!(state))
        }
        Request::Enroll { enrollment } => {
            if enrollment.subject_key != crypto::public_key(need_key()?) {
                return Err(Error::invalid("enrollment key mismatch"));
            }
            let signed = crypto::sign(need_key()?, "enrollment", enrollment)?;
            protocol::validate_enrollment(
                &signed,
                &signed.payload.audience,
                &signed.payload.nonce,
                signed.payload.issued_at,
            )?;
            Ok(json!(signed))
        }
        Request::Attest {
            enrollment,
            evidence,
            expected_audience,
            expected_nonce,
            now,
        } => {
            protocol::validate_enrollment(&enrollment, &expected_audience, &expected_nonce, now)?;
            protocol::validate_evidence(&evidence)?;
            protocol::window(evidence.issued_at, evidence.expires_at, now)?;
            if evidence.authority_id != enrollment.payload.authority_id
                || evidence.subject_key != enrollment.payload.subject_key
            {
                return Err(Error::new("binding", "evidence does not match enrollment"));
            }
            Ok(json!(crypto::sign(need_key()?, "evidence", evidence)?))
        }
        Request::Assess {
            state,
            evidence,
            roots,
            policy,
            revocations,
            now,
        } => Ok(json!(protocol::assess(
            &state,
            &evidence,
            &roots,
            &policy,
            &revocations,
            now
        )?)),
        Request::ApproveTransition { transition } => {
            crypto::decode::<32>(&transition.authority_id)?;
            crypto::parse_public(&transition.previous_key)?;
            crypto::parse_public(&transition.new_key)?;
            protocol::window(
                transition.issued_at,
                transition.expires_at,
                transition.issued_at,
            )?;
            Ok(json!(crypto::sign(need_key()?, "transition", transition)?))
        }
        Request::ApplyTransition {
            state,
            approvals,
            revocations,
            now,
        } => Ok(json!(protocol::apply_transition(
            &state,
            &approvals,
            &revocations,
            now
        )?)),
        Request::Delegate { delegation } => {
            protocol::validate_delegation(&delegation)?;
            Ok(json!(crypto::sign(need_key()?, "delegation", delegation)?))
        }
        Request::SignAction { action } => {
            protocol::validate_action(&action)?;
            Ok(json!(crypto::sign(need_key()?, "action", action)?))
        }
        Request::VerifyAction {
            state,
            chain,
            action,
            expected,
            revocations,
            now,
        } => Ok(json!(protocol::verify_action(
            &state,
            &chain,
            &action,
            &expected,
            &revocations,
            now
        )?)),
        Request::EnvelopeDigest { envelope } => Ok(json!(normalized_envelope_digest(envelope)?)),
        Request::EvidenceReference { issuer, id } => {
            Ok(json!(protocol::evidence_reference(&issuer, &id)?))
        }
    }
}

// Normalize each payload through its schema before hashing. Swift omits nil fields,
// while Rust signs their canonical null representation. Never hash raw JSON here.
fn normalized_envelope_digest(value: Value) -> Result<String> {
    macro_rules! typed_digest {
        ($type:ty, $kind:literal) => {{
            let signed: Signed<$type> = serde_json::from_value(value).map_err(Error::json)?;
            crypto::verify(&signed, $kind, &signed.signer)?;
            crypto::signed_digest(&signed)
        }};
    }
    match value.get("kind").and_then(Value::as_str) {
        Some("enrollment") => typed_digest!(Enrollment, "enrollment"),
        Some("evidence") => typed_digest!(Evidence, "evidence"),
        Some("transition") => typed_digest!(Transition, "transition"),
        Some("delegation") => typed_digest!(Delegation, "delegation"),
        Some("action") => typed_digest!(Action, "action"),
        _ => Err(Error::invalid("unknown signed envelope kind")),
    }
}
