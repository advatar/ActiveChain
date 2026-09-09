use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

macro_rules! model {
    ($name:ident { $($field:ident : $type:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $(pub $field: $type),* }
    };
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub version: u8,
    pub kind: String,
    pub signer: String,
    pub payload: T,
    pub signature: String,
}
model!(Enrollment {
    authority_id: String,
    subject_key: String,
    audience: String,
    nonce: String,
    issued_at: u64,
    expires_at: u64
});
model!(Evidence {
    id: String, authority_id: String, subject_key: String, issuer: String,
    credential_kind: String, claims: BTreeSet<String>, assurance_level: u8,
    liveness: bool, hardware_bound: bool, issued_at: u64, expires_at: u64
});
model!(TrustedRoot {
    issuer: String, public_key: String, independence_group: String,
    credential_kinds: BTreeSet<String>, maximum_assurance_level: u8
});
model!(AssurancePolicy {
    minimum_independent_roots: usize, minimum_assurance_level: u8,
    maximum_age_seconds: u64, required_claims: BTreeSet<String>,
    require_liveness: bool, require_hardware: bool
});
model!(Assurance {
    authority_id: String, subject_key: String, independent_roots: usize,
    accepted_evidence: Vec<String>, claims: BTreeSet<String>, valid_until: u64
});
model!(AuthorityState {
    authority_id: String, current_key: String, epoch: u64,
    recovery_keys: BTreeSet<String>, recovery_threshold: usize
});
model!(Transition {
    authority_id: String,
    previous_key: String,
    new_key: String,
    epoch: u64,
    issued_at: u64,
    expires_at: u64,
    recovery: bool
});
model!(RevocationSnapshot {
    checked_at: u64, valid_until: u64, revoked_keys: BTreeSet<String>,
    revoked_evidence: BTreeSet<String>, revoked_delegations: BTreeSet<String>,
    revoked_authorities: BTreeSet<String>
});
model!(Scope {
    operations: BTreeSet<String>, resources: BTreeSet<String>,
    maximum_amount_minor: Option<u64>, currency: Option<String>,
    merchant_category: Option<String>
});
model!(Delegation {
    authority_id: String, epoch: u64, parent_digest: Option<String>,
    delegate_key: String, audience: String, scope: Scope,
    not_before: u64, expires_at: u64, remaining_depth: u8
});
model!(Action {
    authority_id: String, epoch: u64, audience: String, nonce: String,
    operation: String, resource: String, payload_digest: String,
    amount_minor: Option<u64>, currency: Option<String>,
    merchant_category: Option<String>, issued_at: u64, expires_at: u64
});
model!(Verification {
    authority_id: String,
    signer: String,
    delegation_depth: usize,
    action_digest: String,
    valid_until: u64
});
