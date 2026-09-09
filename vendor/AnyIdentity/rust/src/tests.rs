use super::*;
use crate::{crypto::*, protocol::*};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}
fn state() -> AuthorityState {
    let k = public_key(&key(1));
    AuthorityState {
        authority_id: authority_id(&k).unwrap(),
        current_key: k,
        epoch: 0,
        recovery_keys: [public_key(&key(4)), public_key(&key(5))].into(),
        recovery_threshold: 2,
    }
}
fn revocations() -> RevocationSnapshot {
    RevocationSnapshot {
        checked_at: 100,
        valid_until: 1000,
        revoked_keys: BTreeSet::new(),
        revoked_evidence: BTreeSet::new(),
        revoked_delegations: BTreeSet::new(),
        revoked_authorities: BTreeSet::new(),
    }
}
fn evidence(issuer: &str, s: &AuthorityState) -> Evidence {
    Evidence {
        id: "credential-1".into(),
        authority_id: s.authority_id.clone(),
        subject_key: s.current_key.clone(),
        issuer: issuer.into(),
        credential_kind: "passport".into(),
        claims: set(&["adult", "person"]),
        assurance_level: 2,
        liveness: true,
        hardware_bound: false,
        issued_at: 100,
        expires_at: 1000,
    }
}
fn roots() -> Vec<TrustedRoot> {
    (2..=3)
        .map(|n| TrustedRoot {
            issuer: format!("issuer-{n}"),
            public_key: public_key(&key(n)),
            independence_group: format!("group-{n}"),
            credential_kinds: set(&["passport"]),
            maximum_assurance_level: 2,
        })
        .collect()
}
fn policy() -> AssurancePolicy {
    AssurancePolicy {
        minimum_independent_roots: 2,
        minimum_assurance_level: 2,
        maximum_age_seconds: 500,
        required_claims: set(&["adult"]),
        require_liveness: true,
        require_hardware: false,
    }
}
fn all_evidence(s: &AuthorityState) -> Vec<Signed<Evidence>> {
    (2..=3)
        .map(|n| sign(&key(n), "evidence", evidence(&format!("issuer-{n}"), s)).unwrap())
        .collect()
}
fn scope() -> Scope {
    Scope {
        operations: set(&["book"]),
        resources: set(&["flight"]),
        maximum_amount_minor: Some(200_000),
        currency: Some("GBP".into()),
        merchant_category: Some("travel".into()),
    }
}
fn delegation() -> Delegation {
    Delegation {
        authority_id: state().authority_id,
        epoch: 0,
        parent_digest: None,
        delegate_key: public_key(&key(6)),
        audience: "travel.example".into(),
        scope: scope(),
        not_before: 100,
        expires_at: 900,
        remaining_depth: 1,
    }
}
fn action() -> Action {
    Action {
        authority_id: state().authority_id,
        epoch: 0,
        audience: "travel.example".into(),
        nonce: "random-verifier-challenge".into(),
        operation: "book".into(),
        resource: "flight".into(),
        payload_digest: digest(b"flight-details"),
        amount_minor: Some(123_000),
        currency: Some("GBP".into()),
        merchant_category: Some("travel".into()),
        issued_at: 150,
        expires_at: 200,
    }
}
fn transition(recovery: bool) -> Transition {
    Transition {
        authority_id: state().authority_id,
        previous_key: state().current_key,
        new_key: public_key(&key(7)),
        epoch: 1,
        issued_at: 100,
        expires_at: 300,
        recovery,
    }
}

#[test]
fn rfc8032_vector_and_sha256() {
    let seed =
        decode::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let k = SigningKey::from_bytes(&seed);
    assert_eq!(
        public_key(&k),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    assert_eq!(hex::encode(k.sign(b"").to_bytes()), "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    assert_eq!(
        digest(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
#[test]
fn pairwise_is_stable_separated_and_not_the_master() {
    let first = public_key(&derive(&key(1), "bank.example").unwrap());
    assert_eq!(first, public_key(&derive(&key(1), "bank.example").unwrap()));
    assert_ne!(
        first,
        public_key(&derive(&key(1), "hospital.example").unwrap())
    );
    assert_ne!(first, public_key(&derive(&key(2), "bank.example").unwrap()));
    assert_ne!(first, public_key(&key(1)));
    assert!(derive(&key(1), "").is_err());
}
#[test]
fn signatures_bind_type_version_and_all_payload_fields() {
    let mut signed = sign(&key(1), "action", action()).unwrap();
    verify(&signed, "action", &state().current_key).unwrap();
    assert!(verify(&signed, "delegation", &state().current_key).is_err());
    signed.version = 2;
    assert!(verify(&signed, "action", &state().current_key).is_err());
    signed.version = 1;
    signed.payload.amount_minor = Some(1);
    assert!(verify(&signed, "action", &state().current_key).is_err());
}
#[test]
fn multi_root_assurance_and_credential_renewal() {
    let s = state();
    let mut evidence = all_evidence(&s);
    let a = assess(&s, &evidence, &roots(), &policy(), &revocations(), 150).unwrap();
    assert_eq!(a.independent_roots, 2);
    assert_eq!(a.valid_until, 600);
    evidence[0].payload.id = "renewed-passport".into();
    evidence[0] = sign(&key(2), "evidence", evidence[0].payload.clone()).unwrap();
    assert_eq!(
        assess(&s, &evidence, &roots(), &policy(), &revocations(), 150)
            .unwrap()
            .authority_id,
        s.authority_id
    );
}
#[test]
fn duplicated_roots_cannot_raise_assurance() {
    let s = state();
    let e = all_evidence(&s);
    let mut r = roots();
    r[1].independence_group = r[0].independence_group.clone();
    assert!(assess(&s, &e, &r, &policy(), &revocations(), 150).is_err());
    r = roots();
    r[1].public_key = r[0].public_key.clone();
    assert!(assess(&s, &e, &r, &policy(), &revocations(), 150).is_err());
    assert!(assess(
        &s,
        &[e[0].clone(), e[0].clone()],
        &roots(),
        &policy(),
        &revocations(),
        150
    )
    .is_err());
}
#[test]
fn assurance_rejects_stale_revoked_wrong_subject_and_claims() {
    let s = state();
    let e = all_evidence(&s);
    assert!(assess(&s, &e, &roots(), &policy(), &revocations(), 600).is_err());
    let mut r = revocations();
    r.revoked_evidence
        .insert(evidence_reference("issuer-2", "credential-1").unwrap());
    assert!(assess(&s, &e, &roots(), &policy(), &r, 150).is_err());
    let mut wrong = e.clone();
    wrong[0].payload.subject_key = public_key(&key(7));
    wrong[0] = sign(&key(2), "evidence", wrong[0].payload.clone()).unwrap();
    assert!(assess(&s, &wrong, &roots(), &policy(), &revocations(), 150).is_err());
    let mut p = policy();
    p.required_claims.insert("physician".into());
    assert!(assess(&s, &e, &roots(), &p, &revocations(), 150).is_err());
    p = policy();
    p.require_hardware = true;
    assert!(assess(&s, &e, &roots(), &p, &revocations(), 150).is_err());
    let mut r = revocations();
    r.valid_until = 150;
    assert!(assess(&s, &e, &roots(), &policy(), &r, 150).is_err());
}
#[test]
fn unknown_root_never_counts_and_trusted_signature_must_verify() {
    let s = state();
    let mut e = all_evidence(&s);
    e[1] = sign(&key(8), "evidence", e[1].payload.clone()).unwrap();
    assert!(assess(&s, &e, &roots(), &policy(), &revocations(), 150).is_err());
    e[1].payload.issuer = "unknown".into();
    assert!(assess(&s, &e, &roots(), &policy(), &revocations(), 150).is_err());
}
#[test]
fn enrollment_checks_challenge_audience_possession_and_binding() {
    let s = state();
    let e = Enrollment {
        authority_id: s.authority_id.clone(),
        subject_key: s.current_key.clone(),
        audience: "issuer-2".into(),
        nonce: "one-use-challenge".into(),
        issued_at: 100,
        expires_at: 200,
    };
    let signed = sign(&key(1), "enrollment", e.clone()).unwrap();
    validate_enrollment(&signed, "issuer-2", "one-use-challenge", 150).unwrap();
    assert!(validate_enrollment(&signed, "issuer-2", "wrong", 150).is_err());
    assert!(validate_enrollment(&signed, "issuer-3", "one-use-challenge", 150).is_err());
    assert!(validate_enrollment(
        &sign(&key(2), "enrollment", e).unwrap(),
        "issuer-2",
        "one-use-challenge",
        150
    )
    .is_err());
    let mut binding = evidence("issuer-2", &s);
    binding.subject_key = public_key(&key(8));
    let request = json!({"op":"attest", "enrollment":signed,"evidence":binding,"expected_audience":"issuer-2","expected_nonce":"one-use-challenge","now":150});
    assert!(dispatch(Some(&key(2)), &serde_json::to_vec(&request).unwrap()).is_err());
}
#[test]
fn rotation_requires_old_and_new_keys_and_preserves_identity() {
    let p = transition(false);
    let old = sign(&key(1), "transition", p.clone()).unwrap();
    let new = sign(&key(7), "transition", p).unwrap();
    assert!(apply_transition(&state(), std::slice::from_ref(&old), &revocations(), 150).is_err());
    let s = apply_transition(&state(), &[old.clone(), new.clone()], &revocations(), 150).unwrap();
    assert_eq!(s.authority_id, state().authority_id);
    assert_eq!(s.epoch, 1);
    assert!(apply_transition(&s, &[old, new], &revocations(), 150).is_err());
    assert!(assess(
        &s,
        &all_evidence(&state()),
        &roots(),
        &policy(),
        &revocations(),
        150
    )
    .is_err());
    assert!(assess(
        &s,
        &all_evidence(&s),
        &roots(),
        &policy(),
        &revocations(),
        150
    )
    .is_ok());
}
#[test]
fn recovery_requires_distinct_pinned_guardians_and_new_key() {
    let p = transition(true);
    let new = sign(&key(7), "transition", p.clone()).unwrap();
    let a = sign(&key(4), "transition", p.clone()).unwrap();
    let b = sign(&key(5), "transition", p.clone()).unwrap();
    assert!(apply_transition(&state(), &[a.clone(), new.clone()], &revocations(), 150).is_err());
    assert!(apply_transition(
        &state(),
        &[a.clone(), a.clone(), new.clone()],
        &revocations(),
        150
    )
    .is_err());
    let mut r = revocations();
    r.revoked_keys.insert(state().current_key);
    assert!(apply_transition(&state(), &[a.clone(), b.clone(), new.clone()], &r, 150).is_ok());
    r.revoked_keys.insert(public_key(&key(5)));
    assert!(apply_transition(&state(), &[a, b, new], &r, 150).is_err());
}
#[test]
fn direct_and_delegated_actions_verify_and_bind_expected_request() {
    let action = action();
    let chain = vec![sign(&key(1), "delegation", delegation()).unwrap()];
    let signed = sign(&key(6), "action", action.clone()).unwrap();
    assert_eq!(
        verify_action(&state(), &chain, &signed, &action, &revocations(), 150)
            .unwrap()
            .delegation_depth,
        1
    );
    assert!(verify_action(&state(), &[], &signed, &action, &revocations(), 150).is_err());
    let direct = sign(&key(1), "action", action.clone()).unwrap();
    verify_action(&state(), &[], &direct, &action, &revocations(), 150).unwrap();
    let mut expected = action;
    expected.nonce = "new-challenge".into();
    assert!(verify_action(&state(), &chain, &signed, &expected, &revocations(), 150).is_err());
}
#[test]
fn delegation_enforces_all_scope_dimensions() {
    let chain = vec![sign(&key(1), "delegation", delegation()).unwrap()];
    for n in 0..8 {
        let mut a = action();
        match n {
            0 => a.amount_minor = Some(200_001),
            1 => a.currency = Some("USD".into()),
            2 => a.operation = "delete".into(),
            3 => a.resource = "hotel".into(),
            4 => a.merchant_category = Some("gambling".into()),
            5 => a.audience = "evil.example".into(),
            6 => a.expires_at = 901,
            _ => {
                a.amount_minor = None;
                a.currency = None;
            }
        }
        let signed = sign(&key(6), "action", a.clone()).unwrap();
        assert!(
            verify_action(&state(), &chain, &signed, &a, &revocations(), 150).is_err(),
            "case {n}"
        );
    }
}
#[test]
fn child_delegation_attenuates_and_revocation_cascades() {
    let root = sign(&key(1), "delegation", delegation()).unwrap();
    let mut child = delegation();
    child.delegate_key = public_key(&key(7));
    child.remaining_depth = 0;
    child.parent_digest = Some(signed_digest(&root).unwrap());
    child.scope.maximum_amount_minor = Some(150_000);
    let signed_child = sign(&key(6), "delegation", child.clone()).unwrap();
    let a = action();
    let signed = sign(&key(7), "action", a.clone()).unwrap();
    verify_action(
        &state(),
        &[root.clone(), signed_child.clone()],
        &signed,
        &a,
        &revocations(),
        150,
    )
    .unwrap();
    let mut r = revocations();
    r.revoked_delegations.insert(signed_digest(&root).unwrap());
    assert!(verify_action(
        &state(),
        &[root.clone(), signed_child],
        &signed,
        &a,
        &r,
        150
    )
    .is_err());
    for n in 0..5 {
        let mut c = child.clone();
        match n {
            0 => c.scope.maximum_amount_minor = None,
            1 => c.remaining_depth = 1,
            2 => c.expires_at = 1000,
            3 => c.parent_digest = Some("00".repeat(32)),
            _ => c
                .scope
                .operations
                .insert("delete".into())
                .then_some(())
                .unwrap(),
        };
        let signed_child = sign(&key(6), "delegation", c).unwrap();
        assert!(verify_action(
            &state(),
            &[root.clone(), signed_child],
            &signed,
            &a,
            &revocations(),
            150
        )
        .is_err());
    }
}
#[test]
fn no_redelegation_and_current_epoch_are_enforced() {
    let mut d = delegation();
    d.remaining_depth = 0;
    let root = sign(&key(1), "delegation", d).unwrap();
    let mut child = delegation();
    child.delegate_key = public_key(&key(7));
    child.remaining_depth = 0;
    child.parent_digest = Some(signed_digest(&root).unwrap());
    let c = sign(&key(6), "delegation", child).unwrap();
    let a = action();
    let signed = sign(&key(7), "action", a.clone()).unwrap();
    assert!(verify_action(&state(), &[root, c], &signed, &a, &revocations(), 150).is_err());
    let mut s = state();
    s.epoch = 1;
    s.current_key = public_key(&key(7));
    assert!(verify_action(&s, &[], &signed, &a, &revocations(), 150).is_err());
}
#[test]
fn malformed_keys_and_unknown_fields_are_rejected() {
    assert!(parse_public(&"00".repeat(32)).is_err());
    assert!(parse_public(&public_key(&key(1)).to_uppercase()).is_err());
    let mut a = serde_json::to_value(action()).unwrap();
    a["unrecognized_limit"] = json!(1);
    assert!(serde_json::from_value::<Action>(a).is_err());
    assert!(dispatch(None, b"{\"op\":\"public_key\"}").is_err());
}

#[test]
fn envelope_digest_normalizes_omitted_optional_fields() {
    let signed = sign(&key(1), "delegation", delegation()).unwrap();
    let mut value = serde_json::to_value(&signed).unwrap();
    value["payload"]
        .as_object_mut()
        .unwrap()
        .remove("parent_digest");
    assert_eq!(
        normalized_envelope_digest(value).unwrap(),
        signed_digest(&signed).unwrap()
    );
}
