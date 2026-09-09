use crate::{crypto::*, model::*, Error, Result};
use std::collections::BTreeSet;

pub fn nonempty(s: &str) -> Result<()> {
    if s.trim().is_empty() || s.len() > 4096 || s.chars().any(char::is_control) {
        return Err(Error::invalid(
            "identifier is empty, oversized or contains control characters",
        ));
    }
    Ok(())
}
pub fn window(start: u64, end: u64, now: u64) -> Result<()> {
    if start >= end || now < start || now >= end {
        return Err(Error::new("expired", "outside validity window"));
    }
    Ok(())
}
pub fn validate_state(state: &AuthorityState) -> Result<()> {
    decode::<32>(&state.authority_id)?;
    parse_public(&state.current_key)?;
    if state.epoch == 0 && state.authority_id != authority_id(&state.current_key)? {
        return Err(Error::invalid("genesis authority identifier mismatch"));
    }
    if state.recovery_threshold > state.recovery_keys.len()
        || (!state.recovery_keys.is_empty() && state.recovery_threshold == 0)
        || state.recovery_keys.contains(&state.current_key)
    {
        return Err(Error::invalid("invalid recovery configuration"));
    }
    for k in &state.recovery_keys {
        parse_public(k)?;
    }
    Ok(())
}
pub fn check_revocations(r: &RevocationSnapshot, now: u64, state: &AuthorityState) -> Result<()> {
    validate_state(state)?;
    window(r.checked_at, r.valid_until, now)?;
    if r.revoked_keys.contains(&state.current_key)
        || r.revoked_authorities.contains(&state.authority_id)
    {
        return Err(Error::new("revoked", "authority or current key revoked"));
    }
    Ok(())
}
pub fn validate_enrollment(
    e: &Signed<Enrollment>,
    audience: &str,
    nonce: &str,
    now: u64,
) -> Result<()> {
    let p = &e.payload;
    decode::<32>(&p.authority_id)?;
    nonempty(&p.audience)?;
    nonempty(&p.nonce)?;
    window(p.issued_at, p.expires_at, now)?;
    if p.audience != audience || p.nonce != nonce {
        return Err(Error::new(
            "challenge",
            "enrollment audience or challenge mismatch",
        ));
    }
    verify(e, "enrollment", &p.subject_key)
}
pub fn validate_evidence(e: &Evidence) -> Result<()> {
    nonempty(&e.id)?;
    nonempty(&e.issuer)?;
    nonempty(&e.credential_kind)?;
    decode::<32>(&e.authority_id)?;
    parse_public(&e.subject_key)?;
    if e.assurance_level == 0 || e.assurance_level > 3 || e.issued_at >= e.expires_at {
        return Err(Error::invalid("invalid evidence assurance or validity"));
    }
    for c in &e.claims {
        nonempty(c)?;
    }
    Ok(())
}
pub fn assess(
    state: &AuthorityState,
    evidence: &[Signed<Evidence>],
    roots: &[TrustedRoot],
    policy: &AssurancePolicy,
    revocations: &RevocationSnapshot,
    now: u64,
) -> Result<Assurance> {
    check_revocations(revocations, now, state)?;
    if policy.minimum_independent_roots == 0
        || policy.minimum_assurance_level == 0
        || policy.minimum_assurance_level > 3
        || policy.maximum_age_seconds == 0
        || evidence.len() > 64
    {
        return Err(Error::invalid("invalid assurance policy or evidence count"));
    }
    let mut issuers = BTreeSet::new();
    // A single key cannot be configured as multiple independent roots.
    let mut root_keys = BTreeSet::new();
    for root in roots {
        nonempty(&root.issuer)?;
        nonempty(&root.independence_group)?;
        parse_public(&root.public_key)?;
        if !issuers.insert(&root.issuer)
            || !root_keys.insert(&root.public_key)
            || root.maximum_assurance_level == 0
            || root.maximum_assurance_level > 3
        {
            return Err(Error::invalid("duplicate or invalid trusted root"));
        }
    }
    let mut groups = BTreeSet::new();
    let mut accepted = Vec::new();
    let mut seen = BTreeSet::new();
    let mut claims = BTreeSet::new();
    let mut valid_until = revocations.valid_until;
    for signed in evidence {
        let e = &signed.payload;
        validate_evidence(e)?;
        if !seen.insert((&e.issuer, &e.id)) {
            return Err(Error::invalid("duplicate evidence"));
        }
        let Some(root) = roots.iter().find(|r| r.issuer == e.issuer) else {
            continue;
        };
        verify(signed, "evidence", &root.public_key)?;
        if e.authority_id != state.authority_id || e.subject_key != state.current_key {
            return Err(Error::new(
                "binding",
                "evidence is bound to a different authority or key",
            ));
        }
        let freshness_end = e.issued_at.saturating_add(policy.maximum_age_seconds);
        if e.issued_at > now
            || now >= e.expires_at
            || now >= freshness_end
            || revocations.revoked_keys.contains(&root.public_key)
            || revocations
                .revoked_evidence
                .contains(&evidence_reference(&e.issuer, &e.id)?)
            || !root.credential_kinds.contains(&e.credential_kind)
            || e.assurance_level > root.maximum_assurance_level
            || e.assurance_level < policy.minimum_assurance_level
            || (policy.require_liveness && !e.liveness)
            || (policy.require_hardware && !e.hardware_bound)
            || !policy.required_claims.is_subset(&e.claims)
        {
            continue;
        }
        groups.insert(&root.independence_group);
        accepted.push(evidence_reference(&e.issuer, &e.id)?);
        claims.extend(e.claims.clone());
        valid_until = valid_until.min(e.expires_at).min(freshness_end);
    }
    if groups.len() < policy.minimum_independent_roots {
        return Err(Error::new(
            "assurance",
            "insufficient independent qualifying identity roots",
        ));
    }
    Ok(Assurance {
        authority_id: state.authority_id.clone(),
        subject_key: state.current_key.clone(),
        independent_roots: groups.len(),
        accepted_evidence: accepted,
        claims,
        valid_until,
    })
}
pub fn evidence_reference(issuer: &str, id: &str) -> Result<String> {
    Ok(digest(&canonical(&(
        "AnyIdentity/evidence-reference/v1",
        issuer,
        id,
    ))?))
}
pub fn apply_transition(
    state: &AuthorityState,
    approvals: &[Signed<Transition>],
    revocations: &RevocationSnapshot,
    now: u64,
) -> Result<AuthorityState> {
    validate_state(state)?;
    window(revocations.checked_at, revocations.valid_until, now)?;
    if revocations
        .revoked_authorities
        .contains(&state.authority_id)
    {
        return Err(Error::new("revoked", "authority revoked"));
    }
    let p = &approvals
        .first()
        .ok_or_else(|| Error::invalid("missing transition approvals"))?
        .payload;
    window(p.issued_at, p.expires_at, now)?;
    parse_public(&p.new_key)?;
    if p.authority_id != state.authority_id
        || p.previous_key != state.current_key
        || Some(p.epoch) != state.epoch.checked_add(1)
        || p.new_key == p.previous_key
        || state.recovery_keys.contains(&p.new_key)
        || revocations.revoked_keys.contains(&p.new_key)
    {
        return Err(Error::new(
            "continuity",
            "invalid transition or stale authority state",
        ));
    }
    let mut signers = BTreeSet::new();
    for a in approvals {
        if a.payload != *p || !signers.insert(a.signer.clone()) {
            return Err(Error::invalid("inconsistent or duplicate approvals"));
        }
        verify(a, "transition", &a.signer)?;
        if revocations.revoked_keys.contains(&a.signer) {
            return Err(Error::new("revoked", "transition signer revoked"));
        }
    }
    let authorized = if p.recovery {
        state.recovery_threshold > 0
            && signers.intersection(&state.recovery_keys).count() >= state.recovery_threshold
    } else {
        signers.contains(&state.current_key)
    };
    if !authorized || !signers.contains(&p.new_key) {
        return Err(Error::new(
            "continuity",
            "missing authorization or new-key possession proof",
        ));
    }
    let mut result = state.clone();
    result.current_key = p.new_key.clone();
    result.epoch = p.epoch;
    Ok(result)
}
pub fn validate_scope(scope: &Scope) -> Result<()> {
    if scope.operations.is_empty()
        || scope.resources.is_empty()
        || scope.maximum_amount_minor.is_some() != scope.currency.is_some()
    {
        return Err(Error::invalid(
            "scope needs operations/resources and paired amount/currency",
        ));
    }
    for s in scope.operations.iter().chain(scope.resources.iter()) {
        nonempty(s)?;
    }
    if let Some(c) = &scope.currency {
        validate_currency(c)?;
    }
    if let Some(m) = &scope.merchant_category {
        nonempty(m)?;
    }
    Ok(())
}
fn validate_currency(s: &str) -> Result<()> {
    if s.len() != 3 || !s.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(Error::invalid(
            "currency must be a three-letter uppercase code",
        ));
    }
    Ok(())
}
pub fn attenuates(child: &Scope, parent: &Scope) -> bool {
    child.operations.is_subset(&parent.operations)
        && child.resources.is_subset(&parent.resources)
        && match parent.maximum_amount_minor {
            Some(limit) => {
                child.maximum_amount_minor.is_some_and(|n| n <= limit)
                    && child.currency == parent.currency
            }
            None => true,
        }
        && match &parent.merchant_category {
            Some(m) => child.merchant_category.as_ref() == Some(m),
            None => true,
        }
}
pub fn validate_delegation(d: &Delegation) -> Result<()> {
    decode::<32>(&d.authority_id)?;
    parse_public(&d.delegate_key)?;
    nonempty(&d.audience)?;
    if let Some(p) = &d.parent_digest {
        decode::<32>(p)?;
    }
    validate_scope(&d.scope)?;
    if d.not_before >= d.expires_at || d.remaining_depth > 8 {
        return Err(Error::invalid("invalid delegation window or depth"));
    }
    Ok(())
}
pub fn validate_action(a: &Action) -> Result<()> {
    decode::<32>(&a.authority_id)?;
    decode::<32>(&a.payload_digest)?;
    for s in [&a.audience, &a.nonce, &a.operation, &a.resource] {
        nonempty(s)?;
    }
    if a.issued_at >= a.expires_at || a.amount_minor.is_some() != a.currency.is_some() {
        return Err(Error::invalid("invalid action window or amount/currency"));
    }
    if let Some(c) = &a.currency {
        validate_currency(c)?;
    }
    if let Some(m) = &a.merchant_category {
        nonempty(m)?;
    }
    Ok(())
}
pub fn verify_action(
    state: &AuthorityState,
    chain: &[Signed<Delegation>],
    action: &Signed<Action>,
    expected: &Action,
    r: &RevocationSnapshot,
    now: u64,
) -> Result<Verification> {
    check_revocations(r, now, state)?;
    validate_action(&action.payload)?;
    if action.payload != *expected
        || expected.authority_id != state.authority_id
        || expected.epoch != state.epoch
    {
        return Err(Error::new(
            "binding",
            "action differs from expected request or current authority",
        ));
    }
    window(expected.issued_at, expected.expires_at, now)?;
    if chain.len() > 9 {
        return Err(Error::invalid("delegation chain too deep"));
    }
    let mut signer = state.current_key.clone();
    let mut parent: Option<&Signed<Delegation>> = None;
    let mut valid_until = expected.expires_at.min(r.valid_until);
    let mut keys = BTreeSet::from([signer.clone()]);
    for signed in chain {
        let d = &signed.payload;
        validate_delegation(d)?;
        verify(signed, "delegation", &signer)?;
        window(d.not_before, d.expires_at, now)?;
        if d.authority_id != state.authority_id
            || d.epoch != state.epoch
            || d.audience != expected.audience
            || !keys.insert(d.delegate_key.clone())
        {
            return Err(Error::new(
                "delegation",
                "delegation authority, audience, epoch or cycle mismatch",
            ));
        }
        if r.revoked_delegations.contains(&signed_digest(signed)?)
            || r.revoked_keys.contains(&d.delegate_key)
        {
            return Err(Error::new("revoked", "delegation or delegate revoked"));
        }
        match parent {
            None => {
                if d.parent_digest.is_some() {
                    return Err(Error::new("delegation", "root delegation has a parent"));
                }
            }
            Some(p) => {
                let previous = &p.payload;
                if d.parent_digest.as_ref() != Some(&signed_digest(p)?)
                    || previous.remaining_depth == 0
                    || d.remaining_depth >= previous.remaining_depth
                    || d.not_before < previous.not_before
                    || d.expires_at > previous.expires_at
                    || !attenuates(&d.scope, &previous.scope)
                {
                    return Err(Error::new("delegation", "child expands parent authority"));
                }
            }
        }
        // A delegated action must be wholly within every ancestor's signed window.
        if expected.issued_at < d.not_before || expected.expires_at > d.expires_at {
            return Err(Error::new("scope", "action validity exceeds delegation"));
        }
        let s = &d.scope;
        if !s.operations.contains(&expected.operation)
            || !s.resources.contains(&expected.resource)
            || s.maximum_amount_minor.is_some_and(|max| {
                expected.amount_minor.is_none_or(|v| v > max) || expected.currency != s.currency
            })
            || s.merchant_category
                .as_ref()
                .is_some_and(|m| expected.merchant_category.as_ref() != Some(m))
        {
            return Err(Error::new(
                "scope",
                "requested action exceeds delegation scope",
            ));
        }
        valid_until = valid_until.min(d.expires_at);
        signer = d.delegate_key.clone();
        parent = Some(signed);
    }
    verify(action, "action", &signer)?;
    Ok(Verification {
        authority_id: state.authority_id.clone(),
        signer,
        delegation_depth: chain.len(),
        action_digest: signed_digest(action)?,
        valid_until,
    })
}
