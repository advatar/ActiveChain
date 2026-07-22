//! Total, metered APL evaluation and canonical decisions.

use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::ResourceSelector;

use crate::{
    MAX_POLICY_OBLIGATIONS, MAX_POLICY_PREDICATES, MAX_POLICY_RULES, PolicyEffect,
    PolicyObligation, PolicyPredicate, PolicyRequest, PolicySet,
};

/// Maximum work units consumed by evaluation of one structurally valid policy.
pub const MAX_EVALUATION_STEPS: u16 = (MAX_POLICY_RULES * (1 + MAX_POLICY_PREDICATES)) as u16;

/// The authorization result after applying default deny and forbid precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DecisionResult {
    /// The request is not authorized.
    Deny = 0,
    /// The request is authorized subject to the returned obligations.
    Permit = 1,
}

impl CanonicalEncode for DecisionResult {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for DecisionResult {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Deny),
            1 => Ok(Self::Permit),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "DecisionResult", tag }),
        }
    }
}

/// A deterministic authorization decision and its bounded settlement obligations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    result: DecisionResult,
    matched_permit_rules: u8,
    matched_forbid_rules: u8,
    steps_used: u16,
    obligations: Vec<PolicyObligation>,
}

impl PolicyDecision {
    /// Registered top-level policy-decision type tag.
    pub const TYPE_TAG: u16 = 0x0042;
    /// Initial canonical decision schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Maximum canonical decision body length under all protocol bounds.
    pub const MAX_ENCODED_LEN: usize = 8_327;

    /// Constructs a structurally valid policy decision.
    pub fn new(
        result: DecisionResult,
        matched_permit_rules: u8,
        matched_forbid_rules: u8,
        steps_used: u16,
        obligations: Vec<PolicyObligation>,
    ) -> Result<Self, PolicyDecisionError> {
        let matched_rule_count = usize::from(matched_permit_rules)
            .checked_add(usize::from(matched_forbid_rules))
            .ok_or(PolicyDecisionError::TooManyMatchedRules)?;
        if matched_rule_count > MAX_POLICY_RULES {
            return Err(PolicyDecisionError::TooManyMatchedRules);
        }
        if steps_used > MAX_EVALUATION_STEPS || usize::from(steps_used) < matched_rule_count {
            return Err(PolicyDecisionError::InvalidStepCount);
        }
        if obligations.len() > MAX_POLICY_OBLIGATIONS {
            return Err(PolicyDecisionError::TooManyObligations {
                actual: obligations.len(),
                maximum: MAX_POLICY_OBLIGATIONS,
            });
        }
        if result != combine_effects(matched_permit_rules != 0, matched_forbid_rules != 0) {
            return Err(PolicyDecisionError::ResultDoesNotMatchEffects);
        }
        if result == DecisionResult::Deny && !obligations.is_empty() {
            return Err(PolicyDecisionError::DenyHasObligations);
        }

        Ok(Self { result, matched_permit_rules, matched_forbid_rules, steps_used, obligations })
    }

    /// Returns the final permit-or-deny result.
    #[must_use]
    pub const fn result(&self) -> DecisionResult {
        self.result
    }

    /// Returns the number of matching permit rules.
    #[must_use]
    pub const fn matched_permit_rules(&self) -> u8 {
        self.matched_permit_rules
    }

    /// Returns the number of matching forbid rules.
    #[must_use]
    pub const fn matched_forbid_rules(&self) -> u8 {
        self.matched_forbid_rules
    }

    /// Returns deterministic work units consumed by evaluation.
    #[must_use]
    pub const fn steps_used(&self) -> u16 {
        self.steps_used
    }

    /// Borrows settlement and audit obligations in canonical rule order.
    #[must_use]
    pub fn obligations(&self) -> &[PolicyObligation] {
        &self.obligations
    }
}

impl CanonicalEncode for PolicyDecision {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.result.encode(encoder)?;
        self.matched_permit_rules.encode(encoder)?;
        self.matched_forbid_rules.encode(encoder)?;
        self.steps_used.encode(encoder)?;
        encoder.write_length(self.obligations.len(), MAX_POLICY_OBLIGATIONS)?;
        for obligation in &self.obligations {
            obligation.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for PolicyDecision {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let result = DecisionResult::decode(decoder)?;
        let matched_permit_rules = u8::decode(decoder)?;
        let matched_forbid_rules = u8::decode(decoder)?;
        let steps_used = u16::decode(decoder)?;
        let obligation_count = decoder.read_length(MAX_POLICY_OBLIGATIONS)?;
        let mut obligations = Vec::with_capacity(obligation_count);
        for _ in 0..obligation_count {
            obligations.push(PolicyObligation::decode(decoder)?);
        }
        Self::new(result, matched_permit_rules, matched_forbid_rules, steps_used, obligations)
            .map_err(policy_decision_decode_error)
    }
}

impl CanonicalType for PolicyDecision {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Policy-decision validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyDecisionError {
    /// The reported matching-rule counts exceed the policy rule bound.
    TooManyMatchedRules,
    /// The work count is below matched rules or above the protocol maximum.
    InvalidStepCount,
    /// The returned obligation list exceeds its protocol bound.
    TooManyObligations { actual: usize, maximum: usize },
    /// The result does not implement default deny and forbid precedence.
    ResultDoesNotMatchEffects,
    /// Denied requests cannot carry obligations.
    DenyHasObligations,
}

/// Applies APL's complete decision table to the existence of matching effects.
#[must_use]
pub const fn combine_effects(has_permit: bool, has_forbid: bool) -> DecisionResult {
    if has_permit && !has_forbid { DecisionResult::Permit } else { DecisionResult::Deny }
}

/// Evaluates every rule and predicate, returning a total deterministic decision.
#[must_use]
pub fn evaluate(policy: &PolicySet, request: &PolicyRequest) -> PolicyDecision {
    let mut matched_permit_rules = 0_u8;
    let mut matched_forbid_rules = 0_u8;
    let mut steps_used = 0_u16;
    let mut obligations = Vec::with_capacity(MAX_POLICY_OBLIGATIONS);

    for rule in policy.rules() {
        steps_used += 1;
        let mut rule_matches = true;
        for predicate in rule.predicates() {
            steps_used += 1;
            // Bitwise assignment is intentional: every predicate is evaluated.
            rule_matches &= predicate_matches(predicate, request);
        }

        if rule_matches {
            match rule.effect() {
                PolicyEffect::Permit => {
                    matched_permit_rules += 1;
                    obligations.extend_from_slice(rule.obligations());
                }
                PolicyEffect::Forbid => matched_forbid_rules += 1,
            }
        }
    }

    let result = combine_effects(matched_permit_rules != 0, matched_forbid_rules != 0);
    if result == DecisionResult::Deny {
        obligations.clear();
    }

    PolicyDecision { result, matched_permit_rules, matched_forbid_rules, steps_used, obligations }
}

fn predicate_matches(predicate: &PolicyPredicate, request: &PolicyRequest) -> bool {
    match predicate {
        PolicyPredicate::ActorIs(actor) => request.actor() == *actor,
        PolicyPredicate::ActionIs(action) => request.action() == *action,
        PolicyPredicate::ResourceMatches(selector) => {
            ResourceSelector::exact(request.resource()).is_subset_of(selector)
        }
        PolicyPredicate::ValueAtMost(maximum) => request.value() <= *maximum,
        PolicyPredicate::ValueAtLeast(minimum) => request.value() >= *minimum,
        PolicyPredicate::HeightAtLeast(minimum) => request.height() >= *minimum,
        PolicyPredicate::HeightAtMost(maximum) => request.height() <= *maximum,
        PolicyPredicate::HasCredentialSchema(schema) => request.contains_credential_schema(schema),
        PolicyPredicate::HasCapability(capability) => request.contains_capability(capability),
        PolicyPredicate::ApprovalCountAtLeast { role, minimum } => {
            request.approval_count(role) >= *minimum
        }
        PolicyPredicate::FreezeStateIs(freeze_state) => request.freeze_state() == *freeze_state,
        PolicyPredicate::DeclaredPurposeIs(purpose) => request.declared_purpose() == Some(*purpose),
    }
}

fn policy_decision_decode_error(error: PolicyDecisionError) -> DecodeError {
    match error {
        PolicyDecisionError::TooManyMatchedRules => {
            DecodeError::InvalidValue("decision exceeds the matching-rule bound")
        }
        PolicyDecisionError::InvalidStepCount => {
            DecodeError::InvalidValue("decision has an invalid evaluation-step count")
        }
        PolicyDecisionError::TooManyObligations { .. } => {
            DecodeError::InvalidValue("decision exceeds the obligation bound")
        }
        PolicyDecisionError::ResultDoesNotMatchEffects => {
            DecodeError::InvalidValue("decision result does not match rule effects")
        }
        PolicyDecisionError::DenyHasObligations => {
            DecodeError::InvalidValue("denied decision contains obligations")
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::{vec, vec::Vec};

    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use activechain_protocol_types::{
        ActionId, CapabilityId, Digest384, FreezeState, ObjectId, PrincipalId, ResourceSelector,
    };

    use crate::{
        APL_LANGUAGE_VERSION, ActorBinding, ApprovalFact, DecisionResult, PolicyEffect,
        PolicyObligation, PolicyPredicate, PolicyRequest, PolicyRequestFields, PolicyRule,
        PolicySet, combine_effects, evaluate,
    };

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn request(value: u128, action_byte: u8) -> PolicyRequest {
        PolicyRequest::new(PolicyRequestFields {
            actor: ActorBinding::Principal(PrincipalId::new(digest(0x10))),
            action: ActionId::new(digest(action_byte)),
            resource: ObjectId::new(digest(0x30)),
            height: 50,
            value,
            freeze_state: FreezeState::Active,
            declared_purpose: Some(digest(0x40)),
            credential_schemas: vec![digest(0x50)],
            capabilities: vec![CapabilityId::new(digest(0x60))],
            approvals: vec![ApprovalFact::new(digest(0x70), 2).expect("non-zero")],
        })
        .expect("request facts are canonical")
    }

    #[test]
    fn complete_effect_table_is_default_deny_with_forbid_precedence() {
        assert_eq!(combine_effects(false, false), DecisionResult::Deny);
        assert_eq!(combine_effects(false, true), DecisionResult::Deny);
        assert_eq!(combine_effects(true, false), DecisionResult::Permit);
        assert_eq!(combine_effects(true, true), DecisionResult::Deny);
    }

    #[test]
    fn production_evaluator_refines_the_general_effect_fold() {
        fn check(observations: &[(PolicyEffect, bool)]) {
            let mut expected_permits = 0_u8;
            let mut expected_forbids = 0_u8;
            let mut expected_obligations = Vec::new();
            let mut rules = Vec::new();

            for (index, (effect, matched)) in observations.iter().copied().enumerate() {
                let predicates =
                    if matched { vec![] } else { vec![PolicyPredicate::ValueAtMost(0)] };
                let obligations = if effect == PolicyEffect::Permit {
                    vec![PolicyObligation::EmitAuditCommitment(digest(index as u8 + 1))]
                } else {
                    vec![]
                };
                if matched {
                    match effect {
                        PolicyEffect::Permit => {
                            expected_permits += 1;
                            expected_obligations.extend_from_slice(&obligations);
                        }
                        PolicyEffect::Forbid => expected_forbids += 1,
                    }
                }
                rules.push(PolicyRule::new(effect, predicates, obligations).expect("bounded rule"));
            }

            let policy = PolicySet::new(APL_LANGUAGE_VERSION, rules).expect("bounded policy");
            let decision = evaluate(&policy, &request(10, 0x20));
            let expected_result = combine_effects(expected_permits != 0, expected_forbids != 0);
            assert_eq!(decision.result(), expected_result, "observations: {observations:?}");
            assert_eq!(decision.matched_permit_rules(), expected_permits);
            assert_eq!(decision.matched_forbid_rules(), expected_forbids);
            assert_eq!(
                decision.steps_used(),
                observations.len() as u16 * 2
                    - observations.iter().filter(|(_, matched)| *matched).count() as u16
            );
            if expected_result == DecisionResult::Permit {
                assert_eq!(decision.obligations(), expected_obligations);
            } else {
                assert!(decision.obligations().is_empty());
            }
        }

        fn enumerate(prefix: &mut Vec<(PolicyEffect, bool)>, remaining: usize) {
            check(prefix);
            if remaining == 0 {
                return;
            }
            for observation in [
                (PolicyEffect::Permit, false),
                (PolicyEffect::Permit, true),
                (PolicyEffect::Forbid, false),
                (PolicyEffect::Forbid, true),
            ] {
                prefix.push(observation);
                enumerate(prefix, remaining - 1);
                prefix.pop();
            }
        }

        enumerate(&mut Vec::new(), 6);
    }

    #[test]
    fn empty_policy_denies_without_obligations() {
        let policy = PolicySet::new(APL_LANGUAGE_VERSION, vec![]).expect("valid policy");
        let decision = evaluate(&policy, &request(10, 0x20));
        assert_eq!(decision.result(), DecisionResult::Deny);
        assert_eq!(decision.steps_used(), 0);
        assert!(decision.obligations().is_empty());
    }

    #[test]
    fn matching_permit_returns_obligations_in_rule_order() {
        let first = PolicyObligation::EmitAuditCommitment(digest(0x80));
        let second = PolicyObligation::DelaySettlementUntil(55);
        let policy = PolicySet::new(
            APL_LANGUAGE_VERSION,
            vec![
                PolicyRule::new(
                    PolicyEffect::Permit,
                    vec![
                        PolicyPredicate::ActionIs(ActionId::new(digest(0x20))),
                        PolicyPredicate::ValueAtMost(100),
                    ],
                    vec![first],
                )
                .expect("valid rule"),
                PolicyRule::new(
                    PolicyEffect::Permit,
                    vec![PolicyPredicate::HasCredentialSchema(digest(0x50))],
                    vec![second],
                )
                .expect("valid rule"),
            ],
        )
        .expect("valid policy");

        let decision = evaluate(&policy, &request(10, 0x20));
        assert_eq!(decision.result(), DecisionResult::Permit);
        assert_eq!(decision.matched_permit_rules(), 2);
        assert_eq!(decision.matched_forbid_rules(), 0);
        assert_eq!(decision.steps_used(), 5);
        assert_eq!(decision.obligations(), &[first, second]);
    }

    #[test]
    fn every_version_one_predicate_family_has_total_matching_semantics() {
        let policy = PolicySet::new(
            APL_LANGUAGE_VERSION,
            vec![
                PolicyRule::new(
                    PolicyEffect::Permit,
                    vec![
                        PolicyPredicate::ActorIs(ActorBinding::Principal(PrincipalId::new(
                            digest(0x10),
                        ))),
                        PolicyPredicate::ActionIs(ActionId::new(digest(0x20))),
                        PolicyPredicate::ResourceMatches(ResourceSelector::exact(ObjectId::new(
                            digest(0x30),
                        ))),
                        PolicyPredicate::ValueAtMost(10),
                        PolicyPredicate::ValueAtLeast(10),
                        PolicyPredicate::HeightAtLeast(50),
                        PolicyPredicate::HeightAtMost(50),
                        PolicyPredicate::HasCredentialSchema(digest(0x50)),
                        PolicyPredicate::HasCapability(CapabilityId::new(digest(0x60))),
                        PolicyPredicate::ApprovalCountAtLeast { role: digest(0x70), minimum: 2 },
                        PolicyPredicate::FreezeStateIs(FreezeState::Active),
                        PolicyPredicate::DeclaredPurposeIs(digest(0x40)),
                    ],
                    vec![],
                )
                .expect("all predicates fit one rule"),
            ],
        )
        .expect("valid policy");

        let decision = evaluate(&policy, &request(10, 0x20));
        assert_eq!(decision.result(), DecisionResult::Permit);
        assert_eq!(decision.steps_used(), 13);
    }

    #[test]
    fn any_matching_forbid_overrides_permits_and_clears_obligations() {
        let policy = PolicySet::new(
            APL_LANGUAGE_VERSION,
            vec![
                PolicyRule::new(
                    PolicyEffect::Permit,
                    vec![PolicyPredicate::ValueAtMost(100)],
                    vec![PolicyObligation::EmitAuditCommitment(digest(0x80))],
                )
                .expect("valid rule"),
                PolicyRule::new(
                    PolicyEffect::Forbid,
                    vec![PolicyPredicate::FreezeStateIs(FreezeState::Active)],
                    vec![],
                )
                .expect("valid rule"),
            ],
        )
        .expect("valid policy");

        let decision = evaluate(&policy, &request(10, 0x20));
        assert_eq!(decision.result(), DecisionResult::Deny);
        assert_eq!(decision.matched_permit_rules(), 1);
        assert_eq!(decision.matched_forbid_rules(), 1);
        assert!(decision.obligations().is_empty());
    }

    #[test]
    fn metering_does_not_depend_on_earlier_predicate_results() {
        let policy = PolicySet::new(
            APL_LANGUAGE_VERSION,
            vec![
                PolicyRule::new(
                    PolicyEffect::Permit,
                    vec![
                        PolicyPredicate::ActionIs(ActionId::new(digest(0x20))),
                        PolicyPredicate::ValueAtMost(100),
                        PolicyPredicate::ResourceMatches(ResourceSelector::ANY),
                    ],
                    vec![],
                )
                .expect("valid rule"),
            ],
        )
        .expect("valid policy");

        let matching = evaluate(&policy, &request(10, 0x20));
        let first_predicate_fails = evaluate(&policy, &request(10_000, 0xff));
        assert_eq!(matching.steps_used(), 4);
        assert_eq!(first_predicate_fails.steps_used(), matching.steps_used());
    }

    #[test]
    fn decisions_round_trip_through_the_canonical_envelope() {
        let policy = PolicySet::new(
            APL_LANGUAGE_VERSION,
            vec![PolicyRule::new(PolicyEffect::Permit, vec![], vec![]).expect("valid rule")],
        )
        .expect("valid policy");
        let decision = evaluate(&policy, &request(10, 0x20));
        let bytes = encode_envelope(&decision).expect("decision fits its bound");
        assert_eq!(decode_envelope(&bytes), Ok(decision));
    }
}
