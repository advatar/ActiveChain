//! Canonical APL policy abstract syntax.

use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{
    ActionId, Amount, CapabilityId, Digest384, FreezeState, Height, PrincipalId, ResourceSelector,
};

/// The only APL language version recognized by this protocol revision.
pub const APL_LANGUAGE_VERSION: u16 = 1;
/// Maximum rules in one policy set.
pub const MAX_POLICY_RULES: usize = 32;
/// Maximum predicates conjoined by one rule.
pub const MAX_POLICY_PREDICATES: usize = 16;
/// Maximum obligations returned by one permit rule.
pub const MAX_OBLIGATIONS_PER_RULE: usize = 4;
/// Maximum obligations structurally present in one policy set.
pub const MAX_POLICY_OBLIGATIONS: usize = MAX_POLICY_RULES * MAX_OBLIGATIONS_PER_RULE;

const MAX_RULE_ENCODED_LEN: usize = 1
    + 1
    + MAX_POLICY_PREDICATES * 52
    + 1
    + MAX_OBLIGATIONS_PER_RULE * PolicyObligation::MAX_ENCODED_LEN;

/// A public or privacy-preserving actor identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorBinding {
    /// A public protocol principal.
    Principal(PrincipalId),
    /// A private principal commitment proven by the authorization layer.
    Private(Digest384),
}

impl CanonicalEncode for ActorBinding {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Principal(principal_id) => {
                0_u8.encode(encoder)?;
                principal_id.encode(encoder)
            }
            Self::Private(commitment) => {
                1_u8.encode(encoder)?;
                commitment.encode(encoder)
            }
        }
    }
}

impl CanonicalDecode for ActorBinding {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Principal(PrincipalId::decode(decoder)?)),
            1 => Ok(Self::Private(Digest384::decode(decoder)?)),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ActorBinding", tag }),
        }
    }
}

/// A rule's authorization effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PolicyEffect {
    /// A matching rule contributes a permit.
    Permit = 0,
    /// A matching rule contributes an overriding forbid.
    Forbid = 1,
}

impl CanonicalEncode for PolicyEffect {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for PolicyEffect {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Permit),
            1 => Ok(Self::Forbid),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "PolicyEffect", tag }),
        }
    }
}

/// One total, typed predicate over an authorization request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyPredicate {
    /// Actor binding equals the supplied value.
    ActorIs(ActorBinding),
    /// Action identifier equals the supplied value.
    ActionIs(ActionId),
    /// Requested object is contained by the selector.
    ResourceMatches(ResourceSelector),
    /// Transaction value is no greater than the bound.
    ValueAtMost(Amount),
    /// Transaction value is no less than the bound.
    ValueAtLeast(Amount),
    /// Block height is at least the bound.
    HeightAtLeast(Height),
    /// Block height is at most the bound.
    HeightAtMost(Height),
    /// The verified request facts include a credential schema.
    HasCredentialSchema(Digest384),
    /// The verified request facts include a capability identifier.
    HasCapability(CapabilityId),
    /// Verified approvals for a role meet a threshold.
    ApprovalCountAtLeast { role: Digest384, minimum: u8 },
    /// The principal's committed freeze state equals the supplied value.
    FreezeStateIs(FreezeState),
    /// The request declares the exact purpose commitment.
    DeclaredPurposeIs(Digest384),
}

impl CanonicalEncode for PolicyPredicate {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::ActorIs(actor) => {
                0_u8.encode(encoder)?;
                actor.encode(encoder)
            }
            Self::ActionIs(action) => {
                1_u8.encode(encoder)?;
                action.encode(encoder)
            }
            Self::ResourceMatches(selector) => {
                2_u8.encode(encoder)?;
                selector.encode(encoder)
            }
            Self::ValueAtMost(value) => {
                3_u8.encode(encoder)?;
                value.encode(encoder)
            }
            Self::ValueAtLeast(value) => {
                4_u8.encode(encoder)?;
                value.encode(encoder)
            }
            Self::HeightAtLeast(height) => {
                5_u8.encode(encoder)?;
                height.encode(encoder)
            }
            Self::HeightAtMost(height) => {
                6_u8.encode(encoder)?;
                height.encode(encoder)
            }
            Self::HasCredentialSchema(schema) => {
                7_u8.encode(encoder)?;
                schema.encode(encoder)
            }
            Self::HasCapability(capability) => {
                8_u8.encode(encoder)?;
                capability.encode(encoder)
            }
            Self::ApprovalCountAtLeast { role, minimum } => {
                9_u8.encode(encoder)?;
                role.encode(encoder)?;
                minimum.encode(encoder)
            }
            Self::FreezeStateIs(freeze_state) => {
                10_u8.encode(encoder)?;
                freeze_state.encode(encoder)
            }
            Self::DeclaredPurposeIs(purpose) => {
                11_u8.encode(encoder)?;
                purpose.encode(encoder)
            }
        }
    }
}

impl CanonicalDecode for PolicyPredicate {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::ActorIs(ActorBinding::decode(decoder)?)),
            1 => Ok(Self::ActionIs(ActionId::decode(decoder)?)),
            2 => Ok(Self::ResourceMatches(ResourceSelector::decode(decoder)?)),
            3 => Ok(Self::ValueAtMost(u128::decode(decoder)?)),
            4 => Ok(Self::ValueAtLeast(u128::decode(decoder)?)),
            5 => Ok(Self::HeightAtLeast(u64::decode(decoder)?)),
            6 => Ok(Self::HeightAtMost(u64::decode(decoder)?)),
            7 => Ok(Self::HasCredentialSchema(Digest384::decode(decoder)?)),
            8 => Ok(Self::HasCapability(CapabilityId::decode(decoder)?)),
            9 => {
                let role = Digest384::decode(decoder)?;
                let minimum = u8::decode(decoder)?;
                if minimum == 0 {
                    return Err(DecodeError::InvalidValue("approval predicate minimum is zero"));
                }
                Ok(Self::ApprovalCountAtLeast { role, minimum })
            }
            10 => Ok(Self::FreezeStateIs(FreezeState::decode(decoder)?)),
            11 => Ok(Self::DeclaredPurposeIs(Digest384::decode(decoder)?)),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "PolicyPredicate", tag }),
        }
    }
}

/// A bounded state update or audit requirement returned by a permit rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyObligation {
    /// Decrement an on-chain capability budget by the named amount.
    DecrementCapabilityBudget { capability_id: CapabilityId, amount: Amount },
    /// Consume a single-use capability.
    ConsumeCapability(CapabilityId),
    /// Emit an audit commitment without revealing its witness.
    EmitAuditCommitment(Digest384),
    /// Require a named approval role and threshold during settlement.
    RequireApproval { role: Digest384, minimum: u8 },
    /// Delay settlement until at least this height.
    DelaySettlementUntil(Height),
    /// Bind output disclosure to another policy commitment.
    RestrictOutputDisclosure(Digest384),
}

impl PolicyObligation {
    /// Maximum canonical size of any obligation variant.
    pub const MAX_ENCODED_LEN: usize = 65;
}

impl CanonicalEncode for PolicyObligation {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::DecrementCapabilityBudget { capability_id, amount } => {
                0_u8.encode(encoder)?;
                capability_id.encode(encoder)?;
                amount.encode(encoder)
            }
            Self::ConsumeCapability(capability_id) => {
                1_u8.encode(encoder)?;
                capability_id.encode(encoder)
            }
            Self::EmitAuditCommitment(commitment) => {
                2_u8.encode(encoder)?;
                commitment.encode(encoder)
            }
            Self::RequireApproval { role, minimum } => {
                3_u8.encode(encoder)?;
                role.encode(encoder)?;
                minimum.encode(encoder)
            }
            Self::DelaySettlementUntil(height) => {
                4_u8.encode(encoder)?;
                height.encode(encoder)
            }
            Self::RestrictOutputDisclosure(policy_hash) => {
                5_u8.encode(encoder)?;
                policy_hash.encode(encoder)
            }
        }
    }
}

impl CanonicalDecode for PolicyObligation {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::DecrementCapabilityBudget {
                capability_id: CapabilityId::decode(decoder)?,
                amount: u128::decode(decoder)?,
            }),
            1 => Ok(Self::ConsumeCapability(CapabilityId::decode(decoder)?)),
            2 => Ok(Self::EmitAuditCommitment(Digest384::decode(decoder)?)),
            3 => {
                let role = Digest384::decode(decoder)?;
                let minimum = u8::decode(decoder)?;
                if minimum == 0 {
                    return Err(DecodeError::InvalidValue("approval obligation minimum is zero"));
                }
                Ok(Self::RequireApproval { role, minimum })
            }
            4 => Ok(Self::DelaySettlementUntil(u64::decode(decoder)?)),
            5 => Ok(Self::RestrictOutputDisclosure(Digest384::decode(decoder)?)),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "PolicyObligation", tag }),
        }
    }
}

/// One bounded conjunction with either permit or forbid effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    effect: PolicyEffect,
    predicates: Vec<PolicyPredicate>,
    obligations: Vec<PolicyObligation>,
}

impl PolicyRule {
    /// Constructs a bounded rule. An empty predicate list matches every request.
    pub fn new(
        effect: PolicyEffect,
        predicates: Vec<PolicyPredicate>,
        obligations: Vec<PolicyObligation>,
    ) -> Result<Self, PolicyRuleError> {
        if predicates.len() > MAX_POLICY_PREDICATES {
            return Err(PolicyRuleError::TooManyPredicates {
                actual: predicates.len(),
                maximum: MAX_POLICY_PREDICATES,
            });
        }
        if obligations.len() > MAX_OBLIGATIONS_PER_RULE {
            return Err(PolicyRuleError::TooManyObligations {
                actual: obligations.len(),
                maximum: MAX_OBLIGATIONS_PER_RULE,
            });
        }
        if effect == PolicyEffect::Forbid && !obligations.is_empty() {
            return Err(PolicyRuleError::ForbidHasObligations);
        }
        if predicates.iter().any(|predicate| {
            matches!(predicate, PolicyPredicate::ApprovalCountAtLeast { minimum: 0, .. })
        }) || obligations.iter().any(|obligation| {
            matches!(obligation, PolicyObligation::RequireApproval { minimum: 0, .. })
        }) {
            return Err(PolicyRuleError::ZeroApprovalThreshold);
        }
        Ok(Self { effect, predicates, obligations })
    }

    /// Returns this rule's effect.
    #[must_use]
    pub const fn effect(&self) -> PolicyEffect {
        self.effect
    }

    /// Borrows the conjunction of predicates.
    #[must_use]
    pub fn predicates(&self) -> &[PolicyPredicate] {
        &self.predicates
    }

    /// Borrows obligations returned when this permit rule matches.
    #[must_use]
    pub fn obligations(&self) -> &[PolicyObligation] {
        &self.obligations
    }
}

impl CanonicalEncode for PolicyRule {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.effect.encode(encoder)?;
        encoder.write_length(self.predicates.len(), MAX_POLICY_PREDICATES)?;
        for predicate in &self.predicates {
            predicate.encode(encoder)?;
        }
        encoder.write_length(self.obligations.len(), MAX_OBLIGATIONS_PER_RULE)?;
        for obligation in &self.obligations {
            obligation.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for PolicyRule {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let effect = PolicyEffect::decode(decoder)?;
        let predicate_count = decoder.read_length(MAX_POLICY_PREDICATES)?;
        let mut predicates = Vec::with_capacity(predicate_count);
        for _ in 0..predicate_count {
            predicates.push(PolicyPredicate::decode(decoder)?);
        }
        let obligation_count = decoder.read_length(MAX_OBLIGATIONS_PER_RULE)?;
        let mut obligations = Vec::with_capacity(obligation_count);
        for _ in 0..obligation_count {
            obligations.push(PolicyObligation::decode(decoder)?);
        }
        Self::new(effect, predicates, obligations).map_err(policy_rule_decode_error)
    }
}

/// Rule validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyRuleError {
    /// The predicate conjunction exceeds its protocol bound.
    TooManyPredicates { actual: usize, maximum: usize },
    /// The rule returns too many obligations.
    TooManyObligations { actual: usize, maximum: usize },
    /// Forbid rules cannot produce state updates or audit obligations.
    ForbidHasObligations,
    /// A zero approval threshold has a simpler canonical representation.
    ZeroApprovalThreshold,
}

/// A canonical, versioned set of APL rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySet {
    language_version: u16,
    rules: Vec<PolicyRule>,
}

impl PolicySet {
    /// Registered top-level policy type tag.
    pub const TYPE_TAG: u16 = 0x0040;
    /// Initial canonical policy schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Conservative maximum canonical policy body length.
    pub const MAX_ENCODED_LEN: usize = 2 + 1 + MAX_POLICY_RULES * MAX_RULE_ENCODED_LEN;

    /// Constructs a policy set for the supported language version.
    pub fn new(language_version: u16, rules: Vec<PolicyRule>) -> Result<Self, PolicySetError> {
        if language_version != APL_LANGUAGE_VERSION {
            return Err(PolicySetError::UnsupportedLanguageVersion(language_version));
        }
        if rules.len() > MAX_POLICY_RULES {
            return Err(PolicySetError::TooManyRules {
                actual: rules.len(),
                maximum: MAX_POLICY_RULES,
            });
        }
        Ok(Self { language_version, rules })
    }

    /// Returns the APL semantic version.
    #[must_use]
    pub const fn language_version(&self) -> u16 {
        self.language_version
    }

    /// Borrows rules in canonical evaluation and obligation order.
    #[must_use]
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }
}

impl CanonicalEncode for PolicySet {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.language_version.encode(encoder)?;
        encoder.write_length(self.rules.len(), MAX_POLICY_RULES)?;
        for rule in &self.rules {
            rule.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for PolicySet {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let language_version = u16::decode(decoder)?;
        let rule_count = decoder.read_length(MAX_POLICY_RULES)?;
        let mut rules = Vec::with_capacity(rule_count);
        for _ in 0..rule_count {
            rules.push(PolicyRule::decode(decoder)?);
        }
        Self::new(language_version, rules).map_err(|error| match error {
            PolicySetError::UnsupportedLanguageVersion(_) => {
                DecodeError::InvalidValue("unsupported APL language version")
            }
            PolicySetError::TooManyRules { .. } => {
                DecodeError::InvalidValue("policy exceeds its rule bound")
            }
        })
    }
}

impl CanonicalType for PolicySet {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Policy-set validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicySetError {
    /// The evaluator does not implement this language version.
    UnsupportedLanguageVersion(u16),
    /// The number of rules exceeds the protocol bound.
    TooManyRules { actual: usize, maximum: usize },
}

fn policy_rule_decode_error(error: PolicyRuleError) -> DecodeError {
    match error {
        PolicyRuleError::TooManyPredicates { .. } => {
            DecodeError::InvalidValue("policy rule exceeds its predicate bound")
        }
        PolicyRuleError::TooManyObligations { .. } => {
            DecodeError::InvalidValue("policy rule exceeds its obligation bound")
        }
        PolicyRuleError::ForbidHasObligations => {
            DecodeError::InvalidValue("forbid rule contains obligations")
        }
        PolicyRuleError::ZeroApprovalThreshold => {
            DecodeError::InvalidValue("approval threshold is zero")
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;

    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use activechain_protocol_types::{ActionId, Digest384};

    use super::{
        APL_LANGUAGE_VERSION, MAX_OBLIGATIONS_PER_RULE, MAX_POLICY_PREDICATES, MAX_POLICY_RULES,
        PolicyEffect, PolicyObligation, PolicyPredicate, PolicyRule, PolicyRuleError, PolicySet,
        PolicySetError,
    };

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn rule_validation_enforces_bounds_effects_and_non_zero_thresholds() {
        let too_many_predicates = vec![PolicyPredicate::ValueAtMost(1); MAX_POLICY_PREDICATES + 1];
        assert!(matches!(
            PolicyRule::new(PolicyEffect::Permit, too_many_predicates, vec![]),
            Err(PolicyRuleError::TooManyPredicates { .. })
        ));

        let too_many_obligations =
            vec![PolicyObligation::DelaySettlementUntil(1); MAX_OBLIGATIONS_PER_RULE + 1];
        assert!(matches!(
            PolicyRule::new(PolicyEffect::Permit, vec![], too_many_obligations),
            Err(PolicyRuleError::TooManyObligations { .. })
        ));

        assert_eq!(
            PolicyRule::new(
                PolicyEffect::Forbid,
                vec![],
                vec![PolicyObligation::EmitAuditCommitment(digest(1))],
            ),
            Err(PolicyRuleError::ForbidHasObligations)
        );
        assert_eq!(
            PolicyRule::new(
                PolicyEffect::Permit,
                vec![PolicyPredicate::ApprovalCountAtLeast { role: digest(2), minimum: 0 }],
                vec![],
            ),
            Err(PolicyRuleError::ZeroApprovalThreshold)
        );
    }

    #[test]
    fn policy_validation_enforces_language_and_rule_bounds() {
        assert_eq!(
            PolicySet::new(APL_LANGUAGE_VERSION + 1, vec![]),
            Err(PolicySetError::UnsupportedLanguageVersion(APL_LANGUAGE_VERSION + 1))
        );

        let rule = PolicyRule::new(PolicyEffect::Permit, vec![], vec![]).expect("valid rule");
        assert!(matches!(
            PolicySet::new(APL_LANGUAGE_VERSION, vec![rule; MAX_POLICY_RULES + 1]),
            Err(PolicySetError::TooManyRules { .. })
        ));
    }

    #[test]
    fn policy_ast_round_trips_through_the_strict_envelope() {
        let policy = PolicySet::new(
            APL_LANGUAGE_VERSION,
            vec![
                PolicyRule::new(
                    PolicyEffect::Permit,
                    vec![PolicyPredicate::ActionIs(ActionId::new(digest(3)))],
                    vec![PolicyObligation::RestrictOutputDisclosure(digest(4))],
                )
                .expect("valid permit"),
                PolicyRule::new(PolicyEffect::Forbid, vec![], vec![]).expect("valid forbid"),
            ],
        )
        .expect("valid policy");
        let encoded = encode_envelope(&policy).expect("policy fits its declared bound");
        assert_eq!(decode_envelope(&encoded), Ok(policy));
    }
}
