#![no_std]
#![forbid(unsafe_code)]

//! Mechanical capability-delegation attenuation.
//!
//! The verifier is deliberately conservative: if it cannot prove that a child
//! is no broader along every authority dimension, delegation is rejected.

use activechain_protocol_types::{CapabilityGrant, HolderBinding, ObjectId, RateLimit};

/// A precise reason a proposed child capability is not proven narrower.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttenuationError {
    /// The parent explicitly forbids delegation.
    ParentDelegationForbidden,
    /// The child does not identify this exact parent.
    ParentReferenceMismatch,
    /// Version 1 delegation requires a public principal-bound parent holder.
    UnsupportedParentHolderBinding,
    /// The child issuer is not the parent capability's bound principal holder.
    IssuerIsNotParentHolder,
    /// Version 1 does not permit a delegated bearer child.
    BearerChildForbidden,
    /// At least one child action is absent from the parent set.
    ActionsBroadened,
    /// The child resource selector is not contained by the parent selector.
    ResourceScopeBroadened,
    /// The child data selector is not contained by the parent selector.
    DataScopeBroadened,
    /// The child removes or increases a monetary ceiling.
    MonetaryLimitBroadened,
    /// The child removes or increases a compute ceiling.
    ComputeLimitBroadened,
    /// The child removes, changes the window of, or increases a rate limit.
    RateLimitBroadened,
    /// The child removes or increases a total use limit.
    UseLimitBroadened,
    /// The child becomes valid before its parent.
    ValidityStartsEarlier,
    /// The child remains valid after its parent or removes a bounded end.
    ValidityEndsLater,
    /// Remaining delegation depth was not strictly reduced.
    DelegationDepthNotReduced,
    /// The opaque constraint commitment changed without a proof of conjunction.
    ConstraintNotInherited,
    /// The child removed or changed an inherited revocation registry.
    RevocationRegistryNotInherited,
}

/// Proves that `child` is a mechanically recognized attenuation of `parent`.
///
/// A successful result does not verify either issuer signature. Signature,
/// revocation, policy, and holder authentication are separate authorization
/// predicates which MUST also pass before the child is accepted.
pub fn verify_attenuation(
    parent: &CapabilityGrant,
    child: &CapabilityGrant,
) -> Result<(), AttenuationError> {
    let parent = parent.fields();
    let child = child.fields();

    if !parent.delegation_allowed {
        return Err(AttenuationError::ParentDelegationForbidden);
    }
    if child.parent_capability != Some(parent.capability_id) {
        return Err(AttenuationError::ParentReferenceMismatch);
    }
    let HolderBinding::Principal(parent_holder) = parent.holder_binding else {
        return Err(AttenuationError::UnsupportedParentHolderBinding);
    };
    if child.issuer != parent_holder {
        return Err(AttenuationError::IssuerIsNotParentHolder);
    }
    if child.holder_binding == HolderBinding::Bearer {
        return Err(AttenuationError::BearerChildForbidden);
    }

    if !child.permitted_actions.is_subset_of(&parent.permitted_actions) {
        return Err(AttenuationError::ActionsBroadened);
    }
    if !child.resource_scope.is_subset_of(&parent.resource_scope) {
        return Err(AttenuationError::ResourceScopeBroadened);
    }
    if !child.data_scope.is_subset_of(&parent.data_scope) {
        return Err(AttenuationError::DataScopeBroadened);
    }
    if !optional_limit_is_attenuated(parent.monetary_limit, child.monetary_limit) {
        return Err(AttenuationError::MonetaryLimitBroadened);
    }
    if !optional_limit_is_attenuated(parent.compute_limit, child.compute_limit) {
        return Err(AttenuationError::ComputeLimitBroadened);
    }
    if !rate_limit_is_attenuated(parent.rate_limit, child.rate_limit) {
        return Err(AttenuationError::RateLimitBroadened);
    }
    if !optional_limit_is_attenuated(parent.use_limit, child.use_limit) {
        return Err(AttenuationError::UseLimitBroadened);
    }
    if child.valid_from < parent.valid_from {
        return Err(AttenuationError::ValidityStartsEarlier);
    }
    if !optional_end_is_attenuated(parent.valid_until, child.valid_until) {
        return Err(AttenuationError::ValidityEndsLater);
    }
    if child.delegation_depth_remaining >= parent.delegation_depth_remaining {
        return Err(AttenuationError::DelegationDepthNotReduced);
    }
    if child.constraint_hash != parent.constraint_hash {
        return Err(AttenuationError::ConstraintNotInherited);
    }
    if !revocation_registry_is_attenuated(parent.revocation_registry, child.revocation_registry) {
        return Err(AttenuationError::RevocationRegistryNotInherited);
    }
    Ok(())
}

fn optional_limit_is_attenuated<T: Ord + Copy>(parent: Option<T>, child: Option<T>) -> bool {
    match parent {
        None => true,
        Some(parent) => child.is_some_and(|child| child <= parent),
    }
}

fn optional_end_is_attenuated(parent: Option<u64>, child: Option<u64>) -> bool {
    match parent {
        None => true,
        Some(parent) => child.is_some_and(|child| child <= parent),
    }
}

fn rate_limit_is_attenuated(parent: Option<RateLimit>, child: Option<RateLimit>) -> bool {
    match parent {
        None => true,
        Some(parent) => child.is_some_and(|child| {
            child.window_blocks() == parent.window_blocks()
                && child.maximum_uses() <= parent.maximum_uses()
        }),
    }
}

fn revocation_registry_is_attenuated(parent: Option<ObjectId>, child: Option<ObjectId>) -> bool {
    match parent {
        None => true,
        Some(parent) => child == Some(parent),
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;

    use activechain_protocol_types::{
        ActionId, BoundedActionSet, CapabilityGrant, CapabilityGrantFields, CapabilityId,
        CryptoSuiteId, DataSelector, Digest384, HolderBinding, ObjectId, PrincipalId,
        ProtocolSignature, RateLimit, ResourceSelector,
    };
    use proptest::prelude::*;

    use super::{AttenuationError, verify_attenuation};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn action(byte: u8) -> ActionId {
        ActionId::new(digest(byte))
    }

    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }

    fn capability(byte: u8) -> CapabilityId {
        CapabilityId::new(digest(byte))
    }

    fn signature(byte: u8) -> ProtocolSignature {
        ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![byte; 2_420])
            .expect("canonical signature length")
    }

    fn parent_fields() -> CapabilityGrantFields {
        CapabilityGrantFields {
            capability_id: capability(0x10),
            issuer: principal(0x20),
            holder_binding: HolderBinding::Principal(principal(0x30)),
            parent_capability: None,
            permitted_actions: BoundedActionSet::new(vec![action(1), action(2), action(3)])
                .expect("sorted actions"),
            resource_scope: ResourceSelector::ANY,
            data_scope: DataSelector::ANY,
            monetary_limit: Some(1_000),
            compute_limit: Some(10_000),
            rate_limit: Some(RateLimit::new(100, 50).expect("valid rate")),
            use_limit: Some(500),
            valid_from: 10,
            valid_until: Some(1_000),
            delegation_depth_remaining: 3,
            delegation_allowed: true,
            revocation_registry: Some(ObjectId::new(digest(0x40))),
            constraint_hash: digest(0x50),
        }
    }

    fn child_fields() -> CapabilityGrantFields {
        CapabilityGrantFields {
            capability_id: capability(0x11),
            issuer: principal(0x30),
            holder_binding: HolderBinding::Principal(principal(0x31)),
            parent_capability: Some(capability(0x10)),
            permitted_actions: BoundedActionSet::new(vec![action(1), action(3)])
                .expect("sorted actions"),
            resource_scope: ResourceSelector::exact(ObjectId::new(digest(0x60))),
            data_scope: DataSelector::exact(digest(0x70)),
            monetary_limit: Some(500),
            compute_limit: Some(5_000),
            rate_limit: Some(RateLimit::new(50, 50).expect("valid rate")),
            use_limit: Some(100),
            valid_from: 20,
            valid_until: Some(900),
            delegation_depth_remaining: 2,
            delegation_allowed: true,
            revocation_registry: Some(ObjectId::new(digest(0x40))),
            constraint_hash: digest(0x50),
        }
    }

    fn grant(fields: CapabilityGrantFields, signature_byte: u8) -> CapabilityGrant {
        CapabilityGrant::new(fields, signature(signature_byte)).expect("valid grant fields")
    }

    #[test]
    fn fully_narrower_child_is_accepted() {
        assert_eq!(
            verify_attenuation(&grant(parent_fields(), 1), &grant(child_fields(), 2)),
            Ok(())
        );
    }

    #[test]
    fn every_authority_dimension_is_checked() {
        let parent = grant(parent_fields(), 1);

        let mut child = child_fields();
        child.permitted_actions =
            BoundedActionSet::new(vec![action(1), action(4)]).expect("sorted actions");
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::ActionsBroadened)
        );

        let mut scoped_parent_fields = parent_fields();
        scoped_parent_fields.resource_scope = ResourceSelector::exact(ObjectId::new(digest(0x60)));
        let scoped_parent = grant(scoped_parent_fields, 1);
        let mut child = child_fields();
        child.resource_scope = ResourceSelector::ANY;
        assert_eq!(
            verify_attenuation(&scoped_parent, &grant(child, 2)),
            Err(AttenuationError::ResourceScopeBroadened)
        );

        let mut scoped_parent_fields = parent_fields();
        scoped_parent_fields.data_scope = DataSelector::exact(digest(0x70));
        let scoped_parent = grant(scoped_parent_fields, 1);
        let mut child = child_fields();
        child.data_scope = DataSelector::ANY;
        assert_eq!(
            verify_attenuation(&scoped_parent, &grant(child, 2)),
            Err(AttenuationError::DataScopeBroadened)
        );

        let mut child = child_fields();
        child.monetary_limit = Some(1_001);
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::MonetaryLimitBroadened)
        );

        let mut child = child_fields();
        child.compute_limit = None;
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::ComputeLimitBroadened)
        );

        let mut child = child_fields();
        child.rate_limit = Some(RateLimit::new(50, 51).expect("valid rate"));
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::RateLimitBroadened)
        );

        let mut child = child_fields();
        child.use_limit = Some(501);
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::UseLimitBroadened)
        );

        let mut child = child_fields();
        child.valid_from = 9;
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::ValidityStartsEarlier)
        );

        let mut child = child_fields();
        child.valid_until = None;
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::ValidityEndsLater)
        );

        let mut child = child_fields();
        child.delegation_depth_remaining = 3;
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::DelegationDepthNotReduced)
        );

        let mut child = child_fields();
        child.constraint_hash = digest(0x51);
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::ConstraintNotInherited)
        );

        let mut child = child_fields();
        child.revocation_registry = None;
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::RevocationRegistryNotInherited)
        );
    }

    #[test]
    fn delegation_requires_the_bound_parent_holder() {
        let parent = grant(parent_fields(), 1);

        let mut child = child_fields();
        child.parent_capability = Some(capability(0x12));
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::ParentReferenceMismatch)
        );

        let mut child = child_fields();
        child.issuer = principal(0x99);
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::IssuerIsNotParentHolder)
        );

        let mut child = child_fields();
        child.holder_binding = HolderBinding::Bearer;
        assert_eq!(
            verify_attenuation(&parent, &grant(child, 2)),
            Err(AttenuationError::BearerChildForbidden)
        );

        let mut private_parent = parent_fields();
        private_parent.holder_binding = HolderBinding::Private(digest(0x30));
        assert_eq!(
            verify_attenuation(&grant(private_parent, 1), &grant(child_fields(), 2)),
            Err(AttenuationError::UnsupportedParentHolderBinding)
        );

        let mut non_delegating_parent = parent_fields();
        non_delegating_parent.delegation_allowed = false;
        non_delegating_parent.delegation_depth_remaining = 0;
        assert_eq!(
            verify_attenuation(&grant(non_delegating_parent, 1), &grant(child_fields(), 2)),
            Err(AttenuationError::ParentDelegationForbidden)
        );
    }

    proptest! {
        #[test]
        fn bounded_numeric_children_never_amplify(
            parent_money in 1_u64..u64::MAX,
            child_money in 0_u64..u64::MAX,
            parent_compute in 1_u64..u64::MAX,
            child_compute in 0_u64..u64::MAX,
        ) {
            let mut parent = parent_fields();
            parent.monetary_limit = Some(u128::from(parent_money));
            parent.compute_limit = Some(u128::from(parent_compute));
            let parent = grant(parent, 1);

            let mut child = child_fields();
            child.monetary_limit = Some(u128::from(child_money.min(parent_money)));
            child.compute_limit = Some(u128::from(child_compute.min(parent_compute)));
            let child = grant(child, 2);
            prop_assert_eq!(verify_attenuation(&parent, &child), Ok(()));
        }

        #[test]
        fn increasing_a_finite_monetary_limit_is_always_rejected(parent_money in 0_u64..u64::MAX) {
            let mut parent = parent_fields();
            parent.monetary_limit = Some(u128::from(parent_money));
            let parent = grant(parent, 1);

            let mut child = child_fields();
            child.monetary_limit = Some(u128::from(parent_money) + 1);
            let child = grant(child, 2);
            prop_assert_eq!(
                verify_attenuation(&parent, &child),
                Err(AttenuationError::MonetaryLimitBroadened)
            );
        }
    }
}
