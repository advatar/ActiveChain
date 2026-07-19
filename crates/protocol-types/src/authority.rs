//! Canonical recovery and capability authority types.

extern crate alloc;

use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};

use crate::{
    ActionId, Amount, CapabilityId, Digest384, Height, ObjectId, PrincipalId, ProtocolSignature,
    ResourceUnits,
};

/// Maximum distinct actions in one development capability grant.
pub const MAX_CAPABILITY_ACTIONS: usize = 32;

/// A recovery proposal committed when a principal enters `RecoveryPending`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryRequest {
    principal_id: PrincipalId,
    expected_sequence: u64,
    proposed_controller_policy_hash: Digest384,
    proposed_authenticator_set_root: Digest384,
    recovery_evidence_commitment: Digest384,
    initiated_at: Height,
    challenge_deadline: Height,
    recovery_bond: Amount,
}

impl RecoveryRequest {
    /// Registered top-level type tag.
    pub const TYPE_TAG: u16 = 0x0022;
    /// Initial recovery-request schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Recovery request version 1 has a fixed 232-byte body.
    pub const ENCODED_LENGTH: usize = 232;

    /// Creates a request with a non-empty challenge period.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        principal_id: PrincipalId,
        expected_sequence: u64,
        proposed_controller_policy_hash: Digest384,
        proposed_authenticator_set_root: Digest384,
        recovery_evidence_commitment: Digest384,
        initiated_at: Height,
        challenge_deadline: Height,
        recovery_bond: Amount,
    ) -> Result<Self, RecoveryRequestError> {
        if challenge_deadline <= initiated_at {
            return Err(RecoveryRequestError::ChallengeDeadlineNotAfterInitiation);
        }
        Ok(Self {
            principal_id,
            expected_sequence,
            proposed_controller_policy_hash,
            proposed_authenticator_set_root,
            recovery_evidence_commitment,
            initiated_at,
            challenge_deadline,
            recovery_bond,
        })
    }

    /// Returns the principal being recovered.
    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    /// Returns the principal sequence consumed by initiation.
    #[must_use]
    pub const fn expected_sequence(&self) -> u64 {
        self.expected_sequence
    }

    /// Returns the proposed replacement controller policy.
    #[must_use]
    pub const fn proposed_controller_policy_hash(&self) -> Digest384 {
        self.proposed_controller_policy_hash
    }

    /// Returns the proposed replacement authenticator-set root.
    #[must_use]
    pub const fn proposed_authenticator_set_root(&self) -> Digest384 {
        self.proposed_authenticator_set_root
    }

    /// Returns the recovery evidence commitment.
    #[must_use]
    pub const fn recovery_evidence_commitment(&self) -> Digest384 {
        self.recovery_evidence_commitment
    }

    /// Returns the initiation height.
    #[must_use]
    pub const fn initiated_at(&self) -> Height {
        self.initiated_at
    }

    /// Returns the first height after the challenge period.
    #[must_use]
    pub const fn challenge_deadline(&self) -> Height {
        self.challenge_deadline
    }

    /// Returns the bond escrowed with the recovery request.
    #[must_use]
    pub const fn recovery_bond(&self) -> Amount {
        self.recovery_bond
    }
}

impl CanonicalEncode for RecoveryRequest {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.principal_id.encode(encoder)?;
        self.expected_sequence.encode(encoder)?;
        self.proposed_controller_policy_hash.encode(encoder)?;
        self.proposed_authenticator_set_root.encode(encoder)?;
        self.recovery_evidence_commitment.encode(encoder)?;
        self.initiated_at.encode(encoder)?;
        self.challenge_deadline.encode(encoder)?;
        self.recovery_bond.encode(encoder)
    }
}

impl CanonicalDecode for RecoveryRequest {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(decoder)?,
            u64::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u128::decode(decoder)?,
        )
        .map_err(|_| {
            DecodeError::InvalidValue("recovery challenge deadline is not after initiation")
        })
    }
}

impl CanonicalType for RecoveryRequest {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}

/// Recovery-request validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryRequestError {
    /// The challenge deadline is equal to or earlier than initiation.
    ChallengeDeadlineNotAfterInitiation,
}

/// A canonical selector used by resource and data scopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeSelector {
    /// All values in the scope dimension.
    Any,
    /// Exactly one 384-bit identifier or namespace.
    Exact(Digest384),
    /// All values sharing a canonical bit prefix shorter than 384 bits.
    Prefix { bytes: Digest384, bits: u16 },
}

impl ScopeSelector {
    /// Constructs a normalized, non-empty prefix selector.
    pub fn prefix(bytes: Digest384, bits: u16) -> Result<Self, ScopeSelectorError> {
        if bits == 0 {
            return Err(ScopeSelectorError::EmptyPrefixMustUseAny);
        }
        if usize::from(bits) >= crate::DIGEST_LENGTH * 8 {
            return Err(ScopeSelectorError::FullPrefixMustUseExact);
        }
        if !is_normalized_prefix(bytes.as_bytes(), bits) {
            return Err(ScopeSelectorError::NonZeroBitsOutsidePrefix);
        }
        Ok(Self::Prefix { bytes, bits })
    }

    /// Returns whether this selector is provably contained by `parent`.
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        match (self, parent) {
            (_, Self::Any) => true,
            (Self::Exact(child), Self::Exact(parent)) => child == parent,
            (Self::Exact(child), Self::Prefix { bytes, bits }) => {
                matches_prefix(child.as_bytes(), bytes.as_bytes(), *bits)
            }
            (
                Self::Prefix { bytes: child, bits: child_bits },
                Self::Prefix { bytes: parent, bits: parent_bits },
            ) => {
                child_bits >= parent_bits
                    && matches_prefix(child.as_bytes(), parent.as_bytes(), *parent_bits)
            }
            (Self::Any | Self::Prefix { .. }, Self::Exact(_))
            | (Self::Any, Self::Prefix { .. }) => false,
        }
    }
}

impl CanonicalEncode for ScopeSelector {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Any => 0_u8.encode(encoder),
            Self::Exact(value) => {
                1_u8.encode(encoder)?;
                value.encode(encoder)
            }
            Self::Prefix { bytes, bits } => {
                2_u8.encode(encoder)?;
                bits.encode(encoder)?;
                bytes.encode(encoder)
            }
        }
    }
}

impl CanonicalDecode for ScopeSelector {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Any),
            1 => Ok(Self::Exact(Digest384::decode(decoder)?)),
            2 => {
                let bits = u16::decode(decoder)?;
                let bytes = Digest384::decode(decoder)?;
                Self::prefix(bytes, bits).map_err(|_| {
                    DecodeError::InvalidValue(
                        "scope prefix is empty, full-length, or non-normalized",
                    )
                })
            }
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ScopeSelector", tag }),
        }
    }
}

/// Scope-selector construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeSelectorError {
    /// A zero-bit prefix has the canonical representation `Any`.
    EmptyPrefixMustUseAny,
    /// A 384-bit prefix has the canonical representation `Exact`.
    FullPrefixMustUseExact,
    /// Bits outside the declared prefix were not zero.
    NonZeroBitsOutsidePrefix,
}

/// A resource-specific scope selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct ResourceSelector(ScopeSelector);

impl ResourceSelector {
    /// Selects all resources.
    pub const ANY: Self = Self(ScopeSelector::Any);

    /// Selects one exact object.
    #[must_use]
    pub const fn exact(object_id: ObjectId) -> Self {
        Self(ScopeSelector::Exact(object_id.into_digest()))
    }

    /// Selects a canonical object-ID prefix.
    pub fn prefix(bytes: Digest384, bits: u16) -> Result<Self, ScopeSelectorError> {
        ScopeSelector::prefix(bytes, bits).map(Self)
    }

    /// Borrows the underlying selector.
    #[must_use]
    pub const fn as_scope(&self) -> &ScopeSelector {
        &self.0
    }

    /// Returns whether this resource scope is contained by `parent`.
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.0.is_subset_of(&parent.0)
    }
}

impl CanonicalEncode for ResourceSelector {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.0.encode(encoder)
    }
}

impl CanonicalDecode for ResourceSelector {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self(ScopeSelector::decode(decoder)?))
    }
}

/// A data-specific scope selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct DataSelector(ScopeSelector);

impl DataSelector {
    /// Selects all data.
    pub const ANY: Self = Self(ScopeSelector::Any);

    /// Selects one exact data identifier or namespace.
    #[must_use]
    pub const fn exact(identifier: Digest384) -> Self {
        Self(ScopeSelector::Exact(identifier))
    }

    /// Selects a canonical data-identifier prefix.
    pub fn prefix(bytes: Digest384, bits: u16) -> Result<Self, ScopeSelectorError> {
        ScopeSelector::prefix(bytes, bits).map(Self)
    }

    /// Borrows the underlying selector.
    #[must_use]
    pub const fn as_scope(&self) -> &ScopeSelector {
        &self.0
    }

    /// Returns whether this data scope is contained by `parent`.
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.0.is_subset_of(&parent.0)
    }
}

impl CanonicalEncode for DataSelector {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.0.encode(encoder)
    }
}

impl CanonicalDecode for DataSelector {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self(ScopeSelector::decode(decoder)?))
    }
}

/// The identity binding required to exercise a capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HolderBinding {
    /// A public protocol principal.
    Principal(PrincipalId),
    /// A private holder commitment proven during authorization.
    Private(Digest384),
    /// An explicitly unbound bearer capability.
    Bearer,
}

impl CanonicalEncode for HolderBinding {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Principal(principal) => {
                0_u8.encode(encoder)?;
                principal.encode(encoder)
            }
            Self::Private(commitment) => {
                1_u8.encode(encoder)?;
                commitment.encode(encoder)
            }
            Self::Bearer => 2_u8.encode(encoder),
        }
    }
}

impl CanonicalDecode for HolderBinding {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Principal(PrincipalId::decode(decoder)?)),
            1 => Ok(Self::Private(Digest384::decode(decoder)?)),
            2 => Ok(Self::Bearer),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "HolderBinding", tag }),
        }
    }
}

/// A sorted, duplicate-free, non-empty action set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedActionSet(Vec<ActionId>);

impl BoundedActionSet {
    /// Maximum canonical size including the item-count prefix.
    pub const MAX_ENCODED_LEN: usize = 1 + MAX_CAPABILITY_ACTIONS * crate::DIGEST_LENGTH;

    /// Validates canonical order, uniqueness, and bounds.
    pub fn new(actions: Vec<ActionId>) -> Result<Self, BoundedActionSetError> {
        if actions.is_empty() {
            return Err(BoundedActionSetError::Empty);
        }
        if actions.len() > MAX_CAPABILITY_ACTIONS {
            return Err(BoundedActionSetError::TooMany {
                actual: actions.len(),
                maximum: MAX_CAPABILITY_ACTIONS,
            });
        }
        if actions.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(BoundedActionSetError::NotStrictlyOrdered);
        }
        Ok(Self(actions))
    }

    /// Borrows the canonical sorted actions.
    #[must_use]
    pub fn as_slice(&self) -> &[ActionId] {
        &self.0
    }

    /// Returns whether every child action is present in `parent`.
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.0.iter().all(|action| parent.0.binary_search(action).is_ok())
    }
}

impl CanonicalEncode for BoundedActionSet {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.0.len(), MAX_CAPABILITY_ACTIONS)?;
        for action in &self.0 {
            action.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for BoundedActionSet {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let length = decoder.read_length(MAX_CAPABILITY_ACTIONS)?;
        let mut actions = Vec::with_capacity(length);
        for _ in 0..length {
            actions.push(ActionId::decode(decoder)?);
        }
        Self::new(actions).map_err(|error| match error {
            BoundedActionSetError::Empty => {
                DecodeError::InvalidValue("capability action set is empty")
            }
            BoundedActionSetError::TooMany { .. } => {
                DecodeError::InvalidValue("capability action set exceeds its bound")
            }
            BoundedActionSetError::NotStrictlyOrdered => {
                DecodeError::InvalidValue("capability actions are not strictly ordered")
            }
        })
    }
}

/// Action-set construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedActionSetError {
    /// A capability must authorize at least one action.
    Empty,
    /// The number of actions exceeds the protocol bound.
    TooMany { actual: usize, maximum: usize },
    /// Actions contain duplicates or are not in ascending identifier order.
    NotStrictlyOrdered,
}

/// A deterministic maximum-use count per fixed block window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimit {
    maximum_uses: u64,
    window_blocks: u64,
}

impl RateLimit {
    /// Creates a non-zero rate limit.
    pub const fn new(maximum_uses: u64, window_blocks: u64) -> Result<Self, RateLimitError> {
        if maximum_uses == 0 {
            return Err(RateLimitError::ZeroMaximumUses);
        }
        if window_blocks == 0 {
            return Err(RateLimitError::ZeroWindow);
        }
        Ok(Self { maximum_uses, window_blocks })
    }

    /// Returns the maximum uses allowed in one window.
    #[must_use]
    pub const fn maximum_uses(self) -> u64 {
        self.maximum_uses
    }

    /// Returns the window length in blocks.
    #[must_use]
    pub const fn window_blocks(self) -> u64 {
        self.window_blocks
    }
}

impl CanonicalEncode for RateLimit {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.maximum_uses.encode(encoder)?;
        self.window_blocks.encode(encoder)
    }
}

impl CanonicalDecode for RateLimit {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(u64::decode(decoder)?, u64::decode(decoder)?).map_err(|error| match error {
            RateLimitError::ZeroMaximumUses => {
                DecodeError::InvalidValue("rate-limit maximum uses is zero")
            }
            RateLimitError::ZeroWindow => DecodeError::InvalidValue("rate-limit window is zero"),
        })
    }
}

/// Rate-limit validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitError {
    /// Zero uses never grants authority and is not canonical.
    ZeroMaximumUses,
    /// A rate-limit window must contain at least one block.
    ZeroWindow,
}

/// Construction fields for a canonical capability grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityGrantFields {
    /// Stable grant identifier.
    pub capability_id: CapabilityId,
    /// Principal issuing this grant or delegation.
    pub issuer: PrincipalId,
    /// Holder authentication binding.
    pub holder_binding: HolderBinding,
    /// Immediate parent for delegated authority.
    pub parent_capability: Option<CapabilityId>,
    /// Permitted actions in canonical sorted order.
    pub permitted_actions: BoundedActionSet,
    /// Resource authority boundary.
    pub resource_scope: ResourceSelector,
    /// Data-access authority boundary.
    pub data_scope: DataSelector,
    /// Optional monetary ceiling; `None` is unbounded.
    pub monetary_limit: Option<Amount>,
    /// Optional compute ceiling; `None` is unbounded.
    pub compute_limit: Option<ResourceUnits>,
    /// Optional block-window use rate.
    pub rate_limit: Option<RateLimit>,
    /// Optional total use count; `None` is unbounded.
    pub use_limit: Option<u64>,
    /// First valid block height.
    pub valid_from: Height,
    /// Optional final valid block height.
    pub valid_until: Option<Height>,
    /// Remaining permitted delegation steps.
    pub delegation_depth_remaining: u8,
    /// Whether this grant may issue children.
    pub delegation_allowed: bool,
    /// Optional mutable revocation registry.
    pub revocation_registry: Option<ObjectId>,
    /// Commitment to additional immutable constraints.
    pub constraint_hash: Digest384,
}

/// A signed, holder-bound, mechanically attenuable capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityGrant {
    fields: CapabilityGrantFields,
    issuer_signature: ProtocolSignature,
}

impl CapabilityGrant {
    /// Registered top-level type tag.
    pub const TYPE_TAG: u16 = 0x0030;
    /// Initial capability-grant schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Maximum canonical body length.
    pub const MAX_ENCODED_LEN: usize = 22_024;

    /// Constructs a capability after validating cross-field invariants.
    pub fn new(
        fields: CapabilityGrantFields,
        issuer_signature: ProtocolSignature,
    ) -> Result<Self, CapabilityValidationError> {
        if fields.parent_capability == Some(fields.capability_id) {
            return Err(CapabilityValidationError::SelfParent);
        }
        if fields.valid_until.is_some_and(|height| height < fields.valid_from) {
            return Err(CapabilityValidationError::ValidityEndsBeforeStart);
        }
        match (fields.delegation_allowed, fields.delegation_depth_remaining) {
            (true, 0) => return Err(CapabilityValidationError::DelegationAllowedWithZeroDepth),
            (false, 1..) => {
                return Err(CapabilityValidationError::DepthPresentWhenDelegationForbidden);
            }
            _ => {}
        }
        Ok(Self { fields, issuer_signature })
    }

    /// Borrows all authority-bearing fields.
    #[must_use]
    pub const fn fields(&self) -> &CapabilityGrantFields {
        &self.fields
    }

    /// Borrows the issuer signature.
    #[must_use]
    pub const fn issuer_signature(&self) -> &ProtocolSignature {
        &self.issuer_signature
    }
}

impl CanonicalEncode for CapabilityGrant {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        let fields = &self.fields;
        fields.capability_id.encode(encoder)?;
        fields.issuer.encode(encoder)?;
        fields.holder_binding.encode(encoder)?;
        fields.parent_capability.encode(encoder)?;
        fields.permitted_actions.encode(encoder)?;
        fields.resource_scope.encode(encoder)?;
        fields.data_scope.encode(encoder)?;
        fields.monetary_limit.encode(encoder)?;
        fields.compute_limit.encode(encoder)?;
        fields.rate_limit.encode(encoder)?;
        fields.use_limit.encode(encoder)?;
        fields.valid_from.encode(encoder)?;
        fields.valid_until.encode(encoder)?;
        fields.delegation_depth_remaining.encode(encoder)?;
        fields.delegation_allowed.encode(encoder)?;
        fields.revocation_registry.encode(encoder)?;
        fields.constraint_hash.encode(encoder)?;
        self.issuer_signature.encode(encoder)
    }
}

impl CanonicalDecode for CapabilityGrant {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let fields = CapabilityGrantFields {
            capability_id: CapabilityId::decode(decoder)?,
            issuer: PrincipalId::decode(decoder)?,
            holder_binding: HolderBinding::decode(decoder)?,
            parent_capability: Option::<CapabilityId>::decode(decoder)?,
            permitted_actions: BoundedActionSet::decode(decoder)?,
            resource_scope: ResourceSelector::decode(decoder)?,
            data_scope: DataSelector::decode(decoder)?,
            monetary_limit: Option::<u128>::decode(decoder)?,
            compute_limit: Option::<u128>::decode(decoder)?,
            rate_limit: Option::<RateLimit>::decode(decoder)?,
            use_limit: Option::<u64>::decode(decoder)?,
            valid_from: u64::decode(decoder)?,
            valid_until: Option::<u64>::decode(decoder)?,
            delegation_depth_remaining: u8::decode(decoder)?,
            delegation_allowed: bool::decode(decoder)?,
            revocation_registry: Option::<ObjectId>::decode(decoder)?,
            constraint_hash: Digest384::decode(decoder)?,
        };
        Self::new(fields, ProtocolSignature::decode(decoder)?).map_err(|error| match error {
            CapabilityValidationError::SelfParent => {
                DecodeError::InvalidValue("capability cannot be its own parent")
            }
            CapabilityValidationError::ValidityEndsBeforeStart => {
                DecodeError::InvalidValue("capability validity ends before it starts")
            }
            CapabilityValidationError::DelegationAllowedWithZeroDepth => {
                DecodeError::InvalidValue("delegation is allowed with zero remaining depth")
            }
            CapabilityValidationError::DepthPresentWhenDelegationForbidden => {
                DecodeError::InvalidValue(
                    "delegation depth is non-zero while delegation is forbidden",
                )
            }
        })
    }
}

impl CanonicalType for CapabilityGrant {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Capability cross-field validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityValidationError {
    /// A capability identifier appears as its own parent.
    SelfParent,
    /// The optional validity end predates the start.
    ValidityEndsBeforeStart,
    /// Delegation is enabled but there is no remaining child depth.
    DelegationAllowedWithZeroDepth,
    /// Non-zero depth is non-canonical when delegation is disabled.
    DepthPresentWhenDelegationForbidden,
}

fn is_normalized_prefix(bytes: &[u8; crate::DIGEST_LENGTH], bits: u16) -> bool {
    let full_bytes = usize::from(bits / 8);
    // Safe: a remainder modulo eight is always in 0..=7.
    let remaining_bits = (bits % 8) as u8;
    let trailing_start = if remaining_bits == 0 {
        full_bytes
    } else {
        let unused_mask = (1_u8 << (8 - remaining_bits)) - 1;
        if bytes[full_bytes] & unused_mask != 0 {
            return false;
        }
        full_bytes + 1
    };
    bytes[trailing_start..].iter().all(|byte| *byte == 0)
}

fn matches_prefix(
    candidate: &[u8; crate::DIGEST_LENGTH],
    prefix: &[u8; crate::DIGEST_LENGTH],
    bits: u16,
) -> bool {
    let full_bytes = usize::from(bits / 8);
    if candidate[..full_bytes] != prefix[..full_bytes] {
        return false;
    }
    // Safe: a remainder modulo eight is always in 0..=7.
    let remaining_bits = (bits % 8) as u8;
    if remaining_bits == 0 {
        true
    } else {
        let mask = u8::MAX << (8 - remaining_bits);
        candidate[full_bytes] & mask == prefix[full_bytes] & mask
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::{vec, vec::Vec};

    use activechain_canonical_codec::{decode_envelope, encode_envelope};

    use super::{
        BoundedActionSet, BoundedActionSetError, CapabilityGrant, CapabilityGrantFields,
        CapabilityValidationError, DataSelector, HolderBinding, RateLimit, RecoveryRequest,
        ResourceSelector, ScopeSelector, ScopeSelectorError,
    };
    use crate::{
        ActionId, CapabilityId, CryptoSuiteId, Digest384, ObjectId, PrincipalId, ProtocolSignature,
    };

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn action(byte: u8) -> ActionId {
        ActionId::new(digest(byte))
    }

    fn capability_id(byte: u8) -> CapabilityId {
        CapabilityId::new(digest(byte))
    }

    fn principal_id(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0x5a; 2_420])
            .expect("canonical signature length")
    }

    fn grant_fields() -> CapabilityGrantFields {
        CapabilityGrantFields {
            capability_id: capability_id(0x10),
            issuer: principal_id(0x20),
            holder_binding: HolderBinding::Principal(principal_id(0x30)),
            parent_capability: None,
            permitted_actions: BoundedActionSet::new(vec![action(1), action(2)])
                .expect("sorted actions"),
            resource_scope: ResourceSelector::ANY,
            data_scope: DataSelector::ANY,
            monetary_limit: Some(1_000),
            compute_limit: Some(5_000),
            rate_limit: Some(RateLimit::new(10, 100).expect("nonzero rate")),
            use_limit: Some(50),
            valid_from: 10,
            valid_until: Some(1_000),
            delegation_depth_remaining: 2,
            delegation_allowed: true,
            revocation_registry: Some(ObjectId::new(digest(0x40))),
            constraint_hash: digest(0x50),
        }
    }

    #[test]
    fn recovery_request_has_strict_challenge_period_and_round_trips() {
        let request = RecoveryRequest::new(
            principal_id(1),
            7,
            digest(2),
            digest(3),
            digest(4),
            100,
            200,
            500,
        )
        .expect("valid request");
        let bytes = encode_envelope(&request).expect("request encodes");
        assert_eq!(decode_envelope::<RecoveryRequest>(&bytes), Ok(request));
    }

    #[test]
    fn action_sets_reject_empty_duplicate_and_unsorted_inputs() {
        assert_eq!(BoundedActionSet::new(Vec::new()), Err(BoundedActionSetError::Empty));
        assert_eq!(
            BoundedActionSet::new(vec![action(1), action(1)]),
            Err(BoundedActionSetError::NotStrictlyOrdered)
        );
        assert_eq!(
            BoundedActionSet::new(vec![action(2), action(1)]),
            Err(BoundedActionSetError::NotStrictlyOrdered)
        );
    }

    #[test]
    fn prefix_scopes_are_normalized_and_have_mechanical_subset_semantics() {
        let parent = ScopeSelector::prefix(
            Digest384::new([
                0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            1,
        )
        .expect("normalized prefix");
        let child = ScopeSelector::Exact(digest(0x81));
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
        assert_eq!(
            ScopeSelector::prefix(digest(0x81), 1),
            Err(ScopeSelectorError::NonZeroBitsOutsidePrefix)
        );
    }

    #[test]
    fn capability_grants_round_trip_and_reject_inconsistent_delegation() {
        let grant = CapabilityGrant::new(grant_fields(), signature()).expect("valid grant");
        let bytes = encode_envelope(&grant).expect("grant fits its bound");
        assert_eq!(decode_envelope::<CapabilityGrant>(&bytes), Ok(grant));

        let mut invalid = grant_fields();
        invalid.delegation_allowed = false;
        assert_eq!(
            CapabilityGrant::new(invalid, signature()),
            Err(CapabilityValidationError::DepthPresentWhenDelegationForbidden)
        );
    }
}
