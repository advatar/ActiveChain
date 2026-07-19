//! Canonical, bounded authorization requests consumed by APL.

use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{
    ActionId, Amount, CapabilityId, Digest384, FreezeState, Height, ObjectId,
};

use crate::ActorBinding;

/// Maximum credential-schema facts admitted by one authorization request.
pub const MAX_CREDENTIAL_FACTS: usize = 32;
/// Maximum capability facts admitted by one authorization request.
pub const MAX_CAPABILITY_FACTS: usize = 32;
/// Maximum distinct approval roles admitted by one authorization request.
pub const MAX_APPROVAL_FACTS: usize = 16;

/// A verified approval count for one role commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalFact {
    role: Digest384,
    count: u8,
}

impl ApprovalFact {
    /// Constructs a non-zero approval fact.
    pub const fn new(role: Digest384, count: u8) -> Result<Self, ApprovalFactError> {
        if count == 0 {
            return Err(ApprovalFactError::ZeroCount);
        }
        Ok(Self { role, count })
    }

    /// Returns the committed approval role.
    #[must_use]
    pub const fn role(&self) -> Digest384 {
        self.role
    }

    /// Returns the number of verified, distinct approvals for the role.
    #[must_use]
    pub const fn count(&self) -> u8 {
        self.count
    }
}

impl CanonicalEncode for ApprovalFact {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.role.encode(encoder)?;
        self.count.encode(encoder)
    }
}

impl CanonicalDecode for ApprovalFact {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(Digest384::decode(decoder)?, u8::decode(decoder)?)
            .map_err(|_| DecodeError::InvalidValue("approval fact count is zero"))
    }
}

/// Approval-fact validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalFactError {
    /// Zero approvals carry no information and are omitted canonically.
    ZeroCount,
}

/// Fields used to construct a bounded authorization request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRequestFields {
    /// Public identifier or private commitment for the requesting actor.
    pub actor: ActorBinding,
    /// Action the actor is requesting.
    pub action: ActionId,
    /// Exact object affected by the request.
    pub resource: ObjectId,
    /// Deterministic block height supplied by transition context.
    pub height: Height,
    /// Value moved or placed at risk by the request.
    pub value: Amount,
    /// Committed lifecycle state of the actor principal.
    pub freeze_state: FreezeState,
    /// Optional purpose commitment explicitly declared by the request.
    pub declared_purpose: Option<Digest384>,
    /// Strictly increasing verified credential-schema commitments.
    pub credential_schemas: Vec<Digest384>,
    /// Strictly increasing verified capability identifiers.
    pub capabilities: Vec<CapabilityId>,
    /// Strictly increasing, non-zero approval facts ordered by role.
    pub approvals: Vec<ApprovalFact>,
}

/// A canonical collection of facts available to the policy evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRequest {
    actor: ActorBinding,
    action: ActionId,
    resource: ObjectId,
    height: Height,
    value: Amount,
    freeze_state: FreezeState,
    declared_purpose: Option<Digest384>,
    credential_schemas: Vec<Digest384>,
    capabilities: Vec<CapabilityId>,
    approvals: Vec<ApprovalFact>,
}

impl PolicyRequest {
    /// Registered top-level policy-request type tag.
    pub const TYPE_TAG: u16 = 0x0041;
    /// Initial canonical request schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Maximum canonical request body length under all protocol bounds.
    pub const MAX_ENCODED_LEN: usize = 4_078;

    /// Validates bounds and canonical set ordering before constructing a request.
    pub fn new(fields: PolicyRequestFields) -> Result<Self, PolicyRequestError> {
        if fields.credential_schemas.len() > MAX_CREDENTIAL_FACTS {
            return Err(PolicyRequestError::TooManyCredentialFacts {
                actual: fields.credential_schemas.len(),
                maximum: MAX_CREDENTIAL_FACTS,
            });
        }
        if fields.capabilities.len() > MAX_CAPABILITY_FACTS {
            return Err(PolicyRequestError::TooManyCapabilityFacts {
                actual: fields.capabilities.len(),
                maximum: MAX_CAPABILITY_FACTS,
            });
        }
        if fields.approvals.len() > MAX_APPROVAL_FACTS {
            return Err(PolicyRequestError::TooManyApprovalFacts {
                actual: fields.approvals.len(),
                maximum: MAX_APPROVAL_FACTS,
            });
        }
        if !strictly_increasing(&fields.credential_schemas) {
            return Err(PolicyRequestError::CredentialFactsNotStrictlyIncreasing);
        }
        if !strictly_increasing(&fields.capabilities) {
            return Err(PolicyRequestError::CapabilityFactsNotStrictlyIncreasing);
        }
        if !fields.approvals.windows(2).all(|pair| pair[0].role < pair[1].role) {
            return Err(PolicyRequestError::ApprovalFactsNotStrictlyIncreasing);
        }

        Ok(Self {
            actor: fields.actor,
            action: fields.action,
            resource: fields.resource,
            height: fields.height,
            value: fields.value,
            freeze_state: fields.freeze_state,
            declared_purpose: fields.declared_purpose,
            credential_schemas: fields.credential_schemas,
            capabilities: fields.capabilities,
            approvals: fields.approvals,
        })
    }

    /// Returns the actor binding.
    #[must_use]
    pub const fn actor(&self) -> ActorBinding {
        self.actor
    }

    /// Returns the requested action.
    #[must_use]
    pub const fn action(&self) -> ActionId {
        self.action
    }

    /// Returns the exact requested resource.
    #[must_use]
    pub const fn resource(&self) -> ObjectId {
        self.resource
    }

    /// Returns the deterministic evaluation height.
    #[must_use]
    pub const fn height(&self) -> Height {
        self.height
    }

    /// Returns the request value.
    #[must_use]
    pub const fn value(&self) -> Amount {
        self.value
    }

    /// Returns the actor's committed freeze state.
    #[must_use]
    pub const fn freeze_state(&self) -> FreezeState {
        self.freeze_state
    }

    /// Returns the optional declared-purpose commitment.
    #[must_use]
    pub const fn declared_purpose(&self) -> Option<Digest384> {
        self.declared_purpose
    }

    /// Borrows credential-schema facts in canonical order.
    #[must_use]
    pub fn credential_schemas(&self) -> &[Digest384] {
        &self.credential_schemas
    }

    /// Borrows capability facts in canonical order.
    #[must_use]
    pub fn capabilities(&self) -> &[CapabilityId] {
        &self.capabilities
    }

    /// Borrows approval facts in canonical role order.
    #[must_use]
    pub fn approvals(&self) -> &[ApprovalFact] {
        &self.approvals
    }

    /// Returns whether a verified credential schema is present.
    #[must_use]
    pub fn contains_credential_schema(&self, schema: &Digest384) -> bool {
        self.credential_schemas.binary_search(schema).is_ok()
    }

    /// Returns whether a verified capability is present.
    #[must_use]
    pub fn contains_capability(&self, capability: &CapabilityId) -> bool {
        self.capabilities.binary_search(capability).is_ok()
    }

    /// Returns the verified approval count for a role, or zero when absent.
    #[must_use]
    pub fn approval_count(&self, role: &Digest384) -> u8 {
        self.approvals
            .binary_search_by_key(role, |fact| fact.role)
            .map_or(0, |index| self.approvals[index].count)
    }
}

impl CanonicalEncode for PolicyRequest {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.actor.encode(encoder)?;
        self.action.encode(encoder)?;
        self.resource.encode(encoder)?;
        self.height.encode(encoder)?;
        self.value.encode(encoder)?;
        self.freeze_state.encode(encoder)?;
        self.declared_purpose.encode(encoder)?;

        encoder.write_length(self.credential_schemas.len(), MAX_CREDENTIAL_FACTS)?;
        for schema in &self.credential_schemas {
            schema.encode(encoder)?;
        }

        encoder.write_length(self.capabilities.len(), MAX_CAPABILITY_FACTS)?;
        for capability in &self.capabilities {
            capability.encode(encoder)?;
        }

        encoder.write_length(self.approvals.len(), MAX_APPROVAL_FACTS)?;
        for approval in &self.approvals {
            approval.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for PolicyRequest {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let actor = ActorBinding::decode(decoder)?;
        let action = ActionId::decode(decoder)?;
        let resource = ObjectId::decode(decoder)?;
        let height = u64::decode(decoder)?;
        let value = u128::decode(decoder)?;
        let freeze_state = FreezeState::decode(decoder)?;
        let declared_purpose = Option::<Digest384>::decode(decoder)?;

        let credential_count = decoder.read_length(MAX_CREDENTIAL_FACTS)?;
        let mut credential_schemas = Vec::with_capacity(credential_count);
        for _ in 0..credential_count {
            credential_schemas.push(Digest384::decode(decoder)?);
        }

        let capability_count = decoder.read_length(MAX_CAPABILITY_FACTS)?;
        let mut capabilities = Vec::with_capacity(capability_count);
        for _ in 0..capability_count {
            capabilities.push(CapabilityId::decode(decoder)?);
        }

        let approval_count = decoder.read_length(MAX_APPROVAL_FACTS)?;
        let mut approvals = Vec::with_capacity(approval_count);
        for _ in 0..approval_count {
            approvals.push(ApprovalFact::decode(decoder)?);
        }

        Self::new(PolicyRequestFields {
            actor,
            action,
            resource,
            height,
            value,
            freeze_state,
            declared_purpose,
            credential_schemas,
            capabilities,
            approvals,
        })
        .map_err(policy_request_decode_error)
    }
}

impl CanonicalType for PolicyRequest {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Request construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyRequestError {
    /// Too many credential-schema facts were supplied.
    TooManyCredentialFacts { actual: usize, maximum: usize },
    /// Too many capability facts were supplied.
    TooManyCapabilityFacts { actual: usize, maximum: usize },
    /// Too many approval-role facts were supplied.
    TooManyApprovalFacts { actual: usize, maximum: usize },
    /// Credential schemas are duplicated or out of canonical order.
    CredentialFactsNotStrictlyIncreasing,
    /// Capability identifiers are duplicated or out of canonical order.
    CapabilityFactsNotStrictlyIncreasing,
    /// Approval roles are duplicated or out of canonical order.
    ApprovalFactsNotStrictlyIncreasing,
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn policy_request_decode_error(error: PolicyRequestError) -> DecodeError {
    match error {
        PolicyRequestError::TooManyCredentialFacts { .. } => {
            DecodeError::InvalidValue("request exceeds its credential-fact bound")
        }
        PolicyRequestError::TooManyCapabilityFacts { .. } => {
            DecodeError::InvalidValue("request exceeds its capability-fact bound")
        }
        PolicyRequestError::TooManyApprovalFacts { .. } => {
            DecodeError::InvalidValue("request exceeds its approval-fact bound")
        }
        PolicyRequestError::CredentialFactsNotStrictlyIncreasing => {
            DecodeError::InvalidValue("credential facts are not strictly increasing")
        }
        PolicyRequestError::CapabilityFactsNotStrictlyIncreasing => {
            DecodeError::InvalidValue("capability facts are not strictly increasing")
        }
        PolicyRequestError::ApprovalFactsNotStrictlyIncreasing => {
            DecodeError::InvalidValue("approval facts are not strictly increasing")
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;

    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use activechain_protocol_types::{
        ActionId, CapabilityId, Digest384, FreezeState, ObjectId, PrincipalId,
    };
    use proptest::prelude::*;

    use super::{
        ApprovalFact, ApprovalFactError, PolicyRequest, PolicyRequestError, PolicyRequestFields,
    };
    use crate::ActorBinding;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn fields() -> PolicyRequestFields {
        PolicyRequestFields {
            actor: ActorBinding::Principal(PrincipalId::new(digest(0x10))),
            action: ActionId::new(digest(0x20)),
            resource: ObjectId::new(digest(0x30)),
            height: 42,
            value: 100,
            freeze_state: FreezeState::Active,
            declared_purpose: Some(digest(0x40)),
            credential_schemas: vec![digest(0x50), digest(0x51)],
            capabilities: vec![CapabilityId::new(digest(0x60)), CapabilityId::new(digest(0x61))],
            approvals: vec![
                ApprovalFact::new(digest(0x70), 1).expect("non-zero"),
                ApprovalFact::new(digest(0x71), 2).expect("non-zero"),
            ],
        }
    }

    #[test]
    fn facts_must_be_unique_and_strictly_increasing() {
        let mut request = fields();
        request.credential_schemas.swap(0, 1);
        assert_eq!(
            PolicyRequest::new(request),
            Err(PolicyRequestError::CredentialFactsNotStrictlyIncreasing)
        );

        let mut request = fields();
        request.capabilities[1] = request.capabilities[0];
        assert_eq!(
            PolicyRequest::new(request),
            Err(PolicyRequestError::CapabilityFactsNotStrictlyIncreasing)
        );

        let mut request = fields();
        request.approvals.swap(0, 1);
        assert_eq!(
            PolicyRequest::new(request),
            Err(PolicyRequestError::ApprovalFactsNotStrictlyIncreasing)
        );
    }

    #[test]
    fn zero_approval_fact_is_not_canonical() {
        assert_eq!(ApprovalFact::new(digest(0x70), 0), Err(ApprovalFactError::ZeroCount));
    }

    #[test]
    fn fact_membership_and_approval_lookup_are_exact() {
        let request = PolicyRequest::new(fields()).expect("canonical request");
        assert!(request.contains_credential_schema(&digest(0x50)));
        assert!(!request.contains_credential_schema(&digest(0xff)));
        assert!(request.contains_capability(&CapabilityId::new(digest(0x61))));
        assert_eq!(request.approval_count(&digest(0x71)), 2);
        assert_eq!(request.approval_count(&digest(0xff)), 0);
    }

    proptest! {
        #[test]
        fn arbitrary_numeric_context_round_trips(
            height: u64,
            value: u128,
            action_byte: u8,
            resource_byte: u8,
            private_actor: bool,
        ) {
            let actor = if private_actor {
                ActorBinding::Private(digest(0x11))
            } else {
                ActorBinding::Principal(PrincipalId::new(digest(0x10)))
            };
            let request = PolicyRequest::new(PolicyRequestFields {
                actor,
                action: ActionId::new(digest(action_byte)),
                resource: ObjectId::new(digest(resource_byte)),
                height,
                value,
                freeze_state: FreezeState::RecoveryPending,
                declared_purpose: None,
                credential_schemas: vec![],
                capabilities: vec![],
                approvals: vec![],
            }).expect("empty fact sets are canonical");
            let encoded = encode_envelope(&request).expect("request fits its declared bound");
            prop_assert_eq!(decode_envelope(&encoded), Ok(request));
        }
    }
}
