//! Canonical transaction, explicit state, and receipt types.

use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_policy_kernel::{MAX_EVALUATION_STEPS, PolicyRequest, PolicySet};
use activechain_protocol_types::{
    AccessManifest, ActionId, Digest384, Height, Object, ObjectId, ObjectOwner, ObjectVersionRef,
};

/// Maximum transfer commands in one development transaction.
pub const MAX_TRANSFER_COMMANDS: usize = 32;
/// Maximum objects in the explicit development state fixture.
pub const MAX_OBJECT_STATE_OBJECTS: usize = 64;
/// Maximum accumulated APL work across one transfer transaction.
pub const MAX_TRANSACTION_POLICY_STEPS: u32 =
    MAX_TRANSFER_COMMANDS as u32 * MAX_EVALUATION_STEPS as u32;

const fn transfer_action_id() -> ActionId {
    let mut bytes = [0_u8; 48];
    bytes[47] = 1;
    ActionId::new(Digest384::new(bytes))
}

/// Registered P-030 action identifier for basic object ownership transfer.
pub const TRANSFER_OBJECT_ACTION_ID: ActionId = transfer_action_id();

/// One authorized object ownership transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferCommand {
    input: ObjectVersionRef,
    new_owner: ObjectOwner,
    control_policy: PolicySet,
    request: PolicyRequest,
}

impl TransferCommand {
    /// Maximum canonical transfer-command body length.
    pub const MAX_ENCODED_LEN: usize = 39_226;

    /// Constructs one structurally valid command from validated constituents.
    #[must_use]
    pub const fn new(
        input: ObjectVersionRef,
        new_owner: ObjectOwner,
        control_policy: PolicySet,
        request: PolicyRequest,
    ) -> Self {
        Self { input, new_owner, control_policy, request }
    }

    /// Returns the exact object input.
    #[must_use]
    pub const fn input(&self) -> ObjectVersionRef {
        self.input
    }

    /// Returns the destination owner.
    #[must_use]
    pub const fn new_owner(&self) -> ObjectOwner {
        self.new_owner
    }

    /// Borrows the policy claimed to open the object's control commitment.
    #[must_use]
    pub const fn control_policy(&self) -> &PolicySet {
        &self.control_policy
    }

    /// Borrows the pre-verified policy request facts.
    #[must_use]
    pub const fn request(&self) -> &PolicyRequest {
        &self.request
    }
}

impl CanonicalEncode for TransferCommand {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.input.encode(encoder)?;
        self.new_owner.encode(encoder)?;
        self.control_policy.encode(encoder)?;
        self.request.encode(encoder)
    }
}

impl CanonicalDecode for TransferCommand {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(
            ObjectVersionRef::decode(decoder)?,
            ObjectOwner::decode(decoder)?,
            PolicySet::decode(decoder)?,
            PolicyRequest::decode(decoder)?,
        ))
    }
}

/// A bounded, canonically ordered batch of independent object transfers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferTransaction {
    height: Height,
    access_manifest: AccessManifest,
    commands: Vec<TransferCommand>,
}

impl TransferTransaction {
    /// Registered top-level transfer transaction type tag.
    pub const TYPE_TAG: u16 = 0x0052;
    /// Initial canonical transfer transaction schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Maximum canonical transfer transaction body length.
    pub const MAX_ENCODED_LEN: usize = 1_265_334;

    /// Validates non-empty bounded commands and canonical target ordering.
    pub fn new(
        height: Height,
        access_manifest: AccessManifest,
        commands: Vec<TransferCommand>,
    ) -> Result<Self, TransferTransactionError> {
        if commands.is_empty() {
            return Err(TransferTransactionError::EmptyCommands);
        }
        if commands.len() > MAX_TRANSFER_COMMANDS {
            return Err(TransferTransactionError::TooManyCommands {
                actual: commands.len(),
                maximum: MAX_TRANSFER_COMMANDS,
            });
        }
        if !commands.windows(2).all(|pair| pair[0].input.object_id() < pair[1].input.object_id()) {
            return Err(TransferTransactionError::CommandsNotStrictlyIncreasing);
        }
        Ok(Self { height, access_manifest, commands })
    }

    /// Returns deterministic block height context.
    #[must_use]
    pub const fn height(&self) -> Height {
        self.height
    }

    /// Borrows the access manifest.
    #[must_use]
    pub const fn access_manifest(&self) -> &AccessManifest {
        &self.access_manifest
    }

    /// Borrows commands in canonical target order.
    #[must_use]
    pub fn commands(&self) -> &[TransferCommand] {
        &self.commands
    }
}

impl CanonicalEncode for TransferTransaction {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.height.encode(encoder)?;
        self.access_manifest.encode(encoder)?;
        encoder.write_length(self.commands.len(), MAX_TRANSFER_COMMANDS)?;
        for command in &self.commands {
            command.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for TransferTransaction {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let height = u64::decode(decoder)?;
        let access_manifest = AccessManifest::decode(decoder)?;
        let command_count = decoder.read_length(MAX_TRANSFER_COMMANDS)?;
        let mut commands = Vec::with_capacity(command_count);
        for _ in 0..command_count {
            commands.push(TransferCommand::decode(decoder)?);
        }
        Self::new(height, access_manifest, commands).map_err(|error| match error {
            TransferTransactionError::EmptyCommands => {
                DecodeError::InvalidValue("transfer transaction has no commands")
            }
            TransferTransactionError::TooManyCommands { .. } => {
                DecodeError::InvalidValue("transfer transaction exceeds its command bound")
            }
            TransferTransactionError::CommandsNotStrictlyIncreasing => {
                DecodeError::InvalidValue("transfer commands are not strictly increasing")
            }
        })
    }
}

impl CanonicalType for TransferTransaction {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Transfer-transaction construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferTransactionError {
    /// A transaction must perform at least one transfer.
    EmptyCommands,
    /// The command count exceeds the development protocol bound.
    TooManyCommands { actual: usize, maximum: usize },
    /// Command targets are duplicated or not ordered by object identifier.
    CommandsNotStrictlyIncreasing,
}

/// An explicit bounded state fixture for the pre-state-tree semantic kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectState {
    objects: Vec<Object>,
}

impl ObjectState {
    /// Registered top-level explicit object-state type tag.
    pub const TYPE_TAG: u16 = 0x0054;
    /// Initial canonical object-state schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Maximum canonical object-state body length.
    pub const MAX_ENCODED_LEN: usize = 1_078_785;

    /// Validates the state bound and strict object-identifier order.
    pub fn new(objects: Vec<Object>) -> Result<Self, ObjectStateError> {
        if objects.len() > MAX_OBJECT_STATE_OBJECTS {
            return Err(ObjectStateError::TooManyObjects {
                actual: objects.len(),
                maximum: MAX_OBJECT_STATE_OBJECTS,
            });
        }
        if !objects.windows(2).all(|pair| pair[0].object_id() < pair[1].object_id()) {
            return Err(ObjectStateError::ObjectsNotStrictlyIncreasing);
        }
        Ok(Self { objects })
    }

    /// Borrows objects in canonical identifier order.
    #[must_use]
    pub fn objects(&self) -> &[Object] {
        &self.objects
    }

    /// Looks up one exact identifier without relying on host map iteration.
    #[must_use]
    pub fn find(&self, object_id: ObjectId) -> Option<&Object> {
        self.objects
            .binary_search_by_key(&object_id, Object::object_id)
            .ok()
            .map(|index| &self.objects[index])
    }
}

impl CanonicalEncode for ObjectState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.objects.len(), MAX_OBJECT_STATE_OBJECTS)?;
        for object in &self.objects {
            object.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for ObjectState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let object_count = decoder.read_length(MAX_OBJECT_STATE_OBJECTS)?;
        let mut objects = Vec::with_capacity(object_count);
        for _ in 0..object_count {
            objects.push(Object::decode(decoder)?);
        }
        Self::new(objects).map_err(|error| match error {
            ObjectStateError::TooManyObjects { .. } => {
                DecodeError::InvalidValue("object state exceeds its object bound")
            }
            ObjectStateError::ObjectsNotStrictlyIncreasing => {
                DecodeError::InvalidValue("state objects are not strictly increasing")
            }
        })
    }
}

impl CanonicalType for ObjectState {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Explicit object-state construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectStateError {
    /// Too many objects were supplied to the bounded fixture.
    TooManyObjects { actual: usize, maximum: usize },
    /// Objects are duplicated or out of canonical identifier order.
    ObjectsNotStrictlyIncreasing,
}

/// Total semantic receipt outcomes for the P-030 transfer refinement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReceiptResult {
    /// Every command was published atomically.
    Success = 0,
    /// Policy request height, action, or resource did not bind the command.
    RequestContextMismatch = 1,
    /// The command's exact input was not declared writable.
    AccessManifestViolation = 2,
    /// The explicit state did not contain the requested object.
    ObjectNotFound = 3,
    /// The input version was not current.
    StaleObjectVersion = 4,
    /// The supplied policy did not open the object's control commitment.
    ControlPolicyMismatch = 5,
    /// The committed control policy denied the request.
    AuthorizationDenied = 6,
    /// A permit returned obligations this refinement cannot settle.
    UnsupportedObligation = 7,
    /// An immutable source or destination was requested.
    ImmutableObject = 8,
    /// The object was not marked transferable.
    TransferDisabled = 9,
    /// The requested owner was already current.
    OwnerUnchanged = 10,
    /// The current version could not advance without overflow.
    VersionExhausted = 11,
}

impl CanonicalEncode for ReceiptResult {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for ReceiptResult {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Success),
            1 => Ok(Self::RequestContextMismatch),
            2 => Ok(Self::AccessManifestViolation),
            3 => Ok(Self::ObjectNotFound),
            4 => Ok(Self::StaleObjectVersion),
            5 => Ok(Self::ControlPolicyMismatch),
            6 => Ok(Self::AuthorizationDenied),
            7 => Ok(Self::UnsupportedObligation),
            8 => Ok(Self::ImmutableObject),
            9 => Ok(Self::TransferDisabled),
            10 => Ok(Self::OwnerUnchanged),
            11 => Ok(Self::VersionExhausted),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ReceiptResult", tag }),
        }
    }
}

/// Canonical binding of one total transition outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionReceipt {
    result: ReceiptResult,
    failed_command: Option<u8>,
    objects_updated: u8,
    policy_steps: u32,
    pre_state_commitment: Digest384,
    post_state_commitment: Digest384,
}

impl TransitionReceipt {
    /// Registered top-level transition-receipt type tag.
    pub const TYPE_TAG: u16 = 0x0053;
    /// Initial canonical transition-receipt schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Fixed maximum canonical receipt body length.
    pub const MAX_ENCODED_LEN: usize = 104;

    /// Checks success/failure shape, counts, work, and atomic commitments.
    pub fn new(
        result: ReceiptResult,
        failed_command: Option<u8>,
        objects_updated: u8,
        policy_steps: u32,
        pre_state_commitment: Digest384,
        post_state_commitment: Digest384,
    ) -> Result<Self, TransitionReceiptError> {
        if usize::from(objects_updated) > MAX_TRANSFER_COMMANDS {
            return Err(TransitionReceiptError::TooManyUpdatedObjects(objects_updated));
        }
        if policy_steps > MAX_TRANSACTION_POLICY_STEPS {
            return Err(TransitionReceiptError::TooManyPolicySteps(policy_steps));
        }
        match result {
            ReceiptResult::Success => {
                if failed_command.is_some() || objects_updated == 0 {
                    return Err(TransitionReceiptError::InvalidSuccessShape);
                }
            }
            _ => {
                let Some(failed_index) = failed_command else {
                    return Err(TransitionReceiptError::InvalidFailureShape);
                };
                if usize::from(failed_index) >= MAX_TRANSFER_COMMANDS
                    || objects_updated != 0
                    || pre_state_commitment != post_state_commitment
                {
                    return Err(TransitionReceiptError::InvalidFailureShape);
                }
            }
        }
        Ok(Self {
            result,
            failed_command,
            objects_updated,
            policy_steps,
            pre_state_commitment,
            post_state_commitment,
        })
    }

    /// Returns the semantic result.
    #[must_use]
    pub const fn result(self) -> ReceiptResult {
        self.result
    }

    /// Returns the zero-based failing command index.
    #[must_use]
    pub const fn failed_command(self) -> Option<u8> {
        self.failed_command
    }

    /// Returns the count of object versions published.
    #[must_use]
    pub const fn objects_updated(self) -> u8 {
        self.objects_updated
    }

    /// Returns accumulated APL work.
    #[must_use]
    pub const fn policy_steps(self) -> u32 {
        self.policy_steps
    }

    /// Returns the committed canonical pre-state.
    #[must_use]
    pub const fn pre_state_commitment(self) -> Digest384 {
        self.pre_state_commitment
    }

    /// Returns the committed canonical post-state.
    #[must_use]
    pub const fn post_state_commitment(self) -> Digest384 {
        self.post_state_commitment
    }
}

impl CanonicalEncode for TransitionReceipt {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.result.encode(encoder)?;
        self.failed_command.encode(encoder)?;
        self.objects_updated.encode(encoder)?;
        self.policy_steps.encode(encoder)?;
        self.pre_state_commitment.encode(encoder)?;
        self.post_state_commitment.encode(encoder)
    }
}

impl CanonicalDecode for TransitionReceipt {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ReceiptResult::decode(decoder)?,
            Option::<u8>::decode(decoder)?,
            u8::decode(decoder)?,
            u32::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
        )
        .map_err(|error| match error {
            TransitionReceiptError::TooManyUpdatedObjects(_) => {
                DecodeError::InvalidValue("receipt exceeds the updated-object bound")
            }
            TransitionReceiptError::TooManyPolicySteps(_) => {
                DecodeError::InvalidValue("receipt exceeds the policy-work bound")
            }
            TransitionReceiptError::InvalidSuccessShape => {
                DecodeError::InvalidValue("receipt has an invalid success shape")
            }
            TransitionReceiptError::InvalidFailureShape => {
                DecodeError::InvalidValue("receipt has an invalid failure shape")
            }
        })
    }
}

impl CanonicalType for TransitionReceipt {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Receipt construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionReceiptError {
    /// The published update count exceeds the command bound.
    TooManyUpdatedObjects(u8),
    /// Accumulated policy work exceeds the structural maximum.
    TooManyPolicySteps(u32),
    /// Success did not carry a non-zero update count and no failure index.
    InvalidSuccessShape,
    /// Failure did not carry one bounded index, zero updates, and equal state commitments.
    InvalidFailureShape,
}
