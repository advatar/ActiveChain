//! Canonical P-040 development admission values.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_policy_kernel::ActorBinding;
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    Amount, ChainId, Digest384, Height, ObjectId, PrincipalId, TransactionId,
};
use activechain_transition::TransferTransaction;

/// Initial public development action protocol version.
pub const ACTION_PROTOCOL_VERSION: u16 = 1;

/// Six independent deterministic resource quantities.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceVector {
    policy_steps: u64,
    object_reads: u64,
    object_writes: u64,
    vm_gas: u64,
    events: u64,
    encoded_bytes: u64,
}

impl ResourceVector {
    /// Fixed nested canonical length.
    pub const ENCODED_LENGTH: usize = 48;

    /// Constructs an explicit multidimensional resource vector.
    #[must_use]
    pub const fn new(
        policy_steps: u64,
        object_reads: u64,
        object_writes: u64,
        vm_gas: u64,
        events: u64,
        encoded_bytes: u64,
    ) -> Self {
        Self { policy_steps, object_reads, object_writes, vm_gas, events, encoded_bytes }
    }

    /// Returns policy evaluator steps.
    #[must_use]
    pub const fn policy_steps(self) -> u64 {
        self.policy_steps
    }

    /// Returns explicit object reads.
    #[must_use]
    pub const fn object_reads(self) -> u64 {
        self.object_reads
    }

    /// Returns attempted object writes.
    #[must_use]
    pub const fn object_writes(self) -> u64 {
        self.object_writes
    }

    /// Returns ObjectVM gas.
    #[must_use]
    pub const fn vm_gas(self) -> u64 {
        self.vm_gas
    }

    /// Returns emitted event count.
    #[must_use]
    pub const fn events(self) -> u64 {
        self.events
    }

    /// Returns canonical encoded envelope bytes.
    #[must_use]
    pub const fn encoded_bytes(self) -> u64 {
        self.encoded_bytes
    }

    /// Checks every dimension independently against a ceiling.
    #[must_use]
    pub const fn fits_within(self, ceiling: Self) -> bool {
        self.policy_steps <= ceiling.policy_steps
            && self.object_reads <= ceiling.object_reads
            && self.object_writes <= ceiling.object_writes
            && self.vm_gas <= ceiling.vm_gas
            && self.events <= ceiling.events
            && self.encoded_bytes <= ceiling.encoded_bytes
    }

    /// Computes the checked `u128` scalar charge under explicit prices.
    pub fn checked_charge(self, prices: ResourcePrices) -> Option<Amount> {
        let terms = [
            (self.policy_steps, prices.policy_step),
            (self.object_reads, prices.object_read),
            (self.object_writes, prices.object_write),
            (self.vm_gas, prices.vm_gas),
            (self.events, prices.event),
            (self.encoded_bytes, prices.encoded_byte),
        ];
        let mut charge = 0_u128;
        for (units, price) in terms {
            let term = u128::from(units).checked_mul(u128::from(price))?;
            charge = charge.checked_add(term)?;
        }
        Some(charge)
    }
}

impl CanonicalEncode for ResourceVector {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.policy_steps.encode(encoder)?;
        self.object_reads.encode(encoder)?;
        self.object_writes.encode(encoder)?;
        self.vm_gas.encode(encoder)?;
        self.events.encode(encoder)?;
        self.encoded_bytes.encode(encoder)
    }
}

impl CanonicalDecode for ResourceVector {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        ))
    }
}

/// Per-unit development prices in resource-vector order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourcePrices {
    policy_step: u64,
    object_read: u64,
    object_write: u64,
    vm_gas: u64,
    event: u64,
    encoded_byte: u64,
}

impl ResourcePrices {
    /// Fixed nested canonical length.
    pub const ENCODED_LENGTH: usize = 48;

    /// Constructs one price for each resource dimension.
    #[must_use]
    pub const fn new(
        policy_step: u64,
        object_read: u64,
        object_write: u64,
        vm_gas: u64,
        event: u64,
        encoded_byte: u64,
    ) -> Self {
        Self { policy_step, object_read, object_write, vm_gas, event, encoded_byte }
    }
}

impl CanonicalEncode for ResourcePrices {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.policy_step.encode(encoder)?;
        self.object_read.encode(encoder)?;
        self.object_write.encode(encoder)?;
        self.vm_gas.encode(encoder)?;
        self.event.encode(encoder)?;
        self.encoded_byte.encode(encoder)
    }
}

impl CanonicalDecode for ResourcePrices {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        ))
    }
}

/// Inclusive block-height validity bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidityInterval {
    valid_from: Height,
    valid_until: Height,
}

impl ValidityInterval {
    /// Fixed nested canonical length.
    pub const ENCODED_LENGTH: usize = 16;

    /// Rejects an inverted interval.
    pub const fn new(
        valid_from: Height,
        valid_until: Height,
    ) -> Result<Self, ValidityIntervalError> {
        if valid_from > valid_until {
            Err(ValidityIntervalError::Inverted)
        } else {
            Ok(Self { valid_from, valid_until })
        }
    }

    /// Returns the inclusive lower height.
    #[must_use]
    pub const fn valid_from(self) -> Height {
        self.valid_from
    }

    /// Returns the inclusive upper height.
    #[must_use]
    pub const fn valid_until(self) -> Height {
        self.valid_until
    }

    /// Checks inclusive membership.
    #[must_use]
    pub const fn contains(self, height: Height) -> bool {
        self.valid_from <= height && height <= self.valid_until
    }
}

impl CanonicalEncode for ValidityInterval {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.valid_from.encode(encoder)?;
        self.valid_until.encode(encoder)
    }
}

impl CanonicalDecode for ValidityInterval {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(u64::decode(decoder)?, u64::decode(decoder)?)
            .map_err(|_| DecodeError::InvalidValue("action validity interval is inverted"))
    }
}

/// Validity interval construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidityIntervalError {
    /// The lower height is greater than the upper height.
    Inverted,
}

/// One-shot public development fee reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeTicket {
    ticket_id: ObjectId,
    payer: PrincipalId,
    reserved_amount: Amount,
    valid_until: Height,
    nonce: u64,
    permitted_resources: ResourceVector,
}

impl FeeTicket {
    /// Registered fee-ticket type tag.
    pub const TYPE_TAG: u16 = 0x0070;
    /// Initial fee-ticket schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Fixed canonical fee-ticket body length.
    pub const ENCODED_LENGTH: usize = 176;

    /// Requires a non-zero reservation.
    pub const fn new(
        ticket_id: ObjectId,
        payer: PrincipalId,
        reserved_amount: Amount,
        valid_until: Height,
        nonce: u64,
        permitted_resources: ResourceVector,
    ) -> Result<Self, FeeTicketError> {
        if reserved_amount == 0 {
            return Err(FeeTicketError::ZeroReservation);
        }
        Ok(Self { ticket_id, payer, reserved_amount, valid_until, nonce, permitted_resources })
    }

    /// Returns the unique one-shot identifier.
    #[must_use]
    pub const fn ticket_id(self) -> ObjectId {
        self.ticket_id
    }

    /// Returns the fee payer, which may differ from the sender.
    #[must_use]
    pub const fn payer(self) -> PrincipalId {
        self.payer
    }

    /// Returns the maximum reserved charge.
    #[must_use]
    pub const fn reserved_amount(self) -> Amount {
        self.reserved_amount
    }

    /// Returns the final valid block height.
    #[must_use]
    pub const fn valid_until(self) -> Height {
        self.valid_until
    }

    /// Returns the ticket issuer's nonce.
    #[must_use]
    pub const fn nonce(self) -> u64 {
        self.nonce
    }

    /// Returns the independently bounded permitted resource vector.
    #[must_use]
    pub const fn permitted_resources(self) -> ResourceVector {
        self.permitted_resources
    }
}

impl CanonicalEncode for FeeTicket {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.ticket_id.encode(encoder)?;
        self.payer.encode(encoder)?;
        self.reserved_amount.encode(encoder)?;
        self.valid_until.encode(encoder)?;
        self.nonce.encode(encoder)?;
        self.permitted_resources.encode(encoder)
    }
}

impl CanonicalDecode for FeeTicket {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ObjectId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            u128::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            ResourceVector::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("fee ticket has zero reservation"))
    }
}

impl CanonicalType for FeeTicket {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}

/// Fee-ticket construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeeTicketError {
    /// A ticket must reserve a positive amount.
    ZeroReservation,
}

/// Exact replay-protection state for one public sender channel.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NonceChannel {
    sender: PrincipalId,
    channel: u16,
    next_sequence: u64,
}

impl NonceChannel {
    /// Registered nonce-channel type tag.
    pub const TYPE_TAG: u16 = 0x0072;
    /// Initial nonce-channel schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Fixed canonical nonce-channel body length.
    pub const ENCODED_LENGTH: usize = 58;

    /// Constructs explicit channel state.
    #[must_use]
    pub const fn new(sender: PrincipalId, channel: u16, next_sequence: u64) -> Self {
        Self { sender, channel, next_sequence }
    }

    /// Returns the public sender.
    #[must_use]
    pub const fn sender(self) -> PrincipalId {
        self.sender
    }

    /// Returns the sender-local channel number.
    #[must_use]
    pub const fn channel(self) -> u16 {
        self.channel
    }

    /// Returns the only sequence currently admissible.
    #[must_use]
    pub const fn next_sequence(self) -> u64 {
        self.next_sequence
    }

    /// Advances exactly once, rejecting replay, gaps, and exhaustion.
    pub const fn advance(self, supplied: u64) -> Result<Self, NonceAdvanceError> {
        if supplied < self.next_sequence {
            return Err(NonceAdvanceError::Replay { supplied, expected: self.next_sequence });
        }
        if supplied > self.next_sequence {
            return Err(NonceAdvanceError::SequenceGap { supplied, expected: self.next_sequence });
        }
        let Some(next_sequence) = self.next_sequence.checked_add(1) else {
            return Err(NonceAdvanceError::SequenceExhausted);
        };
        Ok(Self { next_sequence, ..self })
    }
}

impl CanonicalEncode for NonceChannel {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.sender.encode(encoder)?;
        self.channel.encode(encoder)?;
        self.next_sequence.encode(encoder)
    }
}

impl CanonicalDecode for NonceChannel {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(PrincipalId::decode(decoder)?, u16::decode(decoder)?, u64::decode(decoder)?))
    }
}

impl CanonicalType for NonceChannel {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}

/// Exact nonce advancement failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceAdvanceError {
    /// The supplied sequence has already been consumed.
    Replay { supplied: u64, expected: u64 },
    /// One or more earlier sequences are absent.
    SequenceGap { supplied: u64, expected: u64 },
    /// The channel cannot advance without wrapping.
    SequenceExhausted,
}

/// Canonical public development action envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionEnvelope {
    protocol_version: u16,
    chain_id: ChainId,
    sender: PrincipalId,
    fee_ticket: FeeTicket,
    nonce_channel: u16,
    sequence: u64,
    validity: ValidityInterval,
    maximum_resources: ResourceVector,
    payload_commitment: Digest384,
    payload: TransferTransaction,
    authorization_commitment: Digest384,
}

impl ActionEnvelope {
    /// Registered action-envelope type tag.
    pub const TYPE_TAG: u16 = 0x0071;
    /// Initial action-envelope schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Worst-case canonical action-envelope body length.
    pub const MAX_ENCODED_LEN: usize = 1_265_778;

    /// Validates protocol, payload, actor, validity, and ticket-resource binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_version: u16,
        chain_id: ChainId,
        sender: PrincipalId,
        fee_ticket: FeeTicket,
        nonce_channel: u16,
        sequence: u64,
        validity: ValidityInterval,
        maximum_resources: ResourceVector,
        payload_commitment: Digest384,
        payload: TransferTransaction,
        authorization_commitment: Digest384,
    ) -> Result<Self, ActionEnvelopeError> {
        if protocol_version != ACTION_PROTOCOL_VERSION {
            return Err(ActionEnvelopeError::UnsupportedProtocolVersion(protocol_version));
        }
        let expected_payload = commit(DomainTag::CANONICAL_VALUE, &payload)
            .map_err(ActionEnvelopeError::PayloadEncoding)?;
        if payload_commitment != expected_payload {
            return Err(ActionEnvelopeError::PayloadCommitmentMismatch);
        }
        if !validity.contains(payload.height()) {
            return Err(ActionEnvelopeError::PayloadHeightOutsideValidity);
        }
        let actor_matches = payload
            .commands()
            .iter()
            .all(|command| command.request().actor() == ActorBinding::Principal(sender));
        if !actor_matches {
            return Err(ActionEnvelopeError::SenderActorMismatch);
        }
        if !maximum_resources.fits_within(fee_ticket.permitted_resources()) {
            return Err(ActionEnvelopeError::ResourcesExceedTicket);
        }
        Ok(Self {
            protocol_version,
            chain_id,
            sender,
            fee_ticket,
            nonce_channel,
            sequence,
            validity,
            maximum_resources,
            payload_commitment,
            payload,
            authorization_commitment,
        })
    }

    /// Returns the explicit protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Returns the replay-protection chain identifier.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Returns the public sender bound into every request.
    #[must_use]
    pub const fn sender(&self) -> PrincipalId {
        self.sender
    }

    /// Returns the one-shot fee ticket.
    #[must_use]
    pub const fn fee_ticket(&self) -> FeeTicket {
        self.fee_ticket
    }

    /// Returns the sender-local nonce channel.
    #[must_use]
    pub const fn nonce_channel(&self) -> u16 {
        self.nonce_channel
    }

    /// Returns the exact channel sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns inclusive height validity.
    #[must_use]
    pub const fn validity(&self) -> ValidityInterval {
        self.validity
    }

    /// Returns the per-dimension execution ceiling.
    #[must_use]
    pub const fn maximum_resources(&self) -> ResourceVector {
        self.maximum_resources
    }

    /// Returns the typed transfer payload commitment.
    #[must_use]
    pub const fn payload_commitment(&self) -> Digest384 {
        self.payload_commitment
    }

    /// Borrows the exact typed transfer payload.
    #[must_use]
    pub const fn payload(&self) -> &TransferTransaction {
        &self.payload
    }

    /// Returns the externally verified development evidence commitment.
    #[must_use]
    pub const fn authorization_commitment(&self) -> Digest384 {
        self.authorization_commitment
    }
}

impl CanonicalEncode for ActionEnvelope {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.protocol_version.encode(encoder)?;
        self.chain_id.encode(encoder)?;
        self.sender.encode(encoder)?;
        self.fee_ticket.encode(encoder)?;
        self.nonce_channel.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.validity.encode(encoder)?;
        self.maximum_resources.encode(encoder)?;
        self.payload_commitment.encode(encoder)?;
        self.payload.encode(encoder)?;
        self.authorization_commitment.encode(encoder)
    }
}

impl CanonicalDecode for ActionEnvelope {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            u16::decode(decoder)?,
            ChainId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            FeeTicket::decode(decoder)?,
            u16::decode(decoder)?,
            u64::decode(decoder)?,
            ValidityInterval::decode(decoder)?,
            ResourceVector::decode(decoder)?,
            Digest384::decode(decoder)?,
            TransferTransaction::decode(decoder)?,
            Digest384::decode(decoder)?,
        )
        .map_err(action_envelope_decode_error)
    }
}

impl CanonicalType for ActionEnvelope {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Action-envelope construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionEnvelopeError {
    /// Only public development version 1 is registered.
    UnsupportedProtocolVersion(u16),
    /// The typed payload could not be canonically committed.
    PayloadEncoding(EncodeError),
    /// The supplied commitment does not open the embedded payload.
    PayloadCommitmentMismatch,
    /// The transfer height lies outside the envelope interval.
    PayloadHeightOutsideValidity,
    /// A command request is private or names another public actor.
    SenderActorMismatch,
    /// The envelope ceiling exceeds one ticket dimension.
    ResourcesExceedTicket,
}

/// Derives the complete canonical public action identifier.
pub fn action_id(envelope: &ActionEnvelope) -> Result<TransactionId, EncodeError> {
    commit(DomainTag::ACTION_ID, envelope).map(TransactionId::new)
}

fn action_envelope_decode_error(error: ActionEnvelopeError) -> DecodeError {
    match error {
        ActionEnvelopeError::UnsupportedProtocolVersion(_) => {
            DecodeError::InvalidValue("action envelope uses an unsupported protocol version")
        }
        ActionEnvelopeError::PayloadEncoding(_) => {
            DecodeError::InvalidValue("action payload cannot be canonically committed")
        }
        ActionEnvelopeError::PayloadCommitmentMismatch => {
            DecodeError::InvalidValue("action payload commitment does not match")
        }
        ActionEnvelopeError::PayloadHeightOutsideValidity => {
            DecodeError::InvalidValue("action payload height is outside validity")
        }
        ActionEnvelopeError::SenderActorMismatch => {
            DecodeError::InvalidValue("action sender does not bind every request actor")
        }
        ActionEnvelopeError::ResourcesExceedTicket => {
            DecodeError::InvalidValue("action resources exceed its fee ticket")
        }
    }
}
