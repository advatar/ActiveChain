//! Canonical block/receipt values and explicit development chain state.

use alloc::vec::Vec;
use core::cmp::Ordering;

use activechain_action_kernel::{ActionEnvelope, NonceChannel, ResourcePrices, ResourceVector};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{Amount, ChainId, Digest384, Height, ObjectId, TransactionId};
use activechain_state_tree::StateCommitment;
use activechain_transition::{ObjectState, TransitionReceipt};

/// Maximum canonically ordered actions in one development block.
pub const MAX_BLOCK_ACTIONS: usize = 32;
/// Maximum sender nonce channels in the explicit development chain state.
pub const MAX_NONCE_CHANNELS: usize = 64;
/// Maximum one-shot tickets retained by the bounded development chain.
pub const MAX_USED_FEE_TICKETS: usize = 256;

/// Canonical single-node block proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevnetBlock {
    chain_id: ChainId,
    height: Height,
    parent_block_id: Digest384,
    pre_state: StateCommitment,
    actions: Vec<ActionEnvelope>,
}

impl DevnetBlock {
    /// Registered development-block type tag.
    pub const TYPE_TAG: u16 = 0x0073;
    /// Initial development-block schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Worst-case canonical development-block body length.
    pub const MAX_ENCODED_LEN: usize = 40_505_057;

    /// Enforces the block action-count bound. Ordering is commitment-dependent and checked later.
    pub fn new(
        chain_id: ChainId,
        height: Height,
        parent_block_id: Digest384,
        pre_state: StateCommitment,
        actions: Vec<ActionEnvelope>,
    ) -> Result<Self, DevnetBlockError> {
        if actions.len() > MAX_BLOCK_ACTIONS {
            return Err(DevnetBlockError::TooManyActions {
                actual: actions.len(),
                maximum: MAX_BLOCK_ACTIONS,
            });
        }
        Ok(Self { chain_id, height, parent_block_id, pre_state, actions })
    }

    /// Returns the chain identifier.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Returns the proposed block height.
    #[must_use]
    pub const fn height(&self) -> Height {
        self.height
    }

    /// Returns the required current head identifier.
    #[must_use]
    pub const fn parent_block_id(&self) -> Digest384 {
        self.parent_block_id
    }

    /// Returns the required current state-tree commitment.
    #[must_use]
    pub const fn pre_state(&self) -> StateCommitment {
        self.pre_state
    }

    /// Borrows actions in claimed canonical order.
    #[must_use]
    pub fn actions(&self) -> &[ActionEnvelope] {
        &self.actions
    }
}

impl CanonicalEncode for DevnetBlock {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(encoder)?;
        self.height.encode(encoder)?;
        self.parent_block_id.encode(encoder)?;
        self.pre_state.encode(encoder)?;
        encoder.write_length(self.actions.len(), MAX_BLOCK_ACTIONS)?;
        for action in &self.actions {
            action.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for DevnetBlock {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(decoder)?;
        let height = u64::decode(decoder)?;
        let parent_block_id = Digest384::decode(decoder)?;
        let pre_state = StateCommitment::decode(decoder)?;
        let action_count = decoder.read_length(MAX_BLOCK_ACTIONS)?;
        let mut actions = Vec::with_capacity(action_count);
        for _ in 0..action_count {
            actions.push(ActionEnvelope::decode(decoder)?);
        }
        Self::new(chain_id, height, parent_block_id, pre_state, actions)
            .map_err(|_| DecodeError::InvalidValue("development block exceeds its action bound"))
    }
}

impl CanonicalType for DevnetBlock {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Development-block construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevnetBlockError {
    /// Too many action envelopes were supplied.
    TooManyActions { actual: usize, maximum: usize },
}

/// Total outcome after an action has consumed replay/fee admission state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionOutcome {
    /// P-030 returned its canonical success or semantic-failure receipt.
    Transition(TransitionReceipt),
    /// Measured work exceeded at least one independent envelope ceiling.
    ResourceLimitExceeded,
}

impl CanonicalEncode for ActionOutcome {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Transition(receipt) => {
                0_u8.encode(encoder)?;
                receipt.encode(encoder)
            }
            Self::ResourceLimitExceeded => 1_u8.encode(encoder),
        }
    }
}

impl CanonicalDecode for ActionOutcome {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Transition(TransitionReceipt::decode(decoder)?)),
            1 => Ok(Self::ResourceLimitExceeded),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ActionOutcome", tag }),
        }
    }
}

/// Canonical receipt for one admitted action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionReceipt {
    transaction_id: TransactionId,
    outcome: ActionOutcome,
    resources_used: ResourceVector,
    fee_charged: Amount,
    sequence: u64,
    post_state: StateCommitment,
}

impl ActionReceipt {
    /// Maximum nested canonical action-receipt length.
    pub const MAX_ENCODED_LEN: usize = 281;

    /// Constructs an already-executed bounded action receipt.
    #[must_use]
    pub const fn new(
        transaction_id: TransactionId,
        outcome: ActionOutcome,
        resources_used: ResourceVector,
        fee_charged: Amount,
        sequence: u64,
        post_state: StateCommitment,
    ) -> Self {
        Self { transaction_id, outcome, resources_used, fee_charged, sequence, post_state }
    }

    /// Returns the complete canonical action identifier.
    #[must_use]
    pub const fn transaction_id(self) -> TransactionId {
        self.transaction_id
    }

    /// Returns the total admitted outcome.
    #[must_use]
    pub const fn outcome(self) -> ActionOutcome {
        self.outcome
    }

    /// Returns measured resource use.
    #[must_use]
    pub const fn resources_used(self) -> ResourceVector {
        self.resources_used
    }

    /// Returns the deterministic recorded charge.
    #[must_use]
    pub const fn fee_charged(self) -> Amount {
        self.fee_charged
    }

    /// Returns the consumed sender-channel sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the object state tree after this admitted action.
    #[must_use]
    pub const fn post_state(self) -> StateCommitment {
        self.post_state
    }
}

impl CanonicalEncode for ActionReceipt {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.transaction_id.encode(encoder)?;
        self.outcome.encode(encoder)?;
        self.resources_used.encode(encoder)?;
        self.fee_charged.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.post_state.encode(encoder)
    }
}

impl CanonicalDecode for ActionReceipt {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(
            TransactionId::decode(decoder)?,
            ActionOutcome::decode(decoder)?,
            ResourceVector::decode(decoder)?,
            u128::decode(decoder)?,
            u64::decode(decoder)?,
            StateCommitment::decode(decoder)?,
        ))
    }
}

/// Canonical ordered receipt set for one finalized development block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockReceipt {
    block_id: Digest384,
    height: Height,
    pre_state: StateCommitment,
    post_state: StateCommitment,
    action_receipts: Vec<ActionReceipt>,
}

impl BlockReceipt {
    /// Registered block-receipt type tag.
    pub const TYPE_TAG: u16 = 0x0074;
    /// Initial block-receipt schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Worst-case canonical block-receipt body length.
    pub const MAX_ENCODED_LEN: usize = 9_161;

    /// Enforces the receipt-count bound.
    pub fn new(
        block_id: Digest384,
        height: Height,
        pre_state: StateCommitment,
        post_state: StateCommitment,
        action_receipts: Vec<ActionReceipt>,
    ) -> Result<Self, BlockReceiptError> {
        if action_receipts.len() > MAX_BLOCK_ACTIONS {
            return Err(BlockReceiptError::TooManyActionReceipts {
                actual: action_receipts.len(),
                maximum: MAX_BLOCK_ACTIONS,
            });
        }
        Ok(Self { block_id, height, pre_state, post_state, action_receipts })
    }

    /// Returns the committed development block identifier.
    #[must_use]
    pub const fn block_id(&self) -> Digest384 {
        self.block_id
    }

    /// Returns the finalized height.
    #[must_use]
    pub const fn height(&self) -> Height {
        self.height
    }

    /// Returns the required input state tree.
    #[must_use]
    pub const fn pre_state(&self) -> StateCommitment {
        self.pre_state
    }

    /// Returns the published output state tree.
    #[must_use]
    pub const fn post_state(&self) -> StateCommitment {
        self.post_state
    }

    /// Borrows receipts in action order.
    #[must_use]
    pub fn action_receipts(&self) -> &[ActionReceipt] {
        &self.action_receipts
    }
}

impl CanonicalEncode for BlockReceipt {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.block_id.encode(encoder)?;
        self.height.encode(encoder)?;
        self.pre_state.encode(encoder)?;
        self.post_state.encode(encoder)?;
        encoder.write_length(self.action_receipts.len(), MAX_BLOCK_ACTIONS)?;
        for receipt in &self.action_receipts {
            receipt.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for BlockReceipt {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let block_id = Digest384::decode(decoder)?;
        let height = u64::decode(decoder)?;
        let pre_state = StateCommitment::decode(decoder)?;
        let post_state = StateCommitment::decode(decoder)?;
        let receipt_count = decoder.read_length(MAX_BLOCK_ACTIONS)?;
        let mut action_receipts = Vec::with_capacity(receipt_count);
        for _ in 0..receipt_count {
            action_receipts.push(ActionReceipt::decode(decoder)?);
        }
        Self::new(block_id, height, pre_state, post_state, action_receipts)
            .map_err(|_| DecodeError::InvalidValue("block receipt exceeds its action bound"))
    }
}

impl CanonicalType for BlockReceipt {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Block-receipt construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockReceiptError {
    /// Too many per-action receipts were supplied.
    TooManyActionReceipts { actual: usize, maximum: usize },
}

/// Explicit bounded single-node chain state outside the canonical block format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainState {
    chain_id: ChainId,
    height: Height,
    head_block_id: Digest384,
    objects: ObjectState,
    nonce_channels: Vec<NonceChannel>,
    used_fee_tickets: Vec<ObjectId>,
    resource_prices: ResourcePrices,
}

impl ChainState {
    /// Constructs genesis at height zero with an all-zero parent identifier.
    pub fn genesis(
        chain_id: ChainId,
        objects: ObjectState,
        nonce_channels: Vec<NonceChannel>,
        resource_prices: ResourcePrices,
    ) -> Result<Self, ChainStateError> {
        Self::new(
            chain_id,
            0,
            Digest384::ZERO,
            objects,
            nonce_channels,
            Vec::new(),
            resource_prices,
        )
    }

    /// Validates all explicit collection bounds and canonical key ordering.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        height: Height,
        head_block_id: Digest384,
        objects: ObjectState,
        nonce_channels: Vec<NonceChannel>,
        used_fee_tickets: Vec<ObjectId>,
        resource_prices: ResourcePrices,
    ) -> Result<Self, ChainStateError> {
        if nonce_channels.len() > MAX_NONCE_CHANNELS {
            return Err(ChainStateError::TooManyNonceChannels {
                actual: nonce_channels.len(),
                maximum: MAX_NONCE_CHANNELS,
            });
        }
        if !nonce_channels.windows(2).all(|pair| nonce_key_order(&pair[0], &pair[1]).is_lt()) {
            return Err(ChainStateError::NonceChannelsNotStrictlyIncreasing);
        }
        if used_fee_tickets.len() > MAX_USED_FEE_TICKETS {
            return Err(ChainStateError::TooManyUsedFeeTickets {
                actual: used_fee_tickets.len(),
                maximum: MAX_USED_FEE_TICKETS,
            });
        }
        if !used_fee_tickets.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ChainStateError::UsedFeeTicketsNotStrictlyIncreasing);
        }
        Ok(Self {
            chain_id,
            height,
            head_block_id,
            objects,
            nonce_channels,
            used_fee_tickets,
            resource_prices,
        })
    }

    /// Returns the configured chain identifier.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Returns the latest finalized height.
    #[must_use]
    pub const fn height(&self) -> Height {
        self.height
    }

    /// Returns the latest finalized block identifier.
    #[must_use]
    pub const fn head_block_id(&self) -> Digest384 {
        self.head_block_id
    }

    /// Borrows current explicit objects.
    #[must_use]
    pub const fn objects(&self) -> &ObjectState {
        &self.objects
    }

    /// Borrows nonce channels in sender/channel order.
    #[must_use]
    pub fn nonce_channels(&self) -> &[NonceChannel] {
        &self.nonce_channels
    }

    /// Borrows consumed ticket identifiers in canonical order.
    #[must_use]
    pub fn used_fee_tickets(&self) -> &[ObjectId] {
        &self.used_fee_tickets
    }

    /// Returns the fixed development price vector.
    #[must_use]
    pub const fn resource_prices(&self) -> ResourcePrices {
        self.resource_prices
    }
}

impl CanonicalEncode for ChainState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(encoder)?;
        self.height.encode(encoder)?;
        self.head_block_id.encode(encoder)?;
        self.objects.encode(encoder)?;
        encoder.write_length(self.nonce_channels.len(), MAX_NONCE_CHANNELS)?;
        for channel in &self.nonce_channels {
            channel.encode(encoder)?;
        }
        encoder.write_length(self.used_fee_tickets.len(), MAX_USED_FEE_TICKETS)?;
        for ticket in &self.used_fee_tickets {
            ticket.encode(encoder)?;
        }
        self.resource_prices.encode(encoder)
    }
}

impl CanonicalDecode for ChainState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(decoder)?;
        let height = u64::decode(decoder)?;
        let head_block_id = Digest384::decode(decoder)?;
        let objects = ObjectState::decode(decoder)?;
        let channel_count = decoder.read_length(MAX_NONCE_CHANNELS)?;
        let mut channels = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            channels.push(NonceChannel::decode(decoder)?);
        }
        let ticket_count = decoder.read_length(MAX_USED_FEE_TICKETS)?;
        let mut tickets = Vec::with_capacity(ticket_count);
        for _ in 0..ticket_count {
            tickets.push(ObjectId::decode(decoder)?);
        }
        Self::new(
            chain_id,
            height,
            head_block_id,
            objects,
            channels,
            tickets,
            ResourcePrices::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid durable chain state"))
    }
}

impl CanonicalType for ChainState {
    const TYPE_TAG: u16 = 0x007b;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48
        + 8
        + 48
        + ObjectState::MAX_ENCODED_LEN
        + 2
        + MAX_NONCE_CHANNELS * NonceChannel::ENCODED_LENGTH
        + 2
        + MAX_USED_FEE_TICKETS * 48
        + ResourcePrices::ENCODED_LENGTH;
}

pub(crate) fn nonce_key_order(left: &NonceChannel, right: &NonceChannel) -> Ordering {
    left.sender().cmp(&right.sender()).then_with(|| left.channel().cmp(&right.channel()))
}

/// Explicit chain-state construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainStateError {
    /// Too many replay-protection channels were supplied.
    TooManyNonceChannels { actual: usize, maximum: usize },
    /// Channel keys are duplicated or not in sender/channel order.
    NonceChannelsNotStrictlyIncreasing,
    /// The bounded development ticket history is full.
    TooManyUsedFeeTickets { actual: usize, maximum: usize },
    /// Ticket identifiers are duplicated or not ordered.
    UsedFeeTicketsNotStrictlyIncreasing,
}
