//! Pure deterministic development-block application.

use alloc::vec::Vec;

use activechain_action_kernel::{NonceAdvanceError, ResourceVector, action_id};
use activechain_canonical_codec::{EncodeError, encode_envelope};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{Digest384, ObjectId, PrincipalId};
use activechain_state_tree::{StateTreeError, commit_objects};
use activechain_transition::{TransitionError, apply_transfer_transaction};

use crate::types::nonce_key_order;
use crate::{
    ActionOutcome, ActionReceipt, BlockReceipt, BlockReceiptError, ChainState, ChainStateError,
    DevnetBlock, MAX_USED_FEE_TICKETS,
};

/// Applies one canonical development block without mutating its input state.
pub fn apply_block(
    state: &ChainState,
    block: &DevnetBlock,
) -> Result<BlockOutput, BlockApplyError> {
    if block.chain_id() != state.chain_id() {
        return Err(BlockApplyError::WrongChain);
    }
    let expected_height = state.height().checked_add(1).ok_or(BlockApplyError::HeightExhausted)?;
    if block.height() != expected_height {
        return Err(BlockApplyError::UnexpectedHeight {
            expected: expected_height,
            actual: block.height(),
        });
    }
    if block.parent_block_id() != state.head_block_id() {
        return Err(BlockApplyError::WrongParent);
    }
    let actual_pre_state =
        commit_objects(state.objects().objects()).map_err(BlockApplyError::StateTree)?;
    if block.pre_state() != actual_pre_state {
        return Err(BlockApplyError::PreStateMismatch);
    }

    let block_id =
        commit(DomainTag::BLOCK_ID, block).map_err(BlockApplyError::CommitmentEncoding)?;
    let mut action_ids = Vec::with_capacity(block.actions().len());
    for (index, action) in block.actions().iter().enumerate() {
        let id = action_id(action).map_err(BlockApplyError::CommitmentEncoding)?;
        if let Some(previous) = action_ids.last()
            && *previous >= id
        {
            return Err(BlockApplyError::ActionsNotStrictlyIncreasing { index });
        }
        action_ids.push(id);
    }

    let mut objects = state.objects().clone();
    let mut nonce_channels = Vec::from(state.nonce_channels());
    let mut used_fee_tickets = Vec::from(state.used_fee_tickets());
    let mut action_receipts = Vec::with_capacity(block.actions().len());

    for (index, (action, transaction_id)) in block.actions().iter().zip(action_ids).enumerate() {
        if action.chain_id() != state.chain_id() {
            return Err(BlockApplyError::ActionWrongChain { index });
        }
        if !action.validity().contains(block.height()) {
            return Err(BlockApplyError::ActionOutsideValidity { index });
        }
        if action.payload().height() != block.height() {
            return Err(BlockApplyError::PayloadHeightMismatch { index });
        }
        let ticket = action.fee_ticket();
        if ticket.valid_until() < block.height() {
            return Err(BlockApplyError::FeeTicketExpired { index });
        }
        let maximum_charge = action
            .maximum_resources()
            .checked_charge(state.resource_prices())
            .ok_or(BlockApplyError::ResourceChargeOverflow { index })?;
        if maximum_charge > ticket.reserved_amount() {
            return Err(BlockApplyError::InsufficientFeeReservation { index });
        }

        insert_used_ticket(&mut used_fee_tickets, ticket.ticket_id(), index)?;
        let channel_index =
            find_nonce_channel(&nonce_channels, action.sender(), action.nonce_channel())
                .ok_or(BlockApplyError::MissingNonceChannel { index })?;
        nonce_channels[channel_index] = nonce_channels[channel_index]
            .advance(action.sequence())
            .map_err(|error| BlockApplyError::Nonce { index, error })?;

        let encoded_length =
            encode_envelope(action).map_err(BlockApplyError::EnvelopeEncoding)?.len();
        let encoded_bytes = u64::try_from(encoded_length)
            .map_err(|_| BlockApplyError::ResourceCountOverflow { index })?;
        let object_accesses = u64::try_from(action.payload().commands().len())
            .map_err(|_| BlockApplyError::ResourceCountOverflow { index })?;
        let transition = apply_transfer_transaction(&objects, action.payload())
            .map_err(BlockApplyError::Transition)?;
        let resources_used = ResourceVector::new(
            u64::from(transition.receipt().policy_steps()),
            object_accesses,
            object_accesses,
            0,
            0,
            encoded_bytes,
        );

        let (outcome, fee_charged) = if resources_used.fits_within(action.maximum_resources()) {
            objects = transition.state().clone();
            let charge = resources_used
                .checked_charge(state.resource_prices())
                .ok_or(BlockApplyError::ResourceChargeOverflow { index })?;
            (ActionOutcome::Transition(transition.receipt()), charge)
        } else {
            (ActionOutcome::ResourceLimitExceeded, maximum_charge)
        };
        let post_state = commit_objects(objects.objects()).map_err(BlockApplyError::StateTree)?;
        action_receipts.push(ActionReceipt::new(
            transaction_id,
            outcome,
            resources_used,
            fee_charged,
            action.sequence(),
            post_state,
        ));
    }

    let post_state = commit_objects(objects.objects()).map_err(BlockApplyError::StateTree)?;
    let receipt =
        BlockReceipt::new(block_id, block.height(), actual_pre_state, post_state, action_receipts)
            .map_err(BlockApplyError::InvalidBlockReceipt)?;
    let receipt_root = commit(DomainTag::CANONICAL_VALUE, &receipt)
        .map_err(BlockApplyError::CommitmentEncoding)?;
    let next_state = ChainState::new(
        state.chain_id(),
        block.height(),
        block_id,
        objects,
        nonce_channels,
        used_fee_tickets,
        state.resource_prices(),
    )
    .map_err(BlockApplyError::InvalidChainState)?;
    Ok(BlockOutput { state: next_state, receipt, receipt_root })
}

fn find_nonce_channel(
    channels: &[activechain_action_kernel::NonceChannel],
    sender: PrincipalId,
    channel: u16,
) -> Option<usize> {
    let key = activechain_action_kernel::NonceChannel::new(sender, channel, 0);
    channels.binary_search_by(|candidate| nonce_key_order(candidate, &key)).ok()
}

fn insert_used_ticket(
    tickets: &mut Vec<ObjectId>,
    ticket: ObjectId,
    index: usize,
) -> Result<(), BlockApplyError> {
    match tickets.binary_search(&ticket) {
        Ok(_) => Err(BlockApplyError::FeeTicketAlreadyUsed { index }),
        Err(position) => {
            if tickets.len() >= MAX_USED_FEE_TICKETS {
                return Err(BlockApplyError::UsedFeeTicketCapacityExhausted { index });
            }
            tickets.insert(position, ticket);
            Ok(())
        }
    }
}

/// Complete pure block-application output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockOutput {
    state: ChainState,
    receipt: BlockReceipt,
    receipt_root: Digest384,
}

impl BlockOutput {
    /// Borrows the atomically published chain state.
    #[must_use]
    pub const fn state(&self) -> &ChainState {
        &self.state
    }

    /// Borrows the canonical ordered block receipt.
    #[must_use]
    pub const fn receipt(&self) -> &BlockReceipt {
        &self.receipt
    }

    /// Returns the canonical-value commitment to the block receipt.
    #[must_use]
    pub const fn receipt_root(&self) -> Digest384 {
        self.receipt_root
    }
}

/// Errors before an atomic development block can be published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockApplyError {
    /// The block targets another chain.
    WrongChain,
    /// The current height cannot advance without wrapping.
    HeightExhausted,
    /// The block is not the exact next height.
    UnexpectedHeight { expected: u64, actual: u64 },
    /// The block does not extend the current head.
    WrongParent,
    /// The claimed pre-state does not match current objects.
    PreStateMismatch,
    /// An action identifier is duplicated or out of order.
    ActionsNotStrictlyIncreasing { index: usize },
    /// One nested action targets another chain.
    ActionWrongChain { index: usize },
    /// The block height is outside one action interval.
    ActionOutsideValidity { index: usize },
    /// The typed transfer height does not equal the block height.
    PayloadHeightMismatch { index: usize },
    /// A one-shot fee ticket has expired.
    FeeTicketExpired { index: usize },
    /// The same fee-ticket identifier was already consumed.
    FeeTicketAlreadyUsed { index: usize },
    /// The bounded development ticket history is full.
    UsedFeeTicketCapacityExhausted { index: usize },
    /// The chain has no declared channel for this sender and number.
    MissingNonceChannel { index: usize },
    /// Exact sequence advancement failed.
    Nonce { index: usize, error: NonceAdvanceError },
    /// The declared maximum charge does not fit the ticket reservation.
    InsufficientFeeReservation { index: usize },
    /// A resource count did not fit its canonical field.
    ResourceCountOverflow { index: usize },
    /// Multidimensional price arithmetic overflowed.
    ResourceChargeOverflow { index: usize },
    /// A canonical envelope did not encode for byte accounting.
    EnvelopeEncoding(EncodeError),
    /// A canonical value did not encode for its commitment.
    CommitmentEncoding(EncodeError),
    /// State-tree commitment failed.
    StateTree(StateTreeError),
    /// The underlying total transfer kernel hit an implementation invariant.
    Transition(TransitionError),
    /// Generated receipt bounds were inconsistent.
    InvalidBlockReceipt(BlockReceiptError),
    /// Generated explicit chain state violated its bounds or ordering.
    InvalidChainState(ChainStateError),
}
