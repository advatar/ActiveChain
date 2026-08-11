//! Pure deterministic development-block application.

use alloc::vec::Vec;

use activechain_action_kernel::{ActionPayloadV2, NonceAdvanceError, ResourceVector, action_id};
use activechain_application_primitives::{AnchorStateRecordV1, anchor_state_object};
use activechain_canonical_codec::{EncodeError, encode_envelope};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{Digest384, PrincipalId};
use activechain_state_tree::{StateTreeError, commit_objects};
use activechain_transition::{TransitionError, apply_transfer_transaction};

use crate::types::{FeeAccountConsumeError, nonce_key_order};
use crate::{
    ActionOutcome, ActionReceipt, BlockReceipt, BlockReceiptError, ChainState, ChainStateError,
    DevnetBlock, FEE_TICKET_ADMISSION_CHARGE, MAX_FEE_TICKET_LIFETIME, MAX_USED_FEE_TICKETS,
    UsedFeeTicket,
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
    let actual_pre_chain_state = state.commitment().map_err(BlockApplyError::CommitmentEncoding)?;
    if block.pre_chain_state() != actual_pre_chain_state {
        return Err(BlockApplyError::PreChainStateMismatch);
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
    let mut asset_ledger = state.asset_ledger().clone();
    let mut nonce_channels = Vec::from(state.nonce_channels());
    let mut fee_accounts = Vec::from(state.fee_accounts());
    let mut used_fee_tickets = Vec::from(state.used_fee_tickets());
    used_fee_tickets.retain(|ticket| ticket.expires_at() >= block.height());
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
        if ticket.payer() != action.sender() {
            return Err(BlockApplyError::FeePayerDoesNotMatchSender { index });
        }
        if ticket.valid_until() != action.validity().valid_until()
            || ticket.valid_until().saturating_sub(action.validity().valid_from())
                > MAX_FEE_TICKET_LIFETIME
        {
            return Err(BlockApplyError::FeeTicketValidityTooLong { index });
        }
        let maximum_charge = action
            .maximum_resources()
            .checked_charge(state.resource_prices())
            .ok_or(BlockApplyError::ResourceChargeOverflow { index })?;
        let maximum_backed_charge = maximum_charge
            .checked_add(FEE_TICKET_ADMISSION_CHARGE)
            .ok_or(BlockApplyError::ResourceChargeOverflow { index })?;
        if maximum_backed_charge > ticket.reserved_amount() {
            return Err(BlockApplyError::InsufficientFeeReservation { index });
        }
        let fee_account_index = fee_accounts
            .binary_search_by_key(&ticket.payer(), |account| account.payer())
            .map_err(|_| BlockApplyError::MissingFeeAccount { index })?;
        let account = fee_accounts[fee_account_index];
        if ticket.nonce() < account.next_nonce() {
            return Err(BlockApplyError::FeeTicketNonceReplay {
                index,
                supplied: ticket.nonce(),
                expected: account.next_nonce(),
            });
        }
        if ticket.nonce() > account.next_nonce() {
            return Err(BlockApplyError::FeeTicketNonceGap {
                index,
                supplied: ticket.nonce(),
                expected: account.next_nonce(),
            });
        }
        if account.balance() < ticket.reserved_amount() {
            return Err(BlockApplyError::InsufficientFeeBalance { index });
        }

        insert_used_ticket(
            &mut used_fee_tickets,
            UsedFeeTicket::new(ticket.ticket_id(), ticket.valid_until()),
            index,
        )?;
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
        let object_accesses = u64::try_from(action.payload().object_accesses())
            .map_err(|_| BlockApplyError::ResourceCountOverflow { index })?;
        let candidate = match action.payload() {
            ActionPayloadV2::Transfer(transfer) => {
                let transition = apply_transfer_transaction(&objects, transfer)
                    .map_err(BlockApplyError::Transition)?;
                (
                    Some(transition.state().clone()),
                    None,
                    ActionOutcome::Transition(transition.receipt()),
                    u64::from(transition.receipt().policy_steps()),
                )
            }
            ActionPayloadV2::SubmitAnchor { statement, .. } => {
                let reference = statement
                    .submission_reference()
                    .map_err(|_| BlockApplyError::InvalidAnchorStatement { index })?;
                let record = AnchorStateRecordV1::new(
                    statement.clone(),
                    transaction_id,
                    block.height(),
                    block_id,
                )
                .map_err(|_| BlockApplyError::InvalidAnchorState { index })?;
                let object = anchor_state_object(&record)
                    .map_err(|_| BlockApplyError::InvalidAnchorState { index })?;
                let next = insert_anchor_object(&objects, object, index)?;
                (Some(next), None, ActionOutcome::AnchorSubmitted { reference }, 1)
            }
            payload => {
                let pre = commit(DomainTag::CANONICAL_VALUE, &asset_ledger)
                    .map_err(BlockApplyError::CommitmentEncoding)?;
                let next = asset_ledger
                    .apply(payload, block.height())
                    .map_err(BlockApplyError::AssetTransition)?;
                let post = commit(DomainTag::CANONICAL_VALUE, &next)
                    .map_err(BlockApplyError::CommitmentEncoding)?;
                (
                    None,
                    Some(next),
                    ActionOutcome::AssetTransition { pre_ledger: pre, post_ledger: post },
                    1,
                )
            }
        };
        let resources_used =
            ResourceVector::new(candidate.3, object_accesses, object_accesses, 0, 0, encoded_bytes);

        let (outcome, resource_charge) = if resources_used.fits_within(action.maximum_resources()) {
            if let Some(next) = candidate.0 {
                objects = next;
            }
            if let Some(next) = candidate.1 {
                asset_ledger = next;
            }
            let charge = resources_used
                .checked_charge(state.resource_prices())
                .ok_or(BlockApplyError::ResourceChargeOverflow { index })?;
            (candidate.2, charge)
        } else {
            (ActionOutcome::ResourceLimitExceeded, maximum_charge)
        };
        let fee_charged = resource_charge
            .checked_add(FEE_TICKET_ADMISSION_CHARGE)
            .ok_or(BlockApplyError::ResourceChargeOverflow { index })?;
        fee_accounts[fee_account_index].consume(fee_charged).map_err(|error| match error {
            FeeAccountConsumeError::InsufficientBalance => {
                BlockApplyError::InsufficientFeeBalance { index }
            }
            FeeAccountConsumeError::NonceExhausted => {
                BlockApplyError::FeeTicketNonceExhausted { index }
            }
        })?;
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
    let next_state = ChainState::new_with_asset_ledger(
        state.chain_id(),
        block.height(),
        block_id,
        objects,
        nonce_channels,
        fee_accounts,
        used_fee_tickets,
        state.resource_prices(),
        asset_ledger,
    )
    .map_err(BlockApplyError::InvalidChainState)?;
    let post_chain_state = next_state.commitment().map_err(BlockApplyError::CommitmentEncoding)?;
    let receipt = BlockReceipt::new(
        block_id,
        block.height(),
        actual_pre_state,
        post_state,
        actual_pre_chain_state,
        post_chain_state,
        action_receipts,
    )
    .map_err(BlockApplyError::InvalidBlockReceipt)?;
    let receipt_root = commit(DomainTag::CANONICAL_VALUE, &receipt)
        .map_err(BlockApplyError::CommitmentEncoding)?;
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
    tickets: &mut Vec<UsedFeeTicket>,
    ticket: UsedFeeTicket,
    index: usize,
) -> Result<(), BlockApplyError> {
    match tickets.binary_search_by_key(&ticket.ticket_id(), |candidate| candidate.ticket_id()) {
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

fn insert_anchor_object(
    state: &activechain_transition::ObjectState,
    object: activechain_protocol_types::Object,
    index: usize,
) -> Result<activechain_transition::ObjectState, BlockApplyError> {
    let mut objects = state.objects().to_vec();
    match objects
        .binary_search_by_key(&object.object_id(), activechain_protocol_types::Object::object_id)
    {
        Ok(_) => Err(BlockApplyError::AnchorAlreadySubmitted { index }),
        Err(position) => {
            objects.insert(position, object);
            activechain_transition::ObjectState::new(objects)
                .map_err(|_| BlockApplyError::AnchorStateCapacity { index })
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
    /// The claimed full pre-state does not match durable admission and object state.
    PreChainStateMismatch,
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
    /// A development ticket may only debit its authenticated sender's account.
    FeePayerDoesNotMatchSender { index: usize },
    /// Ticket validity is not identical to the action or exceeds the replay window.
    FeeTicketValidityTooLong { index: usize },
    /// No durable funded account exists for the declared payer.
    MissingFeeAccount { index: usize },
    /// The ticket nonce was already consumed.
    FeeTicketNonceReplay { index: usize, supplied: u64, expected: u64 },
    /// The ticket skips one or more payer nonces.
    FeeTicketNonceGap { index: usize, supplied: u64, expected: u64 },
    /// The payer cannot cover the ticket's complete declared reservation.
    InsufficientFeeBalance { index: usize },
    /// The payer nonce cannot advance without wrapping.
    FeeTicketNonceExhausted { index: usize },
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
    /// A native anchor payload did not produce its canonical statement reference.
    InvalidAnchorStatement { index: usize },
    /// A native anchor payload could not produce its canonical immutable state record.
    InvalidAnchorState { index: usize },
    /// The exact anchor reference already has an immutable consensus record.
    AnchorAlreadySubmitted { index: usize },
    /// The bounded development object state cannot admit another anchor record.
    AnchorStateCapacity { index: usize },
    /// An issuer operation did not match the exact consensus asset pre-state.
    AssetTransition(activechain_cash_kernel::NativeMoneyError),
    /// Generated receipt bounds were inconsistent.
    InvalidBlockReceipt(BlockReceiptError),
    /// Generated explicit chain state violated its bounds or ordering.
    InvalidChainState(ChainStateError),
}
