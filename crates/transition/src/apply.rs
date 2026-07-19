//! Atomic scratch-state execution for transfer transactions.

use alloc::vec::Vec;

use activechain_canonical_codec::EncodeError;
use activechain_object::{ObjectTransitionError, transfer_object};
use activechain_policy_kernel::{DecisionResult, evaluate};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{Object, ObjectValidationError};

use crate::{
    ObjectState, ObjectStateError, ReceiptResult, TRANSFER_OBJECT_ACTION_ID, TransferTransaction,
    TransitionReceipt, TransitionReceiptError,
};

/// Published state and its canonical total receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionOutput {
    state: ObjectState,
    receipt: TransitionReceipt,
}

impl TransitionOutput {
    /// Borrows the atomically published state.
    #[must_use]
    pub const fn state(&self) -> &ObjectState {
        &self.state
    }

    /// Returns the canonical transition receipt.
    #[must_use]
    pub const fn receipt(&self) -> TransitionReceipt {
        self.receipt
    }
}

/// Executes every command against scratch state and publishes all or none.
pub fn apply_transfer_transaction(
    pre_state: &ObjectState,
    transaction: &TransferTransaction,
) -> Result<TransitionOutput, TransitionError> {
    let pre_state_commitment = commit(DomainTag::CANONICAL_VALUE, pre_state)
        .map_err(TransitionError::CommitmentEncoding)?;
    let mut scratch = Vec::from(pre_state.objects());
    let mut policy_steps = 0_u32;

    for (command_index, command) in transaction.commands().iter().enumerate() {
        let failed_index =
            u8::try_from(command_index).map_err(|_| TransitionError::InvalidCommandIndex)?;
        let request = command.request();
        if request.height() != transaction.height()
            || request.action() != TRANSFER_OBJECT_ACTION_ID
            || request.resource() != command.input().object_id()
        {
            return failure_output(
                pre_state,
                pre_state_commitment,
                ReceiptResult::RequestContextMismatch,
                failed_index,
                policy_steps,
            );
        }
        if !transaction.access_manifest().permits_exact_write(command.input()) {
            return failure_output(
                pre_state,
                pre_state_commitment,
                ReceiptResult::AccessManifestViolation,
                failed_index,
                policy_steps,
            );
        }

        let Some(object_index) =
            scratch.binary_search_by_key(&command.input().object_id(), Object::object_id).ok()
        else {
            return failure_output(
                pre_state,
                pre_state_commitment,
                ReceiptResult::ObjectNotFound,
                failed_index,
                policy_steps,
            );
        };
        let object = &scratch[object_index];
        if object.object_version() != command.input().version() {
            return failure_output(
                pre_state,
                pre_state_commitment,
                ReceiptResult::StaleObjectVersion,
                failed_index,
                policy_steps,
            );
        }

        let policy_commitment = commit(DomainTag::CANONICAL_VALUE, command.control_policy())
            .map_err(TransitionError::CommitmentEncoding)?;
        if policy_commitment != object.control_policy_hash() {
            return failure_output(
                pre_state,
                pre_state_commitment,
                ReceiptResult::ControlPolicyMismatch,
                failed_index,
                policy_steps,
            );
        }

        let decision = evaluate(command.control_policy(), request);
        policy_steps = policy_steps
            .checked_add(u32::from(decision.steps_used()))
            .ok_or(TransitionError::PolicyStepOverflow)?;
        if decision.result() != DecisionResult::Permit {
            return failure_output(
                pre_state,
                pre_state_commitment,
                ReceiptResult::AuthorizationDenied,
                failed_index,
                policy_steps,
            );
        }
        if !decision.obligations().is_empty() {
            return failure_output(
                pre_state,
                pre_state_commitment,
                ReceiptResult::UnsupportedObligation,
                failed_index,
                policy_steps,
            );
        }

        match transfer_object(object, command.input(), command.new_owner()) {
            Ok(updated) => scratch[object_index] = updated,
            Err(ObjectTransitionError::ObjectIdMismatch) => {
                return Err(TransitionError::ObjectIdInvariant);
            }
            Err(ObjectTransitionError::StaleObjectVersion { .. }) => {
                return failure_output(
                    pre_state,
                    pre_state_commitment,
                    ReceiptResult::StaleObjectVersion,
                    failed_index,
                    policy_steps,
                );
            }
            Err(ObjectTransitionError::ImmutableObject) => {
                return failure_output(
                    pre_state,
                    pre_state_commitment,
                    ReceiptResult::ImmutableObject,
                    failed_index,
                    policy_steps,
                );
            }
            Err(ObjectTransitionError::TransferDisabled) => {
                return failure_output(
                    pre_state,
                    pre_state_commitment,
                    ReceiptResult::TransferDisabled,
                    failed_index,
                    policy_steps,
                );
            }
            Err(ObjectTransitionError::OwnerUnchanged) => {
                return failure_output(
                    pre_state,
                    pre_state_commitment,
                    ReceiptResult::OwnerUnchanged,
                    failed_index,
                    policy_steps,
                );
            }
            Err(ObjectTransitionError::VersionExhausted) => {
                return failure_output(
                    pre_state,
                    pre_state_commitment,
                    ReceiptResult::VersionExhausted,
                    failed_index,
                    policy_steps,
                );
            }
            Err(ObjectTransitionError::InvalidResult(error)) => {
                return Err(TransitionError::InvalidObjectResult(error));
            }
        }
    }

    let state = ObjectState::new(scratch).map_err(TransitionError::InvalidScratchState)?;
    let post_state_commitment =
        commit(DomainTag::CANONICAL_VALUE, &state).map_err(TransitionError::CommitmentEncoding)?;
    let objects_updated = u8::try_from(transaction.commands().len())
        .map_err(|_| TransitionError::InvalidCommandIndex)?;
    let receipt = TransitionReceipt::new(
        ReceiptResult::Success,
        None,
        objects_updated,
        policy_steps,
        pre_state_commitment,
        post_state_commitment,
    )
    .map_err(TransitionError::InvalidReceipt)?;
    Ok(TransitionOutput { state, receipt })
}

fn failure_output(
    pre_state: &ObjectState,
    pre_state_commitment: activechain_protocol_types::Digest384,
    result: ReceiptResult,
    failed_command: u8,
    policy_steps: u32,
) -> Result<TransitionOutput, TransitionError> {
    let receipt = TransitionReceipt::new(
        result,
        Some(failed_command),
        0,
        policy_steps,
        pre_state_commitment,
        pre_state_commitment,
    )
    .map_err(TransitionError::InvalidReceipt)?;
    Ok(TransitionOutput { state: pre_state.clone(), receipt })
}

/// Failures outside the total semantic receipt domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
    /// A structurally bounded canonical value did not encode for commitment.
    CommitmentEncoding(EncodeError),
    /// A command index did not fit the protocol's bounded representation.
    InvalidCommandIndex,
    /// Accumulated policy work overflowed despite structural bounds.
    PolicyStepOverflow,
    /// Scratch state lost canonical order or exceeded its bound.
    InvalidScratchState(ObjectStateError),
    /// A reconstructed object violated its canonical schema.
    InvalidObjectResult(ObjectValidationError),
    /// Lookup and transfer disagreed about object identity.
    ObjectIdInvariant,
    /// The generated receipt contradicted transition invariants.
    InvalidReceipt(TransitionReceiptError),
}
