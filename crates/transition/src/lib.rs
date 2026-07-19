#![no_std]
#![forbid(unsafe_code)]

//! P-030's bounded, atomic object-transfer reference transition.

extern crate alloc;

mod apply;
mod types;

pub use apply::{TransitionError, TransitionOutput, apply_transfer_transaction};
pub use types::{
    MAX_OBJECT_STATE_OBJECTS, MAX_TRANSACTION_POLICY_STEPS, MAX_TRANSFER_COMMANDS, ObjectState,
    ObjectStateError, ReceiptResult, TRANSFER_OBJECT_ACTION_ID, TransferCommand,
    TransferTransaction, TransferTransactionError, TransitionReceipt, TransitionReceiptError,
};

#[cfg(test)]
mod tests;
