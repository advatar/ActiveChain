#![no_std]
#![forbid(unsafe_code)]

//! Pure P-010/P-040 single-node block application over explicit bounded state.

extern crate alloc;

mod apply;
mod types;

pub use apply::{BlockApplyError, BlockOutput, apply_block};
pub use types::{
    ActionOutcome, ActionReceipt, BlockReceipt, BlockReceiptError, ChainState, ChainStateError,
    DevnetBlock, DevnetBlockError, MAX_BLOCK_ACTIONS, MAX_NONCE_CHANNELS, MAX_USED_FEE_TICKETS,
};

#[cfg(test)]
mod tests;
