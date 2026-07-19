#![no_std]
#![forbid(unsafe_code)]

//! P-040 public action envelopes, fee tickets, resources, and replay protection.

extern crate alloc;

mod types;

pub use types::{
    ACTION_PROTOCOL_VERSION, ActionEnvelope, ActionEnvelopeError, FeeTicket, FeeTicketError,
    NonceAdvanceError, NonceChannel, ResourcePrices, ResourceVector, ValidityInterval,
    ValidityIntervalError, action_id,
};

#[cfg(test)]
mod tests;
