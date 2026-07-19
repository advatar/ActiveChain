#![no_std]
#![forbid(unsafe_code)]

//! P-050's deterministic, metered ObjectVM reference interpreter.

extern crate alloc;

mod execute;
mod value;

pub use execute::{VmExecutionError, execute};
pub use value::{VmEventValue, VmExecutionResult, VmExecutionResultError, VmValue};

#[cfg(test)]
mod tests;
