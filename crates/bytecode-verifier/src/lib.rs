#![no_std]
#![forbid(unsafe_code)]

//! P-050's bounded typed bytecode and consensus security verifier.

extern crate alloc;

mod bytecode;
mod verify;

pub use bytecode::{
    MAX_VM_EVENTS, MAX_VM_INPUTS, MAX_VM_INSTRUCTIONS, MAX_VM_OUTPUTS, MAX_VM_REGISTERS,
    VmInstruction, VmProgram, VmProgramValidationError, VmValueType,
};
pub use verify::{VerifiedProgram, VmVerificationError, verify};

#[cfg(test)]
mod tests;
