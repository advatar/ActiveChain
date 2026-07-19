//! Deterministic prepaid-gas interpretation of verified bytecode.

use alloc::vec;
use alloc::vec::Vec;

use activechain_bytecode_verifier::{VerifiedProgram, VmInstruction, VmValueType};

use crate::{VmEventValue, VmExecutionResult, VmExecutionResultError, VmValue};

/// Executes one verified program with exact explicit inputs and a gas limit.
pub fn execute(
    verified: &VerifiedProgram,
    inputs: Vec<VmValue>,
    gas_limit: u64,
) -> Result<VmExecutionResult, VmExecutionError> {
    let program = verified.program();
    let expected_inputs = usize::from(program.input_count());
    if inputs.len() != expected_inputs {
        return Err(VmExecutionError::InputCountMismatch {
            expected: expected_inputs,
            actual: inputs.len(),
        });
    }

    let mut registers = vec![None; program.register_types().len()];
    for (register, input) in inputs.into_iter().enumerate() {
        let expected = program.register_types()[register];
        let actual = input.value_type();
        if actual != expected {
            return Err(VmExecutionError::InputTypeMismatch {
                register: register as u8,
                expected,
                actual,
            });
        }
        registers[register] = Some(input);
    }

    let mut program_counter = 0_usize;
    let mut gas_used = 0_u64;
    let mut steps = 0_u16;
    let mut events = Vec::with_capacity(usize::from(program.maximum_events()));

    loop {
        let instruction = program.instructions().get(program_counter).ok_or(
            VmExecutionError::InvariantViolation {
                program_counter,
                reason: "verified program counter is out of bounds",
            },
        )?;
        let cost = instruction.gas_cost();
        let next_gas = gas_used.checked_add(cost).ok_or(VmExecutionError::GasExhausted {
            program_counter,
            gas_used,
            instruction_cost: cost,
            gas_limit,
        })?;
        if next_gas > gas_limit {
            return Err(VmExecutionError::GasExhausted {
                program_counter,
                gas_used,
                instruction_cost: cost,
                gas_limit,
            });
        }
        gas_used = next_gas;
        steps = steps.checked_add(1).ok_or(VmExecutionError::InvariantViolation {
            program_counter,
            reason: "verified instruction count exceeds u16",
        })?;

        match instruction {
            VmInstruction::LoadU64 { destination, value } => {
                initialize(&mut registers, program_counter, *destination, VmValue::U64(*value))?;
                program_counter += 1;
            }
            VmInstruction::LoadBool { destination, value } => {
                initialize(&mut registers, program_counter, *destination, VmValue::Bool(*value))?;
                program_counter += 1;
            }
            VmInstruction::LoadDigest { destination, value } => {
                initialize(&mut registers, program_counter, *destination, VmValue::Digest(*value))?;
                program_counter += 1;
            }
            VmInstruction::Copy { destination, source } => {
                let value = read(&registers, program_counter, *source)?.clone();
                if !value.value_type().is_copyable() {
                    return invariant(program_counter, "verified copy source is not copyable");
                }
                initialize(&mut registers, program_counter, *destination, value)?;
                program_counter += 1;
            }
            VmInstruction::Move { destination, source } => {
                let value = take(&mut registers, program_counter, *source)?;
                initialize(&mut registers, program_counter, *destination, value)?;
                program_counter += 1;
            }
            VmInstruction::AddU64 { destination, left, right } => {
                let left = read_u64(&registers, program_counter, *left)?;
                let right = read_u64(&registers, program_counter, *right)?;
                let value = left
                    .checked_add(right)
                    .ok_or(VmExecutionError::ArithmeticOverflow { program_counter })?;
                initialize(&mut registers, program_counter, *destination, VmValue::U64(value))?;
                program_counter += 1;
            }
            VmInstruction::EqU64 { destination, left, right } => {
                let left = read_u64(&registers, program_counter, *left)?;
                let right = read_u64(&registers, program_counter, *right)?;
                initialize(
                    &mut registers,
                    program_counter,
                    *destination,
                    VmValue::Bool(left == right),
                )?;
                program_counter += 1;
            }
            VmInstruction::Jump { target } => {
                program_counter = usize::from(*target);
            }
            VmInstruction::BranchIf { condition, target } => {
                let condition = read_bool(&registers, program_counter, *condition)?;
                if condition {
                    program_counter = usize::from(*target);
                } else {
                    program_counter += 1;
                }
            }
            VmInstruction::ConsumeCapability { source } => {
                let value = take(&mut registers, program_counter, *source)?;
                if !matches!(value, VmValue::Capability(_)) {
                    return invariant(
                        program_counter,
                        "verified consume source is not a capability",
                    );
                }
                program_counter += 1;
            }
            VmInstruction::Emit { source } => {
                let event =
                    VmEventValue::from_vm_value(read(&registers, program_counter, *source)?)
                        .ok_or(VmExecutionError::InvariantViolation {
                            program_counter,
                            reason: "verified event source is not scalar",
                        })?;
                if events.len() >= usize::from(program.maximum_events()) {
                    return invariant(program_counter, "verified event path exceeds declaration");
                }
                events.push(event);
                program_counter += 1;
            }
            VmInstruction::Return { sources } => {
                let mut outputs = Vec::with_capacity(sources.len());
                for source in sources {
                    outputs.push(take(&mut registers, program_counter, *source)?);
                }
                return VmExecutionResult::new(gas_used, steps, outputs, events)
                    .map_err(VmExecutionError::InvalidResult);
            }
        }
    }
}

fn initialize(
    registers: &mut [Option<VmValue>],
    program_counter: usize,
    register: u8,
    value: VmValue,
) -> Result<(), VmExecutionError> {
    let slot =
        registers.get_mut(usize::from(register)).ok_or(VmExecutionError::InvariantViolation {
            program_counter,
            reason: "verified destination register is out of bounds",
        })?;
    if slot.is_some() {
        return invariant(program_counter, "verified destination is already initialized");
    }
    *slot = Some(value);
    Ok(())
}

fn read(
    registers: &[Option<VmValue>],
    program_counter: usize,
    register: u8,
) -> Result<&VmValue, VmExecutionError> {
    registers.get(usize::from(register)).and_then(Option::as_ref).ok_or(
        VmExecutionError::InvariantViolation {
            program_counter,
            reason: "verified source register is unavailable",
        },
    )
}

fn take(
    registers: &mut [Option<VmValue>],
    program_counter: usize,
    register: u8,
) -> Result<VmValue, VmExecutionError> {
    registers.get_mut(usize::from(register)).and_then(Option::take).ok_or(
        VmExecutionError::InvariantViolation {
            program_counter,
            reason: "verified source register is unavailable",
        },
    )
}

fn read_u64(
    registers: &[Option<VmValue>],
    program_counter: usize,
    register: u8,
) -> Result<u64, VmExecutionError> {
    match read(registers, program_counter, register)? {
        VmValue::U64(value) => Ok(*value),
        _ => invariant(program_counter, "verified unsigned operand has the wrong type"),
    }
}

fn read_bool(
    registers: &[Option<VmValue>],
    program_counter: usize,
    register: u8,
) -> Result<bool, VmExecutionError> {
    match read(registers, program_counter, register)? {
        VmValue::Bool(value) => Ok(*value),
        _ => invariant(program_counter, "verified Boolean operand has the wrong type"),
    }
}

fn invariant<T>(program_counter: usize, reason: &'static str) -> Result<T, VmExecutionError> {
    Err(VmExecutionError::InvariantViolation { program_counter, reason })
}

/// Deterministic ObjectVM invocation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmExecutionError {
    /// Runtime input arity differs from the verified prefix.
    InputCountMismatch { expected: usize, actual: usize },
    /// One runtime input has the wrong static type.
    InputTypeMismatch { register: u8, expected: VmValueType, actual: VmValueType },
    /// The next instruction could not be prepaid in full.
    GasExhausted { program_counter: usize, gas_used: u64, instruction_cost: u64, gas_limit: u64 },
    /// Checked `u64` addition overflowed.
    ArithmeticOverflow { program_counter: usize },
    /// Static verification and runtime structure disagreed.
    InvariantViolation { program_counter: usize, reason: &'static str },
    /// An internally produced successful result violated canonical bounds.
    InvalidResult(VmExecutionResultError),
}
