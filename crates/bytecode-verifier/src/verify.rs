//! Total static verification for bounded ObjectVM programs.

use alloc::vec;
use alloc::vec::Vec;

use crate::{VmInstruction, VmProgram, VmValueType};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegisterState {
    Uninitialized,
    Available,
    Moved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FlowState {
    registers: Vec<RegisterState>,
    maximum_events: usize,
}

/// Opaque evidence that a canonical program satisfies P-050's static rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProgram {
    program: VmProgram,
}

impl VerifiedProgram {
    /// Borrows the verified canonical program.
    #[must_use]
    pub const fn program(&self) -> &VmProgram {
        &self.program
    }
}

/// Verifies all instruction, type, resource, control-flow, and event invariants.
pub fn verify(program: VmProgram) -> Result<VerifiedProgram, VmVerificationError> {
    let instruction_count = program.instructions().len();
    let mut states: Vec<Option<FlowState>> = vec![None; instruction_count];
    let input_count = usize::from(program.input_count());
    let mut entry_registers = vec![RegisterState::Uninitialized; program.register_types().len()];
    entry_registers[..input_count].fill(RegisterState::Available);
    states[0] = Some(FlowState { registers: entry_registers, maximum_events: 0 });

    for program_counter in 0..instruction_count {
        let mut state = states[program_counter]
            .clone()
            .ok_or(VmVerificationError::UnreachableInstruction { program_counter })?;
        match &program.instructions()[program_counter] {
            VmInstruction::LoadU64 { destination, .. } => {
                require_destination(
                    &program,
                    &state,
                    program_counter,
                    *destination,
                    VmValueType::U64,
                )?;
                state.registers[usize::from(*destination)] = RegisterState::Available;
                propagate_fallthrough(&mut states, program_counter, state)?;
            }
            VmInstruction::LoadBool { destination, .. } => {
                require_destination(
                    &program,
                    &state,
                    program_counter,
                    *destination,
                    VmValueType::Bool,
                )?;
                state.registers[usize::from(*destination)] = RegisterState::Available;
                propagate_fallthrough(&mut states, program_counter, state)?;
            }
            VmInstruction::LoadDigest { destination, .. } => {
                require_destination(
                    &program,
                    &state,
                    program_counter,
                    *destination,
                    VmValueType::Digest,
                )?;
                state.registers[usize::from(*destination)] = RegisterState::Available;
                propagate_fallthrough(&mut states, program_counter, state)?;
            }
            VmInstruction::Copy { destination, source } => {
                let source_type = require_source(&program, &state, program_counter, *source)?;
                if !source_type.is_copyable() {
                    return Err(VmVerificationError::CopyRequiresCopyable {
                        program_counter,
                        source: *source,
                        actual: source_type,
                    });
                }
                require_destination(&program, &state, program_counter, *destination, source_type)?;
                state.registers[usize::from(*destination)] = RegisterState::Available;
                propagate_fallthrough(&mut states, program_counter, state)?;
            }
            VmInstruction::Move { destination, source } => {
                let source_type = require_source(&program, &state, program_counter, *source)?;
                require_destination(&program, &state, program_counter, *destination, source_type)?;
                state.registers[usize::from(*source)] = RegisterState::Moved;
                state.registers[usize::from(*destination)] = RegisterState::Available;
                propagate_fallthrough(&mut states, program_counter, state)?;
            }
            VmInstruction::AddU64 { destination, left, right } => {
                require_destination(
                    &program,
                    &state,
                    program_counter,
                    *destination,
                    VmValueType::U64,
                )?;
                require_source_type(&program, &state, program_counter, *left, VmValueType::U64)?;
                require_source_type(&program, &state, program_counter, *right, VmValueType::U64)?;
                state.registers[usize::from(*destination)] = RegisterState::Available;
                propagate_fallthrough(&mut states, program_counter, state)?;
            }
            VmInstruction::EqU64 { destination, left, right } => {
                require_destination(
                    &program,
                    &state,
                    program_counter,
                    *destination,
                    VmValueType::Bool,
                )?;
                require_source_type(&program, &state, program_counter, *left, VmValueType::U64)?;
                require_source_type(&program, &state, program_counter, *right, VmValueType::U64)?;
                state.registers[usize::from(*destination)] = RegisterState::Available;
                propagate_fallthrough(&mut states, program_counter, state)?;
            }
            VmInstruction::Jump { target } => {
                let target = require_target(program_counter, *target, instruction_count)?;
                merge_state(&mut states, target, state)?;
            }
            VmInstruction::BranchIf { condition, target } => {
                require_source_type(
                    &program,
                    &state,
                    program_counter,
                    *condition,
                    VmValueType::Bool,
                )?;
                let target = require_target(program_counter, *target, instruction_count)?;
                let fallthrough = next_program_counter(program_counter, instruction_count)?;
                merge_state(&mut states, fallthrough, state.clone())?;
                merge_state(&mut states, target, state)?;
            }
            VmInstruction::ConsumeCapability { source } => {
                require_source_type(
                    &program,
                    &state,
                    program_counter,
                    *source,
                    VmValueType::Capability,
                )?;
                state.registers[usize::from(*source)] = RegisterState::Moved;
                propagate_fallthrough(&mut states, program_counter, state)?;
            }
            VmInstruction::Emit { source } => {
                let source_type = require_source(&program, &state, program_counter, *source)?;
                if !source_type.is_event_scalar() {
                    return Err(VmVerificationError::EmitRequiresScalar {
                        program_counter,
                        source: *source,
                        actual: source_type,
                    });
                }
                state.maximum_events = state
                    .maximum_events
                    .checked_add(1)
                    .ok_or(VmVerificationError::EventLimitExceeded { program_counter })?;
                if state.maximum_events > usize::from(program.maximum_events()) {
                    return Err(VmVerificationError::EventLimitExceeded { program_counter });
                }
                propagate_fallthrough(&mut states, program_counter, state)?;
            }
            VmInstruction::Return { sources } => {
                verify_return(&program, &state, program_counter, sources)?;
            }
        }
    }
    Ok(VerifiedProgram { program })
}

fn require_register(
    program: &VmProgram,
    program_counter: usize,
    register: u8,
) -> Result<usize, VmVerificationError> {
    let index = usize::from(register);
    if index >= program.register_types().len() {
        Err(VmVerificationError::RegisterOutOfBounds { program_counter, register })
    } else {
        Ok(index)
    }
}

fn require_source(
    program: &VmProgram,
    state: &FlowState,
    program_counter: usize,
    register: u8,
) -> Result<VmValueType, VmVerificationError> {
    let index = require_register(program, program_counter, register)?;
    if state.registers[index] != RegisterState::Available {
        return Err(VmVerificationError::SourceUnavailable { program_counter, register });
    }
    Ok(program.register_types()[index])
}

fn require_source_type(
    program: &VmProgram,
    state: &FlowState,
    program_counter: usize,
    register: u8,
    expected: VmValueType,
) -> Result<(), VmVerificationError> {
    let actual = require_source(program, state, program_counter, register)?;
    if actual != expected {
        return Err(VmVerificationError::TypeMismatch {
            program_counter,
            register,
            expected,
            actual,
        });
    }
    Ok(())
}

fn require_destination(
    program: &VmProgram,
    state: &FlowState,
    program_counter: usize,
    register: u8,
    expected: VmValueType,
) -> Result<(), VmVerificationError> {
    let index = require_register(program, program_counter, register)?;
    let actual = program.register_types()[index];
    if actual != expected {
        return Err(VmVerificationError::TypeMismatch {
            program_counter,
            register,
            expected,
            actual,
        });
    }
    if state.registers[index] != RegisterState::Uninitialized {
        return Err(VmVerificationError::DestinationAlreadyInitialized {
            program_counter,
            register,
        });
    }
    Ok(())
}

fn require_target(
    program_counter: usize,
    target: u16,
    instruction_count: usize,
) -> Result<usize, VmVerificationError> {
    let target_index = usize::from(target);
    if target_index >= instruction_count {
        return Err(VmVerificationError::TargetOutOfBounds { program_counter, target });
    }
    if target_index <= program_counter {
        return Err(VmVerificationError::TargetNotForward { program_counter, target });
    }
    Ok(target_index)
}

fn next_program_counter(
    program_counter: usize,
    instruction_count: usize,
) -> Result<usize, VmVerificationError> {
    let next = program_counter + 1;
    if next >= instruction_count {
        Err(VmVerificationError::FallthroughPastEnd { program_counter })
    } else {
        Ok(next)
    }
}

fn propagate_fallthrough(
    states: &mut [Option<FlowState>],
    program_counter: usize,
    state: FlowState,
) -> Result<(), VmVerificationError> {
    let next = next_program_counter(program_counter, states.len())?;
    merge_state(states, next, state)
}

fn merge_state(
    states: &mut [Option<FlowState>],
    target: usize,
    candidate: FlowState,
) -> Result<(), VmVerificationError> {
    match &mut states[target] {
        None => states[target] = Some(candidate),
        Some(existing) => {
            if existing.registers != candidate.registers {
                return Err(VmVerificationError::InconsistentMerge { program_counter: target });
            }
            existing.maximum_events = existing.maximum_events.max(candidate.maximum_events);
        }
    }
    Ok(())
}

fn verify_return(
    program: &VmProgram,
    state: &FlowState,
    program_counter: usize,
    sources: &[u8],
) -> Result<(), VmVerificationError> {
    if sources.len() != program.output_types().len() {
        return Err(VmVerificationError::OutputCountMismatch {
            program_counter,
            expected: program.output_types().len(),
            actual: sources.len(),
        });
    }
    let mut returned = vec![false; program.register_types().len()];
    for (source, expected) in sources.iter().copied().zip(program.output_types().iter().copied()) {
        let index = require_register(program, program_counter, source)?;
        if returned[index] {
            return Err(VmVerificationError::DuplicateReturnRegister {
                program_counter,
                register: source,
            });
        }
        require_source_type(program, state, program_counter, source, expected)?;
        returned[index] = true;
    }
    for (index, value_type) in program.register_types().iter().copied().enumerate() {
        if value_type.is_linear()
            && state.registers[index] == RegisterState::Available
            && !returned[index]
        {
            return Err(VmVerificationError::LinearObjectNotReturned {
                program_counter,
                register: index as u8,
            });
        }
    }
    Ok(())
}

/// Static ObjectVM verification failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmVerificationError {
    /// An instruction references a register outside the declaration.
    RegisterOutOfBounds { program_counter: usize, register: u8 },
    /// A source has not been initialized or was already moved.
    SourceUnavailable { program_counter: usize, register: u8 },
    /// SSA destinations may be initialized only once.
    DestinationAlreadyInitialized { program_counter: usize, register: u8 },
    /// An operand's declared type does not match the instruction.
    TypeMismatch {
        program_counter: usize,
        register: u8,
        expected: VmValueType,
        actual: VmValueType,
    },
    /// Copy accepts only scalar registers.
    CopyRequiresCopyable { program_counter: usize, source: u8, actual: VmValueType },
    /// Emit accepts only scalar registers.
    EmitRequiresScalar { program_counter: usize, source: u8, actual: VmValueType },
    /// A jump target does not identify an instruction.
    TargetOutOfBounds { program_counter: usize, target: u16 },
    /// Version 1 forbids self and backward edges.
    TargetNotForward { program_counter: usize, target: u16 },
    /// A nonterminal instruction has no following instruction.
    FallthroughPastEnd { program_counter: usize },
    /// A control-flow merge disagrees about register availability.
    InconsistentMerge { program_counter: usize },
    /// The program contains dead bytecode.
    UnreachableInstruction { program_counter: usize },
    /// One path can emit more events than declared.
    EventLimitExceeded { program_counter: usize },
    /// A return does not match the output arity.
    OutputCountMismatch { program_counter: usize, expected: usize, actual: usize },
    /// A return lists the same register more than once.
    DuplicateReturnRegister { program_counter: usize, register: u8 },
    /// A live linear object would be implicitly discarded.
    LinearObjectNotReturned { program_counter: usize, register: u8 },
}
