//! Canonical bounded ObjectVM bytecode.

use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::Digest384;

/// Maximum registers declared by one version-1 program.
pub const MAX_VM_REGISTERS: usize = 32;
/// Maximum prefix registers initialized from explicit inputs.
pub const MAX_VM_INPUTS: usize = 16;
/// Maximum output signature and returned value count.
pub const MAX_VM_OUTPUTS: usize = 16;
/// Maximum instructions in one single-entry program.
pub const MAX_VM_INSTRUCTIONS: usize = 256;
/// Maximum scalar events on any execution path.
pub const MAX_VM_EVENTS: usize = 16;

/// Static ObjectVM register type and resource class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VmValueType {
    /// Copyable unsigned 64-bit integer.
    U64 = 0,
    /// Copyable Boolean.
    Bool = 1,
    /// Copyable 384-bit digest.
    Digest = 2,
    /// Linear canonical object.
    Object = 3,
    /// Affine capability identifier.
    Capability = 4,
}

impl VmValueType {
    /// Returns whether the value may be duplicated.
    #[must_use]
    pub const fn is_copyable(self) -> bool {
        matches!(self, Self::U64 | Self::Bool | Self::Digest)
    }

    /// Returns whether the value is an affine capability.
    #[must_use]
    pub const fn is_affine(self) -> bool {
        matches!(self, Self::Capability)
    }

    /// Returns whether the value must survive exactly once to a return.
    #[must_use]
    pub const fn is_linear(self) -> bool {
        matches!(self, Self::Object)
    }

    /// Returns whether the value can be copied into the ordered event stream.
    #[must_use]
    pub const fn is_event_scalar(self) -> bool {
        self.is_copyable()
    }
}

impl CanonicalEncode for VmValueType {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for VmValueType {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::U64),
            1 => Ok(Self::Bool),
            2 => Ok(Self::Digest),
            3 => Ok(Self::Object),
            4 => Ok(Self::Capability),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "VmValueType", tag }),
        }
    }
}

/// Version-1 typed register instructions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VmInstruction {
    /// Initialize one `U64` register.
    LoadU64 { destination: u8, value: u64 },
    /// Initialize one `Bool` register.
    LoadBool { destination: u8, value: bool },
    /// Initialize one `Digest` register.
    LoadDigest { destination: u8, value: Digest384 },
    /// Duplicate one copyable register.
    Copy { destination: u8, source: u8 },
    /// Transfer any available register and invalidate its source.
    Move { destination: u8, source: u8 },
    /// Checked unsigned addition without consuming either operand.
    AddU64 { destination: u8, left: u8, right: u8 },
    /// Compare two unsigned registers without consuming them.
    EqU64 { destination: u8, left: u8, right: u8 },
    /// Continue at one strictly later instruction.
    Jump { target: u16 },
    /// Continue at `target` when the Boolean condition is true, else fall through.
    BranchIf { condition: u8, target: u16 },
    /// Explicitly consume one affine capability.
    ConsumeCapability { source: u8 },
    /// Copy one scalar into the ordered event stream.
    Emit { source: u8 },
    /// Terminate with values matching the declared output signature.
    Return { sources: Vec<u8> },
}

impl VmInstruction {
    /// Consensus gas charged before this instruction executes.
    #[must_use]
    pub fn gas_cost(&self) -> u64 {
        match self {
            Self::LoadDigest { .. } | Self::AddU64 { .. } => 2,
            Self::Emit { .. } => 4,
            Self::Return { sources } => 1 + sources.len() as u64,
            _ => 1,
        }
    }
}

impl CanonicalEncode for VmInstruction {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::LoadU64 { destination, value } => {
                0_u8.encode(encoder)?;
                destination.encode(encoder)?;
                value.encode(encoder)
            }
            Self::LoadBool { destination, value } => {
                1_u8.encode(encoder)?;
                destination.encode(encoder)?;
                value.encode(encoder)
            }
            Self::LoadDigest { destination, value } => {
                2_u8.encode(encoder)?;
                destination.encode(encoder)?;
                value.encode(encoder)
            }
            Self::Copy { destination, source } => {
                3_u8.encode(encoder)?;
                destination.encode(encoder)?;
                source.encode(encoder)
            }
            Self::Move { destination, source } => {
                4_u8.encode(encoder)?;
                destination.encode(encoder)?;
                source.encode(encoder)
            }
            Self::AddU64 { destination, left, right } => {
                5_u8.encode(encoder)?;
                destination.encode(encoder)?;
                left.encode(encoder)?;
                right.encode(encoder)
            }
            Self::EqU64 { destination, left, right } => {
                6_u8.encode(encoder)?;
                destination.encode(encoder)?;
                left.encode(encoder)?;
                right.encode(encoder)
            }
            Self::Jump { target } => {
                7_u8.encode(encoder)?;
                target.encode(encoder)
            }
            Self::BranchIf { condition, target } => {
                8_u8.encode(encoder)?;
                condition.encode(encoder)?;
                target.encode(encoder)
            }
            Self::ConsumeCapability { source } => {
                9_u8.encode(encoder)?;
                source.encode(encoder)
            }
            Self::Emit { source } => {
                10_u8.encode(encoder)?;
                source.encode(encoder)
            }
            Self::Return { sources } => {
                11_u8.encode(encoder)?;
                encoder.write_length(sources.len(), MAX_VM_OUTPUTS)?;
                for source in sources {
                    source.encode(encoder)?;
                }
                Ok(())
            }
        }
    }
}

impl CanonicalDecode for VmInstruction {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::LoadU64 {
                destination: u8::decode(decoder)?,
                value: u64::decode(decoder)?,
            }),
            1 => Ok(Self::LoadBool {
                destination: u8::decode(decoder)?,
                value: bool::decode(decoder)?,
            }),
            2 => Ok(Self::LoadDigest {
                destination: u8::decode(decoder)?,
                value: Digest384::decode(decoder)?,
            }),
            3 => Ok(Self::Copy { destination: u8::decode(decoder)?, source: u8::decode(decoder)? }),
            4 => Ok(Self::Move { destination: u8::decode(decoder)?, source: u8::decode(decoder)? }),
            5 => Ok(Self::AddU64 {
                destination: u8::decode(decoder)?,
                left: u8::decode(decoder)?,
                right: u8::decode(decoder)?,
            }),
            6 => Ok(Self::EqU64 {
                destination: u8::decode(decoder)?,
                left: u8::decode(decoder)?,
                right: u8::decode(decoder)?,
            }),
            7 => Ok(Self::Jump { target: u16::decode(decoder)? }),
            8 => Ok(Self::BranchIf {
                condition: u8::decode(decoder)?,
                target: u16::decode(decoder)?,
            }),
            9 => Ok(Self::ConsumeCapability { source: u8::decode(decoder)? }),
            10 => Ok(Self::Emit { source: u8::decode(decoder)? }),
            11 => {
                let source_count = decoder.read_length(MAX_VM_OUTPUTS)?;
                let mut sources = Vec::with_capacity(source_count);
                for _ in 0..source_count {
                    sources.push(u8::decode(decoder)?);
                }
                Ok(Self::Return { sources })
            }
            tag => Err(DecodeError::InvalidEnumTag { type_name: "VmInstruction", tag }),
        }
    }
}

/// A bounded single-entry ObjectVM program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmProgram {
    input_count: u8,
    register_types: Vec<VmValueType>,
    output_types: Vec<VmValueType>,
    instructions: Vec<VmInstruction>,
    maximum_events: u8,
}

impl VmProgram {
    /// Registered ObjectVM program type tag.
    pub const TYPE_TAG: u16 = 0x0060;
    /// Initial canonical ObjectVM schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Worst-case canonical program body length.
    pub const MAX_ENCODED_LEN: usize = 12_854;

    /// Validates only canonical structural bounds; static semantics use [`crate::verify`].
    pub fn new(
        input_count: u8,
        register_types: Vec<VmValueType>,
        output_types: Vec<VmValueType>,
        instructions: Vec<VmInstruction>,
        maximum_events: u8,
    ) -> Result<Self, VmProgramValidationError> {
        if register_types.is_empty() {
            return Err(VmProgramValidationError::EmptyRegisters);
        }
        if register_types.len() > MAX_VM_REGISTERS {
            return Err(VmProgramValidationError::TooManyRegisters {
                actual: register_types.len(),
                maximum: MAX_VM_REGISTERS,
            });
        }
        if usize::from(input_count) > MAX_VM_INPUTS {
            return Err(VmProgramValidationError::TooManyInputs {
                actual: usize::from(input_count),
                maximum: MAX_VM_INPUTS,
            });
        }
        if usize::from(input_count) > register_types.len() {
            return Err(VmProgramValidationError::InputCountExceedsRegisters);
        }
        if output_types.len() > MAX_VM_OUTPUTS {
            return Err(VmProgramValidationError::TooManyOutputs {
                actual: output_types.len(),
                maximum: MAX_VM_OUTPUTS,
            });
        }
        if instructions.is_empty() {
            return Err(VmProgramValidationError::EmptyInstructions);
        }
        if instructions.len() > MAX_VM_INSTRUCTIONS {
            return Err(VmProgramValidationError::TooManyInstructions {
                actual: instructions.len(),
                maximum: MAX_VM_INSTRUCTIONS,
            });
        }
        for instruction in &instructions {
            if let VmInstruction::Return { sources } = instruction
                && sources.len() > MAX_VM_OUTPUTS
            {
                return Err(VmProgramValidationError::TooManyReturnSources {
                    actual: sources.len(),
                    maximum: MAX_VM_OUTPUTS,
                });
            }
        }
        if usize::from(maximum_events) > MAX_VM_EVENTS {
            return Err(VmProgramValidationError::TooManyEvents {
                actual: usize::from(maximum_events),
                maximum: MAX_VM_EVENTS,
            });
        }
        Ok(Self { input_count, register_types, output_types, instructions, maximum_events })
    }

    /// Returns the number of prefix registers initialized from inputs.
    #[must_use]
    pub const fn input_count(&self) -> u8 {
        self.input_count
    }

    /// Borrows all statically declared register types.
    #[must_use]
    pub fn register_types(&self) -> &[VmValueType] {
        &self.register_types
    }

    /// Borrows the exact return signature.
    #[must_use]
    pub fn output_types(&self) -> &[VmValueType] {
        &self.output_types
    }

    /// Borrows instructions in program-counter order.
    #[must_use]
    pub fn instructions(&self) -> &[VmInstruction] {
        &self.instructions
    }

    /// Returns the maximum emitted events on any path.
    #[must_use]
    pub const fn maximum_events(&self) -> u8 {
        self.maximum_events
    }
}

impl CanonicalEncode for VmProgram {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.input_count.encode(encoder)?;
        encoder.write_length(self.register_types.len(), MAX_VM_REGISTERS)?;
        for value_type in &self.register_types {
            value_type.encode(encoder)?;
        }
        encoder.write_length(self.output_types.len(), MAX_VM_OUTPUTS)?;
        for value_type in &self.output_types {
            value_type.encode(encoder)?;
        }
        encoder.write_length(self.instructions.len(), MAX_VM_INSTRUCTIONS)?;
        for instruction in &self.instructions {
            instruction.encode(encoder)?;
        }
        self.maximum_events.encode(encoder)
    }
}

impl CanonicalDecode for VmProgram {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let input_count = u8::decode(decoder)?;
        let register_count = decoder.read_length(MAX_VM_REGISTERS)?;
        let mut register_types = Vec::with_capacity(register_count);
        for _ in 0..register_count {
            register_types.push(VmValueType::decode(decoder)?);
        }
        let output_count = decoder.read_length(MAX_VM_OUTPUTS)?;
        let mut output_types = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            output_types.push(VmValueType::decode(decoder)?);
        }
        let instruction_count = decoder.read_length(MAX_VM_INSTRUCTIONS)?;
        let mut instructions = Vec::with_capacity(instruction_count);
        for _ in 0..instruction_count {
            instructions.push(VmInstruction::decode(decoder)?);
        }
        let maximum_events = u8::decode(decoder)?;
        Self::new(input_count, register_types, output_types, instructions, maximum_events)
            .map_err(program_validation_decode_error)
    }
}

impl CanonicalType for VmProgram {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Canonical program construction failures, before semantic verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmProgramValidationError {
    /// At least one register is required.
    EmptyRegisters,
    /// The register vector exceeds the protocol bound.
    TooManyRegisters { actual: usize, maximum: usize },
    /// The explicit input prefix exceeds its protocol bound.
    TooManyInputs { actual: usize, maximum: usize },
    /// More inputs than registers were declared.
    InputCountExceedsRegisters,
    /// The output signature exceeds its protocol bound.
    TooManyOutputs { actual: usize, maximum: usize },
    /// At least one terminal instruction is required.
    EmptyInstructions,
    /// The instruction vector exceeds the protocol bound.
    TooManyInstructions { actual: usize, maximum: usize },
    /// A return operand list exceeds the output bound.
    TooManyReturnSources { actual: usize, maximum: usize },
    /// The declared path event maximum exceeds the protocol bound.
    TooManyEvents { actual: usize, maximum: usize },
}

fn program_validation_decode_error(error: VmProgramValidationError) -> DecodeError {
    match error {
        VmProgramValidationError::EmptyRegisters => {
            DecodeError::InvalidValue("ObjectVM program declares no registers")
        }
        VmProgramValidationError::TooManyRegisters { .. } => {
            DecodeError::InvalidValue("ObjectVM program exceeds the register bound")
        }
        VmProgramValidationError::TooManyInputs { .. } => {
            DecodeError::InvalidValue("ObjectVM program exceeds the input bound")
        }
        VmProgramValidationError::InputCountExceedsRegisters => {
            DecodeError::InvalidValue("ObjectVM input count exceeds its registers")
        }
        VmProgramValidationError::TooManyOutputs { .. } => {
            DecodeError::InvalidValue("ObjectVM program exceeds the output bound")
        }
        VmProgramValidationError::EmptyInstructions => {
            DecodeError::InvalidValue("ObjectVM program has no instructions")
        }
        VmProgramValidationError::TooManyInstructions { .. } => {
            DecodeError::InvalidValue("ObjectVM program exceeds the instruction bound")
        }
        VmProgramValidationError::TooManyReturnSources { .. } => {
            DecodeError::InvalidValue("ObjectVM return exceeds the output bound")
        }
        VmProgramValidationError::TooManyEvents { .. } => {
            DecodeError::InvalidValue("ObjectVM program exceeds the event bound")
        }
    }
}
