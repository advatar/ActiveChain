//! Canonical runtime values and successful execution results.

use alloc::boxed::Box;
use alloc::vec::Vec;

use activechain_bytecode_verifier::{
    MAX_VM_EVENTS, MAX_VM_INSTRUCTIONS, MAX_VM_OUTPUTS, VmValueType,
};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{CapabilityId, Digest384, Object};

/// One typed ObjectVM register or returned value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VmValue {
    /// Copyable unsigned integer.
    U64(u64),
    /// Copyable Boolean.
    Bool(bool),
    /// Copyable digest.
    Digest(Digest384),
    /// Linear canonical object.
    Object(Box<Object>),
    /// Affine capability identifier.
    Capability(CapabilityId),
}

impl VmValue {
    /// Returns the static register type corresponding to this value.
    #[must_use]
    pub const fn value_type(&self) -> VmValueType {
        match self {
            Self::U64(_) => VmValueType::U64,
            Self::Bool(_) => VmValueType::Bool,
            Self::Digest(_) => VmValueType::Digest,
            Self::Object(_) => VmValueType::Object,
            Self::Capability(_) => VmValueType::Capability,
        }
    }
}

impl CanonicalEncode for VmValue {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::U64(value) => {
                0_u8.encode(encoder)?;
                value.encode(encoder)
            }
            Self::Bool(value) => {
                1_u8.encode(encoder)?;
                value.encode(encoder)
            }
            Self::Digest(value) => {
                2_u8.encode(encoder)?;
                value.encode(encoder)
            }
            Self::Object(value) => {
                3_u8.encode(encoder)?;
                value.encode(encoder)
            }
            Self::Capability(value) => {
                4_u8.encode(encoder)?;
                value.encode(encoder)
            }
        }
    }
}

impl CanonicalDecode for VmValue {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::U64(u64::decode(decoder)?)),
            1 => Ok(Self::Bool(bool::decode(decoder)?)),
            2 => Ok(Self::Digest(Digest384::decode(decoder)?)),
            3 => Ok(Self::Object(Box::new(Object::decode(decoder)?))),
            4 => Ok(Self::Capability(CapabilityId::decode(decoder)?)),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "VmValue", tag }),
        }
    }
}

/// One ordered scalar event value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmEventValue {
    /// Unsigned integer event.
    U64(u64),
    /// Boolean event.
    Bool(bool),
    /// Digest event.
    Digest(Digest384),
}

impl VmEventValue {
    pub(crate) const fn from_vm_value(value: &VmValue) -> Option<Self> {
        match value {
            VmValue::U64(value) => Some(Self::U64(*value)),
            VmValue::Bool(value) => Some(Self::Bool(*value)),
            VmValue::Digest(value) => Some(Self::Digest(*value)),
            VmValue::Object(_) | VmValue::Capability(_) => None,
        }
    }
}

impl CanonicalEncode for VmEventValue {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::U64(value) => {
                0_u8.encode(encoder)?;
                value.encode(encoder)
            }
            Self::Bool(value) => {
                1_u8.encode(encoder)?;
                value.encode(encoder)
            }
            Self::Digest(value) => {
                2_u8.encode(encoder)?;
                value.encode(encoder)
            }
        }
    }
}

impl CanonicalDecode for VmEventValue {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::U64(u64::decode(decoder)?)),
            1 => Ok(Self::Bool(bool::decode(decoder)?)),
            2 => Ok(Self::Digest(Digest384::decode(decoder)?)),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "VmEventValue", tag }),
        }
    }
}

/// Canonical successful ObjectVM result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmExecutionResult {
    gas_used: u64,
    steps: u16,
    outputs: Vec<VmValue>,
    events: Vec<VmEventValue>,
}

impl VmExecutionResult {
    /// Registered execution-result type tag.
    pub const TYPE_TAG: u16 = 0x0061;
    /// Initial canonical execution-result schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Worst-case canonical execution-result body length.
    pub const MAX_ENCODED_LEN: usize = 270_508;

    /// Validates successful step, output, and event bounds.
    pub fn new(
        gas_used: u64,
        steps: u16,
        outputs: Vec<VmValue>,
        events: Vec<VmEventValue>,
    ) -> Result<Self, VmExecutionResultError> {
        if steps == 0 || usize::from(steps) > MAX_VM_INSTRUCTIONS {
            return Err(VmExecutionResultError::InvalidStepCount(steps));
        }
        if outputs.len() > MAX_VM_OUTPUTS {
            return Err(VmExecutionResultError::TooManyOutputs {
                actual: outputs.len(),
                maximum: MAX_VM_OUTPUTS,
            });
        }
        if events.len() > MAX_VM_EVENTS {
            return Err(VmExecutionResultError::TooManyEvents {
                actual: events.len(),
                maximum: MAX_VM_EVENTS,
            });
        }
        Ok(Self { gas_used, steps, outputs, events })
    }

    /// Returns exact prepaid gas consumed by executed instructions.
    #[must_use]
    pub const fn gas_used(&self) -> u64 {
        self.gas_used
    }

    /// Returns the count of executed instructions, including `Return`.
    #[must_use]
    pub const fn steps(&self) -> u16 {
        self.steps
    }

    /// Borrows ordered returned values.
    #[must_use]
    pub fn outputs(&self) -> &[VmValue] {
        &self.outputs
    }

    /// Borrows ordered scalar events.
    #[must_use]
    pub fn events(&self) -> &[VmEventValue] {
        &self.events
    }
}

impl CanonicalEncode for VmExecutionResult {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.gas_used.encode(encoder)?;
        self.steps.encode(encoder)?;
        encoder.write_length(self.outputs.len(), MAX_VM_OUTPUTS)?;
        for output in &self.outputs {
            output.encode(encoder)?;
        }
        encoder.write_length(self.events.len(), MAX_VM_EVENTS)?;
        for event in &self.events {
            event.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for VmExecutionResult {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let gas_used = u64::decode(decoder)?;
        let steps = u16::decode(decoder)?;
        let output_count = decoder.read_length(MAX_VM_OUTPUTS)?;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(VmValue::decode(decoder)?);
        }
        let event_count = decoder.read_length(MAX_VM_EVENTS)?;
        let mut events = Vec::with_capacity(event_count);
        for _ in 0..event_count {
            events.push(VmEventValue::decode(decoder)?);
        }
        Self::new(gas_used, steps, outputs, events).map_err(|error| match error {
            VmExecutionResultError::InvalidStepCount(_) => {
                DecodeError::InvalidValue("ObjectVM result has an invalid step count")
            }
            VmExecutionResultError::TooManyOutputs { .. } => {
                DecodeError::InvalidValue("ObjectVM result exceeds the output bound")
            }
            VmExecutionResultError::TooManyEvents { .. } => {
                DecodeError::InvalidValue("ObjectVM result exceeds the event bound")
            }
        })
    }
}

impl CanonicalType for VmExecutionResult {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Successful execution-result construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmExecutionResultError {
    /// A successful bounded execution runs between one and 256 instructions.
    InvalidStepCount(u16),
    /// Returned values exceed the protocol bound.
    TooManyOutputs { actual: usize, maximum: usize },
    /// Emitted events exceed the protocol bound.
    TooManyEvents { actual: usize, maximum: usize },
}
