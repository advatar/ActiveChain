use crate::{VmExecutionResult, VmValue, execute};
use activechain_bytecode_verifier::{VerifiedProgram, VmProgram, verify};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use alloc::vec::Vec;

/// Replay-verifiable execution evidence for transparent block admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionEvidence {
    program: VmProgram,
    inputs: Vec<VmValue>,
    gas_limit: u64,
    result: VmExecutionResult,
}
impl ExecutionEvidence {
    pub const TYPE_TAG: u16 = 0x0062;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        VmProgram::MAX_ENCODED_LEN + 4 + 8 + VmExecutionResult::MAX_ENCODED_LEN;
    pub fn create(
        verified: &VerifiedProgram,
        inputs: Vec<VmValue>,
        gas_limit: u64,
    ) -> Result<Self, EvidenceError> {
        let result =
            execute(verified, inputs.clone(), gas_limit).map_err(EvidenceError::Execution)?;
        Ok(Self { program: verified.program().clone(), inputs, gas_limit, result })
    }
    pub fn verify(&self) -> Result<(), EvidenceError> {
        let verified = verify(self.program.clone()).map_err(EvidenceError::Verification)?;
        let replayed = execute(&verified, self.inputs.clone(), self.gas_limit)
            .map_err(EvidenceError::Execution)?;
        if replayed != self.result {
            return Err(EvidenceError::ResultMismatch);
        }
        Ok(())
    }
    pub const fn program(&self) -> &VmProgram {
        &self.program
    }
    pub fn inputs(&self) -> &[VmValue] {
        &self.inputs
    }
    pub const fn gas_limit(&self) -> u64 {
        self.gas_limit
    }
    pub const fn result(&self) -> &VmExecutionResult {
        &self.result
    }
}
#[derive(Debug, Eq, PartialEq)]
pub enum EvidenceError {
    Verification(activechain_bytecode_verifier::VmVerificationError),
    Execution(crate::VmExecutionError),
    ResultMismatch,
    InvalidBounds,
}
impl CanonicalEncode for ExecutionEvidence {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.program.encode(e)?;
        e.write_length(self.inputs.len(), activechain_bytecode_verifier::MAX_VM_INPUTS)?;
        for input in &self.inputs {
            input.encode(e)?;
        }
        self.gas_limit.encode(e)?;
        self.result.encode(e)
    }
}
impl CanonicalDecode for ExecutionEvidence {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let program = VmProgram::decode(d)?;
        let count = d.read_length(activechain_bytecode_verifier::MAX_VM_INPUTS)?;
        let mut inputs = Vec::with_capacity(count);
        for _ in 0..count {
            inputs.push(VmValue::decode(d)?);
        }
        let gas_limit = u64::decode(d)?;
        let result = VmExecutionResult::decode(d)?;
        if verify(program.clone()).is_err() {
            return Err(DecodeError::InvalidValue("execution evidence program is not verified"));
        }
        Ok(Self { program, inputs, gas_limit, result })
    }
}
impl CanonicalType for ExecutionEvidence {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}
