extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use activechain_canonical_codec::{DecodeError, decode_envelope, encode_body, encode_envelope};
use activechain_protocol_types::Digest384;

use crate::{
    MAX_VM_INSTRUCTIONS, VmInstruction, VmProgram, VmProgramValidationError, VmValueType,
    VmVerificationError, verify,
};

fn program(
    input_count: u8,
    registers: Vec<VmValueType>,
    outputs: Vec<VmValueType>,
    instructions: Vec<VmInstruction>,
    maximum_events: u8,
) -> VmProgram {
    VmProgram::new(input_count, registers, outputs, instructions, maximum_events)
        .expect("test program is structurally bounded")
}

fn valid_resource_program() -> VmProgram {
    program(
        3,
        vec![
            VmValueType::Object,
            VmValueType::Capability,
            VmValueType::U64,
            VmValueType::U64,
            VmValueType::U64,
            VmValueType::Bool,
            VmValueType::Digest,
            VmValueType::Object,
        ],
        vec![VmValueType::Object, VmValueType::U64, VmValueType::Bool],
        vec![
            VmInstruction::LoadU64 { destination: 3, value: 5 },
            VmInstruction::AddU64 { destination: 4, left: 2, right: 3 },
            VmInstruction::EqU64 { destination: 5, left: 4, right: 3 },
            VmInstruction::LoadDigest { destination: 6, value: Digest384::new([0x44; 48]) },
            VmInstruction::Emit { source: 6 },
            VmInstruction::ConsumeCapability { source: 1 },
            VmInstruction::Move { destination: 7, source: 0 },
            VmInstruction::Return { sources: vec![7, 4, 5] },
        ],
        1,
    )
}

#[test]
fn valid_typed_resource_program_verifies_and_round_trips() {
    let program = valid_resource_program();
    let bytes = encode_envelope(&program).expect("program fits its canonical bound");
    assert_eq!(decode_envelope(&bytes), Ok(program.clone()));
    assert_eq!(verify(program.clone()).expect("program verifies").program(), &program);
}

#[test]
fn affine_and_linear_values_cannot_be_copied() {
    for resource_type in [VmValueType::Capability, VmValueType::Object] {
        let candidate = program(
            1,
            vec![resource_type, resource_type],
            vec![resource_type],
            vec![
                VmInstruction::Copy { destination: 1, source: 0 },
                VmInstruction::Return { sources: vec![0] },
            ],
            0,
        );
        assert!(matches!(
            verify(candidate),
            Err(VmVerificationError::CopyRequiresCopyable { actual, .. }) if actual == resource_type
        ));
    }
}

#[test]
fn every_live_linear_object_must_be_returned_exactly_once() {
    let lost = program(
        1,
        vec![VmValueType::Object],
        vec![],
        vec![VmInstruction::Return { sources: vec![] }],
        0,
    );
    assert_eq!(
        verify(lost),
        Err(VmVerificationError::LinearObjectNotReturned { program_counter: 0, register: 0 })
    );

    let duplicate = program(
        1,
        vec![VmValueType::Object],
        vec![VmValueType::Object, VmValueType::Object],
        vec![VmInstruction::Return { sources: vec![0, 0] }],
        0,
    );
    assert_eq!(
        verify(duplicate),
        Err(VmVerificationError::DuplicateReturnRegister { program_counter: 0, register: 0 })
    );
}

#[test]
fn targets_must_be_forward_in_bounds_and_all_code_reachable() {
    let backward = program(
        0,
        vec![VmValueType::Bool],
        vec![],
        vec![
            VmInstruction::LoadBool { destination: 0, value: true },
            VmInstruction::Jump { target: 0 },
            VmInstruction::Return { sources: vec![] },
        ],
        0,
    );
    assert!(matches!(verify(backward), Err(VmVerificationError::TargetNotForward { .. })));

    let out_of_bounds =
        program(0, vec![VmValueType::Bool], vec![], vec![VmInstruction::Jump { target: 9 }], 0);
    assert!(matches!(verify(out_of_bounds), Err(VmVerificationError::TargetOutOfBounds { .. })));

    let dead = program(
        0,
        vec![VmValueType::Bool],
        vec![],
        vec![
            VmInstruction::Jump { target: 2 },
            VmInstruction::Return { sources: vec![] },
            VmInstruction::Return { sources: vec![] },
        ],
        0,
    );
    assert_eq!(
        verify(dead),
        Err(VmVerificationError::UnreachableInstruction { program_counter: 1 })
    );
}

#[test]
fn branch_merges_require_identical_register_availability() {
    let inconsistent = program(
        1,
        vec![VmValueType::Bool, VmValueType::U64],
        vec![VmValueType::U64],
        vec![
            VmInstruction::BranchIf { condition: 0, target: 2 },
            VmInstruction::LoadU64 { destination: 1, value: 7 },
            VmInstruction::Return { sources: vec![1] },
        ],
        0,
    );
    assert_eq!(
        verify(inconsistent),
        Err(VmVerificationError::InconsistentMerge { program_counter: 2 })
    );
}

#[test]
fn initialization_typing_and_event_bounds_are_static() {
    let wrong_destination = program(
        0,
        vec![VmValueType::Bool],
        vec![],
        vec![
            VmInstruction::LoadU64 { destination: 0, value: 7 },
            VmInstruction::Return { sources: vec![] },
        ],
        0,
    );
    assert!(matches!(verify(wrong_destination), Err(VmVerificationError::TypeMismatch { .. })));

    let event_overrun = program(
        1,
        vec![VmValueType::Digest],
        vec![],
        vec![VmInstruction::Emit { source: 0 }, VmInstruction::Return { sources: vec![] }],
        0,
    );
    assert_eq!(
        verify(event_overrun),
        Err(VmVerificationError::EventLimitExceeded { program_counter: 0 })
    );
}

#[test]
fn published_program_body_bound_is_exact() {
    let instructions =
        vec![
            VmInstruction::LoadDigest { destination: 0, value: Digest384::new([0x55; 48]) };
            MAX_VM_INSTRUCTIONS
        ];
    let maximum =
        program(0, vec![VmValueType::Digest; 32], vec![VmValueType::Digest; 16], instructions, 16);
    assert_eq!(
        encode_body(&maximum).expect("maximum structural program encodes").len(),
        VmProgram::MAX_ENCODED_LEN
    );
}

#[test]
fn structural_bounds_and_malformed_program_bytes_are_rejected() {
    assert_eq!(
        VmProgram::new(0, vec![], vec![], vec![VmInstruction::Return { sources: vec![] }], 0),
        Err(VmProgramValidationError::EmptyRegisters)
    );
    assert_eq!(
        VmProgram::new(0, vec![VmValueType::U64], vec![], vec![], 0),
        Err(VmProgramValidationError::EmptyInstructions)
    );
    assert_eq!(
        VmProgram::new(
            17,
            vec![VmValueType::U64; 17],
            vec![],
            vec![VmInstruction::Return { sources: vec![] }],
            0,
        ),
        Err(VmProgramValidationError::TooManyInputs { actual: 17, maximum: 16 })
    );

    let minimal = program(
        0,
        vec![VmValueType::U64],
        vec![],
        vec![VmInstruction::Return { sources: vec![] }],
        0,
    );
    let mut malformed = encode_envelope(&minimal).expect("minimal program encodes");
    malformed[10] = 0xff;
    assert_eq!(
        decode_envelope::<VmProgram>(&malformed),
        Err(DecodeError::InvalidEnumTag { type_name: "VmInstruction", tag: 0xff })
    );

    let mut trailing = encode_envelope(&minimal).expect("minimal program encodes");
    trailing.push(0);
    assert_eq!(
        decode_envelope::<VmProgram>(&trailing),
        Err(DecodeError::TrailingData { remaining: 1 })
    );
}
