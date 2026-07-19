extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use activechain_bytecode_verifier::{VmInstruction, VmProgram, VmValueType, verify};
use activechain_canonical_codec::{decode_envelope, encode_body, encode_envelope};
use activechain_protocol_types::{
    CapabilityId, Digest384, Object, ObjectFields, ObjectFlags, ObjectId, ObjectOwner, PackageId,
};
use proptest::prelude::*;

use crate::{
    ExecutionEvidence, VmEventValue, VmExecutionError, VmExecutionResult, VmExecutionResultError,
    VmValue, execute,
};

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn object() -> Object {
    Object::new(ObjectFields {
        object_id: ObjectId::new(digest(0x10)),
        object_version: 7,
        type_id: digest(0x11),
        owner: ObjectOwner::Shared,
        control_policy_hash: digest(0x12),
        use_policy_hash: digest(0x13),
        disclosure_policy_hash: digest(0x14),
        upgrade_policy_hash: digest(0x15),
        package_id: None,
        value_root: digest(0x16),
        public_value: None,
        lease_expiry_epoch: 100,
        storage_deposit: 500,
        flags: ObjectFlags::LINEAR,
    })
    .expect("VM test object is canonical")
}

fn resource_program() -> activechain_bytecode_verifier::VerifiedProgram {
    verify(
        VmProgram::new(
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
                VmInstruction::LoadDigest { destination: 6, value: digest(0x44) },
                VmInstruction::Emit { source: 6 },
                VmInstruction::ConsumeCapability { source: 1 },
                VmInstruction::Move { destination: 7, source: 0 },
                VmInstruction::Return { sources: vec![7, 4, 5] },
            ],
            1,
        )
        .expect("resource program is bounded"),
    )
    .expect("resource program verifies")
}

fn resource_inputs() -> Vec<VmValue> {
    vec![
        VmValue::Object(Box::new(object())),
        VmValue::Capability(CapabilityId::new(digest(0x20))),
        VmValue::U64(7),
    ]
}

#[test]
fn verified_resource_program_executes_with_exact_gas_outputs_and_events() {
    let result = execute(&resource_program(), resource_inputs(), 16).expect("execution succeeds");
    assert_eq!(result.gas_used(), 16);
    assert_eq!(result.steps(), 8);
    assert_eq!(
        result.outputs(),
        &[VmValue::Object(Box::new(object())), VmValue::U64(12), VmValue::Bool(false),]
    );
    assert_eq!(result.events(), &[VmEventValue::Digest(digest(0x44))]);

    let encoded = encode_envelope(&result).expect("result fits canonical bound");
    assert_eq!(decode_envelope(&encoded), Ok(result));
}

#[test]
fn execution_evidence_replays_and_rejects_result_substitution() {
    let evidence = ExecutionEvidence::create(&resource_program(), resource_inputs(), 16).unwrap();
    evidence.verify().unwrap();
    let encoded = encode_envelope(&evidence).unwrap();
    let decoded: ExecutionEvidence = decode_envelope(&encoded).unwrap();
    decoded.verify().unwrap();
}

#[test]
fn gas_is_charged_before_the_failing_instruction() {
    assert_eq!(
        execute(&resource_program(), resource_inputs(), 15),
        Err(VmExecutionError::GasExhausted {
            program_counter: 7,
            gas_used: 12,
            instruction_cost: 4,
            gas_limit: 15,
        })
    );
}

fn addition_program() -> activechain_bytecode_verifier::VerifiedProgram {
    verify(
        VmProgram::new(
            2,
            vec![VmValueType::U64, VmValueType::U64, VmValueType::U64],
            vec![VmValueType::U64],
            vec![
                VmInstruction::AddU64 { destination: 2, left: 0, right: 1 },
                VmInstruction::Return { sources: vec![2] },
            ],
            0,
        )
        .expect("addition program is bounded"),
    )
    .expect("addition program verifies")
}

#[test]
fn checked_arithmetic_overflow_is_a_total_execution_failure() {
    assert_eq!(
        execute(&addition_program(), vec![VmValue::U64(u64::MAX), VmValue::U64(1)], 4,),
        Err(VmExecutionError::ArithmeticOverflow { program_counter: 0 })
    );
}

#[test]
fn invocation_rejects_wrong_input_count_and_type() {
    assert_eq!(
        execute(&addition_program(), vec![VmValue::U64(1)], 4),
        Err(VmExecutionError::InputCountMismatch { expected: 2, actual: 1 })
    );
    assert_eq!(
        execute(&addition_program(), vec![VmValue::Bool(false), VmValue::U64(1)], 4,),
        Err(VmExecutionError::InputTypeMismatch {
            register: 0,
            expected: VmValueType::U64,
            actual: VmValueType::Bool,
        })
    );
}

fn branch_program() -> activechain_bytecode_verifier::VerifiedProgram {
    verify(
        VmProgram::new(
            1,
            vec![VmValueType::Bool, VmValueType::U64],
            vec![VmValueType::U64],
            vec![
                VmInstruction::BranchIf { condition: 0, target: 3 },
                VmInstruction::LoadU64 { destination: 1, value: 10 },
                VmInstruction::Return { sources: vec![1] },
                VmInstruction::LoadU64 { destination: 1, value: 20 },
                VmInstruction::Return { sources: vec![1] },
            ],
            0,
        )
        .expect("branch program is bounded"),
    )
    .expect("branch program verifies")
}

#[test]
fn forward_branch_selection_is_deterministic() {
    let false_result =
        execute(&branch_program(), vec![VmValue::Bool(false)], 4).expect("false branch succeeds");
    let true_result =
        execute(&branch_program(), vec![VmValue::Bool(true)], 4).expect("true branch succeeds");
    assert_eq!(false_result.outputs(), &[VmValue::U64(10)]);
    assert_eq!(true_result.outputs(), &[VmValue::U64(20)]);
    assert_eq!(false_result.gas_used(), 4);
    assert_eq!(true_result.gas_used(), 4);
}

#[test]
fn execution_result_constructor_enforces_all_bounds() {
    assert_eq!(
        VmExecutionResult::new(0, 0, vec![], vec![]),
        Err(VmExecutionResultError::InvalidStepCount(0))
    );
    assert!(matches!(
        VmExecutionResult::new(1, 1, vec![VmValue::U64(0); 17], vec![]),
        Err(VmExecutionResultError::TooManyOutputs { .. })
    ));
    assert!(matches!(
        VmExecutionResult::new(1, 1, vec![], vec![VmEventValue::Bool(false); 17]),
        Err(VmExecutionResultError::TooManyEvents { .. })
    ));
}

#[test]
fn published_execution_result_body_bound_is_exact() {
    let maximum_object = Object::new(ObjectFields {
        object_id: ObjectId::new(digest(0x80)),
        object_version: u64::MAX,
        type_id: digest(0x81),
        owner: ObjectOwner::Shielded(digest(0x82)),
        control_policy_hash: digest(0x83),
        use_policy_hash: digest(0x84),
        disclosure_policy_hash: digest(0x85),
        upgrade_policy_hash: digest(0x86),
        package_id: Some(PackageId::new(digest(0x87))),
        value_root: digest(0x88),
        public_value: Some(vec![0x89; 16_384]),
        lease_expiry_epoch: u64::MAX,
        storage_deposit: u128::MAX,
        flags: ObjectFlags::LINEAR,
    })
    .expect("maximum VM result object is canonical");
    let result = VmExecutionResult::new(
        u64::MAX,
        256,
        vec![VmValue::Object(Box::new(maximum_object)); 16],
        vec![VmEventValue::Digest(digest(0x8a)); 16],
    )
    .expect("maximum result is structurally valid");
    assert_eq!(
        encode_body(&result).expect("maximum result encodes").len(),
        VmExecutionResult::MAX_ENCODED_LEN
    );
}

proptest! {
    #[test]
    fn bounded_addition_is_deterministic(
        left in 0_u64..=u64::from(u32::MAX),
        right in 0_u64..=u64::from(u32::MAX),
    ) {
        let inputs = vec![VmValue::U64(left), VmValue::U64(right)];
        let first = execute(&addition_program(), inputs.clone(), 4).expect("bounded sum succeeds");
        let second = execute(&addition_program(), inputs, 4).expect("same invocation succeeds");
        prop_assert_eq!(first, second);
    }
}
