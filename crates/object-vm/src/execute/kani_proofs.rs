//! Bounded Kani proofs for private production ObjectVM semantic helpers.
//!
//! Public callers still enter through `execute(&VerifiedProgram, ...)`. These harnesses check the
//! exact gas, arithmetic, and branch helpers called by the private interpreter without replacing
//! them with a model or expanding its allocation-heavy dispatch loop in the same solver query.

use activechain_bytecode_verifier::MAX_VM_INSTRUCTIONS;

use super::{checked_add, prepay_gas, select_branch_target};
use crate::VmExecutionError;

#[kani::proof]
fn prepaid_gas_refines_checked_addition_and_the_limit_for_all_u64_values() {
    let program_counter: usize = kani::any();
    let gas_used: u64 = kani::any();
    let instruction_cost: u64 = kani::any();
    let gas_limit: u64 = kani::any();
    kani::assume(program_counter < MAX_VM_INSTRUCTIONS);

    let result = prepay_gas(program_counter, gas_used, instruction_cost, gas_limit);
    match gas_used.checked_add(instruction_cost) {
        Some(next_gas) if next_gas <= gas_limit => assert_eq!(result, Ok(next_gas)),
        _ => assert_eq!(
            result,
            Err(VmExecutionError::GasExhausted {
                program_counter,
                gas_used,
                instruction_cost,
                gas_limit,
            })
        ),
    }
}

#[kani::proof]
fn checked_addition_refines_an_overflowing_add_oracle_for_all_u64_values() {
    let program_counter: usize = kani::any();
    let left: u64 = kani::any();
    let right: u64 = kani::any();
    kani::assume(program_counter < MAX_VM_INSTRUCTIONS);

    let result = checked_add(program_counter, left, right);
    let (sum, overflowed) = left.overflowing_add(right);
    if overflowed {
        assert_eq!(result, Err(VmExecutionError::ArithmeticOverflow { program_counter }));
    } else {
        assert_eq!(result, Ok(sum));
    }
}

#[kani::proof]
fn branch_selection_refines_the_boolean_oracle_under_protocol_bounds() {
    let program_counter: usize = kani::any();
    let condition: bool = kani::any();
    let target: u16 = kani::any();
    kani::assume(program_counter < MAX_VM_INSTRUCTIONS);
    kani::assume(usize::from(target) < MAX_VM_INSTRUCTIONS);

    let selected = select_branch_target(program_counter, condition, target);
    assert_eq!(selected, if condition { usize::from(target) } else { program_counter + 1 });
}

#[kani::proof]
fn verifier_valid_branch_edges_remain_strictly_forward_and_in_bounds() {
    let program_counter: usize = kani::any();
    let condition: bool = kani::any();
    let target: u16 = kani::any();
    let target = usize::from(target);
    kani::assume(program_counter < MAX_VM_INSTRUCTIONS - 1);
    kani::assume(program_counter < target);
    kani::assume(target < MAX_VM_INSTRUCTIONS);

    let selected = select_branch_target(program_counter, condition, target as u16);
    assert!(selected > program_counter);
    assert!(selected < MAX_VM_INSTRUCTIONS);
    if condition {
        assert_eq!(selected, target);
    } else {
        assert_eq!(selected, program_counter + 1);
    }
}
