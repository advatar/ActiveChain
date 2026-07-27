use winterfell::{BatchingMethod, FieldExtension, ProofOptions};

use crate::hash::boundary_hash;
use crate::model::MAX_ACTIONS;

pub const PROTOCOL_VERSION: u32 = 1;
pub const VERIFIER_VERSION: u32 = 1;
pub const SUITE_ID: u32 = 0x0006_0001;
pub const RECEIPT_KIND_EXECUTION: u16 = 1;
pub const RECEIPT_CODEC_VERSION: u16 = 1;

pub const NUM_QUERIES: usize = 48;
pub const BLOWUP_FACTOR: usize = 8;
pub const GRINDING_BITS: u32 = 16;
pub const FRI_FOLDING_FACTOR: usize = 8;
pub const FRI_REMAINDER_MAX_DEGREE: usize = 31;
pub const MIN_CONJECTURED_SOUNDNESS_BITS: u32 = 100;

pub const MAX_PROOF_BYTES: usize = 131_072;
pub const MAX_PUBLIC_INPUT_BYTES: usize = 20_000;
pub const MAX_RECEIPT_BYTES: usize = 160_000;
pub const MAX_TRACE_LENGTH: usize = 2048;
pub const TRACE_WIDTH: usize = 3;

pub const AIR_MANIFEST: &str = concat!(
    "P060-ACCUMULATOR-AIR-v1;",
    "field=2^64-2^32+1;",
    "columns=state,opcode,operand;",
    "opcodes=add:0,mul:1;",
    "padding=add(0);",
    "max_actions=1024;",
    "transition=op_boolean_and_selected_add_mul"
);

pub fn program_id() -> [u8; 48] {
    boundary_hash(b"air-program", AIR_MANIFEST.as_bytes())
}

pub fn proof_options() -> ProofOptions {
    ProofOptions::new(
        NUM_QUERIES,
        BLOWUP_FACTOR,
        GRINDING_BITS,
        FieldExtension::Quadratic,
        FRI_FOLDING_FACTOR,
        FRI_REMAINDER_MAX_DEGREE,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub fn trace_length(action_count: usize) -> usize {
    debug_assert!(action_count <= MAX_ACTIONS);
    (action_count + 1).max(8).next_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_trace_is_bounded() {
        assert_eq!(2048, trace_length(MAX_ACTIONS));
        assert_eq!(8, trace_length(0));
        assert!(trace_length(MAX_ACTIONS) <= MAX_TRACE_LENGTH);
    }
}
