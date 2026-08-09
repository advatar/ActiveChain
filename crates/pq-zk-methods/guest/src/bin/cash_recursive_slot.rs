#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_cash_air::{
    CashAggregationLevel, CashAggregationNodeV1, CashAggregationStatementV1,
    cash_aggregation_journal, recursive_cash_child_journals,
};
use risc0_zkvm::guest::env;

const CHILD_IMAGE_ID: [u32; 8] = [
    387_383_635,
    3_853_526_580,
    1_366_600_641,
    2_486_919_890,
    2_140_127_208,
    3_482_827_727,
    773_474_270,
    1_134_606_913,
];

fn main() {
    let encoded: Vec<u8> = env::read();
    let statement: CashAggregationStatementV1 =
        decode_envelope(&encoded).expect("canonical recursive cash-slot statement");
    let child_journals =
        recursive_cash_child_journals(&statement, CashAggregationLevel::CashSlot, &CHILD_IMAGE_ID)
            .expect("valid recursive cash-slot statement");
    for journal in child_journals {
        env::verify(CHILD_IMAGE_ID, journal.as_slice()).expect("verified cash partition");
    }
    let node = CashAggregationNodeV1::from_statement(&statement);
    let journal = cash_aggregation_journal(&node).expect("bounded recursive cash journal");
    env::commit_slice(&journal);
}
