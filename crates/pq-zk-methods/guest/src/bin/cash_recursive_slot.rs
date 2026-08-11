#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_cash_air::{
    CashAggregationLevel, CashAggregationNodeV1, CashAggregationStatementV1,
    cash_aggregation_journal, recursive_cash_child_journals,
};
use risc0_zkvm::guest::env;

const CHILD_IMAGE_ID: [u32; 8] = [
    680_530_904,
    3_526_479_120,
    2_356_346_960,
    4_005_243_480,
    3_011_874_599,
    3_977_522_463,
    3_231_022_324,
    2_568_690_237,
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
