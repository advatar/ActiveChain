#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_cash_air::{
    CashAggregationLevel, CashAggregationNodeV1, CashAggregationStatementV1,
    cash_aggregation_journal, recursive_cash_child_journals,
};
use risc0_zkvm::guest::env;

const CHILD_IMAGE_ID: [u32; 8] = [
    4_283_046_316,
    568_441_792,
    3_544_329_019,
    336_699_584,
    1_475_267_648,
    3_460_557_324,
    3_085_274_318,
    3_332_276_344,
];

fn main() {
    let encoded: Vec<u8> = env::read();
    let statement: CashAggregationStatementV1 =
        decode_envelope(&encoded).expect("canonical recursive global cash statement");
    let child_journals = recursive_cash_child_journals(
        &statement,
        CashAggregationLevel::GlobalTransition,
        &CHILD_IMAGE_ID,
    )
    .expect("valid recursive global cash statement");
    for journal in child_journals {
        env::verify(CHILD_IMAGE_ID, journal.as_slice()).expect("verified cash-slot transition");
    }
    let node = CashAggregationNodeV1::from_statement(&statement);
    let journal = cash_aggregation_journal(&node).expect("bounded recursive cash journal");
    env::commit_slice(&journal);
}
