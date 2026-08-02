#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_cash_air::{
    CashAggregationLevel, CashAggregationNodeV1, CashAggregationStatementV1,
    cash_aggregation_journal, recursive_cash_child_journals,
};
use risc0_zkvm::guest::env;

const CHILD_IMAGE_ID: [u32; 8] = [
    4_173_216_735,
    4_278_302_057,
    3_639_145_799,
    3_704_809_677,
    2_103_831_577,
    4_132_460_347,
    3_878_950_527,
    2_023_297_161,
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
