#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_cash_air::{
    CashAggregationLevel, CashAggregationNodeV1, CashAggregationStatementV1,
    cash_aggregation_journal, recursive_cash_child_journals,
};
use risc0_zkvm::guest::env;

const CHILD_IMAGE_ID: [u32; 8] = [
    505_211_415,
    1_568_707_832,
    2_152_948_109,
    4_089_280_842,
    2_421_805_915,
    2_095_107_498,
    853_422_456,
    3_257_453_624,
];

fn main() {
    let encoded: Vec<u8> = env::read();
    let statement: CashAggregationStatementV1 =
        decode_envelope(&encoded).expect("canonical recursive cash partition statement");
    let child_journals =
        recursive_cash_child_journals(&statement, CashAggregationLevel::Partition, &CHILD_IMAGE_ID)
            .expect("valid recursive cash partition statement");
    for journal in child_journals {
        env::verify(CHILD_IMAGE_ID, journal.as_slice()).expect("verified cash microbatch");
    }
    let node = CashAggregationNodeV1::from_statement(&statement);
    let journal = cash_aggregation_journal(&node).expect("bounded recursive cash journal");
    env::commit_slice(&journal);
}
