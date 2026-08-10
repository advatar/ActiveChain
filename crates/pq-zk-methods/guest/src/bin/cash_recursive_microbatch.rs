#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_cash_air::{
    CashAggregationLevel, CashAggregationNodeV1, CashAggregationStatementV1,
    cash_aggregation_journal, recursive_cash_child_journals,
};
use risc0_zkvm::guest::env;

const CHILD_IMAGE_ID: [u32; 8] = [
    3_975_139_043,
    4_289_215_438,
    555_673_819,
    1_250_836_547,
    3_018_087_756,
    896_731_760,
    1_300_409_873,
    1_349_542_459,
];

fn main() {
    let encoded: Vec<u8> = env::read();
    let statement: CashAggregationStatementV1 =
        decode_envelope(&encoded).expect("canonical recursive cash microbatch statement");
    let child_journals =
        recursive_cash_child_journals(&statement, CashAggregationLevel::Microbatch, &CHILD_IMAGE_ID)
            .expect("valid recursive cash microbatch statement");
    for journal in child_journals {
        env::verify(CHILD_IMAGE_ID, journal.as_slice()).expect("verified recursive cash leaf");
    }
    let node = CashAggregationNodeV1::from_statement(&statement);
    let journal = cash_aggregation_journal(&node).expect("bounded recursive cash journal");
    env::commit_slice(&journal);
}
