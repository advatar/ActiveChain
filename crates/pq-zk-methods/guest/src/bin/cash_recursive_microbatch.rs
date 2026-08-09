#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_cash_air::{
    CashAggregationLevel, CashAggregationNodeV1, CashAggregationStatementV1,
    cash_aggregation_journal, recursive_cash_child_journals,
};
use risc0_zkvm::guest::env;

const CHILD_IMAGE_ID: [u32; 8] = [
    167_784_142,
    3_538_011_993,
    3_632_903_056,
    2_926_400_057,
    3_289_900_018,
    96_239_202,
    1_803_838_409,
    2_186_720_516,
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
