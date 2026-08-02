#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_cash_air::{
    CashAggregationLevel, CashAggregationNodeV1, CashAggregationStatementV1,
    cash_aggregation_journal, recursive_cash_child_journals,
};
use risc0_zkvm::guest::env;

const CHILD_IMAGE_ID: [u32; 8] = [
    3_754_611_624,
    1_570_809_914,
    2_115_629_729,
    2_247_806_748,
    1_870_143_348,
    317_544_254,
    2_570_299_082,
    3_824_171_377,
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
