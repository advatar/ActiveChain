#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_cash_air::{CashAggregationLeafInputV1, cash_aggregation_journal};
use risc0_zkvm::guest::env;

fn main() {
    let encoded: Vec<u8> = env::read();
    let input: CashAggregationLeafInputV1 =
        decode_envelope(&encoded).expect("canonical recursive cash leaf input");
    let node = input.verify().expect("valid authenticated recursive cash leaf");
    let journal = cash_aggregation_journal(&node).expect("bounded recursive cash leaf journal");
    env::commit_slice(&journal);
}
