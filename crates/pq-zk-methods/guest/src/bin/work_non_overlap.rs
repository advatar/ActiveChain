#![forbid(unsafe_code)]
use activechain_canonical_codec::decode_envelope;
use activechain_work_proof::{WorkClaimRelationInputV1, public_journal, verify_relation};
use risc0_zkvm::guest::env;
fn main() { let encoded: Vec<u8> = env::read(); let input: WorkClaimRelationInputV1 = decode_envelope(&encoded).expect("canonical work relation"); verify_relation(&input).expect("valid non-overlap relation"); env::commit_slice(&public_journal(&input.public).expect("bounded work journal")); }
