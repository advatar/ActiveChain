#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_privacy_kernel::{ProofOfFundsRelationInputV1, witness_satisfies};
use risc0_zkvm::guest::env;

const JOURNAL_DOMAIN: &[u8] = b"ACTIVECHAIN-PROOF-OF-FUNDS-RISC0-STARK-V1";

fn main() {
    let encoded: Vec<u8> = env::read();
    let input: ProofOfFundsRelationInputV1 =
        decode_envelope(&encoded).expect("canonical proof-of-funds relation");
    witness_satisfies(input.public.predicate, input.witness)
        .expect("valid proof-of-funds relation");
    env::commit_slice(JOURNAL_DOMAIN);
    env::commit_slice(input.public.commitment().expect("bounded public inputs").as_bytes());
    env::commit_slice(input.public.predicate.nonce().as_bytes());
}
