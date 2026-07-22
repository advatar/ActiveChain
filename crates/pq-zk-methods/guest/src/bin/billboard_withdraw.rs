#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_private_billboard::{BillboardVerifier, WithdrawalRelationInput};
use risc0_zkvm::guest::env;

const JOURNAL_DOMAIN: &[u8] = b"ACTIVECHAIN-BILLBOARD-WITHDRAW-RISC0-STARK-V1";

fn main() {
    let encoded: Vec<u8> = env::read();
    let input: WithdrawalRelationInput =
        decode_envelope(&encoded).expect("canonical withdrawal relation");
    let proof = BillboardVerifier::verify_withdrawal(
        input.config,
        input.public,
        &input.witness,
        &input.decisions,
    )
    .expect("valid private billboard withdrawal relation");
    env::commit_slice(JOURNAL_DOMAIN);
    env::commit_slice(proof.public_inputs_commitment().as_bytes());
    env::commit_slice(proof.permit_commitment().as_bytes());
}
