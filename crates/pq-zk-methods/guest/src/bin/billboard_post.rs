#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_private_billboard::{BillboardVerifier, PostRelationInput};
use risc0_zkvm::guest::env;

const JOURNAL_DOMAIN: &[u8] = b"ACTIVECHAIN-BILLBOARD-POST-RISC0-STARK-V1";

fn main() {
    let encoded: Vec<u8> = env::read();
    let input: PostRelationInput = decode_envelope(&encoded).expect("canonical post relation");
    let proof = BillboardVerifier::verify_post(
        input.config,
        &input.public,
        &input.witness,
        &input.decisions,
    )
    .expect("valid private billboard post relation");
    env::commit_slice(JOURNAL_DOMAIN);
    env::commit_slice(proof.public_inputs_commitment().as_bytes());
    env::commit_slice(proof.permit_commitment().as_bytes());
}
