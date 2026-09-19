#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_private_billboard::{BillboardVerifier, PostRelationInputV2};
use risc0_zkvm::guest::env;

const JOURNAL_DOMAIN: &[u8] = b"ACTIVECHAIN-EMERALD-POST-RISC0-STARK-V2";

fn main() {
    let encoded: Vec<u8> = env::read();
    let input: PostRelationInputV2 =
        decode_envelope(&encoded).expect("canonical Emerald post v2 relation");
    let proof = BillboardVerifier::verify_post_v2(
        input.config,
        &input.public,
        &input.witness,
        &input.decisions,
    )
    .expect("valid Emerald private post v2 relation");
    env::commit_slice(JOURNAL_DOMAIN);
    env::commit_slice(proof.public_inputs_commitment().as_bytes());
    env::commit_slice(proof.nullifier().as_bytes());
}
