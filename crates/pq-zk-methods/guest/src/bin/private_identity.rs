#![forbid(unsafe_code)]

use activechain_canonical_codec::decode_envelope;
use activechain_privacy_kernel::{PrivateIdentityRelationInputV1, verify_private_identity_relation};
use risc0_zkvm::guest::env;

const JOURNAL_DOMAIN: &[u8] = b"ACTIVECHAIN-PRIVATE-IDENTITY-RISC0-STARK-V1";
fn main() {
    let encoded: Vec<u8> = env::read();
    let input: PrivateIdentityRelationInputV1 = decode_envelope(&encoded).expect("canonical private identity relation");
    verify_private_identity_relation(&input).expect("valid private identity relation");
    env::commit_slice(JOURNAL_DOMAIN);
    env::commit_slice(input.public.commitment().expect("bounded public inputs").as_bytes());
    env::commit_slice(input.public.nonce.as_bytes());
}
