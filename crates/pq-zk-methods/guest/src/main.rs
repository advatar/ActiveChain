#![forbid(unsafe_code)]

use risc0_zkvm::guest::env;
use sha3::{Digest, Sha3_256};

const PROFILE_ID: &[u8] = b"ACTIVECHAIN-PQ-ZK-RISC0-STARK-V1";

fn main() {
    let secret: Vec<u8> = env::read();
    let digest = Sha3_256::digest(&secret);
    env::commit_slice(PROFILE_ID);
    env::commit_slice(&digest);
}
