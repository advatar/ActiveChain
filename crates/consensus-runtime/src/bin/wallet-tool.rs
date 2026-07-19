//! Deterministic post-quantum wallet identity generator for local testnet use.
use ml_dsa::{Keypair, MlDsa44, Seed, SigningKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::env;

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let index: u64 =
        args.next().ok_or("usage: wallet-tool <index> <epoch> <activation-height>")?.parse()?;
    let epoch: u64 = args.next().ok_or("missing epoch")?.parse()?;
    let activation: u64 = args.next().ok_or("missing activation height")?.parse()?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let mut seed = [0_u8; 32];
    seed[..8].copy_from_slice(&index.to_be_bytes());
    seed[8..16].copy_from_slice(&epoch.to_be_bytes());
    seed[16..24].copy_from_slice(&activation.to_be_bytes());
    let key = SigningKey::<MlDsa44>::from_seed(&Seed::from(seed));
    let public_key = key.verifying_key().encode();
    let mut id_bytes = [0_u8; 48];
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-TESTNET-WALLET-ID-V1");
    hasher.update(&seed);
    hasher.finalize_xof().read(&mut id_bytes);
    println!("suite=ML_DSA_44");
    println!("principal_id={}", hex(&id_bytes));
    println!("public_key={}", hex(public_key.as_slice()));
    Ok(())
}
