use ml_dsa::{Keypair, MlDsa44, Seed, SigningKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::env;

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [TABLE[(byte >> 4) as usize] as char, TABLE[(byte & 0x0f) as usize] as char]
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or("usage: activechain-wallet derive <index> <epoch> <activation-height>")?;
    if command != "derive" {
        return Err("only the derive command is available in the testnet POC".into());
    }
    let index: u64 = args.next().ok_or("missing index")?.parse()?;
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
    let mut principal = [0_u8; 48];
    let mut shake = Shake256::default();
    shake.update(b"ACTIVECHAIN-TESTNET-WALLET-ID-V1");
    shake.update(&seed);
    shake.finalize_xof().read(&mut principal);
    println!("suite=ML_DSA_44");
    println!("principal_id={}", hex(&principal));
    println!("public_key={}", hex(public_key.as_slice()));
    println!("key_material=store-encrypted-seed-out-of-band");
    Ok(())
}
