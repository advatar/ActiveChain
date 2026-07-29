use ml_dsa::{Keypair, MlDsa44, Seed, SigningKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{env, io::Write as _, path::Path};
use zeroize::Zeroize as _;

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
    let command = args.next().ok_or("usage: activechain-wallet derive <new-key-file>")?;
    if command != "derive" {
        return Err("only the derive command is available in the testnet POC".into());
    }
    let key_file = args.next().ok_or("missing new key file")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|_| "operating-system randomness unavailable")?;
    let key = SigningKey::<MlDsa44>::from_seed(&Seed::from(seed));
    let public_key = key.verifying_key().encode();
    let mut principal = [0_u8; 48];
    let mut shake = Shake256::default();
    shake.update(b"ACTIVECHAIN-WALLET-PUBLIC-KEY-ID-V1");
    shake.update(public_key.as_slice());
    shake.finalize_xof().read(&mut principal);
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(Path::new(&key_file))?
    };
    #[cfg(not(unix))]
    let mut file =
        std::fs::OpenOptions::new().write(true).create_new(true).open(Path::new(&key_file))?;
    file.write_all(b"ACWKEY01")?;
    file.write_all(&seed)?;
    file.sync_all()?;
    seed.zeroize();
    println!("suite=ML_DSA_44");
    println!("principal_id={}", hex(&principal));
    println!("public_key={}", hex(public_key.as_slice()));
    println!("key_file={key_file}");
    Ok(())
}
