//! Generates one offline ML-DSA-44 trust signer.
//!
//! Run this only on the machine that will hold the signer, and never on a
//! verifier host. The secret output is the 32-byte seed; the public output is
//! the hex key that goes into a signer set.

use activechain_trust_ceremony::{SignerSeed, derive_signer_id, encode_hex};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write as _,
    path::Path,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let secret_path = arguments.next().ok_or("usage: actum-trust-keygen <secret> <public>")?;
    let public_path = arguments.next().ok_or("public output path is required")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let secret_path = Path::new(&secret_path);
    let public_path = Path::new(&public_path);
    if secret_path.exists() || public_path.exists() {
        return Err("refusing to overwrite existing signer material".into());
    }

    let seed = SignerSeed::generate()?;
    let public_key = seed.public_key();
    let signer_id = derive_signer_id(&public_key)?;

    write_private(secret_path, seed.expose())?;
    fs::write(public_path, format!("{}\n", encode_hex(&public_key)))?;

    println!("signer_id {}", encode_hex(signer_id.as_bytes()));
    println!("public_key {}", public_path.display());
    println!("secret_seed {} (mode 0600, keep offline)", secret_path.display());
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
