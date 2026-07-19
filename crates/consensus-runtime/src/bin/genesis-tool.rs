//! Reproducible local-testnet genesis manifest generator.

use activechain_canonical_codec::encode_envelope;
use activechain_protocol_types::{
    Digest384, ML_DSA44_PUBLIC_KEY_LENGTH, PrincipalId, ValidatorGenesis, ValidatorGenesisEntry,
};
use ml_dsa::{Keypair, MlDsa44, Seed, SigningKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let output = args.next().ok_or(
        "usage: genesis-tool <output> <epoch> <activation-height> <validator-count> [stake]",
    )?;
    let epoch: u64 = args.next().ok_or("missing epoch")?.parse()?;
    let activation_height: u64 = args.next().ok_or("missing activation height")?.parse()?;
    let count: usize = args.next().ok_or("missing validator count")?.parse()?;
    let stake: u128 = args.next().unwrap_or_else(|| "1".to_owned()).parse()?;
    if count == 0 || count > activechain_protocol_types::MAX_VALIDATORS_PER_EPOCH || stake == 0 {
        return Err("invalid validator count or stake".into());
    }
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let mut seed = [0_u8; 32];
        seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
        seed[8..16].copy_from_slice(&epoch.to_be_bytes());
        seed[16..24].copy_from_slice(&activation_height.to_be_bytes());
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from(seed));
        let mut id_bytes = [0_u8; 48];
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-TESTNET-VALIDATOR-ID-V1");
        hasher.update(&seed);
        hasher.finalize_xof().read(&mut id_bytes);
        let public_key: [u8; ML_DSA44_PUBLIC_KEY_LENGTH] = key
            .verifying_key()
            .encode()
            .as_slice()
            .try_into()
            .map_err(|_| "invalid ML-DSA public key length")?;
        entries.push(
            ValidatorGenesisEntry::new(
                PrincipalId::new(Digest384::new(id_bytes)),
                stake,
                public_key,
            )
            .map_err(|error| format!("invalid validator entry: {error:?}"))?,
        );
    }
    entries.sort_by_key(|entry| entry.validator());
    let genesis = ValidatorGenesis::new(epoch, activation_height, entries)
        .map_err(|error| format!("invalid genesis: {error:?}"))?;
    fs::write(
        Path::new(&output),
        encode_envelope(&genesis).map_err(|error| format!("genesis encoding failed: {error:?}"))?,
    )?;
    println!(
        "wrote {} validators at epoch {} activation {} root {:02x?}",
        count,
        epoch,
        activation_height,
        genesis.validator_set_root().as_bytes()
    );
    Ok(())
}
