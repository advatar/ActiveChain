//! Secure validator-key and genesis manifest generator.

use activechain_canonical_codec::encode_envelope;
use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
use std::{env, fs, io::Write, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let output = args.next().ok_or(
        "usage: genesis-tool <output> <epoch> <activation-height> <validator-count> <key-directory> [stake]",
    )?;
    let epoch: u64 = args.next().ok_or("missing epoch")?.parse()?;
    let activation_height: u64 = args.next().ok_or("missing activation height")?.parse()?;
    let count: usize = args.next().ok_or("missing validator count")?.parse()?;
    let key_directory = args.next().ok_or("missing validator key directory")?;
    let stake: u128 = args.next().unwrap_or_else(|| "1".to_owned()).parse()?;
    if count == 0 || count > activechain_protocol_types::MAX_VALIDATORS_PER_EPOCH || stake == 0 {
        return Err("invalid validator count or stake".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&key_directory)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(&key_directory)?;

    let mut provisioned = Vec::with_capacity(count);
    for index in 0..count {
        let temporary = Path::new(&key_directory).join(format!(".unsorted-{index}.key"));
        let (validator, public_key) =
            activechain_consensus_runtime::provision_validator_key(&temporary)?;
        let public_key =
            public_key.as_slice().try_into().map_err(|_| "invalid ML-DSA public key length")?;
        let entry = ValidatorGenesisEntry::new(validator, stake, public_key)
            .map_err(|error| format!("invalid validator entry: {error:?}"))?;
        provisioned.push((entry, temporary));
    }
    provisioned.sort_by_key(|(entry, _)| entry.validator());
    let mut entries = Vec::with_capacity(count);
    for (index, (entry, temporary)) in provisioned.into_iter().enumerate() {
        fs::rename(temporary, Path::new(&key_directory).join(format!("validator-{index}.key")))?;
        entries.push(entry);
    }
    let genesis = ValidatorGenesis::new(epoch, activation_height, entries)
        .map_err(|error| format!("invalid genesis: {error:?}"))?;
    let bytes =
        encode_envelope(&genesis).map_err(|error| format!("genesis encoding failed: {error:?}"))?;
    let mut output_file =
        fs::OpenOptions::new().write(true).create_new(true).open(Path::new(&output))?;
    output_file.write_all(&bytes)?;
    output_file.sync_all()?;
    let genesis_commitment = genesis.genesis_commitment();
    let commitment_hex =
        genesis_commitment.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("genesis_commitment={commitment_hex}");
    println!(
        "wrote {} validators at epoch {} activation {} root {:02x?}",
        count,
        epoch,
        activation_height,
        genesis.validator_set_root().as_bytes()
    );
    Ok(())
}
