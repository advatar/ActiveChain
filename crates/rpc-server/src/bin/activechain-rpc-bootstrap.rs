use activechain_canonical_codec::decode_envelope;
use activechain_protocol_types::{ChainId, Digest384, ValidatorGenesis};
use activechain_rpc_server::{DurableRpcStore, RpcIndex};
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let genesis_path = PathBuf::from(arguments.next().ok_or(
        "usage: activechain-rpc-bootstrap <genesis-manifest> <chain-id-hex> \
         <rpc-index-snapshot> [maximum-staleness-seconds]",
    )?);
    let chain_id = parse_chain_id(&arguments.next().ok_or("missing chain ID")?)?;
    let snapshot_path = PathBuf::from(arguments.next().ok_or("missing RPC index snapshot")?);
    let maximum_staleness_seconds =
        arguments.next().unwrap_or_else(|| "300".to_owned()).parse::<u64>()?;
    if maximum_staleness_seconds == 0 || arguments.next().is_some() {
        return Err("invalid maximum staleness or unexpected argument".into());
    }
    if snapshot_path.exists() {
        return Err(format!("RPC index already exists: {}", snapshot_path.display()).into());
    }

    let genesis = load_genesis(&genesis_path)?;
    let finalized_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let index = RpcIndex::new(
        chain_id,
        genesis.genesis_commitment(),
        genesis.protocol_revision(),
        0,
        finalized_at,
        maximum_staleness_seconds,
        Vec::new(),
        Vec::new(),
    )
    .map_err(|error| format!("invalid bootstrap RPC index: {error:?}"))?;
    DurableRpcStore::create(snapshot_path.clone(), index)
        .map_err(|error| format!("could not persist RPC index: {error:?}"))?;
    println!(
        "created RPC index {} for chain {} genesis {}",
        snapshot_path.display(),
        encode_hex(chain_id.digest().as_bytes()),
        encode_hex(genesis.genesis_commitment().as_bytes())
    );
    Ok(())
}

fn load_genesis(path: &Path) -> Result<ValidatorGenesis, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    decode_envelope(&bytes).map_err(|error| format!("invalid genesis manifest: {error:?}").into())
}

fn parse_chain_id(value: &str) -> Result<ChainId, Box<dyn std::error::Error>> {
    if value.len() != 96 {
        return Err("chain ID must be exactly 48 bytes of lowercase hexadecimal".into());
    }
    let mut bytes = [0_u8; 48];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)?;
        if pair.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err("chain ID must use lowercase hexadecimal".into());
        }
        bytes[index] = u8::from_str_radix(pair, 16)?;
    }
    let digest = Digest384::new(bytes);
    if digest == Digest384::ZERO {
        return Err("chain ID must not be zero".into());
    }
    Ok(ChainId::new(digest))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{encode_hex, parse_chain_id};

    #[test]
    fn accepts_exact_nonzero_lowercase_chain_id() {
        let encoded = "01".repeat(48);
        let chain_id = parse_chain_id(&encoded).unwrap();
        assert_eq!(encode_hex(chain_id.digest().as_bytes()), encoded);
    }

    #[test]
    fn rejects_zero_wrong_length_and_uppercase_chain_ids() {
        assert!(parse_chain_id(&"00".repeat(48)).is_err());
        assert!(parse_chain_id("01").is_err());
        assert!(parse_chain_id(&"AB".repeat(48)).is_err());
    }
}
