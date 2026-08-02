//! Minimal deterministic finalized-state indexer for local testnet operations.
use activechain_consensus_runtime::{
    PERSISTED_VALIDATOR_STATE_SCHEMA_VERSION, PERSISTED_VALIDATOR_STATE_TYPE_TAG, load_snapshot,
    load_snapshot_chain_genesis_commitment,
};
use activechain_devnet_kernel::ChainState;
use std::{env, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let first = args.next().ok_or("usage: indexer-tool [--execution] <snapshot>")?;
    let execution = first == "--execution";
    let path =
        if execution { args.next().ok_or("execution snapshot path is missing")? } else { first };
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    if execution {
        let bytes = std::fs::read(&path)?;
        if bytes.len() < 4 {
            return Err("execution snapshot envelope is truncated".into());
        }
        let source_schema = u16::from_be_bytes([bytes[2], bytes[3]]);
        let (state, migration_required) = ChainState::decode_snapshot(&bytes, Vec::new())
            .map_err(|error| format!("execution snapshot decoding failed: {error:?}"))?;
        println!(
            "{{\"snapshot_type\":\"execution\",\"source_schema_version\":{},\"target_schema_version\":{},\"migration_required\":{},\"chain_id\":\"{}\",\"height\":{},\"head_block_id\":\"{}\"}}",
            source_schema,
            <ChainState as activechain_canonical_codec::CanonicalType>::SCHEMA_VERSION,
            migration_required,
            hex(state.chain_id().digest().as_bytes()),
            state.height(),
            hex(state.head_block_id().as_bytes()),
        );
        return Ok(());
    }
    let state = load_snapshot(Path::new(&path))?;
    let genesis = load_snapshot_chain_genesis_commitment(Path::new(&path))?
        .ok_or("snapshot has no immutable genesis commitment")?;
    let genesis_hex: String = genesis.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
    println!(
        "{{\"snapshot_type_tag\":{},\"snapshot_schema_version\":{},\"genesis_commitment\":\"{}\",\"epoch\":{},\"finalized_height\":{},\"finalized_round\":{},\"validator_set_root\":\"{:02x?}\"}}",
        PERSISTED_VALIDATOR_STATE_TYPE_TAG,
        PERSISTED_VALIDATOR_STATE_SCHEMA_VERSION,
        genesis_hex,
        state.epoch(),
        state.finalized_height(),
        state.finalized_round(),
        state.validator_set_root().as_bytes(),
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
