//! Minimal deterministic finalized-state indexer for local testnet operations.
use activechain_consensus_runtime::{
    PERSISTED_VALIDATOR_STATE_SCHEMA_VERSION, PERSISTED_VALIDATOR_STATE_TYPE_TAG, load_snapshot,
    load_snapshot_chain_genesis_commitment,
};
use std::{env, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let path = args.next().ok_or("usage: indexer-tool <validator-snapshot>")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
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
