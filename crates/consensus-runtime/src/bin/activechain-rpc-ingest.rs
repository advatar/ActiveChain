use activechain_consensus_runtime::{
    FinalizedCashSnapshot, load_snapshot, load_snapshot_chain_genesis_commitment,
};
use activechain_rpc_server::{DurableRpcStore, finalized_coin_cell_records};
use std::{
    env,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let validator_path = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: activechain-rpc-ingest <validator-snapshot> <rpc-index-snapshot> [cash-snapshot] [finality-bundle]")?,
    );
    let rpc_path = PathBuf::from(arguments.next().ok_or("missing RPC index snapshot")?);
    let cash_path = arguments.next().map(PathBuf::from);
    let finality_path = arguments.next().map(PathBuf::from);
    if arguments.next().is_some() || cash_path.is_some() != finality_path.is_some() {
        return Err("unexpected argument".into());
    }

    let state = load_snapshot(Path::new(&validator_path))?;
    let genesis = load_snapshot_chain_genesis_commitment(Path::new(&validator_path))?
        .ok_or("validator snapshot has no immutable genesis commitment")?;
    let finalized_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let store = DurableRpcStore::load(rpc_path)
        .map_err(|error| format!("could not load RPC index: {error:?}"))?;
    if let (Some(cash_path), Some(finality_path)) = (cash_path, finality_path) {
        let cash = FinalizedCashSnapshot::load(&cash_path)?;
        if cash.chain_genesis != genesis || cash.finalized_height != state.finalized_height() {
            return Err("cash snapshot does not match validator finality".into());
        }
        let finality = std::fs::read(finality_path)?;
        activechain_verifier_api::verify_finality_bundle_with_chain_genesis(&finality, genesis)
            .map_err(|_| "finality bundle does not match validator genesis")?;
        let records = finalized_coin_cell_records(&cash.cells, cash.finalized_height, &finality)
            .map_err(|error| format!("could not build finalized Coin Cell records: {error:?}"))?;
        store
            .replace_finalized_records(genesis, cash.finalized_height, finalized_at, records)
            .map_err(|error| format!("could not ingest finalized cash state: {error:?}"))?;
    } else {
        store
            .advance_finality(genesis, state.finalized_height(), finalized_at)
            .map_err(|error| format!("could not ingest finalized state: {error:?}"))?;
    }
    println!(
        "ingested finalized height {} from {}",
        state.finalized_height(),
        validator_path.display()
    );
    Ok(())
}
