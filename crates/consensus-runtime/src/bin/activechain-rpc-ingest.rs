use activechain_consensus_runtime::{load_snapshot, load_snapshot_chain_genesis_commitment};
use activechain_rpc_server::DurableRpcStore;
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
            .ok_or("usage: activechain-rpc-ingest <validator-snapshot> <rpc-index-snapshot>")?,
    );
    let rpc_path = PathBuf::from(arguments.next().ok_or("missing RPC index snapshot")?);
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }

    let state = load_snapshot(Path::new(&validator_path))?;
    let genesis = load_snapshot_chain_genesis_commitment(Path::new(&validator_path))?
        .ok_or("validator snapshot has no immutable genesis commitment")?;
    let finalized_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    DurableRpcStore::load(rpc_path)
        .map_err(|error| format!("could not load RPC index: {error:?}"))?
        .advance_finality(genesis, state.finalized_height(), finalized_at)
        .map_err(|error| format!("could not ingest finalized state: {error:?}"))?;
    println!(
        "ingested finalized height {} from {}",
        state.finalized_height(),
        validator_path.display()
    );
    Ok(())
}
