use activechain_consensus_runtime::{
    FinalizedCashSnapshot, load_snapshot, load_snapshot_chain_genesis_commitment,
};
use activechain_rpc_server::{DurableRpcStore, finalized_coin_cell_records_with_chain_genesis};
use std::{
    env,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn validate_cash_chain(
    cash: &FinalizedCashSnapshot,
    genesis: activechain_protocol_types::Digest384,
) -> Result<(), &'static str> {
    if cash.chain_genesis != genesis {
        return Err("cash snapshot does not match validator chain identity");
    }
    Ok(())
}

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
    let mut published_height = state.finalized_height();
    if let (Some(cash_path), Some(finality_path)) = (cash_path, finality_path) {
        let cash = FinalizedCashSnapshot::load_canonical(&cash_path)?;
        validate_cash_chain(&cash, genesis)?;
        let finality = std::fs::read(finality_path)?;
        cash.verify_against_finality(&finality)
            .map_err(|error| format!("cash snapshot/finality mismatch: {error}"))?;
        published_height = cash.finalized_height;
        let records = finalized_coin_cell_records_with_chain_genesis(
            &cash.cells,
            cash.finalized_height,
            &finality,
            genesis,
        )
        .map_err(|error| format!("could not build finalized Coin Cell records: {error:?}"))?;
        store
            .replace_finalized_records(genesis, cash.finalized_height, finalized_at, records)
            .map_err(|error| format!("could not ingest finalized cash state: {error:?}"))?;
    } else {
        store
            .advance_finality(genesis, state.finalized_height(), finalized_at)
            .map_err(|error| format!("could not ingest finalized state: {error:?}"))?;
    }
    println!("ingested finalized height {published_height} from {}", validator_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_cash_kernel::CoinCellSet;
    use activechain_protocol_types::Digest384;

    #[test]
    fn cash_publication_is_chain_bound_but_may_lead_safety_snapshot_height() {
        let genesis = Digest384::new([7; 48]);
        let cash =
            FinalizedCashSnapshot::new(genesis, 12, CoinCellSet::new(Vec::new()).unwrap()).unwrap();
        assert_eq!(validate_cash_chain(&cash, genesis), Ok(()));
        assert_eq!(
            validate_cash_chain(&cash, Digest384::new([8; 48])),
            Err("cash snapshot does not match validator chain identity")
        );
    }
}
