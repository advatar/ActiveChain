//! Minimal deterministic finalized-state indexer for local testnet operations.
use activechain_consensus_runtime::load_snapshot;
use std::{env, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let path = args.next().ok_or("usage: indexer-tool <validator-snapshot>")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let state = load_snapshot(Path::new(&path))?;
    println!(
        "{{\"epoch\":{},\"finalized_height\":{},\"finalized_round\":{},\"validator_set_root\":\"{:02x?}\"}}",
        state.epoch(),
        state.finalized_height(),
        state.finalized_round(),
        state.validator_set_root().as_bytes(),
    );
    Ok(())
}
