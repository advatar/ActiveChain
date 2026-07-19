use activechain_consensus_runtime::{
    PeerListener, ValidatorService, load_genesis, load_snapshot, save_snapshot,
};
use activechain_protocol_types::ConsensusState;
use std::env;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let port: u16 = args.next().as_deref().unwrap_or("4400").parse()?;
    let snapshot_path = args.next();
    let genesis_path = args.next();
    let genesis_epoch: u64 = args.next().as_deref().unwrap_or("0").parse()?;
    let state = snapshot_path
        .as_deref()
        .map(Path::new)
        .map(load_snapshot)
        .transpose()?
        .unwrap_or_else(|| ConsensusState::new(genesis_epoch));
    if let Some(path) = snapshot_path.as_deref() {
        save_snapshot(Path::new(path), &state)?;
    }
    let listener = PeerListener::bind(("0.0.0.0", port))?;
    println!(
        "activechain validator listening on {} (epoch {}, finalized height {})",
        listener.local_addr()?,
        state.epoch(),
        state.finalized_height()
    );
    if let Some(genesis_path) = genesis_path {
        let genesis = load_genesis(Path::new(&genesis_path))?;
        let service = std::sync::Arc::new(
            ValidatorService::from_genesis(
                state,
                &genesis,
                snapshot_path
                    .as_deref()
                    .map(Path::new)
                    .unwrap_or_else(|| Path::new("validator.snapshot"))
                    .to_path_buf(),
            )
            .map_err(|error| format!("validator service configuration failed: {error:?}"))?,
        );
        listener.spawn_accept_loop(move |peer| {
            let service = std::sync::Arc::clone(&service);
            let _ = service.serve_peer(peer);
        })?;
    } else {
        listener.spawn_accept_loop(|mut peer| {
            let _ = peer.receive_frame();
        })?;
    }
    Ok(())
}
