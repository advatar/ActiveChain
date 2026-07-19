use activechain_consensus_runtime::{PeerListener, load_snapshot};
use activechain_protocol_types::ConsensusState;
use std::env;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let port: u16 = args.next().as_deref().unwrap_or("4400").parse()?;
    let snapshot_path = args.next();
    let state = snapshot_path
        .as_deref()
        .map(Path::new)
        .map(load_snapshot)
        .transpose()?
        .unwrap_or_else(|| ConsensusState::new(0));
    let listener = PeerListener::bind(("0.0.0.0", port))?;
    println!(
        "activechain validator listening on {} (epoch {}, finalized height {})",
        listener.local_addr()?,
        state.epoch(),
        state.finalized_height()
    );
    listener.spawn_accept_loop(|mut peer| {
        let _ = peer.receive_frame();
    })?;
    Ok(())
}
