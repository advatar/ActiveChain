use activechain_consensus_runtime::{
    PeerListener, ValidatorService, load_genesis, load_snapshot, save_snapshot,
};
use activechain_protocol_types::ConsensusState;
use activechain_protocol_types::Digest384;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::env;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let port: u16 = args.next().as_deref().unwrap_or("4400").parse()?;
    let snapshot_path = args.next();
    let genesis_path = args.next();
    let genesis_epoch: u64 = args.next().as_deref().unwrap_or("0").parse()?;
    let validator_index: Option<usize> = args.next().map(|value| value.parse()).transpose()?;
    let run_once = args.next().as_deref() == Some("--once");
    let genesis = genesis_path.as_deref().map(Path::new).map(load_genesis).transpose()?;
    let state = snapshot_path
        .as_deref()
        .filter(|path| Path::new(path).exists())
        .map(Path::new)
        .map(load_snapshot)
        .transpose()?
        .unwrap_or_else(|| {
            genesis.as_ref().map_or_else(
                || ConsensusState::new(genesis_epoch),
                |config| {
                    ConsensusState::new_with_validator_set_root(
                        config.epoch(),
                        config.validator_set_root(),
                    )
                },
            )
        });
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
    if let (Some(genesis), Some(index)) = (genesis.as_ref(), validator_index) {
        if index >= genesis.entries().len() {
            return Err(format!("validator index {index} is outside genesis set").into());
        }
        let mut seed = [0_u8; 32];
        seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
        seed[8..16].copy_from_slice(&genesis.epoch().to_be_bytes());
        seed[16..24].copy_from_slice(&genesis.activation_height().to_be_bytes());
        let probe = activechain_consensus_runtime::ValidatorSigner::from_seed(
            activechain_protocol_types::PrincipalId::new(Digest384::new([0; 48])),
            seed,
        );
        let public_key = probe.public_key();
        let entry = genesis
            .entries()
            .iter()
            .find(|entry| entry.public_key() == public_key.as_slice())
            .ok_or("derived signer does not match genesis public key")?;
        let signer =
            activechain_consensus_runtime::ValidatorSigner::from_seed(entry.validator(), seed);
        if run_once {
            let next_height = state.finalized_height().saturating_add(1);
            let service = ValidatorService::from_genesis(
                state,
                genesis,
                snapshot_path
                    .as_deref()
                    .map(Path::new)
                    .unwrap_or_else(|| Path::new("validator.snapshot"))
                    .to_path_buf(),
            )
            .map_err(|error| format!("validator service configuration failed: {error:?}"))?;
            let block_digest = {
                let mut digest = [0_u8; 48];
                let mut hasher = Shake256::default();
                hasher.update(b"ACTIVECHAIN-TESTNET-ROUND-V1");
                hasher.update(genesis.validator_set_root().as_bytes());
                hasher.finalize_xof().read(&mut digest);
                Digest384::new(digest)
            };
            service
                .propose_round(&signer, next_height, 0, block_digest, 1)
                .map_err(|error| format!("deterministic round failed: {error:?}"))?;
            let metrics = service.metrics();
            println!(
                "completed deterministic round: finalized_height={} proposals={} votes={} rejected={}",
                service
                    .state()
                    .map_err(|error| format!("state read failed: {error:?}"))?
                    .finalized_height(),
                metrics.proposals,
                metrics.votes,
                metrics.rejected_messages
            );
            return Ok(());
        }
    }
    if let Some(genesis) = genesis {
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
