use activechain_consensus_runtime::{
    PeerListener, ValidatorService, load_genesis, load_snapshot,
    load_snapshot_chain_genesis_commitment, save_snapshot,
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
    let extras: Vec<String> = args.collect();
    let run_once = extras.iter().any(|value| value == "--once");
    let peer_specs: Vec<&str> =
        extras.iter().filter_map(|value| value.strip_prefix("--peer=")).collect();
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
                    ConsensusState::new_with_consensus_context(
                        config.epoch(),
                        config.validator_set_root(),
                        config.protocol_revision(),
                    )
                    .expect("validated manifest must define a consensus context")
                },
            )
        });
    let chain_genesis_commitment = snapshot_path
        .as_deref()
        .filter(|path| Path::new(path).exists())
        .map(Path::new)
        .map(load_snapshot_chain_genesis_commitment)
        .transpose()?
        .flatten()
        .or_else(|| genesis.as_ref().map(|config| config.genesis_commitment()));
    if let Some(path) = snapshot_path.as_deref().filter(|path| !Path::new(path).exists()) {
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
        let entry = genesis.entries().get(index).ok_or("validator index outside genesis")?;
        let (seed, entry) = (0..genesis.entries().len())
            .find_map(|candidate| {
                let mut seed = [0_u8; 32];
                seed[..8].copy_from_slice(&(candidate as u64).to_be_bytes());
                seed[8..16].copy_from_slice(&genesis.epoch().to_be_bytes());
                seed[16..24].copy_from_slice(&genesis.activation_height().to_be_bytes());
                let probe = activechain_consensus_runtime::ValidatorSigner::from_seed(
                    activechain_protocol_types::PrincipalId::new(Digest384::new([0; 48])),
                    seed,
                );
                (probe.public_key() == entry.public_key()).then_some((seed, entry))
            })
            .ok_or("could not derive signer for genesis entry")?;
        let local_peer_id = index as u16 + 1;
        let signer =
            activechain_consensus_runtime::ValidatorSigner::from_seed(entry.validator(), seed);
        if run_once && !peer_specs.is_empty() {
            let next_height = state.finalized_height().saturating_add(1);
            let service = std::sync::Arc::new(
                ValidatorService::from_active_manifest(
                    state,
                    genesis,
                    chain_genesis_commitment.ok_or("missing immutable chain genesis commitment")?,
                    snapshot_path
                        .as_deref()
                        .map(Path::new)
                        .unwrap_or_else(|| Path::new("validator.snapshot"))
                        .to_path_buf(),
                )
                .map_err(|error| format!("validator service configuration failed: {error:?}"))?,
            );
            let listener_thread_service = std::sync::Arc::clone(&service);
            let listener_thread_signer = std::sync::Arc::new(
                activechain_consensus_runtime::ValidatorSigner::from_seed(entry.validator(), seed),
            );
            std::thread::spawn(move || {
                let _ = listener.spawn_accept_loop(move |peer| {
                    let service = std::sync::Arc::clone(&listener_thread_service);
                    let signer = std::sync::Arc::clone(&listener_thread_signer);
                    let _ = service.serve_authenticated_genesis_peer_with_voting(
                        peer,
                        local_peer_id,
                        &signer,
                        [23; 32],
                    );
                });
            });
            let mut endpoints = Vec::new();
            for spec in &peer_specs {
                let (id, address) = spec.split_once('@').ok_or("peer must use <id>@<address>")?;
                let id: u16 = id.parse().map_err(|_| "invalid peer ID")?;
                let entry = genesis
                    .entries()
                    .get(id.saturating_sub(1) as usize)
                    .ok_or("peer ID is outside genesis set")?;
                endpoints.push(
                    activechain_consensus_runtime::PeerEndpoint::from_genesis_address(
                        id,
                        address,
                        entry.public_key().to_vec(),
                    )
                    .map_err(|_| "invalid peer endpoint")?,
                );
            }
            let connector = activechain_consensus_runtime::PeerConnector::new(endpoints)
                .map_err(|_| "invalid peer configuration")?;
            let challenge = [23; 32];
            let (mut peers, failures) =
                connector.connect_all_with_handshake(local_peer_id, &signer, challenge);
            if !failures.is_empty() {
                return Err(format!("peer connection failures: {failures:?}").into());
            }
            let peer_ids: Vec<u16> = peers.peers().map(|(id, _)| *id).collect();
            let block_digest = Digest384::new([index as u8 + 120; 48]);
            let state = service
                .propose_round_collect_votes(
                    &signer,
                    next_height,
                    0,
                    block_digest,
                    1,
                    &mut peers,
                    &peer_ids,
                )
                .map_err(|error| format!("network round failed: {error:?}"))?;
            println!("completed network round: finalized_height={}", state.finalized_height());
            return Ok(());
        }
        if run_once {
            let next_height = state.finalized_height().saturating_add(1);
            let service = ValidatorService::from_active_manifest(
                state,
                genesis,
                chain_genesis_commitment.ok_or("missing immutable chain genesis commitment")?,
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
            ValidatorService::from_active_manifest(
                state,
                &genesis,
                chain_genesis_commitment.ok_or("missing immutable chain genesis commitment")?,
                snapshot_path
                    .as_deref()
                    .map(Path::new)
                    .unwrap_or_else(|| Path::new("validator.snapshot"))
                    .to_path_buf(),
            )
            .map_err(|error| format!("validator service configuration failed: {error:?}"))?,
        );
        if let Some(index) = validator_index {
            let entry = genesis.entries().get(index).ok_or("validator index outside genesis")?;
            let (seed, entry) = (0..genesis.entries().len())
                .find_map(|candidate| {
                    let mut seed = [0_u8; 32];
                    seed[..8].copy_from_slice(&(candidate as u64).to_be_bytes());
                    seed[8..16].copy_from_slice(&genesis.epoch().to_be_bytes());
                    seed[16..24].copy_from_slice(&genesis.activation_height().to_be_bytes());
                    let probe = activechain_consensus_runtime::ValidatorSigner::from_seed(
                        activechain_protocol_types::PrincipalId::new(Digest384::new([0; 48])),
                        seed,
                    );
                    (probe.public_key() == entry.public_key()).then_some((seed, entry))
                })
                .ok_or("could not derive signer for genesis entry")?;
            let local_peer_id = index as u16 + 1;
            let signer = std::sync::Arc::new(
                activechain_consensus_runtime::ValidatorSigner::from_seed(entry.validator(), seed),
            );
            listener.spawn_accept_loop(move |peer| {
                let service = std::sync::Arc::clone(&service);
                let signer = std::sync::Arc::clone(&signer);
                let _ = service.serve_authenticated_genesis_peer_with_voting(
                    peer,
                    local_peer_id,
                    &signer,
                    [23; 32],
                );
            })?;
        } else {
            listener.spawn_accept_loop(move |peer| {
                let service = std::sync::Arc::clone(&service);
                let _ = service.serve_peer(peer);
            })?;
        }
    } else {
        listener.spawn_accept_loop(|mut peer| {
            let _ = peer.receive_frame();
        })?;
    }
    Ok(())
}
