use activechain_consensus_runtime::{
    PeerIngressMetricsSnapshot, PeerIngressMonitor, PeerListener, ValidatorService, load_genesis,
    load_snapshot, load_snapshot_chain_genesis_commitment, save_snapshot,
};
use activechain_protocol_types::ConsensusState;
use activechain_protocol_types::Digest384;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::env;
use std::path::Path;

fn log_ingress_metrics(validator_id: u16, metrics: PeerIngressMetricsSnapshot) {
    eprintln!(
        "peer_ingress event=metrics validator={validator_id} accepted={} active={} queued={} shed={} pre_auth_rate_limited={} recovered={}",
        metrics.accepted,
        metrics.active,
        metrics.queued,
        metrics.shed,
        metrics.pre_auth_rate_limited,
        metrics.recovered,
    );
}

fn spawn_ingress_metrics_logger(monitor: PeerIngressMonitor, validator_id: u16) {
    std::thread::spawn(move || {
        let mut previous = PeerIngressMetricsSnapshot::default();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            let current = monitor.snapshot();
            if current != previous {
                log_ingress_metrics(validator_id, current);
                previous = current;
            }
        }
    });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let port: u16 = args.next().as_deref().unwrap_or("4400").parse()?;
    let snapshot_path = args.next();
    let genesis_path = args.next();
    let genesis_epoch: u64 = args.next().as_deref().unwrap_or("0").parse()?;
    let validator_index: Option<usize> = args.next().map(|value| value.parse()).transpose()?;
    let extras: Vec<String> = args.collect();
    let run_once = extras.iter().any(|value| value == "--once");
    let timeout_once = extras.iter().any(|value| value == "--timeout-once");
    let timeout_delay_ms = extras
        .iter()
        .find_map(|value| value.strip_prefix("--timeout-delay-ms="))
        .map(str::parse)
        .transpose()?
        .unwrap_or(0_u64);
    let key_file = extras.iter().find_map(|value| value.strip_prefix("--key-file="));
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
    let signer = match (genesis.as_ref(), validator_index) {
        (Some(genesis), Some(index)) => {
            let entry = genesis
                .entries()
                .get(index)
                .ok_or_else(|| format!("validator index {index} is outside genesis set"))?;
            let key_file = key_file.ok_or("validator identity requires --key-file=<path>")?;
            Some(std::sync::Arc::new(
                activechain_consensus_runtime::ValidatorSigner::from_key_file(
                    Path::new(key_file),
                    genesis,
                    entry,
                )
                .map_err(|error| format!("validator key rejected: {error}"))?,
            ))
        }
        (None, Some(_)) => return Err("validator index requires a genesis manifest".into()),
        _ => None,
    };
    if let Some(path) = snapshot_path.as_deref().filter(|path| !Path::new(path).exists()) {
        save_snapshot(Path::new(path), &state)?;
    }
    let listener = PeerListener::bind(("0.0.0.0", port))?;
    let ingress_monitor = listener.monitor();
    println!(
        "activechain validator listening on {} (epoch {}, finalized height {})",
        listener.local_addr()?,
        state.epoch(),
        state.finalized_height()
    );
    if let (Some(genesis), Some(index), Some(signer)) =
        (genesis.as_ref(), validator_index, signer.as_ref())
    {
        let local_peer_id = index as u16 + 1;
        let signer = std::sync::Arc::clone(signer);
        if (run_once || timeout_once) && !peer_specs.is_empty() {
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
            let listener_thread_signer = std::sync::Arc::clone(&signer);
            std::thread::spawn(move || {
                let _ = listener.spawn_accept_loop(move |peer| {
                    let service = std::sync::Arc::clone(&listener_thread_service);
                    let signer = std::sync::Arc::clone(&listener_thread_signer);
                    if let Err(error) = service.serve_authenticated_genesis_peer_with_voting(
                        peer,
                        local_peer_id,
                        &signer,
                    ) {
                        eprintln!("authenticated genesis peer {} rejected: {error}", local_peer_id);
                    }
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
            if timeout_delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(timeout_delay_ms));
            }
            let (mut peers, failures) =
                connector.connect_all_authenticated(local_peer_id, &signer, &service);
            if !failures.is_empty() {
                return Err(format!("peer connection failures: {failures:?}").into());
            }
            let peer_ids: Vec<u16> = peers.peer_ids().collect();
            let (next_height, next_round) = service
                .next_proposal_position()
                .map_err(|error| format!("cannot derive next proposal position: {error:?}"))?;
            let sequence = service
                .next_sequence(local_peer_id)
                .map_err(|error| format!("cannot reserve next sequence: {error:?}"))?;
            if timeout_once {
                service
                    .timeout_round_and_broadcast(
                        &signer,
                        next_height,
                        next_round,
                        sequence,
                        &mut peers,
                    )
                    .map_err(|error| format!("timeout vote failed: {error:?}"))?;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                loop {
                    let (height, round) = service
                        .next_proposal_position()
                        .map_err(|error| format!("cannot read view-change position: {error:?}"))?;
                    if height == next_height && round == next_round + 1 {
                        println!(
                            "completed timeout quorum: height={height} timed_out_round={next_round} next_round={round}"
                        );
                        return Ok(());
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err("timeout quorum did not form".into());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
            let block_digest = {
                let mut digest = [0_u8; 48];
                let mut hasher = Shake256::default();
                hasher.update(b"ACTIVECHAIN-TESTNET-NETWORK-ROUND-V2");
                hasher.update(genesis.validator_set_root().as_bytes());
                hasher.update(&next_height.to_be_bytes());
                hasher.update(&next_round.to_be_bytes());
                hasher.finalize_xof().read(&mut digest);
                Digest384::new(digest)
            };
            let state = service
                .propose_round_collect_votes(
                    &signer,
                    next_height,
                    next_round,
                    block_digest,
                    sequence,
                    &mut peers,
                    &peer_ids,
                )
                .map_err(|error| format!("network round failed: {error:?}"))?;
            println!("completed network round: finalized_height={}", state.finalized_height());
            let metrics = service.metrics();
            println!(
                "network round metrics: proposals={} votes={} rejected={}",
                metrics.proposals, metrics.votes, metrics.rejected_messages
            );
            log_ingress_metrics(local_peer_id, ingress_monitor.snapshot());
            return Ok(());
        }
        if run_once {
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
            let (next_height, next_round) = service
                .next_proposal_position()
                .map_err(|error| format!("cannot derive next proposal position: {error:?}"))?;
            let sequence = service
                .next_sequence(local_peer_id)
                .map_err(|error| format!("cannot reserve next sequence: {error:?}"))?;
            let block_digest = {
                let mut digest = [0_u8; 48];
                let mut hasher = Shake256::default();
                hasher.update(b"ACTIVECHAIN-TESTNET-ROUND-V2");
                hasher.update(genesis.validator_set_root().as_bytes());
                hasher.update(&next_height.to_be_bytes());
                hasher.update(&next_round.to_be_bytes());
                hasher.finalize_xof().read(&mut digest);
                Digest384::new(digest)
            };
            service
                .propose_round(&signer, next_height, next_round, block_digest, sequence)
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
            let local_peer_id = index as u16 + 1;
            spawn_ingress_metrics_logger(ingress_monitor, local_peer_id);
            let signer =
                std::sync::Arc::clone(signer.as_ref().ok_or("validator signer was not loaded")?);
            listener.spawn_accept_loop(move |peer| {
                let service = std::sync::Arc::clone(&service);
                let signer = std::sync::Arc::clone(&signer);
                if let Err(error) = service.serve_authenticated_genesis_peer_with_voting(
                    peer,
                    local_peer_id,
                    &signer,
                ) {
                    eprintln!("authenticated genesis peer {} rejected: {error}", local_peer_id);
                }
            })?;
        } else {
            return Err("validator genesis requires a configured validator index".into());
        }
    } else {
        spawn_ingress_metrics_logger(ingress_monitor, 0);
        listener.spawn_accept_loop(|mut peer| {
            let _ = peer.receive_frame();
        })?;
    }
    Ok(())
}
