use activechain_canonical_codec::encode_envelope;
use activechain_cash_kernel::CoinCellSet;
use activechain_consensus_runtime::{
    FinalizedCashSnapshot, PeerIngressMetricsSnapshot, PeerIngressMonitor, PeerListener,
    ValidatorService, load_genesis, load_snapshot, load_snapshot_chain_genesis_commitment,
    save_snapshot,
};
use activechain_finality_types::{
    FinalityCertificateBundle, FinalizedBlockHeader, ProofPublicInputs,
};
use activechain_protocol_types::{ChainId, ConsensusState, Digest384, ValidatorGenesis};
use activechain_state_tree::StateCommitment;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::env;
use std::path::Path;

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Digest384 {
    let mut output = [0_u8; 48];
    let mut hasher = Shake256::default();
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

fn parse_chain_id(value: &str) -> Result<ChainId, &'static str> {
    if value.len() != 96 {
        return Err("chain ID must be exactly 48 bytes of hexadecimal");
    }
    let mut bytes = [0_u8; 48];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "chain ID contains non-hexadecimal input")?;
    }
    Ok(ChainId::new(Digest384::new(bytes)))
}

fn kanalen_finalized_header(
    genesis: &ValidatorGenesis,
    chain_id: ChainId,
    height: u64,
    cash_cell_root: Digest384,
) -> FinalizedBlockHeader {
    let height_bytes = height.to_be_bytes();
    let parent_block_id = digest_parts(b"ACTIVECHAIN-KANALEN-PARENT-V1", &[&height_bytes]);
    let pre_root = digest_parts(b"ACTIVECHAIN-KANALEN-PRE-STATE-V1", &[&height_bytes]);
    let post_root = digest_parts(b"ACTIVECHAIN-KANALEN-POST-STATE-V1", &[&height_bytes]);
    let inputs = ProofPublicInputs {
        chain_id,
        epoch: genesis.epoch(),
        height,
        protocol_revision: genesis.protocol_revision(),
        validator_set_root: genesis.validator_set_root(),
        parent_block_id,
        pre_state: StateCommitment::new(pre_root, height.saturating_sub(1)),
        authorization_root: digest_parts(b"ACTIVECHAIN-KANALEN-AUTHORIZATIONS-V1", &[]),
        action_root: digest_parts(b"ACTIVECHAIN-KANALEN-ACTIONS-V1", &[]),
        execution_order_root: digest_parts(b"ACTIVECHAIN-KANALEN-EXECUTION-ORDER-V1", &[]),
        total_fees: 0,
        pre_supply: 0,
        issuance: 0,
        burn: 0,
        post_supply: 0,
        cash_cell_root,
        post_state: StateCommitment::new(post_root, height),
        receipt_root: digest_parts(b"ACTIVECHAIN-KANALEN-RECEIPTS-V1", &[]),
        data_availability_commitment: digest_parts(b"ACTIVECHAIN-KANALEN-DA-V1", &[]),
    };
    FinalizedBlockHeader {
        inputs,
        proof_statement_commitment: digest_parts(
            b"ACTIVECHAIN-KANALEN-EMPTY-EXECUTION-PROOF-V1",
            &[cash_cell_root.as_bytes(), &height_bytes],
        ),
    }
}

fn publish_finalized_cash(
    cash_path: &Path,
    finality_path: &Path,
    snapshot: &FinalizedCashSnapshot,
    bundle: &FinalityCertificateBundle,
) -> Result<(), Box<dyn std::error::Error>> {
    let finality = encode_envelope(bundle)
        .map_err(|_| std::io::Error::other("finality bundle encoding failed"))?;
    snapshot.save_with_finality(cash_path, &finality)?;
    let temporary = finality_path.with_extension("tmp");
    std::fs::write(&temporary, &finality)?;
    std::fs::rename(temporary, finality_path)?;
    Ok(())
}

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
    let chain_id = extras
        .iter()
        .find_map(|value| value.strip_prefix("--chain-id-hex="))
        .map(parse_chain_id)
        .transpose()?;
    let finalized_cash_out =
        extras.iter().find_map(|value| value.strip_prefix("--finalized-cash-out="));
    let finality_out = extras.iter().find_map(|value| value.strip_prefix("--finality-out="));
    if finalized_cash_out.is_some() != finality_out.is_some()
        || finalized_cash_out.is_some() != chain_id.is_some()
    {
        return Err(
            "--chain-id-hex, --finalized-cash-out, and --finality-out must be supplied together"
                .into(),
        );
    }
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
            let cash_snapshot = FinalizedCashSnapshot::new(
                genesis.genesis_commitment(),
                next_height,
                CoinCellSet::new(Vec::new())
                    .map_err(|_| "empty finalized cash state is invalid")?,
            )?;
            let publication_header = chain_id.map(|chain_id| {
                kanalen_finalized_header(
                    genesis,
                    chain_id,
                    next_height,
                    cash_snapshot.cash_cell_root,
                )
            });
            let block_digest = match publication_header {
                Some(header) => {
                    header.digest().map_err(|_| "Kanalen finalized header encoding failed")?
                }
                None => digest_parts(
                    b"ACTIVECHAIN-TESTNET-NETWORK-ROUND-V2",
                    &[
                        genesis.validator_set_root().as_bytes(),
                        &next_height.to_be_bytes(),
                        &next_round.to_be_bytes(),
                    ],
                ),
            };
            let (state, certified) = service
                .propose_round_collect_votes_with_certificate(
                    &signer,
                    next_height,
                    next_round,
                    block_digest,
                    sequence,
                    &mut peers,
                    &peer_ids,
                )
                .map_err(|error| format!("network round failed: {error:?}"))?;
            if let (Some(header), Some(cash_path), Some(finality_path)) =
                (publication_header, finalized_cash_out, finality_out)
            {
                let certified = certified.ok_or("network round did not produce a certificate")?;
                let bundle = FinalityCertificateBundle::new(
                    header,
                    genesis.clone(),
                    certified.certificate().clone(),
                    certified.votes().to_vec(),
                )
                .map_err(|_| "certified Kanalen finality bundle is invalid")?;
                publish_finalized_cash(
                    Path::new(cash_path),
                    Path::new(finality_path),
                    &cash_snapshot,
                    &bundle,
                )?;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{PrincipalId, ValidatorGenesisEntry};

    fn genesis() -> ValidatorGenesis {
        ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    PrincipalId::new(Digest384::new([2; 48])),
                    1,
                    [3; activechain_protocol_types::ML_DSA44_PUBLIC_KEY_LENGTH],
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn publication_header_binds_chain_height_and_cash_root() {
        let chain = parse_chain_id(&"11".repeat(48)).unwrap();
        let cash_root = Digest384::new([7; 48]);
        let header = kanalen_finalized_header(&genesis(), chain, 9, cash_root);
        assert_eq!(header.inputs.chain_id, chain);
        assert_eq!(header.inputs.height, 9);
        assert_eq!(header.inputs.cash_cell_root, cash_root);
        assert_ne!(header.digest().unwrap(), Digest384::ZERO);
    }

    #[test]
    fn publication_chain_id_is_exact_and_canonical() {
        assert!(parse_chain_id(&"ab".repeat(48)).is_ok());
        assert!(parse_chain_id("00").is_err());
        assert!(parse_chain_id(&"zz".repeat(48)).is_err());
    }
}
