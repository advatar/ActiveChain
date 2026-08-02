use activechain_action_kernel::ResourcePrices;
use activechain_authorization_kernel::AuthorizationReplayStore;
use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_cash_kernel::CashLedger;
use activechain_consensus_runtime::{
    CashOnlyFinalizedBlockVerifier, FinalizedCashSnapshot, GenesisBackedFinalizedBlockVerifier,
    PeerIngressMetricsSnapshot, PeerIngressMonitor, PeerListener, PreparedDirectFinalizedBlock,
    ValidatorService, WalletTransactionGateway, load_genesis, load_snapshot,
    load_snapshot_chain_genesis_commitment, save_snapshot,
};
use activechain_devnet_kernel::{ChainState, DevnetBlock};
use activechain_finality_types::{
    FinalityCertificateBundle, FinalizedBlockHeader, ProofPublicInputs,
};
use activechain_protocol_types::{ChainId, ConsensusState, Digest384, ValidatorGenesis};
use activechain_state_tree::{StateCommitment, commit_objects};
use activechain_transition::ObjectState;
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

fn load_authoritative_cash_gateway(
    path: &Path,
    chain_id: ChainId,
) -> Result<WalletTransactionGateway, Box<dyn std::error::Error>> {
    if let Ok(gateway) = WalletTransactionGateway::load_snapshot(path, chain_id) {
        return Ok(gateway);
    }
    let bytes = std::fs::read(path)?;
    let ledger: CashLedger = decode_envelope(&bytes)
        .map_err(|_| std::io::Error::other("cash ledger snapshot is not canonical"))?;
    ledger
        .verify_invariants()
        .map_err(|_| std::io::Error::other("cash ledger invariants failed"))?;
    if ledger.definition().chain_id() != chain_id {
        return Err(std::io::Error::other("cash ledger belongs to another chain").into());
    }
    WalletTransactionGateway::from_ledger(ledger, path.to_path_buf())
        .map_err(|_| std::io::Error::other("cash ingress construction failed").into())
}

fn load_or_create_execution_state(
    path: &Path,
    chain_id: ChainId,
) -> Result<ChainState, Box<dyn std::error::Error>> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let state: ChainState = decode_envelope(&bytes)
            .map_err(|_| std::io::Error::other("execution state is not canonical"))?;
        if encode_envelope(&state).map_err(|_| "execution state encoding failed")? != bytes
            || state.chain_id() != chain_id
        {
            return Err(
                std::io::Error::other("execution state is noncanonical or cross-chain").into()
            );
        }
        return Ok(state);
    }
    let objects = ObjectState::new(Vec::new())
        .map_err(|_| std::io::Error::other("empty execution object state is invalid"))?;
    ChainState::genesis(chain_id, objects, Vec::new(), ResourcePrices::new(1, 1, 1, 1, 1, 1))
        .map_err(|_| std::io::Error::other("execution genesis construction failed").into())
}

fn save_execution_state(path: &Path, state: &ChainState) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = encode_envelope(state).map_err(|_| "execution state encoding failed")?;
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

const MAX_CASH_ROUND_ACTIONS: usize = 32;

fn load_cash_action_batch(path: &Path) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let mut offset = 0_usize;
    let mut actions = Vec::new();
    while offset < bytes.len() {
        if actions.len() == MAX_CASH_ROUND_ACTIONS || bytes.len() - offset < 4 {
            return Err(std::io::Error::other("cash action batch is malformed or oversized").into());
        }
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if length == 0
            || length > activechain_wallet_core::MAX_INGRESS_FRAME
            || bytes.len() - offset < length
        {
            return Err(std::io::Error::other("cash action frame is malformed or oversized").into());
        }
        actions.push(bytes[offset..offset + length].to_vec());
        offset += length;
    }
    Ok(actions)
}

fn kanalen_finalized_header(
    genesis: &ValidatorGenesis,
    chain_id: ChainId,
    height: u64,
    pre_cash_cell_root: Digest384,
    cash_action_root: Digest384,
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
        pre_cash_cell_root,
        cash_action_root,
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

fn cash_action_root(actions: &[activechain_protocol_types::TransactionId]) -> Digest384 {
    let mut bytes = Vec::with_capacity(actions.len() * 48);
    for action in actions {
        bytes.extend_from_slice(action.digest().as_bytes());
    }
    activechain_finality_types::commit_parts(b"ACTIVECHAIN-BLOCK-CASH-ACTIONS-V1", &[&bytes])
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
    let cash_ledger = extras.iter().find_map(|value| value.strip_prefix("--cash-ledger="));
    let cash_actions = extras.iter().find_map(|value| value.strip_prefix("--cash-actions="));
    let execution_state_path =
        extras.iter().find_map(|value| value.strip_prefix("--execution-state="));
    if finalized_cash_out.is_some() != finality_out.is_some()
        || finalized_cash_out.is_some() != chain_id.is_some()
        || finalized_cash_out.is_some() != cash_ledger.is_some()
        || finalized_cash_out.is_some() != execution_state_path.is_some()
    {
        return Err(
            "--chain-id-hex, --cash-ledger, --execution-state, --finalized-cash-out, and --finality-out must be supplied together".into(),
        );
    }
    if cash_actions.is_some() && cash_ledger.is_none() {
        return Err("--cash-actions requires --cash-ledger".into());
    }
    let mut authoritative_cash = cash_ledger
        .map(Path::new)
        .zip(chain_id)
        .map(|(path, chain)| load_authoritative_cash_gateway(path, chain))
        .transpose()?;
    let mut execution_state = execution_state_path
        .map(Path::new)
        .zip(chain_id)
        .map(|(path, chain)| load_or_create_execution_state(path, chain))
        .transpose()?;
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
            let prepared_cash = match (authoritative_cash.as_ref(), cash_actions) {
                (Some(gateway), Some(path)) => Some(
                    gateway
                        .prepare_envelope_batch(
                            &load_cash_action_batch(Path::new(path))?,
                            next_height,
                        )
                        .map_err(|error| {
                            format!("cash action batch rejected atomically: {error:?}")
                        })?,
                ),
                _ => None,
            };
            let cash_snapshot = if chain_id.is_some() {
                let ledger = prepared_cash
                    .as_ref()
                    .map(|prepared| prepared.ledger())
                    .or_else(|| authoritative_cash.as_ref().map(|gateway| gateway.ledger()))
                    .ok_or("authoritative cash ledger is required for a published round")?;
                Some(FinalizedCashSnapshot::new(
                    genesis.genesis_commitment(),
                    next_height,
                    ledger.cells().clone(),
                )?)
            } else {
                None
            };
            let publication_draft = chain_id
                .zip(cash_snapshot.as_ref())
                .map(|(chain_id, cash)| -> Result<PreparedDirectFinalizedBlock, Box<dyn std::error::Error>> {
                    let pre_root = prepared_cash.as_ref().map_or(cash.cash_cell_root, |prepared| {
                        prepared.pre_cash_cell_root()
                    });
                    let state = execution_state
                        .as_ref()
                        .ok_or("execution state is required for a published round")?;
                    if state.height().checked_add(1) != Some(next_height) {
                        return Err("execution state height does not match consensus round".into());
                    }
                    let block = DevnetBlock::new(
                        chain_id,
                        next_height,
                        state.head_block_id(),
                        commit_objects(state.objects().objects())
                            .map_err(|_| std::io::Error::other("execution object root failed"))?,
                        state
                            .commitment()
                            .map_err(|_| std::io::Error::other("execution state commitment failed"))?,
                        Vec::new(),
                    )
                    .map_err(|_| std::io::Error::other("canonical cash execution block construction failed"))?;
                    let supply = authoritative_cash
                        .as_ref()
                        .ok_or("authoritative cash gateway disappeared")?
                        .ledger()
                        .supply()
                        .current_total_supply();
                    PreparedDirectFinalizedBlock::new(
                        state,
                        &block,
                        genesis.epoch(),
                        genesis.protocol_revision(),
                        genesis.validator_set_root(),
                        supply,
                        0,
                        0,
                        pre_root,
                        prepared_cash.as_ref().map_or(&[][..], |prepared| prepared.action_ids()),
                        cash.cash_cell_root,
                        1,
                        1,
                        signer.validator(),
                    )
                    .map_err(|_| std::io::Error::other("canonical finalized cash draft construction failed").into())
                })
                .transpose()?;
            let block_digest = match publication_draft.as_ref() {
                Some(draft) => draft
                    .header()
                    .digest()
                    .map_err(|_| "Kanalen finalized header encoding failed")?,
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
            if let (Some(draft), Some(cash_path), Some(finality_path)) =
                (publication_draft, finalized_cash_out, finality_out)
            {
                let certified = certified.ok_or("network round did not produce a certificate")?;
                let pre_root = prepared_cash.as_ref().map_or_else(
                    || cash_snapshot.as_ref().unwrap().cash_cell_root,
                    |prepared| prepared.pre_cash_cell_root(),
                );
                let action_ids = prepared_cash
                    .as_ref()
                    .map_or_else(Vec::new, |prepared| prepared.action_ids().to_vec());
                let post_root = cash_snapshot.as_ref().unwrap().cash_cell_root;
                let supply = authoritative_cash
                    .as_ref()
                    .ok_or("authoritative cash gateway disappeared")?
                    .ledger()
                    .supply()
                    .current_total_supply();
                let authorization_path =
                    Path::new(execution_state_path.ok_or("execution state path disappeared")?)
                        .with_extension("authorization");
                let authorization_store = if authorization_path.exists() {
                    let store = AuthorizationReplayStore::load(authorization_path)?;
                    if store.chain_genesis_commitment() != genesis.genesis_commitment()
                        || store.epoch() != genesis.epoch()
                    {
                        return Err(
                            "authorization replay store belongs to another consensus context"
                                .into(),
                        );
                    }
                    store
                } else {
                    AuthorizationReplayStore::new(
                        authorization_path,
                        genesis.genesis_commitment(),
                        genesis.epoch(),
                    )
                    .map_err(|_| "authorization replay store construction failed")?
                };
                let verifier = GenesisBackedFinalizedBlockVerifier::new(
                    genesis.clone(),
                    CashOnlyFinalizedBlockVerifier,
                );
                let admitted = draft
                    .into_candidate(certified.certificate().clone(), certified.votes().to_vec())
                    .admit(
                        execution_state.as_ref().unwrap(),
                        genesis.genesis_commitment(),
                        genesis.epoch(),
                        genesis.protocol_revision(),
                        genesis.validator_set_root(),
                        supply,
                        0,
                        0,
                        pre_root,
                        &action_ids,
                        post_root,
                        &authorization_store,
                        &verifier,
                    )
                    .map_err(|error| format!("typed finalized cash admission failed: {error:?}"))?;
                let header = admitted.header;
                let bundle = FinalityCertificateBundle::new(
                    header,
                    genesis.clone(),
                    certified.certificate().clone(),
                    certified.votes().to_vec(),
                )
                .map_err(|_| "certified Kanalen finality bundle is invalid")?;
                if let Some(prepared) = prepared_cash {
                    authoritative_cash
                        .as_mut()
                        .ok_or("authoritative cash gateway disappeared")?
                        .commit_prepared(prepared)
                        .map_err(|error| {
                            format!("certified cash state persistence failed: {error:?}")
                        })?;
                    if let Some(path) = cash_actions {
                        let finalized = format!("{path}.finalized-{next_height}");
                        std::fs::rename(path, finalized)?;
                    }
                }
                publish_finalized_cash(
                    Path::new(cash_path),
                    Path::new(finality_path),
                    cash_snapshot
                        .as_ref()
                        .ok_or("authoritative cash snapshot was not materialized")?,
                    &bundle,
                )?;
                execution_state = Some(admitted.next_state);
                save_execution_state(
                    Path::new(execution_state_path.unwrap()),
                    execution_state.as_ref().unwrap(),
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
    use activechain_cash_kernel::{GenesisAllocation, GenesisEconomy, NativeAssetDefinition};
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
        let header = kanalen_finalized_header(
            &genesis(),
            chain,
            9,
            Digest384::new([6; 48]),
            cash_action_root(&[]),
            cash_root,
        );
        assert_eq!(header.inputs.chain_id, chain);
        assert_eq!(header.inputs.height, 9);
        assert_eq!(header.inputs.cash_cell_root, cash_root);
        assert_eq!(header.inputs.pre_cash_cell_root, Digest384::new([6; 48]));
        assert_eq!(header.inputs.cash_action_root, cash_action_root(&[]));
        assert_ne!(header.digest().unwrap(), Digest384::ZERO);
    }

    #[test]
    fn publication_chain_id_is_exact_and_canonical() {
        assert!(parse_chain_id(&"ab".repeat(48)).is_ok());
        assert!(parse_chain_id("00").is_err());
        assert!(parse_chain_id(&"zz".repeat(48)).is_err());
    }

    fn cash_ledger(chain: ChainId) -> CashLedger {
        let definition = NativeAssetDefinition::new(
            chain,
            b"ACT".to_vec(),
            18,
            1_000,
            150,
            Digest384::new([70; 48]),
            Digest384::new([71; 48]),
            Digest384::new([72; 48]),
        )
        .unwrap();
        CashLedger::from_genesis(
            &GenesisEconomy::new(
                definition,
                vec![
                    GenesisAllocation::new(PrincipalId::new(Digest384::new([73; 48])), 900, 0)
                        .unwrap(),
                ],
                100,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn authoritative_cash_loader_rejects_cross_chain_and_noncanonical_state() {
        let chain = ChainId::new(Digest384::new([80; 48]));
        let path = std::env::temp_dir()
            .join(format!("activechain-authoritative-cash-{}.snapshot", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, encode_envelope(&cash_ledger(chain)).unwrap()).unwrap();
        let loaded = load_authoritative_cash_gateway(&path, chain).unwrap();
        assert_eq!(loaded.ledger().definition().chain_id(), chain);
        assert!(!loaded.ledger().cells().as_slice().is_empty());
        assert!(
            load_authoritative_cash_gateway(&path, ChainId::new(Digest384::new([81; 48]))).is_err()
        );
        let ingress =
            activechain_wallet_core::TransactionIngress::from_ledger(cash_ledger(chain)).unwrap();
        std::fs::write(&path, encode_envelope(&ingress).unwrap()).unwrap();
        assert_eq!(
            load_authoritative_cash_gateway(&path, chain).unwrap().ledger().definition().chain_id(),
            chain
        );
        std::fs::write(&path, b"not canonical").unwrap();
        assert!(load_authoritative_cash_gateway(&path, chain).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn execution_state_is_canonical_chain_bound_and_restart_safe() {
        let chain = ChainId::new(Digest384::new([82; 48]));
        let path = std::env::temp_dir()
            .join(format!("activechain-validator-execution-{}.snapshot", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let state = load_or_create_execution_state(&path, chain).unwrap();
        assert_eq!(state.height(), 0);
        assert_eq!(state.chain_id(), chain);
        save_execution_state(&path, &state).unwrap();
        assert_eq!(load_or_create_execution_state(&path, chain).unwrap(), state);
        assert!(
            load_or_create_execution_state(&path, ChainId::new(Digest384::new([83; 48]))).is_err()
        );
        let mut malformed = std::fs::read(&path).unwrap();
        malformed.push(0);
        std::fs::write(&path, malformed).unwrap();
        assert!(load_or_create_execution_state(&path, chain).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn cash_action_batch_is_strictly_framed_and_bounded() {
        let path = std::env::temp_dir()
            .join(format!("activechain-cash-actions-{}.batch", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&3_u32.to_be_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.push(4);
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(load_cash_action_batch(&path).unwrap(), vec![vec![1, 2, 3], vec![4]]);
        bytes.pop();
        std::fs::write(&path, &bytes).unwrap();
        assert!(load_cash_action_batch(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
