use activechain_rpc_server::{
    DurableRpcStore, DurableTransferSubmissions, frame_actions, parse_framed_actions,
};
use activechain_wallet_core::TransactionIngress;
use std::{
    env,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_ROUND_ACTIONS: usize = 32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("prepare") => prepare(arguments),
        Some("reconcile-latest") => reconcile_latest(arguments),
        _ => Err(
            "usage: activechain-transfer-spool prepare <transfer-snapshot> <cash-ingress-snapshot> <rpc-index-snapshot> <cash-action-batch> | reconcile-latest <transfer-snapshot> <rpc-index-snapshot> <archive-directory>"
                .into(),
        ),
    }
}

fn prepare(mut arguments: impl Iterator<Item = String>) -> Result<(), Box<dyn std::error::Error>> {
    let transfer_path = PathBuf::from(arguments.next().ok_or("missing transfer snapshot")?);
    let ingress_path = PathBuf::from(arguments.next().ok_or("missing cash ingress snapshot")?);
    let rpc_path = PathBuf::from(arguments.next().ok_or("missing RPC index snapshot")?);
    let batch_path = PathBuf::from(arguments.next().ok_or("missing cash action batch")?);
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }

    let store = DurableRpcStore::load(rpc_path)
        .map_err(|error| format!("could not load RPC index: {error:?}"))?;
    let chain = store.chain_id().map_err(|error| format!("could not read RPC chain: {error:?}"))?;
    let genesis = store
        .genesis_commitment()
        .map_err(|error| format!("could not read RPC genesis: {error:?}"))?;
    let height = store
        .finalized_height()
        .map_err(|error| format!("could not read finalized height: {error:?}"))?
        .checked_add(1)
        .ok_or("next height overflow")?;
    let ingress = TransactionIngress::load(&ingress_path, chain)
        .map_err(|error| format!("could not load cash ingress: {error:?}"))?;
    let mut transfers = DurableTransferSubmissions::restore(transfer_path)
        .map_err(|error| format!("could not load transfer submissions: {error:?}"))?;
    if transfers.policy().chain_id != chain || transfers.policy().genesis_commitment != genesis {
        return Err("transfer snapshot does not match the finalized RPC identity".into());
    }
    let prefix = if batch_path.exists() {
        parse_framed_actions(&std::fs::read(&batch_path)?)
            .map_err(|error| format!("existing cash action batch is invalid: {error:?}"))?
    } else {
        Vec::new()
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates Unix epoch")?
        .as_secs();
    let appended = transfers
        .prepare_pending_batch(&ingress, &prefix, height, now, MAX_ROUND_ACTIONS)
        .map_err(|error| format!("could not prepare transfer batch: {error:?}"))?;
    let appended_count = appended.len();
    let mut actions = prefix;
    actions.extend(appended);
    let framed = frame_actions(&actions)
        .map_err(|error| format!("could not frame transfer batch: {error:?}"))?;
    atomic_write(&batch_path, &framed)?;
    println!(
        "prepared cash action batch: total={} public_transfers={} next_height={height}",
        actions.len(),
        appended_count
    );
    Ok(())
}

fn reconcile_latest(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let transfer_path = PathBuf::from(arguments.next().ok_or("missing transfer snapshot")?);
    let rpc_path = PathBuf::from(arguments.next().ok_or("missing RPC index snapshot")?);
    let archive = PathBuf::from(arguments.next().ok_or("missing archive directory")?);
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let store = DurableRpcStore::load(rpc_path)
        .map_err(|error| format!("could not load RPC index: {error:?}"))?;
    let height = store
        .finalized_height()
        .map_err(|error| format!("could not read finalized height: {error:?}"))?;
    let batch = archive.join(format!("pending-cash-actions.batch.finalized-{height}"));
    let finality = archive.join(format!("finality.bundle.finalized-{height}"));
    if !batch.is_file() || !finality.is_file() {
        return Err("latest cash action or finality archive is missing".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates Unix epoch")?
        .as_secs();
    let mut transfers = DurableTransferSubmissions::restore(transfer_path)
        .map_err(|error| format!("could not load transfer submissions: {error:?}"))?;
    let reconciled = transfers
        .reconcile_finality(&std::fs::read(batch)?, &std::fs::read(finality)?, now)
        .map_err(|error| format!("could not reconcile transfer finality: {error:?}"))?;
    println!("reconciled public transfers: count={reconciled} finalized_height={height}");
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err("cash action batch parent is not a directory".into());
    }
    let temporary = path.with_extension(format!("transfer-spool-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
