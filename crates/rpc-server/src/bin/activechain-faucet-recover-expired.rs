//! Offline, evidence-bound rejection of an expired, provably unexecuted faucet grant.
use activechain_protocol_types::Digest384;
use activechain_rpc_server::{DurableRpcStore, reject_expired_unexecuted_grant};
use activechain_wallet_core::TransactionIngress;
use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 6 {
        return Err("usage (stop RPC and round runner first): activechain-faucet-recover-expired <faucet.snapshot> <settlement.journal> <cash-ledger.snapshot> <rpc-index.snapshot> <finality.bundle> <grant-reference-hex>".into());
    }
    let mut bytes = [0; 48];
    if args[5].len() != 96 || !args[5].bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("grant reference must be 96 hexadecimal characters".into());
    }
    for (index, value) in bytes.iter_mut().enumerate() {
        *value = u8::from_str_radix(&args[5][index * 2..index * 2 + 2], 16)?;
    }
    let store = DurableRpcStore::load(PathBuf::from(&args[3]))
        .map_err(|e| format!("RPC snapshot: {e:?}"))?;
    let chain = store.chain_id().map_err(|e| format!("chain: {e:?}"))?;
    let genesis = store.genesis_commitment().map_err(|e| format!("genesis: {e:?}"))?;
    let height = store.finalized_height().map_err(|e| format!("height: {e:?}"))?;
    let ingress = TransactionIngress::load(&PathBuf::from(&args[2]), chain)
        .map_err(|e| format!("cash snapshot: {e:?}"))?;
    reject_expired_unexecuted_grant(
        &PathBuf::from(&args[0]),
        &PathBuf::from(&args[1]),
        Digest384::new(bytes),
        &ingress,
        genesis,
        height,
        &std::fs::read(&args[4])?,
    )
    .map_err(|e| format!("recovery refused; grant remains unchanged: {e:?}"))?;
    println!(
        "rejected expired unexecuted grant {} at verified height {height}; signed journal preserved",
        args[5]
    );
    Ok(())
}
