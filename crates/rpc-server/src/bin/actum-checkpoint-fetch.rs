//! Fetches the authenticated block receipt for a finalized checkpoint.
//!
//! The trust ceremony pins a checkpoint by height, block id, state root,
//! finality commitment, and validator set root. Every one of those except the
//! block id is carried by the finality bundle; the block id lives only in the
//! block receipt, which the RPC serves keyed by the bundle's own
//! `inputs.receipt_root`. Fetching it here keeps checkpoint identity out of
//! hand-typed ceremony input.

use activechain_canonical_codec::decode_envelope;
use activechain_devnet_kernel::BlockReceipt;
use activechain_finality_types::FinalityCertificateBundle;
use activechain_rpc_server::query;
use activechain_rpc_types::{QueryKind, RpcRequest, RpcResponse};
use std::{env, fs, path::Path};

const MAX_BUNDLE_BYTES: u64 = 4 * 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let address = arguments
        .next()
        .ok_or("usage: actum-checkpoint-fetch <host:port> <finality-bundle> <receipt-out>")?;
    let finality_path = arguments.next().ok_or("finality bundle path is required")?;
    let output = arguments.next().ok_or("receipt output path is required")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let output = Path::new(&output);
    if output.exists() {
        return Err("refusing to overwrite an existing receipt".into());
    }

    let finality_bytes = read_bounded(Path::new(&finality_path))?;
    let finality = decode_envelope::<FinalityCertificateBundle>(&finality_bytes)
        .map_err(|_| "input is not a canonical finality certificate bundle")?;
    let inputs = finality.header().inputs;

    let response = query(
        &address,
        &RpcRequest::Get { kind: QueryKind::Receipt, key: inputs.receipt_root },
    )
    .map_err(|error| format!("receipt query failed: {error:?}"))?;
    let RpcResponse::Record(record) = response else {
        return Err("RPC did not return a receipt record".into());
    };
    let receipt = decode_envelope::<BlockReceipt>(record.value())
        .map_err(|_| "RPC returned an undecodable block receipt")?;

    // The receipt must describe the same finalized block the bundle commits to,
    // otherwise the ceremony would pin a checkpoint that never existed.
    if receipt.height() != inputs.height || receipt.post_state() != inputs.post_state {
        return Err(format!(
            "receipt at height {} does not match the finality bundle at height {}",
            receipt.height(),
            inputs.height
        )
        .into());
    }

    fs::write(output, record.value())?;
    println!("checkpoint_height {}", receipt.height());
    println!("checkpoint_block_id {}", hex(receipt.block_id().as_bytes()));
    println!("checkpoint_state_root {}", hex(inputs.post_state.root().as_bytes()));
    println!("checkpoint_object_count {}", inputs.post_state.object_count());
    println!("validator_set_root {}", hex(inputs.validator_set_root.as_bytes()));
    println!("receipt_bytes {}", record.value().len());
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_BUNDLE_BYTES {
        return Err("input is not a bounded regular file".into());
    }
    Ok(fs::read(path)?)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
