use activechain_rpc_server::query;
use activechain_rpc_types::{RpcRequest, RpcResponse};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let address = arguments.next().unwrap_or_else(|| "127.0.0.1:49151".to_owned());
    if arguments.next().is_some() {
        return Err("usage: activechain-rpc-probe [host:port]".into());
    }
    let RpcResponse::Status(status) = query(&address, &RpcRequest::Status)
        .map_err(|error| format!("RPC query failed: {error:?}"))?
    else {
        return Err("RPC did not return status".into());
    };
    println!(
        "chain_id={} genesis={} protocol_revision={} rpc_schema_revision={} \
         finalized_height={} health={:?}",
        encode_hex(status.chain_id().digest().as_bytes()),
        encode_hex(status.genesis_commitment().as_bytes()),
        status.protocol_revision(),
        status.rpc_schema_revision(),
        status.finalized_height(),
        status.health(),
    );
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
