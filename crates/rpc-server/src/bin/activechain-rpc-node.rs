use activechain_rpc_server::{DurableRpcStore, RpcServer};
use std::{
    env,
    net::TcpListener,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let snapshot = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: activechain-rpc-node <rpc-index-snapshot> [bind-address]")?,
    );
    let address = arguments.next().unwrap_or_else(|| "127.0.0.1:49151".to_owned());
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let store = Arc::new(
        DurableRpcStore::load(snapshot)
            .map_err(|error| format!("could not load RPC index: {error:?}"))?,
    );
    let listener = TcpListener::bind(&address)?;
    eprintln!("ActiveChain development RPC listening on {}", listener.local_addr()?);
    let server = RpcServer::new(store);
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock predates Unix epoch")?
            .as_secs();
        if let Err(error) = server.serve_once(&listener, now) {
            eprintln!("RPC request rejected: {error:?}");
        }
    }
}
