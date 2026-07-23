use activechain_application_primitives::DurableAnchorRegistry;
use activechain_rpc_server::{
    DurableRpcStore, RpcAccessController, RpcServer, load_access_terms, verify_access_terms,
};
use activechain_rpc_types::RpcAccessMode;
use std::{
    env,
    net::TcpListener,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let snapshot = PathBuf::from(arguments.next().ok_or(
        "usage: activechain-rpc-node <rpc-index-snapshot> [bind-address] \
                 [access-terms] [usage-snapshot] [anchor-snapshot]",
    )?);
    let address = arguments.next().unwrap_or_else(|| "127.0.0.1:49151".to_owned());
    let access_terms = arguments.next().map(PathBuf::from);
    let usage_snapshot = arguments.next().map(PathBuf::from);
    let anchor_snapshot = arguments
        .next()
        .map(PathBuf::from)
        .or_else(|| env::var_os("ACTIVECHAIN_ANCHOR_SNAPSHOT").map(PathBuf::from));
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let store = Arc::new(
        DurableRpcStore::load(snapshot)
            .map_err(|error| format!("could not load RPC index: {error:?}"))?,
    );
    let listener = TcpListener::bind(&address)?;
    eprintln!("ActiveChain development RPC listening on {}", listener.local_addr()?);
    let server = if let Some(terms_path) = access_terms {
        let terms = load_access_terms(&terms_path)
            .map_err(|error| format!("could not load RPC access terms: {error:?}"))?;
        let startup_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock predates Unix epoch")?
            .as_secs();
        verify_access_terms(
            &terms,
            store
                .chain_id()
                .map_err(|error| format!("could not read RPC chain identity: {error:?}"))?,
            terms.operator_id(),
            startup_now,
        )
        .map_err(|error| format!("RPC access terms are not currently valid: {error:?}"))?;
        let access = if terms.mode() == RpcAccessMode::Free {
            if usage_snapshot.is_some() {
                return Err("free RPC access does not use a usage snapshot".into());
            }
            RpcAccessController::free(terms)
        } else {
            let usage_path =
                usage_snapshot.ok_or("non-free RPC access requires a usage snapshot path")?;
            if usage_path.exists() {
                RpcAccessController::load(terms, usage_path)
            } else {
                RpcAccessController::create(terms, usage_path)
            }
        }
        .map_err(|error| format!("could not initialize RPC access policy: {error:?}"))?;
        RpcServer::with_access(store, Arc::new(access))
            .map_err(|error| format!("RPC access policy does not match the index: {error:?}"))?
    } else {
        if usage_snapshot.is_some() {
            return Err("usage snapshot requires access terms".into());
        }
        RpcServer::new(store)
    };
    let server = if let Some(anchor_path) = anchor_snapshot {
        server.with_anchor_registry(
            DurableAnchorRegistry::open(anchor_path)
                .map_err(|error| format!("could not initialize anchor registry: {error:?}"))?,
        )
    } else {
        server
    };
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
