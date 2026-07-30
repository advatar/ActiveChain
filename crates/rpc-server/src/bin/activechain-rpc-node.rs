use activechain_application_primitives::DurableAnchorRegistry;
use activechain_rpc_server::{
    DurableFaucet, DurableRpcStore, FaucetPolicy, RpcAccessController, RpcServer, SybilPolicy,
    WalletIngressAuthorizedSettlementAdapter, load_access_terms, verify_access_terms,
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
    let chain_id = store
        .chain_id()
        .map_err(|error| format!("could not read RPC chain identity: {error:?}"))?;
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
        RpcServer::with_access(Arc::clone(&store), Arc::new(access))
            .map_err(|error| format!("RPC access policy does not match the index: {error:?}"))?
    } else {
        if usage_snapshot.is_some() {
            return Err("usage snapshot requires access terms".into());
        }
        RpcServer::new(Arc::clone(&store))
    };
    let server = if let Some(anchor_path) = anchor_snapshot {
        server.with_anchor_registry(
            DurableAnchorRegistry::open(anchor_path)
                .map_err(|error| format!("could not initialize anchor registry: {error:?}"))?,
        )
    } else {
        server
    };
    let wallet_path = env::var_os("ACTIVECHAIN_WALLET_INGRESS_SNAPSHOT").map(PathBuf::from);
    let wallet_ingress_enabled = wallet_path.is_some();
    let server = if let Some(wallet_path) = wallet_path {
        let ingress = activechain_wallet_core::TransactionIngress::load(&wallet_path, chain_id)
            .map_err(|error| format!("could not load wallet ingress snapshot: {error:?}"))?;
        let adapter = WalletIngressAuthorizedSettlementAdapter::new(
            Arc::new(std::sync::Mutex::new(ingress)),
            wallet_path,
            Arc::clone(&store),
        );
        server.with_authorized_faucet_settlement_adapter(adapter)
    } else {
        server
    };
    let server = if let Some(faucet_path) = env::var_os("ACTIVECHAIN_FAUCET_SNAPSHOT") {
        if !wallet_ingress_enabled {
            return Err("faucet snapshot requires ACTIVECHAIN_WALLET_INGRESS_SNAPSHOT".into());
        }
        let faucet_path = PathBuf::from(faucet_path);
        let policy = FaucetPolicy {
            chain_id,
            genesis_commitment: store
                .genesis_commitment()
                .map_err(|error| format!("could not read faucet genesis: {error:?}"))?,
            testnet_only: true,
            enabled: required_env("ACTIVECHAIN_FAUCET_ENABLED")?.parse::<bool>()?,
            policy_revision: required_env("ACTIVECHAIN_FAUCET_POLICY_REVISION")?.parse()?,
            valid_until: required_env("ACTIVECHAIN_FAUCET_VALID_UNTIL")?.parse()?,
            grant_amount: required_env("ACTIVECHAIN_FAUCET_GRANT_AMOUNT")?.parse()?,
            recipient_cooldown_seconds: required_env("ACTIVECHAIN_FAUCET_RECIPIENT_COOLDOWN")?
                .parse()?,
            recipient_lifetime_limit: required_env("ACTIVECHAIN_FAUCET_RECIPIENT_LIMIT")?
                .parse()?,
            source_window_seconds: required_env("ACTIVECHAIN_FAUCET_SOURCE_WINDOW")?.parse()?,
            source_window_limit: required_env("ACTIVECHAIN_FAUCET_SOURCE_LIMIT")?.parse()?,
            global_window_seconds: required_env("ACTIVECHAIN_FAUCET_GLOBAL_WINDOW")?.parse()?,
            global_window_limit: required_env("ACTIVECHAIN_FAUCET_GLOBAL_LIMIT")?.parse()?,
            sybil_policy: match env::var("ACTIVECHAIN_FAUCET_POW_BITS") {
                Ok(bits) => SybilPolicy::ProofOfWork { leading_zero_bits: bits.parse()? },
                Err(env::VarError::NotPresent) => SybilPolicy::CooldownOnly,
                Err(error) => return Err(error.into()),
            },
        };
        let faucet = if faucet_path.exists() {
            DurableFaucet::open(policy, faucet_path)
        } else {
            DurableFaucet::create(policy, faucet_path)
        }
        .map_err(|error| format!("could not initialize faucet: {error:?}"))?;
        server.with_faucet(faucet)
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

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("{name} is required when faucet is enabled").into())
}
