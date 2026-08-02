use activechain_application_primitives::DurableAnchorRegistry;
use activechain_protocol_types::{Digest384, PrincipalId};
use activechain_rpc_server::{
    DurableFaucet, DurableOperatorFaucetSettlement, DurableRpcStore, FaucetPolicy,
    MlDsa44FaucetAuthorizer, RpcAccessController, RpcServer, SpoolOperatorFaucetIngressAdapter,
    SybilPolicy, WalletIngressOperatorSettlementAdapter, load_access_terms, verify_access_terms,
};
use activechain_rpc_types::RpcAccessMode;
use ml_dsa::{MlDsa44, Seed, SigningKey};
use std::{
    collections::BTreeSet,
    env,
    net::TcpListener,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

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
    let wallet_state = if let Some(wallet_path) = wallet_path {
        let ingress = activechain_wallet_core::TransactionIngress::load(&wallet_path, chain_id)
            .map_err(|error| format!("could not load wallet ingress snapshot: {error:?}"))?;
        Some((Arc::new(std::sync::Mutex::new(ingress)), wallet_path))
    } else {
        None
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
        let server = server.with_faucet(faucet);
        if policy.enabled {
            let (ingress, wallet_path) =
                wallet_state.as_ref().ok_or("enabled faucet requires wallet ingress state")?;
            let seed_path = PathBuf::from(required_env("ACTIVECHAIN_FAUCET_OPERATOR_SEED")?);
            let signing_key = load_operator_key(&seed_path)?;
            let source = parse_principal(&required_env("ACTIVECHAIN_FAUCET_SOURCE")?)?;
            let journal = PathBuf::from(required_env("ACTIVECHAIN_FAUCET_SETTLEMENT_JOURNAL")?);
            let authorizer = MlDsa44FaucetAuthorizer::new(
                Arc::clone(ingress),
                chain_id,
                source,
                signing_key,
                required_env("ACTIVECHAIN_FAUCET_FEE")?.parse()?,
                required_env("ACTIVECHAIN_FAUCET_VALIDITY_BLOCKS")?.parse()?,
                Arc::clone(&store),
            )
            .map_err(|error| format!("invalid faucet operator policy: {error:?}"))?;
            let authorizer = authorizer.with_snapshot_reload(wallet_path.clone());
            let spool = env::var_os("ACTIVECHAIN_FAUCET_ACTION_SPOOL").map(PathBuf::from);
            let ingress_adapter = match spool {
                Some(path) => {
                    FaucetIngress::Spool(SpoolOperatorFaucetIngressAdapter::new(path).map_err(
                        |error| format!("could not initialize faucet action spool: {error:?}"),
                    )?)
                }
                None => FaucetIngress::Local(WalletIngressOperatorSettlementAdapter::new(
                    Arc::clone(ingress),
                    wallet_path.clone(),
                    Arc::clone(&store),
                )),
            };
            let settlement = if journal.exists() {
                DurableOperatorFaucetSettlement::open(journal, authorizer, ingress_adapter)
            } else {
                DurableOperatorFaucetSettlement::create(journal, authorizer, ingress_adapter)
            }
            .map_err(|error| format!("could not initialize faucet settlement: {error:?}"))?;
            server.with_faucet_settlement_adapter(settlement)
        } else {
            server
        }
    } else {
        server
    };
    let finality_archive =
        env::var_os("ACTIVECHAIN_FAUCET_FINALITY_ARCHIVE_DIR").map(PathBuf::from);
    let mut reconciled_archives = BTreeSet::new();
    loop {
        if let Some(directory) = finality_archive.as_ref() {
            reconcile_faucet_archives(&server, directory, &mut reconciled_archives)?;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock predates Unix epoch")?
            .as_secs();
        if let Err(error) = server.serve_once(&listener, now) {
            eprintln!("RPC request rejected: {error:?}");
        }
    }
}

fn reconcile_faucet_archives(
    server: &RpcServer,
    directory: &PathBuf,
    reconciled: &mut BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(height) = name.strip_prefix("pending-cash-actions.batch.finalized-") else {
            continue;
        };
        if reconciled.contains(&name) {
            continue;
        }
        let finality = directory.join(format!("finality.bundle.finalized-{height}"));
        if !finality.is_file() {
            continue;
        }
        let batch = std::fs::read(entry.path())?;
        let proof = std::fs::read(finality)?;
        server
            .reconcile_faucet_finality(&batch, &proof)
            .map_err(|error| format!("could not reconcile faucet archive {name}: {error:?}"))?;
        reconciled.insert(name);
    }
    Ok(())
}

enum FaucetIngress {
    Local(WalletIngressOperatorSettlementAdapter),
    Spool(SpoolOperatorFaucetIngressAdapter),
}

impl activechain_rpc_server::OperatorFaucetIngressAdapter for FaucetIngress {
    fn settle_operator_authorization(
        &self,
        authorization: &activechain_wallet_core::OperatorFaucetAuthorizationV1,
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<activechain_protocol_types::TransactionId, activechain_rpc_server::FaucetError>
    {
        match self {
            Self::Local(adapter) => {
                activechain_rpc_server::OperatorFaucetIngressAdapter::settle_operator_authorization(
                    adapter,
                    authorization,
                    recipient,
                    amount,
                    reference,
                )
            }
            Self::Spool(adapter) => {
                activechain_rpc_server::OperatorFaucetIngressAdapter::settle_operator_authorization(
                    adapter,
                    authorization,
                    recipient,
                    amount,
                    reference,
                )
            }
        }
    }
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("{name} is required when faucet is enabled").into())
}

fn load_operator_key(path: &PathBuf) -> Result<SigningKey<MlDsa44>, Box<dyn std::error::Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err("faucet operator seed must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("faucet operator seed must not be group/world accessible".into());
        }
    }
    let mut bytes = std::fs::read(path)?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err("faucet operator seed must contain exactly 32 binary bytes".into());
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&bytes);
    bytes.zeroize();
    let key = SigningKey::<MlDsa44>::from_seed(&Seed::from(seed));
    seed.zeroize();
    Ok(key)
}

fn parse_principal(value: &str) -> Result<PrincipalId, Box<dyn std::error::Error>> {
    if value.len() != 96 {
        return Err("faucet source principal must be 96 lowercase hexadecimal characters".into());
    }
    let mut bytes = [0_u8; 48];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    let digest = Digest384::new(bytes);
    if digest == Digest384::ZERO {
        return Err("faucet source principal cannot be zero".into());
    }
    Ok(PrincipalId::new(digest))
}

fn hex_nibble(byte: u8) -> Result<u8, Box<dyn std::error::Error>> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("faucet source principal must use lowercase hexadecimal".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_seed_requires_exact_private_regular_file() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir()
            .join(format!("activechain-faucet-operator-seed-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, [7_u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_operator_key(&path).is_ok());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_operator_key(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, [7_u8; 31]).unwrap();
        assert!(load_operator_key(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn source_principal_parser_is_strict_lowercase_nonzero_hex() {
        assert!(parse_principal(&"11".repeat(48)).is_ok());
        assert!(parse_principal(&"00".repeat(48)).is_err());
        assert!(parse_principal(&"AA".repeat(48)).is_err());
        assert!(parse_principal("11").is_err());
    }
}
