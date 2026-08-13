//! Turns an applied deployment into a chain that can run.
//!
//! Generating a genesis, validator keys and a cash ledger is ordinary
//! provisioning: the reset script has always done it unattended, and a chain
//! serves blocks and funds wallets without anyone signing anything by hand.
//!
//! The trust ceremony is the exception, and it stays outside. A threshold
//! bundle needs signatures from parties who are not this process — automating
//! it would put every signer in one program and reduce a 2-of-3 to a 1-of-1.
//! A chain runs perfectly well without one; what needs it is the Actum verifier
//! trust path, which is a separate concern from having a network.
//!
//! Every secret this creates is written by the tools that own it, at the paths
//! the deployment expects, with the operator seed readable only by its owner.

use crate::NetworkPlan;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug)]
pub enum ProvisionError {
    /// No release is installed, so the tools that generate a genesis are absent.
    NoRelease(PathBuf),
    /// State already exists; provisioning again would orphan a running chain.
    AlreadyProvisioned(PathBuf),
    Tool {
        tool: String,
        detail: String,
    },
    Io(String),
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRelease(path) => write!(
                formatter,
                "no release binaries at {}; install a release before provisioning",
                path.display()
            ),
            Self::AlreadyProvisioned(path) => write!(
                formatter,
                "{} already exists; provisioning again would abandon the current chain",
                path.display()
            ),
            Self::Tool { tool, detail } => write!(formatter, "{tool} failed: {detail}"),
            Self::Io(detail) => write!(formatter, "{detail}"),
        }
    }
}

/// What provisioning produced, in terms an operator can check against a node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provisioned {
    pub genesis_commitment: String,
    pub treasury_owner: String,
    pub started: Vec<String>,
    /// Named because it is genuinely outstanding, not because it was skipped.
    pub remaining: Vec<String>,
}

/// Generates chain state and, optionally, starts the services.
///
/// # Errors
/// Refuses when no release is installed or when state already exists, and
/// surfaces any tool failure with the tool's own diagnostics.
pub fn provision(
    plan: &NetworkPlan,
    home: &Path,
    start_services: bool,
) -> Result<Provisioned, ProvisionError> {
    let root = home.join("activechain-deploy").join(&plan.name);
    let bin = root.join("current/bin");
    let genesis_tool = bin.join("genesis-tool");
    let cash_tool = bin.join("cash-genesis-tool");
    if !genesis_tool.exists() || !cash_tool.exists() {
        return Err(ProvisionError::NoRelease(bin));
    }
    let chain_dir = root.join("chain");
    let genesis_path = chain_dir.join("genesis.bin");
    if genesis_path.exists() {
        return Err(ProvisionError::AlreadyProvisioned(genesis_path));
    }
    // Not created here: genesis-tool makes the key directory itself and refuses
    // a pre-existing one, which is how it guarantees it is not writing a
    // validator key beside somebody else's. The seed below is written after it
    // runs, by which time the directory exists.
    let keys = chain_dir.join("keys");
    fs::create_dir_all(&chain_dir).map_err(|error| ProvisionError::Io(error.to_string()))?;

    // Validator set and genesis. The tool owns the keys it writes.
    let validators = plan.ports.validators.len().to_string();
    let genesis_output = run(
        &genesis_tool,
        &[
            genesis_path.to_string_lossy().as_ref(),
            "1",
            "1",
            &validators,
            keys.to_string_lossy().as_ref(),
        ],
    )?;
    let genesis_commitment = field(&genesis_output, "genesis_commitment=")
        .filter(|value| value.len() == 96 && value.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| ProvisionError::Tool {
            tool: "genesis-tool".to_owned(),
            detail: "did not return a 96-character genesis commitment".to_owned(),
        })?;

    // The faucet operator seed is a secret this process creates, so it is
    // written unreadable to anyone else before the tool that consumes it runs.
    let seed_path = keys.join("faucet-operator.seed");
    write_seed(&seed_path)?;

    let chain_id: String =
        plan.chain_id.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
    let cash_output = run(
        &cash_tool,
        &[
            chain_dir.join("cash-ledger.snapshot").to_string_lossy().as_ref(),
            &chain_id,
            "operator",
            &plan.genesis_supply.to_string(),
            &plan.security_reserve.to_string(),
            &format!("--operator-seed={}", seed_path.display()),
            &format!("--treasury-cells={}", plan.treasury_cells),
        ],
    )?;
    let treasury_owner = field(&cash_output, "cash_genesis_owner=")
        .filter(|value| value.len() == 96)
        .ok_or_else(|| ProvisionError::Tool {
            tool: "cash-genesis-tool".to_owned(),
            detail: "did not return a treasury owner".to_owned(),
        })?;

    // Only now do the commitments exist, so only now may they be recorded.
    // Writing them earlier would let a node start against a genesis nobody
    // generated.
    let network_env = root.join("network.env");
    let mut contents =
        fs::read_to_string(&network_env).map_err(|error| ProvisionError::Io(error.to_string()))?;
    contents.push_str(&format!(
        "ACTIVECHAIN_GENESIS_COMMITMENT_HEX={genesis_commitment}\n\
         ACTIVECHAIN_CASH_GENESIS_OWNER_HEX={treasury_owner}\n"
    ));
    fs::write(&network_env, contents).map_err(|error| ProvisionError::Io(error.to_string()))?;

    let started = if start_services { bootstrap(home, &plan.name)? } else { Vec::new() };

    Ok(Provisioned {
        genesis_commitment,
        treasury_owner,
        started,
        remaining: vec![
            "run the trust ceremony with its own signers if this network needs a verifier \
             trust bundle; a chain runs without one"
                .to_owned(),
        ],
    })
}

/// Loads the network's launch agents so the chain actually runs.
fn bootstrap(home: &Path, network: &str) -> Result<Vec<String>, ProvisionError> {
    let agents = home.join("Library/LaunchAgents");
    let prefix = format!("dev.activechain.{network}.");
    let mut started = Vec::new();
    let entries = fs::read_dir(&agents).map_err(|error| ProvisionError::Io(error.to_string()))?;
    let domain = format!("gui/{}", unsafe_uid());
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else { continue };
        let Some(label) = name.strip_suffix(".plist") else { continue };
        if !label.starts_with(&prefix) {
            continue;
        }
        // Already-loaded agents are booted out first, the same ordering the
        // activation script uses, because launchd refuses a duplicate label.
        let _ = Command::new("launchctl").args(["bootout", &format!("{domain}/{label}")]).output();
        let outcome = Command::new("launchctl")
            .args(["bootstrap", &domain, path.to_string_lossy().as_ref()])
            .output()
            .map_err(|error| ProvisionError::Io(error.to_string()))?;
        if outcome.status.success() {
            started.push(label.to_owned());
        }
    }
    Ok(started)
}

fn unsafe_uid() -> u32 {
    // `id -u` rather than a libc call, to keep this crate free of unsafe.
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(501)
}

fn run(tool: &Path, arguments: &[&str]) -> Result<String, ProvisionError> {
    let name = tool.file_name().unwrap_or_default().to_string_lossy().to_string();
    let output = Command::new(tool)
        .args(arguments)
        .output()
        .map_err(|error| ProvisionError::Tool { tool: name.clone(), detail: error.to_string() })?;
    if !output.status.success() {
        return Err(ProvisionError::Tool {
            tool: name,
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn field(output: &str, prefix: &str) -> Option<String> {
    output.lines().find_map(|line| line.strip_prefix(prefix)).map(str::to_owned)
}

/// Writes 32 bytes of system randomness, readable only by its owner.
fn write_seed(path: &Path) -> Result<(), ProvisionError> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|error| ProvisionError::Io(format!("no system randomness: {error}")))?;
    fs::write(path, seed).map_err(|error| ProvisionError::Io(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| ProvisionError::Io(error.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::manifest;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "activechain-provision-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("scratch home");
        path
    }

    #[test]
    fn provisioning_without_a_release_says_so_rather_than_half_succeeding() {
        let home = scratch("no-release");
        let plan = crate::plan(&manifest("kibera", 55_000)).unwrap();
        let outcome = provision(&plan, &home, false);
        assert!(
            matches!(outcome, Err(ProvisionError::NoRelease(_))),
            "expected a missing-release refusal, got {outcome:?}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// Provisioning over a chain that already has a genesis would abandon it,
    /// leaving validators holding state for a chain nobody can reach.
    #[test]
    fn provisioning_an_existing_chain_is_refused() {
        let home = scratch("existing");
        let plan = crate::plan(&manifest("kibera", 55_020)).unwrap();
        let root = home.join("activechain-deploy/kibera");
        let bin = root.join("current/bin");
        fs::create_dir_all(&bin).unwrap();
        for tool in ["genesis-tool", "cash-genesis-tool"] {
            fs::write(bin.join(tool), b"#!/bin/sh\nexit 0\n").unwrap();
        }
        fs::create_dir_all(root.join("chain")).unwrap();
        fs::write(root.join("chain/genesis.bin"), b"existing").unwrap();

        let outcome = provision(&plan, &home, false);
        assert!(
            matches!(outcome, Err(ProvisionError::AlreadyProvisioned(_))),
            "expected an already-provisioned refusal, got {outcome:?}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// The operator seed is a secret this process writes; it must not be
    /// readable by other accounts on a shared host.
    #[cfg(unix)]
    #[test]
    fn the_operator_seed_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let home = scratch("seed");
        let path = home.join("faucet-operator.seed");
        write_seed(&path).expect("seed");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the seed must be readable only by its owner");
        assert_eq!(fs::read(&path).unwrap().len(), 32);
        let _ = fs::remove_dir_all(&home);
    }
}
