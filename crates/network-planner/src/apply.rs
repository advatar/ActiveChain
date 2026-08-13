//! Writes a materialized plan to disk.
//!
//! Deliberately thin. Everything worth reviewing — what the files contain, what
//! the plan permits — was decided by the compiler and the renderer, both pure.
//! This layer only puts bytes where they belong, and refuses to do so when the
//! environment says it should not.
//!
//! What it does **not** do is generate keys or a genesis. Those need the
//! release's own tools and, in the trust ceremony's case, signers who are not
//! this process. Apply prepares the ground and stops at the boundary where
//! custody begins.

use crate::{NetworkPlan, preflight, render};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub enum ApplyError {
    /// The host is not in a state where this plan can be applied.
    Blocked(Vec<String>),
    /// Refusing to write over an existing deployment.
    AlreadyPresent(PathBuf),
    Io(String),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocked(findings) => {
                write!(formatter, "the host cannot accept this plan:\n  {}", findings.join("\n  "))
            }
            Self::AlreadyPresent(path) => write!(
                formatter,
                "a deployment already exists at {}; remove or archive it first",
                path.display()
            ),
            Self::Io(detail) => write!(formatter, "{detail}"),
        }
    }
}

/// What was written, so an operator can see it without inspecting the disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedRecord {
    pub network: String,
    /// Hex of the plan digest this deployment was produced from.
    pub plan_digest: String,
    pub root: PathBuf,
    pub directories: usize,
    pub files: Vec<String>,
    pub launch_agents: Vec<String>,
    /// Steps deliberately left to the operator, named rather than implied.
    pub remaining: Vec<String>,
}

/// Writes the deployment a plan describes.
///
/// `launch_agent_root` is where launchd reads from, normally
/// `~/Library/LaunchAgents`. It is a parameter so a test never writes there.
///
/// # Errors
/// Refuses when preflight reports a blocking finding, when a deployment is
/// already present, or on any write failure. Nothing is loaded or started here:
/// producing the files and activating them are separate acts.
pub fn apply(
    plan: &NetworkPlan,
    home: &Path,
    launch_agent_root: &Path,
) -> Result<AppliedRecord, ApplyError> {
    let home_text = home.to_string_lossy().to_string();
    let root = home.join("activechain-deploy").join(&plan.name);

    let assessment = preflight::assess(plan, &root);
    let blocking: Vec<String> =
        assessment.blocking().iter().map(|finding| finding.to_string()).collect();
    if !blocking.is_empty() {
        // The existing-root finding gets its own error, because it is the one
        // an operator resolves differently from the rest.
        if root.exists() {
            return Err(ApplyError::AlreadyPresent(root));
        }
        return Err(ApplyError::Blocked(blocking));
    }

    let materialization = render::materialize(plan, &home_text);
    // The plan is written into the deployment so the network can later be
    // described without guessing: ports, hostnames, and the digest that
    // identifies which plan produced it. A deployment nobody can account for
    // is how a host accumulates networks whose configuration is folklore.
    let plan_record = serde_json::to_string_pretty(plan)
        .map_err(|error| ApplyError::Io(format!("could not record the plan: {error}")))?;
    for directory in &materialization.directories {
        fs::create_dir_all(directory).map_err(|error| io_error("create", directory, &error))?;
    }
    for (name, body) in &materialization.files {
        let path = root.join(name);
        write_new(&path, body)?;
    }
    write_new(&root.join("plan.json"), &plan_record)?;
    fs::create_dir_all(launch_agent_root)
        .map_err(|error| io_error("create", &launch_agent_root.display().to_string(), &error))?;
    for (label, body) in &materialization.launch_agents {
        let path = launch_agent_root.join(format!("{label}.plist"));
        write_new(&path, body)?;
    }

    let digest = plan
        .digest()
        .map(|value| value.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect())
        .unwrap_or_else(|_| "unavailable".to_owned());

    Ok(AppliedRecord {
        network: plan.name.clone(),
        plan_digest: digest,
        root,
        directories: materialization.directories.len(),
        files: materialization
            .files
            .iter()
            .map(|(name, _)| name.clone())
            .chain(std::iter::once("plan.json".to_owned()))
            .collect(),
        launch_agents: materialization
            .launch_agents
            .iter()
            .map(|(label, _)| label.clone())
            .collect(),
        remaining: vec![
            "generate validator keys and the genesis with the release's genesis-tool".to_owned(),
            "generate the cash ledger with cash-genesis-tool, using the treasury cell count \
             recorded in network.env"
                .to_owned(),
            "run the trust ceremony with its own signers and assemble the verifier bundle"
                .to_owned(),
            "bootstrap the launch agents once the genesis and keys exist".to_owned(),
        ],
    })
}

/// Never overwrites. A deployment file that already exists is either a second
/// apply or something an operator put there, and silently replacing either is
/// how state gets lost.
fn write_new(path: &Path, body: &str) -> Result<(), ApplyError> {
    if path.exists() {
        return Err(ApplyError::AlreadyPresent(path.to_path_buf()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| io_error("create", &parent.display().to_string(), &error))?;
    }
    fs::write(path, body).map_err(|error| io_error("write", &path.display().to_string(), &error))
}

fn io_error(action: &str, path: &str, error: &io::Error) -> ApplyError {
    ApplyError::Io(format!("could not {action} {path}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::manifest;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "activechain-apply-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        // A real operator's home exists; only the deploy tree beneath it does not.
        fs::create_dir_all(&path).expect("scratch home");
        path
    }

    #[test]
    fn applying_writes_a_complete_deployment_and_names_what_it_left_undone() {
        let home = scratch("complete");
        let agents = home.join("LaunchAgents");
        let plan = crate::plan(&manifest("kibera", 51_001)).unwrap();

        let record = apply(&plan, &home, &agents).expect("a clean host must accept the plan");
        assert_eq!(record.network, "kibera");
        assert_eq!(record.plan_digest.len(), 96, "the record carries the plan's identity");
        assert!(home.join("activechain-deploy/kibera/network.env").exists());
        assert!(
            home.join("activechain-deploy/kibera/plan.json").exists(),
            "a deployment must record the plan that produced it"
        );
        assert!(home.join("activechain-deploy/kibera/chain").is_dir());
        assert!(agents.join("dev.activechain.kibera.rpc.plist").exists());
        assert!(agents.join("dev.activechain.kibera.validator0.plist").exists());

        // Key material and genesis are not this process's business, and saying
        // so is better than leaving an operator to discover the gap.
        assert!(record.remaining.iter().any(|step| step.contains("trust ceremony")));
        assert!(record.remaining.iter().any(|step| step.contains("genesis-tool")));

        let _ = fs::remove_dir_all(&home);
    }

    /// Applying twice must not quietly rewrite a live deployment.
    #[test]
    fn applying_over_an_existing_deployment_is_refused() {
        let home = scratch("existing");
        let agents = home.join("LaunchAgents");
        let plan = crate::plan(&manifest("kibera", 51_020)).unwrap();

        apply(&plan, &home, &agents).expect("first apply");
        let second = apply(&plan, &home, &agents);
        assert!(
            matches!(second, Err(ApplyError::AlreadyPresent(_))),
            "a second apply must refuse, got {second:?}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// Two networks applied to one host must not touch each other's files.
    #[test]
    fn two_networks_apply_side_by_side_without_collision() {
        let home = scratch("fleet");
        let agents = home.join("LaunchAgents");
        let first = crate::plan(&manifest("kanalen", 51_040)).unwrap();
        let second = crate::plan(&manifest("kibera", 51_060)).unwrap();

        apply(&first, &home, &agents).expect("first network");
        apply(&second, &home, &agents).expect("second network must not disturb the first");

        assert!(home.join("activechain-deploy/kanalen/network.env").exists());
        assert!(home.join("activechain-deploy/kibera/network.env").exists());
        assert!(agents.join("dev.activechain.kanalen.rpc.plist").exists());
        assert!(agents.join("dev.activechain.kibera.rpc.plist").exists());

        let one = fs::read_to_string(home.join("activechain-deploy/kanalen/network.env")).unwrap();
        let two = fs::read_to_string(home.join("activechain-deploy/kibera/network.env")).unwrap();
        assert_ne!(one, two, "each network must carry its own derived chain id");
        let _ = fs::remove_dir_all(&home);
    }
}
