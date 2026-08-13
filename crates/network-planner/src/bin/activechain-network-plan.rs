//! Validates network manifests and reports the plan, or refuses.
//!
//! ```text
//! activechain-network-plan <manifest.json> [more.json ...] [--json]
//! activechain-network-plan <manifest.json> --apply [--home <dir>]
//! activechain-network-plan <manifest.json> --provision   # apply and generate a genesis
//! activechain-network-plan <manifest.json> --start       # and load the launch agents
//! ```
//!
//! Without `--apply` nothing is written: the plan is validated and reported.
//! With it, the deployment's files and launch agents are created. Keys, the
//! genesis, and the trust ceremony are deliberately left to the operator and
//! named in the result.
//!
//! Every manifest named in one invocation is planned as a fleet sharing a host,
//! so name and port collisions between them are refused here rather than
//! discovered when the second network starts. Reads nothing else, contacts no
//! host, and creates nothing: a refusal costs only the time to read it.
//!
//! Exits non-zero on refusal.

use activechain_network_planner::{
    NetworkManifest, NetworkPlan, PlanError, apply, plan_fleet, preflight, provision,
};
use std::{env, fs, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let mut paths = Vec::new();
    let mut as_json = false;
    let mut applying = false;
    let mut provisioning = false;
    let mut starting = false;
    let mut home: Option<PathBuf> = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--json" {
            as_json = true;
        } else if argument == "--apply" {
            applying = true;
        } else if argument == "--provision" {
            applying = true;
            provisioning = true;
        } else if argument == "--start" {
            applying = true;
            provisioning = true;
            starting = true;
        } else if argument == "--home" {
            home = Some(PathBuf::from(
                arguments.next().ok_or_else(|| "--home needs a directory".to_owned())?,
            ));
        } else if argument.starts_with('-') {
            return Err(format!("unknown option {argument}"));
        } else {
            paths.push(argument);
        }
    }
    if paths.is_empty() {
        return Err(
            "usage: activechain-network-plan <manifest.json> [more.json ...] [--json]".to_owned()
        );
    }

    let mut manifests = Vec::with_capacity(paths.len());
    for path in &paths {
        let bytes = fs::read(path).map_err(|error| format!("could not read {path}: {error}"))?;
        manifests.push(
            serde_json::from_slice::<NetworkManifest>(&bytes)
                .map_err(|error| format!("{path} is not a valid network manifest: {error}"))?,
        );
    }

    let plans = plan_fleet(&manifests).map_err(describe)?;

    if applying {
        let home = home
            .or_else(|| env::var_os("HOME").map(PathBuf::from))
            .ok_or_else(|| "could not determine the home directory; pass --home".to_owned())?;
        let agents = home.join("Library/LaunchAgents");
        let mut report = String::new();
        for plan in &plans {
            // An existing deployment is not an error when the goal is to
            // provision it: an operator may apply one day and provision the
            // next. It stays an error when apply is the whole request, because
            // then it would silently do nothing.
            let record = match apply::apply(plan, &home, &agents) {
                Ok(record) => record,
                Err(apply::ApplyError::AlreadyPresent(_)) if provisioning => {
                    report.push_str(&format!("{} already applied\n", plan.name));
                    provision_into(&mut report, plan, &home, starting)?;
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            };
            report.push_str(&format!(
                "applied {} at {}\n  plan digest      {}\n  wrote            {} directories, \
                 {} file(s), {} launch agent(s)\n",
                record.network,
                record.root.display(),
                record.plan_digest,
                record.directories,
                record.files.len(),
                record.launch_agents.len()
            ));
            if provisioning {
                provision_into(&mut report, plan, &home, starting)?;
            } else {
                for step in &record.remaining {
                    report.push_str(&format!("  still to do      {step}\n"));
                }
            }
        }
        return Ok(report);
    }

    // Reporting a plan also reports what this host would say about it, so an
    // operator sees both the intent and the circumstance before applying.
    let mut environment = String::new();
    if let Some(root) = env::var_os("HOME").map(PathBuf::from) {
        for plan in &plans {
            let assessment =
                preflight::assess(plan, &root.join("activechain-deploy").join(&plan.name));
            for finding in &assessment.findings {
                environment.push_str(&format!("  host              {finding}\n"));
            }
        }
    }

    if as_json {
        return serde_json::to_string_pretty(&plans)
            .map(|value| format!("{value}\n"))
            .map_err(|error| format!("could not encode the plan: {error}"));
    }
    Ok(plans.iter().map(render).collect::<String>() + &environment)
}

fn provision_into(
    report: &mut String,
    plan: &NetworkPlan,
    home: &std::path::Path,
    starting: bool,
) -> Result<(), String> {
    let done = provision::provision(plan, home, starting)
        .map_err(|error| format!("provisioning {}: {error}", plan.name))?;
    report.push_str(&format!(
        "  genesis          {}…\n  treasury owner   {}…\n",
        &done.genesis_commitment[..16],
        &done.treasury_owner[..16]
    ));
    if starting {
        report.push_str(&format!("  started          {} service(s)\n", done.started.len()));
    }
    for step in &done.remaining {
        report.push_str(&format!("  still to do      {step}\n"));
    }
    Ok(())
}

fn render(plan: &NetworkPlan) -> String {
    let mut out = format!("network {}\n", plan.name);
    out.push_str(&format!("  deployment root   {}\n", plan.deployment_root));
    out.push_str(&format!(
        "  ports             rpc {} validators {:?} anchor {} work-proof {} (reserved {}-{})\n",
        plan.ports.rpc,
        plan.ports.validators,
        plan.ports.anchor,
        plan.ports.work_proof,
        plan.ports.reserved.0,
        plan.ports.reserved.1
    ));
    out.push_str(&format!("  launch agents     {}\n", plan.launch_labels.join(", ")));
    out.push_str(&format!(
        "  treasury          {} Coin Cells of a {}-cell index budget\n",
        plan.treasury_cells, plan.indexed_cell_ceiling
    ));
    out.push_str(&format!("  grant capacity    {} recipient(s)\n", plan.grant_capacity));
    for advisory in &plan.advisories {
        out.push_str(&format!("  note              {advisory}\n"));
    }
    out
}

/// Refusals say what is wrong and what would fix it. A planner that only says
/// "invalid" leaves the operator to rediscover the reason on a live host.
fn describe(error: PlanError) -> String {
    match error {
        PlanError::NameNotALabel(name) => format!(
            "network name {name:?} is not usable as a launchd label, a path, and a hostname: \
             use lowercase letters, digits and single hyphens, starting with a letter"
        ),
        PlanError::NoValidators => "a network needs at least one validator".to_owned(),
        PlanError::TreasuryCannotSpend { cells } => format!(
            "a treasury of {cells} Coin Cell(s) can never construct a transfer: a transfer \
             consumes an input and a distinct fee reserve, so at least 2 are required"
        ),
        PlanError::TreasuryExceedsIndex { cells, ceiling } => format!(
            "{cells} Coin Cells exceed the {ceiling} the RPC index can publish; the round \
             would fail with Invalid and the index would stay empty"
        ),
        PlanError::TreasuryNotDivisible { cells } => {
            format!("the allocation does not divide into {cells} non-empty Coin Cells")
        }
        PlanError::SecurityReserveExceedsSupply => {
            "the security reserve must be smaller than the genesis supply".to_owned()
        }
        PlanError::RecipientsCannotSpend { cells_per_grant } => format!(
            "a grant of {cells_per_grant} Coin Cell(s) leaves the recipient unable to spend it: \
             deliver at least 2, since a transfer needs an input and a distinct fee reserve"
        ),
        PlanError::NoGrantCapacity { cells, cells_per_grant } => format!(
            "a treasury of {cells} cells cannot fund even one recipient at {cells_per_grant} \
             cell(s) per grant and remain able to spend"
        ),
        PlanError::GrantBelowFee { grant_amount, fee } => {
            format!("a grant of {grant_amount} does not cover its own fee of {fee}")
        }
        PlanError::ThresholdExceedsSigners { threshold, signers } => {
            format!("a threshold of {threshold} cannot be met by {signers} signer(s)")
        }
        PlanError::ThresholdIsZero => "a trust threshold of zero signs nothing".to_owned(),
        PlanError::BasePortTooLow(port) => {
            format!("base port {port} is privileged or in common use; use 1024 or above")
        }
        PlanError::PortRangeOverlaps { other } => format!(
            "this network's reserved port range overlaps {other}; space the base ports by at \
             least 16"
        ),
        PlanError::HostnameEmpty(role) => format!("the {role} hostname is empty"),
        PlanError::HostnamesNotDistinct => {
            "the rpc, anchor and verify hostnames must differ".to_owned()
        }
        PlanError::DuplicateNetworkName(name) => {
            format!("two networks are both named {name:?}; names must be unique on a host")
        }
        PlanError::TooManyValidatorsForReservation { validators } => format!(
            "{validators} validators do not fit the per-network port reservation; at most 3 \
             fit alongside the rpc, anchor and work-proof ports"
        ),
    }
}
