//! Validates network manifests and reports the plan, or refuses.
//!
//! ```text
//! activechain-network-plan <manifest.json> [more.json ...] [--json]
//! ```
//!
//! Every manifest named in one invocation is planned as a fleet sharing a host,
//! so name and port collisions between them are refused here rather than
//! discovered when the second network starts. Reads nothing else, contacts no
//! host, and creates nothing: a refusal costs only the time to read it.
//!
//! Exits non-zero on refusal.

use activechain_network_planner::{NetworkManifest, NetworkPlan, PlanError, plan_fleet};
use std::{env, fs, process::ExitCode};

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
    for argument in env::args().skip(1) {
        if argument == "--json" {
            as_json = true;
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
    if as_json {
        return serde_json::to_string_pretty(&plans)
            .map(|value| format!("{value}\n"))
            .map_err(|error| format!("could not encode the plan: {error}"));
    }
    Ok(plans.iter().map(render).collect())
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
        PlanError::TreasuryNotDivisible { cells } => format!(
            "the allocation does not divide into {cells} non-empty Coin Cells"
        ),
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
