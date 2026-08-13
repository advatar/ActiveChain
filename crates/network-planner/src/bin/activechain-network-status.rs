//! Reports every ActiveChain network deployed on this host.
//!
//! ```text
//! activechain-network-status [--home <dir>] [--json]
//! ```
//!
//! Reads the plan each deployment recorded when it was applied, so what is
//! shown is what was intended, and probes the ports so the difference between
//! intention and reality is visible. Read-only: it starts nothing, stops
//! nothing, and changes nothing.

use activechain_network_planner::fleet;
use std::{env, path::PathBuf, process::ExitCode};

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
    let mut home: Option<PathBuf> = None;
    let mut as_json = false;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--json" => as_json = true,
            "--home" => {
                home = Some(PathBuf::from(
                    arguments.next().ok_or_else(|| "--home needs a directory".to_owned())?,
                ));
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    let home = home
        .or_else(|| env::var_os("HOME").map(PathBuf::from))
        .ok_or_else(|| "could not determine the home directory; pass --home".to_owned())?;

    let fleet = fleet::discover(&home);
    if as_json {
        return render_json(&fleet);
    }

    if fleet.deployments.is_empty() && fleet.unaccounted.is_empty() {
        return Ok(format!("no ActiveChain networks are deployed under {}\n", home.display()));
    }

    let mut out = String::new();
    for deployment in &fleet.deployments {
        let plan = &deployment.plan;
        let chain: String =
            plan.chain_id.as_bytes().iter().take(8).map(|byte| format!("{byte:02x}")).collect();
        let state = if deployment.fully_running() {
            "running"
        } else if deployment.stopped() {
            "stopped"
        } else {
            "partial"
        };
        out.push_str(&format!("{:<12} {state:<8} chain {chain}…\n", plan.name));
        out.push_str(&format!("  domain            {}\n", plan.domain));
        out.push_str(&format!("  rpc               {}\n", plan.rpc_hostname));
        out.push_str(&format!(
            "  treasury          {} Coin Cells, {} grant(s) of capacity\n",
            plan.treasury_cells, plan.grant_capacity
        ));
        for (role, port, running) in &deployment.services {
            out.push_str(&format!(
                "  {role:<16}  {port}  {}\n",
                if *running { "listening" } else { "-" }
            ));
        }
    }
    // Named rather than omitted: a deployment nobody can describe is the one
    // most worth knowing about.
    for name in &fleet.unaccounted {
        out.push_str(&format!(
            "{name:<12} unknown  no recorded plan; this deployment cannot be described\n"
        ));
    }
    Ok(out)
}

/// Typed rather than `serde_json::Value`: a `Value::Number` cannot hold a
/// `u128` above `u64::MAX`, and a genesis supply routinely is.
#[derive(serde::Serialize)]
struct FleetReport<'a> {
    deployments: Vec<DeploymentReport<'a>>,
    unaccounted: &'a [String],
}

#[derive(serde::Serialize)]
struct DeploymentReport<'a> {
    plan: &'a activechain_network_planner::NetworkPlan,
    services: Vec<ServiceReport<'a>>,
}

#[derive(serde::Serialize)]
struct ServiceReport<'a> {
    role: &'a str,
    port: u16,
    listening: bool,
}

fn render_json(fleet: &fleet::Fleet) -> Result<String, String> {
    let report = FleetReport {
        deployments: fleet
            .deployments
            .iter()
            .map(|deployment| DeploymentReport {
                plan: &deployment.plan,
                services: deployment
                    .services
                    .iter()
                    .map(|(role, port, listening)| ServiceReport {
                        role,
                        port: *port,
                        listening: *listening,
                    })
                    .collect(),
            })
            .collect(),
        unaccounted: &fleet.unaccounted,
    };
    serde_json::to_string_pretty(&report)
        .map(|value| format!("{value}\n"))
        .map_err(|error| format!("could not encode the fleet: {error}"))
}
