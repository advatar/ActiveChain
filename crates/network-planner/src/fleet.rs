//! Reports every network deployed on a host.
//!
//! An operator running several networks needs to know what is actually there,
//! not what they remember putting there. Until now that meant reading launch
//! agents and guessing which ports belonged to whom, which is exactly how a
//! host accumulates deployments whose configuration is folklore.
//!
//! This reads the plan each deployment recorded when it was applied, so what is
//! reported is what was intended, and compares it against what is listening, so
//! the difference between the two is visible rather than assumed.

use crate::{NetworkPlan, preflight};
use std::{fs, path::Path};

/// One deployment found on the host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Deployment {
    pub plan: NetworkPlan,
    /// Whether each service's port is currently bound, by role.
    pub services: Vec<(String, u16, bool)>,
}

impl Deployment {
    /// Every service is answering.
    #[must_use]
    pub fn fully_running(&self) -> bool {
        self.services.iter().all(|(_, _, running)| *running)
    }

    /// Nothing is answering, which usually means it was never started rather
    /// than that it failed.
    #[must_use]
    pub fn stopped(&self) -> bool {
        self.services.iter().all(|(_, _, running)| !*running)
    }
}

/// What a host is running, and what it cannot account for.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Fleet {
    pub deployments: Vec<Deployment>,
    /// Directories that look like deployments but carry no recorded plan.
    ///
    /// Reported rather than skipped: a network nobody can describe is worth
    /// knowing about, and silently omitting it would make the report a
    /// comforting fiction.
    pub unaccounted: Vec<String>,
}

/// Reads every deployment under a home directory.
///
/// Performs I/O by design, like [`crate::preflight`]: it describes a host at a
/// moment, and says nothing about whether a plan is sound.
#[must_use]
pub fn discover(home: &Path) -> Fleet {
    let root = home.join("activechain-deploy");
    let Ok(entries) = fs::read_dir(&root) else {
        return Fleet::default();
    };

    let mut fleet = Fleet::default();
    let mut names: Vec<_> =
        entries.flatten().filter(|entry| entry.path().is_dir()).map(|entry| entry.path()).collect();
    names.sort();

    for path in names {
        let recorded = fs::read_to_string(path.join("plan.json"))
            .ok()
            .and_then(|text| serde_json::from_str::<NetworkPlan>(&text).ok());
        match recorded {
            Some(plan) => {
                let services = probe(&plan);
                fleet.deployments.push(Deployment { plan, services });
            }
            None => fleet
                .unaccounted
                .push(path.file_name().unwrap_or_default().to_string_lossy().to_string()),
        }
    }
    fleet
}

/// A bound port is the only evidence available without talking to a service,
/// and it is honest about what it means: something is listening there, not that
/// the network is healthy.
fn probe(plan: &NetworkPlan) -> Vec<(String, u16, bool)> {
    let mut services = vec![("rpc".to_owned(), plan.ports.rpc)];
    for (index, port) in plan.ports.validators.iter().enumerate() {
        services.push((format!("validator{index}"), *port));
    }
    services.push(("anchor".to_owned(), plan.ports.anchor));
    services.push(("work-proof".to_owned(), plan.ports.work_proof));
    services
        .into_iter()
        .map(|(role, port)| {
            let listening = !preflight::port_is_free(port);
            (role, port, listening)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{apply, tests_support::manifest};
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "activechain-fleet-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("scratch home");
        path
    }

    #[test]
    fn every_applied_network_is_reported_with_the_plan_it_was_built_from() {
        let home = scratch("reported");
        let agents = home.join("LaunchAgents");
        for (name, port) in [("kanalen", 53_000_u16), ("kibera", 53_020)] {
            let plan = crate::plan(&manifest(name, port)).unwrap();
            apply::apply(&plan, &home, &agents).expect("apply");
        }

        let fleet = discover(&home);
        assert_eq!(fleet.deployments.len(), 2);
        assert!(fleet.unaccounted.is_empty());

        let names: Vec<_> = fleet.deployments.iter().map(|d| d.plan.name.clone()).collect();
        assert_eq!(names, vec!["kanalen", "kibera"]);
        // Ports come from the recorded plan, not from guessing.
        assert_eq!(fleet.deployments[1].plan.ports.rpc, 53_020);
        assert!(fleet.deployments[0].stopped(), "nothing was started");
        let _ = fs::remove_dir_all(&home);
    }

    /// A directory that looks like a deployment but records no plan is named,
    /// not skipped. Omitting it would make the report reassuring and wrong.
    #[test]
    fn a_deployment_with_no_recorded_plan_is_reported_as_unaccounted() {
        let home = scratch("unaccounted");
        fs::create_dir_all(home.join("activechain-deploy/mystery/chain")).unwrap();
        let fleet = discover(&home);
        assert!(fleet.deployments.is_empty());
        assert_eq!(fleet.unaccounted, vec!["mystery".to_owned()]);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn a_host_with_no_deployments_reports_nothing_rather_than_failing() {
        let home = scratch("empty");
        assert_eq!(discover(&home), Fleet::default());
        let _ = fs::remove_dir_all(&home);
    }

    /// A running service must be visible as running, or the report cannot be
    /// used to decide whether it is safe to apply something else.
    #[test]
    fn a_listening_service_is_reported_as_running() {
        let home = scratch("running");
        let agents = home.join("LaunchAgents");
        // Bind a port first, then build a plan that claims it.
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = held.local_addr().unwrap().port();
        let plan = crate::plan(&manifest("kibera", port)).unwrap();
        // apply would refuse a bound port, so write the record directly.
        let root = home.join("activechain-deploy/kibera");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("plan.json"), serde_json::to_string(&plan).unwrap()).unwrap();
        drop(agents);

        let fleet = discover(&home);
        let deployment = &fleet.deployments[0];
        assert!(
            deployment.services.iter().any(|(role, _, running)| role == "rpc" && *running),
            "the bound rpc port must read as running: {:?}",
            deployment.services
        );
        assert!(!deployment.fully_running(), "the other services are not listening");
        let _ = fs::remove_dir_all(&home);
    }
}
