//! Environmental checks against a compiled plan.
//!
//! Deliberately separate from the compiler. Everything here consults the world
//! — DNS, sockets, the filesystem — so its answers vary by machine and moment,
//! and none of it may influence the plan itself. A plan compiled in Stockholm,
//! in CI, and on the target host must be byte-identical; only the assessment
//! below is allowed to differ.
//!
//! That separation is what will later let us show that a manifest produced the
//! network it claims to have produced: the plan is the invariant, the
//! assessment is the circumstance.

use crate::NetworkPlan;
use std::{fmt, net::TcpListener, path::Path};

/// What the environment says about a plan, at one moment on one host.
///
/// Never a pass/fail verdict on the plan. A port in use is a fact about the
/// host, and whether it blocks a deployment depends on what is running there
/// and why.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnvironmentAssessment {
    pub findings: Vec<Finding>,
}

impl EnvironmentAssessment {
    /// Findings that would stop this plan from deploying here.
    #[must_use]
    pub fn blocking(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|finding| finding.blocking).collect()
    }

    #[must_use]
    pub fn is_clear(&self) -> bool {
        self.blocking().is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub subject: String,
    pub detail: String,
    /// Whether deploying over this would be expected to fail.
    pub blocking: bool,
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let severity = if self.blocking { "blocking" } else { "note" };
        write!(formatter, "{severity}: {} — {}", self.subject, self.detail)
    }
}

/// Checks a compiled plan against this host.
///
/// Performs I/O by design. Binds no long-lived resources and changes nothing.
#[must_use]
pub fn assess(plan: &NetworkPlan, deployment_root: &Path) -> EnvironmentAssessment {
    let mut findings = Vec::new();

    // A port already in use is the failure mode that takes a *running* network
    // down rather than merely refusing the new one, so it blocks.
    for (role, port) in occupied_ports(plan) {
        findings.push(Finding {
            subject: format!("port {port}"),
            detail: format!("already in use; {role} cannot bind it"),
            blocking: true,
        });
    }

    if deployment_root.exists() {
        findings.push(Finding {
            subject: deployment_root.display().to_string(),
            detail: "a deployment already exists at this root; applying would adopt or \
                     overwrite it"
                .to_owned(),
            blocking: true,
        });
    } else if let Some(home) = deployment_root.parent().and_then(Path::parent)
        && !home.exists()
    {
        // The deploy tree itself is created by apply, so its absence is normal.
        // The directory *containing* it is not: a missing home means a typo or
        // an unmounted volume, and creating a fresh tree there would look like
        // success while deploying into nowhere.
        findings.push(Finding {
            subject: home.display().to_string(),
            detail: "home directory does not exist; the deployment would be created                      somewhere unintended"
                .to_owned(),
            blocking: true,
        });
    }

    EnvironmentAssessment { findings }
}

/// Reports which of the plan's ports are already bound on this host.
fn occupied_ports(plan: &NetworkPlan) -> Vec<(&'static str, u16)> {
    let mut candidates = vec![("the rpc node", plan.ports.rpc)];
    candidates.extend(plan.ports.validators.iter().map(|port| ("a validator", *port)));
    candidates.push(("the anchor gateway", plan.ports.anchor));
    candidates.push(("the work-proof service", plan.ports.work_proof));
    candidates.into_iter().filter(|(_, port)| !is_free(*port)).collect()
}

/// Binding and immediately releasing is the only honest test of availability;
/// a port can be free to one process and taken for another.
fn is_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn plan_for(port: u16) -> NetworkPlan {
        crate::plan(&crate::tests_support::manifest("kibera", port)).unwrap()
    }

    #[test]
    fn a_port_already_bound_is_reported_as_blocking() {
        // Bind something first so the check has a real occupant to find.
        let held = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = held.local_addr().unwrap().port();
        let plan = plan_for(port);
        let assessment =
            assess(&plan, Path::new("/nonexistent-root-for-test/activechain-deploy/kibera"));
        assert!(
            assessment.findings.iter().any(|f| f.blocking && f.subject.contains(&port.to_string())),
            "an occupied port must block: {:?}",
            assessment.findings
        );
        assert!(!assessment.is_clear());
    }

    #[test]
    fn an_existing_deployment_root_blocks_rather_than_being_silently_adopted() {
        let root = std::env::temp_dir();
        let plan = plan_for(52_001);
        let assessment = assess(&plan, &root);
        assert!(
            assessment.blocking().iter().any(|f| f.detail.contains("already exists")),
            "an existing root must be surfaced: {:?}",
            assessment.findings
        );
    }

    /// The assessment must never be mistaken for part of the plan: the same
    /// plan assessed on two hosts is still the same plan.
    #[test]
    fn assessing_does_not_change_the_plan_or_its_digest() {
        let plan = plan_for(52_010);
        let before = plan.digest().unwrap();
        let _ = assess(&plan, Path::new("/nonexistent-root-for-test/kibera"));
        assert_eq!(plan.digest().unwrap(), before);
    }
}
