#![forbid(unsafe_code)]

//! Validated planning of ActiveChain network deployments.
//!
//! Standing up a network is a sequence of tools whose derived values are
//! threaded between them by hand: a chain id into the cash tool, a treasury
//! owner into the RPC launch agent, a genesis commitment into every wallet.
//! Every deployment failure worth remembering has been a *planning* error
//! rather than an execution error — a configuration that could never have
//! worked, discovered only once part of it was live:
//!
//! * a treasury split into more cells than the RPC index can publish, which
//!   surfaces as a round failing with `Invalid` and an index that stays empty;
//! * a treasury of two cells, which buys exactly one grant before the faucet
//!   can no longer construct a transfer at all;
//! * a faucet whose grants leave recipients holding a single Coin Cell, which
//!   they cannot spend;
//! * ports and launch-agent labels chosen by hand, which collide the moment a
//!   second network shares a host.
//!
//! This crate is the answer: a pure function from a manifest to either a plan
//! or a refusal. It performs no I/O, creates nothing, and contacts no host, so
//! a configuration can be rejected before it costs anything. Executing a plan
//! is a separate concern.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// `RpcIndex::MAX_ENCODED_LEN` — the frame a published index must fit inside.
pub const INDEX_FRAME_BYTES: usize = 4 * 1024 * 1024 - 32;

/// Bytes per indexed Coin Cell record, measured on Kanalen at two scales:
/// 2,064,747 bytes for 64 cells and 3,548,662 for 110, both 32,26x per record.
///
/// Every indexed cell republishes its own copy of the finality bundle, which is
/// what makes a record this large. Reducing it is the durable fix for the
/// ceiling; until then it is a constant to plan against rather than discover.
pub const MEASURED_RECORD_BYTES: usize = 32_262;

/// Reserve against a record growing, since the measurement is a floor.
pub const INDEX_HEADROOM: f64 = 0.85;

/// The most Coin Cells a network can hold **across all owners** before a round
/// can no longer publish its index.
///
/// This is a whole-chain limit, not a per-wallet one. Ordinary transfers are
/// cell-count neutral at best — a transfer consumes its inputs and fee reserve
/// and creates a recipient cell and at most one change cell — so the total is
/// monotonically non-increasing and the genesis treasury fixes the maximum for
/// the life of the chain.
#[must_use]
pub fn indexed_cell_ceiling() -> usize {
    ((INDEX_FRAME_BYTES as f64 * INDEX_HEADROOM) as usize) / MEASURED_RECORD_BYTES
}

/// A transfer needs an input and a *distinct* fee reserve, so anything holding
/// fewer cells than this cannot spend, whatever value it holds.
pub const MIN_SPENDABLE_CELLS: usize = 2;

/// Ports a single network occupies, relative to its base.
pub const PORTS_PER_NETWORK: u16 = 16;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetworkManifest {
    /// Names the deployment root, launch-agent labels, and hostnames, so it
    /// must be safe in all three.
    pub name: String,
    pub validators: u8,
    pub base_port: u16,
    pub hostnames: Hostnames,
    pub treasury: Treasury,
    pub faucet: Faucet,
    pub trust: Trust,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Hostnames {
    pub rpc: String,
    pub anchor: String,
    pub verify: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Treasury {
    pub genesis_supply: u128,
    pub security_reserve: u128,
    /// How many Coin Cells the genesis treasury is split into. Also the
    /// network's whole-chain cell budget, and its total grant capacity.
    pub cells: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Faucet {
    pub grant_amount: u128,
    pub fee: u128,
    /// Coin Cells delivered per grant. One leaves the recipient unable to
    /// spend; see [`MIN_SPENDABLE_CELLS`].
    pub cells_per_grant: usize,
    pub recipient_cooldown_seconds: u64,
    pub recipient_limit: u16,
    pub source_window_seconds: u64,
    pub source_limit: u16,
    pub global_window_seconds: u64,
    pub global_limit: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Trust {
    pub signers: u8,
    pub threshold: u8,
}

/// A refusal. Each variant is a configuration that has cost real time to
/// discover the expensive way.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanError {
    /// The name reaches launchd labels, filesystem paths, and hostnames.
    NameNotALabel(String),
    NoValidators,
    /// Below the fee-reserve-plus-input minimum: the treasury could never spend.
    TreasuryCannotSpend { cells: usize },
    /// More cells than a round can publish; the index would stay empty.
    TreasuryExceedsIndex { cells: usize, ceiling: usize },
    /// The allocation does not divide into that many non-empty cells.
    TreasuryNotDivisible { cells: usize },
    SecurityReserveExceedsSupply,
    /// Recipients would hold too few cells to spend what they were granted.
    RecipientsCannotSpend { cells_per_grant: usize },
    /// The treasury cannot fund even one recipient and remain able to spend.
    NoGrantCapacity { cells: usize, cells_per_grant: usize },
    /// A grant must cover its own fee.
    GrantBelowFee { grant_amount: u128, fee: u128 },
    ThresholdExceedsSigners { threshold: u8, signers: u8 },
    ThresholdIsZero,
    BasePortTooLow(u16),
    /// Two networks on one host would fight over the same ports.
    PortRangeOverlaps { other: String },
    HostnameEmpty(&'static str),
    HostnamesNotDistinct,
    /// Two networks on one host cannot share a name.
    DuplicateNetworkName(String),
    /// More validators than the per-network port reservation can seat.
    TooManyValidatorsForReservation { validators: u8 },
}

/// A validated deployment. Every value an executor needs is resolved here, so
/// nothing downstream has to invent one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkPlan {
    pub name: String,
    pub deployment_root: String,
    pub ports: Ports,
    pub launch_labels: Vec<String>,
    pub treasury_cells: usize,
    /// Whole-chain Coin Cell budget; equal to the genesis treasury, since
    /// transfers cannot increase the count.
    pub indexed_cell_budget: usize,
    pub indexed_cell_ceiling: usize,
    /// Recipients fundable before the treasury can no longer spend.
    pub grant_capacity: usize,
    /// True where a shortfall is survivable but worth stating plainly.
    pub advisories: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Ports {
    pub rpc: u16,
    pub validators: Vec<u16>,
    pub anchor: u16,
    pub work_proof: u16,
    /// Inclusive range this network reserves on the host.
    pub reserved: (u16, u16),
}

/// Ports below this are privileged or in common use; a network deployment has
/// no business there.
const MINIMUM_BASE_PORT: u16 = 1024;

/// Plans one network in isolation.
///
/// # Errors
/// Returns the first configuration defect found.
pub fn plan(manifest: &NetworkManifest) -> Result<NetworkPlan, PlanError> {
    plan_fleet(std::slice::from_ref(manifest)).map(|mut plans| plans.remove(0))
}

/// Plans every network intended to share a host, so collisions between them are
/// refused rather than discovered when the second one starts.
///
/// # Errors
/// Returns the first configuration defect found, including cross-network
/// conflicts.
pub fn plan_fleet(manifests: &[NetworkManifest]) -> Result<Vec<NetworkPlan>, PlanError> {
    let mut plans = Vec::with_capacity(manifests.len());
    let mut names = BTreeSet::new();
    for manifest in manifests {
        if !names.insert(manifest.name.clone()) {
            return Err(PlanError::DuplicateNetworkName(manifest.name.clone()));
        }
        plans.push(plan_one(manifest)?);
    }
    for (index, plan) in plans.iter().enumerate() {
        for other in &plans[index + 1..] {
            if overlaps(plan.ports.reserved, other.ports.reserved) {
                return Err(PlanError::PortRangeOverlaps { other: other.name.clone() });
            }
        }
    }
    Ok(plans)
}

const fn overlaps(left: (u16, u16), right: (u16, u16)) -> bool {
    left.0 <= right.1 && right.0 <= left.1
}

fn plan_one(manifest: &NetworkManifest) -> Result<NetworkPlan, PlanError> {
    validate_name(&manifest.name)?;
    validate_hostnames(&manifest.hostnames)?;
    if manifest.validators == 0 {
        return Err(PlanError::NoValidators);
    }
    if manifest.trust.threshold == 0 {
        return Err(PlanError::ThresholdIsZero);
    }
    if manifest.trust.threshold > manifest.trust.signers {
        return Err(PlanError::ThresholdExceedsSigners {
            threshold: manifest.trust.threshold,
            signers: manifest.trust.signers,
        });
    }

    let cells = manifest.treasury.cells;
    if cells < MIN_SPENDABLE_CELLS {
        return Err(PlanError::TreasuryCannotSpend { cells });
    }
    let ceiling = indexed_cell_ceiling();
    if cells > ceiling {
        return Err(PlanError::TreasuryExceedsIndex { cells, ceiling });
    }
    let allocation = manifest
        .treasury
        .genesis_supply
        .checked_sub(manifest.treasury.security_reserve)
        .filter(|amount| *amount > 0)
        .ok_or(PlanError::SecurityReserveExceedsSupply)?;
    if allocation / (cells as u128) == 0 {
        return Err(PlanError::TreasuryNotDivisible { cells });
    }

    let per_grant = manifest.faucet.cells_per_grant;
    if per_grant < MIN_SPENDABLE_CELLS {
        return Err(PlanError::RecipientsCannotSpend { cells_per_grant: per_grant });
    }
    if manifest.faucet.grant_amount <= manifest.faucet.fee {
        return Err(PlanError::GrantBelowFee {
            grant_amount: manifest.faucet.grant_amount,
            fee: manifest.faucet.fee,
        });
    }
    // Each delivered cell costs the treasury one of its own, and the treasury
    // must still hold enough to construct a transfer afterwards.
    let grant_capacity = cells.saturating_sub(MIN_SPENDABLE_CELLS) / per_grant;
    if grant_capacity == 0 {
        return Err(PlanError::NoGrantCapacity { cells, cells_per_grant: per_grant });
    }

    if manifest.base_port < MINIMUM_BASE_PORT {
        return Err(PlanError::BasePortTooLow(manifest.base_port));
    }
    let ports = allocate_ports(manifest)?;

    let mut advisories = Vec::new();
    if manifest.faucet.source_limit < 16 {
        advisories.push(format!(
            "source limit of {} per {}s is shared by everyone behind one egress address, \
             because the abuse identity is derived from the peer address",
            manifest.faucet.source_limit, manifest.faucet.source_window_seconds
        ));
    }
    if grant_capacity < 16 {
        advisories.push(format!(
            "only {grant_capacity} recipient(s) can be funded before the treasury can no \
             longer spend; a larger treasury or pool maintenance is needed for more"
        ));
    }
    if cells * 4 > ceiling * 3 {
        advisories.push(format!(
            "{cells} cells uses most of the {ceiling}-cell index budget, leaving little \
             margin if a record grows"
        ));
    }

    Ok(NetworkPlan {
        name: manifest.name.clone(),
        deployment_root: format!("$HOME/activechain-deploy/{}", manifest.name),
        ports,
        launch_labels: launch_labels(&manifest.name),
        treasury_cells: cells,
        indexed_cell_budget: cells,
        indexed_cell_ceiling: ceiling,
        grant_capacity,
        advisories,
    })
}

fn allocate_ports(manifest: &NetworkManifest) -> Result<Ports, PlanError> {
    let base = manifest.base_port;
    let last = base
        .checked_add(PORTS_PER_NETWORK - 1)
        .ok_or(PlanError::BasePortTooLow(base))?;
    let validators = (0..u16::from(manifest.validators))
        .map(|index| base + 2 + index)
        .collect::<Vec<_>>();
    // Validators must not run into the anchor and work-proof ports, or a
    // network overruns its own reservation before any other network is
    // involved.
    if validators.last().is_some_and(|port| *port >= base + 5) {
        return Err(PlanError::TooManyValidatorsForReservation {
            validators: manifest.validators,
        });
    }
    // Offsets match the layout Kanalen already runs, so an existing network
    // plans to exactly what it is rather than to something merely equivalent.
    Ok(Ports {
        rpc: base,
        validators,
        anchor: base + 5,
        work_proof: base + 6,
        reserved: (base, last),
    })
}

fn launch_labels(name: &str) -> Vec<String> {
    ["rpc", "anchor", "work-proof", "round"]
        .iter()
        .map(|role| format!("dev.activechain.{name}.{role}"))
        .collect()
}

/// A network name reaches launchd labels, filesystem paths, and hostnames, so
/// it is restricted to what all three accept without quoting.
fn validate_name(name: &str) -> Result<(), PlanError> {
    let acceptable = !name.is_empty()
        && name.len() <= 32
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.ends_with('-')
        && !name.contains("--");
    if acceptable { Ok(()) } else { Err(PlanError::NameNotALabel(name.to_owned())) }
}

fn validate_hostnames(hostnames: &Hostnames) -> Result<(), PlanError> {
    for (label, value) in
        [("rpc", &hostnames.rpc), ("anchor", &hostnames.anchor), ("verify", &hostnames.verify)]
    {
        if value.trim().is_empty() {
            return Err(PlanError::HostnameEmpty(label));
        }
    }
    let distinct = BTreeSet::from([&hostnames.rpc, &hostnames.anchor, &hostnames.verify]);
    if distinct.len() == 3 { Ok(()) } else { Err(PlanError::HostnamesNotDistinct) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(name: &str, base_port: u16) -> NetworkManifest {
        NetworkManifest {
            name: name.to_owned(),
            validators: 3,
            base_port,
            hostnames: Hostnames {
                rpc: format!("rpc.{name}.activechain.dev"),
                anchor: format!("anchor.{name}.activechain.dev"),
                verify: format!("verify.{name}.activechain.dev"),
            },
            treasury: Treasury {
                genesis_supply: 1_000_000_000_000_000_000_000_000_000,
                security_reserve: 100_000_000_000_000_000_000_000_000,
                cells: 96,
            },
            faucet: Faucet {
                grant_amount: 100_000_000_000_000_000_000,
                fee: 1_000_000_000_000_000,
                cells_per_grant: 2,
                recipient_cooldown_seconds: 86_400,
                recipient_limit: 3,
                source_window_seconds: 3_600,
                source_limit: 5,
                global_window_seconds: 3_600,
                global_limit: 100,
            },
            trust: Trust { signers: 3, threshold: 2 },
        }
    }

    #[test]
    fn a_sound_manifest_resolves_every_value_an_executor_needs() {
        let plan = plan(&manifest("kanalen", 49_151)).unwrap();
        assert_eq!(plan.deployment_root, "$HOME/activechain-deploy/kanalen");
        assert_eq!(plan.ports.rpc, 49_151);
        assert_eq!(plan.ports.validators, vec![49_153, 49_154, 49_155]);
        assert_eq!(plan.ports.anchor, 49_156, "must match the deployed layout");
        assert_eq!(plan.ports.work_proof, 49_157, "must match the deployed layout");
        assert_eq!(plan.ports.reserved, (49_151, 49_166));
        assert!(plan.launch_labels.contains(&"dev.activechain.kanalen.rpc".to_owned()));
        assert_eq!(plan.treasury_cells, 96);
        assert_eq!(plan.grant_capacity, 47, "96 cells at two per grant, keeping two spendable");
    }

    /// The wedge that started all of this: a treasury below the fee-reserve
    /// plus input minimum cannot construct a transfer, whatever it holds.
    #[test]
    fn a_treasury_that_could_never_spend_is_refused() {
        let mut candidate = manifest("kanalen", 49_151);
        candidate.treasury.cells = 1;
        assert_eq!(plan(&candidate), Err(PlanError::TreasuryCannotSpend { cells: 1 }));
        candidate.treasury.cells = 2;
        // Two cells is spendable but funds nobody, which is its own refusal.
        assert_eq!(
            plan(&candidate),
            Err(PlanError::NoGrantCapacity { cells: 2, cells_per_grant: 2 })
        );
    }

    /// 1024 cells produced a 13 MiB index; the round failed with `Invalid` and
    /// the index stayed empty, leaving the treasury unqueryable.
    #[test]
    fn a_treasury_larger_than_the_index_can_publish_is_refused() {
        let ceiling = indexed_cell_ceiling();
        let mut candidate = manifest("kanalen", 49_151);
        candidate.treasury.cells = 1024;
        assert_eq!(
            plan(&candidate),
            Err(PlanError::TreasuryExceedsIndex { cells: 1024, ceiling })
        );
        // The measured ceiling must stay in the region the live chain proved
        // publishable: 110 cells occupied 85% of the frame.
        assert!((100..=130).contains(&ceiling), "implausible ceiling {ceiling}");
        candidate.treasury.cells = ceiling;
        assert!(plan(&candidate).is_ok(), "the ceiling itself must be plannable");
    }

    /// A recipient holding one Coin Cell cannot spend it, so a faucet that
    /// delivers one is not a working faucet.
    #[test]
    fn grants_that_leave_recipients_unable_to_spend_are_refused() {
        let mut candidate = manifest("kanalen", 49_151);
        candidate.faucet.cells_per_grant = 1;
        assert_eq!(plan(&candidate), Err(PlanError::RecipientsCannotSpend { cells_per_grant: 1 }));
    }

    /// Two networks on one host must not fight over ports, and the check has to
    /// consider the whole reservation rather than the base alone.
    #[test]
    fn networks_sharing_a_host_may_not_share_ports() {
        let fleet = [manifest("kanalen", 49_151), manifest("kibera", 49_160)];
        assert_eq!(
            plan_fleet(&fleet),
            Err(PlanError::PortRangeOverlaps { other: "kibera".to_owned() }),
            "overlapping reservations must be refused even though the bases differ"
        );
        let spaced = [manifest("kanalen", 49_151), manifest("kibera", 49_167)];
        let plans = plan_fleet(&spaced).unwrap();
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[1].ports.rpc, 49_167);
        assert_ne!(plans[0].launch_labels, plans[1].launch_labels);
    }

    #[test]
    fn networks_sharing_a_host_may_not_share_a_name() {
        let fleet = [manifest("kanalen", 49_151), manifest("kanalen", 49_200)];
        assert_eq!(plan_fleet(&fleet), Err(PlanError::DuplicateNetworkName("kanalen".to_owned())));
    }

    /// The name becomes a launchd label, a path, and a hostname component.
    #[test]
    fn a_name_that_is_unsafe_in_a_label_or_a_path_is_refused() {
        for name in ["", "Kanalen", "kanalen/../etc", "9lives", "kanalen-", "a--b", "kan alen"] {
            assert!(
                matches!(plan(&manifest(name, 49_151)), Err(PlanError::NameNotALabel(_))),
                "accepted unsafe network name {name:?}"
            );
        }
    }

    #[test]
    fn trust_thresholds_and_validator_counts_must_be_satisfiable() {
        let mut candidate = manifest("kanalen", 49_151);
        candidate.trust.threshold = 4;
        assert_eq!(
            plan(&candidate),
            Err(PlanError::ThresholdExceedsSigners { threshold: 4, signers: 3 })
        );
        candidate.trust.threshold = 0;
        assert_eq!(plan(&candidate), Err(PlanError::ThresholdIsZero));
        let mut empty = manifest("kanalen", 49_151);
        empty.validators = 0;
        assert_eq!(plan(&empty), Err(PlanError::NoValidators));
        let mut crowded = manifest("kanalen", 49_151);
        crowded.validators = 8;
        assert_eq!(
            plan(&crowded),
            Err(PlanError::TooManyValidatorsForReservation { validators: 8 })
        );
    }

    #[test]
    fn a_supply_that_cannot_be_split_or_cover_a_fee_is_refused() {
        let mut candidate = manifest("kanalen", 49_151);
        candidate.treasury.genesis_supply = 100;
        candidate.treasury.security_reserve = 99;
        assert_eq!(plan(&candidate), Err(PlanError::TreasuryNotDivisible { cells: 96 }));
        candidate.treasury.security_reserve = 100;
        assert_eq!(plan(&candidate), Err(PlanError::SecurityReserveExceedsSupply));

        let mut cheap = manifest("kanalen", 49_151);
        cheap.faucet.fee = cheap.faucet.grant_amount;
        assert!(matches!(plan(&cheap), Err(PlanError::GrantBelowFee { .. })));
    }

    /// Advisories name survivable shortfalls rather than failing, because an
    /// operator who is told nothing assumes nothing is wrong.
    #[test]
    fn survivable_shortfalls_are_named_rather_than_hidden() {
        let plan = plan(&manifest("kanalen", 49_151)).unwrap();
        assert!(
            plan.advisories.iter().any(|note| note.contains("egress address")),
            "a source limit of 5 shares one allowance across a whole office: {:?}",
            plan.advisories
        );
    }

    #[test]
    fn hostnames_must_be_present_and_distinct() {
        let mut blank = manifest("kanalen", 49_151);
        blank.hostnames.anchor = "  ".to_owned();
        assert_eq!(plan(&blank), Err(PlanError::HostnameEmpty("anchor")));
        let mut same = manifest("kanalen", 49_151);
        same.hostnames.verify = same.hostnames.rpc.clone();
        assert_eq!(plan(&same), Err(PlanError::HostnamesNotDistinct));
    }

    #[test]
    fn a_manifest_round_trips_through_its_serialized_form() {
        let original = manifest("kanalen", 49_151);
        let encoded = serde_json::to_string(&original).unwrap();
        let decoded: NetworkManifest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(plan(&decoded).unwrap(), plan(&original).unwrap());
    }
}
