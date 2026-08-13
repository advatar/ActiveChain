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

pub mod apply;
pub mod fleet;
pub mod preflight;
pub mod provision;
pub mod render;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::Digest384;
use serde::{Deserialize, Serialize};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::collections::BTreeSet;

/// Bytes per indexed Coin Cell record once the shared finality bundle is
/// factored out, derived from the 32,26x per record measured on Kanalen before
/// deduplication less the ~13 KiB bundle each record used to carry.
pub const MEASURED_RECORD_BYTES: usize = 19_000;

/// An operational budget for the whole-chain index, not a format limit.
///
/// The stored index is paged, so a single frame no longer caps it and the
/// format itself allows 65,535 records. What remains is practical: the index is
/// held in memory and rebuilt on every publication, so cells cost round time
/// and resident memory. This budget keeps that bounded at roughly 78 MiB.
pub const INDEX_MEMORY_BUDGET_BYTES: usize = 78 * 1024 * 1024;

/// The most Coin Cells a network should be planned to hold **across all
/// owners**.
///
/// This is a whole-chain figure, not a per-wallet one. Ordinary transfers are
/// cell-count neutral at best — a transfer consumes its inputs and fee reserve
/// and creates a recipient cell and at most one change cell — so the total is
/// monotonically non-increasing and the genesis treasury fixes the maximum for
/// the life of the chain.
#[must_use]
pub fn indexed_cell_ceiling() -> usize {
    INDEX_MEMORY_BUDGET_BYTES / MEASURED_RECORD_BYTES
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
    /// The network's own domain. The chain id is derived from it, so this is
    /// the network's identity rather than merely where it answers.
    pub domain: String,
    pub rpc: String,
    pub anchor: String,
    pub verify: String,
}

/// The chain id a network domain commits to.
///
/// Derived rather than configured, so it cannot be mistyped into a manifest or
/// carried by hand from one tool to the next — which is how a chain id reached
/// the cash tool and a treasury owner reached a launch agent until now.
#[must_use]
pub fn chain_id_for(domain: &str) -> Digest384 {
    let mut shake = Shake256::default();
    shake.update(b"ACTIVECHAIN-CHAIN-ID-V1");
    shake.update(domain.as_bytes());
    let mut digest = [0_u8; 48];
    shake.finalize_xof().read(&mut digest);
    Digest384::new(digest)
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
    TreasuryCannotSpend {
        cells: usize,
    },
    /// More cells than a round can publish; the index would stay empty.
    TreasuryExceedsIndex {
        cells: usize,
        ceiling: usize,
    },
    /// The allocation does not divide into that many non-empty cells.
    TreasuryNotDivisible {
        cells: usize,
    },
    SecurityReserveExceedsSupply,
    /// Recipients would hold too few cells to spend what they were granted.
    RecipientsCannotSpend {
        cells_per_grant: usize,
    },
    /// The treasury cannot fund even one recipient and remain able to spend.
    NoGrantCapacity {
        cells: usize,
        cells_per_grant: usize,
    },
    /// A grant must cover its own fee.
    GrantBelowFee {
        grant_amount: u128,
        fee: u128,
    },
    ThresholdExceedsSigners {
        threshold: u8,
        signers: u8,
    },
    ThresholdIsZero,
    BasePortTooLow(u16),
    /// Two networks on one host would fight over the same ports.
    PortRangeOverlaps {
        other: String,
    },
    HostnameEmpty(&'static str),
    HostnamesNotDistinct,
    /// Two networks on one host cannot share a name.
    DuplicateNetworkName(String),
    /// More validators than the per-network port reservation can seat.
    TooManyValidatorsForReservation {
        validators: u8,
    },
}

/// A validated deployment. Every value an executor needs is resolved here, so
/// nothing downstream has to invent one.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkPlan {
    pub name: String,
    pub domain: String,
    /// Derived from the domain; never supplied by hand.
    #[serde(with = "hex_digest")]
    pub chain_id: Digest384,
    pub deployment_root: String,
    pub rpc_hostname: String,
    pub genesis_supply: u128,
    pub security_reserve: u128,
    pub cells_per_grant: usize,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

const MAX_PLAN_NAME: usize = 32;
const MAX_PLAN_PATH: usize = 256;
const MAX_PLAN_LABELS: usize = 16;
const MAX_PLAN_VALIDATORS: usize = 16;

impl CanonicalType for NetworkPlan {
    // 0x0150 belongs to ComplianceReplayWitness; planner types occupy 0x01c3+.
    const TYPE_TAG: u16 = 0x01c3;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = MAX_PLAN_NAME
        + MAX_PLAN_PATH
        + MAX_PLAN_PATH
        + 48
        + 32
        + MAX_PLAN_LABELS * (MAX_PLAN_NAME + MAX_PLAN_PATH)
        + MAX_PLAN_VALIDATORS * 2
        + 64;
}

/// The plan is committed to as a canonical object, never as rendered text.
///
/// Advisories are deliberately excluded: they are guidance for a reader, not
/// part of what a deployment *is*, and wording changes must not alter the
/// identity of an otherwise identical plan.
impl CanonicalEncode for NetworkPlan {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_bytes(self.name.as_bytes(), MAX_PLAN_NAME)?;
        e.write_bytes(self.domain.as_bytes(), MAX_PLAN_PATH)?;
        self.chain_id.encode(e)?;
        e.write_bytes(self.deployment_root.as_bytes(), MAX_PLAN_PATH)?;
        e.write_bytes(self.rpc_hostname.as_bytes(), MAX_PLAN_PATH)?;
        self.genesis_supply.encode(e)?;
        self.security_reserve.encode(e)?;
        (self.cells_per_grant as u64).encode(e)?;
        self.ports.rpc.encode(e)?;
        e.write_length(self.ports.validators.len(), MAX_PLAN_VALIDATORS)?;
        for port in &self.ports.validators {
            port.encode(e)?;
        }
        self.ports.anchor.encode(e)?;
        self.ports.work_proof.encode(e)?;
        self.ports.reserved.0.encode(e)?;
        self.ports.reserved.1.encode(e)?;
        e.write_length(self.launch_labels.len(), MAX_PLAN_LABELS)?;
        for label in &self.launch_labels {
            e.write_bytes(label.as_bytes(), MAX_PLAN_NAME + MAX_PLAN_PATH)?;
        }
        (self.treasury_cells as u64).encode(e)?;
        (self.indexed_cell_budget as u64).encode(e)?;
        (self.grant_capacity as u64).encode(e)?;
        Ok(())
    }
}

/// Decoding drops advisories, matching what the encoding commits to: two plans
/// that deploy the same network are the same plan however their guidance reads.
impl CanonicalDecode for NetworkPlan {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let text = |bytes: &[u8]| {
            core::str::from_utf8(bytes)
                .map(str::to_owned)
                .map_err(|_| DecodeError::InvalidValue("network plan text is not UTF-8"))
        };
        let name = text(d.read_bytes(MAX_PLAN_NAME)?)?;
        let domain = text(d.read_bytes(MAX_PLAN_PATH)?)?;
        let chain_id = Digest384::decode(d)?;
        let deployment_root = text(d.read_bytes(MAX_PLAN_PATH)?)?;
        let rpc_hostname = text(d.read_bytes(MAX_PLAN_PATH)?)?;
        let genesis_supply = u128::decode(d)?;
        let security_reserve = u128::decode(d)?;
        let cells_per_grant = usize::try_from(u64::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("cells per grant overflows"))?;
        let rpc = u16::decode(d)?;
        let validator_count = d.read_length(MAX_PLAN_VALIDATORS)?;
        let mut validators = Vec::with_capacity(validator_count);
        for _ in 0..validator_count {
            validators.push(u16::decode(d)?);
        }
        let anchor = u16::decode(d)?;
        let work_proof = u16::decode(d)?;
        let reserved = (u16::decode(d)?, u16::decode(d)?);
        let label_count = d.read_length(MAX_PLAN_LABELS)?;
        let mut launch_labels = Vec::with_capacity(label_count);
        for _ in 0..label_count {
            launch_labels.push(text(d.read_bytes(MAX_PLAN_NAME + MAX_PLAN_PATH)?)?);
        }
        let treasury_cells = usize::try_from(u64::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("treasury cell count overflows"))?;
        let indexed_cell_budget = usize::try_from(u64::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("index budget overflows"))?;
        let grant_capacity = usize::try_from(u64::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("grant capacity overflows"))?;
        Ok(Self {
            name,
            domain,
            chain_id,
            deployment_root,
            rpc_hostname,
            genesis_supply,
            security_reserve,
            cells_per_grant,
            ports: Ports { rpc, validators, anchor, work_proof, reserved },
            launch_labels,
            treasury_cells,
            indexed_cell_budget,
            indexed_cell_ceiling: indexed_cell_ceiling(),
            grant_capacity,
            advisories: Vec::new(),
        })
    }
}

impl NetworkPlan {
    /// The identity of this deployment, and the thing an operator signs.
    ///
    /// # Errors
    /// Returns an error only if the plan exceeds its canonical bounds.
    pub fn digest(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }
}

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
            "{cells} cells uses most of the {ceiling}-cell index budget; the index is held \
             in memory and rebuilt each publication, so this costs round time"
        ));
    }

    Ok(NetworkPlan {
        name: manifest.name.clone(),
        domain: manifest.hostnames.domain.clone(),
        chain_id: chain_id_for(&manifest.hostnames.domain),
        deployment_root: format!("$HOME/activechain-deploy/{}", manifest.name),
        rpc_hostname: manifest.hostnames.rpc.clone(),
        genesis_supply: manifest.treasury.genesis_supply,
        security_reserve: manifest.treasury.security_reserve,
        cells_per_grant: per_grant,
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
    let last = base.checked_add(PORTS_PER_NETWORK - 1).ok_or(PlanError::BasePortTooLow(base))?;
    let validators =
        (0..u16::from(manifest.validators)).map(|index| base + 2 + index).collect::<Vec<_>>();
    // Validators must not run into the anchor and work-proof ports, or a
    // network overruns its own reservation before any other network is
    // involved.
    if validators.last().is_some_and(|port| *port >= base + 5) {
        return Err(PlanError::TooManyValidatorsForReservation { validators: manifest.validators });
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

/// Serializes a digest as hex so a plan reads as something an operator can
/// compare against a node, rather than as an array of numbers.
mod hex_digest {
    use activechain_protocol_types::Digest384;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(value: &Digest384, serializer: S) -> Result<S::Ok, S::Error> {
        let hex: String = value.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Digest384, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() != 96 {
            return Err(D::Error::custom("a chain id is 96 hex characters"));
        }
        let mut bytes = [0_u8; 48];
        for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            let pair = core::str::from_utf8(pair).map_err(D::Error::custom)?;
            bytes[index] = u8::from_str_radix(pair, 16).map_err(D::Error::custom)?;
        }
        Ok(Digest384::new(bytes))
    }
}

fn validate_hostnames(hostnames: &Hostnames) -> Result<(), PlanError> {
    for (label, value) in [
        ("domain", &hostnames.domain),
        ("rpc", &hostnames.rpc),
        ("anchor", &hostnames.anchor),
        ("verify", &hostnames.verify),
    ] {
        if value.trim().is_empty() {
            return Err(PlanError::HostnameEmpty(label));
        }
    }
    let distinct = BTreeSet::from([&hostnames.rpc, &hostnames.anchor, &hostnames.verify]);
    if distinct.len() == 3 { Ok(()) } else { Err(PlanError::HostnamesNotDistinct) }
}

/// Shared fixtures for this crate's tests, including the preflight module's.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    pub(crate) fn manifest(name: &str, base_port: u16) -> NetworkManifest {
        NetworkManifest {
            name: name.to_owned(),
            validators: 3,
            base_port,
            hostnames: Hostnames {
                domain: format!("{name}.activechain.dev"),
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
}

#[cfg(test)]
mod tests {
    use super::{tests_support::manifest, *};

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

    /// Pagination removed the 4 MiB frame that once capped a chain at ~130
    /// cells across all owners, so 1024 is now plannable. What remains is an
    /// operational budget on memory and round time, and exceeding that is
    /// still refused.
    #[test]
    fn the_treasury_is_bounded_by_an_operational_budget_not_a_frame() {
        let ceiling = indexed_cell_ceiling();
        assert!(ceiling > 1024, "pagination must have lifted the old ~130 ceiling");

        let mut candidate = manifest("kanalen", 49_151);
        candidate.treasury.cells = 1024;
        assert!(plan(&candidate).is_ok(), "1024 cells is publishable once the index is paged");

        candidate.treasury.cells = ceiling;
        assert!(plan(&candidate).is_ok(), "the budget itself must be plannable");

        candidate.treasury.cells = ceiling + 1;
        assert_eq!(
            plan(&candidate),
            Err(PlanError::TreasuryExceedsIndex { cells: ceiling + 1, ceiling })
        );
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

    /// The derivation must reproduce the chain the live network actually runs,
    /// or planning an existing deployment would silently propose a different
    /// chain wearing its name.
    #[test]
    fn the_chain_id_is_derived_from_the_domain_and_matches_the_live_network() {
        let plan = plan(&manifest("kanalen", 49_151)).unwrap();
        let hex: String =
            plan.chain_id.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0b\
             095e6cfe944bd2c9f6535b4c927782f1",
            "derived chain id must equal the one Kanalen runs"
        );
        // Two domains are two chains, whatever else the manifests share.
        let mut other = manifest("kanalen", 49_151);
        other.hostnames.domain = "kibera.activechain.dev".to_owned();
        assert_ne!(plan.chain_id, super::plan(&other).unwrap().chain_id);
    }

    /// A genesis supply exceeds `u64::MAX`, so a plan cannot be routed through
    /// `serde_json::Value` — `Value::Number` cannot hold it and construction
    /// panics. Direct serialization streams and must keep working, because two
    /// JSON surfaces were built on the wrong one and only failed when run.
    #[test]
    fn a_plan_serializes_despite_a_supply_larger_than_a_u64() {
        let plan = plan(&manifest("kanalen", 49_151)).unwrap();
        assert!(plan.genesis_supply > u128::from(u64::MAX), "the fixture must exercise this");
        let encoded = serde_json::to_string(&plan).expect("a plan must serialize directly");
        assert!(encoded.contains("1000000000000000000000000000"));
        assert!(
            serde_json::to_value(&plan).is_err(),
            "if Value ever gains u128 support this test should be revisited rather than deleted"
        );
    }

    #[test]
    fn a_manifest_round_trips_through_its_serialized_form() {
        let original = manifest("kanalen", 49_151);
        let encoded = serde_json::to_string(&original).unwrap();
        let decoded: NetworkManifest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(plan(&decoded).unwrap(), plan(&original).unwrap());
    }
}
