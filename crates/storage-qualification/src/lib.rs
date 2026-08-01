#![forbid(unsafe_code)]

use activechain_storage_profile::{
    ACTIVE_STATE_BUDGET_BYTES, ARCHIVE_DATA_SHARDS, ARCHIVE_MIN_FAILURE_DOMAINS,
    CONSENSUS_INDEX_BUDGET_BYTES, HOT_HISTORY_BUDGET_BYTES, HOT_RETENTION_DAYS,
    HOT_SNAPSHOT_GENERATIONS, OPERATIONAL_RESERVE_BYTES, PHYSICAL_CEILING_BYTES,
    SNAPSHOT_BUDGET_BYTES, StoragePressure, pressure_for_basis_points, utilization_basis_points,
};

pub const MAX_ACCEPTABLE_SYNC_LAG_BLOCKS: u64 = 64;
pub const MAX_ACCEPTABLE_PRUNING_LAG_DAYS: u64 = HOT_RETENTION_DAYS + 2;
pub const MAX_ACCEPTABLE_SNAPSHOT_AGE_HOURS: u64 = 25;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationError {
    Bounds,
    Overflow,
    BudgetExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageTelemetry {
    pub active_state_bytes: u64,
    pub hot_history_bytes: u64,
    pub snapshot_bytes: u64,
    pub consensus_index_bytes: u64,
    pub operational_bytes: u64,
    pub archive_available_shards: u8,
    pub archive_failure_domains: u8,
    pub snapshot_age_hours: u64,
    pub pruning_lag_days: u64,
    pub sync_lag_blocks: u64,
    pub rent_frozen_objects: u64,
    pub hibernation_backlog_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorSnapshot {
    pub physical_bytes: u64,
    pub physical_pressure: StoragePressure,
    pub active_pressure: StoragePressure,
    pub history_pressure: StoragePressure,
    pub snapshot_pressure: StoragePressure,
    pub consensus_pressure: StoragePressure,
    pub operational_pressure: StoragePressure,
    pub archive_reconstructable: bool,
    pub snapshot_fresh: bool,
    pub pruning_current: bool,
    pub sync_current: bool,
    pub rent_frozen_objects: u64,
    pub hibernation_backlog_bytes: u64,
}

impl StorageTelemetry {
    pub fn summarize(self) -> Result<OperatorSnapshot, QualificationError> {
        let physical_bytes = [
            self.active_state_bytes,
            self.hot_history_bytes,
            self.snapshot_bytes,
            self.consensus_index_bytes,
            self.operational_bytes,
        ]
        .into_iter()
        .try_fold(0_u64, |total, value| total.checked_add(value))
        .ok_or(QualificationError::Overflow)?;
        Ok(OperatorSnapshot {
            physical_bytes,
            physical_pressure: pressure(physical_bytes, PHYSICAL_CEILING_BYTES)?,
            active_pressure: pressure(self.active_state_bytes, ACTIVE_STATE_BUDGET_BYTES)?,
            history_pressure: pressure(self.hot_history_bytes, HOT_HISTORY_BUDGET_BYTES)?,
            snapshot_pressure: pressure(self.snapshot_bytes, SNAPSHOT_BUDGET_BYTES)?,
            consensus_pressure: pressure(self.consensus_index_bytes, CONSENSUS_INDEX_BUDGET_BYTES)?,
            operational_pressure: pressure(self.operational_bytes, OPERATIONAL_RESERVE_BYTES)?,
            archive_reconstructable: self.archive_available_shards >= ARCHIVE_DATA_SHARDS
                && self.archive_failure_domains >= ARCHIVE_MIN_FAILURE_DOMAINS,
            snapshot_fresh: self.snapshot_age_hours <= MAX_ACCEPTABLE_SNAPSHOT_AGE_HOURS,
            pruning_current: self.pruning_lag_days <= MAX_ACCEPTABLE_PRUNING_LAG_DAYS,
            sync_current: self.sync_lag_blocks <= MAX_ACCEPTABLE_SYNC_LAG_BLOCKS,
            rent_frozen_objects: self.rent_frozen_objects,
            hibernation_backlog_bytes: self.hibernation_backlog_bytes,
        })
    }
}

fn pressure(used: u64, budget: u64) -> Result<StoragePressure, QualificationError> {
    utilization_basis_points(used, budget)
        .map(pressure_for_basis_points)
        .map_err(|_| QualificationError::Overflow)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityScenario {
    pub days: u64,
    pub initial_active_bytes: u64,
    pub active_growth_bytes_per_day: u64,
    pub hibernated_bytes_per_day: u64,
    pub assigned_history_bytes_per_day: u64,
    pub full_snapshot_bytes: u64,
    pub initial_consensus_index_bytes: u64,
    pub consensus_index_bytes_per_day: u64,
    pub operational_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityReport {
    pub days: u64,
    pub final_active_bytes: u64,
    pub maximum_hot_history_bytes: u64,
    pub snapshot_bytes: u64,
    pub final_consensus_index_bytes: u64,
    pub maximum_physical_bytes: u64,
    pub minimum_headroom_bytes: u64,
}

pub fn qualify_capacity(scenario: CapacityScenario) -> Result<CapacityReport, QualificationError> {
    if scenario.days == 0
        || scenario.hibernated_bytes_per_day > scenario.active_growth_bytes_per_day
        || HOT_SNAPSHOT_GENERATIONS == 0
    {
        return Err(QualificationError::Bounds);
    }
    let net_active_growth = scenario
        .active_growth_bytes_per_day
        .checked_sub(scenario.hibernated_bytes_per_day)
        .ok_or(QualificationError::Bounds)?;
    let snapshot_bytes = scenario
        .full_snapshot_bytes
        .checked_mul(u64::from(HOT_SNAPSHOT_GENERATIONS))
        .ok_or(QualificationError::Overflow)?;
    let mut maximum_physical_bytes = 0_u64;
    let mut maximum_hot_history_bytes = 0_u64;
    let mut final_active_bytes = scenario.initial_active_bytes;
    let mut final_consensus_index_bytes = scenario.initial_consensus_index_bytes;

    for day in 1..=scenario.days {
        final_active_bytes = scenario
            .initial_active_bytes
            .checked_add(net_active_growth.checked_mul(day).ok_or(QualificationError::Overflow)?)
            .ok_or(QualificationError::Overflow)?;
        let retained_days = day.min(HOT_RETENTION_DAYS);
        let hot_history_bytes = scenario
            .assigned_history_bytes_per_day
            .checked_mul(retained_days)
            .ok_or(QualificationError::Overflow)?;
        maximum_hot_history_bytes = maximum_hot_history_bytes.max(hot_history_bytes);
        final_consensus_index_bytes = scenario
            .initial_consensus_index_bytes
            .checked_add(
                scenario
                    .consensus_index_bytes_per_day
                    .checked_mul(day)
                    .ok_or(QualificationError::Overflow)?,
            )
            .ok_or(QualificationError::Overflow)?;
        let telemetry = StorageTelemetry {
            active_state_bytes: final_active_bytes,
            hot_history_bytes,
            snapshot_bytes,
            consensus_index_bytes: final_consensus_index_bytes,
            operational_bytes: scenario.operational_bytes,
            archive_available_shards: ARCHIVE_DATA_SHARDS,
            archive_failure_domains: ARCHIVE_MIN_FAILURE_DOMAINS,
            snapshot_age_hours: 24,
            pruning_lag_days: HOT_RETENTION_DAYS,
            sync_lag_blocks: 0,
            rent_frozen_objects: 0,
            hibernation_backlog_bytes: 0,
        };
        let snapshot = telemetry.summarize()?;
        if final_active_bytes > ACTIVE_STATE_BUDGET_BYTES
            || hot_history_bytes > HOT_HISTORY_BUDGET_BYTES
            || snapshot_bytes > SNAPSHOT_BUDGET_BYTES
            || final_consensus_index_bytes > CONSENSUS_INDEX_BUDGET_BYTES
            || scenario.operational_bytes > OPERATIONAL_RESERVE_BYTES
            || snapshot.physical_bytes > PHYSICAL_CEILING_BYTES
        {
            return Err(QualificationError::BudgetExceeded);
        }
        maximum_physical_bytes = maximum_physical_bytes.max(snapshot.physical_bytes);
    }
    Ok(CapacityReport {
        days: scenario.days,
        final_active_bytes,
        maximum_hot_history_bytes,
        snapshot_bytes,
        final_consensus_index_bytes,
        maximum_physical_bytes,
        minimum_headroom_bytes: PHYSICAL_CEILING_BYTES - maximum_physical_bytes,
    })
}

#[must_use]
pub const fn reference_scenario() -> CapacityScenario {
    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    CapacityScenario {
        days: 730,
        initial_active_bytes: 300 * GIB,
        active_growth_bytes_per_day: GIB,
        hibernated_bytes_per_day: 900 * MIB,
        assigned_history_bytes_per_day: 6 * GIB,
        full_snapshot_bytes: 50 * GIB,
        initial_consensus_index_bytes: 20 * GIB,
        consensus_index_bytes_per_day: 32 * MIB,
        operational_bytes: 20 * GIB,
    }
}

#[must_use]
pub fn render_qualification_fixture() -> String {
    let report = qualify_capacity(reference_scenario()).expect("reference scenario fits");
    format!(
        "fixture_version=1\ndays={}\nfinal_active_bytes={}\nmaximum_hot_history_bytes={}\nsnapshot_bytes={}\nfinal_consensus_index_bytes={}\nmaximum_physical_bytes={}\nminimum_headroom_bytes={}\n",
        report.days,
        report.final_active_bytes,
        report.maximum_hot_history_bytes,
        report.snapshot_bytes,
        report.final_consensus_index_bytes,
        report.maximum_physical_bytes,
        report.minimum_headroom_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pressure_boundaries_and_health_signals_are_stable() {
        let telemetry = StorageTelemetry {
            active_state_bytes: ACTIVE_STATE_BUDGET_BYTES * 9 / 10 + 1,
            hot_history_bytes: 1,
            snapshot_bytes: 1,
            consensus_index_bytes: 1,
            operational_bytes: 1,
            archive_available_shards: ARCHIVE_DATA_SHARDS - 1,
            archive_failure_domains: ARCHIVE_MIN_FAILURE_DOMAINS,
            snapshot_age_hours: MAX_ACCEPTABLE_SNAPSHOT_AGE_HOURS + 1,
            pruning_lag_days: MAX_ACCEPTABLE_PRUNING_LAG_DAYS + 1,
            sync_lag_blocks: MAX_ACCEPTABLE_SYNC_LAG_BLOCKS + 1,
            rent_frozen_objects: 2,
            hibernation_backlog_bytes: 3,
        };
        let snapshot = telemetry.summarize().unwrap();
        assert_eq!(snapshot.active_pressure, StoragePressure::CapacityFrozen);
        assert!(!snapshot.archive_reconstructable);
        assert!(!snapshot.snapshot_fresh);
        assert!(!snapshot.pruning_current);
        assert!(!snapshot.sync_current);
        assert_eq!(snapshot.rent_frozen_objects, 2);
        assert_eq!(snapshot.hibernation_backlog_bytes, 3);
    }

    #[test]
    fn two_year_reference_run_remains_bounded_after_retention_plateau() {
        let report = qualify_capacity(reference_scenario()).unwrap();
        assert_eq!(report.days, 730);
        assert_eq!(
            report.maximum_hot_history_bytes,
            reference_scenario().assigned_history_bytes_per_day * HOT_RETENTION_DAYS
        );
        assert!(report.minimum_headroom_bytes > 0);
    }

    #[test]
    fn budget_breach_and_arithmetic_overflow_fail_closed() {
        let mut breach = reference_scenario();
        breach.initial_active_bytes = ACTIVE_STATE_BUDGET_BYTES;
        assert_eq!(qualify_capacity(breach), Err(QualificationError::BudgetExceeded));
        let mut overflow = reference_scenario();
        overflow.active_growth_bytes_per_day = u64::MAX;
        assert_eq!(qualify_capacity(overflow), Err(QualificationError::Overflow));
    }

    #[test]
    fn checked_in_qualification_fixture_does_not_drift() {
        assert_eq!(
            render_qualification_fixture(),
            include_str!("../../../testing/storage/qualification-v1.txt")
        );
    }
}
