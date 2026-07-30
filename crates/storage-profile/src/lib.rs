#![forbid(unsafe_code)]

//! Deterministic logical storage accounting for the bounded-validator contract.
//!
//! Filesystem allocation and database amplification are deliberately excluded from consensus.
//! Releases qualify this conservative logical schedule against the physical ceiling separately.

pub const GIB: u64 = 1 << 30;
pub const TIB: u64 = 1 << 40;
pub const PHYSICAL_CEILING_BYTES: u64 = TIB;
pub const ACTIVE_STATE_BUDGET_BYTES: u64 = 512 * GIB;
pub const HOT_HISTORY_BUDGET_BYTES: u64 = 256 * GIB;
pub const SNAPSHOT_BUDGET_BYTES: u64 = 128 * GIB;
pub const CONSENSUS_INDEX_BUDGET_BYTES: u64 = 64 * GIB;
pub const OPERATIONAL_RESERVE_BYTES: u64 = 64 * GIB;
pub const HOT_RETENTION_DAYS: u64 = 30;
pub const HOT_SNAPSHOT_GENERATIONS: u8 = 2;
pub const ARCHIVE_DATA_SHARDS: u8 = 8;
pub const ARCHIVE_TOTAL_SHARDS: u8 = 12;
pub const ARCHIVE_MIN_FAILURE_DOMAINS: u8 = 4;
pub const ARCHIVE_MAX_SHARDS_PER_FAILURE_DOMAIN: u8 = 3;

/// Conservative v1 charge: twice the canonical bytes plus one KiB for tree and index material.
pub const OBJECT_FIXED_OVERHEAD_BYTES: u64 = 1_024;
pub const OBJECT_CANONICAL_MULTIPLIER: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoragePressure {
    Normal,
    Elevated,
    High,
    CapacityFrozen,
    ExpansionRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageAccountingError {
    ZeroDenominator,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Workload {
    pub active_object_count: u64,
    pub average_canonical_object_bytes: u64,
    pub hot_source_bytes_per_day: u64,
    pub assigned_history_numerator: u64,
    pub assigned_history_denominator: u64,
    pub full_snapshot_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkloadReport {
    pub charged_active_state_bytes: u64,
    pub assigned_hot_history_bytes: u64,
    pub hot_snapshot_bytes: u64,
    pub total_planned_bytes: u64,
    pub active_state_fits: bool,
    pub hot_history_fits: bool,
    pub snapshots_fit: bool,
    pub physical_ceiling_fits: bool,
}

#[must_use]
pub const fn physical_budget_sum() -> u64 {
    ACTIVE_STATE_BUDGET_BYTES
        + HOT_HISTORY_BUDGET_BYTES
        + SNAPSHOT_BUDGET_BYTES
        + CONSENSUS_INDEX_BUDGET_BYTES
        + OPERATIONAL_RESERVE_BYTES
}

pub fn charged_object_bytes(canonical_bytes: u64) -> Result<u64, StorageAccountingError> {
    canonical_bytes
        .checked_mul(OBJECT_CANONICAL_MULTIPLIER)
        .and_then(|bytes| bytes.checked_add(OBJECT_FIXED_OVERHEAD_BYTES))
        .ok_or(StorageAccountingError::Overflow)
}

/// Classifies exact basis-point utilization. Boundaries are intentionally inclusive.
#[must_use]
pub const fn pressure_for_basis_points(utilization_basis_points: u16) -> StoragePressure {
    match utilization_basis_points {
        0..7_000 => StoragePressure::Normal,
        7_000..8_500 => StoragePressure::Elevated,
        8_500..9_000 => StoragePressure::High,
        9_000..9_500 => StoragePressure::CapacityFrozen,
        _ => StoragePressure::ExpansionRejected,
    }
}

pub fn utilization_basis_points(
    used_bytes: u64,
    budget_bytes: u64,
) -> Result<u16, StorageAccountingError> {
    if budget_bytes == 0 {
        return Err(StorageAccountingError::ZeroDenominator);
    }
    let basis_points =
        u128::from(used_bytes).checked_mul(10_000).ok_or(StorageAccountingError::Overflow)?
            / u128::from(budget_bytes);
    Ok(basis_points.min(u128::from(u16::MAX)) as u16)
}

pub fn report(workload: Workload) -> Result<WorkloadReport, StorageAccountingError> {
    if workload.assigned_history_denominator == 0 {
        return Err(StorageAccountingError::ZeroDenominator);
    }
    let per_object = charged_object_bytes(workload.average_canonical_object_bytes)?;
    let charged_active_state_bytes = workload
        .active_object_count
        .checked_mul(per_object)
        .ok_or(StorageAccountingError::Overflow)?;
    let hot_source = workload
        .hot_source_bytes_per_day
        .checked_mul(HOT_RETENTION_DAYS)
        .and_then(|bytes| bytes.checked_mul(workload.assigned_history_numerator))
        .ok_or(StorageAccountingError::Overflow)?;
    let assigned_hot_history_bytes = hot_source / workload.assigned_history_denominator;
    let hot_snapshot_bytes = workload
        .full_snapshot_bytes
        .checked_mul(u64::from(HOT_SNAPSHOT_GENERATIONS))
        .ok_or(StorageAccountingError::Overflow)?;
    let total_planned_bytes = charged_active_state_bytes
        .checked_add(assigned_hot_history_bytes)
        .and_then(|bytes| bytes.checked_add(hot_snapshot_bytes))
        .and_then(|bytes| bytes.checked_add(CONSENSUS_INDEX_BUDGET_BYTES))
        .and_then(|bytes| bytes.checked_add(OPERATIONAL_RESERVE_BYTES))
        .ok_or(StorageAccountingError::Overflow)?;
    Ok(WorkloadReport {
        charged_active_state_bytes,
        assigned_hot_history_bytes,
        hot_snapshot_bytes,
        total_planned_bytes,
        active_state_fits: charged_active_state_bytes <= ACTIVE_STATE_BUDGET_BYTES,
        hot_history_fits: assigned_hot_history_bytes <= HOT_HISTORY_BUDGET_BYTES,
        snapshots_fit: hot_snapshot_bytes <= SNAPSHOT_BUDGET_BYTES,
        physical_ceiling_fits: total_planned_bytes <= PHYSICAL_CEILING_BYTES,
    })
}

#[must_use]
pub const fn representative_workload() -> Workload {
    Workload {
        active_object_count: 10_000_000,
        average_canonical_object_bytes: 1_024,
        hot_source_bytes_per_day: 48 * GIB,
        assigned_history_numerator: 1,
        assigned_history_denominator: 12,
        full_snapshot_bytes: 40 * GIB,
    }
}

pub fn render_representative_workload_tsv() -> Result<String, StorageAccountingError> {
    let workload = representative_workload();
    let report = report(workload)?;
    Ok(format!(
        "workload_version\t1\nactive_objects\t{}\naverage_canonical_object_bytes\t{}\nhot_source_bytes_per_day\t{}\nassigned_history_numerator\t{}\nassigned_history_denominator\t{}\nfull_snapshot_bytes\t{}\ncharged_active_state_bytes\t{}\nassigned_hot_history_bytes\t{}\nhot_snapshot_bytes\t{}\ntotal_planned_bytes\t{}\nactive_state_fits\t{}\nhot_history_fits\t{}\nsnapshots_fit\t{}\nphysical_ceiling_fits\t{}\n",
        workload.active_object_count,
        workload.average_canonical_object_bytes,
        workload.hot_source_bytes_per_day,
        workload.assigned_history_numerator,
        workload.assigned_history_denominator,
        workload.full_snapshot_bytes,
        report.charged_active_state_bytes,
        report.assigned_hot_history_bytes,
        report.hot_snapshot_bytes,
        report.total_planned_bytes,
        report.active_state_fits,
        report.hot_history_fits,
        report.snapshots_fit,
        report.physical_ceiling_fits,
    ))
}

#[must_use]
pub fn render_profile_tsv() -> String {
    format!(
        "profile_version\t1\nphysical_ceiling_bytes\t{PHYSICAL_CEILING_BYTES}\nactive_state_budget_bytes\t{ACTIVE_STATE_BUDGET_BYTES}\nhot_history_budget_bytes\t{HOT_HISTORY_BUDGET_BYTES}\nsnapshot_budget_bytes\t{SNAPSHOT_BUDGET_BYTES}\nconsensus_index_budget_bytes\t{CONSENSUS_INDEX_BUDGET_BYTES}\noperational_reserve_bytes\t{OPERATIONAL_RESERVE_BYTES}\nhot_retention_days\t{HOT_RETENTION_DAYS}\nhot_snapshot_generations\t{HOT_SNAPSHOT_GENERATIONS}\narchive_data_shards\t{ARCHIVE_DATA_SHARDS}\narchive_total_shards\t{ARCHIVE_TOTAL_SHARDS}\narchive_min_failure_domains\t{ARCHIVE_MIN_FAILURE_DOMAINS}\narchive_max_shards_per_failure_domain\t{ARCHIVE_MAX_SHARDS_PER_FAILURE_DOMAIN}\nobject_fixed_overhead_bytes\t{OBJECT_FIXED_OVERHEAD_BYTES}\nobject_canonical_multiplier\t{OBJECT_CANONICAL_MULTIPLIER}\npressure_elevated_basis_points\t7000\npressure_high_basis_points\t8500\npressure_capacity_frozen_basis_points\t9000\npressure_expansion_rejected_basis_points\t9500\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_partitions_sum_exactly_to_one_tibibyte() {
        assert_eq!(physical_budget_sum(), PHYSICAL_CEILING_BYTES);
    }

    #[test]
    fn pressure_boundaries_are_exact() {
        assert_eq!(pressure_for_basis_points(6_999), StoragePressure::Normal);
        assert_eq!(pressure_for_basis_points(7_000), StoragePressure::Elevated);
        assert_eq!(pressure_for_basis_points(8_500), StoragePressure::High);
        assert_eq!(pressure_for_basis_points(9_000), StoragePressure::CapacityFrozen);
        assert_eq!(pressure_for_basis_points(9_500), StoragePressure::ExpansionRejected);
    }

    #[test]
    fn accounting_is_overflow_safe() {
        assert_eq!(charged_object_bytes(u64::MAX), Err(StorageAccountingError::Overflow));
        assert_eq!(
            report(Workload {
                active_object_count: u64::MAX,
                average_canonical_object_bytes: 1,
                hot_source_bytes_per_day: 1,
                assigned_history_numerator: 1,
                assigned_history_denominator: 1,
                full_snapshot_bytes: 1,
            }),
            Err(StorageAccountingError::Overflow)
        );
    }

    #[test]
    fn checked_in_profile_does_not_drift() {
        assert_eq!(render_profile_tsv(), include_str!("../../../testing/storage-profile-v1.tsv"));
        assert_eq!(
            render_representative_workload_tsv().unwrap(),
            include_str!("../../../testing/storage-workload-v1.tsv")
        );
    }
}
