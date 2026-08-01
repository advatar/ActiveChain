#![forbid(unsafe_code)]

use activechain_archive::{
    ArchiveBundle, ArchiveCertificate, ArchiveDataClass, ArchiveError, ArchiveProvider,
    ArchiveShard, CustodyReceipt, DATA_SHARDS, ReceiptVerifier,
};
use activechain_pruning::{PruningError, PruningEvidence, PruningMode, PruningStore};
use activechain_storage_engine::{
    LedgerRecord, LedgerStore, PARTITION_COUNT, PartitionSnapshot, PartitionStateStore,
    SealedSegment, SnapshotManifest, SnapshotStore, StorageError, partition_payload_root,
};
use std::{
    fmt, fs,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub type Root = [u8; 48];

pub const DEFAULT_PARTITION_BYTES: usize = 16 * 1024;
pub const DEFAULT_SEGMENT_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_SEGMENTS: u32 = 8;
pub const SNAPSHOT_GENERATIONS_EXERCISED: u64 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SoakConfig {
    pub partition_bytes: usize,
    pub segment_bytes: usize,
    pub segments: u32,
}

impl Default for SoakConfig {
    fn default() -> Self {
        Self {
            partition_bytes: DEFAULT_PARTITION_BYTES,
            segment_bytes: DEFAULT_SEGMENT_BYTES,
            segments: DEFAULT_SEGMENTS,
        }
    }
}

impl SoakConfig {
    pub fn validate(self) -> Result<Self, SoakError> {
        if self.partition_bytes == 0
            || self.partition_bytes > 1 << 30
            || self.segment_bytes == 0
            || self.segment_bytes > activechain_storage_engine::MAX_RECORD_BYTES
            || self.segments == 0
        {
            return Err(SoakError::Bounds);
        }
        Ok(self)
    }

    pub fn logical_snapshot_bytes(self) -> Result<u64, SoakError> {
        u64::try_from(self.partition_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_mul(PARTITION_COUNT as u64))
            .ok_or(SoakError::Overflow)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoakReport {
    pub partition_bytes: usize,
    pub segment_bytes: usize,
    pub segments: u32,
    pub logical_snapshot_bytes: u64,
    pub peak_physical_bytes: u64,
    pub final_physical_bytes: u64,
    pub interrupted_activation_rejected: bool,
    pub prior_generation_survived_restart: bool,
    pub corruption_detected_on_restart: bool,
    pub eight_shards_reconstructed: bool,
    pub seven_shards_rejected: bool,
    pub incomplete_pruning_rejected: bool,
    pub pruning_resumed_after_restart: bool,
}

impl SoakReport {
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            concat!(
                "report_version=1\n",
                "partition_bytes={}\n",
                "segment_bytes={}\n",
                "segments={}\n",
                "logical_snapshot_bytes={}\n",
                "peak_physical_bytes={}\n",
                "final_physical_bytes={}\n",
                "interrupted_activation_rejected={}\n",
                "prior_generation_survived_restart={}\n",
                "corruption_detected_on_restart={}\n",
                "eight_shards_reconstructed={}\n",
                "seven_shards_rejected={}\n",
                "incomplete_pruning_rejected={}\n",
                "pruning_resumed_after_restart={}\n"
            ),
            self.partition_bytes,
            self.segment_bytes,
            self.segments,
            self.logical_snapshot_bytes,
            self.peak_physical_bytes,
            self.final_physical_bytes,
            self.interrupted_activation_rejected,
            self.prior_generation_survived_restart,
            self.corruption_detected_on_restart,
            self.eight_shards_reconstructed,
            self.seven_shards_rejected,
            self.incomplete_pruning_rejected,
            self.pruning_resumed_after_restart,
        )
    }
}

#[derive(Debug)]
pub enum SoakError {
    Bounds,
    Overflow,
    DirectoryNotEmpty,
    Storage(StorageError),
    Archive(ArchiveError),
    Pruning(PruningError),
    Io(std::io::Error),
    Invariant(&'static str),
}

impl fmt::Display for SoakError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SoakError {}

impl From<StorageError> for SoakError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<ArchiveError> for SoakError {
    fn from(error: ArchiveError) -> Self {
        Self::Archive(error)
    }
}

impl From<PruningError> for SoakError {
    fn from(error: PruningError) -> Self {
        Self::Pruning(error)
    }
}

impl From<std::io::Error> for SoakError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn run_soak(directory: &Path, config: SoakConfig) -> Result<SoakReport, SoakError> {
    let config = config.validate()?;
    prepare_directory(directory)?;
    let chain_genesis = root(1);
    let ledger_directory = directory.join("ledger");
    let state_directory = directory.join("state");
    let archive_directory = directory.join("archive");
    let pruning_directory = directory.join("pruning");
    fs::create_dir_all(&archive_directory)?;

    let ledger = LedgerStore::open(&ledger_directory, chain_genesis)?;
    let segments = append_segments(&ledger, chain_genesis, config)?;
    let mut peak_physical_bytes = physical_bytes(directory)?;

    let state = PartitionStateStore::open(&state_directory, chain_genesis)?;
    let first =
        stage_generation(&state, chain_genesis, 1, config.partition_bytes, 0..PARTITION_COUNT)?;
    state.activate(&first)?;
    peak_physical_bytes = peak_physical_bytes.max(physical_bytes(directory)?);

    let second = manifest_for_generation(chain_genesis, 2, config.partition_bytes)?;
    let midpoint = PARTITION_COUNT / 2;
    stage_manifest_range(&state, &second, 2, config.partition_bytes, 0..midpoint)?;
    let interrupted_activation_rejected = state.activate(&second).is_err();
    drop(state);
    let reopened = PartitionStateStore::open(&state_directory, chain_genesis)?;
    let prior_generation_survived_restart = reopened.load_active()?.height == 1;
    stage_manifest_range(&reopened, &second, 2, config.partition_bytes, midpoint..PARTITION_COUNT)?;
    peak_physical_bytes = peak_physical_bytes.max(physical_bytes(directory)?);
    reopened.activate(&second)?;
    peak_physical_bytes = peak_physical_bytes.max(physical_bytes(directory)?);

    let third =
        stage_generation(&reopened, chain_genesis, 3, config.partition_bytes, 0..PARTITION_COUNT)?;
    peak_physical_bytes = peak_physical_bytes.max(physical_bytes(directory)?);
    reopened.activate(&third)?;
    let retained =
        SnapshotStore::open(state_directory.join("snapshots"), chain_genesis)?.generations()?;
    if retained != [2, 3] {
        return Err(SoakError::Invariant("snapshot generations were not bounded to two"));
    }
    peak_physical_bytes = peak_physical_bytes.max(physical_bytes(directory)?);

    let archive_bundle = archive_segment(&segments[0], chain_genesis, &archive_directory)?;
    let eight = load_shards(&archive_directory, 0..DATA_SHARDS)?;
    let eight_shards_reconstructed =
        archive_bundle.manifest.reconstruct(&eight, 50)? == segments[0].encode()?;
    fs::remove_file(archive_directory.join(format!("shard-{:02}.bin", DATA_SHARDS - 1)))?;
    let seven = load_shards(&archive_directory, 0..DATA_SHARDS - 1)?;
    let seven_shards_rejected = matches!(
        archive_bundle.manifest.reconstruct(&seven, 50),
        Err(ArchiveError::InsufficientShards)
    );

    let certificate = certificate(&archive_bundle)?;
    let pruning = PruningStore::open(&pruning_directory, chain_genesis, PruningMode::Pruned)?;
    let incomplete_pruning_rejected = matches!(
        pruning.authorize(&segments[0], pruning_evidence(&certificate, [0; 48]), 50, 50,),
        Err(PruningError::Checkpoint)
    ) && ledger.contains(0)
        && pruning.watermark()?.is_none();
    let watermark =
        pruning.authorize(&segments[0], pruning_evidence(&certificate, root(9)), 50, 50)?;
    drop(pruning);
    let reopened_pruning =
        PruningStore::open(&pruning_directory, chain_genesis, PruningMode::Pruned)?;
    reopened_pruning.complete_pending(&ledger)?;
    let pruning_resumed_after_restart =
        !ledger.contains(0) && reopened_pruning.watermark()? == Some(watermark);

    corrupt_active_partition(&state_directory, third.partitions[0].chunk_root)?;
    let corruption_detected_on_restart = matches!(
        PartitionStateStore::open(&state_directory, chain_genesis)?.load_active(),
        Err(StorageError::Corrupt)
    );

    let final_physical_bytes = physical_bytes(directory)?;
    peak_physical_bytes = peak_physical_bytes.max(final_physical_bytes);
    let report = SoakReport {
        partition_bytes: config.partition_bytes,
        segment_bytes: config.segment_bytes,
        segments: config.segments,
        logical_snapshot_bytes: config.logical_snapshot_bytes()?,
        peak_physical_bytes,
        final_physical_bytes,
        interrupted_activation_rejected,
        prior_generation_survived_restart,
        corruption_detected_on_restart,
        eight_shards_reconstructed,
        seven_shards_rejected,
        incomplete_pruning_rejected,
        pruning_resumed_after_restart,
    };
    if !report.interrupted_activation_rejected
        || !report.prior_generation_survived_restart
        || !report.corruption_detected_on_restart
        || !report.eight_shards_reconstructed
        || !report.seven_shards_rejected
        || !report.incomplete_pruning_rejected
        || !report.pruning_resumed_after_restart
    {
        return Err(SoakError::Invariant("one or more soak invariants failed"));
    }
    write_report(directory.join("soak-report-v1.txt"), &report.render())?;
    Ok(report)
}

fn prepare_directory(directory: &Path) -> Result<(), SoakError> {
    if directory.exists() {
        if fs::read_dir(directory)?.next().transpose()?.is_some() {
            return Err(SoakError::DirectoryNotEmpty);
        }
    } else {
        fs::create_dir_all(directory)?;
    }
    Ok(())
}

fn append_segments(
    ledger: &LedgerStore,
    chain_genesis: Root,
    config: SoakConfig,
) -> Result<Vec<SealedSegment>, SoakError> {
    let mut segments = Vec::with_capacity(config.segments as usize);
    let mut previous = [0; 48];
    for sequence in 0..u64::from(config.segments) {
        let byte = u8::try_from(sequence % 251 + 1).map_err(|_| SoakError::Overflow)?;
        let record = LedgerRecord::new(1, vec![byte; config.segment_bytes])?;
        let segment = SealedSegment::seal(chain_genesis, sequence, previous, vec![record])?;
        ledger.append(&segment)?;
        previous = segment.content_root;
        segments.push(segment);
    }
    Ok(segments)
}

fn stage_generation(
    state: &PartitionStateStore,
    chain_genesis: Root,
    generation: u64,
    partition_bytes: usize,
    range: std::ops::Range<usize>,
) -> Result<SnapshotManifest, SoakError> {
    let manifest = manifest_for_generation(chain_genesis, generation, partition_bytes)?;
    stage_manifest_range(state, &manifest, generation, partition_bytes, range)?;
    Ok(manifest)
}

fn manifest_for_generation(
    chain_genesis: Root,
    generation: u64,
    partition_bytes: usize,
) -> Result<SnapshotManifest, SoakError> {
    let mut partitions = Vec::with_capacity(PARTITION_COUNT);
    for partition_id in 0..PARTITION_COUNT {
        let partition_id = u16::try_from(partition_id).map_err(|_| SoakError::Overflow)?;
        let payload = partition_payload(generation, partition_id, partition_bytes);
        partitions.push(PartitionSnapshot {
            partition_id,
            root: partition_state_root(generation, partition_id),
            charged_bytes: payload.len() as u64,
            chunk_root: partition_payload_root(partition_id, &payload),
            chunk_bytes: payload.len() as u64,
        });
    }
    SnapshotManifest::new(chain_genesis, generation, 1, generation_root(generation), partitions)
        .map_err(SoakError::from)
}

fn stage_manifest_range(
    state: &PartitionStateStore,
    manifest: &SnapshotManifest,
    generation: u64,
    partition_bytes: usize,
    range: std::ops::Range<usize>,
) -> Result<(), SoakError> {
    for index in range {
        let expected = *manifest.partitions.get(index).ok_or(SoakError::Bounds)?;
        let payload = partition_payload(generation, expected.partition_id, partition_bytes);
        state.stage_partition(expected, &payload)?;
    }
    Ok(())
}

fn partition_payload(generation: u64, partition_id: u16, bytes: usize) -> Vec<u8> {
    let mut payload = vec![0_u8; bytes];
    let generation_bytes = generation.to_be_bytes();
    let partition_bytes = partition_id.to_be_bytes();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = generation_bytes[index % generation_bytes.len()]
            ^ partition_bytes[index % partition_bytes.len()]
            ^ (index % 251) as u8;
    }
    payload
}

fn partition_state_root(generation: u64, partition_id: u16) -> Root {
    let mut value = [0_u8; 48];
    value[..8].copy_from_slice(&generation.to_be_bytes());
    value[8..10].copy_from_slice(&partition_id.to_be_bytes());
    value[47] = 1;
    value
}

fn generation_root(generation: u64) -> Root {
    let mut value = [0_u8; 48];
    value[..8].copy_from_slice(&generation.to_be_bytes());
    value[47] = 1;
    value
}

fn archive_segment(
    segment: &SealedSegment,
    chain_genesis: Root,
    directory: &Path,
) -> Result<ArchiveBundle, SoakError> {
    let providers = std::array::from_fn(|index| ArchiveProvider {
        principal: root((index + 10) as u8),
        failure_domain: root((index / 3 + 100) as u8),
    });
    let bundle = ArchiveBundle::encode(
        &segment.encode()?,
        chain_genesis,
        ArchiveDataClass::Ledger,
        1,
        10,
        100,
        providers,
    )?;
    for shard in &bundle.shards {
        let path = directory.join(format!("shard-{:02}.bin", shard.shard_index));
        write_synced(&path, &shard.bytes)?;
    }
    Ok(bundle)
}

fn load_shards(
    directory: &Path,
    range: std::ops::Range<usize>,
) -> Result<Vec<ArchiveShard>, SoakError> {
    range
        .map(|index| {
            let mut bytes = Vec::new();
            File::open(directory.join(format!("shard-{index:02}.bin")))?.read_to_end(&mut bytes)?;
            Ok(ArchiveShard { shard_index: index as u8, bytes })
        })
        .collect()
}

struct AcceptReceipt;

impl ReceiptVerifier for AcceptReceipt {
    fn verify(&self, _provider: Root, _statement: Root, signature: &[u8]) -> bool {
        signature == [1]
    }
}

fn certificate(bundle: &ArchiveBundle) -> Result<ArchiveCertificate, SoakError> {
    let receipts = bundle
        .manifest
        .assignments
        .iter()
        .map(|assignment| CustodyReceipt {
            provider: assignment.provider.principal,
            shard_index: assignment.shard_index,
            manifest_root: bundle.manifest.manifest_root,
            retention_expiry_epoch: bundle.manifest.retention_expiry_epoch,
            signature: vec![1],
        })
        .collect();
    ArchiveCertificate::new(bundle.manifest.clone(), receipts, 50, &AcceptReceipt)
        .map_err(SoakError::from)
}

fn pruning_evidence(
    certificate: &ArchiveCertificate,
    history_accumulator_root: Root,
) -> PruningEvidence<'_> {
    PruningEvidence {
        segment_last_height: 10,
        hot_retention_until_epoch: 40,
        proof_grace_until_height: 20,
        history_accumulator_root,
        snapshot_generations: [20, 30],
        archive_certificate: certificate,
    }
}

fn corrupt_active_partition(directory: &Path, chunk_root: Root) -> Result<(), SoakError> {
    let path = directory.join("chunks").join(format!("{}.chunk", hex(&chunk_root)));
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let mut first = [0_u8; 1];
    file.read_exact(&mut first)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&[first[0] ^ 0xff])?;
    file.sync_all()?;
    Ok(())
}

fn physical_bytes(directory: &Path) -> Result<u64, SoakError> {
    let mut total = 0_u64;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            total = total.checked_add(physical_bytes(&path)?).ok_or(SoakError::Overflow)?;
        } else if metadata.is_file() {
            total = total.checked_add(metadata.len()).ok_or(SoakError::Overflow)?;
        } else {
            return Err(SoakError::Invariant("unsupported filesystem entry"));
        }
    }
    Ok(total)
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), SoakError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_report(path: PathBuf, contents: &str) -> Result<(), SoakError> {
    write_synced(&path, contents.as_bytes())
}

fn root(value: u8) -> Root {
    [value; 48]
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn physical_soak_exercises_fail_closed_recovery() {
        let temporary = tempdir().unwrap();
        let directory = temporary.path().join("soak");
        let report =
            run_soak(&directory, SoakConfig { partition_bytes: 8, segment_bytes: 32, segments: 2 })
                .unwrap();
        assert_eq!(report.logical_snapshot_bytes, (PARTITION_COUNT * 8) as u64);
        assert!(report.peak_physical_bytes >= report.final_physical_bytes);
        assert_eq!(
            fs::read_to_string(directory.join("soak-report-v1.txt")).unwrap(),
            report.render()
        );
    }

    #[test]
    fn invalid_or_reused_targets_fail_before_mutation() {
        assert_eq!(
            SoakConfig { partition_bytes: 0, segment_bytes: 1, segments: 1 }
                .validate()
                .unwrap_err()
                .to_string(),
            SoakError::Bounds.to_string()
        );
        let temporary = tempdir().unwrap();
        fs::write(temporary.path().join("owned"), b"user data").unwrap();
        assert!(matches!(
            run_soak(
                temporary.path(),
                SoakConfig { partition_bytes: 1, segment_bytes: 1, segments: 1 }
            ),
            Err(SoakError::DirectoryNotEmpty)
        ));
    }
}
