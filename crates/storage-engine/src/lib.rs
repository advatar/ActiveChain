#![forbid(unsafe_code)]

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub type Root = [u8; 48];

pub const MAX_SEGMENT_RECORDS: usize = 4_096;
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
pub const PARTITION_COUNT: usize = 4_096;
pub const MAX_PARTITION_CHUNK_BYTES: u64 = 1 << 30;

const SEGMENT_MAGIC: &[u8; 8] = b"ACLSEG01";
const SEGMENT_FOOTER: &[u8; 8] = b"ACLEND01";
const SNAPSHOT_MAGIC: &[u8; 8] = b"ACSNAP01";
const INDEX_MAGIC: &[u8; 8] = b"ACSIDX01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    Bounds,
    Corrupt,
    Identity,
    Sequence,
    Exists,
    Io,
    Overflow,
}

impl From<std::io::Error> for StorageError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerRecord {
    pub kind: u8,
    pub bytes: Vec<u8>,
}

impl LedgerRecord {
    pub fn new(kind: u8, bytes: Vec<u8>) -> Result<Self, StorageError> {
        if kind == 0 || bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(StorageError::Bounds);
        }
        Ok(Self { kind, bytes })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedSegment {
    pub chain_genesis: Root,
    pub sequence: u64,
    pub previous_segment_root: Root,
    pub records: Vec<LedgerRecord>,
    pub content_root: Root,
}

impl SealedSegment {
    pub fn seal(
        chain_genesis: Root,
        sequence: u64,
        previous_segment_root: Root,
        records: Vec<LedgerRecord>,
    ) -> Result<Self, StorageError> {
        if chain_genesis == [0; 48]
            || records.is_empty()
            || records.len() > MAX_SEGMENT_RECORDS
            || (sequence == 0) != (previous_segment_root == [0; 48])
        {
            return Err(StorageError::Bounds);
        }
        let content_root = segment_root(
            chain_genesis,
            sequence,
            previous_segment_root,
            records.iter().map(record_root),
        );
        Ok(Self { chain_genesis, sequence, previous_segment_root, records, content_root })
    }

    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let rebuilt = Self::seal(
            self.chain_genesis,
            self.sequence,
            self.previous_segment_root,
            self.records.clone(),
        )?;
        if rebuilt.content_root != self.content_root {
            return Err(StorageError::Corrupt);
        }
        let capacity = self.records.iter().try_fold(124_usize, |total, record| {
            total.checked_add(1 + 4 + record.bytes.len() + 48).ok_or(StorageError::Overflow)
        })?;
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(SEGMENT_MAGIC);
        out.extend_from_slice(&self.chain_genesis);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.previous_segment_root);
        out.extend_from_slice(&(self.records.len() as u32).to_be_bytes());
        for record in &self.records {
            out.push(record.kind);
            out.extend_from_slice(&(record.bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&record.bytes);
            out.extend_from_slice(&record_root(record));
        }
        out.extend_from_slice(SEGMENT_FOOTER);
        out.extend_from_slice(&self.content_root);
        out.extend_from_slice(&(self.records.len() as u32).to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != SEGMENT_MAGIC {
            return Err(StorageError::Corrupt);
        }
        let chain_genesis = cursor.root()?;
        let sequence = cursor.u64()?;
        let previous_segment_root = cursor.root()?;
        let count = cursor.u32()? as usize;
        if count == 0 || count > MAX_SEGMENT_RECORDS {
            return Err(StorageError::Bounds);
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = cursor.byte()?;
            let length = cursor.u32()? as usize;
            if length == 0 || length > MAX_RECORD_BYTES {
                return Err(StorageError::Bounds);
            }
            let record = LedgerRecord::new(kind, cursor.take(length)?.to_vec())?;
            if cursor.root()? != record_root(&record) {
                return Err(StorageError::Corrupt);
            }
            records.push(record);
        }
        if cursor.take(8)? != SEGMENT_FOOTER {
            return Err(StorageError::Corrupt);
        }
        let stored_root = cursor.root()?;
        if cursor.u32()? as usize != count || !cursor.is_empty() {
            return Err(StorageError::Corrupt);
        }
        let segment = Self::seal(chain_genesis, sequence, previous_segment_root, records)?;
        if segment.content_root != stored_root {
            return Err(StorageError::Corrupt);
        }
        Ok(segment)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartitionSnapshot {
    pub partition_id: u16,
    pub root: Root,
    pub charged_bytes: u64,
    pub chunk_root: Root,
    pub chunk_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotManifest {
    pub chain_genesis: Root,
    pub height: u64,
    pub protocol_revision: u64,
    pub state_root: Root,
    pub charged_bytes: u64,
    pub partitions: Vec<PartitionSnapshot>,
    pub manifest_root: Root,
}

impl SnapshotManifest {
    pub fn new(
        chain_genesis: Root,
        height: u64,
        protocol_revision: u64,
        state_root: Root,
        partitions: Vec<PartitionSnapshot>,
    ) -> Result<Self, StorageError> {
        if chain_genesis == [0; 48]
            || height == 0
            || protocol_revision == 0
            || state_root == [0; 48]
            || partitions.len() != PARTITION_COUNT
        {
            return Err(StorageError::Bounds);
        }
        let mut charged_bytes = 0_u64;
        for (expected, partition) in partitions.iter().enumerate() {
            if usize::from(partition.partition_id) != expected
                || partition.chunk_root == [0; 48]
                || partition.chunk_bytes > MAX_PARTITION_CHUNK_BYTES
            {
                return Err(StorageError::Bounds);
            }
            charged_bytes =
                charged_bytes.checked_add(partition.charged_bytes).ok_or(StorageError::Overflow)?;
        }
        let manifest_root = snapshot_root(
            chain_genesis,
            height,
            protocol_revision,
            state_root,
            charged_bytes,
            &partitions,
        );
        Ok(Self {
            chain_genesis,
            height,
            protocol_revision,
            state_root,
            charged_bytes,
            partitions,
            manifest_root,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let rebuilt = Self::new(
            self.chain_genesis,
            self.height,
            self.protocol_revision,
            self.state_root,
            self.partitions.clone(),
        )?;
        if rebuilt.charged_bytes != self.charged_bytes
            || rebuilt.manifest_root != self.manifest_root
        {
            return Err(StorageError::Corrupt);
        }
        let mut out = Vec::with_capacity(8 + 48 + 8 + 8 + 48 + 8 + 4 + PARTITION_COUNT * 114 + 48);
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(&self.chain_genesis);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.protocol_revision.to_be_bytes());
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.charged_bytes.to_be_bytes());
        out.extend_from_slice(&(PARTITION_COUNT as u32).to_be_bytes());
        for partition in &self.partitions {
            out.extend_from_slice(&partition.partition_id.to_be_bytes());
            out.extend_from_slice(&partition.root);
            out.extend_from_slice(&partition.charged_bytes.to_be_bytes());
            out.extend_from_slice(&partition.chunk_root);
            out.extend_from_slice(&partition.chunk_bytes.to_be_bytes());
        }
        out.extend_from_slice(&self.manifest_root);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != SNAPSHOT_MAGIC {
            return Err(StorageError::Corrupt);
        }
        let chain_genesis = cursor.root()?;
        let height = cursor.u64()?;
        let protocol_revision = cursor.u64()?;
        let state_root = cursor.root()?;
        let charged_bytes = cursor.u64()?;
        if cursor.u32()? as usize != PARTITION_COUNT {
            return Err(StorageError::Bounds);
        }
        let mut partitions = Vec::with_capacity(PARTITION_COUNT);
        for _ in 0..PARTITION_COUNT {
            partitions.push(PartitionSnapshot {
                partition_id: cursor.u16()?,
                root: cursor.root()?,
                charged_bytes: cursor.u64()?,
                chunk_root: cursor.root()?,
                chunk_bytes: cursor.u64()?,
            });
        }
        let stored_root = cursor.root()?;
        if !cursor.is_empty() {
            return Err(StorageError::Corrupt);
        }
        let manifest = Self::new(chain_genesis, height, protocol_revision, state_root, partitions)?;
        if manifest.charged_bytes != charged_bytes || manifest.manifest_root != stored_root {
            return Err(StorageError::Corrupt);
        }
        Ok(manifest)
    }
}

pub struct LedgerStore {
    directory: PathBuf,
    chain_genesis: Root,
}

impl LedgerStore {
    pub fn open(directory: impl Into<PathBuf>, chain_genesis: Root) -> Result<Self, StorageError> {
        if chain_genesis == [0; 48] {
            return Err(StorageError::Identity);
        }
        let directory = directory.into();
        fs::create_dir_all(&directory)?;
        Ok(Self { directory, chain_genesis })
    }

    pub fn append(&self, segment: &SealedSegment) -> Result<PathBuf, StorageError> {
        if segment.chain_genesis != self.chain_genesis {
            return Err(StorageError::Identity);
        }
        if segment.sequence > 0 {
            let previous = self.load(segment.sequence - 1)?;
            if previous.content_root != segment.previous_segment_root {
                return Err(StorageError::Sequence);
            }
        }
        let path = self.segment_path(segment.sequence);
        if path.exists() {
            return if self.load(segment.sequence)? == *segment {
                Ok(path)
            } else {
                Err(StorageError::Exists)
            };
        }
        atomic_write(&path, &segment.encode()?, false)?;
        Ok(path)
    }

    pub fn load(&self, sequence: u64) -> Result<SealedSegment, StorageError> {
        let mut bytes = Vec::new();
        File::open(self.segment_path(sequence))?.read_to_end(&mut bytes)?;
        let segment = SealedSegment::decode(&bytes)?;
        if segment.chain_genesis != self.chain_genesis || segment.sequence != sequence {
            return Err(StorageError::Identity);
        }
        Ok(segment)
    }

    fn segment_path(&self, sequence: u64) -> PathBuf {
        self.directory.join(format!("segment-{sequence:016x}.seg"))
    }
}

pub struct SnapshotStore {
    directory: PathBuf,
    chain_genesis: Root,
}

#[must_use]
pub fn render_segment_fixture() -> String {
    let segment = SealedSegment::seal(
        [1; 48],
        0,
        [0; 48],
        vec![LedgerRecord::new(1, b"block-one".to_vec()).expect("fixture record is bounded")],
    )
    .expect("fixture segment is valid");
    let encoded = segment.encode().expect("fixture segment encodes");
    format!(
        "fixture_version=1\ncontent_root={}\nencoded_bytes={}\n",
        hex(&segment.content_root),
        hex(&encoded)
    )
}

impl SnapshotStore {
    pub fn open(directory: impl Into<PathBuf>, chain_genesis: Root) -> Result<Self, StorageError> {
        if chain_genesis == [0; 48] {
            return Err(StorageError::Identity);
        }
        let directory = directory.into();
        fs::create_dir_all(&directory)?;
        Ok(Self { directory, chain_genesis })
    }

    pub fn publish(&self, manifest: &SnapshotManifest) -> Result<(), StorageError> {
        if manifest.chain_genesis != self.chain_genesis {
            return Err(StorageError::Identity);
        }
        let mut generations = self.generations()?;
        if generations.last() == Some(&manifest.height) {
            return if self.load(manifest.height)? == *manifest {
                Ok(())
            } else {
                Err(StorageError::Exists)
            };
        }
        if generations.last().is_some_and(|height| manifest.height < *height) {
            return Err(StorageError::Sequence);
        }
        let path = self.manifest_path(manifest.height);
        let encoded = manifest.encode()?;
        if path.exists() {
            let mut existing = Vec::new();
            File::open(&path)?.read_to_end(&mut existing)?;
            if existing != encoded {
                return Err(StorageError::Exists);
            }
        } else {
            atomic_write(&path, &encoded, false)?;
        }
        generations.push(manifest.height);
        if generations.len() > 2 {
            generations.remove(0);
        }
        atomic_write(
            &self.directory.join("generations.idx"),
            &encode_generations(&generations),
            true,
        )?;
        for entry in fs::read_dir(&self.directory)? {
            let path = entry?.path();
            if let Some(height) = manifest_height(&path)
                && !generations.contains(&height)
            {
                fs::remove_file(path)?;
            }
        }
        sync_directory(&self.directory)?;
        Ok(())
    }

    pub fn generations(&self) -> Result<Vec<u64>, StorageError> {
        let path = self.directory.join("generations.idx");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut bytes = Vec::new();
        File::open(path)?.read_to_end(&mut bytes)?;
        decode_generations(&bytes)
    }

    pub fn load(&self, height: u64) -> Result<SnapshotManifest, StorageError> {
        if !self.generations()?.contains(&height) {
            return Err(StorageError::Sequence);
        }
        let mut bytes = Vec::new();
        File::open(self.manifest_path(height))?.read_to_end(&mut bytes)?;
        let manifest = SnapshotManifest::decode(&bytes)?;
        if manifest.chain_genesis != self.chain_genesis || manifest.height != height {
            return Err(StorageError::Identity);
        }
        Ok(manifest)
    }

    fn manifest_path(&self, height: u64) -> PathBuf {
        self.directory.join(format!("snapshot-{height:016x}.manifest"))
    }
}

fn record_root(record: &LedgerRecord) -> Root {
    digest(&[
        b"ACTIVECHAIN-LEDGER-RECORD-V1",
        &[record.kind],
        &(record.bytes.len() as u64).to_be_bytes(),
        &record.bytes,
    ])
}

fn segment_root(
    chain_genesis: Root,
    sequence: u64,
    previous: Root,
    records: impl Iterator<Item = Root>,
) -> Root {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-LEDGER-SEGMENT-V1");
    hasher.update(&chain_genesis);
    hasher.update(&sequence.to_be_bytes());
    hasher.update(&previous);
    for root in records {
        hasher.update(&root);
    }
    finish(hasher)
}

fn snapshot_root(
    chain_genesis: Root,
    height: u64,
    protocol_revision: u64,
    state_root: Root,
    charged_bytes: u64,
    partitions: &[PartitionSnapshot],
) -> Root {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-SNAPSHOT-MANIFEST-V1");
    hasher.update(&chain_genesis);
    hasher.update(&height.to_be_bytes());
    hasher.update(&protocol_revision.to_be_bytes());
    hasher.update(&state_root);
    hasher.update(&charged_bytes.to_be_bytes());
    for partition in partitions {
        hasher.update(&partition.partition_id.to_be_bytes());
        hasher.update(&partition.root);
        hasher.update(&partition.charged_bytes.to_be_bytes());
        hasher.update(&partition.chunk_root);
        hasher.update(&partition.chunk_bytes.to_be_bytes());
    }
    finish(hasher)
}

fn digest(parts: &[&[u8]]) -> Root {
    let mut hasher = Shake256::default();
    for part in parts {
        hasher.update(part);
    }
    finish(hasher)
}

fn finish(hasher: Shake256) -> Root {
    let mut reader = hasher.finalize_xof();
    let mut root = [0; 48];
    reader.read(&mut root);
    root
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

fn encode_generations(generations: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(9 + generations.len() * 8);
    bytes.extend_from_slice(INDEX_MAGIC);
    bytes.push(generations.len() as u8);
    for generation in generations {
        bytes.extend_from_slice(&generation.to_be_bytes());
    }
    let checksum = digest(&[b"ACTIVECHAIN-SNAPSHOT-INDEX-V1", &bytes]);
    bytes.extend_from_slice(&checksum);
    bytes
}

fn decode_generations(bytes: &[u8]) -> Result<Vec<u64>, StorageError> {
    if bytes.len() < 57 || &bytes[..8] != INDEX_MAGIC {
        return Err(StorageError::Corrupt);
    }
    let count = usize::from(bytes[8]);
    if count > 2 || bytes.len() != 9 + count * 8 + 48 {
        return Err(StorageError::Corrupt);
    }
    let checksum_offset = bytes.len() - 48;
    if digest(&[b"ACTIVECHAIN-SNAPSHOT-INDEX-V1", &bytes[..checksum_offset]])
        != bytes[checksum_offset..]
    {
        return Err(StorageError::Corrupt);
    }
    let mut generations = Vec::with_capacity(count);
    for chunk in bytes[9..checksum_offset].chunks_exact(8) {
        let height = u64::from_be_bytes(chunk.try_into().map_err(|_| StorageError::Corrupt)?);
        if height == 0 || generations.last().is_some_and(|previous| height <= *previous) {
            return Err(StorageError::Corrupt);
        }
        generations.push(height);
    }
    Ok(generations)
}

fn manifest_height(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    let value = name.strip_prefix("snapshot-")?.strip_suffix(".manifest")?;
    u64::from_str_radix(value, 16).ok()
}

fn atomic_write(path: &Path, bytes: &[u8], replace: bool) -> Result<(), StorageError> {
    let parent = path.parent().ok_or(StorageError::Io)?;
    fs::create_dir_all(parent)?;
    let mut temporary = None;
    for nonce in 0..64_u32 {
        let candidate = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&candidate) {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(StorageError::Io),
        }
    }
    let (temporary_path, mut file) = temporary.ok_or(StorageError::Exists)?;
    let result: Result<(), StorageError> = (|| -> Result<(), StorageError> {
        file.write_all(bytes)?;
        file.sync_all()?;
        if replace {
            fs::rename(&temporary_path, path)?;
        } else {
            fs::hard_link(&temporary_path, path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    StorageError::Exists
                } else {
                    StorageError::Io
                }
            })?;
            fs::remove_file(&temporary_path)?;
        }
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    File::open(path)?.sync_all()
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StorageError> {
        let end = self.offset.checked_add(length).ok_or(StorageError::Overflow)?;
        let value = self.bytes.get(self.offset..end).ok_or(StorageError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, StorageError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, StorageError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| StorageError::Corrupt)?))
    }

    fn u32(&mut self) -> Result<u32, StorageError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| StorageError::Corrupt)?))
    }

    fn u64(&mut self) -> Result<u64, StorageError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| StorageError::Corrupt)?))
    }

    fn root(&mut self) -> Result<Root, StorageError> {
        self.take(48)?.try_into().map_err(|_| StorageError::Corrupt)
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn root(value: u8) -> Root {
        [value; 48]
    }

    fn manifest(height: u64) -> SnapshotManifest {
        let partitions = (0..PARTITION_COUNT)
            .map(|index| PartitionSnapshot {
                partition_id: index as u16,
                root: root((index % 251) as u8),
                charged_bytes: index as u64,
                chunk_root: root(((index + 1) % 251 + 1) as u8),
                chunk_bytes: index as u64,
            })
            .collect();
        SnapshotManifest::new(root(1), height, 1, root(2), partitions).unwrap()
    }

    #[test]
    fn sealed_segments_are_deterministic_linked_and_strict() {
        let first = SealedSegment::seal(
            root(1),
            0,
            [0; 48],
            vec![LedgerRecord::new(1, b"block-one".to_vec()).unwrap()],
        )
        .unwrap();
        let bytes = first.encode().unwrap();
        assert_eq!(SealedSegment::decode(&bytes).unwrap(), first);
        assert_eq!(first.encode().unwrap(), bytes);
        let mut tampered = bytes.clone();
        tampered[120] ^= 1;
        assert_eq!(SealedSegment::decode(&tampered), Err(StorageError::Corrupt));
        assert_eq!(SealedSegment::decode(&bytes[..bytes.len() - 1]), Err(StorageError::Corrupt));

        let directory = tempdir().unwrap();
        let store = LedgerStore::open(directory.path(), root(1)).unwrap();
        store.append(&first).unwrap();
        assert_eq!(store.append(&first).unwrap(), store.segment_path(0));
        let second = SealedSegment::seal(
            root(1),
            1,
            first.content_root,
            vec![LedgerRecord::new(2, b"receipt-one".to_vec()).unwrap()],
        )
        .unwrap();
        store.append(&second).unwrap();
        assert_eq!(store.load(1).unwrap(), second);
        let wrong =
            SealedSegment::seal(root(1), 2, root(9), vec![LedgerRecord::new(1, vec![1]).unwrap()])
                .unwrap();
        assert_eq!(store.append(&wrong), Err(StorageError::Sequence));
    }

    #[test]
    fn checked_in_segment_fixture_does_not_drift() {
        assert_eq!(
            render_segment_fixture(),
            include_str!("../../../testing/storage/segment-v1.txt")
        );
    }

    #[test]
    fn snapshots_round_trip_and_reject_substitution() {
        let manifest = manifest(10);
        let bytes = manifest.encode().unwrap();
        assert_eq!(SnapshotManifest::decode(&bytes).unwrap(), manifest);
        let mut tampered = bytes;
        tampered[64] ^= 1;
        assert_eq!(SnapshotManifest::decode(&tampered), Err(StorageError::Corrupt));
    }

    #[test]
    fn snapshot_store_retains_exactly_two_complete_generations() {
        let directory = tempdir().unwrap();
        let store = SnapshotStore::open(directory.path(), root(1)).unwrap();
        for height in [10, 20, 30] {
            store.publish(&manifest(height)).unwrap();
        }
        assert_eq!(store.publish(&manifest(30)), Ok(()));
        assert_eq!(store.generations().unwrap(), vec![20, 30]);
        assert_eq!(store.load(20).unwrap().height, 20);
        assert_eq!(store.load(30).unwrap().height, 30);
        assert_eq!(store.load(10), Err(StorageError::Sequence));
        assert!(!store.manifest_path(10).exists());

        let reopened = SnapshotStore::open(directory.path(), root(1)).unwrap();
        assert_eq!(reopened.generations().unwrap(), vec![20, 30]);
        let mut index = fs::read(directory.path().join("generations.idx")).unwrap();
        index[9] ^= 1;
        fs::write(directory.path().join("generations.idx"), index).unwrap();
        assert_eq!(reopened.generations(), Err(StorageError::Corrupt));
    }
}
