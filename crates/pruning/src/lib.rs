#![forbid(unsafe_code)]

use activechain_archive::{ArchiveCertificate, ArchiveDataClass, Root, content_commitment};
use activechain_storage_engine::{LedgerStore, SealedSegment, StorageError};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const WATERMARK_MAGIC: &[u8; 8] = b"ACPRUNE1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PruningMode {
    Pruned,
    Archive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PruningError {
    Early,
    Snapshot,
    Archive,
    Checkpoint,
    Sequence,
    Identity,
    Corrupt,
    Io,
}

impl From<std::io::Error> for PruningError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

impl From<StorageError> for PruningError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::Identity => Self::Identity,
            StorageError::Sequence => Self::Sequence,
            StorageError::Corrupt => Self::Corrupt,
            _ => Self::Io,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PruningWatermark {
    pub chain_genesis: Root,
    pub segment_sequence: u64,
    pub segment_root: Root,
    pub last_height: u64,
}

impl PruningWatermark {
    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(168);
        bytes.extend_from_slice(WATERMARK_MAGIC);
        bytes.extend_from_slice(&self.chain_genesis);
        bytes.extend_from_slice(&self.segment_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.segment_root);
        bytes.extend_from_slice(&self.last_height.to_be_bytes());
        let checksum = digest(b"ACTIVECHAIN-PRUNING-WATERMARK-V1", &bytes);
        bytes.extend_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, PruningError> {
        if bytes.len() != 168 || &bytes[..8] != WATERMARK_MAGIC {
            return Err(PruningError::Corrupt);
        }
        let checksum_offset = bytes.len() - 48;
        if digest(b"ACTIVECHAIN-PRUNING-WATERMARK-V1", &bytes[..checksum_offset])
            != bytes[checksum_offset..]
        {
            return Err(PruningError::Corrupt);
        }
        let chain_genesis = bytes[8..56].try_into().map_err(|_| PruningError::Corrupt)?;
        let segment_sequence =
            u64::from_be_bytes(bytes[56..64].try_into().map_err(|_| PruningError::Corrupt)?);
        let segment_root = bytes[64..112].try_into().map_err(|_| PruningError::Corrupt)?;
        let last_height =
            u64::from_be_bytes(bytes[112..120].try_into().map_err(|_| PruningError::Corrupt)?);
        if chain_genesis == [0; 48] || segment_root == [0; 48] || last_height == 0 {
            return Err(PruningError::Corrupt);
        }
        Ok(Self { chain_genesis, segment_sequence, segment_root, last_height })
    }
}

pub struct PruningEvidence<'a> {
    pub segment_last_height: u64,
    pub hot_retention_until_epoch: u64,
    pub proof_grace_until_height: u64,
    pub history_accumulator_root: Root,
    pub snapshot_generations: [u64; 2],
    pub archive_certificate: &'a ArchiveCertificate,
}

pub struct PruningStore {
    directory: PathBuf,
    chain_genesis: Root,
    mode: PruningMode,
}

impl PruningStore {
    pub fn open(
        directory: impl Into<PathBuf>,
        chain_genesis: Root,
        mode: PruningMode,
    ) -> Result<Self, PruningError> {
        if chain_genesis == [0; 48] {
            return Err(PruningError::Identity);
        }
        let directory = directory.into();
        fs::create_dir_all(&directory)?;
        let store = Self { directory, chain_genesis, mode };
        if let Some(watermark) = store.watermark()?
            && watermark.chain_genesis != chain_genesis
        {
            return Err(PruningError::Identity);
        }
        Ok(store)
    }

    pub fn authorize(
        &self,
        segment: &SealedSegment,
        evidence: PruningEvidence<'_>,
        current_epoch: u64,
        current_height: u64,
    ) -> Result<PruningWatermark, PruningError> {
        if segment.chain_genesis != self.chain_genesis {
            return Err(PruningError::Identity);
        }
        let expected_sequence =
            self.watermark()?.map_or(0, |watermark| watermark.segment_sequence.saturating_add(1));
        if segment.sequence != expected_sequence {
            return Err(PruningError::Sequence);
        }
        if evidence.segment_last_height == 0
            || current_epoch <= evidence.hot_retention_until_epoch
            || current_height <= evidence.proof_grace_until_height
        {
            return Err(PruningError::Early);
        }
        if evidence.snapshot_generations[0] <= evidence.segment_last_height
            || evidence.snapshot_generations[1] <= evidence.snapshot_generations[0]
        {
            return Err(PruningError::Snapshot);
        }
        if evidence.history_accumulator_root == [0; 48] {
            return Err(PruningError::Checkpoint);
        }
        let manifest = evidence.archive_certificate.manifest();
        let segment_bytes = segment.encode().map_err(PruningError::from)?;
        if manifest.chain_genesis != self.chain_genesis
            || manifest.data_class != ArchiveDataClass::Ledger
            || manifest.last_height != evidence.segment_last_height
            || manifest.retention_expiry_epoch < current_epoch
            || manifest.content_root != content_commitment(&segment_bytes)
        {
            return Err(PruningError::Archive);
        }
        let watermark = PruningWatermark {
            chain_genesis: self.chain_genesis,
            segment_sequence: segment.sequence,
            segment_root: segment.content_root,
            last_height: evidence.segment_last_height,
        };
        atomic_replace(&self.watermark_path(), &watermark.encode())?;
        Ok(watermark)
    }

    pub fn authorize_and_prune(
        &self,
        ledger: &LedgerStore,
        segment: &SealedSegment,
        evidence: PruningEvidence<'_>,
        current_epoch: u64,
        current_height: u64,
    ) -> Result<PruningWatermark, PruningError> {
        let watermark = self.authorize(segment, evidence, current_epoch, current_height)?;
        self.complete_pending(ledger)?;
        Ok(watermark)
    }

    pub fn complete_pending(&self, ledger: &LedgerStore) -> Result<(), PruningError> {
        if self.mode == PruningMode::Archive {
            return Ok(());
        }
        if let Some(watermark) = self.watermark()? {
            ledger.delete_if_matches(watermark.segment_sequence, watermark.segment_root)?;
        }
        Ok(())
    }

    pub fn watermark(&self) -> Result<Option<PruningWatermark>, PruningError> {
        let path = self.watermark_path();
        if !path.exists() {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        File::open(path)?.read_to_end(&mut bytes)?;
        Ok(Some(PruningWatermark::decode(&bytes)?))
    }

    fn watermark_path(&self) -> PathBuf {
        self.directory.join("pruning.watermark")
    }
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), PruningError> {
    let parent = path.parent().ok_or(PruningError::Io)?;
    let mut temporary = None;
    for nonce in 0..64_u32 {
        let candidate = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&candidate) {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(PruningError::Io),
        }
    }
    let (temporary, mut file) = temporary.ok_or(PruningError::Io)?;
    let result = (|| -> Result<(), PruningError> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn digest(domain: &[u8], bytes: &[u8]) -> Root {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(bytes);
    let mut reader = hasher.finalize_xof();
    let mut output = [0; 48];
    reader.read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_archive::{
        ArchiveBundle, ArchiveProvider, CustodyReceipt, ReceiptVerifier, TOTAL_SHARDS,
    };
    use activechain_storage_engine::LedgerRecord;
    use tempfile::tempdir;

    fn root(value: u8) -> Root {
        [value; 48]
    }

    struct TestVerifier;
    impl ReceiptVerifier for TestVerifier {
        fn verify(&self, provider: Root, statement: Root, signature: &[u8]) -> bool {
            signature == digest(&provider, &statement)
        }
    }

    fn segment() -> SealedSegment {
        SealedSegment::seal(
            root(1),
            0,
            [0; 48],
            vec![LedgerRecord::new(1, b"finalized-segment".to_vec()).unwrap()],
        )
        .unwrap()
    }

    fn certificate(segment: &SealedSegment) -> ArchiveCertificate {
        let providers = std::array::from_fn(|index| {
            ArchiveProvider::new(root((index + 10) as u8), root((index / 3 + 100) as u8)).unwrap()
        });
        let bundle = ArchiveBundle::encode(
            &segment.encode().unwrap(),
            root(1),
            ArchiveDataClass::Ledger,
            1,
            10,
            100,
            providers,
        )
        .unwrap();
        let receipts = bundle
            .manifest
            .assignments
            .iter()
            .map(|assignment| {
                let mut receipt = CustodyReceipt {
                    provider: assignment.provider.principal,
                    shard_index: assignment.shard_index,
                    manifest_root: bundle.manifest.manifest_root,
                    retention_expiry_epoch: bundle.manifest.retention_expiry_epoch,
                    signature: Vec::new(),
                };
                receipt.signature = digest(&receipt.provider, &receipt.statement()).to_vec();
                receipt
            })
            .collect::<Vec<_>>();
        assert_eq!(receipts.len(), TOTAL_SHARDS);
        ArchiveCertificate::new(bundle.manifest, receipts, 50, &TestVerifier).unwrap()
    }

    fn evidence(certificate: &ArchiveCertificate) -> PruningEvidence<'_> {
        PruningEvidence {
            segment_last_height: 10,
            hot_retention_until_epoch: 40,
            proof_grace_until_height: 20,
            history_accumulator_root: root(3),
            snapshot_generations: [20, 30],
            archive_certificate: certificate,
        }
    }

    #[test]
    fn complete_evidence_persists_before_idempotent_deletion() {
        let directory = tempdir().unwrap();
        let ledger = LedgerStore::open(directory.path().join("ledger"), root(1)).unwrap();
        let segment = segment();
        ledger.append(&segment).unwrap();
        let certificate = certificate(&segment);
        let pruning =
            PruningStore::open(directory.path().join("pruning"), root(1), PruningMode::Pruned)
                .unwrap();
        let watermark = pruning.authorize(&segment, evidence(&certificate), 50, 50).unwrap();
        assert!(ledger.contains(0));
        assert_eq!(pruning.watermark().unwrap(), Some(watermark));
        pruning.complete_pending(&ledger).unwrap();
        assert!(!ledger.contains(0));
        pruning.complete_pending(&ledger).unwrap();

        let reopened =
            PruningStore::open(directory.path().join("pruning"), root(1), PruningMode::Pruned)
                .unwrap();
        reopened.complete_pending(&ledger).unwrap();
        assert_eq!(reopened.watermark().unwrap(), Some(watermark));
    }

    #[test]
    fn every_missing_prerequisite_fails_closed() {
        let directory = tempdir().unwrap();
        let segment = segment();
        let certificate = certificate(&segment);
        let pruning = PruningStore::open(directory.path(), root(1), PruningMode::Pruned).unwrap();

        assert_eq!(
            pruning.authorize(&segment, evidence(&certificate), 40, 50),
            Err(PruningError::Early)
        );
        assert_eq!(
            pruning.authorize(&segment, evidence(&certificate), 50, 20),
            Err(PruningError::Early)
        );
        let mut missing_snapshot = evidence(&certificate);
        missing_snapshot.snapshot_generations = [10, 30];
        assert_eq!(
            pruning.authorize(&segment, missing_snapshot, 50, 50),
            Err(PruningError::Snapshot)
        );
        let mut missing_history = evidence(&certificate);
        missing_history.history_accumulator_root = [0; 48];
        assert_eq!(
            pruning.authorize(&segment, missing_history, 50, 50),
            Err(PruningError::Checkpoint)
        );
        let other_segment = SealedSegment::seal(
            root(1),
            0,
            [0; 48],
            vec![LedgerRecord::new(1, b"other-segment".to_vec()).unwrap()],
        )
        .unwrap();
        assert_eq!(
            pruning.authorize(&other_segment, evidence(&certificate), 50, 50),
            Err(PruningError::Archive)
        );
    }

    #[test]
    fn archive_mode_records_eligibility_without_deleting() {
        let directory = tempdir().unwrap();
        let ledger = LedgerStore::open(directory.path().join("ledger"), root(1)).unwrap();
        let segment = segment();
        ledger.append(&segment).unwrap();
        let certificate = certificate(&segment);
        let pruning =
            PruningStore::open(directory.path().join("pruning"), root(1), PruningMode::Archive)
                .unwrap();
        pruning.authorize_and_prune(&ledger, &segment, evidence(&certificate), 50, 50).unwrap();
        assert!(ledger.contains(0));
    }

    #[test]
    fn corrupt_watermark_fails_closed() {
        let directory = tempdir().unwrap();
        let pruning = PruningStore::open(directory.path(), root(1), PruningMode::Pruned).unwrap();
        fs::write(pruning.watermark_path(), b"corrupt").unwrap();
        assert_eq!(pruning.watermark(), Err(PruningError::Corrupt));
        assert_eq!(
            PruningStore::open(directory.path(), root(1), PruningMode::Pruned).err(),
            Some(PruningError::Corrupt)
        );
    }
}
