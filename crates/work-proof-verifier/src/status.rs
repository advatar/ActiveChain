//! Durable, independent delivery and anchor lifecycle state.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::ProofLifecycleV1;

const STATUS_MAGIC: &[u8; 8] = b"ACWPS01\0";
const MAX_STATUS_RECORDS: usize = 1_000_000;
const STATUS_RECORD_BYTES: usize = 48 + 3;
const MAX_STATUS_FILE_BYTES: u64 =
    (STATUS_MAGIC.len() + 4 + MAX_STATUS_RECORDS * STATUS_RECORD_BYTES) as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DeliveryLifecycleV1 {
    Pending = 0,
    Delivered = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AnchorLifecycleV1 {
    Absent = 0,
    Submitted = 1,
    Finalized = 2,
    Rejected = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofStatusV1 {
    pub claim_id: [u8; 48],
    pub proof_generated: bool,
    pub delivery: DeliveryLifecycleV1,
    pub anchor: AnchorLifecycleV1,
}

#[derive(Debug)]
pub enum StatusStoreError {
    Io(std::io::Error),
    Corrupt,
    Capacity,
    InvalidTransition,
}

impl fmt::Display for StatusStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("proof status storage unavailable"),
            Self::Corrupt => formatter.write_str("proof status storage is corrupt"),
            Self::Capacity => formatter.write_str("proof status storage capacity exceeded"),
            Self::InvalidTransition => formatter.write_str("invalid proof lifecycle transition"),
        }
    }
}

impl std::error::Error for StatusStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Corrupt | Self::Capacity | Self::InvalidTransition => None,
        }
    }
}

impl From<std::io::Error> for StatusStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct DurableProofStatusStore {
    path: PathBuf,
    records: BTreeMap<[u8; 48], ProofStatusV1>,
}

impl DurableProofStatusStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StatusStoreError> {
        let path = path.into();
        if !path.exists() {
            return Ok(Self { path, records: BTreeMap::new() });
        }
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_STATUS_FILE_BYTES {
            return Err(StatusStoreError::Capacity);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(StatusStoreError::Corrupt);
            }
        }

        let mut bytes = Vec::new();
        File::open(&path)?.read_to_end(&mut bytes)?;
        let records = decode_records(&bytes)?;
        Ok(Self { path, records })
    }

    pub fn status(&self, claim_id: &[u8; 48]) -> Option<ProofStatusV1> {
        self.records.get(claim_id).copied()
    }

    pub fn record(
        &mut self,
        claim_id: [u8; 48],
        transition: ProofLifecycleV1,
    ) -> Result<ProofStatusV1, StatusStoreError> {
        let current = self.records.get(&claim_id).copied();
        let next = apply_transition(claim_id, current, transition)?;
        if current == Some(next) {
            return Ok(next);
        }
        if current.is_none() && self.records.len() >= MAX_STATUS_RECORDS {
            return Err(StatusStoreError::Capacity);
        }

        let mut candidate = self.records.clone();
        candidate.insert(claim_id, next);
        persist_records(&self.path, &candidate)?;
        self.records = candidate;
        Ok(next)
    }
}

fn apply_transition(
    claim_id: [u8; 48],
    current: Option<ProofStatusV1>,
    transition: ProofLifecycleV1,
) -> Result<ProofStatusV1, StatusStoreError> {
    let mut status = current.unwrap_or(ProofStatusV1 {
        claim_id,
        proof_generated: false,
        delivery: DeliveryLifecycleV1::Pending,
        anchor: AnchorLifecycleV1::Absent,
    });

    match transition {
        ProofLifecycleV1::ProofGenerated if !status.proof_generated => {
            status.proof_generated = true;
        }
        ProofLifecycleV1::ProofGenerated if status.proof_generated => {}
        ProofLifecycleV1::Delivered if status.proof_generated => {
            status.delivery = DeliveryLifecycleV1::Delivered;
        }
        ProofLifecycleV1::AnchorSubmitted
            if status.proof_generated
                && matches!(
                    status.anchor,
                    AnchorLifecycleV1::Absent | AnchorLifecycleV1::Submitted
                ) =>
        {
            status.anchor = AnchorLifecycleV1::Submitted;
        }
        ProofLifecycleV1::AnchorFinalized
            if matches!(
                status.anchor,
                AnchorLifecycleV1::Submitted | AnchorLifecycleV1::Finalized
            ) =>
        {
            status.anchor = AnchorLifecycleV1::Finalized;
        }
        ProofLifecycleV1::AnchorRejected
            if matches!(
                status.anchor,
                AnchorLifecycleV1::Submitted | AnchorLifecycleV1::Rejected
            ) =>
        {
            status.anchor = AnchorLifecycleV1::Rejected;
        }
        _ => return Err(StatusStoreError::InvalidTransition),
    }
    Ok(status)
}

fn persist_records(
    path: &Path,
    records: &BTreeMap<[u8; 48], ProofStatusV1>,
) -> Result<(), StatusStoreError> {
    let bytes = encode_records(records)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new().create(true).truncate(true).write(true).open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn encode_records(
    records: &BTreeMap<[u8; 48], ProofStatusV1>,
) -> Result<Vec<u8>, StatusStoreError> {
    let count = u32::try_from(records.len()).map_err(|_| StatusStoreError::Capacity)?;
    let mut bytes =
        Vec::with_capacity(STATUS_MAGIC.len() + 4 + records.len() * STATUS_RECORD_BYTES);
    bytes.extend_from_slice(STATUS_MAGIC);
    bytes.extend_from_slice(&count.to_be_bytes());
    for status in records.values() {
        bytes.extend_from_slice(&status.claim_id);
        bytes.push(u8::from(status.proof_generated));
        bytes.push(status.delivery as u8);
        bytes.push(status.anchor as u8);
    }
    Ok(bytes)
}

fn decode_records(bytes: &[u8]) -> Result<BTreeMap<[u8; 48], ProofStatusV1>, StatusStoreError> {
    if bytes.len() < STATUS_MAGIC.len() + 4 || &bytes[..STATUS_MAGIC.len()] != STATUS_MAGIC {
        return Err(StatusStoreError::Corrupt);
    }
    let count_offset = STATUS_MAGIC.len();
    let count = u32::from_be_bytes(
        bytes[count_offset..count_offset + 4].try_into().map_err(|_| StatusStoreError::Corrupt)?,
    ) as usize;
    if count > MAX_STATUS_RECORDS
        || bytes.len() != STATUS_MAGIC.len() + 4 + count * STATUS_RECORD_BYTES
    {
        return Err(StatusStoreError::Corrupt);
    }

    let mut records = BTreeMap::new();
    let mut offset = STATUS_MAGIC.len() + 4;
    for _ in 0..count {
        let mut claim_id = [0_u8; 48];
        claim_id.copy_from_slice(&bytes[offset..offset + 48]);
        offset += 48;
        let proof_generated = match bytes[offset] {
            0 => false,
            1 => true,
            _ => return Err(StatusStoreError::Corrupt),
        };
        offset += 1;
        let delivery = match bytes[offset] {
            0 => DeliveryLifecycleV1::Pending,
            1 => DeliveryLifecycleV1::Delivered,
            _ => return Err(StatusStoreError::Corrupt),
        };
        offset += 1;
        let anchor = match bytes[offset] {
            0 => AnchorLifecycleV1::Absent,
            1 => AnchorLifecycleV1::Submitted,
            2 => AnchorLifecycleV1::Finalized,
            3 => AnchorLifecycleV1::Rejected,
            _ => return Err(StatusStoreError::Corrupt),
        };
        offset += 1;
        let status = ProofStatusV1 { claim_id, proof_generated, delivery, anchor };
        if records.insert(claim_id, status).is_some() {
            return Err(StatusStoreError::Corrupt);
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_never_implies_anchor_finality_and_state_survives_restart() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("proof-status.bin");
        let claim_id = [7_u8; 48];
        let mut store = DurableProofStatusStore::open(&path).expect("open status store");
        store.record(claim_id, ProofLifecycleV1::ProofGenerated).expect("record generated proof");
        let delivered =
            store.record(claim_id, ProofLifecycleV1::Delivered).expect("record delivery");
        assert_eq!(delivered.delivery, DeliveryLifecycleV1::Delivered);
        assert_eq!(delivered.anchor, AnchorLifecycleV1::Absent);
        drop(store);

        let reopened = DurableProofStatusStore::open(&path).expect("reopen status store");
        assert_eq!(reopened.status(&claim_id), Some(delivered));
    }

    #[test]
    fn anchor_transitions_are_monotonic_and_terminal() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut store = DurableProofStatusStore::open(directory.path().join("status.bin"))
            .expect("open status store");
        let claim_id = [9_u8; 48];
        assert!(matches!(
            store.record(claim_id, ProofLifecycleV1::AnchorSubmitted),
            Err(StatusStoreError::InvalidTransition)
        ));
        store.record(claim_id, ProofLifecycleV1::ProofGenerated).expect("record generated proof");
        store.record(claim_id, ProofLifecycleV1::AnchorSubmitted).expect("record submitted anchor");
        let finalized = store
            .record(claim_id, ProofLifecycleV1::AnchorFinalized)
            .expect("record finalized anchor");
        assert_eq!(finalized.anchor, AnchorLifecycleV1::Finalized);
        assert!(matches!(
            store.record(claim_id, ProofLifecycleV1::AnchorRejected),
            Err(StatusStoreError::InvalidTransition)
        ));
    }
}
