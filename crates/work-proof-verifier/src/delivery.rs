//! Durable, idempotent storage for delivered work-proof artifacts.

use activechain_protocol_types::Digest384;
use sha3::{Digest as _, Sha3_384};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const MAX_DELIVERY_ARTIFACT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_DELIVERY_REQUEST_ID_BYTES: usize = 128;
pub const MAX_DELIVERY_RECORDS: usize = 4_096;
pub const MAX_DELIVERY_STORE_BYTES: u64 = 256 * 1024 * 1024;

const RECORD_MAGIC: &[u8; 8] = b"ACDLV1\0\0";
const RECORD_FIXED_BYTES: usize = 8 + 2 + 48 + 4 + 48;
const MAX_RECORD_BYTES: u64 =
    (RECORD_FIXED_BYTES + MAX_DELIVERY_REQUEST_ID_BYTES + MAX_DELIVERY_ARTIFACT_BYTES) as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryError {
    Invalid,
    Conflict,
    Capacity,
    Persistence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryReceipt {
    pub reference: Digest384,
    pub duplicate: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeliveryMetadata {
    reference: Digest384,
    artifact_bytes: u64,
}

pub struct DurableDeliveryStore {
    root: PathBuf,
    entries: BTreeMap<Vec<u8>, DeliveryMetadata>,
    artifact_bytes: u64,
    _lock: File,
}

impl Drop for DurableDeliveryStore {
    fn drop(&mut self) {
        let _ = File::unlock(&self._lock);
    }
}

impl DurableDeliveryStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, DeliveryError> {
        let root = root.into();
        ensure_private_directory(&root)?;
        let lock_path = root.join("delivery.lock");
        reject_non_file_if_present(&lock_path)?;
        let lock =
            private_file_options(false).open(&lock_path).map_err(|_| DeliveryError::Persistence)?;
        lock.try_lock().map_err(|_| DeliveryError::Persistence)?;

        let mut entries = BTreeMap::new();
        let mut artifact_bytes = 0_u64;
        for item in fs::read_dir(&root).map_err(|_| DeliveryError::Persistence)? {
            let path = item.map_err(|_| DeliveryError::Persistence)?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("delivery") {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).map_err(|_| DeliveryError::Persistence)?;
            if !metadata.file_type().is_file() || metadata.len() > MAX_RECORD_BYTES {
                return Err(DeliveryError::Invalid);
            }
            require_private_mode(&metadata)?;
            let bytes = fs::read(&path).map_err(|_| DeliveryError::Persistence)?;
            let (request_id, record) = decode_record(&bytes)?;
            if path.file_stem().and_then(|value| value.to_str())
                != Some(&digest_hex(request_key(&request_id)))
                || entries.insert(request_id, record).is_some()
            {
                return Err(DeliveryError::Invalid);
            }
            artifact_bytes =
                artifact_bytes.checked_add(record.artifact_bytes).ok_or(DeliveryError::Invalid)?;
            if entries.len() > MAX_DELIVERY_RECORDS || artifact_bytes > MAX_DELIVERY_STORE_BYTES {
                return Err(DeliveryError::Invalid);
            }
        }
        Ok(Self { root, entries, artifact_bytes, _lock: lock })
    }

    pub fn deliver(
        &mut self,
        request_id: &[u8],
        artifact: &[u8],
    ) -> Result<DeliveryReceipt, DeliveryError> {
        validate_request_id(request_id)?;
        if artifact.is_empty() || artifact.len() > MAX_DELIVERY_ARTIFACT_BYTES {
            return Err(DeliveryError::Invalid);
        }
        let reference = artifact_reference(artifact);
        if let Some(existing) = self.entries.get(request_id) {
            return if existing.reference == reference {
                Ok(DeliveryReceipt { reference, duplicate: true })
            } else {
                Err(DeliveryError::Conflict)
            };
        }
        let artifact_bytes = u64::try_from(artifact.len()).map_err(|_| DeliveryError::Invalid)?;
        if self.entries.len() >= MAX_DELIVERY_RECORDS
            || self.artifact_bytes.saturating_add(artifact_bytes) > MAX_DELIVERY_STORE_BYTES
        {
            return Err(DeliveryError::Capacity);
        }
        let path = self.root.join(format!("{}.delivery", digest_hex(request_key(request_id))));
        if fs::symlink_metadata(&path).is_ok() {
            return Err(DeliveryError::Persistence);
        }
        atomic_create(&path, &encode_record(request_id, reference, artifact)?)?;
        self.entries.insert(request_id.to_vec(), DeliveryMetadata { reference, artifact_bytes });
        self.artifact_bytes += artifact_bytes;
        Ok(DeliveryReceipt { reference, duplicate: false })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn validate_request_id(value: &[u8]) -> Result<(), DeliveryError> {
    if value.is_empty()
        || value.len() > MAX_DELIVERY_REQUEST_ID_BYTES
        || value.iter().any(|byte| {
            !matches!(*byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'-')
        })
    {
        return Err(DeliveryError::Invalid);
    }
    Ok(())
}

fn artifact_reference(bytes: &[u8]) -> Digest384 {
    domain_hash(b"ACTUM-WORK-DELIVERY-ARTIFACT-V1", bytes)
}

fn request_key(bytes: &[u8]) -> Digest384 {
    domain_hash(b"ACTUM-WORK-DELIVERY-REQUEST-V1", bytes)
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest384 {
    let mut hash = Sha3_384::new();
    hash.update(domain);
    hash.update(bytes);
    Digest384::new(hash.finalize().into())
}

fn encode_record(
    request_id: &[u8],
    reference: Digest384,
    artifact: &[u8],
) -> Result<Vec<u8>, DeliveryError> {
    validate_request_id(request_id)?;
    if artifact.is_empty() || artifact.len() > MAX_DELIVERY_ARTIFACT_BYTES {
        return Err(DeliveryError::Invalid);
    }
    let mut bytes = Vec::with_capacity(RECORD_FIXED_BYTES + request_id.len() + artifact.len());
    bytes.extend_from_slice(RECORD_MAGIC);
    bytes.extend_from_slice(
        &u16::try_from(request_id.len()).map_err(|_| DeliveryError::Invalid)?.to_le_bytes(),
    );
    bytes.extend_from_slice(request_id);
    bytes.extend_from_slice(reference.as_bytes());
    bytes.extend_from_slice(
        &u32::try_from(artifact.len()).map_err(|_| DeliveryError::Invalid)?.to_le_bytes(),
    );
    bytes.extend_from_slice(artifact);
    let tag = domain_hash(b"ACTUM-WORK-DELIVERY-RECORD-V1", &bytes);
    bytes.extend_from_slice(tag.as_bytes());
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<(Vec<u8>, DeliveryMetadata), DeliveryError> {
    if bytes.len() < RECORD_FIXED_BYTES || bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(DeliveryError::Invalid);
    }
    let (encoded, tag) = bytes.split_at(bytes.len() - 48);
    if tag != domain_hash(b"ACTUM-WORK-DELIVERY-RECORD-V1", encoded).as_bytes()
        || encoded.get(..8) != Some(RECORD_MAGIC)
    {
        return Err(DeliveryError::Invalid);
    }
    let request_length_bytes: [u8; 2] = encoded
        .get(8..10)
        .ok_or(DeliveryError::Invalid)?
        .try_into()
        .map_err(|_| DeliveryError::Invalid)?;
    let request_length = usize::from(u16::from_le_bytes(request_length_bytes));
    let request_end = 10_usize.checked_add(request_length).ok_or(DeliveryError::Invalid)?;
    let request_id = encoded.get(10..request_end).ok_or(DeliveryError::Invalid)?.to_vec();
    validate_request_id(&request_id)?;
    let reference_end = request_end.checked_add(48).ok_or(DeliveryError::Invalid)?;
    let reference_bytes: [u8; 48] = encoded
        .get(request_end..reference_end)
        .ok_or(DeliveryError::Invalid)?
        .try_into()
        .map_err(|_| DeliveryError::Invalid)?;
    let reference = Digest384::new(reference_bytes);
    let length_end = reference_end.checked_add(4).ok_or(DeliveryError::Invalid)?;
    let artifact_length_bytes: [u8; 4] = encoded
        .get(reference_end..length_end)
        .ok_or(DeliveryError::Invalid)?
        .try_into()
        .map_err(|_| DeliveryError::Invalid)?;
    let artifact_length = usize::try_from(u32::from_le_bytes(artifact_length_bytes))
        .map_err(|_| DeliveryError::Invalid)?;
    let artifact = encoded.get(length_end..).ok_or(DeliveryError::Invalid)?;
    if artifact.len() != artifact_length
        || artifact.is_empty()
        || artifact.len() > MAX_DELIVERY_ARTIFACT_BYTES
        || artifact_reference(artifact) != reference
    {
        return Err(DeliveryError::Invalid);
    }
    Ok((request_id, DeliveryMetadata { reference, artifact_bytes: artifact.len() as u64 }))
}

fn ensure_private_directory(path: &Path) -> Result<(), DeliveryError> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|_| DeliveryError::Persistence)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| DeliveryError::Persistence)?;
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| DeliveryError::Persistence)?;
    if !metadata.file_type().is_dir() {
        return Err(DeliveryError::Invalid);
    }
    require_private_mode(&metadata)
}

fn reject_non_file_if_present(path: &Path) -> Result<(), DeliveryError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => require_private_mode(&metadata),
        Ok(_) => Err(DeliveryError::Invalid),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DeliveryError::Persistence),
    }
}

fn require_private_mode(metadata: &fs::Metadata) -> Result<(), DeliveryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(DeliveryError::Invalid);
        }
    }
    Ok(())
}

fn private_file_options(create_new: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn atomic_create(path: &Path, bytes: &[u8]) -> Result<(), DeliveryError> {
    let parent = path.parent().ok_or(DeliveryError::Persistence)?;
    let file_name = path.file_name().ok_or(DeliveryError::Persistence)?.to_string_lossy();
    let mut created = None;
    for attempt in 0..16_u8 {
        let temporary = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), attempt));
        match private_file_options(true).open(&temporary) {
            Ok(file) => {
                created = Some((temporary, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(DeliveryError::Persistence),
        }
    }
    let (temporary, mut file) = created.ok_or(DeliveryError::Persistence)?;
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(DeliveryError::Persistence);
    }
    if fs::rename(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(DeliveryError::Persistence);
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| DeliveryError::Persistence)
}

fn digest_hex(value: Digest384) -> String {
    value.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_is_durable_idempotent_and_conflict_safe() {
        let directory = tempfile::tempdir().unwrap();
        let store_path = directory.path().join("store");
        let reference = {
            let mut store = DurableDeliveryStore::open(&store_path).unwrap();
            let first = store.deliver(b"request-1", b"proof artifact").unwrap();
            assert!(!first.duplicate);
            assert_eq!(store.len(), 1);
            assert_eq!(
                store.deliver(b"request-1", b"different artifact"),
                Err(DeliveryError::Conflict)
            );
            first.reference
        };
        let mut reopened = DurableDeliveryStore::open(&store_path).unwrap();
        assert_eq!(reopened.len(), 1);
        assert_eq!(
            reopened.deliver(b"request-1", b"proof artifact"),
            Ok(DeliveryReceipt { reference, duplicate: true })
        );
    }

    #[test]
    fn malformed_requests_and_corrupt_records_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let store_path = directory.path().join("store");
        let mut store = DurableDeliveryStore::open(&store_path).unwrap();
        assert_eq!(store.deliver(b"../escape", b"proof"), Err(DeliveryError::Invalid));
        assert_eq!(store.deliver(b"request", b""), Err(DeliveryError::Invalid));
        store.deliver(b"request", b"proof").unwrap();
        drop(store);
        let record = fs::read_dir(&store_path)
            .unwrap()
            .map(Result::unwrap)
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("delivery"))
            .unwrap();
        let mut bytes = fs::read(&record).unwrap();
        bytes[20] ^= 1;
        fs::write(record, bytes).unwrap();
        assert!(matches!(DurableDeliveryStore::open(&store_path), Err(DeliveryError::Invalid)));
    }

    #[test]
    fn a_second_service_cannot_open_the_same_store() {
        let directory = tempfile::tempdir().unwrap();
        let store_path = directory.path().join("store");
        let first = DurableDeliveryStore::open(&store_path).unwrap();
        assert!(matches!(DurableDeliveryStore::open(&store_path), Err(DeliveryError::Persistence)));
        drop(first);
        DurableDeliveryStore::open(&store_path).unwrap();
    }
}
