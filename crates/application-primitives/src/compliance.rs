use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_protocol_types::{ComplianceError, ComplianceReplayKey, ComplianceReplaySet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::vec::Vec;

#[derive(Debug)]
pub enum CompliancePersistenceError {
    Persistence,
    Replay,
    Capacity,
}

pub struct DurableComplianceReplayJournal {
    path: PathBuf,
    set: ComplianceReplaySet,
}
impl DurableComplianceReplayJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CompliancePersistenceError> {
        let path = path.as_ref().to_path_buf();
        let set = match std::fs::read(&path) {
            Ok(bytes) => {
                decode_envelope(&bytes).map_err(|_| CompliancePersistenceError::Persistence)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ComplianceReplaySet::new(Vec::new())
                    .map_err(|_| CompliancePersistenceError::Persistence)?
            }
            Err(_) => return Err(CompliancePersistenceError::Persistence),
        };
        Ok(Self { path, set })
    }
    pub fn contains(&self, key: ComplianceReplayKey) -> bool {
        self.set.contains(key)
    }
    pub fn insert(&mut self, key: ComplianceReplayKey) -> Result<(), CompliancePersistenceError> {
        let mut next = self.set.clone();
        next.insert(key).map_err(|e| match e {
            ComplianceError::Replay => CompliancePersistenceError::Replay,
            ComplianceError::TooManyEntries => CompliancePersistenceError::Capacity,
            _ => CompliancePersistenceError::Persistence,
        })?;
        let bytes = encode_envelope(&next).map_err(|_| CompliancePersistenceError::Persistence)?;
        let parent = self.path.parent().ok_or(CompliancePersistenceError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| CompliancePersistenceError::Persistence)?;
        let temporary = self.path.with_extension("tmp");
        let mut file = std::fs::File::create(&temporary)
            .map_err(|_| CompliancePersistenceError::Persistence)?;
        file.write_all(&bytes).map_err(|_| CompliancePersistenceError::Persistence)?;
        file.sync_all().map_err(|_| CompliancePersistenceError::Persistence)?;
        std::fs::rename(&temporary, &self.path)
            .map_err(|_| CompliancePersistenceError::Persistence)?;
        self.set = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{Digest384, PrincipalId, TransactionId};
    fn key(n: u8) -> ComplianceReplayKey {
        ComplianceReplayKey::new(
            Digest384::new([1; 48]),
            PrincipalId::new(Digest384::new([2; 48])),
            TransactionId::new(Digest384::new([3; 48])),
            Digest384::new([n; 48]),
        )
    }
    #[test]
    fn journal_survives_restart_and_rejects_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.bin");
        let mut j = DurableComplianceReplayJournal::open(&path).unwrap();
        j.insert(key(4)).unwrap();
        assert!(matches!(j.insert(key(4)), Err(CompliancePersistenceError::Replay)));
        let j2 = DurableComplianceReplayJournal::open(&path).unwrap();
        assert!(j2.contains(key(4)));
    }
}
