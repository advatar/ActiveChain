use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_types::{
    FungibleAssetPolicyV1, FungibleControllerRotationV1, FungibleControllerStateV1, Height,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerRotationPersistenceError {
    InvalidState,
    InvalidRotation,
    Persistence,
}

/// Exact mutable policy and controller revision persisted as one crash-consistency unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerLedgerSnapshotV1 {
    policy: FungibleAssetPolicyV1,
    controller: FungibleControllerStateV1,
}

impl ControllerLedgerSnapshotV1 {
    pub const TYPE_TAG: u16 = 0x0181;

    pub fn new(
        policy: FungibleAssetPolicyV1,
        controller: FungibleControllerStateV1,
    ) -> Result<Self, ControllerRotationPersistenceError> {
        let expected = FungibleControllerStateV1::from_policy(&policy, controller.revision())
            .map_err(|_| ControllerRotationPersistenceError::InvalidState)?;
        if expected != controller {
            return Err(ControllerRotationPersistenceError::InvalidState);
        }
        Ok(Self { policy, controller })
    }

    pub const fn policy(&self) -> &FungibleAssetPolicyV1 {
        &self.policy
    }

    pub const fn controller(&self) -> &FungibleControllerStateV1 {
        &self.controller
    }
}

impl CanonicalEncode for ControllerLedgerSnapshotV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.policy.encode(encoder)?;
        self.controller.encode(encoder)
    }
}

impl CanonicalDecode for ControllerLedgerSnapshotV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            FungibleAssetPolicyV1::decode(decoder)?,
            FungibleControllerStateV1::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid controller ledger snapshot"))
    }
}

impl CanonicalType for ControllerLedgerSnapshotV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        FungibleAssetPolicyV1::MAX_ENCODED_LEN + FungibleControllerStateV1::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableControllerLedger {
    path: PathBuf,
    snapshot: ControllerLedgerSnapshotV1,
}

impl DurableControllerLedger {
    pub fn create(
        path: impl AsRef<Path>,
        snapshot: ControllerLedgerSnapshotV1,
    ) -> Result<Self, ControllerRotationPersistenceError> {
        let path = path.as_ref().to_path_buf();
        save_atomic(&snapshot, &path)?;
        Ok(Self { path, snapshot })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, ControllerRotationPersistenceError> {
        let path = path.as_ref().to_path_buf();
        let bytes =
            std::fs::read(&path).map_err(|_| ControllerRotationPersistenceError::Persistence)?;
        let snapshot =
            decode_envelope(&bytes).map_err(|_| ControllerRotationPersistenceError::Persistence)?;
        Ok(Self { path, snapshot })
    }

    pub const fn snapshot(&self) -> &ControllerLedgerSnapshotV1 {
        &self.snapshot
    }

    pub fn rotate(
        &mut self,
        rotation: &FungibleControllerRotationV1,
        height: Height,
    ) -> Result<(), ControllerRotationPersistenceError> {
        let (policy, controller) = self
            .snapshot
            .controller
            .apply_rotation(&self.snapshot.policy, rotation, height)
            .map_err(|_| ControllerRotationPersistenceError::InvalidRotation)?;
        let next = ControllerLedgerSnapshotV1::new(policy, controller)?;
        save_atomic(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }
}

fn save_atomic(
    snapshot: &ControllerLedgerSnapshotV1,
    path: &Path,
) -> Result<(), ControllerRotationPersistenceError> {
    let bytes =
        encode_envelope(snapshot).map_err(|_| ControllerRotationPersistenceError::Persistence)?;
    let parent = path.parent().ok_or(ControllerRotationPersistenceError::Persistence)?;
    std::fs::create_dir_all(parent).map_err(|_| ControllerRotationPersistenceError::Persistence)?;
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)
        .map_err(|_| ControllerRotationPersistenceError::Persistence)?;
    file.write_all(&bytes).map_err(|_| ControllerRotationPersistenceError::Persistence)?;
    file.sync_all().map_err(|_| ControllerRotationPersistenceError::Persistence)?;
    std::fs::rename(temporary, path).map_err(|_| ControllerRotationPersistenceError::Persistence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{AssetId, Digest384, FungibleAssetLifecycle, PrincipalId};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn fixture() -> (ControllerLedgerSnapshotV1, FungibleControllerRotationV1) {
        let policy = FungibleAssetPolicyV1::new(
            AssetId::new(digest(1)),
            PrincipalId::new(digest(2)),
            digest(3),
            digest(4),
            digest(5),
            digest(6),
            1_000,
            100,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap();
        let controller = FungibleControllerStateV1::from_policy(&policy, 7).unwrap();
        let rotation = FungibleControllerRotationV1::new(
            policy.asset_id(),
            policy.issuer(),
            controller.commitment().unwrap(),
            policy.authority_set(),
            digest(8),
            digest(9),
            7,
            10,
            20,
        )
        .unwrap();
        (ControllerLedgerSnapshotV1::new(policy, controller).unwrap(), rotation)
    }

    #[test]
    fn accepted_rotation_survives_restart_and_replay_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("controller-ledger.bin");
        let (snapshot, rotation) = fixture();
        let mut durable = DurableControllerLedger::create(&path, snapshot).unwrap();
        durable.rotate(&rotation, 10).unwrap();
        assert_eq!(durable.snapshot().controller().revision(), 8);
        assert_eq!(durable.snapshot().policy().authority_set(), digest(8));
        let restarted = DurableControllerLedger::open(&path).unwrap();
        assert_eq!(restarted.snapshot(), durable.snapshot());
        let before = durable.snapshot().clone();
        assert_eq!(
            durable.rotate(&rotation, 10),
            Err(ControllerRotationPersistenceError::InvalidRotation)
        );
        assert_eq!(durable.snapshot(), &before);
    }

    #[test]
    fn substituted_and_corrupt_state_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("controller-ledger.bin");
        let (snapshot, _) = fixture();
        let substituted_policy = FungibleAssetPolicyV1::new(
            snapshot.policy().asset_id(),
            snapshot.policy().issuer(),
            digest(3),
            digest(4),
            digest(5),
            digest(10),
            1_000,
            100,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap();
        assert_eq!(
            ControllerLedgerSnapshotV1::new(substituted_policy, *snapshot.controller()),
            Err(ControllerRotationPersistenceError::InvalidState)
        );
        std::fs::write(&path, b"not canonical").unwrap();
        assert_eq!(
            DurableControllerLedger::open(&path),
            Err(ControllerRotationPersistenceError::Persistence)
        );
    }

    #[test]
    fn failed_write_does_not_advance_memory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("controller-ledger.bin");
        let (snapshot, rotation) = fixture();
        let mut durable = DurableControllerLedger::create(&path, snapshot).unwrap();
        let before = durable.snapshot().clone();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            durable.rotate(&rotation, 10),
            Err(ControllerRotationPersistenceError::Persistence)
        );
        assert_eq!(durable.snapshot(), &before);
    }
}
