use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_protocol_types::{
    Digest384, FungibleAssetPolicyV1, FungibleCorporateActionRegistryV1, FungibleCorporateActionV1,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorporateActionPersistenceError {
    InvalidAction,
    Replay,
    Persistence,
}

/// Write-before-acknowledgement corporate-action replay state for application execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableCorporateActionRegistry {
    path: PathBuf,
    registry: FungibleCorporateActionRegistryV1,
}

impl DurableCorporateActionRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CorporateActionPersistenceError> {
        let path = path.as_ref().to_path_buf();
        let registry = match std::fs::read(&path) {
            Ok(bytes) => {
                decode_envelope(&bytes).map_err(|_| CorporateActionPersistenceError::Persistence)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                FungibleCorporateActionRegistryV1::default()
            }
            Err(_) => return Err(CorporateActionPersistenceError::Persistence),
        };
        Ok(Self { path, registry })
    }

    pub const fn registry(&self) -> &FungibleCorporateActionRegistryV1 {
        &self.registry
    }

    pub fn admit(
        &mut self,
        policy: &FungibleAssetPolicyV1,
        action: &FungibleCorporateActionV1,
        finalized_height: u64,
    ) -> Result<Digest384, CorporateActionPersistenceError> {
        let action_id =
            action.action_id().map_err(|_| CorporateActionPersistenceError::InvalidAction)?;
        if self.registry.action_ids().binary_search(&action_id).is_ok() {
            return Err(CorporateActionPersistenceError::Replay);
        }
        let mut next = self.registry.clone();
        next.admit(
            action,
            policy.asset_id(),
            policy.commitment().map_err(|_| CorporateActionPersistenceError::InvalidAction)?,
            policy.authority_set(),
            finalized_height,
        )
        .map_err(|_| CorporateActionPersistenceError::InvalidAction)?;
        save_atomic(&next, &self.path)?;
        self.registry = next;
        Ok(action_id)
    }
}

fn save_atomic(
    registry: &FungibleCorporateActionRegistryV1,
    path: &Path,
) -> Result<(), CorporateActionPersistenceError> {
    let bytes =
        encode_envelope(registry).map_err(|_| CorporateActionPersistenceError::Persistence)?;
    let parent = path.parent().ok_or(CorporateActionPersistenceError::Persistence)?;
    std::fs::create_dir_all(parent).map_err(|_| CorporateActionPersistenceError::Persistence)?;
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)
        .map_err(|_| CorporateActionPersistenceError::Persistence)?;
    file.write_all(&bytes).map_err(|_| CorporateActionPersistenceError::Persistence)?;
    file.sync_all().map_err(|_| CorporateActionPersistenceError::Persistence)?;
    std::fs::rename(&temporary, path).map_err(|_| CorporateActionPersistenceError::Persistence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{
        AssetId, FungibleAssetLifecycle, FungibleCorporateActionKind, PrincipalId,
    };

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn policy() -> FungibleAssetPolicyV1 {
        FungibleAssetPolicyV1::new(
            AssetId::new(digest(1)),
            PrincipalId::new(digest(2)),
            Digest384::ZERO,
            Digest384::ZERO,
            Digest384::ZERO,
            digest(3),
            1_000,
            100,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap()
    }

    fn action(policy: &FungibleAssetPolicyV1) -> FungibleCorporateActionV1 {
        FungibleCorporateActionV1::new(
            policy.asset_id(),
            policy.issuer(),
            policy.commitment().unwrap(),
            policy.authority_set(),
            digest(4),
            digest(5),
            FungibleCorporateActionKind::Distribution,
            10,
            20,
            30,
            5,
            1,
            1,
        )
        .unwrap()
    }

    #[test]
    fn accepted_action_survives_restart_and_replay_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corporate-actions.bin");
        let policy = policy();
        let action = action(&policy);
        let mut durable = DurableCorporateActionRegistry::open(&path).unwrap();
        let action_id = durable.admit(&policy, &action, 20).unwrap();
        assert_eq!(durable.registry().action_ids(), &[action_id]);

        let mut restarted = DurableCorporateActionRegistry::open(&path).unwrap();
        assert_eq!(restarted.registry(), durable.registry());
        assert_eq!(
            restarted.admit(&policy, &action, 20),
            Err(CorporateActionPersistenceError::Replay)
        );
    }

    #[test]
    fn stale_substituted_and_corrupt_state_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corporate-actions.bin");
        let policy = policy();
        let action = action(&policy);
        let mut durable = DurableCorporateActionRegistry::open(&path).unwrap();
        assert_eq!(
            durable.admit(&policy, &action, 30),
            Err(CorporateActionPersistenceError::InvalidAction)
        );
        assert!(durable.registry().action_ids().is_empty());
        std::fs::write(&path, b"not canonical").unwrap();
        assert_eq!(
            DurableCorporateActionRegistry::open(&path),
            Err(CorporateActionPersistenceError::Persistence)
        );
    }

    #[test]
    fn persistence_failure_does_not_advance_memory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corporate-actions.bin");
        let mut durable = DurableCorporateActionRegistry::open(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let policy = policy();
        assert_eq!(
            durable.admit(&policy, &action(&policy), 20),
            Err(CorporateActionPersistenceError::Persistence)
        );
        assert!(durable.registry().action_ids().is_empty());
    }
}
