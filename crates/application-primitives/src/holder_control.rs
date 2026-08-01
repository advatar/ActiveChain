use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_types::{
    FungibleAssetDefinition, FungibleExceptionalControlActionV1, FungibleExceptionalControlKind,
    FungibleExceptionalControlPolicyV1, FungibleHolderControlStateV1,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    vec::Vec,
};

const MAX_HOLDER_CONTROL_STATES: usize = 65_535;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HolderControlPersistenceError {
    InvalidAction,
    Capacity,
    Persistence,
}

/// Canonically sorted revision state for declared holder freeze controls.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HolderControlRegistryV1 {
    states: Vec<FungibleHolderControlStateV1>,
}

impl HolderControlRegistryV1 {
    pub const TYPE_TAG: u16 = 0x017b;

    pub fn states(&self) -> &[FungibleHolderControlStateV1] {
        &self.states
    }

    fn apply(
        &mut self,
        definition: &FungibleAssetDefinition,
        policy: &FungibleExceptionalControlPolicyV1,
        action: &FungibleExceptionalControlActionV1,
        height: u64,
    ) -> Result<FungibleHolderControlStateV1, HolderControlPersistenceError> {
        if action.kind() == FungibleExceptionalControlKind::Clawback {
            return Err(HolderControlPersistenceError::InvalidAction);
        }
        let key = (action.asset_id(), action.holder());
        match self.states.binary_search_by_key(&key, |state| (state.asset_id(), state.holder())) {
            Ok(index) => {
                let next = self.states[index]
                    .apply(definition, policy, action, height)
                    .map_err(|_| HolderControlPersistenceError::InvalidAction)?;
                self.states[index] = next;
                Ok(next)
            }
            Err(index) => {
                if self.states.len() == MAX_HOLDER_CONTROL_STATES {
                    return Err(HolderControlPersistenceError::Capacity);
                }
                let next = FungibleHolderControlStateV1::new(action.asset_id(), action.holder())
                    .and_then(|state| state.apply(definition, policy, action, height))
                    .map_err(|_| HolderControlPersistenceError::InvalidAction)?;
                self.states.insert(index, next);
                Ok(next)
            }
        }
    }
}

impl CanonicalEncode for HolderControlRegistryV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.states.len(), MAX_HOLDER_CONTROL_STATES)?;
        for state in &self.states {
            state.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for HolderControlRegistryV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_HOLDER_CONTROL_STATES)?;
        let mut states = Vec::with_capacity(count);
        for _ in 0..count {
            let state = FungibleHolderControlStateV1::decode(decoder)?;
            let key = (state.asset_id(), state.holder());
            if states.last().is_some_and(|previous: &FungibleHolderControlStateV1| {
                (previous.asset_id(), previous.holder()) >= key
            }) {
                return Err(DecodeError::InvalidValue(
                    "holder control states are not canonically ordered",
                ));
            }
            states.push(state);
        }
        Ok(Self { states })
    }
}

impl CanonicalType for HolderControlRegistryV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        3 + MAX_HOLDER_CONTROL_STATES * FungibleHolderControlStateV1::MAX_ENCODED_LEN;
}

/// Write-before-acknowledgement freeze/unfreeze registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableHolderControlRegistry {
    path: PathBuf,
    registry: HolderControlRegistryV1,
}

impl DurableHolderControlRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, HolderControlPersistenceError> {
        let path = path.as_ref().to_path_buf();
        let registry = match std::fs::read(&path) {
            Ok(bytes) => {
                decode_envelope(&bytes).map_err(|_| HolderControlPersistenceError::Persistence)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                HolderControlRegistryV1::default()
            }
            Err(_) => return Err(HolderControlPersistenceError::Persistence),
        };
        Ok(Self { path, registry })
    }

    pub const fn registry(&self) -> &HolderControlRegistryV1 {
        &self.registry
    }

    pub fn apply(
        &mut self,
        definition: &FungibleAssetDefinition,
        policy: &FungibleExceptionalControlPolicyV1,
        action: &FungibleExceptionalControlActionV1,
        height: u64,
    ) -> Result<FungibleHolderControlStateV1, HolderControlPersistenceError> {
        let mut next = self.registry.clone();
        let state = next.apply(definition, policy, action, height)?;
        save_atomic(&next, &self.path)?;
        self.registry = next;
        Ok(state)
    }
}

fn save_atomic(
    registry: &HolderControlRegistryV1,
    path: &Path,
) -> Result<(), HolderControlPersistenceError> {
    let bytes =
        encode_envelope(registry).map_err(|_| HolderControlPersistenceError::Persistence)?;
    let parent = path.parent().ok_or(HolderControlPersistenceError::Persistence)?;
    std::fs::create_dir_all(parent).map_err(|_| HolderControlPersistenceError::Persistence)?;
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)
        .map_err(|_| HolderControlPersistenceError::Persistence)?;
    file.write_all(&bytes).map_err(|_| HolderControlPersistenceError::Persistence)?;
    file.sync_all().map_err(|_| HolderControlPersistenceError::Persistence)?;
    std::fs::rename(temporary, path).map_err(|_| HolderControlPersistenceError::Persistence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{AssetId, Digest384, PrincipalId};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn fixture(
        holder_byte: u8,
        kind: FungibleExceptionalControlKind,
        revision: u64,
    ) -> (
        FungibleAssetDefinition,
        FungibleExceptionalControlPolicyV1,
        FungibleExceptionalControlActionV1,
    ) {
        let asset = AssetId::new(digest(1));
        let issuer = PrincipalId::new(digest(2));
        let authority = digest(3);
        let policy =
            FungibleExceptionalControlPolicyV1::new(asset, issuer, authority, true, true).unwrap();
        let definition = FungibleAssetDefinition::new(
            asset,
            issuer,
            b"TEST".to_vec(),
            2,
            1_000,
            policy.commitment().unwrap(),
        )
        .unwrap();
        let holder = PrincipalId::new(digest(holder_byte));
        let (recipient, amount) = if kind == FungibleExceptionalControlKind::Clawback {
            (PrincipalId::new(digest(8)), 10)
        } else {
            (holder, 0)
        };
        let action = FungibleExceptionalControlActionV1::new(
            asset,
            holder,
            recipient,
            policy.commitment().unwrap(),
            authority,
            digest(5),
            digest(6),
            kind,
            amount,
            revision,
            10,
            20,
        )
        .unwrap();
        (definition, policy, action)
    }

    #[test]
    fn freeze_survives_restart_and_replay_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("holder-controls.bin");
        let (definition, policy, freeze) = fixture(4, FungibleExceptionalControlKind::Freeze, 0);
        let mut durable = DurableHolderControlRegistry::open(&path).unwrap();
        let state = durable.apply(&definition, &policy, &freeze, 10).unwrap();
        assert!(state.frozen());
        assert_eq!(state.revision(), 1);
        let mut restarted = DurableHolderControlRegistry::open(&path).unwrap();
        assert_eq!(restarted.registry(), durable.registry());
        assert_eq!(
            restarted.apply(&definition, &policy, &freeze, 10),
            Err(HolderControlPersistenceError::InvalidAction)
        );
        assert_eq!(restarted.registry(), durable.registry());
    }

    #[test]
    fn registry_orders_holders_and_rejects_state_only_clawback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("holder-controls.bin");
        let mut durable = DurableHolderControlRegistry::open(&path).unwrap();
        for holder in [9, 4] {
            let (definition, policy, freeze) =
                fixture(holder, FungibleExceptionalControlKind::Freeze, 0);
            durable.apply(&definition, &policy, &freeze, 10).unwrap();
        }
        assert!(durable.registry().states()[0].holder() < durable.registry().states()[1].holder());
        let (definition, policy, clawback) =
            fixture(7, FungibleExceptionalControlKind::Clawback, 0);
        assert_eq!(
            durable.apply(&definition, &policy, &clawback, 10),
            Err(HolderControlPersistenceError::InvalidAction)
        );
        assert_eq!(durable.registry().states().len(), 2);
    }

    #[test]
    fn corruption_and_failed_persistence_do_not_advance_memory() {
        let directory = tempfile::tempdir().unwrap();
        let corrupt = directory.path().join("corrupt.bin");
        std::fs::write(&corrupt, b"not canonical").unwrap();
        assert_eq!(
            DurableHolderControlRegistry::open(&corrupt),
            Err(HolderControlPersistenceError::Persistence)
        );
        let path = directory.path().join("holder-controls.bin");
        let mut durable = DurableHolderControlRegistry::open(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let (definition, policy, freeze) = fixture(4, FungibleExceptionalControlKind::Freeze, 0);
        assert_eq!(
            durable.apply(&definition, &policy, &freeze, 10),
            Err(HolderControlPersistenceError::Persistence)
        );
        assert!(durable.registry().states().is_empty());
    }
}
