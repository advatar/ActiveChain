#![no_std]
#![forbid(unsafe_code)]

//! Pure P-030 object-version transitions.

use activechain_protocol_types::{
    Object, ObjectFlags, ObjectOwner, ObjectValidationError, ObjectVersionRef,
};

/// Transfers ownership while consuming exactly one object version.
pub fn transfer_object(
    object: &Object,
    input: ObjectVersionRef,
    new_owner: ObjectOwner,
) -> Result<Object, ObjectTransitionError> {
    if input.object_id() != object.object_id() {
        return Err(ObjectTransitionError::ObjectIdMismatch);
    }
    if input.version() != object.object_version() {
        return Err(ObjectTransitionError::StaleObjectVersion {
            expected: input.version(),
            actual: object.object_version(),
        });
    }
    if object.owner() == ObjectOwner::Immutable || new_owner == ObjectOwner::Immutable {
        return Err(ObjectTransitionError::ImmutableObject);
    }
    if !object.flags().contains(ObjectFlags::TRANSFERABLE) {
        return Err(ObjectTransitionError::TransferDisabled);
    }
    if object.owner() == new_owner {
        return Err(ObjectTransitionError::OwnerUnchanged);
    }
    let next_version =
        object.object_version().checked_add(1).ok_or(ObjectTransitionError::VersionExhausted)?;

    let mut fields = object.to_fields();
    fields.object_version = next_version;
    fields.owner = new_owner;
    Object::new(fields).map_err(ObjectTransitionError::InvalidResult)
}

/// Deterministic object-transfer failures in normative validation order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectTransitionError {
    /// The supplied reference names a different object.
    ObjectIdMismatch,
    /// The supplied version does not equal current committed state.
    StaleObjectVersion { expected: u64, actual: u64 },
    /// An immutable source or destination cannot participate in basic transfer.
    ImmutableObject,
    /// The source object does not carry the registered transfer flag.
    TransferDisabled,
    /// The destination owner equals the current owner.
    OwnerUnchanged,
    /// The current version is `u64::MAX` and cannot advance.
    VersionExhausted,
    /// Reconstructing the result violated a canonical object invariant.
    InvalidResult(ObjectValidationError),
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;

    use activechain_protocol_types::{
        Digest384, Object, ObjectFields, ObjectFlags, ObjectId, ObjectOwner, ObjectVersionRef,
        PrincipalId,
    };
    use proptest::prelude::*;

    use super::{ObjectTransitionError, transfer_object};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn object(version: u64, owner_byte: u8, flags: ObjectFlags) -> Object {
        Object::new(ObjectFields {
            object_id: ObjectId::new(digest(0x10)),
            object_version: version,
            type_id: digest(0x20),
            owner: ObjectOwner::Principal(PrincipalId::new(digest(owner_byte))),
            control_policy_hash: digest(0x30),
            use_policy_hash: digest(0x31),
            disclosure_policy_hash: digest(0x32),
            upgrade_policy_hash: digest(0x33),
            package_id: None,
            value_root: digest(0x40),
            public_value: Some(vec![1, 2, 3]),
            lease_expiry_epoch: 100,
            storage_deposit: 500,
            flags,
        })
        .expect("test object is valid")
    }

    #[test]
    fn successful_transfer_changes_only_owner_and_next_version() {
        let before = object(7, 0x50, ObjectFlags::TRANSFERABLE.union(ObjectFlags::LINEAR));
        let new_owner = ObjectOwner::Shielded(digest(0x60));
        let after = transfer_object(
            &before,
            ObjectVersionRef::new(before.object_id(), before.object_version()),
            new_owner,
        )
        .expect("transfer is valid");

        let mut expected = before.to_fields();
        expected.object_version = 8;
        expected.owner = new_owner;
        assert_eq!(after, Object::new(expected).expect("expected object is valid"));
    }

    #[test]
    fn stale_disabled_immutable_and_noop_transfers_are_rejected() {
        let transferable = object(7, 0x50, ObjectFlags::TRANSFERABLE);
        assert!(matches!(
            transfer_object(
                &transferable,
                ObjectVersionRef::new(transferable.object_id(), 6),
                ObjectOwner::Shared,
            ),
            Err(ObjectTransitionError::StaleObjectVersion { .. })
        ));
        assert_eq!(
            transfer_object(
                &object(7, 0x50, ObjectFlags::NONE),
                ObjectVersionRef::new(transferable.object_id(), 7),
                ObjectOwner::Shared,
            ),
            Err(ObjectTransitionError::TransferDisabled)
        );
        assert_eq!(
            transfer_object(
                &transferable,
                ObjectVersionRef::new(transferable.object_id(), 7),
                transferable.owner(),
            ),
            Err(ObjectTransitionError::OwnerUnchanged)
        );
        assert_eq!(
            transfer_object(
                &transferable,
                ObjectVersionRef::new(transferable.object_id(), 7),
                ObjectOwner::Immutable,
            ),
            Err(ObjectTransitionError::ImmutableObject)
        );
    }

    #[test]
    fn maximum_version_cannot_wrap() {
        let value = object(u64::MAX, 0x50, ObjectFlags::TRANSFERABLE);
        assert_eq!(
            transfer_object(
                &value,
                ObjectVersionRef::new(value.object_id(), u64::MAX),
                ObjectOwner::Shared,
            ),
            Err(ObjectTransitionError::VersionExhausted)
        );
    }

    proptest! {
        #[test]
        fn every_non_exhausted_version_advances_exactly_once(version in 0_u64..u64::MAX) {
            let before = object(version, 0x50, ObjectFlags::TRANSFERABLE);
            let after = transfer_object(
                &before,
                ObjectVersionRef::new(before.object_id(), version),
                ObjectOwner::Shared,
            ).expect("non-exhausted transferable object advances");
            prop_assert_eq!(after.object_version(), version + 1);
            prop_assert_eq!(after.object_id(), before.object_id());
        }
    }
}
