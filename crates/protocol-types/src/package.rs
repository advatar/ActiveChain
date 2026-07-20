//! Canonical immutable ObjectVM package manifests (P-051).

extern crate alloc;

use crate::{Digest384, PackageId};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use alloc::vec::Vec;

pub const MAX_PACKAGE_ENTRIES: usize = 64;
pub const MAX_PACKAGE_IMPORTS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UpgradePolicy {
    Immutable = 0,
    Governed = 1,
}

impl CanonicalEncode for UpgradePolicy {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for UpgradePolicy {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Immutable),
            1 => Ok(Self::Governed),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "UpgradePolicy", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageManifest {
    bytecode_commitment: Digest384,
    entry_points: Vec<u16>,
    imports: Vec<PackageId>,
    upgrade_policy: UpgradePolicy,
}

impl PackageManifest {
    pub const TYPE_TAG: u16 = 0x0062;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        48 + 1 + MAX_PACKAGE_ENTRIES * 2 + 1 + MAX_PACKAGE_IMPORTS * 48 + 1;

    pub fn new(
        bytecode_commitment: Digest384,
        entry_points: Vec<u16>,
        imports: Vec<PackageId>,
        upgrade_policy: UpgradePolicy,
    ) -> Result<Self, PackageManifestError> {
        if entry_points.is_empty() || entry_points.len() > MAX_PACKAGE_ENTRIES {
            return Err(PackageManifestError::EntryPointBounds);
        }
        if entry_points.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(PackageManifestError::EntryPointsNotStrictlySorted);
        }
        if imports.len() > MAX_PACKAGE_IMPORTS {
            return Err(PackageManifestError::ImportBounds);
        }
        if imports.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(PackageManifestError::ImportsNotStrictlySorted);
        }
        Ok(Self { bytecode_commitment, entry_points, imports, upgrade_policy })
    }
    pub const fn bytecode_commitment(&self) -> Digest384 {
        self.bytecode_commitment
    }
    pub fn entry_points(&self) -> &[u16] {
        &self.entry_points
    }
    pub fn imports(&self) -> &[PackageId] {
        &self.imports
    }
    pub const fn upgrade_policy(&self) -> UpgradePolicy {
        self.upgrade_policy
    }

    pub fn validate_upgrade_from(&self, replacement: &Self) -> Result<(), PackageUpgradeError> {
        if self.upgrade_policy == UpgradePolicy::Immutable {
            return Err(PackageUpgradeError::ImmutablePackage);
        }
        if replacement.upgrade_policy != self.upgrade_policy {
            return Err(PackageUpgradeError::PolicyChanged);
        }
        if replacement.entry_points != self.entry_points {
            return Err(PackageUpgradeError::EntryPointsChanged);
        }
        if !self.imports.iter().all(|import| replacement.imports.binary_search(import).is_ok()) {
            return Err(PackageUpgradeError::ImportRemoved);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageManifestError {
    EntryPointBounds,
    EntryPointsNotStrictlySorted,
    ImportBounds,
    ImportsNotStrictlySorted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageUpgradeError {
    ImmutablePackage,
    PolicyChanged,
    EntryPointsChanged,
    ImportRemoved,
}

impl CanonicalEncode for PackageManifest {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.bytecode_commitment.encode(e)?;
        e.write_length(self.entry_points.len(), MAX_PACKAGE_ENTRIES)?;
        for entry in &self.entry_points {
            entry.encode(e)?;
        }
        e.write_length(self.imports.len(), MAX_PACKAGE_IMPORTS)?;
        for import in &self.imports {
            import.encode(e)?;
        }
        self.upgrade_policy.encode(e)
    }
}
impl CanonicalDecode for PackageManifest {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            {
                let n = d.read_length(MAX_PACKAGE_ENTRIES)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(u16::decode(d)?);
                }
                v
            },
            {
                let n = d.read_length(MAX_PACKAGE_IMPORTS)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(PackageId::decode(d)?);
                }
                v
            },
            UpgradePolicy::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid P-051 package manifest"))
    }
}
impl CanonicalType for PackageManifest {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::vec;
    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    #[test]
    fn package_manifest_round_trips() {
        let value = PackageManifest::new(
            digest(1),
            vec![0, 4],
            vec![PackageId::new(digest(2))],
            UpgradePolicy::Immutable,
        )
        .unwrap();
        let bytes = encode_envelope(&value).unwrap();
        assert_eq!(decode_envelope::<PackageManifest>(&bytes), Ok(value));
    }
    #[test]
    fn package_manifest_rejects_unsorted_entries() {
        assert_eq!(
            PackageManifest::new(digest(1), vec![2, 1], Vec::new(), UpgradePolicy::Immutable),
            Err(PackageManifestError::EntryPointsNotStrictlySorted)
        );
    }
    #[test]
    fn frozen_package_vector_matches_canonical_bounds() {
        let vector = include_str!("../../../testing/vectors/object/package-v1.txt");
        assert!(vector.contains("entry_points=0,4,9"));
        assert!(vector.contains("upgrade_policy=immutable"));
        let value =
            PackageManifest::new(digest(1), vec![0, 4, 9], Vec::new(), UpgradePolicy::Immutable)
                .unwrap();
        assert_eq!(value.entry_points(), &[0, 4, 9]);
        assert_eq!(
            PackageManifest::new(digest(1), vec![4, 4], Vec::new(), UpgradePolicy::Immutable),
            Err(PackageManifestError::EntryPointsNotStrictlySorted)
        );
    }
    #[test]
    fn package_entry_point_order_property_rejects_all_duplicate_or_descending_pairs() {
        for first in 0_u16..8 {
            for second in 0_u16..8 {
                let result = PackageManifest::new(
                    digest(1),
                    vec![first, second],
                    Vec::new(),
                    UpgradePolicy::Immutable,
                );
                if first < second {
                    assert!(result.is_ok());
                } else {
                    assert_eq!(result, Err(PackageManifestError::EntryPointsNotStrictlySorted));
                }
            }
        }
    }

    #[test]
    fn governed_upgrade_preserves_entry_points_and_dependencies() {
        let current = PackageManifest::new(
            digest(1),
            vec![0, 4],
            vec![PackageId::new(digest(2))],
            UpgradePolicy::Governed,
        )
        .unwrap();
        let replacement = PackageManifest::new(
            digest(3),
            vec![0, 4],
            vec![PackageId::new(digest(2)), PackageId::new(digest(4))],
            UpgradePolicy::Governed,
        )
        .unwrap();
        assert_eq!(current.validate_upgrade_from(&replacement), Ok(()));
    }

    #[test]
    fn immutable_upgrade_and_entry_point_changes_are_rejected() {
        let current =
            PackageManifest::new(digest(1), vec![0, 4], Vec::new(), UpgradePolicy::Immutable)
                .unwrap();
        let replacement =
            PackageManifest::new(digest(3), vec![0, 4], Vec::new(), UpgradePolicy::Immutable)
                .unwrap();
        assert_eq!(
            current.validate_upgrade_from(&replacement),
            Err(PackageUpgradeError::ImmutablePackage)
        );
        let governed =
            PackageManifest::new(digest(1), vec![0, 4], Vec::new(), UpgradePolicy::Governed)
                .unwrap();
        let changed =
            PackageManifest::new(digest(3), vec![0, 5], Vec::new(), UpgradePolicy::Governed)
                .unwrap();
        assert_eq!(
            governed.validate_upgrade_from(&changed),
            Err(PackageUpgradeError::EntryPointsChanged)
        );
    }
}
