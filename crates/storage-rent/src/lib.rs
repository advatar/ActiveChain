#![forbid(unsafe_code)]

use activechain_archive::{ArchiveCertificate, ArchiveDataClass, Root, content_commitment};
use activechain_storage_profile::{
    ACTIVE_STATE_BUDGET_BYTES, StorageAccountingError, StoragePressure, charged_object_bytes,
    pressure_for_basis_points, utilization_basis_points,
};

pub const MAX_PRINCIPAL_ANCHOR_BYTES: u64 = 4 * 1_024;
pub const MAX_BASE_OWNERSHIP_BYTES: u64 = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRentError {
    Bounds,
    Overflow,
    Underpayment,
    CriticalPressure,
    Early,
    Archive,
    Identity,
    Capacity,
}

impl From<StorageAccountingError> for StorageRentError {
    fn from(error: StorageAccountingError) -> Self {
        match error {
            StorageAccountingError::Overflow => Self::Overflow,
            StorageAccountingError::ZeroDenominator => Self::Bounds,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageClass {
    Ordinary,
    PrincipalAnchor,
    BaseAssetOwnership,
}

impl StorageClass {
    pub fn validate(self, canonical_bytes: u64) -> Result<(), StorageRentError> {
        match self {
            Self::Ordinary => Ok(()),
            Self::PrincipalAnchor if canonical_bytes <= MAX_PRINCIPAL_ANCHOR_BYTES => Ok(()),
            Self::BaseAssetOwnership if canonical_bytes <= MAX_BASE_OWNERSHIP_BYTES => Ok(()),
            Self::PrincipalAnchor | Self::BaseAssetOwnership => Err(StorageRentError::Bounds),
        }
    }

    #[must_use]
    pub const fn is_endowed(self) -> bool {
        !matches!(self, Self::Ordinary)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseQuote {
    pub charged_bytes: u64,
    pub epochs: u64,
    pub unit_price: u128,
    pub pressure_multiplier: u8,
    pub total: u128,
}

pub fn quote_lease(
    canonical_bytes: u64,
    epochs: u64,
    unit_price: u128,
    pressure: StoragePressure,
) -> Result<LeaseQuote, StorageRentError> {
    if canonical_bytes == 0 || epochs == 0 || unit_price == 0 {
        return Err(StorageRentError::Bounds);
    }
    let charged_bytes = charged_object_bytes(canonical_bytes)?;
    let pressure_multiplier = match pressure {
        StoragePressure::Normal => 1,
        StoragePressure::Elevated => 2,
        StoragePressure::High => 4,
        StoragePressure::CapacityFrozen => 8,
        StoragePressure::ExpansionRejected => 16,
    };
    let total = u128::from(charged_bytes)
        .checked_mul(u128::from(epochs))
        .and_then(|value| value.checked_mul(unit_price))
        .and_then(|value| value.checked_mul(u128::from(pressure_multiplier)))
        .ok_or(StorageRentError::Overflow)?;
    Ok(LeaseQuote { charged_bytes, epochs, unit_price, pressure_multiplier, total })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageAdmission {
    used_charged_bytes: u64,
}

impl StorageAdmission {
    pub fn new(used_charged_bytes: u64) -> Result<Self, StorageRentError> {
        if used_charged_bytes > ACTIVE_STATE_BUDGET_BYTES {
            return Err(StorageRentError::Capacity);
        }
        Ok(Self { used_charged_bytes })
    }

    #[must_use]
    pub const fn used_charged_bytes(self) -> u64 {
        self.used_charged_bytes
    }

    pub fn pressure(self) -> Result<StoragePressure, StorageRentError> {
        Ok(pressure_for_basis_points(utilization_basis_points(
            self.used_charged_bytes,
            ACTIVE_STATE_BUDGET_BYTES,
        )?))
    }

    pub fn apply_change(
        &mut self,
        old_charged_bytes: u64,
        new_charged_bytes: u64,
        is_system: bool,
    ) -> Result<StoragePressure, StorageRentError> {
        if old_charged_bytes > self.used_charged_bytes {
            return Err(StorageRentError::Bounds);
        }
        let pressure = self.pressure()?;
        if new_charged_bytes > old_charged_bytes
            && pressure == StoragePressure::ExpansionRejected
            && !is_system
        {
            return Err(StorageRentError::CriticalPressure);
        }
        let next = self
            .used_charged_bytes
            .checked_sub(old_charged_bytes)
            .and_then(|value| value.checked_add(new_charged_bytes))
            .ok_or(StorageRentError::Overflow)?;
        if next > ACTIVE_STATE_BUDGET_BYTES {
            return Err(StorageRentError::Capacity);
        }
        self.used_charged_bytes = next;
        self.pressure()
    }

    pub fn capacity_increase_allowed(self) -> Result<bool, StorageRentError> {
        Ok(!matches!(
            self.pressure()?,
            StoragePressure::CapacityFrozen | StoragePressure::ExpansionRejected
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeasedObject {
    pub object_id: Root,
    pub version: u64,
    pub type_id: Root,
    pub owner_commitment: Root,
    pub policy_root: Root,
    pub value_root: Root,
    pub canonical_value: Vec<u8>,
    pub storage_class: StorageClass,
    pub lease_expiry_epoch: u64,
    pub charged_bytes: u64,
}

impl LeasedObject {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        object_id: Root,
        version: u64,
        type_id: Root,
        owner_commitment: Root,
        policy_root: Root,
        value_root: Root,
        canonical_value: Vec<u8>,
        storage_class: StorageClass,
        lease_expiry_epoch: u64,
    ) -> Result<Self, StorageRentError> {
        if object_id == [0; 48]
            || type_id == [0; 48]
            || owner_commitment == [0; 48]
            || policy_root == [0; 48]
            || value_root == [0; 48]
            || canonical_value.is_empty()
            || lease_expiry_epoch == 0
        {
            return Err(StorageRentError::Bounds);
        }
        storage_class.validate(canonical_value.len() as u64)?;
        let charged_bytes = charged_object_bytes(canonical_value.len() as u64)?;
        Ok(Self {
            object_id,
            version,
            type_id,
            owner_commitment,
            policy_root,
            value_root,
            canonical_value,
            storage_class,
            lease_expiry_epoch,
            charged_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HibernationRecord {
    pub object_id: Root,
    pub version: u64,
    pub type_id: Root,
    pub owner_commitment: Root,
    pub policy_root: Root,
    pub value_root: Root,
    pub archived_value_root: Root,
    pub hibernated_at_epoch: u64,
    pub cold_retention_expiry_epoch: u64,
    pub prior_charged_bytes: u64,
}

pub fn hibernate(
    object: LeasedObject,
    archive: &ArchiveCertificate,
    current_epoch: u64,
) -> Result<HibernationRecord, StorageRentError> {
    if object.storage_class.is_endowed() || current_epoch <= object.lease_expiry_epoch {
        return Err(StorageRentError::Early);
    }
    let manifest = archive.manifest();
    let archived_value_root = content_commitment(&object.canonical_value);
    if manifest.data_class != ArchiveDataClass::HibernatedObject
        || manifest.content_root != archived_value_root
        || manifest.retention_expiry_epoch < current_epoch
    {
        return Err(StorageRentError::Archive);
    }
    Ok(HibernationRecord {
        object_id: object.object_id,
        version: object.version,
        type_id: object.type_id,
        owner_commitment: object.owner_commitment,
        policy_root: object.policy_root,
        value_root: object.value_root,
        archived_value_root,
        hibernated_at_epoch: current_epoch,
        cold_retention_expiry_epoch: manifest.retention_expiry_epoch,
        prior_charged_bytes: object.charged_bytes,
    })
}

pub fn restore(
    record: HibernationRecord,
    canonical_value: Vec<u8>,
    new_lease_expiry_epoch: u64,
    current_epoch: u64,
    unit_price: u128,
    pressure: StoragePressure,
    payment: u128,
) -> Result<LeasedObject, StorageRentError> {
    if current_epoch < record.hibernated_at_epoch || new_lease_expiry_epoch <= current_epoch {
        return Err(StorageRentError::Bounds);
    }
    if content_commitment(&canonical_value) != record.archived_value_root {
        return Err(StorageRentError::Identity);
    }
    let epochs = new_lease_expiry_epoch - current_epoch;
    let quote = quote_lease(canonical_value.len() as u64, epochs, unit_price, pressure)?;
    if payment != quote.total {
        return Err(StorageRentError::Underpayment);
    }
    let object = LeasedObject::new(
        record.object_id,
        record.version,
        record.type_id,
        record.owner_commitment,
        record.policy_root,
        record.value_root,
        canonical_value,
        StorageClass::Ordinary,
        new_lease_expiry_epoch,
    )?;
    if object.charged_bytes != quote.charged_bytes
        || object.charged_bytes != record.prior_charged_bytes
    {
        return Err(StorageRentError::Identity);
    }
    Ok(object)
}

#[must_use]
pub fn render_rent_fixture() -> String {
    let quote =
        quote_lease(1_024, 10, 2, StoragePressure::High).expect("frozen lease quote is valid");
    format!(
        "fixture_version=1\ncanonical_bytes=1024\ncharged_bytes={}\nepochs={}\nunit_price={}\npressure_multiplier={}\ntotal={}\n",
        quote.charged_bytes, quote.epochs, quote.unit_price, quote.pressure_multiplier, quote.total
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_archive::{ArchiveBundle, ArchiveProvider, CustodyReceipt, ReceiptVerifier};

    fn root(value: u8) -> Root {
        [value; 48]
    }

    struct TestVerifier;
    impl ReceiptVerifier for TestVerifier {
        fn verify(&self, provider: Root, statement: Root, signature: &[u8]) -> bool {
            signature == [provider.as_slice(), statement.as_slice()].concat()
        }
    }

    fn object() -> LeasedObject {
        LeasedObject::new(
            root(1),
            7,
            root(2),
            root(3),
            root(4),
            root(5),
            b"archived object value".to_vec(),
            StorageClass::Ordinary,
            10,
        )
        .unwrap()
    }

    fn archive(value: &[u8]) -> ArchiveCertificate {
        let providers = std::array::from_fn(|index| {
            ArchiveProvider::new(root((index + 10) as u8), root((index / 3 + 100) as u8)).unwrap()
        });
        let bundle = ArchiveBundle::encode(
            value,
            root(9),
            ArchiveDataClass::HibernatedObject,
            1,
            1,
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
                receipt.signature =
                    [receipt.provider.as_slice(), receipt.statement().as_slice()].concat();
                receipt
            })
            .collect();
        ArchiveCertificate::new(bundle.manifest, receipts, 20, &TestVerifier).unwrap()
    }

    #[test]
    fn quotes_and_pressure_are_checked_and_exact() {
        let quote = quote_lease(1_024, 10, 2, StoragePressure::High).unwrap();
        assert_eq!(quote.charged_bytes, 3_072);
        assert_eq!(quote.total, 245_760);
        assert_eq!(
            quote_lease(u64::MAX, 1, 1, StoragePressure::Normal),
            Err(StorageRentError::Overflow)
        );

        let critical = (ACTIVE_STATE_BUDGET_BYTES * 9_500).div_ceil(10_000);
        let mut admission = StorageAdmission::new(critical).unwrap();
        assert_eq!(admission.pressure().unwrap(), StoragePressure::ExpansionRejected);
        assert_eq!(admission.apply_change(0, 1, false), Err(StorageRentError::CriticalPressure));
        admission.apply_change(1, 0, false).unwrap();
        let frozen =
            StorageAdmission::new((ACTIVE_STATE_BUDGET_BYTES * 9_000).div_ceil(10_000)).unwrap();
        assert!(!frozen.capacity_increase_allowed().unwrap());
    }

    #[test]
    fn checked_in_rent_fixture_does_not_drift() {
        assert_eq!(render_rent_fixture(), include_str!("../../../testing/storage/rent-v1.txt"));
    }

    #[test]
    fn endowments_are_minimal_and_cannot_hibernate() {
        assert!(StorageClass::PrincipalAnchor.validate(MAX_PRINCIPAL_ANCHOR_BYTES).is_ok());
        assert_eq!(
            StorageClass::PrincipalAnchor.validate(MAX_PRINCIPAL_ANCHOR_BYTES + 1),
            Err(StorageRentError::Bounds)
        );
        let endowed = LeasedObject::new(
            root(1),
            0,
            root(2),
            root(3),
            root(4),
            root(5),
            vec![1; 128],
            StorageClass::BaseAssetOwnership,
            10,
        )
        .unwrap();
        let certificate = archive(&endowed.canonical_value);
        assert_eq!(hibernate(endowed, &certificate, 20), Err(StorageRentError::Early));
    }

    #[test]
    fn hibernation_and_owner_copy_restoration_preserve_identity() {
        let object = object();
        let value = object.canonical_value.clone();
        let certificate = archive(&value);
        assert_eq!(hibernate(object.clone(), &certificate, 10), Err(StorageRentError::Early));
        let record = hibernate(object.clone(), &certificate, 20).unwrap();
        assert_eq!(record.prior_charged_bytes, object.charged_bytes);

        let quote = quote_lease(value.len() as u64, 10, 2, StoragePressure::Normal).unwrap();
        let restored =
            restore(record, value.clone(), 130, 120, 2, StoragePressure::Normal, quote.total)
                .unwrap();
        assert_eq!(restored.object_id, object.object_id);
        assert_eq!(restored.version, object.version);
        assert_eq!(restored.owner_commitment, object.owner_commitment);
        assert_eq!(restored.policy_root, object.policy_root);
        assert_eq!(restored.value_root, object.value_root);

        let mut substituted = value;
        substituted[0] ^= 1;
        assert_eq!(
            restore(record, substituted, 130, 120, 2, StoragePressure::Normal, quote.total,),
            Err(StorageRentError::Identity)
        );
    }
}
