#![forbid(unsafe_code)]

use activechain_archive::{ArchiveCertificate, ArchiveDataClass, Root, content_commitment};
use activechain_canonical_codec::encode_envelope;
use activechain_protocol_types::{Object, ObjectFlags};
use activechain_state_tree::{
    StateCommitment, StateProof, StateProofUpdateError, apply_single_key_update,
};
use activechain_storage_profile::charged_object_bytes;
use activechain_storage_rent::{LeaseQuote, StorageAdmission, StorageRentError, quote_lease};

const HIBERNATION_MAGIC: &[u8; 8] = b"ACHIBR01";
pub const HIBERNATION_MARKER_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageTransitionError {
    Bounds,
    Identity,
    Lease,
    Payment,
    Archive,
    StateProof,
    Capacity,
    Encoding,
    Overflow,
}

impl From<StorageRentError> for StorageTransitionError {
    fn from(error: StorageRentError) -> Self {
        match error {
            StorageRentError::Underpayment => Self::Payment,
            StorageRentError::Archive => Self::Archive,
            StorageRentError::Identity => Self::Identity,
            StorageRentError::Overflow => Self::Overflow,
            StorageRentError::CriticalPressure | StorageRentError::Capacity => Self::Capacity,
            StorageRentError::Bounds | StorageRentError::Early => Self::Bounds,
        }
    }
}

impl From<StateProofUpdateError> for StorageTransitionError {
    fn from(_: StateProofUpdateError) -> Self {
        Self::StateProof
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HibernationMarker {
    pub archived_value_root: Root,
    pub cold_retention_expiry_epoch: u64,
}

impl HibernationMarker {
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HIBERNATION_MARKER_BYTES);
        bytes.extend_from_slice(HIBERNATION_MAGIC);
        bytes.extend_from_slice(&self.archived_value_root);
        bytes.extend_from_slice(&self.cold_retention_expiry_epoch.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StorageTransitionError> {
        if bytes.len() != HIBERNATION_MARKER_BYTES || &bytes[..8] != HIBERNATION_MAGIC {
            return Err(StorageTransitionError::Identity);
        }
        let archived_value_root =
            bytes[8..56].try_into().map_err(|_| StorageTransitionError::Identity)?;
        let cold_retention_expiry_epoch = u64::from_be_bytes(
            bytes[56..64].try_into().map_err(|_| StorageTransitionError::Identity)?,
        );
        if archived_value_root == [0; 48] || cold_retention_expiry_epoch == 0 {
            return Err(StorageTransitionError::Identity);
        }
        Ok(Self { archived_value_root, cold_retention_expiry_epoch })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageTransitionOutput {
    pub object: Object,
    pub state: StateCommitment,
    pub admission: StorageAdmission,
    pub old_charged_bytes: u64,
    pub new_charged_bytes: u64,
    pub lease_quote: Option<LeaseQuote>,
}

#[allow(clippy::too_many_arguments)]
pub fn renew(
    state: StateCommitment,
    admission: StorageAdmission,
    proof: &StateProof,
    object: &Object,
    current_epoch: u64,
    new_lease_expiry_epoch: u64,
    unit_price: u128,
    payment: u128,
) -> Result<StorageTransitionOutput, StorageTransitionError> {
    if current_epoch == 0
        || current_epoch > object.lease_expiry_epoch()
        || new_lease_expiry_epoch <= object.lease_expiry_epoch()
    {
        return Err(StorageTransitionError::Lease);
    }
    let old_charged_bytes = object_charge(object)?;
    let epochs = new_lease_expiry_epoch - current_epoch;
    let pressure = admission.pressure()?;
    let quote = quote_lease(canonical_len(object)?, epochs, unit_price, pressure)?;
    if quote.total != payment {
        return Err(StorageTransitionError::Payment);
    }
    let mut fields = object.to_fields();
    fields.object_version =
        fields.object_version.checked_add(1).ok_or(StorageTransitionError::Overflow)?;
    fields.lease_expiry_epoch = new_lease_expiry_epoch;
    fields.storage_deposit = payment;
    let after = Object::new(fields).map_err(|_| StorageTransitionError::Bounds)?;
    transition(state, admission, proof, object, after, old_charged_bytes, Some(quote))
}

pub fn hibernate(
    state: StateCommitment,
    admission: StorageAdmission,
    proof: &StateProof,
    object: &Object,
    certificate: &ArchiveCertificate,
    current_epoch: u64,
) -> Result<StorageTransitionOutput, StorageTransitionError> {
    if current_epoch == 0
        || current_epoch <= object.lease_expiry_epoch()
        || object.flags().contains(ObjectFlags::SYSTEM)
    {
        return Err(StorageTransitionError::Lease);
    }
    let value = object.public_value().ok_or(StorageTransitionError::Bounds)?;
    let manifest = certificate.manifest();
    let archived_value_root = content_commitment(value);
    if manifest.data_class != ArchiveDataClass::HibernatedObject
        || manifest.content_root != archived_value_root
        || manifest.retention_expiry_epoch < current_epoch
    {
        return Err(StorageTransitionError::Archive);
    }
    let marker = HibernationMarker {
        archived_value_root,
        cold_retention_expiry_epoch: manifest.retention_expiry_epoch,
    };
    let old_charged_bytes = object_charge(object)?;
    let mut fields = object.to_fields();
    fields.object_version =
        fields.object_version.checked_add(1).ok_or(StorageTransitionError::Overflow)?;
    fields.public_value = Some(marker.encode());
    fields.lease_expiry_epoch = current_epoch;
    fields.storage_deposit = 0;
    let after = Object::new(fields).map_err(|_| StorageTransitionError::Bounds)?;
    if object_charge(&after)? >= old_charged_bytes {
        return Err(StorageTransitionError::Bounds);
    }
    transition(state, admission, proof, object, after, old_charged_bytes, None)
}

#[allow(clippy::too_many_arguments)]
pub fn restore(
    state: StateCommitment,
    admission: StorageAdmission,
    proof: &StateProof,
    hibernated: &Object,
    canonical_value: Vec<u8>,
    current_epoch: u64,
    new_lease_expiry_epoch: u64,
    unit_price: u128,
    payment: u128,
) -> Result<StorageTransitionOutput, StorageTransitionError> {
    if current_epoch == 0 || new_lease_expiry_epoch <= current_epoch || canonical_value.is_empty() {
        return Err(StorageTransitionError::Lease);
    }
    let marker = HibernationMarker::decode(
        hibernated.public_value().ok_or(StorageTransitionError::Identity)?,
    )?;
    if content_commitment(&canonical_value) != marker.archived_value_root {
        return Err(StorageTransitionError::Identity);
    }
    let old_charged_bytes = object_charge(hibernated)?;
    let pressure = admission.pressure()?;
    let mut fields = hibernated.to_fields();
    fields.object_version =
        fields.object_version.checked_add(1).ok_or(StorageTransitionError::Overflow)?;
    fields.public_value = Some(canonical_value);
    fields.lease_expiry_epoch = new_lease_expiry_epoch;
    let candidate = Object::new(fields.clone()).map_err(|_| StorageTransitionError::Bounds)?;
    let epochs = new_lease_expiry_epoch - current_epoch;
    let quote = quote_lease(canonical_len(&candidate)?, epochs, unit_price, pressure)?;
    if quote.total != payment {
        return Err(StorageTransitionError::Payment);
    }
    fields.storage_deposit = payment;
    let after = Object::new(fields).map_err(|_| StorageTransitionError::Bounds)?;
    transition(state, admission, proof, hibernated, after, old_charged_bytes, Some(quote))
}

fn transition(
    state: StateCommitment,
    mut admission: StorageAdmission,
    proof: &StateProof,
    before: &Object,
    after: Object,
    old_charged_bytes: u64,
    lease_quote: Option<LeaseQuote>,
) -> Result<StorageTransitionOutput, StorageTransitionError> {
    if after.object_id() != before.object_id()
        || after.object_version()
            != before.object_version().checked_add(1).ok_or(StorageTransitionError::Overflow)?
        || after.type_id() != before.type_id()
        || after.owner() != before.owner()
        || after.control_policy_hash() != before.control_policy_hash()
        || after.use_policy_hash() != before.use_policy_hash()
        || after.disclosure_policy_hash() != before.disclosure_policy_hash()
        || after.upgrade_policy_hash() != before.upgrade_policy_hash()
        || after.package_id() != before.package_id()
        || after.value_root() != before.value_root()
        || after.flags() != before.flags()
    {
        return Err(StorageTransitionError::Identity);
    }
    let new_charged_bytes = object_charge(&after)?;
    admission.apply_change(
        old_charged_bytes,
        new_charged_bytes,
        before.flags().contains(ObjectFlags::SYSTEM),
    )?;
    let next_state = apply_single_key_update(state, proof, Some(before), Some(&after))?;
    Ok(StorageTransitionOutput {
        object: after,
        state: next_state,
        admission,
        old_charged_bytes,
        new_charged_bytes,
        lease_quote,
    })
}

fn canonical_len(object: &Object) -> Result<u64, StorageTransitionError> {
    let bytes = encode_envelope(object).map_err(|_| StorageTransitionError::Encoding)?;
    u64::try_from(bytes.len()).map_err(|_| StorageTransitionError::Overflow)
}

fn object_charge(object: &Object) -> Result<u64, StorageTransitionError> {
    charged_object_bytes(canonical_len(object)?).map_err(|_| StorageTransitionError::Overflow)
}

#[must_use]
pub fn render_hibernation_fixture() -> String {
    let marker =
        HibernationMarker { archived_value_root: [7; 48], cold_retention_expiry_epoch: 99 };
    format!("fixture_version=1\nmarker={}\n", hex(&marker.encode()))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_archive::{ArchiveBundle, ArchiveProvider, CustodyReceipt, ReceiptVerifier};
    use activechain_protocol_types::{Digest384, ObjectFields, ObjectId, ObjectOwner, PrincipalId};
    use activechain_state_tree::{commit_objects, prove_object};
    use activechain_storage_profile::StoragePressure;

    struct TestVerifier;
    impl ReceiptVerifier for TestVerifier {
        fn verify(&self, provider: Root, statement: Root, signature: &[u8]) -> bool {
            signature == [provider.as_slice(), statement.as_slice()].concat()
        }
    }

    fn digest(value: u8) -> Digest384 {
        Digest384::new([value; 48])
    }

    fn object() -> Object {
        Object::new(ObjectFields {
            object_id: ObjectId::new(digest(1)),
            object_version: 7,
            type_id: digest(2),
            owner: ObjectOwner::Principal(PrincipalId::new(digest(3))),
            control_policy_hash: digest(4),
            use_policy_hash: digest(5),
            disclosure_policy_hash: digest(6),
            upgrade_policy_hash: digest(7),
            package_id: None,
            value_root: digest(8),
            public_value: Some(vec![42; 1_024]),
            lease_expiry_epoch: 10,
            storage_deposit: 100,
            flags: ObjectFlags::TRANSFERABLE,
        })
        .unwrap()
    }

    fn archive(value: &[u8]) -> ArchiveCertificate {
        let providers = std::array::from_fn(|index| {
            ArchiveProvider::new([(index + 10) as u8; 48], [(index / 3 + 100) as u8; 48]).unwrap()
        });
        let bundle = ArchiveBundle::encode(
            value,
            [9; 48],
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
    fn renew_hibernate_restore_each_advance_exact_authenticated_root() {
        let original = object();
        let state = commit_objects(std::slice::from_ref(&original)).unwrap();
        let admission = StorageAdmission::new(object_charge(&original).unwrap()).unwrap();
        let proof = prove_object(std::slice::from_ref(&original), original.object_id()).unwrap();
        let pressure = admission.pressure().unwrap();
        assert_eq!(pressure, StoragePressure::Normal);
        let quote = quote_lease(canonical_len(&original).unwrap(), 15, 2, pressure).unwrap();
        let renewed = renew(state, admission, &proof, &original, 5, 20, 2, quote.total).unwrap();
        assert_eq!(renewed.object.object_version(), 8);
        assert_eq!(renewed.object.lease_expiry_epoch(), 20);
        assert_eq!(renewed.state, commit_objects(std::slice::from_ref(&renewed.object)).unwrap());

        let renewed_proof =
            prove_object(std::slice::from_ref(&renewed.object), renewed.object.object_id())
                .unwrap();
        let certificate = archive(renewed.object.public_value().unwrap());
        let hibernated = hibernate(
            renewed.state,
            renewed.admission,
            &renewed_proof,
            &renewed.object,
            &certificate,
            21,
        )
        .unwrap();
        assert_eq!(hibernated.object.object_version(), 9);
        assert!(hibernated.new_charged_bytes < hibernated.old_charged_bytes);
        assert_eq!(
            hibernated.state,
            commit_objects(std::slice::from_ref(&hibernated.object)).unwrap()
        );

        let restore_proof =
            prove_object(std::slice::from_ref(&hibernated.object), hibernated.object.object_id())
                .unwrap();
        let value = original.public_value().unwrap().to_vec();
        let mut candidate_fields = hibernated.object.to_fields();
        candidate_fields.object_version += 1;
        candidate_fields.public_value = Some(value.clone());
        candidate_fields.lease_expiry_epoch = 40;
        let candidate = Object::new(candidate_fields).unwrap();
        let restore_quote = quote_lease(
            canonical_len(&candidate).unwrap(),
            19,
            2,
            hibernated.admission.pressure().unwrap(),
        )
        .unwrap();
        let restored = restore(
            hibernated.state,
            hibernated.admission,
            &restore_proof,
            &hibernated.object,
            value,
            21,
            40,
            2,
            restore_quote.total,
        )
        .unwrap();
        assert_eq!(restored.object.object_version(), 10);
        assert_eq!(restored.object.value_root(), original.value_root());
        assert_eq!(restored.object.owner(), original.owner());
        assert_eq!(restored.state, commit_objects(std::slice::from_ref(&restored.object)).unwrap());
    }

    #[test]
    fn rejected_payment_archive_value_and_stale_proof_leave_inputs_unchanged() {
        let original = object();
        let state = commit_objects(std::slice::from_ref(&original)).unwrap();
        let admission = StorageAdmission::new(object_charge(&original).unwrap()).unwrap();
        let proof = prove_object(std::slice::from_ref(&original), original.object_id()).unwrap();
        assert_eq!(
            renew(state, admission, &proof, &original, 5, 20, 2, 1),
            Err(StorageTransitionError::Payment)
        );
        let wrong_archive = archive(b"other value");
        assert_eq!(
            hibernate(state, admission, &proof, &original, &wrong_archive, 11),
            Err(StorageTransitionError::Archive)
        );
        let quote =
            quote_lease(canonical_len(&original).unwrap(), 15, 2, admission.pressure().unwrap())
                .unwrap();
        let renewed = renew(state, admission, &proof, &original, 5, 20, 2, quote.total).unwrap();
        let replay_quote = quote_lease(
            canonical_len(&original).unwrap(),
            24,
            2,
            renewed.admission.pressure().unwrap(),
        )
        .unwrap();
        assert_eq!(
            renew(
                renewed.state,
                renewed.admission,
                &proof,
                &original,
                6,
                30,
                2,
                replay_quote.total,
            ),
            Err(StorageTransitionError::StateProof)
        );
    }

    #[test]
    fn checked_in_hibernation_marker_does_not_drift() {
        assert_eq!(
            render_hibernation_fixture(),
            include_str!("../../../testing/storage/hibernation-marker-v1.txt")
        );
    }
}
