#![no_std]
#![forbid(unsafe_code)]

use activechain_canonical_codec::{DecodeError, decode_envelope, inspect_canonical_envelope};
use activechain_policy_kernel::PolicyDecision;
use activechain_protocol_types::{
    CapabilityGrant, Digest384, INITIAL_PROTOCOL_REVISION, Object, ObjectId, Principal,
};
use activechain_state_tree::{
    StateCommitment, StateProof, verify_membership, verify_non_membership,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_ENVELOPE_LENGTH: usize = 256 * 1024;
pub const VERIFIER_ABI_REVISION: u32 = 1;
pub const VERIFIER_SCHEMA_REVISION: u32 = 1;
pub const VERIFIER_PROTOCOL_REVISION: u64 = INITIAL_PROTOCOL_REVISION;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeMetadata {
    pub type_tag: u16,
    pub schema_version: u16,
    pub body_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    TooLarge,
    Decode(DecodeError),
    TypeMismatch,
    VersionMismatch,
    CommitmentMismatch,
    RelationMismatch,
}

impl VerifyError {
    pub const fn code(self) -> u32 {
        match self {
            Self::TooLarge => 1,
            Self::Decode(_) => 2,
            Self::TypeMismatch => 3,
            Self::VersionMismatch => 4,
            Self::CommitmentMismatch => 5,
            Self::RelationMismatch => 7,
        }
    }
}

pub const VERIFY_OK: u32 = 0;

pub fn inspect_envelope_code(bytes: &[u8], expected_type: u16, expected_version: u16) -> u32 {
    inspect_envelope(bytes, expected_type, expected_version)
        .map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_commitment_code(domain: &[u8], body: &[u8], expected: Digest384) -> u32 {
    verify_shake_commitment(domain, body, expected).map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_principal_code(bytes: &[u8]) -> u32 {
    verify_principal(bytes).map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_principal(bytes: &[u8]) -> Result<Principal, VerifyError> {
    inspect_envelope(bytes, Principal::TYPE_TAG, Principal::SCHEMA_VERSION)?;
    decode_envelope::<Principal>(bytes).map_err(VerifyError::Decode)
}

pub fn verify_capability_code(bytes: &[u8]) -> u32 {
    verify_capability(bytes).map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_capability(bytes: &[u8]) -> Result<CapabilityGrant, VerifyError> {
    inspect_envelope(bytes, CapabilityGrant::TYPE_TAG, CapabilityGrant::SCHEMA_VERSION)?;
    decode_envelope::<CapabilityGrant>(bytes).map_err(VerifyError::Decode)
}

pub fn verify_capability_attenuation_code(parent: &[u8], child: &[u8]) -> u32 {
    verify_capability_attenuation(parent, child).map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_capability_attenuation(parent: &[u8], child: &[u8]) -> Result<(), VerifyError> {
    if parent.len().checked_add(child.len()).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return Err(VerifyError::TooLarge);
    }
    let parent = verify_capability(parent)?;
    let child = verify_capability(child)?;
    activechain_capability::verify_attenuation(&parent, &child)
        .map_err(|_| VerifyError::RelationMismatch)
}

pub fn verify_policy_decision_code(bytes: &[u8]) -> u32 {
    verify_policy_decision(bytes).map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_policy_decision(bytes: &[u8]) -> Result<PolicyDecision, VerifyError> {
    inspect_envelope(bytes, PolicyDecision::TYPE_TAG, PolicyDecision::SCHEMA_VERSION)?;
    decode_envelope::<PolicyDecision>(bytes).map_err(VerifyError::Decode)
}

pub fn verify_state_membership_code(commitment: &[u8], object: &[u8], proof: &[u8]) -> u32 {
    verify_state_membership(commitment, object, proof)
        .map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_state_membership(
    commitment: &[u8],
    object: &[u8],
    proof: &[u8],
) -> Result<(), VerifyError> {
    let total = commitment
        .len()
        .checked_add(object.len())
        .and_then(|length| length.checked_add(proof.len()))
        .ok_or(VerifyError::TooLarge)?;
    if total > MAX_ENVELOPE_LENGTH {
        return Err(VerifyError::TooLarge);
    }
    inspect_envelope(commitment, StateCommitment::TYPE_TAG, StateCommitment::SCHEMA_VERSION)?;
    inspect_envelope(object, Object::TYPE_TAG, Object::SCHEMA_VERSION)?;
    inspect_envelope(proof, StateProof::TYPE_TAG, StateProof::SCHEMA_VERSION)?;
    let commitment = decode_envelope::<StateCommitment>(commitment).map_err(VerifyError::Decode)?;
    let object = decode_envelope::<Object>(object).map_err(VerifyError::Decode)?;
    let proof = decode_envelope::<StateProof>(proof).map_err(VerifyError::Decode)?;
    verify_membership(commitment, &object, &proof).map_err(|_| VerifyError::RelationMismatch)
}

pub fn verify_state_non_membership_code(
    commitment: &[u8],
    object_id: ObjectId,
    proof: &[u8],
) -> u32 {
    verify_state_non_membership(commitment, object_id, proof)
        .map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_state_non_membership(
    commitment: &[u8],
    object_id: ObjectId,
    proof: &[u8],
) -> Result<(), VerifyError> {
    if commitment.len().checked_add(proof.len()).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return Err(VerifyError::TooLarge);
    }
    inspect_envelope(commitment, StateCommitment::TYPE_TAG, StateCommitment::SCHEMA_VERSION)?;
    inspect_envelope(proof, StateProof::TYPE_TAG, StateProof::SCHEMA_VERSION)?;
    let commitment = decode_envelope::<StateCommitment>(commitment).map_err(VerifyError::Decode)?;
    let proof = decode_envelope::<StateProof>(proof).map_err(VerifyError::Decode)?;
    verify_non_membership(commitment, object_id, &proof).map_err(|_| VerifyError::RelationMismatch)
}

pub fn verify_shake_commitment(
    domain: &[u8],
    body: &[u8],
    expected: Digest384,
) -> Result<(), VerifyError> {
    if domain.len().checked_add(body.len()).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return Err(VerifyError::TooLarge);
    }
    let mut output = [0_u8; 48];
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(body);
    hasher.finalize_xof().read(&mut output);
    if Digest384::new(output) == expected { Ok(()) } else { Err(VerifyError::CommitmentMismatch) }
}

pub fn inspect_envelope(
    bytes: &[u8],
    expected_type: u16,
    expected_version: u16,
) -> Result<EnvelopeMetadata, VerifyError> {
    if bytes.len() > MAX_ENVELOPE_LENGTH {
        return Err(VerifyError::TooLarge);
    }
    let envelope =
        inspect_canonical_envelope(bytes, expected_type, expected_version, MAX_ENVELOPE_LENGTH)
            .map_err(|error| match error {
                DecodeError::InvalidTypeTag { .. } => VerifyError::TypeMismatch,
                DecodeError::UnsupportedSchemaVersion { .. } => VerifyError::VersionMismatch,
                error => VerifyError::Decode(error),
            })?;
    Ok(EnvelopeMetadata {
        type_tag: envelope.type_tag(),
        schema_version: envelope.schema_version(),
        body_length: envelope.body().len(),
    })
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use activechain_canonical_codec::encode_envelope;
    use activechain_policy_kernel::DecisionResult;
    use activechain_protocol_types::{
        ActionId, BoundedActionSet, CapabilityGrantFields, CapabilityId, CryptoSuiteId,
        DataSelector, FreezeState, HolderBinding, ObjectFields, ObjectFlags, ObjectOwner,
        PrincipalId, PrincipalKind, ProtocolSignature, ResourceSelector,
    };
    use activechain_state_tree::{commit_objects, prove_object};
    use alloc::{vec, vec::Vec};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn principal() -> Principal {
        Principal::new(
            PrincipalId::new(digest(1)),
            PrincipalKind::Human,
            digest(2),
            digest(3),
            digest(4),
            7,
            FreezeState::Active,
            digest(5),
            10,
            11,
            12,
        )
        .unwrap()
    }

    fn capability(
        id: u8,
        issuer: u8,
        holder: u8,
        parent: Option<u8>,
        actions: &[u8],
        delegation_depth_remaining: u8,
        delegation_allowed: bool,
    ) -> CapabilityGrant {
        let permitted_actions =
            actions.iter().map(|byte| ActionId::new(digest(*byte))).collect::<Vec<_>>();
        CapabilityGrant::new(
            CapabilityGrantFields {
                capability_id: CapabilityId::new(digest(id)),
                issuer: PrincipalId::new(digest(issuer)),
                holder_binding: HolderBinding::Principal(PrincipalId::new(digest(holder))),
                parent_capability: parent.map(|byte| CapabilityId::new(digest(byte))),
                permitted_actions: BoundedActionSet::new(permitted_actions).unwrap(),
                resource_scope: ResourceSelector::ANY,
                data_scope: DataSelector::ANY,
                monetary_limit: Some(100),
                compute_limit: Some(100),
                rate_limit: None,
                use_limit: Some(10),
                valid_from: 1,
                valid_until: Some(100),
                delegation_depth_remaining,
                delegation_allowed,
                revocation_registry: None,
                constraint_hash: digest(9),
            },
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![6; 2_420]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn strict_inspection_rejects_wrong_version_and_trailing_bytes() {
        let valid = [0x12, 0x34, 0, 1, 2, 0xaa, 0xbb];
        assert_eq!(inspect_envelope(&valid, 0x1234, 1).unwrap().body_length, 2);
        assert_eq!(inspect_envelope(&valid, 0x1234, 2), Err(VerifyError::VersionMismatch));
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert!(matches!(inspect_envelope(&trailing, 0x1234, 1), Err(VerifyError::Decode(_))));
        let expected = {
            let mut output = [0_u8; 48];
            let mut h = Shake256::default();
            h.update(b"demo");
            h.update(&[0xaa, 0xbb]);
            h.finalize_xof().read(&mut output);
            Digest384::new(output)
        };
        assert_eq!(verify_shake_commitment(b"demo", &[0xaa, 0xbb], expected), Ok(()));
        assert_eq!(
            verify_shake_commitment(b"wrong", &[0xaa, 0xbb], expected),
            Err(VerifyError::CommitmentMismatch)
        );
        assert_eq!(inspect_envelope_code(&valid, 0x1234, 1), VERIFY_OK);
        assert_eq!(inspect_envelope_code(&valid, 0x1234, 2), 4);
        assert_eq!(verify_commitment_code(b"wrong", &[0xaa, 0xbb], expected), 5);
    }

    #[test]
    fn principal_verifier_checks_semantics_and_exact_framing() {
        assert_eq!(VERIFIER_ABI_REVISION, 1);
        assert_eq!(VERIFIER_SCHEMA_REVISION, 1);
        assert_eq!(VERIFIER_PROTOCOL_REVISION, INITIAL_PROTOCOL_REVISION);
        let encoded = encode_envelope(&principal()).unwrap();
        assert_eq!(verify_principal(&encoded), Ok(principal()));
        assert_eq!(verify_principal_code(&encoded), VERIFY_OK);

        let mut wrong_version = encoded.clone();
        wrong_version[3] = 2;
        assert_eq!(verify_principal_code(&wrong_version), VerifyError::VersionMismatch.code());

        let mut invalid_height_order = encoded.clone();
        let body_start = invalid_height_order.len() - Principal::ENCODED_LENGTH;
        invalid_height_order[body_start + Principal::ENCODED_LENGTH - 16..][..8]
            .copy_from_slice(&13_u64.to_be_bytes());
        invalid_height_order[body_start + Principal::ENCODED_LENGTH - 8..]
            .copy_from_slice(&12_u64.to_be_bytes());
        assert_eq!(
            verify_principal_code(&invalid_height_order),
            VerifyError::Decode(DecodeError::InvalidValue("last_updated_at predates created_at"))
                .code()
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            verify_principal_code(&trailing),
            VerifyError::Decode(DecodeError::TrailingData { remaining: 1 }).code()
        );
    }

    #[test]
    fn capability_verifier_checks_shape_and_parent_child_attenuation() {
        let parent = encode_envelope(&capability(10, 2, 3, None, &[1, 2], 1, true)).unwrap();
        let child = encode_envelope(&capability(11, 3, 4, Some(10), &[1], 0, false)).unwrap();
        assert_eq!(verify_capability_code(&parent), VERIFY_OK);
        assert_eq!(verify_capability_attenuation(&parent, &child), Ok(()));
        assert_eq!(verify_capability_attenuation_code(&parent, &child), VERIFY_OK);

        let broadened =
            encode_envelope(&capability(12, 3, 4, Some(10), &[1, 3], 0, false)).unwrap();
        assert_eq!(
            verify_capability_attenuation_code(&parent, &broadened),
            VerifyError::RelationMismatch.code()
        );

        let mut wrong_version = child.clone();
        wrong_version[3] = 2;
        assert_eq!(
            verify_capability_attenuation_code(&parent, &wrong_version),
            VerifyError::VersionMismatch.code()
        );
        let mut truncated = child;
        truncated.pop();
        assert_eq!(
            verify_capability_attenuation_code(&parent, &truncated),
            VerifyError::Decode(DecodeError::UnexpectedEnd { needed: 1, remaining: 0 }).code()
        );
    }

    #[test]
    fn policy_decision_verifier_enforces_default_deny_effect_consistency() {
        let deny =
            encode_envelope(&PolicyDecision::new(DecisionResult::Deny, 0, 0, 0, vec![]).unwrap())
                .unwrap();
        assert_eq!(verify_policy_decision_code(&deny), VERIFY_OK);
        let mut inconsistent = deny;
        let body_start = inconsistent.len() - 6;
        inconsistent[body_start] = DecisionResult::Permit as u8;
        assert_eq!(
            verify_policy_decision_code(&inconsistent),
            VerifyError::Decode(DecodeError::InvalidValue(
                "policy result does not match matched effects"
            ))
            .code()
        );
    }

    #[test]
    fn state_witness_verifier_binds_root_key_object_and_proof_kind() {
        let member = Object::new(ObjectFields {
            object_id: ObjectId::new(digest(21)),
            object_version: 1,
            type_id: digest(22),
            owner: ObjectOwner::Shared,
            control_policy_hash: digest(23),
            use_policy_hash: digest(24),
            disclosure_policy_hash: digest(25),
            upgrade_policy_hash: digest(26),
            package_id: None,
            value_root: digest(27),
            public_value: None,
            lease_expiry_epoch: 10,
            storage_deposit: 5,
            flags: ObjectFlags::TRANSFERABLE,
        })
        .unwrap();
        let objects = vec![member.clone()];
        let commitment = encode_envelope(&commit_objects(&objects).unwrap()).unwrap();
        let member_proof =
            encode_envelope(&prove_object(&objects, member.object_id()).unwrap()).unwrap();
        let member_bytes = encode_envelope(&member).unwrap();
        assert_eq!(
            verify_state_membership_code(&commitment, &member_bytes, &member_proof),
            VERIFY_OK
        );

        let absent_id = ObjectId::new(digest(31));
        let absent_proof = encode_envelope(&prove_object(&objects, absent_id).unwrap()).unwrap();
        assert_eq!(
            verify_state_non_membership_code(&commitment, absent_id, &absent_proof),
            VERIFY_OK
        );
        assert_eq!(
            verify_state_non_membership_code(&commitment, ObjectId::new(digest(32)), &absent_proof),
            VerifyError::RelationMismatch.code()
        );
        let mut substituted_commitment = commitment;
        let last = substituted_commitment.len() - 1;
        substituted_commitment[last] ^= 1;
        assert_eq!(
            verify_state_membership_code(&substituted_commitment, &member_bytes, &member_proof),
            VerifyError::RelationMismatch.code()
        );
    }
}
