#![allow(unsafe_code)]

use activechain_protocol_types::Digest384;

pub const ACTIVECHAIN_VERIFY_OK: u32 = 0;
pub const ACTIVECHAIN_VERIFY_TOO_LARGE: u32 = 1;
pub const ACTIVECHAIN_VERIFY_DECODE_ERROR: u32 = 2;
pub const ACTIVECHAIN_VERIFY_TYPE_MISMATCH: u32 = 3;
pub const ACTIVECHAIN_VERIFY_VERSION_MISMATCH: u32 = 4;
pub const ACTIVECHAIN_VERIFY_COMMITMENT_MISMATCH: u32 = 5;
pub const ACTIVECHAIN_VERIFY_NULL_POINTER: u32 = 6;
pub const ACTIVECHAIN_VERIFY_RELATION_MISMATCH: u32 = 7;
pub const ACTIVECHAIN_VERIFY_BUFFER_TOO_SMALL: u32 = 8;
pub const ACTIVECHAIN_VERIFY_DETAIL_NONE: u32 = 0;
pub const ACTIVECHAIN_VERIFY_DETAIL_UNEXPECTED_END: u32 = 1;
pub const ACTIVECHAIN_VERIFY_DETAIL_NON_MINIMAL_LENGTH: u32 = 2;
pub const ACTIVECHAIN_VERIFY_DETAIL_LENGTH_OVERFLOW: u32 = 3;
pub const ACTIVECHAIN_VERIFY_DETAIL_LENGTH_LIMIT: u32 = 4;
pub const ACTIVECHAIN_VERIFY_DETAIL_INVALID_BOOLEAN: u32 = 5;
pub const ACTIVECHAIN_VERIFY_DETAIL_INVALID_ENUM: u32 = 6;
pub const ACTIVECHAIN_VERIFY_DETAIL_INVALID_VALUE: u32 = 7;
pub const ACTIVECHAIN_VERIFY_DETAIL_TRAILING_DATA: u32 = 8;
const TOO_LARGE: u32 = ACTIVECHAIN_VERIFY_TOO_LARGE;
const NULL_POINTER: u32 = ACTIVECHAIN_VERIFY_NULL_POINTER;
const MAX_ENVELOPE_LENGTH: u32 = activechain_verifier_api::MAX_ENVELOPE_LENGTH as u32;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivechainVerifierResult {
    pub code: u32,
    pub detail: u32,
    pub offset: u32,
    pub required_body_length: u32,
    pub type_tag: u16,
    pub schema_version: u16,
    pub canonical_value_commitment: [u8; 48],
}

impl Default for ActivechainVerifierResult {
    fn default() -> Self {
        Self {
            code: 0,
            detail: 0,
            offset: 0,
            required_body_length: 0,
            type_tag: 0,
            schema_version: 0,
            canonical_value_commitment: [0; 48],
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn activechain_verifier_abi_revision() -> u32 {
    activechain_verifier_api::VERIFIER_ABI_REVISION
}

#[unsafe(no_mangle)]
pub extern "C" fn activechain_verifier_schema_revision() -> u32 {
    activechain_verifier_api::VERIFIER_SCHEMA_REVISION
}

#[unsafe(no_mangle)]
pub extern "C" fn activechain_verifier_protocol_revision() -> u64 {
    activechain_verifier_api::VERIFIER_PROTOCOL_REVISION
}

#[unsafe(no_mangle)]
/// Inspects one bounded canonical envelope and returns its exact body and canonical commitment.
///
/// A null `body_output` with zero capacity is a size query. The result descriptor is populated on
/// every path for which it is non-null. No pointer is retained.
///
/// # Safety
/// `result` must be writable. For accepted lengths, `bytes` must be readable unless length is zero.
/// `body_output` must be writable for `body_capacity` bytes unless capacity is zero. The result,
/// input, and output regions must not overlap.
pub unsafe extern "C" fn activechain_verify_envelope_v1(
    bytes: *const u8,
    bytes_len: u32,
    expected_type: u16,
    expected_version: u16,
    body_output: *mut u8,
    body_capacity: u32,
    result: *mut ActivechainVerifierResult,
) -> u32 {
    if result.is_null() {
        return NULL_POINTER;
    }
    let mut report = ActivechainVerifierResult::default();
    if (bytes.is_null() && bytes_len != 0) || (body_output.is_null() && body_capacity != 0) {
        report.code = NULL_POINTER;
        unsafe { result.write(report) };
        return report.code;
    }
    if bytes_len > MAX_ENVELOPE_LENGTH {
        report.code = TOO_LARGE;
        report.offset = MAX_ENVELOPE_LENGTH;
        unsafe { result.write(report) };
        return report.code;
    }
    let input = if bytes_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(bytes, bytes_len as usize) }
    };
    let verified =
        activechain_verifier_api::inspect_envelope_report(input, expected_type, expected_version);
    let verified = match verified {
        Ok(verified) => verified,
        Err(error) => {
            let failure = error.failure(input.len());
            report.code = failure.code;
            report.detail = failure.detail;
            report.offset = u32::try_from(failure.offset).unwrap_or(u32::MAX);
            unsafe { result.write(report) };
            return report.code;
        }
    };
    report.required_body_length = verified.metadata.body_length as u32;
    report.type_tag = verified.metadata.type_tag;
    report.schema_version = verified.metadata.schema_version;
    report.canonical_value_commitment = *verified.canonical_value_commitment.as_bytes();
    if body_capacity < report.required_body_length {
        report.code = ACTIVECHAIN_VERIFY_BUFFER_TOO_SMALL;
        unsafe { result.write(report) };
        return report.code;
    }
    if report.required_body_length != 0 {
        let body_offset = input.len() - verified.metadata.body_length;
        unsafe {
            core::ptr::copy_nonoverlapping(
                input.as_ptr().add(body_offset),
                body_output,
                verified.metadata.body_length,
            );
        }
    }
    report.code = ACTIVECHAIN_VERIFY_OK;
    unsafe { result.write(report) };
    report.code
}

#[unsafe(no_mangle)]
/// # Safety
/// For lengths through [`activechain_verifier_api::MAX_ENVELOPE_LENGTH`], the caller must provide a
/// readable `bytes` buffer of `bytes_len` bytes, or a null pointer only when `bytes_len` is zero.
/// Oversized inputs are rejected before the pointer is materialized. The verifier does not retain
/// or write through the pointer.
pub unsafe extern "C" fn activechain_inspect_envelope_code(
    bytes: *const u8,
    bytes_len: u32,
    expected_type: u16,
    expected_version: u16,
) -> u32 {
    if bytes.is_null() && bytes_len != 0 {
        return NULL_POINTER;
    }
    if bytes_len > MAX_ENVELOPE_LENGTH {
        return TOO_LARGE;
    }
    let input = if bytes_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(bytes, bytes_len as usize) }
    };
    activechain_verifier_api::inspect_envelope_code(input, expected_type, expected_version)
}

#[unsafe(no_mangle)]
/// # Safety
/// For lengths through [`activechain_verifier_api::MAX_ENVELOPE_LENGTH`], the caller must provide a
/// readable `bytes` buffer of `bytes_len` bytes. The verifier does not retain or write through it.
pub unsafe extern "C" fn activechain_verify_principal_code(
    bytes: *const u8,
    bytes_len: u32,
) -> u32 {
    if bytes.is_null() && bytes_len != 0 {
        return NULL_POINTER;
    }
    if bytes_len > MAX_ENVELOPE_LENGTH {
        return TOO_LARGE;
    }
    let input = if bytes_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(bytes, bytes_len as usize) }
    };
    activechain_verifier_api::verify_principal_code(input)
}

#[unsafe(no_mangle)]
/// # Safety
/// The caller must provide a readable `bytes` buffer of `bytes_len` bytes. No pointer is retained.
pub unsafe extern "C" fn activechain_verify_capability_code(
    bytes: *const u8,
    bytes_len: u32,
) -> u32 {
    if bytes.is_null() && bytes_len != 0 {
        return NULL_POINTER;
    }
    if bytes_len > MAX_ENVELOPE_LENGTH {
        return TOO_LARGE;
    }
    let input = if bytes_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(bytes, bytes_len as usize) }
    };
    activechain_verifier_api::verify_capability_code(input)
}

#[unsafe(no_mangle)]
/// # Safety
/// The caller must provide readable parent and child buffers for the declared lengths. No pointer
/// is retained, and oversized combined input is rejected before either pointer is materialized.
pub unsafe extern "C" fn activechain_verify_capability_attenuation_code(
    parent: *const u8,
    parent_len: u32,
    child: *const u8,
    child_len: u32,
) -> u32 {
    if (parent.is_null() && parent_len != 0) || (child.is_null() && child_len != 0) {
        return NULL_POINTER;
    }
    if parent_len.checked_add(child_len).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return TOO_LARGE;
    }
    let parent = if parent_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(parent, parent_len as usize) }
    };
    let child = if child_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(child, child_len as usize) }
    };
    activechain_verifier_api::verify_capability_attenuation_code(parent, child)
}

#[unsafe(no_mangle)]
/// # Safety
/// The caller must provide a readable canonical authorization-chain buffer. No pointer is retained.
pub unsafe extern "C" fn activechain_verify_authorization_chain_code(
    bytes: *const u8,
    bytes_len: u32,
) -> u32 {
    if bytes.is_null() && bytes_len != 0 {
        return NULL_POINTER;
    }
    if bytes_len > MAX_ENVELOPE_LENGTH {
        return TOO_LARGE;
    }
    let input = if bytes_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(bytes, bytes_len as usize) }
    };
    activechain_verifier_api::verify_authorization_chain_code(input)
}

#[unsafe(no_mangle)]
/// # Safety
/// The caller must provide a readable `bytes` buffer of `bytes_len` bytes. No pointer is retained.
pub unsafe extern "C" fn activechain_verify_policy_decision_code(
    bytes: *const u8,
    bytes_len: u32,
) -> u32 {
    if bytes.is_null() && bytes_len != 0 {
        return NULL_POINTER;
    }
    if bytes_len > MAX_ENVELOPE_LENGTH {
        return TOO_LARGE;
    }
    let input = if bytes_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(bytes, bytes_len as usize) }
    };
    activechain_verifier_api::verify_policy_decision_code(input)
}

#[unsafe(no_mangle)]
/// # Safety
/// The caller must provide readable buffers for all declared lengths. No pointer is retained.
pub unsafe extern "C" fn activechain_verify_state_membership_code(
    commitment: *const u8,
    commitment_len: u32,
    object: *const u8,
    object_len: u32,
    proof: *const u8,
    proof_len: u32,
) -> u32 {
    if (commitment.is_null() && commitment_len != 0)
        || (object.is_null() && object_len != 0)
        || (proof.is_null() && proof_len != 0)
    {
        return NULL_POINTER;
    }
    if commitment_len
        .checked_add(object_len)
        .and_then(|length| length.checked_add(proof_len))
        .is_none_or(|length| length > MAX_ENVELOPE_LENGTH)
    {
        return TOO_LARGE;
    }
    let commitment = if commitment_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(commitment, commitment_len as usize) }
    };
    let object = if object_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(object, object_len as usize) }
    };
    let proof = if proof_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(proof, proof_len as usize) }
    };
    activechain_verifier_api::verify_state_membership_code(commitment, object, proof)
}

#[unsafe(no_mangle)]
/// # Safety
/// The caller must provide readable commitment/proof buffers and a readable 48-byte object ID.
pub unsafe extern "C" fn activechain_verify_state_non_membership_code(
    commitment: *const u8,
    commitment_len: u32,
    object_id: *const u8,
    proof: *const u8,
    proof_len: u32,
) -> u32 {
    if (commitment.is_null() && commitment_len != 0)
        || object_id.is_null()
        || (proof.is_null() && proof_len != 0)
    {
        return NULL_POINTER;
    }
    if commitment_len.checked_add(proof_len).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return TOO_LARGE;
    }
    let commitment = if commitment_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(commitment, commitment_len as usize) }
    };
    let proof = if proof_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(proof, proof_len as usize) }
    };
    let id = unsafe { core::slice::from_raw_parts(object_id, 48) };
    let mut id_bytes = [0_u8; 48];
    id_bytes.copy_from_slice(id);
    activechain_verifier_api::verify_state_non_membership_code(
        commitment,
        activechain_protocol_types::ObjectId::new(Digest384::new(id_bytes)),
        proof,
    )
}

#[unsafe(no_mangle)]
/// # Safety
/// The caller must provide a readable canonical finality-bundle buffer. No pointer is retained.
pub unsafe extern "C" fn activechain_verify_finality_bundle_code(
    bytes: *const u8,
    bytes_len: u32,
) -> u32 {
    if bytes.is_null() && bytes_len != 0 {
        return NULL_POINTER;
    }
    if bytes_len > MAX_ENVELOPE_LENGTH {
        return TOO_LARGE;
    }
    let input = if bytes_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(bytes, bytes_len as usize) }
    };
    activechain_verifier_api::verify_finality_bundle_code(input)
}

#[unsafe(no_mangle)]
/// # Safety
/// The caller must provide readable canonical finality and receipt buffers for the declared
/// lengths. Null pointers are permitted only for zero-length buffers. No pointer is retained.
pub unsafe extern "C" fn activechain_verify_block_receipt_code(
    finality: *const u8,
    finality_len: u32,
    receipt: *const u8,
    receipt_len: u32,
) -> u32 {
    if (finality.is_null() && finality_len != 0) || (receipt.is_null() && receipt_len != 0) {
        return NULL_POINTER;
    }
    if finality_len.checked_add(receipt_len).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return TOO_LARGE;
    }
    let finality = if finality_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(finality, finality_len as usize) }
    };
    let receipt = if receipt_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(receipt, receipt_len as usize) }
    };
    activechain_verifier_api::verify_block_receipt_code(finality, receipt)
}

#[unsafe(no_mangle)]
/// Verifies canonical finalized anchor evidence against explicit trusted network parameters.
///
/// # Safety
/// Evidence and statement buffers must be readable for their declared lengths. `chain_id` and
/// `genesis` must each point to readable 48-byte values. No pointer is retained.
pub unsafe extern "C" fn activechain_verify_anchor_finalized_evidence_code(
    evidence: *const u8,
    evidence_len: u32,
    statement: *const u8,
    statement_len: u32,
    chain_id: *const u8,
    genesis: *const u8,
    protocol_revision: u64,
    verifier_revision: u32,
) -> u32 {
    if (evidence.is_null() && evidence_len != 0)
        || (statement.is_null() && statement_len != 0)
        || chain_id.is_null()
        || genesis.is_null()
    {
        return NULL_POINTER;
    }
    if evidence_len.checked_add(statement_len).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return TOO_LARGE;
    }
    let evidence = if evidence_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(evidence, evidence_len as usize) }
    };
    let statement = if statement_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(statement, statement_len as usize) }
    };
    let mut chain_bytes = [0_u8; 48];
    chain_bytes.copy_from_slice(unsafe { core::slice::from_raw_parts(chain_id, 48) });
    let mut genesis_bytes = [0_u8; 48];
    genesis_bytes.copy_from_slice(unsafe { core::slice::from_raw_parts(genesis, 48) });
    activechain_verifier_api::verify_anchor_finalized_evidence_code(
        evidence,
        statement,
        activechain_protocol_types::ChainId::new(Digest384::new(chain_bytes)),
        Digest384::new(genesis_bytes),
        protocol_revision,
        verifier_revision,
    )
}

#[cfg(kani)]
mod kani_proofs;

#[unsafe(no_mangle)]
/// # Safety
/// The caller must provide readable buffers for the declared lengths and a readable 48-byte digest.
/// Null pointers are permitted only for zero-length buffers and no pointer is retained.
pub unsafe extern "C" fn activechain_verify_commitment_code(
    domain: *const u8,
    domain_len: u32,
    body: *const u8,
    body_len: u32,
    expected_digest: *const u8,
) -> u32 {
    if (domain.is_null() && domain_len != 0)
        || (body.is_null() && body_len != 0)
        || expected_digest.is_null()
    {
        return NULL_POINTER;
    }
    if domain_len.checked_add(body_len).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return TOO_LARGE;
    }
    let domain = if domain_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(domain, domain_len as usize) }
    };
    let body = if body_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(body, body_len as usize) }
    };
    let digest_bytes = unsafe { core::slice::from_raw_parts(expected_digest, 48) };
    let mut digest = [0_u8; 48];
    digest.copy_from_slice(digest_bytes);
    activechain_verifier_api::verify_commitment_code(domain, body, Digest384::new(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::encode_envelope;
    use activechain_devnet_kernel::BlockReceipt;
    use activechain_finality_types::{
        FinalityCertificateBundle, FinalizedBlockHeader, ProofPublicInputs,
    };
    use activechain_policy_kernel::{DecisionResult, PolicyDecision};
    use activechain_protocol_commitment::{DomainTag, commit};
    use activechain_protocol_types::{
        ActionId, BoundedActionSet, CapabilityGrant, CapabilityGrantFields, CapabilityId,
        CryptoSuiteId, DataSelector, FreezeState, HolderBinding, Object, ObjectFields, ObjectFlags,
        ObjectId, ObjectOwner, Principal, PrincipalId, PrincipalKind, ProtocolSignature,
        QuorumCertificate, ResourceSelector, ValidatorGenesis, ValidatorGenesisEntry,
        ValidatorVote,
    };
    use activechain_state_tree::{commit_objects, prove_object};
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn structured_envelope_api_supports_size_query_copy_and_failures() {
        let principal = Principal::new(
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
        .unwrap();
        let encoded = encode_envelope(&principal).unwrap();
        let mut result = ActivechainVerifierResult::default();
        assert_eq!(
            unsafe {
                activechain_verify_envelope_v1(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    Principal::TYPE_TAG,
                    Principal::SCHEMA_VERSION,
                    core::ptr::null_mut(),
                    0,
                    &mut result,
                )
            },
            ACTIVECHAIN_VERIFY_BUFFER_TOO_SMALL
        );
        assert_eq!(result.required_body_length as usize, encoded.len() - 6);
        assert_eq!(
            result.canonical_value_commitment,
            *commit(DomainTag::CANONICAL_VALUE, &principal).unwrap().as_bytes()
        );
        let mut body = vec![0; result.required_body_length as usize];
        let body_capacity = body.len() as u32;
        assert_eq!(
            unsafe {
                activechain_verify_envelope_v1(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    Principal::TYPE_TAG,
                    Principal::SCHEMA_VERSION,
                    body.as_mut_ptr(),
                    body_capacity,
                    &mut result,
                )
            },
            ACTIVECHAIN_VERIFY_OK
        );
        assert_eq!(body, encoded[encoded.len() - body.len()..]);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            unsafe {
                activechain_verify_envelope_v1(
                    trailing.as_ptr(),
                    trailing.len() as u32,
                    Principal::TYPE_TAG,
                    Principal::SCHEMA_VERSION,
                    core::ptr::null_mut(),
                    0,
                    &mut result,
                )
            },
            ACTIVECHAIN_VERIFY_DECODE_ERROR
        );
        assert_eq!(result.detail, 8);
        assert_eq!(result.offset as usize, encoded.len());
        assert_eq!(
            unsafe {
                activechain_verify_envelope_v1(
                    core::ptr::null(),
                    1,
                    Principal::TYPE_TAG,
                    Principal::SCHEMA_VERSION,
                    core::ptr::null_mut(),
                    0,
                    &mut result,
                )
            },
            ACTIVECHAIN_VERIFY_NULL_POINTER
        );
        assert_eq!(result.code, ACTIVECHAIN_VERIFY_NULL_POINTER);
        assert_eq!(
            unsafe {
                activechain_verify_envelope_v1(
                    encoded.as_ptr(),
                    MAX_ENVELOPE_LENGTH + 1,
                    Principal::TYPE_TAG,
                    Principal::SCHEMA_VERSION,
                    core::ptr::null_mut(),
                    0,
                    &mut result,
                )
            },
            ACTIVECHAIN_VERIFY_TOO_LARGE
        );
        assert_eq!(result.offset, MAX_ENVELOPE_LENGTH);
        assert_eq!(
            unsafe {
                activechain_verify_envelope_v1(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    Principal::TYPE_TAG,
                    Principal::SCHEMA_VERSION + 1,
                    core::ptr::null_mut(),
                    0,
                    &mut result,
                )
            },
            ACTIVECHAIN_VERIFY_VERSION_MISMATCH
        );
        assert_eq!(result.offset, 2);
        assert_eq!(
            unsafe {
                activechain_verify_envelope_v1(
                    encoded.as_ptr(),
                    encoded.len() as u32,
                    Principal::TYPE_TAG,
                    Principal::SCHEMA_VERSION,
                    core::ptr::null_mut(),
                    0,
                    core::ptr::null_mut(),
                )
            },
            ACTIVECHAIN_VERIFY_NULL_POINTER
        );
    }

    fn capability(
        id: u8,
        issuer: u8,
        holder: u8,
        parent: Option<u8>,
        depth: u8,
        allowed: bool,
    ) -> CapabilityGrant {
        CapabilityGrant::new(
            CapabilityGrantFields {
                capability_id: CapabilityId::new(digest(id)),
                issuer: PrincipalId::new(digest(issuer)),
                holder_binding: HolderBinding::Principal(PrincipalId::new(digest(holder))),
                parent_capability: parent.map(|byte| CapabilityId::new(digest(byte))),
                permitted_actions: BoundedActionSet::new(vec![ActionId::new(digest(1))]).unwrap(),
                resource_scope: ResourceSelector::ANY,
                data_scope: DataSelector::ANY,
                monetary_limit: Some(100),
                compute_limit: Some(100),
                rate_limit: None,
                use_limit: Some(10),
                valid_from: 1,
                valid_until: Some(100),
                delegation_depth_remaining: depth,
                delegation_allowed: allowed,
                revocation_registry: None,
                constraint_hash: digest(9),
            },
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![6; 2_420]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn abi_rejects_null_and_accepts_canonical_envelopes() {
        assert_eq!(activechain_verifier_abi_revision(), 1);
        assert_eq!(activechain_verifier_schema_revision(), 1);
        assert_eq!(activechain_verifier_protocol_revision(), 1);
        assert_eq!(
            unsafe { activechain_inspect_envelope_code(core::ptr::null(), 1, 0x1234, 1) },
            NULL_POINTER
        );
        let bytes = [0x12, 0x34, 0, 1, 1, 0xaa];
        assert_eq!(
            unsafe {
                activechain_inspect_envelope_code(bytes.as_ptr(), bytes.len() as u32, 0x1234, 1)
            },
            0
        );
        assert_eq!(
            unsafe {
                activechain_inspect_envelope_code(
                    core::ptr::NonNull::<u8>::dangling().as_ptr(),
                    MAX_ENVELOPE_LENGTH + 1,
                    0x1234,
                    1,
                )
            },
            TOO_LARGE
        );
    }

    #[test]
    fn principal_abi_matches_rust_verifier_codes() {
        let principal = Principal::new(
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
        .unwrap();
        let encoded = encode_envelope(&principal).unwrap();
        assert_eq!(
            unsafe { activechain_verify_principal_code(encoded.as_ptr(), encoded.len() as u32) },
            activechain_verifier_api::verify_principal_code(&encoded)
        );
        assert_eq!(
            unsafe { activechain_verify_principal_code(core::ptr::null(), 1) },
            NULL_POINTER
        );
    }

    #[test]
    fn capability_abi_matches_rust_shape_and_attenuation_results() {
        let parent = encode_envelope(&capability(10, 2, 3, None, 1, true)).unwrap();
        let child = encode_envelope(&capability(11, 3, 4, Some(10), 0, false)).unwrap();
        assert_eq!(
            unsafe { activechain_verify_capability_code(parent.as_ptr(), parent.len() as u32) },
            activechain_verifier_api::verify_capability_code(&parent)
        );
        assert_eq!(
            unsafe {
                activechain_verify_capability_attenuation_code(
                    parent.as_ptr(),
                    parent.len() as u32,
                    child.as_ptr(),
                    child.len() as u32,
                )
            },
            activechain_verifier_api::verify_capability_attenuation_code(&parent, &child)
        );
        assert_eq!(
            unsafe {
                activechain_verify_capability_attenuation_code(
                    core::ptr::null(),
                    1,
                    child.as_ptr(),
                    child.len() as u32,
                )
            },
            NULL_POINTER
        );
    }

    #[test]
    fn authorization_chain_abi_matches_rust_results_and_null_safety() {
        let chain = activechain_verifier_api::AuthorizationChain::new(
            PrincipalId::new(digest(4)),
            10,
            vec![capability(10, 2, 3, None, 1, true), capability(11, 3, 4, Some(10), 0, false)],
        )
        .unwrap();
        let encoded = encode_envelope(&chain).unwrap();
        assert_eq!(
            unsafe {
                activechain_verify_authorization_chain_code(encoded.as_ptr(), encoded.len() as u32)
            },
            activechain_verifier_api::verify_authorization_chain_code(&encoded)
        );
        assert_eq!(
            unsafe { activechain_verify_authorization_chain_code(core::ptr::null(), 1) },
            NULL_POINTER
        );
    }

    #[test]
    fn policy_decision_abi_matches_rust_verifier_result() {
        let encoded =
            encode_envelope(&PolicyDecision::new(DecisionResult::Deny, 0, 0, 0, vec![]).unwrap())
                .unwrap();
        assert_eq!(
            unsafe {
                activechain_verify_policy_decision_code(encoded.as_ptr(), encoded.len() as u32)
            },
            activechain_verifier_api::verify_policy_decision_code(&encoded)
        );
    }

    #[test]
    fn state_witness_abi_matches_rust_verifier_results() {
        let object = Object::new(ObjectFields {
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
        let objects = vec![object.clone()];
        let commitment = encode_envelope(&commit_objects(&objects).unwrap()).unwrap();
        let proof = encode_envelope(&prove_object(&objects, object.object_id()).unwrap()).unwrap();
        let object_bytes = encode_envelope(&object).unwrap();
        assert_eq!(
            unsafe {
                activechain_verify_state_membership_code(
                    commitment.as_ptr(),
                    commitment.len() as u32,
                    object_bytes.as_ptr(),
                    object_bytes.len() as u32,
                    proof.as_ptr(),
                    proof.len() as u32,
                )
            },
            activechain_verifier_api::verify_state_membership_code(
                &commitment,
                &object_bytes,
                &proof
            )
        );
        let absent_id = ObjectId::new(digest(31));
        let absent_proof = encode_envelope(&prove_object(&objects, absent_id).unwrap()).unwrap();
        assert_eq!(
            unsafe {
                activechain_verify_state_non_membership_code(
                    commitment.as_ptr(),
                    commitment.len() as u32,
                    absent_id.into_digest().as_bytes().as_ptr(),
                    absent_proof.as_ptr(),
                    absent_proof.len() as u32,
                )
            },
            activechain_verifier_api::verify_state_non_membership_code(
                &commitment,
                absent_id,
                &absent_proof
            )
        );
    }

    #[test]
    fn finality_bundle_abi_preserves_rust_error_codes_and_null_safety() {
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([1; 32]));
        let validator = PrincipalId::new(digest(1));
        let genesis = ValidatorGenesis::new_with_revision(
            3,
            1,
            4,
            vec![
                ValidatorGenesisEntry::new(validator, 1, key.verifying_key().encode().into())
                    .unwrap(),
            ],
        )
        .unwrap();
        let header = FinalizedBlockHeader {
            inputs: ProofPublicInputs {
                chain_id: activechain_protocol_types::ChainId::new(digest(40)),
                epoch: 3,
                height: 9,
                protocol_revision: 4,
                validator_set_root: genesis.validator_set_root(),
                parent_block_id: digest(41),
                pre_state: activechain_state_tree::StateCommitment::new(digest(42), 0),
                authorization_root: digest(43),
                action_root: digest(44),
                execution_order_root: digest(45),
                total_fees: 0,
                pre_supply: 0,
                issuance: 0,
                burn: 0,
                post_supply: 0,
                post_state: activechain_state_tree::StateCommitment::new(digest(46), 0),
                receipt_root: digest(47),
                data_availability_commitment: digest(48),
            },
            proof_statement_commitment: digest(49),
        };
        let context = activechain_protocol_types::ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            3,
            genesis.validator_set_root(),
            4,
        )
        .unwrap();
        let unsigned = ValidatorVote::new(
            validator,
            context,
            9,
            2,
            header.digest().unwrap(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        let signature = key.sign(&unsigned.signing_payload());
        let vote = ValidatorVote::new(
            validator,
            context,
            9,
            2,
            header.digest().unwrap(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap();
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
        hasher.update(key.verifying_key().encode().as_slice());
        hasher.update(&vote.signing_payload());
        hasher.update(vote.signature().as_bytes());
        let mut root = [0; 48];
        hasher.finalize_xof().read(&mut root);
        let certificate = QuorumCertificate::new(
            context,
            9,
            2,
            header.digest().unwrap(),
            Digest384::new(root),
            1,
            1,
        )
        .unwrap();
        let valid = encode_envelope(
            &FinalityCertificateBundle::new(header, genesis, certificate, vec![vote]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            unsafe { activechain_verify_finality_bundle_code(valid.as_ptr(), valid.len() as u32) },
            activechain_verifier_api::VERIFY_OK
        );
        let malformed = [0_u8; 1];
        assert_eq!(
            unsafe {
                activechain_verify_finality_bundle_code(malformed.as_ptr(), malformed.len() as u32)
            },
            activechain_verifier_api::verify_finality_bundle_code(&malformed)
        );
        assert_eq!(
            unsafe { activechain_verify_finality_bundle_code(core::ptr::null(), 1) },
            NULL_POINTER
        );
    }

    #[test]
    fn block_receipt_abi_preserves_rust_relation_codes_and_null_safety() {
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([7; 32]));
        let validator = PrincipalId::new(digest(1));
        let genesis = ValidatorGenesis::new_with_revision(
            3,
            1,
            4,
            vec![
                ValidatorGenesisEntry::new(validator, 1, key.verifying_key().encode().into())
                    .unwrap(),
            ],
        )
        .unwrap();
        let pre_state = activechain_state_tree::StateCommitment::new(digest(42), 0);
        let post_state = activechain_state_tree::StateCommitment::new(digest(46), 0);
        let receipt = BlockReceipt::new(digest(50), 9, pre_state, post_state, vec![]).unwrap();
        let receipt_root = commit(DomainTag::CANONICAL_VALUE, &receipt).unwrap();
        let header = FinalizedBlockHeader {
            inputs: ProofPublicInputs {
                chain_id: activechain_protocol_types::ChainId::new(digest(40)),
                epoch: 3,
                height: 9,
                protocol_revision: 4,
                validator_set_root: genesis.validator_set_root(),
                parent_block_id: digest(41),
                pre_state,
                authorization_root: digest(43),
                action_root: digest(44),
                execution_order_root: digest(45),
                total_fees: 0,
                pre_supply: 0,
                issuance: 0,
                burn: 0,
                post_supply: 0,
                post_state,
                receipt_root,
                data_availability_commitment: digest(48),
            },
            proof_statement_commitment: digest(49),
        };
        let context = activechain_protocol_types::ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            3,
            genesis.validator_set_root(),
            4,
        )
        .unwrap();
        let unsigned = ValidatorVote::new(
            validator,
            context,
            9,
            2,
            header.digest().unwrap(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        let signature = key.sign(&unsigned.signing_payload());
        let vote = ValidatorVote::new(
            validator,
            context,
            9,
            2,
            header.digest().unwrap(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap();
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
        hasher.update(key.verifying_key().encode().as_slice());
        hasher.update(&vote.signing_payload());
        hasher.update(vote.signature().as_bytes());
        let mut root = [0; 48];
        hasher.finalize_xof().read(&mut root);
        let certificate = QuorumCertificate::new(
            context,
            9,
            2,
            header.digest().unwrap(),
            Digest384::new(root),
            1,
            1,
        )
        .unwrap();
        let finality = encode_envelope(
            &FinalityCertificateBundle::new(header, genesis, certificate, vec![vote]).unwrap(),
        )
        .unwrap();
        let encoded_receipt = encode_envelope(&receipt).unwrap();
        assert_eq!(
            unsafe {
                activechain_verify_block_receipt_code(
                    finality.as_ptr(),
                    finality.len() as u32,
                    encoded_receipt.as_ptr(),
                    encoded_receipt.len() as u32,
                )
            },
            activechain_verifier_api::VERIFY_OK
        );
        assert_eq!(
            unsafe {
                activechain_verify_block_receipt_code(
                    core::ptr::null(),
                    1,
                    encoded_receipt.as_ptr(),
                    encoded_receipt.len() as u32,
                )
            },
            NULL_POINTER
        );
    }

    #[test]
    fn finalized_anchor_abi_rejects_null_and_oversized_inputs_before_dereference() {
        assert_eq!(
            unsafe {
                activechain_verify_anchor_finalized_evidence_code(
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    core::ptr::null(),
                    1,
                    1,
                )
            },
            NULL_POINTER
        );
        let trusted = [0_u8; 48];
        assert_eq!(
            unsafe {
                activechain_verify_anchor_finalized_evidence_code(
                    core::ptr::NonNull::<u8>::dangling().as_ptr(),
                    MAX_ENVELOPE_LENGTH,
                    core::ptr::NonNull::<u8>::dangling().as_ptr(),
                    1,
                    trusted.as_ptr(),
                    trusted.as_ptr(),
                    1,
                    1,
                )
            },
            TOO_LARGE
        );
    }

    #[test]
    fn abi_rejects_null_commitment_and_checks_known_commitment() {
        assert_eq!(
            unsafe {
                activechain_verify_commitment_code(
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                )
            },
            NULL_POINTER
        );
        let digest = [0_u8; 48];
        assert_eq!(
            unsafe {
                activechain_verify_commitment_code(
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    digest.as_ptr(),
                )
            },
            5
        );
        assert_eq!(
            unsafe {
                activechain_verify_commitment_code(
                    core::ptr::NonNull::<u8>::dangling().as_ptr(),
                    MAX_ENVELOPE_LENGTH,
                    core::ptr::NonNull::<u8>::dangling().as_ptr(),
                    1,
                    digest.as_ptr(),
                )
            },
            TOO_LARGE
        );

        let mut empty_digest = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
            0x6e, 0xd5, 0x76, 0x2f, 0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00, 0xcb, 0x05,
            0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6,
        ];
        assert_eq!(
            unsafe {
                activechain_verify_commitment_code(
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    empty_digest.as_ptr(),
                )
            },
            0
        );
        empty_digest[0] ^= 1;
        assert_eq!(
            unsafe {
                activechain_verify_commitment_code(
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    empty_digest.as_ptr(),
                )
            },
            5
        );
    }
}
