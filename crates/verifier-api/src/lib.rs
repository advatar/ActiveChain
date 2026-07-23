#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use activechain_application_primitives::{AnchorFinalizedEvidenceV1, DigestAnchorStatementV1};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, inspect_canonical_envelope,
};
use activechain_devnet_kernel::BlockReceipt;
use activechain_finality_types::FinalityCertificateBundle;
use activechain_policy_kernel::PolicyDecision;
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    CapabilityGrant, Digest384, INITIAL_PROTOCOL_REVISION, Object, ObjectId, Principal, PrincipalId,
};
use activechain_state_tree::{
    StateCommitment, StateProof, verify_membership, verify_non_membership,
};
use alloc::vec::Vec;
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
pub struct EnvelopeReport {
    pub metadata: EnvelopeMetadata,
    pub canonical_value_commitment: Digest384,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyFailure {
    pub code: u32,
    pub detail: u32,
    pub offset: usize,
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

    #[must_use]
    pub const fn failure(self, input_length: usize) -> VerifyFailure {
        let (detail, offset) = match self {
            Self::TooLarge => (0, MAX_ENVELOPE_LENGTH),
            Self::TypeMismatch => (0, 0),
            Self::VersionMismatch => (0, 2),
            Self::CommitmentMismatch | Self::RelationMismatch => (0, 0),
            Self::Decode(error) => match error {
                DecodeError::UnexpectedEnd { .. } => (1, input_length),
                DecodeError::NonMinimalLength => (2, 4),
                DecodeError::LengthOverflow => (3, 4),
                DecodeError::LengthLimitExceeded { .. } => (4, 4),
                DecodeError::InvalidBoolean(_) => (5, 5),
                DecodeError::InvalidEnumTag { .. } => (6, 5),
                DecodeError::InvalidValue(_) => (7, 5),
                DecodeError::TrailingData { remaining } => (8, input_length - remaining),
                DecodeError::InvalidTypeTag { .. } => (0, 0),
                DecodeError::UnsupportedSchemaVersion { .. } => (0, 2),
            },
        };
        VerifyFailure { code: self.code(), detail, offset }
    }
}

pub const VERIFY_OK: u32 = 0;
pub const MAX_AUTHORIZATION_CHAIN_DEPTH: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationChain {
    actor: PrincipalId,
    height: u64,
    capabilities: Vec<CapabilityGrant>,
}

impl AuthorizationChain {
    pub const TYPE_TAG: u16 = 0x007f;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        48 + 8 + 1 + MAX_AUTHORIZATION_CHAIN_DEPTH * CapabilityGrant::MAX_ENCODED_LEN;

    pub fn new(
        actor: PrincipalId,
        height: u64,
        capabilities: Vec<CapabilityGrant>,
    ) -> Result<Self, DecodeError> {
        if capabilities.is_empty() || capabilities.len() > MAX_AUTHORIZATION_CHAIN_DEPTH {
            return Err(DecodeError::InvalidValue("authorization chain depth is out of bounds"));
        }
        Ok(Self { actor, height, capabilities })
    }

    #[must_use]
    pub const fn actor(&self) -> PrincipalId {
        self.actor
    }

    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    #[must_use]
    pub fn capabilities(&self) -> &[CapabilityGrant] {
        &self.capabilities
    }
}

impl CanonicalEncode for AuthorizationChain {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.actor.encode(encoder)?;
        self.height.encode(encoder)?;
        encoder.write_length(self.capabilities.len(), MAX_AUTHORIZATION_CHAIN_DEPTH)?;
        for capability in &self.capabilities {
            capability.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for AuthorizationChain {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let actor = PrincipalId::decode(decoder)?;
        let height = u64::decode(decoder)?;
        let count = decoder.read_length(MAX_AUTHORIZATION_CHAIN_DEPTH)?;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(CapabilityGrant::decode(decoder)?);
        }
        Self::new(actor, height, capabilities)
    }
}

impl CanonicalType for AuthorizationChain {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

pub fn inspect_envelope_code(bytes: &[u8], expected_type: u16, expected_version: u16) -> u32 {
    inspect_envelope(bytes, expected_type, expected_version)
        .map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn inspect_envelope_report(
    bytes: &[u8],
    expected_type: u16,
    expected_version: u16,
) -> Result<EnvelopeReport, VerifyError> {
    let metadata = inspect_envelope(bytes, expected_type, expected_version)?;
    let body = &bytes[bytes.len() - metadata.body_length..];
    Ok(EnvelopeReport {
        metadata,
        canonical_value_commitment: canonical_value_commitment(
            metadata.type_tag,
            metadata.schema_version,
            body,
        ),
    })
}

#[must_use]
pub fn canonical_value_commitment(type_tag: u16, schema_version: u16, body: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-COMMITMENT");
    hasher.update(&1_u16.to_be_bytes());
    hasher.update(&DomainTag::CANONICAL_VALUE.as_u16().to_be_bytes());
    hasher.update(&type_tag.to_be_bytes());
    hasher.update(&schema_version.to_be_bytes());
    hasher.update(&(body.len() as u64).to_be_bytes());
    hasher.update(body);
    let mut output = [0; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
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

pub fn verify_authorization_chain_code(bytes: &[u8]) -> u32 {
    verify_authorization_chain(bytes).map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_authorization_chain(bytes: &[u8]) -> Result<AuthorizationChain, VerifyError> {
    inspect_envelope(bytes, AuthorizationChain::TYPE_TAG, AuthorizationChain::SCHEMA_VERSION)?;
    let chain = decode_envelope::<AuthorizationChain>(bytes).map_err(VerifyError::Decode)?;
    let capabilities = chain.capabilities();
    if capabilities[0].fields().parent_capability.is_some() {
        return Err(VerifyError::RelationMismatch);
    }
    for (index, capability) in capabilities.iter().enumerate() {
        let fields = capability.fields();
        if chain.height < fields.valid_from
            || fields.valid_until.is_some_and(|end| chain.height > end)
        {
            return Err(VerifyError::RelationMismatch);
        }
        if index > 0 {
            activechain_capability::verify_attenuation(&capabilities[index - 1], capability)
                .map_err(|_| VerifyError::RelationMismatch)?;
        }
    }
    if capabilities.last().is_none_or(|leaf| {
        leaf.fields().holder_binding
            != activechain_protocol_types::HolderBinding::Principal(chain.actor)
    }) {
        return Err(VerifyError::RelationMismatch);
    }
    Ok(chain)
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

pub fn verify_finality_bundle_code(bytes: &[u8]) -> u32 {
    verify_finality_bundle(bytes).map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_finality_bundle(bytes: &[u8]) -> Result<FinalityCertificateBundle, VerifyError> {
    inspect_envelope(
        bytes,
        FinalityCertificateBundle::TYPE_TAG,
        FinalityCertificateBundle::SCHEMA_VERSION,
    )?;
    let bundle =
        decode_envelope::<FinalityCertificateBundle>(bytes).map_err(VerifyError::Decode)?;
    let expected_genesis = bundle.validator_genesis().genesis_commitment();
    verify_decoded_finality_bundle(bundle, expected_genesis)
}

pub fn verify_finality_bundle_with_chain_genesis(
    bytes: &[u8],
    expected_chain_genesis: Digest384,
) -> Result<FinalityCertificateBundle, VerifyError> {
    inspect_envelope(
        bytes,
        FinalityCertificateBundle::TYPE_TAG,
        FinalityCertificateBundle::SCHEMA_VERSION,
    )?;
    let bundle =
        decode_envelope::<FinalityCertificateBundle>(bytes).map_err(VerifyError::Decode)?;
    verify_decoded_finality_bundle(bundle, expected_chain_genesis)
}

fn verify_decoded_finality_bundle(
    bundle: FinalityCertificateBundle,
    expected_chain_genesis: Digest384,
) -> Result<FinalityCertificateBundle, VerifyError> {
    let header = bundle.header();
    let genesis = bundle.validator_genesis();
    let certificate = bundle.certificate();
    if genesis.epoch() != header.inputs.epoch
        || genesis.protocol_revision() != header.inputs.protocol_revision
        || genesis.validator_set_root() != header.inputs.validator_set_root
        || certificate.genesis_commitment() != expected_chain_genesis
        || certificate.epoch() != header.inputs.epoch
        || certificate.protocol_revision() != header.inputs.protocol_revision
        || certificate.validator_set_root() != header.inputs.validator_set_root
        || certificate.height() != header.inputs.height
        || header.digest().map_err(|_| {
            VerifyError::Decode(DecodeError::InvalidValue(
                "finalized block header could not be encoded",
            ))
        })? != certificate.block_digest()
    {
        return Err(VerifyError::RelationMismatch);
    }
    let validator_set = genesis.validator_set().map_err(|_| VerifyError::RelationMismatch)?;
    let mut votes = Vec::with_capacity(bundle.votes().len());
    for vote in bundle.votes() {
        let entry = genesis
            .entries()
            .iter()
            .find(|entry| entry.validator() == vote.validator())
            .ok_or(VerifyError::RelationMismatch)?;
        votes.push((entry.public_key().as_slice(), vote.clone()));
    }
    activechain_consensus_verifier::verify_quorum_certificate(certificate, &validator_set, &votes)
        .map_err(|_| VerifyError::RelationMismatch)?;
    Ok(bundle)
}

pub fn verify_block_receipt_code(finality: &[u8], receipt: &[u8]) -> u32 {
    verify_block_receipt(finality, receipt).map_or_else(|error| error.code(), |_| VERIFY_OK)
}

pub fn verify_block_receipt(finality: &[u8], receipt: &[u8]) -> Result<BlockReceipt, VerifyError> {
    if finality.len().checked_add(receipt.len()).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return Err(VerifyError::TooLarge);
    }
    let finality = verify_finality_bundle(finality)?;
    verify_block_receipt_with_finality(finality, receipt)
}

pub fn verify_anchor_finalized_evidence_code(
    evidence: &[u8],
    expected_statement: &[u8],
    trusted_chain: activechain_protocol_types::ChainId,
    trusted_genesis: Digest384,
    protocol_revision: u64,
    verifier_revision: u32,
) -> u32 {
    verify_anchor_finalized_evidence(
        evidence,
        expected_statement,
        trusted_chain,
        trusted_genesis,
        protocol_revision,
        verifier_revision,
    )
    .map_or_else(|error| error.code(), |_| VERIFY_OK)
}

/// Verifies a finalized digest anchor without trusting evidence-supplied callbacks.
///
/// The finality bundle and block receipt carried by the evidence are verified by
/// the same bounded verifier used by ordinary ActiveChain clients. The receipt
/// must describe the declared finalized block and contain the declared anchor
/// transaction.
pub fn verify_anchor_finalized_evidence(
    evidence: &[u8],
    expected_statement: &[u8],
    trusted_chain: activechain_protocol_types::ChainId,
    trusted_genesis: Digest384,
    protocol_revision: u64,
    verifier_revision: u32,
) -> Result<AnchorFinalizedEvidenceV1, VerifyError> {
    if evidence
        .len()
        .checked_add(expected_statement.len())
        .is_none_or(|length| length > MAX_ENVELOPE_LENGTH)
    {
        return Err(VerifyError::TooLarge);
    }
    inspect_envelope(
        evidence,
        AnchorFinalizedEvidenceV1::TYPE_TAG,
        AnchorFinalizedEvidenceV1::SCHEMA_VERSION,
    )?;
    inspect_envelope(
        expected_statement,
        DigestAnchorStatementV1::TYPE_TAG,
        DigestAnchorStatementV1::SCHEMA_VERSION,
    )?;
    let evidence =
        decode_envelope::<AnchorFinalizedEvidenceV1>(evidence).map_err(VerifyError::Decode)?;
    let expected_statement = decode_envelope::<DigestAnchorStatementV1>(expected_statement)
        .map_err(VerifyError::Decode)?;
    if evidence.statement() != &expected_statement
        || evidence.chain() != trusted_chain
        || evidence.genesis() != trusted_genesis
        || evidence.protocol_revision() != protocol_revision
        || evidence.verifier_revision() != verifier_revision
    {
        return Err(VerifyError::RelationMismatch);
    }
    let receipt = verify_block_receipt_with_chain_genesis(
        evidence.finality_proof(),
        evidence.inclusion_proof(),
        trusted_genesis,
    )?;
    if receipt.block_id() != evidence.finalized_block()
        || receipt.height() != evidence.finalized_height()
        || !receipt
            .action_receipts()
            .iter()
            .any(|receipt| receipt.transaction_id() == evidence.transaction())
    {
        return Err(VerifyError::RelationMismatch);
    }
    Ok(evidence)
}

pub fn verify_block_receipt_with_chain_genesis(
    finality: &[u8],
    receipt: &[u8],
    expected_chain_genesis: Digest384,
) -> Result<BlockReceipt, VerifyError> {
    if finality.len().checked_add(receipt.len()).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return Err(VerifyError::TooLarge);
    }
    let finality = verify_finality_bundle_with_chain_genesis(finality, expected_chain_genesis)?;
    verify_block_receipt_with_finality(finality, receipt)
}

fn verify_block_receipt_with_finality(
    finality: FinalityCertificateBundle,
    receipt: &[u8],
) -> Result<BlockReceipt, VerifyError> {
    inspect_envelope(receipt, BlockReceipt::TYPE_TAG, BlockReceipt::SCHEMA_VERSION)?;
    let receipt = decode_envelope::<BlockReceipt>(receipt).map_err(VerifyError::Decode)?;
    let inputs = finality.header().inputs;
    let receipt_root = commit(DomainTag::CANONICAL_VALUE, &receipt).map_err(|_| {
        VerifyError::Decode(DecodeError::InvalidValue("block receipt could not be encoded"))
    })?;
    if receipt_root != inputs.receipt_root
        || receipt.height() != inputs.height
        || receipt.pre_state() != inputs.pre_state
        || receipt.post_state() != inputs.post_state
    {
        return Err(VerifyError::RelationMismatch);
    }
    Ok(receipt)
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
    use activechain_action_kernel::ResourceVector;
    use activechain_application_primitives::{AnchorFinalizedEvidenceV1, DigestAnchorStatementV1};
    use activechain_canonical_codec::encode_envelope;
    use activechain_devnet_kernel::{ActionOutcome, ActionReceipt};
    use activechain_policy_kernel::DecisionResult;
    use activechain_protocol_types::{
        ActionId, BoundedActionSet, CapabilityGrantFields, CapabilityId, ConsensusVoteContext,
        CryptoSuiteId, DataSelector, FreezeState, HolderBinding, ObjectFields, ObjectFlags,
        ObjectOwner, PrincipalId, PrincipalKind, ProtocolSignature, QuorumCertificate,
        ResourceSelector, TransactionId, ValidatorGenesis, ValidatorGenesisEntry, ValidatorVote,
    };
    use activechain_state_tree::{commit_objects, prove_object};
    use alloc::{vec, vec::Vec};
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};

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
    fn structured_envelope_report_returns_exact_body_and_commitment() {
        let value = principal();
        let encoded = encode_envelope(&value).unwrap();
        let report =
            inspect_envelope_report(&encoded, Principal::TYPE_TAG, Principal::SCHEMA_VERSION)
                .unwrap();
        assert_eq!(report.metadata.body_length, encoded.len() - 6);
        assert_eq!(
            report.canonical_value_commitment,
            commit(DomainTag::CANONICAL_VALUE, &value).unwrap()
        );
        let failure =
            inspect_envelope_report(&encoded, Principal::TYPE_TAG, Principal::SCHEMA_VERSION + 1)
                .unwrap_err()
                .failure(encoded.len());
        assert_eq!(failure, VerifyFailure { code: 4, detail: 0, offset: 2 });
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
    fn authorization_chain_verifier_checks_every_hop_height_and_actor_binding() {
        let parent = capability(10, 2, 3, None, &[1, 2], 1, true);
        let child = capability(11, 3, 4, Some(10), &[1], 0, false);
        let chain = AuthorizationChain::new(
            PrincipalId::new(digest(4)),
            10,
            vec![parent.clone(), child.clone()],
        )
        .unwrap();
        let encoded = encode_envelope(&chain).unwrap();
        assert_eq!(verify_authorization_chain_code(&encoded), VERIFY_OK);
        assert_eq!(verify_authorization_chain(&encoded), Ok(chain));

        let wrong_actor = encode_envelope(
            &AuthorizationChain::new(PrincipalId::new(digest(5)), 10, vec![parent.clone(), child])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_authorization_chain_code(&wrong_actor),
            VerifyError::RelationMismatch.code()
        );
        let parented_root = encode_envelope(
            &AuthorizationChain::new(
                PrincipalId::new(digest(4)),
                10,
                vec![capability(12, 2, 4, Some(9), &[1], 0, false)],
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_authorization_chain_code(&parented_root),
            VerifyError::RelationMismatch.code()
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_ne!(verify_authorization_chain_code(&trailing), VERIFY_OK);
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

    fn finality_bundle_with_inputs(
        receipt_root: Digest384,
        pre_state: StateCommitment,
        post_state: StateCommitment,
    ) -> FinalityCertificateBundle {
        let keys = [
            SigningKey::<MlDsa44>::from_seed(&Seed::from([1; 32])),
            SigningKey::<MlDsa44>::from_seed(&Seed::from([2; 32])),
        ];
        let entries = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                ValidatorGenesisEntry::new(
                    PrincipalId::new(digest((index + 1) as u8)),
                    1,
                    key.verifying_key().encode().into(),
                )
                .unwrap()
            })
            .collect();
        let genesis = ValidatorGenesis::new_with_revision(3, 1, 4, entries).unwrap();
        let inputs = activechain_finality_types::ProofPublicInputs {
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
        };
        let header = activechain_finality_types::FinalizedBlockHeader {
            inputs,
            proof_statement_commitment: digest(49),
        };
        let block_digest = header.digest().unwrap();
        let context = ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        let mut votes = Vec::new();
        let mut vote_set_hasher = Shake256::default();
        vote_set_hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
        for (index, key) in keys.iter().enumerate() {
            let validator = PrincipalId::new(digest((index + 1) as u8));
            let unsigned = ValidatorVote::new(
                validator,
                context,
                9,
                2,
                block_digest,
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
            )
            .unwrap();
            let signature = key.sign(&unsigned.signing_payload());
            let vote = ValidatorVote::new(
                validator,
                context,
                9,
                2,
                block_digest,
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                    .unwrap(),
            )
            .unwrap();
            vote_set_hasher.update(key.verifying_key().encode().as_slice());
            vote_set_hasher.update(&vote.signing_payload());
            vote_set_hasher.update(vote.signature().as_bytes());
            votes.push(vote);
        }
        let mut vote_set_root = [0; 48];
        vote_set_hasher.finalize_xof().read(&mut vote_set_root);
        let certificate = QuorumCertificate::new(
            context,
            9,
            2,
            block_digest,
            Digest384::new(vote_set_root),
            2,
            2,
        )
        .unwrap();
        FinalityCertificateBundle::new(header, genesis, certificate, votes).unwrap()
    }

    fn finality_bundle() -> FinalityCertificateBundle {
        finality_bundle_with_inputs(
            digest(47),
            StateCommitment::new(digest(42), 0),
            StateCommitment::new(digest(46), 0),
        )
    }

    #[test]
    fn finality_bundle_verifies_header_context_quorum_and_real_pq_votes() {
        let bundle = finality_bundle();
        let encoded = encode_envelope(&bundle).unwrap();
        assert_eq!(verify_finality_bundle_code(&encoded), VERIFY_OK);
        assert_eq!(verify_finality_bundle(&encoded), Ok(bundle));

        let mut substituted = encoded.clone();
        let last = substituted.len() - 1;
        substituted[last] ^= 1;
        assert_ne!(verify_finality_bundle_code(&substituted), VERIFY_OK);
        let metadata = inspect_envelope(
            &encoded,
            FinalityCertificateBundle::TYPE_TAG,
            FinalityCertificateBundle::SCHEMA_VERSION,
        )
        .unwrap();
        let body_start = encoded.len() - metadata.body_length;
        let mut wrong_context = encoded.clone();
        wrong_context[body_start + 48..body_start + 56].copy_from_slice(&4_u64.to_be_bytes());
        assert_eq!(
            verify_finality_bundle_code(&wrong_context),
            VerifyError::RelationMismatch.code()
        );
        let mut truncated = encoded.clone();
        truncated.pop();
        assert_ne!(verify_finality_bundle_code(&truncated), VERIFY_OK);
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_ne!(verify_finality_bundle_code(&trailing), VERIFY_OK);
        let mut wrong_version = encoded;
        wrong_version[3] = 2;
        assert_eq!(
            verify_finality_bundle_code(&wrong_version),
            VerifyError::VersionMismatch.code()
        );
    }

    #[test]
    fn block_receipt_verifier_binds_finality_root_height_and_state_transition() {
        let pre_state = StateCommitment::new(digest(60), 2);
        let post_state = StateCommitment::new(digest(61), 3);
        let receipt = BlockReceipt::new(digest(62), 9, pre_state, post_state, vec![]).unwrap();
        let receipt_root = commit(DomainTag::CANONICAL_VALUE, &receipt).unwrap();
        let finality =
            encode_envelope(&finality_bundle_with_inputs(receipt_root, pre_state, post_state))
                .unwrap();
        let encoded = encode_envelope(&receipt).unwrap();
        assert_eq!(verify_block_receipt_code(&finality, &encoded), VERIFY_OK);
        assert_eq!(verify_block_receipt(&finality, &encoded), Ok(receipt.clone()));

        let substituted = encode_envelope(
            &BlockReceipt::new(digest(63), 9, pre_state, post_state, vec![]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_block_receipt_code(&finality, &substituted),
            VerifyError::RelationMismatch.code()
        );
        let wrong_height = encode_envelope(
            &BlockReceipt::new(digest(62), 10, pre_state, post_state, vec![]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_block_receipt_code(&finality, &wrong_height),
            VerifyError::RelationMismatch.code()
        );
        let mut truncated = encoded.clone();
        truncated.pop();
        assert_ne!(verify_block_receipt_code(&finality, &truncated), VERIFY_OK);
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_ne!(verify_block_receipt_code(&finality, &trailing), VERIFY_OK);
        let mut wrong_version = encoded;
        wrong_version[3] = 2;
        assert_eq!(
            verify_block_receipt_code(&finality, &wrong_version),
            VerifyError::VersionMismatch.code()
        );
    }

    #[test]
    fn finalized_anchor_verifier_uses_real_finality_and_receipt_verifiers() {
        let pre_state = StateCommitment::new(digest(60), 2);
        let post_state = StateCommitment::new(digest(61), 3);
        let transaction = TransactionId::new(digest(70));
        let receipt = BlockReceipt::new(
            digest(62),
            9,
            pre_state,
            post_state,
            vec![ActionReceipt::new(
                transaction,
                ActionOutcome::ResourceLimitExceeded,
                ResourceVector::new(1, 0, 0, 0, 0, 1),
                0,
                1,
                post_state,
            )],
        )
        .unwrap();
        let receipt_root = commit(DomainTag::CANONICAL_VALUE, &receipt).unwrap();
        let finality_bundle = finality_bundle_with_inputs(receipt_root, pre_state, post_state);
        let trusted_genesis = finality_bundle.validator_genesis().genesis_commitment();
        let statement = DigestAnchorStatementV1::new(
            b"mademark.external-anchor.statement.v1".to_vec(),
            [0x11; 32],
        )
        .unwrap();
        let evidence = AnchorFinalizedEvidenceV1::new(
            activechain_protocol_types::ChainId::new(digest(40)),
            trusted_genesis,
            transaction,
            9,
            receipt.block_id(),
            statement.clone(),
            None,
            None,
            4,
            VERIFIER_SCHEMA_REVISION,
            encode_envelope(&receipt).unwrap(),
            encode_envelope(&finality_bundle).unwrap(),
        )
        .unwrap();
        let encoded_evidence = encode_envelope(&evidence).unwrap();
        let encoded_statement = encode_envelope(&statement).unwrap();
        assert_eq!(
            verify_anchor_finalized_evidence_code(
                &encoded_evidence,
                &encoded_statement,
                evidence.chain(),
                trusted_genesis,
                4,
                VERIFIER_SCHEMA_REVISION,
            ),
            VERIFY_OK
        );
        assert_eq!(
            verify_anchor_finalized_evidence_code(
                &encoded_evidence,
                &encoded_statement,
                activechain_protocol_types::ChainId::new(digest(41)),
                trusted_genesis,
                4,
                VERIFIER_SCHEMA_REVISION,
            ),
            VerifyError::RelationMismatch.code()
        );
        let wrong_statement = encode_envelope(
            &DigestAnchorStatementV1::new(
                b"mademark.external-anchor.statement.v1".to_vec(),
                [0x12; 32],
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_anchor_finalized_evidence_code(
                &encoded_evidence,
                &wrong_statement,
                evidence.chain(),
                trusted_genesis,
                4,
                VERIFIER_SCHEMA_REVISION,
            ),
            VerifyError::RelationMismatch.code()
        );
    }
}
