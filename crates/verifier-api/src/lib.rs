#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod signed_authorization;

pub use signed_authorization::{
    AuthorizationControllerWitnessV1, CapabilityNonRevocationProofV1,
    CapabilityRevocationWitnessV1, SignedAuthorizationChainV1, verify_signed_authorization_chain,
    verify_signed_authorization_chain_code,
};

use activechain_application_primitives::{AnchorFinalizedEvidenceV1, DigestAnchorStatementV1};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope, inspect_canonical_envelope,
};
use activechain_cash_kernel::{CoinCellMembershipProof, CoinCellRecord};
use activechain_devnet_kernel::BlockReceipt;
use activechain_finality_types::{FinalityCertificateBundle, commit_parts};
use activechain_payment_types::{
    PaymentFinalizedRefundV1, PaymentFinalizedSettlementV1, payment_finality_proof_commitment,
};
use activechain_policy_kernel::PolicyDecision;
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    AuthenticatorId, AuthenticatorPurpose, AuthenticatorSetV1, CapabilityGrant, Digest384,
    FreezeState, INITIAL_PROTOCOL_REVISION, NonFungibleSeriesV1, NonFungibleTokenRegistryV1,
    Object, ObjectFlags, ObjectId, ObjectOwner, Principal, PrincipalId,
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
pub const NFT_SERIES_QUERY_KIND: u8 = 12;
pub const NFT_TOKEN_REGISTRY_QUERY_KIND: u8 = 13;

const PRINCIPAL_REGISTRY_OBJECT_TYPE_DOMAIN: &[u8] =
    b"ACTIVECHAIN-PRINCIPAL-REGISTRY-OBJECT-TYPE-V1";
const PRINCIPAL_REGISTRY_OBJECT_VALUE_DOMAIN: &[u8] =
    b"ACTIVECHAIN-PRINCIPAL-REGISTRY-OBJECT-VALUE-V1";

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
    pub const SCHEMA_VERSION: u16 = 2;
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

/// Verifies one proof-bearing owner-scoped Coin Cell returned by an RPC page.
///
/// The record is accepted only when its canonical key, owner, authenticated
/// cash root, finalized height, and validator certificate all bind to the
/// caller's exact trusted chain genesis.
#[allow(clippy::too_many_arguments)]
pub fn verify_owner_coin_cell_record_code(
    key: Digest384,
    finalized_height: u64,
    value: &[u8],
    proof: &[u8],
    finality: &[u8],
    owner: PrincipalId,
    trusted_genesis: Digest384,
) -> u32 {
    verify_owner_coin_cell_record(
        key,
        finalized_height,
        value,
        proof,
        finality,
        owner,
        trusted_genesis,
    )
    .map_or_else(|error| error.code(), |()| VERIFY_OK)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_owner_coin_cell_record(
    key: Digest384,
    finalized_height: u64,
    value: &[u8],
    proof: &[u8],
    finality: &[u8],
    owner: PrincipalId,
    trusted_genesis: Digest384,
) -> Result<(), VerifyError> {
    if value
        .len()
        .checked_add(proof.len())
        .and_then(|length| length.checked_add(finality.len()))
        .is_none_or(|length| length > MAX_ENVELOPE_LENGTH)
    {
        return Err(VerifyError::TooLarge);
    }
    let finality = verify_finality_bundle_with_chain_genesis(finality, trusted_genesis)?;
    if finality.header().inputs.height != finalized_height {
        return Err(VerifyError::RelationMismatch);
    }
    let record = decode_envelope::<CoinCellRecord>(value).map_err(VerifyError::Decode)?;
    let membership =
        decode_envelope::<CoinCellMembershipProof>(proof).map_err(VerifyError::Decode)?;
    if record.id().into_digest() != key
        || record.cell().owner() != owner
        || membership.record() != record
        || membership.root().into_digest() != finality.header().inputs.cash_cell_root
    {
        return Err(VerifyError::RelationMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_nft_state_record_code(
    query_kind: u8,
    key: Digest384,
    finalized_height: u64,
    value: &[u8],
    proof: &[u8],
    finality: &[u8],
    trusted_genesis: Digest384,
) -> u32 {
    verify_nft_state_record(
        query_kind,
        key,
        finalized_height,
        value,
        proof,
        finality,
        trusted_genesis,
    )
    .map_or_else(|error| error.code(), |()| VERIFY_OK)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_nft_state_record(
    query_kind: u8,
    key: Digest384,
    finalized_height: u64,
    value: &[u8],
    proof: &[u8],
    finality: &[u8],
    trusted_genesis: Digest384,
) -> Result<(), VerifyError> {
    if value
        .len()
        .checked_add(proof.len())
        .and_then(|length| length.checked_add(finality.len()))
        .is_none_or(|length| length > MAX_ENVELOPE_LENGTH)
    {
        return Err(VerifyError::TooLarge);
    }
    let finality = verify_finality_bundle_with_chain_genesis(finality, trusted_genesis)?;
    if finality.header().inputs.height != finalized_height {
        return Err(VerifyError::RelationMismatch);
    }
    let object = decode_envelope::<Object>(value).map_err(VerifyError::Decode)?;
    if object.object_id().into_digest() != key {
        return Err(VerifyError::RelationMismatch);
    }
    let public_value = object.public_value().ok_or(VerifyError::RelationMismatch)?;
    let type_tag = match query_kind {
        NFT_SERIES_QUERY_KIND => {
            decode_envelope::<NonFungibleSeriesV1>(public_value).map_err(VerifyError::Decode)?;
            NonFungibleSeriesV1::TYPE_TAG
        }
        NFT_TOKEN_REGISTRY_QUERY_KIND => {
            decode_envelope::<NonFungibleTokenRegistryV1>(public_value)
                .map_err(VerifyError::Decode)?;
            NonFungibleTokenRegistryV1::TYPE_TAG
        }
        _ => return Err(VerifyError::TypeMismatch),
    };
    let kind = [query_kind];
    let tag = type_tag.to_be_bytes();
    let expected_type = commit_parts(b"ACTIVECHAIN-NATIVE-ASSET-RPC-TYPE-V1", &[&kind, &tag]);
    let expected_value = commit_parts(b"ACTIVECHAIN-NATIVE-ASSET-RPC-VALUE-V1", &[public_value]);
    if object.type_id() != expected_type || object.value_root() != expected_value {
        return Err(VerifyError::CommitmentMismatch);
    }
    let commitment =
        activechain_canonical_codec::encode_envelope(&finality.header().inputs.post_state)
            .map_err(|_| {
                VerifyError::Decode(DecodeError::InvalidValue(
                    "finalized state commitment could not be encoded",
                ))
            })?;
    verify_state_membership(&commitment, value, proof)
}

/// Returns the fixed type commitment required for principal-registry state objects.
#[must_use]
pub fn principal_registry_object_type() -> Digest384 {
    commit_parts(
        PRINCIPAL_REGISTRY_OBJECT_TYPE_DOMAIN,
        &[&Principal::TYPE_TAG.to_be_bytes(), &Principal::SCHEMA_VERSION.to_be_bytes()],
    )
}

/// Verifies a finalized principal object and one active authenticator under its committed set.
#[allow(clippy::too_many_arguments)]
pub fn verify_finalized_principal_authenticator_code(
    principal_object: &[u8],
    principal_proof: &[u8],
    authenticator_set: &[u8],
    finality: &[u8],
    trusted_genesis: Digest384,
    expected_principal: PrincipalId,
    expected_authenticator: AuthenticatorId,
    expected_purpose: AuthenticatorPurpose,
) -> u32 {
    verify_finalized_principal_authenticator(
        principal_object,
        principal_proof,
        authenticator_set,
        finality,
        trusted_genesis,
        expected_principal,
        expected_authenticator,
        expected_purpose,
    )
    .map_or_else(|error| error.code(), |()| VERIFY_OK)
}

/// Verifies the complete object/state/finality and authenticator-set relation.
#[allow(clippy::too_many_arguments)]
pub fn verify_finalized_principal_authenticator(
    principal_object: &[u8],
    principal_proof: &[u8],
    authenticator_set: &[u8],
    finality: &[u8],
    trusted_genesis: Digest384,
    expected_principal: PrincipalId,
    expected_authenticator: AuthenticatorId,
    expected_purpose: AuthenticatorPurpose,
) -> Result<(), VerifyError> {
    let total = principal_object
        .len()
        .checked_add(principal_proof.len())
        .and_then(|length| length.checked_add(authenticator_set.len()))
        .and_then(|length| length.checked_add(finality.len()))
        .ok_or(VerifyError::TooLarge)?;
    if total > MAX_ENVELOPE_LENGTH {
        return Err(VerifyError::TooLarge);
    }
    let finality = verify_finality_bundle_with_chain_genesis(finality, trusted_genesis)?;
    let object = decode_envelope::<Object>(principal_object).map_err(VerifyError::Decode)?;
    let set =
        decode_envelope::<AuthenticatorSetV1>(authenticator_set).map_err(VerifyError::Decode)?;
    let public_value = object.public_value().ok_or(VerifyError::RelationMismatch)?;
    let principal = decode_envelope::<Principal>(public_value).map_err(VerifyError::Decode)?;
    let expected_object_id = ObjectId::new(expected_principal.into_digest());
    let height = finality.header().inputs.height;

    if object.object_id() != expected_object_id
        || object.type_id() != principal_registry_object_type()
        || object.owner() != ObjectOwner::Principal(expected_principal)
        || !object.flags().contains(ObjectFlags::SYSTEM)
        || object.package_id().is_some()
        || principal.principal_id() != expected_principal
        || principal.freeze_state() != FreezeState::Active
        || principal.last_updated_at() > height
        || set.root().map_err(|_| VerifyError::CommitmentMismatch)?
            != principal.authenticator_set_root()
        || object.value_root()
            != commit_parts(PRINCIPAL_REGISTRY_OBJECT_VALUE_DOMAIN, &[public_value])
    {
        return Err(VerifyError::RelationMismatch);
    }
    let authenticator =
        set.authenticator(expected_authenticator).ok_or(VerifyError::RelationMismatch)?;
    if authenticator.purpose() != expected_purpose || !authenticator.is_active_at(height) {
        return Err(VerifyError::RelationMismatch);
    }

    let commitment = encode_envelope(&finality.header().inputs.post_state).map_err(|_| {
        VerifyError::Decode(DecodeError::InvalidValue(
            "finalized state commitment could not be encoded",
        ))
    })?;
    verify_state_membership(&commitment, principal_object, principal_proof)
}

fn verify_decoded_finality_bundle(
    bundle: FinalityCertificateBundle,
    expected_chain_genesis: Digest384,
) -> Result<FinalityCertificateBundle, VerifyError> {
    let header = bundle.header();
    let genesis = bundle.validator_genesis();
    let certificate = bundle.certificate();
    let empty_cash_actions =
        activechain_finality_types::commit_parts(b"ACTIVECHAIN-BLOCK-CASH-ACTIONS-V1", &[&[]]);
    if genesis.epoch() != header.inputs.epoch
        || genesis.protocol_revision() != header.inputs.protocol_revision
        || genesis.validator_set_root() != header.inputs.validator_set_root
        || certificate.genesis_commitment() != expected_chain_genesis
        || certificate.epoch() != header.inputs.epoch
        || certificate.protocol_revision() != header.inputs.protocol_revision
        || certificate.validator_set_root() != header.inputs.validator_set_root
        || certificate.height() != header.inputs.height
        || header.inputs.pre_cash_cell_root == Digest384::ZERO
        || header.inputs.cash_action_root == Digest384::ZERO
        || header.inputs.cash_cell_root == Digest384::ZERO
        || (header.inputs.cash_action_root == empty_cash_actions
            && header.inputs.pre_cash_cell_root != header.inputs.cash_cell_root)
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

/// Verifies the exact finality bundle and block receipt committed by a payment settlement.
pub fn verify_payment_finalized_settlement(
    settlement: &[u8],
    finality: &[u8],
    receipt: &[u8],
    expected_chain_genesis: Digest384,
) -> Result<PaymentFinalizedSettlementV1, VerifyError> {
    let total = settlement
        .len()
        .checked_add(finality.len())
        .and_then(|length| length.checked_add(receipt.len()))
        .ok_or(VerifyError::TooLarge)?;
    if total > MAX_ENVELOPE_LENGTH {
        return Err(VerifyError::TooLarge);
    }
    inspect_envelope(
        settlement,
        PaymentFinalizedSettlementV1::TYPE_TAG,
        PaymentFinalizedSettlementV1::SCHEMA_VERSION,
    )?;
    let settlement =
        decode_envelope::<PaymentFinalizedSettlementV1>(settlement).map_err(VerifyError::Decode)?;
    let verified_receipt =
        verify_block_receipt_with_chain_genesis(finality, receipt, expected_chain_genesis)?;
    let receipt_commitment =
        commit(DomainTag::CANONICAL_VALUE, &verified_receipt).map_err(|_| {
            VerifyError::Decode(DecodeError::InvalidValue("payment receipt could not be committed"))
        })?;
    if verified_receipt.block_id() != settlement.finalized_block()
        || verified_receipt.height() != settlement.finalized_height()
        || receipt_commitment != settlement.receipt_commitment()
        || payment_finality_proof_commitment(finality) != settlement.proof_commitment()
        || !verified_receipt
            .action_receipts()
            .iter()
            .any(|action| action.transaction_id() == settlement.transaction())
    {
        return Err(VerifyError::RelationMismatch);
    }
    Ok(settlement)
}

/// Verifies trusted-genesis finality and exact action inclusion for a complete payment refund.
pub fn verify_payment_finalized_refund(
    refund: &[u8],
    finality: &[u8],
    receipt: &[u8],
    expected_chain_genesis: Digest384,
) -> Result<PaymentFinalizedRefundV1, VerifyError> {
    let total = refund
        .len()
        .checked_add(finality.len())
        .and_then(|length| length.checked_add(receipt.len()))
        .ok_or(VerifyError::TooLarge)?;
    if total > MAX_ENVELOPE_LENGTH {
        return Err(VerifyError::TooLarge);
    }
    inspect_envelope(
        refund,
        PaymentFinalizedRefundV1::TYPE_TAG,
        PaymentFinalizedRefundV1::SCHEMA_VERSION,
    )?;
    let refund =
        decode_envelope::<PaymentFinalizedRefundV1>(refund).map_err(VerifyError::Decode)?;
    let verified_receipt =
        verify_block_receipt_with_chain_genesis(finality, receipt, expected_chain_genesis)?;
    let receipt_commitment =
        commit(DomainTag::CANONICAL_VALUE, &verified_receipt).map_err(|_| {
            VerifyError::Decode(DecodeError::InvalidValue("refund receipt could not be committed"))
        })?;
    if verified_receipt.block_id() != refund.finalized_block()
        || verified_receipt.height() != refund.finalized_height()
        || receipt_commitment != refund.receipt_commitment()
        || payment_finality_proof_commitment(finality) != refund.proof_commitment()
        || !verified_receipt
            .action_receipts()
            .iter()
            .any(|action| action.transaction_id() == refund.transaction())
    {
        return Err(VerifyError::RelationMismatch);
    }
    Ok(refund)
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
    use activechain_accumulator::{AccumulatorDomain, ReferenceSet};
    use activechain_action_kernel::ResourceVector;
    use activechain_application_primitives::{AnchorFinalizedEvidenceV1, DigestAnchorStatementV1};
    use activechain_authorization_kernel::AuthorizationEnvelope;
    use activechain_canonical_codec::encode_envelope;
    use activechain_cash_kernel::{
        CoinCell, CoinCellOrigin, CoinCellRecord, CoinCellSet, prove_coin_cell_membership,
    };
    use activechain_devnet_kernel::{ActionOutcome, ActionReceipt};
    use activechain_payment_types::{
        AssetAmountV1, PaymentFinalizedRefundV1, PaymentFinalizedSettlementV1, PaymentIntentId,
        PaymentRefundId, payment_finality_proof_commitment,
    };
    use activechain_policy_kernel::DecisionResult;
    use activechain_protocol_types::{
        ActionId, AssetId, AuthenticatorDescriptor, AuthenticatorPurpose, AuthenticatorSetV1,
        BoundedActionSet, CapabilityGrantFields, CapabilityId, CapabilityRevocationRegistryV1,
        ConsensusVoteContext, CryptoSuiteId, DataSelector, FreezeState, HolderBinding,
        ObjectFields, ObjectFlags, ObjectId, ObjectOwner, PrincipalId, PrincipalKind,
        ProtocolSignature, QuorumCertificate, ResourceSelector, TransactionId, ValidatorGenesis,
        ValidatorGenesisEntry, ValidatorVote,
    };
    use activechain_state_tree::{commit_objects, prove_object};
    use alloc::{vec, vec::Vec};
    use ml_dsa::{Keypair, MlDsa44, MlDsa65, Seed, Signer, SigningKey};

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
        wrong_version[2..4].copy_from_slice(&(CapabilityGrant::SCHEMA_VERSION + 1).to_be_bytes());
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
        cash_cell_root: Digest384,
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
            pre_cash_cell_root: cash_cell_root,
            cash_action_root: digest(50),
            cash_cell_root,
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
                digest(49),
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
                digest(49),
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
            digest(49),
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
            digest(50),
        )
    }

    #[test]
    fn finalized_principal_authenticator_binds_state_set_lifecycle_and_purpose() {
        let principal_id = PrincipalId::new(digest(70));
        let authenticator_id = AuthenticatorId::new(digest(71));
        let authenticator = AuthenticatorDescriptor::new(
            authenticator_id,
            CryptoSuiteId::ML_DSA_65,
            vec![72; CryptoSuiteId::ML_DSA_65.verification_key_length().unwrap()],
            AuthenticatorPurpose::Control,
            1,
            Some(12),
            None,
        )
        .unwrap();
        let set = AuthenticatorSetV1::new(vec![authenticator]).unwrap();
        let principal = Principal::new(
            principal_id,
            PrincipalKind::Organization,
            digest(73),
            digest(74),
            set.root().unwrap(),
            1,
            FreezeState::Active,
            digest(75),
            1,
            1,
            8,
        )
        .unwrap();
        let principal_value = encode_envelope(&principal).unwrap();
        let object = Object::new(ObjectFields {
            object_id: ObjectId::new(principal_id.into_digest()),
            object_version: 1,
            type_id: principal_registry_object_type(),
            owner: ObjectOwner::Principal(principal_id),
            control_policy_hash: digest(76),
            use_policy_hash: digest(77),
            disclosure_policy_hash: digest(78),
            upgrade_policy_hash: digest(79),
            package_id: None,
            value_root: commit_parts(PRINCIPAL_REGISTRY_OBJECT_VALUE_DOMAIN, &[&principal_value]),
            public_value: Some(principal_value),
            lease_expiry_epoch: 10,
            storage_deposit: 1,
            flags: ObjectFlags::SYSTEM,
        })
        .unwrap();
        let objects = vec![object.clone()];
        let proof = encode_envelope(&prove_object(&objects, object.object_id()).unwrap()).unwrap();
        let object_bytes = encode_envelope(&object).unwrap();
        let set_bytes = encode_envelope(&set).unwrap();
        let bundle = finality_bundle_with_inputs(
            digest(47),
            StateCommitment::new(digest(42), 0),
            commit_objects(&objects).unwrap(),
            digest(50),
        );
        let trusted_genesis = bundle.validator_genesis().genesis_commitment();
        let finality = encode_envelope(&bundle).unwrap();

        assert_eq!(
            verify_finalized_principal_authenticator_code(
                &object_bytes,
                &proof,
                &set_bytes,
                &finality,
                trusted_genesis,
                principal_id,
                authenticator_id,
                AuthenticatorPurpose::Control,
            ),
            VERIFY_OK
        );
        assert_eq!(
            verify_finalized_principal_authenticator_code(
                &object_bytes,
                &proof,
                &set_bytes,
                &finality,
                trusted_genesis,
                principal_id,
                authenticator_id,
                AuthenticatorPurpose::Session,
            ),
            VerifyError::RelationMismatch.code()
        );
        assert_eq!(
            verify_finalized_principal_authenticator_code(
                &object_bytes,
                &proof,
                &set_bytes,
                &finality,
                trusted_genesis,
                PrincipalId::new(digest(80)),
                authenticator_id,
                AuthenticatorPurpose::Control,
            ),
            VerifyError::RelationMismatch.code()
        );
        let mut substituted_set = set_bytes.clone();
        substituted_set[70] ^= 1;
        assert_eq!(
            verify_finalized_principal_authenticator_code(
                &object_bytes,
                &proof,
                &substituted_set,
                &finality,
                trusted_genesis,
                principal_id,
                authenticator_id,
                AuthenticatorPurpose::Control,
            ),
            VerifyError::RelationMismatch.code()
        );
        assert_eq!(
            verify_finalized_principal_authenticator_code(
                &object_bytes,
                &proof,
                &set_bytes,
                &finality,
                digest(81),
                principal_id,
                authenticator_id,
                AuthenticatorPurpose::Control,
            ),
            VerifyError::RelationMismatch.code()
        );
        let mut trailing_object = object_bytes;
        trailing_object.push(0);
        assert_eq!(
            verify_finalized_principal_authenticator_code(
                &trailing_object,
                &proof,
                &set_bytes,
                &finality,
                trusted_genesis,
                principal_id,
                authenticator_id,
                AuthenticatorPurpose::Control,
            ),
            VerifyError::Decode(DecodeError::TrailingData { remaining: 1 }).code()
        );
    }

    #[test]
    fn signed_authorization_chain_joins_real_signatures_to_finalized_controllers() {
        let actor_id = PrincipalId::new(digest(90));
        let root_issuer = PrincipalId::new(digest(91));
        let child_issuer = PrincipalId::new(digest(92));
        let actor_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([90; 32]));
        let root_key = SigningKey::<MlDsa65>::from_seed(&Seed::from([91; 32]));
        let child_key = SigningKey::<MlDsa65>::from_seed(&Seed::from([92; 32]));

        let identity = |principal_id: PrincipalId,
                        authenticator_id: AuthenticatorId,
                        suite: CryptoSuiteId,
                        key: Vec<u8>,
                        purpose: AuthenticatorPurpose| {
            let authenticator = AuthenticatorDescriptor::new(
                authenticator_id,
                suite,
                key,
                purpose,
                1,
                Some(12),
                None,
            )
            .unwrap();
            let set = AuthenticatorSetV1::new(vec![authenticator]).unwrap();
            let principal = Principal::new(
                principal_id,
                PrincipalKind::Organization,
                digest(93),
                digest(94),
                set.root().unwrap(),
                1,
                FreezeState::Active,
                digest(95),
                1,
                1,
                8,
            )
            .unwrap();
            let value = encode_envelope(&principal).unwrap();
            let object = Object::new(ObjectFields {
                object_id: ObjectId::new(principal_id.into_digest()),
                object_version: 1,
                type_id: principal_registry_object_type(),
                owner: ObjectOwner::Principal(principal_id),
                control_policy_hash: digest(96),
                use_policy_hash: digest(97),
                disclosure_policy_hash: digest(98),
                upgrade_policy_hash: digest(99),
                package_id: None,
                value_root: commit_parts(PRINCIPAL_REGISTRY_OBJECT_VALUE_DOMAIN, &[&value]),
                public_value: Some(value),
                lease_expiry_epoch: 10,
                storage_deposit: 1,
                flags: ObjectFlags::SYSTEM,
            })
            .unwrap();
            (object, set, authenticator_id)
        };
        let identities = [
            identity(
                actor_id,
                AuthenticatorId::new(digest(100)),
                CryptoSuiteId::ML_DSA_44,
                actor_key.verifying_key().encode().to_vec(),
                AuthenticatorPurpose::Session,
            ),
            identity(
                root_issuer,
                AuthenticatorId::new(digest(101)),
                CryptoSuiteId::ML_DSA_65,
                root_key.verifying_key().encode().to_vec(),
                AuthenticatorPurpose::Control,
            ),
            identity(
                child_issuer,
                AuthenticatorId::new(digest(102)),
                CryptoSuiteId::ML_DSA_65,
                child_key.verifying_key().encode().to_vec(),
                AuthenticatorPurpose::Control,
            ),
        ];
        let registry_id = ObjectId::new(digest(108));
        let make_registry_object = |registry: CapabilityRevocationRegistryV1| {
            let value = encode_envelope(&registry).unwrap();
            Object::new(ObjectFields {
                object_id: registry_id,
                object_version: 1,
                type_id: commit_parts(
                    b"ACTIVECHAIN-CAPABILITY-REVOCATION-OBJECT-TYPE-V1",
                    &[
                        &CapabilityRevocationRegistryV1::TYPE_TAG.to_be_bytes(),
                        &CapabilityRevocationRegistryV1::SCHEMA_VERSION.to_be_bytes(),
                    ],
                ),
                owner: ObjectOwner::Shared,
                control_policy_hash: digest(109),
                use_policy_hash: digest(110),
                disclosure_policy_hash: digest(111),
                upgrade_policy_hash: digest(112),
                package_id: None,
                value_root: commit_parts(
                    b"ACTIVECHAIN-CAPABILITY-REVOCATION-OBJECT-VALUE-V1",
                    &[&value],
                ),
                public_value: Some(value),
                lease_expiry_epoch: 10,
                storage_deposit: 1,
                flags: ObjectFlags::SYSTEM,
            })
            .unwrap()
        };
        let revocations = ReferenceSet::new(AccumulatorDomain::Revocation);
        let commitment = revocations.commitment();
        let registry =
            CapabilityRevocationRegistryV1::new(Digest384::new(commitment.root), commitment.count)
                .unwrap();
        let registry_object = make_registry_object(registry);
        let mut objects = identities.iter().map(|entry| entry.0.clone()).collect::<Vec<_>>();
        objects.push(registry_object.clone());
        let state = commit_objects(&objects).unwrap();
        let provisional = finality_bundle_with_inputs(
            digest(47),
            StateCommitment::new(digest(42), 0),
            state,
            digest(50),
        );
        let genesis = provisional.validator_genesis().genesis_commitment();
        let unsigned_capability = |id: u8,
                                   issuer: PrincipalId,
                                   holder: PrincipalId,
                                   parent: Option<u8>,
                                   depth: u8,
                                   allowed: bool| {
            CapabilityGrant::new(
                CapabilityGrantFields {
                    capability_id: CapabilityId::new(digest(id)),
                    issuer,
                    holder_binding: HolderBinding::Principal(holder),
                    parent_capability: parent.map(|value| CapabilityId::new(digest(value))),
                    permitted_actions: BoundedActionSet::new(vec![ActionId::new(digest(1))])
                        .unwrap(),
                    resource_scope: ResourceSelector::ANY,
                    data_scope: DataSelector::ANY,
                    monetary_limit: Some(100),
                    compute_limit: Some(100),
                    rate_limit: None,
                    use_limit: Some(10),
                    valid_from: 1,
                    valid_until: Some(12),
                    delegation_depth_remaining: depth,
                    delegation_allowed: allowed,
                    revocation_registry: Some(registry_id),
                    constraint_hash: digest(103),
                },
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, vec![0; 3_309]).unwrap(),
            )
            .unwrap()
        };
        let sign_capability = |unsigned: CapabilityGrant, key: &SigningKey<MlDsa65>| {
            let signature = key.sign(&unsigned.signing_payload(genesis).unwrap());
            CapabilityGrant::new(
                unsigned.fields().clone(),
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, signature.encode().to_vec())
                    .unwrap(),
            )
            .unwrap()
        };
        // The root id deliberately sorts AFTER the child id, so the chain's delegation order
        // ([105, 104]) differs from the strictly ascending order an AuthorizationEnvelope
        // requires. Verification must compare on the envelope's canonical order; comparing in
        // delegation order rejects this correct chain.
        let root = sign_capability(
            unsigned_capability(105, root_issuer, child_issuer, None, 1, true),
            &root_key,
        );
        let child = sign_capability(
            unsigned_capability(104, child_issuer, actor_id, Some(105), 0, false),
            &child_key,
        );
        let root_authenticator = AuthenticatorDescriptor::new(
            AuthenticatorId::new(digest(101)),
            CryptoSuiteId::ML_DSA_65,
            root_key.verifying_key().encode().to_vec(),
            AuthenticatorPurpose::Control,
            1,
            Some(12),
            None,
        )
        .unwrap();
        assert!(signed_authorization::verify_signature(
            root_authenticator.clone(),
            root.issuer_signature(),
            &root.signing_payload(genesis).unwrap(),
        ));
        assert!(!signed_authorization::verify_signature(
            root_authenticator,
            root.issuer_signature(),
            &root.signing_payload(digest(0xee)).unwrap(),
        ));
        let chain = AuthorizationChain::new(actor_id, 9, vec![root, child]).unwrap();
        let mut capability_ids = chain
            .capabilities()
            .iter()
            .map(|capability| capability.fields().capability_id)
            .collect::<Vec<_>>();
        capability_ids.sort_unstable();
        let unsigned_envelope = AuthorizationEnvelope::new(
            digest(106),
            genesis,
            3,
            actor_id,
            9,
            1,
            state.root(),
            digest(107),
            1,
            1,
            FreezeState::Active,
            None,
            vec![],
            vec![],
            capability_ids.clone(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        let actor_signature = actor_key.sign(&unsigned_envelope.signing_payload().unwrap());
        let envelope = AuthorizationEnvelope::new(
            digest(106),
            genesis,
            3,
            actor_id,
            9,
            1,
            state.root(),
            digest(107),
            1,
            1,
            FreezeState::Active,
            None,
            vec![],
            vec![],
            capability_ids,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, actor_signature.encode().to_vec())
                .unwrap(),
        )
        .unwrap();
        let controllers = [0_usize, 1, 2]
            .into_iter()
            .map(|index| {
                AuthorizationControllerWitnessV1::new(
                    encode_envelope(&identities[index].0).unwrap(),
                    encode_envelope(
                        &prove_object(&objects, identities[index].0.object_id()).unwrap(),
                    )
                    .unwrap(),
                    encode_envelope(&identities[index].1).unwrap(),
                    identities[index].2,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let revocation_witness =
            |registry_object: &Object, objects: &[Object], revocations: &ReferenceSet| {
                let proofs = [104_u8, 105]
                    .into_iter()
                    .map(|id| {
                        let capability_id = CapabilityId::new(digest(id));
                        let proof = revocations
                            .non_membership_witness(capability_id.into_digest().into_bytes())
                            .unwrap();
                        CapabilityNonRevocationProofV1::new(
                            capability_id,
                            proof.siblings.into_iter().map(Digest384::new).collect(),
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>();
                CapabilityRevocationWitnessV1::new(
                    encode_envelope(registry_object).unwrap(),
                    encode_envelope(&prove_object(objects, registry_id).unwrap()).unwrap(),
                    proofs,
                )
                .unwrap()
            };
        let witness = revocation_witness(&registry_object, &objects, &revocations);
        let signed = SignedAuthorizationChainV1::new(
            encode_envelope(&envelope).unwrap(),
            chain.clone(),
            controllers.clone(),
            Some(witness),
        )
        .unwrap();
        let signed_bytes = encode_envelope(&signed).unwrap();
        let finality = encode_envelope(&provisional).unwrap();
        assert_eq!(verify_signed_authorization_chain(&signed_bytes, &finality, genesis), Ok(()));

        let missing = SignedAuthorizationChainV1::new(
            encode_envelope(&envelope).unwrap(),
            chain.clone(),
            controllers.clone(),
            None,
        )
        .unwrap();
        assert_eq!(
            verify_signed_authorization_chain(
                &encode_envelope(&missing).unwrap(),
                &finality,
                genesis,
            ),
            Err(VerifyError::RelationMismatch)
        );

        let substituted_witness = CapabilityRevocationWitnessV1::new(
            encode_envelope(&identities[0].0).unwrap(),
            encode_envelope(&prove_object(&objects, identities[0].0.object_id()).unwrap()).unwrap(),
            [104_u8, 105]
                .into_iter()
                .map(|id| {
                    let capability_id = CapabilityId::new(digest(id));
                    let proof = revocations
                        .non_membership_witness(capability_id.into_digest().into_bytes())
                        .unwrap();
                    CapabilityNonRevocationProofV1::new(
                        capability_id,
                        proof.siblings.into_iter().map(Digest384::new).collect(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let substituted = SignedAuthorizationChainV1::new(
            encode_envelope(&envelope).unwrap(),
            chain.clone(),
            controllers.clone(),
            Some(substituted_witness),
        )
        .unwrap();
        assert!(
            verify_signed_authorization_chain(
                &encode_envelope(&substituted).unwrap(),
                &finality,
                genesis,
            )
            .is_err()
        );

        let mut malformed = signed_bytes.clone();
        malformed.pop();
        assert!(verify_signed_authorization_chain(&malformed, &finality, genesis).is_err());

        let mut stale_revocations = ReferenceSet::new(AccumulatorDomain::Revocation);
        stale_revocations.insert(digest(0xaa).into_bytes()).unwrap();
        let stale_commitment = stale_revocations.commitment();
        let stale_registry = make_registry_object(
            CapabilityRevocationRegistryV1::new(
                Digest384::new(stale_commitment.root),
                stale_commitment.count,
            )
            .unwrap(),
        );
        let stale = SignedAuthorizationChainV1::new(
            encode_envelope(&envelope).unwrap(),
            chain.clone(),
            controllers.clone(),
            Some(revocation_witness(&stale_registry, &objects, &revocations)),
        )
        .unwrap();
        assert!(
            verify_signed_authorization_chain(
                &encode_envelope(&stale).unwrap(),
                &finality,
                genesis,
            )
            .is_err()
        );

        let mut revoked = ReferenceSet::new(AccumulatorDomain::Revocation);
        let stale_child_witness = revoked
            .non_membership_witness(CapabilityId::new(digest(104)).into_digest().into_bytes())
            .unwrap();
        revoked.insert(CapabilityId::new(digest(104)).into_digest().into_bytes()).unwrap();
        let revoked_commitment = revoked.commitment();
        let revoked_object = make_registry_object(
            CapabilityRevocationRegistryV1::new(
                Digest384::new(revoked_commitment.root),
                revoked_commitment.count,
            )
            .unwrap(),
        );
        let mut revoked_objects =
            identities.iter().map(|entry| entry.0.clone()).collect::<Vec<_>>();
        revoked_objects.push(revoked_object.clone());
        let revoked_state = commit_objects(&revoked_objects).unwrap();
        let revoked_finality = finality_bundle_with_inputs(
            digest(47),
            StateCommitment::new(digest(42), 0),
            revoked_state,
            digest(50),
        );
        let revoked_unsigned_envelope = AuthorizationEnvelope::new(
            digest(106),
            genesis,
            3,
            actor_id,
            9,
            1,
            revoked_state.root(),
            digest(107),
            1,
            1,
            FreezeState::Active,
            None,
            vec![],
            vec![],
            vec![CapabilityId::new(digest(104)), CapabilityId::new(digest(105))],
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        let revoked_actor_signature =
            actor_key.sign(&revoked_unsigned_envelope.signing_payload().unwrap());
        let revoked_envelope = AuthorizationEnvelope::new(
            digest(106),
            genesis,
            3,
            actor_id,
            9,
            1,
            revoked_state.root(),
            digest(107),
            1,
            1,
            FreezeState::Active,
            None,
            vec![],
            vec![],
            vec![CapabilityId::new(digest(104)), CapabilityId::new(digest(105))],
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                revoked_actor_signature.encode().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let child_proof = CapabilityNonRevocationProofV1::new(
            CapabilityId::new(digest(104)),
            stale_child_witness.siblings.into_iter().map(Digest384::new).collect(),
        )
        .unwrap();
        let root_id = CapabilityId::new(digest(105));
        let root_proof =
            revoked.non_membership_witness(root_id.into_digest().into_bytes()).unwrap();
        let revoked_witness = CapabilityRevocationWitnessV1::new(
            encode_envelope(&revoked_object).unwrap(),
            encode_envelope(&prove_object(&revoked_objects, registry_id).unwrap()).unwrap(),
            vec![
                child_proof,
                CapabilityNonRevocationProofV1::new(
                    root_id,
                    root_proof.siblings.into_iter().map(Digest384::new).collect(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let revoked_controllers = [0_usize, 1, 2]
            .into_iter()
            .map(|index| {
                AuthorizationControllerWitnessV1::new(
                    encode_envelope(&identities[index].0).unwrap(),
                    encode_envelope(
                        &prove_object(&revoked_objects, identities[index].0.object_id()).unwrap(),
                    )
                    .unwrap(),
                    encode_envelope(&identities[index].1).unwrap(),
                    identities[index].2,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let revoked_signed = SignedAuthorizationChainV1::new(
            encode_envelope(&revoked_envelope).unwrap(),
            chain,
            revoked_controllers,
            Some(revoked_witness),
        )
        .unwrap();
        assert!(
            verify_signed_authorization_chain(
                &encode_envelope(&revoked_signed).unwrap(),
                &encode_envelope(&revoked_finality).unwrap(),
                revoked_finality.validator_genesis().genesis_commitment(),
            )
            .is_err()
        );
    }

    #[test]
    fn owner_coin_cell_verifier_binds_owner_key_height_root_and_genesis() {
        let owner = PrincipalId::new(digest(60));
        let origin = CoinCellOrigin::new(TransactionId::new(digest(62)), 0);
        let record = CoinCellRecord::new(
            activechain_protocol_commitment::coin_cell_id(&origin).unwrap(),
            CoinCell::new(origin, owner, 25, 1).unwrap(),
        );
        let cells = CoinCellSet::new(vec![record]).unwrap();
        let membership = prove_coin_cell_membership(&cells, record.id()).unwrap();
        let bundle = finality_bundle_with_inputs(
            digest(47),
            StateCommitment::new(digest(42), 0),
            StateCommitment::new(digest(46), 0),
            membership.root().into_digest(),
        );
        let trusted_genesis = bundle.validator_genesis().genesis_commitment();
        let value = encode_envelope(&record).unwrap();
        let proof = encode_envelope(&membership).unwrap();
        let finality = encode_envelope(&bundle).unwrap();

        assert_eq!(
            verify_owner_coin_cell_record_code(
                record.id().into_digest(),
                9,
                &value,
                &proof,
                &finality,
                owner,
                trusted_genesis,
            ),
            VERIFY_OK
        );
        for result in [
            verify_owner_coin_cell_record_code(
                digest(63),
                9,
                &value,
                &proof,
                &finality,
                owner,
                trusted_genesis,
            ),
            verify_owner_coin_cell_record_code(
                record.id().into_digest(),
                10,
                &value,
                &proof,
                &finality,
                owner,
                trusted_genesis,
            ),
            verify_owner_coin_cell_record_code(
                record.id().into_digest(),
                9,
                &value,
                &proof,
                &finality,
                PrincipalId::new(digest(64)),
                trusted_genesis,
            ),
            verify_owner_coin_cell_record_code(
                record.id().into_digest(),
                9,
                &value,
                &proof,
                &finality,
                owner,
                digest(65),
            ),
        ] {
            assert_ne!(result, VERIFY_OK);
        }
    }

    #[test]
    fn nft_state_verifier_binds_kind_value_membership_height_and_genesis() {
        let asset = AssetId::new(digest(70));
        let series =
            NonFungibleSeriesV1::new(asset, PrincipalId::new(digest(71)), 10, 1, digest(72))
                .unwrap();
        let registry = NonFungibleTokenRegistryV1::new(asset, vec![digest(73)]).unwrap();
        for (index, (query_kind, type_tag, public_value)) in [
            (
                NFT_SERIES_QUERY_KIND,
                NonFungibleSeriesV1::TYPE_TAG,
                encode_envelope(&series).unwrap(),
            ),
            (
                NFT_TOKEN_REGISTRY_QUERY_KIND,
                NonFungibleTokenRegistryV1::TYPE_TAG,
                encode_envelope(&registry).unwrap(),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let kind = [query_kind];
            let tag = type_tag.to_be_bytes();
            let object = Object::new(ObjectFields {
                object_id: ObjectId::new(digest(74 + index as u8)),
                object_version: 1,
                type_id: commit_parts(b"ACTIVECHAIN-NATIVE-ASSET-RPC-TYPE-V1", &[&kind, &tag]),
                owner: ObjectOwner::Immutable,
                control_policy_hash: digest(76),
                use_policy_hash: digest(77),
                disclosure_policy_hash: digest(78),
                upgrade_policy_hash: digest(79),
                package_id: None,
                value_root: commit_parts(
                    b"ACTIVECHAIN-NATIVE-ASSET-RPC-VALUE-V1",
                    &[&public_value],
                ),
                public_value: Some(public_value),
                lease_expiry_epoch: 10,
                storage_deposit: 5,
                flags: ObjectFlags::NONE,
            })
            .unwrap();
            let objects = vec![object.clone()];
            let post_state = commit_objects(&objects).unwrap();
            let proof =
                encode_envelope(&prove_object(&objects, object.object_id()).unwrap()).unwrap();
            let bundle = finality_bundle_with_inputs(
                digest(47),
                StateCommitment::new(digest(42), 0),
                post_state,
                digest(50),
            );
            let trusted_genesis = bundle.validator_genesis().genesis_commitment();
            let value = encode_envelope(&object).unwrap();
            let finality = encode_envelope(&bundle).unwrap();
            assert_eq!(
                verify_nft_state_record_code(
                    query_kind,
                    object.object_id().into_digest(),
                    9,
                    &value,
                    &proof,
                    &finality,
                    trusted_genesis,
                ),
                VERIFY_OK
            );
            for result in [
                verify_nft_state_record_code(
                    if query_kind == NFT_SERIES_QUERY_KIND {
                        NFT_TOKEN_REGISTRY_QUERY_KIND
                    } else {
                        NFT_SERIES_QUERY_KIND
                    },
                    object.object_id().into_digest(),
                    9,
                    &value,
                    &proof,
                    &finality,
                    trusted_genesis,
                ),
                verify_nft_state_record_code(
                    query_kind,
                    digest(80),
                    9,
                    &value,
                    &proof,
                    &finality,
                    trusted_genesis,
                ),
                verify_nft_state_record_code(
                    query_kind,
                    object.object_id().into_digest(),
                    10,
                    &value,
                    &proof,
                    &finality,
                    trusted_genesis,
                ),
                verify_nft_state_record_code(
                    query_kind,
                    object.object_id().into_digest(),
                    9,
                    &value,
                    &proof,
                    &finality,
                    digest(81),
                ),
            ] {
                assert_ne!(result, VERIFY_OK);
            }
        }
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
        let receipt =
            BlockReceipt::new(digest(62), 9, pre_state, post_state, digest(64), digest(65), vec![])
                .unwrap();
        let receipt_root = commit(DomainTag::CANONICAL_VALUE, &receipt).unwrap();
        let finality = encode_envelope(&finality_bundle_with_inputs(
            receipt_root,
            pre_state,
            post_state,
            digest(50),
        ))
        .unwrap();
        let encoded = encode_envelope(&receipt).unwrap();
        assert_eq!(verify_block_receipt_code(&finality, &encoded), VERIFY_OK);
        assert_eq!(verify_block_receipt(&finality, &encoded), Ok(receipt.clone()));

        let substituted = encode_envelope(
            &BlockReceipt::new(
                digest(63),
                9,
                pre_state,
                post_state,
                digest(64),
                digest(65),
                vec![],
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_block_receipt_code(&finality, &substituted),
            VerifyError::RelationMismatch.code()
        );
        let wrong_height = encode_envelope(
            &BlockReceipt::new(
                digest(62),
                10,
                pre_state,
                post_state,
                digest(64),
                digest(65),
                vec![],
            )
            .unwrap(),
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
        wrong_version[3] = 3;
        assert_eq!(
            verify_block_receipt_code(&finality, &wrong_version),
            VerifyError::VersionMismatch.code()
        );
    }

    #[test]
    fn payment_settlement_verifier_binds_finality_receipt_and_action_transaction() {
        let pre_state = StateCommitment::new(digest(60), 2);
        let post_state = StateCommitment::new(digest(61), 3);
        let transaction = TransactionId::new(digest(70));
        let receipt = BlockReceipt::new(
            digest(62),
            9,
            pre_state,
            post_state,
            digest(64),
            digest(65),
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
        let receipt_commitment = commit(DomainTag::CANONICAL_VALUE, &receipt).unwrap();
        let bundle =
            finality_bundle_with_inputs(receipt_commitment, pre_state, post_state, digest(50));
        let trusted_genesis = bundle.validator_genesis().genesis_commitment();
        let finality = encode_envelope(&bundle).unwrap();
        let receipt_bytes = encode_envelope(&receipt).unwrap();
        let settlement = PaymentFinalizedSettlementV1::new(
            PaymentIntentId::new(digest(71)).unwrap(),
            transaction,
            AssetAmountV1::new(AssetId::new(digest(72)), 95).unwrap(),
            9,
            receipt.block_id(),
            receipt_commitment,
            payment_finality_proof_commitment(&finality),
        )
        .unwrap();
        let encoded = encode_envelope(&settlement).unwrap();
        assert_eq!(
            verify_payment_finalized_settlement(
                &encoded,
                &finality,
                &receipt_bytes,
                trusted_genesis,
            ),
            Ok(settlement)
        );

        let wrong_proof = PaymentFinalizedSettlementV1::new(
            settlement.intent(),
            transaction,
            settlement.settled_amount(),
            9,
            receipt.block_id(),
            receipt_commitment,
            digest(73),
        )
        .unwrap();
        assert_eq!(
            verify_payment_finalized_settlement(
                &encode_envelope(&wrong_proof).unwrap(),
                &finality,
                &receipt_bytes,
                trusted_genesis,
            ),
            Err(VerifyError::RelationMismatch)
        );
        let wrong_transaction = PaymentFinalizedSettlementV1::new(
            settlement.intent(),
            TransactionId::new(digest(74)),
            settlement.settled_amount(),
            9,
            receipt.block_id(),
            receipt_commitment,
            payment_finality_proof_commitment(&finality),
        )
        .unwrap();
        assert_eq!(
            verify_payment_finalized_settlement(
                &encode_envelope(&wrong_transaction).unwrap(),
                &finality,
                &receipt_bytes,
                trusted_genesis,
            ),
            Err(VerifyError::RelationMismatch)
        );
    }

    #[test]
    fn payment_refund_verifier_binds_finality_receipt_and_action_transaction() {
        let pre_state = StateCommitment::new(digest(80), 2);
        let post_state = StateCommitment::new(digest(81), 3);
        let transaction = TransactionId::new(digest(82));
        let receipt = BlockReceipt::new(
            digest(83),
            9,
            pre_state,
            post_state,
            digest(84),
            digest(85),
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
        let receipt_commitment = commit(DomainTag::CANONICAL_VALUE, &receipt).unwrap();
        let bundle =
            finality_bundle_with_inputs(receipt_commitment, pre_state, post_state, digest(50));
        let trusted_genesis = bundle.validator_genesis().genesis_commitment();
        let finality = encode_envelope(&bundle).unwrap();
        let receipt_bytes = encode_envelope(&receipt).unwrap();
        let refund = PaymentFinalizedRefundV1::new(
            PaymentRefundId::new(digest(86)).unwrap(),
            PaymentIntentId::new(digest(87)).unwrap(),
            digest(88),
            AssetAmountV1::new(AssetId::new(digest(89)), 95).unwrap(),
            transaction,
            9,
            receipt.block_id(),
            receipt_commitment,
            payment_finality_proof_commitment(&finality),
        )
        .unwrap();
        assert_eq!(
            verify_payment_finalized_refund(
                &encode_envelope(&refund).unwrap(),
                &finality,
                &receipt_bytes,
                trusted_genesis,
            ),
            Ok(refund)
        );
        let substituted = PaymentFinalizedRefundV1::new(
            refund.refund(),
            refund.intent(),
            refund.settlement_commitment(),
            refund.refunded_amount(),
            TransactionId::new(digest(90)),
            9,
            receipt.block_id(),
            receipt_commitment,
            payment_finality_proof_commitment(&finality),
        )
        .unwrap();
        assert_eq!(
            verify_payment_finalized_refund(
                &encode_envelope(&substituted).unwrap(),
                &finality,
                &receipt_bytes,
                trusted_genesis,
            ),
            Err(VerifyError::RelationMismatch)
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
            digest(64),
            digest(65),
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
        let finality_bundle =
            finality_bundle_with_inputs(receipt_root, pre_state, post_state, digest(50));
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
