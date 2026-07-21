#![no_std]
#![forbid(unsafe_code)]

//! Bounded canonical statements for ActiveChain's fixed privacy profiles.
//!
//! This crate does not implement a proof system and makes no privacy claim. It defines the
//! consensus-facing values a proof verifier must bind and a fail-closed state transition over
//! preverified evidence. Proof verification remains an explicit caller responsibility.

extern crate alloc;

mod builder;
mod protected;

pub use builder::{
    BondSettlement, BuilderAuction, BuilderBid, BuilderOutcome, BuilderSettlementError,
    MAX_BUILDER_BIDS,
};

pub use protected::{
    CommitteeKind, MAX_COMMITTEE_MEMBERS, MAX_ORDERING_ITEMS, OrderingError, ProtectedCommittee,
    ProtectedEnvelope, ProtectedOrdering,
};

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{AssetId, ChainId, CoinCellId, Digest384, PrincipalId};
use alloc::vec::Vec;

/// Maximum inputs or outputs in one shielded transfer.
pub const MAX_SHIELDED_ITEMS: usize = 16;
/// Maximum nullifiers retained by this bounded reference state.
pub const MAX_SPENT_NULLIFIERS: usize = 4_096;
/// Maximum explicitly disclosed field identifiers in one capability.
pub const MAX_DISCLOSED_FIELDS: usize = 64;

/// Semantic rejection at the privacy admission boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyError {
    EmptyTransfer,
    TooManyItems,
    ZeroValue,
    InvalidValidityWindow,
    InvalidViewingScope,
    NonCanonicalOrder,
    DuplicateNullifier,
    NullifierAlreadySpent,
    NullifierCapacityExceeded,
    WrongChain,
    WrongAnchor,
    Expired,
    PublicInputMismatch,
    ProofNotVerified,
    CommitmentEncoding,
    ScopeEscalation,
}

fn map_decode<T>(result: Result<T, PrivacyError>) -> Result<T, DecodeError> {
    result.map_err(|_| DecodeError::InvalidValue("invalid privacy value"))
}

/// Private opening committed by a shielded output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShieldedNote {
    chain_id: ChainId,
    asset_id: AssetId,
    owner_key: Digest384,
    value: u128,
    blinding: Digest384,
    rho: Digest384,
}

impl ShieldedNote {
    pub const TYPE_TAG: u16 = 0x00a0;

    pub fn new(
        chain_id: ChainId,
        asset_id: AssetId,
        owner_key: Digest384,
        value: u128,
        blinding: Digest384,
        rho: Digest384,
    ) -> Result<Self, PrivacyError> {
        if value == 0 {
            return Err(PrivacyError::ZeroValue);
        }
        Ok(Self { chain_id, asset_id, owner_key, value, blinding, rho })
    }

    pub fn commitment(&self) -> Result<Digest384, PrivacyError> {
        commit(DomainTag::SHIELDED_NOTE, self).map_err(|_| PrivacyError::CommitmentEncoding)
    }
}

impl CanonicalEncode for ShieldedNote {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.asset_id.encode(e)?;
        self.owner_key.encode(e)?;
        self.value.encode(e)?;
        self.blinding.encode(e)?;
        self.rho.encode(e)
    }
}

impl CanonicalDecode for ShieldedNote {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        map_decode(Self::new(
            ChainId::decode(d)?,
            AssetId::decode(d)?,
            Digest384::decode(d)?,
            u128::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
        ))
    }
}

impl CanonicalType for ShieldedNote {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 5 + 16;
}

/// Secret material whose commitment is revealed once when a note is consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NullifierOpening {
    chain_id: ChainId,
    note_commitment: Digest384,
    nullifier_key: Digest384,
    note_position: u64,
}

impl NullifierOpening {
    pub const TYPE_TAG: u16 = 0x00a1;

    #[must_use]
    pub const fn new(
        chain_id: ChainId,
        note_commitment: Digest384,
        nullifier_key: Digest384,
        note_position: u64,
    ) -> Self {
        Self { chain_id, note_commitment, nullifier_key, note_position }
    }

    pub fn nullifier(&self) -> Result<Digest384, PrivacyError> {
        commit(DomainTag::NULLIFIER, self).map_err(|_| PrivacyError::CommitmentEncoding)
    }
}

impl CanonicalEncode for NullifierOpening {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.note_commitment.encode(e)?;
        self.nullifier_key.encode(e)?;
        self.note_position.encode(e)
    }
}

impl CanonicalDecode for NullifierOpening {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
        ))
    }
}

impl CanonicalType for NullifierOpening {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 4 + 8;
}

/// Explicitly scoped capability for decrypting note metadata off chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ViewingCapability {
    chain_id: ChainId,
    asset_id: AssetId,
    viewer: PrincipalId,
    viewing_key_commitment: Digest384,
    scope_commitment: Digest384,
    not_before: u64,
    expires_at: u64,
}

impl ViewingCapability {
    pub const TYPE_TAG: u16 = 0x00a2;

    pub fn new(
        chain_id: ChainId,
        asset_id: AssetId,
        viewer: PrincipalId,
        viewing_key_commitment: Digest384,
        scope_commitment: Digest384,
        not_before: u64,
        expires_at: u64,
    ) -> Result<Self, PrivacyError> {
        if not_before > expires_at {
            return Err(PrivacyError::InvalidValidityWindow);
        }
        if scope_commitment == Digest384::new([0; 48]) {
            return Err(PrivacyError::InvalidViewingScope);
        }
        Ok(Self {
            chain_id,
            asset_id,
            viewer,
            viewing_key_commitment,
            scope_commitment,
            not_before,
            expires_at,
        })
    }

    #[must_use]
    pub fn is_valid_at(&self, height: u64) -> bool {
        self.not_before <= height && height <= self.expires_at
    }
}

impl CanonicalEncode for ViewingCapability {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.asset_id.encode(e)?;
        self.viewer.encode(e)?;
        self.viewing_key_commitment.encode(e)?;
        self.scope_commitment.encode(e)?;
        self.not_before.encode(e)?;
        self.expires_at.encode(e)
    }
}

impl CanonicalDecode for ViewingCapability {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        map_decode(Self::new(
            ChainId::decode(d)?,
            AssetId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        ))
    }
}

impl CanonicalType for ViewingCapability {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 5 + 16;
}

/// Private opening for an unlinkable-by-construction, domain-scoped holder pseudonym.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainPseudonymOpening {
    chain_id: ChainId,
    domain: Digest384,
    holder_secret_commitment: Digest384,
    epoch: u64,
}

impl DomainPseudonymOpening {
    pub const TYPE_TAG: u16 = 0x00a8;

    pub fn new(
        chain_id: ChainId,
        domain: Digest384,
        holder_secret_commitment: Digest384,
        epoch: u64,
    ) -> Result<Self, PrivacyError> {
        if domain == Digest384::ZERO || holder_secret_commitment == Digest384::ZERO {
            return Err(PrivacyError::InvalidViewingScope);
        }
        Ok(Self { chain_id, domain, holder_secret_commitment, epoch })
    }

    pub fn pseudonym(&self) -> Result<Digest384, PrivacyError> {
        commit(DomainTag::DOMAIN_PSEUDONYM, self).map_err(|_| PrivacyError::CommitmentEncoding)
    }
}

impl CanonicalEncode for DomainPseudonymOpening {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.domain.encode(e)?;
        self.holder_secret_commitment.encode(e)?;
        self.epoch.encode(e)
    }
}

impl CanonicalDecode for DomainPseudonymOpening {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        map_decode(Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
        ))
    }
}

impl CanonicalType for DomainPseudonymOpening {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 3 + 8;
}

/// Public statement for a zero-knowledge credential presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateCredentialPresentation {
    chain_id: ChainId,
    domain: Digest384,
    pseudonym: Digest384,
    issuer: PrincipalId,
    schema: Digest384,
    credential_commitment: Digest384,
    status_registry_root: Digest384,
    status_sequence: u64,
    status_effective_height: u64,
    maximum_status_age: u64,
    non_revocation_commitment: Digest384,
    predicate_commitment: Digest384,
    expires_at: u64,
}

impl PrivateCredentialPresentation {
    pub const TYPE_TAG: u16 = 0x00a9;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        domain: Digest384,
        pseudonym: Digest384,
        issuer: PrincipalId,
        schema: Digest384,
        credential_commitment: Digest384,
        status_registry_root: Digest384,
        status_sequence: u64,
        status_effective_height: u64,
        maximum_status_age: u64,
        non_revocation_commitment: Digest384,
        predicate_commitment: Digest384,
        expires_at: u64,
    ) -> Result<Self, PrivacyError> {
        if domain == Digest384::ZERO
            || pseudonym == Digest384::ZERO
            || status_registry_root == Digest384::ZERO
            || non_revocation_commitment == Digest384::ZERO
            || predicate_commitment == Digest384::ZERO
        {
            return Err(PrivacyError::InvalidViewingScope);
        }
        if status_sequence == 0 || maximum_status_age == 0 || status_effective_height > expires_at {
            return Err(PrivacyError::InvalidValidityWindow);
        }
        Ok(Self {
            chain_id,
            domain,
            pseudonym,
            issuer,
            schema,
            credential_commitment,
            status_registry_root,
            status_sequence,
            status_effective_height,
            maximum_status_age,
            non_revocation_commitment,
            predicate_commitment,
            expires_at,
        })
    }

    pub fn commitment(&self) -> Result<Digest384, PrivacyError> {
        commit(DomainTag::PRIVATE_CREDENTIAL_PRESENTATION, self)
            .map_err(|_| PrivacyError::CommitmentEncoding)
    }

    /// Admits only an exact, fresh finalized-registry statement with a preverified proof.
    pub fn verify(
        &self,
        proof: VerifiedPrivacyProof,
        expected_chain: ChainId,
        expected_domain: Digest384,
        finalized_registry_root: Digest384,
        minimum_status_sequence: u64,
        current_height: u64,
    ) -> Result<(), PrivacyError> {
        if self.chain_id != expected_chain {
            return Err(PrivacyError::WrongChain);
        }
        if self.domain != expected_domain
            || self.status_registry_root != finalized_registry_root
            || self.status_sequence < minimum_status_sequence
        {
            return Err(PrivacyError::PublicInputMismatch);
        }
        if current_height > self.expires_at
            || current_height < self.status_effective_height
            || current_height - self.status_effective_height > self.maximum_status_age
        {
            return Err(PrivacyError::Expired);
        }
        if !proof.verified {
            return Err(PrivacyError::ProofNotVerified);
        }
        if proof.public_inputs_commitment != self.commitment()? {
            return Err(PrivacyError::PublicInputMismatch);
        }
        Ok(())
    }
}

impl CanonicalEncode for PrivateCredentialPresentation {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.domain.encode(e)?;
        self.pseudonym.encode(e)?;
        self.issuer.encode(e)?;
        self.schema.encode(e)?;
        self.credential_commitment.encode(e)?;
        self.status_registry_root.encode(e)?;
        self.status_sequence.encode(e)?;
        self.status_effective_height.encode(e)?;
        self.maximum_status_age.encode(e)?;
        self.non_revocation_commitment.encode(e)?;
        self.predicate_commitment.encode(e)?;
        self.expires_at.encode(e)
    }
}

impl CanonicalDecode for PrivateCredentialPresentation {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        map_decode(Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
        ))
    }
}

impl CanonicalType for PrivateCredentialPresentation {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 9 + 8 * 4;
}

/// Viewer- and purpose-bound permission to decrypt selected private-object fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisclosureCapability {
    chain_id: ChainId,
    object_commitment: Digest384,
    viewer: PrincipalId,
    viewing_key_commitment: Digest384,
    purpose: Digest384,
    fields: Vec<u16>,
    not_before: u64,
    expires_at: u64,
}

impl DisclosureCapability {
    pub const TYPE_TAG: u16 = 0x00aa;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        object_commitment: Digest384,
        viewer: PrincipalId,
        viewing_key_commitment: Digest384,
        purpose: Digest384,
        fields: Vec<u16>,
        not_before: u64,
        expires_at: u64,
    ) -> Result<Self, PrivacyError> {
        if object_commitment == Digest384::ZERO
            || viewing_key_commitment == Digest384::ZERO
            || purpose == Digest384::ZERO
            || fields.is_empty()
            || fields.len() > MAX_DISCLOSED_FIELDS
        {
            return Err(PrivacyError::InvalidViewingScope);
        }
        if fields.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(PrivacyError::NonCanonicalOrder);
        }
        if not_before > expires_at {
            return Err(PrivacyError::InvalidValidityWindow);
        }
        Ok(Self {
            chain_id,
            object_commitment,
            viewer,
            viewing_key_commitment,
            purpose,
            fields,
            not_before,
            expires_at,
        })
    }

    #[must_use]
    pub fn is_valid_at(&self, height: u64) -> bool {
        self.not_before <= height && height <= self.expires_at
    }

    /// Requires a child disclosure to preserve identity/purpose and narrow fields and time.
    pub fn verify_attenuation(&self, child: &Self) -> Result<(), PrivacyError> {
        if child.chain_id != self.chain_id
            || child.object_commitment != self.object_commitment
            || child.viewer != self.viewer
            || child.viewing_key_commitment != self.viewing_key_commitment
            || child.purpose != self.purpose
            || child.not_before < self.not_before
            || child.expires_at > self.expires_at
            || !child.fields.iter().all(|field| self.fields.binary_search(field).is_ok())
        {
            return Err(PrivacyError::ScopeEscalation);
        }
        Ok(())
    }
}

impl CanonicalEncode for DisclosureCapability {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.object_commitment.encode(e)?;
        self.viewer.encode(e)?;
        self.viewing_key_commitment.encode(e)?;
        self.purpose.encode(e)?;
        e.write_length(self.fields.len(), MAX_DISCLOSED_FIELDS)?;
        for field in &self.fields {
            field.encode(e)?;
        }
        self.not_before.encode(e)?;
        self.expires_at.encode(e)
    }
}

impl CanonicalDecode for DisclosureCapability {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(d)?;
        let object_commitment = Digest384::decode(d)?;
        let viewer = PrincipalId::decode(d)?;
        let viewing_key_commitment = Digest384::decode(d)?;
        let purpose = Digest384::decode(d)?;
        let count = d.read_length(MAX_DISCLOSED_FIELDS)?;
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count {
            fields.push(u16::decode(d)?);
        }
        map_decode(Self::new(
            chain_id,
            object_commitment,
            viewer,
            viewing_key_commitment,
            purpose,
            fields,
            u64::decode(d)?,
            u64::decode(d)?,
        ))
    }
}

impl CanonicalType for DisclosureCapability {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 5 + 1 + MAX_DISCLOSED_FIELDS * 2 + 16;
}

/// Complete public statement that a private-object transition proof must bind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateObjectTransition {
    chain_id: ChainId,
    pre_state_root: Digest384,
    post_state_root: Digest384,
    object_class: Digest384,
    prior_object_commitment: Digest384,
    output_object_commitment: Digest384,
    authorization_commitment: Digest384,
    policy_decision_commitment: Digest384,
    program_commitment: Digest384,
    access_manifest_commitment: Digest384,
    disclosure_root: Digest384,
    expires_at: u64,
}

impl PrivateObjectTransition {
    pub const TYPE_TAG: u16 = 0x00ab;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        pre_state_root: Digest384,
        post_state_root: Digest384,
        object_class: Digest384,
        prior_object_commitment: Digest384,
        output_object_commitment: Digest384,
        authorization_commitment: Digest384,
        policy_decision_commitment: Digest384,
        program_commitment: Digest384,
        access_manifest_commitment: Digest384,
        disclosure_root: Digest384,
        expires_at: u64,
    ) -> Result<Self, PrivacyError> {
        let required = [
            pre_state_root,
            post_state_root,
            object_class,
            prior_object_commitment,
            output_object_commitment,
            authorization_commitment,
            policy_decision_commitment,
            program_commitment,
            access_manifest_commitment,
            disclosure_root,
        ];
        if required.contains(&Digest384::ZERO) || pre_state_root == post_state_root {
            return Err(PrivacyError::PublicInputMismatch);
        }
        Ok(Self {
            chain_id,
            pre_state_root,
            post_state_root,
            object_class,
            prior_object_commitment,
            output_object_commitment,
            authorization_commitment,
            policy_decision_commitment,
            program_commitment,
            access_manifest_commitment,
            disclosure_root,
            expires_at,
        })
    }

    pub fn commitment(&self) -> Result<Digest384, PrivacyError> {
        commit(DomainTag::PRIVATE_OBJECT_TRANSITION, self)
            .map_err(|_| PrivacyError::CommitmentEncoding)
    }

    pub fn verify(
        &self,
        proof: VerifiedPrivacyProof,
        expected_chain: ChainId,
        expected_pre_state_root: Digest384,
        current_height: u64,
    ) -> Result<Digest384, PrivacyError> {
        if self.chain_id != expected_chain {
            return Err(PrivacyError::WrongChain);
        }
        if self.pre_state_root != expected_pre_state_root {
            return Err(PrivacyError::WrongAnchor);
        }
        if current_height > self.expires_at {
            return Err(PrivacyError::Expired);
        }
        if !proof.verified {
            return Err(PrivacyError::ProofNotVerified);
        }
        if proof.public_inputs_commitment != self.commitment()? {
            return Err(PrivacyError::PublicInputMismatch);
        }
        Ok(self.post_state_root)
    }
}

impl CanonicalEncode for PrivateObjectTransition {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.pre_state_root.encode(e)?;
        self.post_state_root.encode(e)?;
        self.object_class.encode(e)?;
        self.prior_object_commitment.encode(e)?;
        self.output_object_commitment.encode(e)?;
        self.authorization_commitment.encode(e)?;
        self.policy_decision_commitment.encode(e)?;
        self.program_commitment.encode(e)?;
        self.access_manifest_commitment.encode(e)?;
        self.disclosure_root.encode(e)?;
        self.expires_at.encode(e)
    }
}

impl CanonicalDecode for PrivateObjectTransition {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        map_decode(Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
        ))
    }
}

impl CanonicalType for PrivateObjectTransition {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 11 + 8;
}

/// Exact public statement that a shielded-transfer proof must verify.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShieldedTransferPublicInputs {
    chain_id: ChainId,
    anchor: Digest384,
    asset_id: AssetId,
    balance_commitment: Digest384,
    nullifiers: Vec<Digest384>,
    output_commitments: Vec<Digest384>,
    fee: u128,
    expires_at: u64,
}

impl ShieldedTransferPublicInputs {
    pub const TYPE_TAG: u16 = 0x00a3;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        anchor: Digest384,
        asset_id: AssetId,
        balance_commitment: Digest384,
        nullifiers: Vec<Digest384>,
        output_commitments: Vec<Digest384>,
        fee: u128,
        expires_at: u64,
    ) -> Result<Self, PrivacyError> {
        if nullifiers.is_empty() || output_commitments.is_empty() {
            return Err(PrivacyError::EmptyTransfer);
        }
        if nullifiers.len() > MAX_SHIELDED_ITEMS || output_commitments.len() > MAX_SHIELDED_ITEMS {
            return Err(PrivacyError::TooManyItems);
        }
        if !strictly_sorted(&nullifiers) || !strictly_sorted(&output_commitments) {
            return Err(PrivacyError::NonCanonicalOrder);
        }
        Ok(Self {
            chain_id,
            anchor,
            asset_id,
            balance_commitment,
            nullifiers,
            output_commitments,
            fee,
            expires_at,
        })
    }

    pub fn commitment(&self) -> Result<Digest384, PrivacyError> {
        commit(DomainTag::PRIVACY_PUBLIC_INPUTS, self).map_err(|_| PrivacyError::CommitmentEncoding)
    }
}

fn strictly_sorted(values: &[Digest384]) -> bool {
    values.windows(2).all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
}

impl CanonicalEncode for ShieldedTransferPublicInputs {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.anchor.encode(e)?;
        self.asset_id.encode(e)?;
        self.balance_commitment.encode(e)?;
        e.write_length(self.nullifiers.len(), MAX_SHIELDED_ITEMS)?;
        for value in &self.nullifiers {
            value.encode(e)?;
        }
        e.write_length(self.output_commitments.len(), MAX_SHIELDED_ITEMS)?;
        for value in &self.output_commitments {
            value.encode(e)?;
        }
        self.fee.encode(e)?;
        self.expires_at.encode(e)
    }
}

impl CanonicalDecode for ShieldedTransferPublicInputs {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(d)?;
        let anchor = Digest384::decode(d)?;
        let asset_id = AssetId::decode(d)?;
        let balance_commitment = Digest384::decode(d)?;
        let nullifier_len = d.read_length(MAX_SHIELDED_ITEMS)?;
        let mut nullifiers = Vec::with_capacity(nullifier_len);
        for _ in 0..nullifier_len {
            nullifiers.push(Digest384::decode(d)?);
        }
        let output_len = d.read_length(MAX_SHIELDED_ITEMS)?;
        let mut outputs = Vec::with_capacity(output_len);
        for _ in 0..output_len {
            outputs.push(Digest384::decode(d)?);
        }
        map_decode(Self::new(
            chain_id,
            anchor,
            asset_id,
            balance_commitment,
            nullifiers,
            outputs,
            u128::decode(d)?,
            u64::decode(d)?,
        ))
    }
}

impl CanonicalType for ShieldedTransferPublicInputs {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * (4 + MAX_SHIELDED_ITEMS * 2) + 2 + 16 + 8;
}

/// Result produced by a configured proof verifier, bound to exact public inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPrivacyProof {
    pub public_inputs_commitment: Digest384,
    pub verified: bool,
}

/// Public-to-shielded native-value transition bound to its first private outputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShieldIntent {
    chain_id: ChainId,
    asset_id: AssetId,
    owner: PrincipalId,
    inputs: Vec<CoinCellId>,
    fee_reserve: CoinCellId,
    amount: u128,
    fee: u128,
    output_commitments: Vec<Digest384>,
    valid_until: u64,
}

impl ShieldIntent {
    pub const TYPE_TAG: u16 = 0x00a6;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        asset_id: AssetId,
        owner: PrincipalId,
        inputs: Vec<CoinCellId>,
        fee_reserve: CoinCellId,
        amount: u128,
        fee: u128,
        output_commitments: Vec<Digest384>,
        valid_until: u64,
    ) -> Result<Self, PrivacyError> {
        if amount == 0 {
            return Err(PrivacyError::ZeroValue);
        }
        if inputs.is_empty()
            || inputs.len() > MAX_SHIELDED_ITEMS
            || output_commitments.is_empty()
            || output_commitments.len() > MAX_SHIELDED_ITEMS
        {
            return Err(PrivacyError::TooManyItems);
        }
        if inputs.windows(2).any(|pair| pair[0] >= pair[1])
            || inputs.binary_search(&fee_reserve).is_ok()
            || !strictly_sorted(&output_commitments)
        {
            return Err(PrivacyError::NonCanonicalOrder);
        }
        Ok(Self {
            chain_id,
            asset_id,
            owner,
            inputs,
            fee_reserve,
            amount,
            fee,
            output_commitments,
            valid_until,
        })
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    #[must_use]
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    #[must_use]
    pub const fn owner(&self) -> PrincipalId {
        self.owner
    }
    #[must_use]
    pub fn inputs(&self) -> &[CoinCellId] {
        &self.inputs
    }
    #[must_use]
    pub const fn fee_reserve(&self) -> CoinCellId {
        self.fee_reserve
    }
    #[must_use]
    pub const fn amount(&self) -> u128 {
        self.amount
    }
    #[must_use]
    pub const fn fee(&self) -> u128 {
        self.fee
    }
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

impl CanonicalEncode for ShieldIntent {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.asset_id.encode(e)?;
        self.owner.encode(e)?;
        e.write_length(self.inputs.len(), MAX_SHIELDED_ITEMS)?;
        for input in &self.inputs {
            input.encode(e)?;
        }
        self.fee_reserve.encode(e)?;
        self.amount.encode(e)?;
        self.fee.encode(e)?;
        e.write_length(self.output_commitments.len(), MAX_SHIELDED_ITEMS)?;
        for output in &self.output_commitments {
            output.encode(e)?;
        }
        self.valid_until.encode(e)
    }
}

impl CanonicalDecode for ShieldIntent {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(d)?;
        let asset_id = AssetId::decode(d)?;
        let owner = PrincipalId::decode(d)?;
        let input_len = d.read_length(MAX_SHIELDED_ITEMS)?;
        let mut inputs = Vec::with_capacity(input_len);
        for _ in 0..input_len {
            inputs.push(CoinCellId::decode(d)?);
        }
        let fee_reserve = CoinCellId::decode(d)?;
        let amount = u128::decode(d)?;
        let fee = u128::decode(d)?;
        let output_len = d.read_length(MAX_SHIELDED_ITEMS)?;
        let mut outputs = Vec::with_capacity(output_len);
        for _ in 0..output_len {
            outputs.push(Digest384::decode(d)?);
        }
        map_decode(Self::new(
            chain_id,
            asset_id,
            owner,
            inputs,
            fee_reserve,
            amount,
            fee,
            outputs,
            u64::decode(d)?,
        ))
    }
}

impl CanonicalType for ShieldIntent {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * (4 + MAX_SHIELDED_ITEMS * 2) + 2 + 16 * 2 + 8;
}

/// Shielded-to-public native-value transition authorized by spent nullifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnshieldIntent {
    chain_id: ChainId,
    asset_id: AssetId,
    anchor: Digest384,
    recipient: PrincipalId,
    amount: u128,
    fee: u128,
    nullifiers: Vec<Digest384>,
    change_commitments: Vec<Digest384>,
    valid_until: u64,
}

impl UnshieldIntent {
    pub const TYPE_TAG: u16 = 0x00a7;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        asset_id: AssetId,
        anchor: Digest384,
        recipient: PrincipalId,
        amount: u128,
        fee: u128,
        nullifiers: Vec<Digest384>,
        change_commitments: Vec<Digest384>,
        valid_until: u64,
    ) -> Result<Self, PrivacyError> {
        if amount == 0 {
            return Err(PrivacyError::ZeroValue);
        }
        if nullifiers.is_empty()
            || nullifiers.len() > MAX_SHIELDED_ITEMS
            || change_commitments.len() > MAX_SHIELDED_ITEMS
        {
            return Err(PrivacyError::TooManyItems);
        }
        if !strictly_sorted(&nullifiers) || !strictly_sorted(&change_commitments) {
            return Err(PrivacyError::NonCanonicalOrder);
        }
        Ok(Self {
            chain_id,
            asset_id,
            anchor,
            recipient,
            amount,
            fee,
            nullifiers,
            change_commitments,
            valid_until,
        })
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    #[must_use]
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    #[must_use]
    pub const fn anchor(&self) -> Digest384 {
        self.anchor
    }
    #[must_use]
    pub const fn recipient(&self) -> PrincipalId {
        self.recipient
    }
    #[must_use]
    pub const fn amount(&self) -> u128 {
        self.amount
    }
    #[must_use]
    pub const fn fee(&self) -> u128 {
        self.fee
    }
    #[must_use]
    pub fn nullifiers(&self) -> &[Digest384] {
        &self.nullifiers
    }
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

impl CanonicalEncode for UnshieldIntent {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.asset_id.encode(e)?;
        self.anchor.encode(e)?;
        self.recipient.encode(e)?;
        self.amount.encode(e)?;
        self.fee.encode(e)?;
        e.write_length(self.nullifiers.len(), MAX_SHIELDED_ITEMS)?;
        for value in &self.nullifiers {
            value.encode(e)?;
        }
        e.write_length(self.change_commitments.len(), MAX_SHIELDED_ITEMS)?;
        for value in &self.change_commitments {
            value.encode(e)?;
        }
        self.valid_until.encode(e)
    }
}

impl CanonicalDecode for UnshieldIntent {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(d)?;
        let asset_id = AssetId::decode(d)?;
        let anchor = Digest384::decode(d)?;
        let recipient = PrincipalId::decode(d)?;
        let amount = u128::decode(d)?;
        let fee = u128::decode(d)?;
        let count = d.read_length(MAX_SHIELDED_ITEMS)?;
        let mut nullifiers = Vec::with_capacity(count);
        for _ in 0..count {
            nullifiers.push(Digest384::decode(d)?);
        }
        let count = d.read_length(MAX_SHIELDED_ITEMS)?;
        let mut changes = Vec::with_capacity(count);
        for _ in 0..count {
            changes.push(Digest384::decode(d)?);
        }
        map_decode(Self::new(
            chain_id,
            asset_id,
            anchor,
            recipient,
            amount,
            fee,
            nullifiers,
            changes,
            u64::decode(d)?,
        ))
    }
}

impl CanonicalType for UnshieldIntent {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * (4 + MAX_SHIELDED_ITEMS * 2) + 2 + 16 * 2 + 8;
}

/// Bounded reference spent-nullifier state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NullifierSet {
    spent: Vec<Digest384>,
}

impl NullifierSet {
    pub const TYPE_TAG: u16 = 0x00a4;

    pub fn new(spent: Vec<Digest384>) -> Result<Self, PrivacyError> {
        if spent.len() > MAX_SPENT_NULLIFIERS {
            return Err(PrivacyError::NullifierCapacityExceeded);
        }
        if !strictly_sorted(&spent) {
            return Err(PrivacyError::NonCanonicalOrder);
        }
        Ok(Self { spent })
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Digest384] {
        &self.spent
    }

    /// Validates all conditions before changing state, so every rejection is atomic.
    pub fn admit(
        &mut self,
        inputs: &ShieldedTransferPublicInputs,
        proof: VerifiedPrivacyProof,
        expected_chain: ChainId,
        expected_anchor: Digest384,
        current_height: u64,
    ) -> Result<(), PrivacyError> {
        if inputs.chain_id != expected_chain {
            return Err(PrivacyError::WrongChain);
        }
        if inputs.anchor != expected_anchor {
            return Err(PrivacyError::WrongAnchor);
        }
        if current_height > inputs.expires_at {
            return Err(PrivacyError::Expired);
        }
        if !proof.verified {
            return Err(PrivacyError::ProofNotVerified);
        }
        if proof.public_inputs_commitment != inputs.commitment()? {
            return Err(PrivacyError::PublicInputMismatch);
        }
        self.consume_verified(&inputs.nullifiers)
    }

    /// Consumes already proof-verified, strictly ordered nullifiers atomically.
    pub fn consume_verified(&mut self, nullifiers: &[Digest384]) -> Result<(), PrivacyError> {
        if nullifiers.is_empty() || nullifiers.len() > MAX_SHIELDED_ITEMS {
            return Err(PrivacyError::EmptyTransfer);
        }
        if !strictly_sorted(nullifiers) {
            return Err(PrivacyError::NonCanonicalOrder);
        }
        if self
            .spent
            .len()
            .checked_add(nullifiers.len())
            .is_none_or(|length| length > MAX_SPENT_NULLIFIERS)
        {
            return Err(PrivacyError::NullifierCapacityExceeded);
        }
        if nullifiers.iter().any(|nullifier| self.spent.binary_search(nullifier).is_ok()) {
            return Err(PrivacyError::NullifierAlreadySpent);
        }
        let mut next = self.spent.clone();
        for nullifier in nullifiers {
            let position = next.binary_search(nullifier).unwrap_or_else(|index| index);
            next.insert(position, *nullifier);
        }
        self.spent = next;
        Ok(())
    }
}

impl CanonicalEncode for NullifierSet {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_length(self.spent.len(), MAX_SPENT_NULLIFIERS)?;
        for nullifier in &self.spent {
            nullifier.encode(e)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for NullifierSet {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let length = d.read_length(MAX_SPENT_NULLIFIERS)?;
        let mut spent = Vec::with_capacity(length);
        for _ in 0..length {
            spent.push(Digest384::decode(d)?);
        }
        map_decode(Self::new(spent))
    }
}

impl CanonicalType for NullifierSet {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 2 + MAX_SPENT_NULLIFIERS * 48;
}

/// Persistable shielded native-value partition and replay state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShieldedCashState {
    pool_balance: u128,
    anchor: Digest384,
    nullifiers: NullifierSet,
}

impl Default for ShieldedCashState {
    fn default() -> Self {
        Self { pool_balance: 0, anchor: Digest384::ZERO, nullifiers: NullifierSet::default() }
    }
}

impl ShieldedCashState {
    pub const TYPE_TAG: u16 = 0x00a5;

    pub fn new(
        pool_balance: u128,
        anchor: Digest384,
        nullifiers: NullifierSet,
    ) -> Result<Self, PrivacyError> {
        if pool_balance == 0 && anchor != Digest384::ZERO {
            return Err(PrivacyError::WrongAnchor);
        }
        Ok(Self { pool_balance, anchor, nullifiers })
    }

    #[must_use]
    pub const fn pool_balance(&self) -> u128 {
        self.pool_balance
    }

    #[must_use]
    pub const fn anchor(&self) -> Digest384 {
        self.anchor
    }

    #[must_use]
    pub const fn nullifiers(&self) -> &NullifierSet {
        &self.nullifiers
    }

    pub fn credit(&mut self, amount: u128, next_anchor: Digest384) -> Result<(), PrivacyError> {
        if amount == 0 || next_anchor == Digest384::ZERO {
            return Err(PrivacyError::ZeroValue);
        }
        self.pool_balance = self.pool_balance.checked_add(amount).ok_or(PrivacyError::ZeroValue)?;
        self.anchor = next_anchor;
        Ok(())
    }

    pub fn debit(
        &mut self,
        amount: u128,
        nullifiers: &[Digest384],
        next_anchor: Digest384,
    ) -> Result<(), PrivacyError> {
        if amount == 0 || amount > self.pool_balance || next_anchor == Digest384::ZERO {
            return Err(PrivacyError::ZeroValue);
        }
        let mut next_nullifiers = self.nullifiers.clone();
        next_nullifiers.consume_verified(nullifiers)?;
        self.pool_balance -= amount;
        self.nullifiers = next_nullifiers;
        self.anchor = if self.pool_balance == 0 { Digest384::ZERO } else { next_anchor };
        Ok(())
    }
}

impl CanonicalEncode for ShieldedCashState {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.pool_balance.encode(e)?;
        self.anchor.encode(e)?;
        self.nullifiers.encode(e)
    }
}

impl CanonicalDecode for ShieldedCashState {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        map_decode(Self::new(u128::decode(d)?, Digest384::decode(d)?, NullifierSet::decode(d)?))
    }
}

impl CanonicalType for ShieldedCashState {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 16 + 48 + NullifierSet::MAX_ENCODED_LEN;
}

#[cfg(test)]
mod tests;
