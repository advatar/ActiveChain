#![no_std]
#![forbid(unsafe_code)]

//! Bounded canonical statements for ActiveChain's fixed privacy profiles.
//!
//! This crate does not implement a proof system and makes no privacy claim. It defines the
//! consensus-facing values a proof verifier must bind and a fail-closed state transition over
//! preverified evidence. Proof verification remains an explicit caller responsibility.

extern crate alloc;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{AssetId, ChainId, Digest384, PrincipalId};
use alloc::vec::Vec;

/// Maximum inputs or outputs in one shielded transfer.
pub const MAX_SHIELDED_ITEMS: usize = 16;
/// Maximum nullifiers retained by this bounded reference state.
pub const MAX_SPENT_NULLIFIERS: usize = 4_096;

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

/// Bounded reference spent-nullifier state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NullifierSet {
    spent: Vec<Digest384>,
}

impl NullifierSet {
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
        if self
            .spent
            .len()
            .checked_add(inputs.nullifiers.len())
            .is_none_or(|length| length > MAX_SPENT_NULLIFIERS)
        {
            return Err(PrivacyError::NullifierCapacityExceeded);
        }
        if inputs.nullifiers.iter().any(|nullifier| self.spent.binary_search(nullifier).is_ok()) {
            return Err(PrivacyError::NullifierAlreadySpent);
        }

        for nullifier in &inputs.nullifiers {
            let position = self.spent.binary_search(nullifier).unwrap_or_else(|index| index);
            self.spent.insert(position, *nullifier);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
