//! Canonical compressed proofs and bottom-up verification.

use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{Digest384, Object, ObjectId};

use crate::hash::{empty_hashes, hash_leaf, hash_node, hash_state_root};
use crate::tree::path_nibble_at;
use crate::{STATE_TREE_ARITY, STATE_TREE_DEPTH};

/// Whether a single-key witness opens an object leaf or the canonical empty leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StateProofKind {
    /// The queried object is present and supplied separately to verification.
    Membership = 0,
    /// The queried key terminates in the canonical empty leaf.
    NonMembership = 1,
}

impl CanonicalEncode for StateProofKind {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for StateProofKind {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Membership),
            1 => Ok(Self::NonMembership),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "StateProofKind", tag }),
        }
    }
}

/// One root-to-leaf level's non-default sibling hashes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProofLevel {
    sibling_bitmap: u16,
    siblings: Vec<Digest384>,
}

impl StateProofLevel {
    /// Worst-case canonical level length.
    pub const MAX_ENCODED_LEN: usize = 2 + 15 * 48;

    /// Checks that the bitmap population count exactly determines the hash count.
    pub fn new(
        sibling_bitmap: u16,
        siblings: Vec<Digest384>,
    ) -> Result<Self, StateProofValidationError> {
        let expected = sibling_bitmap.count_ones() as usize;
        if expected > STATE_TREE_ARITY - 1 {
            return Err(StateProofValidationError::TooManySiblings { actual: expected });
        }
        if siblings.len() != expected {
            return Err(StateProofValidationError::SiblingCountMismatch {
                expected,
                actual: siblings.len(),
            });
        }
        Ok(Self { sibling_bitmap, siblings })
    }

    /// Returns the child-position bitmap in ascending digest order.
    #[must_use]
    pub const fn sibling_bitmap(&self) -> u16 {
        self.sibling_bitmap
    }

    /// Borrows non-default sibling hashes ordered by child index.
    #[must_use]
    pub fn siblings(&self) -> &[Digest384] {
        &self.siblings
    }
}

impl CanonicalEncode for StateProofLevel {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.sibling_bitmap.encode(encoder)?;
        for sibling in &self.siblings {
            sibling.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for StateProofLevel {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let sibling_bitmap = u16::decode(decoder)?;
        let sibling_count = sibling_bitmap.count_ones() as usize;
        if sibling_count > STATE_TREE_ARITY - 1 {
            return Err(DecodeError::InvalidValue("proof level encodes all sixteen children"));
        }
        let mut siblings = Vec::with_capacity(sibling_count);
        for _ in 0..sibling_count {
            siblings.push(Digest384::decode(decoder)?);
        }
        Self::new(sibling_bitmap, siblings)
            .map_err(|_| DecodeError::InvalidValue("proof sibling bitmap and values disagree"))
    }
}

/// A canonical compressed 96-level sparse-state witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProof {
    kind: StateProofKind,
    object_id: ObjectId,
    levels: Vec<StateProofLevel>,
}

impl StateProof {
    /// Registered top-level state-proof type tag.
    pub const TYPE_TAG: u16 = 0x0055;
    /// Initial canonical state-proof schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Worst-case canonical proof body length.
    pub const MAX_ENCODED_LEN: usize = 69_361;

    /// Validates fixed depth, path exclusion, and default-sibling compression.
    pub fn new(
        kind: StateProofKind,
        object_id: ObjectId,
        levels: Vec<StateProofLevel>,
    ) -> Result<Self, StateProofValidationError> {
        if levels.len() != STATE_TREE_DEPTH {
            return Err(StateProofValidationError::WrongLevelCount {
                actual: levels.len(),
                expected: STATE_TREE_DEPTH,
            });
        }
        let empty = empty_hashes();
        for (depth, level) in levels.iter().enumerate() {
            let path_child = usize::from(path_nibble_at(object_id, depth));
            let path_bit = 1_u16 << path_child;
            if level.sibling_bitmap & path_bit != 0 {
                return Err(StateProofValidationError::PathChildEncoded { depth });
            }
            if level.siblings.len() != level.sibling_bitmap.count_ones() as usize {
                return Err(StateProofValidationError::SiblingCountMismatch {
                    expected: level.sibling_bitmap.count_ones() as usize,
                    actual: level.siblings.len(),
                });
            }
            if level.siblings.iter().any(|sibling| *sibling == empty[depth + 1]) {
                return Err(StateProofValidationError::DefaultSiblingEncoded { depth });
            }
        }
        Ok(Self { kind, object_id, levels })
    }

    /// Returns the membership claim kind.
    #[must_use]
    pub const fn kind(&self) -> StateProofKind {
        self.kind
    }

    /// Returns the queried object identifier.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Borrows all root-to-leaf proof levels.
    #[must_use]
    pub fn levels(&self) -> &[StateProofLevel] {
        &self.levels
    }
}

impl CanonicalEncode for StateProof {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.kind.encode(encoder)?;
        self.object_id.encode(encoder)?;
        for level in &self.levels {
            level.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for StateProof {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let kind = StateProofKind::decode(decoder)?;
        let object_id = ObjectId::decode(decoder)?;
        let mut levels = Vec::with_capacity(STATE_TREE_DEPTH);
        for _ in 0..STATE_TREE_DEPTH {
            levels.push(StateProofLevel::decode(decoder)?);
        }
        Self::new(kind, object_id, levels).map_err(proof_validation_decode_error)
    }
}

impl CanonicalType for StateProof {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// The canonical final state root and exact object count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateCommitment {
    root: Digest384,
    object_count: u64,
}

impl StateCommitment {
    /// Registered top-level state-commitment type tag.
    pub const TYPE_TAG: u16 = 0x0056;
    /// Initial canonical state-commitment schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Fixed state-commitment body length.
    pub const ENCODED_LENGTH: usize = 56;

    /// Constructs a root/count commitment pair.
    #[must_use]
    pub const fn new(root: Digest384, object_count: u64) -> Self {
        Self { root, object_count }
    }

    /// Returns the final state root.
    #[must_use]
    pub const fn root(self) -> Digest384 {
        self.root
    }

    /// Returns the exact committed object count.
    #[must_use]
    pub const fn object_count(self) -> u64 {
        self.object_count
    }
}

impl CanonicalEncode for StateCommitment {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.root.encode(encoder)?;
        self.object_count.encode(encoder)
    }
}

impl CanonicalDecode for StateCommitment {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(Digest384::decode(decoder)?, u64::decode(decoder)?))
    }
}

impl CanonicalType for StateCommitment {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}

/// Canonical state-proof construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateProofValidationError {
    /// The proof does not contain exactly 96 levels.
    WrongLevelCount { actual: usize, expected: usize },
    /// One level encodes more than the possible 15 siblings.
    TooManySiblings { actual: usize },
    /// Bitmap population count and supplied hashes differ.
    SiblingCountMismatch { expected: usize, actual: usize },
    /// The queried path child was redundantly encoded as its own sibling.
    PathChildEncoded { depth: usize },
    /// A canonical default child was explicitly encoded instead of omitted.
    DefaultSiblingEncoded { depth: usize },
}

/// State-proof verification failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateProofVerificationError {
    /// The supplied verifier entry point does not match the proof kind.
    WrongProofKind,
    /// The separately supplied object or key does not match the proof key.
    ObjectIdMismatch,
    /// A canonical membership leaf could not be encoded.
    ObjectEncoding(EncodeError),
    /// Bottom-up folding did not reproduce the committed final root.
    RootMismatch,
}

/// Authenticated single-key state-update failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateProofUpdateError {
    /// The supplied proof does not open the claimed pre-state leaf.
    InvalidPreState(StateProofVerificationError),
    /// The replacement object does not use the proof's exact key.
    AfterObjectIdMismatch,
    /// A replacement membership leaf could not be encoded.
    ObjectEncoding(EncodeError),
    /// Inserting into an already maximal object count would wrap.
    ObjectCountOverflow,
    /// Deleting from a zero-count commitment is contradictory.
    ObjectCountUnderflow,
}

/// Verifies a canonical object membership proof.
pub fn verify_membership(
    commitment: StateCommitment,
    object: &Object,
    proof: &StateProof,
) -> Result<(), StateProofVerificationError> {
    if proof.kind != StateProofKind::Membership {
        return Err(StateProofVerificationError::WrongProofKind);
    }
    if proof.object_id != object.object_id() {
        return Err(StateProofVerificationError::ObjectIdMismatch);
    }
    let leaf = hash_leaf(object).map_err(StateProofVerificationError::ObjectEncoding)?;
    verify_fold(commitment, proof, leaf)
}

/// Verifies a canonical proof that an object identifier is absent.
pub fn verify_non_membership(
    commitment: StateCommitment,
    object_id: ObjectId,
    proof: &StateProof,
) -> Result<(), StateProofVerificationError> {
    if proof.kind != StateProofKind::NonMembership {
        return Err(StateProofVerificationError::WrongProofKind);
    }
    if proof.object_id != object_id {
        return Err(StateProofVerificationError::ObjectIdMismatch);
    }
    let empty = empty_hashes();
    verify_fold(commitment, proof, empty[STATE_TREE_DEPTH])
}

/// Reconstructs the unwrapped sparse-tree root from a canonical proof and leaf hash.
///
/// Callers must separately establish whether `leaf` is the membership hash for the
/// proof key or the canonical empty leaf. The public membership/non-membership and
/// update entry points perform that binding before using this fold.
#[must_use]
pub fn reconstruct_tree_root(proof: &StateProof, mut accumulator: Digest384) -> Digest384 {
    let empty = empty_hashes();
    for depth in (0..STATE_TREE_DEPTH).rev() {
        let level = &proof.levels[depth];
        let path_child = usize::from(path_nibble_at(proof.object_id, depth));
        let mut children = [empty[depth + 1]; STATE_TREE_ARITY];
        let mut sibling_index = 0;
        for (child, slot) in children.iter_mut().enumerate() {
            if level.sibling_bitmap & (1_u16 << child) != 0 {
                *slot = level.siblings[sibling_index];
                sibling_index += 1;
            }
        }
        children[path_child] = accumulator;
        accumulator = hash_node(depth, &children);
    }
    accumulator
}

/// Applies one proof-authenticated insert, replacement, or deletion to a state root.
///
/// This derives the post-root without trusting mutable tree storage: the exact pre
/// leaf is first verified against `commitment`, the same canonical sibling path is
/// folded with the replacement leaf, and object count changes exactly for
/// absence-to-membership or membership-to-absence transitions.
pub fn apply_single_key_update(
    commitment: StateCommitment,
    proof: &StateProof,
    before: Option<&Object>,
    after: Option<&Object>,
) -> Result<StateCommitment, StateProofUpdateError> {
    match before {
        Some(object) => verify_membership(commitment, object, proof),
        None => verify_non_membership(commitment, proof.object_id, proof),
    }
    .map_err(StateProofUpdateError::InvalidPreState)?;

    if let Some(object) = after
        && object.object_id() != proof.object_id
    {
        return Err(StateProofUpdateError::AfterObjectIdMismatch);
    }

    let object_count = match (before.is_some(), after.is_some()) {
        (false, true) => commitment
            .object_count
            .checked_add(1)
            .ok_or(StateProofUpdateError::ObjectCountOverflow)?,
        (true, false) => commitment
            .object_count
            .checked_sub(1)
            .ok_or(StateProofUpdateError::ObjectCountUnderflow)?,
        (false, false) | (true, true) => commitment.object_count,
    };
    let replacement_leaf = match after {
        Some(object) => hash_leaf(object).map_err(StateProofUpdateError::ObjectEncoding)?,
        None => empty_hashes()[STATE_TREE_DEPTH],
    };
    let tree_root = reconstruct_tree_root(proof, replacement_leaf);
    Ok(StateCommitment::new(hash_state_root(object_count, tree_root), object_count))
}

fn verify_fold(
    commitment: StateCommitment,
    proof: &StateProof,
    mut accumulator: Digest384,
) -> Result<(), StateProofVerificationError> {
    accumulator = reconstruct_tree_root(proof, accumulator);
    let root = hash_state_root(commitment.object_count, accumulator);
    if root == commitment.root { Ok(()) } else { Err(StateProofVerificationError::RootMismatch) }
}

fn proof_validation_decode_error(error: StateProofValidationError) -> DecodeError {
    match error {
        StateProofValidationError::WrongLevelCount { .. } => {
            DecodeError::InvalidValue("state proof has the wrong fixed depth")
        }
        StateProofValidationError::TooManySiblings { .. } => {
            DecodeError::InvalidValue("state proof level has too many siblings")
        }
        StateProofValidationError::SiblingCountMismatch { .. } => {
            DecodeError::InvalidValue("state proof sibling bitmap and values disagree")
        }
        StateProofValidationError::PathChildEncoded { .. } => {
            DecodeError::InvalidValue("state proof bitmap contains the queried path child")
        }
        StateProofValidationError::DefaultSiblingEncoded { .. } => {
            DecodeError::InvalidValue("state proof explicitly encodes a default sibling")
        }
    }
}
