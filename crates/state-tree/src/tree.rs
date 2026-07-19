//! Deterministic sparse-tree construction and proof generation.

use alloc::vec::Vec;

use activechain_canonical_codec::EncodeError;
use activechain_protocol_types::{Digest384, Object, ObjectId};

use crate::hash::{empty_hashes, hash_leaf, hash_node, hash_state_root};
use crate::{
    StateCommitment, StateProof, StateProofKind, StateProofLevel, StateProofValidationError,
};

/// Nibbles in one 384-bit object identifier.
pub const STATE_TREE_DEPTH: usize = 96;
/// Ordered children at every internal node.
pub const STATE_TREE_ARITY: usize = 16;
/// Object bound inherited from the explicit P-030 development state.
pub const MAX_REFERENCE_STATE_OBJECTS: usize = 64;

/// Returns the high-to-low path nibble at one depth.
#[must_use]
pub fn path_nibble(object_id: ObjectId, depth: usize) -> Option<u8> {
    if depth < STATE_TREE_DEPTH { Some(path_nibble_at(object_id, depth)) } else { None }
}

pub(crate) fn path_nibble_at(object_id: ObjectId, depth: usize) -> u8 {
    let byte = object_id.digest().as_bytes()[depth / 2];
    if depth.is_multiple_of(2) { byte >> 4 } else { byte & 0x0f }
}

/// Returns the logical partition selected by the first 12 identifier bits.
#[must_use]
pub fn partition_id(object_id: ObjectId) -> u16 {
    let bytes = object_id.digest().as_bytes();
    (u16::from(bytes[0]) << 4) | (u16::from(bytes[1]) >> 4)
}

/// Computes the canonical state commitment for sorted unique objects.
pub fn commit_objects(objects: &[Object]) -> Result<StateCommitment, StateTreeError> {
    validate_objects(objects)?;
    let empty = empty_hashes();
    let tree_root = subtree_hash(objects, 0, &empty)?;
    let object_count =
        u64::try_from(objects.len()).map_err(|_| StateTreeError::ObjectCountOverflow)?;
    Ok(StateCommitment::new(hash_state_root(object_count, tree_root), object_count))
}

/// Generates a canonical membership or non-membership proof for one identifier.
pub fn prove_object(objects: &[Object], object_id: ObjectId) -> Result<StateProof, StateTreeError> {
    validate_objects(objects)?;
    let empty = empty_hashes();
    let mut current = objects;
    let mut levels = Vec::with_capacity(STATE_TREE_DEPTH);

    for depth in 0..STATE_TREE_DEPTH {
        let ranges = child_ranges(current, depth);
        let path_child = usize::from(path_nibble_at(object_id, depth));
        let mut sibling_bitmap = 0_u16;
        let mut siblings = Vec::new();
        for (child, (start, end)) in ranges.iter().copied().enumerate() {
            if child == path_child || start == end {
                continue;
            }
            let sibling = subtree_hash(&current[start..end], depth + 1, &empty)?;
            if sibling != empty[depth + 1] {
                sibling_bitmap |= 1_u16 << child;
                siblings.push(sibling);
            }
        }
        levels.push(
            StateProofLevel::new(sibling_bitmap, siblings)
                .map_err(StateTreeError::InvalidGeneratedProof)?,
        );
        let (start, end) = ranges[path_child];
        current = &current[start..end];
    }

    let kind = if current.len() == 1 && current[0].object_id() == object_id {
        StateProofKind::Membership
    } else {
        StateProofKind::NonMembership
    };
    StateProof::new(kind, object_id, levels).map_err(StateTreeError::InvalidGeneratedProof)
}

/// State-tree input, hashing, or generated-proof failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateTreeError {
    /// The development state exceeds its explicit object bound.
    TooManyObjects { actual: usize, maximum: usize },
    /// Objects are duplicated or not strictly ordered by identifier.
    ObjectsNotStrictlyIncreasing,
    /// A canonical object leaf did not encode.
    ObjectEncoding(EncodeError),
    /// The host could not represent the object count in the canonical field.
    ObjectCountOverflow,
    /// A recursion terminal contained an impossible number of full-key objects.
    InvalidLeafMultiplicity,
    /// Proof generation violated the canonical proof constructor.
    InvalidGeneratedProof(StateProofValidationError),
}

fn validate_objects(objects: &[Object]) -> Result<(), StateTreeError> {
    if objects.len() > MAX_REFERENCE_STATE_OBJECTS {
        return Err(StateTreeError::TooManyObjects {
            actual: objects.len(),
            maximum: MAX_REFERENCE_STATE_OBJECTS,
        });
    }
    if !objects.windows(2).all(|pair| pair[0].object_id() < pair[1].object_id()) {
        return Err(StateTreeError::ObjectsNotStrictlyIncreasing);
    }
    Ok(())
}

fn subtree_hash(
    objects: &[Object],
    depth: usize,
    empty: &[Digest384; STATE_TREE_DEPTH + 1],
) -> Result<Digest384, StateTreeError> {
    if objects.is_empty() {
        return Ok(empty[depth]);
    }
    if depth == STATE_TREE_DEPTH {
        if objects.len() != 1 {
            return Err(StateTreeError::InvalidLeafMultiplicity);
        }
        return hash_leaf(&objects[0]).map_err(StateTreeError::ObjectEncoding);
    }

    let ranges = child_ranges(objects, depth);
    let mut children = [empty[depth + 1]; STATE_TREE_ARITY];
    for (child, (start, end)) in ranges.iter().copied().enumerate() {
        if start != end {
            children[child] = subtree_hash(&objects[start..end], depth + 1, empty)?;
        }
    }
    Ok(hash_node(depth, &children))
}

fn child_ranges(objects: &[Object], depth: usize) -> [(usize, usize); STATE_TREE_ARITY] {
    let mut ranges = [(0, 0); STATE_TREE_ARITY];
    let mut cursor = 0;
    for (child, range) in ranges.iter_mut().enumerate() {
        let start = cursor;
        while cursor < objects.len()
            && usize::from(path_nibble_at(objects[cursor].object_id(), depth)) == child
        {
            cursor += 1;
        }
        *range = (start, cursor);
    }
    ranges
}
