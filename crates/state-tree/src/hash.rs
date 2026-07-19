//! Domain-separated SHAKE256/384 state-tree transcripts.

use activechain_canonical_codec::{EncodeError, encode_envelope};
use activechain_protocol_types::{DIGEST_LENGTH, Digest384, Object};
use sha3::{Shake256, digest::ExtendableOutput, digest::Update, digest::XofReader};

use crate::{STATE_TREE_ARITY, STATE_TREE_DEPTH};

const TRANSCRIPT_PREFIX: &[u8] = b"ACTIVECHAIN-STATE-TREE";
const TRANSCRIPT_VERSION: u16 = 1;
const LEAF_KIND: u8 = 0;
const EMPTY_LEAF_KIND: u8 = 1;
const INTERNAL_NODE_KIND: u8 = 2;
const STATE_ROOT_KIND: u8 = 3;

pub(crate) fn hash_leaf(object: &Object) -> Result<Digest384, EncodeError> {
    let envelope = encode_envelope(object)?;
    let envelope_length = u32::try_from(envelope.len()).map_err(|_| EncodeError::LengthOverflow)?;
    let mut hasher = transcript(LEAF_KIND);
    hasher.update(object.object_id().digest().as_bytes());
    hasher.update(&envelope_length.to_be_bytes());
    hasher.update(&envelope);
    Ok(finish(hasher))
}

fn hash_empty_leaf() -> Digest384 {
    finish(transcript(EMPTY_LEAF_KIND))
}

pub(crate) fn hash_node(depth: usize, children: &[Digest384; STATE_TREE_ARITY]) -> Digest384 {
    let mut hasher = transcript(INTERNAL_NODE_KIND);
    hasher.update(&[depth as u8]);
    for child in children {
        hasher.update(child.as_bytes());
    }
    finish(hasher)
}

pub(crate) fn hash_state_root(object_count: u64, tree_root: Digest384) -> Digest384 {
    let mut hasher = transcript(STATE_ROOT_KIND);
    hasher.update(&object_count.to_be_bytes());
    hasher.update(tree_root.as_bytes());
    finish(hasher)
}

pub(crate) fn empty_hashes() -> [Digest384; STATE_TREE_DEPTH + 1] {
    let mut hashes = [Digest384::ZERO; STATE_TREE_DEPTH + 1];
    hashes[STATE_TREE_DEPTH] = hash_empty_leaf();
    for depth in (0..STATE_TREE_DEPTH).rev() {
        hashes[depth] = hash_node(depth, &[hashes[depth + 1]; STATE_TREE_ARITY]);
    }
    hashes
}

fn transcript(kind: u8) -> Shake256 {
    let mut hasher = Shake256::default();
    hasher.update(TRANSCRIPT_PREFIX);
    hasher.update(&TRANSCRIPT_VERSION.to_be_bytes());
    hasher.update(&[kind]);
    hasher
}

fn finish(hasher: Shake256) -> Digest384 {
    let mut output = [0_u8; DIGEST_LENGTH];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}
