#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{collections::BTreeSet, format, string::String, vec, vec::Vec};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub type Root = [u8; 48];
pub const KEY_BITS: usize = 384;
pub const HISTORY_BITS: usize = 32;
pub const PARTITION_BITS: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccumulatorError {
    Bounds,
    Duplicate,
    WrongRoot,
    WrongKey,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AccumulatorDomain {
    Nullifier = 1,
    SpentInput = 2,
    Revocation = 3,
    RetiredValidatorSet = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetCommitment {
    pub domain: AccumulatorDomain,
    pub root: Root,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonMembershipWitness {
    pub key: Root,
    /// Root-to-leaf sibling order, exactly 384 entries.
    pub siblings: Vec<Root>,
}

impl SetCommitment {
    #[must_use]
    pub fn empty(domain: AccumulatorDomain) -> Self {
        let tree_root = set_empty_hashes(domain)[0];
        Self { domain, root: set_commitment_root(domain, 0, tree_root), count: 0 }
    }

    pub fn insert(
        self,
        key: Root,
        witness: &NonMembershipWitness,
    ) -> Result<Self, AccumulatorError> {
        if key == [0; 48] || witness.key != key || witness.siblings.len() != KEY_BITS {
            return Err(AccumulatorError::WrongKey);
        }
        let empty_tree_root =
            fold_key(self.domain, key, empty_set_leaf(self.domain), &witness.siblings);
        if set_commitment_root(self.domain, self.count, empty_tree_root) != self.root {
            return Err(AccumulatorError::WrongRoot);
        }
        let count = self.count.checked_add(1).ok_or(AccumulatorError::Overflow)?;
        let tree_root = fold_key(self.domain, key, set_leaf(self.domain, key), &witness.siblings);
        Ok(Self {
            domain: self.domain,
            root: set_commitment_root(self.domain, count, tree_root),
            count,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ReferenceSet {
    domain: AccumulatorDomain,
    keys: BTreeSet<Root>,
}

impl Default for ReferenceSet {
    fn default() -> Self {
        Self::new(AccumulatorDomain::Nullifier)
    }
}

impl ReferenceSet {
    #[must_use]
    pub const fn new(domain: AccumulatorDomain) -> Self {
        Self { domain, keys: BTreeSet::new() }
    }

    #[must_use]
    pub fn commitment(&self) -> SetCommitment {
        let keys = self.keys.iter().copied().collect::<Vec<_>>();
        let empty = set_empty_hashes(self.domain);
        let tree_root = set_subtree(self.domain, &keys, 0, &empty);
        SetCommitment {
            domain: self.domain,
            root: set_commitment_root(self.domain, self.keys.len() as u64, tree_root),
            count: self.keys.len() as u64,
        }
    }

    pub fn non_membership_witness(
        &self,
        key: Root,
    ) -> Result<NonMembershipWitness, AccumulatorError> {
        if key == [0; 48] || self.keys.contains(&key) {
            return Err(AccumulatorError::Duplicate);
        }
        let empty = set_empty_hashes(self.domain);
        let mut candidates = self.keys.iter().copied().collect::<Vec<_>>();
        let mut siblings = Vec::with_capacity(KEY_BITS);
        for depth in 0..KEY_BITS {
            let (left, right): (Vec<_>, Vec<_>) =
                candidates.into_iter().partition(|candidate| !key_bit(candidate, depth));
            if key_bit(&key, depth) {
                siblings.push(set_subtree(self.domain, &left, depth + 1, &empty));
                candidates = right;
            } else {
                siblings.push(set_subtree(self.domain, &right, depth + 1, &empty));
                candidates = left;
            }
        }
        Ok(NonMembershipWitness { key, siblings })
    }

    pub fn insert(&mut self, key: Root) -> Result<(), AccumulatorError> {
        if key == [0; 48] || !self.keys.insert(key) {
            return Err(AccumulatorError::Duplicate);
        }
        Ok(())
    }
}

#[must_use]
pub const fn partition_id(key: Root) -> u16 {
    (u16::from_be_bytes([key[0], key[1]]) >> 4) & 0x0fff
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryCommitment {
    pub root: Root,
    pub count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryProof {
    pub index: u32,
    pub header_digest: Root,
    /// Root-to-leaf sibling order, exactly 32 entries.
    pub siblings: Vec<Root>,
}

impl HistoryCommitment {
    pub fn append(
        self,
        header_digest: Root,
        absence_witness: &HistoryProof,
    ) -> Result<Self, AccumulatorError> {
        if header_digest == [0; 48]
            || absence_witness.index != self.count
            || absence_witness.header_digest != [0; 48]
            || absence_witness.siblings.len() != HISTORY_BITS
        {
            return Err(AccumulatorError::Bounds);
        }
        let empty_tree = fold_history(self.count, empty_history_leaf(), &absence_witness.siblings);
        if history_commitment_root(self.count, empty_tree) != self.root {
            return Err(AccumulatorError::WrongRoot);
        }
        let count = self.count.checked_add(1).ok_or(AccumulatorError::Overflow)?;
        let tree = fold_history(
            self.count,
            history_leaf(self.count, header_digest),
            &absence_witness.siblings,
        );
        Ok(Self { root: history_commitment_root(count, tree), count })
    }

    pub fn verify(&self, proof: &HistoryProof) -> Result<(), AccumulatorError> {
        if proof.index >= self.count
            || proof.header_digest == [0; 48]
            || proof.siblings.len() != HISTORY_BITS
        {
            return Err(AccumulatorError::Bounds);
        }
        let tree = fold_history(
            proof.index,
            history_leaf(proof.index, proof.header_digest),
            &proof.siblings,
        );
        if history_commitment_root(self.count, tree) != self.root {
            return Err(AccumulatorError::WrongRoot);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReferenceHistory {
    headers: Vec<Root>,
}

impl ReferenceHistory {
    #[must_use]
    pub fn commitment(&self) -> HistoryCommitment {
        let empty = history_empty_hashes();
        let indexed = self.headers.iter().copied().enumerate().collect::<Vec<_>>();
        let tree = history_subtree(&indexed, 0, &empty);
        HistoryCommitment {
            root: history_commitment_root(self.headers.len() as u32, tree),
            count: self.headers.len() as u32,
        }
    }

    pub fn absence_witness(&self) -> Result<HistoryProof, AccumulatorError> {
        let index = u32::try_from(self.headers.len()).map_err(|_| AccumulatorError::Overflow)?;
        history_proof(&self.headers, index, [0; 48])
    }

    pub fn proof(&self, index: u32) -> Result<HistoryProof, AccumulatorError> {
        let digest = *self.headers.get(index as usize).ok_or(AccumulatorError::Bounds)?;
        history_proof(&self.headers, index, digest)
    }

    pub fn append(&mut self, header_digest: Root) -> Result<(), AccumulatorError> {
        if header_digest == [0; 48] || self.headers.len() == u32::MAX as usize {
            return Err(AccumulatorError::Bounds);
        }
        self.headers.push(header_digest);
        Ok(())
    }
}

fn history_proof(
    headers: &[Root],
    index: u32,
    header_digest: Root,
) -> Result<HistoryProof, AccumulatorError> {
    let empty = history_empty_hashes();
    let mut candidates = headers.iter().copied().enumerate().collect::<Vec<_>>();
    let mut siblings = Vec::with_capacity(HISTORY_BITS);
    for depth in 0..HISTORY_BITS {
        let (left, right): (Vec<_>, Vec<_>) =
            candidates.into_iter().partition(|(candidate, _)| !index_bit(*candidate as u32, depth));
        if index_bit(index, depth) {
            siblings.push(history_subtree(&left, depth + 1, &empty));
            candidates = right;
        } else {
            siblings.push(history_subtree(&right, depth + 1, &empty));
            candidates = left;
        }
    }
    Ok(HistoryProof { index, header_digest, siblings })
}

fn fold_key(domain: AccumulatorDomain, key: Root, mut leaf: Root, siblings: &[Root]) -> Root {
    for depth in (0..KEY_BITS).rev() {
        leaf = if key_bit(&key, depth) {
            set_node(domain, depth, siblings[depth], leaf)
        } else {
            set_node(domain, depth, leaf, siblings[depth])
        };
    }
    leaf
}

fn fold_history(index: u32, mut leaf: Root, siblings: &[Root]) -> Root {
    for depth in (0..HISTORY_BITS).rev() {
        leaf = if index_bit(index, depth) {
            history_node(depth, siblings[depth], leaf)
        } else {
            history_node(depth, leaf, siblings[depth])
        };
    }
    leaf
}

fn set_subtree(domain: AccumulatorDomain, keys: &[Root], depth: usize, empty: &[Root]) -> Root {
    if keys.is_empty() {
        return empty[depth];
    }
    if depth == KEY_BITS {
        return set_leaf(domain, keys[0]);
    }
    let split = keys.partition_point(|key| !key_bit(key, depth));
    set_node(
        domain,
        depth,
        set_subtree(domain, &keys[..split], depth + 1, empty),
        set_subtree(domain, &keys[split..], depth + 1, empty),
    )
}

fn history_subtree(entries: &[(usize, Root)], depth: usize, empty: &[Root]) -> Root {
    if entries.is_empty() {
        return empty[depth];
    }
    if depth == HISTORY_BITS {
        return history_leaf(entries[0].0 as u32, entries[0].1);
    }
    let split = entries.partition_point(|(index, _)| !index_bit(*index as u32, depth));
    history_node(
        depth,
        history_subtree(&entries[..split], depth + 1, empty),
        history_subtree(&entries[split..], depth + 1, empty),
    )
}

fn set_empty_hashes(domain: AccumulatorDomain) -> Vec<Root> {
    let mut empty = vec![[0; 48]; KEY_BITS + 1];
    empty[KEY_BITS] = empty_set_leaf(domain);
    for depth in (0..KEY_BITS).rev() {
        empty[depth] = set_node(domain, depth, empty[depth + 1], empty[depth + 1]);
    }
    empty
}

fn history_empty_hashes() -> Vec<Root> {
    let mut empty = vec![[0; 48]; HISTORY_BITS + 1];
    empty[HISTORY_BITS] = empty_history_leaf();
    for depth in (0..HISTORY_BITS).rev() {
        empty[depth] = history_node(depth, empty[depth + 1], empty[depth + 1]);
    }
    empty
}

fn key_bit(key: &Root, depth: usize) -> bool {
    key[depth / 8] & (1 << (7 - depth % 8)) != 0
}

fn index_bit(index: u32, depth: usize) -> bool {
    index & (1 << (31 - depth)) != 0
}

fn empty_set_leaf(domain: AccumulatorDomain) -> Root {
    digest(&[b"ACTIVECHAIN-SPARSE-SET-EMPTY-V1", &[domain as u8]])
}

fn set_leaf(domain: AccumulatorDomain, key: Root) -> Root {
    digest(&[b"ACTIVECHAIN-SPARSE-SET-LEAF-V1", &[domain as u8], &key])
}

fn set_node(domain: AccumulatorDomain, depth: usize, left: Root, right: Root) -> Root {
    digest(&[
        b"ACTIVECHAIN-SPARSE-SET-NODE-V1",
        &[domain as u8],
        &(depth as u16).to_be_bytes(),
        &left,
        &right,
    ])
}

fn set_commitment_root(domain: AccumulatorDomain, count: u64, tree_root: Root) -> Root {
    digest(&[b"ACTIVECHAIN-SPARSE-SET-ROOT-V1", &[domain as u8], &count.to_be_bytes(), &tree_root])
}

fn empty_history_leaf() -> Root {
    digest(&[b"ACTIVECHAIN-HISTORY-EMPTY-V1"])
}

fn history_leaf(index: u32, header: Root) -> Root {
    digest(&[b"ACTIVECHAIN-HISTORY-LEAF-V1", &index.to_be_bytes(), &header])
}

fn history_node(depth: usize, left: Root, right: Root) -> Root {
    digest(&[b"ACTIVECHAIN-HISTORY-NODE-V1", &(depth as u16).to_be_bytes(), &left, &right])
}

fn history_commitment_root(count: u32, tree_root: Root) -> Root {
    digest(&[b"ACTIVECHAIN-HISTORY-ROOT-V1", &count.to_be_bytes(), &tree_root])
}

fn digest(parts: &[&[u8]]) -> Root {
    let mut hasher = Shake256::default();
    for part in parts {
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    let mut root = [0; 48];
    reader.read(&mut root);
    root
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

#[must_use]
pub fn render_accumulator_fixture() -> String {
    let mut set = ReferenceSet::default();
    set.insert([1; 48]).expect("fixture key");
    set.insert([2; 48]).expect("fixture key");
    let mut history = ReferenceHistory::default();
    history.append([3; 48]).expect("fixture header");
    history.append([4; 48]).expect("fixture header");
    format!(
        "fixture_version=1\nset_count=2\nset_root={}\nhistory_count=2\nhistory_root={}\n",
        hex(&set.commitment().root),
        hex(&history.commitment().root)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: u8) -> Root {
        [value; 48]
    }

    #[test]
    fn witnessed_insertions_match_full_recomputation_and_replay_fails() {
        let mut reference = ReferenceSet::default();
        let mut commitment = reference.commitment();
        for value in 1..=24 {
            let key = key(value);
            let witness = reference.non_membership_witness(key).unwrap();
            let next = commitment.insert(key, &witness).unwrap();
            reference.insert(key).unwrap();
            assert_eq!(next, reference.commitment());
            assert_eq!(next.insert(key, &witness), Err(AccumulatorError::WrongRoot));
            commitment = next;
        }
    }

    #[test]
    fn wrong_key_path_and_malformed_witness_fail_closed() {
        let reference = ReferenceSet::default();
        let commitment = reference.commitment();
        let witness = reference.non_membership_witness(key(1)).unwrap();
        assert_eq!(commitment.insert(key(2), &witness), Err(AccumulatorError::WrongKey));
        let mut malformed = witness;
        malformed.siblings.pop();
        assert_eq!(commitment.insert(key(1), &malformed), Err(AccumulatorError::WrongKey));
        assert_eq!(
            partition_id([
                0x12, 0x3f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]),
            0x123
        );
    }

    #[test]
    fn replay_domains_have_distinct_roots_and_reject_cross_domain_witnesses() {
        let nullifiers = ReferenceSet::new(AccumulatorDomain::Nullifier);
        let revocations = ReferenceSet::new(AccumulatorDomain::Revocation);
        assert_ne!(nullifiers.commitment().root, revocations.commitment().root);

        let candidate = key(7);
        let nullifier_witness = nullifiers.non_membership_witness(candidate).unwrap();
        assert_eq!(
            revocations.commitment().insert(candidate, &nullifier_witness),
            Err(AccumulatorError::WrongRoot)
        );
    }

    #[test]
    fn history_append_and_archived_membership_proofs_bind_index_count_and_digest() {
        let mut reference = ReferenceHistory::default();
        let mut commitment = reference.commitment();
        for value in 1..=16 {
            let witness = reference.absence_witness().unwrap();
            let next = commitment.append(key(value), &witness).unwrap();
            reference.append(key(value)).unwrap();
            assert_eq!(next, reference.commitment());
            commitment = next;
        }
        for index in 0..16 {
            commitment.verify(&reference.proof(index).unwrap()).unwrap();
        }
        let mut substituted = reference.proof(3).unwrap();
        substituted.header_digest = key(99);
        assert_eq!(commitment.verify(&substituted), Err(AccumulatorError::WrongRoot));
    }

    #[test]
    fn checked_in_accumulator_fixture_does_not_drift() {
        assert_eq!(
            render_accumulator_fixture(),
            include_str!("../../../testing/storage/accumulator-v1.txt")
        );
    }
}
