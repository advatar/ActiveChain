use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::coin_cell_id;
use activechain_protocol_types::{CoinCellId, DIGEST_LENGTH, Digest384};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    CoinCellRecord, CoinCellSet, MAX_CASH_PARTITIONS, MAX_COIN_CELLS, MAX_TRANSFER_INPUTS,
    cash_partition_for,
};

pub const AUTHENTICATED_CASH_DEPTH: usize = DIGEST_LENGTH * 8;
const TRANSCRIPT_PREFIX: &[u8] = b"ACTIVECHAIN-AUTHENTICATED-COIN-CELLS";
const TRANSCRIPT_VERSION: u16 = 1;
const LEAF_KIND: u8 = 0;
const EMPTY_LEAF_KIND: u8 = 1;
const NODE_KIND: u8 = 2;
const ROOT_KIND: u8 = 3;
const PARTITION_ROOTS_KIND: u8 = 4;
pub const MAX_AUTHENTICATED_CASH_MUTATIONS: usize = MAX_TRANSFER_INPUTS + 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthenticatedCoinCellRoot(Digest384);

impl AuthenticatedCoinCellRoot {
    #[must_use]
    pub const fn new(digest: Digest384) -> Self {
        Self(digest)
    }

    #[must_use]
    pub const fn into_digest(self) -> Digest384 {
        self.0
    }
}

impl CanonicalEncode for AuthenticatedCoinCellRoot {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.0.encode(encoder)
    }
}

impl CanonicalDecode for AuthenticatedCoinCellRoot {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self(Digest384::decode(decoder)?))
    }
}

impl CanonicalType for AuthenticatedCoinCellRoot {
    const TYPE_TAG: u16 = 0x009a;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = DIGEST_LENGTH;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedCoinCellPartitionRoots {
    partitions: u16,
    roots: Vec<AuthenticatedCoinCellRoot>,
    global_root: Digest384,
}

impl AuthenticatedCoinCellPartitionRoots {
    #[must_use]
    pub const fn partitions(&self) -> u16 {
        self.partitions
    }

    #[must_use]
    pub fn roots(&self) -> &[AuthenticatedCoinCellRoot] {
        &self.roots
    }

    #[must_use]
    pub const fn global_root(&self) -> Digest384 {
        self.global_root
    }
}

impl CanonicalEncode for AuthenticatedCoinCellPartitionRoots {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.partitions.encode(encoder)?;
        encoder.write_length(self.roots.len(), usize::from(MAX_CASH_PARTITIONS))?;
        for root in &self.roots {
            root.encode(encoder)?;
        }
        self.global_root.encode(encoder)
    }
}

impl CanonicalDecode for AuthenticatedCoinCellPartitionRoots {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let partitions = u16::decode(decoder)?;
        let count = decoder.read_length(usize::from(MAX_CASH_PARTITIONS))?;
        if partitions == 0 || partitions > MAX_CASH_PARTITIONS || count != usize::from(partitions) {
            return Err(DecodeError::InvalidValue("invalid authenticated cash partition roots"));
        }
        let mut roots = Vec::with_capacity(count);
        for _ in 0..count {
            roots.push(AuthenticatedCoinCellRoot::decode(decoder)?);
        }
        let global_root = Digest384::decode(decoder)?;
        if authenticated_coin_cell_partition_roots_hash(partitions, &roots) != global_root {
            return Err(DecodeError::InvalidValue(
                "wrong authenticated cash global partition root",
            ));
        }
        Ok(Self { partitions, roots, global_root })
    }
}

impl CanonicalType for AuthenticatedCoinCellPartitionRoots {
    const TYPE_TAG: u16 = 0x009e;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        2 + 2 + MAX_CASH_PARTITIONS as usize * DIGEST_LENGTH + DIGEST_LENGTH;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinCellPartitionMutationWitness {
    partition: u16,
    transition: CoinCellTransitionWitness,
}

impl CoinCellPartitionMutationWitness {
    #[must_use]
    pub const fn partition(&self) -> u16 {
        self.partition
    }

    #[must_use]
    pub const fn transition(&self) -> &CoinCellTransitionWitness {
        &self.transition
    }
}

impl CanonicalEncode for CoinCellPartitionMutationWitness {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.partition.encode(encoder)?;
        self.transition.encode(encoder)
    }
}

impl CanonicalDecode for CoinCellPartitionMutationWitness {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            partition: u16::decode(decoder)?,
            transition: CoinCellTransitionWitness::decode(decoder)?,
        })
    }
}

impl CanonicalType for CoinCellPartitionMutationWitness {
    const TYPE_TAG: u16 = 0x009f;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 2 + CoinCellTransitionWitness::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinCellPartitionTransitionWitness {
    partitions: u16,
    pre_global_root: Digest384,
    post_global_root: Digest384,
    pre_roots: Vec<AuthenticatedCoinCellRoot>,
    mutations: Vec<CoinCellPartitionMutationWitness>,
}

impl CoinCellPartitionTransitionWitness {
    #[must_use]
    pub const fn partitions(&self) -> u16 {
        self.partitions
    }

    #[must_use]
    pub const fn pre_global_root(&self) -> Digest384 {
        self.pre_global_root
    }

    #[must_use]
    pub const fn post_global_root(&self) -> Digest384 {
        self.post_global_root
    }

    #[must_use]
    pub fn pre_roots(&self) -> &[AuthenticatedCoinCellRoot] {
        &self.pre_roots
    }

    #[must_use]
    pub fn mutations(&self) -> &[CoinCellPartitionMutationWitness] {
        &self.mutations
    }
}

impl CanonicalEncode for CoinCellPartitionTransitionWitness {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.partitions.encode(encoder)?;
        self.pre_global_root.encode(encoder)?;
        self.post_global_root.encode(encoder)?;
        encoder.write_length(self.pre_roots.len(), usize::from(MAX_CASH_PARTITIONS))?;
        for root in &self.pre_roots {
            root.encode(encoder)?;
        }
        encoder.write_length(self.mutations.len(), MAX_AUTHENTICATED_CASH_MUTATIONS)?;
        for mutation in &self.mutations {
            mutation.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for CoinCellPartitionTransitionWitness {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let partitions = u16::decode(decoder)?;
        let pre_global_root = Digest384::decode(decoder)?;
        let post_global_root = Digest384::decode(decoder)?;
        let root_count = decoder.read_length(usize::from(MAX_CASH_PARTITIONS))?;
        let mut pre_roots = Vec::with_capacity(root_count);
        for _ in 0..root_count {
            pre_roots.push(AuthenticatedCoinCellRoot::decode(decoder)?);
        }
        let mutation_count = decoder.read_length(MAX_AUTHENTICATED_CASH_MUTATIONS)?;
        let mut mutations = Vec::with_capacity(mutation_count);
        for _ in 0..mutation_count {
            mutations.push(CoinCellPartitionMutationWitness::decode(decoder)?);
        }
        let witness = Self { partitions, pre_global_root, post_global_root, pre_roots, mutations };
        verify_coin_cell_partition_transition(&witness).map_err(|_| {
            DecodeError::InvalidValue("invalid authenticated cash partition transition")
        })?;
        Ok(witness)
    }
}

impl CanonicalType for CoinCellPartitionTransitionWitness {
    const TYPE_TAG: u16 = 0x00a0;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 2
        + DIGEST_LENGTH * 2
        + 2
        + MAX_CASH_PARTITIONS as usize * DIGEST_LENGTH
        + 2
        + MAX_AUTHENTICATED_CASH_MUTATIONS * CoinCellPartitionMutationWitness::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoinCellMutationError {
    Encoding,
    InvalidShape,
    WrongRoot,
    WrongRecord,
    Capacity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinCellMutationWitness {
    pre_root: AuthenticatedCoinCellRoot,
    post_root: AuthenticatedCoinCellRoot,
    pre_count: u32,
    post_count: u32,
    id: CoinCellId,
    previous: Option<CoinCellRecord>,
    next: Option<CoinCellRecord>,
    siblings: Vec<Digest384>,
}

impl CoinCellMutationWitness {
    #[must_use]
    pub const fn pre_root(&self) -> AuthenticatedCoinCellRoot {
        self.pre_root
    }

    #[must_use]
    pub const fn post_root(&self) -> AuthenticatedCoinCellRoot {
        self.post_root
    }

    #[must_use]
    pub const fn pre_count(&self) -> u32 {
        self.pre_count
    }

    #[must_use]
    pub const fn post_count(&self) -> u32 {
        self.post_count
    }

    #[must_use]
    pub const fn id(&self) -> CoinCellId {
        self.id
    }

    #[must_use]
    pub const fn previous(&self) -> Option<CoinCellRecord> {
        self.previous
    }

    #[must_use]
    pub const fn next(&self) -> Option<CoinCellRecord> {
        self.next
    }

    #[must_use]
    pub fn siblings(&self) -> &[Digest384] {
        &self.siblings
    }
}

impl CanonicalEncode for CoinCellMutationWitness {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.pre_root.encode(encoder)?;
        self.post_root.encode(encoder)?;
        self.pre_count.encode(encoder)?;
        self.post_count.encode(encoder)?;
        self.id.encode(encoder)?;
        encode_record_option(self.previous, encoder)?;
        encode_record_option(self.next, encoder)?;
        encoder.write_length(self.siblings.len(), AUTHENTICATED_CASH_DEPTH)?;
        for sibling in &self.siblings {
            sibling.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for CoinCellMutationWitness {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let witness = Self {
            pre_root: AuthenticatedCoinCellRoot::decode(decoder)?,
            post_root: AuthenticatedCoinCellRoot::decode(decoder)?,
            pre_count: u32::decode(decoder)?,
            post_count: u32::decode(decoder)?,
            id: CoinCellId::decode(decoder)?,
            previous: decode_record_option(decoder)?,
            next: decode_record_option(decoder)?,
            siblings: {
                let count = decoder.read_length(AUTHENTICATED_CASH_DEPTH)?;
                let mut siblings = Vec::with_capacity(count);
                for _ in 0..count {
                    siblings.push(Digest384::decode(decoder)?);
                }
                siblings
            },
        };
        verify_coin_cell_mutation(&witness)
            .map_err(|_| DecodeError::InvalidValue("invalid authenticated Coin Cell mutation"))?;
        Ok(witness)
    }
}

impl CanonicalType for CoinCellMutationWitness {
    const TYPE_TAG: u16 = 0x009b;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = DIGEST_LENGTH * 3
        + 4 * 2
        + 1
        + CoinCellRecord::MAX_ENCODED_LEN
        + 1
        + CoinCellRecord::MAX_ENCODED_LEN
        + 2
        + AUTHENTICATED_CASH_DEPTH * DIGEST_LENGTH;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinCellTransitionWitness {
    pre_root: AuthenticatedCoinCellRoot,
    post_root: AuthenticatedCoinCellRoot,
    mutations: Vec<CoinCellMutationWitness>,
}

impl CoinCellTransitionWitness {
    #[must_use]
    pub const fn pre_root(&self) -> AuthenticatedCoinCellRoot {
        self.pre_root
    }

    #[must_use]
    pub const fn post_root(&self) -> AuthenticatedCoinCellRoot {
        self.post_root
    }

    #[must_use]
    pub fn mutations(&self) -> &[CoinCellMutationWitness] {
        &self.mutations
    }
}

impl CanonicalEncode for CoinCellTransitionWitness {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.pre_root.encode(encoder)?;
        self.post_root.encode(encoder)?;
        encoder.write_length(self.mutations.len(), MAX_AUTHENTICATED_CASH_MUTATIONS)?;
        for mutation in &self.mutations {
            mutation.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for CoinCellTransitionWitness {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let pre_root = AuthenticatedCoinCellRoot::decode(decoder)?;
        let post_root = AuthenticatedCoinCellRoot::decode(decoder)?;
        let count = decoder.read_length(MAX_AUTHENTICATED_CASH_MUTATIONS)?;
        let mut mutations = Vec::with_capacity(count);
        for _ in 0..count {
            mutations.push(CoinCellMutationWitness::decode(decoder)?);
        }
        let witness = Self { pre_root, post_root, mutations };
        verify_coin_cell_transition(&witness)
            .map_err(|_| DecodeError::InvalidValue("invalid authenticated Coin Cell transition"))?;
        Ok(witness)
    }
}

impl CanonicalType for CoinCellTransitionWitness {
    const TYPE_TAG: u16 = 0x009c;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = DIGEST_LENGTH * 2
        + 1
        + MAX_AUTHENTICATED_CASH_MUTATIONS * CoinCellMutationWitness::MAX_ENCODED_LEN;
}

pub fn authenticated_coin_cell_root(
    cells: &CoinCellSet,
) -> Result<AuthenticatedCoinCellRoot, CoinCellMutationError> {
    let tree = build_tree(cells, None)?.0;
    Ok(hash_root(cells.as_slice().len(), tree))
}

pub fn authenticated_coin_cell_partition_roots(
    cells: &CoinCellSet,
    partitions: u16,
) -> Result<AuthenticatedCoinCellPartitionRoots, CoinCellMutationError> {
    let grouped = partition_coin_cell_sets(cells, partitions)?;
    let roots = grouped.iter().map(authenticated_coin_cell_root).collect::<Result<Vec<_>, _>>()?;
    let global_root = authenticated_coin_cell_partition_roots_hash(partitions, &roots);
    Ok(AuthenticatedCoinCellPartitionRoots { partitions, roots, global_root })
}

fn partition_coin_cell_sets(
    cells: &CoinCellSet,
    partitions: u16,
) -> Result<Vec<CoinCellSet>, CoinCellMutationError> {
    if partitions == 0 || partitions > MAX_CASH_PARTITIONS {
        return Err(CoinCellMutationError::InvalidShape);
    }
    let mut grouped = vec![Vec::new(); usize::from(partitions)];
    for record in cells.as_slice() {
        grouped[usize::from(cash_partition_for(record.id(), partitions))].push(*record);
    }
    grouped
        .into_iter()
        .map(|records| CoinCellSet::new(records).map_err(|_| CoinCellMutationError::WrongRecord))
        .collect()
}

#[must_use]
pub fn authenticated_coin_cell_partition_roots_transcript(
    partitions: u16,
    roots: &[AuthenticatedCoinCellRoot],
) -> Vec<u8> {
    let mut transcript = transcript_prefix(PARTITION_ROOTS_KIND);
    transcript.extend_from_slice(&partitions.to_be_bytes());
    for (index, root) in roots.iter().enumerate() {
        transcript.extend_from_slice(&(index as u16).to_be_bytes());
        transcript.extend_from_slice(root.into_digest().as_bytes());
    }
    transcript
}

#[must_use]
pub fn authenticated_coin_cell_partition_roots_hash(
    partitions: u16,
    roots: &[AuthenticatedCoinCellRoot],
) -> Digest384 {
    hash_transcript(&authenticated_coin_cell_partition_roots_transcript(partitions, roots))
}

pub fn authenticated_coin_cell_leaf_transcript(
    record: &CoinCellRecord,
) -> Result<Vec<u8>, CoinCellMutationError> {
    if !record_has_canonical_id(*record) {
        return Err(CoinCellMutationError::WrongRecord);
    }
    let mut encoder = Encoder::new(CoinCellRecord::MAX_ENCODED_LEN);
    record.encode(&mut encoder).map_err(|_| CoinCellMutationError::Encoding)?;
    let bytes = encoder.finish();
    let mut transcript = transcript_prefix(LEAF_KIND);
    transcript.extend_from_slice(record.id().into_digest().as_bytes());
    transcript.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    transcript.extend_from_slice(&bytes);
    Ok(transcript)
}

#[must_use]
pub fn authenticated_empty_coin_cell_leaf_transcript() -> Vec<u8> {
    transcript_prefix(EMPTY_LEAF_KIND)
}

pub fn authenticated_coin_cell_node_transcript(
    depth: usize,
    left: Digest384,
    right: Digest384,
) -> Result<Vec<u8>, CoinCellMutationError> {
    if depth >= AUTHENTICATED_CASH_DEPTH {
        return Err(CoinCellMutationError::InvalidShape);
    }
    let mut transcript = transcript_prefix(NODE_KIND);
    transcript.extend_from_slice(&(depth as u16).to_be_bytes());
    transcript.extend_from_slice(left.as_bytes());
    transcript.extend_from_slice(right.as_bytes());
    Ok(transcript)
}

pub fn authenticated_coin_cell_root_transcript(
    count: usize,
    tree: Digest384,
) -> Result<Vec<u8>, CoinCellMutationError> {
    if count > MAX_COIN_CELLS {
        return Err(CoinCellMutationError::Capacity);
    }
    let mut transcript = transcript_prefix(ROOT_KIND);
    transcript.extend_from_slice(&(count as u32).to_be_bytes());
    transcript.extend_from_slice(tree.as_bytes());
    Ok(transcript)
}

pub fn authenticated_coin_cell_leaf_hash(
    record: &CoinCellRecord,
) -> Result<Digest384, CoinCellMutationError> {
    authenticated_coin_cell_leaf_transcript(record).map(|transcript| hash_transcript(&transcript))
}

#[must_use]
pub fn authenticated_empty_coin_cell_leaf_hash() -> Digest384 {
    hash_transcript(&authenticated_empty_coin_cell_leaf_transcript())
}

pub fn authenticated_coin_cell_node_hash(
    depth: usize,
    left: Digest384,
    right: Digest384,
) -> Result<Digest384, CoinCellMutationError> {
    authenticated_coin_cell_node_transcript(depth, left, right)
        .map(|transcript| hash_transcript(&transcript))
}

pub fn authenticated_coin_cell_count_root_hash(
    count: usize,
    tree: Digest384,
) -> Result<AuthenticatedCoinCellRoot, CoinCellMutationError> {
    authenticated_coin_cell_root_transcript(count, tree)
        .map(|transcript| AuthenticatedCoinCellRoot(hash_transcript(&transcript)))
}

pub fn prove_coin_cell_mutation(
    cells: &CoinCellSet,
    id: CoinCellId,
    next: Option<CoinCellRecord>,
) -> Result<CoinCellMutationWitness, CoinCellMutationError> {
    let position = cells.as_slice().binary_search_by_key(&id, |record| record.id());
    let previous = position.ok().map(|index| cells.as_slice()[index]);
    if previous == next
        || previous.is_some_and(|record| record.id() != id)
        || next.is_some_and(|record| record.id() != id)
    {
        return Err(CoinCellMutationError::InvalidShape);
    }
    let post_count = match (previous, next) {
        (None, Some(_)) => cells
            .as_slice()
            .len()
            .checked_add(1)
            .filter(|count| *count <= MAX_COIN_CELLS)
            .ok_or(CoinCellMutationError::Capacity)?,
        (Some(_), None) => cells.as_slice().len() - 1,
        (Some(_), Some(_)) => cells.as_slice().len(),
        (None, None) => return Err(CoinCellMutationError::InvalidShape),
    };
    let (pre_tree, siblings) = build_tree(cells, Some(id))?;
    let pre_count =
        u32::try_from(cells.as_slice().len()).map_err(|_| CoinCellMutationError::Capacity)?;
    let post_count = u32::try_from(post_count).map_err(|_| CoinCellMutationError::Capacity)?;
    let pre_root = hash_root(pre_count as usize, pre_tree);
    let post_tree = reconstruct_tree(id, next.as_ref().map(hash_leaf).transpose()?, &siblings)?;
    let post_root = hash_root(post_count as usize, post_tree);
    let witness = CoinCellMutationWitness {
        pre_root,
        post_root,
        pre_count,
        post_count,
        id,
        previous,
        next,
        siblings,
    };
    verify_coin_cell_mutation(&witness)?;
    Ok(witness)
}

pub fn verify_coin_cell_mutation(
    witness: &CoinCellMutationWitness,
) -> Result<(), CoinCellMutationError> {
    if witness.siblings.len() != AUTHENTICATED_CASH_DEPTH
        || witness.previous == witness.next
        || witness.previous.is_some_and(|record| record.id() != witness.id)
        || witness.next.is_some_and(|record| record.id() != witness.id)
    {
        return Err(CoinCellMutationError::InvalidShape);
    }
    if witness.previous.is_some_and(|record| !record_has_canonical_id(record))
        || witness.next.is_some_and(|record| !record_has_canonical_id(record))
    {
        return Err(CoinCellMutationError::WrongRecord);
    }
    let expected_post_count = match (witness.previous, witness.next) {
        (None, Some(_)) => witness.pre_count.checked_add(1),
        (Some(_), None) => witness.pre_count.checked_sub(1),
        (Some(_), Some(_)) => Some(witness.pre_count),
        (None, None) => None,
    };
    if expected_post_count != Some(witness.post_count)
        || usize::try_from(witness.post_count).map_or(true, |count| count > MAX_COIN_CELLS)
    {
        return Err(CoinCellMutationError::Capacity);
    }
    let pre_tree = reconstruct_tree(
        witness.id,
        witness.previous.as_ref().map(hash_leaf).transpose()?,
        &witness.siblings,
    )?;
    let post_tree = reconstruct_tree(
        witness.id,
        witness.next.as_ref().map(hash_leaf).transpose()?,
        &witness.siblings,
    )?;
    if hash_root(witness.pre_count as usize, pre_tree) != witness.pre_root
        || hash_root(witness.post_count as usize, post_tree) != witness.post_root
    {
        return Err(CoinCellMutationError::WrongRoot);
    }
    Ok(())
}

fn record_has_canonical_id(record: CoinCellRecord) -> bool {
    coin_cell_id(&record.cell().origin()).is_ok_and(|expected| expected == record.id())
}

pub fn prove_coin_cell_transition(
    pre: &CoinCellSet,
    post: &CoinCellSet,
) -> Result<CoinCellTransitionWitness, CoinCellMutationError> {
    let mut changes = Vec::new();
    let mut pre_index = 0;
    let mut post_index = 0;
    while pre_index < pre.as_slice().len() || post_index < post.as_slice().len() {
        match (pre.as_slice().get(pre_index), post.as_slice().get(post_index)) {
            (Some(before), Some(after)) if before.id() == after.id() => {
                if before != after {
                    changes.push((before.id(), Some(*after)));
                }
                pre_index += 1;
                post_index += 1;
            }
            (Some(before), Some(after)) if before.id() < after.id() => {
                changes.push((before.id(), None));
                pre_index += 1;
            }
            (Some(_), Some(after)) => {
                changes.push((after.id(), Some(*after)));
                post_index += 1;
            }
            (Some(before), None) => {
                changes.push((before.id(), None));
                pre_index += 1;
            }
            (None, Some(after)) => {
                changes.push((after.id(), Some(*after)));
                post_index += 1;
            }
            (None, None) => break,
        }
    }
    if changes.is_empty() || changes.len() > MAX_AUTHENTICATED_CASH_MUTATIONS {
        return Err(CoinCellMutationError::InvalidShape);
    }
    changes.sort_by_key(|change| change.0);
    let pre_root = authenticated_coin_cell_root(pre)?;
    let mut current = pre.clone();
    let mut mutations = Vec::with_capacity(changes.len());
    for (id, next) in changes {
        let mutation = prove_coin_cell_mutation(&current, id, next)?;
        current = apply_mutation(&current, id, next)?;
        mutations.push(mutation);
    }
    if &current != post {
        return Err(CoinCellMutationError::WrongRecord);
    }
    let witness = CoinCellTransitionWitness {
        pre_root,
        post_root: authenticated_coin_cell_root(post)?,
        mutations,
    };
    verify_coin_cell_transition(&witness)?;
    Ok(witness)
}

pub fn verify_coin_cell_transition(
    witness: &CoinCellTransitionWitness,
) -> Result<(), CoinCellMutationError> {
    if witness.mutations.is_empty()
        || witness.mutations.len() > MAX_AUTHENTICATED_CASH_MUTATIONS
        || witness.mutations.windows(2).any(|pair| pair[0].id() >= pair[1].id())
        || witness.mutations[0].pre_root() != witness.pre_root
        || witness.mutations.last().map(CoinCellMutationWitness::post_root)
            != Some(witness.post_root)
    {
        return Err(CoinCellMutationError::InvalidShape);
    }
    for (index, mutation) in witness.mutations.iter().enumerate() {
        verify_coin_cell_mutation(mutation)?;
        if index > 0 && witness.mutations[index - 1].post_root() != mutation.pre_root() {
            return Err(CoinCellMutationError::WrongRoot);
        }
    }
    Ok(())
}

pub fn prove_coin_cell_partition_transition(
    pre: &CoinCellSet,
    post: &CoinCellSet,
    partitions: u16,
) -> Result<CoinCellPartitionTransitionWitness, CoinCellMutationError> {
    let pre_sets = partition_coin_cell_sets(pre, partitions)?;
    let post_sets = partition_coin_cell_sets(post, partitions)?;
    let pre_roots =
        pre_sets.iter().map(authenticated_coin_cell_root).collect::<Result<Vec<_>, _>>()?;
    let post_roots =
        post_sets.iter().map(authenticated_coin_cell_root).collect::<Result<Vec<_>, _>>()?;
    let mut mutations = Vec::new();
    for (partition, (pre_set, post_set)) in pre_sets.iter().zip(&post_sets).enumerate() {
        if pre_set != post_set {
            mutations.push(CoinCellPartitionMutationWitness {
                partition: u16::try_from(partition).map_err(|_| CoinCellMutationError::Capacity)?,
                transition: prove_coin_cell_transition(pre_set, post_set)?,
            });
        }
    }
    if mutations.is_empty() || mutations.len() > MAX_AUTHENTICATED_CASH_MUTATIONS {
        return Err(CoinCellMutationError::InvalidShape);
    }
    let witness = CoinCellPartitionTransitionWitness {
        partitions,
        pre_global_root: authenticated_coin_cell_partition_roots_hash(partitions, &pre_roots),
        post_global_root: authenticated_coin_cell_partition_roots_hash(partitions, &post_roots),
        pre_roots,
        mutations,
    };
    verify_coin_cell_partition_transition(&witness)?;
    Ok(witness)
}

pub fn verify_coin_cell_partition_transition(
    witness: &CoinCellPartitionTransitionWitness,
) -> Result<(), CoinCellMutationError> {
    if witness.partitions == 0
        || witness.partitions > MAX_CASH_PARTITIONS
        || witness.pre_roots.len() != usize::from(witness.partitions)
        || witness.mutations.is_empty()
        || witness.mutations.len() > MAX_AUTHENTICATED_CASH_MUTATIONS
        || witness.mutations.windows(2).any(|pair| pair[0].partition >= pair[1].partition)
        || authenticated_coin_cell_partition_roots_hash(witness.partitions, &witness.pre_roots)
            != witness.pre_global_root
    {
        return Err(CoinCellMutationError::InvalidShape);
    }
    let mut post_roots = witness.pre_roots.clone();
    for mutation in &witness.mutations {
        let partition = usize::from(mutation.partition);
        if partition >= post_roots.len()
            || mutation.transition.pre_root != witness.pre_roots[partition]
            || mutation.transition.pre_root == mutation.transition.post_root
        {
            return Err(CoinCellMutationError::WrongRoot);
        }
        verify_coin_cell_transition(&mutation.transition)?;
        if mutation
            .transition
            .mutations
            .iter()
            .any(|nested| cash_partition_for(nested.id(), witness.partitions) != mutation.partition)
        {
            return Err(CoinCellMutationError::WrongRecord);
        }
        post_roots[partition] = mutation.transition.post_root;
    }
    if authenticated_coin_cell_partition_roots_hash(witness.partitions, &post_roots)
        != witness.post_global_root
    {
        return Err(CoinCellMutationError::WrongRoot);
    }
    Ok(())
}

fn apply_mutation(
    cells: &CoinCellSet,
    id: CoinCellId,
    next: Option<CoinCellRecord>,
) -> Result<CoinCellSet, CoinCellMutationError> {
    let mut records = cells.as_slice().to_vec();
    match records.binary_search_by_key(&id, |record| record.id()) {
        Ok(index) => match next {
            Some(record) => records[index] = record,
            None => {
                records.remove(index);
            }
        },
        Err(index) => {
            let record = next.ok_or(CoinCellMutationError::WrongRecord)?;
            records.insert(index, record);
        }
    }
    CoinCellSet::new(records).map_err(|_| CoinCellMutationError::WrongRecord)
}

fn build_tree(
    cells: &CoinCellSet,
    proof_id: Option<CoinCellId>,
) -> Result<(Digest384, Vec<Digest384>), CoinCellMutationError> {
    let empty = empty_hashes();
    let mut level = BTreeMap::<[u8; DIGEST_LENGTH], Digest384>::new();
    for record in cells.as_slice() {
        if !record_has_canonical_id(*record) {
            return Err(CoinCellMutationError::WrongRecord);
        }
        let key = *record.id().into_digest().as_bytes();
        if level.insert(key, hash_leaf(record)?).is_some() {
            return Err(CoinCellMutationError::WrongRecord);
        }
    }
    let mut target = proof_id.map(|id| *id.into_digest().as_bytes());
    let mut siblings = Vec::with_capacity(AUTHENTICATED_CASH_DEPTH);
    for child_depth in (1..=AUTHENTICATED_CASH_DEPTH).rev() {
        if let Some(key) = target {
            let mut sibling = key;
            toggle_bit(&mut sibling, child_depth - 1);
            siblings.push(level.get(&sibling).copied().unwrap_or(empty[child_depth]));
        }
        let mut parents = BTreeMap::new();
        for key in level.keys() {
            let mut parent = *key;
            clear_bit(&mut parent, child_depth - 1);
            if parents.contains_key(&parent) {
                continue;
            }
            let mut right = parent;
            set_bit(&mut right, child_depth - 1);
            let left_hash = level.get(&parent).copied().unwrap_or(empty[child_depth]);
            let right_hash = level.get(&right).copied().unwrap_or(empty[child_depth]);
            parents.insert(parent, hash_node(child_depth - 1, left_hash, right_hash));
        }
        level = parents;
        if let Some(key) = &mut target {
            clear_bit(key, child_depth - 1);
        }
    }
    let root = level.values().next().copied().unwrap_or(empty[0]);
    Ok((root, siblings))
}

fn reconstruct_tree(
    id: CoinCellId,
    leaf: Option<Digest384>,
    siblings: &[Digest384],
) -> Result<Digest384, CoinCellMutationError> {
    if siblings.len() != AUTHENTICATED_CASH_DEPTH {
        return Err(CoinCellMutationError::InvalidShape);
    }
    let key = id.into_digest();
    let mut current = leaf.unwrap_or_else(empty_leaf);
    for (offset, sibling) in siblings.iter().enumerate() {
        let depth = AUTHENTICATED_CASH_DEPTH - 1 - offset;
        current = if bit(key.as_bytes(), depth) == 0 {
            hash_node(depth, current, *sibling)
        } else {
            hash_node(depth, *sibling, current)
        };
    }
    Ok(current)
}

fn hash_leaf(record: &CoinCellRecord) -> Result<Digest384, CoinCellMutationError> {
    authenticated_coin_cell_leaf_hash(record)
}

fn hash_node(depth: usize, left: Digest384, right: Digest384) -> Digest384 {
    authenticated_coin_cell_node_hash(depth, left, right)
        .expect("internal authenticated cash depth is bounded")
}

fn hash_root(count: usize, tree: Digest384) -> AuthenticatedCoinCellRoot {
    authenticated_coin_cell_count_root_hash(count, tree)
        .expect("internal authenticated cash count is bounded")
}

fn empty_hashes() -> [Digest384; AUTHENTICATED_CASH_DEPTH + 1] {
    let mut hashes = [Digest384::ZERO; AUTHENTICATED_CASH_DEPTH + 1];
    hashes[AUTHENTICATED_CASH_DEPTH] = empty_leaf();
    for depth in (0..AUTHENTICATED_CASH_DEPTH).rev() {
        hashes[depth] = hash_node(depth, hashes[depth + 1], hashes[depth + 1]);
    }
    hashes
}

fn empty_leaf() -> Digest384 {
    authenticated_empty_coin_cell_leaf_hash()
}

fn encode_record_option(
    record: Option<CoinCellRecord>,
    encoder: &mut Encoder,
) -> Result<(), EncodeError> {
    encoder.write_bool(record.is_some())?;
    if let Some(record) = record {
        record.encode(encoder)?;
    }
    Ok(())
}

fn decode_record_option(decoder: &mut Decoder<'_>) -> Result<Option<CoinCellRecord>, DecodeError> {
    if bool::decode(decoder)? { Ok(Some(CoinCellRecord::decode(decoder)?)) } else { Ok(None) }
}

fn transcript_prefix(kind: u8) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(TRANSCRIPT_PREFIX.len() + 3);
    transcript.extend_from_slice(TRANSCRIPT_PREFIX);
    transcript.extend_from_slice(&TRANSCRIPT_VERSION.to_be_bytes());
    transcript.push(kind);
    transcript
}

fn hash_transcript(transcript: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(transcript);
    let mut output = [0_u8; DIGEST_LENGTH];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

fn bit(bytes: &[u8; DIGEST_LENGTH], depth: usize) -> u8 {
    (bytes[depth / 8] >> (7 - depth % 8)) & 1
}

fn toggle_bit(bytes: &mut [u8; DIGEST_LENGTH], depth: usize) {
    bytes[depth / 8] ^= 1 << (7 - depth % 8);
}

fn clear_bit(bytes: &mut [u8; DIGEST_LENGTH], depth: usize) {
    bytes[depth / 8] &= !(1 << (7 - depth % 8));
}

fn set_bit(bytes: &mut [u8; DIGEST_LENGTH], depth: usize) {
    bytes[depth / 8] |= 1 << (7 - depth % 8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoinCell, CoinCellOrigin};
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use activechain_protocol_types::{PrincipalId, TransactionId};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; DIGEST_LENGTH])
    }

    fn record(byte: u8, amount: u128) -> CoinCellRecord {
        let origin = CoinCellOrigin::new(TransactionId::new(digest(byte + 20)), 0);
        let id = coin_cell_id(&origin).unwrap();
        CoinCellRecord::new(
            id,
            CoinCell::new(origin, PrincipalId::new(digest(90)), amount, 1).unwrap(),
        )
    }

    fn set(records: &[CoinCellRecord]) -> CoinCellSet {
        let mut records = records.to_vec();
        records.sort_by_key(|record| record.id());
        CoinCellSet::new(records).unwrap()
    }

    #[test]
    fn sparse_membership_consumption_and_insertion_match_full_recomputation() {
        let first = record(1, 10);
        let second = record(2, 20);
        let third = record(3, 30);
        let initial = set(&[first, second, third]);

        let removal = prove_coin_cell_mutation(&initial, second.id(), None).unwrap();
        verify_coin_cell_mutation(&removal).unwrap();
        let after_removal = set(&[first, third]);
        assert_eq!(removal.pre_root(), authenticated_coin_cell_root(&initial).unwrap());
        assert_eq!(removal.post_root(), authenticated_coin_cell_root(&after_removal).unwrap());

        let fourth = record(4, 40);
        let insertion =
            prove_coin_cell_mutation(&after_removal, fourth.id(), Some(fourth)).unwrap();
        verify_coin_cell_mutation(&insertion).unwrap();
        assert_eq!(insertion.previous(), None);
        assert_eq!(insertion.next(), Some(fourth));
        assert_eq!(
            insertion.post_root(),
            authenticated_coin_cell_root(&set(&[first, third, fourth])).unwrap()
        );
    }

    #[test]
    fn partition_roots_use_canonical_mapping_and_bind_order_and_count() {
        let first = record(1, 10);
        let second = record(2, 20);
        let third = record(3, 30);
        let initial = set(&[first, second, third]);
        let roots = authenticated_coin_cell_partition_roots(&initial, 8).unwrap();
        assert_eq!(roots.partitions(), 8);
        assert_eq!(roots.roots().len(), 8);
        for record in initial.as_slice() {
            let partition = usize::from(cash_partition_for(record.id(), 8));
            let local = set(&[*record]);
            if initial
                .as_slice()
                .iter()
                .filter(|candidate| cash_partition_for(candidate.id(), 8) == partition as u16)
                .count()
                == 1
            {
                assert_eq!(roots.roots()[partition], authenticated_coin_cell_root(&local).unwrap());
            }
        }

        let replacement = record(2, 25);
        let changed =
            authenticated_coin_cell_partition_roots(&set(&[first, replacement, third]), 8).unwrap();
        assert_eq!(
            roots.roots().iter().zip(changed.roots()).filter(|(left, right)| left != right).count(),
            1
        );
        assert_ne!(roots.global_root(), changed.global_root());
        assert_ne!(
            roots.global_root(),
            authenticated_coin_cell_partition_roots(&initial, 4).unwrap().global_root()
        );
        let mut reordered = roots.roots().to_vec();
        let left = reordered
            .iter()
            .enumerate()
            .find_map(|(index, root)| {
                reordered.iter().position(|candidate| candidate != root).map(|right| (index, right))
            })
            .unwrap();
        reordered.swap(left.0, left.1);
        assert_ne!(
            roots.global_root(),
            authenticated_coin_cell_partition_roots_hash(8, &reordered)
        );

        let encoded = encode_envelope(&roots).unwrap();
        assert_eq!(decode_envelope(&encoded), Ok(roots.clone()));
        let mut tampered = encoded;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decode_envelope::<AuthenticatedCoinCellPartitionRoots>(&tampered).is_err());
        assert_eq!(
            authenticated_coin_cell_partition_roots(&initial, 0),
            Err(CoinCellMutationError::InvalidShape)
        );
    }

    #[test]
    fn canonical_transition_chains_ordered_mutations_and_round_trips() {
        let first = record(1, 10);
        let second = record(2, 20);
        let third = record(3, 30);
        let fourth = record(4, 40);
        let pre = set(&[first, second, third]);
        let post = set(&[first, third, fourth]);
        let transition = prove_coin_cell_transition(&pre, &post).unwrap();
        assert_eq!(transition.mutations().len(), 2);
        assert!(transition.mutations().iter().any(|mutation| mutation.id() == second.id()));
        assert!(transition.mutations().iter().any(|mutation| mutation.id() == fourth.id()));
        assert!(transition.mutations().windows(2).all(|pair| pair[0].id() < pair[1].id()));
        verify_coin_cell_transition(&transition).unwrap();
        let encoded = encode_envelope(&transition).unwrap();
        assert_eq!(decode_envelope::<CoinCellTransitionWitness>(&encoded), Ok(transition));
    }

    #[test]
    fn partition_transition_authenticates_changed_partition_roots_and_round_trips() {
        let first = record(1, 10);
        let second = record(2, 20);
        let third = record(3, 30);
        let fourth = record(4, 40);
        let pre = set(&[first, second, third]);
        let post = set(&[first, third, fourth]);
        let witness = prove_coin_cell_partition_transition(&pre, &post, 8).unwrap();
        let pre_roots = authenticated_coin_cell_partition_roots(&pre, 8).unwrap();
        let post_roots = authenticated_coin_cell_partition_roots(&post, 8).unwrap();

        assert_eq!(witness.pre_global_root(), pre_roots.global_root());
        assert_eq!(witness.post_global_root(), post_roots.global_root());
        assert!(
            witness.mutations().windows(2).all(|pair| pair[0].partition() < pair[1].partition())
        );
        for mutation in witness.mutations() {
            assert!(mutation.transition().mutations().iter().all(|nested| {
                cash_partition_for(nested.id(), witness.partitions()) == mutation.partition()
            }));
        }
        verify_coin_cell_partition_transition(&witness).unwrap();
        let encoded = encode_envelope(&witness).unwrap();
        assert_eq!(decode_envelope::<CoinCellPartitionTransitionWitness>(&encoded), Ok(witness));
    }

    #[test]
    fn partition_transition_rejects_wrong_partition_roots_order_and_encoding() {
        let first = record(1, 10);
        let second = record(2, 20);
        let third = record(3, 30);
        let fourth = record(4, 40);
        let witness =
            prove_coin_cell_partition_transition(&set(&[first, second]), &set(&[third, fourth]), 8)
                .unwrap();

        let mut wrong_partition = witness.clone();
        wrong_partition.mutations[0].partition =
            (wrong_partition.mutations[0].partition + 1) % wrong_partition.partitions;
        assert!(verify_coin_cell_partition_transition(&wrong_partition).is_err());

        let mut wrong_pre_root = witness.clone();
        wrong_pre_root.pre_roots[0] = AuthenticatedCoinCellRoot::new(digest(71));
        assert!(verify_coin_cell_partition_transition(&wrong_pre_root).is_err());

        let mut substituted_global = witness.clone();
        substituted_global.post_global_root = digest(72);
        assert_eq!(
            verify_coin_cell_partition_transition(&substituted_global),
            Err(CoinCellMutationError::WrongRoot)
        );

        if witness.mutations().len() > 1 {
            let mut wrong_order = witness.clone();
            wrong_order.mutations.reverse();
            assert_eq!(
                verify_coin_cell_partition_transition(&wrong_order),
                Err(CoinCellMutationError::InvalidShape)
            );
        }

        let mut malformed = encode_envelope(&witness).unwrap();
        *malformed.last_mut().unwrap() ^= 1;
        assert!(decode_envelope::<CoinCellPartitionTransitionWitness>(&malformed).is_err());
    }

    #[test]
    fn substituted_paths_roots_records_and_order_fail_closed() {
        let first = record(1, 10);
        let second = record(2, 20);
        let third = record(3, 30);
        let pre = set(&[first, second]);
        let post = set(&[first, third]);
        let transition = prove_coin_cell_transition(&pre, &post).unwrap();

        let mut wrong_path = transition.mutations()[0].clone();
        wrong_path.siblings[0] = digest(77);
        assert_eq!(verify_coin_cell_mutation(&wrong_path), Err(CoinCellMutationError::WrongRoot));

        let mut wrong_root = transition.clone();
        wrong_root.post_root = AuthenticatedCoinCellRoot::new(digest(78));
        assert!(verify_coin_cell_transition(&wrong_root).is_err());

        let mut wrong_record = transition
            .mutations()
            .iter()
            .find(|mutation| mutation.previous().is_some())
            .unwrap()
            .clone();
        let substituted_cell = third.cell();
        wrong_record.previous = Some(CoinCellRecord::new(wrong_record.id(), substituted_cell));
        assert_eq!(
            verify_coin_cell_mutation(&wrong_record),
            Err(CoinCellMutationError::WrongRecord)
        );

        let mut wrong_order = transition;
        wrong_order.mutations.reverse();
        assert_eq!(
            verify_coin_cell_transition(&wrong_order),
            Err(CoinCellMutationError::InvalidShape)
        );

        let mut malformed = encode_envelope(&wrong_path).unwrap();
        malformed.truncate(malformed.len() - DIGEST_LENGTH);
        assert!(decode_envelope::<CoinCellMutationWitness>(&malformed).is_err());
    }

    #[test]
    fn empty_and_singleton_roots_are_domain_and_count_bound() {
        let empty = set(&[]);
        let singleton = set(&[record(1, 10)]);
        assert_ne!(
            authenticated_coin_cell_root(&empty).unwrap(),
            authenticated_coin_cell_root(&singleton).unwrap()
        );
        let replacement = record(1, 11);
        let mutation =
            prove_coin_cell_mutation(&singleton, replacement.id(), Some(replacement)).unwrap();
        assert_eq!(mutation.pre_count, mutation.post_count);
        assert_ne!(mutation.pre_root(), mutation.post_root());
    }
}
