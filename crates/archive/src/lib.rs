#![forbid(unsafe_code)]

use reed_solomon_erasure::galois_8::ReedSolomon;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::collections::{BTreeMap, BTreeSet};

pub type Root = [u8; 48];

pub const DATA_SHARDS: usize = 8;
pub const TOTAL_SHARDS: usize = 12;
pub const PARITY_SHARDS: usize = TOTAL_SHARDS - DATA_SHARDS;
pub const MIN_FAILURE_DOMAINS: usize = 4;
pub const MAX_SHARDS_PER_FAILURE_DOMAIN: usize = 3;
pub const CHUNK_BYTES: usize = 4_096;
pub const MAX_ARCHIVE_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_RECEIPT_SIGNATURE_BYTES: usize = 8_192;

#[must_use]
pub fn content_commitment(payload: &[u8]) -> Root {
    digest(&[b"ACTIVECHAIN-ARCHIVE-CONTENT-V1", payload])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveError {
    Bounds,
    Identity,
    Diversity,
    Expired,
    Corrupt,
    InsufficientShards,
    Coding,
    Signature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ArchiveDataClass {
    Ledger = 1,
    Witness = 2,
    Snapshot = 3,
    HibernatedObject = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ArchiveProvider {
    pub principal: Root,
    pub failure_domain: Root,
}

impl ArchiveProvider {
    pub fn new(principal: Root, failure_domain: Root) -> Result<Self, ArchiveError> {
        if principal == [0; 48] || failure_domain == [0; 48] {
            return Err(ArchiveError::Identity);
        }
        Ok(Self { principal, failure_domain })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveAssignment {
    pub shard_index: u8,
    pub provider: ArchiveProvider,
    pub shard_root: Root,
    pub shard_bytes: u64,
    pub chunk_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveManifest {
    pub chain_genesis: Root,
    pub content_root: Root,
    pub data_class: ArchiveDataClass,
    pub first_height: u64,
    pub last_height: u64,
    pub original_bytes: u64,
    pub shard_bytes: u64,
    pub retention_expiry_epoch: u64,
    pub assignments: [ArchiveAssignment; TOTAL_SHARDS],
    pub manifest_root: Root,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveShard {
    pub shard_index: u8,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveBundle {
    pub manifest: ArchiveManifest,
    pub shards: Vec<ArchiveShard>,
}

impl ArchiveBundle {
    pub fn encode(
        payload: &[u8],
        chain_genesis: Root,
        data_class: ArchiveDataClass,
        first_height: u64,
        last_height: u64,
        retention_expiry_epoch: u64,
        providers: [ArchiveProvider; TOTAL_SHARDS],
    ) -> Result<Self, ArchiveError> {
        if payload.is_empty()
            || payload.len() > MAX_ARCHIVE_PAYLOAD_BYTES
            || chain_genesis == [0; 48]
            || first_height == 0
            || last_height < first_height
            || retention_expiry_epoch == 0
        {
            return Err(ArchiveError::Bounds);
        }
        validate_providers(&providers)?;
        let shard_size = payload.len().div_ceil(DATA_SHARDS);
        let mut raw_shards = vec![vec![0_u8; shard_size]; TOTAL_SHARDS];
        for (index, byte) in payload.iter().enumerate() {
            raw_shards[index / shard_size][index % shard_size] = *byte;
        }
        ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
            .map_err(|_| ArchiveError::Coding)?
            .encode(&mut raw_shards)
            .map_err(|_| ArchiveError::Coding)?;
        let mut assignments = Vec::with_capacity(TOTAL_SHARDS);
        let mut shards = Vec::with_capacity(TOTAL_SHARDS);
        for (index, (provider, bytes)) in providers.into_iter().zip(raw_shards).enumerate() {
            let (shard_root, chunk_count) = chunk_tree_root(&bytes);
            assignments.push(ArchiveAssignment {
                shard_index: index as u8,
                provider,
                shard_root,
                shard_bytes: bytes.len() as u64,
                chunk_count: chunk_count as u32,
            });
            shards.push(ArchiveShard { shard_index: index as u8, bytes });
        }
        let assignments: [ArchiveAssignment; TOTAL_SHARDS] =
            assignments.try_into().map_err(|_| ArchiveError::Bounds)?;
        let content_root = content_commitment(payload);
        let manifest_root = manifest_root(
            chain_genesis,
            content_root,
            data_class,
            first_height,
            last_height,
            payload.len() as u64,
            shard_size as u64,
            retention_expiry_epoch,
            &assignments,
        );
        Ok(Self {
            manifest: ArchiveManifest {
                chain_genesis,
                content_root,
                data_class,
                first_height,
                last_height,
                original_bytes: payload.len() as u64,
                shard_bytes: shard_size as u64,
                retention_expiry_epoch,
                assignments,
                manifest_root,
            },
            shards,
        })
    }
}

#[must_use]
pub fn render_archive_fixture() -> String {
    let providers = std::array::from_fn(|index| ArchiveProvider {
        principal: [(index + 1) as u8; 48],
        failure_domain: [(index / 3 + 100) as u8; 48],
    });
    let bundle = ArchiveBundle::encode(
        b"ACT-ARCHIVE-V1",
        [90; 48],
        ArchiveDataClass::Ledger,
        1,
        1,
        100,
        providers,
    )
    .expect("frozen archive fixture is valid");
    let shard_roots = bundle
        .manifest
        .assignments
        .iter()
        .map(|assignment| hex(&assignment.shard_root))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "fixture_version=1\ncontent_root={}\nmanifest_root={}\nshard_roots={}\n",
        hex(&bundle.manifest.content_root),
        hex(&bundle.manifest.manifest_root),
        shard_roots
    )
}

impl ArchiveManifest {
    pub fn validate(&self, current_epoch: u64) -> Result<(), ArchiveError> {
        if self.chain_genesis == [0; 48]
            || self.content_root == [0; 48]
            || self.first_height == 0
            || self.last_height < self.first_height
            || self.original_bytes == 0
            || self.original_bytes > MAX_ARCHIVE_PAYLOAD_BYTES as u64
            || self.shard_bytes == 0
            || current_epoch > self.retention_expiry_epoch
        {
            return Err(if current_epoch > self.retention_expiry_epoch {
                ArchiveError::Expired
            } else {
                ArchiveError::Bounds
            });
        }
        let providers = self.assignments.map(|assignment| assignment.provider);
        validate_providers(&providers)?;
        for (index, assignment) in self.assignments.iter().enumerate() {
            if usize::from(assignment.shard_index) != index
                || assignment.shard_root == [0; 48]
                || assignment.shard_bytes != self.shard_bytes
                || assignment.chunk_count == 0
            {
                return Err(ArchiveError::Bounds);
            }
        }
        let expected = manifest_root(
            self.chain_genesis,
            self.content_root,
            self.data_class,
            self.first_height,
            self.last_height,
            self.original_bytes,
            self.shard_bytes,
            self.retention_expiry_epoch,
            &self.assignments,
        );
        if expected != self.manifest_root {
            return Err(ArchiveError::Corrupt);
        }
        Ok(())
    }

    pub fn reconstruct(
        &self,
        available: &[ArchiveShard],
        current_epoch: u64,
    ) -> Result<Vec<u8>, ArchiveError> {
        self.validate(current_epoch)?;
        if available.len() < DATA_SHARDS {
            return Err(ArchiveError::InsufficientShards);
        }
        let mut indices = BTreeSet::new();
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
        for shard in available {
            let index = usize::from(shard.shard_index);
            if index >= TOTAL_SHARDS || !indices.insert(index) {
                return Err(ArchiveError::Bounds);
            }
            let assignment = self.assignments[index];
            if shard.bytes.len() as u64 != assignment.shard_bytes
                || chunk_tree_root(&shard.bytes).0 != assignment.shard_root
            {
                return Err(ArchiveError::Corrupt);
            }
            shards[index] = Some(shard.bytes.clone());
        }
        ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
            .map_err(|_| ArchiveError::Coding)?
            .reconstruct(&mut shards)
            .map_err(|_| ArchiveError::Coding)?;
        let mut payload = Vec::with_capacity(self.original_bytes as usize);
        for shard in shards.iter().take(DATA_SHARDS) {
            payload.extend_from_slice(shard.as_ref().ok_or(ArchiveError::Coding)?);
        }
        payload.truncate(self.original_bytes as usize);
        if content_commitment(&payload) != self.content_root {
            return Err(ArchiveError::Corrupt);
        }
        Ok(payload)
    }
}

pub trait ReceiptVerifier {
    fn verify(&self, provider: Root, statement: Root, signature: &[u8]) -> bool;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyReceipt {
    pub provider: Root,
    pub shard_index: u8,
    pub manifest_root: Root,
    pub retention_expiry_epoch: u64,
    pub signature: Vec<u8>,
}

impl CustodyReceipt {
    #[must_use]
    pub fn statement(&self) -> Root {
        digest(&[
            b"ACTIVECHAIN-ARCHIVE-CUSTODY-V1",
            &self.provider,
            &[self.shard_index],
            &self.manifest_root,
            &self.retention_expiry_epoch.to_be_bytes(),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveCertificate {
    manifest: ArchiveManifest,
    receipts: Vec<CustodyReceipt>,
}

impl ArchiveCertificate {
    pub fn new(
        manifest: ArchiveManifest,
        receipts: Vec<CustodyReceipt>,
        current_epoch: u64,
        verifier: &impl ReceiptVerifier,
    ) -> Result<Self, ArchiveError> {
        manifest.validate(current_epoch)?;
        if receipts.len() != TOTAL_SHARDS {
            return Err(ArchiveError::Bounds);
        }
        for (index, receipt) in receipts.iter().enumerate() {
            let assignment = manifest.assignments[index];
            if usize::from(receipt.shard_index) != index
                || receipt.provider != assignment.provider.principal
                || receipt.manifest_root != manifest.manifest_root
                || receipt.retention_expiry_epoch != manifest.retention_expiry_epoch
                || receipt.signature.is_empty()
                || receipt.signature.len() > MAX_RECEIPT_SIGNATURE_BYTES
            {
                return Err(ArchiveError::Identity);
            }
            if !verifier.verify(receipt.provider, receipt.statement(), &receipt.signature) {
                return Err(ArchiveError::Signature);
            }
        }
        Ok(Self { manifest, receipts })
    }

    #[must_use]
    pub const fn manifest(&self) -> &ArchiveManifest {
        &self.manifest
    }

    #[must_use]
    pub fn receipts(&self) -> &[CustodyReceipt] {
        &self.receipts
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetrievalChallenge {
    pub manifest_root: Root,
    pub provider: Root,
    pub shard_index: u8,
    pub epoch: u64,
    pub chunk_index: u32,
}

impl RetrievalChallenge {
    pub fn derive(
        manifest: &ArchiveManifest,
        shard_index: u8,
        epoch: u64,
        entropy: Root,
    ) -> Result<Self, ArchiveError> {
        manifest.validate(epoch)?;
        let assignment =
            *manifest.assignments.get(usize::from(shard_index)).ok_or(ArchiveError::Bounds)?;
        let seed = digest(&[
            b"ACTIVECHAIN-ARCHIVE-CHALLENGE-V1",
            &manifest.manifest_root,
            &assignment.provider.principal,
            &[shard_index],
            &epoch.to_be_bytes(),
            &entropy,
        ]);
        let value = u64::from_be_bytes(seed[..8].try_into().map_err(|_| ArchiveError::Corrupt)?);
        Ok(Self {
            manifest_root: manifest.manifest_root,
            provider: assignment.provider.principal,
            shard_index,
            epoch,
            chunk_index: (value % u64::from(assignment.chunk_count)) as u32,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrievalResponse {
    pub challenge: RetrievalChallenge,
    pub chunk: Vec<u8>,
    pub path: Vec<Root>,
}

impl ArchiveShard {
    pub fn answer(
        &self,
        challenge: RetrievalChallenge,
        manifest: &ArchiveManifest,
    ) -> Result<RetrievalResponse, ArchiveError> {
        if challenge.manifest_root != manifest.manifest_root
            || challenge.shard_index != self.shard_index
            || challenge.provider
                != manifest.assignments[usize::from(self.shard_index)].provider.principal
        {
            return Err(ArchiveError::Identity);
        }
        let chunks = chunks(&self.bytes);
        let index = challenge.chunk_index as usize;
        let chunk = chunks.get(index).ok_or(ArchiveError::Bounds)?.to_vec();
        let path = merkle_path(&chunks, index)?;
        Ok(RetrievalResponse { challenge, chunk, path })
    }
}

impl RetrievalResponse {
    pub fn verify(&self, manifest: &ArchiveManifest) -> Result<(), ArchiveError> {
        let assignment = *manifest
            .assignments
            .get(usize::from(self.challenge.shard_index))
            .ok_or(ArchiveError::Bounds)?;
        if self.challenge.manifest_root != manifest.manifest_root
            || self.challenge.provider != assignment.provider.principal
            || self.challenge.chunk_index >= assignment.chunk_count
            || self.chunk.is_empty()
            || self.chunk.len() > CHUNK_BYTES
        {
            return Err(ArchiveError::Identity);
        }
        let mut root = chunk_leaf(self.challenge.chunk_index, &self.chunk);
        let mut index = self.challenge.chunk_index as usize;
        for sibling in &self.path {
            root =
                if index.is_multiple_of(2) { node(root, *sibling) } else { node(*sibling, root) };
            index /= 2;
        }
        if root != assignment.shard_root {
            return Err(ArchiveError::Corrupt);
        }
        Ok(())
    }
}

fn validate_providers(providers: &[ArchiveProvider; TOTAL_SHARDS]) -> Result<(), ArchiveError> {
    let mut principals = BTreeSet::new();
    let mut domains = BTreeMap::<Root, usize>::new();
    for provider in providers {
        if provider.principal == [0; 48]
            || provider.failure_domain == [0; 48]
            || !principals.insert(provider.principal)
        {
            return Err(ArchiveError::Identity);
        }
        let count = domains.entry(provider.failure_domain).or_default();
        *count += 1;
        if *count > MAX_SHARDS_PER_FAILURE_DOMAIN {
            return Err(ArchiveError::Diversity);
        }
    }
    if domains.len() < MIN_FAILURE_DOMAINS {
        return Err(ArchiveError::Diversity);
    }
    Ok(())
}

fn chunks(bytes: &[u8]) -> Vec<&[u8]> {
    bytes.chunks(CHUNK_BYTES).collect()
}

fn chunk_tree_root(bytes: &[u8]) -> (Root, usize) {
    let chunks = chunks(bytes);
    (merkle_levels(&chunks).last().expect("non-empty shard")[0], chunks.len())
}

fn merkle_path(chunks: &[&[u8]], index: usize) -> Result<Vec<Root>, ArchiveError> {
    if index >= chunks.len() {
        return Err(ArchiveError::Bounds);
    }
    let levels = merkle_levels(chunks);
    let mut position = index;
    let mut path = Vec::with_capacity(levels.len().saturating_sub(1));
    for level in levels.iter().take(levels.len().saturating_sub(1)) {
        path.push(level[position ^ 1]);
        position /= 2;
    }
    Ok(path)
}

fn merkle_levels(chunks: &[&[u8]]) -> Vec<Vec<Root>> {
    let width = chunks.len().max(1).next_power_of_two();
    let mut level = Vec::with_capacity(width);
    for index in 0..width {
        level.push(if let Some(chunk) = chunks.get(index) {
            chunk_leaf(index as u32, chunk)
        } else {
            empty_leaf(index as u32)
        });
    }
    let mut levels = vec![level];
    while levels.last().expect("one level").len() > 1 {
        let next = levels
            .last()
            .expect("one level")
            .chunks_exact(2)
            .map(|pair| node(pair[0], pair[1]))
            .collect();
        levels.push(next);
    }
    levels
}

fn chunk_leaf(index: u32, bytes: &[u8]) -> Root {
    digest(&[
        b"ACTIVECHAIN-ARCHIVE-CHUNK-V1",
        &index.to_be_bytes(),
        &(bytes.len() as u32).to_be_bytes(),
        bytes,
    ])
}

fn empty_leaf(index: u32) -> Root {
    digest(&[b"ACTIVECHAIN-ARCHIVE-EMPTY-CHUNK-V1", &index.to_be_bytes()])
}

fn node(left: Root, right: Root) -> Root {
    digest(&[b"ACTIVECHAIN-ARCHIVE-CHUNK-NODE-V1", &left, &right])
}

#[allow(clippy::too_many_arguments)]
fn manifest_root(
    chain_genesis: Root,
    content_root: Root,
    data_class: ArchiveDataClass,
    first_height: u64,
    last_height: u64,
    original_bytes: u64,
    shard_bytes: u64,
    retention_expiry_epoch: u64,
    assignments: &[ArchiveAssignment; TOTAL_SHARDS],
) -> Root {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-ARCHIVE-MANIFEST-V1");
    hasher.update(&chain_genesis);
    hasher.update(&content_root);
    hasher.update(&[data_class as u8]);
    hasher.update(&first_height.to_be_bytes());
    hasher.update(&last_height.to_be_bytes());
    hasher.update(&original_bytes.to_be_bytes());
    hasher.update(&shard_bytes.to_be_bytes());
    hasher.update(&retention_expiry_epoch.to_be_bytes());
    for assignment in assignments {
        hasher.update(&[assignment.shard_index]);
        hasher.update(&assignment.provider.principal);
        hasher.update(&assignment.provider.failure_domain);
        hasher.update(&assignment.shard_root);
        hasher.update(&assignment.shard_bytes.to_be_bytes());
        hasher.update(&assignment.chunk_count.to_be_bytes());
    }
    finish(hasher)
}

fn digest(parts: &[&[u8]]) -> Root {
    let mut hasher = Shake256::default();
    for part in parts {
        hasher.update(part);
    }
    finish(hasher)
}

fn finish(hasher: Shake256) -> Root {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn root(value: u8) -> Root {
        [value; 48]
    }

    fn providers() -> [ArchiveProvider; TOTAL_SHARDS] {
        std::array::from_fn(|index| {
            ArchiveProvider::new(root((index + 1) as u8), root((index / 3 + 100) as u8)).unwrap()
        })
    }

    fn bundle() -> ArchiveBundle {
        let payload = (0..70_000).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        ArchiveBundle::encode(&payload, root(90), ArchiveDataClass::Ledger, 1, 20, 100, providers())
            .unwrap()
    }

    #[test]
    fn any_eight_shards_reconstruct_and_seven_fail() {
        let bundle = bundle();
        let expected = (0..70_000).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        for mask in 0_u16..(1_u16 << TOTAL_SHARDS) {
            if mask.count_ones() != DATA_SHARDS as u32 {
                continue;
            }
            let available = bundle
                .shards
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, shard)| shard.clone())
                .collect::<Vec<_>>();
            assert_eq!(bundle.manifest.reconstruct(&available, 50).unwrap(), expected);
        }
        assert_eq!(
            bundle.manifest.reconstruct(&bundle.shards[..7], 50),
            Err(ArchiveError::InsufficientShards)
        );
    }

    #[test]
    fn checked_in_archive_fixture_does_not_drift() {
        assert_eq!(
            render_archive_fixture(),
            include_str!("../../../testing/storage/archive-v1.txt")
        );
    }

    #[test]
    fn corruption_expiry_and_diversity_fail_closed() {
        let bundle = bundle();
        let mut corrupt = bundle.shards[..8].to_vec();
        corrupt[0].bytes[0] ^= 1;
        assert_eq!(bundle.manifest.reconstruct(&corrupt, 50), Err(ArchiveError::Corrupt));
        assert_eq!(bundle.manifest.validate(101), Err(ArchiveError::Expired));

        let mut bad_providers = providers();
        for provider in &mut bad_providers {
            provider.failure_domain = root(99);
        }
        assert_eq!(
            ArchiveBundle::encode(
                b"payload",
                root(90),
                ArchiveDataClass::Ledger,
                1,
                1,
                100,
                bad_providers,
            ),
            Err(ArchiveError::Diversity)
        );
    }

    #[test]
    fn retrieval_challenge_binds_provider_shard_epoch_and_content() {
        let bundle = bundle();
        let challenge = RetrievalChallenge::derive(&bundle.manifest, 3, 50, root(44)).unwrap();
        let response = bundle.shards[3].answer(challenge, &bundle.manifest).unwrap();
        response.verify(&bundle.manifest).unwrap();
        let mut corrupt = response.clone();
        corrupt.chunk[0] ^= 1;
        assert_eq!(corrupt.verify(&bundle.manifest), Err(ArchiveError::Corrupt));
        let mut substituted = response;
        substituted.challenge.provider = root(88);
        assert_eq!(substituted.verify(&bundle.manifest), Err(ArchiveError::Identity));
    }

    struct TestVerifier;
    impl ReceiptVerifier for TestVerifier {
        fn verify(&self, provider: Root, statement: Root, signature: &[u8]) -> bool {
            signature == digest(&[b"TEST-ARCHIVE-SIGNATURE", &provider, &statement])
        }
    }

    #[test]
    fn custody_certificate_requires_every_exact_signature() {
        let bundle = bundle();
        let receipts = bundle
            .manifest
            .assignments
            .iter()
            .map(|assignment| {
                let mut receipt = CustodyReceipt {
                    provider: assignment.provider.principal,
                    shard_index: assignment.shard_index,
                    manifest_root: bundle.manifest.manifest_root,
                    retention_expiry_epoch: bundle.manifest.retention_expiry_epoch,
                    signature: Vec::new(),
                };
                receipt.signature =
                    digest(&[b"TEST-ARCHIVE-SIGNATURE", &receipt.provider, &receipt.statement()])
                        .to_vec();
                receipt
            })
            .collect::<Vec<_>>();
        ArchiveCertificate::new(bundle.manifest.clone(), receipts.clone(), 50, &TestVerifier)
            .unwrap();
        let mut invalid = receipts;
        invalid[0].signature[0] ^= 1;
        assert_eq!(
            ArchiveCertificate::new(bundle.manifest, invalid, 50, &TestVerifier),
            Err(ArchiveError::Signature)
        );
    }
}
