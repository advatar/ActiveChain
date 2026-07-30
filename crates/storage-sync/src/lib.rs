#![forbid(unsafe_code)]

use activechain_storage_engine::{PARTITION_COUNT, Root, SnapshotManifest};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_FINALITY_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DELTA_PROOF_BYTES: usize = 16 * 1024 * 1024;
const JOURNAL_MAGIC: &[u8; 8] = b"ACSYNC01";
const BITMAP_WORDS: usize = PARTITION_COUNT / 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncError {
    Bounds,
    Identity,
    Finality,
    Manifest,
    Partition,
    Duplicate,
    Incomplete,
    Corrupt,
    Sequence,
    Revision,
    Delta,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub chain_genesis: Root,
    pub finalized_height: u64,
    pub protocol_revision: u64,
    pub validator_set_root: Root,
    pub state_root: Root,
    pub manifest_root: Root,
    pub history_root: Root,
}

impl Checkpoint {
    pub fn validate(self) -> Result<Self, SyncError> {
        if self.chain_genesis == [0; 48]
            || self.finalized_height == 0
            || self.protocol_revision == 0
            || self.validator_set_root == [0; 48]
            || self.state_root == [0; 48]
            || self.manifest_root == [0; 48]
            || self.history_root == [0; 48]
        {
            return Err(SyncError::Bounds);
        }
        Ok(self)
    }

    #[must_use]
    pub fn commitment(self) -> Root {
        digest(&[
            b"ACTIVECHAIN-SYNC-CHECKPOINT-V1",
            &self.chain_genesis,
            &self.finalized_height.to_be_bytes(),
            &self.protocol_revision.to_be_bytes(),
            &self.validator_set_root,
            &self.state_root,
            &self.manifest_root,
            &self.history_root,
        ])
    }
}

pub trait FinalityVerifier {
    fn verify_finality(&self, checkpoint: &Checkpoint, proof: &[u8]) -> bool;
}

pub trait PartitionVerifier {
    fn verify_partition(&self, partition_id: u16, bytes: &[u8]) -> Option<VerifiedPartition>;
}

pub trait DeltaVerifier {
    fn verify_delta(&self, delta: &CertifiedDelta, proof: &[u8]) -> bool;
}

/// Supplies a node-local MAC or signature for crash-resume journals.
pub trait JournalAuthenticator {
    fn authenticate(&self, journal_body: &[u8]) -> Root;

    fn verify(&self, journal_body: &[u8], tag: Root) -> bool {
        self.authenticate(journal_body) == tag
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPartition {
    pub state_root: Root,
    pub charged_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DownloadRequest {
    pub partition_id: u16,
    pub chunk_root: Root,
    pub chunk_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivatedSnapshot {
    pub checkpoint: Checkpoint,
    pub charged_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertifiedDelta {
    pub chain_genesis: Root,
    pub from_height: u64,
    pub to_height: u64,
    pub protocol_revision: u64,
    pub previous_state_root: Root,
    pub next_state_root: Root,
    pub payload_root: Root,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncedHead {
    pub chain_genesis: Root,
    pub height: u64,
    pub protocol_revision: u64,
    pub state_root: Root,
}

impl SyncedHead {
    #[must_use]
    pub const fn from_snapshot(snapshot: ActivatedSnapshot) -> Self {
        Self {
            chain_genesis: snapshot.checkpoint.chain_genesis,
            height: snapshot.checkpoint.finalized_height,
            protocol_revision: snapshot.checkpoint.protocol_revision,
            state_root: snapshot.checkpoint.state_root,
        }
    }

    pub fn apply_delta<V: DeltaVerifier>(
        self,
        delta: CertifiedDelta,
        proof: &[u8],
        verifier: &V,
    ) -> Result<Self, SyncError> {
        if proof.is_empty() || proof.len() > MAX_DELTA_PROOF_BYTES || delta.payload_root == [0; 48]
        {
            return Err(SyncError::Bounds);
        }
        if delta.chain_genesis != self.chain_genesis || delta.previous_state_root != self.state_root
        {
            return Err(SyncError::Identity);
        }
        if delta.from_height != self.height
            || delta.to_height != self.height.checked_add(1).ok_or(SyncError::Bounds)?
        {
            return Err(SyncError::Sequence);
        }
        if delta.protocol_revision != self.protocol_revision {
            return Err(SyncError::Revision);
        }
        if delta.next_state_root == [0; 48] || !verifier.verify_delta(&delta, proof) {
            return Err(SyncError::Delta);
        }
        Ok(Self { height: delta.to_height, state_root: delta.next_state_root, ..self })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncSession {
    checkpoint: Checkpoint,
    manifest: SnapshotManifest,
    completed: [u64; BITMAP_WORDS],
    completed_count: u16,
}

impl SyncSession {
    pub fn begin<V: FinalityVerifier>(
        checkpoint: Checkpoint,
        manifest: SnapshotManifest,
        finality_proof: &[u8],
        verifier: &V,
    ) -> Result<Self, SyncError> {
        verify_checkpoint(checkpoint, &manifest, finality_proof, verifier)?;
        Ok(Self { checkpoint, manifest, completed: [0; BITMAP_WORDS], completed_count: 0 })
    }

    #[must_use]
    pub const fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }

    #[must_use]
    pub const fn completed_count(&self) -> u16 {
        self.completed_count
    }

    #[must_use]
    pub fn download_plan(&self) -> Vec<DownloadRequest> {
        self.manifest
            .partitions
            .iter()
            .filter(|partition| !self.is_complete(partition.partition_id))
            .map(|partition| DownloadRequest {
                partition_id: partition.partition_id,
                chunk_root: partition.chunk_root,
                chunk_bytes: partition.chunk_bytes,
            })
            .collect()
    }

    pub fn stage_partition<V: PartitionVerifier>(
        &mut self,
        partition_id: u16,
        bytes: &[u8],
        verifier: &V,
    ) -> Result<(), SyncError> {
        let expected =
            self.manifest.partitions.get(usize::from(partition_id)).ok_or(SyncError::Bounds)?;
        if expected.partition_id != partition_id || bytes.len() as u64 != expected.chunk_bytes {
            return Err(SyncError::Bounds);
        }
        if self.is_complete(partition_id) {
            return Err(SyncError::Duplicate);
        }
        if partition_payload_root(partition_id, bytes) != expected.chunk_root {
            return Err(SyncError::Corrupt);
        }
        let verified =
            verifier.verify_partition(partition_id, bytes).ok_or(SyncError::Partition)?;
        if verified.state_root != expected.root || verified.charged_bytes != expected.charged_bytes
        {
            return Err(SyncError::Partition);
        }
        let word = usize::from(partition_id) / 64;
        let bit = usize::from(partition_id) % 64;
        self.completed[word] |= 1_u64 << bit;
        self.completed_count = self.completed_count.checked_add(1).ok_or(SyncError::Bounds)?;
        Ok(())
    }

    pub fn activate(self) -> Result<ActivatedSnapshot, SyncError> {
        if usize::from(self.completed_count) != PARTITION_COUNT
            || self.completed.iter().any(|word| *word != u64::MAX)
        {
            return Err(SyncError::Incomplete);
        }
        Ok(ActivatedSnapshot {
            checkpoint: self.checkpoint,
            charged_bytes: self.manifest.charged_bytes,
        })
    }

    #[must_use]
    pub fn encode_journal<A: JournalAuthenticator>(&self, authenticator: &A) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 48 + 2 + BITMAP_WORDS * 8 + 48);
        bytes.extend_from_slice(JOURNAL_MAGIC);
        bytes.extend_from_slice(&self.checkpoint.commitment());
        bytes.extend_from_slice(&self.completed_count.to_be_bytes());
        for word in self.completed {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        let tag = authenticator.authenticate(&bytes);
        bytes.extend_from_slice(&tag);
        bytes
    }

    pub fn resume<V: FinalityVerifier, A: JournalAuthenticator>(
        checkpoint: Checkpoint,
        manifest: SnapshotManifest,
        finality_proof: &[u8],
        journal: &[u8],
        verifier: &V,
        authenticator: &A,
    ) -> Result<Self, SyncError> {
        verify_checkpoint(checkpoint, &manifest, finality_proof, verifier)?;
        let expected_len = 8 + 48 + 2 + BITMAP_WORDS * 8 + 48;
        if journal.len() != expected_len || &journal[..8] != JOURNAL_MAGIC {
            return Err(SyncError::Corrupt);
        }
        let body_end = expected_len - 48;
        let tag: Root = journal[body_end..].try_into().map_err(|_| SyncError::Corrupt)?;
        if !authenticator.verify(&journal[..body_end], tag) {
            return Err(SyncError::Corrupt);
        }
        if checkpoint.commitment() != journal[8..56] {
            return Err(SyncError::Identity);
        }
        let completed_count = u16::from_be_bytes([journal[56], journal[57]]);
        let mut completed = [0_u64; BITMAP_WORDS];
        for (index, word) in completed.iter_mut().enumerate() {
            let start = 58 + index * 8;
            *word = u64::from_be_bytes(
                journal[start..start + 8].try_into().map_err(|_| SyncError::Corrupt)?,
            );
        }
        if completed.iter().map(|word| word.count_ones()).sum::<u32>() != u32::from(completed_count)
        {
            return Err(SyncError::Corrupt);
        }
        Ok(Self { checkpoint, manifest, completed, completed_count })
    }

    fn is_complete(&self, partition_id: u16) -> bool {
        let word = usize::from(partition_id) / 64;
        let bit = usize::from(partition_id) % 64;
        self.completed[word] & (1_u64 << bit) != 0
    }
}

pub fn verify_light_checkpoint<V: FinalityVerifier>(
    checkpoint: Checkpoint,
    manifest: &SnapshotManifest,
    finality_proof: &[u8],
    verifier: &V,
) -> Result<Checkpoint, SyncError> {
    verify_checkpoint(checkpoint, manifest, finality_proof, verifier)?;
    Ok(checkpoint)
}

fn verify_checkpoint<V: FinalityVerifier>(
    checkpoint: Checkpoint,
    manifest: &SnapshotManifest,
    finality_proof: &[u8],
    verifier: &V,
) -> Result<(), SyncError> {
    checkpoint.validate()?;
    if finality_proof.is_empty() || finality_proof.len() > MAX_FINALITY_PROOF_BYTES {
        return Err(SyncError::Bounds);
    }
    if checkpoint.chain_genesis != manifest.chain_genesis
        || checkpoint.finalized_height != manifest.height
        || checkpoint.protocol_revision != manifest.protocol_revision
        || checkpoint.state_root != manifest.state_root
        || checkpoint.manifest_root != manifest.manifest_root
    {
        return Err(SyncError::Manifest);
    }
    let rebuilt = SnapshotManifest::new(
        manifest.chain_genesis,
        manifest.height,
        manifest.protocol_revision,
        manifest.state_root,
        manifest.partitions.clone(),
    )
    .map_err(|_| SyncError::Manifest)?;
    if rebuilt != *manifest {
        return Err(SyncError::Manifest);
    }
    if !verifier.verify_finality(&checkpoint, finality_proof) {
        return Err(SyncError::Finality);
    }
    Ok(())
}

#[must_use]
pub fn partition_payload_root(partition_id: u16, bytes: &[u8]) -> Root {
    digest(&[
        b"ACTIVECHAIN-SNAPSHOT-PARTITION-V1",
        &partition_id.to_be_bytes(),
        &(bytes.len() as u64).to_be_bytes(),
        bytes,
    ])
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

#[must_use]
pub fn render_sync_fixture() -> String {
    let payload = b"ACT-SYNC-V1";
    let chunk_root = partition_payload_root(7, payload);
    let checkpoint = Checkpoint {
        chain_genesis: [1; 48],
        finalized_height: 42,
        protocol_revision: 3,
        validator_set_root: [2; 48],
        state_root: [3; 48],
        manifest_root: [4; 48],
        history_root: [5; 48],
    };
    format!(
        "fixture_version=1\ncheckpoint_root={}\npartition_7_root={}\n",
        hex(&checkpoint.commitment()),
        hex(&chunk_root)
    )
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
    use activechain_storage_engine::PartitionSnapshot;

    struct TestVerifier;

    impl FinalityVerifier for TestVerifier {
        fn verify_finality(&self, checkpoint: &Checkpoint, proof: &[u8]) -> bool {
            proof == checkpoint.commitment()
        }
    }

    impl PartitionVerifier for TestVerifier {
        fn verify_partition(&self, partition_id: u16, bytes: &[u8]) -> Option<VerifiedPartition> {
            Some(VerifiedPartition {
                state_root: digest(&[b"TEST-PARTITION-STATE", &partition_id.to_be_bytes(), bytes]),
                charged_bytes: bytes.len() as u64,
            })
        }
    }

    impl DeltaVerifier for TestVerifier {
        fn verify_delta(&self, delta: &CertifiedDelta, proof: &[u8]) -> bool {
            proof == delta.payload_root
        }
    }

    impl JournalAuthenticator for TestVerifier {
        fn authenticate(&self, journal_body: &[u8]) -> Root {
            digest(&[b"TEST-JOURNAL-SECRET", journal_body])
        }
    }

    fn fixture() -> (Checkpoint, SnapshotManifest, Vec<Vec<u8>>) {
        let payloads =
            (0..PARTITION_COUNT).map(|index| vec![(index % 251) as u8]).collect::<Vec<_>>();
        let partitions = payloads
            .iter()
            .enumerate()
            .map(|(index, bytes)| PartitionSnapshot {
                partition_id: index as u16,
                root: digest(&[b"TEST-PARTITION-STATE", &(index as u16).to_be_bytes(), bytes]),
                charged_bytes: bytes.len() as u64,
                chunk_root: partition_payload_root(index as u16, bytes),
                chunk_bytes: bytes.len() as u64,
            })
            .collect();
        let manifest = SnapshotManifest::new([1; 48], 42, 3, [3; 48], partitions).unwrap();
        let checkpoint = Checkpoint {
            chain_genesis: manifest.chain_genesis,
            finalized_height: manifest.height,
            protocol_revision: manifest.protocol_revision,
            validator_set_root: [2; 48],
            state_root: manifest.state_root,
            manifest_root: manifest.manifest_root,
            history_root: [5; 48],
        };
        (checkpoint, manifest, payloads)
    }

    #[test]
    fn complete_sync_is_bounded_resumable_and_activates_atomically() {
        let (checkpoint, manifest, payloads) = fixture();
        let proof = checkpoint.commitment();
        let mut session =
            SyncSession::begin(checkpoint, manifest.clone(), &proof, &TestVerifier).unwrap();
        assert_eq!(session.download_plan().len(), PARTITION_COUNT);
        for (index, payload) in payloads.iter().enumerate().take(2000) {
            session.stage_partition(index as u16, payload, &TestVerifier).unwrap();
        }
        let journal = session.encode_journal(&TestVerifier);
        let mut resumed = SyncSession::resume(
            checkpoint,
            manifest,
            &proof,
            &journal,
            &TestVerifier,
            &TestVerifier,
        )
        .unwrap();
        assert_eq!(resumed.completed_count(), 2000);
        for (index, payload) in payloads.iter().enumerate().skip(2000) {
            resumed.stage_partition(index as u16, payload, &TestVerifier).unwrap();
        }
        let activated = resumed.activate().unwrap();
        assert_eq!(activated.checkpoint, checkpoint);
        assert_eq!(activated.charged_bytes, PARTITION_COUNT as u64);
    }

    #[test]
    fn substitution_corruption_duplicate_and_incomplete_sync_fail_closed() {
        let (checkpoint, manifest, payloads) = fixture();
        let proof = checkpoint.commitment();
        let mut wrong = checkpoint;
        wrong.protocol_revision += 1;
        assert_eq!(
            SyncSession::begin(wrong, manifest.clone(), &proof, &TestVerifier),
            Err(SyncError::Manifest)
        );
        let mut session =
            SyncSession::begin(checkpoint, manifest.clone(), &proof, &TestVerifier).unwrap();
        assert_eq!(session.stage_partition(0, &[9], &TestVerifier), Err(SyncError::Corrupt));
        session.stage_partition(0, &payloads[0], &TestVerifier).unwrap();
        assert_eq!(
            session.stage_partition(0, &payloads[0], &TestVerifier),
            Err(SyncError::Duplicate)
        );
        assert_eq!(session.activate(), Err(SyncError::Incomplete));

        let session =
            SyncSession::begin(checkpoint, manifest.clone(), &proof, &TestVerifier).unwrap();
        let mut journal = session.encode_journal(&TestVerifier);
        journal[70] ^= 1;
        assert_eq!(
            SyncSession::resume(
                checkpoint,
                manifest,
                &proof,
                &journal,
                &TestVerifier,
                &TestVerifier,
            ),
            Err(SyncError::Corrupt)
        );
    }

    #[test]
    fn light_client_and_consecutive_deltas_bind_all_checkpoint_context() {
        let (checkpoint, manifest, _) = fixture();
        let proof = checkpoint.commitment();
        assert_eq!(
            verify_light_checkpoint(checkpoint, &manifest, &proof, &TestVerifier).unwrap(),
            checkpoint
        );
        let activated = ActivatedSnapshot { checkpoint, charged_bytes: manifest.charged_bytes };
        let head = SyncedHead::from_snapshot(activated);
        let delta = CertifiedDelta {
            chain_genesis: checkpoint.chain_genesis,
            from_height: checkpoint.finalized_height,
            to_height: checkpoint.finalized_height + 1,
            protocol_revision: checkpoint.protocol_revision,
            previous_state_root: checkpoint.state_root,
            next_state_root: [8; 48],
            payload_root: [9; 48],
        };
        let next = head.apply_delta(delta, &[9; 48], &TestVerifier).unwrap();
        assert_eq!(next.height, checkpoint.finalized_height + 1);
        assert_eq!(next.apply_delta(delta, &[9; 48], &TestVerifier), Err(SyncError::Identity));
    }

    #[test]
    fn checked_in_sync_fixture_does_not_drift() {
        assert_eq!(render_sync_fixture(), include_str!("../../../testing/storage/sync-v1.txt"));
    }
}
