use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{ChainId, Digest384, TransactionId};
use alloc::{collections::BTreeMap, vec::Vec};
use sha2::{Digest as _, Sha256};

pub const MAX_ANCHOR_APPLICATION_DOMAIN_LENGTH: usize = 128;
const MAX_ANCHORS: usize = 4_096;
const MAX_BATCH_DEPTH: usize = 32;
// Two proofs plus all evidence metadata must fit one MAX_RPC_BLOB_LENGTH response.
const MAX_ANCHOR_PROOF_LENGTH: usize = 120 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestAnchorStatementV1 {
    application_domain: Vec<u8>,
    digest: [u8; 32],
}

impl DigestAnchorStatementV1 {
    pub fn new(application_domain: Vec<u8>, digest: [u8; 32]) -> Result<Self, AnchorError> {
        if application_domain.is_empty()
            || application_domain.len() > MAX_ANCHOR_APPLICATION_DOMAIN_LENGTH
            || application_domain
                .iter()
                .any(|byte| !matches!(*byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
        {
            return Err(AnchorError::InvalidStatement);
        }
        Ok(Self { application_domain, digest })
    }

    pub fn application_domain(&self) -> &[u8] {
        &self.application_domain
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn submission_reference(&self) -> Result<Digest384, AnchorError> {
        commit(DomainTag::CANONICAL_VALUE, self).map_err(|_| AnchorError::Encoding)
    }
}

impl CanonicalEncode for DigestAnchorStatementV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_bytes(&self.application_domain, MAX_ANCHOR_APPLICATION_DOMAIN_LENGTH)?;
        encoder.write_raw(&self.digest)
    }
}

impl CanonicalDecode for DigestAnchorStatementV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            decoder.read_bytes(MAX_ANCHOR_APPLICATION_DOMAIN_LENGTH)?.to_vec(),
            decoder.read_array()?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid digest anchor statement"))
    }
}

impl CanonicalType for DigestAnchorStatementV1 {
    const TYPE_TAG: u16 = 0x00c6;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 2 + MAX_ANCHOR_APPLICATION_DOMAIN_LENGTH + 32;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorBatchProofV1 {
    leaf_index: u32,
    leaf_count: u32,
    siblings: Vec<[u8; 32]>,
}

impl AnchorBatchProofV1 {
    pub fn new(
        leaf_index: u32,
        leaf_count: u32,
        siblings: Vec<[u8; 32]>,
    ) -> Result<Self, AnchorError> {
        if leaf_count == 0
            || !leaf_count.is_power_of_two()
            || leaf_index >= leaf_count
            || siblings.len() > MAX_BATCH_DEPTH
            || leaf_count.trailing_zeros() as usize != siblings.len()
        {
            return Err(AnchorError::InvalidBatchProof);
        }
        Ok(Self { leaf_index, leaf_count, siblings })
    }

    pub fn verify(&self, statement: &DigestAnchorStatementV1, expected_root: [u8; 32]) -> bool {
        let mut current = anchor_leaf_hash(statement);
        let mut index = self.leaf_index;
        for sibling in &self.siblings {
            current = if index & 1 == 0 {
                anchor_node_hash(current, *sibling)
            } else {
                anchor_node_hash(*sibling, current)
            };
            index >>= 1;
        }
        current == expected_root
    }
}

impl CanonicalEncode for AnchorBatchProofV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.leaf_index.encode(encoder)?;
        self.leaf_count.encode(encoder)?;
        encoder.write_length(self.siblings.len(), MAX_BATCH_DEPTH)?;
        for sibling in &self.siblings {
            sibling.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for AnchorBatchProofV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let leaf_index = u32::decode(decoder)?;
        let leaf_count = u32::decode(decoder)?;
        let count = decoder.read_length(MAX_BATCH_DEPTH)?;
        let mut siblings = Vec::with_capacity(count);
        for _ in 0..count {
            siblings.push(<[u8; 32]>::decode(decoder)?);
        }
        Self::new(leaf_index, leaf_count, siblings)
            .map_err(|_| DecodeError::InvalidValue("invalid anchor batch proof"))
    }
}

impl CanonicalType for AnchorBatchProofV1 {
    const TYPE_TAG: u16 = 0x00c9;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 4 + 4 + 2 + MAX_BATCH_DEPTH * 32;
}

pub fn anchor_leaf_hash(statement: &DigestAnchorStatementV1) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update([0]);
    hash.update(
        u16::try_from(statement.application_domain.len())
            .expect("bounded application domain")
            .to_be_bytes(),
    );
    hash.update(&statement.application_domain);
    hash.update(statement.digest);
    hash.finalize().into()
}

pub fn anchor_node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update([1]);
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorFinalizedEvidenceV1 {
    chain: ChainId,
    genesis: Digest384,
    transaction: TransactionId,
    finalized_height: u64,
    finalized_block: Digest384,
    statement: DigestAnchorStatementV1,
    batch_leaf: Option<DigestAnchorStatementV1>,
    batch_proof: Option<AnchorBatchProofV1>,
    protocol_revision: u64,
    verifier_revision: u32,
    inclusion_proof: Vec<u8>,
    finality_proof: Vec<u8>,
}

impl AnchorFinalizedEvidenceV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: ChainId,
        genesis: Digest384,
        transaction: TransactionId,
        finalized_height: u64,
        finalized_block: Digest384,
        statement: DigestAnchorStatementV1,
        batch_leaf: Option<DigestAnchorStatementV1>,
        batch_proof: Option<AnchorBatchProofV1>,
        protocol_revision: u64,
        verifier_revision: u32,
        inclusion_proof: Vec<u8>,
        finality_proof: Vec<u8>,
    ) -> Result<Self, AnchorError> {
        if genesis == Digest384::ZERO
            || finalized_block == Digest384::ZERO
            || protocol_revision == 0
            || verifier_revision == 0
            || inclusion_proof.is_empty()
            || inclusion_proof.len() > MAX_ANCHOR_PROOF_LENGTH
            || finality_proof.is_empty()
            || finality_proof.len() > MAX_ANCHOR_PROOF_LENGTH
            || batch_leaf.is_some() != batch_proof.is_some()
            || batch_leaf
                .as_ref()
                .zip(batch_proof.as_ref())
                .is_some_and(|(leaf, proof)| !proof.verify(leaf, *statement.digest()))
        {
            return Err(AnchorError::InvalidFinalizedEvidence);
        }
        Ok(Self {
            chain,
            genesis,
            transaction,
            finalized_height,
            finalized_block,
            statement,
            batch_leaf,
            batch_proof,
            protocol_revision,
            verifier_revision,
            inclusion_proof,
            finality_proof,
        })
    }

    pub fn statement(&self) -> &DigestAnchorStatementV1 {
        &self.statement
    }
    pub fn batch_leaf(&self) -> Option<&DigestAnchorStatementV1> {
        self.batch_leaf.as_ref()
    }
    pub fn batch_proof(&self) -> Option<&AnchorBatchProofV1> {
        self.batch_proof.as_ref()
    }
    pub const fn chain(&self) -> ChainId {
        self.chain
    }
    pub const fn genesis(&self) -> Digest384 {
        self.genesis
    }
    pub const fn transaction(&self) -> TransactionId {
        self.transaction
    }
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }
    pub const fn finalized_block(&self) -> Digest384 {
        self.finalized_block
    }
    pub const fn protocol_revision(&self) -> u64 {
        self.protocol_revision
    }
    pub const fn verifier_revision(&self) -> u32 {
        self.verifier_revision
    }
    pub fn inclusion_proof(&self) -> &[u8] {
        &self.inclusion_proof
    }
    pub fn finality_proof(&self) -> &[u8] {
        &self.finality_proof
    }
}

impl CanonicalEncode for AnchorFinalizedEvidenceV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain.encode(encoder)?;
        self.genesis.encode(encoder)?;
        self.transaction.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        self.finalized_block.encode(encoder)?;
        self.statement.encode(encoder)?;
        self.batch_leaf.encode(encoder)?;
        self.batch_proof.encode(encoder)?;
        self.protocol_revision.encode(encoder)?;
        self.verifier_revision.encode(encoder)?;
        encoder.write_bytes(&self.inclusion_proof, MAX_ANCHOR_PROOF_LENGTH)?;
        encoder.write_bytes(&self.finality_proof, MAX_ANCHOR_PROOF_LENGTH)
    }
}

impl CanonicalDecode for AnchorFinalizedEvidenceV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(decoder)?,
            Digest384::decode(decoder)?,
            TransactionId::decode(decoder)?,
            u64::decode(decoder)?,
            Digest384::decode(decoder)?,
            DigestAnchorStatementV1::decode(decoder)?,
            Option::<DigestAnchorStatementV1>::decode(decoder)?,
            Option::<AnchorBatchProofV1>::decode(decoder)?,
            u64::decode(decoder)?,
            u32::decode(decoder)?,
            decoder.read_bytes(MAX_ANCHOR_PROOF_LENGTH)?.to_vec(),
            decoder.read_bytes(MAX_ANCHOR_PROOF_LENGTH)?.to_vec(),
        )
        .map_err(|_| DecodeError::InvalidValue("invalid finalized anchor evidence"))
    }
}

impl CanonicalType for AnchorFinalizedEvidenceV1 {
    const TYPE_TAG: u16 = 0x00ca;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 4
        + 8
        + DigestAnchorStatementV1::MAX_ENCODED_LEN
        + 1
        + DigestAnchorStatementV1::MAX_ENCODED_LEN
        + 1
        + AnchorBatchProofV1::MAX_ENCODED_LEN
        + 8
        + 4
        + 4
        + MAX_ANCHOR_PROOF_LENGTH * 2;
}

#[allow(clippy::too_many_arguments)]
pub fn verify_anchor_evidence(
    evidence: &AnchorFinalizedEvidenceV1,
    expected_statement: &DigestAnchorStatementV1,
    trusted_chain: ChainId,
    trusted_genesis: Digest384,
    protocol_revision: u64,
    verifier_revision: u32,
    verify_proofs: impl FnOnce(&[u8], &[u8], TransactionId, u64, Digest384) -> bool,
) -> Result<(), AnchorError> {
    if evidence.statement != *expected_statement
        || evidence.chain != trusted_chain
        || evidence.genesis != trusted_genesis
        || evidence.protocol_revision != protocol_revision
        || evidence.verifier_revision != verifier_revision
        || !verify_proofs(
            &evidence.inclusion_proof,
            &evidence.finality_proof,
            evidence.transaction,
            evidence.finalized_height,
            evidence.finalized_block,
        )
    {
        return Err(AnchorError::InvalidFinalizedEvidence);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AnchorStatus {
    Pending = 0,
    Finalized = 1,
    Rejected = 2,
}

impl CanonicalEncode for AnchorStatus {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for AnchorStatus {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Finalized),
            2 => Ok(Self::Rejected),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "AnchorStatus", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorRecord {
    statement: DigestAnchorStatementV1,
    status: AnchorStatus,
    evidence: Option<AnchorFinalizedEvidenceV1>,
}

impl AnchorRecord {
    pub fn statement(&self) -> &DigestAnchorStatementV1 {
        &self.statement
    }

    pub const fn status(&self) -> AnchorStatus {
        self.status
    }
    pub fn evidence(&self) -> Option<&AnchorFinalizedEvidenceV1> {
        self.evidence.as_ref()
    }
}

impl CanonicalEncode for AnchorRecord {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.statement.encode(encoder)?;
        self.status.encode(encoder)?;
        self.evidence.encode(encoder)
    }
}

impl CanonicalDecode for AnchorRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            statement: DigestAnchorStatementV1::decode(decoder)?,
            status: AnchorStatus::decode(decoder)?,
            evidence: Option::<AnchorFinalizedEvidenceV1>::decode(decoder)?,
        };
        if (value.status == AnchorStatus::Finalized) != value.evidence.is_some()
            || value.evidence.as_ref().is_some_and(|evidence| evidence.statement != value.statement)
        {
            return Err(DecodeError::InvalidValue("invalid anchor record evidence"));
        }
        Ok(value)
    }
}

impl CanonicalType for AnchorRecord {
    const TYPE_TAG: u16 = 0x00c7;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = DigestAnchorStatementV1::MAX_ENCODED_LEN
        + 1
        + 1
        + AnchorFinalizedEvidenceV1::MAX_ENCODED_LEN;
}

#[derive(Default)]
pub struct AnchorRegistry {
    records: BTreeMap<Digest384, AnchorRecord>,
}

impl AnchorRegistry {
    pub fn submit(&mut self, statement: DigestAnchorStatementV1) -> Result<Digest384, AnchorError> {
        let reference = statement.submission_reference()?;
        match self.records.get(&reference) {
            Some(existing) if existing.statement == statement => return Ok(reference),
            Some(_) => return Err(AnchorError::ReferenceCollision),
            None if self.records.len() >= MAX_ANCHORS => return Err(AnchorError::Capacity),
            None => {}
        }
        self.records.insert(
            reference,
            AnchorRecord { statement, status: AnchorStatus::Pending, evidence: None },
        );
        Ok(reference)
    }

    pub fn resolve(&self, reference: Digest384) -> Option<&AnchorRecord> {
        self.records.get(&reference)
    }

    pub fn set_status(
        &mut self,
        reference: Digest384,
        status: AnchorStatus,
    ) -> Result<(), AnchorError> {
        let record = self.records.get_mut(&reference).ok_or(AnchorError::UnknownReference)?;
        if record.status != AnchorStatus::Pending || status != AnchorStatus::Rejected {
            return Err(AnchorError::InvalidTransition);
        }
        record.status = status;
        Ok(())
    }

    pub fn finalize(
        &mut self,
        reference: Digest384,
        evidence: AnchorFinalizedEvidenceV1,
    ) -> Result<(), AnchorError> {
        let record = self.records.get_mut(&reference).ok_or(AnchorError::UnknownReference)?;
        if record.status != AnchorStatus::Pending || record.statement != evidence.statement {
            return Err(AnchorError::InvalidTransition);
        }
        record.status = AnchorStatus::Finalized;
        record.evidence = Some(evidence);
        Ok(())
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, AnchorError> {
        encode_envelope(&AnchorSnapshot {
            records: self
                .records
                .iter()
                .map(|(reference, record)| (*reference, record.clone()))
                .collect(),
        })
        .map_err(|_| AnchorError::Encoding)
    }

    pub fn restore(bytes: &[u8]) -> Result<Self, AnchorError> {
        let snapshot =
            decode_envelope::<AnchorSnapshot>(bytes).map_err(|_| AnchorError::Persistence)?;
        Ok(Self { records: snapshot.records.into_iter().collect() })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AnchorSnapshot {
    records: Vec<(Digest384, AnchorRecord)>,
}

impl CanonicalEncode for AnchorSnapshot {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.records.len(), MAX_ANCHORS)?;
        for (reference, record) in &self.records {
            reference.encode(encoder)?;
            record.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for AnchorSnapshot {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_ANCHORS)?;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            records.push((Digest384::decode(decoder)?, AnchorRecord::decode(decoder)?));
        }
        if records.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || records.iter().any(|(reference, record)| {
                record.statement.submission_reference().ok() != Some(*reference)
            })
        {
            return Err(DecodeError::InvalidValue("invalid anchor snapshot"));
        }
        Ok(Self { records })
    }
}

impl CanonicalType for AnchorSnapshot {
    const TYPE_TAG: u16 = 0x00c8;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 3 + MAX_ANCHORS * (48 + AnchorRecord::MAX_ENCODED_LEN);
}

#[cfg(feature = "std")]
pub struct DurableAnchorRegistry {
    path: std::path::PathBuf,
    registry: AnchorRegistry,
}

#[cfg(feature = "std")]
impl DurableAnchorRegistry {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, AnchorError> {
        let path = path.as_ref().to_path_buf();
        let registry = match std::fs::read(&path) {
            Ok(bytes) => AnchorRegistry::restore(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => AnchorRegistry::default(),
            Err(_) => return Err(AnchorError::Persistence),
        };
        Ok(Self { path, registry })
    }

    pub const fn registry(&self) -> &AnchorRegistry {
        &self.registry
    }

    pub fn update<T>(
        &mut self,
        operation: impl FnOnce(&mut AnchorRegistry) -> Result<T, AnchorError>,
    ) -> Result<T, AnchorError> {
        let before = self.registry.snapshot()?;
        let result = operation(&mut self.registry)?;
        if self.persist().is_err() {
            self.registry = AnchorRegistry::restore(&before)?;
            return Err(AnchorError::Persistence);
        }
        Ok(result)
    }

    fn persist(&self) -> Result<(), AnchorError> {
        use std::io::Write;
        let bytes = self.registry.snapshot()?;
        let parent = self.path.parent().ok_or(AnchorError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| AnchorError::Persistence)?;
        let temporary = self.path.with_extension("tmp");
        let mut file = std::fs::File::create(&temporary).map_err(|_| AnchorError::Persistence)?;
        file.write_all(&bytes).map_err(|_| AnchorError::Persistence)?;
        file.sync_all().map_err(|_| AnchorError::Persistence)?;
        std::fs::rename(&temporary, &self.path).map_err(|_| AnchorError::Persistence)?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AnchorError::Persistence)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorError {
    InvalidStatement,
    ReferenceCollision,
    Capacity,
    UnknownReference,
    InvalidTransition,
    InvalidBatchProof,
    InvalidFinalizedEvidence,
    Encoding,
    Persistence,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn statement(byte: u8) -> DigestAnchorStatementV1 {
        DigestAnchorStatementV1::new(b"mademark.external-anchor.statement.v1".to_vec(), [byte; 32])
            .unwrap()
    }

    #[test]
    fn exact_submission_is_idempotent_and_terminal_status_is_one_shot() {
        let mut registry = AnchorRegistry::default();
        let reference = registry.submit(statement(7)).unwrap();
        assert_eq!(registry.submit(statement(7)), Ok(reference));
        assert_eq!(
            registry.resolve(reference).map(AnchorRecord::status),
            Some(AnchorStatus::Pending)
        );
        registry.set_status(reference, AnchorStatus::Rejected).unwrap();
        assert_eq!(
            registry.set_status(reference, AnchorStatus::Rejected),
            Err(AnchorError::InvalidTransition)
        );
    }

    #[test]
    fn snapshot_round_trip_rejects_reference_substitution() {
        let mut registry = AnchorRegistry::default();
        let reference = registry.submit(statement(9)).unwrap();
        let bytes = registry.snapshot().unwrap();
        let restored = AnchorRegistry::restore(&bytes).unwrap();
        assert_eq!(restored.resolve(reference), registry.resolve(reference));

        let mut corrupt = bytes;
        // Envelope header (tag, revision, one-byte body length), then one-byte record count.
        corrupt[6] ^= 1;
        assert!(matches!(AnchorRegistry::restore(&corrupt), Err(AnchorError::Persistence)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn durable_registry_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("anchors.bin");
        let reference = {
            let mut durable = DurableAnchorRegistry::open(&path).unwrap();
            durable.update(|registry| registry.submit(statement(11))).unwrap()
        };
        let restored = DurableAnchorRegistry::open(&path).unwrap();
        assert_eq!(
            restored.registry().resolve(reference).map(AnchorRecord::status),
            Some(AnchorStatus::Pending)
        );
    }

    #[test]
    fn batch_path_binds_leaf_domain_digest_and_position() {
        let left = statement(21);
        let right = statement(22);
        let left_hash = anchor_leaf_hash(&left);
        let right_hash = anchor_leaf_hash(&right);
        let root = anchor_node_hash(left_hash, right_hash);
        let left_proof = AnchorBatchProofV1::new(0, 2, vec![right_hash]).unwrap();
        let right_proof = AnchorBatchProofV1::new(1, 2, vec![left_hash]).unwrap();
        assert!(left_proof.verify(&left, root));
        assert!(right_proof.verify(&right, root));
        assert!(!left_proof.verify(&right, root));
        assert!(!right_proof.verify(&left, root));
    }

    #[test]
    fn finalized_evidence_round_trip_binds_exact_statement() {
        const {
            assert!(AnchorRecord::MAX_ENCODED_LEN <= activechain_rpc_types::MAX_RPC_BLOB_LENGTH);
        }
        let evidence = AnchorFinalizedEvidenceV1::new(
            ChainId::new(Digest384::new([1; 48])),
            Digest384::new([2; 48]),
            TransactionId::new(Digest384::new([3; 48])),
            44,
            Digest384::new([4; 48]),
            statement(5),
            None,
            None,
            6,
            7,
            vec![8],
            vec![8, 9],
        )
        .unwrap();
        let bytes = encode_envelope(&evidence).unwrap();
        assert_eq!(decode_envelope::<AnchorFinalizedEvidenceV1>(&bytes), Ok(evidence.clone()));
        assert!(
            verify_anchor_evidence(
                &evidence,
                evidence.statement(),
                evidence.chain(),
                evidence.genesis(),
                evidence.protocol_revision(),
                evidence.verifier_revision(),
                |inclusion, finality, transaction, height, block| {
                    inclusion == [8]
                        && finality == [8, 9]
                        && transaction == evidence.transaction()
                        && height == evidence.finalized_height()
                        && block == evidence.finalized_block()
                },
            )
            .is_ok()
        );
        assert_eq!(
            verify_anchor_evidence(
                &evidence,
                &statement(6),
                evidence.chain(),
                evidence.genesis(),
                evidence.protocol_revision(),
                evidence.verifier_revision(),
                |_, _, _, _, _| true,
            ),
            Err(AnchorError::InvalidFinalizedEvidence)
        );
    }
}
