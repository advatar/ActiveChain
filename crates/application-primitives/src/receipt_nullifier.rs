use activechain_accumulator::{AccumulatorDomain, ReferenceSet};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_privacy_kernel::{NullifierSet, NullifierWitness};
use activechain_protocol_types::{
    CredentialPredicateReceiptV1, CredentialPredicateV1, TlsCredentialEvidenceV1,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    vec::Vec,
};

const MAX_CREDENTIAL_RECEIPTS: usize = 65_535;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialReceiptJournalError {
    InvalidReceipt,
    InvalidOrReplayedNullifier,
    Capacity,
    Persistence,
}

/// Exact receipt evidence and its reconstructed canonical nullifier accumulator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialReceiptLedgerV1 {
    nullifiers: NullifierSet,
    receipts: Vec<CredentialPredicateReceiptV1>,
}

impl Default for CredentialReceiptLedgerV1 {
    fn default() -> Self {
        Self { nullifiers: NullifierSet::empty(), receipts: Vec::new() }
    }
}

impl CredentialReceiptLedgerV1 {
    pub const TYPE_TAG: u16 = 0x017e;

    pub fn new(
        nullifiers: NullifierSet,
        receipts: Vec<CredentialPredicateReceiptV1>,
    ) -> Result<Self, CredentialReceiptJournalError> {
        if receipts.len() > MAX_CREDENTIAL_RECEIPTS
            || receipts.windows(2).any(|pair| pair[0].nullifier() >= pair[1].nullifier())
            || u64::try_from(receipts.len()).ok() != Some(nullifiers.count())
        {
            return Err(CredentialReceiptJournalError::InvalidReceipt);
        }
        let mut reference = ReferenceSet::new(AccumulatorDomain::Nullifier);
        for receipt in &receipts {
            reference
                .insert(receipt.nullifier().into_bytes())
                .map_err(|_| CredentialReceiptJournalError::InvalidReceipt)?;
        }
        let commitment = reference.commitment();
        if commitment.root != nullifiers.root().into_bytes()
            || commitment.count != nullifiers.count()
        {
            return Err(CredentialReceiptJournalError::InvalidReceipt);
        }
        Ok(Self { nullifiers, receipts })
    }

    pub const fn nullifiers(&self) -> &NullifierSet {
        &self.nullifiers
    }

    pub fn receipts(&self) -> &[CredentialPredicateReceiptV1] {
        &self.receipts
    }
}

impl CanonicalEncode for CredentialReceiptLedgerV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.nullifiers.encode(encoder)?;
        encoder.write_length(self.receipts.len(), MAX_CREDENTIAL_RECEIPTS)?;
        for receipt in &self.receipts {
            receipt.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for CredentialReceiptLedgerV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let nullifiers = NullifierSet::decode(decoder)?;
        let count = decoder.read_length(MAX_CREDENTIAL_RECEIPTS)?;
        let mut receipts = Vec::with_capacity(count);
        for _ in 0..count {
            receipts.push(CredentialPredicateReceiptV1::decode(decoder)?);
        }
        Self::new(nullifiers, receipts)
            .map_err(|_| DecodeError::InvalidValue("invalid credential receipt ledger"))
    }
}

impl CanonicalType for CredentialReceiptLedgerV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = NullifierSet::MAX_ENCODED_LEN
        + 3
        + MAX_CREDENTIAL_RECEIPTS * CredentialPredicateReceiptV1::MAX_ENCODED_LEN;
}

/// Write-before-acknowledgement receipt evidence plus replay state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableCredentialReceiptLedger {
    path: PathBuf,
    ledger: CredentialReceiptLedgerV1,
}

impl DurableCredentialReceiptLedger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CredentialReceiptJournalError> {
        let path = path.as_ref().to_path_buf();
        let ledger = match std::fs::read(&path) {
            Ok(bytes) => {
                decode_envelope(&bytes).map_err(|_| CredentialReceiptJournalError::Persistence)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                CredentialReceiptLedgerV1::default()
            }
            Err(_) => return Err(CredentialReceiptJournalError::Persistence),
        };
        Ok(Self { path, ledger })
    }

    pub const fn ledger(&self) -> &CredentialReceiptLedgerV1 {
        &self.ledger
    }

    pub fn admit_bound_receipt(
        &mut self,
        receipt: &CredentialPredicateReceiptV1,
        evidence: &TlsCredentialEvidenceV1,
        predicate: &CredentialPredicateV1,
        witness: &NullifierWitness,
    ) -> Result<(), CredentialReceiptJournalError> {
        if !receipt.binds(evidence, predicate) || witness.nullifier() != receipt.nullifier() {
            return Err(CredentialReceiptJournalError::InvalidReceipt);
        }
        if self.ledger.receipts.len() == MAX_CREDENTIAL_RECEIPTS {
            return Err(CredentialReceiptJournalError::Capacity);
        }
        let mut nullifiers = self.ledger.nullifiers.clone();
        nullifiers
            .consume_verified(&[receipt.nullifier()], core::slice::from_ref(witness))
            .map_err(|_| CredentialReceiptJournalError::InvalidOrReplayedNullifier)?;
        let mut receipts = self.ledger.receipts.clone();
        let index = match receipts
            .binary_search_by_key(&receipt.nullifier(), |candidate| candidate.nullifier())
        {
            Ok(_) => return Err(CredentialReceiptJournalError::InvalidOrReplayedNullifier),
            Err(index) => index,
        };
        receipts.insert(index, *receipt);
        let next = CredentialReceiptLedgerV1::new(nullifiers, receipts)?;
        save_receipt_ledger_atomic(&next, &self.path)?;
        self.ledger = next;
        Ok(())
    }
}

/// Crash-safe exactly-once nullifier state for already verified credential receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableCredentialReceiptJournal {
    path: PathBuf,
    nullifiers: NullifierSet,
}
impl DurableCredentialReceiptJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CredentialReceiptJournalError> {
        let path = path.as_ref().to_path_buf();
        let nullifiers = match std::fs::read(&path) {
            Ok(bytes) => {
                decode_envelope(&bytes).map_err(|_| CredentialReceiptJournalError::Persistence)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => NullifierSet::empty(),
            Err(_) => return Err(CredentialReceiptJournalError::Persistence),
        };
        Ok(Self { path, nullifiers })
    }

    pub const fn nullifiers(&self) -> &NullifierSet {
        &self.nullifiers
    }

    /// Admits a receipt only after its evidence/predicate binding was reconstructed by the caller's
    /// verified proof path. Persistence completes before live memory or acknowledgement advances.
    pub fn admit_bound_receipt(
        &mut self,
        receipt: &CredentialPredicateReceiptV1,
        evidence: &TlsCredentialEvidenceV1,
        predicate: &CredentialPredicateV1,
        witness: &NullifierWitness,
    ) -> Result<(), CredentialReceiptJournalError> {
        if !receipt.binds(evidence, predicate) || witness.nullifier() != receipt.nullifier() {
            return Err(CredentialReceiptJournalError::InvalidReceipt);
        }
        let mut next = self.nullifiers.clone();
        next.consume_verified(&[receipt.nullifier()], core::slice::from_ref(witness))
            .map_err(|_| CredentialReceiptJournalError::InvalidOrReplayedNullifier)?;
        save_atomic(&next, &self.path)?;
        self.nullifiers = next;
        Ok(())
    }
}

fn save_atomic(
    nullifiers: &NullifierSet,
    path: &Path,
) -> Result<(), CredentialReceiptJournalError> {
    let bytes =
        encode_envelope(nullifiers).map_err(|_| CredentialReceiptJournalError::Persistence)?;
    let parent = path.parent().ok_or(CredentialReceiptJournalError::Persistence)?;
    std::fs::create_dir_all(parent).map_err(|_| CredentialReceiptJournalError::Persistence)?;
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)
        .map_err(|_| CredentialReceiptJournalError::Persistence)?;
    file.write_all(&bytes).map_err(|_| CredentialReceiptJournalError::Persistence)?;
    file.sync_all().map_err(|_| CredentialReceiptJournalError::Persistence)?;
    std::fs::rename(&temporary, path).map_err(|_| CredentialReceiptJournalError::Persistence)
}

fn save_receipt_ledger_atomic(
    ledger: &CredentialReceiptLedgerV1,
    path: &Path,
) -> Result<(), CredentialReceiptJournalError> {
    let bytes = encode_envelope(ledger).map_err(|_| CredentialReceiptJournalError::Persistence)?;
    let parent = path.parent().ok_or(CredentialReceiptJournalError::Persistence)?;
    std::fs::create_dir_all(parent).map_err(|_| CredentialReceiptJournalError::Persistence)?;
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)
        .map_err(|_| CredentialReceiptJournalError::Persistence)?;
    file.write_all(&bytes).map_err(|_| CredentialReceiptJournalError::Persistence)?;
    file.sync_all().map_err(|_| CredentialReceiptJournalError::Persistence)?;
    std::fs::rename(temporary, path).map_err(|_| CredentialReceiptJournalError::Persistence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_accumulator::{AccumulatorDomain, ReferenceSet};
    use activechain_protocol_types::{
        ChainId, CredentialAssuranceClassV1, CredentialPredicateKind, Digest384, PrincipalId,
        TransactionId,
    };
    use std::vec;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn fixture() -> (
        TlsCredentialEvidenceV1,
        CredentialPredicateV1,
        CredentialPredicateReceiptV1,
        NullifierWitness,
    ) {
        let holder = digest(5);
        let schema = digest(6);
        let evidence = TlsCredentialEvidenceV1::new(
            digest(1),
            digest(2),
            digest(3),
            digest(4),
            holder,
            schema,
            10,
            30,
            digest(7),
            CredentialAssuranceClassV1::HolderSelfIssued,
            None,
        )
        .unwrap();
        let predicate = CredentialPredicateV1::new(
            schema,
            evidence.commitment().unwrap(),
            holder,
            ChainId::new(digest(8)),
            PrincipalId::new(digest(9)),
            TransactionId::new(digest(10)),
            digest(11),
            2,
            25,
            CredentialPredicateKind::AssetAmountAtLeast,
            digest(12),
        )
        .unwrap();
        let receipt = CredentialPredicateReceiptV1::from_tls_evidence(
            &evidence,
            &predicate,
            PrincipalId::new(digest(13)),
            digest(14),
            digest(15),
            digest(16),
            20,
            21,
        )
        .unwrap();
        let reference = ReferenceSet::new(AccumulatorDomain::Nullifier);
        let proof = reference.non_membership_witness(receipt.nullifier().into_bytes()).unwrap();
        let witness = NullifierWitness::new(
            receipt.nullifier(),
            proof.siblings.into_iter().map(Digest384::new).collect(),
        )
        .unwrap();
        (evidence, predicate, receipt, witness)
    }

    #[test]
    fn receipt_nullifier_survives_restart_and_replay_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential-nullifiers.bin");
        let (evidence, predicate, receipt, witness) = fixture();
        let mut journal = DurableCredentialReceiptJournal::open(&path).unwrap();
        journal.admit_bound_receipt(&receipt, &evidence, &predicate, &witness).unwrap();
        assert_eq!(journal.nullifiers().count(), 1);
        let mut restarted = DurableCredentialReceiptJournal::open(&path).unwrap();
        assert_eq!(restarted.nullifiers(), journal.nullifiers());
        assert_eq!(
            restarted.admit_bound_receipt(&receipt, &evidence, &predicate, &witness),
            Err(CredentialReceiptJournalError::InvalidOrReplayedNullifier)
        );
    }

    #[test]
    fn substituted_receipt_and_corrupt_restart_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential-nullifiers.bin");
        let (_evidence, predicate, receipt, witness) = fixture();
        let substituted = TlsCredentialEvidenceV1::new(
            digest(1),
            digest(2),
            digest(99),
            digest(4),
            digest(5),
            digest(6),
            10,
            30,
            digest(7),
            CredentialAssuranceClassV1::HolderSelfIssued,
            None,
        )
        .unwrap();
        let mut journal = DurableCredentialReceiptJournal::open(&path).unwrap();
        assert_eq!(
            journal.admit_bound_receipt(&receipt, &substituted, &predicate, &witness),
            Err(CredentialReceiptJournalError::InvalidReceipt)
        );
        assert_eq!(journal.nullifiers().count(), 0);
        std::fs::write(&path, b"corrupt").unwrap();
        assert_eq!(
            DurableCredentialReceiptJournal::open(&path),
            Err(CredentialReceiptJournalError::Persistence)
        );
    }

    #[test]
    fn persistence_failure_does_not_advance_nullifier_root() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential-nullifiers.bin");
        let mut journal = DurableCredentialReceiptJournal::open(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let (evidence, predicate, receipt, witness) = fixture();
        let root = journal.nullifiers().root();
        assert_eq!(
            journal.admit_bound_receipt(&receipt, &evidence, &predicate, &witness),
            Err(CredentialReceiptJournalError::Persistence)
        );
        assert_eq!(journal.nullifiers().root(), root);
        assert_eq!(journal.nullifiers().count(), 0);
    }

    #[test]
    fn receipt_ledger_survives_restart_with_exact_reconstructed_accumulator() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential-receipts.bin");
        let (evidence, predicate, receipt, witness) = fixture();
        let mut durable = DurableCredentialReceiptLedger::open(&path).unwrap();
        durable.admit_bound_receipt(&receipt, &evidence, &predicate, &witness).unwrap();
        assert_eq!(durable.ledger().receipts(), core::slice::from_ref(&receipt));
        assert_eq!(durable.ledger().nullifiers().count(), 1);
        let mut restarted = DurableCredentialReceiptLedger::open(&path).unwrap();
        assert_eq!(restarted.ledger(), durable.ledger());
        assert_eq!(
            restarted.admit_bound_receipt(&receipt, &evidence, &predicate, &witness),
            Err(CredentialReceiptJournalError::InvalidOrReplayedNullifier)
        );
        assert_eq!(restarted.ledger(), durable.ledger());
    }

    #[test]
    fn receipt_ledger_decode_rejects_receipts_without_matching_accumulator() {
        let (_, _, receipt, _) = fixture();
        let inconsistent = CredentialReceiptLedgerV1 {
            nullifiers: NullifierSet::empty(),
            receipts: vec![receipt],
        };
        let encoded = encode_envelope(&inconsistent).unwrap();
        assert!(decode_envelope::<CredentialReceiptLedgerV1>(&encoded).is_err());
    }

    #[test]
    fn failed_receipt_ledger_write_advances_neither_receipts_nor_nullifiers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential-receipts.bin");
        let mut durable = DurableCredentialReceiptLedger::open(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let (evidence, predicate, receipt, witness) = fixture();
        assert_eq!(
            durable.admit_bound_receipt(&receipt, &evidence, &predicate, &witness),
            Err(CredentialReceiptJournalError::Persistence)
        );
        assert!(durable.ledger().receipts().is_empty());
        assert_eq!(durable.ledger().nullifiers().count(), 0);
    }
}
