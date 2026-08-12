use crate::{FaucetError, FaucetSettlementAdapter};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, DecodeError, Decoder, EncodeError, Encoder, decode_envelope,
    encode_envelope,
};
use activechain_cash_kernel::{CoinTransfer, MAX_TRANSFER_INPUTS};
use activechain_protocol_types::{ChainId, CryptoSuiteId, ProtocolSignature};
use activechain_protocol_types::{Digest384, PrincipalId, TransactionId};
use activechain_wallet_core::{
    AuthorizedCashSessionGrantV1, AuthorizedCashTransferV1, CashAuthorizationRequestV1,
    CashSessionGrantV1, OperatorFaucetAuthorizationV1, TransactionIngress,
};
use ml_dsa::{MlDsa44, Signer, SigningKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

const JOURNAL_VERSION: u16 = 1;
const JOURNAL_TAG_LENGTH: usize = 32;
const MAX_OPERATOR_SETTLEMENTS: usize = 65_535;
const MAX_AUTHORIZED_ENVELOPE: usize = 64 * 1024;

/// Operator/HSM boundary that produces a treasury-signed cash envelope only after faucet policy
/// admission. Implementations retain custody of the faucet source key.
pub trait FaucetEnvelopeAuthorizer: Send {
    fn authorize(
        &mut self,
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<OperatorFaucetAuthorizationV1, FaucetError>;
}

impl<F> FaucetEnvelopeAuthorizer for F
where
    F: FnMut(PrincipalId, u128, Digest384) -> Result<OperatorFaucetAuthorizationV1, FaucetError>
        + Send,
{
    fn authorize(
        &mut self,
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<OperatorFaucetAuthorizationV1, FaucetError> {
        self(recipient, amount, reference)
    }
}

/// Validator ingress boundary for the complete operator session-plus-transfer bundle.
pub trait OperatorFaucetIngressAdapter: Send + Sync {
    fn settle_operator_authorization(
        &self,
        authorization: &OperatorFaucetAuthorizationV1,
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<TransactionId, FaucetError>;
}

/// Concrete operator authorizer backed by an ML-DSA-44 treasury key and the current durable cash
/// state. Secret-key loading and protection remain deployment concerns; this value never exposes
/// the key or accepts signing payloads from the network.
pub struct MlDsa44FaucetAuthorizer {
    ingress: std::sync::Arc<Mutex<TransactionIngress>>,
    chain_id: ChainId,
    source: PrincipalId,
    signing_key: SigningKey<MlDsa44>,
    fee: u128,
    valid_for_blocks: u64,
    finalized_height: std::sync::Arc<crate::DurableRpcStore>,
    reload_path: Option<PathBuf>,
}

impl MlDsa44FaucetAuthorizer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ingress: std::sync::Arc<Mutex<TransactionIngress>>,
        chain_id: ChainId,
        source: PrincipalId,
        signing_key: SigningKey<MlDsa44>,
        fee: u128,
        valid_for_blocks: u64,
        finalized_height: std::sync::Arc<crate::DurableRpcStore>,
    ) -> Result<Self, FaucetError> {
        if valid_for_blocks == 0 {
            return Err(FaucetError::InvalidPolicy);
        }
        Ok(Self {
            ingress,
            chain_id,
            source,
            signing_key,
            fee,
            valid_for_blocks,
            finalized_height,
            reload_path: None,
        })
    }

    /// Reload the consensus-owned ingress snapshot immediately before each authorization.
    #[must_use]
    pub fn with_snapshot_reload(mut self, path: PathBuf) -> Self {
        self.reload_path = Some(path);
        self
    }
}

impl FaucetEnvelopeAuthorizer for MlDsa44FaucetAuthorizer {
    fn authorize(
        &mut self,
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<OperatorFaucetAuthorizationV1, FaucetError> {
        self.finalized_height.reload().map_err(|_| FaucetError::Persistence)?;
        if let Some(path) = self.reload_path.as_ref() {
            let fresh = TransactionIngress::load(path, self.chain_id)
                .map_err(|_| FaucetError::Persistence)?;
            *self.ingress.lock().map_err(|_| FaucetError::Persistence)? = fresh;
        }
        let height =
            self.finalized_height.finalized_height().map_err(|_| FaucetError::Persistence)?;
        let valid_until =
            height.checked_add(self.valid_for_blocks).ok_or(FaucetError::InvalidTransition)?;
        let required = amount.checked_add(self.fee).ok_or(FaucetError::InvalidTransition)?;
        let ingress = self.ingress.lock().map_err(|_| FaucetError::Persistence)?;
        let nonce = ingress.next_nonce(self.source).ok_or(FaucetError::InvalidTransition)?;
        let mut cells = ingress
            .ledger()
            .cells()
            .as_slice()
            .iter()
            .filter(|record| record.cell().owner() == self.source)
            .copied()
            .collect::<Vec<_>>();
        cells.sort_by(|left, right| {
            right
                .cell()
                .amount()
                .cmp(&left.cell().amount())
                .then_with(|| left.id().cmp(&right.id()))
        });
        if cells.len() < 2 {
            return Err(FaucetError::InvalidTransition);
        }
        let fee_reserve = cells[0];
        let mut inputs = Vec::new();
        let mut selected = fee_reserve.cell().amount();
        for record in cells.iter().skip(1).take(MAX_TRANSFER_INPUTS) {
            inputs.push(record.id());
            selected = selected
                .checked_add(record.cell().amount())
                .ok_or(FaucetError::InvalidTransition)?;
            if selected >= required {
                break;
            }
        }
        if selected < required || inputs.is_empty() {
            return Err(FaucetError::InvalidTransition);
        }
        inputs.sort_unstable();
        drop(ingress);

        let transfer = CoinTransfer::new(
            self.source,
            recipient,
            inputs,
            fee_reserve.id(),
            amount,
            self.fee,
            valid_until,
        )
        .map_err(|_| FaucetError::InvalidTransition)?;
        let grant = CashSessionGrantV1::new(
            self.chain_id,
            self.source,
            reference,
            height,
            valid_until,
            required,
        )
        .map_err(|_| FaucetError::InvalidTransition)?;
        let grant_signature = self
            .signing_key
            .sign(&grant.signing_payload().map_err(|_| FaucetError::InvalidTransition)?);
        let grant = AuthorizedCashSessionGrantV1::new(
            grant,
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                grant_signature.encode().as_slice().to_vec(),
            )
            .map_err(|_| FaucetError::InvalidTransition)?,
        )
        .map_err(|_| FaucetError::InvalidTransition)?;
        let request = CashAuthorizationRequestV1::new_with_settlement_reference(
            self.chain_id,
            self.source,
            nonce,
            reference,
            valid_until,
            Some(reference),
            transfer,
        )
        .map_err(|_| FaucetError::InvalidTransition)?;
        let transfer_signature = self
            .signing_key
            .sign(&request.signing_payload().map_err(|_| FaucetError::InvalidTransition)?);
        let transfer = AuthorizedCashTransferV1::new(
            request,
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                transfer_signature.encode().as_slice().to_vec(),
            )
            .map_err(|_| FaucetError::InvalidTransition)?,
        )
        .map_err(|_| FaucetError::InvalidTransition)?;
        OperatorFaucetAuthorizationV1::new(grant, transfer)
            .map_err(|_| FaucetError::InvalidTransition)
    }
}

/// Cross-process validator ingress. Each admitted authorization is published as one immutable,
/// length-prefixed spool member; the round runner assembles members under its existing round lock.
pub struct SpoolOperatorFaucetIngressAdapter {
    directory: PathBuf,
}

impl SpoolOperatorFaucetIngressAdapter {
    pub fn new(directory: PathBuf) -> Result<Self, FaucetError> {
        std::fs::create_dir_all(&directory).map_err(|_| FaucetError::Persistence)?;
        if !directory.is_dir() {
            return Err(FaucetError::Persistence);
        }
        Ok(Self { directory })
    }
}

impl OperatorFaucetIngressAdapter for SpoolOperatorFaucetIngressAdapter {
    fn settle_operator_authorization(
        &self,
        authorization: &OperatorFaucetAuthorizationV1,
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<TransactionId, FaucetError> {
        let request = authorization.transfer().request();
        let transaction =
            TransactionId::new(request.intent_id().map_err(|_| FaucetError::InvalidTransition)?);
        if request.transfer().recipient() != recipient
            || request.transfer().amount() != amount
            || request.settlement_reference() != Some(reference)
        {
            return Err(FaucetError::InvalidTransition);
        }
        let envelope =
            encode_envelope(authorization).map_err(|_| FaucetError::InvalidTransition)?;
        let length = u32::try_from(envelope.len()).map_err(|_| FaucetError::InvalidTransition)?;
        let mut framed = Vec::with_capacity(4 + envelope.len());
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(&envelope);
        let name = transaction
            .digest()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let target = self.directory.join(format!("{name}.action"));
        if target.exists() {
            return if std::fs::read(&target).map_err(|_| FaucetError::Persistence)? == framed {
                Ok(transaction)
            } else {
                Err(FaucetError::InvalidTransition)
            };
        }
        let temporary = self.directory.join(format!(".{name}.{}.tmp", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| FaucetError::Persistence)?;
        file.write_all(&framed).map_err(|_| FaucetError::Persistence)?;
        file.sync_all().map_err(|_| FaucetError::Persistence)?;
        std::fs::rename(&temporary, &target).map_err(|_| FaucetError::Persistence)?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| FaucetError::Persistence)?;
        Ok(transaction)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedSettlement {
    reference: Digest384,
    recipient: PrincipalId,
    amount: u128,
    transaction: TransactionId,
    envelope: Vec<u8>,
}

impl CanonicalEncode for PreparedSettlement {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.reference.encode(encoder)?;
        self.recipient.encode(encoder)?;
        self.amount.encode(encoder)?;
        self.transaction.encode(encoder)?;
        encoder.write_bytes(&self.envelope, MAX_AUTHORIZED_ENVELOPE)
    }
}

impl CanonicalDecode for PreparedSettlement {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let settlement = Self {
            reference: Digest384::decode(decoder)?,
            recipient: PrincipalId::decode(decoder)?,
            amount: u128::decode(decoder)?,
            transaction: TransactionId::decode(decoder)?,
            envelope: decoder.read_bytes(MAX_AUTHORIZED_ENVELOPE)?.to_vec(),
        };
        validate_prepared(&settlement)
            .map_err(|_| DecodeError::InvalidValue("invalid prepared faucet settlement"))?;
        Ok(settlement)
    }
}

struct OperatorJournal {
    path: PathBuf,
    records: Vec<PreparedSettlement>,
    faulted: bool,
}

impl OperatorJournal {
    fn create(path: PathBuf) -> Result<Self, FaucetError> {
        if path.exists() {
            return Err(FaucetError::Persistence);
        }
        let journal = Self { path, records: Vec::new(), faulted: false };
        save_journal(&journal.path, &journal.records)?;
        Ok(journal)
    }

    fn open(path: PathBuf) -> Result<Self, FaucetError> {
        let records = load_journal(&path)?;
        Ok(Self { path, records, faulted: false })
    }

    fn find(&self, reference: Digest384) -> Option<&PreparedSettlement> {
        self.records
            .binary_search_by_key(&reference, |record| record.reference)
            .ok()
            .map(|index| &self.records[index])
    }

    fn prepare(&mut self, settlement: PreparedSettlement) -> Result<(), FaucetError> {
        if self.faulted || self.records.len() == MAX_OPERATOR_SETTLEMENTS {
            return Err(if self.faulted {
                FaucetError::Persistence
            } else {
                FaucetError::Capacity
            });
        }
        let position = match self
            .records
            .binary_search_by_key(&settlement.reference, |record| record.reference)
        {
            Ok(index) => {
                return if self.records[index] == settlement {
                    Ok(())
                } else {
                    Err(FaucetError::InvalidTransition)
                };
            }
            Err(position) => position,
        };
        let mut next = self.records.clone();
        next.insert(position, settlement);
        if save_journal(&self.path, &next).is_err() {
            self.faulted = true;
            return Err(FaucetError::Persistence);
        }
        self.records = next;
        Ok(())
    }
}

/// Durable adapter for the public, unsigned `RequestFaucet` path. It journals the exact
/// operator-authorized envelope before validator submission, making a retry after a lost
/// acknowledgement replay the byte-identical transaction rather than spend treasury funds twice.
pub struct DurableOperatorFaucetSettlement<A, S> {
    journal: Mutex<OperatorJournal>,
    authorizer: Mutex<S>,
    authorized_ingress: A,
}

impl<A, S> DurableOperatorFaucetSettlement<A, S>
where
    A: OperatorFaucetIngressAdapter,
    S: FaucetEnvelopeAuthorizer,
{
    pub fn create(
        path: PathBuf,
        authorizer: S,
        authorized_ingress: A,
    ) -> Result<Self, FaucetError> {
        Ok(Self {
            journal: Mutex::new(OperatorJournal::create(path)?),
            authorizer: Mutex::new(authorizer),
            authorized_ingress,
        })
    }

    pub fn open(path: PathBuf, authorizer: S, authorized_ingress: A) -> Result<Self, FaucetError> {
        Ok(Self {
            journal: Mutex::new(OperatorJournal::open(path)?),
            authorizer: Mutex::new(authorizer),
            authorized_ingress,
        })
    }
}

impl<A, S> FaucetSettlementAdapter for DurableOperatorFaucetSettlement<A, S>
where
    A: OperatorFaucetIngressAdapter,
    S: FaucetEnvelopeAuthorizer,
{
    fn settle(
        &self,
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<TransactionId, FaucetError> {
        if reference == Digest384::ZERO || amount == 0 {
            return Err(FaucetError::InvalidTransition);
        }
        let mut journal = self.journal.lock().map_err(|_| FaucetError::Persistence)?;
        let prepared = if let Some(prepared) = journal.find(reference) {
            if prepared.recipient != recipient || prepared.amount != amount {
                return Err(FaucetError::InvalidTransition);
            }
            prepared.clone()
        } else {
            let authorization = self
                .authorizer
                .lock()
                .map_err(|_| FaucetError::Persistence)?
                .authorize(recipient, amount, reference)?;
            let envelope =
                encode_envelope(&authorization).map_err(|_| FaucetError::InvalidTransition)?;
            let prepared = prepared_settlement(envelope, recipient, amount, reference)?;
            journal.prepare(prepared.clone())?;
            prepared
        };
        drop(journal);
        let authorization = decode_envelope::<OperatorFaucetAuthorizationV1>(&prepared.envelope)
            .map_err(|_| FaucetError::InvalidTransition)?;
        let transaction = self.authorized_ingress.settle_operator_authorization(
            &authorization,
            recipient,
            amount,
            reference,
        )?;
        if transaction != prepared.transaction {
            return Err(FaucetError::InvalidTransition);
        }
        Ok(transaction)
    }
}

fn prepared_settlement(
    envelope: Vec<u8>,
    recipient: PrincipalId,
    amount: u128,
    reference: Digest384,
) -> Result<PreparedSettlement, FaucetError> {
    if envelope.is_empty() || envelope.len() > MAX_AUTHORIZED_ENVELOPE {
        return Err(FaucetError::InvalidTransition);
    }
    let authorized = decode_envelope::<OperatorFaucetAuthorizationV1>(&envelope)
        .map_err(|_| FaucetError::InvalidTransition)?;
    let request = authorized.transfer().request();
    let transaction =
        TransactionId::new(request.intent_id().map_err(|_| FaucetError::InvalidTransition)?);
    let prepared = PreparedSettlement { reference, recipient, amount, transaction, envelope };
    validate_prepared(&prepared)?;
    Ok(prepared)
}

fn validate_prepared(prepared: &PreparedSettlement) -> Result<(), FaucetError> {
    let authorized = decode_envelope::<OperatorFaucetAuthorizationV1>(&prepared.envelope)
        .map_err(|_| FaucetError::InvalidTransition)?;
    let request = authorized.transfer().request();
    if request.settlement_reference() != Some(prepared.reference)
        || request.transfer().recipient() != prepared.recipient
        || request.transfer().amount() != prepared.amount
        || TransactionId::new(request.intent_id().map_err(|_| FaucetError::InvalidTransition)?)
            != prepared.transaction
    {
        return Err(FaucetError::InvalidTransition);
    }
    Ok(())
}

fn save_journal(path: &Path, records: &[PreparedSettlement]) -> Result<(), FaucetError> {
    let maximum = 8 + records.len() * (48 + 48 + 16 + 48 + 4 + MAX_AUTHORIZED_ENVELOPE);
    let mut encoder = Encoder::new(maximum);
    JOURNAL_VERSION.encode(&mut encoder).map_err(|_| FaucetError::Persistence)?;
    encoder
        .write_length(records.len(), MAX_OPERATOR_SETTLEMENTS)
        .map_err(|_| FaucetError::Persistence)?;
    for record in records {
        record.encode(&mut encoder).map_err(|_| FaucetError::Persistence)?;
    }
    let bytes = encoder.finish();
    let mut output = bytes.clone();
    output.extend_from_slice(&journal_tag(&bytes));
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| FaucetError::Persistence)?;
    let result = (|| {
        file.write_all(&output).map_err(|_| FaucetError::Persistence)?;
        file.sync_all().map_err(|_| FaucetError::Persistence)?;
        std::fs::rename(&temporary, path).map_err(|_| FaucetError::Persistence)?;
        File::open(path.parent().unwrap_or_else(|| Path::new(".")))
            .and_then(|directory| directory.sync_all())
            .map_err(|_| FaucetError::Persistence)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Settlement references the operator has durably authorized.
///
/// The journal is written before a transfer is published, so a reference that
/// is absent from it was never authorized and no transfer for it can exist.
/// That is the one fact which makes rejecting an unresolved reservation safe,
/// and startup recovery needs it before it may touch anything.
pub fn journal_references(path: &Path) -> Result<Vec<Digest384>, FaucetError> {
    Ok(load_journal(path)?.into_iter().map(|prepared| prepared.reference).collect())
}

fn load_journal(path: &Path) -> Result<Vec<PreparedSettlement>, FaucetError> {
    let bytes = std::fs::read(path).map_err(|_| FaucetError::Persistence)?;
    if bytes.len() < JOURNAL_TAG_LENGTH {
        return Err(FaucetError::Persistence);
    }
    let body_length = bytes.len() - JOURNAL_TAG_LENGTH;
    let (body, tag) = bytes.split_at(body_length);
    if journal_tag(body).as_slice() != tag {
        return Err(FaucetError::Persistence);
    }
    let mut decoder = Decoder::new(body);
    if u16::decode(&mut decoder).map_err(|_| FaucetError::Persistence)? != JOURNAL_VERSION {
        return Err(FaucetError::Persistence);
    }
    let count =
        decoder.read_length(MAX_OPERATOR_SETTLEMENTS).map_err(|_| FaucetError::Persistence)?;
    let mut records = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let record =
            PreparedSettlement::decode(&mut decoder).map_err(|_| FaucetError::Persistence)?;
        if previous.is_some_and(|reference| reference >= record.reference) {
            return Err(FaucetError::Persistence);
        }
        previous = Some(record.reference);
        records.push(record);
    }
    decoder.finish().map_err(|_| FaucetError::Persistence)?;
    Ok(records)
}

fn journal_tag(bytes: &[u8]) -> [u8; JOURNAL_TAG_LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-OPERATOR-FAUCET-JOURNAL-V1");
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    let mut tag = [0; JOURNAL_TAG_LENGTH];
    XofReader::read(&mut hasher.finalize_xof(), &mut tag);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_cash_kernel::CoinTransfer;
    use activechain_protocol_types::{ChainId, CoinCellId, CryptoSuiteId, ProtocolSignature};
    use activechain_wallet_core::{
        AuthorizedCashSessionGrantV1, AuthorizedCashTransferV1, CashAuthorizationRequestV1,
        CashSessionGrantV1,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn authorization(
        reference: Digest384,
        recipient: PrincipalId,
        amount: u128,
    ) -> OperatorFaucetAuthorizationV1 {
        let sender = PrincipalId::new(digest(2));
        let transfer = CoinTransfer::new(
            sender,
            recipient,
            vec![CoinCellId::new(digest(3))],
            CoinCellId::new(digest(4)),
            amount,
            1,
            20,
        )
        .unwrap();
        let request = CashAuthorizationRequestV1::new_with_settlement_reference(
            ChainId::new(digest(1)),
            sender,
            0,
            reference,
            20,
            Some(reference),
            transfer,
        )
        .unwrap();
        let signature =
            || ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![7; 2_420]).unwrap();
        let session = AuthorizedCashSessionGrantV1::new(
            CashSessionGrantV1::new(ChainId::new(digest(1)), sender, reference, 1, 20, amount + 1)
                .unwrap(),
            signature(),
        )
        .unwrap();
        let transfer = AuthorizedCashTransferV1::new(request, signature()).unwrap();
        OperatorFaucetAuthorizationV1::new(session, transfer).unwrap()
    }

    struct Ingress {
        calls: AtomicUsize,
    }
    impl OperatorFaucetIngressAdapter for Ingress {
        fn settle_operator_authorization(
            &self,
            authorization: &OperatorFaucetAuthorizationV1,
            _recipient: PrincipalId,
            _amount: u128,
            _reference: Digest384,
        ) -> Result<TransactionId, FaucetError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(TransactionId::new(authorization.transfer().request().intent_id().unwrap()))
        }
    }

    #[test]
    fn prepared_operator_envelope_survives_restart_and_is_reused_byte_identically() {
        let path = std::env::temp_dir()
            .join(format!("activechain-operator-faucet-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let reference = digest(8);
        let recipient = PrincipalId::new(digest(9));
        let authorizations = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&authorizations);
        let adapter = DurableOperatorFaucetSettlement::create(
            path.clone(),
            move |recipient, amount, reference| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(authorization(reference, recipient, amount))
            },
            Ingress { calls: AtomicUsize::new(0) },
        )
        .unwrap();
        let transaction = adapter.settle(recipient, 10, reference).unwrap();
        assert_eq!(authorizations.load(Ordering::SeqCst), 1);
        drop(adapter);

        let counter = std::sync::Arc::clone(&authorizations);
        let restored = DurableOperatorFaucetSettlement::open(
            path.clone(),
            move |recipient, amount, reference| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(authorization(reference, recipient, amount))
            },
            Ingress { calls: AtomicUsize::new(0) },
        )
        .unwrap();
        assert_eq!(restored.settle(recipient, 10, reference).unwrap(), transaction);
        assert_eq!(authorizations.load(Ordering::SeqCst), 1);
        assert_eq!(
            restored.settle(PrincipalId::new(digest(10)), 10, reference),
            Err(FaucetError::InvalidTransition)
        );
        std::fs::remove_file(path).unwrap();
    }

    /// Startup recovery rejects a reservation on the strength of its reference
    /// being absent from the journal, so "absent" must never be reachable from
    /// a journal that could not be read. A missing, truncated, or tampered
    /// journal has to fail rather than report an empty set — otherwise a
    /// corrupt file would look exactly like an operator who authorized nothing,
    /// and recovery would close reservations that may in fact have settled.
    #[test]
    fn an_unreadable_journal_yields_an_error_rather_than_no_references() {
        let nonce =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("activechain-journal-{nonce}.bin"));

        assert!(journal_references(&path).is_err(), "a missing journal is not an empty journal");

        std::fs::write(&path, b"short").unwrap();
        assert!(journal_references(&path).is_err(), "a truncated journal is not an empty journal");

        // Long enough to carry an integrity tag, but not one that matches.
        std::fs::write(&path, vec![0_u8; JOURNAL_TAG_LENGTH + 8]).unwrap();
        assert!(journal_references(&path).is_err(), "a tampered journal is not an empty journal");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn spool_adapter_publishes_one_idempotent_validator_frame() {
        let directory =
            std::env::temp_dir().join(format!("activechain-faucet-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir(&directory);
        let adapter = SpoolOperatorFaucetIngressAdapter::new(directory.clone()).unwrap();
        let reference = digest(21);
        let recipient = PrincipalId::new(digest(22));
        let authorization = authorization(reference, recipient, 10);
        let transaction = adapter
            .settle_operator_authorization(&authorization, recipient, 10, reference)
            .unwrap();
        assert_eq!(
            adapter
                .settle_operator_authorization(&authorization, recipient, 10, reference)
                .unwrap(),
            transaction
        );
        let entries =
            std::fs::read_dir(&directory).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(entries.len(), 1);
        let frame = std::fs::read(entries[0].path()).unwrap();
        let length = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(length, frame.len() - 4);
        assert_eq!(
            decode_envelope::<OperatorFaucetAuthorizationV1>(&frame[4..]).unwrap(),
            authorization
        );
        assert_eq!(
            adapter.settle_operator_authorization(
                &authorization,
                PrincipalId::new(digest(23)),
                10,
                reference,
            ),
            Err(FaucetError::InvalidTransition)
        );
        std::fs::remove_file(entries[0].path()).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
