use crate::{FaucetError, FaucetSettlementAdapter};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, DecodeError, Decoder, EncodeError, Encoder, decode_envelope,
    encode_envelope,
};
use activechain_protocol_types::{Digest384, PrincipalId, TransactionId};
use activechain_wallet_core::OperatorFaucetAuthorizationV1;
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
}
