use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, DecodeError, Decoder, EncodeError, Encoder, decode_envelope,
    encode_envelope,
};
use activechain_finality_types::commit_parts;
use activechain_protocol_types::{ChainId, Digest384, PrincipalId, TransactionId};
use activechain_rpc_types::{
    MAX_TRANSFER_ENVELOPE_LENGTH, MAX_TRANSFER_SESSION_LENGTH, TransferReceiptV1,
    TransferRejectionCode, TransferRejectionV1, TransferState,
};
use activechain_wallet_core::{
    AuthorizedCashSessionGrantV1, AuthorizedCashTransferV1, OperatorFaucetAuthorizationV1,
    TransactionIngress, WalletError,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const SNAPSHOT_VERSION: u16 = 1;
const SNAPSHOT_TAG_LENGTH: usize = 32;
const MAX_TRANSFER_RECORDS: usize = 1_024;
const MAX_PENDING_TRANSFERS: usize = 32;
const MAX_TRANSFER_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferSubmissionPolicy {
    pub chain_id: ChainId,
    pub genesis_commitment: Digest384,
    pub enabled: bool,
    pub maximum_pending_count: u16,
    pub maximum_pending_bytes: u32,
    pub maximum_retained_records: u16,
    pub terminal_retention_seconds: u64,
    pub signer_window_seconds: u64,
    pub signer_window_limit: u16,
    pub global_window_seconds: u64,
    pub global_window_limit: u16,
}

impl TransferSubmissionPolicy {
    pub fn validate(self) -> Result<(), TransferSubmissionError> {
        if self.genesis_commitment == Digest384::ZERO
            || self.maximum_pending_count == 0
            || usize::from(self.maximum_pending_count) > MAX_PENDING_TRANSFERS
            || self.maximum_pending_bytes == 0
            || usize::try_from(self.maximum_pending_bytes)
                .ok()
                .is_none_or(|bytes| bytes > MAX_TRANSFER_SNAPSHOT_BYTES)
            || self.maximum_retained_records == 0
            || usize::from(self.maximum_retained_records) > MAX_TRANSFER_RECORDS
            || self.terminal_retention_seconds == 0
            || self.signer_window_seconds == 0
            || self.signer_window_limit == 0
            || self.global_window_seconds == 0
            || self.global_window_limit == 0
        {
            return Err(TransferSubmissionError::InvalidPolicy);
        }
        Ok(())
    }
}

impl CanonicalEncode for TransferSubmissionPolicy {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(encoder)?;
        self.genesis_commitment.encode(encoder)?;
        self.enabled.encode(encoder)?;
        self.maximum_pending_count.encode(encoder)?;
        self.maximum_pending_bytes.encode(encoder)?;
        self.maximum_retained_records.encode(encoder)?;
        self.terminal_retention_seconds.encode(encoder)?;
        self.signer_window_seconds.encode(encoder)?;
        self.signer_window_limit.encode(encoder)?;
        self.global_window_seconds.encode(encoder)?;
        self.global_window_limit.encode(encoder)
    }
}

impl CanonicalDecode for TransferSubmissionPolicy {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let policy = Self {
            chain_id: ChainId::decode(decoder)?,
            genesis_commitment: Digest384::decode(decoder)?,
            enabled: bool::decode(decoder)?,
            maximum_pending_count: u16::decode(decoder)?,
            maximum_pending_bytes: u32::decode(decoder)?,
            maximum_retained_records: u16::decode(decoder)?,
            terminal_retention_seconds: u64::decode(decoder)?,
            signer_window_seconds: u64::decode(decoder)?,
            signer_window_limit: u16::decode(decoder)?,
            global_window_seconds: u64::decode(decoder)?,
            global_window_limit: u16::decode(decoder)?,
        };
        policy
            .validate()
            .map_err(|_| DecodeError::InvalidValue("invalid transfer submission policy"))?;
        Ok(policy)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferSubmissionError {
    InvalidPolicy,
    Rejected(TransferRejectionV1),
    Persistence,
    InvalidFinality,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransferRecord {
    reference: Digest384,
    signer: PrincipalId,
    session_id: Digest384,
    accepted_at: u64,
    updated_at: u64,
    session: Vec<u8>,
    transfer: Vec<u8>,
    receipt: TransferReceiptV1,
}

impl TransferRecord {
    fn encoded_bundle_length(&self) -> usize {
        self.session.len().saturating_add(self.transfer.len())
    }

    fn validate(&self) -> Result<(), TransferSubmissionError> {
        if self.reference == Digest384::ZERO
            || self.session_id == Digest384::ZERO
            || self.accepted_at == 0
            || self.updated_at < self.accepted_at
            || self.session.is_empty()
            || self.session.len() > MAX_TRANSFER_SESSION_LENGTH
            || self.transfer.is_empty()
            || self.transfer.len() > MAX_TRANSFER_ENVELOPE_LENGTH
            || self.receipt.reference() != self.reference
            || self.receipt.state() == TransferState::Unknown
        {
            return Err(TransferSubmissionError::Persistence);
        }
        let session = canonical_session(&self.session)?;
        let transfer = canonical_transfer(&self.transfer)?;
        let request = transfer.request();
        if session.grant().signer() != self.signer
            || request.signer() != self.signer
            || session.grant().session_id() != self.session_id
            || request.session_id() != self.session_id
            || request.intent_id().map_err(|_| TransferSubmissionError::Persistence)?
                != self.reference
        {
            return Err(TransferSubmissionError::Persistence);
        }
        Ok(())
    }
}

impl CanonicalEncode for TransferRecord {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.reference.encode(encoder)?;
        self.signer.encode(encoder)?;
        self.session_id.encode(encoder)?;
        self.accepted_at.encode(encoder)?;
        self.updated_at.encode(encoder)?;
        encoder.write_bytes(&self.session, MAX_TRANSFER_SESSION_LENGTH)?;
        encoder.write_bytes(&self.transfer, MAX_TRANSFER_ENVELOPE_LENGTH)?;
        self.receipt.encode(encoder)
    }
}

impl CanonicalDecode for TransferRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let record = Self {
            reference: Digest384::decode(decoder)?,
            signer: PrincipalId::decode(decoder)?,
            session_id: Digest384::decode(decoder)?,
            accepted_at: u64::decode(decoder)?,
            updated_at: u64::decode(decoder)?,
            session: decoder.read_bytes(MAX_TRANSFER_SESSION_LENGTH)?.to_vec(),
            transfer: decoder.read_bytes(MAX_TRANSFER_ENVELOPE_LENGTH)?.to_vec(),
            receipt: TransferReceiptV1::decode(decoder)?,
        };
        record
            .validate()
            .map_err(|_| DecodeError::InvalidValue("invalid durable transfer record"))?;
        Ok(record)
    }
}

pub struct DurableTransferSubmissions {
    policy: TransferSubmissionPolicy,
    path: PathBuf,
    records: Vec<TransferRecord>,
    faulted: bool,
}

struct SnapshotLock {
    _file: File,
}

impl DurableTransferSubmissions {
    pub fn create(
        policy: TransferSubmissionPolicy,
        path: PathBuf,
    ) -> Result<Self, TransferSubmissionError> {
        policy.validate()?;
        let _lock = lock_snapshot(&path)?;
        if path.exists() {
            return Err(TransferSubmissionError::Persistence);
        }
        let submissions = Self { policy, path, records: Vec::new(), faulted: false };
        save_snapshot(&submissions.path, submissions.policy, &submissions.records)?;
        Ok(submissions)
    }

    pub fn open(
        policy: TransferSubmissionPolicy,
        path: PathBuf,
    ) -> Result<Self, TransferSubmissionError> {
        policy.validate()?;
        let submissions = Self::restore(path)?;
        if submissions.policy != policy {
            return Err(TransferSubmissionError::InvalidPolicy);
        }
        Ok(submissions)
    }

    /// Restores the policy and records from the authenticated snapshot. The
    /// round assembler independently checks the stored chain and genesis
    /// against the finalized RPC index before exporting any action.
    pub fn restore(path: PathBuf) -> Result<Self, TransferSubmissionError> {
        let _lock = lock_snapshot(&path)?;
        let (policy, records) = load_snapshot(&path)?;
        Ok(Self { policy, path, records, faulted: false })
    }

    #[must_use]
    pub const fn policy(&self) -> TransferSubmissionPolicy {
        self.policy
    }

    pub fn submit(
        &mut self,
        session_bytes: &[u8],
        transfer_bytes: &[u8],
        ingress: &TransactionIngress,
        finalized_height: u64,
        now: u64,
    ) -> Result<TransferReceiptV1, TransferSubmissionError> {
        if self.faulted {
            return Err(TransferSubmissionError::Persistence);
        }
        let _lock = lock_snapshot(&self.path)?;
        self.reload_locked()?;
        if !self.policy.enabled {
            return Err(rejected(TransferRejectionCode::Disabled, None, None));
        }
        if session_bytes.is_empty()
            || session_bytes.len() > MAX_TRANSFER_SESSION_LENGTH
            || transfer_bytes.is_empty()
            || transfer_bytes.len() > MAX_TRANSFER_ENVELOPE_LENGTH
        {
            return Err(rejected(TransferRejectionCode::Malformed, None, None));
        }
        let session = canonical_session(session_bytes)
            .map_err(|_| rejected(TransferRejectionCode::Malformed, None, None))?;
        let transfer = canonical_transfer(transfer_bytes)
            .map_err(|_| rejected(TransferRejectionCode::Malformed, None, None))?;
        let request = transfer.request();
        let reference = request
            .intent_id()
            .map_err(|_| rejected(TransferRejectionCode::Malformed, None, None))?;

        if let Ok(index) = self.records.binary_search_by_key(&reference, |record| record.reference)
        {
            return Ok(self.records[index].receipt.clone());
        }
        if request.chain_id() != self.policy.chain_id
            || session.grant().chain_id() != self.policy.chain_id
        {
            return Err(rejected(TransferRejectionCode::WrongNetwork, None, Some(reference)));
        }
        if session.grant().signer() != request.signer()
            || session.grant().session_id() != request.session_id()
            || session.grant().chain_id() != request.chain_id()
        {
            return Err(rejected(TransferRejectionCode::SessionInvalid, None, Some(reference)));
        }

        // Authentication happens before quota or durable state. A request that
        // cannot prove authority cannot consume somebody else's allowance or
        // reserve their intent identifier.
        let mut preview = ingress.clone();
        preview.register_session(&session).map_err(|error| {
            rejected(classify_pre_spool(error, request, finalized_height), None, Some(reference))
        })?;
        preview.submit_authorized(&transfer, finalized_height).map_err(|error| {
            rejected(classify_pre_spool(error, request, finalized_height), None, Some(reference))
        })?;

        let signer = request.signer();
        let session_id = request.session_id();
        if self.records.iter().any(|record| {
            record.receipt.state() == TransferState::Pending
                && record.signer == signer
                && record.session_id == session_id
        }) {
            return Err(rejected(TransferRejectionCode::SessionInvalid, None, Some(reference)));
        }
        let signer_start = now.saturating_sub(self.policy.signer_window_seconds);
        let signer_count = self
            .records
            .iter()
            .filter(|record| record.signer == signer && record.accepted_at >= signer_start)
            .count();
        if signer_count >= usize::from(self.policy.signer_window_limit) {
            return Err(rejected(
                TransferRejectionCode::SignerLimited,
                Some(self.policy.signer_window_seconds),
                Some(reference),
            ));
        }
        let global_start = now.saturating_sub(self.policy.global_window_seconds);
        let global_count =
            self.records.iter().filter(|record| record.accepted_at >= global_start).count();
        if global_count >= usize::from(self.policy.global_window_limit) {
            return Err(rejected(
                TransferRejectionCode::GlobalLimited,
                Some(self.policy.global_window_seconds),
                Some(reference),
            ));
        }

        let pending_count = self
            .records
            .iter()
            .filter(|record| record.receipt.state() == TransferState::Pending)
            .count();
        let pending_bytes = self
            .records
            .iter()
            .filter(|record| record.receipt.state() == TransferState::Pending)
            .map(TransferRecord::encoded_bundle_length)
            .sum::<usize>();
        let bundle_bytes = session_bytes.len().saturating_add(transfer_bytes.len());
        if pending_count >= usize::from(self.policy.maximum_pending_count)
            || pending_bytes.saturating_add(bundle_bytes)
                > usize::try_from(self.policy.maximum_pending_bytes).unwrap_or(usize::MAX)
        {
            return Err(rejected(TransferRejectionCode::SpoolFull, Some(1), Some(reference)));
        }

        let mut next = self.records.clone();
        evict_expired(&mut next, self.policy, now);
        while next.len() >= usize::from(self.policy.maximum_retained_records) {
            let Some((index, _)) = next
                .iter()
                .enumerate()
                .filter(|(_, record)| record.receipt.state() != TransferState::Pending)
                .min_by_key(|(_, record)| (record.updated_at, record.reference))
            else {
                return Err(rejected(TransferRejectionCode::SpoolFull, Some(1), Some(reference)));
            };
            next.remove(index);
        }
        let receipt =
            TransferReceiptV1::new(reference, TransferState::Pending, None, None, None, None)
                .map_err(|_| TransferSubmissionError::Persistence)?;
        let record = TransferRecord {
            reference,
            signer,
            session_id,
            accepted_at: now,
            updated_at: now,
            session: session_bytes.to_vec(),
            transfer: transfer_bytes.to_vec(),
            receipt: receipt.clone(),
        };
        let position =
            next.binary_search_by_key(&reference, |record| record.reference).unwrap_err();
        next.insert(position, record);
        self.publish(next)?;
        Ok(receipt)
    }

    pub fn resolve(
        &mut self,
        reference: Digest384,
    ) -> Result<TransferReceiptV1, TransferSubmissionError> {
        if self.faulted {
            return Err(TransferSubmissionError::Persistence);
        }
        let _lock = lock_snapshot(&self.path)?;
        self.reload_locked()?;
        if reference == Digest384::ZERO {
            return Err(TransferSubmissionError::Persistence);
        }
        if let Ok(index) = self.records.binary_search_by_key(&reference, |record| record.reference)
        {
            return Ok(self.records[index].receipt.clone());
        }
        TransferReceiptV1::new(reference, TransferState::Unknown, None, None, None, None)
            .map_err(|_| TransferSubmissionError::Persistence)
    }

    /// Revalidates pending bundles against the exact finalized ingress state
    /// used to build the next round. Invalidated submissions become terminal
    /// before the batch is published; accepted bundles remain Pending until a
    /// finality archive proves their exact transaction identifiers.
    pub fn prepare_pending_batch(
        &mut self,
        ingress: &TransactionIngress,
        prefix_actions: &[Vec<u8>],
        height: u64,
        now: u64,
        maximum_actions: usize,
    ) -> Result<Vec<Vec<u8>>, TransferSubmissionError> {
        if self.faulted {
            return Err(TransferSubmissionError::Persistence);
        }
        let _lock = lock_snapshot(&self.path)?;
        self.reload_locked()?;
        if maximum_actions > MAX_PENDING_TRANSFERS || prefix_actions.len() > maximum_actions {
            return Err(TransferSubmissionError::Persistence);
        }
        let mut preview = ingress.clone();
        for action in prefix_actions {
            apply_action(&mut preview, action, height)?;
        }
        let mut next = self.records.clone();
        let mut actions = Vec::new();
        let mut changed = false;
        let mut pending = next
            .iter()
            .enumerate()
            .filter(|(_, record)| record.receipt.state() == TransferState::Pending)
            .map(|(index, record)| (index, record.accepted_at, record.reference))
            .collect::<Vec<_>>();
        pending.sort_by_key(|(_, accepted_at, reference)| (*accepted_at, *reference));
        for (index, _, _) in pending {
            if prefix_actions.len() + actions.len() == maximum_actions {
                break;
            }
            let session = canonical_session(&next[index].session)?;
            let transfer = canonical_transfer(&next[index].transfer)?;
            let mut candidate = preview.clone();
            let result = candidate
                .register_session(&session)
                .and_then(|()| candidate.submit_authorized(&transfer, height));
            match result {
                Ok(()) => {
                    let bundle = OperatorFaucetAuthorizationV1::new(session, transfer)
                        .map_err(|_| TransferSubmissionError::Persistence)?;
                    actions.push(
                        encode_envelope(&bundle)
                            .map_err(|_| TransferSubmissionError::Persistence)?,
                    );
                    preview = candidate;
                }
                Err(error) => {
                    let code = classify_post_spool(error, transfer.request(), height)?;
                    let rejection =
                        TransferRejectionV1::new(code, None, Some(next[index].reference))
                            .map_err(|_| TransferSubmissionError::Persistence)?;
                    next[index].receipt = TransferReceiptV1::new(
                        next[index].reference,
                        TransferState::Rejected,
                        None,
                        None,
                        None,
                        Some(rejection),
                    )
                    .map_err(|_| TransferSubmissionError::Persistence)?;
                    next[index].updated_at = now;
                    changed = true;
                }
            }
        }
        if changed {
            self.publish(next)?;
        }
        Ok(actions)
    }

    pub fn reconcile_finality(
        &mut self,
        batch: &[u8],
        finality: &[u8],
        now: u64,
    ) -> Result<usize, TransferSubmissionError> {
        if self.faulted {
            return Err(TransferSubmissionError::Persistence);
        }
        let _lock = lock_snapshot(&self.path)?;
        self.reload_locked()?;
        let actions = parse_framed_actions(batch)?;
        let ids = actions.iter().map(|action| action_id(action)).collect::<Result<Vec<_>, _>>()?;
        let mut committed = Vec::with_capacity(ids.len() * 48);
        for id in &ids {
            committed.extend_from_slice(id.digest().as_bytes());
        }
        let bundle = activechain_verifier_api::verify_finality_bundle_with_chain_genesis(
            finality,
            self.policy.genesis_commitment,
        )
        .map_err(|_| TransferSubmissionError::InvalidFinality)?;
        if commit_parts(b"ACTIVECHAIN-BLOCK-CASH-ACTIONS-V1", &[&committed])
            != bundle.header().inputs.cash_action_root
        {
            return Err(TransferSubmissionError::InvalidFinality);
        }
        let height = bundle.header().inputs.height;
        let block =
            bundle.header().digest().map_err(|_| TransferSubmissionError::InvalidFinality)?;
        let mut next = self.records.clone();
        let mut reconciled = 0;
        for record in &mut next {
            let transaction = TransactionId::new(record.reference);
            if record.receipt.state() == TransferState::Pending && ids.contains(&transaction) {
                record.receipt = TransferReceiptV1::new(
                    record.reference,
                    TransferState::Finalized,
                    Some(transaction),
                    Some(height),
                    Some(block),
                    None,
                )
                .map_err(|_| TransferSubmissionError::Persistence)?;
                record.updated_at = now;
                reconciled += 1;
            }
        }
        if reconciled > 0 {
            self.publish(next)?;
        }
        Ok(reconciled)
    }

    fn publish(&mut self, records: Vec<TransferRecord>) -> Result<(), TransferSubmissionError> {
        if save_snapshot(&self.path, self.policy, &records).is_err() {
            self.faulted = true;
            return Err(TransferSubmissionError::Persistence);
        }
        self.records = records;
        Ok(())
    }

    fn reload_locked(&mut self) -> Result<(), TransferSubmissionError> {
        let (policy, records) = load_snapshot(&self.path)?;
        if policy != self.policy {
            self.faulted = true;
            return Err(TransferSubmissionError::InvalidPolicy);
        }
        self.records = records;
        Ok(())
    }
}

pub fn parse_framed_actions(bytes: &[u8]) -> Result<Vec<Vec<u8>>, TransferSubmissionError> {
    let mut offset = 0;
    let mut actions = Vec::new();
    while offset < bytes.len() {
        if actions.len() == MAX_PENDING_TRANSFERS || bytes.len() - offset < 4 {
            return Err(TransferSubmissionError::Persistence);
        }
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| TransferSubmissionError::Persistence)?,
        ) as usize;
        offset += 4;
        if length == 0
            || length > activechain_wallet_core::MAX_INGRESS_FRAME
            || bytes.len() - offset < length
        {
            return Err(TransferSubmissionError::Persistence);
        }
        actions.push(bytes[offset..offset + length].to_vec());
        offset += length;
    }
    Ok(actions)
}

pub fn frame_actions(actions: &[Vec<u8>]) -> Result<Vec<u8>, TransferSubmissionError> {
    if actions.len() > MAX_PENDING_TRANSFERS {
        return Err(TransferSubmissionError::Persistence);
    }
    let mut framed = Vec::new();
    for action in actions {
        if action.is_empty() || action.len() > activechain_wallet_core::MAX_INGRESS_FRAME {
            return Err(TransferSubmissionError::Persistence);
        }
        let length =
            u32::try_from(action.len()).map_err(|_| TransferSubmissionError::Persistence)?;
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(action);
    }
    Ok(framed)
}

fn canonical_session(
    bytes: &[u8],
) -> Result<AuthorizedCashSessionGrantV1, TransferSubmissionError> {
    let session = decode_envelope::<AuthorizedCashSessionGrantV1>(bytes)
        .map_err(|_| TransferSubmissionError::Persistence)?;
    if encode_envelope(&session).map_err(|_| TransferSubmissionError::Persistence)? != bytes {
        return Err(TransferSubmissionError::Persistence);
    }
    Ok(session)
}

fn canonical_transfer(bytes: &[u8]) -> Result<AuthorizedCashTransferV1, TransferSubmissionError> {
    let transfer = decode_envelope::<AuthorizedCashTransferV1>(bytes)
        .map_err(|_| TransferSubmissionError::Persistence)?;
    if encode_envelope(&transfer).map_err(|_| TransferSubmissionError::Persistence)? != bytes {
        return Err(TransferSubmissionError::Persistence);
    }
    Ok(transfer)
}

fn apply_action(
    ingress: &mut TransactionIngress,
    action: &[u8],
    height: u64,
) -> Result<(), TransferSubmissionError> {
    if let Ok(bundle) = decode_envelope::<OperatorFaucetAuthorizationV1>(action) {
        ingress
            .submit_operator_faucet_authorization(&bundle, height)
            .map_err(|_| TransferSubmissionError::Persistence)
    } else {
        ingress.submit_envelope(action, height).map_err(|_| TransferSubmissionError::Persistence)
    }
}

fn action_id(action: &[u8]) -> Result<TransactionId, TransferSubmissionError> {
    let digest = if let Ok(bundle) = decode_envelope::<OperatorFaucetAuthorizationV1>(action) {
        bundle.transfer().request().intent_id()
    } else {
        decode_envelope::<AuthorizedCashTransferV1>(action)
            .map_err(|_| TransferSubmissionError::InvalidFinality)?
            .request()
            .intent_id()
    }
    .map_err(|_| TransferSubmissionError::InvalidFinality)?;
    Ok(TransactionId::new(digest))
}

fn classify_pre_spool(
    error: WalletError,
    request: &activechain_wallet_core::CashAuthorizationRequestV1,
    height: u64,
) -> TransferRejectionCode {
    match error {
        WalletError::WrongChain => TransferRejectionCode::WrongNetwork,
        WalletError::Expired if height > request.transfer().valid_until() => {
            TransferRejectionCode::ValidityWindowLapsed
        }
        WalletError::Expired => TransferRejectionCode::SessionExpired,
        WalletError::SessionReplay | WalletError::UnknownSession => {
            TransferRejectionCode::SessionInvalid
        }
        WalletError::InputReplay | WalletError::InsufficientFunds => {
            TransferRejectionCode::InputAlreadySpent
        }
        _ => TransferRejectionCode::InvalidAuthorization,
    }
}

fn classify_post_spool(
    error: WalletError,
    request: &activechain_wallet_core::CashAuthorizationRequestV1,
    height: u64,
) -> Result<TransferRejectionCode, TransferSubmissionError> {
    match error {
        WalletError::Expired if height > request.transfer().valid_until() => {
            Ok(TransferRejectionCode::ValidityWindowLapsed)
        }
        WalletError::Expired => Ok(TransferRejectionCode::SessionExpired),
        WalletError::InputReplay
        | WalletError::InsufficientFunds
        | WalletError::InvalidNonce
        | WalletError::SessionReplay
        | WalletError::UnknownSession => Ok(TransferRejectionCode::InputAlreadySpent),
        // These were authenticated and canonical at admission. Seeing a
        // structural/signature/network failure later means durable state was
        // corrupted or replaced, not that the client earned a new outcome.
        _ => Err(TransferSubmissionError::Persistence),
    }
}

fn rejected(
    code: TransferRejectionCode,
    retry_after_seconds: Option<u64>,
    intent: Option<Digest384>,
) -> TransferSubmissionError {
    let rejection = TransferRejectionV1::new(code, retry_after_seconds, intent)
        .expect("internally selected transfer rejection is valid");
    TransferSubmissionError::Rejected(rejection)
}

fn evict_expired(records: &mut Vec<TransferRecord>, policy: TransferSubmissionPolicy, now: u64) {
    records.retain(|record| {
        record.receipt.state() == TransferState::Pending
            || now.saturating_sub(record.updated_at) < policy.terminal_retention_seconds
    });
}

fn save_snapshot(
    path: &Path,
    policy: TransferSubmissionPolicy,
    records: &[TransferRecord],
) -> Result<(), TransferSubmissionError> {
    if records.len() > usize::from(policy.maximum_retained_records)
        || records.windows(2).any(|pair| pair[0].reference >= pair[1].reference)
    {
        return Err(TransferSubmissionError::Persistence);
    }
    let mut encoder = Encoder::new(MAX_TRANSFER_SNAPSHOT_BYTES);
    SNAPSHOT_VERSION.encode(&mut encoder).map_err(|_| TransferSubmissionError::Persistence)?;
    policy.encode(&mut encoder).map_err(|_| TransferSubmissionError::Persistence)?;
    encoder
        .write_length(records.len(), MAX_TRANSFER_RECORDS)
        .map_err(|_| TransferSubmissionError::Persistence)?;
    for record in records {
        record.validate()?;
        record.encode(&mut encoder).map_err(|_| TransferSubmissionError::Persistence)?;
    }
    let body = encoder.finish();
    if body.len() > MAX_TRANSFER_SNAPSHOT_BYTES - SNAPSHOT_TAG_LENGTH {
        return Err(TransferSubmissionError::Persistence);
    }
    let mut snapshot = body.clone();
    snapshot.extend_from_slice(&snapshot_tag(&body));
    atomic_write(path, &snapshot)
}

fn load_snapshot(
    path: &Path,
) -> Result<(TransferSubmissionPolicy, Vec<TransferRecord>), TransferSubmissionError> {
    let bytes = std::fs::read(path).map_err(|_| TransferSubmissionError::Persistence)?;
    if bytes.len() <= SNAPSHOT_TAG_LENGTH || bytes.len() > MAX_TRANSFER_SNAPSHOT_BYTES {
        return Err(TransferSubmissionError::Persistence);
    }
    let body_length = bytes.len() - SNAPSHOT_TAG_LENGTH;
    if snapshot_tag(&bytes[..body_length]).as_slice() != &bytes[body_length..] {
        return Err(TransferSubmissionError::Persistence);
    }
    let mut decoder = Decoder::new(&bytes[..body_length]);
    if u16::decode(&mut decoder).map_err(|_| TransferSubmissionError::Persistence)?
        != SNAPSHOT_VERSION
    {
        return Err(TransferSubmissionError::Persistence);
    }
    let policy = TransferSubmissionPolicy::decode(&mut decoder)
        .map_err(|_| TransferSubmissionError::Persistence)?;
    let count = decoder
        .read_length(MAX_TRANSFER_RECORDS)
        .map_err(|_| TransferSubmissionError::Persistence)?;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(
            TransferRecord::decode(&mut decoder)
                .map_err(|_| TransferSubmissionError::Persistence)?,
        );
    }
    if decoder.remaining() != 0
        || records.windows(2).any(|pair| pair[0].reference >= pair[1].reference)
        || records.len() > usize::from(policy.maximum_retained_records)
    {
        return Err(TransferSubmissionError::Persistence);
    }
    Ok((policy, records))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), TransferSubmissionError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(TransferSubmissionError::Persistence);
    }
    let temporary = path.with_extension(format!("transfer-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|_| TransferSubmissionError::Persistence)?;
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        return Err(TransferSubmissionError::Persistence);
    }
    std::fs::rename(&temporary, path).map_err(|_| TransferSubmissionError::Persistence)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| TransferSubmissionError::Persistence)
}

fn lock_snapshot(path: &Path) -> Result<SnapshotLock, TransferSubmissionError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(TransferSubmissionError::Persistence);
    }
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(PathBuf::from(lock_name))
        .map_err(|_| TransferSubmissionError::Persistence)?;
    file.lock().map_err(|_| TransferSubmissionError::Persistence)?;
    Ok(SnapshotLock { _file: file })
}

fn snapshot_tag(body: &[u8]) -> [u8; SNAPSHOT_TAG_LENGTH] {
    let mut shake = Shake256::default();
    shake.update(b"ACTIVECHAIN-DURABLE-TRANSFER-SUBMISSIONS-V1");
    shake.update(body);
    let mut tag = [0; SNAPSHOT_TAG_LENGTH];
    shake.finalize_xof().read(&mut tag);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_cash_kernel::{
        CoinTransfer, GenesisAllocation, GenesisEconomy, NativeAssetDefinition,
    };
    use activechain_finality_types::{
        FinalityCertificateBundle, FinalizedBlockHeader, ProofPublicInputs,
    };
    use activechain_protocol_types::{
        ConsensusVoteContext, CryptoSuiteId, ProtocolSignature, QuorumCertificate,
        ValidatorGenesis, ValidatorGenesisEntry, ValidatorVote,
    };
    use activechain_state_tree::StateCommitment;
    use activechain_wallet_core::{CashAuthorizationRequestV1, CashSessionGrantV1};
    use ml_dsa::{MlDsa44, Seed, Signer, SigningKey, signature::Keypair as _};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("activechain-transfer-submission-{name}-{}", std::process::id()))
    }

    fn remove_snapshot(path: &Path) {
        let _ = std::fs::remove_file(path);
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let _ = std::fs::remove_file(PathBuf::from(lock_name));
    }

    fn policy() -> TransferSubmissionPolicy {
        TransferSubmissionPolicy {
            chain_id: ChainId::new(digest(1)),
            genesis_commitment: digest(2),
            enabled: true,
            maximum_pending_count: 4,
            maximum_pending_bytes: 256 * 1024,
            maximum_retained_records: 4,
            terminal_retention_seconds: 100,
            signer_window_seconds: 60,
            signer_window_limit: 4,
            global_window_seconds: 60,
            global_window_limit: 4,
        }
    }

    fn fixture(
        session_byte: u8,
        nonce: u64,
    ) -> (TransactionIngress, AuthorizedCashSessionGrantV1, AuthorizedCashTransferV1) {
        let owner = principal(10);
        let recipient = principal(11);
        let definition = NativeAssetDefinition::new(
            ChainId::new(digest(1)),
            b"ACT".to_vec(),
            18,
            1_000,
            150,
            digest(3),
            digest(4),
            digest(5),
        )
        .unwrap();
        let economy = GenesisEconomy::new(
            definition,
            vec![
                GenesisAllocation::new(owner, 700, 100).unwrap(),
                GenesisAllocation::new(owner, 100, 0).unwrap(),
            ],
            100,
        )
        .unwrap();
        let mut ingress = TransactionIngress::from_genesis(&economy).unwrap();
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([91; 32]));
        ingress
            .bootstrap_genesis_authorization_key(owner, key.verifying_key().encode().into())
            .unwrap();
        let cells = ingress.ledger().cells().as_slice();
        let transfer =
            CoinTransfer::new(owner, recipient, vec![cells[0].id()], cells[1].id(), 10, 1, 20)
                .unwrap();
        let session_id = digest(session_byte);
        let grant = CashSessionGrantV1::new(ChainId::new(digest(1)), owner, session_id, 1, 15, 100)
            .unwrap();
        let grant_signature = key.sign(&grant.signing_payload().unwrap());
        let grant = AuthorizedCashSessionGrantV1::new(
            grant,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, grant_signature.encode().to_vec())
                .unwrap(),
        )
        .unwrap();
        let request = CashAuthorizationRequestV1::new(
            ChainId::new(digest(1)),
            owner,
            nonce,
            session_id,
            15,
            transfer,
        )
        .unwrap();
        let transfer_signature = key.sign(&request.signing_payload().unwrap());
        let transfer = AuthorizedCashTransferV1::new(
            request,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, transfer_signature.encode().to_vec())
                .unwrap(),
        )
        .unwrap();
        (ingress, grant, transfer)
    }

    fn signed_finality(inputs: ProofPublicInputs) -> (Digest384, Vec<u8>) {
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([77; 32]));
        let validator = principal(70);
        let genesis = ValidatorGenesis::new_with_revision(
            3,
            1,
            4,
            vec![
                ValidatorGenesisEntry::new(validator, 1, key.verifying_key().encode().into())
                    .unwrap(),
            ],
        )
        .unwrap();
        let header = FinalizedBlockHeader {
            inputs: ProofPublicInputs {
                validator_set_root: genesis.validator_set_root(),
                ..inputs
            },
            proof_statement_commitment: digest(76),
        };
        let context = ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        let unsigned = ValidatorVote::new(
            validator,
            context,
            7,
            2,
            header.digest().unwrap(),
            header.proof_statement_commitment,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        let signature = key.sign(&unsigned.signing_payload());
        let vote = ValidatorVote::new(
            validator,
            context,
            7,
            2,
            header.digest().unwrap(),
            header.proof_statement_commitment,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap();
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
        hasher.update(key.verifying_key().encode().as_slice());
        hasher.update(&vote.signing_payload());
        hasher.update(vote.signature().as_bytes());
        let mut vote_root = [0; 48];
        XofReader::read(&mut hasher.finalize_xof(), &mut vote_root);
        let certificate = QuorumCertificate::new(
            context,
            7,
            2,
            header.digest().unwrap(),
            header.proof_statement_commitment,
            Digest384::new(vote_root),
            1,
            1,
        )
        .unwrap();
        let commitment = genesis.genesis_commitment();
        let encoded = encode_envelope(
            &FinalityCertificateBundle::new(header, genesis, certificate, vec![vote]).unwrap(),
        )
        .unwrap();
        (commitment, encoded)
    }

    fn finality_inputs(cash_action_root: Digest384) -> ProofPublicInputs {
        ProofPublicInputs {
            chain_id: ChainId::new(digest(1)),
            epoch: 3,
            height: 7,
            protocol_revision: 4,
            validator_set_root: digest(69),
            parent_block_id: digest(71),
            pre_state: StateCommitment::new(digest(80), 0),
            authorization_root: digest(72),
            action_root: digest(73),
            execution_order_root: digest(74),
            total_fees: 0,
            pre_supply: 1_000,
            issuance: 0,
            burn: 0,
            post_supply: 1_000,
            pre_cash_cell_root: digest(75),
            cash_action_root,
            cash_cell_root: digest(76),
            post_state: StateCommitment::new(digest(81), 0),
            receipt_root: digest(77),
            data_availability_commitment: digest(78),
        }
    }

    #[test]
    fn accepted_bundle_and_receipt_are_atomic_durable_and_idempotent() {
        let path = path("durable");
        let _ = std::fs::remove_file(&path);
        let (ingress, session, transfer) = fixture(12, 0);
        let session = encode_envelope(&session).unwrap();
        let transfer = encode_envelope(&transfer).unwrap();
        let mut submissions = DurableTransferSubmissions::create(policy(), path.clone()).unwrap();
        let accepted = submissions.submit(&session, &transfer, &ingress, 5, 100).unwrap();
        assert_eq!(accepted.state(), TransferState::Pending);
        assert_eq!(submissions.submit(&session, &transfer, &ingress, 5, 101), Ok(accepted.clone()));
        drop(submissions);
        let mut restored = DurableTransferSubmissions::open(policy(), path.clone()).unwrap();
        assert_eq!(restored.resolve(accepted.reference()), Ok(accepted));

        let mut corrupted = std::fs::read(&path).unwrap();
        corrupted[0] ^= 1;
        std::fs::write(&path, corrupted).unwrap();
        assert!(matches!(
            DurableTransferSubmissions::open(policy(), path.clone()),
            Err(TransferSubmissionError::Persistence)
        ));
        remove_snapshot(&path);
    }

    #[test]
    fn malformed_input_never_reserves_an_intent_or_consumes_quota() {
        let path = path("malformed");
        let _ = std::fs::remove_file(&path);
        let (ingress, session, transfer) = fixture(12, 0);
        let mut submissions = DurableTransferSubmissions::create(policy(), path.clone()).unwrap();
        assert!(matches!(
            submissions.submit(&[0], &[1], &ingress, 5, 100),
            Err(TransferSubmissionError::Rejected(rejection))
                if rejection.code() == TransferRejectionCode::Malformed
                    && rejection.intent().is_none()
        ));
        let mut tampered_transfer = encode_envelope(&transfer).unwrap();
        *tampered_transfer.last_mut().unwrap() ^= 1;
        assert!(matches!(
            submissions.submit(
                &encode_envelope(&session).unwrap(),
                &tampered_transfer,
                &ingress,
                5,
                100,
            ),
            Err(TransferSubmissionError::Rejected(rejection))
                if rejection.code() == TransferRejectionCode::InvalidAuthorization
                    && rejection.intent().is_some()
        ));
        let accepted = submissions
            .submit(
                &encode_envelope(&session).unwrap(),
                &encode_envelope(&transfer).unwrap(),
                &ingress,
                5,
                100,
            )
            .unwrap();
        assert_eq!(accepted.state(), TransferState::Pending);
        remove_snapshot(&path);
    }

    #[test]
    fn pre_round_revalidation_records_a_terminal_refusal_and_eviction_is_unknown() {
        let path = path("revalidation");
        let _ = std::fs::remove_file(&path);
        let (mut ingress, session, transfer) = fixture(12, 0);
        let session_bytes = encode_envelope(&session).unwrap();
        let transfer_bytes = encode_envelope(&transfer).unwrap();
        let mut submissions = DurableTransferSubmissions::create(policy(), path.clone()).unwrap();
        let accepted =
            submissions.submit(&session_bytes, &transfer_bytes, &ingress, 5, 100).unwrap();

        // Another finalized path consumed the same session and inputs after
        // admission but before round assembly.
        ingress.register_session(&session).unwrap();
        ingress.submit_authorized(&transfer, 5).unwrap();
        assert_eq!(
            submissions.prepare_pending_batch(&ingress, &[], 6, 110, 32).unwrap(),
            Vec::<Vec<u8>>::new()
        );
        let rejected = submissions.resolve(accepted.reference()).unwrap();
        assert_eq!(rejected.state(), TransferState::Rejected);
        assert_eq!(rejected.rejection().unwrap().code(), TransferRejectionCode::InputAlreadySpent);
        drop(submissions);
        let mut submissions = DurableTransferSubmissions::open(policy(), path.clone()).unwrap();
        assert_eq!(submissions.resolve(accepted.reference()), Ok(rejected.clone()));
        assert_eq!(
            submissions.submit(&session_bytes, &transfer_bytes, &ingress, 6, 111),
            Ok(rejected.clone())
        );
        assert!(submissions.prepare_pending_batch(&ingress, &[], 6, 112, 32).unwrap().is_empty());

        let (_fresh, second_session, second_transfer) = fixture(13, 0);
        // The old terminal record is evicted by retention before admission is
        // considered; resolving it can never silently resurrect Pending.
        let fresh_ingress = fixture(13, 0).0;
        submissions
            .submit(
                &encode_envelope(&second_session).unwrap(),
                &encode_envelope(&second_transfer).unwrap(),
                &fresh_ingress,
                5,
                211,
            )
            .unwrap();
        assert_eq!(
            submissions.resolve(accepted.reference()).unwrap().state(),
            TransferState::Unknown
        );
        drop(submissions);
        let mut restored = DurableTransferSubmissions::open(policy(), path.clone()).unwrap();
        assert_eq!(restored.resolve(accepted.reference()).unwrap().state(), TransferState::Unknown);
        remove_snapshot(&path);
    }

    #[test]
    fn independent_process_views_reload_under_the_snapshot_lock() {
        let path = path("locked-reload");
        remove_snapshot(&path);
        let (ingress, first_session, first_transfer) = fixture(12, 0);
        let (_, second_session, second_transfer) = fixture(13, 0);
        let mut first = DurableTransferSubmissions::create(policy(), path.clone()).unwrap();
        let mut second = DurableTransferSubmissions::open(policy(), path.clone()).unwrap();
        let first_receipt = first
            .submit(
                &encode_envelope(&first_session).unwrap(),
                &encode_envelope(&first_transfer).unwrap(),
                &ingress,
                5,
                100,
            )
            .unwrap();
        let second_receipt = second
            .submit(
                &encode_envelope(&second_session).unwrap(),
                &encode_envelope(&second_transfer).unwrap(),
                &ingress,
                5,
                101,
            )
            .unwrap();
        let mut restored = DurableTransferSubmissions::open(policy(), path.clone()).unwrap();
        assert_eq!(restored.resolve(first_receipt.reference()), Ok(first_receipt));
        assert_eq!(restored.resolve(second_receipt.reference()), Ok(second_receipt));
        remove_snapshot(&path);
    }

    #[test]
    fn pending_count_refuses_before_spooling_without_reserving_the_intent() {
        let path = path("spool-quota");
        remove_snapshot(&path);
        let mut limited = policy();
        limited.maximum_pending_count = 1;
        let (ingress, first_session, first_transfer) = fixture(12, 0);
        let (_, second_session, second_transfer) = fixture(13, 0);
        let second_reference = second_transfer.request().intent_id().unwrap();
        let mut submissions = DurableTransferSubmissions::create(limited, path.clone()).unwrap();
        submissions
            .submit(
                &encode_envelope(&first_session).unwrap(),
                &encode_envelope(&first_transfer).unwrap(),
                &ingress,
                5,
                100,
            )
            .unwrap();
        assert!(matches!(
            submissions.submit(
                &encode_envelope(&second_session).unwrap(),
                &encode_envelope(&second_transfer).unwrap(),
                &ingress,
                5,
                101,
            ),
            Err(TransferSubmissionError::Rejected(rejection))
                if rejection.code() == TransferRejectionCode::SpoolFull
                    && rejection.intent() == Some(second_reference)
        ));
        assert_eq!(submissions.resolve(second_reference).unwrap().state(), TransferState::Unknown);
        remove_snapshot(&path);
    }

    #[test]
    fn mismatched_expired_and_quota_limited_bundles_never_reach_the_journal() {
        let path = path("admission-refusals");
        remove_snapshot(&path);
        let (ingress, session, transfer) = fixture(12, 0);
        let (_, other_session, other_transfer) = fixture(13, 0);
        let mut submissions = DurableTransferSubmissions::create(policy(), path.clone()).unwrap();
        assert!(matches!(
            submissions.submit(
                &encode_envelope(&other_session).unwrap(),
                &encode_envelope(&transfer).unwrap(),
                &ingress,
                5,
                100,
            ),
            Err(TransferSubmissionError::Rejected(rejection))
                if rejection.code() == TransferRejectionCode::SessionInvalid
        ));
        assert!(matches!(
            submissions.submit(
                &encode_envelope(&session).unwrap(),
                &encode_envelope(&transfer).unwrap(),
                &ingress,
                16,
                100,
            ),
            Err(TransferSubmissionError::Rejected(rejection))
                if rejection.code() == TransferRejectionCode::SessionExpired
        ));
        drop(submissions);
        remove_snapshot(&path);

        let mut signer_policy = policy();
        signer_policy.signer_window_limit = 1;
        let mut submissions =
            DurableTransferSubmissions::create(signer_policy, path.clone()).unwrap();
        submissions
            .submit(
                &encode_envelope(&session).unwrap(),
                &encode_envelope(&transfer).unwrap(),
                &ingress,
                5,
                100,
            )
            .unwrap();
        assert!(matches!(
            submissions.submit(
                &encode_envelope(&other_session).unwrap(),
                &encode_envelope(&other_transfer).unwrap(),
                &ingress,
                5,
                101,
            ),
            Err(TransferSubmissionError::Rejected(rejection))
                if rejection.code() == TransferRejectionCode::SignerLimited
        ));
        drop(submissions);
        remove_snapshot(&path);

        let mut global_policy = policy();
        global_policy.global_window_limit = 1;
        let mut submissions =
            DurableTransferSubmissions::create(global_policy, path.clone()).unwrap();
        submissions
            .submit(
                &encode_envelope(&session).unwrap(),
                &encode_envelope(&transfer).unwrap(),
                &ingress,
                5,
                100,
            )
            .unwrap();
        assert!(matches!(
            submissions.submit(
                &encode_envelope(&other_session).unwrap(),
                &encode_envelope(&other_transfer).unwrap(),
                &ingress,
                5,
                101,
            ),
            Err(TransferSubmissionError::Rejected(rejection))
                if rejection.code() == TransferRejectionCode::GlobalLimited
        ));
        remove_snapshot(&path);
    }

    #[test]
    fn exact_finality_archive_moves_pending_to_finalized() {
        let path = path("finality");
        remove_snapshot(&path);
        let (ingress, session, transfer) = fixture(12, 0);
        let reference = transfer.request().intent_id().unwrap();
        let action_root =
            commit_parts(b"ACTIVECHAIN-BLOCK-CASH-ACTIONS-V1", &[reference.as_bytes()]);
        let (genesis, finality) = signed_finality(finality_inputs(action_root));
        let mut configured = policy();
        configured.genesis_commitment = genesis;
        let mut submissions = DurableTransferSubmissions::create(configured, path.clone()).unwrap();
        submissions
            .submit(
                &encode_envelope(&session).unwrap(),
                &encode_envelope(&transfer).unwrap(),
                &ingress,
                5,
                100,
            )
            .unwrap();
        let actions = submissions.prepare_pending_batch(&ingress, &[], 7, 110, 32).unwrap();
        assert_eq!(actions.len(), 1);
        let batch = frame_actions(&actions).unwrap();

        let (_, wrong_finality) = signed_finality(finality_inputs(digest(99)));
        assert_eq!(
            submissions.reconcile_finality(&batch, &wrong_finality, 120),
            Err(TransferSubmissionError::InvalidFinality)
        );
        assert_eq!(submissions.reconcile_finality(&batch, &finality, 121), Ok(1));
        let receipt = submissions.resolve(reference).unwrap();
        assert_eq!(receipt.state(), TransferState::Finalized);
        assert_eq!(receipt.transaction_id(), Some(TransactionId::new(reference)));
        assert_eq!(receipt.finalized_height(), Some(7));
        drop(submissions);
        let mut restored = DurableTransferSubmissions::open(configured, path.clone()).unwrap();
        assert_eq!(restored.resolve(reference), Ok(receipt));
        remove_snapshot(&path);
    }

    #[test]
    fn batch_framing_is_bounded_and_strict() {
        let actions = vec![vec![1, 2, 3], vec![4]];
        let framed = frame_actions(&actions).unwrap();
        assert_eq!(parse_framed_actions(&framed), Ok(actions));
        assert!(parse_framed_actions(&framed[..framed.len() - 1]).is_err());
        assert!(frame_actions(&vec![vec![1]; MAX_PENDING_TRANSFERS + 1]).is_err());
    }
}
