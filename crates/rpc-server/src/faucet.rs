use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    encode_envelope,
};
use activechain_protocol_types::{ChainId, Digest384, PrincipalId, TransactionId};
use activechain_rpc_types::{
    FaucetChallengeKind, FaucetReceiptV1, FaucetRequestV1, FaucetState, FaucetTermsV1,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

const MAX_FAUCET_RECORDS: usize = 65_535;
const SNAPSHOT_TAG_LENGTH: usize = 32;
const FAUCET_SNAPSHOT_VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SybilPolicy {
    CooldownOnly,
    ProofOfWork { leading_zero_bits: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaucetPolicy {
    pub chain_id: ChainId,
    pub genesis_commitment: Digest384,
    /// Faucet issuance is deliberately limited to a testnet deployment. A
    /// production/regulated profile must use a separately governed issuer.
    pub testnet_only: bool,
    pub enabled: bool,
    pub policy_revision: u64,
    pub valid_until: u64,
    pub grant_amount: u128,
    pub recipient_cooldown_seconds: u64,
    pub recipient_lifetime_limit: u16,
    pub source_window_seconds: u64,
    pub source_window_limit: u16,
    pub global_window_seconds: u64,
    pub global_window_limit: u32,
    pub sybil_policy: SybilPolicy,
}

impl FaucetPolicy {
    pub fn validate(&self) -> Result<(), FaucetError> {
        let difficulty = match self.sybil_policy {
            SybilPolicy::CooldownOnly => 0,
            SybilPolicy::ProofOfWork { leading_zero_bits } => leading_zero_bits,
        };
        if !self.testnet_only
            || self.genesis_commitment == Digest384::ZERO
            || self.grant_amount == 0
            || self.policy_revision == 0
            || self.valid_until == 0
            || self.recipient_cooldown_seconds == 0
            || self.recipient_lifetime_limit == 0
            || self.source_window_seconds == 0
            || self.source_window_limit == 0
            || self.global_window_seconds == 0
            || self.global_window_limit == 0
            || difficulty > 32
        {
            return Err(FaucetError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaucetError {
    Disabled,
    WrongNetwork,
    InvalidPolicy,
    InvalidChallenge,
    RecipientCooldown,
    RecipientExhausted,
    SourceLimited,
    GlobalLimited,
    NotFound,
    InvalidTransition,
    Persistence,
    Capacity,
    InvalidFinalityEvidence,
    ReconciliationRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Admission {
    Accept,
    RecipientCooldown,
    RecipientExhausted,
    SourceLimited,
    GlobalLimited,
}

#[allow(clippy::too_many_arguments)]
fn admission(
    recipient_count: usize,
    seconds_since_recipient: Option<u64>,
    source_count: usize,
    global_count: usize,
    recipient_lifetime_limit: u16,
    recipient_cooldown_seconds: u64,
    source_window_limit: u16,
    global_window_limit: u32,
) -> Admission {
    if recipient_count >= usize::from(recipient_lifetime_limit) {
        Admission::RecipientExhausted
    } else if seconds_since_recipient.is_some_and(|age| age < recipient_cooldown_seconds) {
        Admission::RecipientCooldown
    } else if source_count >= usize::from(source_window_limit) {
        Admission::SourceLimited
    } else if global_count >= usize::try_from(global_window_limit).unwrap_or(usize::MAX) {
        Admission::GlobalLimited
    } else {
        Admission::Accept
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn accepted_admission_is_below_every_limit() {
        let recipient_count: usize = kani::any();
        let source_count: usize = kani::any();
        let global_count: usize = kani::any();
        let recipient_limit: u16 = kani::any();
        let source_limit: u16 = kani::any();
        let global_limit: u32 = kani::any();
        kani::assume(recipient_limit > 0);
        kani::assume(source_limit > 0);
        kani::assume(global_limit > 0);
        let result = admission(
            recipient_count,
            None,
            source_count,
            global_count,
            recipient_limit,
            1,
            source_limit,
            global_limit,
        );
        if result == Admission::Accept {
            assert!(recipient_count < usize::from(recipient_limit));
            assert!(source_count < usize::from(source_limit));
            assert!(global_count < usize::try_from(global_limit).unwrap_or(usize::MAX));
        }
    }

    #[kani::proof]
    fn cooldown_admission_precedes_source_and_global_capacity() {
        let age: u64 = kani::any();
        let cooldown: u64 = kani::any();
        let recipient_count: usize = kani::any();
        let source_count: usize = kani::any();
        let global_count: usize = kani::any();
        let recipient_limit: u16 = kani::any();
        let source_limit: u16 = kani::any();
        let global_limit: u32 = kani::any();
        kani::assume(cooldown > 0);
        kani::assume(recipient_limit > 0);
        kani::assume(source_limit > 0);
        kani::assume(global_limit > 0);
        if age < cooldown {
            assert_eq!(
                admission(
                    recipient_count,
                    Some(age),
                    source_count,
                    global_count,
                    recipient_limit,
                    cooldown,
                    source_limit,
                    global_limit,
                ),
                Admission::RecipientCooldown
            );
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FaucetRecord {
    idempotency_key: Digest384,
    abuse_identity: Digest384,
    request_commitment: Digest384,
    settlement_commitment: Digest384,
    created_at: u64,
    receipt: FaucetReceiptV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaucetReconciliation {
    idempotency_key: Digest384,
    abuse_identity: Digest384,
    request_commitment: Digest384,
    settlement_commitment: Digest384,
    receipt: FaucetReceiptV1,
}

impl FaucetReconciliation {
    pub const fn idempotency_key(&self) -> Digest384 {
        self.idempotency_key
    }
    pub const fn abuse_identity(&self) -> Digest384 {
        self.abuse_identity
    }
    pub const fn request_commitment(&self) -> Digest384 {
        self.request_commitment
    }
    pub const fn settlement_commitment(&self) -> Digest384 {
        self.settlement_commitment
    }
    pub const fn receipt(&self) -> &FaucetReceiptV1 {
        &self.receipt
    }
}

pub struct DurableFaucet {
    policy: FaucetPolicy,
    path: PathBuf,
    records: Vec<FaucetRecord>,
    persistence_faulted: bool,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestFault {
    Reservation(SaveStage),
    BeforeSettlement,
    AfterSettlement,
    Receipt(SaveStage),
}

#[cfg(test)]
fn reservation_save_fault(fault: Option<RequestFault>) -> Option<SaveStage> {
    fault.and_then(|fault| match fault {
        RequestFault::Reservation(stage) => Some(stage),
        _ => None,
    })
}

#[cfg(not(test))]
fn reservation_save_fault(_fault: Option<()>) -> Option<()> {
    None
}

#[cfg(test)]
fn receipt_save_fault(fault: Option<RequestFault>) -> Option<SaveStage> {
    fault.and_then(|fault| match fault {
        RequestFault::Receipt(stage) => Some(stage),
        _ => None,
    })
}

#[cfg(not(test))]
fn receipt_save_fault(_fault: Option<()>) -> Option<()> {
    None
}

impl DurableFaucet {
    pub fn create(policy: FaucetPolicy, path: PathBuf) -> Result<Self, FaucetError> {
        policy.validate()?;
        if path.exists() {
            return Err(FaucetError::Persistence);
        }
        let service = Self { policy, path, records: Vec::new(), persistence_faulted: false };
        service.save()?;
        Ok(service)
    }

    pub fn open(policy: FaucetPolicy, path: PathBuf) -> Result<Self, FaucetError> {
        policy.validate()?;
        let records = load_records(&path)?;
        if records.iter().any(|record| {
            record.receipt.amount() != policy.grant_amount
                || record.receipt.recipient().into_digest() == Digest384::ZERO
        }) {
            return Err(FaucetError::Persistence);
        }
        Ok(Self { policy, path, records, persistence_faulted: false })
    }

    pub const fn policy(&self) -> FaucetPolicy {
        self.policy
    }

    pub fn terms(&self) -> Result<FaucetTermsV1, FaucetError> {
        let (challenge_kind, challenge_difficulty) = match self.policy.sybil_policy {
            SybilPolicy::CooldownOnly => (FaucetChallengeKind::CooldownOnly, 0),
            SybilPolicy::ProofOfWork { leading_zero_bits } => {
                (FaucetChallengeKind::ProofOfWork, leading_zero_bits)
            }
        };
        FaucetTermsV1::new(
            self.policy.chain_id,
            self.policy.genesis_commitment,
            self.policy.policy_revision,
            self.policy.valid_until,
            self.policy.grant_amount,
            self.policy.recipient_cooldown_seconds,
            self.policy.recipient_lifetime_limit,
            self.policy.source_window_seconds,
            self.policy.source_window_limit,
            self.policy.global_window_seconds,
            self.policy.global_window_limit,
            challenge_kind,
            challenge_difficulty,
        )
        .map_err(|_| FaucetError::InvalidPolicy)
    }

    pub fn request<F>(
        &mut self,
        request: &FaucetRequestV1,
        abuse_identity: Digest384,
        settlement_commitment: Digest384,
        now: u64,
        submit: F,
    ) -> Result<FaucetReceiptV1, FaucetError>
    where
        F: FnOnce(PrincipalId, u128, Digest384) -> Result<TransactionId, FaucetError>,
    {
        self.request_at(request, abuse_identity, settlement_commitment, now, submit, None)
    }

    #[cfg(test)]
    fn request_interrupted<F>(
        &mut self,
        request: &FaucetRequestV1,
        abuse_identity: Digest384,
        settlement_commitment: Digest384,
        now: u64,
        submit: F,
        fault: RequestFault,
    ) -> Result<FaucetReceiptV1, FaucetError>
    where
        F: FnOnce(PrincipalId, u128, Digest384) -> Result<TransactionId, FaucetError>,
    {
        self.request_at(request, abuse_identity, settlement_commitment, now, submit, Some(fault))
    }

    fn request_at<F>(
        &mut self,
        request: &FaucetRequestV1,
        abuse_identity: Digest384,
        settlement_commitment: Digest384,
        now: u64,
        submit: F,
        #[cfg(test)] fault: Option<RequestFault>,
        #[cfg(not(test))] fault: Option<()>,
    ) -> Result<FaucetReceiptV1, FaucetError>
    where
        F: FnOnce(PrincipalId, u128, Digest384) -> Result<TransactionId, FaucetError>,
    {
        if request.chain_id() != self.policy.chain_id
            || request.genesis_commitment() != self.policy.genesis_commitment
        {
            return Err(FaucetError::WrongNetwork);
        }
        if self.persistence_faulted {
            return Err(FaucetError::Persistence);
        }
        if abuse_identity == Digest384::ZERO || settlement_commitment == Digest384::ZERO {
            return Err(FaucetError::InvalidChallenge);
        }
        let request_commitment = faucet_request_commitment(request)?;
        if let Some(existing) =
            self.records.iter().find(|record| record.idempotency_key == request.idempotency_key())
        {
            if existing.receipt.recipient() == request.recipient()
                && existing.abuse_identity == abuse_identity
                && existing.request_commitment == request_commitment
                && existing.settlement_commitment == settlement_commitment
            {
                if existing.receipt.transaction_id().is_some()
                    || existing.receipt.state() != FaucetState::Pending
                {
                    return Ok(existing.receipt.clone());
                }
                return self.resume_pending(request.idempotency_key(), submit, fault);
            }
            return Err(FaucetError::InvalidChallenge);
        }
        if !self.policy.enabled || now > self.policy.valid_until {
            return Err(FaucetError::Disabled);
        }
        self.verify_challenge(request, abuse_identity)?;

        let recipient_records: Vec<_> = self
            .records
            .iter()
            .filter(|record| record.receipt.recipient() == request.recipient())
            .collect();
        let seconds_since_recipient =
            recipient_records.iter().map(|record| now.saturating_sub(record.created_at)).min();
        let source_count = self
            .records
            .iter()
            .filter(|record| {
                record.abuse_identity == abuse_identity
                    && now.saturating_sub(record.created_at) < self.policy.source_window_seconds
            })
            .count();
        let global_count = self
            .records
            .iter()
            .filter(|record| {
                now.saturating_sub(record.created_at) < self.policy.global_window_seconds
            })
            .count();
        match admission(
            recipient_records.len(),
            seconds_since_recipient,
            source_count,
            global_count,
            self.policy.recipient_lifetime_limit,
            self.policy.recipient_cooldown_seconds,
            self.policy.source_window_limit,
            self.policy.global_window_limit,
        ) {
            Admission::Accept => {}
            Admission::RecipientCooldown => return Err(FaucetError::RecipientCooldown),
            Admission::RecipientExhausted => return Err(FaucetError::RecipientExhausted),
            Admission::SourceLimited => return Err(FaucetError::SourceLimited),
            Admission::GlobalLimited => return Err(FaucetError::GlobalLimited),
        }
        if self.records.len() >= MAX_FAUCET_RECORDS {
            return Err(FaucetError::Capacity);
        }

        let reference =
            request.settlement_reference().map_err(|_| FaucetError::InvalidTransition)?;
        let reservation = FaucetReceiptV1::new(
            reference,
            request.recipient(),
            self.policy.grant_amount,
            FaucetState::Pending,
            None,
            None,
            None,
            Vec::new(),
        )
        .map_err(|_| FaucetError::InvalidTransition)?;
        let mut next = self.records.clone();
        next.push(FaucetRecord {
            idempotency_key: request.idempotency_key(),
            abuse_identity,
            request_commitment,
            settlement_commitment,
            created_at: now,
            receipt: reservation,
        });
        self.publish_at(next, reservation_save_fault(fault))?;
        self.resume_pending(request.idempotency_key(), submit, fault)
    }

    fn resume_pending<F>(
        &mut self,
        idempotency_key: Digest384,
        submit: F,
        #[cfg(test)] fault: Option<RequestFault>,
        #[cfg(not(test))] fault: Option<()>,
    ) -> Result<FaucetReceiptV1, FaucetError>
    where
        F: FnOnce(PrincipalId, u128, Digest384) -> Result<TransactionId, FaucetError>,
    {
        let index = self
            .records
            .iter()
            .position(|record| record.idempotency_key == idempotency_key)
            .ok_or(FaucetError::NotFound)?;
        let current = &self.records[index].receipt;
        if current.transaction_id().is_some() || current.state() != FaucetState::Pending {
            return Ok(current.clone());
        }
        #[cfg(test)]
        if fault == Some(RequestFault::BeforeSettlement) {
            return Err(FaucetError::Persistence);
        }
        let transaction = submit(current.recipient(), current.amount(), current.reference())?;
        #[cfg(test)]
        if fault == Some(RequestFault::AfterSettlement) {
            return Err(FaucetError::ReconciliationRequired);
        }
        let pending = FaucetReceiptV1::new(
            current.reference(),
            current.recipient(),
            current.amount(),
            FaucetState::Pending,
            Some(transaction),
            None,
            None,
            Vec::new(),
        )
        .map_err(|_| FaucetError::InvalidTransition)?;
        let mut next = self.records.clone();
        next[index].receipt = pending.clone();
        self.publish_at(next, receipt_save_fault(fault))
            .map_err(|_| FaucetError::ReconciliationRequired)?;
        Ok(pending)
    }

    /// Returns every durable reservation whose settlement outcome still needs reconciliation.
    pub fn pending_reconciliation(&self) -> Vec<FaucetReconciliation> {
        self.records
            .iter()
            .filter(|record| {
                record.receipt.state() == FaucetState::Pending
                    && record.receipt.transaction_id().is_none()
            })
            .map(|record| FaucetReconciliation {
                idempotency_key: record.idempotency_key,
                abuse_identity: record.abuse_identity,
                request_commitment: record.request_commitment,
                settlement_commitment: record.settlement_commitment,
                receipt: record.receipt.clone(),
            })
            .collect()
    }

    /// Reconciles an existing reservation using the same immutable request, abuse identity, and
    /// settlement transcript. It never creates a new grant and remains available after issuance is
    /// disabled so operators can close uncertain outcomes safely.
    pub fn reconcile_pending<F>(
        &mut self,
        request: &FaucetRequestV1,
        abuse_identity: Digest384,
        settlement_commitment: Digest384,
        submit: F,
    ) -> Result<FaucetReceiptV1, FaucetError>
    where
        F: FnOnce(PrincipalId, u128, Digest384) -> Result<TransactionId, FaucetError>,
    {
        if !self.records.iter().any(|record| {
            record.idempotency_key == request.idempotency_key()
                && record.receipt.state() == FaucetState::Pending
                && record.receipt.transaction_id().is_none()
        }) {
            return Err(FaucetError::NotFound);
        }
        self.request(
            request,
            abuse_identity,
            settlement_commitment,
            self.policy.valid_until,
            submit,
        )
    }

    /// Marks a reservation rejected only after an operator has established that settlement did
    /// not occur. The record remains durable audit and rate-limit evidence.
    pub fn reject_pending(&mut self, reference: Digest384) -> Result<FaucetReceiptV1, FaucetError> {
        let index = self
            .records
            .iter()
            .position(|record| record.receipt.reference() == reference)
            .ok_or(FaucetError::NotFound)?;
        let current = &self.records[index].receipt;
        if current.state() != FaucetState::Pending || current.transaction_id().is_some() {
            return Err(FaucetError::InvalidTransition);
        }
        let rejected = FaucetReceiptV1::new(
            reference,
            current.recipient(),
            current.amount(),
            FaucetState::Rejected,
            None,
            None,
            None,
            Vec::new(),
        )
        .map_err(|_| FaucetError::InvalidTransition)?;
        let mut next = self.records.clone();
        next[index].receipt = rejected.clone();
        self.publish(next)?;
        Ok(rejected)
    }

    pub fn resolve(&self, reference: Digest384) -> Option<&FaucetReceiptV1> {
        self.records
            .iter()
            .find(|record| record.receipt.reference() == reference)
            .map(|record| &record.receipt)
    }

    pub fn finalize(
        &mut self,
        reference: Digest384,
        height: u64,
        block: Digest384,
        proof: Vec<u8>,
    ) -> Result<FaucetReceiptV1, FaucetError> {
        let index = self
            .records
            .iter()
            .position(|record| record.receipt.reference() == reference)
            .ok_or(FaucetError::NotFound)?;
        let current = &self.records[index].receipt;
        let transaction = current.transaction_id().ok_or(FaucetError::InvalidTransition)?;
        let finalized = FaucetReceiptV1::new(
            reference,
            current.recipient(),
            current.amount(),
            FaucetState::Finalized,
            Some(transaction),
            Some(height),
            Some(block),
            proof,
        )
        .map_err(|_| FaucetError::InvalidTransition)?;
        let mut next = self.records.clone();
        next[index].receipt = finalized.clone();
        self.publish(next)?;
        Ok(finalized)
    }

    /// Finalizes a grant only when the supplied evidence is a valid certificate
    /// for the configured chain and exact block identity.  The legacy
    /// `finalize` method remains available for local fixtures; production RPC
    /// adapters should use this fail-closed boundary.
    pub fn finalize_verified(
        &mut self,
        reference: Digest384,
        height: u64,
        block: Digest384,
        proof: Vec<u8>,
    ) -> Result<FaucetReceiptV1, FaucetError> {
        let bundle = activechain_verifier_api::verify_finality_bundle_with_chain_genesis(
            &proof,
            self.policy.genesis_commitment,
        )
        .map_err(|_| FaucetError::InvalidFinalityEvidence)?;
        if bundle.header().inputs.height != height
            || bundle.header().digest().map_err(|_| FaucetError::InvalidFinalityEvidence)? != block
        {
            return Err(FaucetError::InvalidFinalityEvidence);
        }
        self.finalize(reference, height, block, proof)
    }

    fn verify_challenge(
        &self,
        request: &FaucetRequestV1,
        source_commitment: Digest384,
    ) -> Result<(), FaucetError> {
        let SybilPolicy::ProofOfWork { leading_zero_bits } = self.policy.sybil_policy else {
            return Ok(());
        };
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-TESTNET-FAUCET-POW-V1");
        hasher.update(self.policy.genesis_commitment.as_bytes());
        hasher.update(request.recipient().into_digest().as_bytes());
        hasher.update(request.idempotency_key().as_bytes());
        hasher.update(source_commitment.as_bytes());
        hasher.update(&request.challenge_nonce().to_be_bytes());
        hasher.update(request.challenge_evidence());
        let mut output = [0_u8; 32];
        XofReader::read(&mut hasher.finalize_xof(), &mut output);
        if leading_zero_count(&output) < u32::from(leading_zero_bits) {
            return Err(FaucetError::InvalidChallenge);
        }
        Ok(())
    }

    fn save(&self) -> Result<(), FaucetError> {
        save_records(&self.path, &self.records)
    }

    fn publish(&mut self, next: Vec<FaucetRecord>) -> Result<(), FaucetError> {
        self.publish_at(next, None)
    }

    fn publish_at(
        &mut self,
        next: Vec<FaucetRecord>,
        #[cfg(test)] interrupt_after: Option<SaveStage>,
        #[cfg(not(test))] interrupt_after: Option<()>,
    ) -> Result<(), FaucetError> {
        if self.persistence_faulted {
            return Err(FaucetError::Persistence);
        }
        match save_records_classified_at(&self.path, &next, interrupt_after) {
            Ok(()) => {
                self.records = next;
                Ok(())
            }
            Err(SaveError::BeforePublish) => Err(FaucetError::Persistence),
            Err(SaveError::PublicationUncertain) => {
                self.persistence_faulted = true;
                Err(FaucetError::Persistence)
            }
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn accepted_admission_is_strictly_within_every_limit() {
        let recipient_count: usize = kani::any();
        let recipient_age: Option<u64> = kani::any();
        let source_count: usize = kani::any();
        let global_count: usize = kani::any();
        let recipient_limit: u16 = kani::any();
        let cooldown: u64 = kani::any();
        let source_limit: u16 = kani::any();
        let global_limit: u32 = kani::any();
        kani::assume(recipient_limit > 0);
        kani::assume(cooldown > 0);
        kani::assume(source_limit > 0);
        kani::assume(global_limit > 0);

        if admission(
            recipient_count,
            recipient_age,
            source_count,
            global_count,
            recipient_limit,
            cooldown,
            source_limit,
            global_limit,
        ) == Admission::Accept
        {
            assert!(recipient_count < usize::from(recipient_limit));
            assert!(recipient_age.is_none_or(|age| age >= cooldown));
            assert!(source_count < usize::from(source_limit));
            assert!(global_count < usize::try_from(global_limit).unwrap_or(usize::MAX));
        }
    }

    #[kani::proof]
    fn increasing_usage_cannot_turn_a_rejection_into_acceptance() {
        let recipient_count: u16 = kani::any();
        let source_count: u16 = kani::any();
        let global_count: u32 = kani::any();
        let recipient_limit: u16 = kani::any();
        let source_limit: u16 = kani::any();
        let global_limit: u32 = kani::any();
        kani::assume(recipient_count < u16::MAX);
        kani::assume(source_count < u16::MAX);
        kani::assume(global_count < u32::MAX);

        let before = admission(
            usize::from(recipient_count),
            None,
            usize::from(source_count),
            usize::try_from(global_count).unwrap_or(usize::MAX),
            recipient_limit,
            1,
            source_limit,
            global_limit,
        );
        let after = admission(
            usize::from(recipient_count + 1),
            None,
            usize::from(source_count + 1),
            usize::try_from(global_count + 1).unwrap_or(usize::MAX),
            recipient_limit,
            1,
            source_limit,
            global_limit,
        );
        if before != Admission::Accept {
            assert!(after != Admission::Accept);
        }
    }
}

fn faucet_request_commitment(request: &FaucetRequestV1) -> Result<Digest384, FaucetError> {
    let bytes = encode_envelope(request).map_err(|_| FaucetError::InvalidChallenge)?;
    Ok(domain_commitment(b"ACTIVECHAIN-FAUCET-REQUEST-V1", &bytes))
}

pub fn faucet_settlement_commitment(bytes: &[u8]) -> Digest384 {
    domain_commitment(b"ACTIVECHAIN-FAUCET-SETTLEMENT-V1", bytes)
}

pub fn faucet_abuse_identity(identity: &[u8]) -> Digest384 {
    domain_commitment(b"ACTIVECHAIN-FAUCET-ABUSE-IDENTITY-V1", identity)
}

fn domain_commitment(domain: &[u8], bytes: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    let mut output = [0; 48];
    XofReader::read(&mut hasher.finalize_xof(), &mut output);
    Digest384::new(output)
}

fn leading_zero_count(bytes: &[u8]) -> u32 {
    let mut count = 0;
    for byte in bytes {
        let zeros = byte.leading_zeros();
        count += zeros;
        if zeros != 8 {
            break;
        }
    }
    count
}

impl CanonicalEncode for FaucetRecord {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.idempotency_key.encode(encoder)?;
        self.abuse_identity.encode(encoder)?;
        self.request_commitment.encode(encoder)?;
        self.settlement_commitment.encode(encoder)?;
        self.created_at.encode(encoder)?;
        self.receipt.encode(encoder)
    }
}
impl CanonicalDecode for FaucetRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            idempotency_key: Digest384::decode(decoder)?,
            abuse_identity: Digest384::decode(decoder)?,
            request_commitment: Digest384::decode(decoder)?,
            settlement_commitment: Digest384::decode(decoder)?,
            created_at: u64::decode(decoder)?,
            receipt: FaucetReceiptV1::decode(decoder)?,
        })
    }
}

fn save_records(path: &Path, records: &[FaucetRecord]) -> Result<(), FaucetError> {
    save_records_classified(path, records).map_err(|_| FaucetError::Persistence)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SaveError {
    BeforePublish,
    PublicationUncertain,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SaveStage {
    TemporaryCreated,
    BodyWritten,
    TemporarySynced,
    Renamed,
    DirectorySynced,
}

#[cfg(test)]
fn interrupt_save(
    requested: Option<SaveStage>,
    current: SaveStage,
    published: bool,
) -> Result<(), SaveError> {
    if requested == Some(current) {
        Err(if published { SaveError::PublicationUncertain } else { SaveError::BeforePublish })
    } else {
        Ok(())
    }
}

fn save_records_classified(path: &Path, records: &[FaucetRecord]) -> Result<(), SaveError> {
    save_records_classified_at(path, records, None)
}

fn save_records_classified_at(
    path: &Path,
    records: &[FaucetRecord],
    #[cfg(test)] interrupt_after: Option<SaveStage>,
    #[cfg(not(test))] _interrupt_after: Option<()>,
) -> Result<(), SaveError> {
    let mut encoder = Encoder::new(6 + records.len() * (200 + FaucetReceiptV1::MAX_ENCODED_LEN));
    FAUCET_SNAPSHOT_VERSION.encode(&mut encoder).map_err(|_| SaveError::BeforePublish)?;
    encoder
        .write_length(records.len(), MAX_FAUCET_RECORDS)
        .map_err(|_| SaveError::BeforePublish)?;
    for record in records {
        record.encode(&mut encoder).map_err(|_| SaveError::BeforePublish)?;
    }
    let bytes = encoder.finish();
    let tag = snapshot_tag_v2(&bytes);
    let temporary = path.with_extension("tmp");
    let mut file = File::create(&temporary).map_err(|_| SaveError::BeforePublish)?;
    #[cfg(test)]
    interrupt_save(interrupt_after, SaveStage::TemporaryCreated, false)?;
    file.write_all(&bytes).map_err(|_| SaveError::BeforePublish)?;
    file.write_all(&tag).map_err(|_| SaveError::BeforePublish)?;
    #[cfg(test)]
    interrupt_save(interrupt_after, SaveStage::BodyWritten, false)?;
    file.sync_all().map_err(|_| SaveError::BeforePublish)?;
    #[cfg(test)]
    interrupt_save(interrupt_after, SaveStage::TemporarySynced, false)?;
    std::fs::rename(&temporary, path).map_err(|_| SaveError::BeforePublish)?;
    #[cfg(test)]
    interrupt_save(interrupt_after, SaveStage::Renamed, true)?;
    let parent =
        path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| SaveError::PublicationUncertain)?;
    #[cfg(test)]
    interrupt_save(interrupt_after, SaveStage::DirectorySynced, true)?;
    Ok(())
}

fn load_records(path: &Path) -> Result<Vec<FaucetRecord>, FaucetError> {
    let bytes = std::fs::read(path).map_err(|_| FaucetError::Persistence)?;
    if bytes.len() < SNAPSHOT_TAG_LENGTH {
        return Err(FaucetError::Persistence);
    }
    let body_len = bytes.len() - SNAPSHOT_TAG_LENGTH;
    let body = &bytes[..body_len];
    if snapshot_tag_v2(body) == bytes[body_len..] {
        return decode_records_v2(body);
    }
    if snapshot_tag_v1(body) == bytes[body_len..] {
        return decode_records_v1(body);
    }
    Err(FaucetError::Persistence)
}

fn decode_records_v2(bytes: &[u8]) -> Result<Vec<FaucetRecord>, FaucetError> {
    let mut decoder = Decoder::new(bytes);
    if u16::decode(&mut decoder).map_err(|_| FaucetError::Persistence)? != FAUCET_SNAPSHOT_VERSION {
        return Err(FaucetError::Persistence);
    }
    let count = decoder.read_length(MAX_FAUCET_RECORDS).map_err(|_| FaucetError::Persistence)?;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(FaucetRecord::decode(&mut decoder).map_err(|_| FaucetError::Persistence)?);
    }
    decoder.finish().map_err(|_| FaucetError::Persistence)?;
    validate_records(records)
}

fn decode_records_v1(bytes: &[u8]) -> Result<Vec<FaucetRecord>, FaucetError> {
    let mut decoder = Decoder::new(bytes);
    let count = decoder.read_length(MAX_FAUCET_RECORDS).map_err(|_| FaucetError::Persistence)?;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let idempotency_key =
            Digest384::decode(&mut decoder).map_err(|_| FaucetError::Persistence)?;
        let abuse_identity =
            Digest384::decode(&mut decoder).map_err(|_| FaucetError::Persistence)?;
        let created_at = u64::decode(&mut decoder).map_err(|_| FaucetError::Persistence)?;
        let receipt =
            FaucetReceiptV1::decode(&mut decoder).map_err(|_| FaucetError::Persistence)?;
        // V1 records were written only after settlement returned a transaction id. They remain
        // resolvable and count toward limits, but their missing transcript cannot authorize a new
        // settlement attempt under V2.
        if receipt.transaction_id().is_none() {
            return Err(FaucetError::Persistence);
        }
        records.push(FaucetRecord {
            idempotency_key,
            abuse_identity,
            request_commitment: Digest384::ZERO,
            settlement_commitment: Digest384::ZERO,
            created_at,
            receipt,
        });
    }
    decoder.finish().map_err(|_| FaucetError::Persistence)?;
    validate_records(records)
}

fn validate_records(mut records: Vec<FaucetRecord>) -> Result<Vec<FaucetRecord>, FaucetError> {
    if records.iter().any(|record| {
        record.idempotency_key == Digest384::ZERO
            || record.abuse_identity == Digest384::ZERO
            || ((record.request_commitment == Digest384::ZERO)
                != (record.settlement_commitment == Digest384::ZERO))
            || (record.request_commitment == Digest384::ZERO
                && record.receipt.transaction_id().is_none())
    }) {
        return Err(FaucetError::Persistence);
    }
    records.sort_by_key(|record| record.idempotency_key);
    if records.windows(2).any(|pair| pair[0].idempotency_key == pair[1].idempotency_key) {
        return Err(FaucetError::Persistence);
    }
    Ok(records)
}

fn snapshot_tag_v1(bytes: &[u8]) -> [u8; SNAPSHOT_TAG_LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-FAUCET-SNAPSHOT-V1");
    hasher.update(bytes);
    let mut output = [0; SNAPSHOT_TAG_LENGTH];
    XofReader::read(&mut hasher.finalize_xof(), &mut output);
    output
}

fn snapshot_tag_v2(bytes: &[u8]) -> [u8; SNAPSHOT_TAG_LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-FAUCET-SNAPSHOT-V2");
    hasher.update(bytes);
    let mut output = [0; SNAPSHOT_TAG_LENGTH];
    XofReader::read(&mut hasher.finalize_xof(), &mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }
    fn policy() -> FaucetPolicy {
        FaucetPolicy {
            chain_id: ChainId::new(digest(1)),
            genesis_commitment: digest(2),
            testnet_only: true,
            enabled: true,
            policy_revision: 1,
            valid_until: 10_000,
            grant_amount: 1_000,
            recipient_cooldown_seconds: 60,
            recipient_lifetime_limit: 2,
            source_window_seconds: 60,
            source_window_limit: 2,
            global_window_seconds: 60,
            global_window_limit: 3,
            sybil_policy: SybilPolicy::CooldownOnly,
        }
    }

    #[test]
    fn production_profile_is_rejected_before_faucet_creation() {
        let mut policy = policy();
        policy.testnet_only = false;
        assert!(matches!(
            DurableFaucet::create(policy, PathBuf::from("/definitely/not-created")),
            Err(FaucetError::InvalidPolicy)
        ));
    }
    fn request(recipient: u8, key: u8) -> FaucetRequestV1 {
        FaucetRequestV1::new(
            ChainId::new(digest(1)),
            digest(2),
            principal(recipient),
            digest(key),
            digest(3),
            0,
            Vec::new(),
        )
        .unwrap()
    }
    fn path(name: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("activechain-faucet-{name}-{nonce}.snapshot"))
    }

    #[test]
    fn idempotency_and_limits_survive_restart() {
        let path = path("limits");
        let mut faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
        assert_eq!(faucet.terms().unwrap().grant_amount(), 1_000);
        assert_eq!(faucet.terms().unwrap().policy_revision(), 1);
        let receipt = faucet
            .request(&request(3, 4), digest(9), digest(30), 100, |_, _, _| {
                Ok(TransactionId::new(digest(10)))
            })
            .unwrap();
        assert_eq!(
            faucet.request(&request(3, 4), digest(9), digest(30), 101, |_, _, _| panic!()),
            Ok(receipt.clone())
        );
        assert_eq!(
            faucet.request(&request(3, 5), digest(9), digest(31), 101, |_, _, _| panic!()),
            Err(FaucetError::RecipientCooldown)
        );
        drop(faucet);
        let faucet = DurableFaucet::open(policy(), path.clone()).unwrap();
        assert_eq!(faucet.resolve(receipt.reference()), Some(&receipt));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn wrong_network_and_source_reuse_are_rejected() {
        let path = path("network");
        let mut faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
        let wrong = FaucetRequestV1::new(
            ChainId::new(digest(8)),
            digest(2),
            principal(3),
            digest(4),
            digest(5),
            0,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            faucet.request(&wrong, digest(9), digest(30), 100, |_, _, _| panic!()),
            Err(FaucetError::WrongNetwork)
        );
        faucet
            .request(&request(3, 4), digest(9), digest(30), 100, |_, _, _| {
                Ok(TransactionId::new(digest(10)))
            })
            .unwrap();
        assert_eq!(
            faucet.request(&request(4, 4), digest(9), digest(30), 200, |_, _, _| panic!()),
            Err(FaucetError::InvalidChallenge)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn finalized_receipt_carries_chain_evidence() {
        let path = path("finalize");
        let mut faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
        let pending = faucet
            .request(&request(3, 4), digest(9), digest(30), 100, |_, _, _| {
                Ok(TransactionId::new(digest(10)))
            })
            .unwrap();
        let finalized =
            faucet.finalize(pending.reference(), 12, digest(11), vec![1, 2, 3]).unwrap();
        assert_eq!(finalized.state(), FaucetState::Finalized);
        assert_eq!(finalized.finalized_height(), Some(12));
        drop(faucet);
        assert_eq!(
            DurableFaucet::open(policy(), path.clone()).unwrap().resolve(pending.reference()),
            Some(&finalized)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn verified_finalization_rejects_untrusted_or_malformed_evidence() {
        let path = path("verified-finalize");
        let mut faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
        let pending = faucet
            .request(&request(3, 4), digest(9), digest(30), 100, |_, _, _| {
                Ok(TransactionId::new(digest(10)))
            })
            .unwrap();
        assert_eq!(
            faucet.finalize_verified(pending.reference(), 12, digest(11), vec![1, 2, 3]),
            Err(FaucetError::InvalidFinalityEvidence)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn corrupted_snapshot_is_rejected() {
        let path = path("corrupt");
        let faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
        drop(faucet);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            DurableFaucet::open(policy(), path.clone()),
            Err(FaucetError::Persistence)
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn legacy_settled_records_migrate_without_authorizing_transcript_free_retries() {
        let path = path("legacy-v1");
        let request = request(3, 4);
        let reference = request.settlement_reference().unwrap();
        let receipt = FaucetReceiptV1::new(
            reference,
            request.recipient(),
            1_000,
            FaucetState::Pending,
            Some(TransactionId::new(digest(10))),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let mut encoder = Encoder::new(512);
        encoder.write_length(1, MAX_FAUCET_RECORDS).unwrap();
        request.idempotency_key().encode(&mut encoder).unwrap();
        digest(9).encode(&mut encoder).unwrap();
        100_u64.encode(&mut encoder).unwrap();
        receipt.encode(&mut encoder).unwrap();
        let body = encoder.finish();
        let mut snapshot = body.clone();
        snapshot.extend_from_slice(&snapshot_tag_v1(&body));
        std::fs::write(&path, snapshot).unwrap();

        let mut restored = DurableFaucet::open(policy(), path.clone()).unwrap();
        assert_eq!(restored.resolve(reference), Some(&receipt));
        assert_eq!(
            restored.request(&request, digest(9), digest(30), 101, |_, _, _| panic!()),
            Err(FaucetError::InvalidChallenge)
        );
        let finalized = restored.finalize(reference, 12, digest(11), vec![1]).unwrap();
        drop(restored);
        assert_eq!(
            DurableFaucet::open(policy(), path.clone()).unwrap().resolve(reference),
            Some(&finalized)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_settlement_is_atomic_and_limits_are_monotonic() {
        let path = path("invariants");
        let mut faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
        let target = request(3, 40);
        assert_eq!(
            faucet.request(&target, digest(40), digest(50), 100, |_, _, _| {
                Err(FaucetError::Persistence)
            }),
            Err(FaucetError::Persistence)
        );
        // A failed or uncertain validator submission retains its durable reservation and retries
        // the exact same settlement reference.
        assert!(
            faucet
                .request(&target, digest(40), digest(50), 100, |_, _, _| {
                    Ok(TransactionId::new(digest(41)))
                })
                .is_ok()
        );

        assert!(
            faucet
                .request(&request(4, 41), digest(40), digest(51), 120, |_, _, _| {
                    Ok(TransactionId::new(digest(42)))
                })
                .is_ok()
        );
        assert_eq!(
            faucet.request(&request(5, 42), digest(40), digest(52), 120, |_, _, _| Ok(
                TransactionId::new(digest(43))
            )),
            Err(FaucetError::SourceLimited)
        );
        // Different sources can still use the global budget until it is exhausted.
        assert!(
            faucet
                .request(&request(6, 43), digest(42), digest(53), 120, |_, _, _| {
                    Ok(TransactionId::new(digest(43)))
                })
                .is_ok()
        );
        assert_eq!(
            faucet.request(&request(7, 44), digest(43), digest(54), 120, |_, _, _| Ok(
                TransactionId::new(digest(45))
            )),
            Err(FaucetError::GlobalLimited)
        );
        drop(faucet);
        let reopened = DurableFaucet::open(policy(), path.clone()).unwrap();
        assert_eq!(reopened.records.len(), 3);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn every_reservation_write_fault_prevents_settlement_and_recovers_fail_closed() {
        for stage in [
            SaveStage::TemporaryCreated,
            SaveStage::BodyWritten,
            SaveStage::TemporarySynced,
            SaveStage::Renamed,
            SaveStage::DirectorySynced,
        ] {
            let path = path(&format!("reservation-{stage:?}"));
            let mut faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
            let calls = AtomicUsize::new(0);
            assert_eq!(
                faucet.request_interrupted(
                    &request(3, 4),
                    digest(9),
                    digest(30),
                    100,
                    |_, _, _| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(TransactionId::new(digest(10)))
                    },
                    RequestFault::Reservation(stage),
                ),
                Err(FaucetError::Persistence)
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            let restored = DurableFaucet::open(policy(), path.clone()).unwrap();
            let expected =
                usize::from(matches!(stage, SaveStage::Renamed | SaveStage::DirectorySynced));
            assert_eq!(restored.pending_reconciliation().len(), expected);
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn settlement_and_receipt_faults_retry_one_reference_without_double_effect() {
        for fault in [
            RequestFault::BeforeSettlement,
            RequestFault::AfterSettlement,
            RequestFault::Receipt(SaveStage::TemporaryCreated),
            RequestFault::Receipt(SaveStage::BodyWritten),
            RequestFault::Receipt(SaveStage::TemporarySynced),
            RequestFault::Receipt(SaveStage::Renamed),
            RequestFault::Receipt(SaveStage::DirectorySynced),
        ] {
            let path = path(&format!("settlement-{fault:?}"));
            let mut faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
            let effects = Arc::new(Mutex::new(Vec::new()));
            let first_effects = Arc::clone(&effects);
            assert!(
                faucet
                    .request_interrupted(
                        &request(3, 4),
                        digest(9),
                        digest(30),
                        100,
                        move |_, _, reference| {
                            let mut effects = first_effects.lock().unwrap();
                            if !effects.contains(&reference) {
                                effects.push(reference);
                            }
                            Ok(TransactionId::new(digest(10)))
                        },
                        fault,
                    )
                    .is_err()
            );
            drop(faucet);

            let mut restored = DurableFaucet::open(policy(), path.clone()).unwrap();
            let retry_effects = Arc::clone(&effects);
            let receipt = restored
                .request(&request(3, 4), digest(9), digest(30), 101, move |_, _, reference| {
                    let mut effects = retry_effects.lock().unwrap();
                    if !effects.contains(&reference) {
                        effects.push(reference);
                    }
                    Ok(TransactionId::new(digest(10)))
                })
                .unwrap();
            assert_eq!(receipt.transaction_id(), Some(TransactionId::new(digest(10))));
            assert_eq!(effects.lock().unwrap().len(), 1);
            assert!(restored.pending_reconciliation().is_empty());
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn concurrent_duplicate_requests_publish_one_settlement() {
        let path = path("concurrent");
        let faucet = Arc::new(Mutex::new(DurableFaucet::create(policy(), path.clone()).unwrap()));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let faucet = Arc::clone(&faucet);
            let calls = Arc::clone(&calls);
            threads.push(std::thread::spawn(move || {
                faucet
                    .lock()
                    .unwrap()
                    .request(&request(3, 4), digest(9), digest(30), 100, |_, _, _| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(TransactionId::new(digest(10)))
                    })
                    .unwrap()
            }));
        }
        let first = threads.remove(0).join().unwrap();
        let second = threads.remove(0).join().unwrap();
        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn operator_reconciliation_remains_available_after_new_grants_are_disabled() {
        let path = path("disabled-reconciliation");
        let mut faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
        let request = request(3, 4);
        assert_eq!(
            faucet.request(&request, digest(9), digest(30), 100, |_, _, _| {
                Err(FaucetError::Persistence)
            }),
            Err(FaucetError::Persistence)
        );
        drop(faucet);
        let mut disabled = policy();
        disabled.enabled = false;
        let mut restored = DurableFaucet::open(disabled, path.clone()).unwrap();
        let pending = &restored.pending_reconciliation()[0];
        assert_eq!(pending.idempotency_key(), request.idempotency_key());
        assert_eq!(pending.abuse_identity(), digest(9));
        assert_ne!(pending.request_commitment(), Digest384::ZERO);
        assert_eq!(pending.settlement_commitment(), digest(30));
        let receipt = restored
            .reconcile_pending(&request, digest(9), digest(30), |_, _, _| {
                Ok(TransactionId::new(digest(10)))
            })
            .unwrap();
        assert_eq!(receipt.transaction_id(), Some(TransactionId::new(digest(10))));
        assert!(restored.pending_reconciliation().is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn operator_rejection_retains_durable_audit_record() {
        let path = path("operator-rejection");
        let mut faucet = DurableFaucet::create(policy(), path.clone()).unwrap();
        let request = request(3, 4);
        assert!(
            faucet
                .request(&request, digest(9), digest(30), 100, |_, _, _| {
                    Err(FaucetError::InvalidTransition)
                })
                .is_err()
        );
        let reference = faucet.pending_reconciliation()[0].receipt().reference();
        let rejected = faucet.reject_pending(reference).unwrap();
        assert_eq!(rejected.state(), FaucetState::Rejected);
        drop(faucet);
        let restored = DurableFaucet::open(policy(), path.clone()).unwrap();
        assert_eq!(restored.resolve(reference), Some(&rejected));
        assert!(restored.pending_reconciliation().is_empty());
        std::fs::remove_file(path).unwrap();
    }
}
