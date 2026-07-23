#![forbid(unsafe_code)]

//! Protocol-owned wallet primitives intended to sit underneath OpenWallet adapters.
//! This crate never stores plaintext secret keys and never signs an unconstrained request.

extern crate alloc;

mod cash_authorization;
mod cash_persistence;
mod openwallet;

pub use cash_authorization::{
    AuthorizedCashSessionGrantV1, AuthorizedCashTransferV1, CashAuthorizationRequestV1,
    CashSessionAdmissionWitnessV1, CashSessionGrantV1, recipient_commitment,
};
pub use cash_persistence::{
    FinalizedIdentityKeyProof, FinalizedIdentityKeyVerifier, authenticator_set_root,
};
pub use openwallet::{
    CredentialFormat, IssuanceSessionState, OpenWalletAdapterV1, OpenWalletConsentV1,
    OpenWalletCredentialOfferV1, OpenWalletCredentialRefV1, OpenWalletPresentationRequestV1,
    OpenWalletSessionV1, PresentationResponseMode, RequestedCredentialV1,
};

use activechain_canonical_codec::decode_envelope;
use activechain_cash_kernel::{CashLedger, CashTransitionError, GenesisEconomy};
use activechain_cash_kernel::{CoinCellRecord, CoinTransfer, FeeQuote};
use activechain_protocol_commitment::cash_transition_id;
use activechain_protocol_types::{
    AuthenticatorId, ChainId, CoinCellId, Digest384, ML_DSA44_PUBLIC_KEY_LENGTH, PrincipalId,
    TransactionId,
};
use alloc::vec::Vec;
use std::io::{Read, Write};
use std::net::TcpListener;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpendPolicy {
    pub daily_limit: u128,
    pub max_single_payment: u128,
    pub recipient_commitment: Option<Digest384>,
}

impl SpendPolicy {
    pub fn allows(&self, amount: u128, recipient: Digest384, spent_today: u128) -> bool {
        amount <= self.max_single_payment
            && spent_today.saturating_add(amount) <= self.daily_limit
            && self.recipient_commitment.is_none_or(|allowed| allowed == recipient)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletIntent {
    pub intent_id: Digest384,
    pub sender: PrincipalId,
    pub recipient: PrincipalId,
    pub recipient_commitment: Digest384,
    pub amount: u128,
    pub fee: FeeQuote,
    pub input: CoinCellId,
    pub fee_reserve: CoinCellId,
    pub valid_until: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaymentSession {
    pub session_id: Digest384,
    pub intent_id: Digest384,
    pub expires_at: u64,
    pub witness: Digest384,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationWitness {
    pub session_id: Digest384,
    pub intent_id: Digest384,
    pub expires_at: u64,
    pub witness: Digest384,
}

impl PaymentSession {
    pub fn open(
        session_id: Digest384,
        intent: &WalletIntent,
        expires_at: u64,
    ) -> Result<Self, WalletError> {
        if expires_at == 0 || expires_at > intent.valid_until {
            return Err(WalletError::Expired);
        }
        let witness = Self::derive_witness(session_id, intent.intent_id, expires_at);
        Ok(Self { session_id, intent_id: intent.intent_id, expires_at, witness })
    }

    pub fn verify(&self, intent: &WalletIntent, height: u64) -> Result<(), WalletError> {
        if height > self.expires_at || intent.intent_id != self.intent_id {
            return Err(WalletError::Expired);
        }
        if self.witness != Self::derive_witness(self.session_id, self.intent_id, self.expires_at) {
            return Err(WalletError::PolicyDenied);
        }
        Ok(())
    }

    pub fn witness(&self) -> AuthorizationWitness {
        AuthorizationWitness {
            session_id: self.session_id,
            intent_id: self.intent_id,
            expires_at: self.expires_at,
            witness: self.witness,
        }
    }

    fn derive_witness(session: Digest384, intent: Digest384, expires_at: u64) -> Digest384 {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut h = sha3::Shake256::default();
        h.update(b"ACTIVECHAIN-PQ-PAYMENT-SESSION-V1");
        h.update(session.as_bytes());
        h.update(intent.as_bytes());
        h.update(&expires_at.to_be_bytes());
        let mut out = [0_u8; 48];
        XofReader::read(&mut h.finalize_xof(), &mut out);
        Digest384::new(out)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletError {
    ZeroAmount,
    PolicyDenied,
    MissingFee,
    Expired,
    DuplicateIntent,
    InsufficientFunds,
    KeySlotExists,
    KeySlotMissing,
    EmptyCiphertext,
    Replay,
    MalformedAuthorization,
    WrongChain,
    WrongSender,
    WrongRecipient,
    InvalidNonce,
    NonceExhausted,
    SessionReplay,
    UnknownSession,
    SessionBudgetExceeded,
    InputReplay,
    AuthorizationKeyExists,
    UnknownAuthorizationKey,
    InvalidAuthorizationKey,
    InvalidSignature,
    InvalidIdentityProof,
    StaleIdentityProof,
    StateLimit,
    Persistence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CashAuthorizationLane {
    sender: PrincipalId,
    public_key: [u8; ML_DSA44_PUBLIC_KEY_LENGTH],
    next_nonce: u64,
    consumed_sessions: Vec<Digest384>,
    session_budgets: Vec<CashSessionBudget>,
    identity_sequence: u64,
    authenticator_id: AuthenticatorId,
    finalized_state_root: Digest384,
    finalized_height: u64,
    finality_proof: Digest384,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CashSessionBudget {
    session_id: Digest384,
    valid_from: u64,
    expires_at: u64,
    max_spend: u128,
    spent: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionIngress {
    ledger: CashLedger,
    chain_id: ChainId,
    authorization_lanes: Vec<CashAuthorizationLane>,
    consumed_inputs: Vec<CoinCellId>,
    non_authoritative_accepted: Vec<TransactionId>,
}

pub const MAX_INGRESS_FRAME: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressError {
    Io,
    FrameTooLarge,
    Malformed,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaucetGrant {
    pub genesis_hash: Digest384,
    pub recipient: PrincipalId,
    pub amount: u128,
    pub claim_id: Digest384,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FaucetService {
    claims: Vec<Digest384>,
}

impl FaucetService {
    pub fn claim(
        &mut self,
        genesis_hash: Digest384,
        recipient: PrincipalId,
        amount: u128,
    ) -> Result<FaucetGrant, WalletError> {
        if amount == 0 {
            return Err(WalletError::ZeroAmount);
        }
        let mut bytes = [0_u8; 48];
        let recipient_bytes = recipient.into_digest().into_bytes();
        let mut hasher = sha3::Shake256::default();
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        hasher.update(b"ACTIVECHAIN-TESTNET-FAUCET-CLAIM-V1");
        hasher.update(genesis_hash.as_bytes());
        hasher.update(&recipient_bytes);
        hasher.update(&amount.to_be_bytes());
        XofReader::read(&mut hasher.finalize_xof(), &mut bytes);
        let claim_id = Digest384::new(bytes);
        if self.claims.contains(&claim_id) {
            return Err(WalletError::Replay);
        }
        self.claims.push(claim_id);
        Ok(FaucetGrant { genesis_hash, recipient, amount, claim_id })
    }
}

impl TransactionIngress {
    pub fn from_genesis(economy: &GenesisEconomy) -> Result<Self, CashTransitionError> {
        Ok(Self {
            ledger: CashLedger::from_genesis(economy)?,
            chain_id: economy.definition().chain_id(),
            authorization_lanes: Vec::new(),
            consumed_inputs: Vec::new(),
            non_authoritative_accepted: Vec::new(),
        })
    }

    /// Installs or rotates a cash key only after verifying finalized identity provenance.
    pub fn install_finalized_authorization_key<V: FinalizedIdentityKeyVerifier>(
        &mut self,
        proof: &FinalizedIdentityKeyProof,
        initial_nonce: u64,
        verifier: &V,
    ) -> Result<(), WalletError> {
        proof.validate(verifier)?;
        let sender = proof.principal().principal_id();
        let public_key: [u8; ML_DSA44_PUBLIC_KEY_LENGTH] = proof
            .authenticator()
            .verification_key()
            .try_into()
            .map_err(|_| WalletError::InvalidAuthorizationKey)?;
        match self.authorization_lanes.binary_search_by_key(&sender, |lane| lane.sender) {
            Ok(position) => {
                let lane = &mut self.authorization_lanes[position];
                if proof.principal().sequence() <= lane.identity_sequence
                    || proof.finalized_height() < lane.finalized_height
                {
                    return Err(WalletError::StaleIdentityProof);
                }
                lane.public_key = public_key;
                lane.identity_sequence = proof.principal().sequence();
                lane.authenticator_id = proof.authenticator().authenticator_id();
                lane.finalized_state_root = proof.finalized_state_root();
                lane.finalized_height = proof.finalized_height();
                lane.finality_proof = proof.finality_proof();
                Ok(())
            }
            Err(position) => {
                if self.authorization_lanes.len() == cash_persistence::MAX_AUTHORIZATION_LANES {
                    return Err(WalletError::StateLimit);
                }
                self.authorization_lanes.insert(
                    position,
                    CashAuthorizationLane {
                        sender,
                        public_key,
                        next_nonce: initial_nonce,
                        consumed_sessions: Vec::new(),
                        session_budgets: Vec::new(),
                        identity_sequence: proof.principal().sequence(),
                        authenticator_id: proof.authenticator().authenticator_id(),
                        finalized_state_root: proof.finalized_state_root(),
                        finalized_height: proof.finalized_height(),
                        finality_proof: proof.finality_proof(),
                    },
                );
                Ok(())
            }
        }
    }

    /// Registers a bounded one-shot session under the lane's finalized ML-DSA cash key.
    pub fn register_session(
        &mut self,
        authorized: &AuthorizedCashSessionGrantV1,
    ) -> Result<(), WalletError> {
        let grant = authorized.grant();
        if grant.chain_id() != self.chain_id {
            return Err(WalletError::WrongChain);
        }
        let lane_index = self
            .authorization_lanes
            .binary_search_by_key(&grant.signer(), |lane| lane.sender)
            .map_err(|_| WalletError::UnknownAuthorizationKey)?;
        let lane = &self.authorization_lanes[lane_index];
        authorized.verify(&lane.public_key)?;
        match lane
            .session_budgets
            .binary_search_by_key(&grant.session_id(), |session| session.session_id)
        {
            Ok(_) => return Err(WalletError::SessionReplay),
            Err(_)
                if lane.session_budgets.len() == cash_persistence::MAX_SESSION_BUDGETS_PER_LANE =>
            {
                return Err(WalletError::StateLimit);
            }
            Err(position) => {
                let mut next = self.clone();
                next.authorization_lanes[lane_index].session_budgets.insert(
                    position,
                    CashSessionBudget {
                        session_id: grant.session_id(),
                        valid_from: grant.valid_from(),
                        expires_at: grant.expires_at(),
                        max_spend: grant.max_spend(),
                        spent: 0,
                    },
                );
                *self = next;
            }
        }
        Ok(())
    }

    /// Strict network admission for an ML-DSA-authorized bounded cash session.
    pub fn register_session_envelope(&mut self, bytes: &[u8]) -> Result<(), WalletError> {
        let authorized = decode_envelope::<AuthorizedCashSessionGrantV1>(bytes)
            .map_err(|_| WalletError::MalformedAuthorization)?;
        self.register_session(&authorized)
    }

    /// Returns `(spent, max_spend, valid_from, expires_at)` for an authoritative session.
    #[must_use]
    pub fn session_budget(
        &self,
        sender: PrincipalId,
        session_id: Digest384,
    ) -> Option<(u128, u128, u64, u64)> {
        let lane = self
            .authorization_lanes
            .binary_search_by_key(&sender, |lane| lane.sender)
            .ok()
            .map(|index| &self.authorization_lanes[index])?;
        let session = lane
            .session_budgets
            .binary_search_by_key(&session_id, |session| session.session_id)
            .ok()
            .map(|index| lane.session_budgets[index])?;
        Some((session.spent, session.max_spend, session.valid_from, session.expires_at))
    }

    /// Executes the authoritative admission path on a clone and returns its exact budget witness.
    pub fn preview_authorized_session_witness(
        &self,
        authorized: &AuthorizedCashTransferV1,
        height: u64,
    ) -> Result<CashSessionAdmissionWitnessV1, WalletError> {
        let request = authorized.request();
        let (pre_spent, max_spend, valid_from, expires_at) = self
            .session_budget(request.signer(), request.session_id())
            .ok_or(WalletError::UnknownSession)?;
        let mut next = self.clone();
        next.submit_authorized(authorized, height)?;
        let (post_spent, post_max, post_valid_from, post_expires_at) = next
            .session_budget(request.signer(), request.session_id())
            .ok_or(WalletError::UnknownSession)?;
        if (max_spend, valid_from, expires_at) != (post_max, post_valid_from, post_expires_at) {
            return Err(WalletError::MalformedAuthorization);
        }
        CashSessionAdmissionWitnessV1::new(
            request.chain_id(),
            request.signer(),
            request.session_id(),
            height,
            valid_from,
            expires_at,
            request.transfer().amount(),
            request.transfer().fee(),
            max_spend,
            pre_spent,
            post_spent,
        )
    }

    /// Applies an already-decoded authoritative cash request atomically in memory.
    pub fn submit_authorized(
        &mut self,
        authorized: &AuthorizedCashTransferV1,
        height: u64,
    ) -> Result<(), WalletError> {
        let request = authorized.request();
        let transfer = request.transfer();
        if request.chain_id() != self.chain_id {
            return Err(WalletError::WrongChain);
        }
        if request.signer() != transfer.sender() {
            return Err(WalletError::WrongSender);
        }
        if request.recipient_commitment() != recipient_commitment(transfer.recipient()) {
            return Err(WalletError::WrongRecipient);
        }
        if height > transfer.valid_until() || height > request.session_expires_at() {
            return Err(WalletError::Expired);
        }
        let lane_index = self
            .authorization_lanes
            .binary_search_by_key(&request.signer(), |lane| lane.sender)
            .map_err(|_| WalletError::UnknownAuthorizationKey)?;
        let lane = &self.authorization_lanes[lane_index];
        if request.nonce() != lane.next_nonce {
            return Err(WalletError::InvalidNonce);
        }
        if lane.consumed_sessions.contains(&request.session_id()) {
            return Err(WalletError::SessionReplay);
        }
        let session_index = lane
            .session_budgets
            .binary_search_by_key(&request.session_id(), |session| session.session_id)
            .map_err(|_| WalletError::UnknownSession)?;
        let session = lane.session_budgets[session_index];
        if height < session.valid_from
            || height > session.expires_at
            || request.session_expires_at() > session.expires_at
        {
            return Err(WalletError::Expired);
        }
        let session_spend = transfer
            .amount()
            .checked_add(transfer.fee())
            .ok_or(WalletError::SessionBudgetExceeded)?;
        let next_session_spend =
            session.spent.checked_add(session_spend).ok_or(WalletError::SessionBudgetExceeded)?;
        if next_session_spend > session.max_spend {
            return Err(WalletError::SessionBudgetExceeded);
        }
        if lane.consumed_sessions.len() == cash_persistence::MAX_CONSUMED_SESSIONS_PER_LANE
            || self.consumed_inputs.len().saturating_add(transfer.inputs().len() + 1)
                > cash_persistence::MAX_CONSUMED_INPUTS
        {
            return Err(WalletError::StateLimit);
        }
        if transfer
            .inputs()
            .iter()
            .chain(core::iter::once(&transfer.fee_reserve()))
            .any(|input| self.consumed_inputs.contains(input))
        {
            return Err(WalletError::InputReplay);
        }
        authorized.verify(&lane.public_key)?;
        let next_nonce = lane.next_nonce.checked_add(1).ok_or(WalletError::NonceExhausted)?;

        // Construct the complete next state off to the side. No nonce, session, input barrier, or
        // ledger state becomes visible unless every ledger invariant and state update succeeds.
        let mut next = self.clone();
        next.ledger.apply_transfer(transfer, height).map_err(|_| WalletError::InsufficientFunds)?;
        let lane = &mut next.authorization_lanes[lane_index];
        lane.next_nonce = next_nonce;
        lane.session_budgets[session_index].spent = next_session_spend;
        lane.consumed_sessions.push(request.session_id());
        lane.consumed_sessions.sort_unstable();
        next.consumed_inputs.extend_from_slice(transfer.inputs());
        next.consumed_inputs.push(transfer.fee_reserve());
        next.consumed_inputs.sort_unstable();
        *self = next;
        Ok(())
    }

    /// Strict network admission: only an `AuthorizedCashTransferV1` envelope is accepted.
    pub fn submit_envelope(&mut self, bytes: &[u8], height: u64) -> Result<(), WalletError> {
        let authorized = decode_envelope::<AuthorizedCashTransferV1>(bytes)
            .map_err(|_| WalletError::MalformedAuthorization)?;
        self.submit_authorized(&authorized, height)
    }

    /// Non-authoritative compatibility helper for isolated ledger tests only.
    ///
    /// Network handlers MUST call [`Self::submit_envelope`] instead.
    pub fn submit_bare_non_authoritative_for_testing(
        &mut self,
        transfer: &CoinTransfer,
        height: u64,
    ) -> Result<(), WalletError> {
        let id = cash_transition_id(transfer).map_err(|_| WalletError::MissingFee)?;
        if self.non_authoritative_accepted.contains(&id) {
            return Err(WalletError::Replay);
        }
        if self.non_authoritative_accepted.len() == cash_persistence::MAX_NON_AUTHORITATIVE_ACCEPTED
        {
            return Err(WalletError::StateLimit);
        }
        self.ledger.apply_transfer(transfer, height).map_err(|_| WalletError::InsufficientFunds)?;
        self.non_authoritative_accepted.push(id);
        self.non_authoritative_accepted.sort_unstable();
        Ok(())
    }

    pub fn ledger(&self) -> &CashLedger {
        &self.ledger
    }

    #[must_use]
    pub fn next_nonce(&self, sender: PrincipalId) -> Option<u64> {
        self.authorization_lanes
            .binary_search_by_key(&sender, |lane| lane.sender)
            .ok()
            .map(|index| self.authorization_lanes[index].next_nonce)
    }

    #[must_use]
    pub fn session_consumed(&self, sender: PrincipalId, session_id: Digest384) -> bool {
        self.authorization_lanes.binary_search_by_key(&sender, |lane| lane.sender).is_ok_and(
            |index| self.authorization_lanes[index].consumed_sessions.contains(&session_id),
        )
    }

    pub fn serve_once(
        &mut self,
        listener: &TcpListener,
        height: u64,
        snapshot_path: &std::path::Path,
    ) -> Result<(), IngressError> {
        let (mut stream, _) = listener.accept().map_err(|_| IngressError::Io)?;
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).map_err(|_| IngressError::Io)?;
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > MAX_INGRESS_FRAME {
            return Err(IngressError::FrameTooLarge);
        }
        let mut frame = alloc::vec![0_u8; length];
        stream.read_exact(&mut frame).map_err(|_| IngressError::Io)?;
        let result = self
            .submit_envelope_durable(&frame, height, snapshot_path)
            .map_err(|_| IngressError::Rejected);
        let response = if result.is_ok() { [1_u8, 0, 0, 0] } else { [0_u8, 0, 0, 1] };
        stream.write_all(&response).map_err(|_| IngressError::Io)?;
        result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPurpose {
    Authentication,
    KeyAgreement,
    Recovery,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySlot {
    pub id: Digest384,
    pub purpose: KeyPurpose,
    pub version: u32,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EncryptedKeystore {
    slots: Vec<KeySlot>,
}

/// Platform-neutral bridge used by native mobile shells. Platform code supplies only opaque
/// ciphertext and hardware-backed signing callbacks; policy and transfer construction stay here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WalletBridge {
    keystore: EncryptedKeystore,
}

impl WalletBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn import_key_slot(&mut self, slot: KeySlot) -> Result<(), WalletError> {
        self.keystore.import_ciphertext(slot)
    }

    pub fn rotate_key_slot(
        &mut self,
        old: Digest384,
        replacement: KeySlot,
    ) -> Result<(), WalletError> {
        self.keystore.rotate(old, replacement)
    }

    pub fn key_slots(&self) -> &[KeySlot] {
        self.keystore.slots()
    }

    pub fn approve_and_build(
        &self,
        policy: SpendPolicy,
        intent: WalletIntent,
        spent_today: u128,
        current_height: u64,
    ) -> Result<CoinTransfer, WalletError> {
        authorize_intent(policy, intent, spent_today, current_height)?;
        build_transfer(intent, current_height)
    }
}

impl EncryptedKeystore {
    pub fn import_ciphertext(&mut self, slot: KeySlot) -> Result<(), WalletError> {
        if slot.ciphertext.is_empty() {
            return Err(WalletError::EmptyCiphertext);
        }
        if self.slots.iter().any(|existing| existing.id == slot.id) {
            return Err(WalletError::KeySlotExists);
        }
        self.slots.push(slot);
        self.slots.sort_by_key(|slot| slot.id);
        Ok(())
    }
    pub fn rotate(&mut self, old: Digest384, replacement: KeySlot) -> Result<(), WalletError> {
        let position =
            self.slots.iter().position(|slot| slot.id == old).ok_or(WalletError::KeySlotMissing)?;
        if replacement.ciphertext.is_empty()
            || self.slots.iter().any(|slot| slot.id == replacement.id)
        {
            return Err(WalletError::KeySlotExists);
        }
        self.slots.remove(position);
        self.slots.push(replacement);
        self.slots.sort_by_key(|slot| slot.id);
        Ok(())
    }
    pub fn slots(&self) -> &[KeySlot] {
        &self.slots
    }
}

pub fn select_cells(
    cells: &[CoinCellRecord],
    owner: PrincipalId,
    amount: u128,
    fee: u128,
) -> Result<(CoinCellId, CoinCellId), WalletError> {
    let required = amount.checked_add(fee).ok_or(WalletError::InsufficientFunds)?;
    let mut payment = None;
    let mut reserve = None;
    for record in cells {
        if record.cell().owner() != owner {
            continue;
        }
        if payment.is_none() && record.cell().amount() >= required {
            payment = Some(record.id());
            continue;
        }
        if reserve.is_none() && record.cell().amount() >= fee {
            reserve = Some(record.id());
        }
        if payment.is_some() && reserve.is_some() {
            break;
        }
    }
    match (payment, reserve) {
        (Some(payment), Some(reserve)) if payment != reserve => Ok((payment, reserve)),
        _ => Err(WalletError::InsufficientFunds),
    }
}

pub fn authorize_intent(
    policy: SpendPolicy,
    intent: WalletIntent,
    spent_today: u128,
    current_height: u64,
) -> Result<WalletIntent, WalletError> {
    if intent.amount == 0 {
        return Err(WalletError::ZeroAmount);
    }
    if intent.fee.total().is_none() {
        return Err(WalletError::MissingFee);
    }
    if current_height > intent.valid_until {
        return Err(WalletError::Expired);
    }
    if intent.recipient_commitment != recipient_commitment(intent.recipient) {
        return Err(WalletError::WrongRecipient);
    }
    if !policy.allows(intent.amount, intent.recipient_commitment, spent_today) {
        return Err(WalletError::PolicyDenied);
    }
    Ok(intent)
}

pub fn authorize_with_witness(
    intent: WalletIntent,
    witness: AuthorizationWitness,
    policy: SpendPolicy,
    spent_today: u128,
    current_height: u64,
) -> Result<WalletIntent, WalletError> {
    let session = PaymentSession {
        session_id: witness.session_id,
        intent_id: witness.intent_id,
        expires_at: witness.expires_at,
        witness: witness.witness,
    };
    session.verify(&intent, current_height)?;
    authorize_intent(policy, intent, spent_today, current_height)
}

pub fn build_transfer(
    intent: WalletIntent,
    current_height: u64,
) -> Result<CoinTransfer, WalletError> {
    if current_height > intent.valid_until {
        return Err(WalletError::Expired);
    }
    let fee = intent.fee.total().ok_or(WalletError::MissingFee)?;
    CoinTransfer::new(
        intent.sender,
        intent.recipient,
        alloc::vec![intent.input],
        intent.fee_reserve,
        intent.amount,
        fee,
        intent.valid_until,
    )
    .map_err(|_| WalletError::InsufficientFunds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::encode_envelope;
    use activechain_cash_kernel::{
        CoinCell, CoinCellOrigin, GenesisAllocation, NativeAssetDefinition,
    };
    use activechain_protocol_types::{
        AuthenticatorDescriptor, AuthenticatorId, AuthenticatorPurpose, CryptoSuiteId, FreezeState,
        Principal, PrincipalKind, ProtocolSignature, TransactionId,
    };
    use alloc::vec;
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }
    fn intent() -> WalletIntent {
        WalletIntent {
            intent_id: digest(1),
            sender: principal(2),
            recipient: principal(3),
            recipient_commitment: recipient_commitment(principal(3)),
            amount: 10,
            fee: FeeQuote { base: 1, resource_units: 2, resource_price: 1, congestion_price: 0 },
            input: CoinCellId::new(digest(4)),
            fee_reserve: CoinCellId::new(digest(5)),
            valid_until: 20,
        }
    }

    fn test_economy(owner: PrincipalId) -> GenesisEconomy {
        let definition = NativeAssetDefinition::new(
            ChainId::new(digest(1)),
            b"ACT".to_vec(),
            18,
            1_000,
            150,
            digest(2),
            digest(3),
            digest(4),
        )
        .unwrap();
        GenesisEconomy::new(
            definition,
            vec![
                GenesisAllocation::new(owner, 700, 0).unwrap(),
                GenesisAllocation::new(owner, 200, 0).unwrap(),
            ],
            100,
        )
        .unwrap()
    }

    fn setup_authorized_ingress(
        key_seed: u8,
    ) -> (TransactionIngress, SigningKey<MlDsa44>, PrincipalId, CoinCellId, CoinCellId) {
        let owner = principal(10);
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([key_seed; 32]));
        let economy = test_economy(owner);
        let mut ingress = TransactionIngress::from_genesis(&economy).unwrap();
        let proof = identity_key_proof(owner, &key, 0, 1, 30);
        ingress.install_finalized_authorization_key(&proof, 0, &AcceptFinality).unwrap();
        let input = ingress
            .ledger()
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().amount() == 700)
            .unwrap()
            .id();
        let reserve = ingress
            .ledger()
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.cell().amount() == 200)
            .unwrap()
            .id();
        (ingress, key, owner, input, reserve)
    }

    fn identity_key_proof(
        owner: PrincipalId,
        key: &SigningKey<MlDsa44>,
        sequence: u64,
        finalized_height: u64,
        authenticator_byte: u8,
    ) -> FinalizedIdentityKeyProof {
        let authenticator = AuthenticatorDescriptor::new(
            AuthenticatorId::new(digest(authenticator_byte)),
            CryptoSuiteId::ML_DSA_44,
            key.verifying_key().encode().as_slice().to_vec(),
            AuthenticatorPurpose::Session,
            1,
            None,
            None,
        )
        .unwrap();
        let identity = Principal::new(
            owner,
            PrincipalKind::Human,
            digest(31),
            digest(32),
            authenticator_set_root(core::slice::from_ref(&authenticator)).unwrap(),
            sequence,
            FreezeState::Active,
            digest(33),
            1,
            1,
            finalized_height,
        )
        .unwrap();
        FinalizedIdentityKeyProof::new(
            identity,
            authenticator,
            digest(34),
            finalized_height,
            digest(35),
        )
    }

    struct AcceptFinality;
    impl FinalizedIdentityKeyVerifier for AcceptFinality {
        fn verify_finalized_identity_key(&self, _proof: &FinalizedIdentityKeyProof) -> bool {
            true
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn cash_request(
        chain_id: ChainId,
        signer: PrincipalId,
        nonce: u64,
        session_id: Digest384,
        session_expires_at: u64,
        input: CoinCellId,
        reserve: CoinCellId,
        amount: u128,
    ) -> CashAuthorizationRequestV1 {
        let transfer =
            CoinTransfer::new(principal(10), principal(11), vec![input], reserve, amount, 1, 20)
                .unwrap();
        CashAuthorizationRequestV1::new(
            chain_id,
            signer,
            nonce,
            session_id,
            session_expires_at,
            transfer,
        )
        .unwrap()
    }

    fn sign_cash_request(
        request: CashAuthorizationRequestV1,
        key: &SigningKey<MlDsa44>,
    ) -> AuthorizedCashTransferV1 {
        let signature = key.sign(&request.signing_payload().unwrap());
        AuthorizedCashTransferV1::new(
            request,
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                signature.encode().as_slice().to_vec(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn sign_session_grant(
        request: &CashAuthorizationRequestV1,
        key: &SigningKey<MlDsa44>,
        max_spend: u128,
    ) -> AuthorizedCashSessionGrantV1 {
        let grant = CashSessionGrantV1::new(
            request.chain_id(),
            request.signer(),
            request.session_id(),
            1,
            request.session_expires_at(),
            max_spend,
        )
        .unwrap();
        let signature = key.sign(&grant.signing_payload().unwrap());
        AuthorizedCashSessionGrantV1::new(
            grant,
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                signature.encode().as_slice().to_vec(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn register_request_session(
        ingress: &mut TransactionIngress,
        request: &CashAuthorizationRequestV1,
        key: &SigningKey<MlDsa44>,
        max_spend: u128,
    ) {
        ingress.register_session(&sign_session_grant(request, key, max_spend)).unwrap();
    }

    #[test]
    fn policy_gates_intent_before_signing() {
        let policy = SpendPolicy {
            daily_limit: 100,
            max_single_payment: 25,
            recipient_commitment: Some(recipient_commitment(principal(3))),
        };
        assert!(authorize_intent(policy, intent(), 20, 10).is_ok());
        assert_eq!(authorize_intent(policy, intent(), 95, 10), Err(WalletError::PolicyDenied));
    }

    #[test]
    fn expired_and_zero_intents_are_rejected() {
        let policy =
            SpendPolicy { daily_limit: 100, max_single_payment: 25, recipient_commitment: None };
        assert_eq!(authorize_intent(policy, intent(), 0, 21), Err(WalletError::Expired));
        let mut zero = intent();
        zero.amount = 0;
        assert_eq!(authorize_intent(policy, zero, 0, 1), Err(WalletError::ZeroAmount));
    }

    #[test]
    fn cell_selection_is_deterministic_and_keeps_fee_reserve_separate() {
        let owner = principal(2);
        let cells = vec![
            CoinCellRecord::new(
                CoinCellId::new(digest(4)),
                CoinCell::new(CoinCellOrigin::new(TransactionId::new(digest(6)), 0), owner, 20, 1)
                    .unwrap(),
            ),
            CoinCellRecord::new(
                CoinCellId::new(digest(5)),
                CoinCell::new(CoinCellOrigin::new(TransactionId::new(digest(7)), 0), owner, 5, 1)
                    .unwrap(),
            ),
        ];
        let (payment, reserve) = select_cells(&cells, owner, 10, 2).unwrap();
        assert_ne!(payment, reserve);
        assert_eq!(select_cells(&cells, owner, 30, 2), Err(WalletError::InsufficientFunds));
    }

    #[test]
    fn intent_builds_canonical_transfer_with_fee_reserve() {
        let transfer = build_transfer(intent(), 10).unwrap();
        assert_eq!(transfer.amount(), 10);
        assert_eq!(transfer.fee(), 3);
        assert_eq!(transfer.fee_reserve(), CoinCellId::new(digest(5)));
    }

    #[test]
    fn keystore_only_accepts_opaque_ciphertext_and_supports_rotation() {
        let mut store = EncryptedKeystore::default();
        let first = KeySlot {
            id: digest(8),
            purpose: KeyPurpose::Authentication,
            version: 1,
            ciphertext: vec![1, 2, 3],
        };
        store.import_ciphertext(first.clone()).unwrap();
        assert_eq!(store.import_ciphertext(first), Err(WalletError::KeySlotExists));
        let replacement = KeySlot {
            id: digest(9),
            purpose: KeyPurpose::Authentication,
            version: 2,
            ciphertext: vec![4, 5],
        };
        store.rotate(digest(8), replacement).unwrap();
        assert_eq!(store.slots()[0].id, digest(9));
    }

    #[test]
    fn faucet_grants_are_genesis_bound_and_one_shot() {
        let mut faucet = FaucetService::default();
        let grant = faucet.claim(digest(1), principal(2), 100).unwrap();
        assert_eq!(grant.genesis_hash, digest(1));
        assert_eq!(faucet.claim(digest(1), principal(2), 100), Err(WalletError::Replay));
        assert_ne!(faucet.claim(digest(2), principal(2), 100).unwrap().claim_id, grant.claim_id);
    }

    #[test]
    fn mobile_bridge_keeps_policy_and_keystore_boundaries() {
        let mut bridge = WalletBridge::new();
        bridge
            .import_key_slot(KeySlot {
                id: digest(8),
                purpose: KeyPurpose::Authentication,
                version: 1,
                ciphertext: vec![1, 2, 3],
            })
            .unwrap();
        let policy = SpendPolicy {
            daily_limit: 100,
            max_single_payment: 25,
            recipient_commitment: Some(recipient_commitment(principal(3))),
        };
        assert_eq!(bridge.approve_and_build(policy, intent(), 0, 10).unwrap().amount(), 10);
        assert_eq!(bridge.key_slots().len(), 1);
    }

    #[test]
    fn payment_session_is_bound_and_expires() {
        let session = PaymentSession::open(digest(7), &intent(), 15).unwrap();
        assert!(session.verify(&intent(), 15).is_ok());
        assert_eq!(session.verify(&intent(), 16), Err(WalletError::Expired));
        let mut altered = session;
        altered.intent_id = digest(8);
        assert_eq!(altered.verify(&intent(), 1), Err(WalletError::Expired));
    }

    #[test]
    fn witness_authorizes_persistent_intent_without_mutating_it() {
        let original = intent();
        let witness = PaymentSession::open(digest(7), &original, 15).unwrap().witness();
        let policy = SpendPolicy {
            daily_limit: 100,
            max_single_payment: 25,
            recipient_commitment: Some(recipient_commitment(principal(3))),
        };
        assert_eq!(authorize_with_witness(original, witness, policy, 0, 10).unwrap(), original);
    }

    #[test]
    fn openwallet_adapter_is_deterministic_and_replay_safe() {
        let mut adapter = OpenWalletAdapterV1::new();
        let credential = OpenWalletCredentialRefV1 {
            credential_id: digest(1),
            schema_id: digest(2),
            issuer: digest(3),
        };
        adapter.register_credential(credential).unwrap();
        assert!(adapter.register_credential(credential).is_err());
        let session =
            OpenWalletSessionV1 { session_id: digest(4), relying_party: digest(5), expires_at: 10 };
        adapter.open_session(session, 1).unwrap();
        assert!(adapter.open_session(session, 1).is_err());
    }

    #[test]
    fn authorized_cash_envelope_accepts_exact_pq_intent_and_consumes_all_barriers() {
        let (mut ingress, key, owner, input, reserve) = setup_authorized_ingress(21);
        let session = digest(30);
        let request =
            cash_request(ChainId::new(digest(1)), owner, 0, session, 15, input, reserve, 10);
        register_request_session(&mut ingress, &request, &key, 11);
        let intent_id = request.intent_id().unwrap();
        let signed = sign_cash_request(request, &key);
        let envelope = encode_envelope(&signed).unwrap();

        let witness = ingress.preview_authorized_session_witness(&signed, 5).unwrap();
        assert_eq!((witness.pre_spent(), witness.post_spent()), (0, 11));
        assert_eq!((witness.amount(), witness.fee(), witness.max_spend()), (10, 1, 11));
        assert_eq!(
            activechain_canonical_codec::decode_envelope::<CashSessionAdmissionWitnessV1>(
                &encode_envelope(&witness).unwrap()
            )
            .unwrap(),
            witness
        );

        ingress.submit_envelope(&envelope, 5).unwrap();

        assert_eq!(ingress.next_nonce(owner), Some(1));
        assert!(ingress.session_consumed(owner, session));
        assert_eq!(ingress.submit_envelope(&envelope, 5), Err(WalletError::InvalidNonce));
        assert_eq!(signed.request().intent_id().unwrap(), intent_id);

        let same_session = sign_cash_request(
            cash_request(ChainId::new(digest(1)), owner, 1, session, 15, input, reserve, 10),
            &key,
        );
        assert_eq!(ingress.submit_authorized(&same_session, 5), Err(WalletError::SessionReplay));

        let same_inputs_request =
            cash_request(ChainId::new(digest(1)), owner, 1, digest(31), 15, input, reserve, 10);
        register_request_session(&mut ingress, &same_inputs_request, &key, 11);
        let same_inputs = sign_cash_request(same_inputs_request, &key);
        assert_eq!(ingress.submit_authorized(&same_inputs, 5), Err(WalletError::InputReplay));
    }

    #[test]
    fn network_ingress_rejects_bare_wrong_version_and_trailing_bytes() {
        let (mut ingress, key, owner, input, reserve) = setup_authorized_ingress(22);
        let request =
            cash_request(ChainId::new(digest(1)), owner, 0, digest(32), 15, input, reserve, 10);
        let transfer_envelope = encode_envelope(request.transfer()).unwrap();
        assert_eq!(
            ingress.submit_envelope(&transfer_envelope, 5),
            Err(WalletError::MalformedAuthorization)
        );

        let signed = sign_cash_request(request, &key);
        let envelope = encode_envelope(&signed).unwrap();
        let mut wrong_version = envelope.clone();
        wrong_version[3] = 2;
        assert_eq!(
            ingress.submit_envelope(&wrong_version, 5),
            Err(WalletError::MalformedAuthorization)
        );
        let mut trailing = envelope;
        trailing.push(0);
        assert_eq!(ingress.submit_envelope(&trailing, 5), Err(WalletError::MalformedAuthorization));
    }

    #[test]
    fn authorization_rejects_wrong_chain_sender_key_nonce_and_expiry() {
        let (mut ingress, key, owner, input, reserve) = setup_authorized_ingress(23);
        let wrong_chain = sign_cash_request(
            cash_request(ChainId::new(digest(99)), owner, 0, digest(33), 15, input, reserve, 10),
            &key,
        );
        assert_eq!(ingress.submit_authorized(&wrong_chain, 5), Err(WalletError::WrongChain));

        let wrong_sender = sign_cash_request(
            cash_request(
                ChainId::new(digest(1)),
                principal(99),
                0,
                digest(34),
                15,
                input,
                reserve,
                10,
            ),
            &key,
        );
        assert_eq!(ingress.submit_authorized(&wrong_sender, 5), Err(WalletError::WrongSender));

        let wrong_nonce = sign_cash_request(
            cash_request(ChainId::new(digest(1)), owner, 1, digest(35), 15, input, reserve, 10),
            &key,
        );
        assert_eq!(ingress.submit_authorized(&wrong_nonce, 5), Err(WalletError::InvalidNonce));

        let other_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([24; 32]));
        let wrong_key = sign_cash_request(
            cash_request(ChainId::new(digest(1)), owner, 0, digest(36), 15, input, reserve, 10),
            &other_key,
        );
        register_request_session(&mut ingress, wrong_key.request(), &key, 11);
        assert_eq!(ingress.submit_authorized(&wrong_key, 5), Err(WalletError::InvalidSignature));

        let expired = sign_cash_request(
            cash_request(ChainId::new(digest(1)), owner, 0, digest(37), 4, input, reserve, 10),
            &key,
        );
        assert_eq!(ingress.submit_authorized(&expired, 5), Err(WalletError::Expired));
    }

    #[test]
    fn tampering_signed_transfer_or_recipient_commitment_is_rejected() {
        let (mut ingress, key, owner, input, reserve) = setup_authorized_ingress(25);
        let original_request =
            cash_request(ChainId::new(digest(1)), owner, 0, digest(38), 15, input, reserve, 10);
        register_request_session(&mut ingress, &original_request, &key, 12);
        let original = sign_cash_request(original_request, &key);
        let tampered_request =
            cash_request(ChainId::new(digest(1)), owner, 0, digest(38), 15, input, reserve, 11);
        assert_ne!(original.request().intent_id().unwrap(), tampered_request.intent_id().unwrap());
        let tampered =
            AuthorizedCashTransferV1::new(tampered_request, original.signature().clone()).unwrap();
        assert_eq!(ingress.submit_authorized(&tampered, 5), Err(WalletError::InvalidSignature));

        let mut recipient_tampered = encode_envelope(&original).unwrap();
        let commitment = original.request().recipient_commitment().into_bytes();
        let offset = recipient_tampered
            .windows(commitment.len())
            .position(|window| window == commitment)
            .expect("recipient commitment occurs in canonical request");
        recipient_tampered[offset] ^= 1;
        assert_eq!(
            ingress.submit_envelope(&recipient_tampered, 5),
            Err(WalletError::MalformedAuthorization)
        );
    }

    #[test]
    fn failed_ledger_transition_does_not_consume_nonce_session_or_inputs() {
        let (mut ingress, key, owner, input, reserve) = setup_authorized_ingress(26);
        let session = digest(39);
        let unaffordable_request =
            cash_request(ChainId::new(digest(1)), owner, 0, session, 15, input, reserve, 901);
        register_request_session(&mut ingress, &unaffordable_request, &key, 1_000);
        let unaffordable = sign_cash_request(unaffordable_request, &key);
        assert_eq!(
            ingress.submit_authorized(&unaffordable, 5),
            Err(WalletError::InsufficientFunds)
        );
        assert_eq!(ingress.next_nonce(owner), Some(0));
        assert!(!ingress.session_consumed(owner, session));

        let affordable = sign_cash_request(
            cash_request(ChainId::new(digest(1)), owner, 0, session, 15, input, reserve, 10),
            &key,
        );
        ingress.submit_authorized(&affordable, 5).unwrap();
        assert_eq!(ingress.next_nonce(owner), Some(1));
        assert!(ingress.session_consumed(owner, session));
    }

    #[test]
    fn cash_keys_require_finality_and_rotate_only_from_newer_identity_state() {
        struct RejectFinality;
        impl FinalizedIdentityKeyVerifier for RejectFinality {
            fn verify_finalized_identity_key(&self, _proof: &FinalizedIdentityKeyProof) -> bool {
                false
            }
        }

        let owner = principal(10);
        let first = SigningKey::<MlDsa44>::from_seed(&Seed::from([41; 32]));
        let replacement = SigningKey::<MlDsa44>::from_seed(&Seed::from([42; 32]));
        let mut ingress = TransactionIngress::from_genesis(&test_economy(owner)).unwrap();
        let initial = identity_key_proof(owner, &first, 0, 1, 40);
        assert_eq!(
            ingress.install_finalized_authorization_key(&initial, 0, &RejectFinality),
            Err(WalletError::InvalidIdentityProof)
        );
        ingress.install_finalized_authorization_key(&initial, 0, &AcceptFinality).unwrap();
        assert_eq!(
            ingress.install_finalized_authorization_key(&initial, 0, &AcceptFinality),
            Err(WalletError::StaleIdentityProof)
        );
        let rotated = identity_key_proof(owner, &replacement, 1, 2, 41);
        ingress.install_finalized_authorization_key(&rotated, 99, &AcceptFinality).unwrap();
        assert_eq!(ingress.next_nonce(owner), Some(0), "rotation preserves the cash nonce lane");
    }

    #[test]
    fn signed_session_grants_enforce_key_window_budget_and_canonical_network_boundary() {
        let (mut ingress, key, owner, input, reserve) = setup_authorized_ingress(47);
        let request =
            cash_request(ChainId::new(digest(1)), owner, 0, digest(48), 15, input, reserve, 10);
        let grant = sign_session_grant(&request, &key, 10);
        let envelope = encode_envelope(&grant).unwrap();
        ingress.register_session_envelope(&envelope).unwrap();
        assert_eq!(ingress.session_budget(owner, digest(48)), Some((0, 10, 1, 15)));
        assert_eq!(ingress.register_session_envelope(&envelope), Err(WalletError::SessionReplay));

        let transfer = sign_cash_request(request, &key);
        assert_eq!(
            ingress.submit_authorized(&transfer, 5),
            Err(WalletError::SessionBudgetExceeded)
        );
        assert_eq!(ingress.session_budget(owner, digest(48)), Some((0, 10, 1, 15)));
        assert_eq!(ingress.next_nonce(owner), Some(0));

        let unknown_request =
            cash_request(ChainId::new(digest(1)), owner, 0, digest(49), 15, input, reserve, 10);
        assert_eq!(
            ingress.submit_authorized(&sign_cash_request(unknown_request, &key), 5),
            Err(WalletError::UnknownSession)
        );

        let other_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([48; 32]));
        let invalid = sign_session_grant(
            &cash_request(ChainId::new(digest(1)), owner, 0, digest(50), 15, input, reserve, 10),
            &other_key,
            11,
        );
        assert_eq!(ingress.register_session(&invalid), Err(WalletError::InvalidSignature));
        assert_eq!(ingress.session_budget(owner, digest(50)), None);
    }

    #[test]
    fn durable_cash_admission_survives_restart_and_rejects_corruption_and_replay() {
        let (mut ingress, key, owner, input, reserve) = setup_authorized_ingress(43);
        let session = digest(44);
        let signed = sign_cash_request(
            cash_request(ChainId::new(digest(1)), owner, 0, session, 15, input, reserve, 10),
            &key,
        );
        register_request_session(&mut ingress, signed.request(), &key, 11);
        let envelope = encode_envelope(&signed).unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-cash-ingress-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        ingress.submit_envelope_durable(&envelope, 5, &path).unwrap();

        let mut restored = TransactionIngress::load(&path, ChainId::new(digest(1))).unwrap();
        assert_eq!(restored.next_nonce(owner), Some(1));
        assert!(restored.session_consumed(owner, session));
        assert_eq!(restored.session_budget(owner, session), Some((11, 11, 1, 15)));
        assert_eq!(restored.ledger(), ingress.ledger());
        assert_eq!(restored.submit_envelope(&envelope, 5), Err(WalletError::InvalidNonce));
        assert_eq!(
            TransactionIngress::load(&path, ChainId::new(digest(99))),
            Err(WalletError::WrongChain)
        );

        let mut corrupted = std::fs::read(&path).unwrap();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        std::fs::write(&path, corrupted).unwrap();
        assert_eq!(
            TransactionIngress::load(&path, ChainId::new(digest(1))),
            Err(WalletError::Persistence)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_cash_snapshot_publish_exposes_no_ledger_or_replay_mutation() {
        let (mut ingress, key, owner, input, reserve) = setup_authorized_ingress(45);
        let session = digest(46);
        let signed = sign_cash_request(
            cash_request(ChainId::new(digest(1)), owner, 0, session, 15, input, reserve, 10),
            &key,
        );
        register_request_session(&mut ingress, signed.request(), &key, 11);
        let envelope = encode_envelope(&signed).unwrap();
        let directory = std::env::temp_dir()
            .join(format!("activechain-cash-publish-failure-{}", std::process::id()));
        let _ = std::fs::remove_dir(&directory);
        std::fs::create_dir(&directory).unwrap();
        assert_eq!(
            ingress.submit_envelope_durable(&envelope, 5, &directory),
            Err(WalletError::Persistence)
        );
        assert_eq!(ingress.next_nonce(owner), Some(0));
        assert!(!ingress.session_consumed(owner, session));
        std::fs::remove_dir(directory).unwrap();
    }
}
