#![forbid(unsafe_code)]

//! Protocol-owned wallet primitives intended to sit underneath OpenWallet adapters.
//! This crate never stores plaintext secret keys and never signs an unconstrained request.

extern crate alloc;

use activechain_canonical_codec::decode_envelope;
use activechain_cash_kernel::{CashLedger, CashTransitionError, GenesisEconomy};
use activechain_cash_kernel::{CoinCellRecord, CoinTransfer, FeeQuote};
use activechain_protocol_commitment::cash_transition_id;
use activechain_protocol_types::{CoinCellId, Digest384, PrincipalId, TransactionId};
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
}

pub struct TransactionIngress {
    ledger: CashLedger,
    accepted: Vec<TransactionId>,
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
        hasher.finalize_xof().read(&mut bytes);
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
        Ok(Self { ledger: CashLedger::from_genesis(economy)?, accepted: Vec::new() })
    }
    pub fn submit(&mut self, transfer: &CoinTransfer, height: u64) -> Result<(), WalletError> {
        let id = cash_transition_id(transfer).map_err(|_| WalletError::MissingFee)?;
        if self.accepted.contains(&id) {
            return Err(WalletError::Replay);
        }
        self.ledger.apply_transfer(transfer, height).map_err(|_| WalletError::InsufficientFunds)?;
        self.accepted.push(id);
        Ok(())
    }
    pub fn submit_envelope(&mut self, bytes: &[u8], height: u64) -> Result<(), WalletError> {
        let transfer =
            decode_envelope::<CoinTransfer>(bytes).map_err(|_| WalletError::MissingFee)?;
        self.submit(&transfer, height)
    }
    pub fn ledger(&self) -> &CashLedger {
        &self.ledger
    }

    pub fn serve_once(&mut self, listener: &TcpListener, height: u64) -> Result<(), IngressError> {
        let (mut stream, _) = listener.accept().map_err(|_| IngressError::Io)?;
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).map_err(|_| IngressError::Io)?;
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > MAX_INGRESS_FRAME {
            return Err(IngressError::FrameTooLarge);
        }
        let mut frame = alloc::vec![0_u8; length];
        stream.read_exact(&mut frame).map_err(|_| IngressError::Io)?;
        let result = self.submit_envelope(&frame, height).map_err(|_| IngressError::Rejected);
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
    if !policy.allows(intent.amount, intent.recipient_commitment, spent_today) {
        return Err(WalletError::PolicyDenied);
    }
    Ok(intent)
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
    use activechain_cash_kernel::{CoinCell, CoinCellOrigin};
    use activechain_protocol_types::TransactionId;
    use alloc::vec;
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
            recipient_commitment: digest(3),
            amount: 10,
            fee: FeeQuote { base: 1, resource_units: 2, resource_price: 1, congestion_price: 0 },
            input: CoinCellId::new(digest(4)),
            fee_reserve: CoinCellId::new(digest(5)),
            valid_until: 20,
        }
    }

    #[test]
    fn policy_gates_intent_before_signing() {
        let policy = SpendPolicy {
            daily_limit: 100,
            max_single_payment: 25,
            recipient_commitment: Some(digest(3)),
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
            recipient_commitment: Some(digest(3)),
        };
        assert_eq!(bridge.approve_and_build(policy, intent(), 0, 10).unwrap().amount(), 10);
        assert_eq!(bridge.key_slots().len(), 1);
    }
}
