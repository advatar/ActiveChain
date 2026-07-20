#![forbid(unsafe_code)]

//! Protocol-owned wallet primitives intended to sit underneath OpenWallet adapters.
//! This crate never stores plaintext secret keys and never signs an unconstrained request.

use activechain_cash_kernel::FeeQuote;
use activechain_protocol_types::{CoinCellId, Digest384, PrincipalId};

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
