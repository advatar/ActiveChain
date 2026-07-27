#![forbid(unsafe_code)]

use activechain_protocol_types::{Digest384, PrincipalId, TransactionId};
use activechain_rpc_server::FaucetError;

/// Backend implemented by the validator process or a local authenticated IPC client.
pub trait FaucetSettlementBackend: Send + Sync {
    fn submit_and_await_finality(
        &self,
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<TransactionId, FaucetError>;
}

/// Explicit bridge between RPC faucet admission and validator-backed settlement.
pub struct ValidatorRpcBridge<B> {
    backend: B,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Backend;
    impl FaucetSettlementBackend for Backend {
        fn submit_and_await_finality(&self, _recipient: PrincipalId, _amount: u128, reference: Digest384) -> Result<TransactionId, FaucetError> {
            Ok(TransactionId::new(reference))
        }
    }

    #[test]
    fn delegates_only_non_empty_finalized_settlements() {
        let bridge = ValidatorRpcBridge::new(Backend);
        let reference = Digest384::new([7; 48]);
        assert_eq!(bridge.settle(PrincipalId::new(Digest384::new([8; 48])), 10, reference).unwrap(), TransactionId::new(reference));
        assert_eq!(bridge.settle(PrincipalId::new(Digest384::new([8; 48])), 0, reference), Err(FaucetError::InvalidChallenge));
        assert_eq!(bridge.settle(PrincipalId::new(Digest384::new([8; 48])), 10, Digest384::ZERO), Err(FaucetError::InvalidChallenge));
    }
}

impl<B: FaucetSettlementBackend> ValidatorRpcBridge<B> {
    pub const fn new(backend: B) -> Self { Self { backend } }

    pub fn settle(
        &self,
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<TransactionId, FaucetError> {
        if reference == Digest384::ZERO || amount == 0 {
            return Err(FaucetError::InvalidChallenge);
        }
        self.backend.submit_and_await_finality(recipient, amount, reference)
    }
}
