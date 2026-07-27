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

