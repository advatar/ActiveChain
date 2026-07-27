#![forbid(unsafe_code)]

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{Digest384, PrincipalId, TransactionId};
use activechain_rpc_server::FaucetError;

pub const MAX_BRIDGE_FRAME: usize = 64 * 1024;

pub fn encode_request(request: &SettlementRequest) -> Result<Vec<u8>, EncodeError> {
    let body = activechain_canonical_codec::encode_envelope(request)?;
    if body.len() > MAX_BRIDGE_FRAME {
        return Err(EncodeError::OutputLimitExceeded {
            attempted: body.len(),
            maximum: MAX_BRIDGE_FRAME,
        });
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn decode_request(frame: &[u8]) -> Result<SettlementRequest, DecodeError> {
    if frame.len() < 4 {
        return Err(DecodeError::UnexpectedEnd { needed: 4, remaining: frame.len() });
    }
    let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    if len > MAX_BRIDGE_FRAME || frame.len() != len + 4 {
        return Err(DecodeError::InvalidValue("invalid bridge frame length"));
    }
    activechain_canonical_codec::decode_envelope(&frame[4..])
}

pub fn encode_response(response: &SettlementResponse) -> Result<Vec<u8>, EncodeError> {
    let body = activechain_canonical_codec::encode_envelope(response)?;
    if body.len() > MAX_BRIDGE_FRAME {
        return Err(EncodeError::OutputLimitExceeded {
            attempted: body.len(),
            maximum: MAX_BRIDGE_FRAME,
        });
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn decode_response(frame: &[u8]) -> Result<SettlementResponse, DecodeError> {
    if frame.len() < 4 {
        return Err(DecodeError::UnexpectedEnd { needed: 4, remaining: frame.len() });
    }
    let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    if len > MAX_BRIDGE_FRAME || frame.len() != len + 4 {
        return Err(DecodeError::InvalidValue("invalid bridge frame length"));
    }
    activechain_canonical_codec::decode_envelope(&frame[4..])
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementRequest {
    pub recipient: PrincipalId,
    pub amount: u128,
    pub reference: Digest384,
}
impl CanonicalEncode for SettlementRequest {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.recipient.encode(e)?;
        self.amount.encode(e)?;
        self.reference.encode(e)
    }
}
impl CanonicalDecode for SettlementRequest {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            recipient: PrincipalId::decode(d)?,
            amount: u128::decode(d)?,
            reference: Digest384::decode(d)?,
        })
    }
}
impl CanonicalType for SettlementRequest {
    const TYPE_TAG: u16 = 0x00D0;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 16 + 48;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementResponse {
    pub reference: Digest384,
    pub transaction: TransactionId,
}
impl CanonicalEncode for SettlementResponse {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.reference.encode(e)?;
        self.transaction.encode(e)
    }
}
impl CanonicalDecode for SettlementResponse {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { reference: Digest384::decode(d)?, transaction: TransactionId::decode(d)? })
    }
}
impl CanonicalType for SettlementResponse {
    const TYPE_TAG: u16 = 0x00D1;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 96;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Backend;
    impl FaucetSettlementBackend for Backend {
        fn submit_and_await_finality(
            &self,
            _recipient: PrincipalId,
            _amount: u128,
            reference: Digest384,
        ) -> Result<TransactionId, FaucetError> {
            Ok(TransactionId::new(reference))
        }
    }

    #[test]
    fn delegates_only_non_empty_finalized_settlements() {
        let bridge = ValidatorRpcBridge::new(Backend);
        let reference = Digest384::new([7; 48]);
        assert_eq!(
            bridge.settle(PrincipalId::new(Digest384::new([8; 48])), 10, reference).unwrap(),
            TransactionId::new(reference)
        );
        assert_eq!(
            bridge.settle(PrincipalId::new(Digest384::new([8; 48])), 0, reference),
            Err(FaucetError::InvalidChallenge)
        );
        assert_eq!(
            bridge.settle(PrincipalId::new(Digest384::new([8; 48])), 10, Digest384::ZERO),
            Err(FaucetError::InvalidChallenge)
        );
    }

    #[test]
    fn request_and_response_frames_round_trip() {
        let request = SettlementRequest {
            recipient: PrincipalId::new(Digest384::new([8; 48])),
            amount: 10,
            reference: Digest384::new([7; 48]),
        };
        let request_frame = encode_request(&request).unwrap();
        assert_eq!(decode_request(&request_frame).unwrap(), request);

        let response = SettlementResponse {
            reference: Digest384::new([7; 48]),
            transaction: TransactionId::new(Digest384::new([9; 48])),
        };
        let response_frame = encode_response(&response).unwrap();
        assert_eq!(decode_response(&response_frame).unwrap(), response);
    }

    #[test]
    fn settlement_response_binds_request_reference() {
        let bridge = ValidatorRpcBridge::new(Backend);
        let request = SettlementRequest {
            recipient: PrincipalId::new(Digest384::new([8; 48])),
            amount: 10,
            reference: Digest384::new([7; 48]),
        };
        let response = bridge.settle_request(&request).unwrap();
        assert_eq!(response.reference, request.reference);
        assert_eq!(response.transaction, TransactionId::new(request.reference));
    }

    #[test]
    fn frames_reject_truncation_and_trailing_bytes() {
        let response = SettlementResponse {
            reference: Digest384::new([7; 48]),
            transaction: TransactionId::new(Digest384::new([9; 48])),
        };
        let frame = encode_response(&response).unwrap();
        assert!(matches!(decode_response(&frame[..3]), Err(DecodeError::UnexpectedEnd { .. })));
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(matches!(decode_response(&trailing), Err(DecodeError::InvalidValue(_))));
        let mut oversized = frame;
        oversized[..4].copy_from_slice(&((MAX_BRIDGE_FRAME as u32) + 1).to_be_bytes());
        assert!(matches!(decode_response(&oversized), Err(DecodeError::InvalidValue(_))));
    }
}

impl<B: FaucetSettlementBackend> ValidatorRpcBridge<B> {
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

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

    pub fn settle_request(
        &self,
        request: &SettlementRequest,
    ) -> Result<SettlementResponse, FaucetError> {
        let transaction = self.settle(request.recipient, request.amount, request.reference)?;
        Ok(SettlementResponse { reference: request.reference, transaction })
    }
}
