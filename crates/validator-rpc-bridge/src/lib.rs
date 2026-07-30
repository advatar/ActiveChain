#![forbid(unsafe_code)]

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{Digest384, PrincipalId, TransactionId};
use activechain_rpc_server::FaucetError;
use activechain_wallet_core::AuthorizedCashTransferV1;

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

pub fn encode_authorized_request(
    request: &AuthorizedSettlementRequest,
) -> Result<Vec<u8>, EncodeError> {
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

pub fn decode_authorized_request(frame: &[u8]) -> Result<AuthorizedSettlementRequest, DecodeError> {
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

    /// Authoritative settlement path for a pre-signed cash intent. Backends
    /// should submit these exact canonical bytes to validator ingress.
    fn submit_authorized_envelope(
        &self,
        _envelope: &[u8],
        _recipient: PrincipalId,
        _amount: u128,
        _reference: Digest384,
    ) -> Result<TransactionId, FaucetError> {
        Err(FaucetError::InvalidChallenge)
    }
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

/// Canonical validator-facing request carrying the exact pre-signed cash
/// authorization selected by a faucet decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedSettlementRequest {
    pub envelope: Vec<u8>,
    pub recipient: PrincipalId,
    pub amount: u128,
    pub reference: Digest384,
}
impl CanonicalEncode for AuthorizedSettlementRequest {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_bytes(&self.envelope, 64 * 1024)?;
        self.recipient.encode(e)?;
        self.amount.encode(e)?;
        self.reference.encode(e)
    }
}
impl CanonicalDecode for AuthorizedSettlementRequest {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            envelope: d.read_bytes(64 * 1024)?.to_vec(),
            recipient: PrincipalId::decode(d)?,
            amount: u128::decode(d)?,
            reference: Digest384::decode(d)?,
        })
    }
}
impl CanonicalType for AuthorizedSettlementRequest {
    const TYPE_TAG: u16 = 0x0126;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 64 * 1024 + 48 + 16 + 48;
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
    const TYPE_TAG: u16 = 0x0123;
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
    const TYPE_TAG: u16 = 0x0125;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 96;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SettlementState {
    Pending = 0,
    Finalized = 1,
    Rejected = 2,
}
impl CanonicalEncode for SettlementState {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for SettlementState {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Finalized),
            2 => Ok(Self::Rejected),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "SettlementState", tag }),
        }
    }
}

/// Proof-neutral status envelope used while a faucet transition moves through validator finality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementStatusResponse {
    pub reference: Digest384,
    pub state: SettlementState,
    pub transaction: Option<TransactionId>,
    pub reason: Option<Digest384>,
}
impl SettlementStatusResponse {
    pub const TYPE_TAG: u16 = 0x0128;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 1 + 1 + 48 + 1 + 48;
    pub fn new(
        reference: Digest384,
        state: SettlementState,
        transaction: Option<TransactionId>,
        reason: Option<Digest384>,
    ) -> Result<Self, DecodeError> {
        if reference == Digest384::ZERO {
            return Err(DecodeError::InvalidValue("zero settlement reference"));
        }
        if matches!(state, SettlementState::Finalized) != transaction.is_some()
            || matches!(state, SettlementState::Rejected) != reason.is_some()
        {
            return Err(DecodeError::InvalidValue("inconsistent settlement status"));
        }
        Ok(Self { reference, state, transaction, reason })
    }
}
impl CanonicalEncode for SettlementStatusResponse {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.reference.encode(e)?;
        self.state.encode(e)?;
        self.transaction.encode(e)?;
        self.reason.encode(e)
    }
}
impl CanonicalDecode for SettlementStatusResponse {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            SettlementState::decode(d)?,
            Option::<TransactionId>::decode(d)?,
            Option::<Digest384>::decode(d)?,
        )
    }
}
impl CanonicalType for SettlementStatusResponse {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
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

    /// Validate and settle an exact authorized cash envelope for a faucet
    /// decision. The envelope's intent id, recipient, amount, and reference
    /// must all agree before the backend sees any bytes.
    pub fn settle_authorized_envelope(
        &self,
        envelope: &[u8],
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<SettlementResponse, FaucetError> {
        if envelope.is_empty() || reference == Digest384::ZERO || amount == 0 {
            return Err(FaucetError::InvalidChallenge);
        }
        let authorized =
            activechain_canonical_codec::decode_envelope::<AuthorizedCashTransferV1>(envelope)
                .map_err(|_| FaucetError::InvalidChallenge)?;
        let request = authorized.request();
        let transfer = request.transfer();
        if request.intent_id().map_err(|_| FaucetError::InvalidChallenge)? != reference
            || transfer.recipient() != recipient
            || transfer.amount() != amount
        {
            return Err(FaucetError::InvalidChallenge);
        }
        let transaction =
            self.backend.submit_authorized_envelope(envelope, recipient, amount, reference)?;
        Ok(SettlementResponse { reference, transaction })
    }

    pub fn settle_authorized_request(
        &self,
        request: &AuthorizedSettlementRequest,
    ) -> Result<SettlementResponse, FaucetError> {
        self.settle_authorized_envelope(
            &request.envelope,
            request.recipient,
            request.amount,
            request.reference,
        )
    }
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
    fn authorized_settlement_rejects_malformed_or_empty_envelopes_before_backend() {
        let bridge = ValidatorRpcBridge::new(Backend);
        let recipient = PrincipalId::new(Digest384::new([8; 48]));
        let reference = Digest384::new([7; 48]);
        assert_eq!(
            bridge.settle_authorized_envelope(&[], recipient, 10, reference),
            Err(FaucetError::InvalidChallenge)
        );
        assert_eq!(
            bridge.settle_authorized_envelope(&[0xff], recipient, 10, reference),
            Err(FaucetError::InvalidChallenge)
        );
    }

    #[test]
    fn authorized_settlement_request_round_trips_and_preserves_binding_fields() {
        let request = AuthorizedSettlementRequest {
            envelope: vec![1, 2, 3],
            recipient: PrincipalId::new(Digest384::new([8; 48])),
            amount: 10,
            reference: Digest384::new([7; 48]),
        };
        let encoded = activechain_canonical_codec::encode_envelope(&request).unwrap();
        let decoded: AuthorizedSettlementRequest =
            activechain_canonical_codec::decode_envelope(&encoded).unwrap();
        assert_eq!(decoded, request);
        let mut malformed = encoded;
        malformed.push(0);
        assert!(
            activechain_canonical_codec::decode_envelope::<AuthorizedSettlementRequest>(&malformed)
                .is_err()
        );

        let frame = encode_authorized_request(&request).unwrap();
        assert_eq!(decode_authorized_request(&frame).unwrap(), request);
        let mut trailing = frame;
        trailing.push(0);
        assert!(decode_authorized_request(&trailing).is_err());
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

    #[test]
    fn settlement_status_requires_state_consistent_evidence() {
        let pending = SettlementStatusResponse::new(
            Digest384::new([7; 48]),
            SettlementState::Pending,
            None,
            None,
        )
        .unwrap();
        let bytes = activechain_canonical_codec::encode_envelope(&pending).unwrap();
        assert_eq!(
            activechain_canonical_codec::decode_envelope::<SettlementStatusResponse>(&bytes),
            Ok(pending)
        );
        assert!(
            SettlementStatusResponse::new(
                Digest384::new([7; 48]),
                SettlementState::Finalized,
                None,
                None,
            )
            .is_err()
        );
        assert!(
            SettlementStatusResponse::new(
                Digest384::new([7; 48]),
                SettlementState::Rejected,
                None,
                None,
            )
            .is_err()
        );
    }
}
