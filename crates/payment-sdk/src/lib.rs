#![forbid(unsafe_code)]

//! Transport-neutral ActiveBridge client requests and proof-aware responses.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_payment_types::{
    PaymentApiOperation, PaymentApiSignedAuthorizationV1, PaymentLifecycleRecordV1, PaymentState,
};
use activechain_protocol_types::Digest384;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_PAYMENT_SDK_BODY_BYTES: usize = 65_536;
pub const MAX_PAYMENT_SDK_PROOF_BYTES: usize = 1_048_576;

pub fn payment_sdk_body_commitment(body: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-PAYMENT-SDK-BODY-V1");
    hasher.update(&(body.len() as u64).to_be_bytes());
    hasher.update(body);
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentSdkRequestV1 {
    authorization: PaymentApiSignedAuthorizationV1,
    body: Vec<u8>,
}

impl PaymentSdkRequestV1 {
    pub const TYPE_TAG: u16 = 0x01A7;
    pub const SCHEMA_VERSION: u16 = 1;

    pub fn new(
        authorization: PaymentApiSignedAuthorizationV1,
        body: Vec<u8>,
    ) -> Result<Self, PaymentSdkError> {
        if body.is_empty()
            || body.len() > MAX_PAYMENT_SDK_BODY_BYTES
            || authorization.authorization().request_commitment()
                != payment_sdk_body_commitment(&body)
        {
            return Err(PaymentSdkError::InvalidRequest);
        }
        Ok(Self { authorization, body })
    }

    pub const fn operation(&self) -> PaymentApiOperation {
        self.authorization.authorization().operation()
    }
    pub const fn authorization(&self) -> &PaymentApiSignedAuthorizationV1 {
        &self.authorization
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn commitment(&self) -> Result<Digest384, PaymentSdkError> {
        let encoded = encode_envelope(self).map_err(|_| PaymentSdkError::Encoding)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-PAYMENT-SDK-REQUEST-V1");
        hasher.update(&(encoded.len() as u64).to_be_bytes());
        hasher.update(&encoded);
        let mut output = [0_u8; 48];
        hasher.finalize_xof().read(&mut output);
        Ok(Digest384::new(output))
    }
}

impl CanonicalEncode for PaymentSdkRequestV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.authorization.encode(encoder)?;
        encoder.write_bytes(&self.body, MAX_PAYMENT_SDK_BODY_BYTES)
    }
}
impl CanonicalDecode for PaymentSdkRequestV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PaymentApiSignedAuthorizationV1::decode(decoder)?,
            decoder.read_bytes(MAX_PAYMENT_SDK_BODY_BYTES)?.to_vec(),
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment SDK request"))
    }
}
impl CanonicalType for PaymentSdkRequestV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize =
        PaymentApiSignedAuthorizationV1::MAX_ENCODED_LEN + 3 + MAX_PAYMENT_SDK_BODY_BYTES;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PaymentSdkOutcome {
    Accepted = 0,
    IdempotentReplay = 1,
    Rejected = 2,
}
impl CanonicalEncode for PaymentSdkOutcome {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for PaymentSdkOutcome {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::IdempotentReplay),
            2 => Ok(Self::Rejected),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "PaymentSdkOutcome", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentSdkResponseV1 {
    request_commitment: Digest384,
    outcome: PaymentSdkOutcome,
    lifecycle: Option<PaymentLifecycleRecordV1>,
    proof: Vec<u8>,
}
impl PaymentSdkResponseV1 {
    pub const TYPE_TAG: u16 = 0x01A8;
    pub const SCHEMA_VERSION: u16 = 1;

    pub fn new(
        request_commitment: Digest384,
        outcome: PaymentSdkOutcome,
        lifecycle: Option<PaymentLifecycleRecordV1>,
        proof: Vec<u8>,
    ) -> Result<Self, PaymentSdkError> {
        let finalized = lifecycle.as_ref().is_some_and(|record| {
            matches!(record.state(), PaymentState::Finalized | PaymentState::Refunded)
        });
        if request_commitment == Digest384::ZERO
            || proof.len() > MAX_PAYMENT_SDK_PROOF_BYTES
            || (finalized && proof.is_empty())
            || (outcome == PaymentSdkOutcome::Rejected
                && (lifecycle.is_some() || !proof.is_empty()))
        {
            return Err(PaymentSdkError::InvalidResponse);
        }
        Ok(Self { request_commitment, outcome, lifecycle, proof })
    }
    pub const fn request_commitment(&self) -> Digest384 {
        self.request_commitment
    }
    pub const fn outcome(&self) -> PaymentSdkOutcome {
        self.outcome
    }
    pub const fn lifecycle(&self) -> Option<&PaymentLifecycleRecordV1> {
        self.lifecycle.as_ref()
    }
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
}
impl CanonicalEncode for PaymentSdkResponseV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.request_commitment.encode(encoder)?;
        self.outcome.encode(encoder)?;
        self.lifecycle.encode(encoder)?;
        encoder.write_bytes(&self.proof, MAX_PAYMENT_SDK_PROOF_BYTES)
    }
}
impl CanonicalDecode for PaymentSdkResponseV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(decoder)?,
            PaymentSdkOutcome::decode(decoder)?,
            Option::<PaymentLifecycleRecordV1>::decode(decoder)?,
            decoder.read_bytes(MAX_PAYMENT_SDK_PROOF_BYTES)?.to_vec(),
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment SDK response"))
    }
}
impl CanonicalType for PaymentSdkResponseV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize =
        48 + 1 + 1 + PaymentLifecycleRecordV1::MAX_ENCODED_LEN + 4 + MAX_PAYMENT_SDK_PROOF_BYTES;
}

pub trait ActiveBridgeTransport {
    type Error;
    fn send(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

pub struct ActiveBridgeClient<T> {
    transport: T,
}
impl<T> ActiveBridgeClient<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }
    pub fn into_transport(self) -> T {
        self.transport
    }
}
impl<T: ActiveBridgeTransport> ActiveBridgeClient<T> {
    pub fn execute(
        &mut self,
        request: &PaymentSdkRequestV1,
    ) -> Result<PaymentSdkResponseV1, PaymentSdkClientError<T::Error>> {
        let expected = request.commitment().map_err(PaymentSdkClientError::Sdk)?;
        let encoded = encode_envelope(request)
            .map_err(|_| PaymentSdkClientError::Sdk(PaymentSdkError::Encoding))?;
        let response = self.transport.send(&encoded).map_err(PaymentSdkClientError::Transport)?;
        let decoded: PaymentSdkResponseV1 =
            decode_envelope(&response).map_err(|_| PaymentSdkClientError::MalformedResponse)?;
        if decoded.request_commitment != expected {
            return Err(PaymentSdkClientError::ResponseSubstitution);
        }
        Ok(decoded)
    }

    pub fn execute_verified(
        &mut self,
        request: &PaymentSdkRequestV1,
        verify_finality: impl FnOnce(&PaymentLifecycleRecordV1, &[u8]) -> bool,
    ) -> Result<PaymentSdkResponseV1, PaymentSdkClientError<T::Error>> {
        let response = self.execute(request)?;
        if let Some(record) = response.lifecycle()
            && matches!(record.state(), PaymentState::Finalized | PaymentState::Refunded)
            && !verify_finality(record, response.proof())
        {
            return Err(PaymentSdkClientError::ProofRejected);
        }
        Ok(response)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentSdkError {
    InvalidRequest,
    InvalidResponse,
    Encoding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PaymentSdkClientError<E> {
    Sdk(PaymentSdkError),
    Transport(E),
    MalformedResponse,
    ResponseSubstitution,
    ProofRejected,
}

#[cfg(test)]
mod tests;
