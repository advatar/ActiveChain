//! Signed, non-authoritative payment requests.
//!
//! A payment request is an authenticated statement by the recipient describing
//! a desired payment. It never authorizes movement of funds: a payer must still
//! construct, review, and sign a normal cash transfer.

use crate::{WalletError, wallet_principal_id};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    encode_envelope,
};
use activechain_protocol_types::{
    AssetId, ChainId, CryptoSuiteId, Digest384, PrincipalId, ProtocolSignature,
};
use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

const SIGNING_DOMAIN: &[u8] = b"ACTIVECHAIN-PAYMENT-REQUEST-ML-DSA-44-V1";
const REFERENCE_DOMAIN: &[u8] = b"ACTIVECHAIN-PAYMENT-REQUEST-ID-V1";
pub const MAX_PAYMENT_REQUEST_MEMO_LENGTH: usize = 160;
pub const MAX_PAYMENT_REQUEST_LENGTH: usize = 8 * 1024;

/// Canonical wallet-to-wallet payment request.
///
/// `asset == None` means native ACT. `amount == None` creates an open amount
/// request. `expires_at_height == None` means no protocol-level expiry; wallet
/// policy may still impose a local freshness limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentRequestV1 {
    chain_id: ChainId,
    genesis_commitment: Digest384,
    recipient: PrincipalId,
    asset: Option<AssetId>,
    amount: Option<u128>,
    request_nonce: Digest384,
    memo: Vec<u8>,
    expires_at_height: Option<u64>,
    public_key: Vec<u8>,
    signature: ProtocolSignature,
}

impl PaymentRequestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn signing_payload(
        chain_id: ChainId,
        genesis_commitment: Digest384,
        recipient: PrincipalId,
        asset: Option<AssetId>,
        amount: Option<u128>,
        request_nonce: Digest384,
        memo: &[u8],
        expires_at_height: Option<u64>,
        public_key: &[u8],
    ) -> Result<Vec<u8>, WalletError> {
        Self::validate_unsigned(
            genesis_commitment,
            recipient,
            amount,
            request_nonce,
            memo,
            expires_at_height,
            public_key,
        )?;
        if wallet_principal_id(public_key) != recipient {
            return Err(WalletError::WrongRecipient);
        }

        let mut bytes = SIGNING_DOMAIN.to_vec();
        bytes.extend_from_slice(chain_id.digest().as_bytes());
        bytes.extend_from_slice(genesis_commitment.as_bytes());
        bytes.extend_from_slice(recipient.into_digest().as_bytes());
        match asset {
            Some(asset) => {
                bytes.push(1);
                bytes.extend_from_slice(asset.digest().as_bytes());
            }
            None => bytes.push(0),
        }
        match amount {
            Some(amount) => {
                bytes.push(1);
                bytes.extend_from_slice(&amount.to_be_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(request_nonce.as_bytes());
        let memo_len = u16::try_from(memo.len()).map_err(|_| WalletError::MalformedAuthorization)?;
        bytes.extend_from_slice(&memo_len.to_be_bytes());
        bytes.extend_from_slice(memo);
        match expires_at_height {
            Some(height) => {
                bytes.push(1);
                bytes.extend_from_slice(&height.to_be_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(public_key);
        Ok(bytes)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        genesis_commitment: Digest384,
        recipient: PrincipalId,
        asset: Option<AssetId>,
        amount: Option<u128>,
        request_nonce: Digest384,
        memo: Vec<u8>,
        expires_at_height: Option<u64>,
        public_key: Vec<u8>,
        signature: ProtocolSignature,
    ) -> Result<Self, WalletError> {
        let value = Self {
            chain_id,
            genesis_commitment,
            recipient,
            asset,
            amount,
            request_nonce,
            memo,
            expires_at_height,
            public_key,
            signature,
        };
        value.verify(None)?;
        Ok(value)
    }

    /// Verifies the requester signature and all intrinsic request invariants.
    /// When `height` is supplied, expiry is also enforced.
    pub fn verify(&self, height: Option<u64>) -> Result<(), WalletError> {
        if self.signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(WalletError::InvalidSignature);
        }
        let payload = Self::signing_payload(
            self.chain_id,
            self.genesis_commitment,
            self.recipient,
            self.asset,
            self.amount,
            self.request_nonce,
            &self.memo,
            self.expires_at_height,
            &self.public_key,
        )?;
        crate::cash_authorization::verify_ml_dsa(&self.public_key, &self.signature, &payload)?;
        if height.is_some_and(|height| self.expires_at_height.is_some_and(|expiry| height > expiry)) {
            return Err(WalletError::Expired);
        }
        Ok(())
    }

    pub fn reference(&self) -> Result<Digest384, WalletError> {
        let payload = Self::signing_payload(
            self.chain_id,
            self.genesis_commitment,
            self.recipient,
            self.asset,
            self.amount,
            self.request_nonce,
            &self.memo,
            self.expires_at_height,
            &self.public_key,
        )?;
        let mut h = Shake256::default();
        h.update(REFERENCE_DOMAIN);
        h.update(&payload);
        let mut out = [0_u8; 48];
        XofReader::read(&mut h.finalize_xof(), &mut out);
        Ok(Digest384::new(out))
    }

    pub fn envelope(&self) -> Result<Vec<u8>, WalletError> {
        encode_envelope(self).map_err(|_| WalletError::MalformedAuthorization)
    }

    pub const fn chain_id(&self) -> ChainId { self.chain_id }
    pub const fn genesis_commitment(&self) -> Digest384 { self.genesis_commitment }
    pub const fn recipient(&self) -> PrincipalId { self.recipient }
    pub const fn asset(&self) -> Option<AssetId> { self.asset }
    pub const fn amount(&self) -> Option<u128> { self.amount }
    pub const fn request_nonce(&self) -> Digest384 { self.request_nonce }
    pub fn memo(&self) -> &[u8] { &self.memo }
    pub const fn expires_at_height(&self) -> Option<u64> { self.expires_at_height }
    pub fn public_key(&self) -> &[u8] { &self.public_key }
    pub fn signature(&self) -> &ProtocolSignature { &self.signature }

    fn validate_unsigned(
        genesis_commitment: Digest384,
        recipient: PrincipalId,
        amount: Option<u128>,
        request_nonce: Digest384,
        memo: &[u8],
        expires_at_height: Option<u64>,
        public_key: &[u8],
    ) -> Result<(), WalletError> {
        if genesis_commitment == Digest384::ZERO
            || recipient.into_digest() == Digest384::ZERO
            || amount == Some(0)
            || request_nonce == Digest384::ZERO
            || memo.len() > MAX_PAYMENT_REQUEST_MEMO_LENGTH
            || core::str::from_utf8(memo).is_err()
            || expires_at_height == Some(0)
            || public_key.len() != activechain_protocol_types::ML_DSA44_PUBLIC_KEY_LENGTH
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(())
    }
}

impl CanonicalEncode for PaymentRequestV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.genesis_commitment.encode(e)?;
        self.recipient.encode(e)?;
        self.asset.encode(e)?;
        self.amount.encode(e)?;
        self.request_nonce.encode(e)?;
        e.write_bytes(&self.memo, MAX_PAYMENT_REQUEST_MEMO_LENGTH)?;
        self.expires_at_height.encode(e)?;
        e.write_bytes(&self.public_key, activechain_protocol_types::ML_DSA44_PUBLIC_KEY_LENGTH)?;
        self.signature.encode(e)
    }
}

impl CanonicalDecode for PaymentRequestV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            Option::<AssetId>::decode(d)?,
            Option::<u128>::decode(d)?,
            Digest384::decode(d)?,
            d.read_bytes(MAX_PAYMENT_REQUEST_MEMO_LENGTH)?.to_vec(),
            Option::<u64>::decode(d)?,
            d.read_bytes(activechain_protocol_types::ML_DSA44_PUBLIC_KEY_LENGTH)?.to_vec(),
            ProtocolSignature::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment request"))
    }
}

impl CanonicalType for PaymentRequestV1 {
    const TYPE_TAG: u16 = 0x01D4;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = MAX_PAYMENT_REQUEST_LENGTH;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{Keypair, MlDsa44, Signer, SigningKey};

    fn digest(byte: u8) -> Digest384 { Digest384::new([byte; 48]) }

    fn signed_request(amount: Option<u128>, expiry: Option<u64>) -> PaymentRequestV1 {
        let key = SigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from([7_u8; 32]));
        let public_key = key.verifying_key().encode().as_slice().to_vec();
        let recipient = wallet_principal_id(&public_key);
        let chain = ChainId::new(digest(1));
        let payload = PaymentRequestV1::signing_payload(
            chain,
            digest(2),
            recipient,
            None,
            amount,
            digest(3),
            b"Coffee",
            expiry,
            &public_key,
        )
        .unwrap();
        let signature = key.sign(&payload).encode().as_slice().to_vec();
        PaymentRequestV1::new(
            chain,
            digest(2),
            recipient,
            None,
            amount,
            digest(3),
            b"Coffee".to_vec(),
            expiry,
            public_key,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn signed_request_round_trips_and_has_stable_reference() {
        let request = signed_request(Some(25), Some(100));
        let reference = request.reference().unwrap();
        let bytes = request.envelope().unwrap();
        let decoded = activechain_canonical_codec::decode_envelope::<PaymentRequestV1>(&bytes).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.reference().unwrap(), reference);
        assert_eq!(decoded.amount(), Some(25));
        decoded.verify(Some(100)).unwrap();
    }

    #[test]
    fn open_amount_request_is_valid() {
        let request = signed_request(None, None);
        assert_eq!(request.amount(), None);
        request.verify(Some(10_000)).unwrap();
    }

    #[test]
    fn expiry_is_enforced_without_changing_signature_validity() {
        let request = signed_request(Some(1), Some(12));
        assert_eq!(request.verify(Some(13)), Err(WalletError::Expired));
        request.verify(None).unwrap();
    }

    #[test]
    fn tampering_breaks_signature() {
        let request = signed_request(Some(25), Some(100));
        let tampered = PaymentRequestV1 {
            amount: Some(26),
            ..request
        };
        assert_eq!(tampered.verify(Some(50)), Err(WalletError::InvalidSignature));
    }

    #[test]
    fn signer_must_control_recipient() {
        let key = SigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from([9_u8; 32]));
        let public_key = key.verifying_key().encode().as_slice().to_vec();
        assert_eq!(
            PaymentRequestV1::signing_payload(
                ChainId::new(digest(1)),
                digest(2),
                PrincipalId::new(digest(8)),
                None,
                Some(1),
                digest(3),
                b"",
                Some(10),
                &public_key,
            ),
            Err(WalletError::WrongRecipient)
        );
    }
}
