use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    encode_envelope,
};
use activechain_cash_kernel::{CoinTransfer, VerifierRole};
use activechain_protocol_types::{
    ChainId, CoinCellId, CryptoSuiteId, Digest384, PrincipalId, ProtocolSignature,
};
use alloc::vec::Vec;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature, Verifier, VerifyingKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::WalletError;

const CASH_AUTHORIZATION_SIGNING_DOMAIN: &[u8] = b"ACTIVECHAIN-CASH-AUTHORIZATION-ML-DSA-44-V1";
const CASH_INTENT_ID_DOMAIN: &[u8] = b"ACTIVECHAIN-CASH-INTENT-ID-V1";
const RECIPIENT_COMMITMENT_DOMAIN: &[u8] = b"ACTIVECHAIN-CASH-RECIPIENT-V1";
const CASH_SESSION_GRANT_SIGNING_DOMAIN: &[u8] = b"ACTIVECHAIN-CASH-SESSION-GRANT-ML-DSA-44-V1";

/// A finalized cash key's bounded authorization for one short-lived payment session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashSessionGrantV1 {
    chain_id: ChainId,
    signer: PrincipalId,
    session_id: Digest384,
    valid_from: u64,
    expires_at: u64,
    max_spend: u128,
}

impl CashSessionGrantV1 {
    pub fn new(
        chain_id: ChainId,
        signer: PrincipalId,
        session_id: Digest384,
        valid_from: u64,
        expires_at: u64,
        max_spend: u128,
    ) -> Result<Self, WalletError> {
        if valid_from > expires_at || expires_at == 0 || max_spend == 0 {
            return Err(WalletError::Expired);
        }
        Ok(Self { chain_id, signer, session_id, valid_from, expires_at, max_spend })
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    #[must_use]
    pub const fn signer(&self) -> PrincipalId {
        self.signer
    }
    #[must_use]
    pub const fn session_id(&self) -> Digest384 {
        self.session_id
    }
    #[must_use]
    pub const fn valid_from(&self) -> u64 {
        self.valid_from
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    #[must_use]
    pub const fn max_spend(&self) -> u128 {
        self.max_spend
    }

    pub fn signing_payload(&self) -> Result<Vec<u8>, EncodeError> {
        let encoded = encode_envelope(self)?;
        let mut payload =
            Vec::with_capacity(CASH_SESSION_GRANT_SIGNING_DOMAIN.len() + 8 + encoded.len());
        payload.extend_from_slice(CASH_SESSION_GRANT_SIGNING_DOMAIN);
        payload.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        payload.extend_from_slice(&encoded);
        Ok(payload)
    }
}

impl CanonicalEncode for CashSessionGrantV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.signer.encode(e)?;
        self.session_id.encode(e)?;
        self.valid_from.encode(e)?;
        self.expires_at.encode(e)?;
        self.max_spend.encode(e)
    }
}

impl CanonicalDecode for CashSessionGrantV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u128::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid cash session grant"))
    }
}

impl CanonicalType for CashSessionGrantV1 {
    const TYPE_TAG: u16 = 0x0097;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 3 + 8 * 2 + 16;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedCashSessionGrantV1 {
    grant: CashSessionGrantV1,
    signature: ProtocolSignature,
}

impl AuthorizedCashSessionGrantV1 {
    pub fn new(
        grant: CashSessionGrantV1,
        signature: ProtocolSignature,
    ) -> Result<Self, WalletError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(WalletError::InvalidSignature);
        }
        Ok(Self { grant, signature })
    }
    #[must_use]
    pub const fn grant(&self) -> &CashSessionGrantV1 {
        &self.grant
    }
    pub fn verify(&self, public_key: &[u8]) -> Result<(), WalletError> {
        let payload =
            self.grant.signing_payload().map_err(|_| WalletError::MalformedAuthorization)?;
        verify_ml_dsa(public_key, &self.signature, &payload)
    }
}

impl CanonicalEncode for AuthorizedCashSessionGrantV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.grant.encode(e)?;
        self.signature.encode(e)
    }
}

impl CanonicalDecode for AuthorizedCashSessionGrantV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(CashSessionGrantV1::decode(d)?, ProtocolSignature::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid authorized cash session grant"))
    }
}

impl CanonicalType for AuthorizedCashSessionGrantV1 {
    const TYPE_TAG: u16 = 0x0098;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        CashSessionGrantV1::MAX_ENCODED_LEN + ProtocolSignature::MAX_ENCODED_LEN;
}

/// Canonical pre/post budget values produced by successful authoritative admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CashSessionAdmissionWitnessV1 {
    chain_id: ChainId,
    signer: PrincipalId,
    session_id: Digest384,
    height: u64,
    valid_from: u64,
    expires_at: u64,
    amount: u128,
    fee: u128,
    max_spend: u128,
    pre_spent: u128,
    post_spent: u128,
}

impl CashSessionAdmissionWitnessV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        signer: PrincipalId,
        session_id: Digest384,
        height: u64,
        valid_from: u64,
        expires_at: u64,
        amount: u128,
        fee: u128,
        max_spend: u128,
        pre_spent: u128,
        post_spent: u128,
    ) -> Result<Self, WalletError> {
        let spend = amount.checked_add(fee).ok_or(WalletError::SessionBudgetExceeded)?;
        if height < valid_from
            || height > expires_at
            || pre_spent.checked_add(spend) != Some(post_spent)
            || post_spent > max_spend
        {
            return Err(WalletError::SessionBudgetExceeded);
        }
        Ok(Self {
            chain_id,
            signer,
            session_id,
            height,
            valid_from,
            expires_at,
            amount,
            fee,
            max_spend,
            pre_spent,
            post_spent,
        })
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    #[must_use]
    pub const fn signer(&self) -> PrincipalId {
        self.signer
    }
    #[must_use]
    pub const fn session_id(&self) -> Digest384 {
        self.session_id
    }
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }
    #[must_use]
    pub const fn valid_from(&self) -> u64 {
        self.valid_from
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    #[must_use]
    pub const fn amount(&self) -> u128 {
        self.amount
    }
    #[must_use]
    pub const fn fee(&self) -> u128 {
        self.fee
    }
    #[must_use]
    pub const fn max_spend(&self) -> u128 {
        self.max_spend
    }
    #[must_use]
    pub const fn pre_spent(&self) -> u128 {
        self.pre_spent
    }
    #[must_use]
    pub const fn post_spent(&self) -> u128 {
        self.post_spent
    }
}

impl CanonicalEncode for CashSessionAdmissionWitnessV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.signer.encode(e)?;
        self.session_id.encode(e)?;
        self.height.encode(e)?;
        self.valid_from.encode(e)?;
        self.expires_at.encode(e)?;
        self.amount.encode(e)?;
        self.fee.encode(e)?;
        self.max_spend.encode(e)?;
        self.pre_spent.encode(e)?;
        self.post_spent.encode(e)
    }
}

impl CanonicalDecode for CashSessionAdmissionWitnessV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid cash session admission witness"))
    }
}

impl CanonicalType for CashSessionAdmissionWitnessV1 {
    const TYPE_TAG: u16 = 0x0099;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 3 + 8 * 3 + 16 * 5;
}

/// The exact canonical value authorized by an ML-DSA cash signature.
///
/// The recipient commitment is carried on the wire for policy interoperability, but strict
/// decoding recomputes it from `transfer.recipient()` and rejects a mismatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashAuthorizationRequestV1 {
    chain_id: ChainId,
    signer: PrincipalId,
    nonce: u64,
    session_id: Digest384,
    session_expires_at: u64,
    recipient_commitment: Digest384,
    settlement_reference: Option<Digest384>,
    transfer: CoinTransfer,
}

impl CashAuthorizationRequestV1 {
    pub const TYPE_TAG: u16 = 0x008a;
    pub const SCHEMA_VERSION: u16 = 2;
    pub const MAX_ENCODED_LEN: usize =
        48 + 48 + 8 + 48 + 8 + 48 + 1 + 48 + CoinTransfer::MAX_ENCODED_LEN;

    pub fn new(
        chain_id: ChainId,
        signer: PrincipalId,
        nonce: u64,
        session_id: Digest384,
        session_expires_at: u64,
        transfer: CoinTransfer,
    ) -> Result<Self, WalletError> {
        Self::new_with_settlement_reference(
            chain_id,
            signer,
            nonce,
            session_id,
            session_expires_at,
            None,
            transfer,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_settlement_reference(
        chain_id: ChainId,
        signer: PrincipalId,
        nonce: u64,
        session_id: Digest384,
        session_expires_at: u64,
        settlement_reference: Option<Digest384>,
        transfer: CoinTransfer,
    ) -> Result<Self, WalletError> {
        if session_expires_at == 0 || session_expires_at > transfer.valid_until() {
            return Err(WalletError::Expired);
        }
        if settlement_reference == Some(Digest384::ZERO) {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self {
            chain_id,
            signer,
            nonce,
            session_id,
            session_expires_at,
            recipient_commitment: recipient_commitment(transfer.recipient()),
            settlement_reference,
            transfer,
        })
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn signer(&self) -> PrincipalId {
        self.signer
    }

    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    #[must_use]
    pub const fn session_id(&self) -> Digest384 {
        self.session_id
    }

    #[must_use]
    pub const fn session_expires_at(&self) -> u64 {
        self.session_expires_at
    }

    #[must_use]
    pub const fn recipient_commitment(&self) -> Digest384 {
        self.recipient_commitment
    }

    #[must_use]
    pub const fn settlement_reference(&self) -> Option<Digest384> {
        self.settlement_reference
    }

    #[must_use]
    pub const fn transfer(&self) -> &CoinTransfer {
        &self.transfer
    }

    /// Returns the complete domain-separated canonical bytes that an ML-DSA signer authorizes.
    pub fn signing_payload(&self) -> Result<Vec<u8>, EncodeError> {
        let request = encode_envelope(self)?;
        let request_length =
            u64::try_from(request.len()).map_err(|_| EncodeError::LengthOverflow)?;
        let capacity = CASH_AUTHORIZATION_SIGNING_DOMAIN
            .len()
            .checked_add(8)
            .and_then(|length| length.checked_add(request.len()))
            .ok_or(EncodeError::LengthOverflow)?;
        let mut payload = Vec::with_capacity(capacity);
        payload.extend_from_slice(CASH_AUTHORIZATION_SIGNING_DOMAIN);
        payload.extend_from_slice(&request_length.to_be_bytes());
        payload.extend_from_slice(&request);
        Ok(payload)
    }

    /// Recomputes the intent identifier from the exact signing transcript.
    pub fn intent_id(&self) -> Result<Digest384, EncodeError> {
        let payload = self.signing_payload()?;
        let mut hasher = Shake256::default();
        hasher.update(CASH_INTENT_ID_DOMAIN);
        hasher.update(&(payload.len() as u64).to_be_bytes());
        hasher.update(&payload);
        let mut output = [0_u8; 48];
        hasher.finalize_xof().read(&mut output);
        Ok(Digest384::new(output))
    }
}

impl CanonicalEncode for CashAuthorizationRequestV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(encoder)?;
        self.signer.encode(encoder)?;
        self.nonce.encode(encoder)?;
        self.session_id.encode(encoder)?;
        self.session_expires_at.encode(encoder)?;
        self.recipient_commitment.encode(encoder)?;
        self.settlement_reference.encode(encoder)?;
        self.transfer.encode(encoder)
    }
}

impl CanonicalDecode for CashAuthorizationRequestV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(decoder)?;
        let signer = PrincipalId::decode(decoder)?;
        let nonce = u64::decode(decoder)?;
        let session_id = Digest384::decode(decoder)?;
        let session_expires_at = u64::decode(decoder)?;
        let claimed_recipient_commitment = Digest384::decode(decoder)?;
        let settlement_reference = Option::<Digest384>::decode(decoder)?;
        let transfer = CoinTransfer::decode(decoder)?;
        if session_expires_at == 0 || session_expires_at > transfer.valid_until() {
            return Err(DecodeError::InvalidValue(
                "cash authorization session exceeds the transfer validity window",
            ));
        }
        let expected_recipient_commitment = recipient_commitment(transfer.recipient());
        if claimed_recipient_commitment != expected_recipient_commitment {
            return Err(DecodeError::InvalidValue(
                "cash authorization recipient commitment mismatch",
            ));
        }
        if settlement_reference == Some(Digest384::ZERO) {
            return Err(DecodeError::InvalidValue("zero cash settlement reference"));
        }
        Ok(Self {
            chain_id,
            signer,
            nonce,
            session_id,
            session_expires_at,
            recipient_commitment: expected_recipient_commitment,
            settlement_reference,
            transfer,
        })
    }
}

impl CanonicalType for CashAuthorizationRequestV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// A strict canonical cash request plus its exact ML-DSA-44 authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedCashTransferV1 {
    request: CashAuthorizationRequestV1,
    signature: ProtocolSignature,
}

/// Operator-only faucet authorization bundle. The one-shot session grant and transfer are one
/// canonical value so durable settlement cannot replay or publish only half of the authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorFaucetAuthorizationV1 {
    session: AuthorizedCashSessionGrantV1,
    transfer: AuthorizedCashTransferV1,
}

impl OperatorFaucetAuthorizationV1 {
    pub const TYPE_TAG: u16 = 0x0151;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        AuthorizedCashSessionGrantV1::MAX_ENCODED_LEN + AuthorizedCashTransferV1::MAX_ENCODED_LEN;

    pub fn new(
        session: AuthorizedCashSessionGrantV1,
        transfer: AuthorizedCashTransferV1,
    ) -> Result<Self, WalletError> {
        if session.grant().chain_id() != transfer.request().chain_id()
            || session.grant().signer() != transfer.request().signer()
            || session.grant().session_id() != transfer.request().session_id()
            || session.grant().expires_at() < transfer.request().session_expires_at()
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self { session, transfer })
    }

    pub const fn session(&self) -> &AuthorizedCashSessionGrantV1 {
        &self.session
    }

    pub const fn transfer(&self) -> &AuthorizedCashTransferV1 {
        &self.transfer
    }
}

impl CanonicalEncode for OperatorFaucetAuthorizationV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.session.encode(encoder)?;
        self.transfer.encode(encoder)
    }
}

impl CanonicalDecode for OperatorFaucetAuthorizationV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AuthorizedCashSessionGrantV1::decode(decoder)?,
            AuthorizedCashTransferV1::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid operator faucet authorization"))
    }
}

impl CanonicalType for OperatorFaucetAuthorizationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

impl AuthorizedCashTransferV1 {
    pub const TYPE_TAG: u16 = 0x008b;
    pub const SCHEMA_VERSION: u16 = 2;
    pub const MAX_ENCODED_LEN: usize =
        CashAuthorizationRequestV1::MAX_ENCODED_LEN + ProtocolSignature::MAX_ENCODED_LEN;

    pub fn new(
        request: CashAuthorizationRequestV1,
        signature: ProtocolSignature,
    ) -> Result<Self, WalletError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(WalletError::InvalidSignature);
        }
        Ok(Self { request, signature })
    }

    #[must_use]
    pub const fn request(&self) -> &CashAuthorizationRequestV1 {
        &self.request
    }

    #[must_use]
    pub const fn signature(&self) -> &ProtocolSignature {
        &self.signature
    }

    pub fn verify(&self, public_key: &[u8]) -> Result<(), WalletError> {
        let payload =
            self.request.signing_payload().map_err(|_| WalletError::MalformedAuthorization)?;
        verify_ml_dsa(public_key, &self.signature, &payload)
    }
}

const DUTY_RECEIPT_SIGNING_DOMAIN: &[u8] = b"ACTIVECHAIN-DUTY-RECEIPT-ML-DSA-44-V1";

/// One verifier's claim that an assigned duty produced checkable evidence at a height.
///
/// The canonical value binds chain, assignment, verifier, evidence, and height so a signed
/// receipt cannot be replayed for another duty, verifier, or network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DutyReceiptV1 {
    chain_id: ChainId,
    assignment: Digest384,
    verifier: PrincipalId,
    evidence: Digest384,
    height: u64,
}

impl DutyReceiptV1 {
    pub const TYPE_TAG: u16 = 0x01AA;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 4 + 8;

    pub fn new(
        chain_id: ChainId,
        assignment: Digest384,
        verifier: PrincipalId,
        evidence: Digest384,
        height: u64,
    ) -> Result<Self, WalletError> {
        if assignment == Digest384::ZERO
            || evidence == Digest384::ZERO
            || *verifier.digest() == Digest384::ZERO
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self { chain_id, assignment, verifier, evidence, height })
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn assignment(&self) -> Digest384 {
        self.assignment
    }

    #[must_use]
    pub const fn verifier(&self) -> PrincipalId {
        self.verifier
    }

    #[must_use]
    pub const fn evidence(&self) -> Digest384 {
        self.evidence
    }

    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Returns the complete domain-separated canonical bytes that the verifier's key signs.
    pub fn signing_payload(&self) -> Result<Vec<u8>, EncodeError> {
        let encoded = encode_envelope(self)?;
        let mut payload = Vec::with_capacity(DUTY_RECEIPT_SIGNING_DOMAIN.len() + 8 + encoded.len());
        payload.extend_from_slice(DUTY_RECEIPT_SIGNING_DOMAIN);
        payload.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        payload.extend_from_slice(&encoded);
        Ok(payload)
    }
}

impl CanonicalEncode for DutyReceiptV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.assignment.encode(e)?;
        self.verifier.encode(e)?;
        self.evidence.encode(e)?;
        self.height.encode(e)
    }
}

impl CanonicalDecode for DutyReceiptV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid duty receipt"))
    }
}

impl CanonicalType for DutyReceiptV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// A duty receipt bound to exactly one ML-DSA-44 verifier signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedDutyReceiptV1 {
    receipt: DutyReceiptV1,
    signature: ProtocolSignature,
}

impl AuthorizedDutyReceiptV1 {
    pub const TYPE_TAG: u16 = 0x01AB;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        DutyReceiptV1::MAX_ENCODED_LEN + ProtocolSignature::MAX_ENCODED_LEN;

    pub fn new(receipt: DutyReceiptV1, signature: ProtocolSignature) -> Result<Self, WalletError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(WalletError::InvalidSignature);
        }
        Ok(Self { receipt, signature })
    }

    #[must_use]
    pub const fn receipt(&self) -> &DutyReceiptV1 {
        &self.receipt
    }

    /// Verifies the exact chain, verifier, and signature bindings for one settlement consumer.
    pub fn verify(
        &self,
        public_key: &[u8],
        chain_id: ChainId,
        verifier: PrincipalId,
    ) -> Result<(), WalletError> {
        if self.receipt.chain_id != chain_id || self.receipt.verifier != verifier {
            return Err(WalletError::MalformedAuthorization);
        }
        let payload =
            self.receipt.signing_payload().map_err(|_| WalletError::MalformedAuthorization)?;
        verify_ml_dsa(public_key, &self.signature, &payload)
    }
}

impl CanonicalEncode for AuthorizedDutyReceiptV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.receipt.encode(e)?;
        self.signature.encode(e)
    }
}

impl CanonicalDecode for AuthorizedDutyReceiptV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(DutyReceiptV1::decode(d)?, ProtocolSignature::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid authorized duty receipt"))
    }
}

impl CanonicalType for AuthorizedDutyReceiptV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}
const VERIFIER_BOND_SIGNING_DOMAIN: &[u8] = b"ACTIVECHAIN-VERIFIER-BOND-ML-DSA-44-V1";

fn role_code(role: VerifierRole) -> u8 {
    match role {
        VerifierRole::Finality => 0,
        VerifierRole::Availability => 1,
        VerifierRole::Audit => 2,
        VerifierRole::Assurance => 3,
        VerifierRole::PublicGoods => 4,
    }
}

fn role_from_code(code: u8) -> Result<VerifierRole, WalletError> {
    match code {
        0 => Ok(VerifierRole::Finality),
        1 => Ok(VerifierRole::Availability),
        2 => Ok(VerifierRole::Audit),
        3 => Ok(VerifierRole::Assurance),
        4 => Ok(VerifierRole::PublicGoods),
        _ => Err(WalletError::MalformedAuthorization),
    }
}

/// One verifier's offer to lock an exact bond Coin Cell behind an assigned duty role.
///
/// The canonical value binds chain, verifier, role, bond cell, amount, and expiry so a signed
/// registration cannot be replayed for another role, amount, network, or bond input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierBondRegistrationV1 {
    chain_id: ChainId,
    verifier: PrincipalId,
    role: VerifierRole,
    bond: CoinCellId,
    bond_amount: u128,
    valid_until: u64,
}

impl VerifierBondRegistrationV1 {
    pub const TYPE_TAG: u16 = 0x01AD;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 3 + 1 + 16 + 8;

    pub fn new(
        chain_id: ChainId,
        verifier: PrincipalId,
        role: VerifierRole,
        bond: CoinCellId,
        bond_amount: u128,
        valid_until: u64,
    ) -> Result<Self, WalletError> {
        if *verifier.digest() == Digest384::ZERO
            || *bond.digest() == Digest384::ZERO
            || bond_amount == 0
            || valid_until == 0
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self { chain_id, verifier, role, bond, bond_amount, valid_until })
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn verifier(&self) -> PrincipalId {
        self.verifier
    }

    #[must_use]
    pub const fn role(&self) -> VerifierRole {
        self.role
    }

    #[must_use]
    pub const fn bond(&self) -> CoinCellId {
        self.bond
    }

    #[must_use]
    pub const fn bond_amount(&self) -> u128 {
        self.bond_amount
    }

    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }

    /// Returns the complete domain-separated canonical bytes that the verifier's key signs.
    pub fn signing_payload(&self) -> Result<Vec<u8>, EncodeError> {
        let encoded = encode_envelope(self)?;
        let mut payload =
            Vec::with_capacity(VERIFIER_BOND_SIGNING_DOMAIN.len() + 8 + encoded.len());
        payload.extend_from_slice(VERIFIER_BOND_SIGNING_DOMAIN);
        payload.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        payload.extend_from_slice(&encoded);
        Ok(payload)
    }
}

impl CanonicalEncode for VerifierBondRegistrationV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.verifier.encode(e)?;
        role_code(self.role).encode(e)?;
        self.bond.encode(e)?;
        self.bond_amount.encode(e)?;
        self.valid_until.encode(e)
    }
}

impl CanonicalDecode for VerifierBondRegistrationV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(d)?;
        let verifier = PrincipalId::decode(d)?;
        let role = role_from_code(u8::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid verifier role"))?;
        Self::new(
            chain_id,
            verifier,
            role,
            CoinCellId::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid verifier bond registration"))
    }
}

impl CanonicalType for VerifierBondRegistrationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// A verifier bond registration bound to exactly one ML-DSA-44 signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedVerifierBondRegistrationV1 {
    registration: VerifierBondRegistrationV1,
    signature: ProtocolSignature,
}

impl AuthorizedVerifierBondRegistrationV1 {
    pub const TYPE_TAG: u16 = 0x01AE;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        VerifierBondRegistrationV1::MAX_ENCODED_LEN + ProtocolSignature::MAX_ENCODED_LEN;

    pub fn new(
        registration: VerifierBondRegistrationV1,
        signature: ProtocolSignature,
    ) -> Result<Self, WalletError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(WalletError::InvalidSignature);
        }
        Ok(Self { registration, signature })
    }

    #[must_use]
    pub const fn registration(&self) -> &VerifierBondRegistrationV1 {
        &self.registration
    }

    /// Verifies the exact chain, verifier, and signature bindings for one registry consumer.
    pub fn verify(
        &self,
        public_key: &[u8],
        chain_id: ChainId,
        verifier: PrincipalId,
    ) -> Result<(), WalletError> {
        if self.registration.chain_id != chain_id || self.registration.verifier != verifier {
            return Err(WalletError::MalformedAuthorization);
        }
        let payload =
            self.registration.signing_payload().map_err(|_| WalletError::MalformedAuthorization)?;
        verify_ml_dsa(public_key, &self.signature, &payload)
    }
}

impl CanonicalEncode for AuthorizedVerifierBondRegistrationV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.registration.encode(e)?;
        self.signature.encode(e)
    }
}

impl CanonicalDecode for AuthorizedVerifierBondRegistrationV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(VerifierBondRegistrationV1::decode(d)?, ProtocolSignature::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid authorized bond registration"))
    }
}

impl CanonicalType for AuthorizedVerifierBondRegistrationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

fn verify_ml_dsa(
    public_key: &[u8],
    signature: &ProtocolSignature,
    payload: &[u8],
) -> Result<(), WalletError> {
    let key: EncodedVerifyingKey<MlDsa44> =
        public_key.try_into().map_err(|_| WalletError::InvalidAuthorizationKey)?;
    let signature: EncodedSignature<MlDsa44> =
        signature.as_bytes().try_into().map_err(|_| WalletError::InvalidSignature)?;
    let key = VerifyingKey::<MlDsa44>::decode(&key);
    let signature =
        Signature::<MlDsa44>::decode(&signature).ok_or(WalletError::InvalidSignature)?;
    key.verify(payload, &signature).map_err(|_| WalletError::InvalidSignature)
}

impl CanonicalEncode for AuthorizedCashTransferV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.request.encode(encoder)?;
        self.signature.encode(encoder)
    }
}

impl CanonicalDecode for AuthorizedCashTransferV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let request = CashAuthorizationRequestV1::decode(decoder)?;
        let signature = ProtocolSignature::decode(decoder)?;
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(DecodeError::InvalidValue(
                "cash authorization requires the ML-DSA-44 suite",
            ));
        }
        Ok(Self { request, signature })
    }
}

impl CanonicalType for AuthorizedCashTransferV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Derives the protocol recipient binding used by both policy checks and signed cash requests.
#[must_use]
pub fn recipient_commitment(recipient: PrincipalId) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(RECIPIENT_COMMITMENT_DOMAIN);
    hasher.update(recipient.digest().as_bytes());
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}
