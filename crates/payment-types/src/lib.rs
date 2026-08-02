#![no_std]
#![forbid(unsafe_code)]

//! Provider-independent, bounded payment values for ActiveBridge.
//!
//! This crate deliberately contains no networking, provider JSON, secret handling, balance
//! mutation, or consensus integration. It freezes the canonical values shared by those later
//! layers and keeps external observations distinct from finalized ActiveChain evidence.

extern crate alloc;

use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    encode_envelope,
};
use activechain_protocol_types::{
    AssetId, ChainId, CryptoSuiteId, Digest384, ML_DSA44_PUBLIC_KEY_LENGTH, PrincipalId,
    ProtocolSignature, TransactionId,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

/// ActiveBridge schema revision implemented by this crate.
pub const PAYMENT_SCHEMA_REVISION: u16 = 1;

macro_rules! payment_identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(Digest384);

        impl $name {
            /// Constructs a nonzero identifier.
            pub fn new(digest: Digest384) -> Result<Self, PaymentValidationError> {
                if digest == Digest384::ZERO {
                    return Err(PaymentValidationError::ZeroIdentifier);
                }
                Ok(Self(digest))
            }

            /// Returns the identifier commitment.
            #[must_use]
            pub const fn digest(&self) -> Digest384 {
                self.0
            }
        }

        impl CanonicalEncode for $name {
            fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
                self.0.encode(encoder)
            }
        }

        impl CanonicalDecode for $name {
            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                Self::new(Digest384::decode(decoder)?)
                    .map_err(|_| DecodeError::InvalidValue("zero payment identifier"))
            }
        }
    };
}

payment_identifier!(PaymentIntentId, "A network-bound canonical payment intent identifier.");
payment_identifier!(PaymentQuoteId, "A canonical bounded quote identifier.");
payment_identifier!(PaymentAttemptId, "One provider attempt under a payment intent.");
payment_identifier!(ConnectorId, "An operator-registered connector identifier.");
payment_identifier!(RailId, "An operator-registered collection or payout rail.");
payment_identifier!(TreasuryId, "A native merchant treasury object identifier.");
payment_identifier!(PaymentRefundId, "One exact refund request under a finalized payment.");
payment_identifier!(PaymentDisputeId, "One exact dispute under a finalized payment.");
payment_identifier!(PaymentWebhookSubscriptionId, "One authenticated webhook subscription.");
payment_identifier!(PaymentWebhookEventId, "One immutable webhook delivery event.");

/// A validation failure for a canonical payment value or lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentValidationError {
    /// An identifier or mandatory commitment was zero.
    ZeroIdentifier,
    /// An amount required to be positive was zero.
    ZeroAmount,
    /// Two related amounts used different assets.
    AssetMismatch,
    /// A bounded amount relationship was inverted.
    InvalidAmountBound,
    /// A fee total overflowed or exceeded the settlement amount.
    InvalidFees,
    /// A rational exchange rate had a zero term.
    InvalidExchangeRate,
    /// A validity interval was empty or inverted.
    InvalidValidity,
    /// The quote or intent was not bound to the expected parties or policy.
    InvalidBinding,
    /// A lifecycle edge is not permitted.
    InvalidTransition,
    /// A lifecycle sequence did not advance by exactly one.
    InvalidSequence,
    /// Evidence fields do not match the declared lifecycle state.
    InvalidEvidence,
    /// Reusing an idempotency key changed the request body.
    IdempotencyConflict,
}

/// An exact quantity of one native ActiveChain asset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssetAmountV1 {
    asset: AssetId,
    atomic_units: u128,
}

impl AssetAmountV1 {
    /// Constructs a positive asset amount.
    pub fn new(asset: AssetId, atomic_units: u128) -> Result<Self, PaymentValidationError> {
        if asset.digest() == &Digest384::ZERO {
            return Err(PaymentValidationError::ZeroIdentifier);
        }
        if atomic_units == 0 {
            return Err(PaymentValidationError::ZeroAmount);
        }
        Ok(Self { asset, atomic_units })
    }

    /// Returns the exact asset identifier.
    #[must_use]
    pub const fn asset(&self) -> AssetId {
        self.asset
    }

    /// Returns the quantity in registry-defined atomic units.
    #[must_use]
    pub const fn atomic_units(&self) -> u128 {
        self.atomic_units
    }
}

impl CanonicalEncode for AssetAmountV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.asset.encode(encoder)?;
        self.atomic_units.encode(encoder)
    }
}

impl CanonicalDecode for AssetAmountV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(AssetId::decode(decoder)?, u128::decode(decoder)?)
            .map_err(|_| DecodeError::InvalidValue("invalid asset amount"))
    }
}

/// Assurance attached to an observation. Ordering does not imply automatic promotion.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EvidenceClass {
    /// A client supplied an unverified report.
    UntrustedClientReport = 0,
    /// A configured connector authenticated the observation.
    ConnectorAuthenticated = 1,
    /// The upstream provider signed the exact observation.
    ProviderSigned = 2,
    /// A regulated or audited attestation accepted by asset policy.
    RegulatedAttestation = 3,
    /// The exact transition finalized under trusted ActiveChain parameters.
    ActiveChainFinalized = 4,
}

impl CanonicalEncode for EvidenceClass {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for EvidenceClass {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::UntrustedClientReport),
            1 => Ok(Self::ConnectorAuthenticated),
            2 => Ok(Self::ProviderSigned),
            3 => Ok(Self::RegulatedAttestation),
            4 => Ok(Self::ActiveChainFinalized),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "EvidenceClass", tag }),
        }
    }
}

/// Provider-facing operation states normalized without claiming chain finality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProviderOperationState {
    Pending = 0,
    Succeeded = 1,
    Rejected = 2,
    Reversed = 3,
    Cancelled = 4,
    Unknown = 5,
}

impl CanonicalEncode for ProviderOperationState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for ProviderOperationState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Succeeded),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Reversed),
            4 => Ok(Self::Cancelled),
            5 => Ok(Self::Unknown),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ProviderOperationState", tag }),
        }
    }
}

/// One authenticated, replay-bounded external-provider observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderObservationV1 {
    chain: ChainId,
    connector: ConnectorId,
    attempt: PaymentAttemptId,
    intent: PaymentIntentId,
    provider_account_commitment: Digest384,
    provider_reference_commitment: Digest384,
    sequence: u64,
    state: ProviderOperationState,
    amount: AssetAmountV1,
    occurred_at: u64,
    observed_at: u64,
    evidence_class: EvidenceClass,
    payload_commitment: Digest384,
}

impl ProviderObservationV1 {
    /// Constructs an observation. Provider time may not be after connector observation time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: ChainId,
        connector: ConnectorId,
        attempt: PaymentAttemptId,
        intent: PaymentIntentId,
        provider_account_commitment: Digest384,
        provider_reference_commitment: Digest384,
        sequence: u64,
        state: ProviderOperationState,
        amount: AssetAmountV1,
        occurred_at: u64,
        observed_at: u64,
        evidence_class: EvidenceClass,
        payload_commitment: Digest384,
    ) -> Result<Self, PaymentValidationError> {
        if chain.digest() == &Digest384::ZERO
            || provider_account_commitment == Digest384::ZERO
            || provider_reference_commitment == Digest384::ZERO
            || payload_commitment == Digest384::ZERO
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if sequence == 0 || occurred_at == 0 || occurred_at > observed_at {
            return Err(PaymentValidationError::InvalidSequence);
        }
        if matches!(
            evidence_class,
            EvidenceClass::UntrustedClientReport | EvidenceClass::ActiveChainFinalized
        ) {
            return Err(PaymentValidationError::InvalidEvidence);
        }
        Ok(Self {
            chain,
            connector,
            attempt,
            intent,
            provider_account_commitment,
            provider_reference_commitment,
            sequence,
            state,
            amount,
            occurred_at,
            observed_at,
            evidence_class,
            payload_commitment,
        })
    }

    /// Validates exact replay or the next provider sequence for the same bound operation.
    pub fn compare_successor(&self, next: &Self) -> Result<bool, PaymentValidationError> {
        if self == next {
            return Ok(false);
        }
        if self.chain != next.chain
            || self.connector != next.connector
            || self.attempt != next.attempt
            || self.intent != next.intent
            || self.provider_account_commitment != next.provider_account_commitment
            || self.provider_reference_commitment != next.provider_reference_commitment
            || self.amount.asset() != next.amount.asset()
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if self.sequence.checked_add(1) != Some(next.sequence)
            || next.observed_at < self.observed_at
        {
            return Err(PaymentValidationError::InvalidSequence);
        }
        Ok(true)
    }

    #[must_use]
    pub const fn attempt(&self) -> PaymentAttemptId {
        self.attempt
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn state(&self) -> ProviderOperationState {
        self.state
    }

    /// Returns the assurance class without promoting it to chain finality.
    #[must_use]
    pub const fn evidence_class(&self) -> EvidenceClass {
        self.evidence_class
    }
}

impl CanonicalEncode for ProviderObservationV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain.encode(encoder)?;
        self.connector.encode(encoder)?;
        self.attempt.encode(encoder)?;
        self.intent.encode(encoder)?;
        self.provider_account_commitment.encode(encoder)?;
        self.provider_reference_commitment.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.state.encode(encoder)?;
        self.amount.encode(encoder)?;
        self.occurred_at.encode(encoder)?;
        self.observed_at.encode(encoder)?;
        self.evidence_class.encode(encoder)?;
        self.payload_commitment.encode(encoder)
    }
}

impl CanonicalDecode for ProviderObservationV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(decoder)?,
            ConnectorId::decode(decoder)?,
            PaymentAttemptId::decode(decoder)?,
            PaymentIntentId::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            ProviderOperationState::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            EvidenceClass::decode(decoder)?,
            Digest384::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid provider observation"))
    }
}

impl CanonicalType for ProviderObservationV1 {
    const TYPE_TAG: u16 = 0x0141;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 592;
}

/// A signed, expiry-bounded conversion and settlement quote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentQuoteV1 {
    chain: ChainId,
    quote: PaymentQuoteId,
    merchant: PrincipalId,
    connector: ConnectorId,
    source_rail: RailId,
    source_amount: AssetAmountV1,
    settlement_amount: AssetAmountV1,
    provider_fee: AssetAmountV1,
    connector_fee: AssetAmountV1,
    network_fee_limit: AssetAmountV1,
    exchange_rate_numerator: u128,
    exchange_rate_denominator: u128,
    asset_policy_revision: Digest384,
    valid_from: u64,
    expires_at: u64,
    nonce: Digest384,
    terms_commitment: Digest384,
}

impl PaymentQuoteV1 {
    /// Validates all quote bounds and exact fee-asset binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: ChainId,
        quote: PaymentQuoteId,
        merchant: PrincipalId,
        connector: ConnectorId,
        source_rail: RailId,
        source_amount: AssetAmountV1,
        settlement_amount: AssetAmountV1,
        provider_fee: AssetAmountV1,
        connector_fee: AssetAmountV1,
        network_fee_limit: AssetAmountV1,
        exchange_rate_numerator: u128,
        exchange_rate_denominator: u128,
        asset_policy_revision: Digest384,
        valid_from: u64,
        expires_at: u64,
        nonce: Digest384,
        terms_commitment: Digest384,
    ) -> Result<Self, PaymentValidationError> {
        if chain.digest() == &Digest384::ZERO
            || merchant.digest() == &Digest384::ZERO
            || asset_policy_revision == Digest384::ZERO
            || nonce == Digest384::ZERO
            || terms_commitment == Digest384::ZERO
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if valid_from >= expires_at {
            return Err(PaymentValidationError::InvalidValidity);
        }
        if exchange_rate_numerator == 0 || exchange_rate_denominator == 0 {
            return Err(PaymentValidationError::InvalidExchangeRate);
        }
        let settlement_asset = settlement_amount.asset();
        if provider_fee.asset() != settlement_asset
            || connector_fee.asset() != settlement_asset
            || network_fee_limit.asset() != settlement_asset
        {
            return Err(PaymentValidationError::AssetMismatch);
        }
        let fees = provider_fee
            .atomic_units()
            .checked_add(connector_fee.atomic_units())
            .and_then(|total| total.checked_add(network_fee_limit.atomic_units()))
            .ok_or(PaymentValidationError::InvalidFees)?;
        if fees >= settlement_amount.atomic_units() {
            return Err(PaymentValidationError::InvalidFees);
        }
        Ok(Self {
            chain,
            quote,
            merchant,
            connector,
            source_rail,
            source_amount,
            settlement_amount,
            provider_fee,
            connector_fee,
            network_fee_limit,
            exchange_rate_numerator,
            exchange_rate_denominator,
            asset_policy_revision,
            valid_from,
            expires_at,
            nonce,
            terms_commitment,
        })
    }

    /// Returns the quote identifier.
    #[must_use]
    pub const fn quote(&self) -> PaymentQuoteId {
        self.quote
    }

    /// Returns the network binding.
    #[must_use]
    pub const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Returns the merchant principal.
    #[must_use]
    pub const fn merchant(&self) -> PrincipalId {
        self.merchant
    }

    /// Returns the exact settlement amount before explicit fees.
    #[must_use]
    pub const fn settlement_amount(&self) -> AssetAmountV1 {
        self.settlement_amount
    }

    /// Returns the exclusive quote expiry.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl CanonicalEncode for PaymentQuoteV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain.encode(encoder)?;
        self.quote.encode(encoder)?;
        self.merchant.encode(encoder)?;
        self.connector.encode(encoder)?;
        self.source_rail.encode(encoder)?;
        self.source_amount.encode(encoder)?;
        self.settlement_amount.encode(encoder)?;
        self.provider_fee.encode(encoder)?;
        self.connector_fee.encode(encoder)?;
        self.network_fee_limit.encode(encoder)?;
        self.exchange_rate_numerator.encode(encoder)?;
        self.exchange_rate_denominator.encode(encoder)?;
        self.asset_policy_revision.encode(encoder)?;
        self.valid_from.encode(encoder)?;
        self.expires_at.encode(encoder)?;
        self.nonce.encode(encoder)?;
        self.terms_commitment.encode(encoder)
    }
}

impl CanonicalDecode for PaymentQuoteV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(decoder)?,
            PaymentQuoteId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            ConnectorId::decode(decoder)?,
            RailId::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            u128::decode(decoder)?,
            u128::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment quote"))
    }
}

impl CanonicalType for PaymentQuoteV1 {
    const TYPE_TAG: u16 = 0x013d;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 784;
}

/// An application-authorized request to settle a specific quote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentIntentV1 {
    chain: ChainId,
    intent: PaymentIntentId,
    merchant: PrincipalId,
    treasury: TreasuryId,
    payer_reference_commitment: Digest384,
    quote_commitment: Digest384,
    requested_settlement: AssetAmountV1,
    minimum_settlement: AssetAmountV1,
    expires_at: u64,
    idempotency_key: Digest384,
    authorization_context: Digest384,
    disclosure_policy: Digest384,
    callback_commitment: Digest384,
    metadata_commitment: Digest384,
}

impl PaymentIntentV1 {
    /// Constructs an intent whose minimum output cannot exceed the requested settlement.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: ChainId,
        intent: PaymentIntentId,
        merchant: PrincipalId,
        treasury: TreasuryId,
        payer_reference_commitment: Digest384,
        quote_commitment: Digest384,
        requested_settlement: AssetAmountV1,
        minimum_settlement: AssetAmountV1,
        expires_at: u64,
        idempotency_key: Digest384,
        authorization_context: Digest384,
        disclosure_policy: Digest384,
        callback_commitment: Digest384,
        metadata_commitment: Digest384,
    ) -> Result<Self, PaymentValidationError> {
        if chain.digest() == &Digest384::ZERO
            || merchant.digest() == &Digest384::ZERO
            || payer_reference_commitment == Digest384::ZERO
            || quote_commitment == Digest384::ZERO
            || idempotency_key == Digest384::ZERO
            || authorization_context == Digest384::ZERO
            || disclosure_policy == Digest384::ZERO
            || callback_commitment == Digest384::ZERO
            || metadata_commitment == Digest384::ZERO
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if expires_at == 0 {
            return Err(PaymentValidationError::InvalidValidity);
        }
        if requested_settlement.asset() != minimum_settlement.asset() {
            return Err(PaymentValidationError::AssetMismatch);
        }
        if minimum_settlement.atomic_units() > requested_settlement.atomic_units() {
            return Err(PaymentValidationError::InvalidAmountBound);
        }
        Ok(Self {
            chain,
            intent,
            merchant,
            treasury,
            payer_reference_commitment,
            quote_commitment,
            requested_settlement,
            minimum_settlement,
            expires_at,
            idempotency_key,
            authorization_context,
            disclosure_policy,
            callback_commitment,
            metadata_commitment,
        })
    }

    /// Returns the intent identifier.
    #[must_use]
    pub const fn intent(&self) -> PaymentIntentId {
        self.intent
    }

    /// Returns the merchant that owns this request and its idempotency namespace.
    #[must_use]
    pub const fn merchant(&self) -> PrincipalId {
        self.merchant
    }

    /// Returns the caller-chosen idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Digest384 {
        self.idempotency_key
    }

    /// Returns the minimum acceptable output.
    #[must_use]
    pub const fn minimum_settlement(&self) -> AssetAmountV1 {
        self.minimum_settlement
    }

    /// Returns the requested settlement upper bound.
    #[must_use]
    pub const fn requested_settlement(&self) -> AssetAmountV1 {
        self.requested_settlement
    }

    /// Checks the exact native asset and negotiated settlement range.
    #[must_use]
    pub fn accepts_settlement(&self, amount: AssetAmountV1) -> bool {
        amount.asset().digest() == self.requested_settlement.asset().digest()
            && amount.atomic_units() >= self.minimum_settlement.atomic_units()
            && amount.atomic_units() <= self.requested_settlement.atomic_units()
    }

    /// Returns whether the intent remains eligible for initial admission.
    #[must_use]
    pub const fn active_at(&self, timestamp: u64) -> bool {
        timestamp < self.expires_at
    }

    /// Commits to the exact canonical intent body for durable idempotency binding.
    pub fn commitment(&self) -> Result<Digest384, PaymentValidationError> {
        let bytes = encode_envelope(self).map_err(|_| PaymentValidationError::InvalidBinding)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-PAYMENT-INTENT-V1");
        hasher.update(&bytes);
        let mut output = [0_u8; 48];
        hasher.finalize_xof().read(&mut output);
        Ok(Digest384::new(output))
    }
}

impl CanonicalEncode for PaymentIntentV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain.encode(encoder)?;
        self.intent.encode(encoder)?;
        self.merchant.encode(encoder)?;
        self.treasury.encode(encoder)?;
        self.payer_reference_commitment.encode(encoder)?;
        self.quote_commitment.encode(encoder)?;
        self.requested_settlement.encode(encoder)?;
        self.minimum_settlement.encode(encoder)?;
        self.expires_at.encode(encoder)?;
        self.idempotency_key.encode(encoder)?;
        self.authorization_context.encode(encoder)?;
        self.disclosure_policy.encode(encoder)?;
        self.callback_commitment.encode(encoder)?;
        self.metadata_commitment.encode(encoder)
    }
}

impl CanonicalDecode for PaymentIntentV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(decoder)?,
            PaymentIntentId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            TreasuryId::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            u64::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment intent"))
    }
}

impl CanonicalType for PaymentIntentV1 {
    const TYPE_TAG: u16 = 0x013e;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 736;
}

/// Canonical payment lifecycle states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PaymentState {
    Created = 0,
    AwaitingPayer = 1,
    ProviderPending = 2,
    ExternallyConfirmed = 3,
    ChainSubmitted = 4,
    Finalized = 5,
    RefundPending = 6,
    Refunded = 7,
    Expired = 8,
    Rejected = 9,
    Failed = 10,
    Cancelled = 11,
    ManualReview = 12,
}

impl PaymentState {
    /// Returns whether no later state is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Refunded | Self::Expired | Self::Rejected | Self::Failed | Self::Cancelled
        )
    }

    /// Returns whether `next` is a permitted direct transition.
    #[must_use]
    pub const fn permits(self, next: Self) -> bool {
        match self {
            Self::Created => matches!(next, Self::AwaitingPayer | Self::Cancelled | Self::Expired),
            Self::AwaitingPayer => {
                matches!(
                    next,
                    Self::ProviderPending | Self::Cancelled | Self::Expired | Self::Rejected
                )
            }
            Self::ProviderPending => {
                matches!(
                    next,
                    Self::ExternallyConfirmed | Self::Failed | Self::Expired | Self::ManualReview
                )
            }
            Self::ExternallyConfirmed => {
                matches!(next, Self::ChainSubmitted | Self::Failed | Self::ManualReview)
            }
            Self::ChainSubmitted => {
                matches!(next, Self::Finalized | Self::Rejected | Self::Failed | Self::ManualReview)
            }
            Self::Finalized => matches!(next, Self::RefundPending),
            Self::RefundPending => {
                matches!(next, Self::Refunded | Self::Failed | Self::ManualReview)
            }
            Self::ManualReview => matches!(
                next,
                Self::ProviderPending
                    | Self::ExternallyConfirmed
                    | Self::ChainSubmitted
                    | Self::RefundPending
                    | Self::Rejected
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::Refunded | Self::Expired | Self::Rejected | Self::Failed | Self::Cancelled => {
                false
            }
        }
    }
}

impl CanonicalEncode for PaymentState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for PaymentState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Created),
            1 => Ok(Self::AwaitingPayer),
            2 => Ok(Self::ProviderPending),
            3 => Ok(Self::ExternallyConfirmed),
            4 => Ok(Self::ChainSubmitted),
            5 => Ok(Self::Finalized),
            6 => Ok(Self::RefundPending),
            7 => Ok(Self::Refunded),
            8 => Ok(Self::Expired),
            9 => Ok(Self::Rejected),
            10 => Ok(Self::Failed),
            11 => Ok(Self::Cancelled),
            12 => Ok(Self::ManualReview),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "PaymentState", tag }),
        }
    }
}

/// One monotonic, evidence-bound lifecycle observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentLifecycleRecordV1 {
    intent: PaymentIntentId,
    sequence: u64,
    state: PaymentState,
    evidence_class: EvidenceClass,
    observation_commitment: Digest384,
    transaction: Option<TransactionId>,
    finalized_height: u64,
    finalized_block: Option<Digest384>,
    reason_code: u16,
}

impl PaymentLifecycleRecordV1 {
    /// Constructs a lifecycle record and rejects false finality.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent: PaymentIntentId,
        sequence: u64,
        state: PaymentState,
        evidence_class: EvidenceClass,
        observation_commitment: Digest384,
        transaction: Option<TransactionId>,
        finalized_height: u64,
        finalized_block: Option<Digest384>,
        reason_code: u16,
    ) -> Result<Self, PaymentValidationError> {
        if sequence == 0 || observation_commitment == Digest384::ZERO {
            return Err(PaymentValidationError::InvalidEvidence);
        }
        let has_transaction = transaction.is_some();
        let has_finality = finalized_height > 0 && finalized_block.is_some();
        let finalized_state = matches!(state, PaymentState::Finalized | PaymentState::Refunded);
        if finalized_state {
            if evidence_class != EvidenceClass::ActiveChainFinalized
                || !has_transaction
                || !has_finality
            {
                return Err(PaymentValidationError::InvalidEvidence);
            }
        } else if evidence_class == EvidenceClass::ActiveChainFinalized
            || finalized_height != 0
            || finalized_block.is_some()
            || (state == PaymentState::ChainSubmitted && !has_transaction)
            || (state != PaymentState::ChainSubmitted && has_transaction)
        {
            return Err(PaymentValidationError::InvalidEvidence);
        }
        if finalized_block == Some(Digest384::ZERO)
            || transaction.is_some_and(|value| value.digest() == &Digest384::ZERO)
        {
            return Err(PaymentValidationError::InvalidEvidence);
        }
        Ok(Self {
            intent,
            sequence,
            state,
            evidence_class,
            observation_commitment,
            transaction,
            finalized_height,
            finalized_block,
            reason_code,
        })
    }

    /// Creates the initial record.
    pub fn created(
        intent: PaymentIntentId,
        observation_commitment: Digest384,
    ) -> Result<Self, PaymentValidationError> {
        Self::new(
            intent,
            1,
            PaymentState::Created,
            EvidenceClass::UntrustedClientReport,
            observation_commitment,
            None,
            0,
            None,
            0,
        )
    }

    /// Validates an exact next record.
    pub fn validate_successor(&self, next: &Self) -> Result<(), PaymentValidationError> {
        if self.intent != next.intent {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if self.sequence.checked_add(1) != Some(next.sequence) {
            return Err(PaymentValidationError::InvalidSequence);
        }
        if !self.state.permits(next.state) {
            return Err(PaymentValidationError::InvalidTransition);
        }
        if self.state == PaymentState::ChainSubmitted
            && next.state == PaymentState::Finalized
            && self.transaction != next.transaction
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        Ok(())
    }

    /// Returns the intent identifier.
    #[must_use]
    pub const fn intent(&self) -> PaymentIntentId {
        self.intent
    }

    /// Returns the monotonic sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the state.
    #[must_use]
    pub const fn state(&self) -> PaymentState {
        self.state
    }

    /// Returns the assurance class without promoting it.
    #[must_use]
    pub const fn evidence_class(&self) -> EvidenceClass {
        self.evidence_class
    }

    /// Returns the exact evidence commitment carried by this lifecycle record.
    #[must_use]
    pub const fn observation_commitment(&self) -> Digest384 {
        self.observation_commitment
    }
}

impl CanonicalEncode for PaymentLifecycleRecordV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.intent.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.state.encode(encoder)?;
        self.evidence_class.encode(encoder)?;
        self.observation_commitment.encode(encoder)?;
        self.transaction.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        self.finalized_block.encode(encoder)?;
        self.reason_code.encode(encoder)
    }
}

impl CanonicalDecode for PaymentLifecycleRecordV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PaymentIntentId::decode(decoder)?,
            u64::decode(decoder)?,
            PaymentState::decode(decoder)?,
            EvidenceClass::decode(decoder)?,
            Digest384::decode(decoder)?,
            Option::<TransactionId>::decode(decoder)?,
            u64::decode(decoder)?,
            Option::<Digest384>::decode(decoder)?,
            u16::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment lifecycle record"))
    }
}

impl CanonicalType for PaymentLifecycleRecordV1 {
    const TYPE_TAG: u16 = 0x013f;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 264;
}

/// Exact proof-bearing native settlement facts used to construct a finalized lifecycle successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaymentFinalizedSettlementV1 {
    intent: PaymentIntentId,
    transaction: TransactionId,
    settled_amount: AssetAmountV1,
    finalized_height: u64,
    finalized_block: Digest384,
    receipt_commitment: Digest384,
    proof_commitment: Digest384,
}

impl PaymentFinalizedSettlementV1 {
    pub const TYPE_TAG: u16 = 0x0188;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent: PaymentIntentId,
        transaction: TransactionId,
        settled_amount: AssetAmountV1,
        finalized_height: u64,
        finalized_block: Digest384,
        receipt_commitment: Digest384,
        proof_commitment: Digest384,
    ) -> Result<Self, PaymentValidationError> {
        if transaction.digest() == &Digest384::ZERO
            || finalized_height == 0
            || finalized_block == Digest384::ZERO
            || receipt_commitment == Digest384::ZERO
            || proof_commitment == Digest384::ZERO
        {
            return Err(PaymentValidationError::InvalidEvidence);
        }
        Ok(Self {
            intent,
            transaction,
            settled_amount,
            finalized_height,
            finalized_block,
            receipt_commitment,
            proof_commitment,
        })
    }

    pub const fn intent(&self) -> PaymentIntentId {
        self.intent
    }

    pub const fn settled_amount(&self) -> AssetAmountV1 {
        self.settled_amount
    }

    pub const fn transaction(&self) -> TransactionId {
        self.transaction
    }

    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    pub const fn finalized_block(&self) -> Digest384 {
        self.finalized_block
    }

    pub const fn receipt_commitment(&self) -> Digest384 {
        self.receipt_commitment
    }

    pub const fn proof_commitment(&self) -> Digest384 {
        self.proof_commitment
    }

    pub fn commitment(&self) -> Result<Digest384, PaymentValidationError> {
        let bytes = encode_envelope(self).map_err(|_| PaymentValidationError::InvalidEvidence)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-PAYMENT-FINALIZED-SETTLEMENT-V1");
        hasher.update(&bytes);
        let mut output = [0_u8; 48];
        hasher.finalize_xof().read(&mut output);
        Ok(Digest384::new(output))
    }

    pub fn finalized_record(
        &self,
        sequence: u64,
    ) -> Result<PaymentLifecycleRecordV1, PaymentValidationError> {
        PaymentLifecycleRecordV1::new(
            self.intent,
            sequence,
            PaymentState::Finalized,
            EvidenceClass::ActiveChainFinalized,
            self.commitment()?,
            Some(self.transaction),
            self.finalized_height,
            Some(self.finalized_block),
            0,
        )
    }
}

/// Commits the exact canonical finality-bundle bytes consumed by the shared verifier.
#[must_use]
pub fn payment_finality_proof_commitment(finality: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-PAYMENT-FINALITY-PROOF-V1");
    hasher.update(&(finality.len() as u64).to_be_bytes());
    hasher.update(finality);
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

impl CanonicalEncode for PaymentFinalizedSettlementV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.intent.encode(encoder)?;
        self.transaction.encode(encoder)?;
        self.settled_amount.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        self.finalized_block.encode(encoder)?;
        self.receipt_commitment.encode(encoder)?;
        self.proof_commitment.encode(encoder)
    }
}

impl CanonicalDecode for PaymentFinalizedSettlementV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PaymentIntentId::decode(decoder)?,
            TransactionId::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            u64::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid finalized payment settlement"))
    }
}

impl CanonicalType for PaymentFinalizedSettlementV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 48 * 6 + 16 + 8;
}

/// Finalized ActiveChain evidence for one complete payment refund.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaymentFinalizedRefundV1 {
    refund: PaymentRefundId,
    intent: PaymentIntentId,
    settlement_commitment: Digest384,
    refunded_amount: AssetAmountV1,
    transaction: TransactionId,
    finalized_height: u64,
    finalized_block: Digest384,
    receipt_commitment: Digest384,
    proof_commitment: Digest384,
}

impl PaymentFinalizedRefundV1 {
    pub const TYPE_TAG: u16 = 0x018D;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        refund: PaymentRefundId,
        intent: PaymentIntentId,
        settlement_commitment: Digest384,
        refunded_amount: AssetAmountV1,
        transaction: TransactionId,
        finalized_height: u64,
        finalized_block: Digest384,
        receipt_commitment: Digest384,
        proof_commitment: Digest384,
    ) -> Result<Self, PaymentValidationError> {
        if settlement_commitment == Digest384::ZERO
            || transaction.digest() == &Digest384::ZERO
            || finalized_height == 0
            || finalized_block == Digest384::ZERO
            || receipt_commitment == Digest384::ZERO
            || proof_commitment == Digest384::ZERO
        {
            return Err(PaymentValidationError::InvalidEvidence);
        }
        Ok(Self {
            refund,
            intent,
            settlement_commitment,
            refunded_amount,
            transaction,
            finalized_height,
            finalized_block,
            receipt_commitment,
            proof_commitment,
        })
    }

    pub const fn refund(&self) -> PaymentRefundId {
        self.refund
    }
    pub const fn intent(&self) -> PaymentIntentId {
        self.intent
    }
    pub const fn settlement_commitment(&self) -> Digest384 {
        self.settlement_commitment
    }
    pub const fn refunded_amount(&self) -> AssetAmountV1 {
        self.refunded_amount
    }
    pub const fn transaction(&self) -> TransactionId {
        self.transaction
    }
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }
    pub const fn finalized_block(&self) -> Digest384 {
        self.finalized_block
    }
    pub const fn receipt_commitment(&self) -> Digest384 {
        self.receipt_commitment
    }
    pub const fn proof_commitment(&self) -> Digest384 {
        self.proof_commitment
    }

    pub fn commitment(&self) -> Result<Digest384, PaymentValidationError> {
        let bytes = encode_envelope(self).map_err(|_| PaymentValidationError::InvalidEvidence)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-PAYMENT-FINALIZED-REFUND-V1");
        hasher.update(&bytes);
        let mut output = [0_u8; 48];
        hasher.finalize_xof().read(&mut output);
        Ok(Digest384::new(output))
    }

    pub fn refunded_record(
        &self,
        sequence: u64,
    ) -> Result<PaymentLifecycleRecordV1, PaymentValidationError> {
        PaymentLifecycleRecordV1::new(
            self.intent,
            sequence,
            PaymentState::Refunded,
            EvidenceClass::ActiveChainFinalized,
            self.commitment()?,
            Some(self.transaction),
            self.finalized_height,
            Some(self.finalized_block),
            0,
        )
    }
}

impl CanonicalEncode for PaymentFinalizedRefundV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.refund.encode(encoder)?;
        self.intent.encode(encoder)?;
        self.settlement_commitment.encode(encoder)?;
        self.refunded_amount.encode(encoder)?;
        self.transaction.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        self.finalized_block.encode(encoder)?;
        self.receipt_commitment.encode(encoder)?;
        self.proof_commitment.encode(encoder)
    }
}

impl CanonicalDecode for PaymentFinalizedRefundV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PaymentRefundId::decode(decoder)?,
            PaymentIntentId::decode(decoder)?,
            Digest384::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            TransactionId::decode(decoder)?,
            u64::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid finalized payment refund"))
    }
}

impl CanonicalType for PaymentFinalizedRefundV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 408;
}

/// One bounded delivery of an exact lifecycle record to an authenticated subscriber.
///
/// The signing transcript authenticates transport delivery only. It never changes the embedded
/// record's evidence class or promotes external evidence to ActiveChain finality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentWebhookEventV1 {
    subscription: PaymentWebhookSubscriptionId,
    event: PaymentWebhookEventId,
    record: PaymentLifecycleRecordV1,
    payload_commitment: Digest384,
    signing_transcript_commitment: Digest384,
    emitted_at: u64,
    expires_at: u64,
}

impl PaymentWebhookEventV1 {
    pub const TYPE_TAG: u16 = 0x0168;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subscription: PaymentWebhookSubscriptionId,
        event: PaymentWebhookEventId,
        record: PaymentLifecycleRecordV1,
        payload_commitment: Digest384,
        signing_transcript_commitment: Digest384,
        emitted_at: u64,
        expires_at: u64,
    ) -> Result<Self, PaymentValidationError> {
        if payload_commitment == Digest384::ZERO || signing_transcript_commitment == Digest384::ZERO
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if emitted_at >= expires_at {
            return Err(PaymentValidationError::InvalidValidity);
        }
        Ok(Self {
            subscription,
            event,
            record,
            payload_commitment,
            signing_transcript_commitment,
            emitted_at,
            expires_at,
        })
    }

    #[must_use]
    pub const fn subscription(&self) -> PaymentWebhookSubscriptionId {
        self.subscription
    }

    #[must_use]
    pub const fn event(&self) -> PaymentWebhookEventId {
        self.event
    }

    #[must_use]
    pub const fn intent(&self) -> PaymentIntentId {
        self.record.intent()
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.record.sequence()
    }

    #[must_use]
    pub const fn evidence_class(&self) -> EvidenceClass {
        self.record.evidence_class()
    }

    /// Returns the commitment to the transport signer authorized for this delivery.
    #[must_use]
    pub const fn signer_commitment(&self) -> Digest384 {
        self.signing_transcript_commitment
    }

    /// Returns the domain-separated canonical transport-authentication payload.
    pub fn signing_payload(&self) -> Result<Vec<u8>, EncodeError> {
        let encoded = encode_envelope(self)?;
        let mut payload = Vec::with_capacity(34 + encoded.len());
        payload.extend_from_slice(b"ACTIVECHAIN-PAYMENT-WEBHOOK-EVENT-V1");
        payload.extend_from_slice(&encoded);
        Ok(payload)
    }

    #[must_use]
    pub const fn active_at(&self, timestamp: u64) -> bool {
        timestamp >= self.emitted_at && timestamp < self.expires_at
    }
}

impl CanonicalEncode for PaymentWebhookEventV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.subscription.encode(encoder)?;
        self.event.encode(encoder)?;
        self.record.encode(encoder)?;
        self.payload_commitment.encode(encoder)?;
        self.signing_transcript_commitment.encode(encoder)?;
        self.emitted_at.encode(encoder)?;
        self.expires_at.encode(encoder)
    }
}

impl CanonicalDecode for PaymentWebhookEventV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PaymentWebhookSubscriptionId::decode(decoder)?,
            PaymentWebhookEventId::decode(decoder)?,
            PaymentLifecycleRecordV1::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment webhook event"))
    }
}

impl CanonicalType for PaymentWebhookEventV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 48 * 4 + PaymentLifecycleRecordV1::MAX_ENCODED_LEN + 8 * 2;
}

/// Commits a webhook transport signer without assigning finality to its event.
pub fn payment_webhook_signer_commitment(public_key: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-PAYMENT-WEBHOOK-SIGNER-V1");
    hasher.update(&(public_key.len() as u32).to_be_bytes());
    hasher.update(public_key);
    let mut digest = [0_u8; 48];
    hasher.finalize_xof().read(&mut digest);
    Digest384::new(digest)
}

/// Canonical proof that the webhook event's committed transport signer approved the exact event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentWebhookSignedEventV1 {
    event: PaymentWebhookEventV1,
    public_key: Vec<u8>,
    signature: ProtocolSignature,
}
impl PaymentWebhookSignedEventV1 {
    pub const TYPE_TAG: u16 = 0x0178;

    pub fn new(
        event: PaymentWebhookEventV1,
        public_key: Vec<u8>,
        signature: ProtocolSignature,
    ) -> Result<Self, PaymentValidationError> {
        if public_key.len() != ML_DSA44_PUBLIC_KEY_LENGTH
            || signature.suite() != CryptoSuiteId::ML_DSA_44
            || payment_webhook_signer_commitment(&public_key) != event.signer_commitment()
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        Ok(Self { event, public_key, signature })
    }

    pub const fn event(&self) -> &PaymentWebhookEventV1 {
        &self.event
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub const fn signature(&self) -> &ProtocolSignature {
        &self.signature
    }
}
impl CanonicalEncode for PaymentWebhookSignedEventV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.event.encode(encoder)?;
        encoder.write_bytes(&self.public_key, ML_DSA44_PUBLIC_KEY_LENGTH)?;
        self.signature.encode(encoder)
    }
}
impl CanonicalDecode for PaymentWebhookSignedEventV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PaymentWebhookEventV1::decode(decoder)?,
            decoder.read_bytes(ML_DSA44_PUBLIC_KEY_LENGTH)?.to_vec(),
            ProtocolSignature::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid signed payment webhook event"))
    }
}
impl CanonicalType for PaymentWebhookSignedEventV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = PaymentWebhookEventV1::MAX_ENCODED_LEN
        + 3
        + ML_DSA44_PUBLIC_KEY_LENGTH
        + ProtocolSignature::MAX_ENCODED_LEN;
}

/// Durable subscriber progress requiring each lifecycle sequence exactly once and in order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentWebhookCursorV1 {
    subscription: PaymentWebhookSubscriptionId,
    intent: PaymentIntentId,
    next_sequence: u64,
    last_event: Option<PaymentWebhookEventId>,
}

impl PaymentWebhookCursorV1 {
    pub const TYPE_TAG: u16 = 0x0169;

    #[must_use]
    pub const fn new(subscription: PaymentWebhookSubscriptionId, intent: PaymentIntentId) -> Self {
        Self { subscription, intent, next_sequence: 1, last_event: None }
    }

    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    #[must_use]
    pub const fn subscription(&self) -> PaymentWebhookSubscriptionId {
        self.subscription
    }

    #[must_use]
    pub const fn intent(&self) -> PaymentIntentId {
        self.intent
    }

    pub fn advance(
        &self,
        event: &PaymentWebhookEventV1,
        timestamp: u64,
    ) -> Result<Self, PaymentValidationError> {
        if event.subscription() != self.subscription || event.intent() != self.intent {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if event.sequence() != self.next_sequence {
            return Err(PaymentValidationError::InvalidSequence);
        }
        if !event.active_at(timestamp) {
            return Err(PaymentValidationError::InvalidValidity);
        }
        let next_sequence =
            self.next_sequence.checked_add(1).ok_or(PaymentValidationError::InvalidSequence)?;
        Ok(Self { next_sequence, last_event: Some(event.event()), ..self.clone() })
    }
}

impl CanonicalEncode for PaymentWebhookCursorV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.subscription.encode(encoder)?;
        self.intent.encode(encoder)?;
        self.next_sequence.encode(encoder)?;
        self.last_event.encode(encoder)
    }
}

impl CanonicalDecode for PaymentWebhookCursorV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let subscription = PaymentWebhookSubscriptionId::decode(decoder)?;
        let intent = PaymentIntentId::decode(decoder)?;
        let next_sequence = u64::decode(decoder)?;
        let last_event = Option::<PaymentWebhookEventId>::decode(decoder)?;
        if next_sequence == 0
            || (next_sequence == 1 && last_event.is_some())
            || (next_sequence > 1 && last_event.is_none())
        {
            return Err(DecodeError::InvalidValue("invalid payment webhook cursor"));
        }
        Ok(Self { subscription, intent, next_sequence, last_event })
    }
}

impl CanonicalType for PaymentWebhookCursorV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 48 * 2 + 8 + 1 + 48;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PaymentApiOperation {
    Quote = 0,
    CreateIntent = 1,
    Status = 2,
    Refund = 3,
    Dispute = 4,
    TreasuryDebit = 5,
    WebhookAdmin = 6,
}
impl CanonicalEncode for PaymentApiOperation {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for PaymentApiOperation {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Quote),
            1 => Ok(Self::CreateIntent),
            2 => Ok(Self::Status),
            3 => Ok(Self::Refund),
            4 => Ok(Self::Dispute),
            5 => Ok(Self::TreasuryDebit),
            6 => Ok(Self::WebhookAdmin),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "PaymentApiOperation", tag }),
        }
    }
}

/// Authenticator-bound API transcript. Authentication never promotes payment evidence or finality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaymentApiAuthorizationV1 {
    caller: PrincipalId,
    audience: Digest384,
    operation: PaymentApiOperation,
    request_commitment: Digest384,
    idempotency_commitment: Digest384,
    intent: Option<PaymentIntentId>,
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    authenticator_commitment: Digest384,
}
impl PaymentApiAuthorizationV1 {
    pub const TYPE_TAG: u16 = 0x0170;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        caller: PrincipalId,
        audience: Digest384,
        operation: PaymentApiOperation,
        request_commitment: Digest384,
        idempotency_commitment: Digest384,
        intent: Option<PaymentIntentId>,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
        authenticator_commitment: Digest384,
    ) -> Result<Self, PaymentValidationError> {
        if caller.digest() == &Digest384::ZERO
            || audience == Digest384::ZERO
            || request_commitment == Digest384::ZERO
            || idempotency_commitment == Digest384::ZERO
            || authenticator_commitment == Digest384::ZERO
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if sequence == 0 {
            return Err(PaymentValidationError::InvalidSequence);
        }
        if issued_at >= expires_at {
            return Err(PaymentValidationError::InvalidValidity);
        }
        Ok(Self {
            caller,
            audience,
            operation,
            request_commitment,
            idempotency_commitment,
            intent,
            sequence,
            issued_at,
            expires_at,
            authenticator_commitment,
        })
    }
    pub const fn caller(&self) -> PrincipalId {
        self.caller
    }
    pub const fn audience(&self) -> Digest384 {
        self.audience
    }
    pub const fn operation(&self) -> PaymentApiOperation {
        self.operation
    }
    pub const fn request_commitment(&self) -> Digest384 {
        self.request_commitment
    }
    pub const fn intent(&self) -> Option<PaymentIntentId> {
        self.intent
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn authenticator_commitment(&self) -> Digest384 {
        self.authenticator_commitment
    }
    pub fn signing_payload(&self) -> Result<Vec<u8>, EncodeError> {
        let encoded = encode_envelope(self)?;
        let mut payload = Vec::with_capacity(39 + encoded.len());
        payload.extend_from_slice(b"ACTIVECHAIN-PAYMENT-API-AUTHORIZATION-V1");
        payload.extend_from_slice(&encoded);
        Ok(payload)
    }
    pub const fn active_at(&self, timestamp: u64) -> bool {
        timestamp >= self.issued_at && timestamp < self.expires_at
    }
}

pub fn payment_api_authenticator_commitment(public_key: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-PAYMENT-API-AUTHENTICATOR-V1");
    hasher.update(&(public_key.len() as u32).to_be_bytes());
    hasher.update(public_key);
    let mut digest = [0_u8; 48];
    hasher.finalize_xof().read(&mut digest);
    Digest384::new(digest)
}

/// Canonical proof that the committed API authenticator approved an exact authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentApiSignedAuthorizationV1 {
    authorization: PaymentApiAuthorizationV1,
    public_key: Vec<u8>,
    signature: ProtocolSignature,
}
impl PaymentApiSignedAuthorizationV1 {
    pub const TYPE_TAG: u16 = 0x0173;
    pub fn new(
        authorization: PaymentApiAuthorizationV1,
        public_key: Vec<u8>,
        signature: ProtocolSignature,
    ) -> Result<Self, PaymentValidationError> {
        if public_key.len() != ML_DSA44_PUBLIC_KEY_LENGTH
            || signature.suite() != CryptoSuiteId::ML_DSA_44
            || payment_api_authenticator_commitment(&public_key)
                != authorization.authenticator_commitment
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        Ok(Self { authorization, public_key, signature })
    }
    pub const fn authorization(&self) -> &PaymentApiAuthorizationV1 {
        &self.authorization
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    pub const fn signature(&self) -> &ProtocolSignature {
        &self.signature
    }
}
impl CanonicalEncode for PaymentApiSignedAuthorizationV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.authorization.encode(encoder)?;
        encoder.write_bytes(&self.public_key, ML_DSA44_PUBLIC_KEY_LENGTH)?;
        self.signature.encode(encoder)
    }
}
impl CanonicalDecode for PaymentApiSignedAuthorizationV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PaymentApiAuthorizationV1::decode(decoder)?,
            decoder.read_bytes(ML_DSA44_PUBLIC_KEY_LENGTH)?.to_vec(),
            ProtocolSignature::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid signed payment API authorization"))
    }
}
impl CanonicalType for PaymentApiSignedAuthorizationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = PaymentApiAuthorizationV1::MAX_ENCODED_LEN
        + 3
        + ML_DSA44_PUBLIC_KEY_LENGTH
        + ProtocolSignature::MAX_ENCODED_LEN;
}
impl CanonicalEncode for PaymentApiAuthorizationV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.caller.encode(encoder)?;
        self.audience.encode(encoder)?;
        self.operation.encode(encoder)?;
        self.request_commitment.encode(encoder)?;
        self.idempotency_commitment.encode(encoder)?;
        self.intent.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.issued_at.encode(encoder)?;
        self.expires_at.encode(encoder)?;
        self.authenticator_commitment.encode(encoder)
    }
}
impl CanonicalDecode for PaymentApiAuthorizationV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(decoder)?,
            Digest384::decode(decoder)?,
            PaymentApiOperation::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Option::<PaymentIntentId>::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            Digest384::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment API authorization"))
    }
}
impl CanonicalType for PaymentApiAuthorizationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 48 * 5 + 1 + 1 + 48 + 8 * 3;
}

/// Exact next API sequence for one caller and audience.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaymentApiReplayStateV1 {
    caller: PrincipalId,
    audience: Digest384,
    next_sequence: u64,
    last_authenticator: Option<Digest384>,
}
impl PaymentApiReplayStateV1 {
    pub const TYPE_TAG: u16 = 0x0171;
    pub fn new(caller: PrincipalId, audience: Digest384) -> Result<Self, PaymentValidationError> {
        if caller.digest() == &Digest384::ZERO || audience == Digest384::ZERO {
            return Err(PaymentValidationError::InvalidBinding);
        }
        Ok(Self { caller, audience, next_sequence: 1, last_authenticator: None })
    }
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub const fn caller(&self) -> PrincipalId {
        self.caller
    }
    pub const fn audience(&self) -> Digest384 {
        self.audience
    }
    pub fn authorize(
        &self,
        authorization: &PaymentApiAuthorizationV1,
        timestamp: u64,
    ) -> Result<Self, PaymentValidationError> {
        if authorization.caller != self.caller || authorization.audience != self.audience {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if authorization.sequence != self.next_sequence {
            return Err(PaymentValidationError::InvalidSequence);
        }
        if !authorization.active_at(timestamp) {
            return Err(PaymentValidationError::InvalidValidity);
        }
        Ok(Self {
            next_sequence: self
                .next_sequence
                .checked_add(1)
                .ok_or(PaymentValidationError::InvalidSequence)?,
            last_authenticator: Some(authorization.authenticator_commitment),
            ..*self
        })
    }
}
impl CanonicalEncode for PaymentApiReplayStateV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.caller.encode(encoder)?;
        self.audience.encode(encoder)?;
        self.next_sequence.encode(encoder)?;
        self.last_authenticator.encode(encoder)
    }
}
impl CanonicalDecode for PaymentApiReplayStateV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let caller = PrincipalId::decode(decoder)?;
        let audience = Digest384::decode(decoder)?;
        let next_sequence = u64::decode(decoder)?;
        let last_authenticator = Option::<Digest384>::decode(decoder)?;
        if caller.digest() == &Digest384::ZERO
            || audience == Digest384::ZERO
            || next_sequence == 0
            || last_authenticator == Some(Digest384::ZERO)
            || (next_sequence == 1 && last_authenticator.is_some())
            || (next_sequence > 1 && last_authenticator.is_none())
        {
            return Err(DecodeError::InvalidValue("invalid payment API replay state"));
        }
        Ok(Self { caller, audience, next_sequence, last_authenticator })
    }
}
impl CanonicalType for PaymentApiReplayStateV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 48 * 2 + 8 + 1 + 48;
}

/// One bounded refund request against an exact finalized payment settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentRefundRequestV1 {
    refund: PaymentRefundId,
    intent: PaymentIntentId,
    requester: PrincipalId,
    settlement_commitment: Digest384,
    amount: AssetAmountV1,
    reason_commitment: Digest384,
    idempotency_commitment: Digest384,
    sequence: u64,
    expected_refunded_units: u128,
    requested_at: u64,
    expires_at: u64,
}

impl PaymentRefundRequestV1 {
    pub const TYPE_TAG: u16 = 0x0162;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        refund: PaymentRefundId,
        intent: PaymentIntentId,
        requester: PrincipalId,
        settlement_commitment: Digest384,
        amount: AssetAmountV1,
        reason_commitment: Digest384,
        idempotency_commitment: Digest384,
        sequence: u64,
        expected_refunded_units: u128,
        requested_at: u64,
        expires_at: u64,
    ) -> Result<Self, PaymentValidationError> {
        if requester.digest() == &Digest384::ZERO
            || settlement_commitment == Digest384::ZERO
            || reason_commitment == Digest384::ZERO
            || idempotency_commitment == Digest384::ZERO
            || sequence == 0
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if requested_at == 0 || requested_at >= expires_at {
            return Err(PaymentValidationError::InvalidValidity);
        }
        Ok(Self {
            refund,
            intent,
            requester,
            settlement_commitment,
            amount,
            reason_commitment,
            idempotency_commitment,
            sequence,
            expected_refunded_units,
            requested_at,
            expires_at,
        })
    }

    pub const fn refund(&self) -> PaymentRefundId {
        self.refund
    }

    pub const fn intent(&self) -> PaymentIntentId {
        self.intent
    }

    pub const fn amount(&self) -> AssetAmountV1 {
        self.amount
    }

    pub const fn active_at(&self, timestamp: u64) -> bool {
        timestamp >= self.requested_at && timestamp < self.expires_at
    }

    /// Commits to the exact canonical refund request used as lifecycle evidence.
    pub fn commitment(&self) -> Result<Digest384, PaymentValidationError> {
        let bytes = encode_envelope(self).map_err(|_| PaymentValidationError::InvalidBinding)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-PAYMENT-REFUND-REQUEST-V1");
        hasher.update(&bytes);
        let mut output = [0_u8; 48];
        hasher.finalize_xof().read(&mut output);
        Ok(Digest384::new(output))
    }
}

impl CanonicalEncode for PaymentRefundRequestV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.refund.encode(encoder)?;
        self.intent.encode(encoder)?;
        self.requester.encode(encoder)?;
        self.settlement_commitment.encode(encoder)?;
        self.amount.encode(encoder)?;
        self.reason_commitment.encode(encoder)?;
        self.idempotency_commitment.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.expected_refunded_units.encode(encoder)?;
        self.requested_at.encode(encoder)?;
        self.expires_at.encode(encoder)
    }
}

impl CanonicalDecode for PaymentRefundRequestV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PaymentRefundId::decode(decoder)?,
            PaymentIntentId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            Digest384::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u128::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment refund request"))
    }
}

impl CanonicalType for PaymentRefundRequestV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 392;
}

/// Monotonic cumulative refund accounting for one finalized settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentRefundStateV1 {
    intent: PaymentIntentId,
    settlement_commitment: Digest384,
    settled_amount: AssetAmountV1,
    refunded_units: u128,
    next_sequence: u64,
    last_refund: Option<PaymentRefundId>,
}

impl PaymentRefundStateV1 {
    pub const TYPE_TAG: u16 = 0x0163;

    pub fn new(
        intent: PaymentIntentId,
        settlement_commitment: Digest384,
        settled_amount: AssetAmountV1,
    ) -> Result<Self, PaymentValidationError> {
        if settlement_commitment == Digest384::ZERO {
            return Err(PaymentValidationError::InvalidBinding);
        }
        Ok(Self {
            intent,
            settlement_commitment,
            settled_amount,
            refunded_units: 0,
            next_sequence: 1,
            last_refund: None,
        })
    }

    pub const fn refunded_units(&self) -> u128 {
        self.refunded_units
    }

    pub const fn intent(&self) -> PaymentIntentId {
        self.intent
    }

    pub const fn settled_amount(&self) -> AssetAmountV1 {
        self.settled_amount
    }

    pub const fn settlement_commitment(&self) -> Digest384 {
        self.settlement_commitment
    }

    pub const fn last_refund(&self) -> Option<PaymentRefundId> {
        self.last_refund
    }

    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn apply(
        &self,
        request: &PaymentRefundRequestV1,
        timestamp: u64,
    ) -> Result<Self, PaymentValidationError> {
        if request.intent != self.intent
            || request.settlement_commitment != self.settlement_commitment
            || request.amount.asset() != self.settled_amount.asset()
            || request.sequence != self.next_sequence
            || request.expected_refunded_units != self.refunded_units
            || !request.active_at(timestamp)
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        let refunded_units = self
            .refunded_units
            .checked_add(request.amount.atomic_units())
            .ok_or(PaymentValidationError::InvalidAmountBound)?;
        if refunded_units > self.settled_amount.atomic_units() {
            return Err(PaymentValidationError::InvalidAmountBound);
        }
        let next_sequence =
            self.next_sequence.checked_add(1).ok_or(PaymentValidationError::InvalidSequence)?;
        Ok(Self {
            refunded_units,
            next_sequence,
            last_refund: Some(request.refund),
            ..self.clone()
        })
    }
}

impl CanonicalEncode for PaymentRefundStateV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.intent.encode(encoder)?;
        self.settlement_commitment.encode(encoder)?;
        self.settled_amount.encode(encoder)?;
        self.refunded_units.encode(encoder)?;
        self.next_sequence.encode(encoder)?;
        self.last_refund.encode(encoder)
    }
}

impl CanonicalDecode for PaymentRefundStateV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let intent = PaymentIntentId::decode(decoder)?;
        let settlement_commitment = Digest384::decode(decoder)?;
        let settled_amount = AssetAmountV1::decode(decoder)?;
        let refunded_units = u128::decode(decoder)?;
        let next_sequence = u64::decode(decoder)?;
        let last_refund = Option::<PaymentRefundId>::decode(decoder)?;
        if settlement_commitment == Digest384::ZERO
            || refunded_units > settled_amount.atomic_units()
            || next_sequence == 0
            || (refunded_units == 0) != last_refund.is_none()
            || (last_refund.is_none() && next_sequence != 1)
            || (last_refund.is_some() && next_sequence < 2)
        {
            return Err(DecodeError::InvalidValue("invalid payment refund state"));
        }
        Ok(Self {
            intent,
            settlement_commitment,
            settled_amount,
            refunded_units,
            next_sequence,
            last_refund,
        })
    }
}

impl CanonicalType for PaymentRefundStateV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 233;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentDisputeRequestV1 {
    dispute: PaymentDisputeId,
    intent: PaymentIntentId,
    claimant: PrincipalId,
    settlement_commitment: Digest384,
    amount: AssetAmountV1,
    reason_commitment: Digest384,
    evidence_commitment: Digest384,
    idempotency_commitment: Digest384,
    opened_at: u64,
    expires_at: u64,
}

impl PaymentDisputeRequestV1 {
    pub const TYPE_TAG: u16 = 0x0164;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dispute: PaymentDisputeId,
        intent: PaymentIntentId,
        claimant: PrincipalId,
        settlement_commitment: Digest384,
        amount: AssetAmountV1,
        reason_commitment: Digest384,
        evidence_commitment: Digest384,
        idempotency_commitment: Digest384,
        opened_at: u64,
        expires_at: u64,
    ) -> Result<Self, PaymentValidationError> {
        if claimant.digest() == &Digest384::ZERO
            || settlement_commitment == Digest384::ZERO
            || reason_commitment == Digest384::ZERO
            || evidence_commitment == Digest384::ZERO
            || idempotency_commitment == Digest384::ZERO
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if opened_at == 0 || opened_at >= expires_at {
            return Err(PaymentValidationError::InvalidValidity);
        }
        Ok(Self {
            dispute,
            intent,
            claimant,
            settlement_commitment,
            amount,
            reason_commitment,
            evidence_commitment,
            idempotency_commitment,
            opened_at,
            expires_at,
        })
    }

    pub const fn dispute(&self) -> PaymentDisputeId {
        self.dispute
    }

    pub const fn intent(&self) -> PaymentIntentId {
        self.intent
    }

    pub const fn settlement_commitment(&self) -> Digest384 {
        self.settlement_commitment
    }

    pub const fn amount(&self) -> AssetAmountV1 {
        self.amount
    }

    pub const fn active_at(&self, timestamp: u64) -> bool {
        timestamp >= self.opened_at && timestamp < self.expires_at
    }
}

impl CanonicalEncode for PaymentDisputeRequestV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.dispute.encode(encoder)?;
        self.intent.encode(encoder)?;
        self.claimant.encode(encoder)?;
        self.settlement_commitment.encode(encoder)?;
        self.amount.encode(encoder)?;
        self.reason_commitment.encode(encoder)?;
        self.evidence_commitment.encode(encoder)?;
        self.idempotency_commitment.encode(encoder)?;
        self.opened_at.encode(encoder)?;
        self.expires_at.encode(encoder)
    }
}

impl CanonicalDecode for PaymentDisputeRequestV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PaymentDisputeId::decode(decoder)?,
            PaymentIntentId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            Digest384::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment dispute request"))
    }
}

impl CanonicalType for PaymentDisputeRequestV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 416;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PaymentDisputeState {
    Open = 0,
    EvidenceSubmitted = 1,
    ExternallyResolved = 2,
    ChainSubmitted = 3,
    Finalized = 4,
    Rejected = 5,
    Cancelled = 6,
    ManualReview = 7,
}

impl PaymentDisputeState {
    fn permits(self, next: Self) -> bool {
        match self {
            Self::Open => matches!(
                next,
                Self::EvidenceSubmitted | Self::Rejected | Self::Cancelled | Self::ManualReview
            ),
            Self::EvidenceSubmitted => matches!(
                next,
                Self::ExternallyResolved | Self::Rejected | Self::Cancelled | Self::ManualReview
            ),
            Self::ExternallyResolved => {
                matches!(next, Self::ChainSubmitted | Self::Rejected | Self::ManualReview)
            }
            Self::ChainSubmitted => {
                matches!(next, Self::Finalized | Self::Rejected | Self::ManualReview)
            }
            Self::ManualReview => matches!(
                next,
                Self::EvidenceSubmitted
                    | Self::ExternallyResolved
                    | Self::ChainSubmitted
                    | Self::Rejected
                    | Self::Cancelled
            ),
            Self::Finalized | Self::Rejected | Self::Cancelled => false,
        }
    }
}

impl CanonicalEncode for PaymentDisputeState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for PaymentDisputeState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Open),
            1 => Ok(Self::EvidenceSubmitted),
            2 => Ok(Self::ExternallyResolved),
            3 => Ok(Self::ChainSubmitted),
            4 => Ok(Self::Finalized),
            5 => Ok(Self::Rejected),
            6 => Ok(Self::Cancelled),
            7 => Ok(Self::ManualReview),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "PaymentDisputeState", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentDisputeRecordV1 {
    dispute: PaymentDisputeId,
    intent: PaymentIntentId,
    sequence: u64,
    state: PaymentDisputeState,
    evidence_class: EvidenceClass,
    observation_commitment: Digest384,
    transaction: Option<TransactionId>,
    finalized_height: u64,
    finalized_block: Option<Digest384>,
    reason_code: u16,
}

impl PaymentDisputeRecordV1 {
    pub const TYPE_TAG: u16 = 0x0165;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dispute: PaymentDisputeId,
        intent: PaymentIntentId,
        sequence: u64,
        state: PaymentDisputeState,
        evidence_class: EvidenceClass,
        observation_commitment: Digest384,
        transaction: Option<TransactionId>,
        finalized_height: u64,
        finalized_block: Option<Digest384>,
        reason_code: u16,
    ) -> Result<Self, PaymentValidationError> {
        if sequence == 0 || observation_commitment == Digest384::ZERO {
            return Err(PaymentValidationError::InvalidEvidence);
        }
        let finalized = state == PaymentDisputeState::Finalized;
        if finalized {
            if evidence_class != EvidenceClass::ActiveChainFinalized
                || transaction.is_none()
                || finalized_height == 0
                || finalized_block.is_none()
            {
                return Err(PaymentValidationError::InvalidEvidence);
            }
        } else if evidence_class == EvidenceClass::ActiveChainFinalized
            || finalized_height != 0
            || finalized_block.is_some()
            || (state == PaymentDisputeState::ChainSubmitted) != transaction.is_some()
        {
            return Err(PaymentValidationError::InvalidEvidence);
        }
        if state == PaymentDisputeState::ExternallyResolved
            && evidence_class < EvidenceClass::ConnectorAuthenticated
        {
            return Err(PaymentValidationError::InvalidEvidence);
        }
        if transaction.is_some_and(|value| value.digest() == &Digest384::ZERO)
            || finalized_block == Some(Digest384::ZERO)
        {
            return Err(PaymentValidationError::InvalidEvidence);
        }
        Ok(Self {
            dispute,
            intent,
            sequence,
            state,
            evidence_class,
            observation_commitment,
            transaction,
            finalized_height,
            finalized_block,
            reason_code,
        })
    }

    pub fn opened(
        request: &PaymentDisputeRequestV1,
        timestamp: u64,
    ) -> Result<Self, PaymentValidationError> {
        if !request.active_at(timestamp) {
            return Err(PaymentValidationError::InvalidValidity);
        }
        Self::new(
            request.dispute,
            request.intent,
            1,
            PaymentDisputeState::Open,
            EvidenceClass::UntrustedClientReport,
            request.evidence_commitment,
            None,
            0,
            None,
            0,
        )
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), PaymentValidationError> {
        if self.dispute != next.dispute || self.intent != next.intent {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if self.sequence.checked_add(1) != Some(next.sequence) {
            return Err(PaymentValidationError::InvalidSequence);
        }
        if !self.state.permits(next.state) {
            return Err(PaymentValidationError::InvalidTransition);
        }
        Ok(())
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn dispute(&self) -> PaymentDisputeId {
        self.dispute
    }

    pub const fn intent(&self) -> PaymentIntentId {
        self.intent
    }

    pub const fn state(&self) -> PaymentDisputeState {
        self.state
    }
}

impl CanonicalEncode for PaymentDisputeRecordV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.dispute.encode(encoder)?;
        self.intent.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.state.encode(encoder)?;
        self.evidence_class.encode(encoder)?;
        self.observation_commitment.encode(encoder)?;
        self.transaction.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        self.finalized_block.encode(encoder)?;
        self.reason_code.encode(encoder)
    }
}

impl CanonicalDecode for PaymentDisputeRecordV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PaymentDisputeId::decode(decoder)?,
            PaymentIntentId::decode(decoder)?,
            u64::decode(decoder)?,
            PaymentDisputeState::decode(decoder)?,
            EvidenceClass::decode(decoder)?,
            Digest384::decode(decoder)?,
            Option::<TransactionId>::decode(decoder)?,
            u64::decode(decoder)?,
            Option::<Digest384>::decode(decoder)?,
            u16::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment dispute record"))
    }
}

impl CanonicalType for PaymentDisputeRecordV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 312;
}

pub const MAX_TREASURY_OPERATORS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TreasuryDebitKind {
    Payout = 0,
    Conversion = 1,
    Refund = 2,
    Fee = 3,
    Settlement = 4,
}

impl CanonicalEncode for TreasuryDebitKind {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for TreasuryDebitKind {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Payout),
            1 => Ok(Self::Conversion),
            2 => Ok(Self::Refund),
            3 => Ok(Self::Fee),
            4 => Ok(Self::Settlement),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "TreasuryDebitKind", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasuryDebitPolicyV1 {
    treasury: TreasuryId,
    owner: PrincipalId,
    operators: Vec<PrincipalId>,
    asset: AssetId,
    maximum_operation_units: u128,
    period_budget_units: u128,
    spent_units: u128,
    period: u64,
    next_nonce: u64,
    expires_at: u64,
}

impl TreasuryDebitPolicyV1 {
    pub const TYPE_TAG: u16 = 0x0166;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        treasury: TreasuryId,
        owner: PrincipalId,
        operators: Vec<PrincipalId>,
        asset: AssetId,
        maximum_operation_units: u128,
        period_budget_units: u128,
        spent_units: u128,
        period: u64,
        next_nonce: u64,
        expires_at: u64,
    ) -> Result<Self, PaymentValidationError> {
        if owner.digest() == &Digest384::ZERO
            || asset.digest() == &Digest384::ZERO
            || operators.is_empty()
            || operators.len() > MAX_TREASURY_OPERATORS
            || operators.iter().any(|operator| operator.digest() == &Digest384::ZERO)
            || operators.windows(2).any(|pair| pair[0] >= pair[1])
            || maximum_operation_units == 0
            || period_budget_units == 0
            || spent_units > period_budget_units
            || expires_at == 0
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        Ok(Self {
            treasury,
            owner,
            operators,
            asset,
            maximum_operation_units,
            period_budget_units,
            spent_units,
            period,
            next_nonce,
            expires_at,
        })
    }

    pub fn commitment(&self) -> Result<Digest384, PaymentValidationError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)
            .map_err(|_| PaymentValidationError::InvalidBinding)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-ACTIVEBRIDGE-TREASURY-POLICY-V1");
        hasher.update(&bytes);
        let mut output = [0_u8; 48];
        hasher.finalize_xof().read(&mut output);
        Ok(Digest384::new(output))
    }

    pub const fn spent_units(&self) -> u128 {
        self.spent_units
    }

    pub const fn treasury(&self) -> TreasuryId {
        self.treasury
    }

    pub const fn next_nonce(&self) -> u64 {
        self.next_nonce
    }

    pub fn authorize(
        &self,
        request: &TreasuryDebitRequestV1,
        timestamp: u64,
    ) -> Result<Self, PaymentValidationError> {
        if request.treasury != self.treasury
            || self.operators.binary_search(&request.operator).is_err()
            || request.amount.asset() != self.asset
            || request.amount.atomic_units() > self.maximum_operation_units
            || request.policy_commitment != self.commitment()?
            || request.expected_spent_units != self.spent_units
            || request.period != self.period
            || request.nonce != self.next_nonce
            || timestamp >= request.expires_at
            || request.expires_at > self.expires_at
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        let spent_units = self
            .spent_units
            .checked_add(request.amount.atomic_units())
            .ok_or(PaymentValidationError::InvalidAmountBound)?;
        if spent_units > self.period_budget_units {
            return Err(PaymentValidationError::InvalidAmountBound);
        }
        let next_nonce =
            self.next_nonce.checked_add(1).ok_or(PaymentValidationError::InvalidSequence)?;
        Ok(Self { spent_units, next_nonce, ..self.clone() })
    }
}

impl CanonicalEncode for TreasuryDebitPolicyV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.treasury.encode(encoder)?;
        self.owner.encode(encoder)?;
        encoder.write_length(self.operators.len(), MAX_TREASURY_OPERATORS)?;
        for operator in &self.operators {
            operator.encode(encoder)?;
        }
        self.asset.encode(encoder)?;
        self.maximum_operation_units.encode(encoder)?;
        self.period_budget_units.encode(encoder)?;
        self.spent_units.encode(encoder)?;
        self.period.encode(encoder)?;
        self.next_nonce.encode(encoder)?;
        self.expires_at.encode(encoder)
    }
}

impl CanonicalDecode for TreasuryDebitPolicyV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let treasury = TreasuryId::decode(decoder)?;
        let owner = PrincipalId::decode(decoder)?;
        let count = decoder.read_length(MAX_TREASURY_OPERATORS)?;
        let mut operators = Vec::with_capacity(count);
        for _ in 0..count {
            operators.push(PrincipalId::decode(decoder)?);
        }
        Self::new(
            treasury,
            owner,
            operators,
            AssetId::decode(decoder)?,
            u128::decode(decoder)?,
            u128::decode(decoder)?,
            u128::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid treasury debit policy"))
    }
}

impl CanonicalType for TreasuryDebitPolicyV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 48 * 3 + 2 + MAX_TREASURY_OPERATORS * 48 + 16 * 3 + 8 * 3;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasuryDebitRequestV1 {
    treasury: TreasuryId,
    operator: PrincipalId,
    kind: TreasuryDebitKind,
    amount: AssetAmountV1,
    destination_commitment: Digest384,
    quote_context_commitment: Digest384,
    approval_commitment: Digest384,
    policy_commitment: Digest384,
    expected_spent_units: u128,
    period: u64,
    nonce: u64,
    expires_at: u64,
}

impl TreasuryDebitRequestV1 {
    pub const TYPE_TAG: u16 = 0x0167;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        treasury: TreasuryId,
        operator: PrincipalId,
        kind: TreasuryDebitKind,
        amount: AssetAmountV1,
        destination_commitment: Digest384,
        quote_context_commitment: Digest384,
        approval_commitment: Digest384,
        policy_commitment: Digest384,
        expected_spent_units: u128,
        period: u64,
        nonce: u64,
        expires_at: u64,
    ) -> Result<Self, PaymentValidationError> {
        if operator.digest() == &Digest384::ZERO
            || destination_commitment == Digest384::ZERO
            || quote_context_commitment == Digest384::ZERO
            || approval_commitment == Digest384::ZERO
            || policy_commitment == Digest384::ZERO
            || expires_at == 0
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        Ok(Self {
            treasury,
            operator,
            kind,
            amount,
            destination_commitment,
            quote_context_commitment,
            approval_commitment,
            policy_commitment,
            expected_spent_units,
            period,
            nonce,
            expires_at,
        })
    }

    pub const fn treasury(&self) -> TreasuryId {
        self.treasury
    }
}

impl CanonicalEncode for TreasuryDebitRequestV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.treasury.encode(encoder)?;
        self.operator.encode(encoder)?;
        self.kind.encode(encoder)?;
        self.amount.encode(encoder)?;
        self.destination_commitment.encode(encoder)?;
        self.quote_context_commitment.encode(encoder)?;
        self.approval_commitment.encode(encoder)?;
        self.policy_commitment.encode(encoder)?;
        self.expected_spent_units.encode(encoder)?;
        self.period.encode(encoder)?;
        self.nonce.encode(encoder)?;
        self.expires_at.encode(encoder)
    }
}

impl CanonicalDecode for TreasuryDebitRequestV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            TreasuryId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            TreasuryDebitKind::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u128::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid treasury debit request"))
    }
}

impl CanonicalType for TreasuryDebitRequestV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 48 * 6 + 64 + 1 + 16 + 8 * 3;
}

/// Bounded paymaster policy for sponsoring payment network fees.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentFeeSponsorPolicyV1 {
    sponsor: PrincipalId,
    paymaster: PrincipalId,
    fee_asset: AssetId,
    maximum_fee_units: u128,
    budget_units: u128,
    spent_units: u128,
    policy_revision: Digest384,
    next_nonce: u64,
    expires_at: u64,
}

impl PaymentFeeSponsorPolicyV1 {
    pub const TYPE_TAG: u16 = 0x018A;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor: PrincipalId,
        paymaster: PrincipalId,
        fee_asset: AssetId,
        maximum_fee_units: u128,
        budget_units: u128,
        spent_units: u128,
        policy_revision: Digest384,
        next_nonce: u64,
        expires_at: u64,
    ) -> Result<Self, PaymentValidationError> {
        if sponsor.digest() == &Digest384::ZERO
            || paymaster.digest() == &Digest384::ZERO
            || fee_asset.digest() == &Digest384::ZERO
            || maximum_fee_units == 0
            || budget_units == 0
            || spent_units > budget_units
            || policy_revision == Digest384::ZERO
            || next_nonce == 0
            || expires_at == 0
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        Ok(Self {
            sponsor,
            paymaster,
            fee_asset,
            maximum_fee_units,
            budget_units,
            spent_units,
            policy_revision,
            next_nonce,
            expires_at,
        })
    }

    pub const fn sponsor(&self) -> PrincipalId {
        self.sponsor
    }
    pub const fn spent_units(&self) -> u128 {
        self.spent_units
    }
    pub const fn next_nonce(&self) -> u64 {
        self.next_nonce
    }

    pub fn commitment(&self) -> Result<Digest384, PaymentValidationError> {
        let bytes = encode_envelope(self).map_err(|_| PaymentValidationError::InvalidBinding)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-PAYMENT-FEE-SPONSOR-POLICY-V1");
        hasher.update(&bytes);
        let mut output = [0_u8; 48];
        hasher.finalize_xof().read(&mut output);
        Ok(Digest384::new(output))
    }

    pub fn authorize(
        &self,
        request: &PaymentFeeSponsorRequestV1,
        timestamp: u64,
    ) -> Result<Self, PaymentValidationError> {
        if request.sponsor != self.sponsor
            || request.paymaster != self.paymaster
            || request.fee.asset() != self.fee_asset
            || request.fee.atomic_units() > self.maximum_fee_units
            || request.policy_commitment != self.commitment()?
            || request.expected_spent_units != self.spent_units
            || request.nonce != self.next_nonce
            || timestamp >= request.expires_at
            || request.expires_at > self.expires_at
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        let spent_units = self
            .spent_units
            .checked_add(request.fee.atomic_units())
            .ok_or(PaymentValidationError::InvalidAmountBound)?;
        if spent_units > self.budget_units {
            return Err(PaymentValidationError::InvalidAmountBound);
        }
        let next_nonce =
            self.next_nonce.checked_add(1).ok_or(PaymentValidationError::InvalidSequence)?;
        Ok(Self { spent_units, next_nonce, ..self.clone() })
    }
}

impl CanonicalEncode for PaymentFeeSponsorPolicyV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.sponsor.encode(encoder)?;
        self.paymaster.encode(encoder)?;
        self.fee_asset.encode(encoder)?;
        self.maximum_fee_units.encode(encoder)?;
        self.budget_units.encode(encoder)?;
        self.spent_units.encode(encoder)?;
        self.policy_revision.encode(encoder)?;
        self.next_nonce.encode(encoder)?;
        self.expires_at.encode(encoder)
    }
}

impl CanonicalDecode for PaymentFeeSponsorPolicyV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            AssetId::decode(decoder)?,
            u128::decode(decoder)?,
            u128::decode(decoder)?,
            u128::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment fee sponsor policy"))
    }
}

impl CanonicalType for PaymentFeeSponsorPolicyV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 256;
}

/// One exact request to sponsor a payment fee and bind its reimbursement terms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentFeeSponsorRequestV1 {
    intent: PaymentIntentId,
    sponsor: PrincipalId,
    paymaster: PrincipalId,
    fee: AssetAmountV1,
    reimbursement: AssetAmountV1,
    quote_commitment: Digest384,
    maximum_reimbursement_units: u128,
    policy_commitment: Digest384,
    idempotency_commitment: Digest384,
    expected_spent_units: u128,
    nonce: u64,
    expires_at: u64,
}

impl PaymentFeeSponsorRequestV1 {
    pub const TYPE_TAG: u16 = 0x018B;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent: PaymentIntentId,
        sponsor: PrincipalId,
        paymaster: PrincipalId,
        fee: AssetAmountV1,
        reimbursement: AssetAmountV1,
        quote_commitment: Digest384,
        maximum_reimbursement_units: u128,
        policy_commitment: Digest384,
        idempotency_commitment: Digest384,
        expected_spent_units: u128,
        nonce: u64,
        expires_at: u64,
    ) -> Result<Self, PaymentValidationError> {
        if sponsor.digest() == &Digest384::ZERO
            || paymaster.digest() == &Digest384::ZERO
            || policy_commitment == Digest384::ZERO
            || idempotency_commitment == Digest384::ZERO
            || quote_commitment == Digest384::ZERO
            || reimbursement.atomic_units() > maximum_reimbursement_units
            || nonce == 0
            || expires_at == 0
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        Ok(Self {
            intent,
            sponsor,
            paymaster,
            fee,
            reimbursement,
            quote_commitment,
            maximum_reimbursement_units,
            policy_commitment,
            idempotency_commitment,
            expected_spent_units,
            nonce,
            expires_at,
        })
    }

    pub const fn intent(&self) -> PaymentIntentId {
        self.intent
    }
    pub const fn sponsor(&self) -> PrincipalId {
        self.sponsor
    }
}

impl CanonicalEncode for PaymentFeeSponsorRequestV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.intent.encode(encoder)?;
        self.sponsor.encode(encoder)?;
        self.paymaster.encode(encoder)?;
        self.fee.encode(encoder)?;
        self.reimbursement.encode(encoder)?;
        self.quote_commitment.encode(encoder)?;
        self.maximum_reimbursement_units.encode(encoder)?;
        self.policy_commitment.encode(encoder)?;
        self.idempotency_commitment.encode(encoder)?;
        self.expected_spent_units.encode(encoder)?;
        self.nonce.encode(encoder)?;
        self.expires_at.encode(encoder)
    }
}

impl CanonicalDecode for PaymentFeeSponsorRequestV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PaymentIntentId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            AssetAmountV1::decode(decoder)?,
            Digest384::decode(decoder)?,
            u128::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u128::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment fee sponsor request"))
    }
}

impl CanonicalType for PaymentFeeSponsorRequestV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 464;
}

/// Durable binding from a caller's idempotency key to one exact request and operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyBindingV1 {
    caller: PrincipalId,
    idempotency_key: Digest384,
    request_body_commitment: Digest384,
    intent: PaymentIntentId,
    created_at: u64,
    retain_until: u64,
}

impl IdempotencyBindingV1 {
    /// Constructs a durable binding.
    pub fn new(
        caller: PrincipalId,
        idempotency_key: Digest384,
        request_body_commitment: Digest384,
        intent: PaymentIntentId,
        created_at: u64,
        retain_until: u64,
    ) -> Result<Self, PaymentValidationError> {
        if caller.digest() == &Digest384::ZERO
            || idempotency_key == Digest384::ZERO
            || request_body_commitment == Digest384::ZERO
        {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if created_at >= retain_until {
            return Err(PaymentValidationError::InvalidValidity);
        }
        Ok(Self {
            caller,
            idempotency_key,
            request_body_commitment,
            intent,
            created_at,
            retain_until,
        })
    }

    /// Requires exact request-body reuse for the bound key.
    pub fn validate_reuse(
        &self,
        caller: PrincipalId,
        idempotency_key: Digest384,
        request_body_commitment: Digest384,
    ) -> Result<PaymentIntentId, PaymentValidationError> {
        if self.caller != caller || self.idempotency_key != idempotency_key {
            return Err(PaymentValidationError::InvalidBinding);
        }
        if self.request_body_commitment != request_body_commitment {
            return Err(PaymentValidationError::IdempotencyConflict);
        }
        Ok(self.intent)
    }

    pub const fn caller(&self) -> PrincipalId {
        self.caller
    }

    pub const fn idempotency_key(&self) -> Digest384 {
        self.idempotency_key
    }

    pub const fn request_body_commitment(&self) -> Digest384 {
        self.request_body_commitment
    }

    pub const fn intent(&self) -> PaymentIntentId {
        self.intent
    }

    pub const fn active_at(&self, timestamp: u64) -> bool {
        timestamp >= self.created_at && timestamp < self.retain_until
    }

    pub const fn retain_until(&self) -> u64 {
        self.retain_until
    }
}

impl CanonicalEncode for IdempotencyBindingV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.caller.encode(encoder)?;
        self.idempotency_key.encode(encoder)?;
        self.request_body_commitment.encode(encoder)?;
        self.intent.encode(encoder)?;
        self.created_at.encode(encoder)?;
        self.retain_until.encode(encoder)
    }
}

impl CanonicalDecode for IdempotencyBindingV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            PaymentIntentId::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid idempotency binding"))
    }
}

impl CanonicalType for IdempotencyBindingV1 {
    const TYPE_TAG: u16 = 0x0140;
    const SCHEMA_VERSION: u16 = PAYMENT_SCHEMA_REVISION;
    const MAX_ENCODED_LEN: usize = 256;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::vec;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn chain() -> ChainId {
        ChainId::new(digest(1))
    }

    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }

    fn asset(byte: u8) -> AssetId {
        AssetId::new(digest(byte))
    }

    fn amount(asset_byte: u8, units: u128) -> AssetAmountV1 {
        AssetAmountV1::new(asset(asset_byte), units).unwrap()
    }

    fn intent_id() -> PaymentIntentId {
        PaymentIntentId::new(digest(10)).unwrap()
    }

    fn transaction() -> TransactionId {
        TransactionId::new(digest(30))
    }

    #[test]
    fn quote_round_trips_and_rejects_cross_asset_fees() {
        let quote = PaymentQuoteV1::new(
            chain(),
            PaymentQuoteId::new(digest(2)).unwrap(),
            principal(3),
            ConnectorId::new(digest(4)).unwrap(),
            RailId::new(digest(5)).unwrap(),
            amount(6, 1_000),
            amount(7, 900),
            amount(7, 10),
            amount(7, 5),
            amount(7, 4),
            9,
            10,
            digest(8),
            100,
            200,
            digest(9),
            digest(11),
        )
        .unwrap();
        let encoded = encode_envelope(&quote).unwrap();
        assert_eq!(decode_envelope::<PaymentQuoteV1>(&encoded).unwrap(), quote);

        assert_eq!(
            PaymentQuoteV1::new(
                chain(),
                PaymentQuoteId::new(digest(2)).unwrap(),
                principal(3),
                ConnectorId::new(digest(4)).unwrap(),
                RailId::new(digest(5)).unwrap(),
                amount(6, 1_000),
                amount(7, 900),
                amount(8, 10),
                amount(7, 5),
                amount(7, 4),
                9,
                10,
                digest(8),
                100,
                200,
                digest(9),
                digest(11),
            ),
            Err(PaymentValidationError::AssetMismatch)
        );
    }

    #[test]
    fn intent_enforces_minimum_output_and_asset_identity() {
        let build = |requested, minimum| {
            PaymentIntentV1::new(
                chain(),
                intent_id(),
                principal(2),
                TreasuryId::new(digest(3)).unwrap(),
                digest(4),
                digest(5),
                requested,
                minimum,
                200,
                digest(6),
                digest(7),
                digest(8),
                digest(9),
                digest(11),
            )
        };
        assert_eq!(
            build(amount(12, 100), amount(12, 101)),
            Err(PaymentValidationError::InvalidAmountBound)
        );
        assert_eq!(
            build(amount(12, 100), amount(13, 90)),
            Err(PaymentValidationError::AssetMismatch)
        );
        let intent = build(amount(12, 100), amount(12, 90)).unwrap();
        assert!(intent.active_at(199));
        assert!(!intent.active_at(200));
        assert_ne!(intent.commitment().unwrap(), Digest384::ZERO);
        let encoded = encode_envelope(&intent).unwrap();
        let decoded = decode_envelope::<PaymentIntentV1>(&encoded).unwrap();
        assert_eq!(decoded, intent);
        assert_eq!(decoded.commitment(), intent.commitment());
    }

    #[test]
    fn lifecycle_separates_external_confirmation_from_finality() {
        assert_eq!(
            PaymentLifecycleRecordV1::new(
                intent_id(),
                4,
                PaymentState::ExternallyConfirmed,
                EvidenceClass::ActiveChainFinalized,
                digest(20),
                None,
                0,
                None,
                0,
            ),
            Err(PaymentValidationError::InvalidEvidence)
        );
        let submitted = PaymentLifecycleRecordV1::new(
            intent_id(),
            5,
            PaymentState::ChainSubmitted,
            EvidenceClass::ProviderSigned,
            digest(21),
            Some(transaction()),
            0,
            None,
            0,
        )
        .unwrap();
        let finalized = PaymentLifecycleRecordV1::new(
            intent_id(),
            6,
            PaymentState::Finalized,
            EvidenceClass::ActiveChainFinalized,
            digest(22),
            Some(transaction()),
            44,
            Some(digest(23)),
            0,
        )
        .unwrap();
        assert_eq!(submitted.validate_successor(&finalized), Ok(()));
        assert_eq!(
            PaymentLifecycleRecordV1::new(
                intent_id(),
                6,
                PaymentState::Finalized,
                EvidenceClass::ProviderSigned,
                digest(22),
                Some(transaction()),
                44,
                Some(digest(23)),
                0,
            ),
            Err(PaymentValidationError::InvalidEvidence)
        );
    }

    #[test]
    fn finalized_settlement_binds_exact_economics_transaction_and_proof_evidence() {
        let transaction = TransactionId::new(digest(30));
        let settlement = PaymentFinalizedSettlementV1::new(
            intent_id(),
            transaction,
            amount(12, 95),
            50,
            digest(31),
            digest(32),
            digest(33),
        )
        .unwrap();
        let record = settlement.finalized_record(6).unwrap();
        assert_eq!(record.state(), PaymentState::Finalized);
        assert_eq!(record.evidence_class(), EvidenceClass::ActiveChainFinalized);
        assert_ne!(settlement.commitment().unwrap(), Digest384::ZERO);
        let encoded = encode_envelope(&settlement).unwrap();
        assert_eq!(decode_envelope::<PaymentFinalizedSettlementV1>(&encoded).unwrap(), settlement);

        let submitted = PaymentLifecycleRecordV1::new(
            intent_id(),
            5,
            PaymentState::ChainSubmitted,
            EvidenceClass::ConnectorAuthenticated,
            digest(34),
            Some(transaction),
            0,
            None,
            0,
        )
        .unwrap();
        assert_eq!(submitted.validate_successor(&record), Ok(()));
        let substituted = PaymentFinalizedSettlementV1::new(
            intent_id(),
            TransactionId::new(digest(35)),
            amount(12, 95),
            50,
            digest(31),
            digest(32),
            digest(33),
        )
        .unwrap()
        .finalized_record(6)
        .unwrap();
        assert_eq!(
            submitted.validate_successor(&substituted),
            Err(PaymentValidationError::InvalidBinding)
        );
        assert!(
            PaymentFinalizedSettlementV1::new(
                intent_id(),
                transaction,
                amount(12, 95),
                0,
                digest(31),
                digest(32),
                digest(33),
            )
            .is_err()
        );
    }

    #[test]
    fn finalized_refund_round_trips_and_builds_finalized_lifecycle_evidence() {
        let refund = PaymentFinalizedRefundV1::new(
            PaymentRefundId::new(digest(31)).unwrap(),
            intent_id(),
            digest(32),
            amount(12, 100),
            TransactionId::new(digest(33)),
            21,
            digest(34),
            digest(35),
            digest(36),
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<PaymentFinalizedRefundV1>(&encode_envelope(&refund).unwrap()),
            Ok(refund)
        );
        let record = refund.refunded_record(8).unwrap();
        assert_eq!(record.state(), PaymentState::Refunded);
        assert_eq!(record.evidence_class(), EvidenceClass::ActiveChainFinalized);
        assert_eq!(record.observation_commitment(), refund.commitment().unwrap());
    }

    #[test]
    fn terminal_states_are_immutable_and_sequences_are_exact() {
        let cancelled = PaymentLifecycleRecordV1::new(
            intent_id(),
            2,
            PaymentState::Cancelled,
            EvidenceClass::ConnectorAuthenticated,
            digest(20),
            None,
            0,
            None,
            0,
        )
        .unwrap();
        let retry = PaymentLifecycleRecordV1::new(
            intent_id(),
            3,
            PaymentState::ProviderPending,
            EvidenceClass::ConnectorAuthenticated,
            digest(21),
            None,
            0,
            None,
            0,
        )
        .unwrap();
        assert_eq!(
            cancelled.validate_successor(&retry),
            Err(PaymentValidationError::InvalidTransition)
        );

        let created = PaymentLifecycleRecordV1::created(intent_id(), digest(19)).unwrap();
        assert_eq!(
            created.validate_successor(&retry),
            Err(PaymentValidationError::InvalidSequence)
        );
    }

    fn webhook_event(
        subscription_byte: u8,
        event_byte: u8,
        record: PaymentLifecycleRecordV1,
        emitted_at: u64,
        expires_at: u64,
    ) -> PaymentWebhookEventV1 {
        PaymentWebhookEventV1::new(
            PaymentWebhookSubscriptionId::new(digest(subscription_byte)).unwrap(),
            PaymentWebhookEventId::new(digest(event_byte)).unwrap(),
            record,
            digest(60),
            digest(61),
            emitted_at,
            expires_at,
        )
        .unwrap()
    }

    #[test]
    fn webhook_cursor_round_trips_and_advances_exact_sequences() {
        let subscription = PaymentWebhookSubscriptionId::new(digest(50)).unwrap();
        let cursor = PaymentWebhookCursorV1::new(subscription, intent_id());
        let created = PaymentLifecycleRecordV1::created(intent_id(), digest(19)).unwrap();
        let first = webhook_event(50, 51, created, 100, 200);
        assert_eq!(first.evidence_class(), EvidenceClass::UntrustedClientReport);
        assert_eq!(
            decode_envelope::<PaymentWebhookEventV1>(&encode_envelope(&first).unwrap()).unwrap(),
            first
        );

        let cursor = cursor.advance(&first, 100).unwrap();
        assert_eq!(cursor.next_sequence(), 2);
        assert_eq!(
            decode_envelope::<PaymentWebhookCursorV1>(&encode_envelope(&cursor).unwrap()).unwrap(),
            cursor
        );

        let pending = PaymentLifecycleRecordV1::new(
            intent_id(),
            2,
            PaymentState::AwaitingPayer,
            EvidenceClass::ConnectorAuthenticated,
            digest(20),
            None,
            0,
            None,
            0,
        )
        .unwrap();
        let second = webhook_event(50, 52, pending, 110, 210);
        assert_eq!(cursor.advance(&second, 150).unwrap().next_sequence(), 3);
    }

    #[test]
    fn webhook_cursor_rejects_replay_gaps_cross_binding_and_expiry() {
        let subscription = PaymentWebhookSubscriptionId::new(digest(50)).unwrap();
        let cursor = PaymentWebhookCursorV1::new(subscription, intent_id());
        let first = webhook_event(
            50,
            51,
            PaymentLifecycleRecordV1::created(intent_id(), digest(19)).unwrap(),
            100,
            200,
        );
        let advanced = cursor.advance(&first, 150).unwrap();
        assert_eq!(advanced.advance(&first, 150), Err(PaymentValidationError::InvalidSequence));
        assert_eq!(cursor.advance(&first, 200), Err(PaymentValidationError::InvalidValidity));

        let gap = PaymentLifecycleRecordV1::new(
            intent_id(),
            3,
            PaymentState::ProviderPending,
            EvidenceClass::ProviderSigned,
            digest(21),
            None,
            0,
            None,
            0,
        )
        .unwrap();
        assert_eq!(
            advanced.advance(&webhook_event(50, 53, gap, 100, 200), 150),
            Err(PaymentValidationError::InvalidSequence)
        );
        assert_eq!(
            cursor.advance(&webhook_event(49, 54, first.record.clone(), 100, 200), 150),
            Err(PaymentValidationError::InvalidBinding)
        );

        let other_intent = PaymentIntentId::new(digest(11)).unwrap();
        let other_record = PaymentLifecycleRecordV1::created(other_intent, digest(22)).unwrap();
        assert_eq!(
            cursor.advance(&webhook_event(50, 55, other_record, 100, 200), 150),
            Err(PaymentValidationError::InvalidBinding)
        );
    }

    #[test]
    fn webhook_event_rejects_empty_commitments_and_invalid_windows() {
        let record = PaymentLifecycleRecordV1::created(intent_id(), digest(19)).unwrap();
        let build = |payload, transcript, emitted_at, expires_at| {
            PaymentWebhookEventV1::new(
                PaymentWebhookSubscriptionId::new(digest(50)).unwrap(),
                PaymentWebhookEventId::new(digest(51)).unwrap(),
                record.clone(),
                payload,
                transcript,
                emitted_at,
                expires_at,
            )
        };
        assert_eq!(
            build(Digest384::ZERO, digest(61), 100, 200),
            Err(PaymentValidationError::InvalidBinding)
        );
        assert_eq!(
            build(digest(60), Digest384::ZERO, 100, 200),
            Err(PaymentValidationError::InvalidBinding)
        );
        assert_eq!(
            build(digest(60), digest(61), 200, 200),
            Err(PaymentValidationError::InvalidValidity)
        );
    }

    #[test]
    fn signed_webhook_envelope_binds_exact_signer_and_round_trips() {
        let public_key = vec![7_u8; ML_DSA44_PUBLIC_KEY_LENGTH];
        let created = PaymentLifecycleRecordV1::created(intent_id(), digest(19)).unwrap();
        let event = PaymentWebhookEventV1::new(
            PaymentWebhookSubscriptionId::new(digest(50)).unwrap(),
            PaymentWebhookEventId::new(digest(51)).unwrap(),
            created,
            digest(60),
            payment_webhook_signer_commitment(&public_key),
            100,
            200,
        )
        .unwrap();
        let signed = PaymentWebhookSignedEventV1::new(
            event,
            public_key.clone(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![8_u8; 2_420]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<PaymentWebhookSignedEventV1>(&encode_envelope(&signed).unwrap())
                .unwrap(),
            signed
        );
        let wrong_key = vec![9_u8; ML_DSA44_PUBLIC_KEY_LENGTH];
        assert_eq!(
            PaymentWebhookSignedEventV1::new(
                signed.event().clone(),
                wrong_key,
                signed.signature().clone(),
            ),
            Err(PaymentValidationError::InvalidBinding)
        );
    }

    fn api_authorization(
        caller_byte: u8,
        audience_byte: u8,
        sequence: u64,
        operation: PaymentApiOperation,
    ) -> PaymentApiAuthorizationV1 {
        PaymentApiAuthorizationV1::new(
            principal(caller_byte),
            digest(audience_byte),
            operation,
            digest(70),
            digest(71),
            Some(intent_id()),
            sequence,
            100,
            200,
            digest(72),
        )
        .unwrap()
    }

    #[test]
    fn api_authorization_round_trips_and_advances_exact_client_sequence() {
        let authorization = api_authorization(2, 60, 1, PaymentApiOperation::CreateIntent);
        assert_eq!(
            decode_envelope::<PaymentApiAuthorizationV1>(&encode_envelope(&authorization).unwrap()),
            Ok(authorization)
        );
        let state = PaymentApiReplayStateV1::new(principal(2), digest(60)).unwrap();
        let state = state.authorize(&authorization, 100).unwrap();
        assert_eq!(state.next_sequence(), 2);
        assert_eq!(
            decode_envelope::<PaymentApiReplayStateV1>(&encode_envelope(&state).unwrap()),
            Ok(state)
        );
        let next = api_authorization(2, 60, 2, PaymentApiOperation::Status);
        assert_eq!(state.authorize(&next, 150).unwrap().next_sequence(), 3);
    }

    #[test]
    fn api_replay_state_rejects_replay_gap_cross_binding_and_expiry() {
        let first = api_authorization(2, 60, 1, PaymentApiOperation::Quote);
        let state = PaymentApiReplayStateV1::new(principal(2), digest(60)).unwrap();
        let advanced = state.authorize(&first, 150).unwrap();
        assert_eq!(advanced.authorize(&first, 150), Err(PaymentValidationError::InvalidSequence));
        assert_eq!(
            advanced.authorize(&api_authorization(2, 60, 3, PaymentApiOperation::Status), 150,),
            Err(PaymentValidationError::InvalidSequence)
        );
        assert_eq!(
            state.authorize(&api_authorization(3, 60, 1, PaymentApiOperation::Quote), 150,),
            Err(PaymentValidationError::InvalidBinding)
        );
        assert_eq!(
            state.authorize(&api_authorization(2, 61, 1, PaymentApiOperation::Quote), 150,),
            Err(PaymentValidationError::InvalidBinding)
        );
        assert_eq!(state.authorize(&first, 200), Err(PaymentValidationError::InvalidValidity));
        assert_ne!(
            api_authorization(2, 60, 1, PaymentApiOperation::Quote),
            api_authorization(2, 60, 1, PaymentApiOperation::Refund)
        );
    }

    #[test]
    fn api_authorization_rejects_zero_commitments_sequences_and_windows() {
        let build = |audience, request, idempotency, sequence, issued_at, expires_at, auth| {
            PaymentApiAuthorizationV1::new(
                principal(2),
                audience,
                PaymentApiOperation::Quote,
                request,
                idempotency,
                None,
                sequence,
                issued_at,
                expires_at,
                auth,
            )
        };
        assert!(build(Digest384::ZERO, digest(2), digest(3), 1, 10, 20, digest(4)).is_err());
        assert!(build(digest(1), Digest384::ZERO, digest(3), 1, 10, 20, digest(4)).is_err());
        assert!(build(digest(1), digest(2), Digest384::ZERO, 1, 10, 20, digest(4)).is_err());
        assert!(build(digest(1), digest(2), digest(3), 0, 10, 20, digest(4)).is_err());
        assert!(build(digest(1), digest(2), digest(3), 1, 20, 20, digest(4)).is_err());
        assert!(build(digest(1), digest(2), digest(3), 1, 10, 20, Digest384::ZERO).is_err());
    }

    #[test]
    fn signed_api_authorization_binds_exact_ml_dsa_authenticator() {
        let public_key = vec![9; ML_DSA44_PUBLIC_KEY_LENGTH];
        let authorization = PaymentApiAuthorizationV1::new(
            principal(2),
            digest(60),
            PaymentApiOperation::CreateIntent,
            digest(70),
            digest(71),
            Some(intent_id()),
            1,
            100,
            200,
            payment_api_authenticator_commitment(&public_key),
        )
        .unwrap();
        let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![7; 2_420]).unwrap();
        let signed = PaymentApiSignedAuthorizationV1::new(
            authorization,
            public_key.clone(),
            signature.clone(),
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<PaymentApiSignedAuthorizationV1>(&encode_envelope(&signed).unwrap()),
            Ok(signed)
        );
        let mut wrong_key = public_key;
        wrong_key[0] ^= 1;
        assert_eq!(
            PaymentApiSignedAuthorizationV1::new(authorization, wrong_key, signature),
            Err(PaymentValidationError::InvalidBinding)
        );
        assert!(
            authorization
                .signing_payload()
                .unwrap()
                .starts_with(b"ACTIVECHAIN-PAYMENT-API-AUTHORIZATION-V1")
        );
    }

    #[test]
    fn idempotency_reuse_requires_the_exact_body() {
        let binding =
            IdempotencyBindingV1::new(principal(2), digest(3), digest(4), intent_id(), 100, 1_000)
                .unwrap();
        assert_eq!(binding.validate_reuse(principal(2), digest(3), digest(4)), Ok(intent_id()));
        assert_eq!(
            binding.validate_reuse(principal(2), digest(3), digest(5)),
            Err(PaymentValidationError::IdempotencyConflict)
        );
        let encoded = encode_envelope(&binding).unwrap();
        assert_eq!(decode_envelope::<IdempotencyBindingV1>(&encoded).unwrap(), binding);
    }

    fn observation(sequence: u64, payload: u8) -> ProviderObservationV1 {
        ProviderObservationV1::new(
            chain(),
            ConnectorId::new(digest(2)).unwrap(),
            PaymentAttemptId::new(digest(3)).unwrap(),
            intent_id(),
            digest(4),
            digest(5),
            sequence,
            ProviderOperationState::Pending,
            amount(12, 100),
            100,
            100 + sequence,
            EvidenceClass::ProviderSigned,
            digest(payload),
        )
        .unwrap()
    }

    #[test]
    fn provider_observations_accept_exact_replay_and_exact_next_sequence() {
        let first = observation(1, 20);
        assert_eq!(first.compare_successor(&first), Ok(false));
        let next = observation(2, 21);
        assert_eq!(first.compare_successor(&next), Ok(true));
        assert_eq!(
            first.compare_successor(&observation(3, 22)),
            Err(PaymentValidationError::InvalidSequence)
        );
        let encoded = encode_envelope(&next).unwrap();
        assert_eq!(decode_envelope::<ProviderObservationV1>(&encoded).unwrap(), next);
    }

    #[test]
    fn provider_observations_cannot_claim_chain_finality_or_change_binding() {
        assert_eq!(
            ProviderObservationV1::new(
                chain(),
                ConnectorId::new(digest(2)).unwrap(),
                PaymentAttemptId::new(digest(3)).unwrap(),
                intent_id(),
                digest(4),
                digest(5),
                1,
                ProviderOperationState::Succeeded,
                amount(12, 100),
                100,
                101,
                EvidenceClass::ActiveChainFinalized,
                digest(20),
            ),
            Err(PaymentValidationError::InvalidEvidence)
        );
        let first = observation(1, 20);
        let changed_attempt = ProviderObservationV1::new(
            chain(),
            ConnectorId::new(digest(2)).unwrap(),
            PaymentAttemptId::new(digest(30)).unwrap(),
            intent_id(),
            digest(4),
            digest(5),
            2,
            ProviderOperationState::Succeeded,
            amount(12, 100),
            100,
            102,
            EvidenceClass::ProviderSigned,
            digest(21),
        )
        .unwrap();
        assert_eq!(
            first.compare_successor(&changed_attempt),
            Err(PaymentValidationError::InvalidBinding)
        );
    }

    #[test]
    fn malformed_envelopes_and_enum_tags_fail_closed() {
        let record = PaymentLifecycleRecordV1::created(intent_id(), digest(19)).unwrap();
        let mut encoded = encode_envelope(&record).unwrap();
        encoded.push(0);
        assert!(matches!(
            decode_envelope::<PaymentLifecycleRecordV1>(&encoded),
            Err(DecodeError::TrailingData { .. })
        ));

        let mut decoder = Decoder::new(&[99]);
        assert!(matches!(
            EvidenceClass::decode(&mut decoder),
            Err(DecodeError::InvalidEnumTag { type_name: "EvidenceClass", tag: 99 })
        ));
    }

    fn refund_request(
        state: &PaymentRefundStateV1,
        refund_byte: u8,
        units: u128,
    ) -> PaymentRefundRequestV1 {
        PaymentRefundRequestV1::new(
            PaymentRefundId::new(digest(refund_byte)).unwrap(),
            intent_id(),
            principal(2),
            digest(40),
            amount(12, units),
            digest(41),
            digest(42 + refund_byte),
            state.next_sequence(),
            state.refunded_units(),
            100,
            200,
        )
        .unwrap()
    }

    #[test]
    fn partial_refunds_are_cumulative_bounded_and_canonical() {
        let state = PaymentRefundStateV1::new(intent_id(), digest(40), amount(12, 100)).unwrap();
        let first = refund_request(&state, 50, 30);
        assert_eq!(
            decode_envelope::<PaymentRefundRequestV1>(&encode_envelope(&first).unwrap()),
            Ok(first.clone())
        );
        assert_ne!(first.commitment().unwrap(), Digest384::ZERO);
        let state = state.apply(&first, 150).unwrap();
        assert_eq!(state.refunded_units(), 30);
        assert_eq!(state.next_sequence(), 2);
        let second = refund_request(&state, 51, 70);
        assert_ne!(first.commitment().unwrap(), second.commitment().unwrap());
        let state = state.apply(&second, 150).unwrap();
        assert_eq!(state.refunded_units(), 100);
        assert_eq!(
            decode_envelope::<PaymentRefundStateV1>(&encode_envelope(&state).unwrap()),
            Ok(state)
        );
    }

    #[test]
    fn refunds_reject_replay_overrun_expiry_and_asset_substitution() {
        let state = PaymentRefundStateV1::new(intent_id(), digest(40), amount(12, 100)).unwrap();
        let first = refund_request(&state, 50, 60);
        let advanced = state.apply(&first, 150).unwrap();
        assert_eq!(advanced.apply(&first, 150), Err(PaymentValidationError::InvalidBinding));
        let overrun = refund_request(&advanced, 51, 41);
        assert_eq!(advanced.apply(&overrun, 150), Err(PaymentValidationError::InvalidAmountBound));
        let expired = refund_request(&advanced, 52, 40);
        assert_eq!(advanced.apply(&expired, 200), Err(PaymentValidationError::InvalidBinding));
        let wrong_asset = PaymentRefundRequestV1::new(
            PaymentRefundId::new(digest(53)).unwrap(),
            intent_id(),
            principal(2),
            digest(40),
            amount(13, 40),
            digest(41),
            digest(95),
            advanced.next_sequence(),
            advanced.refunded_units(),
            100,
            200,
        )
        .unwrap();
        assert_eq!(advanced.apply(&wrong_asset, 150), Err(PaymentValidationError::InvalidBinding));
    }

    fn dispute_request() -> PaymentDisputeRequestV1 {
        PaymentDisputeRequestV1::new(
            PaymentDisputeId::new(digest(60)).unwrap(),
            intent_id(),
            principal(2),
            digest(61),
            amount(12, 40),
            digest(62),
            digest(63),
            digest(64),
            100,
            200,
        )
        .unwrap()
    }

    #[test]
    fn dispute_lifecycle_separates_external_resolution_from_chain_finality() {
        let request = dispute_request();
        assert_eq!(
            decode_envelope::<PaymentDisputeRequestV1>(&encode_envelope(&request).unwrap()),
            Ok(request.clone())
        );
        let opened = PaymentDisputeRecordV1::opened(&request, 100).unwrap();
        let evidence = PaymentDisputeRecordV1::new(
            request.dispute(),
            request.intent(),
            2,
            PaymentDisputeState::EvidenceSubmitted,
            EvidenceClass::ConnectorAuthenticated,
            digest(65),
            None,
            0,
            None,
            0,
        )
        .unwrap();
        opened.validate_successor(&evidence).unwrap();
        let external = PaymentDisputeRecordV1::new(
            request.dispute(),
            request.intent(),
            3,
            PaymentDisputeState::ExternallyResolved,
            EvidenceClass::ProviderSigned,
            digest(66),
            None,
            0,
            None,
            0,
        )
        .unwrap();
        evidence.validate_successor(&external).unwrap();
        let submitted = PaymentDisputeRecordV1::new(
            request.dispute(),
            request.intent(),
            4,
            PaymentDisputeState::ChainSubmitted,
            EvidenceClass::ProviderSigned,
            digest(67),
            Some(transaction()),
            0,
            None,
            0,
        )
        .unwrap();
        external.validate_successor(&submitted).unwrap();
        let finalized = PaymentDisputeRecordV1::new(
            request.dispute(),
            request.intent(),
            5,
            PaymentDisputeState::Finalized,
            EvidenceClass::ActiveChainFinalized,
            digest(68),
            Some(transaction()),
            900,
            Some(digest(69)),
            0,
        )
        .unwrap();
        submitted.validate_successor(&finalized).unwrap();
        assert_eq!(finalized.state(), PaymentDisputeState::Finalized);
        assert_eq!(
            decode_envelope::<PaymentDisputeRecordV1>(&encode_envelope(&finalized).unwrap()),
            Ok(finalized)
        );
    }

    #[test]
    fn dispute_rejects_false_finality_invalid_edges_and_expired_opening() {
        let request = dispute_request();
        assert_eq!(
            PaymentDisputeRecordV1::opened(&request, 200),
            Err(PaymentValidationError::InvalidValidity)
        );
        assert_eq!(
            PaymentDisputeRecordV1::new(
                request.dispute(),
                request.intent(),
                2,
                PaymentDisputeState::ExternallyResolved,
                EvidenceClass::UntrustedClientReport,
                digest(66),
                None,
                0,
                None,
                0,
            ),
            Err(PaymentValidationError::InvalidEvidence)
        );
        assert_eq!(
            PaymentDisputeRecordV1::new(
                request.dispute(),
                request.intent(),
                2,
                PaymentDisputeState::ExternallyResolved,
                EvidenceClass::ActiveChainFinalized,
                digest(66),
                Some(transaction()),
                10,
                Some(digest(69)),
                0,
            ),
            Err(PaymentValidationError::InvalidEvidence)
        );
        let opened = PaymentDisputeRecordV1::opened(&request, 150).unwrap();
        let finalized = PaymentDisputeRecordV1::new(
            request.dispute(),
            request.intent(),
            2,
            PaymentDisputeState::Finalized,
            EvidenceClass::ActiveChainFinalized,
            digest(68),
            Some(transaction()),
            900,
            Some(digest(69)),
            0,
        )
        .unwrap();
        assert_eq!(
            opened.validate_successor(&finalized),
            Err(PaymentValidationError::InvalidTransition)
        );
    }

    fn treasury_policy(spent: u128) -> TreasuryDebitPolicyV1 {
        TreasuryDebitPolicyV1::new(
            TreasuryId::new(digest(70)).unwrap(),
            principal(71),
            vec![principal(72), principal(73)],
            asset(12),
            100,
            1_000,
            spent,
            9,
            4,
            1_000,
        )
        .unwrap()
    }

    fn treasury_request(
        policy: &TreasuryDebitPolicyV1,
        operator: PrincipalId,
        units: u128,
    ) -> TreasuryDebitRequestV1 {
        TreasuryDebitRequestV1::new(
            TreasuryId::new(digest(70)).unwrap(),
            operator,
            TreasuryDebitKind::Payout,
            amount(12, units),
            digest(74),
            digest(75),
            digest(76),
            policy.commitment().unwrap(),
            policy.spent_units(),
            9,
            policy.next_nonce(),
            900,
        )
        .unwrap()
    }

    #[test]
    fn treasury_debit_advances_exact_budget_and_nonce_canonically() {
        let policy = treasury_policy(200);
        assert_eq!(
            decode_envelope::<TreasuryDebitPolicyV1>(&encode_envelope(&policy).unwrap()),
            Ok(policy.clone())
        );
        let request = treasury_request(&policy, principal(72), 80);
        assert_eq!(
            decode_envelope::<TreasuryDebitRequestV1>(&encode_envelope(&request).unwrap()),
            Ok(request.clone())
        );
        let next = policy.authorize(&request, 800).unwrap();
        assert_eq!(next.spent_units(), 280);
        assert_eq!(next.next_nonce(), 5);
        assert_eq!(next.authorize(&request, 800), Err(PaymentValidationError::InvalidBinding));
    }

    #[test]
    fn treasury_debit_rejects_operator_asset_ceiling_expiry_and_period_overrun() {
        let policy = treasury_policy(200);
        assert_eq!(
            policy.authorize(&treasury_request(&policy, principal(74), 80), 800),
            Err(PaymentValidationError::InvalidBinding)
        );
        assert_eq!(
            policy.authorize(&treasury_request(&policy, principal(72), 101), 800),
            Err(PaymentValidationError::InvalidBinding)
        );
        assert_eq!(
            policy.authorize(&treasury_request(&policy, principal(72), 80), 901),
            Err(PaymentValidationError::InvalidBinding)
        );
        let nearly_spent = treasury_policy(950);
        assert_eq!(
            nearly_spent.authorize(&treasury_request(&nearly_spent, principal(72), 80), 800),
            Err(PaymentValidationError::InvalidAmountBound)
        );
        let wrong_asset = TreasuryDebitRequestV1::new(
            TreasuryId::new(digest(70)).unwrap(),
            principal(72),
            TreasuryDebitKind::Conversion,
            amount(13, 80),
            digest(74),
            digest(75),
            digest(76),
            policy.commitment().unwrap(),
            policy.spent_units(),
            9,
            policy.next_nonce(),
            900,
        )
        .unwrap();
        assert_eq!(
            policy.authorize(&wrong_asset, 800),
            Err(PaymentValidationError::InvalidBinding)
        );
    }

    fn fee_sponsor_policy() -> PaymentFeeSponsorPolicyV1 {
        PaymentFeeSponsorPolicyV1::new(
            principal(20),
            principal(21),
            AssetId::new(digest(22)),
            10,
            20,
            0,
            digest(23),
            1,
            1_000,
        )
        .unwrap()
    }

    fn fee_sponsor_request(
        policy: &PaymentFeeSponsorPolicyV1,
        fee_units: u128,
        expected: u128,
        nonce: u64,
    ) -> PaymentFeeSponsorRequestV1 {
        PaymentFeeSponsorRequestV1::new(
            intent_id(),
            principal(20),
            principal(21),
            amount(22, fee_units),
            amount(24, fee_units),
            digest(26),
            fee_units,
            policy.commitment().unwrap(),
            digest(25 + nonce as u8),
            expected,
            nonce,
            900,
        )
        .unwrap()
    }

    #[test]
    fn fee_sponsor_authorization_is_bounded_exact_and_canonical() {
        let policy = fee_sponsor_policy();
        let request = fee_sponsor_request(&policy, 8, 0, 1);
        assert_eq!(
            decode_envelope::<PaymentFeeSponsorPolicyV1>(&encode_envelope(&policy).unwrap()),
            Ok(policy.clone())
        );
        assert_eq!(
            decode_envelope::<PaymentFeeSponsorRequestV1>(&encode_envelope(&request).unwrap()),
            Ok(request.clone())
        );
        let advanced = policy.authorize(&request, 800).unwrap();
        assert_eq!(advanced.spent_units(), 8);
        assert_eq!(advanced.next_nonce(), 2);
        assert_eq!(advanced.authorize(&request, 800), Err(PaymentValidationError::InvalidBinding));
    }

    #[test]
    fn fee_sponsor_rejects_per_request_and_period_budget_overrun() {
        let policy = fee_sponsor_policy();
        assert_eq!(
            PaymentFeeSponsorRequestV1::new(
                intent_id(),
                principal(20),
                principal(21),
                amount(22, 8),
                amount(24, 8),
                digest(26),
                7,
                policy.commitment().unwrap(),
                digest(27),
                0,
                1,
                900,
            ),
            Err(PaymentValidationError::InvalidBinding)
        );
        assert_eq!(
            policy.authorize(&fee_sponsor_request(&policy, 11, 0, 1), 800),
            Err(PaymentValidationError::InvalidBinding)
        );
        let first = policy.authorize(&fee_sponsor_request(&policy, 10, 0, 1), 800).unwrap();
        let second = first.authorize(&fee_sponsor_request(&first, 10, 10, 2), 800).unwrap();
        assert_eq!(second.spent_units(), 20);
        assert_eq!(
            second.authorize(&fee_sponsor_request(&second, 1, 20, 3), 800),
            Err(PaymentValidationError::InvalidAmountBound)
        );
    }

    #[test]
    fn deterministic_envelope_vectors_are_frozen() {
        let record = PaymentLifecycleRecordV1::created(intent_id(), digest(19)).unwrap();
        assert_eq!(
            encode_envelope(&record).unwrap(),
            decode_hex(
                "013f0001760a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00000000000000010000131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313000000000000000000000000",
            )
        );

        let binding =
            IdempotencyBindingV1::new(principal(2), digest(3), digest(4), intent_id(), 100, 1_000)
                .unwrap();
        assert_eq!(
            encode_envelope(&binding).unwrap(),
            decode_hex(
                "01400001d0010202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000000000000006400000000000003e8",
            )
        );
    }

    fn decode_hex(value: &str) -> std::vec::Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid vector hex"),
        }
    }
}
