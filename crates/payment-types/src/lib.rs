#![no_std]
#![forbid(unsafe_code)]

//! Provider-independent, bounded payment values for ActiveBridge.
//!
//! This crate deliberately contains no networking, provider JSON, secret handling, balance
//! mutation, or consensus integration. It freezes the canonical values shared by those later
//! layers and keeps external observations distinct from finalized ActiveChain evidence.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{AssetId, ChainId, Digest384, PrincipalId, TransactionId};

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
        let encoded = encode_envelope(&intent).unwrap();
        assert_eq!(decode_envelope::<PaymentIntentV1>(&encoded).unwrap(), intent);
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
