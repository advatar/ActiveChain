#![forbid(unsafe_code)]

//! Durable, fail-closed observation state for out-of-consensus payment connectors.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_crypto_provider::verify_ml_dsa44;
use activechain_payment_types::{
    ConnectorId, EvidenceClass, IdempotencyBindingV1, PaymentApiAuthorizationV1,
    PaymentApiReplayStateV1, PaymentApiSignedAuthorizationV1, PaymentDisputeRecordV1,
    PaymentDisputeRequestV1, PaymentFeeSponsorPolicyV1, PaymentFeeSponsorRequestV1,
    PaymentFinalizedRefundV1, PaymentFinalizedSettlementV1, PaymentIntentId, PaymentIntentV1,
    PaymentLifecycleRecordV1, PaymentRefundRequestV1, PaymentRefundStateV1, PaymentState,
    PaymentValidationError, PaymentWebhookCursorV1, PaymentWebhookEventV1,
    PaymentWebhookSignedEventV1, ProviderObservationV1, RailId, TreasuryDebitPolicyV1,
    TreasuryDebitRequestV1,
};
use activechain_protocol_types::{AssetId, Digest384};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{fs::File, io::Write, path::Path};

mod ntzs_sandbox;
mod simulator;

pub use ntzs_sandbox::{
    NtzsOperationKind, NtzsReconciliationEntry, NtzsSandboxConnector, NtzsSandboxError,
    NtzsSandboxQuoteRequest,
};
pub use simulator::{
    ConnectorContract, ConnectorError, DeterministicConnector, SimulatorRequest, SimulatorScenario,
};

const MAX_OBSERVATIONS: usize = 65_535;
const MAX_WEBHOOK_CURSORS: usize = 65_535;
const MAX_API_CLIENTS: usize = 65_535;
const MAX_REFUND_STATES: usize = 65_535;
const MAX_DISPUTES: usize = 65_535;
const MAX_TREASURIES: usize = 65_535;
const MAX_FEE_SPONSORS: usize = 65_535;
const MAX_IDEMPOTENCY_BINDINGS: usize = 65_535;
const MAX_PAYMENT_LIFECYCLES: usize = 65_535;
const MAX_PAYMENT_INTENTS: usize = 65_535;
const SNAPSHOT_TAG_LENGTH: usize = 48;
const SNAPSHOT_DOMAIN: &[u8] = b"ACTIVECHAIN-ACTIVEBRIDGE-JOURNAL-V1";
const MAX_CONNECTOR_ORIGINS: usize = 16;
const MAX_CONNECTOR_ORIGIN_BYTES: usize = 255;
const MAX_CONNECTOR_ROUTES: usize = 64;
const MAX_CONNECTOR_TIMEOUT_MS: u32 = 60_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorPolicyError {
    InvalidIdentity,
    InvalidOrigin,
    InvalidRoute,
    InvalidTimeout,
    Unauthorized,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConnectorRouteV1 {
    rail: RailId,
    asset: AssetId,
    maximum_atomic_units: u128,
}
impl ConnectorRouteV1 {
    pub fn new(
        rail: RailId,
        asset: AssetId,
        maximum_atomic_units: u128,
    ) -> Result<Self, ConnectorPolicyError> {
        if asset.digest() == &Digest384::ZERO || maximum_atomic_units == 0 {
            return Err(ConnectorPolicyError::InvalidRoute);
        }
        Ok(Self { rail, asset, maximum_atomic_units })
    }
}
impl CanonicalEncode for ConnectorRouteV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.rail.encode(encoder)?;
        self.asset.encode(encoder)?;
        self.maximum_atomic_units.encode(encoder)
    }
}
impl CanonicalDecode for ConnectorRouteV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(RailId::decode(decoder)?, AssetId::decode(decoder)?, u128::decode(decoder)?)
            .map_err(|_| DecodeError::InvalidValue("invalid connector route"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorHostPolicyV1 {
    connector: ConnectorId,
    allowed_https_origins: Vec<Vec<u8>>,
    secret_handle: Digest384,
    routes: Vec<ConnectorRouteV1>,
    connect_timeout_ms: u32,
    request_timeout_ms: u32,
}
impl ConnectorHostPolicyV1 {
    pub const TYPE_TAG: u16 = 0x015C;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48
        + 2
        + MAX_CONNECTOR_ORIGINS * (2 + MAX_CONNECTOR_ORIGIN_BYTES)
        + 48
        + 2
        + MAX_CONNECTOR_ROUTES * (48 + 48 + 16)
        + 4
        + 4;

    pub fn new(
        connector: ConnectorId,
        allowed_https_origins: Vec<Vec<u8>>,
        secret_handle: Digest384,
        routes: Vec<ConnectorRouteV1>,
        connect_timeout_ms: u32,
        request_timeout_ms: u32,
    ) -> Result<Self, ConnectorPolicyError> {
        if connector.digest() == Digest384::ZERO || secret_handle == Digest384::ZERO {
            return Err(ConnectorPolicyError::InvalidIdentity);
        }
        if allowed_https_origins.is_empty()
            || allowed_https_origins.len() > MAX_CONNECTOR_ORIGINS
            || allowed_https_origins.windows(2).any(|pair| pair[0] >= pair[1])
            || allowed_https_origins.iter().any(|origin| {
                origin.len() <= b"https://".len()
                    || origin.len() > MAX_CONNECTOR_ORIGIN_BYTES
                    || !origin.starts_with(b"https://")
                    || origin.iter().any(|byte| !byte.is_ascii_graphic())
                    || origin.ends_with(b"/")
            })
        {
            return Err(ConnectorPolicyError::InvalidOrigin);
        }
        if routes.is_empty()
            || routes.len() > MAX_CONNECTOR_ROUTES
            || routes.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ConnectorPolicyError::InvalidRoute);
        }
        if connect_timeout_ms == 0
            || request_timeout_ms == 0
            || connect_timeout_ms > MAX_CONNECTOR_TIMEOUT_MS
            || request_timeout_ms > MAX_CONNECTOR_TIMEOUT_MS
            || connect_timeout_ms > request_timeout_ms
        {
            return Err(ConnectorPolicyError::InvalidTimeout);
        }
        Ok(Self {
            connector,
            allowed_https_origins,
            secret_handle,
            routes,
            connect_timeout_ms,
            request_timeout_ms,
        })
    }

    pub fn authorize(
        &self,
        connector: ConnectorId,
        origin: &[u8],
        rail: RailId,
        asset: AssetId,
        atomic_units: u128,
    ) -> Result<(), ConnectorPolicyError> {
        let route = ConnectorRouteV1::new(rail, asset, atomic_units)?;
        if connector != self.connector
            || self
                .allowed_https_origins
                .binary_search_by(|candidate| candidate.as_slice().cmp(origin))
                .is_err()
            || self
                .routes
                .binary_search_by(|candidate| (candidate.rail, candidate.asset).cmp(&(rail, asset)))
                .ok()
                .is_none_or(|index| atomic_units > self.routes[index].maximum_atomic_units)
            || route.maximum_atomic_units == 0
        {
            return Err(ConnectorPolicyError::Unauthorized);
        }
        Ok(())
    }
}
impl CanonicalEncode for ConnectorHostPolicyV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.connector.encode(encoder)?;
        encoder.write_length(self.allowed_https_origins.len(), MAX_CONNECTOR_ORIGINS)?;
        for origin in &self.allowed_https_origins {
            encoder.write_bytes(origin, MAX_CONNECTOR_ORIGIN_BYTES)?;
        }
        self.secret_handle.encode(encoder)?;
        encoder.write_length(self.routes.len(), MAX_CONNECTOR_ROUTES)?;
        for route in &self.routes {
            route.encode(encoder)?;
        }
        self.connect_timeout_ms.encode(encoder)?;
        self.request_timeout_ms.encode(encoder)
    }
}
impl CanonicalDecode for ConnectorHostPolicyV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let connector = ConnectorId::decode(decoder)?;
        let origin_count = decoder.read_length(MAX_CONNECTOR_ORIGINS)?;
        let mut origins = Vec::with_capacity(origin_count);
        for _ in 0..origin_count {
            origins.push(decoder.read_bytes(MAX_CONNECTOR_ORIGIN_BYTES)?.to_vec());
        }
        let secret_handle = Digest384::decode(decoder)?;
        let route_count = decoder.read_length(MAX_CONNECTOR_ROUTES)?;
        let mut routes = Vec::with_capacity(route_count);
        for _ in 0..route_count {
            routes.push(ConnectorRouteV1::decode(decoder)?);
        }
        Self::new(
            connector,
            origins,
            secret_handle,
            routes,
            u32::decode(decoder)?,
            u32::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid connector host policy"))
    }
}
impl CanonicalType for ConnectorHostPolicyV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    InvalidObservation,
    InvalidDelivery,
    InvalidAuthorization,
    InvalidRefund,
    InvalidDispute,
    InvalidTreasury,
    InvalidIdempotency,
    InvalidLifecycle,
    Capacity,
    Persistence,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConnectorJournalV1 {
    observations: Vec<ProviderObservationV1>,
}

impl ConnectorJournalV1 {
    #[must_use]
    pub fn observations(&self) -> &[ProviderObservationV1] {
        &self.observations
    }

    /// Applies exact replay without mutation or atomically advances one attempt.
    pub fn record(&mut self, observation: ProviderObservationV1) -> Result<bool, JournalError> {
        match self
            .observations
            .binary_search_by_key(&observation.attempt(), ProviderObservationV1::attempt)
        {
            Ok(index) => {
                let changed = self.observations[index]
                    .compare_successor(&observation)
                    .map_err(map_validation)?;
                if changed {
                    self.observations[index] = observation;
                }
                Ok(changed)
            }
            Err(index) => {
                if self.observations.len() == MAX_OBSERVATIONS || observation.sequence() != 1 {
                    return Err(if self.observations.len() == MAX_OBSERVATIONS {
                        JournalError::Capacity
                    } else {
                        JournalError::InvalidObservation
                    });
                }
                self.observations.insert(index, observation);
                Ok(true)
            }
        }
    }

    pub fn record_durable(
        &mut self,
        observation: ProviderObservationV1,
        path: &Path,
    ) -> Result<bool, JournalError> {
        let mut next = self.clone();
        let changed = next.record(observation)?;
        if changed {
            next.save_atomic(path)?;
            *self = next;
        }
        Ok(changed)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), JournalError> {
        save_snapshot(self, path)
    }

    pub fn load(path: &Path) -> Result<Self, JournalError> {
        load_snapshot(path)
    }
}

impl CanonicalEncode for ConnectorJournalV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.observations.len(), MAX_OBSERVATIONS)?;
        for observation in &self.observations {
            observation.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for ConnectorJournalV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_OBSERVATIONS)?;
        let mut observations = Vec::with_capacity(count);
        for _ in 0..count {
            let observation = ProviderObservationV1::decode(decoder)?;
            if observation.sequence() == 0
                || observations.last().is_some_and(|previous: &ProviderObservationV1| {
                    previous.attempt() >= observation.attempt()
                })
            {
                return Err(DecodeError::InvalidValue(
                    "connector observations are not canonically ordered",
                ));
            }
            observations.push(observation);
        }
        Ok(Self { observations })
    }
}

impl CanonicalType for ConnectorJournalV1 {
    const TYPE_TAG: u16 = 0x0142;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 3 + MAX_OBSERVATIONS * ProviderObservationV1::MAX_ENCODED_LEN;
}

/// Crash-safe progress for every webhook subscription and payment intent pair.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WebhookDeliveryJournalV1 {
    cursors: Vec<PaymentWebhookCursorV1>,
}

impl WebhookDeliveryJournalV1 {
    pub const TYPE_TAG: u16 = 0x016A;

    #[must_use]
    pub fn cursors(&self) -> &[PaymentWebhookCursorV1] {
        &self.cursors
    }

    pub fn deliver(
        &mut self,
        event: &PaymentWebhookEventV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        let key = (event.subscription(), event.intent());
        match self
            .cursors
            .binary_search_by_key(&key, |cursor| (cursor.subscription(), cursor.intent()))
        {
            Ok(index) => {
                self.cursors[index] = self.cursors[index]
                    .advance(event, timestamp)
                    .map_err(|_| JournalError::InvalidDelivery)?;
            }
            Err(index) => {
                if self.cursors.len() == MAX_WEBHOOK_CURSORS {
                    return Err(JournalError::Capacity);
                }
                let cursor = PaymentWebhookCursorV1::new(event.subscription(), event.intent())
                    .advance(event, timestamp)
                    .map_err(|_| JournalError::InvalidDelivery)?;
                self.cursors.insert(index, cursor);
            }
        }
        Ok(())
    }

    pub fn deliver_durable(
        &mut self,
        event: &PaymentWebhookEventV1,
        timestamp: u64,
        path: &Path,
    ) -> Result<(), JournalError> {
        let mut next = self.clone();
        next.deliver(event, timestamp)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    pub fn deliver_signed_durable(
        &mut self,
        signed: &PaymentWebhookSignedEventV1,
        timestamp: u64,
        path: &Path,
    ) -> Result<(), JournalError> {
        let event = signed.event();
        let payload = event.signing_payload().map_err(|_| JournalError::InvalidDelivery)?;
        verify_ml_dsa44(signed.public_key(), &payload, signed.signature().as_bytes())
            .map_err(|_| JournalError::InvalidDelivery)?;
        self.deliver_durable(event, timestamp, path)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), JournalError> {
        save_snapshot(self, path)
    }

    pub fn load(path: &Path) -> Result<Self, JournalError> {
        load_snapshot(path)
    }
}

impl CanonicalEncode for WebhookDeliveryJournalV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.cursors.len(), MAX_WEBHOOK_CURSORS)?;
        for cursor in &self.cursors {
            cursor.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for WebhookDeliveryJournalV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_WEBHOOK_CURSORS)?;
        let mut cursors = Vec::with_capacity(count);
        for _ in 0..count {
            let cursor = PaymentWebhookCursorV1::decode(decoder)?;
            let key = (cursor.subscription(), cursor.intent());
            if cursors.last().is_some_and(|previous: &PaymentWebhookCursorV1| {
                (previous.subscription(), previous.intent()) >= key
            }) {
                return Err(DecodeError::InvalidValue(
                    "webhook cursors are not canonically ordered",
                ));
            }
            cursors.push(cursor);
        }
        Ok(Self { cursors })
    }
}

impl CanonicalType for WebhookDeliveryJournalV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        3 + MAX_WEBHOOK_CURSORS * PaymentWebhookCursorV1::MAX_ENCODED_LEN;
}

/// Crash-safe exact API sequence for every authenticated caller and audience pair.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApiAuthorizationJournalV1 {
    states: Vec<PaymentApiReplayStateV1>,
}
impl ApiAuthorizationJournalV1 {
    pub const TYPE_TAG: u16 = 0x0172;
    #[must_use]
    pub fn states(&self) -> &[PaymentApiReplayStateV1] {
        &self.states
    }
    pub fn authorize(
        &mut self,
        authorization: &PaymentApiAuthorizationV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        let key = (authorization.caller(), authorization.audience());
        match self.states.binary_search_by_key(&key, |state| (state.caller(), state.audience())) {
            Ok(index) => {
                self.states[index] = self.states[index]
                    .authorize(authorization, timestamp)
                    .map_err(|_| JournalError::InvalidAuthorization)?;
            }
            Err(index) => {
                if self.states.len() == MAX_API_CLIENTS {
                    return Err(JournalError::Capacity);
                }
                let state =
                    PaymentApiReplayStateV1::new(authorization.caller(), authorization.audience())
                        .and_then(|state| state.authorize(authorization, timestamp))
                        .map_err(|_| JournalError::InvalidAuthorization)?;
                self.states.insert(index, state);
            }
        }
        Ok(())
    }
    pub fn authorize_durable(
        &mut self,
        authorization: &PaymentApiAuthorizationV1,
        timestamp: u64,
        path: &Path,
    ) -> Result<(), JournalError> {
        let mut next = self.clone();
        next.authorize(authorization, timestamp)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }
    pub fn authorize_signed_durable(
        &mut self,
        signed: &PaymentApiSignedAuthorizationV1,
        timestamp: u64,
        path: &Path,
    ) -> Result<(), JournalError> {
        let authorization = signed.authorization();
        let payload =
            authorization.signing_payload().map_err(|_| JournalError::InvalidAuthorization)?;
        verify_ml_dsa44(signed.public_key(), &payload, signed.signature().as_bytes())
            .map_err(|_| JournalError::InvalidAuthorization)?;
        self.authorize_durable(authorization, timestamp, path)
    }
    pub fn save_atomic(&self, path: &Path) -> Result<(), JournalError> {
        save_snapshot(self, path)
    }
    pub fn load(path: &Path) -> Result<Self, JournalError> {
        load_snapshot(path)
    }
}
impl CanonicalEncode for ApiAuthorizationJournalV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.states.len(), MAX_API_CLIENTS)?;
        for state in &self.states {
            state.encode(encoder)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for ApiAuthorizationJournalV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_API_CLIENTS)?;
        let mut states = Vec::with_capacity(count);
        for _ in 0..count {
            let state = PaymentApiReplayStateV1::decode(decoder)?;
            let key = (state.caller(), state.audience());
            if states.last().is_some_and(|previous: &PaymentApiReplayStateV1| {
                (previous.caller(), previous.audience()) >= key
            }) {
                return Err(DecodeError::InvalidValue(
                    "API authorization states are not canonically ordered",
                ));
            }
            states.push(state);
        }
        Ok(Self { states })
    }
}
impl CanonicalType for ApiAuthorizationJournalV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 3 + MAX_API_CLIENTS * PaymentApiReplayStateV1::MAX_ENCODED_LEN;
}

/// Crash-safe cumulative refund accounting for finalized settlements, ordered by intent.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RefundJournalV1 {
    states: Vec<PaymentRefundStateV1>,
}

impl RefundJournalV1 {
    pub const TYPE_TAG: u16 = 0x0182;

    #[must_use]
    pub fn states(&self) -> &[PaymentRefundStateV1] {
        &self.states
    }

    pub fn register(&mut self, state: PaymentRefundStateV1) -> Result<(), JournalError> {
        match self.states.binary_search_by_key(&state.intent(), PaymentRefundStateV1::intent) {
            Ok(_) => Err(JournalError::InvalidRefund),
            Err(_) if self.states.len() == MAX_REFUND_STATES => Err(JournalError::Capacity),
            Err(index) => {
                self.states.insert(index, state);
                Ok(())
            }
        }
    }

    pub fn register_durable(
        &mut self,
        state: PaymentRefundStateV1,
        path: &Path,
    ) -> Result<(), JournalError> {
        let mut next = self.clone();
        next.register(state)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    pub fn apply(
        &mut self,
        request: &PaymentRefundRequestV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        let index = self
            .states
            .binary_search_by_key(&request.intent(), PaymentRefundStateV1::intent)
            .map_err(|_| JournalError::InvalidRefund)?;
        self.states[index] = self.states[index]
            .apply(request, timestamp)
            .map_err(|_| JournalError::InvalidRefund)?;
        Ok(())
    }

    pub fn apply_durable(
        &mut self,
        request: &PaymentRefundRequestV1,
        timestamp: u64,
        path: &Path,
    ) -> Result<(), JournalError> {
        let mut next = self.clone();
        next.apply(request, timestamp)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), JournalError> {
        save_snapshot(self, path)
    }

    pub fn load(path: &Path) -> Result<Self, JournalError> {
        load_snapshot(path)
    }
}

impl CanonicalEncode for RefundJournalV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.states.len(), MAX_REFUND_STATES)?;
        for state in &self.states {
            state.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for RefundJournalV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_REFUND_STATES)?;
        let mut states = Vec::with_capacity(count);
        for _ in 0..count {
            let state = PaymentRefundStateV1::decode(decoder)?;
            if states
                .last()
                .is_some_and(|previous: &PaymentRefundStateV1| previous.intent() >= state.intent())
            {
                return Err(DecodeError::InvalidValue("refund states are not canonically ordered"));
            }
            states.push(state);
        }
        Ok(Self { states })
    }
}

impl CanonicalType for RefundJournalV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 3 + MAX_REFUND_STATES * PaymentRefundStateV1::MAX_ENCODED_LEN;
}

/// Crash-safe monotonic dispute records ordered by immutable dispute identity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DisputeJournalV1 {
    records: Vec<PaymentDisputeRecordV1>,
}

impl DisputeJournalV1 {
    pub const TYPE_TAG: u16 = 0x0183;

    #[must_use]
    pub fn records(&self) -> &[PaymentDisputeRecordV1] {
        &self.records
    }

    pub fn open(
        &mut self,
        request: &PaymentDisputeRequestV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        let record = PaymentDisputeRecordV1::opened(request, timestamp)
            .map_err(|_| JournalError::InvalidDispute)?;
        match self.records.binary_search_by_key(&record.dispute(), PaymentDisputeRecordV1::dispute)
        {
            Ok(_) => Err(JournalError::InvalidDispute),
            Err(_) if self.records.len() == MAX_DISPUTES => Err(JournalError::Capacity),
            Err(index) => {
                self.records.insert(index, record);
                Ok(())
            }
        }
    }

    pub fn open_durable(
        &mut self,
        request: &PaymentDisputeRequestV1,
        timestamp: u64,
        path: &Path,
    ) -> Result<(), JournalError> {
        let mut next = self.clone();
        next.open(request, timestamp)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    pub fn advance(&mut self, next: PaymentDisputeRecordV1) -> Result<(), JournalError> {
        let index = self
            .records
            .binary_search_by_key(&next.dispute(), PaymentDisputeRecordV1::dispute)
            .map_err(|_| JournalError::InvalidDispute)?;
        self.records[index].validate_successor(&next).map_err(|_| JournalError::InvalidDispute)?;
        self.records[index] = next;
        Ok(())
    }

    pub fn advance_durable(
        &mut self,
        next_record: PaymentDisputeRecordV1,
        path: &Path,
    ) -> Result<(), JournalError> {
        let mut next = self.clone();
        next.advance(next_record)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), JournalError> {
        save_snapshot(self, path)
    }

    pub fn load(path: &Path) -> Result<Self, JournalError> {
        load_snapshot(path)
    }
}

impl CanonicalEncode for DisputeJournalV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.records.len(), MAX_DISPUTES)?;
        for record in &self.records {
            record.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for DisputeJournalV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_DISPUTES)?;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let record = PaymentDisputeRecordV1::decode(decoder)?;
            if records.last().is_some_and(|previous: &PaymentDisputeRecordV1| {
                previous.dispute() >= record.dispute()
            }) {
                return Err(DecodeError::InvalidValue(
                    "dispute records are not canonically ordered",
                ));
            }
            records.push(record);
        }
        Ok(Self { records })
    }
}

impl CanonicalType for DisputeJournalV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 3 + MAX_DISPUTES * PaymentDisputeRecordV1::MAX_ENCODED_LEN;
}

/// Crash-safe treasury budgets and exact next nonces, ordered by treasury identity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TreasuryJournalV1 {
    policies: Vec<TreasuryDebitPolicyV1>,
}

impl TreasuryJournalV1 {
    pub const TYPE_TAG: u16 = 0x0184;

    #[must_use]
    pub fn policies(&self) -> &[TreasuryDebitPolicyV1] {
        &self.policies
    }

    pub fn register(&mut self, policy: TreasuryDebitPolicyV1) -> Result<(), JournalError> {
        match self
            .policies
            .binary_search_by_key(&policy.treasury(), TreasuryDebitPolicyV1::treasury)
        {
            Ok(_) => Err(JournalError::InvalidTreasury),
            Err(_) if self.policies.len() == MAX_TREASURIES => Err(JournalError::Capacity),
            Err(index) => {
                self.policies.insert(index, policy);
                Ok(())
            }
        }
    }

    pub fn register_durable(
        &mut self,
        policy: TreasuryDebitPolicyV1,
        path: &Path,
    ) -> Result<(), JournalError> {
        let mut next = self.clone();
        next.register(policy)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    pub fn authorize(
        &mut self,
        request: &TreasuryDebitRequestV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        let index = self
            .policies
            .binary_search_by_key(&request.treasury(), TreasuryDebitPolicyV1::treasury)
            .map_err(|_| JournalError::InvalidTreasury)?;
        self.policies[index] = self.policies[index]
            .authorize(request, timestamp)
            .map_err(|_| JournalError::InvalidTreasury)?;
        Ok(())
    }

    pub fn authorize_durable(
        &mut self,
        request: &TreasuryDebitRequestV1,
        timestamp: u64,
        path: &Path,
    ) -> Result<(), JournalError> {
        let mut next = self.clone();
        next.authorize(request, timestamp)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), JournalError> {
        save_snapshot(self, path)
    }

    pub fn load(path: &Path) -> Result<Self, JournalError> {
        load_snapshot(path)
    }
}

impl CanonicalEncode for TreasuryJournalV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.policies.len(), MAX_TREASURIES)?;
        for policy in &self.policies {
            policy.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for TreasuryJournalV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_TREASURIES)?;
        let mut policies = Vec::with_capacity(count);
        for _ in 0..count {
            let policy = TreasuryDebitPolicyV1::decode(decoder)?;
            if policies.last().is_some_and(|previous: &TreasuryDebitPolicyV1| {
                previous.treasury() >= policy.treasury()
            }) {
                return Err(DecodeError::InvalidValue(
                    "treasury policies are not canonically ordered",
                ));
            }
            policies.push(policy);
        }
        Ok(Self { policies })
    }
}

impl CanonicalType for TreasuryJournalV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 3 + MAX_TREASURIES * TreasuryDebitPolicyV1::MAX_ENCODED_LEN;
}

/// Crash-safe fee-sponsor budgets and exact nonces, ordered by sponsor principal.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FeeSponsorshipJournalV1 {
    policies: Vec<PaymentFeeSponsorPolicyV1>,
}

impl FeeSponsorshipJournalV1 {
    pub const TYPE_TAG: u16 = 0x018C;

    pub fn policies(&self) -> &[PaymentFeeSponsorPolicyV1] {
        &self.policies
    }

    pub fn register(&mut self, policy: PaymentFeeSponsorPolicyV1) -> Result<(), JournalError> {
        match self
            .policies
            .binary_search_by_key(&policy.sponsor(), PaymentFeeSponsorPolicyV1::sponsor)
        {
            Ok(_) => Err(JournalError::InvalidTreasury),
            Err(_) if self.policies.len() == MAX_FEE_SPONSORS => Err(JournalError::Capacity),
            Err(index) => {
                self.policies.insert(index, policy);
                Ok(())
            }
        }
    }

    pub fn authorize(
        &mut self,
        request: &PaymentFeeSponsorRequestV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        let index = self
            .policies
            .binary_search_by_key(&request.sponsor(), PaymentFeeSponsorPolicyV1::sponsor)
            .map_err(|_| JournalError::InvalidTreasury)?;
        self.policies[index] = self.policies[index]
            .authorize(request, timestamp)
            .map_err(|_| JournalError::InvalidTreasury)?;
        Ok(())
    }
}

impl CanonicalEncode for FeeSponsorshipJournalV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.policies.len(), MAX_FEE_SPONSORS)?;
        for policy in &self.policies {
            policy.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for FeeSponsorshipJournalV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_FEE_SPONSORS)?;
        let mut policies = Vec::with_capacity(count);
        for _ in 0..count {
            let policy = PaymentFeeSponsorPolicyV1::decode(decoder)?;
            if policies.last().is_some_and(|previous: &PaymentFeeSponsorPolicyV1| {
                previous.sponsor() >= policy.sponsor()
            }) {
                return Err(DecodeError::InvalidValue(
                    "fee sponsor policies are not canonically ordered",
                ));
            }
            policies.push(policy);
        }
        Ok(Self { policies })
    }
}

impl CanonicalType for FeeSponsorshipJournalV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        3 + MAX_FEE_SPONSORS * PaymentFeeSponsorPolicyV1::MAX_ENCODED_LEN;
}

/// Crash-safe caller-scoped idempotency bindings ordered by caller and key.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdempotencyJournalV1 {
    bindings: Vec<IdempotencyBindingV1>,
}

impl IdempotencyJournalV1 {
    pub const TYPE_TAG: u16 = 0x0185;

    #[must_use]
    pub fn bindings(&self) -> &[IdempotencyBindingV1] {
        &self.bindings
    }

    fn bind(
        &mut self,
        binding: IdempotencyBindingV1,
        timestamp: u64,
    ) -> Result<(activechain_payment_types::PaymentIntentId, bool), JournalError> {
        if !binding.active_at(timestamp) {
            return Err(JournalError::InvalidIdempotency);
        }
        let key = (binding.caller(), binding.idempotency_key());
        match self
            .bindings
            .binary_search_by_key(&key, |existing| (existing.caller(), existing.idempotency_key()))
        {
            Ok(index) => self.bindings[index]
                .validate_reuse(
                    binding.caller(),
                    binding.idempotency_key(),
                    binding.request_body_commitment(),
                )
                .map(|intent| (intent, false))
                .map_err(|_| JournalError::InvalidIdempotency),
            Err(_) if self.bindings.len() == MAX_IDEMPOTENCY_BINDINGS => {
                Err(JournalError::Capacity)
            }
            Err(index) => {
                let intent = binding.intent();
                self.bindings.insert(index, binding);
                Ok((intent, true))
            }
        }
    }

    pub fn bind_durable(
        &mut self,
        binding: IdempotencyBindingV1,
        timestamp: u64,
        path: &Path,
    ) -> Result<activechain_payment_types::PaymentIntentId, JournalError> {
        let mut next = self.clone();
        let (intent, changed) = next.bind(binding, timestamp)?;
        if changed {
            next.save_atomic(path)?;
            *self = next;
        }
        Ok(intent)
    }

    pub fn prune_expired_durable(
        &mut self,
        timestamp: u64,
        path: &Path,
    ) -> Result<usize, JournalError> {
        let mut next = self.clone();
        let before = next.bindings.len();
        next.bindings.retain(|binding| binding.retain_until() > timestamp);
        let removed = before - next.bindings.len();
        if removed != 0 {
            next.save_atomic(path)?;
            *self = next;
        }
        Ok(removed)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), JournalError> {
        save_snapshot(self, path)
    }

    pub fn load(path: &Path) -> Result<Self, JournalError> {
        load_snapshot(path)
    }
}

impl CanonicalEncode for IdempotencyJournalV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.bindings.len(), MAX_IDEMPOTENCY_BINDINGS)?;
        for binding in &self.bindings {
            binding.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for IdempotencyJournalV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_IDEMPOTENCY_BINDINGS)?;
        let mut bindings = Vec::with_capacity(count);
        for _ in 0..count {
            let binding = IdempotencyBindingV1::decode(decoder)?;
            let key = (binding.caller(), binding.idempotency_key());
            if bindings.last().is_some_and(|previous: &IdempotencyBindingV1| {
                (previous.caller(), previous.idempotency_key()) >= key
            }) {
                return Err(DecodeError::InvalidValue(
                    "idempotency bindings are not canonically ordered",
                ));
            }
            bindings.push(binding);
        }
        Ok(Self { bindings })
    }
}

impl CanonicalType for IdempotencyJournalV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        3 + MAX_IDEMPOTENCY_BINDINGS * IdempotencyBindingV1::MAX_ENCODED_LEN;
}

/// Crash-safe payment lifecycle records ordered by immutable payment intent.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PaymentLifecycleJournalV1 {
    records: Vec<PaymentLifecycleRecordV1>,
}

impl PaymentLifecycleJournalV1 {
    pub const TYPE_TAG: u16 = 0x0186;

    #[must_use]
    pub fn records(&self) -> &[PaymentLifecycleRecordV1] {
        &self.records
    }

    pub fn create(
        &mut self,
        intent: PaymentIntentId,
        observation_commitment: Digest384,
    ) -> Result<(), JournalError> {
        let record = PaymentLifecycleRecordV1::created(intent, observation_commitment)
            .map_err(|_| JournalError::InvalidLifecycle)?;
        match self.records.binary_search_by_key(&intent, PaymentLifecycleRecordV1::intent) {
            Ok(_) => Err(JournalError::InvalidLifecycle),
            Err(_) if self.records.len() == MAX_PAYMENT_LIFECYCLES => Err(JournalError::Capacity),
            Err(index) => {
                self.records.insert(index, record);
                Ok(())
            }
        }
    }

    pub fn create_durable(
        &mut self,
        intent: PaymentIntentId,
        observation_commitment: Digest384,
        path: &Path,
    ) -> Result<(), JournalError> {
        let mut next = self.clone();
        next.create(intent, observation_commitment)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    pub fn advance(&mut self, next: PaymentLifecycleRecordV1) -> Result<(), JournalError> {
        let index = self
            .records
            .binary_search_by_key(&next.intent(), PaymentLifecycleRecordV1::intent)
            .map_err(|_| JournalError::InvalidLifecycle)?;
        self.records[index]
            .validate_successor(&next)
            .map_err(|_| JournalError::InvalidLifecycle)?;
        self.records[index] = next;
        Ok(())
    }

    pub fn advance_durable(
        &mut self,
        next_record: PaymentLifecycleRecordV1,
        path: &Path,
    ) -> Result<(), JournalError> {
        let mut next = self.clone();
        next.advance(next_record)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), JournalError> {
        save_snapshot(self, path)
    }

    pub fn load(path: &Path) -> Result<Self, JournalError> {
        load_snapshot(path)
    }
}

impl CanonicalEncode for PaymentLifecycleJournalV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.records.len(), MAX_PAYMENT_LIFECYCLES)?;
        for record in &self.records {
            record.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for PaymentLifecycleJournalV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_PAYMENT_LIFECYCLES)?;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let record = PaymentLifecycleRecordV1::decode(decoder)?;
            if records.last().is_some_and(|previous: &PaymentLifecycleRecordV1| {
                previous.intent() >= record.intent()
            }) {
                return Err(DecodeError::InvalidValue(
                    "payment lifecycle records are not canonically ordered",
                ));
            }
            records.push(record);
        }
        Ok(Self { records })
    }
}

impl CanonicalType for PaymentLifecycleJournalV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        3 + MAX_PAYMENT_LIFECYCLES * PaymentLifecycleRecordV1::MAX_ENCODED_LEN;
}

/// Atomic request state joining each intent to one create binding and one lifecycle record.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PaymentRequestStateV1 {
    intents: Vec<PaymentIntentV1>,
    idempotency: IdempotencyJournalV1,
    lifecycles: PaymentLifecycleJournalV1,
}

impl PaymentRequestStateV1 {
    pub const TYPE_TAG: u16 = 0x0187;

    pub fn new(
        intents: Vec<PaymentIntentV1>,
        idempotency: IdempotencyJournalV1,
        lifecycles: PaymentLifecycleJournalV1,
    ) -> Result<Self, JournalError> {
        if intents.len() > MAX_PAYMENT_INTENTS
            || intents.windows(2).any(|pair| pair[0].intent() >= pair[1].intent())
            || intents.len() != idempotency.bindings().len()
            || intents.len() != lifecycles.records().len()
        {
            return Err(JournalError::InvalidLifecycle);
        }
        for (intent, lifecycle) in intents.iter().zip(lifecycles.records()) {
            if intent.intent() != lifecycle.intent() {
                return Err(JournalError::InvalidLifecycle);
            }
        }
        let mut binding_intents =
            idempotency.bindings().iter().map(IdempotencyBindingV1::intent).collect::<Vec<_>>();
        binding_intents.sort_unstable();
        if binding_intents.windows(2).any(|pair| pair[0] >= pair[1])
            || !binding_intents.iter().copied().eq(intents.iter().map(PaymentIntentV1::intent))
        {
            return Err(JournalError::InvalidIdempotency);
        }
        for binding in idempotency.bindings() {
            let index = intents
                .binary_search_by_key(&binding.intent(), PaymentIntentV1::intent)
                .map_err(|_| JournalError::InvalidIdempotency)?;
            let intent = &intents[index];
            if binding.caller() != intent.merchant()
                || binding.idempotency_key() != intent.idempotency_key()
                || binding.request_body_commitment()
                    != intent.commitment().map_err(|_| JournalError::InvalidIdempotency)?
            {
                return Err(JournalError::InvalidIdempotency);
            }
        }
        Ok(Self { intents, idempotency, lifecycles })
    }

    #[must_use]
    pub fn intents(&self) -> &[PaymentIntentV1] {
        &self.intents
    }

    pub const fn idempotency(&self) -> &IdempotencyJournalV1 {
        &self.idempotency
    }

    pub const fn lifecycles(&self) -> &PaymentLifecycleJournalV1 {
        &self.lifecycles
    }

    fn create_intent_successor(
        &self,
        intent: PaymentIntentV1,
        binding: IdempotencyBindingV1,
        observation_commitment: Digest384,
        timestamp: u64,
    ) -> Result<(Self, PaymentIntentId, bool), JournalError> {
        if !intent.active_at(timestamp)
            || binding.intent() != intent.intent()
            || binding.caller() != intent.merchant()
            || binding.idempotency_key() != intent.idempotency_key()
            || binding.request_body_commitment()
                != intent.commitment().map_err(|_| JournalError::InvalidIdempotency)?
        {
            return Err(JournalError::InvalidIdempotency);
        }
        let mut next = self.clone();
        let (bound_intent, changed) = next.idempotency.bind(binding, timestamp)?;
        if !changed {
            let index = next
                .intents
                .binary_search_by_key(&bound_intent, PaymentIntentV1::intent)
                .map_err(|_| JournalError::InvalidIdempotency)?;
            if next.intents[index] != intent {
                return Err(JournalError::InvalidIdempotency);
            }
            return Ok((next, bound_intent, false));
        }
        let index = next
            .intents
            .binary_search_by_key(&intent.intent(), PaymentIntentV1::intent)
            .map_or_else(|index| index, |_| usize::MAX);
        if index == usize::MAX {
            return Err(JournalError::InvalidIdempotency);
        }
        let intent_id = intent.intent();
        next.intents.insert(index, intent);
        next.lifecycles.create(intent_id, observation_commitment)?;
        Ok((Self::new(next.intents, next.idempotency, next.lifecycles)?, intent_id, true))
    }

    fn lifecycle_successor(
        &self,
        next_record: PaymentLifecycleRecordV1,
    ) -> Result<Self, JournalError> {
        let mut next = self.clone();
        next.lifecycles.advance(next_record)?;
        Self::new(next.intents, next.idempotency, next.lifecycles)
    }

    fn finalized_successor(
        &self,
        settlement: &PaymentFinalizedSettlementV1,
    ) -> Result<(Self, Digest384), JournalError> {
        let index = self
            .intents
            .binary_search_by_key(&settlement.intent(), PaymentIntentV1::intent)
            .map_err(|_| JournalError::InvalidLifecycle)?;
        if !self.intents[index].accepts_settlement(settlement.settled_amount()) {
            return Err(JournalError::InvalidLifecycle);
        }
        let sequence = self.lifecycles.records()[index]
            .sequence()
            .checked_add(1)
            .ok_or(JournalError::InvalidLifecycle)?;
        let record =
            settlement.finalized_record(sequence).map_err(|_| JournalError::InvalidLifecycle)?;
        let commitment = settlement.commitment().map_err(|_| JournalError::InvalidLifecycle)?;
        Ok((self.lifecycle_successor(record)?, commitment))
    }
}

impl CanonicalEncode for PaymentRequestStateV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.intents.len(), MAX_PAYMENT_INTENTS)?;
        for intent in &self.intents {
            intent.encode(encoder)?;
        }
        self.idempotency.encode(encoder)?;
        self.lifecycles.encode(encoder)
    }
}

impl CanonicalDecode for PaymentRequestStateV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_PAYMENT_INTENTS)?;
        let mut intents = Vec::with_capacity(count);
        for _ in 0..count {
            intents.push(PaymentIntentV1::decode(decoder)?);
        }
        Self::new(
            intents,
            IdempotencyJournalV1::decode(decoder)?,
            PaymentLifecycleJournalV1::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment request state"))
    }
}

impl CanonicalType for PaymentRequestStateV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 3
        + MAX_PAYMENT_INTENTS * PaymentIntentV1::MAX_ENCODED_LEN
        + IdempotencyJournalV1::MAX_ENCODED_LEN
        + PaymentLifecycleJournalV1::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurablePaymentRequestState {
    path: std::path::PathBuf,
    snapshot: PaymentRequestStateV1,
}

impl DurablePaymentRequestState {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let snapshot = match std::fs::metadata(&path) {
            Ok(_) => PaymentRequestStateV1::load(&path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                PaymentRequestStateV1::default()
            }
            Err(_) => return Err(JournalError::Persistence),
        };
        Ok(Self { path, snapshot })
    }

    pub const fn snapshot(&self) -> &PaymentRequestStateV1 {
        &self.snapshot
    }

    pub fn create_intent(
        &mut self,
        intent: PaymentIntentV1,
        binding: IdempotencyBindingV1,
        observation_commitment: Digest384,
        timestamp: u64,
    ) -> Result<PaymentIntentId, JournalError> {
        let (next, intent_id, changed) = self.snapshot.create_intent_successor(
            intent,
            binding,
            observation_commitment,
            timestamp,
        )?;
        if changed {
            next.save_atomic(&self.path)?;
            self.snapshot = next;
        }
        Ok(intent_id)
    }

    pub fn advance_lifecycle(
        &mut self,
        next_record: PaymentLifecycleRecordV1,
    ) -> Result<(), JournalError> {
        if matches!(
            next_record.state(),
            PaymentState::Finalized | PaymentState::RefundPending | PaymentState::Refunded
        ) {
            return Err(JournalError::InvalidLifecycle);
        }
        let next = self.snapshot.lifecycle_successor(next_record)?;
        next.save_atomic(&self.path)?;
        self.snapshot = next;
        Ok(())
    }

    /// Persists a finalized successor structurally bound to exact native settlement evidence.
    /// The caller must cryptographically verify the committed receipt/proof before invoking this.
    fn finalize_settlement(
        &mut self,
        settlement: &PaymentFinalizedSettlementV1,
    ) -> Result<Digest384, JournalError> {
        let (next, commitment) = self.snapshot.finalized_successor(settlement)?;
        next.save_atomic(&self.path)?;
        self.snapshot = next;
        Ok(commitment)
    }

    fn finalize_verified_settlement(
        &mut self,
        settlement: &PaymentFinalizedSettlementV1,
        finality: &[u8],
        receipt: &[u8],
        trusted_chain_genesis: Digest384,
    ) -> Result<Digest384, JournalError> {
        let encoded = encode_envelope(settlement).map_err(|_| JournalError::InvalidLifecycle)?;
        let verified = activechain_verifier_api::verify_payment_finalized_settlement(
            &encoded,
            finality,
            receipt,
            trusted_chain_genesis,
        )
        .map_err(|_| JournalError::InvalidLifecycle)?;
        self.finalize_settlement(&verified)
    }
}

/// Complete payment state retaining verified settlement evidence and exact refund accounting.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PaymentSettlementStateV1 {
    requests: PaymentRequestStateV1,
    settlements: Vec<PaymentFinalizedSettlementV1>,
    finalized_refunds: Vec<PaymentFinalizedRefundV1>,
    refunds: RefundJournalV1,
    disputes: DisputeJournalV1,
    treasuries: TreasuryJournalV1,
    authorizations: ApiAuthorizationJournalV1,
    webhooks: WebhookDeliveryJournalV1,
    sponsorships: FeeSponsorshipJournalV1,
}

impl PaymentSettlementStateV1 {
    pub const TYPE_TAG: u16 = 0x0189;

    pub fn new(
        requests: PaymentRequestStateV1,
        settlements: Vec<PaymentFinalizedSettlementV1>,
        finalized_refunds: Vec<PaymentFinalizedRefundV1>,
        refunds: RefundJournalV1,
        disputes: DisputeJournalV1,
        treasuries: TreasuryJournalV1,
        authorizations: ApiAuthorizationJournalV1,
        webhooks: WebhookDeliveryJournalV1,
        sponsorships: FeeSponsorshipJournalV1,
    ) -> Result<Self, JournalError> {
        if settlements.len() > MAX_PAYMENT_INTENTS
            || settlements.windows(2).any(|pair| pair[0].intent() >= pair[1].intent())
            || finalized_refunds.len() > MAX_PAYMENT_INTENTS
            || finalized_refunds.windows(2).any(|pair| pair[0].intent() >= pair[1].intent())
            || settlements.len() != refunds.states().len()
        {
            return Err(JournalError::InvalidLifecycle);
        }
        for (settlement, refund) in settlements.iter().zip(refunds.states()) {
            if settlement.intent() != refund.intent()
                || settlement.settled_amount() != refund.settled_amount()
                || settlement.commitment().map_err(|_| JournalError::InvalidLifecycle)?
                    != refund.settlement_commitment()
            {
                return Err(JournalError::InvalidLifecycle);
            }
        }
        for (intent, lifecycle) in requests.intents().iter().zip(requests.lifecycles().records()) {
            let settlement = settlements
                .binary_search_by_key(&intent.intent(), PaymentFinalizedSettlementV1::intent)
                .ok()
                .map(|index| &settlements[index]);
            if let Some(settlement) = settlement {
                if matches!(
                    lifecycle.state(),
                    PaymentState::Created
                        | PaymentState::AwaitingPayer
                        | PaymentState::ProviderPending
                        | PaymentState::ExternallyConfirmed
                        | PaymentState::ChainSubmitted
                ) || (lifecycle.state() == PaymentState::Finalized
                    && lifecycle.observation_commitment()
                        != settlement.commitment().map_err(|_| JournalError::InvalidLifecycle)?)
                {
                    return Err(JournalError::InvalidLifecycle);
                }
            } else if matches!(
                lifecycle.state(),
                PaymentState::Finalized | PaymentState::RefundPending | PaymentState::Refunded
            ) {
                return Err(JournalError::InvalidLifecycle);
            }
            let finalized_refund = finalized_refunds
                .binary_search_by_key(&intent.intent(), PaymentFinalizedRefundV1::intent)
                .ok()
                .map(|index| &finalized_refunds[index]);
            if lifecycle.state() == PaymentState::Refunded {
                let evidence = finalized_refund.ok_or(JournalError::InvalidRefund)?;
                let refund_index = refunds
                    .states()
                    .binary_search_by_key(&intent.intent(), PaymentRefundStateV1::intent)
                    .map_err(|_| JournalError::InvalidRefund)?;
                let refund = &refunds.states()[refund_index];
                let settlement = settlement.ok_or(JournalError::InvalidRefund)?;
                if evidence.settlement_commitment() != refund.settlement_commitment()
                    || evidence.refunded_amount() != refund.settled_amount()
                    || refund.refunded_units() != refund.settled_amount().atomic_units()
                    || refund.last_refund() != Some(evidence.refund())
                    || lifecycle.observation_commitment()
                        != evidence.commitment().map_err(|_| JournalError::InvalidRefund)?
                    || evidence.refunded_amount() != settlement.settled_amount()
                {
                    return Err(JournalError::InvalidRefund);
                }
            } else if finalized_refund.is_some() {
                return Err(JournalError::InvalidRefund);
            }
        }
        if disputes.records().iter().any(|record| {
            settlements
                .binary_search_by_key(&record.intent(), PaymentFinalizedSettlementV1::intent)
                .is_err()
        }) {
            return Err(JournalError::InvalidDispute);
        }
        Ok(Self {
            requests,
            settlements,
            finalized_refunds,
            refunds,
            disputes,
            treasuries,
            authorizations,
            webhooks,
            sponsorships,
        })
    }

    pub const fn requests(&self) -> &PaymentRequestStateV1 {
        &self.requests
    }

    pub fn settlements(&self) -> &[PaymentFinalizedSettlementV1] {
        &self.settlements
    }

    pub fn finalized_refunds(&self) -> &[PaymentFinalizedRefundV1] {
        &self.finalized_refunds
    }

    pub const fn refunds(&self) -> &RefundJournalV1 {
        &self.refunds
    }

    pub const fn disputes(&self) -> &DisputeJournalV1 {
        &self.disputes
    }

    pub const fn treasuries(&self) -> &TreasuryJournalV1 {
        &self.treasuries
    }

    pub const fn authorizations(&self) -> &ApiAuthorizationJournalV1 {
        &self.authorizations
    }

    pub const fn webhooks(&self) -> &WebhookDeliveryJournalV1 {
        &self.webhooks
    }

    pub const fn sponsorships(&self) -> &FeeSponsorshipJournalV1 {
        &self.sponsorships
    }
}

impl CanonicalEncode for PaymentSettlementStateV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.requests.encode(encoder)?;
        encoder.write_length(self.settlements.len(), MAX_PAYMENT_INTENTS)?;
        for settlement in &self.settlements {
            settlement.encode(encoder)?;
        }
        encoder.write_length(self.finalized_refunds.len(), MAX_PAYMENT_INTENTS)?;
        for refund in &self.finalized_refunds {
            refund.encode(encoder)?;
        }
        self.refunds.encode(encoder)?;
        self.disputes.encode(encoder)?;
        self.treasuries.encode(encoder)?;
        self.authorizations.encode(encoder)?;
        self.webhooks.encode(encoder)?;
        self.sponsorships.encode(encoder)
    }
}

impl CanonicalDecode for PaymentSettlementStateV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let requests = PaymentRequestStateV1::decode(decoder)?;
        let count = decoder.read_length(MAX_PAYMENT_INTENTS)?;
        let mut settlements = Vec::with_capacity(count);
        for _ in 0..count {
            settlements.push(PaymentFinalizedSettlementV1::decode(decoder)?);
        }
        let refund_count = decoder.read_length(MAX_PAYMENT_INTENTS)?;
        let mut finalized_refunds = Vec::with_capacity(refund_count);
        for _ in 0..refund_count {
            finalized_refunds.push(PaymentFinalizedRefundV1::decode(decoder)?);
        }
        Self::new(
            requests,
            settlements,
            finalized_refunds,
            RefundJournalV1::decode(decoder)?,
            DisputeJournalV1::decode(decoder)?,
            TreasuryJournalV1::decode(decoder)?,
            ApiAuthorizationJournalV1::decode(decoder)?,
            WebhookDeliveryJournalV1::decode(decoder)?,
            FeeSponsorshipJournalV1::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid payment settlement state"))
    }
}

impl CanonicalType for PaymentSettlementStateV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = PaymentRequestStateV1::MAX_ENCODED_LEN
        + 3
        + MAX_PAYMENT_INTENTS * PaymentFinalizedSettlementV1::MAX_ENCODED_LEN
        + 3
        + MAX_PAYMENT_INTENTS * PaymentFinalizedRefundV1::MAX_ENCODED_LEN
        + RefundJournalV1::MAX_ENCODED_LEN
        + DisputeJournalV1::MAX_ENCODED_LEN
        + TreasuryJournalV1::MAX_ENCODED_LEN
        + ApiAuthorizationJournalV1::MAX_ENCODED_LEN
        + WebhookDeliveryJournalV1::MAX_ENCODED_LEN
        + FeeSponsorshipJournalV1::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurablePaymentSettlementState {
    path: std::path::PathBuf,
    snapshot: PaymentSettlementStateV1,
}

impl DurablePaymentSettlementState {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let snapshot = match std::fs::metadata(&path) {
            Ok(_) => load_snapshot(&path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                PaymentSettlementStateV1::default()
            }
            Err(_) => return Err(JournalError::Persistence),
        };
        Ok(Self { path, snapshot })
    }

    pub const fn snapshot(&self) -> &PaymentSettlementStateV1 {
        &self.snapshot
    }

    pub fn create_intent(
        &mut self,
        intent: PaymentIntentV1,
        binding: IdempotencyBindingV1,
        observation_commitment: Digest384,
        timestamp: u64,
    ) -> Result<PaymentIntentId, JournalError> {
        let (requests, intent_id, changed) = self.snapshot.requests.create_intent_successor(
            intent,
            binding,
            observation_commitment,
            timestamp,
        )?;
        if changed {
            let next = PaymentSettlementStateV1::new(
                requests,
                self.snapshot.settlements.clone(),
                self.snapshot.finalized_refunds.clone(),
                self.snapshot.refunds.clone(),
                self.snapshot.disputes.clone(),
                self.snapshot.treasuries.clone(),
                self.snapshot.authorizations.clone(),
                self.snapshot.webhooks.clone(),
                self.snapshot.sponsorships.clone(),
            )?;
            save_snapshot(&next, &self.path)?;
            self.snapshot = next;
        }
        Ok(intent_id)
    }

    pub fn advance_lifecycle(
        &mut self,
        next_record: PaymentLifecycleRecordV1,
    ) -> Result<(), JournalError> {
        if matches!(
            next_record.state(),
            PaymentState::Finalized | PaymentState::RefundPending | PaymentState::Refunded
        ) {
            return Err(JournalError::InvalidLifecycle);
        }
        let requests = self.snapshot.requests.lifecycle_successor(next_record)?;
        let next = PaymentSettlementStateV1::new(
            requests,
            self.snapshot.settlements.clone(),
            self.snapshot.finalized_refunds.clone(),
            self.snapshot.refunds.clone(),
            self.snapshot.disputes.clone(),
            self.snapshot.treasuries.clone(),
            self.snapshot.authorizations.clone(),
            self.snapshot.webhooks.clone(),
            self.snapshot.sponsorships.clone(),
        )?;
        save_snapshot(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }

    pub fn finalize_verified_settlement(
        &mut self,
        settlement: &PaymentFinalizedSettlementV1,
        finality: &[u8],
        receipt: &[u8],
        trusted_chain_genesis: Digest384,
    ) -> Result<Digest384, JournalError> {
        let encoded = encode_envelope(settlement).map_err(|_| JournalError::InvalidLifecycle)?;
        let verified = activechain_verifier_api::verify_payment_finalized_settlement(
            &encoded,
            finality,
            receipt,
            trusted_chain_genesis,
        )
        .map_err(|_| JournalError::InvalidLifecycle)?;
        self.finalize_verified_value(&verified)
    }

    fn finalize_verified_value(
        &mut self,
        verified: &PaymentFinalizedSettlementV1,
    ) -> Result<Digest384, JournalError> {
        let (requests, commitment) = self.snapshot.requests.finalized_successor(verified)?;
        let mut settlements = self.snapshot.settlements.clone();
        let index = settlements
            .binary_search_by_key(&verified.intent(), PaymentFinalizedSettlementV1::intent)
            .map_or_else(|index| index, |_| usize::MAX);
        if index == usize::MAX {
            return Err(JournalError::InvalidLifecycle);
        }
        settlements.insert(index, *verified);
        let mut refunds = self.snapshot.refunds.clone();
        refunds.register(
            PaymentRefundStateV1::new(verified.intent(), commitment, verified.settled_amount())
                .map_err(|_| JournalError::InvalidRefund)?,
        )?;
        let next = PaymentSettlementStateV1::new(
            requests,
            settlements,
            self.snapshot.finalized_refunds.clone(),
            refunds,
            self.snapshot.disputes.clone(),
            self.snapshot.treasuries.clone(),
            self.snapshot.authorizations.clone(),
            self.snapshot.webhooks.clone(),
            self.snapshot.sponsorships.clone(),
        )?;
        save_snapshot(&next, &self.path)?;
        self.snapshot = next;
        Ok(commitment)
    }

    /// Atomically joins refund accounting to the first refund-pending lifecycle successor.
    pub fn request_refund(
        &mut self,
        request: &PaymentRefundRequestV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        let index = self
            .snapshot
            .requests
            .intents()
            .binary_search_by_key(&request.intent(), PaymentIntentV1::intent)
            .map_err(|_| JournalError::InvalidRefund)?;
        if self
            .snapshot
            .settlements
            .binary_search_by_key(&request.intent(), PaymentFinalizedSettlementV1::intent)
            .is_err()
        {
            return Err(JournalError::InvalidRefund);
        }

        let lifecycle = &self.snapshot.requests.lifecycles().records()[index];
        let requests = match lifecycle.state() {
            PaymentState::Finalized => {
                let sequence =
                    lifecycle.sequence().checked_add(1).ok_or(JournalError::InvalidLifecycle)?;
                let record = PaymentLifecycleRecordV1::new(
                    request.intent(),
                    sequence,
                    PaymentState::RefundPending,
                    EvidenceClass::UntrustedClientReport,
                    request.commitment().map_err(|_| JournalError::InvalidRefund)?,
                    None,
                    0,
                    None,
                    0,
                )
                .map_err(|_| JournalError::InvalidLifecycle)?;
                self.snapshot.requests.lifecycle_successor(record)?
            }
            PaymentState::RefundPending => self.snapshot.requests.clone(),
            _ => return Err(JournalError::InvalidRefund),
        };

        let mut refunds = self.snapshot.refunds.clone();
        refunds.apply(request, timestamp)?;
        let next = PaymentSettlementStateV1::new(
            requests,
            self.snapshot.settlements.clone(),
            self.snapshot.finalized_refunds.clone(),
            refunds,
            self.snapshot.disputes.clone(),
            self.snapshot.treasuries.clone(),
            self.snapshot.authorizations.clone(),
            self.snapshot.webhooks.clone(),
            self.snapshot.sponsorships.clone(),
        )?;
        save_snapshot(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }

    pub fn finalize_verified_refund(
        &mut self,
        refund: &PaymentFinalizedRefundV1,
        finality: &[u8],
        receipt: &[u8],
        trusted_chain_genesis: Digest384,
    ) -> Result<Digest384, JournalError> {
        let encoded = encode_envelope(refund).map_err(|_| JournalError::InvalidRefund)?;
        let verified = activechain_verifier_api::verify_payment_finalized_refund(
            &encoded,
            finality,
            receipt,
            trusted_chain_genesis,
        )
        .map_err(|_| JournalError::InvalidRefund)?;
        self.finalize_verified_refund_value(&verified)
    }

    fn finalize_verified_refund_value(
        &mut self,
        verified: &PaymentFinalizedRefundV1,
    ) -> Result<Digest384, JournalError> {
        let index = self
            .snapshot
            .requests
            .intents()
            .binary_search_by_key(&verified.intent(), PaymentIntentV1::intent)
            .map_err(|_| JournalError::InvalidRefund)?;
        let lifecycle = &self.snapshot.requests.lifecycles().records()[index];
        let refund_index = self
            .snapshot
            .refunds
            .states()
            .binary_search_by_key(&verified.intent(), PaymentRefundStateV1::intent)
            .map_err(|_| JournalError::InvalidRefund)?;
        let refund = &self.snapshot.refunds.states()[refund_index];
        if lifecycle.state() != PaymentState::RefundPending
            || verified.settlement_commitment() != refund.settlement_commitment()
            || verified.refunded_amount() != refund.settled_amount()
            || refund.refunded_units() != refund.settled_amount().atomic_units()
            || refund.last_refund() != Some(verified.refund())
        {
            return Err(JournalError::InvalidRefund);
        }
        let sequence = lifecycle.sequence().checked_add(1).ok_or(JournalError::InvalidLifecycle)?;
        let record = verified.refunded_record(sequence).map_err(|_| JournalError::InvalidRefund)?;
        let requests = self.snapshot.requests.lifecycle_successor(record)?;
        let mut finalized_refunds = self.snapshot.finalized_refunds.clone();
        let evidence_index = finalized_refunds
            .binary_search_by_key(&verified.intent(), PaymentFinalizedRefundV1::intent)
            .map_or_else(|index| index, |_| usize::MAX);
        if evidence_index == usize::MAX {
            return Err(JournalError::InvalidRefund);
        }
        finalized_refunds.insert(evidence_index, *verified);
        let commitment = verified.commitment().map_err(|_| JournalError::InvalidRefund)?;
        let next = PaymentSettlementStateV1::new(
            requests,
            self.snapshot.settlements.clone(),
            finalized_refunds,
            self.snapshot.refunds.clone(),
            self.snapshot.disputes.clone(),
            self.snapshot.treasuries.clone(),
            self.snapshot.authorizations.clone(),
            self.snapshot.webhooks.clone(),
            self.snapshot.sponsorships.clone(),
        )?;
        save_snapshot(&next, &self.path)?;
        self.snapshot = next;
        Ok(commitment)
    }

    pub fn open_dispute(
        &mut self,
        request: &PaymentDisputeRequestV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        let index = self
            .snapshot
            .settlements
            .binary_search_by_key(&request.intent(), PaymentFinalizedSettlementV1::intent)
            .map_err(|_| JournalError::InvalidDispute)?;
        let settlement = &self.snapshot.settlements[index];
        if request.settlement_commitment()
            != settlement.commitment().map_err(|_| JournalError::InvalidDispute)?
            || request.amount().asset() != settlement.settled_amount().asset()
            || request.amount().atomic_units() > settlement.settled_amount().atomic_units()
        {
            return Err(JournalError::InvalidDispute);
        }
        let mut disputes = self.snapshot.disputes.clone();
        disputes.open(request, timestamp)?;
        let next = PaymentSettlementStateV1::new(
            self.snapshot.requests.clone(),
            self.snapshot.settlements.clone(),
            self.snapshot.finalized_refunds.clone(),
            self.snapshot.refunds.clone(),
            disputes,
            self.snapshot.treasuries.clone(),
            self.snapshot.authorizations.clone(),
            self.snapshot.webhooks.clone(),
            self.snapshot.sponsorships.clone(),
        )?;
        save_snapshot(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }

    pub fn advance_dispute(
        &mut self,
        next_record: PaymentDisputeRecordV1,
    ) -> Result<(), JournalError> {
        let mut disputes = self.snapshot.disputes.clone();
        disputes.advance(next_record)?;
        let next = PaymentSettlementStateV1::new(
            self.snapshot.requests.clone(),
            self.snapshot.settlements.clone(),
            self.snapshot.finalized_refunds.clone(),
            self.snapshot.refunds.clone(),
            disputes,
            self.snapshot.treasuries.clone(),
            self.snapshot.authorizations.clone(),
            self.snapshot.webhooks.clone(),
            self.snapshot.sponsorships.clone(),
        )?;
        save_snapshot(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }

    pub fn register_treasury(&mut self, policy: TreasuryDebitPolicyV1) -> Result<(), JournalError> {
        let mut treasuries = self.snapshot.treasuries.clone();
        treasuries.register(policy)?;
        let next = PaymentSettlementStateV1::new(
            self.snapshot.requests.clone(),
            self.snapshot.settlements.clone(),
            self.snapshot.finalized_refunds.clone(),
            self.snapshot.refunds.clone(),
            self.snapshot.disputes.clone(),
            treasuries,
            self.snapshot.authorizations.clone(),
            self.snapshot.webhooks.clone(),
            self.snapshot.sponsorships.clone(),
        )?;
        save_snapshot(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }

    pub fn authorize_treasury_debit(
        &mut self,
        request: &TreasuryDebitRequestV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        let mut treasuries = self.snapshot.treasuries.clone();
        treasuries.authorize(request, timestamp)?;
        let next = PaymentSettlementStateV1::new(
            self.snapshot.requests.clone(),
            self.snapshot.settlements.clone(),
            self.snapshot.finalized_refunds.clone(),
            self.snapshot.refunds.clone(),
            self.snapshot.disputes.clone(),
            treasuries,
            self.snapshot.authorizations.clone(),
            self.snapshot.webhooks.clone(),
            self.snapshot.sponsorships.clone(),
        )?;
        save_snapshot(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }

    pub fn authorize_api_call(
        &mut self,
        authorization: &PaymentApiAuthorizationV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        let mut authorizations = self.snapshot.authorizations.clone();
        authorizations.authorize(authorization, timestamp)?;
        let next = PaymentSettlementStateV1::new(
            self.snapshot.requests.clone(),
            self.snapshot.settlements.clone(),
            self.snapshot.finalized_refunds.clone(),
            self.snapshot.refunds.clone(),
            self.snapshot.disputes.clone(),
            self.snapshot.treasuries.clone(),
            authorizations,
            self.snapshot.webhooks.clone(),
            self.snapshot.sponsorships.clone(),
        )?;
        save_snapshot(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }

    pub fn authorize_signed_api_call(
        &mut self,
        signed: &PaymentApiSignedAuthorizationV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        let authorization = signed.authorization();
        let payload =
            authorization.signing_payload().map_err(|_| JournalError::InvalidAuthorization)?;
        verify_ml_dsa44(signed.public_key(), &payload, signed.signature().as_bytes())
            .map_err(|_| JournalError::InvalidAuthorization)?;
        self.authorize_api_call(authorization, timestamp)
    }

    pub fn deliver_webhook(
        &mut self,
        event: &PaymentWebhookEventV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        if self
            .snapshot
            .requests
            .intents()
            .binary_search_by_key(&event.intent(), PaymentIntentV1::intent)
            .is_err()
        {
            return Err(JournalError::InvalidDelivery);
        }
        let mut webhooks = self.snapshot.webhooks.clone();
        webhooks.deliver(event, timestamp)?;
        let next = PaymentSettlementStateV1::new(
            self.snapshot.requests.clone(),
            self.snapshot.settlements.clone(),
            self.snapshot.finalized_refunds.clone(),
            self.snapshot.refunds.clone(),
            self.snapshot.disputes.clone(),
            self.snapshot.treasuries.clone(),
            self.snapshot.authorizations.clone(),
            webhooks,
            self.snapshot.sponsorships.clone(),
        )?;
        save_snapshot(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }

    pub fn deliver_signed_webhook(
        &mut self,
        signed: &PaymentWebhookSignedEventV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        let event = signed.event();
        let payload = event.signing_payload().map_err(|_| JournalError::InvalidDelivery)?;
        verify_ml_dsa44(signed.public_key(), &payload, signed.signature().as_bytes())
            .map_err(|_| JournalError::InvalidDelivery)?;
        self.deliver_webhook(event, timestamp)
    }

    pub fn register_fee_sponsor(
        &mut self,
        policy: PaymentFeeSponsorPolicyV1,
    ) -> Result<(), JournalError> {
        let mut sponsorships = self.snapshot.sponsorships.clone();
        sponsorships.register(policy)?;
        let next = PaymentSettlementStateV1::new(
            self.snapshot.requests.clone(),
            self.snapshot.settlements.clone(),
            self.snapshot.finalized_refunds.clone(),
            self.snapshot.refunds.clone(),
            self.snapshot.disputes.clone(),
            self.snapshot.treasuries.clone(),
            self.snapshot.authorizations.clone(),
            self.snapshot.webhooks.clone(),
            sponsorships,
        )?;
        save_snapshot(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }

    pub fn authorize_fee_sponsorship(
        &mut self,
        request: &PaymentFeeSponsorRequestV1,
        timestamp: u64,
    ) -> Result<(), JournalError> {
        if self
            .snapshot
            .requests
            .intents()
            .binary_search_by_key(&request.intent(), PaymentIntentV1::intent)
            .is_err()
        {
            return Err(JournalError::InvalidTreasury);
        }
        let mut sponsorships = self.snapshot.sponsorships.clone();
        sponsorships.authorize(request, timestamp)?;
        let next = PaymentSettlementStateV1::new(
            self.snapshot.requests.clone(),
            self.snapshot.settlements.clone(),
            self.snapshot.finalized_refunds.clone(),
            self.snapshot.refunds.clone(),
            self.snapshot.disputes.clone(),
            self.snapshot.treasuries.clone(),
            self.snapshot.authorizations.clone(),
            self.snapshot.webhooks.clone(),
            sponsorships,
        )?;
        save_snapshot(&next, &self.path)?;
        self.snapshot = next;
        Ok(())
    }
}

impl PaymentRequestStateV1 {
    fn save_atomic(&self, path: &Path) -> Result<(), JournalError> {
        save_snapshot(self, path)
    }

    fn load(path: &Path) -> Result<Self, JournalError> {
        load_snapshot(path)
    }
}

fn map_validation(_: PaymentValidationError) -> JournalError {
    JournalError::InvalidObservation
}

fn save_snapshot<T: CanonicalType + CanonicalEncode>(
    value: &T,
    path: &Path,
) -> Result<(), JournalError> {
    let body = encode_envelope(value).map_err(|_| JournalError::Persistence)?;
    let tag = snapshot_tag(&body);
    let parent = path.parent().ok_or(JournalError::Persistence)?;
    std::fs::create_dir_all(parent).map_err(|_| JournalError::Persistence)?;
    let name = path.file_name().ok_or(JournalError::Persistence)?.to_string_lossy();
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = File::create(&temporary).map_err(|_| JournalError::Persistence)?;
        file.write_all(&body)
            .and_then(|_| file.write_all(&tag))
            .and_then(|_| file.sync_all())
            .map_err(|_| JournalError::Persistence)?;
        std::fs::rename(&temporary, path).map_err(|_| JournalError::Persistence)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| JournalError::Persistence)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

fn load_snapshot<T: CanonicalType + CanonicalDecode>(path: &Path) -> Result<T, JournalError> {
    let bytes = std::fs::read(path).map_err(|_| JournalError::Persistence)?;
    if bytes.len() < SNAPSHOT_TAG_LENGTH {
        return Err(JournalError::Persistence);
    }
    let body_length = bytes.len() - SNAPSHOT_TAG_LENGTH;
    if snapshot_tag(&bytes[..body_length]) != bytes[body_length..] {
        return Err(JournalError::Persistence);
    }
    decode_envelope(&bytes[..body_length]).map_err(|_| JournalError::Persistence)
}

fn snapshot_tag(bytes: &[u8]) -> [u8; SNAPSHOT_TAG_LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(SNAPSHOT_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    let mut output = [0; SNAPSHOT_TAG_LENGTH];
    hasher.finalize_xof().read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_payment_types::{
        AssetAmountV1, ConnectorId, EvidenceClass, PaymentApiOperation, PaymentAttemptId,
        PaymentDisputeId, PaymentDisputeState, PaymentIntentId, PaymentLifecycleRecordV1,
        PaymentRefundId, PaymentRefundRequestV1, PaymentRefundStateV1, PaymentState,
        PaymentWebhookEventId, PaymentWebhookEventV1, PaymentWebhookSignedEventV1,
        PaymentWebhookSubscriptionId, ProviderOperationState, RailId, TreasuryDebitKind,
        TreasuryDebitRequestV1, TreasuryId, payment_api_authenticator_commitment,
        payment_webhook_signer_commitment,
    };
    use activechain_protocol_types::{
        AssetId, ChainId, CryptoSuiteId, Digest384, PrincipalId, ProtocolSignature, TransactionId,
    };
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    use std::path::PathBuf;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn observation(attempt: u8, sequence: u64, payload: u8) -> ProviderObservationV1 {
        ProviderObservationV1::new(
            ChainId::new(digest(1)),
            ConnectorId::new(digest(2)).unwrap(),
            PaymentAttemptId::new(digest(attempt)).unwrap(),
            PaymentIntentId::new(digest(4)).unwrap(),
            digest(5),
            digest(6),
            sequence,
            ProviderOperationState::Pending,
            AssetAmountV1::new(AssetId::new(digest(7)), 100).unwrap(),
            100,
            100 + sequence,
            EvidenceClass::ProviderSigned,
            digest(payload),
        )
        .unwrap()
    }

    fn webhook_event(subscription: u8, event: u8, sequence: u64) -> PaymentWebhookEventV1 {
        let state =
            if sequence == 1 { PaymentState::Created } else { PaymentState::ProviderPending };
        PaymentWebhookEventV1::new(
            PaymentWebhookSubscriptionId::new(digest(subscription)).unwrap(),
            PaymentWebhookEventId::new(digest(event)).unwrap(),
            PaymentLifecycleRecordV1::new(
                PaymentIntentId::new(digest(4)).unwrap(),
                sequence,
                state,
                EvidenceClass::ConnectorAuthenticated,
                digest(70 + sequence as u8),
                None,
                0,
                None,
                0,
            )
            .unwrap(),
            digest(80),
            digest(81),
            100,
            200,
        )
        .unwrap()
    }

    fn api_authorization(caller: u8, audience: u8, sequence: u64) -> PaymentApiAuthorizationV1 {
        PaymentApiAuthorizationV1::new(
            PrincipalId::new(digest(caller)),
            digest(audience),
            PaymentApiOperation::CreateIntent,
            digest(70),
            digest(71),
            Some(PaymentIntentId::new(digest(4)).unwrap()),
            sequence,
            100,
            200,
            digest(72 + sequence as u8),
        )
        .unwrap()
    }

    fn signed_api_authorization(
        seed: u8,
        operation: PaymentApiOperation,
    ) -> PaymentApiSignedAuthorizationV1 {
        let signing_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([seed; 32]));
        let public_key = signing_key.verifying_key().encode().to_vec();
        let authorization = PaymentApiAuthorizationV1::new(
            PrincipalId::new(digest(50)),
            digest(60),
            operation,
            digest(70),
            digest(71),
            Some(PaymentIntentId::new(digest(4)).unwrap()),
            1,
            100,
            200,
            payment_api_authenticator_commitment(&public_key),
        )
        .unwrap();
        let signature = signing_key.sign(&authorization.signing_payload().unwrap());
        PaymentApiSignedAuthorizationV1::new(
            authorization,
            public_key,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap()
    }

    fn signed_webhook_event(
        seed: u8,
        event_byte: u8,
        sequence: u64,
    ) -> PaymentWebhookSignedEventV1 {
        let signing_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([seed; 32]));
        let public_key = signing_key.verifying_key().encode().to_vec();
        let state =
            if sequence == 1 { PaymentState::Created } else { PaymentState::ProviderPending };
        let event = PaymentWebhookEventV1::new(
            PaymentWebhookSubscriptionId::new(digest(50)).unwrap(),
            PaymentWebhookEventId::new(digest(event_byte)).unwrap(),
            PaymentLifecycleRecordV1::new(
                PaymentIntentId::new(digest(4)).unwrap(),
                sequence,
                state,
                EvidenceClass::ConnectorAuthenticated,
                digest(70 + sequence as u8),
                None,
                0,
                None,
                0,
            )
            .unwrap(),
            digest(80),
            payment_webhook_signer_commitment(&public_key),
            100,
            200,
        )
        .unwrap();
        let signature = signing_key.sign(&event.signing_payload().unwrap());
        PaymentWebhookSignedEventV1::new(
            event,
            public_key,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap()
    }

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "activebridge-{name}-{}-{}.bin",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    fn host_policy() -> ConnectorHostPolicyV1 {
        ConnectorHostPolicyV1::new(
            ConnectorId::new(digest(30)).unwrap(),
            vec![b"https://sandbox.example".to_vec()],
            digest(31),
            vec![
                ConnectorRouteV1::new(
                    RailId::new(digest(32)).unwrap(),
                    AssetId::new(digest(33)),
                    10_000,
                )
                .unwrap(),
            ],
            1_000,
            5_000,
        )
        .unwrap()
    }

    #[test]
    fn connector_policy_round_trips_and_authorizes_exact_route() {
        let policy = host_policy();
        let bytes = encode_envelope(&policy).unwrap();
        assert_eq!(decode_envelope::<ConnectorHostPolicyV1>(&bytes).unwrap(), policy);
        assert_eq!(
            policy.authorize(
                ConnectorId::new(digest(30)).unwrap(),
                b"https://sandbox.example",
                RailId::new(digest(32)).unwrap(),
                AssetId::new(digest(33)),
                10_000,
            ),
            Ok(())
        );
    }

    #[test]
    fn connector_policy_fails_closed() {
        let policy = host_policy();
        let connector = ConnectorId::new(digest(30)).unwrap();
        let rail = RailId::new(digest(32)).unwrap();
        let asset = AssetId::new(digest(33));
        assert_eq!(
            policy.authorize(connector, b"http://sandbox.example", rail, asset, 1),
            Err(ConnectorPolicyError::Unauthorized)
        );
        assert_eq!(
            policy.authorize(connector, b"https://sandbox.example", rail, asset, 10_001),
            Err(ConnectorPolicyError::Unauthorized)
        );
        assert_eq!(
            policy.authorize(
                ConnectorId::new(digest(40)).unwrap(),
                b"https://sandbox.example",
                rail,
                asset,
                1,
            ),
            Err(ConnectorPolicyError::Unauthorized)
        );
        assert_eq!(
            policy.authorize(
                connector,
                b"https://sandbox.example",
                RailId::new(digest(41)).unwrap(),
                asset,
                1,
            ),
            Err(ConnectorPolicyError::Unauthorized)
        );
    }

    #[test]
    fn connector_policy_rejects_ambiguous_or_unsafe_configuration() {
        let route = ConnectorRouteV1::new(
            RailId::new(digest(32)).unwrap(),
            AssetId::new(digest(33)),
            10_000,
        )
        .unwrap();
        let connector = ConnectorId::new(digest(30)).unwrap();
        assert_eq!(
            ConnectorHostPolicyV1::new(
                connector,
                vec![b"http://sandbox.example".to_vec()],
                digest(31),
                vec![route],
                1_000,
                5_000,
            ),
            Err(ConnectorPolicyError::InvalidOrigin)
        );
        assert_eq!(
            ConnectorHostPolicyV1::new(
                connector,
                vec![b"https://sandbox.example".to_vec()],
                digest(31),
                vec![route, route],
                1_000,
                5_000,
            ),
            Err(ConnectorPolicyError::InvalidRoute)
        );
        assert_eq!(
            ConnectorHostPolicyV1::new(
                connector,
                vec![b"https://sandbox.example".to_vec()],
                digest(31),
                vec![route],
                6_000,
                5_000,
            ),
            Err(ConnectorPolicyError::InvalidTimeout)
        );
    }

    #[test]
    fn exact_replay_is_noop_and_gaps_fail_closed() {
        let mut journal = ConnectorJournalV1::default();
        let first = observation(10, 1, 20);
        assert_eq!(journal.record(first.clone()), Ok(true));
        assert_eq!(journal.record(first), Ok(false));
        assert_eq!(journal.record(observation(10, 3, 22)), Err(JournalError::InvalidObservation));
        assert_eq!(journal.observations()[0].sequence(), 1);
    }

    #[test]
    fn durable_advance_survives_restart_and_corruption_is_rejected() {
        let path = path("restart");
        let _ = std::fs::remove_file(&path);
        let mut journal = ConnectorJournalV1::default();
        assert_eq!(journal.record_durable(observation(10, 1, 20), &path), Ok(true));
        assert_eq!(ConnectorJournalV1::load(&path).unwrap(), journal);
        assert_eq!(journal.record_durable(observation(10, 2, 21), &path), Ok(true));
        assert_eq!(ConnectorJournalV1::load(&path).unwrap(), journal);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[8] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(ConnectorJournalV1::load(&path), Err(JournalError::Persistence));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_persistence_does_not_mutate_memory() {
        let directory = path("directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let mut journal = ConnectorJournalV1::default();
        assert_eq!(
            journal.record_durable(observation(10, 1, 20), &directory),
            Err(JournalError::Persistence)
        );
        assert!(journal.observations().is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn webhook_delivery_survives_restart_and_rejects_replay_or_gaps() {
        let path = path("webhook-restart");
        let _ = std::fs::remove_file(&path);
        let mut journal = WebhookDeliveryJournalV1::default();
        let first = webhook_event(50, 51, 1);
        journal.deliver_durable(&first, 150, &path).unwrap();
        assert_eq!(WebhookDeliveryJournalV1::load(&path).unwrap(), journal);
        assert_eq!(journal.cursors()[0].next_sequence(), 2);
        assert_eq!(journal.deliver(&first, 150), Err(JournalError::InvalidDelivery));
        assert_eq!(
            journal.deliver(&webhook_event(50, 53, 3), 150),
            Err(JournalError::InvalidDelivery)
        );
        journal.deliver_durable(&webhook_event(50, 52, 2), 150, &path).unwrap();
        assert_eq!(WebhookDeliveryJournalV1::load(&path).unwrap(), journal);
        assert_eq!(journal.cursors()[0].next_sequence(), 3);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn webhook_journal_is_ordered_and_corruption_fails_closed() {
        let path = path("webhook-corrupt");
        let _ = std::fs::remove_file(&path);
        let mut journal = WebhookDeliveryJournalV1::default();
        journal.deliver(&webhook_event(60, 61, 1), 150).unwrap();
        journal.deliver(&webhook_event(50, 51, 1), 150).unwrap();
        assert!(journal.cursors()[0].subscription() < journal.cursors()[1].subscription());
        journal.save_atomic(&path).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[8] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(WebhookDeliveryJournalV1::load(&path), Err(JournalError::Persistence));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_webhook_persistence_does_not_advance_memory() {
        let directory = path("webhook-directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let mut journal = WebhookDeliveryJournalV1::default();
        assert_eq!(
            journal.deliver_durable(&webhook_event(50, 51, 1), 150, &directory),
            Err(JournalError::Persistence)
        );
        assert!(journal.cursors().is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn api_authorization_survives_restart_and_rejects_replay_or_gaps() {
        let path = path("api-auth-restart");
        let _ = std::fs::remove_file(&path);
        let mut journal = ApiAuthorizationJournalV1::default();
        let first = api_authorization(50, 60, 1);
        journal.authorize_durable(&first, 150, &path).unwrap();
        assert_eq!(ApiAuthorizationJournalV1::load(&path).unwrap(), journal);
        assert_eq!(journal.states()[0].next_sequence(), 2);
        assert_eq!(journal.authorize(&first, 150), Err(JournalError::InvalidAuthorization));
        assert_eq!(
            journal.authorize(&api_authorization(50, 60, 3), 150),
            Err(JournalError::InvalidAuthorization)
        );
        journal.authorize_durable(&api_authorization(50, 60, 2), 150, &path).unwrap();
        assert_eq!(ApiAuthorizationJournalV1::load(&path).unwrap(), journal);
        assert_eq!(journal.states()[0].next_sequence(), 3);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn api_authorization_journal_is_ordered_and_corruption_fails_closed() {
        let path = path("api-auth-corrupt");
        let _ = std::fs::remove_file(&path);
        let mut journal = ApiAuthorizationJournalV1::default();
        journal.authorize(&api_authorization(60, 61, 1), 150).unwrap();
        journal.authorize(&api_authorization(50, 60, 1), 150).unwrap();
        assert!(journal.states()[0].caller() < journal.states()[1].caller());
        journal.save_atomic(&path).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[8] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(ApiAuthorizationJournalV1::load(&path), Err(JournalError::Persistence));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_api_authorization_persistence_does_not_advance_memory() {
        let directory = path("api-auth-directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let mut journal = ApiAuthorizationJournalV1::default();
        assert_eq!(
            journal.authorize_durable(&api_authorization(50, 60, 1), 150, &directory),
            Err(JournalError::Persistence)
        );
        assert!(journal.states().is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn signed_api_authorization_verifies_before_replay_state_advances() {
        let path = path("signed-api-auth");
        let _ = std::fs::remove_file(&path);
        let mut journal = ApiAuthorizationJournalV1::default();
        let signed = signed_api_authorization(1, PaymentApiOperation::CreateIntent);
        journal.authorize_signed_durable(&signed, 150, &path).unwrap();
        assert_eq!(journal.states()[0].next_sequence(), 2);
        assert_eq!(ApiAuthorizationJournalV1::load(&path).unwrap(), journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn invalid_or_substituted_api_signature_never_advances_replay_state() {
        let path = path("invalid-signed-api-auth");
        let _ = std::fs::remove_file(&path);
        let valid = signed_api_authorization(1, PaymentApiOperation::CreateIntent);
        let substituted = signed_api_authorization(1, PaymentApiOperation::Refund);
        let forged = PaymentApiSignedAuthorizationV1::new(
            *substituted.authorization(),
            valid.public_key().to_vec(),
            valid.signature().clone(),
        )
        .unwrap();
        let mut journal = ApiAuthorizationJournalV1::default();
        assert_eq!(
            journal.authorize_signed_durable(&forged, 150, &path),
            Err(JournalError::InvalidAuthorization)
        );
        assert!(journal.states().is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn signed_webhook_verifies_before_durable_cursor_advance() {
        let path = path("signed-webhook");
        let _ = std::fs::remove_file(&path);
        let mut journal = WebhookDeliveryJournalV1::default();
        let signed = signed_webhook_event(1, 51, 1);
        journal.deliver_signed_durable(&signed, 150, &path).unwrap();
        assert_eq!(journal.cursors()[0].next_sequence(), 2);
        assert_eq!(WebhookDeliveryJournalV1::load(&path).unwrap(), journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn forged_or_substituted_webhook_never_advances_cursor() {
        let path = path("invalid-signed-webhook");
        let _ = std::fs::remove_file(&path);
        let valid = signed_webhook_event(1, 51, 1);
        let substituted = signed_webhook_event(1, 52, 1);
        let forged = PaymentWebhookSignedEventV1::new(
            substituted.event().clone(),
            valid.public_key().to_vec(),
            valid.signature().clone(),
        )
        .unwrap();
        let mut journal = WebhookDeliveryJournalV1::default();
        assert_eq!(
            journal.deliver_signed_durable(&forged, 150, &path),
            Err(JournalError::InvalidDelivery)
        );
        assert!(journal.cursors().is_empty());
        assert!(!path.exists());
    }

    fn refund_state(intent: u8) -> PaymentRefundStateV1 {
        PaymentRefundStateV1::new(
            PaymentIntentId::new(digest(intent)).unwrap(),
            digest(80),
            AssetAmountV1::new(AssetId::new(digest(81)), 100).unwrap(),
        )
        .unwrap()
    }

    fn refund_request(
        intent: u8,
        refund: u8,
        amount: u128,
        sequence: u64,
        expected: u128,
    ) -> PaymentRefundRequestV1 {
        PaymentRefundRequestV1::new(
            PaymentRefundId::new(digest(refund)).unwrap(),
            PaymentIntentId::new(digest(intent)).unwrap(),
            PrincipalId::new(digest(82)),
            digest(80),
            AssetAmountV1::new(AssetId::new(digest(81)), amount).unwrap(),
            digest(83),
            digest(84),
            sequence,
            expected,
            100,
            200,
        )
        .unwrap()
    }

    #[test]
    fn refund_accounting_survives_restart_and_replay_fails_closed() {
        let path = path("refund-restart");
        let _ = std::fs::remove_file(&path);
        let mut journal = RefundJournalV1::default();
        journal.register_durable(refund_state(10), &path).unwrap();
        let request = refund_request(10, 11, 40, 1, 0);
        journal.apply_durable(&request, 150, &path).unwrap();
        assert_eq!(journal.states()[0].refunded_units(), 40);
        assert_eq!(journal.states()[0].next_sequence(), 2);
        assert_eq!(RefundJournalV1::load(&path).unwrap(), journal);
        let before = journal.clone();
        assert_eq!(journal.apply_durable(&request, 150, &path), Err(JournalError::InvalidRefund));
        assert_eq!(journal, before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn refund_journal_orders_intents_and_rejects_duplicate_unknown_and_over_refund() {
        let mut journal = RefundJournalV1::default();
        journal.register(refund_state(20)).unwrap();
        journal.register(refund_state(10)).unwrap();
        assert!(journal.states()[0].intent() < journal.states()[1].intent());
        assert_eq!(journal.register(refund_state(10)), Err(JournalError::InvalidRefund));
        assert_eq!(
            journal.apply(&refund_request(30, 31, 1, 1, 0), 150),
            Err(JournalError::InvalidRefund)
        );
        assert_eq!(
            journal.apply(&refund_request(10, 12, 101, 1, 0), 150),
            Err(JournalError::InvalidRefund)
        );
        assert_eq!(journal.states()[0].refunded_units(), 0);
    }

    #[test]
    fn failed_refund_persistence_and_corrupt_restart_do_not_advance() {
        let directory = path("refund-directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let mut journal = RefundJournalV1::default();
        assert_eq!(
            journal.register_durable(refund_state(10), &directory),
            Err(JournalError::Persistence)
        );
        assert!(journal.states().is_empty());
        std::fs::remove_dir_all(&directory).unwrap();

        let corrupt = path("refund-corrupt");
        let _ = std::fs::remove_file(&corrupt);
        std::fs::write(&corrupt, b"not canonical").unwrap();
        assert_eq!(RefundJournalV1::load(&corrupt), Err(JournalError::Persistence));
        std::fs::remove_file(corrupt).unwrap();
    }

    fn dispute_request(dispute: u8, intent: u8) -> PaymentDisputeRequestV1 {
        PaymentDisputeRequestV1::new(
            PaymentDisputeId::new(digest(dispute)).unwrap(),
            PaymentIntentId::new(digest(intent)).unwrap(),
            PrincipalId::new(digest(90)),
            digest(91),
            AssetAmountV1::new(AssetId::new(digest(92)), 40).unwrap(),
            digest(93),
            digest(94),
            digest(95),
            100,
            200,
        )
        .unwrap()
    }

    fn dispute_successor(
        dispute: u8,
        intent: u8,
        sequence: u64,
        state: PaymentDisputeState,
    ) -> PaymentDisputeRecordV1 {
        PaymentDisputeRecordV1::new(
            PaymentDisputeId::new(digest(dispute)).unwrap(),
            PaymentIntentId::new(digest(intent)).unwrap(),
            sequence,
            state,
            EvidenceClass::UntrustedClientReport,
            digest(96),
            None,
            0,
            None,
            0,
        )
        .unwrap()
    }

    #[test]
    fn dispute_lifecycle_survives_restart_and_replay_fails_closed() {
        let path = path("dispute-restart");
        let _ = std::fs::remove_file(&path);
        let request = dispute_request(10, 20);
        let mut journal = DisputeJournalV1::default();
        journal.open_durable(&request, 150, &path).unwrap();
        let evidence = dispute_successor(10, 20, 2, PaymentDisputeState::EvidenceSubmitted);
        journal.advance_durable(evidence.clone(), &path).unwrap();
        assert_eq!(journal.records()[0].sequence(), 2);
        assert_eq!(DisputeJournalV1::load(&path).unwrap(), journal);
        let before = journal.clone();
        assert_eq!(journal.advance_durable(evidence, &path), Err(JournalError::InvalidDispute));
        assert_eq!(journal, before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn dispute_journal_orders_ids_and_rejects_duplicate_unknown_and_invalid_edges() {
        let mut journal = DisputeJournalV1::default();
        journal.open(&dispute_request(20, 30), 150).unwrap();
        journal.open(&dispute_request(10, 20), 150).unwrap();
        assert!(journal.records()[0].dispute() < journal.records()[1].dispute());
        assert_eq!(journal.open(&dispute_request(10, 20), 150), Err(JournalError::InvalidDispute));
        assert_eq!(
            journal.advance(dispute_successor(40, 20, 2, PaymentDisputeState::EvidenceSubmitted,)),
            Err(JournalError::InvalidDispute)
        );
        assert_eq!(
            journal.advance(dispute_successor(10, 20, 3, PaymentDisputeState::EvidenceSubmitted,)),
            Err(JournalError::InvalidDispute)
        );
        assert_eq!(journal.records()[0].sequence(), 1);
    }

    #[test]
    fn failed_dispute_persistence_and_corrupt_restart_do_not_advance() {
        let directory = path("dispute-directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let mut journal = DisputeJournalV1::default();
        assert_eq!(
            journal.open_durable(&dispute_request(10, 20), 150, &directory),
            Err(JournalError::Persistence)
        );
        assert!(journal.records().is_empty());
        std::fs::remove_dir_all(&directory).unwrap();

        let corrupt = path("dispute-corrupt");
        let _ = std::fs::remove_file(&corrupt);
        std::fs::write(&corrupt, b"not canonical").unwrap();
        assert_eq!(DisputeJournalV1::load(&corrupt), Err(JournalError::Persistence));
        std::fs::remove_file(corrupt).unwrap();
    }

    fn treasury_policy(treasury: u8) -> TreasuryDebitPolicyV1 {
        TreasuryDebitPolicyV1::new(
            TreasuryId::new(digest(treasury)).unwrap(),
            PrincipalId::new(digest(100)),
            vec![PrincipalId::new(digest(101))],
            AssetId::new(digest(102)),
            50,
            100,
            0,
            7,
            1,
            1_000,
        )
        .unwrap()
    }

    fn treasury_request(
        policy: &TreasuryDebitPolicyV1,
        amount: u128,
        expected: u128,
        nonce: u64,
    ) -> TreasuryDebitRequestV1 {
        TreasuryDebitRequestV1::new(
            policy.treasury(),
            PrincipalId::new(digest(101)),
            TreasuryDebitKind::Payout,
            AssetAmountV1::new(AssetId::new(digest(102)), amount).unwrap(),
            digest(103),
            digest(104),
            digest(105),
            policy.commitment().unwrap(),
            expected,
            7,
            nonce,
            900,
        )
        .unwrap()
    }

    #[test]
    fn treasury_budget_and_nonce_survive_restart_and_replay_fails_closed() {
        let path = path("treasury-restart");
        let _ = std::fs::remove_file(&path);
        let policy = treasury_policy(10);
        let request = treasury_request(&policy, 40, 0, 1);
        let mut journal = TreasuryJournalV1::default();
        journal.register_durable(policy, &path).unwrap();
        journal.authorize_durable(&request, 800, &path).unwrap();
        assert_eq!(journal.policies()[0].spent_units(), 40);
        assert_eq!(journal.policies()[0].next_nonce(), 2);
        assert_eq!(TreasuryJournalV1::load(&path).unwrap(), journal);
        let before = journal.clone();
        assert_eq!(
            journal.authorize_durable(&request, 800, &path),
            Err(JournalError::InvalidTreasury)
        );
        assert_eq!(journal, before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn treasury_journal_orders_ids_and_rejects_duplicate_unknown_and_budget_overrun() {
        let mut journal = TreasuryJournalV1::default();
        journal.register(treasury_policy(20)).unwrap();
        journal.register(treasury_policy(10)).unwrap();
        assert!(journal.policies()[0].treasury() < journal.policies()[1].treasury());
        assert_eq!(journal.register(treasury_policy(10)), Err(JournalError::InvalidTreasury));
        let unknown = treasury_policy(30);
        assert_eq!(
            journal.authorize(&treasury_request(&unknown, 1, 0, 1), 800),
            Err(JournalError::InvalidTreasury)
        );
        let first = treasury_request(&journal.policies()[0], 50, 0, 1);
        journal.authorize(&first, 800).unwrap();
        let over_budget = treasury_request(&journal.policies()[0], 50, 50, 2);
        assert_eq!(journal.authorize(&over_budget, 800), Ok(()));
        let over_limit = treasury_request(&journal.policies()[0], 1, 100, 3);
        assert_eq!(journal.authorize(&over_limit, 800), Err(JournalError::InvalidTreasury));
        assert_eq!(journal.policies()[0].spent_units(), 100);
    }

    #[test]
    fn failed_treasury_persistence_and_corrupt_restart_do_not_advance() {
        let directory = path("treasury-directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let mut journal = TreasuryJournalV1::default();
        assert_eq!(
            journal.register_durable(treasury_policy(10), &directory),
            Err(JournalError::Persistence)
        );
        assert!(journal.policies().is_empty());
        std::fs::remove_dir_all(&directory).unwrap();

        let corrupt = path("treasury-corrupt");
        let _ = std::fs::remove_file(&corrupt);
        std::fs::write(&corrupt, b"not canonical").unwrap();
        assert_eq!(TreasuryJournalV1::load(&corrupt), Err(JournalError::Persistence));
        std::fs::remove_file(corrupt).unwrap();
    }

    fn idempotency_binding(
        caller: u8,
        key: u8,
        body: u8,
        intent: u8,
        created_at: u64,
        retain_until: u64,
    ) -> IdempotencyBindingV1 {
        IdempotencyBindingV1::new(
            PrincipalId::new(digest(caller)),
            digest(key),
            digest(body),
            PaymentIntentId::new(digest(intent)).unwrap(),
            created_at,
            retain_until,
        )
        .unwrap()
    }

    #[test]
    fn idempotency_binding_survives_restart_and_exact_retry_returns_original_intent() {
        let path = path("idempotency-restart");
        let _ = std::fs::remove_file(&path);
        let binding = idempotency_binding(10, 11, 12, 13, 100, 200);
        let mut journal = IdempotencyJournalV1::default();
        assert_eq!(journal.bind_durable(binding.clone(), 150, &path), Ok(binding.intent()));
        assert_eq!(IdempotencyJournalV1::load(&path).unwrap(), journal);
        let restarted_bytes = std::fs::read(&path).unwrap();
        assert_eq!(journal.bind_durable(binding.clone(), 150, &path), Ok(binding.intent()));
        assert_eq!(std::fs::read(&path).unwrap(), restarted_bytes);
        let before = journal.clone();
        assert_eq!(
            journal.bind_durable(idempotency_binding(10, 11, 14, 15, 100, 200), 150, &path),
            Err(JournalError::InvalidIdempotency)
        );
        assert_eq!(journal, before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn idempotency_journal_orders_keys_and_requires_explicit_durable_pruning() {
        let path = path("idempotency-prune");
        let _ = std::fs::remove_file(&path);
        let mut journal = IdempotencyJournalV1::default();
        journal.bind_durable(idempotency_binding(20, 21, 22, 23, 100, 200), 150, &path).unwrap();
        journal.bind_durable(idempotency_binding(10, 11, 12, 13, 100, 300), 150, &path).unwrap();
        assert!(
            (journal.bindings()[0].caller(), journal.bindings()[0].idempotency_key())
                < (journal.bindings()[1].caller(), journal.bindings()[1].idempotency_key())
        );
        assert_eq!(
            journal.bind_durable(idempotency_binding(30, 31, 32, 33, 100, 200), 200, &path),
            Err(JournalError::InvalidIdempotency)
        );
        assert_eq!(journal.prune_expired_durable(200, &path), Ok(1));
        assert_eq!(journal.bindings().len(), 1);
        journal.bind_durable(idempotency_binding(20, 21, 24, 25, 200, 400), 200, &path).unwrap();
        assert_eq!(IdempotencyJournalV1::load(&path).unwrap(), journal);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_idempotency_persistence_and_corrupt_restart_do_not_advance() {
        let directory = path("idempotency-directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let mut journal = IdempotencyJournalV1::default();
        assert_eq!(
            journal.bind_durable(idempotency_binding(10, 11, 12, 13, 100, 200), 150, &directory,),
            Err(JournalError::Persistence)
        );
        assert!(journal.bindings().is_empty());
        std::fs::remove_dir_all(&directory).unwrap();

        let corrupt = path("idempotency-corrupt");
        let _ = std::fs::remove_file(&corrupt);
        std::fs::write(&corrupt, b"not canonical").unwrap();
        assert_eq!(IdempotencyJournalV1::load(&corrupt), Err(JournalError::Persistence));
        std::fs::remove_file(corrupt).unwrap();
    }

    fn lifecycle_successor(
        intent: u8,
        sequence: u64,
        state: PaymentState,
    ) -> PaymentLifecycleRecordV1 {
        let transaction = matches!(state, PaymentState::ChainSubmitted | PaymentState::Finalized)
            .then(|| TransactionId::new(digest(110)));
        let finalized = state == PaymentState::Finalized;
        PaymentLifecycleRecordV1::new(
            PaymentIntentId::new(digest(intent)).unwrap(),
            sequence,
            state,
            if finalized {
                EvidenceClass::ActiveChainFinalized
            } else if matches!(
                state,
                PaymentState::ProviderPending | PaymentState::ExternallyConfirmed
            ) {
                EvidenceClass::ConnectorAuthenticated
            } else {
                EvidenceClass::UntrustedClientReport
            },
            digest(111 + sequence as u8),
            transaction,
            if finalized { 50 } else { 0 },
            finalized.then(|| digest(112)),
            0,
        )
        .unwrap()
    }

    #[test]
    fn payment_lifecycle_survives_restart_without_evidence_promotion() {
        let path = path("lifecycle-restart");
        let _ = std::fs::remove_file(&path);
        let intent = PaymentIntentId::new(digest(10)).unwrap();
        let mut journal = PaymentLifecycleJournalV1::default();
        journal.create_durable(intent, digest(20), &path).unwrap();
        for (sequence, state) in [
            PaymentState::AwaitingPayer,
            PaymentState::ProviderPending,
            PaymentState::ExternallyConfirmed,
        ]
        .into_iter()
        .enumerate()
        {
            journal
                .advance_durable(lifecycle_successor(10, sequence as u64 + 2, state), &path)
                .unwrap();
        }
        assert_eq!(journal.records()[0].state(), PaymentState::ExternallyConfirmed);
        assert_eq!(journal.records()[0].evidence_class(), EvidenceClass::ConnectorAuthenticated);
        assert_eq!(PaymentLifecycleJournalV1::load(&path).unwrap(), journal);
        journal
            .advance_durable(lifecycle_successor(10, 5, PaymentState::ChainSubmitted), &path)
            .unwrap();
        journal
            .advance_durable(lifecycle_successor(10, 6, PaymentState::Finalized), &path)
            .unwrap();
        assert_eq!(journal.records()[0].evidence_class(), EvidenceClass::ActiveChainFinalized);
        let before = journal.clone();
        assert_eq!(
            journal.advance_durable(lifecycle_successor(10, 6, PaymentState::Finalized), &path,),
            Err(JournalError::InvalidLifecycle)
        );
        assert_eq!(journal, before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn lifecycle_journal_orders_intents_and_rejects_duplicate_unknown_and_invalid_edges() {
        let mut journal = PaymentLifecycleJournalV1::default();
        journal.create(PaymentIntentId::new(digest(20)).unwrap(), digest(21)).unwrap();
        journal.create(PaymentIntentId::new(digest(10)).unwrap(), digest(11)).unwrap();
        assert!(journal.records()[0].intent() < journal.records()[1].intent());
        assert_eq!(
            journal.create(PaymentIntentId::new(digest(10)).unwrap(), digest(12)),
            Err(JournalError::InvalidLifecycle)
        );
        assert_eq!(
            journal.advance(lifecycle_successor(30, 2, PaymentState::AwaitingPayer)),
            Err(JournalError::InvalidLifecycle)
        );
        assert_eq!(
            journal.advance(lifecycle_successor(10, 3, PaymentState::ProviderPending)),
            Err(JournalError::InvalidLifecycle)
        );
        assert_eq!(journal.records()[0].sequence(), 1);
    }

    #[test]
    fn failed_lifecycle_persistence_and_corrupt_restart_do_not_advance() {
        let directory = path("lifecycle-directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let mut journal = PaymentLifecycleJournalV1::default();
        assert_eq!(
            journal.create_durable(
                PaymentIntentId::new(digest(10)).unwrap(),
                digest(20),
                &directory,
            ),
            Err(JournalError::Persistence)
        );
        assert!(journal.records().is_empty());
        std::fs::remove_dir_all(&directory).unwrap();

        let corrupt = path("lifecycle-corrupt");
        let _ = std::fs::remove_file(&corrupt);
        std::fs::write(&corrupt, b"not canonical").unwrap();
        assert_eq!(PaymentLifecycleJournalV1::load(&corrupt), Err(JournalError::Persistence));
        std::fs::remove_file(corrupt).unwrap();
    }

    fn payment_intent(intent: u8, merchant: u8, key: u8, metadata: u8) -> PaymentIntentV1 {
        PaymentIntentV1::new(
            ChainId::new(digest(120)),
            PaymentIntentId::new(digest(intent)).unwrap(),
            PrincipalId::new(digest(merchant)),
            TreasuryId::new(digest(121)).unwrap(),
            digest(122),
            digest(123),
            AssetAmountV1::new(AssetId::new(digest(124)), 100).unwrap(),
            AssetAmountV1::new(AssetId::new(digest(124)), 90).unwrap(),
            500,
            digest(key),
            digest(125),
            digest(126),
            digest(127),
            digest(metadata),
        )
        .unwrap()
    }

    fn intent_binding(intent: &PaymentIntentV1) -> IdempotencyBindingV1 {
        IdempotencyBindingV1::new(
            intent.merchant(),
            intent.idempotency_key(),
            intent.commitment().unwrap(),
            intent.intent(),
            100,
            600,
        )
        .unwrap()
    }

    #[test]
    fn intent_binding_and_created_lifecycle_persist_atomically_and_retry_exactly() {
        let path = path("request-state-restart");
        let _ = std::fs::remove_file(&path);
        let intent = payment_intent(10, 11, 12, 13);
        let binding = intent_binding(&intent);
        let mut durable = DurablePaymentRequestState::open(&path).unwrap();
        assert_eq!(
            durable.create_intent(intent.clone(), binding.clone(), digest(14), 150),
            Ok(intent.intent())
        );
        assert_eq!(durable.snapshot().intents(), &[intent.clone()]);
        assert_eq!(durable.snapshot().idempotency().bindings(), &[binding.clone()]);
        assert_eq!(durable.snapshot().lifecycles().records()[0].state(), PaymentState::Created);
        let restarted = DurablePaymentRequestState::open(&path).unwrap();
        assert_eq!(restarted.snapshot(), durable.snapshot());
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            durable.create_intent(intent.clone(), binding, digest(14), 150),
            Ok(intent.intent())
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn intent_creation_rejects_substitution_expiry_and_partial_state() {
        let path = path("request-state-invalid");
        let _ = std::fs::remove_file(&path);
        let intent = payment_intent(10, 11, 12, 13);
        let mut durable = DurablePaymentRequestState::open(&path).unwrap();
        assert_eq!(
            durable.create_intent(
                intent.clone(),
                IdempotencyBindingV1::new(
                    PrincipalId::new(digest(99)),
                    intent.idempotency_key(),
                    intent.commitment().unwrap(),
                    intent.intent(),
                    100,
                    600,
                )
                .unwrap(),
                digest(14),
                150,
            ),
            Err(JournalError::InvalidIdempotency)
        );
        assert_eq!(
            durable.create_intent(intent.clone(), intent_binding(&intent), digest(14), 500),
            Err(JournalError::InvalidIdempotency)
        );
        assert!(durable.snapshot().intents().is_empty());
        assert_eq!(
            PaymentRequestStateV1::new(
                vec![intent],
                IdempotencyJournalV1::default(),
                PaymentLifecycleJournalV1::default(),
            ),
            Err(JournalError::InvalidLifecycle)
        );
        assert!(!path.exists());
    }

    #[test]
    fn conflicting_retry_and_failed_request_state_write_do_not_advance() {
        let directory = path("request-state-directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let intent = payment_intent(10, 11, 12, 13);
        let mut failed = DurablePaymentRequestState {
            path: directory.clone(),
            snapshot: PaymentRequestStateV1::default(),
        };
        assert_eq!(
            failed.create_intent(intent.clone(), intent_binding(&intent), digest(14), 150),
            Err(JournalError::Persistence)
        );
        assert!(failed.snapshot().intents().is_empty());
        std::fs::remove_dir_all(&directory).unwrap();

        let state_path = path("request-state-conflict");
        let _ = std::fs::remove_file(&state_path);
        let mut durable = DurablePaymentRequestState::open(&state_path).unwrap();
        durable.create_intent(intent.clone(), intent_binding(&intent), digest(14), 150).unwrap();
        let before = durable.snapshot().clone();
        let substituted = payment_intent(10, 11, 12, 15);
        assert_eq!(
            durable.create_intent(
                substituted.clone(),
                intent_binding(&substituted),
                digest(14),
                150,
            ),
            Err(JournalError::InvalidIdempotency)
        );
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_file(state_path).unwrap();

        let corrupt = path("request-state-corrupt");
        let _ = std::fs::remove_file(&corrupt);
        std::fs::write(&corrupt, b"not canonical").unwrap();
        assert_eq!(DurablePaymentRequestState::open(&corrupt), Err(JournalError::Persistence));
        std::fs::remove_file(corrupt).unwrap();
    }

    #[test]
    fn joined_lifecycle_advance_survives_restart_and_replay_fails_closed() {
        let path = path("joined-lifecycle-restart");
        let _ = std::fs::remove_file(&path);
        let intent = payment_intent(10, 11, 12, 13);
        let mut durable = DurablePaymentRequestState::open(&path).unwrap();
        durable.create_intent(intent.clone(), intent_binding(&intent), digest(14), 150).unwrap();
        let successor = lifecycle_successor(10, 2, PaymentState::AwaitingPayer);
        durable.advance_lifecycle(successor.clone()).unwrap();
        assert_eq!(durable.snapshot().lifecycles().records()[0], successor);
        assert_eq!(DurablePaymentRequestState::open(&path).unwrap().snapshot(), durable.snapshot());
        let before = durable.snapshot().clone();
        assert_eq!(durable.advance_lifecycle(successor), Err(JournalError::InvalidLifecycle));
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_joined_lifecycle_write_keeps_the_complete_snapshot() {
        let directory = path("joined-lifecycle-directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("request-state.bin");
        let intent = payment_intent(10, 11, 12, 13);
        let mut durable = DurablePaymentRequestState::open(&path).unwrap();
        durable.create_intent(intent.clone(), intent_binding(&intent), digest(14), 150).unwrap();
        let before = durable.snapshot().clone();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            durable.advance_lifecycle(lifecycle_successor(10, 2, PaymentState::AwaitingPayer,)),
            Err(JournalError::Persistence)
        );
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn chain_submitted_request_state(path: &Path) -> DurablePaymentRequestState {
        let intent = payment_intent(10, 11, 12, 13);
        let mut durable = DurablePaymentRequestState::open(path).unwrap();
        durable.create_intent(intent.clone(), intent_binding(&intent), digest(14), 150).unwrap();
        for (sequence, state) in [
            PaymentState::AwaitingPayer,
            PaymentState::ProviderPending,
            PaymentState::ExternallyConfirmed,
            PaymentState::ChainSubmitted,
        ]
        .into_iter()
        .enumerate()
        {
            durable.advance_lifecycle(lifecycle_successor(10, sequence as u64 + 2, state)).unwrap();
        }
        durable
    }

    fn finalized_settlement(
        asset: u8,
        amount: u128,
        transaction: u8,
    ) -> PaymentFinalizedSettlementV1 {
        PaymentFinalizedSettlementV1::new(
            PaymentIntentId::new(digest(10)).unwrap(),
            TransactionId::new(digest(transaction)),
            AssetAmountV1::new(AssetId::new(digest(asset)), amount).unwrap(),
            50,
            digest(130),
            digest(131),
            digest(132),
        )
        .unwrap()
    }

    #[test]
    fn finalized_settlement_advances_joined_state_and_survives_restart() {
        let path = path("finalized-settlement-restart");
        let _ = std::fs::remove_file(&path);
        let mut durable = chain_submitted_request_state(&path);
        let settlement = finalized_settlement(124, 95, 110);
        assert_eq!(
            durable.finalize_settlement(&settlement),
            settlement.commitment().map_err(|_| JournalError::InvalidLifecycle)
        );
        assert_eq!(durable.snapshot().lifecycles().records()[0].state(), PaymentState::Finalized);
        assert_eq!(DurablePaymentRequestState::open(&path).unwrap().snapshot(), durable.snapshot());
        let before = durable.snapshot().clone();
        assert_eq!(durable.finalize_settlement(&settlement), Err(JournalError::InvalidLifecycle));
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn finalized_settlement_rejects_economic_transaction_and_write_substitution() {
        let directory = path("finalized-settlement-directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("request-state.bin");
        let mut durable = chain_submitted_request_state(&path);
        let before = durable.snapshot().clone();
        assert_eq!(
            durable.finalize_verified_settlement(
                &finalized_settlement(124, 95, 110),
                b"invalid finality",
                b"invalid receipt",
                digest(129),
            ),
            Err(JournalError::InvalidLifecycle)
        );
        assert_eq!(
            durable.finalize_settlement(&finalized_settlement(125, 95, 110)),
            Err(JournalError::InvalidLifecycle)
        );
        assert_eq!(
            durable.finalize_settlement(&finalized_settlement(124, 89, 110)),
            Err(JournalError::InvalidLifecycle)
        );
        assert_eq!(
            durable.finalize_settlement(&finalized_settlement(124, 95, 111)),
            Err(JournalError::InvalidLifecycle)
        );
        assert_eq!(durable.snapshot(), &before);

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            durable.finalize_settlement(&finalized_settlement(124, 95, 110)),
            Err(JournalError::Persistence)
        );
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn chain_submitted_settlement_state(path: &Path) -> DurablePaymentSettlementState {
        let intent = payment_intent(10, 11, 12, 13);
        let mut durable = DurablePaymentSettlementState::open(path).unwrap();
        durable.create_intent(intent.clone(), intent_binding(&intent), digest(14), 150).unwrap();
        for (sequence, state) in [
            PaymentState::AwaitingPayer,
            PaymentState::ProviderPending,
            PaymentState::ExternallyConfirmed,
            PaymentState::ChainSubmitted,
        ]
        .into_iter()
        .enumerate()
        {
            durable.advance_lifecycle(lifecycle_successor(10, sequence as u64 + 2, state)).unwrap();
        }
        durable
    }

    fn settlement_refund_request(
        settlement: &PaymentFinalizedSettlementV1,
        refund: u8,
        amount: u128,
        sequence: u64,
        expected: u128,
    ) -> PaymentRefundRequestV1 {
        PaymentRefundRequestV1::new(
            PaymentRefundId::new(digest(refund)).unwrap(),
            settlement.intent(),
            PrincipalId::new(digest(131)),
            settlement.commitment().unwrap(),
            AssetAmountV1::new(settlement.settled_amount().asset(), amount).unwrap(),
            digest(132),
            digest(refund.wrapping_add(1)),
            sequence,
            expected,
            100,
            200,
        )
        .unwrap()
    }

    #[test]
    fn settlement_state_persists_full_evidence_request_and_refund_accounting_together() {
        let path = path("settlement-state-restart");
        let _ = std::fs::remove_file(&path);
        let mut durable = chain_submitted_settlement_state(&path);
        let settlement = finalized_settlement(124, 95, 110);
        let commitment = durable.finalize_verified_value(&settlement).unwrap();
        assert_eq!(durable.snapshot().settlements(), &[settlement]);
        assert_eq!(durable.snapshot().refunds().states()[0].intent(), settlement.intent());
        assert_eq!(
            durable.snapshot().refunds().states()[0].settled_amount(),
            settlement.settled_amount()
        );
        assert_eq!(durable.snapshot().refunds().states()[0].settlement_commitment(), commitment);
        assert_eq!(
            DurablePaymentSettlementState::open(&path).unwrap().snapshot(),
            durable.snapshot()
        );
        let before = durable.snapshot().clone();
        assert_eq!(
            durable.finalize_verified_value(&settlement),
            Err(JournalError::InvalidLifecycle)
        );
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn settlement_state_rejects_partial_state_and_failed_atomic_write() {
        let directory = path("settlement-state-directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settlement-state.bin");
        let mut durable = chain_submitted_settlement_state(&path);
        let settlement = finalized_settlement(124, 95, 110);
        let (finalized_requests, _) =
            durable.snapshot().requests().finalized_successor(&settlement).unwrap();
        assert_eq!(
            PaymentSettlementStateV1::new(
                finalized_requests,
                Vec::new(),
                Vec::new(),
                RefundJournalV1::default(),
                DisputeJournalV1::default(),
                TreasuryJournalV1::default(),
                ApiAuthorizationJournalV1::default(),
                WebhookDeliveryJournalV1::default(),
                FeeSponsorshipJournalV1::default(),
            ),
            Err(JournalError::InvalidLifecycle)
        );
        let before = durable.snapshot().clone();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(durable.finalize_verified_value(&settlement), Err(JournalError::Persistence));
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn atomic_refund_requests_join_lifecycle_and_cumulative_accounting() {
        let path = path("atomic-refund-restart");
        let _ = std::fs::remove_file(&path);
        let mut durable = chain_submitted_settlement_state(&path);
        let settlement = finalized_settlement(124, 95, 110);
        durable.finalize_verified_value(&settlement).unwrap();

        let first = settlement_refund_request(&settlement, 140, 40, 1, 0);
        durable.request_refund(&first, 150).unwrap();
        let first_record = durable.snapshot().requests().lifecycles().records()[0].clone();
        assert_eq!(first_record.state(), PaymentState::RefundPending);
        assert_eq!(first_record.observation_commitment(), first.commitment().unwrap());
        assert_eq!(durable.snapshot().refunds().states()[0].refunded_units(), 40);
        assert_eq!(durable.snapshot().refunds().states()[0].next_sequence(), 2);
        assert_eq!(
            DurablePaymentSettlementState::open(&path).unwrap().snapshot(),
            durable.snapshot()
        );

        let before_replay = durable.snapshot().clone();
        assert_eq!(durable.request_refund(&first, 150), Err(JournalError::InvalidRefund));
        assert_eq!(durable.snapshot(), &before_replay);

        let second = settlement_refund_request(&settlement, 142, 55, 2, 40);
        durable.request_refund(&second, 150).unwrap();
        assert_eq!(durable.snapshot().requests().lifecycles().records()[0], first_record);
        assert_eq!(durable.snapshot().refunds().states()[0].refunded_units(), 95);
        assert_eq!(durable.snapshot().refunds().states()[0].next_sequence(), 3);
        assert_eq!(
            DurablePaymentSettlementState::open(&path).unwrap().snapshot(),
            durable.snapshot()
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn atomic_refund_rejects_substitution_over_refund_and_failed_write() {
        let directory = path("atomic-refund-failure");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settlement-state.bin");
        let mut durable = chain_submitted_settlement_state(&path);
        let settlement = finalized_settlement(124, 95, 110);
        durable.finalize_verified_value(&settlement).unwrap();
        let before = durable.snapshot().clone();

        let over_refund = settlement_refund_request(&settlement, 143, 96, 1, 0);
        assert_eq!(durable.request_refund(&over_refund, 150), Err(JournalError::InvalidRefund));
        let wrong_settlement = PaymentRefundRequestV1::new(
            PaymentRefundId::new(digest(144)).unwrap(),
            settlement.intent(),
            PrincipalId::new(digest(131)),
            digest(145),
            AssetAmountV1::new(settlement.settled_amount().asset(), 40).unwrap(),
            digest(132),
            digest(146),
            1,
            0,
            100,
            200,
        )
        .unwrap();
        assert_eq!(
            durable.request_refund(&wrong_settlement, 150),
            Err(JournalError::InvalidRefund)
        );
        assert_eq!(durable.snapshot(), &before);

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let valid = settlement_refund_request(&settlement, 147, 40, 1, 0);
        assert_eq!(durable.request_refund(&valid, 150), Err(JournalError::Persistence));
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn settlement_dispute_request(
        settlement: &PaymentFinalizedSettlementV1,
    ) -> PaymentDisputeRequestV1 {
        PaymentDisputeRequestV1::new(
            PaymentDisputeId::new(digest(150)).unwrap(),
            settlement.intent(),
            PrincipalId::new(digest(151)),
            settlement.commitment().unwrap(),
            AssetAmountV1::new(settlement.settled_amount().asset(), 40).unwrap(),
            digest(152),
            digest(153),
            digest(154),
            100,
            200,
        )
        .unwrap()
    }

    #[test]
    fn atomic_dispute_state_survives_restart_and_exact_successor() {
        let path = path("atomic-dispute-restart");
        let _ = std::fs::remove_file(&path);
        let mut durable = chain_submitted_settlement_state(&path);
        let settlement = finalized_settlement(124, 95, 110);
        durable.finalize_verified_value(&settlement).unwrap();
        let request = settlement_dispute_request(&settlement);
        durable.open_dispute(&request, 150).unwrap();
        assert_eq!(durable.snapshot().disputes().records()[0].state(), PaymentDisputeState::Open);
        let evidence = dispute_successor(150, 10, 2, PaymentDisputeState::EvidenceSubmitted);
        durable.advance_dispute(evidence).unwrap();
        assert_eq!(durable.snapshot().disputes().records()[0].sequence(), 2);
        assert_eq!(
            DurablePaymentSettlementState::open(&path).unwrap().snapshot(),
            durable.snapshot()
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn atomic_dispute_rejects_substitution_replay_and_failed_write() {
        let directory = path("atomic-dispute-failure");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settlement-state.bin");
        let mut durable = chain_submitted_settlement_state(&path);
        let settlement = finalized_settlement(124, 95, 110);
        durable.finalize_verified_value(&settlement).unwrap();
        let request = settlement_dispute_request(&settlement);
        let before = durable.snapshot().clone();
        let substituted = PaymentDisputeRequestV1::new(
            request.dispute(),
            settlement.intent(),
            PrincipalId::new(digest(151)),
            digest(155),
            AssetAmountV1::new(settlement.settled_amount().asset(), 40).unwrap(),
            digest(152),
            digest(153),
            digest(154),
            100,
            200,
        )
        .unwrap();
        assert_eq!(durable.open_dispute(&substituted, 150), Err(JournalError::InvalidDispute));
        assert_eq!(durable.snapshot(), &before);

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(durable.open_dispute(&request, 150), Err(JournalError::Persistence));
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn atomic_treasury_state_survives_restart_and_replay_fails_closed() {
        let path = path("atomic-treasury-restart");
        let _ = std::fs::remove_file(&path);
        let mut durable = DurablePaymentSettlementState::open(&path).unwrap();
        let policy = treasury_policy(160);
        durable.register_treasury(policy.clone()).unwrap();
        let request = treasury_request(&policy, 40, 0, 1);
        durable.authorize_treasury_debit(&request, 800).unwrap();
        assert_eq!(durable.snapshot().treasuries().policies()[0].spent_units(), 40);
        assert_eq!(durable.snapshot().treasuries().policies()[0].next_nonce(), 2);
        assert_eq!(
            DurablePaymentSettlementState::open(&path).unwrap().snapshot(),
            durable.snapshot()
        );
        let before = durable.snapshot().clone();
        assert_eq!(
            durable.authorize_treasury_debit(&request, 800),
            Err(JournalError::InvalidTreasury)
        );
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn atomic_treasury_failed_write_does_not_advance_budget_or_nonce() {
        let directory = path("atomic-treasury-failure");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settlement-state.bin");
        let mut durable = DurablePaymentSettlementState::open(&path).unwrap();
        let policy = treasury_policy(161);
        durable.register_treasury(policy.clone()).unwrap();
        let request = treasury_request(&policy, 40, 0, 1);
        let before = durable.snapshot().clone();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(durable.authorize_treasury_debit(&request, 800), Err(JournalError::Persistence));
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn atomic_api_replay_state_survives_restart_and_rejects_replay() {
        let path = path("atomic-api-replay");
        let _ = std::fs::remove_file(&path);
        let mut durable = DurablePaymentSettlementState::open(&path).unwrap();
        let first = api_authorization(170, 171, 1);
        durable.authorize_api_call(&first, 150).unwrap();
        assert_eq!(durable.snapshot().authorizations().states()[0].next_sequence(), 2);
        assert_eq!(
            DurablePaymentSettlementState::open(&path).unwrap().snapshot(),
            durable.snapshot()
        );
        let before = durable.snapshot().clone();
        assert_eq!(
            durable.authorize_api_call(&first, 150),
            Err(JournalError::InvalidAuthorization)
        );
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn atomic_api_failed_write_does_not_consume_authorization() {
        let directory = path("atomic-api-failure");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settlement-state.bin");
        let mut durable = DurablePaymentSettlementState::open(&path).unwrap();
        let before = durable.snapshot().clone();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            durable.authorize_api_call(&api_authorization(172, 173, 1), 150),
            Err(JournalError::Persistence)
        );
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn aggregate_webhook_event(intent: u8, event: u8, sequence: u64) -> PaymentWebhookEventV1 {
        PaymentWebhookEventV1::new(
            PaymentWebhookSubscriptionId::new(digest(180)).unwrap(),
            PaymentWebhookEventId::new(digest(event)).unwrap(),
            PaymentLifecycleRecordV1::new(
                PaymentIntentId::new(digest(intent)).unwrap(),
                sequence,
                if sequence == 1 { PaymentState::Created } else { PaymentState::ProviderPending },
                EvidenceClass::ConnectorAuthenticated,
                digest(event.wrapping_add(1)),
                None,
                0,
                None,
                0,
            )
            .unwrap(),
            digest(181),
            digest(182),
            100,
            200,
        )
        .unwrap()
    }

    #[test]
    fn atomic_webhook_cursor_requires_retained_intent_and_survives_restart() {
        let path = path("atomic-webhook-restart");
        let _ = std::fs::remove_file(&path);
        let mut durable = DurablePaymentSettlementState::open(&path).unwrap();
        let unknown = aggregate_webhook_event(10, 183, 1);
        assert_eq!(durable.deliver_webhook(&unknown, 150), Err(JournalError::InvalidDelivery));
        let intent = payment_intent(10, 11, 12, 13);
        durable.create_intent(intent.clone(), intent_binding(&intent), digest(14), 150).unwrap();
        durable.deliver_webhook(&unknown, 150).unwrap();
        assert_eq!(durable.snapshot().webhooks().cursors()[0].next_sequence(), 2);
        assert_eq!(
            DurablePaymentSettlementState::open(&path).unwrap().snapshot(),
            durable.snapshot()
        );
        let before = durable.snapshot().clone();
        assert_eq!(durable.deliver_webhook(&unknown, 150), Err(JournalError::InvalidDelivery));
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn atomic_webhook_failed_write_does_not_advance_cursor() {
        let directory = path("atomic-webhook-failure");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settlement-state.bin");
        let mut durable = DurablePaymentSettlementState::open(&path).unwrap();
        let intent = payment_intent(10, 11, 12, 13);
        durable.create_intent(intent.clone(), intent_binding(&intent), digest(14), 150).unwrap();
        let before = durable.snapshot().clone();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            durable.deliver_webhook(&aggregate_webhook_event(10, 184, 1), 150),
            Err(JournalError::Persistence)
        );
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn aggregate_fee_sponsor_policy() -> PaymentFeeSponsorPolicyV1 {
        PaymentFeeSponsorPolicyV1::new(
            PrincipalId::new(digest(190)),
            PrincipalId::new(digest(191)),
            AssetId::new(digest(192)),
            10,
            20,
            0,
            digest(193),
            1,
            1_000,
        )
        .unwrap()
    }

    fn aggregate_fee_sponsor_request(
        policy: &PaymentFeeSponsorPolicyV1,
    ) -> PaymentFeeSponsorRequestV1 {
        PaymentFeeSponsorRequestV1::new(
            PaymentIntentId::new(digest(10)).unwrap(),
            PrincipalId::new(digest(190)),
            PrincipalId::new(digest(191)),
            AssetAmountV1::new(AssetId::new(digest(192)), 8).unwrap(),
            AssetAmountV1::new(AssetId::new(digest(194)), 8).unwrap(),
            digest(196),
            8,
            policy.commitment().unwrap(),
            digest(195),
            0,
            1,
            900,
        )
        .unwrap()
    }

    #[test]
    fn atomic_fee_sponsorship_requires_intent_and_survives_restart() {
        let path = path("atomic-fee-sponsor-restart");
        let _ = std::fs::remove_file(&path);
        let mut durable = DurablePaymentSettlementState::open(&path).unwrap();
        let policy = aggregate_fee_sponsor_policy();
        durable.register_fee_sponsor(policy.clone()).unwrap();
        let request = aggregate_fee_sponsor_request(&policy);
        assert_eq!(
            durable.authorize_fee_sponsorship(&request, 800),
            Err(JournalError::InvalidTreasury)
        );
        let intent = payment_intent(10, 11, 12, 13);
        durable.create_intent(intent.clone(), intent_binding(&intent), digest(14), 150).unwrap();
        durable.authorize_fee_sponsorship(&request, 800).unwrap();
        assert_eq!(durable.snapshot().sponsorships().policies()[0].spent_units(), 8);
        assert_eq!(durable.snapshot().sponsorships().policies()[0].next_nonce(), 2);
        assert_eq!(
            DurablePaymentSettlementState::open(&path).unwrap().snapshot(),
            durable.snapshot()
        );
        let before = durable.snapshot().clone();
        assert_eq!(
            durable.authorize_fee_sponsorship(&request, 800),
            Err(JournalError::InvalidTreasury)
        );
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn atomic_fee_sponsorship_failed_write_does_not_charge_sponsor() {
        let directory = path("atomic-fee-sponsor-failure");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settlement-state.bin");
        let mut durable = DurablePaymentSettlementState::open(&path).unwrap();
        let intent = payment_intent(10, 11, 12, 13);
        durable.create_intent(intent.clone(), intent_binding(&intent), digest(14), 150).unwrap();
        let policy = aggregate_fee_sponsor_policy();
        durable.register_fee_sponsor(policy.clone()).unwrap();
        let before = durable.snapshot().clone();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            durable.authorize_fee_sponsorship(&aggregate_fee_sponsor_request(&policy), 800),
            Err(JournalError::Persistence)
        );
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn finalized_refund(
        settlement: &PaymentFinalizedSettlementV1,
        refund: u8,
    ) -> PaymentFinalizedRefundV1 {
        PaymentFinalizedRefundV1::new(
            PaymentRefundId::new(digest(refund)).unwrap(),
            settlement.intent(),
            settlement.commitment().unwrap(),
            settlement.settled_amount(),
            TransactionId::new(digest(200)),
            60,
            digest(201),
            digest(202),
            digest(203),
        )
        .unwrap()
    }

    #[test]
    fn finalized_refund_requires_complete_accounting_and_survives_restart() {
        let partial_path = path("finalized-refund-partial");
        let _ = std::fs::remove_file(&partial_path);
        let settlement = finalized_settlement(124, 95, 110);
        let mut partial = chain_submitted_settlement_state(&partial_path);
        partial.finalize_verified_value(&settlement).unwrap();
        partial
            .request_refund(&settlement_refund_request(&settlement, 140, 40, 1, 0), 150)
            .unwrap();
        assert_eq!(
            partial.finalize_verified_refund_value(&finalized_refund(&settlement, 140)),
            Err(JournalError::InvalidRefund)
        );
        assert_eq!(
            partial.snapshot().requests().lifecycles().records()[0].state(),
            PaymentState::RefundPending
        );
        std::fs::remove_file(partial_path).unwrap();

        let path = path("finalized-refund-restart");
        let _ = std::fs::remove_file(&path);
        let mut durable = chain_submitted_settlement_state(&path);
        durable.finalize_verified_value(&settlement).unwrap();
        durable
            .request_refund(&settlement_refund_request(&settlement, 141, 95, 1, 0), 150)
            .unwrap();
        let evidence = finalized_refund(&settlement, 141);
        let commitment = durable.finalize_verified_refund_value(&evidence).unwrap();
        assert_eq!(durable.snapshot().finalized_refunds(), &[evidence]);
        let lifecycle = &durable.snapshot().requests().lifecycles().records()[0];
        assert_eq!(lifecycle.state(), PaymentState::Refunded);
        assert_eq!(lifecycle.observation_commitment(), commitment);
        assert_eq!(
            DurablePaymentSettlementState::open(&path).unwrap().snapshot(),
            durable.snapshot()
        );
        let before = durable.snapshot().clone();
        assert_eq!(
            durable.finalize_verified_refund_value(&evidence),
            Err(JournalError::InvalidRefund)
        );
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn finalized_refund_failed_write_does_not_promote_lifecycle() {
        let directory = path("finalized-refund-failure");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settlement-state.bin");
        let settlement = finalized_settlement(124, 95, 110);
        let mut durable = chain_submitted_settlement_state(&path);
        durable.finalize_verified_value(&settlement).unwrap();
        durable
            .request_refund(&settlement_refund_request(&settlement, 142, 95, 1, 0), 150)
            .unwrap();
        let before = durable.snapshot().clone();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            durable.finalize_verified_refund_value(&finalized_refund(&settlement, 142)),
            Err(JournalError::Persistence)
        );
        assert_eq!(durable.snapshot(), &before);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
