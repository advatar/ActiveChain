#![forbid(unsafe_code)]

//! Durable, fail-closed observation state for out-of-consensus payment connectors.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_crypto_provider::verify_ml_dsa44;
use activechain_payment_types::{
    ConnectorId, PaymentApiAuthorizationV1, PaymentApiReplayStateV1,
    PaymentApiSignedAuthorizationV1, PaymentValidationError, PaymentWebhookCursorV1,
    PaymentWebhookEventV1, ProviderObservationV1, RailId,
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
        PaymentIntentId, PaymentLifecycleRecordV1, PaymentState, PaymentWebhookEventId,
        PaymentWebhookEventV1, PaymentWebhookSubscriptionId, ProviderOperationState, RailId,
        payment_api_authenticator_commitment,
    };
    use activechain_protocol_types::{
        AssetId, ChainId, CryptoSuiteId, Digest384, PrincipalId, ProtocolSignature,
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
}
