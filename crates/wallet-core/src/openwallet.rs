use crate::WalletError;
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::Digest384;
use alloc::vec::Vec;

pub const OPENWALLET_PROFILE_REVISION: u16 = 1;
pub const MAX_OPENWALLET_URI: usize = 2_048;
pub const MAX_CONFIGURATION_IDS: usize = 16;
pub const MAX_REQUESTED_CREDENTIALS: usize = 16;
pub const MAX_DISCLOSED_CLAIMS: usize = 64;
pub const MAX_OPENWALLET_CREDENTIALS: usize = 256;
pub const MAX_OPENWALLET_SESSIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CredentialFormat {
    SdJwtVc = 0,
    Mdoc = 1,
    W3cVc = 2,
}
impl CanonicalEncode for CredentialFormat {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for CredentialFormat {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::SdJwtVc),
            1 => Ok(Self::Mdoc),
            2 => Ok(Self::W3cVc),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "CredentialFormat", tag }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PresentationResponseMode {
    DirectPost = 0,
    DirectPostJwt = 1,
    DigitalCredentialsApi = 2,
}
impl CanonicalEncode for PresentationResponseMode {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for PresentationResponseMode {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::DirectPost),
            1 => Ok(Self::DirectPostJwt),
            2 => Ok(Self::DigitalCredentialsApi),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "PresentationResponseMode", tag }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IssuanceSessionState {
    Offered = 0,
    Authorized = 1,
    Completed = 2,
}
impl CanonicalEncode for IssuanceSessionState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for IssuanceSessionState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Offered),
            1 => Ok(Self::Authorized),
            2 => Ok(Self::Completed),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "IssuanceSessionState", tag }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenWalletCredentialRefV1 {
    pub credential_id: Digest384,
    pub schema_id: Digest384,
    pub issuer: Digest384,
}

impl OpenWalletCredentialRefV1 {
    fn validate(self) -> Result<Self, WalletError> {
        if self.credential_id == Digest384::ZERO
            || self.schema_id == Digest384::ZERO
            || self.issuer == Digest384::ZERO
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(self)
    }
}
impl CanonicalEncode for OpenWalletCredentialRefV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.credential_id.encode(encoder)?;
        self.schema_id.encode(encoder)?;
        self.issuer.encode(encoder)
    }
}
impl CanonicalDecode for OpenWalletCredentialRefV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self {
            credential_id: Digest384::decode(decoder)?,
            schema_id: Digest384::decode(decoder)?,
            issuer: Digest384::decode(decoder)?,
        }
        .validate()
        .map_err(|_| DecodeError::InvalidValue("invalid OpenWallet credential reference"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenWalletSessionV1 {
    pub session_id: Digest384,
    pub relying_party: Digest384,
    pub expires_at: u64,
}
impl OpenWalletSessionV1 {
    fn validate(self) -> Result<Self, WalletError> {
        if self.session_id == Digest384::ZERO
            || self.relying_party == Digest384::ZERO
            || self.expires_at == 0
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(self)
    }
}
impl CanonicalEncode for OpenWalletSessionV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.session_id.encode(encoder)?;
        self.relying_party.encode(encoder)?;
        self.expires_at.encode(encoder)
    }
}
impl CanonicalDecode for OpenWalletSessionV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self {
            session_id: Digest384::decode(decoder)?,
            relying_party: Digest384::decode(decoder)?,
            expires_at: u64::decode(decoder)?,
        }
        .validate()
        .map_err(|_| DecodeError::InvalidValue("invalid OpenWallet session"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenWalletCredentialOfferV1 {
    session: OpenWalletSessionV1,
    issuer_uri: Vec<u8>,
    configuration_ids: Vec<Digest384>,
    authorization_server: Digest384,
    grant_nonce: Digest384,
    consent_digest: Digest384,
    state: IssuanceSessionState,
}
impl OpenWalletCredentialOfferV1 {
    pub fn new(
        session: OpenWalletSessionV1,
        issuer_uri: Vec<u8>,
        configuration_ids: Vec<Digest384>,
        authorization_server: Digest384,
        grant_nonce: Digest384,
        consent_digest: Digest384,
    ) -> Result<Self, WalletError> {
        session.validate()?;
        if issuer_uri.is_empty()
            || issuer_uri.len() > MAX_OPENWALLET_URI
            || !issuer_uri.starts_with(b"https://")
            || configuration_ids.is_empty()
            || configuration_ids.len() > MAX_CONFIGURATION_IDS
            || configuration_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || authorization_server == Digest384::ZERO
            || grant_nonce == Digest384::ZERO
            || consent_digest == Digest384::ZERO
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self {
            session,
            issuer_uri,
            configuration_ids,
            authorization_server,
            grant_nonce,
            consent_digest,
            state: IssuanceSessionState::Offered,
        })
    }
    pub const fn session(&self) -> OpenWalletSessionV1 {
        self.session
    }
    pub const fn state(&self) -> IssuanceSessionState {
        self.state
    }
    pub const fn grant_nonce(&self) -> Digest384 {
        self.grant_nonce
    }
    pub const fn consent_digest(&self) -> Digest384 {
        self.consent_digest
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }
}
impl CanonicalEncode for OpenWalletCredentialOfferV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.session.encode(encoder)?;
        encoder.write_bytes(&self.issuer_uri, MAX_OPENWALLET_URI)?;
        encoder.write_length(self.configuration_ids.len(), MAX_CONFIGURATION_IDS)?;
        for id in &self.configuration_ids {
            id.encode(encoder)?;
        }
        self.authorization_server.encode(encoder)?;
        self.grant_nonce.encode(encoder)?;
        self.consent_digest.encode(encoder)?;
        self.state.encode(encoder)
    }
}
impl CanonicalDecode for OpenWalletCredentialOfferV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let session = OpenWalletSessionV1::decode(decoder)?;
        let issuer_uri = decoder.read_bytes(MAX_OPENWALLET_URI)?.to_vec();
        let count = decoder.read_length(MAX_CONFIGURATION_IDS)?;
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            ids.push(Digest384::decode(decoder)?);
        }
        let authorization_server = Digest384::decode(decoder)?;
        let grant_nonce = Digest384::decode(decoder)?;
        let consent_digest = Digest384::decode(decoder)?;
        let state = IssuanceSessionState::decode(decoder)?;
        let mut value =
            Self::new(session, issuer_uri, ids, authorization_server, grant_nonce, consent_digest)
                .map_err(|_| DecodeError::InvalidValue("invalid OpenWallet credential offer"))?;
        value.state = state;
        Ok(value)
    }
}
impl CanonicalType for OpenWalletCredentialOfferV1 {
    const TYPE_TAG: u16 = 0x00d0;
    const SCHEMA_VERSION: u16 = OPENWALLET_PROFILE_REVISION;
    const MAX_ENCODED_LEN: usize =
        48 + 48 + 8 + 3 + MAX_OPENWALLET_URI + 1 + MAX_CONFIGURATION_IDS * 48 + 48 * 3 + 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestedCredentialV1 {
    pub format: CredentialFormat,
    pub schema_id: Digest384,
    pub claims_digest: Digest384,
}
impl CanonicalEncode for RequestedCredentialV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.format.encode(encoder)?;
        self.schema_id.encode(encoder)?;
        self.claims_digest.encode(encoder)
    }
}
impl CanonicalDecode for RequestedCredentialV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            format: CredentialFormat::decode(decoder)?,
            schema_id: Digest384::decode(decoder)?,
            claims_digest: Digest384::decode(decoder)?,
        };
        if value.schema_id == Digest384::ZERO || value.claims_digest == Digest384::ZERO {
            return Err(DecodeError::InvalidValue("invalid requested credential"));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenWalletPresentationRequestV1 {
    session: OpenWalletSessionV1,
    client_id: Vec<u8>,
    response_uri: Vec<u8>,
    nonce: Digest384,
    state: Digest384,
    response_mode: PresentationResponseMode,
    requested: Vec<RequestedCredentialV1>,
}
impl OpenWalletPresentationRequestV1 {
    pub fn new(
        session: OpenWalletSessionV1,
        client_id: Vec<u8>,
        response_uri: Vec<u8>,
        nonce: Digest384,
        state: Digest384,
        response_mode: PresentationResponseMode,
        requested: Vec<RequestedCredentialV1>,
    ) -> Result<Self, WalletError> {
        session.validate()?;
        if client_id.is_empty()
            || client_id.len() > MAX_OPENWALLET_URI
            || response_uri.is_empty()
            || response_uri.len() > MAX_OPENWALLET_URI
            || !response_uri.starts_with(b"https://")
            || nonce == Digest384::ZERO
            || state == Digest384::ZERO
            || requested.is_empty()
            || requested.len() > MAX_REQUESTED_CREDENTIALS
            || requested.windows(2).any(|pair| {
                (pair[0].schema_id, pair[0].format as u8)
                    >= (pair[1].schema_id, pair[1].format as u8)
            })
            || requested.iter().any(|item| {
                item.schema_id == Digest384::ZERO || item.claims_digest == Digest384::ZERO
            })
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self { session, client_id, response_uri, nonce, state, response_mode, requested })
    }
    pub const fn session(&self) -> OpenWalletSessionV1 {
        self.session
    }
    pub const fn nonce(&self) -> Digest384 {
        self.nonce
    }
    pub fn requested(&self) -> &[RequestedCredentialV1] {
        &self.requested
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }
}
impl CanonicalEncode for OpenWalletPresentationRequestV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.session.encode(encoder)?;
        encoder.write_bytes(&self.client_id, MAX_OPENWALLET_URI)?;
        encoder.write_bytes(&self.response_uri, MAX_OPENWALLET_URI)?;
        self.nonce.encode(encoder)?;
        self.state.encode(encoder)?;
        self.response_mode.encode(encoder)?;
        encoder.write_length(self.requested.len(), MAX_REQUESTED_CREDENTIALS)?;
        for request in &self.requested {
            request.encode(encoder)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for OpenWalletPresentationRequestV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let session = OpenWalletSessionV1::decode(decoder)?;
        let client_id = decoder.read_bytes(MAX_OPENWALLET_URI)?.to_vec();
        let response_uri = decoder.read_bytes(MAX_OPENWALLET_URI)?.to_vec();
        let nonce = Digest384::decode(decoder)?;
        let state = Digest384::decode(decoder)?;
        let response_mode = PresentationResponseMode::decode(decoder)?;
        let count = decoder.read_length(MAX_REQUESTED_CREDENTIALS)?;
        let mut requested = Vec::with_capacity(count);
        for _ in 0..count {
            requested.push(RequestedCredentialV1::decode(decoder)?);
        }
        Self::new(session, client_id, response_uri, nonce, state, response_mode, requested)
            .map_err(|_| DecodeError::InvalidValue("invalid OpenWallet presentation request"))
    }
}
impl CanonicalType for OpenWalletPresentationRequestV1 {
    const TYPE_TAG: u16 = 0x00d1;
    const SCHEMA_VERSION: u16 = OPENWALLET_PROFILE_REVISION;
    const MAX_ENCODED_LEN: usize = 48
        + 48
        + 8
        + 3
        + MAX_OPENWALLET_URI
        + 3
        + MAX_OPENWALLET_URI
        + 48
        + 48
        + 1
        + 1
        + MAX_REQUESTED_CREDENTIALS * 97;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenWalletConsentV1 {
    session_id: Digest384,
    request_commitment: Digest384,
    selected_credentials: Vec<Digest384>,
    disclosed_claims: Vec<Digest384>,
    approved_at: u64,
    expires_at: u64,
}
impl OpenWalletConsentV1 {
    pub fn new(
        session_id: Digest384,
        request_commitment: Digest384,
        selected_credentials: Vec<Digest384>,
        disclosed_claims: Vec<Digest384>,
        approved_at: u64,
        expires_at: u64,
    ) -> Result<Self, WalletError> {
        if session_id == Digest384::ZERO
            || request_commitment == Digest384::ZERO
            || selected_credentials.is_empty()
            || selected_credentials.len() > MAX_REQUESTED_CREDENTIALS
            || selected_credentials.windows(2).any(|pair| pair[0] >= pair[1])
            || disclosed_claims.is_empty()
            || disclosed_claims.len() > MAX_DISCLOSED_CLAIMS
            || disclosed_claims.windows(2).any(|pair| pair[0] >= pair[1])
            || approved_at > expires_at
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self {
            session_id,
            request_commitment,
            selected_credentials,
            disclosed_claims,
            approved_at,
            expires_at,
        })
    }
    pub const fn session_id(&self) -> Digest384 {
        self.session_id
    }
    pub const fn request_commitment(&self) -> Digest384 {
        self.request_commitment
    }
}
impl CanonicalEncode for OpenWalletConsentV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.session_id.encode(encoder)?;
        self.request_commitment.encode(encoder)?;
        encoder.write_length(self.selected_credentials.len(), MAX_REQUESTED_CREDENTIALS)?;
        for id in &self.selected_credentials {
            id.encode(encoder)?;
        }
        encoder.write_length(self.disclosed_claims.len(), MAX_DISCLOSED_CLAIMS)?;
        for claim in &self.disclosed_claims {
            claim.encode(encoder)?;
        }
        self.approved_at.encode(encoder)?;
        self.expires_at.encode(encoder)
    }
}
impl CanonicalDecode for OpenWalletConsentV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let session_id = Digest384::decode(decoder)?;
        let request_commitment = Digest384::decode(decoder)?;
        let credential_count = decoder.read_length(MAX_REQUESTED_CREDENTIALS)?;
        let mut credentials = Vec::with_capacity(credential_count);
        for _ in 0..credential_count {
            credentials.push(Digest384::decode(decoder)?);
        }
        let claim_count = decoder.read_length(MAX_DISCLOSED_CLAIMS)?;
        let mut claims = Vec::with_capacity(claim_count);
        for _ in 0..claim_count {
            claims.push(Digest384::decode(decoder)?);
        }
        Self::new(
            session_id,
            request_commitment,
            credentials,
            claims,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid OpenWallet consent"))
    }
}
impl CanonicalType for OpenWalletConsentV1 {
    const TYPE_TAG: u16 = 0x00d2;
    const SCHEMA_VERSION: u16 = OPENWALLET_PROFILE_REVISION;
    const MAX_ENCODED_LEN: usize =
        48 + 48 + 1 + MAX_REQUESTED_CREDENTIALS * 48 + 1 + MAX_DISCLOSED_CLAIMS * 48 + 16;
}

#[derive(Default)]
pub struct OpenWalletAdapterV1 {
    sessions: Vec<OpenWalletSessionV1>,
    credentials: Vec<OpenWalletCredentialRefV1>,
    issuance: Vec<OpenWalletCredentialOfferV1>,
    presentations: Vec<OpenWalletPresentationRequestV1>,
    consumed_nonces: Vec<Digest384>,
}
impl OpenWalletAdapterV1 {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register_credential(
        &mut self,
        credential: OpenWalletCredentialRefV1,
    ) -> Result<(), WalletError> {
        credential.validate()?;
        if self.credentials.len() >= MAX_OPENWALLET_CREDENTIALS
            || self.credentials.iter().any(|item| item.credential_id == credential.credential_id)
        {
            return Err(WalletError::DuplicateIntent);
        }
        self.credentials.push(credential);
        self.credentials.sort_by_key(|item| item.credential_id);
        Ok(())
    }
    pub fn open_session(
        &mut self,
        session: OpenWalletSessionV1,
        height: u64,
    ) -> Result<(), WalletError> {
        session.validate()?;
        if session.expires_at < height
            || self.sessions.len() >= MAX_OPENWALLET_SESSIONS
            || self.sessions.iter().any(|item| item.session_id == session.session_id)
        {
            return Err(WalletError::Expired);
        }
        self.sessions.push(session);
        self.sessions.sort_by_key(|item| item.session_id);
        Ok(())
    }
    pub fn begin_issuance(
        &mut self,
        offer: OpenWalletCredentialOfferV1,
        height: u64,
    ) -> Result<(), WalletError> {
        if offer.session.expires_at < height
            || self.consumed_nonces.binary_search(&offer.grant_nonce).is_ok()
            || self.issuance.iter().any(|item| item.session.session_id == offer.session.session_id)
        {
            return Err(WalletError::Replay);
        }
        self.open_session(offer.session, height)?;
        self.issuance.push(offer);
        self.issuance.sort_by_key(|item| item.session.session_id);
        Ok(())
    }
    pub fn authorize_issuance(
        &mut self,
        session_id: Digest384,
        consent_digest: Digest384,
        height: u64,
    ) -> Result<(), WalletError> {
        let offer = self
            .issuance
            .iter_mut()
            .find(|item| item.session.session_id == session_id)
            .ok_or(WalletError::UnknownSession)?;
        if offer.state != IssuanceSessionState::Offered
            || offer.consent_digest != consent_digest
            || offer.session.expires_at < height
        {
            return Err(WalletError::PolicyDenied);
        }
        offer.state = IssuanceSessionState::Authorized;
        Ok(())
    }
    pub fn complete_issuance(
        &mut self,
        session_id: Digest384,
        credential: OpenWalletCredentialRefV1,
        grant_nonce: Digest384,
        height: u64,
    ) -> Result<(), WalletError> {
        let index = self
            .issuance
            .iter()
            .position(|item| item.session.session_id == session_id)
            .ok_or(WalletError::UnknownSession)?;
        let offer = &self.issuance[index];
        if offer.state != IssuanceSessionState::Authorized
            || offer.grant_nonce != grant_nonce
            || offer.session.expires_at < height
            || self.consumed_nonces.binary_search(&grant_nonce).is_ok()
        {
            return Err(WalletError::Replay);
        }
        self.register_credential(credential)?;
        self.issuance[index].state = IssuanceSessionState::Completed;
        self.consumed_nonces.push(grant_nonce);
        self.consumed_nonces.sort();
        Ok(())
    }
    pub fn begin_presentation(
        &mut self,
        request: OpenWalletPresentationRequestV1,
        height: u64,
    ) -> Result<(), WalletError> {
        if request.session.expires_at < height
            || self.consumed_nonces.binary_search(&request.nonce).is_ok()
            || self
                .presentations
                .iter()
                .any(|item| item.session.session_id == request.session.session_id)
        {
            return Err(WalletError::Replay);
        }
        self.open_session(request.session, height)?;
        self.presentations.push(request);
        self.presentations.sort_by_key(|item| item.session.session_id);
        Ok(())
    }
    pub fn approve_presentation(
        &mut self,
        consent: &OpenWalletConsentV1,
        height: u64,
    ) -> Result<(), WalletError> {
        let request = self
            .presentations
            .iter()
            .find(|item| item.session.session_id == consent.session_id)
            .ok_or(WalletError::UnknownSession)?;
        if height > consent.expires_at
            || height > request.session.expires_at
            || consent.request_commitment
                != request.commitment().map_err(|_| WalletError::MalformedAuthorization)?
            || self.consumed_nonces.binary_search(&request.nonce).is_ok()
            || consent.selected_credentials.iter().any(|id| {
                self.credentials.binary_search_by_key(id, |item| item.credential_id).is_err()
            })
        {
            return Err(WalletError::PolicyDenied);
        }
        self.consumed_nonces.push(request.nonce);
        self.consumed_nonces.sort();
        Ok(())
    }
    pub fn credentials(&self) -> &[OpenWalletCredentialRefV1] {
        &self.credentials
    }
    pub fn sessions(&self) -> &[OpenWalletSessionV1] {
        &self.sessions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn session(byte: u8) -> OpenWalletSessionV1 {
        OpenWalletSessionV1 {
            session_id: digest(byte),
            relying_party: digest(byte + 1),
            expires_at: 20,
        }
    }
    fn credential(byte: u8) -> OpenWalletCredentialRefV1 {
        OpenWalletCredentialRefV1 {
            credential_id: digest(byte),
            schema_id: digest(byte + 1),
            issuer: digest(byte + 2),
        }
    }

    #[test]
    fn issuance_is_consent_bound_and_nonce_replay_safe() {
        let offer = OpenWalletCredentialOfferV1::new(
            session(1),
            b"https://issuer.example".to_vec(),
            vec![digest(10)],
            digest(11),
            digest(12),
            digest(13),
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<OpenWalletCredentialOfferV1>(&encode_envelope(&offer).unwrap()),
            Ok(offer.clone())
        );
        let mut adapter = OpenWalletAdapterV1::new();
        adapter.begin_issuance(offer, 1).unwrap();
        assert_eq!(
            adapter.authorize_issuance(digest(1), digest(99), 1),
            Err(WalletError::PolicyDenied)
        );
        adapter.authorize_issuance(digest(1), digest(13), 1).unwrap();
        adapter.complete_issuance(digest(1), credential(20), digest(12), 1).unwrap();
        assert_eq!(
            adapter.complete_issuance(digest(1), credential(30), digest(12), 1),
            Err(WalletError::Replay)
        );
    }

    #[test]
    fn presentation_binds_request_consent_credentials_and_one_shot_nonce() {
        let request = OpenWalletPresentationRequestV1::new(
            session(40),
            b"verifier.example".to_vec(),
            b"https://verifier.example/response".to_vec(),
            digest(42),
            digest(43),
            PresentationResponseMode::DirectPostJwt,
            vec![RequestedCredentialV1 {
                format: CredentialFormat::Mdoc,
                schema_id: digest(21),
                claims_digest: digest(44),
            }],
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<OpenWalletPresentationRequestV1>(&encode_envelope(&request).unwrap()),
            Ok(request.clone())
        );
        let mut adapter = OpenWalletAdapterV1::new();
        adapter.register_credential(credential(20)).unwrap();
        adapter.begin_presentation(request.clone(), 1).unwrap();
        let consent = OpenWalletConsentV1::new(
            digest(40),
            request.commitment().unwrap(),
            vec![digest(20)],
            vec![digest(45)],
            1,
            10,
        )
        .unwrap();
        adapter.approve_presentation(&consent, 1).unwrap();
        assert_eq!(adapter.approve_presentation(&consent, 1), Err(WalletError::PolicyDenied));
    }
}
