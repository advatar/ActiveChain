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
    const TYPE_TAG: u16 = 0x0122;
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
    const TYPE_TAG: u16 = 0x0124;
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
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
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
    const TYPE_TAG: u16 = 0x0127;
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
        if offer.state != IssuanceSessionState::Offered {
            return Err(WalletError::PolicyDenied);
        }
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
        {
            return Err(WalletError::PolicyDenied);
        }
        // Every disclosed credential must be held and must answer a requested schema, and every
        // requested schema must be answered. This rejects both over-disclosure of unrelated
        // credentials and selections that do not satisfy the verifier's request.
        let disclosed: Vec<Digest384> = consent
            .selected_credentials
            .iter()
            .map(|id| {
                self.credentials
                    .binary_search_by_key(id, |item| item.credential_id)
                    .map(|index| self.credentials[index].schema_id)
                    .map_err(|_| WalletError::PolicyDenied)
            })
            .collect::<Result<_, _>>()?;
        if disclosed
            .iter()
            .any(|held| !request.requested.iter().any(|want| want.schema_id == *held))
            || request.requested.iter().any(|want| !disclosed.contains(&want.schema_id))
        {
            return Err(WalletError::PolicyDenied);
        }
        let nonce = request.nonce;
        self.consumed_nonces.push(nonce);
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
    fn offer(byte: u8) -> OpenWalletCredentialOfferV1 {
        OpenWalletCredentialOfferV1::new(
            session(byte),
            b"https://issuer.example".to_vec(),
            vec![digest(byte + 10)],
            digest(byte + 11),
            digest(byte + 12),
            digest(byte + 13),
        )
        .expect("fixture offer is valid")
    }
    fn request(byte: u8) -> OpenWalletPresentationRequestV1 {
        OpenWalletPresentationRequestV1::new(
            session(byte),
            b"verifier.example".to_vec(),
            b"https://verifier.example/response".to_vec(),
            digest(byte + 2),
            digest(byte + 3),
            PresentationResponseMode::DirectPostJwt,
            vec![RequestedCredentialV1 {
                format: CredentialFormat::Mdoc,
                schema_id: digest(byte + 4),
                claims_digest: digest(byte + 5),
            }],
        )
        .expect("fixture request is valid")
    }
    fn issuance_state(
        adapter: &OpenWalletAdapterV1,
        session_id: Digest384,
    ) -> Option<IssuanceSessionState> {
        adapter
            .issuance
            .iter()
            .find(|item| item.session.session_id == session_id)
            .map(OpenWalletCredentialOfferV1::state)
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

    #[test]
    fn issuance_happy_path_walks_offered_authorized_completed_exactly_once() {
        let mut adapter = OpenWalletAdapterV1::new();
        let offered = offer(1);
        let session_id = offered.session().session_id;
        let (consent_digest, grant_nonce) = (offered.consent_digest(), offered.grant_nonce());

        adapter.begin_issuance(offered, 1).unwrap();
        assert_eq!(issuance_state(&adapter, session_id), Some(IssuanceSessionState::Offered));
        assert_eq!(adapter.sessions().len(), 1);
        assert!(adapter.credentials().is_empty());

        adapter.authorize_issuance(session_id, consent_digest, 5).unwrap();
        assert_eq!(issuance_state(&adapter, session_id), Some(IssuanceSessionState::Authorized));
        assert!(adapter.credentials().is_empty());

        adapter.complete_issuance(session_id, credential(50), grant_nonce, 5).unwrap();
        assert_eq!(issuance_state(&adapter, session_id), Some(IssuanceSessionState::Completed));
        assert_eq!(adapter.credentials(), &[credential(50)]);
        assert_eq!(adapter.consumed_nonces, vec![grant_nonce]);

        // The terminal state is absorbing: neither step may run a second time.
        assert_eq!(
            adapter.authorize_issuance(session_id, consent_digest, 5),
            Err(WalletError::PolicyDenied)
        );
        assert_eq!(
            adapter.complete_issuance(session_id, credential(60), grant_nonce, 5),
            Err(WalletError::Replay)
        );
    }

    #[test]
    fn issuance_steps_out_of_order_or_for_unknown_sessions_are_rejected() {
        let mut adapter = OpenWalletAdapterV1::new();
        let offered = offer(1);
        let session_id = offered.session().session_id;
        let (consent_digest, grant_nonce) = (offered.consent_digest(), offered.grant_nonce());

        // Neither step exists before the offer is admitted.
        assert_eq!(
            adapter.authorize_issuance(session_id, consent_digest, 1),
            Err(WalletError::UnknownSession)
        );
        assert_eq!(
            adapter.complete_issuance(session_id, credential(50), grant_nonce, 1),
            Err(WalletError::UnknownSession)
        );

        adapter.begin_issuance(offered, 1).unwrap();

        // Completing before authorizing is refused and leaves the offer in the offered state.
        assert_eq!(
            adapter.complete_issuance(session_id, credential(50), grant_nonce, 1),
            Err(WalletError::Replay)
        );
        assert_eq!(issuance_state(&adapter, session_id), Some(IssuanceSessionState::Offered));
        assert!(adapter.credentials().is_empty());
        assert!(adapter.consumed_nonces.is_empty());

        adapter.authorize_issuance(session_id, consent_digest, 1).unwrap();
        // Authorizing twice is refused; the offer stays authorized rather than regressing.
        assert_eq!(
            adapter.authorize_issuance(session_id, consent_digest, 1),
            Err(WalletError::PolicyDenied)
        );
        assert_eq!(issuance_state(&adapter, session_id), Some(IssuanceSessionState::Authorized));

        // Completing with the wrong grant nonce is refused without consuming anything.
        assert_eq!(
            adapter.complete_issuance(session_id, credential(50), digest(99), 1),
            Err(WalletError::Replay)
        );
        assert!(adapter.consumed_nonces.is_empty());
        // Every step also fails once the session expires.
        assert_eq!(
            adapter.complete_issuance(session_id, credential(50), grant_nonce, 21),
            Err(WalletError::Replay)
        );
    }

    #[test]
    fn issuance_rejects_reused_sessions_and_replayed_grant_nonces() {
        let mut adapter = OpenWalletAdapterV1::new();
        let first = offer(1);
        let session_id = first.session().session_id;
        let (consent_digest, grant_nonce) = (first.consent_digest(), first.grant_nonce());
        adapter.begin_issuance(first.clone(), 1).unwrap();

        // The same session identifier may never carry a second offer.
        assert_eq!(adapter.begin_issuance(first, 1), Err(WalletError::Replay));
        // A distinct offer that reuses only the session identifier is refused too.
        let mut aliased = offer(1);
        aliased.grant_nonce = digest(200);
        aliased.consent_digest = digest(201);
        assert_eq!(adapter.begin_issuance(aliased, 1), Err(WalletError::Replay));

        adapter.authorize_issuance(session_id, consent_digest, 1).unwrap();
        adapter.complete_issuance(session_id, credential(50), grant_nonce, 1).unwrap();

        // A fresh session that replays the spent grant nonce is refused at admission.
        let mut replayed = offer(70);
        replayed.grant_nonce = grant_nonce;
        assert_eq!(adapter.begin_issuance(replayed, 1), Err(WalletError::Replay));
        // An offer whose session already expired relative to the current height is refused.
        assert_eq!(adapter.begin_issuance(offer(70), 21), Err(WalletError::Replay));
    }

    /// Regression for #678: a decoded offer must never arrive pre-authorized.
    ///
    /// `decode` restores the wire-supplied state, so without an explicit check `begin_issuance`
    /// would admit an offer already marked `Authorized` and `complete_issuance` would register a
    /// credential without `authorize_issuance` — the only step that verifies `consent_digest`
    /// ever running.
    #[test]
    fn decoded_offers_cannot_arrive_pre_authorized_and_skip_consent() {
        let mut adapter = OpenWalletAdapterV1::new();
        let mut forged = offer(30);
        forged.state = IssuanceSessionState::Authorized;
        let wire = encode_envelope(&forged).unwrap();
        let decoded = decode_envelope::<OpenWalletCredentialOfferV1>(&wire).unwrap();
        assert_eq!(decoded.state(), IssuanceSessionState::Authorized);

        assert_eq!(adapter.begin_issuance(decoded, 1), Err(WalletError::PolicyDenied));
        assert!(issuance_state(&adapter, digest(30)).is_none());
        assert_eq!(
            adapter.complete_issuance(digest(30), credential(70), digest(42), 1),
            Err(WalletError::UnknownSession)
        );
        assert!(adapter.credentials.is_empty());
        assert!(adapter.consumed_nonces.is_empty());

        // A `Completed` offer is refused on the same grounds.
        let mut finished = offer(30);
        finished.state = IssuanceSessionState::Completed;
        assert_eq!(adapter.begin_issuance(finished, 1), Err(WalletError::PolicyDenied));

        // The honest offer for the same session still admits and requires real consent.
        adapter.begin_issuance(offer(30), 1).unwrap();
        assert_eq!(issuance_state(&adapter, digest(30)), Some(IssuanceSessionState::Offered));
        assert_eq!(
            adapter.complete_issuance(digest(30), credential(70), digest(42), 1),
            Err(WalletError::Replay)
        );
        assert_eq!(
            adapter.authorize_issuance(digest(30), digest(99), 1),
            Err(WalletError::PolicyDenied)
        );
        adapter.authorize_issuance(digest(30), digest(43), 1).unwrap();
    }

    /// Regression for #678: disclosure must answer the request and disclose nothing beyond it.
    #[test]
    fn presentation_approval_binds_selected_credentials_to_the_requested_schemas() {
        let mut adapter = OpenWalletAdapterV1::new();
        // request(40) asks for schema digest(44); credential(90) carries unrelated schema
        // digest(91), and credential(43) carries the requested one.
        adapter.register_credential(credential(90)).unwrap();
        adapter.register_credential(credential(43)).unwrap();
        let pending = request(40);
        adapter.begin_presentation(pending.clone(), 1).unwrap();
        let commitment = pending.commitment().unwrap();

        let unrelated = OpenWalletConsentV1::new(
            digest(40),
            commitment,
            vec![digest(90)],
            vec![digest(45)],
            1,
            10,
        )
        .unwrap();
        assert_eq!(adapter.approve_presentation(&unrelated, 1), Err(WalletError::PolicyDenied));

        // Disclosing an unrequested credential alongside the requested one over-discloses.
        let over = OpenWalletConsentV1::new(
            digest(40),
            commitment,
            vec![digest(43), digest(90)],
            vec![digest(45)],
            1,
            10,
        )
        .unwrap();
        assert_eq!(adapter.approve_presentation(&over, 1), Err(WalletError::PolicyDenied));

        // Nothing was consumed by the rejected attempts.
        assert!(adapter.consumed_nonces.is_empty());
        let exact = OpenWalletConsentV1::new(
            digest(40),
            commitment,
            vec![digest(43)],
            vec![digest(45)],
            1,
            10,
        )
        .unwrap();
        adapter.approve_presentation(&exact, 1).unwrap();
    }

    #[test]
    fn presentation_approval_requires_registered_selected_credentials() {
        let mut adapter = OpenWalletAdapterV1::new();
        // credential(43) carries schema digest(44), exactly what request(40) asks for.
        adapter.register_credential(credential(43)).unwrap();
        let pending = request(40);
        adapter.begin_presentation(pending.clone(), 1).unwrap();
        let commitment = pending.commitment().unwrap();

        // A credential the wallet never registered cannot be disclosed.
        let unheld = OpenWalletConsentV1::new(
            digest(40),
            commitment,
            vec![digest(99)],
            vec![digest(45)],
            1,
            10,
        )
        .unwrap();
        assert_eq!(adapter.approve_presentation(&unheld, 1), Err(WalletError::PolicyDenied));
        // A partially held selection fails closed on the missing member.
        let partial = OpenWalletConsentV1::new(
            digest(40),
            commitment,
            vec![digest(43), digest(99)],
            vec![digest(45)],
            1,
            10,
        )
        .unwrap();
        assert_eq!(adapter.approve_presentation(&partial, 1), Err(WalletError::PolicyDenied));
        // Nothing was consumed, so the honest approval still succeeds afterwards.
        assert!(adapter.consumed_nonces.is_empty());
        let honest = OpenWalletConsentV1::new(
            digest(40),
            commitment,
            vec![digest(43)],
            vec![digest(45)],
            1,
            10,
        )
        .unwrap();
        adapter.approve_presentation(&honest, 1).unwrap();
        assert_eq!(adapter.consumed_nonces, vec![pending.nonce()]);
    }

    #[test]
    fn presentation_approval_rejects_unknown_sessions_wrong_commitments_and_expiry() {
        let mut adapter = OpenWalletAdapterV1::new();
        adapter.register_credential(credential(20)).unwrap();
        let pending = request(40);
        adapter.begin_presentation(pending.clone(), 1).unwrap();
        let commitment = pending.commitment().unwrap();

        // A consent naming a session the adapter never opened is unknown, not merely denied.
        let stranger = OpenWalletConsentV1::new(
            digest(70),
            commitment,
            vec![digest(20)],
            vec![digest(45)],
            1,
            10,
        )
        .unwrap();
        assert_eq!(adapter.approve_presentation(&stranger, 1), Err(WalletError::UnknownSession));

        // A consent bound to any other request commitment is refused.
        let mismatched = OpenWalletConsentV1::new(
            digest(40),
            request(60).commitment().unwrap(),
            vec![digest(20)],
            vec![digest(45)],
            1,
            10,
        )
        .unwrap();
        assert_eq!(adapter.approve_presentation(&mismatched, 1), Err(WalletError::PolicyDenied));

        let honest = OpenWalletConsentV1::new(
            digest(40),
            commitment,
            vec![digest(20)],
            vec![digest(45)],
            1,
            10,
        )
        .unwrap();
        // Past the consent expiry, and past the session expiry, approval fails closed.
        assert_eq!(adapter.approve_presentation(&honest, 11), Err(WalletError::PolicyDenied));
        let long_lived = OpenWalletConsentV1::new(
            digest(40),
            commitment,
            vec![digest(20)],
            vec![digest(45)],
            1,
            99,
        )
        .unwrap();
        assert_eq!(adapter.approve_presentation(&long_lived, 21), Err(WalletError::PolicyDenied));
        assert!(adapter.consumed_nonces.is_empty());
    }

    #[test]
    fn presentation_rejects_reused_sessions_and_replayed_nonces() {
        let mut adapter = OpenWalletAdapterV1::new();
        let pending = request(40);
        adapter.begin_presentation(pending.clone(), 1).unwrap();
        assert_eq!(adapter.begin_presentation(pending.clone(), 1), Err(WalletError::Replay));
        assert_eq!(adapter.begin_presentation(request(40), 21), Err(WalletError::Replay));

        adapter.register_credential(credential(43)).unwrap();
        let consent = OpenWalletConsentV1::new(
            digest(40),
            pending.commitment().unwrap(),
            vec![digest(43)],
            vec![digest(45)],
            1,
            10,
        )
        .unwrap();
        adapter.approve_presentation(&consent, 1).unwrap();

        // The spent request nonce is refused for any later session as well.
        let mut replayed = request(80);
        replayed.nonce = pending.nonce();
        assert_eq!(adapter.begin_presentation(replayed, 1), Err(WalletError::Replay));
    }

    #[test]
    fn sessions_and_credentials_reject_zero_identifiers_duplicates_and_capacity() {
        let mut adapter = OpenWalletAdapterV1::new();
        for zeroed in [
            OpenWalletCredentialRefV1 {
                credential_id: Digest384::ZERO,
                schema_id: digest(2),
                issuer: digest(3),
            },
            OpenWalletCredentialRefV1 {
                credential_id: digest(1),
                schema_id: Digest384::ZERO,
                issuer: digest(3),
            },
            OpenWalletCredentialRefV1 {
                credential_id: digest(1),
                schema_id: digest(2),
                issuer: Digest384::ZERO,
            },
        ] {
            assert_eq!(
                adapter.register_credential(zeroed),
                Err(WalletError::MalformedAuthorization)
            );
        }
        adapter.register_credential(credential(20)).unwrap();
        assert_eq!(adapter.register_credential(credential(20)), Err(WalletError::DuplicateIntent));

        for invalid in [
            OpenWalletSessionV1 {
                session_id: Digest384::ZERO,
                relying_party: digest(2),
                expires_at: 20,
            },
            OpenWalletSessionV1 {
                session_id: digest(1),
                relying_party: Digest384::ZERO,
                expires_at: 20,
            },
            OpenWalletSessionV1 { session_id: digest(1), relying_party: digest(2), expires_at: 0 },
        ] {
            assert_eq!(adapter.open_session(invalid, 1), Err(WalletError::MalformedAuthorization));
        }
        // A session that already expired at the current height is refused.
        assert_eq!(adapter.open_session(session(1), 21), Err(WalletError::Expired));

        // The session table is bounded and refuses admission once it is full.
        let mut bounded = OpenWalletAdapterV1::new();
        for index in 1..=MAX_OPENWALLET_SESSIONS {
            let opened = OpenWalletSessionV1 {
                session_id: digest(u8::try_from(index).unwrap()),
                relying_party: digest(0xff),
                expires_at: 20,
            };
            bounded.open_session(opened, 1).unwrap();
        }
        let overflow = OpenWalletSessionV1 {
            session_id: digest(0xfe),
            relying_party: digest(0xff),
            expires_at: 20,
        };
        assert_eq!(bounded.open_session(overflow, 1), Err(WalletError::Expired));
        assert_eq!(bounded.sessions().len(), MAX_OPENWALLET_SESSIONS);
    }

    #[test]
    fn credential_offer_constructor_rejects_malformed_inputs() {
        let valid = |session, uri: &[u8], ids, server, nonce, consent| {
            OpenWalletCredentialOfferV1::new(session, uri.to_vec(), ids, server, nonce, consent)
        };
        let zero_session = OpenWalletSessionV1 {
            session_id: Digest384::ZERO,
            relying_party: digest(2),
            expires_at: 5,
        };
        for rejected in [
            valid(
                zero_session,
                b"https://issuer.example",
                vec![digest(10)],
                digest(11),
                digest(12),
                digest(13),
            ),
            valid(session(1), b"", vec![digest(10)], digest(11), digest(12), digest(13)),
            valid(
                session(1),
                b"http://issuer.example",
                vec![digest(10)],
                digest(11),
                digest(12),
                digest(13),
            ),
            valid(
                session(1),
                b"https://issuer.example",
                Vec::new(),
                digest(11),
                digest(12),
                digest(13),
            ),
            // Configuration identifiers must be strictly ascending, so equal and descending fail.
            valid(
                session(1),
                b"https://issuer.example",
                vec![digest(10), digest(10)],
                digest(11),
                digest(12),
                digest(13),
            ),
            valid(
                session(1),
                b"https://issuer.example",
                vec![digest(11), digest(10)],
                digest(11),
                digest(12),
                digest(13),
            ),
            valid(
                session(1),
                b"https://issuer.example",
                vec![digest(10)],
                Digest384::ZERO,
                digest(12),
                digest(13),
            ),
            valid(
                session(1),
                b"https://issuer.example",
                vec![digest(10)],
                digest(11),
                Digest384::ZERO,
                digest(13),
            ),
            valid(
                session(1),
                b"https://issuer.example",
                vec![digest(10)],
                digest(11),
                digest(12),
                Digest384::ZERO,
            ),
        ] {
            assert_eq!(rejected, Err(WalletError::MalformedAuthorization));
        }
        let oversize = vec![b'a'; MAX_OPENWALLET_URI + 1];
        assert_eq!(
            OpenWalletCredentialOfferV1::new(
                session(1),
                oversize,
                vec![digest(10)],
                digest(11),
                digest(12),
                digest(13),
            ),
            Err(WalletError::MalformedAuthorization)
        );
        let too_many: Vec<Digest384> =
            (0..=MAX_CONFIGURATION_IDS).map(|index| digest(u8::try_from(index).unwrap())).collect();
        assert_eq!(
            OpenWalletCredentialOfferV1::new(
                session(1),
                b"https://issuer.example".to_vec(),
                too_many,
                digest(11),
                digest(12),
                digest(13),
            ),
            Err(WalletError::MalformedAuthorization)
        );
    }

    #[test]
    fn presentation_request_constructor_rejects_malformed_inputs() {
        let requested = |format, schema, claims| RequestedCredentialV1 {
            format,
            schema_id: schema,
            claims_digest: claims,
        };
        let build = |client: &[u8], uri: &[u8], nonce, state, items| {
            OpenWalletPresentationRequestV1::new(
                session(40),
                client.to_vec(),
                uri.to_vec(),
                nonce,
                state,
                PresentationResponseMode::DirectPost,
                items,
            )
        };
        let one = vec![requested(CredentialFormat::Mdoc, digest(21), digest(44))];
        for rejected in [
            build(b"", b"https://verifier.example", digest(42), digest(43), one.clone()),
            build(b"verifier.example", b"", digest(42), digest(43), one.clone()),
            // The response endpoint must be an https URL.
            build(
                b"verifier.example",
                b"http://verifier.example",
                digest(42),
                digest(43),
                one.clone(),
            ),
            build(
                b"verifier.example",
                b"https://verifier.example",
                Digest384::ZERO,
                digest(43),
                one.clone(),
            ),
            build(
                b"verifier.example",
                b"https://verifier.example",
                digest(42),
                Digest384::ZERO,
                one.clone(),
            ),
            build(
                b"verifier.example",
                b"https://verifier.example",
                digest(42),
                digest(43),
                Vec::new(),
            ),
            // Requested credentials must be strictly ascending by (schema_id, format).
            build(
                b"verifier.example",
                b"https://verifier.example",
                digest(42),
                digest(43),
                vec![
                    requested(CredentialFormat::Mdoc, digest(21), digest(44)),
                    requested(CredentialFormat::SdJwtVc, digest(21), digest(45)),
                ],
            ),
            build(
                b"verifier.example",
                b"https://verifier.example",
                digest(42),
                digest(43),
                vec![
                    requested(CredentialFormat::SdJwtVc, digest(22), digest(44)),
                    requested(CredentialFormat::SdJwtVc, digest(21), digest(45)),
                ],
            ),
            // Zero-valued members of an otherwise well-formed list are refused.
            build(
                b"verifier.example",
                b"https://verifier.example",
                digest(42),
                digest(43),
                vec![requested(CredentialFormat::Mdoc, Digest384::ZERO, digest(44))],
            ),
            build(
                b"verifier.example",
                b"https://verifier.example",
                digest(42),
                digest(43),
                vec![requested(CredentialFormat::Mdoc, digest(21), Digest384::ZERO)],
            ),
        ] {
            assert_eq!(rejected, Err(WalletError::MalformedAuthorization));
        }
        let zero_session =
            OpenWalletSessionV1 { session_id: digest(1), relying_party: digest(2), expires_at: 0 };
        assert_eq!(
            OpenWalletPresentationRequestV1::new(
                zero_session,
                b"verifier.example".to_vec(),
                b"https://verifier.example".to_vec(),
                digest(42),
                digest(43),
                PresentationResponseMode::DigitalCredentialsApi,
                one,
            ),
            Err(WalletError::MalformedAuthorization)
        );
    }

    #[test]
    fn consent_constructor_rejects_malformed_inputs() {
        let build = |session_id, commitment, selected, claims, approved, expires| {
            OpenWalletConsentV1::new(session_id, commitment, selected, claims, approved, expires)
        };
        for rejected in [
            build(Digest384::ZERO, digest(2), vec![digest(3)], vec![digest(4)], 1, 10),
            build(digest(1), Digest384::ZERO, vec![digest(3)], vec![digest(4)], 1, 10),
            build(digest(1), digest(2), Vec::new(), vec![digest(4)], 1, 10),
            build(digest(1), digest(2), vec![digest(3)], Vec::new(), 1, 10),
            // Both lists must be strictly ascending with no repeats.
            build(digest(1), digest(2), vec![digest(3), digest(3)], vec![digest(4)], 1, 10),
            build(digest(1), digest(2), vec![digest(4), digest(3)], vec![digest(4)], 1, 10),
            build(digest(1), digest(2), vec![digest(3)], vec![digest(4), digest(4)], 1, 10),
            build(digest(1), digest(2), vec![digest(3)], vec![digest(5), digest(4)], 1, 10),
            // Approval may not postdate the consent expiry.
            build(digest(1), digest(2), vec![digest(3)], vec![digest(4)], 11, 10),
        ] {
            assert_eq!(rejected, Err(WalletError::MalformedAuthorization));
        }
        // Approval exactly at the expiry height is the accepted boundary.
        build(digest(1), digest(2), vec![digest(3)], vec![digest(4)], 10, 10).unwrap();
    }

    #[test]
    fn enveloped_openwallet_types_round_trip_canonically() {
        let offered = offer(1);
        assert_eq!(
            decode_envelope::<OpenWalletCredentialOfferV1>(&encode_envelope(&offered).unwrap()),
            Ok(offered.clone())
        );
        // The declared issuance state travels inside the body rather than being reset on decode.
        let mut authorized = offered;
        authorized.state = IssuanceSessionState::Authorized;
        let decoded =
            decode_envelope::<OpenWalletCredentialOfferV1>(&encode_envelope(&authorized).unwrap())
                .unwrap();
        assert_eq!(decoded.state(), IssuanceSessionState::Authorized);
        assert_eq!(decoded, authorized);

        let pending = request(40);
        assert_eq!(
            decode_envelope::<OpenWalletPresentationRequestV1>(&encode_envelope(&pending).unwrap()),
            Ok(pending.clone())
        );

        let consent = OpenWalletConsentV1::new(
            digest(40),
            pending.commitment().unwrap(),
            vec![digest(20), digest(21)],
            vec![digest(45), digest(46)],
            1,
            10,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<OpenWalletConsentV1>(&encode_envelope(&consent).unwrap()),
            Ok(consent.clone())
        );
        // The canonical commitment is stable and domain separated per value.
        assert_eq!(consent.commitment().unwrap(), consent.commitment().unwrap());
        assert_ne!(consent.commitment().unwrap(), pending.commitment().unwrap());
        assert_eq!(consent.session_id(), digest(40));
        assert_eq!(consent.request_commitment(), pending.commitment().unwrap());
    }

    #[test]
    fn enveloped_openwallet_types_reject_out_of_range_enum_tags() {
        let mut envelope = encode_envelope(&offer(1)).unwrap();
        // The trailing byte of the offer body is the issuance state discriminant.
        *envelope.last_mut().unwrap() = 3;
        assert!(decode_envelope::<OpenWalletCredentialOfferV1>(&envelope).is_err());

        let pending = request(40);
        let body = encode_envelope(&pending).unwrap();
        let mut tampered = body.clone();
        // Zeroing the trailing claims digest must fail the requested-credential validity check.
        let length = tampered.len();
        tampered[length - 48..].fill(0);
        assert!(decode_envelope::<OpenWalletPresentationRequestV1>(&tampered).is_err());
        assert!(decode_envelope::<OpenWalletPresentationRequestV1>(&body).is_ok());
    }
}
