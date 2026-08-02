//! Fail-closed OpenID4VP transport over pinned, commitment-only trust boundaries.

extern crate alloc;
use crate::{CredentialFormat, OpenWalletPresentationRequestV1, WalletError};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{ChainId, Digest384, PrincipalId};
use alloc::vec::Vec;

pub const MAX_OPENID4VP_TRANSPORT_SESSIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedVerifierMetadataV1 {
    pub verifier: PrincipalId,
    pub metadata_commitment: Digest384,
    pub response_uri_commitment: Digest384,
    pub encryption_key_commitment: Digest384,
    pub revision: u64,
    pub valid_until: u64,
}
impl PinnedVerifierMetadataV1 {
    pub fn new(
        verifier: PrincipalId,
        metadata: Digest384,
        response_uri: Digest384,
        encryption_key: Digest384,
        revision: u64,
        valid_until: u64,
    ) -> Result<Self, WalletError> {
        if verifier.digest() == &Digest384::ZERO
            || [metadata, response_uri, encryption_key].into_iter().any(|v| v == Digest384::ZERO)
            || revision == 0
            || valid_until == 0
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self {
            verifier,
            metadata_commitment: metadata,
            response_uri_commitment: response_uri,
            encryption_key_commitment: encryption_key,
            revision,
            valid_until,
        })
    }
}
impl CanonicalEncode for PinnedVerifierMetadataV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.verifier.encode(e)?;
        self.metadata_commitment.encode(e)?;
        self.response_uri_commitment.encode(e)?;
        self.encryption_key_commitment.encode(e)?;
        self.revision.encode(e)?;
        self.valid_until.encode(e)
    }
}
impl CanonicalDecode for PinnedVerifierMetadataV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid pinned verifier metadata"))
    }
}
impl CanonicalType for PinnedVerifierMetadataV1 {
    const TYPE_TAG: u16 = 0x01A2;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 4 + 16;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveTrustStatusAnchorV1 {
    pub chain: ChainId,
    pub chain_genesis: Digest384,
    pub issuer_binding: Digest384,
    pub profile: Digest384,
    pub trust_root: Digest384,
    pub status_root: Digest384,
    pub trust_revision: u64,
    pub status_sequence: u64,
    pub finalized_height: u64,
    pub valid_until: u64,
    pub issuer_active: bool,
}
impl LiveTrustStatusAnchorV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: ChainId,
        genesis: Digest384,
        issuer: Digest384,
        profile: Digest384,
        trust: Digest384,
        status: Digest384,
        trust_revision: u64,
        status_sequence: u64,
        finalized_height: u64,
        valid_until: u64,
        issuer_active: bool,
    ) -> Result<Self, WalletError> {
        if [genesis, issuer, profile, trust, status].into_iter().any(|v| v == Digest384::ZERO)
            || trust_revision == 0
            || status_sequence == 0
            || finalized_height == 0
            || valid_until < finalized_height
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self {
            chain,
            chain_genesis: genesis,
            issuer_binding: issuer,
            profile,
            trust_root: trust,
            status_root: status,
            trust_revision,
            status_sequence,
            finalized_height,
            valid_until,
            issuer_active,
        })
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }
}
impl CanonicalEncode for LiveTrustStatusAnchorV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain.encode(e)?;
        self.chain_genesis.encode(e)?;
        self.issuer_binding.encode(e)?;
        self.profile.encode(e)?;
        self.trust_root.encode(e)?;
        self.status_root.encode(e)?;
        self.trust_revision.encode(e)?;
        self.status_sequence.encode(e)?;
        self.finalized_height.encode(e)?;
        self.valid_until.encode(e)?;
        self.issuer_active.encode(e)
    }
}
impl CanonicalDecode for LiveTrustStatusAnchorV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            bool::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid live trust/status anchor"))
    }
}
impl CanonicalType for LiveTrustStatusAnchorV1 {
    const TYPE_TAG: u16 = 0x01A3;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 6 + 32 + 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OpenId4VpTransportStateV1 {
    Review = 0,
    Approved = 1,
    Posted = 2,
    Consumed = 3,
    Cancelled = 4,
}
impl CanonicalEncode for OpenId4VpTransportStateV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for OpenId4VpTransportStateV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Review),
            1 => Ok(Self::Approved),
            2 => Ok(Self::Posted),
            3 => Ok(Self::Consumed),
            4 => Ok(Self::Cancelled),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "OpenId4VpTransportStateV1", tag }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenId4VpTransportRequestV1 {
    pub session: Digest384,
    pub request_commitment: Digest384,
    pub verifier_metadata_commitment: Digest384,
    pub trust_status_commitment: Digest384,
    pub audience: PrincipalId,
    pub purpose: Digest384,
    pub policy_revision: u64,
    pub nonce: Digest384,
    pub expires_at: u64,
    pub adapter_revision: u16,
    pub format: CredentialFormat,
    pub state: OpenId4VpTransportStateV1,
}
impl OpenId4VpTransportRequestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session: Digest384,
        request: Digest384,
        metadata: Digest384,
        trust: Digest384,
        audience: PrincipalId,
        purpose: Digest384,
        policy_revision: u64,
        nonce: Digest384,
        expires_at: u64,
        adapter_revision: u16,
        format: CredentialFormat,
    ) -> Result<Self, WalletError> {
        if [session, request, metadata, trust, purpose, nonce]
            .into_iter()
            .any(|v| v == Digest384::ZERO)
            || audience.digest() == &Digest384::ZERO
            || policy_revision == 0
            || expires_at == 0
            || adapter_revision == 0
            || format == CredentialFormat::W3cVc
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self {
            session,
            request_commitment: request,
            verifier_metadata_commitment: metadata,
            trust_status_commitment: trust,
            audience,
            purpose,
            policy_revision,
            nonce,
            expires_at,
            adapter_revision,
            format,
            state: OpenId4VpTransportStateV1::Review,
        })
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }
}
impl CanonicalEncode for OpenId4VpTransportRequestV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.session.encode(e)?;
        self.request_commitment.encode(e)?;
        self.verifier_metadata_commitment.encode(e)?;
        self.trust_status_commitment.encode(e)?;
        self.audience.encode(e)?;
        self.purpose.encode(e)?;
        self.policy_revision.encode(e)?;
        self.nonce.encode(e)?;
        self.expires_at.encode(e)?;
        self.adapter_revision.encode(e)?;
        self.format.encode(e)?;
        self.state.encode(e)
    }
}
impl CanonicalDecode for OpenId4VpTransportRequestV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let mut v = Self::new(
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u16::decode(d)?,
            CredentialFormat::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid OpenID4VP transport request"))?;
        v.state = OpenId4VpTransportStateV1::decode(d)?;
        Ok(v)
    }
}
impl CanonicalType for OpenId4VpTransportRequestV1 {
    const TYPE_TAG: u16 = 0x01A4;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 7 + 8 * 2 + 2 + 2;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenId4VpBoundedResponseV1 {
    pub session: Digest384,
    pub request_commitment: Digest384,
    pub adapter_output_commitment: Digest384,
    pub receipt_commitment: Digest384,
    pub trust_status_commitment: Digest384,
    pub response_encryption_commitment: Digest384,
    pub format: CredentialFormat,
}
impl OpenId4VpBoundedResponseV1 {
    pub fn new(
        session: Digest384,
        request: Digest384,
        output: Digest384,
        receipt: Digest384,
        trust: Digest384,
        encryption: Digest384,
        format: CredentialFormat,
    ) -> Result<Self, WalletError> {
        if [session, request, output, receipt, trust, encryption]
            .into_iter()
            .any(|v| v == Digest384::ZERO)
            || format == CredentialFormat::W3cVc
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self {
            session,
            request_commitment: request,
            adapter_output_commitment: output,
            receipt_commitment: receipt,
            trust_status_commitment: trust,
            response_encryption_commitment: encryption,
            format,
        })
    }
}
impl CanonicalEncode for OpenId4VpBoundedResponseV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.session.encode(e)?;
        self.request_commitment.encode(e)?;
        self.adapter_output_commitment.encode(e)?;
        self.receipt_commitment.encode(e)?;
        self.trust_status_commitment.encode(e)?;
        self.response_encryption_commitment.encode(e)?;
        self.format.encode(e)
    }
}
impl CanonicalDecode for OpenId4VpBoundedResponseV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            CredentialFormat::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid bounded OpenID4VP response"))
    }
}
impl CanonicalType for OpenId4VpBoundedResponseV1 {
    const TYPE_TAG: u16 = 0x01A5;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 6 + 1;
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct OpenId4VpTransportSnapshotV1 {
    generation: u64,
    sessions: Vec<OpenId4VpTransportRequestV1>,
    consumed_nonces: Vec<Digest384>,
}
impl OpenId4VpTransportSnapshotV1 {
    pub fn begin(
        &mut self,
        request: OpenId4VpTransportRequestV1,
        now: u64,
    ) -> Result<(), WalletError> {
        if request.expires_at < now
            || self.sessions.len() >= MAX_OPENID4VP_TRANSPORT_SESSIONS
            || self.sessions.iter().any(|s| s.session == request.session)
            || self.consumed_nonces.binary_search(&request.nonce).is_ok()
        {
            return Err(WalletError::Replay);
        }
        self.sessions.push(request);
        self.sessions.sort_by_key(|s| s.session);
        self.generation = self.generation.checked_add(1).ok_or(WalletError::PolicyDenied)?;
        Ok(())
    }
    pub fn approve(
        &mut self,
        session: Digest384,
        request: Digest384,
        user_presence: Digest384,
        now: u64,
    ) -> Result<(), WalletError> {
        let s = self.session_mut(session)?;
        if s.state != OpenId4VpTransportStateV1::Review
            || s.request_commitment != request
            || user_presence == Digest384::ZERO
            || s.expires_at < now
        {
            return Err(WalletError::PolicyDenied);
        }
        s.state = OpenId4VpTransportStateV1::Approved;
        self.generation += 1;
        Ok(())
    }
    pub fn post(
        &mut self,
        response: &OpenId4VpBoundedResponseV1,
        now: u64,
    ) -> Result<(), WalletError> {
        let s = self.session_mut(response.session)?;
        if s.state != OpenId4VpTransportStateV1::Approved
            || s.expires_at < now
            || s.request_commitment != response.request_commitment
            || s.trust_status_commitment != response.trust_status_commitment
            || s.format != response.format
        {
            return Err(WalletError::PolicyDenied);
        }
        s.state = OpenId4VpTransportStateV1::Posted;
        self.generation += 1;
        Ok(())
    }
    pub fn consume_callback(
        &mut self,
        session: Digest384,
        request: Digest384,
        now: u64,
    ) -> Result<(), WalletError> {
        let index = self
            .sessions
            .binary_search_by_key(&session, |s| s.session)
            .map_err(|_| WalletError::UnknownSession)?;
        let s = self.sessions[index];
        if s.state != OpenId4VpTransportStateV1::Posted
            || s.request_commitment != request
            || s.expires_at < now
            || self.consumed_nonces.binary_search(&s.nonce).is_ok()
        {
            return Err(WalletError::Replay);
        }
        self.sessions[index].state = OpenId4VpTransportStateV1::Consumed;
        self.consumed_nonces.push(s.nonce);
        self.consumed_nonces.sort();
        self.generation += 1;
        Ok(())
    }
    fn session_mut(
        &mut self,
        id: Digest384,
    ) -> Result<&mut OpenId4VpTransportRequestV1, WalletError> {
        self.sessions
            .binary_search_by_key(&id, |s| s.session)
            .map(|i| &mut self.sessions[i])
            .map_err(|_| WalletError::UnknownSession)
    }
}
impl CanonicalEncode for OpenId4VpTransportSnapshotV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.generation.encode(e)?;
        e.write_length(self.sessions.len(), MAX_OPENID4VP_TRANSPORT_SESSIONS)?;
        for s in &self.sessions {
            s.encode(e)?;
        }
        e.write_length(self.consumed_nonces.len(), MAX_OPENID4VP_TRANSPORT_SESSIONS)?;
        for n in &self.consumed_nonces {
            n.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for OpenId4VpTransportSnapshotV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let generation = u64::decode(d)?;
        let count = d.read_length(MAX_OPENID4VP_TRANSPORT_SESSIONS)?;
        let mut sessions = Vec::with_capacity(count);
        for _ in 0..count {
            sessions.push(OpenId4VpTransportRequestV1::decode(d)?);
        }
        let count = d.read_length(MAX_OPENID4VP_TRANSPORT_SESSIONS)?;
        let mut consumed_nonces = Vec::with_capacity(count);
        for _ in 0..count {
            consumed_nonces.push(Digest384::decode(d)?);
        }
        if !sessions.windows(2).all(|p| p[0].session < p[1].session)
            || !consumed_nonces.windows(2).all(|p| p[0] < p[1])
        {
            return Err(DecodeError::InvalidValue("noncanonical OpenID4VP snapshot"));
        }
        Ok(Self { generation, sessions, consumed_nonces })
    }
}
impl CanonicalType for OpenId4VpTransportSnapshotV1 {
    const TYPE_TAG: u16 = 0x01A6;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 8
        + 1
        + MAX_OPENID4VP_TRANSPORT_SESSIONS * OpenId4VpTransportRequestV1::MAX_ENCODED_LEN
        + 1
        + MAX_OPENID4VP_TRANSPORT_SESSIONS * 48;
}

pub trait OpenId4VpLiveResolver {
    fn verifier_metadata(&self, verifier: PrincipalId) -> Option<PinnedVerifierMetadataV1>;
    fn trust_status(
        &self,
        issuer: Digest384,
        profile: Digest384,
    ) -> Option<LiveTrustStatusAnchorV1>;
}
#[allow(clippy::too_many_arguments)]
pub fn resolve_live_context(
    resolver: &impl OpenId4VpLiveResolver,
    verifier: PrincipalId,
    issuer: Digest384,
    profile: Digest384,
    expected_chain: ChainId,
    expected_genesis: Digest384,
    minimum_trust_revision: u64,
    minimum_status_sequence: u64,
    now: u64,
) -> Result<(PinnedVerifierMetadataV1, LiveTrustStatusAnchorV1), WalletError> {
    let metadata = resolver.verifier_metadata(verifier).ok_or(WalletError::PolicyDenied)?;
    let anchor = resolver.trust_status(issuer, profile).ok_or(WalletError::PolicyDenied)?;
    if metadata.valid_until < now
        || anchor.valid_until < now
        || !anchor.issuer_active
        || anchor.chain != expected_chain
        || anchor.chain_genesis != expected_genesis
        || anchor.issuer_binding != issuer
        || anchor.profile != profile
        || anchor.trust_revision < minimum_trust_revision
        || anchor.status_sequence < minimum_status_sequence
    {
        return Err(WalletError::PolicyDenied);
    }
    Ok((metadata, anchor))
}

#[allow(clippy::too_many_arguments)]
pub fn bind_openwallet_request(
    request: &OpenWalletPresentationRequestV1,
    metadata: &PinnedVerifierMetadataV1,
    anchor: &LiveTrustStatusAnchorV1,
    audience: PrincipalId,
    purpose: Digest384,
    policy_revision: u64,
    adapter_revision: u16,
    format: CredentialFormat,
) -> Result<OpenId4VpTransportRequestV1, WalletError> {
    OpenId4VpTransportRequestV1::new(
        request.session().session_id,
        request.commitment().map_err(|_| WalletError::MalformedAuthorization)?,
        metadata.metadata_commitment,
        anchor.commitment().map_err(|_| WalletError::MalformedAuthorization)?,
        audience,
        purpose,
        policy_revision,
        request.nonce(),
        request.session().expires_at,
        adapter_revision,
        format,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    fn d(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    fn p(n: u8) -> PrincipalId {
        PrincipalId::new(d(n))
    }
    fn req() -> OpenId4VpTransportRequestV1 {
        OpenId4VpTransportRequestV1::new(
            d(1),
            d(2),
            d(3),
            d(4),
            p(5),
            d(6),
            1,
            d(7),
            20,
            1,
            CredentialFormat::SdJwtVc,
        )
        .unwrap()
    }
    #[test]
    fn snapshot_is_crash_safe_and_callback_is_one_shot() {
        let mut s = OpenId4VpTransportSnapshotV1::default();
        s.begin(req(), 1).unwrap();
        s.approve(d(1), d(2), d(8), 2).unwrap();
        let response = OpenId4VpBoundedResponseV1::new(
            d(1),
            d(2),
            d(9),
            d(10),
            d(4),
            d(11),
            CredentialFormat::SdJwtVc,
        )
        .unwrap();
        s.post(&response, 3).unwrap();
        let bytes = encode_envelope(&s).unwrap();
        let mut restored = decode_envelope::<OpenId4VpTransportSnapshotV1>(&bytes).unwrap();
        restored.consume_callback(d(1), d(2), 4).unwrap();
        assert_eq!(restored.consume_callback(d(1), d(2), 4), Err(WalletError::Replay));
    }
    #[test]
    fn response_substitution_and_format_mixup_fail() {
        let mut s = OpenId4VpTransportSnapshotV1::default();
        s.begin(req(), 1).unwrap();
        s.approve(d(1), d(2), d(8), 2).unwrap();
        for response in [
            OpenId4VpBoundedResponseV1::new(
                d(1),
                d(99),
                d(9),
                d(10),
                d(4),
                d(11),
                CredentialFormat::SdJwtVc,
            )
            .unwrap(),
            OpenId4VpBoundedResponseV1::new(
                d(1),
                d(2),
                d(9),
                d(10),
                d(4),
                d(11),
                CredentialFormat::Mdoc,
            )
            .unwrap(),
        ] {
            assert_eq!(s.post(&response, 3), Err(WalletError::PolicyDenied));
        }
    }
    struct Resolver {
        metadata: PinnedVerifierMetadataV1,
        anchor: LiveTrustStatusAnchorV1,
    }
    impl OpenId4VpLiveResolver for Resolver {
        fn verifier_metadata(&self, _: PrincipalId) -> Option<PinnedVerifierMetadataV1> {
            Some(self.metadata)
        }
        fn trust_status(&self, _: Digest384, _: Digest384) -> Option<LiveTrustStatusAnchorV1> {
            Some(self.anchor)
        }
    }
    #[test]
    fn live_resolution_rejects_rollback_revocation_and_network_substitution() {
        let metadata = PinnedVerifierMetadataV1::new(p(1), d(2), d(3), d(4), 2, 30).unwrap();
        let anchor = LiveTrustStatusAnchorV1::new(
            ChainId::new(d(5)),
            d(6),
            d(7),
            d(8),
            d(9),
            d(10),
            3,
            4,
            10,
            30,
            true,
        )
        .unwrap();
        let resolver = Resolver { metadata, anchor };
        assert!(
            resolve_live_context(&resolver, p(1), d(7), d(8), ChainId::new(d(5)), d(6), 3, 4, 20)
                .is_ok()
        );
        assert!(
            resolve_live_context(&resolver, p(1), d(7), d(8), ChainId::new(d(5)), d(6), 4, 4, 20)
                .is_err()
        );
        let revoked = Resolver {
            metadata,
            anchor: LiveTrustStatusAnchorV1 { issuer_active: false, ..anchor },
        };
        assert!(
            resolve_live_context(&revoked, p(1), d(7), d(8), ChainId::new(d(5)), d(6), 3, 4, 20)
                .is_err()
        );
    }
    #[test]
    fn published_transport_corpus_has_closed_boundary() {
        let vector = include_str!("../../../testing/vectors/openid4vp-transport-v1.tsv");
        let mut accept = 0;
        let mut reject = 0;
        for line in vector.lines().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 3);
            match fields[1] {
                "accept" => accept += 1,
                "reject" => reject += 1,
                other => panic!("unknown {other}"),
            }
        }
        assert_eq!((accept, reject), (5, 16));
        for forbidden in ["raw_sd_jwt", "raw_mdoc", "x509_certificate"] {
            assert!(!vector.contains(forbidden));
        }
    }
}
