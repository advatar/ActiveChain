use crate::{
    AgentConnectionKind, AgentKeyProvenance, MAX_AGENT_CAPABILITIES, MAX_AGENT_LABEL, WalletError,
};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    encode_envelope,
};
use activechain_protocol_types::{
    AuthenticatorDescriptor, AuthenticatorPurpose, CapabilityId, ChainId, CryptoSuiteId, Digest384,
    PrincipalId, ProtocolSignature,
};
use alloc::vec::Vec;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa44, MlDsa65, Signature, Verifier, VerifyingKey,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

const REQUEST_SIGNING_DOMAIN: &[u8] = b"ACTIVECHAIN-AGENT-ENROLLMENT-REQUEST-ML-DSA-65-V1";
const GRANT_SIGNING_DOMAIN: &[u8] = b"ACTIVECHAIN-AGENT-ENROLLMENT-GRANT-ML-DSA-44-V1";
const REQUEST_COMMITMENT_DOMAIN: &[u8] = b"ACTIVECHAIN-AGENT-ENROLLMENT-REQUEST-ID-V1";

/// An agent-authenticated, bounded request for wallet authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentEnrollmentRequestV1 {
    chain_id: ChainId,
    wallet: PrincipalId,
    agent: PrincipalId,
    label: Vec<u8>,
    authenticator: AuthenticatorDescriptor,
    provenance: AgentKeyProvenance,
    connection: AgentConnectionKind,
    capabilities: Vec<CapabilityId>,
    budget_limit: u128,
    valid_from: u64,
    expires_at: u64,
    nonce: Digest384,
}

impl AgentEnrollmentRequestV1 {
    pub fn new(
        chain_id: ChainId,
        wallet: PrincipalId,
        agent: PrincipalId,
        label: Vec<u8>,
        authenticator: AuthenticatorDescriptor,
        provenance: AgentKeyProvenance,
        connection: AgentConnectionKind,
        capabilities: Vec<CapabilityId>,
        budget_limit: u128,
        valid_from: u64,
        expires_at: u64,
        nonce: Digest384,
    ) -> Result<Self, WalletError> {
        if chain_id.into_digest() == Digest384::ZERO
            || wallet.into_digest() == Digest384::ZERO
            || agent.into_digest() == Digest384::ZERO
            || label.is_empty()
            || label.len() > MAX_AGENT_LABEL
            || core::str::from_utf8(&label).is_err()
            || authenticator.authenticator_id().into_digest() == Digest384::ZERO
            || authenticator.scheme() != CryptoSuiteId::ML_DSA_65
            || authenticator.purpose() != AuthenticatorPurpose::Control
            || authenticator.revoked_at().is_some()
            || capabilities.is_empty()
            || capabilities.len() > MAX_AGENT_CAPABILITIES
            || capabilities.windows(2).any(|pair| pair[0] >= pair[1])
            || budget_limit == 0
            || valid_from == 0
            || valid_from > expires_at
            || authenticator.valid_from() > valid_from
            || authenticator.valid_until().is_some_and(|height| height < expires_at)
            || nonce == Digest384::ZERO
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self {
            chain_id,
            wallet,
            agent,
            label,
            authenticator,
            provenance,
            connection,
            capabilities,
            budget_limit,
            valid_from,
            expires_at,
            nonce,
        })
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn wallet(&self) -> PrincipalId {
        self.wallet
    }
    pub const fn agent(&self) -> PrincipalId {
        self.agent
    }
    pub fn label(&self) -> &[u8] {
        &self.label
    }
    pub const fn authenticator(&self) -> &AuthenticatorDescriptor {
        &self.authenticator
    }
    pub const fn provenance(&self) -> AgentKeyProvenance {
        self.provenance
    }
    pub const fn connection(&self) -> AgentConnectionKind {
        self.connection
    }
    pub fn capabilities(&self) -> &[CapabilityId] {
        &self.capabilities
    }
    pub const fn budget_limit(&self) -> u128 {
        self.budget_limit
    }
    pub const fn valid_from(&self) -> u64 {
        self.valid_from
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub const fn nonce(&self) -> Digest384 {
        self.nonce
    }

    pub fn signing_payload(&self) -> Result<Vec<u8>, EncodeError> {
        signing_payload(REQUEST_SIGNING_DOMAIN, self)
    }

    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let encoded = encode_envelope(self)?;
        let mut hash = Shake256::default();
        hash.update(REQUEST_COMMITMENT_DOMAIN);
        hash.update(&(encoded.len() as u64).to_be_bytes());
        hash.update(&encoded);
        let mut output = [0_u8; 48];
        hash.finalize_xof().read(&mut output);
        Ok(Digest384::new(output))
    }
}

impl CanonicalEncode for AgentEnrollmentRequestV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.wallet.encode(e)?;
        self.agent.encode(e)?;
        e.write_bytes(&self.label, MAX_AGENT_LABEL)?;
        self.authenticator.encode(e)?;
        self.provenance.encode(e)?;
        self.connection.encode(e)?;
        e.write_length(self.capabilities.len(), MAX_AGENT_CAPABILITIES)?;
        for capability in &self.capabilities {
            capability.encode(e)?;
        }
        self.budget_limit.encode(e)?;
        self.valid_from.encode(e)?;
        self.expires_at.encode(e)?;
        self.nonce.encode(e)
    }
}

impl CanonicalDecode for AgentEnrollmentRequestV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(d)?;
        let wallet = PrincipalId::decode(d)?;
        let agent = PrincipalId::decode(d)?;
        let label = d.read_bytes(MAX_AGENT_LABEL)?.to_vec();
        let authenticator = AuthenticatorDescriptor::decode(d)?;
        let provenance = AgentKeyProvenance::decode(d)?;
        let connection = AgentConnectionKind::decode(d)?;
        let count = d.read_length(MAX_AGENT_CAPABILITIES)?;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(CapabilityId::decode(d)?);
        }
        Self::new(
            chain_id,
            wallet,
            agent,
            label,
            authenticator,
            provenance,
            connection,
            capabilities,
            u128::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid agent enrollment request"))
    }
}

impl CanonicalType for AgentEnrollmentRequestV1 {
    const TYPE_TAG: u16 = 0x00d5;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 3
        + 3
        + MAX_AGENT_LABEL
        + AuthenticatorDescriptor::MAX_ENCODED_LEN
        + 1
        + 1
        + 1
        + MAX_AGENT_CAPABILITIES * 48
        + 16
        + 8
        + 8
        + 48;
}

/// A structurally valid request carrying proof of control of the proposed agent key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedAgentEnrollmentRequestV1 {
    request: AgentEnrollmentRequestV1,
    signature: ProtocolSignature,
}

impl AuthorizedAgentEnrollmentRequestV1 {
    pub fn new(
        request: AgentEnrollmentRequestV1,
        signature: ProtocolSignature,
    ) -> Result<Self, WalletError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_65 {
            return Err(WalletError::InvalidSignature);
        }
        Ok(Self { request, signature })
    }
    pub const fn request(&self) -> &AgentEnrollmentRequestV1 {
        &self.request
    }
    pub fn verify(
        &self,
        expected_chain: ChainId,
        expected_wallet: PrincipalId,
        current_height: u64,
    ) -> Result<(), WalletError> {
        if self.request.chain_id != expected_chain || self.request.wallet != expected_wallet {
            return Err(WalletError::PolicyDenied);
        }
        if current_height < self.request.valid_from || current_height > self.request.expires_at {
            return Err(WalletError::Expired);
        }
        let payload =
            self.request.signing_payload().map_err(|_| WalletError::MalformedAuthorization)?;
        verify_ml_dsa_65(self.request.authenticator.verification_key(), &self.signature, &payload)
    }
}

impl CanonicalEncode for AuthorizedAgentEnrollmentRequestV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.request.encode(e)?;
        self.signature.encode(e)
    }
}
impl CanonicalDecode for AuthorizedAgentEnrollmentRequestV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(AgentEnrollmentRequestV1::decode(d)?, ProtocolSignature::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid authorized agent enrollment request"))
    }
}
impl CanonicalType for AuthorizedAgentEnrollmentRequestV1 {
    const TYPE_TAG: u16 = 0x00d6;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        AgentEnrollmentRequestV1::MAX_ENCODED_LEN + ProtocolSignature::MAX_ENCODED_LEN;
}

/// The exact attenuated authority approved by a wallet for one authenticated request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentEnrollmentGrantV1 {
    chain_id: ChainId,
    wallet: PrincipalId,
    agent: PrincipalId,
    request_commitment: Digest384,
    capabilities: Vec<CapabilityId>,
    budget_limit: u128,
    expires_at: u64,
    requires_human_approval: bool,
}

impl AgentEnrollmentGrantV1 {
    pub fn attenuate(
        request: &AgentEnrollmentRequestV1,
        capabilities: Vec<CapabilityId>,
        budget_limit: u128,
        expires_at: u64,
        requires_human_approval: bool,
    ) -> Result<Self, WalletError> {
        if capabilities.is_empty()
            || capabilities.len() > MAX_AGENT_CAPABILITIES
            || capabilities.windows(2).any(|pair| pair[0] >= pair[1])
            || capabilities
                .iter()
                .any(|capability| request.capabilities.binary_search(capability).is_err())
            || budget_limit == 0
            || budget_limit > request.budget_limit
            || expires_at < request.valid_from
            || expires_at > request.expires_at
        {
            return Err(WalletError::PolicyDenied);
        }
        let request_commitment =
            request.commitment().map_err(|_| WalletError::MalformedAuthorization)?;
        Ok(Self {
            chain_id: request.chain_id,
            wallet: request.wallet,
            agent: request.agent,
            request_commitment,
            capabilities,
            budget_limit,
            expires_at,
            requires_human_approval,
        })
    }

    pub const fn request_commitment(&self) -> Digest384 {
        self.request_commitment
    }
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn wallet(&self) -> PrincipalId {
        self.wallet
    }
    pub const fn agent(&self) -> PrincipalId {
        self.agent
    }
    pub fn capabilities(&self) -> &[CapabilityId] {
        &self.capabilities
    }
    pub const fn budget_limit(&self) -> u128 {
        self.budget_limit
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub const fn requires_human_approval(&self) -> bool {
        self.requires_human_approval
    }
    pub fn validate_against(&self, request: &AgentEnrollmentRequestV1) -> Result<(), WalletError> {
        if self.chain_id != request.chain_id
            || self.wallet != request.wallet
            || self.agent != request.agent
            || self.request_commitment
                != request.commitment().map_err(|_| WalletError::MalformedAuthorization)?
            || self
                .capabilities
                .iter()
                .any(|capability| request.capabilities.binary_search(capability).is_err())
            || self.budget_limit > request.budget_limit
            || self.expires_at < request.valid_from
            || self.expires_at > request.expires_at
        {
            return Err(WalletError::PolicyDenied);
        }
        Ok(())
    }
    pub fn signing_payload(&self) -> Result<Vec<u8>, EncodeError> {
        signing_payload(GRANT_SIGNING_DOMAIN, self)
    }
}

impl CanonicalEncode for AgentEnrollmentGrantV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.wallet.encode(e)?;
        self.agent.encode(e)?;
        self.request_commitment.encode(e)?;
        e.write_length(self.capabilities.len(), MAX_AGENT_CAPABILITIES)?;
        for capability in &self.capabilities {
            capability.encode(e)?;
        }
        self.budget_limit.encode(e)?;
        self.expires_at.encode(e)?;
        self.requires_human_approval.encode(e)
    }
}
impl CanonicalDecode for AgentEnrollmentGrantV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(d)?;
        let wallet = PrincipalId::decode(d)?;
        let agent = PrincipalId::decode(d)?;
        let request_commitment = Digest384::decode(d)?;
        let count = d.read_length(MAX_AGENT_CAPABILITIES)?;
        if count == 0 {
            return Err(DecodeError::InvalidValue("empty agent enrollment grant"));
        }
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            let capability = CapabilityId::decode(d)?;
            if capabilities.last().is_some_and(|previous| *previous >= capability) {
                return Err(DecodeError::InvalidValue(
                    "agent enrollment grant capabilities are not strictly ordered",
                ));
            }
            capabilities.push(capability);
        }
        let budget_limit = u128::decode(d)?;
        let expires_at = u64::decode(d)?;
        let requires_human_approval = bool::decode(d)?;
        if chain_id.into_digest() == Digest384::ZERO
            || wallet.into_digest() == Digest384::ZERO
            || agent.into_digest() == Digest384::ZERO
            || request_commitment == Digest384::ZERO
            || budget_limit == 0
            || expires_at == 0
        {
            return Err(DecodeError::InvalidValue("invalid agent enrollment grant"));
        }
        Ok(Self {
            chain_id,
            wallet,
            agent,
            request_commitment,
            capabilities,
            budget_limit,
            expires_at,
            requires_human_approval,
        })
    }
}
impl CanonicalType for AgentEnrollmentGrantV1 {
    const TYPE_TAG: u16 = 0x00d7;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 4 + 1 + MAX_AGENT_CAPABILITIES * 48 + 16 + 8 + 1;
}

/// A wallet-authorized grant bound to the exact authenticated request commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedAgentEnrollmentGrantV1 {
    grant: AgentEnrollmentGrantV1,
    signature: ProtocolSignature,
}

impl AuthorizedAgentEnrollmentGrantV1 {
    pub fn new(
        grant: AgentEnrollmentGrantV1,
        signature: ProtocolSignature,
    ) -> Result<Self, WalletError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(WalletError::InvalidSignature);
        }
        Ok(Self { grant, signature })
    }
    pub const fn grant(&self) -> &AgentEnrollmentGrantV1 {
        &self.grant
    }
    pub fn verify(&self, wallet_public_key: &[u8]) -> Result<(), WalletError> {
        let payload =
            self.grant.signing_payload().map_err(|_| WalletError::MalformedAuthorization)?;
        verify_ml_dsa_44(wallet_public_key, &self.signature, &payload)
    }
}
impl CanonicalEncode for AuthorizedAgentEnrollmentGrantV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.grant.encode(e)?;
        self.signature.encode(e)
    }
}
impl CanonicalDecode for AuthorizedAgentEnrollmentGrantV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(AgentEnrollmentGrantV1::decode(d)?, ProtocolSignature::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid authorized agent enrollment grant"))
    }
}
impl CanonicalType for AuthorizedAgentEnrollmentGrantV1 {
    const TYPE_TAG: u16 = 0x00d8;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        AgentEnrollmentGrantV1::MAX_ENCODED_LEN + ProtocolSignature::MAX_ENCODED_LEN;
}

fn signing_payload<T: CanonicalType>(domain: &[u8], value: &T) -> Result<Vec<u8>, EncodeError> {
    let encoded = encode_envelope(value)?;
    let mut payload = Vec::with_capacity(domain.len() + 8 + encoded.len());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

fn verify_ml_dsa_65(
    public_key: &[u8],
    signature: &ProtocolSignature,
    payload: &[u8],
) -> Result<(), WalletError> {
    let key: EncodedVerifyingKey<MlDsa65> =
        public_key.try_into().map_err(|_| WalletError::InvalidAuthorizationKey)?;
    let signature: EncodedSignature<MlDsa65> =
        signature.as_bytes().try_into().map_err(|_| WalletError::InvalidSignature)?;
    let key = VerifyingKey::<MlDsa65>::decode(&key);
    let signature =
        Signature::<MlDsa65>::decode(&signature).ok_or(WalletError::InvalidSignature)?;
    key.verify(payload, &signature).map_err(|_| WalletError::InvalidSignature)
}

fn verify_ml_dsa_44(
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

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use activechain_protocol_types::{AuthenticatorId, Height};
    use ml_dsa::{Keypair, Seed, SigningKey, signature::Signer};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn request(
        key: &SigningKey<MlDsa65>,
        capabilities: Vec<CapabilityId>,
    ) -> AgentEnrollmentRequestV1 {
        let descriptor = AuthenticatorDescriptor::new(
            AuthenticatorId::new(digest(4)),
            CryptoSuiteId::ML_DSA_65,
            key.verifying_key().encode().to_vec(),
            AuthenticatorPurpose::Control,
            10 as Height,
            Some(100),
            None,
        )
        .unwrap();
        AgentEnrollmentRequestV1::new(
            ChainId::new(digest(1)),
            PrincipalId::new(digest(2)),
            PrincipalId::new(digest(3)),
            b"Invoice assistant".to_vec(),
            descriptor,
            AgentKeyProvenance::PlatformHardware,
            AgentConnectionKind::ThirdPartyProtocol,
            capabilities,
            1_000,
            10,
            100,
            digest(9),
        )
        .unwrap()
    }

    #[test]
    fn authenticated_request_and_attenuated_grant_verify() {
        let agent_key = SigningKey::<MlDsa65>::from_seed(&Seed::from([7; 32]));
        let wallet_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([8; 32]));
        let requested = vec![CapabilityId::new(digest(10)), CapabilityId::new(digest(11))];
        let request = request(&agent_key, requested.clone());
        assert_eq!(
            request.commitment().unwrap(),
            Digest384::new([
                205, 230, 138, 250, 22, 31, 76, 114, 33, 191, 106, 248, 191, 92, 202, 130, 145, 60,
                137, 197, 70, 203, 157, 250, 236, 119, 47, 24, 90, 5, 235, 3, 33, 84, 205, 26, 251,
                240, 54, 66, 226, 243, 103, 104, 219, 116, 102, 6,
            ])
        );
        let signature = ProtocolSignature::new(
            CryptoSuiteId::ML_DSA_65,
            agent_key.sign(&request.signing_payload().unwrap()).encode().to_vec(),
        )
        .unwrap();
        let authorized =
            AuthorizedAgentEnrollmentRequestV1::new(request.clone(), signature).unwrap();
        authorized.verify(ChainId::new(digest(1)), PrincipalId::new(digest(2)), 10).unwrap();
        assert_eq!(
            decode_envelope::<AuthorizedAgentEnrollmentRequestV1>(
                &encode_envelope(&authorized).unwrap()
            ),
            Ok(authorized)
        );

        let grant =
            AgentEnrollmentGrantV1::attenuate(&request, vec![requested[0]], 100, 80, true).unwrap();
        grant.validate_against(&request).unwrap();
        let signature = ProtocolSignature::new(
            CryptoSuiteId::ML_DSA_44,
            wallet_key.sign(&grant.signing_payload().unwrap()).encode().to_vec(),
        )
        .unwrap();
        let authorized_grant = AuthorizedAgentEnrollmentGrantV1::new(grant, signature).unwrap();
        authorized_grant.verify(&wallet_key.verifying_key().encode()).unwrap();
    }

    #[test]
    fn amplification_substitution_and_malformed_vectors_fail_closed() {
        let agent_key = SigningKey::<MlDsa65>::from_seed(&Seed::from([7; 32]));
        let impostor = SigningKey::<MlDsa65>::from_seed(&Seed::from([9; 32]));
        let requested = vec![CapabilityId::new(digest(10)), CapabilityId::new(digest(11))];
        let request = request(&agent_key, requested.clone());
        assert_eq!(
            AgentEnrollmentGrantV1::attenuate(
                &request,
                vec![CapabilityId::new(digest(12))],
                100,
                80,
                true,
            ),
            Err(WalletError::PolicyDenied)
        );
        assert_eq!(
            AgentEnrollmentGrantV1::attenuate(&request, requested, 1_001, 80, true),
            Err(WalletError::PolicyDenied)
        );
        let wrong_signature = ProtocolSignature::new(
            CryptoSuiteId::ML_DSA_65,
            impostor.sign(&request.signing_payload().unwrap()).encode().to_vec(),
        )
        .unwrap();
        assert_eq!(
            AuthorizedAgentEnrollmentRequestV1::new(request.clone(), wrong_signature)
                .unwrap()
                .verify(ChainId::new(digest(1)), PrincipalId::new(digest(2)), 10),
            Err(WalletError::InvalidSignature)
        );
        let valid_signature = ProtocolSignature::new(
            CryptoSuiteId::ML_DSA_65,
            agent_key.sign(&request.signing_payload().unwrap()).encode().to_vec(),
        )
        .unwrap();
        let authorized =
            AuthorizedAgentEnrollmentRequestV1::new(request.clone(), valid_signature).unwrap();
        assert_eq!(
            authorized.verify(ChainId::new(digest(99)), PrincipalId::new(digest(2)), 10),
            Err(WalletError::PolicyDenied)
        );
        assert_eq!(
            authorized.verify(ChainId::new(digest(1)), PrincipalId::new(digest(2)), 101),
            Err(WalletError::Expired)
        );
        let mut trailing = encode_envelope(&request).unwrap();
        trailing.push(0);
        assert!(decode_envelope::<AgentEnrollmentRequestV1>(&trailing).is_err());
    }
}
