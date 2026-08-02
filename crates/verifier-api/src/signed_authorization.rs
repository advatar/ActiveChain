use crate::{
    AuthorizationChain, MAX_ENVELOPE_LENGTH, VERIFY_OK, VerifyError, verify_authorization_chain,
    verify_finality_bundle_with_chain_genesis, verify_finalized_principal_authenticator,
};
use activechain_accumulator::{KEY_BITS, NonMembershipWitness};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope, inspect_canonical_envelope,
};
use activechain_finality_types::commit_parts;
use activechain_policy_kernel::{ApprovalFact, MAX_APPROVAL_FACTS};
use activechain_protocol_types::{
    AuthenticatorDescriptor, AuthenticatorId, AuthenticatorPurpose, AuthenticatorSetV1,
    CapabilityId, CapabilityRevocationRegistryV1, CredentialId, CryptoSuiteId, Digest384,
    FreezeState, Object, PrincipalId, ProtocolSignature,
};
use alloc::{vec, vec::Vec};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, Signature, Verifier,
    VerifyingKey,
};

const MAX_AUTHORIZATION_ENVELOPE_LEN: usize = 8_192;
const MAX_CONTROLLER_WITNESSES: usize = 17;
const MAX_OBJECT_ENVELOPE_LEN: usize = 16_864;
const MAX_STATE_PROOF_ENVELOPE_LEN: usize = 69_369;
const MAX_AUTHENTICATOR_SET_ENVELOPE_LEN: usize = 33_440;
const MAX_AUTHORIZATION_CREDENTIALS: usize = 16;
const MAX_CAPABILITY_DEPTH: usize = 16;
const CAPABILITY_REVOCATION_OBJECT_TYPE_DOMAIN: &[u8] =
    b"ACTIVECHAIN-CAPABILITY-REVOCATION-OBJECT-TYPE-V1";
const CAPABILITY_REVOCATION_OBJECT_VALUE_DOMAIN: &[u8] =
    b"ACTIVECHAIN-CAPABILITY-REVOCATION-OBJECT-VALUE-V1";

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizationEnvelopeView {
    invocation_id: Digest384,
    chain_genesis_commitment: Digest384,
    epoch: u64,
    actor: PrincipalId,
    height: u64,
    timestamp: u64,
    finalized_state_root: Digest384,
    transition_commitment: Digest384,
    value: u128,
    compute: u128,
    freeze_state: FreezeState,
    declared_purpose: Option<Digest384>,
    approvals: Vec<ApprovalFact>,
    credential_ids: Vec<CredentialId>,
    capability_ids: Vec<CapabilityId>,
    actor_signature: ProtocolSignature,
}

impl AuthorizationEnvelopeView {
    fn signing_payload(&self) -> Result<Vec<u8>, EncodeError> {
        let mut unsigned = self.clone();
        unsigned.actor_signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420])
            .map_err(|_| EncodeError::LengthOverflow)?;
        let mut payload = b"ACTIVECHAIN-AUTHORIZATION-ENVELOPE-V1".to_vec();
        payload.extend_from_slice(&unsigned.encode_envelope()?);
        Ok(payload)
    }

    fn encode_envelope(&self) -> Result<Vec<u8>, EncodeError> {
        let mut body = Encoder::new(MAX_AUTHORIZATION_ENVELOPE_LEN);
        self.encode(&mut body)?;
        let body = body.finish();
        let mut envelope = Encoder::new(MAX_AUTHORIZATION_ENVELOPE_LEN + 9);
        envelope.write_u16(0x007d)?;
        envelope.write_u16(2)?;
        envelope.write_length(body.len(), MAX_AUTHORIZATION_ENVELOPE_LEN)?;
        envelope.write_raw(&body)?;
        Ok(envelope.finish())
    }
}

impl CanonicalEncode for AuthorizationEnvelopeView {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.invocation_id.encode(encoder)?;
        self.chain_genesis_commitment.encode(encoder)?;
        self.epoch.encode(encoder)?;
        self.actor.encode(encoder)?;
        self.height.encode(encoder)?;
        self.timestamp.encode(encoder)?;
        self.finalized_state_root.encode(encoder)?;
        self.transition_commitment.encode(encoder)?;
        self.value.encode(encoder)?;
        self.compute.encode(encoder)?;
        self.freeze_state.encode(encoder)?;
        self.declared_purpose.encode(encoder)?;
        encoder.write_length(self.approvals.len(), MAX_APPROVAL_FACTS)?;
        for approval in &self.approvals {
            approval.encode(encoder)?;
        }
        encoder.write_length(self.credential_ids.len(), MAX_AUTHORIZATION_CREDENTIALS)?;
        for credential in &self.credential_ids {
            credential.encode(encoder)?;
        }
        encoder.write_length(self.capability_ids.len(), MAX_CAPABILITY_DEPTH)?;
        for capability in &self.capability_ids {
            capability.encode(encoder)?;
        }
        self.actor_signature.encode(encoder)
    }
}

impl CanonicalDecode for AuthorizationEnvelopeView {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            invocation_id: Digest384::decode(decoder)?,
            chain_genesis_commitment: Digest384::decode(decoder)?,
            epoch: u64::decode(decoder)?,
            actor: PrincipalId::decode(decoder)?,
            height: u64::decode(decoder)?,
            timestamp: u64::decode(decoder)?,
            finalized_state_root: Digest384::decode(decoder)?,
            transition_commitment: Digest384::decode(decoder)?,
            value: u128::decode(decoder)?,
            compute: u128::decode(decoder)?,
            freeze_state: FreezeState::decode(decoder)?,
            declared_purpose: Option::<Digest384>::decode(decoder)?,
            approvals: decode_vec(decoder, MAX_APPROVAL_FACTS)?,
            credential_ids: decode_vec(decoder, MAX_AUTHORIZATION_CREDENTIALS)?,
            capability_ids: decode_vec(decoder, MAX_CAPABILITY_DEPTH)?,
            actor_signature: ProtocolSignature::decode(decoder)?,
        };
        if value.invocation_id == Digest384::ZERO
            || value.chain_genesis_commitment == Digest384::ZERO
            || value.finalized_state_root == Digest384::ZERO
            || value.transition_commitment == Digest384::ZERO
            || value.actor_signature.suite() != CryptoSuiteId::ML_DSA_44
            || value.capability_ids.is_empty()
            || value.credential_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || value.capability_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || value.approvals.windows(2).any(|pair| pair[0].role() >= pair[1].role())
        {
            return Err(DecodeError::InvalidValue("invalid authorization envelope"));
        }
        Ok(value)
    }
}

fn decode_vec<T: CanonicalDecode>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<Vec<T>, DecodeError> {
    let count = decoder.read_length(maximum)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(T::decode(decoder)?);
    }
    Ok(values)
}

/// Finalized state evidence for one actor or capability issuer controller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationControllerWitnessV1 {
    principal_object: Vec<u8>,
    principal_proof: Vec<u8>,
    authenticator_set: Vec<u8>,
    authenticator_id: AuthenticatorId,
}

impl AuthorizationControllerWitnessV1 {
    pub fn new(
        principal_object: Vec<u8>,
        principal_proof: Vec<u8>,
        authenticator_set: Vec<u8>,
        authenticator_id: AuthenticatorId,
    ) -> Result<Self, DecodeError> {
        if principal_object.len() > MAX_OBJECT_ENVELOPE_LEN
            || principal_proof.len() > MAX_STATE_PROOF_ENVELOPE_LEN
            || authenticator_set.len() > MAX_AUTHENTICATOR_SET_ENVELOPE_LEN
        {
            return Err(DecodeError::LengthLimitExceeded {
                length: principal_object
                    .len()
                    .max(principal_proof.len())
                    .max(authenticator_set.len()),
                maximum: MAX_ENVELOPE_LENGTH,
            });
        }
        Ok(Self { principal_object, principal_proof, authenticator_set, authenticator_id })
    }
}

impl CanonicalEncode for AuthorizationControllerWitnessV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_bytes(&self.principal_object, MAX_OBJECT_ENVELOPE_LEN)?;
        encoder.write_bytes(&self.principal_proof, MAX_STATE_PROOF_ENVELOPE_LEN)?;
        encoder.write_bytes(&self.authenticator_set, MAX_AUTHENTICATOR_SET_ENVELOPE_LEN)?;
        self.authenticator_id.encode(encoder)
    }
}

impl CanonicalDecode for AuthorizationControllerWitnessV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            decoder.read_bytes(MAX_OBJECT_ENVELOPE_LEN)?.to_vec(),
            decoder.read_bytes(MAX_STATE_PROOF_ENVELOPE_LEN)?.to_vec(),
            decoder.read_bytes(MAX_AUTHENTICATOR_SET_ENVELOPE_LEN)?.to_vec(),
            AuthenticatorId::decode(decoder)?,
        )
    }
}

/// Sparse non-revocation path for one capability in the finalized registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityNonRevocationProofV1 {
    capability_id: CapabilityId,
    siblings: Vec<Digest384>,
}

impl CapabilityNonRevocationProofV1 {
    pub fn new(capability_id: CapabilityId, siblings: Vec<Digest384>) -> Result<Self, DecodeError> {
        if siblings.len() != KEY_BITS {
            return Err(DecodeError::InvalidValue("capability non-revocation path length"));
        }
        Ok(Self { capability_id, siblings })
    }
}

impl CanonicalEncode for CapabilityNonRevocationProofV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.capability_id.encode(encoder)?;
        for sibling in &self.siblings {
            sibling.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for CapabilityNonRevocationProofV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let capability_id = CapabilityId::decode(decoder)?;
        let mut siblings = Vec::with_capacity(KEY_BITS);
        for _ in 0..KEY_BITS {
            siblings.push(Digest384::decode(decoder)?);
        }
        Self::new(capability_id, siblings)
    }
}

/// Finalized registry object and all non-revocation paths required by one linear chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRevocationWitnessV1 {
    registry_object: Vec<u8>,
    registry_proof: Vec<u8>,
    capabilities: Vec<CapabilityNonRevocationProofV1>,
}

impl CapabilityRevocationWitnessV1 {
    pub fn new(
        registry_object: Vec<u8>,
        registry_proof: Vec<u8>,
        capabilities: Vec<CapabilityNonRevocationProofV1>,
    ) -> Result<Self, DecodeError> {
        if registry_object.len() > MAX_OBJECT_ENVELOPE_LEN
            || registry_proof.len() > MAX_STATE_PROOF_ENVELOPE_LEN
            || capabilities.is_empty()
            || capabilities.len() > MAX_CAPABILITY_DEPTH
            || capabilities.windows(2).any(|pair| pair[0].capability_id >= pair[1].capability_id)
        {
            return Err(DecodeError::InvalidValue("invalid capability revocation witness"));
        }
        Ok(Self { registry_object, registry_proof, capabilities })
    }
}

impl CanonicalEncode for CapabilityRevocationWitnessV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_bytes(&self.registry_object, MAX_OBJECT_ENVELOPE_LEN)?;
        encoder.write_bytes(&self.registry_proof, MAX_STATE_PROOF_ENVELOPE_LEN)?;
        encoder.write_length(self.capabilities.len(), MAX_CAPABILITY_DEPTH)?;
        for capability in &self.capabilities {
            capability.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for CapabilityRevocationWitnessV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            decoder.read_bytes(MAX_OBJECT_ENVELOPE_LEN)?.to_vec(),
            decoder.read_bytes(MAX_STATE_PROOF_ENVELOPE_LEN)?.to_vec(),
            decode_vec(decoder, MAX_CAPABILITY_DEPTH)?,
        )
    }
}

/// Actor envelope, capability chain, and ordered finalized controller evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAuthorizationChainV1 {
    authorization_envelope: Vec<u8>,
    chain: AuthorizationChain,
    controllers: Vec<AuthorizationControllerWitnessV1>,
    revocation: Option<CapabilityRevocationWitnessV1>,
}

impl SignedAuthorizationChainV1 {
    pub const TYPE_TAG: u16 = 0x01a9;
    pub const SCHEMA_VERSION: u16 = 3;
    pub const MAX_ENCODED_LEN: usize = MAX_AUTHORIZATION_ENVELOPE_LEN
        + AuthorizationChain::MAX_ENCODED_LEN
        + 1
        + MAX_CONTROLLER_WITNESSES
            * (MAX_OBJECT_ENVELOPE_LEN
                + MAX_STATE_PROOF_ENVELOPE_LEN
                + MAX_AUTHENTICATOR_SET_ENVELOPE_LEN
                + 48
                + 15)
        + 8
        + MAX_OBJECT_ENVELOPE_LEN
        + MAX_STATE_PROOF_ENVELOPE_LEN
        + MAX_CAPABILITY_DEPTH * (48 + KEY_BITS * 48);

    pub fn new(
        authorization_envelope: Vec<u8>,
        chain: AuthorizationChain,
        controllers: Vec<AuthorizationControllerWitnessV1>,
        revocation: Option<CapabilityRevocationWitnessV1>,
    ) -> Result<Self, DecodeError> {
        if authorization_envelope.len() > MAX_AUTHORIZATION_ENVELOPE_LEN
            || controllers.len() != chain.capabilities().len() + 1
            || controllers.len() > MAX_CONTROLLER_WITNESSES
        {
            return Err(DecodeError::InvalidValue(
                "signed authorization controller count mismatch",
            ));
        }
        Ok(Self { authorization_envelope, chain, controllers, revocation })
    }
}

impl CanonicalEncode for SignedAuthorizationChainV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_bytes(&self.authorization_envelope, MAX_AUTHORIZATION_ENVELOPE_LEN)?;
        self.chain.encode(encoder)?;
        encoder.write_length(self.controllers.len(), MAX_CONTROLLER_WITNESSES)?;
        for controller in &self.controllers {
            controller.encode(encoder)?;
        }
        self.revocation.encode(encoder)
    }
}

impl CanonicalDecode for SignedAuthorizationChainV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let envelope = decoder.read_bytes(MAX_AUTHORIZATION_ENVELOPE_LEN)?.to_vec();
        let chain = AuthorizationChain::decode(decoder)?;
        let controllers = decode_vec(decoder, MAX_CONTROLLER_WITNESSES)?;
        let revocation = Option::<CapabilityRevocationWitnessV1>::decode(decoder)?;
        Self::new(envelope, chain, controllers, revocation)
    }
}

impl CanonicalType for SignedAuthorizationChainV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

pub fn verify_signed_authorization_chain_code(
    bytes: &[u8],
    finality: &[u8],
    trusted_genesis: Digest384,
) -> u32 {
    verify_signed_authorization_chain(bytes, finality, trusted_genesis)
        .map_or_else(|error| error.code(), |()| VERIFY_OK)
}

pub fn verify_signed_authorization_chain(
    bytes: &[u8],
    finality: &[u8],
    trusted_genesis: Digest384,
) -> Result<(), VerifyError> {
    if bytes.len().checked_add(finality.len()).is_none_or(|length| length > MAX_ENVELOPE_LENGTH) {
        return Err(VerifyError::TooLarge);
    }
    let signed =
        decode_envelope::<SignedAuthorizationChainV1>(bytes).map_err(VerifyError::Decode)?;
    let chain_bytes = encode_envelope(&signed.chain).map_err(|_| VerifyError::RelationMismatch)?;
    verify_authorization_chain(&chain_bytes)?;
    let envelope = decode_authorization_envelope(&signed.authorization_envelope)
        .map_err(VerifyError::Decode)?;
    let finality_bundle = verify_finality_bundle_with_chain_genesis(finality, trusted_genesis)?;
    let inputs = finality_bundle.header().inputs;
    // Envelopes carry capability ids in strictly ascending canonical order, while the chain
    // carries them in delegation order. Compare on the canonical order the envelope uses, as
    // the authorization kernel does, so a correct chain whose delegation order is not already
    // ascending remains representable.
    let mut ids = signed
        .chain
        .capabilities()
        .iter()
        .map(|capability| capability.fields().capability_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    if envelope.actor != signed.chain.actor()
        || envelope.height != signed.chain.height()
        || envelope.height != inputs.height
        || envelope.epoch != inputs.epoch
        || envelope.finalized_state_root != inputs.post_state.root()
        || envelope.chain_genesis_commitment != trusted_genesis
        || envelope.freeze_state != FreezeState::Active
        || envelope.capability_ids != ids
    {
        return Err(VerifyError::RelationMismatch);
    }

    verify_capability_revocations(&signed, &finality_bundle)?;

    let actor = &signed.controllers[0];
    let actor_key = verify_controller(
        actor,
        &envelope.actor,
        AuthenticatorPurpose::Session,
        finality,
        trusted_genesis,
    )?;
    if !verify_signature(
        actor_key,
        envelope.actor_signature(),
        &envelope.signing_payload().map_err(|_| VerifyError::RelationMismatch)?,
    ) {
        return Err(VerifyError::RelationMismatch);
    }
    for (capability, controller) in signed.chain.capabilities().iter().zip(&signed.controllers[1..])
    {
        let issuer = capability.fields().issuer;
        let key = verify_controller(
            controller,
            &issuer,
            AuthenticatorPurpose::Control,
            finality,
            trusted_genesis,
        )?;
        if !verify_signature(
            key,
            capability.issuer_signature(),
            &capability
                .signing_payload(trusted_genesis)
                .map_err(|_| VerifyError::RelationMismatch)?,
        ) {
            return Err(VerifyError::RelationMismatch);
        }
    }
    Ok(())
}

fn verify_capability_revocations(
    signed: &SignedAuthorizationChainV1,
    finality: &activechain_finality_types::FinalityCertificateBundle,
) -> Result<(), VerifyError> {
    let mut registry = None;
    let mut capability_ids = Vec::new();
    for capability in signed.chain.capabilities() {
        let Some(candidate) = capability.fields().revocation_registry else { continue };
        if registry.is_some_and(|expected| expected != candidate) {
            return Err(VerifyError::RelationMismatch);
        }
        registry = Some(candidate);
        capability_ids.push(capability.fields().capability_id);
    }
    capability_ids.sort_unstable();
    let Some(registry_id) = registry else {
        return if signed.revocation.is_none() {
            Ok(())
        } else {
            Err(VerifyError::RelationMismatch)
        };
    };
    let witness = signed.revocation.as_ref().ok_or(VerifyError::RelationMismatch)?;
    let proof_ids =
        witness.capabilities.iter().map(|proof| proof.capability_id).collect::<Vec<_>>();
    if proof_ids != capability_ids {
        return Err(VerifyError::RelationMismatch);
    }
    let object =
        decode_envelope::<Object>(&witness.registry_object).map_err(VerifyError::Decode)?;
    let public_value = object.public_value().ok_or(VerifyError::RelationMismatch)?;
    let registry_value = decode_envelope::<CapabilityRevocationRegistryV1>(public_value)
        .map_err(VerifyError::Decode)?;
    let expected_type = commit_parts(
        CAPABILITY_REVOCATION_OBJECT_TYPE_DOMAIN,
        &[
            &CapabilityRevocationRegistryV1::TYPE_TAG.to_be_bytes(),
            &CapabilityRevocationRegistryV1::SCHEMA_VERSION.to_be_bytes(),
        ],
    );
    if object.object_id() != registry_id
        || object.type_id() != expected_type
        || object.value_root()
            != commit_parts(CAPABILITY_REVOCATION_OBJECT_VALUE_DOMAIN, &[public_value])
    {
        return Err(VerifyError::CommitmentMismatch);
    }
    let state = encode_envelope(&finality.header().inputs.post_state)
        .map_err(|_| VerifyError::RelationMismatch)?;
    crate::verify_state_membership(&state, &witness.registry_object, &witness.registry_proof)?;
    for proof in &witness.capabilities {
        let witness = NonMembershipWitness {
            key: proof.capability_id.into_digest().into_bytes(),
            siblings: proof.siblings.iter().map(|sibling| sibling.into_bytes()).collect(),
        };
        registry_value
            .verify_not_revoked(proof.capability_id, &witness)
            .map_err(|_| VerifyError::RelationMismatch)?;
    }
    Ok(())
}

fn decode_authorization_envelope(bytes: &[u8]) -> Result<AuthorizationEnvelopeView, DecodeError> {
    let envelope = inspect_canonical_envelope(bytes, 0x007d, 2, MAX_AUTHORIZATION_ENVELOPE_LEN)?;
    let mut decoder = Decoder::new(envelope.body());
    let value = AuthorizationEnvelopeView::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(value)
}

impl AuthorizationEnvelopeView {
    fn actor_signature(&self) -> &ProtocolSignature {
        &self.actor_signature
    }
}

fn verify_controller(
    witness: &AuthorizationControllerWitnessV1,
    principal: &PrincipalId,
    purpose: AuthenticatorPurpose,
    finality: &[u8],
    trusted_genesis: Digest384,
) -> Result<AuthenticatorDescriptor, VerifyError> {
    verify_finalized_principal_authenticator(
        &witness.principal_object,
        &witness.principal_proof,
        &witness.authenticator_set,
        finality,
        trusted_genesis,
        *principal,
        witness.authenticator_id,
        purpose,
    )?;
    let set = decode_envelope::<AuthenticatorSetV1>(&witness.authenticator_set)
        .map_err(VerifyError::Decode)?;
    set.authenticator(witness.authenticator_id).cloned().ok_or(VerifyError::RelationMismatch)
}

pub(super) fn verify_signature(
    authenticator: AuthenticatorDescriptor,
    signature: &ProtocolSignature,
    payload: &[u8],
) -> bool {
    if authenticator.scheme() != signature.suite() {
        return false;
    }
    match signature.suite() {
        CryptoSuiteId::ML_DSA_44 => {
            let Ok(key): Result<EncodedVerifyingKey<MlDsa44>, _> =
                authenticator.verification_key().try_into()
            else {
                return false;
            };
            let Ok(signature): Result<EncodedSignature<MlDsa44>, _> =
                signature.as_bytes().try_into()
            else {
                return false;
            };
            let key = VerifyingKey::<MlDsa44>::decode(&key);
            Signature::<MlDsa44>::decode(&signature)
                .is_some_and(|signature| key.verify(payload, &signature).is_ok())
        }
        CryptoSuiteId::ML_DSA_65 => {
            let Ok(key): Result<EncodedVerifyingKey<MlDsa65>, _> =
                authenticator.verification_key().try_into()
            else {
                return false;
            };
            let Ok(signature): Result<EncodedSignature<MlDsa65>, _> =
                signature.as_bytes().try_into()
            else {
                return false;
            };
            let key = VerifyingKey::<MlDsa65>::decode(&key);
            Signature::<MlDsa65>::decode(&signature)
                .is_some_and(|signature| key.verify(payload, &signature).is_ok())
        }
        CryptoSuiteId::ML_DSA_87 => {
            let Ok(key): Result<EncodedVerifyingKey<MlDsa87>, _> =
                authenticator.verification_key().try_into()
            else {
                return false;
            };
            let Ok(signature): Result<EncodedSignature<MlDsa87>, _> =
                signature.as_bytes().try_into()
            else {
                return false;
            };
            let key = VerifyingKey::<MlDsa87>::decode(&key);
            Signature::<MlDsa87>::decode(&signature)
                .is_some_and(|signature| key.verify(payload, &signature).is_ok())
        }
        _ => false,
    }
}
