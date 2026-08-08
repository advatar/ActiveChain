#![forbid(unsafe_code)]
//! Cryptographic provider boundary for authoritative PQ verification.

extern crate alloc;

use activechain_protocol_types::{
    BlockProposal, CryptoSuiteId, DidControllerOperationV1, DidControllerRecordV1, DidDocumentV1,
    DidOperationAuthorizationV1, MAX_VALIDATORS_PER_EPOCH, ML_DSA44_PUBLIC_KEY_LENGTH, PrincipalId,
    QuorumCertificate, ValidatorGenesis, ValidatorSet, ValidatorVote, ViewChangeCertificate,
};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, Signature, Verifier,
    VerifyingKey,
};
use ml_kem::{
    DecapsulationKey, EncapsulationKey, MlKem768, Seed as KemSeed,
    kem::{Encapsulate, KeyExport, TryDecapsulate},
    ml_kem_768::Ciphertext,
};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use slh_dsa::{
    Shake192s, Signature as SlhSignature, VerifyingKey as SlhVerifyingKey,
    signature::Verifier as SlhVerifier,
};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_PROTECTED_PAYLOAD: usize = 64 * 1024;
pub const AEAD_TAG_LENGTH: usize = 16;
const PROTECTED_ENVELOPE_MAGIC: &[u8; 5] = b"ACPE2";
const PROTECTED_KEY_DOMAIN: &[u8] = b"ACTIVECHAIN-MLKEM-AEAD-KEY-V2";
const PROTECTED_NONCE_DOMAIN: &[u8] = b"ACTIVECHAIN-MLKEM-AEAD-NONCE-V2";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedEnvelope {
    ciphertext: Vec<u8>,
    encrypted_payload: Vec<u8>,
}
impl ProtectedEnvelope {
    pub fn seal(
        public_key: &[u8],
        payload: &[u8],
        associated_data: &[u8],
    ) -> Result<Self, KemError> {
        if payload.len() > MAX_PROTECTED_PAYLOAD {
            return Err(KemError::PayloadTooLarge);
        }
        let (ciphertext, mut shared) = ml_kem768_encapsulate(public_key)?;
        let key = Zeroizing::new(protected_key(&shared, &ciphertext, associated_data));
        shared.zeroize();
        let nonce = protected_nonce(&ciphertext, associated_data);
        let encrypted_payload = aead_seal(&key, nonce, associated_data, payload)?;
        Ok(Self { ciphertext, encrypted_payload })
    }
    pub fn open(
        &self,
        recipient: &MlKem768Recipient,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, KemError> {
        let mut shared = recipient.decapsulate(&self.ciphertext)?;
        let key = Zeroizing::new(protected_key(&shared, &self.ciphertext, associated_data));
        shared.zeroize();
        let nonce = protected_nonce(&self.ciphertext, associated_data);
        aead_open(&key, nonce, associated_data, &self.encrypted_payload)
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn encrypted_payload(&self) -> &[u8] {
        &self.encrypted_payload
    }
    pub fn encode(&self) -> Result<Vec<u8>, KemError> {
        if self.ciphertext.len() > u32::MAX as usize
            || self.encrypted_payload.len() > MAX_PROTECTED_PAYLOAD + AEAD_TAG_LENGTH
        {
            return Err(KemError::PayloadTooLarge);
        }
        let mut bytes =
            Vec::with_capacity(13 + self.ciphertext.len() + self.encrypted_payload.len());
        bytes.extend_from_slice(PROTECTED_ENVELOPE_MAGIC);
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(self.encrypted_payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&self.encrypted_payload);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, KemError> {
        if bytes.len() < 13 + AEAD_TAG_LENGTH || &bytes[..5] != PROTECTED_ENVELOPE_MAGIC {
            return Err(KemError::InvalidEnvelope);
        }
        let ciphertext_len =
            u32::from_be_bytes(bytes[5..9].try_into().map_err(|_| KemError::InvalidEnvelope)?)
                as usize;
        let payload_len =
            u32::from_be_bytes(bytes[9..13].try_into().map_err(|_| KemError::InvalidEnvelope)?)
                as usize;
        if !(AEAD_TAG_LENGTH..=MAX_PROTECTED_PAYLOAD + AEAD_TAG_LENGTH).contains(&payload_len)
            || bytes.len() != 13 + ciphertext_len + payload_len
        {
            return Err(KemError::InvalidEnvelope);
        }
        let payload_start = 13 + ciphertext_len;
        Ok(Self {
            ciphertext: bytes[13..payload_start].to_vec(),
            encrypted_payload: bytes[payload_start..].to_vec(),
        })
    }
}

fn protected_key(shared: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(PROTECTED_KEY_DOMAIN);
    hasher.update(shared);
    hasher.update(&(ciphertext.len() as u32).to_be_bytes());
    hasher.update(ciphertext);
    hasher.update(&(aad.len() as u32).to_be_bytes());
    hasher.update(aad);
    let mut key = [0; 32];
    hasher.finalize_xof().read(&mut key);
    key
}

fn protected_nonce(ciphertext: &[u8], aad: &[u8]) -> [u8; 12] {
    let mut hasher = Shake256::default();
    hasher.update(PROTECTED_NONCE_DOMAIN);
    hasher.update(&(ciphertext.len() as u32).to_be_bytes());
    hasher.update(ciphertext);
    hasher.update(&(aad.len() as u32).to_be_bytes());
    hasher.update(aad);
    let mut nonce = [0; 12];
    hasher.finalize_xof().read(&mut nonce);
    nonce
}

/// Seals a payload with ChaCha20-Poly1305. The caller is responsible for unique nonces per key.
pub fn aead_seal(
    key: &[u8; 32],
    nonce: [u8; 12],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, KemError> {
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| KemError::EncryptionFailed)?;
    let key = LessSafeKey::new(unbound);
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(associated_data),
        &mut in_out,
    )
    .map_err(|_| KemError::EncryptionFailed)?;
    Ok(in_out)
}

/// Opens a ChaCha20-Poly1305 payload and fails closed on any authentication error.
pub fn aead_open(
    key: &[u8; 32],
    nonce: [u8; 12],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KemError> {
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| KemError::AuthenticationFailed)?;
    let key = LessSafeKey::new(unbound);
    let mut in_out = ciphertext.to_vec();
    let plaintext_len = key
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(associated_data), &mut in_out)
        .map_err(|_| KemError::AuthenticationFailed)?
        .len();
    in_out.truncate(plaintext_len);
    Ok(in_out)
}

/// Reviewed ML-KEM-768 boundary for protected transaction key establishment.
pub struct MlKem768Recipient {
    key: DecapsulationKey<MlKem768>,
}
impl MlKem768Recipient {
    pub fn from_seed(mut seed: [u8; 64]) -> Self {
        let key = DecapsulationKey::<MlKem768>::from_seed(KemSeed::from(seed));
        seed.zeroize();
        Self { key }
    }
    pub fn public_key(&self) -> Vec<u8> {
        self.key.encapsulation_key().to_bytes().to_vec()
    }
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32], KemError> {
        let ciphertext =
            Ciphertext::try_from(ciphertext).map_err(|_| KemError::InvalidCiphertext)?;
        let shared =
            self.key.try_decapsulate(&ciphertext).map_err(|_| KemError::DecapsulationFailed)?;
        Ok(shared.into())
    }
}
pub fn ml_kem768_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, [u8; 32]), KemError> {
    let encoded = public_key.try_into().map_err(|_| KemError::InvalidPublicKey)?;
    let key =
        EncapsulationKey::<MlKem768>::new(&encoded).map_err(|_| KemError::InvalidPublicKey)?;
    let (ciphertext, shared) = key.encapsulate();
    Ok((ciphertext.as_slice().to_vec(), shared.into()))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KemError {
    InvalidPublicKey,
    InvalidCiphertext,
    DecapsulationFailed,
    PayloadTooLarge,
    AuthenticationFailed,
    InvalidEnvelope,
    EncryptionFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    InvalidKeyLength,
    InvalidSignatureLength,
    MalformedKey,
    MalformedSignature,
    InvalidSignature,
    UnknownValidator,
    DuplicateValidator,
    NonCanonicalVoteOrder,
    VoteContextMismatch,
    VoteSetRootMismatch,
    StakeMismatch,
    StakeOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidVerificationError {
    ContextMismatch,
    InvalidAuthorizer,
    UnsupportedSuite,
    InvalidKeyLength,
    InvalidSignatureLength,
    MalformedSignature,
    InvalidSignature,
    InvalidLifecycle,
}

/// Verifies the exact network-bound DID operation signature before applying its role-bound
/// canonical document transition.
pub fn verify_did_operation_authorization(
    current: &DidControllerRecordV1,
    current_document: &DidDocumentV1,
    operation: &DidControllerOperationV1,
    next_document: &DidDocumentV1,
    authorization: &DidOperationAuthorizationV1,
    expected_chain_genesis: activechain_protocol_types::Digest384,
    finalized_height: u64,
) -> Result<DidControllerRecordV1, DidVerificationError> {
    if !authorization.binds(expected_chain_genesis, operation) {
        return Err(DidVerificationError::ContextMismatch);
    }
    let method = current_document
        .method(authorization.authorizer())
        .ok_or(DidVerificationError::InvalidAuthorizer)?;
    if method.scheme() != authorization.signature().suite() {
        return Err(DidVerificationError::InvalidAuthorizer);
    }
    let payload = authorization.signing_payload();
    verify_did_signature(
        method.scheme(),
        method.verification_key(),
        &payload,
        authorization.signature().as_bytes(),
    )?;
    current
        .apply_document_operation(
            current_document,
            operation,
            next_document,
            authorization.authorizer(),
            finalized_height,
        )
        .map_err(|_| DidVerificationError::InvalidLifecycle)
}

pub fn verify_did_signature(
    suite: CryptoSuiteId,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), DidVerificationError> {
    macro_rules! verify {
        ($parameters:ty) => {{
            let key: EncodedVerifyingKey<$parameters> =
                public_key.try_into().map_err(|_| DidVerificationError::InvalidKeyLength)?;
            let signature: EncodedSignature<$parameters> =
                signature.try_into().map_err(|_| DidVerificationError::InvalidSignatureLength)?;
            let key = VerifyingKey::<$parameters>::decode(&key);
            let signature = Signature::<$parameters>::decode(&signature)
                .ok_or(DidVerificationError::MalformedSignature)?;
            key.verify(message, &signature).map_err(|_| DidVerificationError::InvalidSignature)
        }};
    }
    match suite {
        CryptoSuiteId::ML_DSA_65 => verify!(MlDsa65),
        CryptoSuiteId::ML_DSA_87 => verify!(MlDsa87),
        CryptoSuiteId::SLH_DSA_SHAKE_192S => {
            let key = SlhVerifyingKey::<Shake192s>::try_from(public_key)
                .map_err(|_| DidVerificationError::InvalidKeyLength)?;
            let signature = SlhSignature::<Shake192s>::try_from(signature)
                .map_err(|_| DidVerificationError::InvalidSignatureLength)?;
            SlhVerifier::verify(&key, message, &signature)
                .map_err(|_| DidVerificationError::InvalidSignature)
        }
        _ => Err(DidVerificationError::UnsupportedSuite),
    }
}

/// Finalized validator public keys used by the production verifier boundary.
///
/// The registry is deliberately immutable and ordered. Callers must replace it only when a
/// finalized epoch transition has been accepted; there is no fallback key or ad-hoc lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorKeyRegistry(Vec<(PrincipalId, [u8; ML_DSA44_PUBLIC_KEY_LENGTH])>);

impl ValidatorKeyRegistry {
    pub fn from_genesis(genesis: &ValidatorGenesis) -> Result<Self, VerificationError> {
        let mut entries = genesis
            .entries()
            .iter()
            .map(|entry| (entry.validator(), *entry.public_key()))
            .collect::<Vec<_>>();
        if entries.is_empty() || entries.len() > MAX_VALIDATORS_PER_EPOCH {
            return Err(VerificationError::UnknownValidator);
        }
        entries.sort_by_key(|(validator, _)| *validator);
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(VerificationError::DuplicateValidator);
        }
        Ok(Self(entries))
    }

    pub fn public_key(&self, validator: &PrincipalId) -> Option<&[u8; ML_DSA44_PUBLIC_KEY_LENGTH]> {
        self.0.binary_search_by_key(validator, |(id, _)| *id).ok().map(|index| &self.0[index].1)
    }

    pub fn verify_vote(
        &self,
        validator: &PrincipalId,
        vote: &ValidatorVote,
    ) -> Result<(), VerificationError> {
        let key = self.public_key(validator).ok_or(VerificationError::UnknownValidator)?;
        verify_validator_vote(key, vote)
    }
}

pub fn verify_ml_dsa44(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerificationError> {
    let key: EncodedVerifyingKey<MlDsa44> =
        public_key.try_into().map_err(|_| VerificationError::InvalidKeyLength)?;
    let sig: EncodedSignature<MlDsa44> =
        signature.try_into().map_err(|_| VerificationError::InvalidSignatureLength)?;
    let verifying_key = VerifyingKey::<MlDsa44>::decode(&key);
    let signature =
        Signature::<MlDsa44>::decode(&sig).ok_or(VerificationError::MalformedSignature)?;
    verifying_key.verify(message, &signature).map_err(|_| VerificationError::InvalidSignature)
}

pub fn verify_validator_vote(
    public_key: &[u8],
    vote: &ValidatorVote,
) -> Result<(), VerificationError> {
    verify_ml_dsa44(public_key, &vote.signing_payload(), vote.signature().as_bytes())
}

/// Verifies every timeout signature and recomputes the exact stake quorum.
pub fn verify_view_change_certificate(
    certificate: &ViewChangeCertificate,
    validator_set: &ValidatorSet,
    public_keys: &[(PrincipalId, &[u8])],
) -> Result<(), VerificationError> {
    if certificate.total_stake() != validator_set.total_stake() {
        return Err(VerificationError::StakeMismatch);
    }
    let mut signer_stake = 0_u128;
    for vote in certificate.votes() {
        let stake =
            validator_set.stake_of(&vote.validator()).ok_or(VerificationError::UnknownValidator)?;
        let public_key = public_keys
            .binary_search_by_key(&vote.validator(), |(validator, _)| *validator)
            .ok()
            .map(|index| public_keys[index].1)
            .ok_or(VerificationError::UnknownValidator)?;
        verify_ml_dsa44(public_key, &vote.signing_payload(), vote.signature().as_bytes())?;
        signer_stake = signer_stake.checked_add(stake).ok_or(VerificationError::StakeOverflow)?;
    }
    if signer_stake != certificate.signer_stake() {
        return Err(VerificationError::StakeMismatch);
    }
    Ok(())
}

pub fn verify_block_proposal(
    public_key: &[u8],
    proposal: &BlockProposal,
) -> Result<(), VerificationError> {
    verify_ml_dsa44(public_key, &proposal.signing_payload(), proposal.signature().as_bytes())
}

pub fn verify_quorum_certificate(
    certificate: &QuorumCertificate,
    validator_set: &ValidatorSet,
    votes: &[(&[u8], ValidatorVote)],
) -> Result<(), VerificationError> {
    let mut seen = alloc::vec::Vec::new();
    let mut signer_stake = 0_u128;
    let mut vote_domain = None;
    let mut proposal_commitment = None;
    let mut previous_validator = None;
    let mut vote_set_hasher = Shake256::default();
    vote_set_hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
    for (public_key, vote) in votes {
        let current_domain =
            (vote.genesis_commitment(), vote.validator_set_root(), vote.protocol_revision());
        if vote.genesis_commitment() != certificate.genesis_commitment()
            || vote.epoch() != certificate.epoch()
            || vote.validator_set_root() != certificate.validator_set_root()
            || vote.protocol_revision() != certificate.protocol_revision()
            || vote_domain.is_some_and(|domain| domain != current_domain)
            || vote.height() != certificate.height()
            || vote.round() != certificate.round()
            || vote.block_digest() != certificate.block_digest()
            || vote.proposal_commitment() != certificate.proposal_commitment()
            || proposal_commitment
                .is_some_and(|commitment| commitment != vote.proposal_commitment())
        {
            return Err(VerificationError::VoteContextMismatch);
        }
        vote_domain = Some(current_domain);
        proposal_commitment = Some(vote.proposal_commitment());
        if seen.contains(&vote.validator()) {
            return Err(VerificationError::DuplicateValidator);
        }
        if previous_validator.is_some_and(|previous| vote.validator() <= previous) {
            return Err(VerificationError::NonCanonicalVoteOrder);
        }
        let stake =
            validator_set.stake_of(&vote.validator()).ok_or(VerificationError::UnknownValidator)?;
        verify_validator_vote(public_key, vote)?;
        vote_set_hasher.update(public_key);
        vote_set_hasher.update(&vote.signing_payload());
        vote_set_hasher.update(vote.signature().as_bytes());
        seen.push(vote.validator());
        previous_validator = Some(vote.validator());
        signer_stake = signer_stake.checked_add(stake).ok_or(VerificationError::StakeMismatch)?;
    }
    let mut vote_set_root = [0_u8; 48];
    vote_set_hasher.finalize_xof().read(&mut vote_set_root);
    if activechain_protocol_types::Digest384::new(vote_set_root) != certificate.vote_set_root() {
        return Err(VerificationError::VoteSetRootMismatch);
    }
    if validator_set.total_stake() != certificate.total_stake()
        || signer_stake != certificate.signer_stake()
    {
        return Err(VerificationError::StakeMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{
        AuthenticatorDescriptor, AuthenticatorId, AuthenticatorPurpose, ConsensusVoteContext,
        CryptoSuiteId, DidControllerOperationV1, DidControllerRecordV1, DidDocumentV1,
        DidKeyAgreementMethodV1, DidOperationAuthorizationV1, DidOperationKind, Digest384,
        ML_KEM_768_PUBLIC_KEY_LENGTH, PrincipalId, ProtocolSignature, QuorumCertificate,
        ValidatorSet, ValidatorVote, ValidatorWeight,
    };
    use ml_dsa::{Keypair, MlDsa44, MlDsa65, Seed, Signer, SigningKey};
    use slh_dsa::{Shake192s, SigningKey as SlhSigningKey, signature::Signer as SlhSigner};
    #[test]
    fn verifies_a_real_ml_dsa44_signature() {
        let seed = Seed::default();
        let signing_key = SigningKey::<MlDsa44>::from_seed(&seed);
        let message = b"activechain-pq-testnet";
        let signature = signing_key.sign(message);
        assert!(
            verify_ml_dsa44(
                signing_key.verifying_key().encode().as_slice(),
                message,
                signature.encode().as_slice()
            )
            .is_ok()
        );
        assert_eq!(
            verify_ml_dsa44(
                signing_key.verifying_key().encode().as_slice(),
                b"tampered",
                signature.encode().as_slice()
            ),
            Err(VerificationError::InvalidSignature)
        );
    }

    #[test]
    fn verifies_a_consensus_vote_payload() {
        let signing_key = SigningKey::<MlDsa44>::from_seed(&Seed::default());
        let unsigned = ValidatorVote::new(
            PrincipalId::new(Digest384::new([7; 48])),
            ConsensusVoteContext::new(Digest384::new([5; 48]), 3, Digest384::new([6; 48])).unwrap(),
            9,
            2,
            Digest384::new([8; 48]),
            Digest384::new([9; 48]),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap(),
        )
        .unwrap();
        let signature = signing_key.sign(&unsigned.signing_payload());
        let vote = ValidatorVote::new(
            unsigned.validator(),
            ConsensusVoteContext::new(
                unsigned.genesis_commitment(),
                unsigned.epoch(),
                unsigned.validator_set_root(),
            )
            .unwrap(),
            unsigned.height(),
            unsigned.round(),
            unsigned.block_digest(),
            unsigned.proposal_commitment(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap();
        assert!(
            verify_validator_vote(signing_key.verifying_key().encode().as_slice(), &vote).is_ok()
        );
        let wrong_epoch = ValidatorVote::new(
            vote.validator(),
            ConsensusVoteContext::new(
                vote.genesis_commitment(),
                vote.epoch() + 1,
                vote.validator_set_root(),
            )
            .unwrap(),
            vote.height(),
            vote.round(),
            vote.block_digest(),
            vote.proposal_commitment(),
            vote.signature().clone(),
        )
        .unwrap();
        assert_eq!(
            verify_validator_vote(signing_key.verifying_key().encode().as_slice(), &wrong_epoch),
            Err(VerificationError::InvalidSignature)
        );
        let wrong_revision = ValidatorVote::new(
            vote.validator(),
            ConsensusVoteContext::new_with_revision(
                vote.genesis_commitment(),
                vote.epoch(),
                vote.validator_set_root(),
                vote.protocol_revision() + 1,
            )
            .unwrap(),
            vote.height(),
            vote.round(),
            vote.block_digest(),
            vote.proposal_commitment(),
            vote.signature().clone(),
        )
        .unwrap();
        assert_eq!(
            verify_validator_vote(signing_key.verifying_key().encode().as_slice(), &wrong_revision),
            Err(VerificationError::InvalidSignature)
        );
    }

    #[test]
    fn quorum_verification_binds_canonical_vote_set_transcript() {
        let context =
            ConsensusVoteContext::new(Digest384::new([20; 48]), 3, Digest384::new([21; 48]))
                .unwrap();
        let block_digest = Digest384::new([22; 48]);
        let proposal_commitment = Digest384::new([23; 48]);
        let validators: Vec<_> = [1_u8, 2]
            .into_iter()
            .map(|byte| ValidatorWeight {
                validator: PrincipalId::new(Digest384::new([byte; 48])),
                stake: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators.clone()).unwrap();
        let mut signed_votes = Vec::new();
        for (index, validator) in validators.iter().enumerate() {
            let signing_key =
                SigningKey::<MlDsa44>::from_seed(&Seed::from([(index + 1) as u8; 32]));
            let unsigned = ValidatorVote::new(
                validator.validator,
                context,
                9,
                2,
                block_digest,
                proposal_commitment,
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap(),
            )
            .unwrap();
            let signature = signing_key.sign(&unsigned.signing_payload());
            signed_votes.push((
                signing_key.verifying_key().encode().to_vec(),
                ValidatorVote::new(
                    validator.validator,
                    context,
                    9,
                    2,
                    block_digest,
                    proposal_commitment,
                    ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                        .unwrap(),
                )
                .unwrap(),
            ));
        }
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
        for (key, vote) in &signed_votes {
            hasher.update(key);
            hasher.update(&vote.signing_payload());
            hasher.update(vote.signature().as_bytes());
        }
        let mut root = [0_u8; 48];
        hasher.finalize_xof().read(&mut root);
        let certificate = QuorumCertificate::new(
            context,
            9,
            2,
            block_digest,
            proposal_commitment,
            Digest384::new(root),
            2,
            2,
        )
        .unwrap();
        let mut vote_refs: Vec<_> =
            signed_votes.iter().map(|(key, vote)| (key.as_slice(), vote.clone())).collect();
        assert_eq!(verify_quorum_certificate(&certificate, &validator_set, &vote_refs), Ok(()));

        let tampered_root = QuorumCertificate::new(
            context,
            9,
            2,
            block_digest,
            proposal_commitment,
            Digest384::new([99; 48]),
            2,
            2,
        )
        .unwrap();
        assert_eq!(
            verify_quorum_certificate(&tampered_root, &validator_set, &vote_refs),
            Err(VerificationError::VoteSetRootMismatch)
        );

        let alternate_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([2_u8; 32]));
        let alternate_unsigned = ValidatorVote::new(
            validators[1].validator,
            context,
            9,
            2,
            block_digest,
            Digest384::new([24; 48]),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap(),
        )
        .unwrap();
        let alternate_vote = ValidatorVote::new(
            validators[1].validator,
            context,
            9,
            2,
            block_digest,
            Digest384::new([24; 48]),
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                alternate_key.sign(&alternate_unsigned.signing_payload()).encode().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let mixed_votes = [
            signed_votes[0].clone(),
            (alternate_key.verifying_key().encode().to_vec(), alternate_vote),
        ];
        let mut mixed_hasher = Shake256::default();
        mixed_hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
        for (key, vote) in &mixed_votes {
            mixed_hasher.update(key);
            mixed_hasher.update(&vote.signing_payload());
            mixed_hasher.update(vote.signature().as_bytes());
        }
        let mut mixed_root = [0_u8; 48];
        mixed_hasher.finalize_xof().read(&mut mixed_root);
        let mixed_certificate = QuorumCertificate::new(
            context,
            9,
            2,
            block_digest,
            Digest384::new([24; 48]),
            Digest384::new(mixed_root),
            2,
            2,
        )
        .unwrap();
        let mixed_refs: Vec<_> =
            mixed_votes.iter().map(|(key, vote)| (key.as_slice(), vote.clone())).collect();
        assert_eq!(
            verify_quorum_certificate(&mixed_certificate, &validator_set, &mixed_refs),
            Err(VerificationError::VoteContextMismatch)
        );

        vote_refs.swap(0, 1);
        assert_eq!(
            verify_quorum_certificate(&certificate, &validator_set, &vote_refs),
            Err(VerificationError::NonCanonicalVoteOrder)
        );
    }

    #[test]
    fn ml_kem768_round_trip_and_tampered_ciphertext_rejects() {
        let recipient = MlKem768Recipient::from_seed([11; 64]);
        let (ciphertext, sender_secret) = ml_kem768_encapsulate(&recipient.public_key()).unwrap();
        let receiver_secret = recipient.decapsulate(&ciphertext).unwrap();
        assert_eq!(sender_secret, receiver_secret);
        let mut tampered = ciphertext;
        tampered[0] ^= 1;
        assert_ne!(recipient.decapsulate(&tampered).unwrap(), sender_secret);
    }

    #[test]
    fn protected_envelope_binds_associated_data_and_payload() {
        let recipient = MlKem768Recipient::from_seed([12; 64]);
        let envelope = ProtectedEnvelope::seal(
            recipient.public_key().as_slice(),
            b"secret action",
            b"chain-1",
        )
        .unwrap();
        let envelope = ProtectedEnvelope::decode(&envelope.encode().unwrap()).unwrap();
        assert_eq!(envelope.open(&recipient, b"chain-1").unwrap(), b"secret action");
        assert_eq!(envelope.open(&recipient, b"chain-2"), Err(KemError::AuthenticationFailed));
        let mut tampered = envelope.clone();
        tampered.encrypted_payload[0] ^= 1;
        assert_eq!(tampered.open(&recipient, b"chain-1"), Err(KemError::AuthenticationFailed));
    }

    #[test]
    fn did_authorization_verifies_real_signature_context_and_role() {
        let digest = |byte| Digest384::new([byte; 48]);
        let principal = PrincipalId::new(digest(1));
        let authorizer = AuthenticatorId::new(digest(2));
        let signing_key = SigningKey::<MlDsa65>::from_seed(&Seed::from([7; 32]));
        let control = AuthenticatorDescriptor::new(
            authorizer,
            CryptoSuiteId::ML_DSA_65,
            signing_key.verifying_key().encode().to_vec(),
            AuthenticatorPurpose::Control,
            1,
            None,
            None,
        )
        .unwrap();
        let agreement = DidKeyAgreementMethodV1::new(
            AuthenticatorId::new(digest(3)),
            CryptoSuiteId::ML_KEM_768,
            vec![3; ML_KEM_768_PUBLIC_KEY_LENGTH],
            1,
            None,
            None,
        )
        .unwrap();
        let current_document =
            DidDocumentV1::new(principal, vec![control.clone()], vec![agreement.clone()], None)
                .unwrap();
        let next_document =
            DidDocumentV1::new(principal, vec![control], vec![agreement], Some(digest(4))).unwrap();
        let current = DidControllerRecordV1::from_document(&current_document, 1, true).unwrap();
        let next = DidControllerRecordV1::from_document(&next_document, 2, true).unwrap();
        let operation = DidControllerOperationV1::new(
            DidOperationKind::Update,
            principal,
            Some(current.commitment().unwrap()),
            next,
            digest(5),
        )
        .unwrap();
        let genesis = digest(6);
        let unsigned = DidOperationAuthorizationV1::new(
            genesis,
            &operation,
            authorizer,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, vec![0; 3_309]).unwrap(),
        )
        .unwrap();
        let signed = DidOperationAuthorizationV1::new(
            genesis,
            &operation,
            authorizer,
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_65,
                signing_key.sign(&unsigned.signing_payload()).encode().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_did_operation_authorization(
                &current,
                &current_document,
                &operation,
                &next_document,
                &signed,
                genesis,
                1,
            ),
            Ok(next)
        );
        assert_eq!(
            verify_did_operation_authorization(
                &current,
                &current_document,
                &operation,
                &next_document,
                &signed,
                digest(9),
                1,
            ),
            Err(DidVerificationError::ContextMismatch)
        );
    }

    #[test]
    fn did_recovery_verifies_real_slh_dsa_and_rejects_controller_substitution() {
        let digest = |byte| Digest384::new([byte; 48]);
        let principal = PrincipalId::new(digest(1));
        let control_key = SigningKey::<MlDsa65>::from_seed(&Seed::from([7; 32]));
        let control_id = AuthenticatorId::new(digest(2));
        let recovery_id = AuthenticatorId::new(digest(3));
        let recovery_key =
            SlhSigningKey::<Shake192s>::slh_keygen_internal(&[8; 24], &[9; 24], &[10; 24]);
        let current_document = DidDocumentV1::new(
            principal,
            vec![
                AuthenticatorDescriptor::new(
                    control_id,
                    CryptoSuiteId::ML_DSA_65,
                    control_key.verifying_key().encode().to_vec(),
                    AuthenticatorPurpose::Control,
                    1,
                    None,
                    None,
                )
                .unwrap(),
                AuthenticatorDescriptor::new(
                    recovery_id,
                    CryptoSuiteId::SLH_DSA_SHAKE_192S,
                    recovery_key.verifying_key().to_bytes().to_vec(),
                    AuthenticatorPurpose::Recovery,
                    1,
                    None,
                    None,
                )
                .unwrap(),
            ],
            vec![
                DidKeyAgreementMethodV1::new(
                    AuthenticatorId::new(digest(4)),
                    CryptoSuiteId::ML_KEM_768,
                    vec![4; ML_KEM_768_PUBLIC_KEY_LENGTH],
                    1,
                    None,
                    None,
                )
                .unwrap(),
            ],
            None,
        )
        .unwrap();
        let next_document = current_document.clone();
        let current = DidControllerRecordV1::from_document(&current_document, 1, true).unwrap();
        let next = DidControllerRecordV1::from_document(&next_document, 2, true).unwrap();
        let operation = DidControllerOperationV1::new(
            DidOperationKind::Recover,
            principal,
            Some(current.commitment().unwrap()),
            next,
            digest(5),
        )
        .unwrap();
        let genesis = digest(6);
        let unsigned = DidOperationAuthorizationV1::new(
            genesis,
            &operation,
            recovery_id,
            ProtocolSignature::new(CryptoSuiteId::SLH_DSA_SHAKE_192S, vec![0; 16_224]).unwrap(),
        )
        .unwrap();
        let signature = SlhSigner::try_sign(&recovery_key, &unsigned.signing_payload()).unwrap();
        let signed = DidOperationAuthorizationV1::new(
            genesis,
            &operation,
            recovery_id,
            ProtocolSignature::new(CryptoSuiteId::SLH_DSA_SHAKE_192S, Vec::<u8>::from(&signature))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_did_operation_authorization(
                &current,
                &current_document,
                &operation,
                &next_document,
                &signed,
                genesis,
                1,
            ),
            Ok(next)
        );
        let wrong_role = DidOperationAuthorizationV1::new(
            genesis,
            &operation,
            control_id,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, vec![0; 3_309]).unwrap(),
        )
        .unwrap();
        assert!(
            verify_did_operation_authorization(
                &current,
                &current_document,
                &operation,
                &next_document,
                &wrong_role,
                genesis,
                1,
            )
            .is_err()
        );
    }
}
