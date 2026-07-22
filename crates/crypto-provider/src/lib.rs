#![forbid(unsafe_code)]
//! Cryptographic provider boundary for authoritative PQ verification.

extern crate alloc;

use activechain_protocol_types::{BlockProposal, QuorumCertificate, ValidatorSet, ValidatorVote};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature, Verifier, VerifyingKey};
use ml_kem::{
    DecapsulationKey, EncapsulationKey, MlKem768, Seed as KemSeed,
    kem::{Encapsulate, KeyExport, TryDecapsulate},
    ml_kem_768::Ciphertext,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_PROTECTED_PAYLOAD: usize = 64 * 1024;
pub const MAX_THRESHOLD_RECIPIENTS: usize = 64;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedEnvelope {
    ciphertext: Vec<u8>,
    encrypted_payload: Vec<u8>,
    tag: [u8; 48],
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
        let (ciphertext, shared) = ml_kem768_encapsulate(public_key)?;
        let encrypted_payload = xor_stream(&shared, &ciphertext, associated_data, payload);
        let tag = envelope_tag(&shared, &ciphertext, associated_data, &encrypted_payload);
        Ok(Self { ciphertext, encrypted_payload, tag })
    }
    pub fn open(
        &self,
        recipient: &MlKem768Recipient,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, KemError> {
        let shared = recipient.decapsulate(&self.ciphertext)?;
        let expected =
            envelope_tag(&shared, &self.ciphertext, associated_data, &self.encrypted_payload);
        if !constant_time_equal(&expected, &self.tag) {
            return Err(KemError::AuthenticationFailed);
        }
        Ok(xor_stream(&shared, &self.ciphertext, associated_data, &self.encrypted_payload))
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn encrypted_payload(&self) -> &[u8] {
        &self.encrypted_payload
    }
    pub const fn tag(&self) -> &[u8; 48] {
        &self.tag
    }
    pub fn encode(&self) -> Result<Vec<u8>, KemError> {
        if self.ciphertext.len() > u32::MAX as usize
            || self.encrypted_payload.len() > MAX_PROTECTED_PAYLOAD
        {
            return Err(KemError::PayloadTooLarge);
        }
        let mut bytes =
            Vec::with_capacity(13 + self.ciphertext.len() + self.encrypted_payload.len());
        bytes.extend_from_slice(b"ACPE1");
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(self.encrypted_payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&self.encrypted_payload);
        bytes.extend_from_slice(&self.tag);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, KemError> {
        if bytes.len() < 13 + 48 || &bytes[..5] != b"ACPE1" {
            return Err(KemError::InvalidEnvelope);
        }
        let ciphertext_len = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
        let payload_len = u32::from_be_bytes(bytes[9..13].try_into().unwrap()) as usize;
        if payload_len > MAX_PROTECTED_PAYLOAD
            || bytes.len() != 13 + ciphertext_len + payload_len + 48
        {
            return Err(KemError::InvalidEnvelope);
        }
        let payload_start = 13 + ciphertext_len;
        Ok(Self {
            ciphertext: bytes[13..payload_start].to_vec(),
            encrypted_payload: bytes[payload_start..payload_start + payload_len].to_vec(),
            tag: bytes[payload_start + payload_len..].try_into().unwrap(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedDecryptionShare {
    member_index: u8,
    envelope: ProtectedEnvelope,
}

impl EncryptedDecryptionShare {
    #[must_use]
    pub const fn member_index(&self) -> u8 {
        self.member_index
    }
    #[must_use]
    pub const fn envelope(&self) -> &ProtectedEnvelope {
        &self.envelope
    }

    pub fn open(
        &self,
        recipient: &MlKem768Recipient,
        associated_data: &[u8],
    ) -> Result<DecryptionShare, KemError> {
        let aad = threshold_share_aad(associated_data, self.member_index);
        let plaintext = self.envelope.open(recipient, &aad)?;
        if plaintext.len() != 33 || plaintext[0] != self.member_index {
            return Err(KemError::InvalidShare);
        }
        let mut value = [0_u8; 32];
        value.copy_from_slice(&plaintext[1..]);
        Ok(DecryptionShare { member_index: self.member_index, value })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecryptionShare {
    member_index: u8,
    value: [u8; 32],
}

impl DecryptionShare {
    #[must_use]
    pub const fn member_index(&self) -> u8 {
        self.member_index
    }
}

/// Multi-recipient payload requiring a declared number of ML-KEM-wrapped Shamir shares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdProtectedEnvelope {
    threshold: u8,
    encrypted_shares: Vec<EncryptedDecryptionShare>,
    encrypted_payload: Vec<u8>,
    tag: [u8; 48],
    share_set_context: [u8; 48],
}

impl ThresholdProtectedEnvelope {
    /// Seals using 64 bytes supplied by the caller's CSPRNG.
    pub fn seal(
        seed: [u8; 64],
        recipient_public_keys: &[Vec<u8>],
        threshold: u8,
        payload: &[u8],
        associated_data: &[u8],
    ) -> Result<Self, KemError> {
        if payload.len() > MAX_PROTECTED_PAYLOAD {
            return Err(KemError::PayloadTooLarge);
        }
        if recipient_public_keys.is_empty()
            || recipient_public_keys.len() > MAX_THRESHOLD_RECIPIENTS
            || threshold == 0
            || usize::from(threshold) > recipient_public_keys.len()
        {
            return Err(KemError::InvalidThreshold);
        }
        let (content_key, coefficients) = threshold_material(&seed, threshold);
        let mut encrypted_shares = Vec::with_capacity(recipient_public_keys.len());
        for (offset, public_key) in recipient_public_keys.iter().enumerate() {
            let member_index = u8::try_from(offset + 1).map_err(|_| KemError::InvalidThreshold)?;
            let share = evaluate_share(content_key, &coefficients, member_index);
            let mut plaintext = Vec::with_capacity(33);
            plaintext.push(member_index);
            plaintext.extend_from_slice(&share);
            let aad = threshold_share_aad(associated_data, member_index);
            encrypted_shares.push(EncryptedDecryptionShare {
                member_index,
                envelope: ProtectedEnvelope::seal(public_key, &plaintext, &aad)?,
            });
        }
        let share_set_context = share_set_context(threshold, &encrypted_shares)?;
        let encrypted_payload =
            xor_stream(&content_key, &share_set_context, associated_data, payload);
        let tag =
            envelope_tag(&content_key, &share_set_context, associated_data, &encrypted_payload);
        Ok(Self { threshold, encrypted_shares, encrypted_payload, tag, share_set_context })
    }

    #[must_use]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }
    #[must_use]
    pub fn encrypted_shares(&self) -> &[EncryptedDecryptionShare] {
        &self.encrypted_shares
    }

    pub fn open(
        &self,
        shares: &[DecryptionShare],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, KemError> {
        if shares.len() < usize::from(self.threshold) {
            return Err(KemError::InsufficientShares);
        }
        let selected = &shares[..usize::from(self.threshold)];
        for (position, share) in selected.iter().enumerate() {
            if share.member_index == 0
                || usize::from(share.member_index) > self.encrypted_shares.len()
                || selected[..position].iter().any(|prior| prior.member_index == share.member_index)
            {
                return Err(KemError::InvalidShare);
            }
        }
        let content_key = interpolate_zero(selected)?;
        let expected = envelope_tag(
            &content_key,
            &self.share_set_context,
            associated_data,
            &self.encrypted_payload,
        );
        if !constant_time_equal(&expected, &self.tag) {
            return Err(KemError::AuthenticationFailed);
        }
        Ok(xor_stream(
            &content_key,
            &self.share_set_context,
            associated_data,
            &self.encrypted_payload,
        ))
    }
}

fn threshold_material(seed: &[u8; 64], threshold: u8) -> ([u8; 32], Vec<[u8; 32]>) {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-THRESHOLD-MATERIAL-V1");
    hasher.update(seed);
    hasher.update(&[threshold]);
    let mut reader = hasher.finalize_xof();
    let mut secret = [0_u8; 32];
    reader.read(&mut secret);
    let mut coefficients = Vec::with_capacity(usize::from(threshold.saturating_sub(1)));
    for _ in 1..threshold {
        let mut coefficient = [0_u8; 32];
        reader.read(&mut coefficient);
        coefficients.push(coefficient);
    }
    (secret, coefficients)
}

fn evaluate_share(secret: [u8; 32], coefficients: &[[u8; 32]], x: u8) -> [u8; 32] {
    let mut output = secret;
    for byte in 0..32 {
        let mut power = x;
        for coefficient in coefficients {
            output[byte] ^= gf_mul(coefficient[byte], power);
            power = gf_mul(power, x);
        }
    }
    output
}

fn interpolate_zero(shares: &[DecryptionShare]) -> Result<[u8; 32], KemError> {
    let mut secret = [0_u8; 32];
    for (index, share) in shares.iter().enumerate() {
        let x_i = share.member_index;
        let mut numerator = 1_u8;
        let mut denominator = 1_u8;
        for (other_index, other) in shares.iter().enumerate() {
            if index == other_index {
                continue;
            }
            numerator = gf_mul(numerator, other.member_index);
            denominator = gf_mul(denominator, other.member_index ^ x_i);
        }
        if denominator == 0 {
            return Err(KemError::InvalidShare);
        }
        let basis = gf_mul(numerator, gf_inverse(denominator));
        for (output, value) in secret.iter_mut().zip(share.value) {
            *output ^= gf_mul(value, basis);
        }
    }
    Ok(secret)
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut output = 0_u8;
    for _ in 0..8 {
        if right & 1 != 0 {
            output ^= left;
        }
        let carry = left & 0x80;
        left <<= 1;
        if carry != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    output
}

fn gf_inverse(value: u8) -> u8 {
    let mut output = 1_u8;
    for _ in 0..254 {
        output = gf_mul(output, value);
    }
    output
}

fn threshold_share_aad(associated_data: &[u8], member_index: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(associated_data.len() + 26);
    aad.extend_from_slice(b"ACTIVECHAIN-THRESHOLD-SHARE-V1");
    aad.push(member_index);
    aad.extend_from_slice(associated_data);
    aad
}

fn share_set_context(
    threshold: u8,
    shares: &[EncryptedDecryptionShare],
) -> Result<[u8; 48], KemError> {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-THRESHOLD-SHARE-SET-V1");
    hasher.update(&[threshold]);
    for share in shares {
        hasher.update(&[share.member_index]);
        let encoded = share.envelope.encode()?;
        hasher.update(&(encoded.len() as u32).to_be_bytes());
        hasher.update(&encoded);
    }
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    Ok(output)
}
fn xor_stream(shared: &[u8; 32], ciphertext: &[u8], aad: &[u8], input: &[u8]) -> Vec<u8> {
    let mut reader = Shake256::default();
    reader.update(b"ACTIVECHAIN-MLKEM-STREAM-V1");
    reader.update(shared);
    reader.update(&(ciphertext.len() as u32).to_be_bytes());
    reader.update(ciphertext);
    reader.update(&(aad.len() as u32).to_be_bytes());
    reader.update(aad);
    let mut stream = vec![0; input.len()];
    reader.finalize_xof().read(&mut stream);
    input.iter().zip(stream).map(|(left, right)| left ^ right).collect()
}
fn envelope_tag(shared: &[u8; 32], ciphertext: &[u8], aad: &[u8], encrypted: &[u8]) -> [u8; 48] {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-MLKEM-TAG-V1");
    hasher.update(shared);
    hasher.update(&(ciphertext.len() as u32).to_be_bytes());
    hasher.update(ciphertext);
    hasher.update(&(aad.len() as u32).to_be_bytes());
    hasher.update(aad);
    hasher.update(&(encrypted.len() as u32).to_be_bytes());
    hasher.update(encrypted);
    let mut tag = [0; 48];
    hasher.finalize_xof().read(&mut tag);
    tag
}
fn constant_time_equal(left: &[u8; 48], right: &[u8; 48]) -> bool {
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Reviewed ML-KEM-768 boundary for protected transaction key establishment.
pub struct MlKem768Recipient {
    key: DecapsulationKey<MlKem768>,
}
impl MlKem768Recipient {
    pub fn from_seed(seed: [u8; 64]) -> Self {
        Self { key: DecapsulationKey::<MlKem768>::from_seed(KemSeed::from(seed)) }
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
    InvalidThreshold,
    InsufficientShares,
    InvalidShare,
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
        {
            return Err(VerificationError::VoteContextMismatch);
        }
        vote_domain = Some(current_domain);
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
        ConsensusVoteContext, CryptoSuiteId, Digest384, PrincipalId, ProtocolSignature,
        QuorumCertificate, ValidatorSet, ValidatorVote, ValidatorWeight,
    };
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
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
        let certificate =
            QuorumCertificate::new(context, 9, 2, block_digest, Digest384::new(root), 2, 2)
                .unwrap();
        let mut vote_refs: Vec<_> =
            signed_votes.iter().map(|(key, vote)| (key.as_slice(), vote.clone())).collect();
        assert_eq!(verify_quorum_certificate(&certificate, &validator_set, &vote_refs), Ok(()));

        let tampered_root =
            QuorumCertificate::new(context, 9, 2, block_digest, Digest384::new([99; 48]), 2, 2)
                .unwrap();
        assert_eq!(
            verify_quorum_certificate(&tampered_root, &validator_set, &vote_refs),
            Err(VerificationError::VoteSetRootMismatch)
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
    fn threshold_envelope_requires_real_ml_kem_wrapped_quorum() {
        let recipients = [
            MlKem768Recipient::from_seed([21; 64]),
            MlKem768Recipient::from_seed([22; 64]),
            MlKem768Recipient::from_seed([23; 64]),
            MlKem768Recipient::from_seed([24; 64]),
        ];
        let public_keys = recipients.iter().map(MlKem768Recipient::public_key).collect::<Vec<_>>();
        let envelope = ThresholdProtectedEnvelope::seal(
            [90; 64],
            &public_keys,
            3,
            b"threshold protected payload",
            b"chain-1/epoch-7",
        )
        .unwrap();
        let shares = [0_usize, 1, 3]
            .into_iter()
            .map(|index| {
                envelope.encrypted_shares()[index]
                    .open(&recipients[index], b"chain-1/epoch-7")
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            envelope.open(&shares, b"chain-1/epoch-7").unwrap(),
            b"threshold protected payload"
        );
        assert_eq!(
            envelope.open(&shares[..2], b"chain-1/epoch-7"),
            Err(KemError::InsufficientShares)
        );
        let all = recipients
            .iter()
            .enumerate()
            .map(|(index, recipient)| {
                envelope.encrypted_shares()[index].open(recipient, b"chain-1/epoch-7").unwrap()
            })
            .collect::<Vec<_>>();
        for first in 0..all.len() {
            assert_eq!(
                envelope.open(&[all[first]], b"chain-1/epoch-7"),
                Err(KemError::InsufficientShares)
            );
            for second in first + 1..all.len() {
                assert_eq!(
                    envelope.open(&[all[first], all[second]], b"chain-1/epoch-7"),
                    Err(KemError::InsufficientShares)
                );
            }
        }
        for omitted in 0..all.len() {
            let quorum = all
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != omitted)
                .map(|(_, share)| *share)
                .collect::<Vec<_>>();
            assert_eq!(
                envelope.open(&quorum, b"chain-1/epoch-7").unwrap(),
                b"threshold protected payload"
            );
        }
    }

    #[test]
    fn threshold_envelope_rejects_duplicate_wrong_and_tampered_shares() {
        let recipients = [
            MlKem768Recipient::from_seed([31; 64]),
            MlKem768Recipient::from_seed([32; 64]),
            MlKem768Recipient::from_seed([33; 64]),
        ];
        let keys = recipients.iter().map(MlKem768Recipient::public_key).collect::<Vec<_>>();
        let envelope =
            ThresholdProtectedEnvelope::seal([91; 64], &keys, 2, b"payload", b"context").unwrap();
        let first = envelope.encrypted_shares()[0].open(&recipients[0], b"context").unwrap();
        let second = envelope.encrypted_shares()[1].open(&recipients[1], b"context").unwrap();
        assert_eq!(envelope.open(&[first, first], b"context"), Err(KemError::InvalidShare));
        assert_eq!(
            envelope.encrypted_shares()[0].open(&recipients[1], b"context"),
            Err(KemError::AuthenticationFailed)
        );
        let mut tampered = second;
        tampered.value[0] ^= 1;
        assert_eq!(
            envelope.open(&[first, tampered], b"context"),
            Err(KemError::AuthenticationFailed)
        );
    }
}
