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
    VoteContextMismatch,
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
    for (public_key, vote) in votes {
        if vote.height() != certificate.height()
            || vote.round() != certificate.round()
            || vote.block_digest() != certificate.block_digest()
        {
            return Err(VerificationError::VoteContextMismatch);
        }
        if seen.contains(&vote.validator()) {
            return Err(VerificationError::DuplicateValidator);
        }
        let stake =
            validator_set.stake_of(&vote.validator()).ok_or(VerificationError::UnknownValidator)?;
        verify_validator_vote(public_key, vote)?;
        seen.push(vote.validator());
        signer_stake = signer_stake.checked_add(stake).ok_or(VerificationError::StakeMismatch)?;
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
        CryptoSuiteId, Digest384, PrincipalId, ProtocolSignature, ValidatorVote,
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
            9,
            2,
            Digest384::new([8; 48]),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap(),
        )
        .unwrap();
        let signature = signing_key.sign(&unsigned.signing_payload());
        let vote = ValidatorVote::new(
            unsigned.validator(),
            unsigned.height(),
            unsigned.round(),
            unsigned.block_digest(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap();
        assert!(
            verify_validator_vote(signing_key.verifying_key().encode().as_slice(), &vote).is_ok()
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
        assert_eq!(envelope.open(&recipient, b"chain-1").unwrap(), b"secret action");
        assert_eq!(envelope.open(&recipient, b"chain-2"), Err(KemError::AuthenticationFailed));
        let mut tampered = envelope.clone();
        tampered.encrypted_payload[0] ^= 1;
        assert_eq!(tampered.open(&recipient, b"chain-1"), Err(KemError::AuthenticationFailed));
    }
}
