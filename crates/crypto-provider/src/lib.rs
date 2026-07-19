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
}
