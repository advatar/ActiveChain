#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use activechain_protocol_types::{Digest384, QuorumCertificate, ValidatorSet, ValidatorVote};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature, Verifier, VerifyingKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

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
    if Digest384::new(vote_set_root) != certificate.vote_set_root() {
        return Err(VerificationError::VoteSetRootMismatch);
    }
    if validator_set.total_stake() != certificate.total_stake()
        || signer_stake != certificate.signer_stake()
    {
        return Err(VerificationError::StakeMismatch);
    }
    Ok(())
}
