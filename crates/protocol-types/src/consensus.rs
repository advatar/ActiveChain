//! PQ-bound consensus message types for the first testnet boundary.

extern crate alloc;
use crate::{CryptoSuiteId, Digest384, Epoch, PrincipalId, ProtocolSignature};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use alloc::vec::Vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorVote {
    validator: PrincipalId,
    height: u64,
    round: u64,
    block_digest: Digest384,
    signature: ProtocolSignature,
}

impl ValidatorVote {
    pub const TYPE_TAG: u16 = 0x0064;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 8 + 8 + 48 + ProtocolSignature::MAX_ENCODED_LEN;
    pub fn new(
        validator: PrincipalId,
        height: u64,
        round: u64,
        block_digest: Digest384,
        signature: ProtocolSignature,
    ) -> Result<Self, ValidatorVoteError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(ValidatorVoteError::InvalidConsensusSuite);
        }
        Ok(Self { validator, height, round, block_digest, signature })
    }
    pub const fn validator(&self) -> PrincipalId {
        self.validator
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn round(&self) -> u64 {
        self.round
    }
    pub const fn block_digest(&self) -> Digest384 {
        self.block_digest
    }
    pub const fn signature(&self) -> &ProtocolSignature {
        &self.signature
    }
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(18 + 48 + 8 + 8 + 48);
        payload.extend_from_slice(b"ACTIVECHAIN-VOTE-V1");
        payload.extend_from_slice(self.validator.digest().as_bytes());
        payload.extend_from_slice(&self.height.to_be_bytes());
        payload.extend_from_slice(&self.round.to_be_bytes());
        payload.extend_from_slice(self.block_digest.as_bytes());
        payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorVoteError {
    InvalidConsensusSuite,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ValidatorWeight {
    pub validator: PrincipalId,
    pub stake: u128,
}

pub const MAX_VALIDATORS_PER_EPOCH: usize = 256;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorSet(Vec<ValidatorWeight>);
impl ValidatorSet {
    pub const MAX_ENCODED_LEN: usize = 1 + MAX_VALIDATORS_PER_EPOCH * (48 + 16);
    pub fn new(validators: Vec<ValidatorWeight>) -> Result<Self, ValidatorSetError> {
        if validators.is_empty() || validators.len() > MAX_VALIDATORS_PER_EPOCH {
            return Err(ValidatorSetError::Bounds);
        }
        if validators.iter().any(|v| v.stake == 0) {
            return Err(ValidatorSetError::ZeroStake);
        }
        if validators.windows(2).any(|pair| pair[0].validator >= pair[1].validator) {
            return Err(ValidatorSetError::NotStrictlyOrdered);
        }
        Ok(Self(validators))
    }
    pub fn as_slice(&self) -> &[ValidatorWeight] {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorSetError {
    Bounds,
    ZeroStake,
    NotStrictlyOrdered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochTransition {
    from_epoch: Epoch,
    to_epoch: Epoch,
    activation_height: u64,
    validator_set_root: Digest384,
}
impl EpochTransition {
    pub const TYPE_TAG: u16 = 0x0067;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const ENCODED_LENGTH: usize = 8 + 8 + 8 + 48;
    pub fn new(
        from_epoch: Epoch,
        to_epoch: Epoch,
        activation_height: u64,
        validator_set_root: Digest384,
    ) -> Result<Self, EpochTransitionError> {
        if to_epoch != from_epoch.saturating_add(1) {
            return Err(EpochTransitionError::NonConsecutiveEpochs);
        }
        if activation_height == 0 {
            return Err(EpochTransitionError::ZeroActivationHeight);
        }
        Ok(Self { from_epoch, to_epoch, activation_height, validator_set_root })
    }
    pub const fn from_epoch(&self) -> Epoch {
        self.from_epoch
    }
    pub const fn to_epoch(&self) -> Epoch {
        self.to_epoch
    }
    pub const fn activation_height(&self) -> u64 {
        self.activation_height
    }
    pub const fn validator_set_root(&self) -> Digest384 {
        self.validator_set_root
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochTransitionError {
    NonConsecutiveEpochs,
    ZeroActivationHeight,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumCertificate {
    epoch: Epoch,
    height: u64,
    round: u64,
    block_digest: Digest384,
    vote_set_root: Digest384,
    total_stake: u128,
    signer_stake: u128,
}

impl QuorumCertificate {
    pub const TYPE_TAG: u16 = 0x0065;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const ENCODED_LENGTH: usize = 8 + 8 + 8 + 48 + 48 + 16 + 16;
    pub fn new(
        epoch: Epoch,
        height: u64,
        round: u64,
        block_digest: Digest384,
        vote_set_root: Digest384,
        total_stake: u128,
        signer_stake: u128,
    ) -> Result<Self, QuorumCertificateError> {
        if total_stake == 0 || signer_stake > total_stake {
            return Err(QuorumCertificateError::InvalidStake);
        }
        if signer_stake.checked_mul(3).ok_or(QuorumCertificateError::StakeOverflow)?
            <= total_stake.checked_mul(2).ok_or(QuorumCertificateError::StakeOverflow)?
        {
            return Err(QuorumCertificateError::InsufficientStake);
        }
        Ok(Self { epoch, height, round, block_digest, vote_set_root, total_stake, signer_stake })
    }
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn round(&self) -> u64 {
        self.round
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumCertificateError {
    InvalidStake,
    InsufficientStake,
    StakeOverflow,
}

impl CanonicalEncode for ValidatorVote {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.validator.encode(e)?;
        self.height.encode(e)?;
        self.round.encode(e)?;
        self.block_digest.encode(e)?;
        self.signature.encode(e)
    }
}
impl CanonicalDecode for ValidatorVote {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            ProtocolSignature::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("validator vote requires ML-DSA-44"))
    }
}
impl CanonicalType for ValidatorVote {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}
impl CanonicalEncode for QuorumCertificate {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.epoch.encode(e)?;
        self.height.encode(e)?;
        self.round.encode(e)?;
        self.block_digest.encode(e)?;
        self.vote_set_root.encode(e)?;
        self.total_stake.encode(e)?;
        self.signer_stake.encode(e)
    }
}
impl CanonicalDecode for QuorumCertificate {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid quorum certificate"))
    }
}
impl CanonicalType for QuorumCertificate {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}
impl CanonicalEncode for ValidatorSet {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_length(self.0.len(), MAX_VALIDATORS_PER_EPOCH)?;
        for validator in &self.0 {
            validator.validator.encode(e)?;
            validator.stake.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for ValidatorSet {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let n = d.read_length(MAX_VALIDATORS_PER_EPOCH)?;
        let mut values = Vec::with_capacity(n);
        for _ in 0..n {
            values.push(ValidatorWeight {
                validator: PrincipalId::decode(d)?,
                stake: u128::decode(d)?,
            });
        }
        Self::new(values).map_err(|_| DecodeError::InvalidValue("invalid validator set"))
    }
}
impl CanonicalType for ValidatorSet {
    const TYPE_TAG: u16 = 0x0066;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}
impl CanonicalEncode for EpochTransition {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.from_epoch.encode(e)?;
        self.to_epoch.encode(e)?;
        self.activation_height.encode(e)?;
        self.validator_set_root.encode(e)
    }
}
impl CanonicalDecode for EpochTransition {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(u64::decode(d)?, u64::decode(d)?, u64::decode(d)?, Digest384::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid epoch transition"))
    }
}
impl CanonicalType for EpochTransition {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::vec;
    extern crate alloc;
    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    #[test]
    fn validator_vote_is_round_scoped_and_pq_bound() {
        let vote = ValidatorVote::new(
            PrincipalId::new(digest(1)),
            7,
            2,
            digest(3),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![4; 2420]).unwrap(),
        )
        .unwrap();
        assert_eq!(vote.height(), 7);
        assert_eq!(vote.round(), 2);
        assert_eq!(decode_envelope::<ValidatorVote>(&encode_envelope(&vote).unwrap()), Ok(vote));
    }
    #[test]
    fn validator_vote_rejects_other_pq_signature_suites() {
        let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, vec![4; 3309]).unwrap();
        assert_eq!(
            ValidatorVote::new(PrincipalId::new(digest(1)), 7, 2, digest(3), signature),
            Err(ValidatorVoteError::InvalidConsensusSuite)
        );
    }
    #[test]
    fn quorum_certificate_requires_strict_two_thirds_stake() {
        assert!(QuorumCertificate::new(1, 2, 3, digest(1), digest(2), 10, 7).is_ok());
        assert_eq!(
            QuorumCertificate::new(1, 2, 3, digest(1), digest(2), 10, 6),
            Err(QuorumCertificateError::InsufficientStake)
        );
    }
    #[test]
    fn epoch_transition_requires_consecutive_epochs() {
        let transition = EpochTransition::new(4, 5, 100, digest(9)).unwrap();
        assert_eq!(transition.to_epoch(), 5);
        assert_eq!(
            EpochTransition::new(4, 6, 100, digest(9)),
            Err(EpochTransitionError::NonConsecutiveEpochs)
        );
    }
}
