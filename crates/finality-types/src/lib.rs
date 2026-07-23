#![no_std]
#![forbid(unsafe_code)]

//! Canonical execution-proof public inputs and finalized-block headers.

extern crate alloc;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    encode_envelope,
};
use activechain_protocol_types::{
    ChainId, Digest384, MAX_VALIDATORS_PER_EPOCH, QuorumCertificate, ValidatorGenesis,
    ValidatorVote,
};
use activechain_state_tree::StateCommitment;
use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

#[doc(hidden)]
#[must_use]
pub fn commit_parts(domain: &[u8], parts: &[&[u8]]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let mut output = [0; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

/// Exact public inputs that an execution proof must bind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofPublicInputs {
    pub chain_id: ChainId,
    pub epoch: u64,
    pub height: u64,
    pub protocol_revision: u64,
    pub validator_set_root: Digest384,
    pub parent_block_id: Digest384,
    pub pre_state: StateCommitment,
    pub authorization_root: Digest384,
    pub action_root: Digest384,
    pub execution_order_root: Digest384,
    pub total_fees: u128,
    pub pre_supply: u128,
    pub issuance: u128,
    pub burn: u128,
    pub post_supply: u128,
    pub post_state: StateCommitment,
    pub receipt_root: Digest384,
    pub data_availability_commitment: Digest384,
}

impl ProofPublicInputs {
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    #[must_use]
    pub const fn post_state(&self) -> StateCommitment {
        self.post_state
    }
}

impl CanonicalEncode for ProofPublicInputs {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(encoder)?;
        self.epoch.encode(encoder)?;
        self.height.encode(encoder)?;
        self.protocol_revision.encode(encoder)?;
        self.validator_set_root.encode(encoder)?;
        self.parent_block_id.encode(encoder)?;
        self.pre_state.encode(encoder)?;
        self.authorization_root.encode(encoder)?;
        self.action_root.encode(encoder)?;
        self.execution_order_root.encode(encoder)?;
        self.total_fees.encode(encoder)?;
        self.pre_supply.encode(encoder)?;
        self.issuance.encode(encoder)?;
        self.burn.encode(encoder)?;
        self.post_supply.encode(encoder)?;
        self.post_state.encode(encoder)?;
        self.receipt_root.encode(encoder)?;
        self.data_availability_commitment.encode(encoder)
    }
}

impl CanonicalDecode for ProofPublicInputs {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            chain_id: ChainId::decode(decoder)?,
            epoch: u64::decode(decoder)?,
            height: u64::decode(decoder)?,
            protocol_revision: u64::decode(decoder)?,
            validator_set_root: Digest384::decode(decoder)?,
            parent_block_id: Digest384::decode(decoder)?,
            pre_state: StateCommitment::decode(decoder)?,
            authorization_root: Digest384::decode(decoder)?,
            action_root: Digest384::decode(decoder)?,
            execution_order_root: Digest384::decode(decoder)?,
            total_fees: u128::decode(decoder)?,
            pre_supply: u128::decode(decoder)?,
            issuance: u128::decode(decoder)?,
            burn: u128::decode(decoder)?,
            post_supply: u128::decode(decoder)?,
            post_state: StateCommitment::decode(decoder)?,
            receipt_root: Digest384::decode(decoder)?,
            data_availability_commitment: Digest384::decode(decoder)?,
        })
    }
}

impl CanonicalType for ProofPublicInputs {
    const TYPE_TAG: u16 = 0x0078;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        48 + 8 + 8 + 8 + 48 + 48 + 56 + 48 + 48 + 48 + 16 * 5 + 56 + 48 + 48;
}

/// Canonical header whose digest is the only digest validators may certify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedBlockHeader {
    pub inputs: ProofPublicInputs,
    pub proof_statement_commitment: Digest384,
}

impl FinalizedBlockHeader {
    pub fn digest(&self) -> Result<Digest384, EncodeError> {
        Ok(commit_parts(b"ACTIVECHAIN-FINALIZED-BLOCK-HEADER-V1", &[&encode_envelope(self)?]))
    }
}

impl CanonicalEncode for FinalizedBlockHeader {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.inputs.encode(encoder)?;
        self.proof_statement_commitment.encode(encoder)
    }
}

impl CanonicalDecode for FinalizedBlockHeader {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            inputs: ProofPublicInputs::decode(decoder)?,
            proof_statement_commitment: Digest384::decode(decoder)?,
        };
        if value.inputs.protocol_revision == 0
            || value.inputs.validator_set_root == Digest384::ZERO
            || value.proof_statement_commitment == Digest384::ZERO
        {
            return Err(DecodeError::InvalidValue("unbound finalized block header"));
        }
        Ok(value)
    }
}

impl CanonicalType for FinalizedBlockHeader {
    const TYPE_TAG: u16 = 0x0079;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = ProofPublicInputs::MAX_ENCODED_LEN + 48;
}

/// Complete public material required to authenticate one finalized header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalityCertificateBundle {
    header: FinalizedBlockHeader,
    validator_genesis: ValidatorGenesis,
    certificate: QuorumCertificate,
    votes: Vec<ValidatorVote>,
}

impl FinalityCertificateBundle {
    pub const TYPE_TAG: u16 = 0x007a;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = FinalizedBlockHeader::MAX_ENCODED_LEN
        + ValidatorGenesis::MAX_ENCODED_LEN
        + QuorumCertificate::ENCODED_LENGTH
        + 2
        + MAX_VALIDATORS_PER_EPOCH * ValidatorVote::MAX_ENCODED_LEN;

    pub fn new(
        header: FinalizedBlockHeader,
        validator_genesis: ValidatorGenesis,
        certificate: QuorumCertificate,
        votes: Vec<ValidatorVote>,
    ) -> Result<Self, DecodeError> {
        if votes.is_empty() || votes.len() > MAX_VALIDATORS_PER_EPOCH {
            return Err(DecodeError::InvalidValue("finality bundle vote count is out of bounds"));
        }
        Ok(Self { header, validator_genesis, certificate, votes })
    }

    #[must_use]
    pub const fn header(&self) -> FinalizedBlockHeader {
        self.header
    }

    #[must_use]
    pub const fn validator_genesis(&self) -> &ValidatorGenesis {
        &self.validator_genesis
    }

    #[must_use]
    pub const fn certificate(&self) -> &QuorumCertificate {
        &self.certificate
    }

    #[must_use]
    pub fn votes(&self) -> &[ValidatorVote] {
        &self.votes
    }
}

impl CanonicalEncode for FinalityCertificateBundle {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.header.encode(encoder)?;
        self.validator_genesis.encode(encoder)?;
        self.certificate.encode(encoder)?;
        encoder.write_length(self.votes.len(), MAX_VALIDATORS_PER_EPOCH)?;
        for vote in &self.votes {
            vote.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for FinalityCertificateBundle {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let header = FinalizedBlockHeader::decode(decoder)?;
        let validator_genesis = ValidatorGenesis::decode(decoder)?;
        let certificate = QuorumCertificate::decode(decoder)?;
        let count = decoder.read_length(MAX_VALIDATORS_PER_EPOCH)?;
        let mut votes = Vec::with_capacity(count);
        for _ in 0..count {
            votes.push(ValidatorVote::decode(decoder)?);
        }
        Self::new(header, validator_genesis, certificate, votes)
    }
}

impl CanonicalType for FinalityCertificateBundle {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn inputs() -> ProofPublicInputs {
        ProofPublicInputs {
            chain_id: ChainId::new(digest(1)),
            epoch: 2,
            height: 3,
            protocol_revision: 4,
            validator_set_root: digest(5),
            parent_block_id: digest(6),
            pre_state: StateCommitment::new(digest(7), 8),
            authorization_root: digest(9),
            action_root: digest(10),
            execution_order_root: digest(11),
            total_fees: 12,
            pre_supply: 13,
            issuance: 14,
            burn: 15,
            post_supply: 12,
            post_state: StateCommitment::new(digest(16), 17),
            receipt_root: digest(18),
            data_availability_commitment: digest(19),
        }
    }

    #[test]
    fn shared_headers_preserve_exact_schema_and_digest_binding() {
        let header =
            FinalizedBlockHeader { inputs: inputs(), proof_statement_commitment: digest(20) };
        let encoded = encode_envelope(&header).unwrap();
        assert_eq!(decode_envelope::<FinalizedBlockHeader>(&encoded), Ok(header));
        let mut substituted = header;
        substituted.inputs.receipt_root = digest(21);
        assert_ne!(header.digest().unwrap(), substituted.digest().unwrap());

        let mut wrong_version = encoded;
        wrong_version[3] = 2;
        assert!(decode_envelope::<FinalizedBlockHeader>(&wrong_version).is_err());
    }
}
