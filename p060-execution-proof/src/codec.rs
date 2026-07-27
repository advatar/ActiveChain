use thiserror::Error;

use crate::model::{Block, ModelError, state_root};
use crate::suite::{
    MAX_PROOF_BYTES, MAX_PUBLIC_INPUT_BYTES, MAX_RECEIPT_BYTES, PROTOCOL_VERSION,
    RECEIPT_CODEC_VERSION, RECEIPT_KIND_EXECUTION, SUITE_ID, VERIFIER_VERSION, program_id,
};

pub const RECEIPT_MAGIC: &[u8; 8] = b"P060RCP1";
const PUBLIC_INPUT_MAGIC: &[u8; 8] = b"P060PUB1";
const PUBLIC_INPUT_CODEC_VERSION: u16 = 1;
const FIXED_HEADER_LEN: usize = 228;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("receipt exceeds the {max}-byte limit: {actual} bytes")]
    ReceiptTooLarge { actual: usize, max: usize },
    #[error("proof exceeds the {max}-byte limit: {actual} bytes")]
    ProofTooLarge { actual: usize, max: usize },
    #[error("public inputs exceed the {max}-byte limit: {actual} bytes")]
    PublicInputsTooLarge { actual: usize, max: usize },
    #[error("malformed receipt: {0}")]
    Malformed(&'static str),
    #[error("receipt binding mismatch: {0}")]
    Binding(&'static str),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReceiptHeader {
    pub codec_version: u16,
    pub receipt_kind: u16,
    pub protocol_version: u32,
    pub verifier_version: u32,
    pub suite_id: u32,
    pub flags: u32,
    pub program_id: [u8; 48],
    pub pre_state_root: [u8; 48],
    pub block_id: [u8; 48],
    pub post_state_root: [u8; 48],
}

impl ReceiptHeader {
    pub fn for_execution(
        pre_state: u64,
        post_state: u64,
        block: &Block,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            codec_version: RECEIPT_CODEC_VERSION,
            receipt_kind: RECEIPT_KIND_EXECUTION,
            protocol_version: PROTOCOL_VERSION,
            verifier_version: VERIFIER_VERSION,
            suite_id: SUITE_ID,
            flags: 0,
            program_id: program_id(),
            pre_state_root: state_root(pre_state)?,
            block_id: block.id()?,
            post_state_root: state_root(post_state)?,
        })
    }

    pub fn validate_bindings(
        &self,
        pre_state: u64,
        post_state: u64,
        block: &Block,
    ) -> Result<(), CodecError> {
        if self.flags != 0 {
            return Err(CodecError::Malformed("non-zero flags"));
        }
        if self.program_id != program_id() {
            return Err(CodecError::Binding("program identity"));
        }
        if self.pre_state_root != state_root(pre_state)? {
            return Err(CodecError::Binding("pre-state root"));
        }
        if self.block_id != block.id()? {
            return Err(CodecError::Binding("canonical block"));
        }
        if self.post_state_root != state_root(post_state)? {
            return Err(CodecError::Binding("post-state root"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Receipt {
    pub header: ReceiptHeader,
    pub pre_state: u64,
    pub post_state: u64,
    pub block: Block,
    pub proof: Vec<u8>,
}

impl Receipt {
    pub fn new(
        header: ReceiptHeader,
        pre_state: u64,
        post_state: u64,
        block: Block,
        proof: Vec<u8>,
    ) -> Result<Self, CodecError> {
        let result = Self {
            header,
            pre_state,
            post_state,
            block,
            proof,
        };
        result.validate_structure()?;
        Ok(result)
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate_structure()?;
        let public_inputs = self.encode_public_inputs()?;
        let total = FIXED_HEADER_LEN
            .checked_add(public_inputs.len())
            .and_then(|n| n.checked_add(self.proof.len()))
            .ok_or(CodecError::Malformed("length overflow"))?;
        if total > MAX_RECEIPT_BYTES {
            return Err(CodecError::ReceiptTooLarge {
                actual: total,
                max: MAX_RECEIPT_BYTES,
            });
        }

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(RECEIPT_MAGIC);
        out.extend_from_slice(&self.header.codec_version.to_be_bytes());
        out.extend_from_slice(&self.header.receipt_kind.to_be_bytes());
        out.extend_from_slice(&self.header.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.header.verifier_version.to_be_bytes());
        out.extend_from_slice(&self.header.suite_id.to_be_bytes());
        out.extend_from_slice(&self.header.flags.to_be_bytes());
        out.extend_from_slice(&self.header.program_id);
        out.extend_from_slice(&self.header.pre_state_root);
        out.extend_from_slice(&self.header.block_id);
        out.extend_from_slice(&self.header.post_state_root);
        out.extend_from_slice(&(public_inputs.len() as u32).to_be_bytes());
        out.extend_from_slice(&(self.proof.len() as u32).to_be_bytes());
        debug_assert_eq!(FIXED_HEADER_LEN, out.len());
        out.extend_from_slice(&public_inputs);
        out.extend_from_slice(&self.proof);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(CodecError::ReceiptTooLarge {
                actual: bytes.len(),
                max: MAX_RECEIPT_BYTES,
            });
        }
        if bytes.len() < FIXED_HEADER_LEN {
            return Err(CodecError::Malformed("short fixed header"));
        }
        let mut d = Decoder::new(bytes);
        if d.take(8)? != RECEIPT_MAGIC {
            return Err(CodecError::Malformed("wrong receipt magic"));
        }
        let header = ReceiptHeader {
            codec_version: d.u16()?,
            receipt_kind: d.u16()?,
            protocol_version: d.u32()?,
            verifier_version: d.u32()?,
            suite_id: d.u32()?,
            flags: d.u32()?,
            program_id: d.array48()?,
            pre_state_root: d.array48()?,
            block_id: d.array48()?,
            post_state_root: d.array48()?,
        };
        if header.codec_version != RECEIPT_CODEC_VERSION {
            return Err(CodecError::Malformed("unknown receipt codec version"));
        }
        if header.flags != 0 {
            return Err(CodecError::Malformed("non-zero flags"));
        }
        let public_len = d.u32()? as usize;
        let proof_len = d.u32()? as usize;
        if public_len > MAX_PUBLIC_INPUT_BYTES {
            return Err(CodecError::PublicInputsTooLarge {
                actual: public_len,
                max: MAX_PUBLIC_INPUT_BYTES,
            });
        }
        if proof_len > MAX_PROOF_BYTES {
            return Err(CodecError::ProofTooLarge {
                actual: proof_len,
                max: MAX_PROOF_BYTES,
            });
        }
        let expected_total = FIXED_HEADER_LEN
            .checked_add(public_len)
            .and_then(|n| n.checked_add(proof_len))
            .ok_or(CodecError::Malformed("length overflow"))?;
        if bytes.len() != expected_total {
            return Err(CodecError::Malformed("wrong length or trailing bytes"));
        }
        let public_bytes = d.take(public_len)?;
        let proof = d.take(proof_len)?.to_vec();
        if !d.is_finished() {
            return Err(CodecError::Malformed("trailing bytes"));
        }
        let (pre_state, post_state, block) = Self::decode_public_inputs(public_bytes)?;
        Ok(Self {
            header,
            pre_state,
            post_state,
            block,
            proof,
        })
    }

    fn validate_structure(&self) -> Result<(), CodecError> {
        if self.proof.is_empty() {
            return Err(CodecError::Malformed("empty proof"));
        }
        if self.proof.len() > MAX_PROOF_BYTES {
            return Err(CodecError::ProofTooLarge {
                actual: self.proof.len(),
                max: MAX_PROOF_BYTES,
            });
        }
        self.block.validate()?;
        self.header
            .validate_bindings(self.pre_state, self.post_state, &self.block)
    }

    fn encode_public_inputs(&self) -> Result<Vec<u8>, CodecError> {
        let block = self.block.encode()?;
        let mut out = Vec::with_capacity(32 + block.len());
        out.extend_from_slice(PUBLIC_INPUT_MAGIC);
        out.extend_from_slice(&PUBLIC_INPUT_CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&self.pre_state.to_be_bytes());
        out.extend_from_slice(&self.post_state.to_be_bytes());
        out.extend_from_slice(&(block.len() as u32).to_be_bytes());
        out.extend_from_slice(&block);
        if out.len() > MAX_PUBLIC_INPUT_BYTES {
            return Err(CodecError::PublicInputsTooLarge {
                actual: out.len(),
                max: MAX_PUBLIC_INPUT_BYTES,
            });
        }
        Ok(out)
    }

    fn decode_public_inputs(bytes: &[u8]) -> Result<(u64, u64, Block), CodecError> {
        let mut d = Decoder::new(bytes);
        if d.take(8)? != PUBLIC_INPUT_MAGIC {
            return Err(CodecError::Malformed("wrong public-input magic"));
        }
        if d.u16()? != PUBLIC_INPUT_CODEC_VERSION {
            return Err(CodecError::Malformed("unknown public-input codec version"));
        }
        if d.u16()? != 0 {
            return Err(CodecError::Malformed("non-zero public-input reserved bits"));
        }
        let pre_state = d.u64()?;
        let post_state = d.u64()?;
        let block_len = d.u32()? as usize;
        let block = Block::decode(d.take(block_len)?)?;
        if !d.is_finished() {
            return Err(CodecError::Malformed("trailing public-input bytes"));
        }
        Ok((pre_state, post_state, block))
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(CodecError::Malformed("length overflow"))?;
        let result = self
            .bytes
            .get(self.pos..end)
            .ok_or(CodecError::Malformed("unexpected end of input"))?;
        self.pos = end;
        Ok(result)
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array48(&mut self) -> Result<[u8; 48], CodecError> {
        Ok(self.take(48)?.try_into().unwrap())
    }

    fn is_finished(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Action;

    fn fake_receipt() -> Receipt {
        let block = Block::new(vec![Action::add(3)]).unwrap();
        let post = block.execute(2).unwrap();
        let header = ReceiptHeader::for_execution(2, post, &block).unwrap();
        Receipt::new(header, 2, post, block, vec![7, 8, 9]).unwrap()
    }

    #[test]
    fn strict_round_trip() {
        let receipt = fake_receipt();
        let encoded = receipt.encode().unwrap();
        assert_eq!(receipt, Receipt::decode(&encoded).unwrap());
    }

    #[test]
    fn trailing_and_reserved_bytes_are_rejected() {
        let mut trailing = fake_receipt().encode().unwrap();
        trailing.push(0);
        assert!(Receipt::decode(&trailing).is_err());

        let mut changed_program = fake_receipt().encode().unwrap();
        changed_program[28] ^= 1; // program identity starts at byte 28.
        assert!(Receipt::decode(&changed_program).is_ok());

        let mut reserved = fake_receipt().encode().unwrap();
        reserved[27] = 1; // flags occupy bytes 24..28.
        assert!(Receipt::decode(&reserved).is_err());
    }
}
