use serde::{Deserialize, Serialize};
use thiserror::Error;
use winterfell::math::{StarkField, fields::f64::BaseElement};

use crate::hash::boundary_hash;

pub const MAX_ACTIONS: usize = 1024;
pub const FIELD_MODULUS: u64 = BaseElement::MODULUS;

const BLOCK_MAGIC: &[u8; 8] = b"P060BLK1";
const BLOCK_CODEC_VERSION: u16 = 1;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum ModelError {
    #[error("state or operand {0} is not canonical for the suite field")]
    NonCanonicalField(u64),
    #[error("block contains {actual} actions; maximum is {max}")]
    TooManyActions { actual: usize, max: usize },
    #[error("unknown opcode {0}")]
    UnknownOpcode(u8),
    #[error("malformed block: {0}")]
    MalformedBlock(&'static str),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "lowercase")]
pub enum Opcode {
    Add = 0,
    Mul = 1,
}

impl TryFrom<u8> for Opcode {
    type Error = ModelError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Add),
            1 => Ok(Self::Mul),
            other => Err(ModelError::UnknownOpcode(other)),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub opcode: Opcode,
    pub operand: u64,
}

impl Action {
    pub const fn add(operand: u64) -> Self {
        Self {
            opcode: Opcode::Add,
            operand,
        }
    }

    pub const fn mul(operand: u64) -> Self {
        Self {
            opcode: Opcode::Mul,
            operand,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        canonical_field(self.operand).map(|_| ())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub actions: Vec<Action>,
}

impl Block {
    pub fn new(actions: Vec<Action>) -> Result<Self, ModelError> {
        let block = Self { actions };
        block.validate()?;
        Ok(block)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.actions.len() > MAX_ACTIONS {
            return Err(ModelError::TooManyActions {
                actual: self.actions.len(),
                max: MAX_ACTIONS,
            });
        }
        for action in &self.actions {
            action.validate()?;
        }
        Ok(())
    }

    pub fn execute(&self, pre_state: u64) -> Result<u64, ModelError> {
        self.validate()?;
        let mut state = canonical_field(pre_state)?;
        for action in &self.actions {
            let operand = canonical_field(action.operand)?;
            state = match action.opcode {
                Opcode::Add => state + operand,
                Opcode::Mul => state * operand,
            };
        }
        Ok(state.as_int())
    }

    /// The one and only accepted canonical block encoding.
    pub fn encode(&self) -> Result<Vec<u8>, ModelError> {
        self.validate()?;
        let mut out = Vec::with_capacity(16 + self.actions.len() * 16);
        out.extend_from_slice(BLOCK_MAGIC);
        out.extend_from_slice(&BLOCK_CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&(self.actions.len() as u32).to_be_bytes());
        for action in &self.actions {
            out.push(action.opcode as u8);
            out.extend_from_slice(&[0; 7]);
            out.extend_from_slice(&action.operand.to_be_bytes());
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ModelError> {
        if bytes.len() < 16 {
            return Err(ModelError::MalformedBlock("short header"));
        }
        if &bytes[..8] != BLOCK_MAGIC {
            return Err(ModelError::MalformedBlock("wrong magic"));
        }
        if u16::from_be_bytes(bytes[8..10].try_into().unwrap()) != BLOCK_CODEC_VERSION {
            return Err(ModelError::MalformedBlock("unknown codec version"));
        }
        if bytes[10..12] != [0, 0] {
            return Err(ModelError::MalformedBlock("non-zero reserved bits"));
        }
        let count = u32::from_be_bytes(bytes[12..16].try_into().unwrap()) as usize;
        if count > MAX_ACTIONS {
            return Err(ModelError::TooManyActions {
                actual: count,
                max: MAX_ACTIONS,
            });
        }
        let expected = 16_usize
            .checked_add(
                count
                    .checked_mul(16)
                    .ok_or(ModelError::MalformedBlock("length overflow"))?,
            )
            .ok_or(ModelError::MalformedBlock("length overflow"))?;
        if bytes.len() != expected {
            return Err(ModelError::MalformedBlock("wrong length or trailing bytes"));
        }
        let mut actions = Vec::with_capacity(count);
        for chunk in bytes[16..].chunks_exact(16) {
            let opcode = Opcode::try_from(chunk[0])?;
            if chunk[1..8] != [0; 7] {
                return Err(ModelError::MalformedBlock("non-zero action reserved bits"));
            }
            let operand = u64::from_be_bytes(chunk[8..16].try_into().unwrap());
            let action = Action { opcode, operand };
            action.validate()?;
            actions.push(action);
        }
        Self::new(actions)
    }

    pub fn id(&self) -> Result<[u8; 48], ModelError> {
        Ok(boundary_hash(b"canonical-block", &self.encode()?))
    }
}

pub fn state_root(state: u64) -> Result<[u8; 48], ModelError> {
    canonical_field(state)?;
    Ok(boundary_hash(b"state-root", &state.to_be_bytes()))
}

pub fn canonical_field(value: u64) -> Result<BaseElement, ModelError> {
    if value >= FIELD_MODULUS {
        return Err(ModelError::NonCanonicalField(value));
    }
    Ok(BaseElement::new(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_round_trip_and_trailing_byte_rejection() {
        let block = Block::new(vec![Action::add(2), Action::mul(9)]).unwrap();
        let encoded = block.encode().unwrap();
        assert_eq!(block, Block::decode(&encoded).unwrap());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(Block::decode(&trailing).is_err());
    }

    #[test]
    fn execution_uses_field_arithmetic() {
        let block = Block::new(vec![Action::add(2), Action::mul(9)]).unwrap();
        assert_eq!(63, block.execute(5).unwrap());
        let wrap = Block::new(vec![Action::add(1)]).unwrap();
        assert_eq!(0, wrap.execute(FIELD_MODULUS - 1).unwrap());
    }
}
