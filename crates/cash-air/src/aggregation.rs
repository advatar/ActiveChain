use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{ChainId, Digest384};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_CASH_AGGREGATION_CHILDREN: usize = 1024;
pub const GLOBAL_CASH_PARTITION: u16 = u16::MAX;
const PROOF_COMMITMENT_DOMAIN: &[u8] = b"ACTIVECHAIN-CASH-AGGREGATION-PROOF-V1";

#[must_use]
pub fn cash_aggregation_proof_commitment(proof: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(PROOF_COMMITMENT_DOMAIN);
    hasher.update(&(proof.len() as u64).to_be_bytes());
    hasher.update(proof);
    let mut digest = [0_u8; 48];
    hasher.finalize_xof().read(&mut digest);
    Digest384::new(digest)
}

pub fn verify_cash_aggregation(
    statement: &CashAggregationStatementV1,
    child_proofs: &[&[u8]],
) -> Result<(), &'static str> {
    statement.verify()?;
    if child_proofs.len() != statement.children.len()
        || statement.children.iter().zip(child_proofs).any(|(child, proof)| {
            child.proof_commitment != cash_aggregation_proof_commitment(proof)
        })
    {
        return Err("cash aggregation child proof commitment mismatch");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CashAggregationLevel {
    Proof = 0,
    Microbatch = 1,
    Partition = 2,
    CashSlot = 3,
    GlobalTransition = 4,
}

impl CashAggregationLevel {
    const fn child(self) -> Option<Self> {
        match self {
            Self::Proof => None,
            Self::Microbatch => Some(Self::Proof),
            Self::Partition => Some(Self::Microbatch),
            Self::CashSlot => Some(Self::Partition),
            Self::GlobalTransition => Some(Self::CashSlot),
        }
    }
}

impl CanonicalEncode for CashAggregationLevel {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for CashAggregationLevel {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Proof),
            1 => Ok(Self::Microbatch),
            2 => Ok(Self::Partition),
            3 => Ok(Self::CashSlot),
            4 => Ok(Self::GlobalTransition),
            _ => Err(DecodeError::InvalidValue("invalid cash aggregation level")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashAggregationChildV1 {
    level: CashAggregationLevel,
    partition: u16,
    pre_root: Digest384,
    post_root: Digest384,
    proof_commitment: Digest384,
    applied: u32,
    rejected: u32,
    resource_units: u64,
}

impl CashAggregationChildV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        level: CashAggregationLevel,
        partition: u16,
        pre_root: Digest384,
        post_root: Digest384,
        proof_commitment: Digest384,
        applied: u32,
        rejected: u32,
        resource_units: u64,
    ) -> Result<Self, &'static str> {
        if pre_root == Digest384::ZERO
            || post_root == Digest384::ZERO
            || proof_commitment == Digest384::ZERO
            || applied.checked_add(rejected).is_none()
        {
            return Err("invalid cash aggregation child");
        }
        Ok(Self {
            level,
            partition,
            pre_root,
            post_root,
            proof_commitment,
            applied,
            rejected,
            resource_units,
        })
    }

    #[must_use]
    pub const fn proof_commitment(&self) -> Digest384 {
        self.proof_commitment
    }
}

impl CanonicalEncode for CashAggregationChildV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.level.encode(encoder)?;
        self.partition.encode(encoder)?;
        self.pre_root.encode(encoder)?;
        self.post_root.encode(encoder)?;
        self.proof_commitment.encode(encoder)?;
        self.applied.encode(encoder)?;
        self.rejected.encode(encoder)?;
        self.resource_units.encode(encoder)
    }
}

impl CanonicalDecode for CashAggregationChildV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            CashAggregationLevel::decode(decoder)?,
            u16::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u32::decode(decoder)?,
            u32::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(DecodeError::InvalidValue)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashAggregationStatementV1 {
    chain_id: ChainId,
    slot: u64,
    level: CashAggregationLevel,
    partition: u16,
    pre_root: Digest384,
    post_root: Digest384,
    applied: u64,
    rejected: u64,
    resource_units: u64,
    children: Vec<CashAggregationChildV1>,
}

impl CashAggregationStatementV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        slot: u64,
        level: CashAggregationLevel,
        partition: u16,
        pre_root: Digest384,
        post_root: Digest384,
        applied: u64,
        rejected: u64,
        resource_units: u64,
        children: Vec<CashAggregationChildV1>,
    ) -> Result<Self, &'static str> {
        let value = Self {
            chain_id,
            slot,
            level,
            partition,
            pre_root,
            post_root,
            applied,
            rejected,
            resource_units,
            children,
        };
        value.verify()?;
        Ok(value)
    }

    pub fn verify(&self) -> Result<(), &'static str> {
        let child_level = self.level.child().ok_or("proof leaves cannot aggregate children")?;
        if self.children.is_empty() || self.children.len() > MAX_CASH_AGGREGATION_CHILDREN {
            return Err("cash aggregation child count is outside bounds");
        }
        if self.chain_id.digest() == &Digest384::ZERO
            || self.pre_root == Digest384::ZERO
            || self.post_root == Digest384::ZERO
        {
            return Err("cash aggregation roots are unbound");
        }
        if self.children.iter().any(|child| child.level != child_level) {
            return Err("cash aggregation child level mismatch");
        }
        match self.level {
            CashAggregationLevel::Microbatch | CashAggregationLevel::Partition => {
                if self.partition == GLOBAL_CASH_PARTITION
                    || self.children.iter().any(|child| child.partition != self.partition)
                {
                    return Err("cash aggregation partition mismatch");
                }
            }
            CashAggregationLevel::CashSlot => {
                if self.partition != GLOBAL_CASH_PARTITION
                    || self.children.windows(2).any(|pair| pair[0].partition >= pair[1].partition)
                {
                    return Err("cash slot partitions are not canonical");
                }
            }
            CashAggregationLevel::GlobalTransition => {
                if self.partition != GLOBAL_CASH_PARTITION
                    || self.children.iter().any(|child| child.partition != GLOBAL_CASH_PARTITION)
                {
                    return Err("global cash aggregation partition mismatch");
                }
            }
            CashAggregationLevel::Proof => return Err("proof leaves cannot be statements"),
        }
        if self.children[0].pre_root != self.pre_root
            || self.children.last().is_none_or(|child| child.post_root != self.post_root)
            || self.children.windows(2).any(|pair| pair[0].post_root != pair[1].pre_root)
        {
            return Err("cash aggregation root chain is discontinuous");
        }
        let totals = self.children.iter().try_fold((0_u64, 0_u64, 0_u64), |totals, child| {
            Some((
                totals.0.checked_add(u64::from(child.applied))?,
                totals.1.checked_add(u64::from(child.rejected))?,
                totals.2.checked_add(child.resource_units)?,
            ))
        });
        if totals != Some((self.applied, self.rejected, self.resource_units)) {
            return Err("cash aggregation totals mismatch or overflow");
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }

    #[must_use]
    pub fn children(&self) -> &[CashAggregationChildV1] {
        &self.children
    }
}

impl CanonicalEncode for CashAggregationStatementV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(encoder)?;
        self.slot.encode(encoder)?;
        self.level.encode(encoder)?;
        self.partition.encode(encoder)?;
        self.pre_root.encode(encoder)?;
        self.post_root.encode(encoder)?;
        self.applied.encode(encoder)?;
        self.rejected.encode(encoder)?;
        self.resource_units.encode(encoder)?;
        encoder.write_length(self.children.len(), MAX_CASH_AGGREGATION_CHILDREN)?;
        for child in &self.children {
            child.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for CashAggregationStatementV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(decoder)?;
        let slot = u64::decode(decoder)?;
        let level = CashAggregationLevel::decode(decoder)?;
        let partition = u16::decode(decoder)?;
        let pre_root = Digest384::decode(decoder)?;
        let post_root = Digest384::decode(decoder)?;
        let applied = u64::decode(decoder)?;
        let rejected = u64::decode(decoder)?;
        let resource_units = u64::decode(decoder)?;
        let count = decoder.read_length(MAX_CASH_AGGREGATION_CHILDREN)?;
        let mut children = Vec::with_capacity(count);
        for _ in 0..count {
            children.push(CashAggregationChildV1::decode(decoder)?);
        }
        Self::new(
            chain_id,
            slot,
            level,
            partition,
            pre_root,
            post_root,
            applied,
            rejected,
            resource_units,
            children,
        )
        .map_err(DecodeError::InvalidValue)
    }
}

impl CanonicalType for CashAggregationStatementV1 {
    const TYPE_TAG: u16 = 0x01AC;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48
        + 8
        + 1
        + 2
        + 48
        + 48
        + 8
        + 8
        + 8
        + 2
        + MAX_CASH_AGGREGATION_CHILDREN * (1 + 2 + 48 + 48 + 48 + 4 + 4 + 8);
}

#[cfg(test)]
mod tests {
    use activechain_canonical_codec::{decode_envelope, encode_envelope};

    use super::*;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn child(partition: u16, pre: u8, post: u8, proof: &[u8]) -> CashAggregationChildV1 {
        CashAggregationChildV1::new(
            CashAggregationLevel::Proof,
            partition,
            digest(pre),
            digest(post),
            cash_aggregation_proof_commitment(proof),
            1,
            0,
            7,
        )
        .unwrap()
    }

    fn microbatch(children: Vec<CashAggregationChildV1>) -> CashAggregationStatementV1 {
        CashAggregationStatementV1::new(
            ChainId::new(digest(1)),
            9,
            CashAggregationLevel::Microbatch,
            3,
            digest(10),
            digest(12),
            children.len() as u64,
            0,
            children.len() as u64 * 7,
            children,
        )
        .unwrap()
    }

    #[test]
    fn canonical_microbatch_binds_order_roots_totals_and_proofs() {
        let statement =
            microbatch(vec![child(3, 10, 11, b"proof-a"), child(3, 11, 12, b"proof-b")]);
        let encoded = encode_envelope(&statement).unwrap();
        assert_eq!(decode_envelope::<CashAggregationStatementV1>(&encoded), Ok(statement.clone()));
        verify_cash_aggregation(&statement, &[b"proof-a", b"proof-b"]).unwrap();
        assert!(verify_cash_aggregation(&statement, &[b"proof-a", b"substitute"]).is_err());

        let reordered = vec![child(3, 11, 12, b"proof-b"), child(3, 10, 11, b"proof-a")];
        assert!(
            CashAggregationStatementV1::new(
                ChainId::new(digest(1)),
                9,
                CashAggregationLevel::Microbatch,
                3,
                digest(10),
                digest(12),
                2,
                0,
                14,
                reordered,
            )
            .is_err()
        );
        assert_ne!(
            statement.commitment().unwrap(),
            microbatch(vec![child(3, 10, 11, b"proof-c"), child(3, 11, 12, b"proof-b"),])
                .commitment()
                .unwrap()
        );
    }

    #[test]
    fn aggregation_rejects_partition_level_gap_and_total_substitution() {
        let children = vec![child(3, 10, 11, b"proof-a"), child(4, 11, 12, b"proof-b")];
        assert!(
            CashAggregationStatementV1::new(
                ChainId::new(digest(1)),
                9,
                CashAggregationLevel::Microbatch,
                3,
                digest(10),
                digest(12),
                2,
                0,
                14,
                children,
            )
            .is_err()
        );
        let children = vec![child(3, 10, 11, b"proof-a"), child(3, 13, 12, b"proof-b")];
        assert!(
            CashAggregationStatementV1::new(
                ChainId::new(digest(1)),
                9,
                CashAggregationLevel::Microbatch,
                3,
                digest(10),
                digest(12),
                2,
                0,
                14,
                children,
            )
            .is_err()
        );
        let children = vec![child(3, 10, 11, b"proof-a"), child(3, 11, 12, b"proof-b")];
        assert!(
            CashAggregationStatementV1::new(
                ChainId::new(digest(1)),
                9,
                CashAggregationLevel::Microbatch,
                3,
                digest(10),
                digest(12),
                3,
                0,
                14,
                children,
            )
            .is_err()
        );
    }

    #[test]
    fn all_four_aggregation_levels_enforce_canonical_partition_ownership() {
        let aggregate_child = |level, partition, pre, post, proof: &[u8]| {
            CashAggregationChildV1::new(
                level,
                partition,
                digest(pre),
                digest(post),
                cash_aggregation_proof_commitment(proof),
                1,
                0,
                7,
            )
            .unwrap()
        };
        let partition = CashAggregationStatementV1::new(
            ChainId::new(digest(1)),
            9,
            CashAggregationLevel::Partition,
            3,
            digest(10),
            digest(12),
            1,
            0,
            7,
            vec![aggregate_child(CashAggregationLevel::Microbatch, 3, 10, 12, b"microbatch")],
        )
        .unwrap();
        verify_cash_aggregation(&partition, &[b"microbatch"]).unwrap();

        let slot = CashAggregationStatementV1::new(
            ChainId::new(digest(1)),
            9,
            CashAggregationLevel::CashSlot,
            GLOBAL_CASH_PARTITION,
            digest(10),
            digest(14),
            2,
            0,
            14,
            vec![
                aggregate_child(CashAggregationLevel::Partition, 3, 10, 12, b"partition-3"),
                aggregate_child(CashAggregationLevel::Partition, 4, 12, 14, b"partition-4"),
            ],
        )
        .unwrap();
        verify_cash_aggregation(&slot, &[b"partition-3", b"partition-4"]).unwrap();

        let global = CashAggregationStatementV1::new(
            ChainId::new(digest(1)),
            9,
            CashAggregationLevel::GlobalTransition,
            GLOBAL_CASH_PARTITION,
            digest(10),
            digest(14),
            1,
            0,
            7,
            vec![aggregate_child(
                CashAggregationLevel::CashSlot,
                GLOBAL_CASH_PARTITION,
                10,
                14,
                b"slot",
            )],
        )
        .unwrap();
        verify_cash_aggregation(&global, &[b"slot"]).unwrap();
    }
}
