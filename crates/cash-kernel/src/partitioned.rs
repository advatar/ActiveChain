use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{CoinCellId, Height};

use crate::types::{MAX_TRANSFER_BATCH, MAX_TRANSFER_INPUTS};
use crate::{CashLedger, CashTransferV1, CashTransitionError, CoinTransfer, NativeMoneyError};

/// Maximum number of deterministic Coin Cell partitions in the v1 cash lane.
pub const MAX_CASH_PARTITIONS: u16 = 256;

/// A deterministic execution plan. `parallel` transfers have disjoint input locks; conflicting
/// transfers are retained in canonical batch order in `fallback`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionedCashPlan {
    partitions: u16,
    parallel: Vec<u16>,
    fallback: Vec<u16>,
    locks: Vec<CoinCellId>,
}

impl PartitionedCashPlan {
    pub fn build(batch: &CashTransferV1, partitions: u16) -> Result<Self, NativeMoneyError> {
        if partitions == 0 || partitions > MAX_CASH_PARTITIONS {
            return Err(NativeMoneyError::InvalidInputs);
        }
        let mut locks = Vec::new();
        let mut parallel = Vec::new();
        let mut fallback = Vec::new();
        for (index, transfer) in batch.transfers().iter().enumerate() {
            let requested = transfer_locks(transfer);
            if requested.iter().any(|id| locks.binary_search(id).is_ok()) {
                fallback.push(index as u16);
            } else {
                parallel.push(index as u16);
            }
            for id in requested {
                if let Err(position) = locks.binary_search(&id) {
                    locks.insert(position, id);
                }
            }
        }
        Ok(Self { partitions, parallel, fallback, locks })
    }

    #[must_use]
    pub const fn partitions(&self) -> u16 {
        self.partitions
    }

    #[must_use]
    pub fn parallel(&self) -> &[u16] {
        &self.parallel
    }

    #[must_use]
    pub fn fallback(&self) -> &[u16] {
        &self.fallback
    }

    #[must_use]
    pub fn locks(&self) -> &[CoinCellId] {
        &self.locks
    }

    /// Stable partition mapping over the first two digest bytes.
    #[must_use]
    pub fn partition_for(&self, id: CoinCellId) -> u16 {
        let bytes = id.into_digest();
        let prefix = u16::from_be_bytes([bytes.as_bytes()[0], bytes.as_bytes()[1]]);
        prefix % self.partitions
    }
}

impl CanonicalEncode for PartitionedCashPlan {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.partitions.encode(e)?;
        e.write_length(self.parallel.len(), MAX_TRANSFER_BATCH)?;
        for index in &self.parallel {
            index.encode(e)?;
        }
        e.write_length(self.fallback.len(), MAX_TRANSFER_BATCH)?;
        for index in &self.fallback {
            index.encode(e)?;
        }
        e.write_length(self.locks.len(), MAX_TRANSFER_BATCH * (MAX_TRANSFER_INPUTS + 1))?;
        for lock in &self.locks {
            lock.encode(e)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for PartitionedCashPlan {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let partitions = u16::decode(d)?;
        if partitions == 0 || partitions > MAX_CASH_PARTITIONS {
            return Err(DecodeError::InvalidValue("invalid cash partition count"));
        }
        let parallel_count = d.read_length(MAX_TRANSFER_BATCH)?;
        let mut parallel = Vec::with_capacity(parallel_count);
        for _ in 0..parallel_count {
            parallel.push(u16::decode(d)?);
        }
        let fallback_count = d.read_length(MAX_TRANSFER_BATCH)?;
        let mut fallback = Vec::with_capacity(fallback_count);
        for _ in 0..fallback_count {
            fallback.push(u16::decode(d)?);
        }
        let total = parallel.len() + fallback.len();
        let mut indices = parallel.iter().chain(fallback.iter()).copied().collect::<Vec<_>>();
        indices.sort_unstable();
        if total > MAX_TRANSFER_BATCH
            || parallel.windows(2).any(|pair| pair[0] >= pair[1])
            || fallback.windows(2).any(|pair| pair[0] >= pair[1])
            || indices.iter().enumerate().any(|(expected, index)| usize::from(*index) != expected)
        {
            return Err(DecodeError::InvalidValue("invalid cash execution indices"));
        }
        let lock_count = d.read_length(MAX_TRANSFER_BATCH * (MAX_TRANSFER_INPUTS + 1))?;
        let mut locks = Vec::with_capacity(lock_count);
        for _ in 0..lock_count {
            locks.push(CoinCellId::decode(d)?);
        }
        if locks.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(DecodeError::InvalidValue("cash locks not canonical"));
        }
        Ok(Self { partitions, parallel, fallback, locks })
    }
}

impl CanonicalType for PartitionedCashPlan {
    const TYPE_TAG: u16 = 0x0092;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 2
        + 2
        + MAX_TRANSFER_BATCH * 2
        + 2
        + MAX_TRANSFER_BATCH * 2
        + 2
        + MAX_TRANSFER_BATCH * (MAX_TRANSFER_INPUTS + 1) * 48;
}

/// Evidence returned after atomic partitioned execution. Locks are planning-only and never persist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionedCashReceipt {
    plan: PartitionedCashPlan,
    applied: u16,
    rejected: u16,
}

impl PartitionedCashReceipt {
    #[must_use]
    pub const fn plan(&self) -> &PartitionedCashPlan {
        &self.plan
    }

    #[must_use]
    pub const fn applied(&self) -> u16 {
        self.applied
    }

    #[must_use]
    pub const fn rejected(&self) -> u16 {
        self.rejected
    }
}

impl CanonicalEncode for PartitionedCashReceipt {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.plan.encode(e)?;
        self.applied.encode(e)?;
        self.rejected.encode(e)
    }
}

impl CanonicalDecode for PartitionedCashReceipt {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let plan = PartitionedCashPlan::decode(d)?;
        let applied = u16::decode(d)?;
        let rejected = u16::decode(d)?;
        if usize::from(applied) + usize::from(rejected) != plan.parallel.len() + plan.fallback.len()
        {
            return Err(DecodeError::InvalidValue("invalid cash execution counts"));
        }
        Ok(Self { plan, applied, rejected })
    }
}

impl CanonicalType for PartitionedCashReceipt {
    const TYPE_TAG: u16 = 0x0093;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = PartitionedCashPlan::MAX_ENCODED_LEN + 4;
}

impl CashLedger {
    /// Atomically executes the disjoint lane followed by canonical ordered conflict fallback.
    /// Disjoint transfers commute, while applying each lane in batch order makes the reference
    /// implementation deterministic and directly comparable with serial re-execution.
    pub fn apply_partitioned_batch(
        &mut self,
        batch: &CashTransferV1,
        height: Height,
        partitions: u16,
    ) -> Result<PartitionedCashReceipt, CashTransitionError> {
        let plan =
            PartitionedCashPlan::build(batch, partitions).map_err(CashTransitionError::Invalid)?;
        let mut next = self.clone();
        let mut applied = 0;
        let mut rejected = 0;
        for index in plan.parallel.iter().chain(plan.fallback.iter()) {
            if next.apply_transfer(&batch.transfers()[usize::from(*index)], height).is_ok() {
                applied += 1;
            } else {
                rejected += 1;
            }
        }
        *self = next;
        Ok(PartitionedCashReceipt { plan, applied, rejected })
    }
}

fn transfer_locks(transfer: &CoinTransfer) -> Vec<CoinCellId> {
    let mut locks = transfer.inputs().to_vec();
    let position = locks.binary_search(&transfer.fee_reserve()).unwrap_or_else(|position| position);
    locks.insert(position, transfer.fee_reserve());
    locks
}
