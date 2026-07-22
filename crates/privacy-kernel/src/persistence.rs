use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{ChainId, Digest384};
use alloc::vec::Vec;

use crate::{
    BondSettlement, MAX_COMMITTEE_MEMBERS, MAX_ORDERING_ITEMS, OrderingError,
    ProtectedDecryptionShare, ProtectedEnvelope, ProtectedOrderedSet, ProtectedSetLock,
};

pub const MAX_PROTECTED_SHARES: usize = MAX_ORDERING_ITEMS * MAX_COMMITTEE_MEMBERS;
pub const MAX_PROTECTED_SETTLEMENTS: usize = 64;
pub const MAX_PROTECTED_REPLAY_BARRIERS: usize = MAX_COMMITTEE_MEMBERS;

/// Complete restart-safe state for one protected-ordering committee epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedStateSnapshot {
    chain_id: ChainId,
    committee_epoch: u64,
    queue: Vec<ProtectedEnvelope>,
    lock: Option<ProtectedSetLock>,
    shares: Vec<ProtectedDecryptionShare>,
    ordered: Option<ProtectedOrderedSet>,
    settlements: Vec<BondSettlement>,
    replay_barriers: Vec<(u16, u64)>,
}

impl ProtectedStateSnapshot {
    pub const TYPE_TAG: u16 = 0x00b9;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        committee_epoch: u64,
        queue: Vec<ProtectedEnvelope>,
        lock: Option<ProtectedSetLock>,
        shares: Vec<ProtectedDecryptionShare>,
        ordered: Option<ProtectedOrderedSet>,
        settlements: Vec<BondSettlement>,
        replay_barriers: Vec<(u16, u64)>,
    ) -> Result<Self, OrderingError> {
        if committee_epoch == 0
            || queue.len() > MAX_ORDERING_ITEMS
            || shares.len() > MAX_PROTECTED_SHARES
            || settlements.len() > MAX_PROTECTED_SETTLEMENTS
            || replay_barriers.len() > MAX_PROTECTED_REPLAY_BARRIERS
        {
            return Err(OrderingError::InvalidValue);
        }
        if queue
            .iter()
            .any(|item| item.chain_id() != chain_id || item.committee_epoch() != committee_epoch)
        {
            return Err(OrderingError::WrongChain);
        }
        for (index, item) in queue.iter().enumerate() {
            if queue[..index].iter().any(|prior| prior.submission_id() == item.submission_id()) {
                return Err(OrderingError::Duplicate);
            }
        }
        if let Some(value) = &lock {
            if value.chain_id() != chain_id || value.committee_epoch() != committee_epoch {
                return Err(OrderingError::WrongEpoch);
            }
            let mut queued_ids: Vec<_> =
                queue.iter().map(ProtectedEnvelope::submission_id).collect();
            queued_ids.sort_unstable();
            if queued_ids != value.submission_ids() {
                return Err(OrderingError::InvalidValue);
            }
        } else if !shares.is_empty() || ordered.is_some() {
            return Err(OrderingError::SetNotLocked);
        }
        for (index, share) in shares.iter().enumerate() {
            let Some(active_lock) = &lock else {
                return Err(OrderingError::SetNotLocked);
            };
            if share.chain_id() != chain_id
                || share.committee_epoch() != committee_epoch
                || share.set_root() != active_lock.set_root()
                || !active_lock.submission_ids().contains(&share.submission_id())
                || share.member() == 0
            {
                return Err(OrderingError::InvalidValue);
            }
            if index > 0
                && (shares[index - 1].submission_id(), shares[index - 1].member())
                    >= (share.submission_id(), share.member())
            {
                return Err(OrderingError::NonCanonicalOrder);
            }
        }
        if let Some(value) = &ordered {
            let Some(active_lock) = &lock else {
                return Err(OrderingError::SetNotLocked);
            };
            let mut ordered_ids = value.submission_ids().to_vec();
            ordered_ids.sort_unstable();
            if value.chain_id() != chain_id
                || value.committee_epoch() != committee_epoch
                || value.set_root() != active_lock.set_root()
                || ordered_ids != active_lock.submission_ids()
            {
                return Err(OrderingError::InvalidValue);
            }
        }
        for (index, settlement) in settlements.iter().enumerate() {
            if settlement.bid_id == Digest384::ZERO
                || settlement.released_bond.checked_add(settlement.slashed_bond).is_none()
                || settlement.released_bond + settlement.slashed_bond == 0
                || (settlement.released_bond > 0 && settlement.slashed_bond > 0)
                || (settlement.slashed_bond > 0 && settlement.fee_paid > 0)
                || settlements[..index].iter().any(|prior| prior.bid_id == settlement.bid_id)
            {
                return Err(OrderingError::InvalidValue);
            }
        }
        for (index, (sender, sequence)) in replay_barriers.iter().copied().enumerate() {
            if sender == 0 || sequence == 0 || index > 0 && replay_barriers[index - 1].0 >= sender {
                return Err(OrderingError::NonCanonicalOrder);
            }
        }
        Ok(Self {
            chain_id,
            committee_epoch,
            queue,
            lock,
            shares,
            ordered,
            settlements,
            replay_barriers,
        })
    }

    pub fn queue(&self) -> &[ProtectedEnvelope] {
        &self.queue
    }
    pub fn lock(&self) -> Option<&ProtectedSetLock> {
        self.lock.as_ref()
    }
    pub fn shares(&self) -> &[ProtectedDecryptionShare] {
        &self.shares
    }
    pub fn ordered(&self) -> Option<&ProtectedOrderedSet> {
        self.ordered.as_ref()
    }
    pub fn settlements(&self) -> &[BondSettlement] {
        &self.settlements
    }
    pub fn replay_barriers(&self) -> &[(u16, u64)] {
        &self.replay_barriers
    }
}

impl CanonicalEncode for ProtectedStateSnapshot {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.committee_epoch.encode(e)?;
        e.write_length(self.queue.len(), MAX_ORDERING_ITEMS)?;
        for item in &self.queue {
            item.encode(e)?;
        }
        self.lock.encode(e)?;
        e.write_length(self.shares.len(), MAX_PROTECTED_SHARES)?;
        for share in &self.shares {
            share.encode(e)?;
        }
        self.ordered.encode(e)?;
        e.write_length(self.settlements.len(), MAX_PROTECTED_SETTLEMENTS)?;
        for value in &self.settlements {
            value.bid_id.encode(e)?;
            value.builder.encode(e)?;
            value.released_bond.encode(e)?;
            value.slashed_bond.encode(e)?;
            value.fee_paid.encode(e)?;
        }
        e.write_length(self.replay_barriers.len(), MAX_PROTECTED_REPLAY_BARRIERS)?;
        for (sender, sequence) in &self.replay_barriers {
            sender.encode(e)?;
            sequence.encode(e)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for ProtectedStateSnapshot {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(d)?;
        let committee_epoch = u64::decode(d)?;
        let queue_count = d.read_length(MAX_ORDERING_ITEMS)?;
        let mut queue = Vec::with_capacity(queue_count);
        for _ in 0..queue_count {
            queue.push(ProtectedEnvelope::decode(d)?);
        }
        let lock = Option::<ProtectedSetLock>::decode(d)?;
        let share_count = d.read_length(MAX_PROTECTED_SHARES)?;
        let mut shares = Vec::with_capacity(share_count);
        for _ in 0..share_count {
            shares.push(ProtectedDecryptionShare::decode(d)?);
        }
        let ordered = Option::<ProtectedOrderedSet>::decode(d)?;
        let settlement_count = d.read_length(MAX_PROTECTED_SETTLEMENTS)?;
        let mut settlements = Vec::with_capacity(settlement_count);
        for _ in 0..settlement_count {
            settlements.push(BondSettlement {
                bid_id: Digest384::decode(d)?,
                builder: activechain_protocol_types::PrincipalId::decode(d)?,
                released_bond: u128::decode(d)?,
                slashed_bond: u128::decode(d)?,
                fee_paid: u128::decode(d)?,
            });
        }
        let replay_count = d.read_length(MAX_PROTECTED_REPLAY_BARRIERS)?;
        let mut replay_barriers = Vec::with_capacity(replay_count);
        for _ in 0..replay_count {
            replay_barriers.push((u16::decode(d)?, u64::decode(d)?));
        }
        Self::new(
            chain_id,
            committee_epoch,
            queue,
            lock,
            shares,
            ordered,
            settlements,
            replay_barriers,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid protected state snapshot"))
    }
}

impl CanonicalType for ProtectedStateSnapshot {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48
        + 8
        + 3
        + MAX_ORDERING_ITEMS * ProtectedEnvelope::MAX_ENCODED_LEN
        + 1
        + ProtectedSetLock::MAX_ENCODED_LEN
        + 3
        + MAX_PROTECTED_SHARES * ProtectedDecryptionShare::MAX_ENCODED_LEN
        + 1
        + ProtectedOrderedSet::MAX_ENCODED_LEN
        + 2
        + MAX_PROTECTED_SETTLEMENTS * (48 * 2 + 16 * 3)
        + 2
        + MAX_PROTECTED_REPLAY_BARRIERS * 10;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use activechain_protocol_types::{CryptoSuiteId, PrincipalId};
    use alloc::vec;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn chain() -> ChainId {
        ChainId::new(digest(1))
    }
    fn envelope(id: u8) -> ProtectedEnvelope {
        ProtectedEnvelope::new(
            chain(),
            digest(id),
            CryptoSuiteId::ML_KEM_768,
            7,
            digest(2),
            digest(id + 20),
            digest(id + 40),
            digest(id + 60),
            10,
            100,
            50,
        )
        .unwrap()
    }
    fn snapshot() -> ProtectedStateSnapshot {
        let root = digest(9);
        ProtectedStateSnapshot::new(
            chain(),
            7,
            vec![envelope(3), envelope(4)],
            Some(ProtectedSetLock::new(chain(), 7, 12, root, vec![digest(3), digest(4)]).unwrap()),
            vec![
                ProtectedDecryptionShare::new(chain(), 7, root, digest(3), 1, [10; 32]).unwrap(),
                ProtectedDecryptionShare::new(chain(), 7, root, digest(4), 1, [11; 32]).unwrap(),
            ],
            Some(
                ProtectedOrderedSet::new(chain(), 7, root, digest(12), vec![digest(4), digest(3)])
                    .unwrap(),
            ),
            vec![BondSettlement {
                bid_id: digest(13),
                builder: PrincipalId::new(digest(14)),
                released_bond: 100,
                slashed_bond: 0,
                fee_paid: 5,
            }],
            vec![(1, 8), (2, 11)],
        )
        .unwrap()
    }

    #[test]
    fn complete_protected_state_round_trips() {
        let state = snapshot();
        assert_eq!(
            decode_envelope::<ProtectedStateSnapshot>(&encode_envelope(&state).unwrap()),
            Ok(state)
        );
    }

    #[test]
    fn snapshot_rejects_inconsistent_lock_shares_order_and_replay() {
        let state = snapshot();
        assert_eq!(state.queue().len(), 2);
        assert_eq!(state.shares().len(), 2);
        assert_eq!(state.settlements().len(), 1);
        assert_eq!(state.replay_barriers(), &[(1, 8), (2, 11)]);
        assert_eq!(
            ProtectedStateSnapshot::new(
                chain(),
                7,
                vec![envelope(3)],
                state.lock().cloned(),
                state.shares().to_vec(),
                state.ordered().cloned(),
                state.settlements().to_vec(),
                vec![(2, 11), (1, 8)],
            ),
            Err(OrderingError::InvalidValue)
        );
        assert_eq!(
            ProtectedStateSnapshot::new(
                chain(),
                7,
                vec![envelope(3), envelope(4)],
                None,
                state.shares().to_vec(),
                None,
                vec![],
                vec![],
            ),
            Err(OrderingError::SetNotLocked)
        );
    }
}
