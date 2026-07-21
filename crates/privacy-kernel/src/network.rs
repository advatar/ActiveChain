use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{ChainId, Digest384};
use alloc::vec::Vec;

use crate::{MAX_ORDERING_ITEMS, OrderingError};

fn invalid<T>(result: Result<T, OrderingError>) -> Result<T, DecodeError> {
    result.map_err(|_| DecodeError::InvalidValue("invalid protected network message"))
}

/// A canonical commitment to the protected submissions frozen for an ordering round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedSetLock {
    chain_id: ChainId,
    committee_epoch: u64,
    lock_height: u64,
    set_root: Digest384,
    submission_ids: Vec<Digest384>,
}

impl ProtectedSetLock {
    pub const TYPE_TAG: u16 = 0x00b6;

    pub fn new(
        chain_id: ChainId,
        committee_epoch: u64,
        lock_height: u64,
        set_root: Digest384,
        submission_ids: Vec<Digest384>,
    ) -> Result<Self, OrderingError> {
        if committee_epoch == 0
            || set_root == Digest384::ZERO
            || submission_ids.is_empty()
            || submission_ids.len() > MAX_ORDERING_ITEMS
            || submission_ids.contains(&Digest384::ZERO)
            || submission_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(OrderingError::InvalidValue);
        }
        Ok(Self { chain_id, committee_epoch, lock_height, set_root, submission_ids })
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn committee_epoch(&self) -> u64 {
        self.committee_epoch
    }
    pub const fn set_root(&self) -> Digest384 {
        self.set_root
    }
    pub fn submission_ids(&self) -> &[Digest384] {
        &self.submission_ids
    }
}

impl CanonicalEncode for ProtectedSetLock {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.committee_epoch.encode(e)?;
        self.lock_height.encode(e)?;
        self.set_root.encode(e)?;
        e.write_length(self.submission_ids.len(), MAX_ORDERING_ITEMS)?;
        for id in &self.submission_ids {
            id.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for ProtectedSetLock {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(d)?;
        let committee_epoch = u64::decode(d)?;
        let lock_height = u64::decode(d)?;
        let set_root = Digest384::decode(d)?;
        let count = d.read_length(MAX_ORDERING_ITEMS)?;
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            ids.push(Digest384::decode(d)?);
        }
        invalid(Self::new(chain_id, committee_epoch, lock_height, set_root, ids))
    }
}
impl CanonicalType for ProtectedSetLock {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 16 + 48 + 2 + MAX_ORDERING_ITEMS * 48;
}

/// One committee member's threshold-decryption contribution for a locked submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedDecryptionShare {
    chain_id: ChainId,
    committee_epoch: u64,
    set_root: Digest384,
    submission_id: Digest384,
    member: u16,
    share: [u8; 32],
}

impl ProtectedDecryptionShare {
    pub const TYPE_TAG: u16 = 0x00b7;

    pub fn new(
        chain_id: ChainId,
        committee_epoch: u64,
        set_root: Digest384,
        submission_id: Digest384,
        member: u16,
        share: [u8; 32],
    ) -> Result<Self, OrderingError> {
        if committee_epoch == 0
            || set_root == Digest384::ZERO
            || submission_id == Digest384::ZERO
            || share == [0; 32]
        {
            return Err(OrderingError::InvalidValue);
        }
        Ok(Self { chain_id, committee_epoch, set_root, submission_id, member, share })
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn committee_epoch(&self) -> u64 {
        self.committee_epoch
    }
    pub const fn set_root(&self) -> Digest384 {
        self.set_root
    }
    pub const fn member(&self) -> u16 {
        self.member
    }
    pub const fn share(&self) -> &[u8; 32] {
        &self.share
    }
}

impl CanonicalEncode for ProtectedDecryptionShare {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.committee_epoch.encode(e)?;
        self.set_root.encode(e)?;
        self.submission_id.encode(e)?;
        self.member.encode(e)?;
        for byte in self.share {
            byte.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for ProtectedDecryptionShare {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        invalid(Self::new(
            ChainId::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u16::decode(d)?,
            {
                let mut share = [0; 32];
                for byte in &mut share {
                    *byte = u8::decode(d)?;
                }
                share
            },
        ))
    }
}
impl CanonicalType for ProtectedDecryptionShare {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 3 + 8 + 2 + 32;
}

/// The beacon-derived order for every submission in a previously announced lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedOrderedSet {
    chain_id: ChainId,
    committee_epoch: u64,
    set_root: Digest384,
    beacon: Digest384,
    submission_ids: Vec<Digest384>,
}

impl ProtectedOrderedSet {
    pub const TYPE_TAG: u16 = 0x00b8;

    pub fn new(
        chain_id: ChainId,
        committee_epoch: u64,
        set_root: Digest384,
        beacon: Digest384,
        submission_ids: Vec<Digest384>,
    ) -> Result<Self, OrderingError> {
        if committee_epoch == 0
            || set_root == Digest384::ZERO
            || beacon == Digest384::ZERO
            || submission_ids.is_empty()
            || submission_ids.len() > MAX_ORDERING_ITEMS
            || submission_ids.contains(&Digest384::ZERO)
        {
            return Err(OrderingError::InvalidValue);
        }
        for (index, id) in submission_ids.iter().enumerate() {
            if submission_ids[..index].contains(id) {
                return Err(OrderingError::Duplicate);
            }
        }
        Ok(Self { chain_id, committee_epoch, set_root, beacon, submission_ids })
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn committee_epoch(&self) -> u64 {
        self.committee_epoch
    }
    pub const fn set_root(&self) -> Digest384 {
        self.set_root
    }
    pub fn submission_ids(&self) -> &[Digest384] {
        &self.submission_ids
    }
}

impl CanonicalEncode for ProtectedOrderedSet {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.committee_epoch.encode(e)?;
        self.set_root.encode(e)?;
        self.beacon.encode(e)?;
        e.write_length(self.submission_ids.len(), MAX_ORDERING_ITEMS)?;
        for id in &self.submission_ids {
            id.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for ProtectedOrderedSet {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(d)?;
        let committee_epoch = u64::decode(d)?;
        let set_root = Digest384::decode(d)?;
        let beacon = Digest384::decode(d)?;
        let count = d.read_length(MAX_ORDERING_ITEMS)?;
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            ids.push(Digest384::decode(d)?);
        }
        invalid(Self::new(chain_id, committee_epoch, set_root, beacon, ids))
    }
}
impl CanonicalType for ProtectedOrderedSet {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 3 + 8 + 2 + MAX_ORDERING_ITEMS * 48;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::vec;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn chain() -> ChainId {
        ChainId::new(digest(1))
    }

    #[test]
    fn protected_network_values_round_trip_and_reject_ambiguity() {
        let lock =
            ProtectedSetLock::new(chain(), 7, 20, digest(2), vec![digest(3), digest(4)]).unwrap();
        let share =
            ProtectedDecryptionShare::new(chain(), 7, digest(2), digest(3), 5, [9; 32]).unwrap();
        let order =
            ProtectedOrderedSet::new(chain(), 7, digest(2), digest(8), vec![digest(4), digest(3)])
                .unwrap();
        assert_eq!(decode_envelope::<ProtectedSetLock>(&encode_envelope(&lock).unwrap()), Ok(lock));
        assert_eq!(
            decode_envelope::<ProtectedDecryptionShare>(&encode_envelope(&share).unwrap()),
            Ok(share)
        );
        assert_eq!(
            decode_envelope::<ProtectedOrderedSet>(&encode_envelope(&order).unwrap()),
            Ok(order)
        );
        assert_eq!(
            ProtectedSetLock::new(chain(), 7, 20, digest(2), vec![digest(4), digest(3)]),
            Err(OrderingError::InvalidValue)
        );
        assert_eq!(
            ProtectedOrderedSet::new(chain(), 7, digest(2), digest(8), vec![digest(3), digest(3)]),
            Err(OrderingError::Duplicate)
        );
    }
}
