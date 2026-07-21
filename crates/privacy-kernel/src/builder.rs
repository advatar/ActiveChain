use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{ChainId, Digest384, PrincipalId};
use alloc::vec::Vec;

pub const MAX_BUILDER_BIDS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuilderSettlementError {
    InvalidBid,
    WrongAuction,
    Expired,
    Duplicate,
    AuctionFull,
    AlreadyLocked,
    NotLocked,
    AlreadySettled,
    ArithmeticOverflow,
    Encoding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuilderBid {
    chain_id: ChainId,
    epoch: u64,
    protected_set_root: Digest384,
    expected_order_root: Digest384,
    builder: PrincipalId,
    fee_bid: u128,
    bond: u128,
    nonce: u64,
    valid_until: u64,
}

impl BuilderBid {
    pub const TYPE_TAG: u16 = 0x00b0;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        epoch: u64,
        protected_set_root: Digest384,
        expected_order_root: Digest384,
        builder: PrincipalId,
        fee_bid: u128,
        bond: u128,
        nonce: u64,
        valid_until: u64,
    ) -> Result<Self, BuilderSettlementError> {
        if epoch == 0
            || protected_set_root == Digest384::ZERO
            || expected_order_root == Digest384::ZERO
            || fee_bid == 0
            || bond == 0
        {
            return Err(BuilderSettlementError::InvalidBid);
        }
        Ok(Self {
            chain_id,
            epoch,
            protected_set_root,
            expected_order_root,
            builder,
            fee_bid,
            bond,
            nonce,
            valid_until,
        })
    }
    pub fn id(&self) -> Result<Digest384, BuilderSettlementError> {
        commit(DomainTag::CANONICAL_VALUE, self).map_err(|_| BuilderSettlementError::Encoding)
    }
    #[must_use]
    pub const fn builder(&self) -> PrincipalId {
        self.builder
    }
    #[must_use]
    pub const fn fee_bid(&self) -> u128 {
        self.fee_bid
    }
    #[must_use]
    pub const fn bond(&self) -> u128 {
        self.bond
    }
}

impl CanonicalEncode for BuilderBid {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.epoch.encode(e)?;
        self.protected_set_root.encode(e)?;
        self.expected_order_root.encode(e)?;
        self.builder.encode(e)?;
        self.fee_bid.encode(e)?;
        self.bond.encode(e)?;
        self.nonce.encode(e)?;
        self.valid_until.encode(e)
    }
}
impl CanonicalDecode for BuilderBid {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid builder bid"))
    }
}
impl CanonicalType for BuilderBid {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 4 + 16 * 2 + 8 * 3;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuilderOutcome {
    Fulfilled { produced_order_root: Digest384 },
    MissedDeadline,
    InvalidOrder { produced_order_root: Digest384 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BondSettlement {
    pub bid_id: Digest384,
    pub builder: PrincipalId,
    pub released_bond: u128,
    pub slashed_bond: u128,
    pub fee_paid: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuilderAuction {
    chain_id: ChainId,
    epoch: u64,
    protected_set_root: Digest384,
    bids: Vec<BuilderBid>,
    locked: Option<BuilderBid>,
    settlement: Option<BondSettlement>,
    total_bonded: u128,
    total_released: u128,
    total_slashed: u128,
}

impl BuilderAuction {
    pub fn new(
        chain_id: ChainId,
        epoch: u64,
        protected_set_root: Digest384,
    ) -> Result<Self, BuilderSettlementError> {
        if epoch == 0 || protected_set_root == Digest384::ZERO {
            return Err(BuilderSettlementError::WrongAuction);
        }
        Ok(Self {
            chain_id,
            epoch,
            protected_set_root,
            bids: Vec::new(),
            locked: None,
            settlement: None,
            total_bonded: 0,
            total_released: 0,
            total_slashed: 0,
        })
    }
    pub fn submit(&mut self, bid: BuilderBid, height: u64) -> Result<(), BuilderSettlementError> {
        if self.locked.is_some() {
            return Err(BuilderSettlementError::AlreadyLocked);
        }
        if bid.chain_id != self.chain_id
            || bid.epoch != self.epoch
            || bid.protected_set_root != self.protected_set_root
        {
            return Err(BuilderSettlementError::WrongAuction);
        }
        if height > bid.valid_until {
            return Err(BuilderSettlementError::Expired);
        }
        if self.bids.len() >= MAX_BUILDER_BIDS {
            return Err(BuilderSettlementError::AuctionFull);
        }
        if self
            .bids
            .iter()
            .any(|prior| prior.builder == bid.builder || prior.id().ok() == bid.id().ok())
        {
            return Err(BuilderSettlementError::Duplicate);
        }
        self.bids.push(bid);
        Ok(())
    }
    pub fn lock_winner(&mut self) -> Result<BuilderBid, BuilderSettlementError> {
        if self.locked.is_some() {
            return Err(BuilderSettlementError::AlreadyLocked);
        }
        let winner = self
            .bids
            .iter()
            .copied()
            .max_by(|left, right| {
                left.fee_bid.cmp(&right.fee_bid).then_with(|| right.builder.cmp(&left.builder))
            })
            .ok_or(BuilderSettlementError::InvalidBid)?;
        self.total_bonded = winner.bond;
        self.locked = Some(winner);
        Ok(winner)
    }
    pub fn settle(
        &mut self,
        outcome: BuilderOutcome,
    ) -> Result<BondSettlement, BuilderSettlementError> {
        if self.settlement.is_some() {
            return Err(BuilderSettlementError::AlreadySettled);
        }
        let bid = self.locked.ok_or(BuilderSettlementError::NotLocked)?;
        let fulfilled = matches!(outcome, BuilderOutcome::Fulfilled { produced_order_root }
            if produced_order_root == bid.expected_order_root);
        let (released, slashed, fee_paid) =
            if fulfilled { (bid.bond, 0, bid.fee_bid) } else { (0, bid.bond, 0) };
        self.total_released = self
            .total_released
            .checked_add(released)
            .ok_or(BuilderSettlementError::ArithmeticOverflow)?;
        self.total_slashed = self
            .total_slashed
            .checked_add(slashed)
            .ok_or(BuilderSettlementError::ArithmeticOverflow)?;
        let settlement = BondSettlement {
            bid_id: bid.id()?,
            builder: bid.builder,
            released_bond: released,
            slashed_bond: slashed,
            fee_paid,
        };
        self.settlement = Some(settlement);
        self.verify_accounting()?;
        Ok(settlement)
    }
    pub fn verify_accounting(&self) -> Result<(), BuilderSettlementError> {
        if self.total_released.checked_add(self.total_slashed) != Some(self.total_bonded) {
            return Err(BuilderSettlementError::ArithmeticOverflow);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn bid(builder: u8, fee: u128, bond: u128) -> BuilderBid {
        BuilderBid::new(
            ChainId::new(digest(1)),
            7,
            digest(2),
            digest(3),
            PrincipalId::new(digest(builder)),
            fee,
            bond,
            u64::from(builder),
            100,
        )
        .unwrap()
    }
    #[test]
    fn bids_round_trip_and_winner_is_deterministic() {
        let value = bid(10, 50, 100);
        assert_eq!(decode_envelope::<BuilderBid>(&encode_envelope(&value).unwrap()), Ok(value));
        let mut auction = BuilderAuction::new(ChainId::new(digest(1)), 7, digest(2)).unwrap();
        auction.submit(bid(12, 60, 120), 10).unwrap();
        auction.submit(bid(11, 60, 110), 10).unwrap();
        assert_eq!(auction.lock_winner().unwrap().builder(), PrincipalId::new(digest(11)));
    }
    #[test]
    fn fulfilled_release_and_objective_failures_slash_once() {
        let mut success = BuilderAuction::new(ChainId::new(digest(1)), 7, digest(2)).unwrap();
        success.submit(bid(10, 50, 100), 10).unwrap();
        success.lock_winner().unwrap();
        let paid =
            success.settle(BuilderOutcome::Fulfilled { produced_order_root: digest(3) }).unwrap();
        assert_eq!((paid.released_bond, paid.slashed_bond, paid.fee_paid), (100, 0, 50));
        assert_eq!(
            success.settle(BuilderOutcome::MissedDeadline),
            Err(BuilderSettlementError::AlreadySettled)
        );
        let mut failed = BuilderAuction::new(ChainId::new(digest(1)), 7, digest(2)).unwrap();
        failed.submit(bid(10, 50, 100), 10).unwrap();
        failed.lock_winner().unwrap();
        let slashed =
            failed.settle(BuilderOutcome::InvalidOrder { produced_order_root: digest(9) }).unwrap();
        assert_eq!((slashed.released_bond, slashed.slashed_bond, slashed.fee_paid), (0, 100, 0));
    }
}
