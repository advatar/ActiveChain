use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{ChainId, CryptoSuiteId, Digest384, PrincipalId};
use alloc::vec::Vec;

pub const MAX_COMMITTEE_MEMBERS: usize = 64;
pub const MAX_ORDERING_ITEMS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderingError {
    InvalidValue,
    NonCanonicalOrder,
    WrongChain,
    WrongEpoch,
    Expired,
    Duplicate,
    QueueFull,
    SetLocked,
    SetNotLocked,
    ForcedInclusionOverdue,
    Encoding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CommitteeKind {
    Decryption = 1,
    Beacon = 2,
}

impl CanonicalEncode for CommitteeKind {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}

impl CanonicalDecode for CommitteeKind {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            1 => Ok(Self::Decryption),
            2 => Ok(Self::Beacon),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "CommitteeKind", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedCommittee {
    chain_id: ChainId,
    kind: CommitteeKind,
    epoch: u64,
    members: Vec<PrincipalId>,
    threshold: u16,
    activation_height: u64,
    retirement_height: u64,
    key_root: Digest384,
}

impl ProtectedCommittee {
    pub const TYPE_TAG: u16 = 0x00ac;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        kind: CommitteeKind,
        epoch: u64,
        members: Vec<PrincipalId>,
        threshold: u16,
        activation_height: u64,
        retirement_height: u64,
        key_root: Digest384,
    ) -> Result<Self, OrderingError> {
        if epoch == 0
            || members.is_empty()
            || members.len() > MAX_COMMITTEE_MEMBERS
            || usize::from(threshold) > members.len()
            || threshold == 0
            || activation_height >= retirement_height
            || key_root == Digest384::ZERO
        {
            return Err(OrderingError::InvalidValue);
        }
        if members.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(OrderingError::NonCanonicalOrder);
        }
        Ok(Self {
            chain_id,
            kind,
            epoch,
            members,
            threshold,
            activation_height,
            retirement_height,
            key_root,
        })
    }

    #[must_use]
    pub fn active_at(&self, height: u64) -> bool {
        self.activation_height <= height && height < self.retirement_height
    }
}

impl CanonicalEncode for ProtectedCommittee {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.kind.encode(e)?;
        self.epoch.encode(e)?;
        e.write_length(self.members.len(), MAX_COMMITTEE_MEMBERS)?;
        for member in &self.members {
            member.encode(e)?;
        }
        self.threshold.encode(e)?;
        self.activation_height.encode(e)?;
        self.retirement_height.encode(e)?;
        self.key_root.encode(e)
    }
}

impl CanonicalDecode for ProtectedCommittee {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain = ChainId::decode(d)?;
        let kind = CommitteeKind::decode(d)?;
        let epoch = u64::decode(d)?;
        let count = d.read_length(MAX_COMMITTEE_MEMBERS)?;
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            members.push(PrincipalId::decode(d)?);
        }
        Self::new(
            chain,
            kind,
            epoch,
            members,
            u16::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid protected committee"))
    }
}

impl CanonicalType for ProtectedCommittee {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 1 + 8 + 1 + MAX_COMMITTEE_MEMBERS * 48 + 2 + 16 + 48;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedEnvelope {
    chain_id: ChainId,
    submission_id: Digest384,
    kem_suite: CryptoSuiteId,
    committee_epoch: u64,
    recipient_set_root: Digest384,
    ciphertext_commitment: Digest384,
    payload_commitment: Digest384,
    fee_commitment: Digest384,
    submitted_at: u64,
    valid_until: u64,
    force_include_by: u64,
}

impl ProtectedEnvelope {
    pub const TYPE_TAG: u16 = 0x00ad;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        submission_id: Digest384,
        kem_suite: CryptoSuiteId,
        committee_epoch: u64,
        recipient_set_root: Digest384,
        ciphertext_commitment: Digest384,
        payload_commitment: Digest384,
        fee_commitment: Digest384,
        submitted_at: u64,
        valid_until: u64,
        force_include_by: u64,
    ) -> Result<Self, OrderingError> {
        if submission_id == Digest384::ZERO
            || kem_suite != CryptoSuiteId::ML_KEM_768
            || committee_epoch == 0
            || recipient_set_root == Digest384::ZERO
            || ciphertext_commitment == Digest384::ZERO
            || payload_commitment == Digest384::ZERO
            || fee_commitment == Digest384::ZERO
            || submitted_at > force_include_by
            || force_include_by > valid_until
        {
            return Err(OrderingError::InvalidValue);
        }
        Ok(Self {
            chain_id,
            submission_id,
            kem_suite,
            committee_epoch,
            recipient_set_root,
            ciphertext_commitment,
            payload_commitment,
            fee_commitment,
            submitted_at,
            valid_until,
            force_include_by,
        })
    }
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    #[must_use]
    pub const fn submission_id(&self) -> Digest384 {
        self.submission_id
    }
    #[must_use]
    pub const fn committee_epoch(&self) -> u64 {
        self.committee_epoch
    }
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }
    #[must_use]
    pub const fn force_include_by(&self) -> u64 {
        self.force_include_by
    }
}

impl CanonicalEncode for ProtectedEnvelope {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.submission_id.encode(e)?;
        self.kem_suite.encode(e)?;
        self.committee_epoch.encode(e)?;
        self.recipient_set_root.encode(e)?;
        self.ciphertext_commitment.encode(e)?;
        self.payload_commitment.encode(e)?;
        self.fee_commitment.encode(e)?;
        self.submitted_at.encode(e)?;
        self.valid_until.encode(e)?;
        self.force_include_by.encode(e)
    }
}

impl CanonicalDecode for ProtectedEnvelope {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            CryptoSuiteId::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid protected envelope"))
    }
}

impl CanonicalType for ProtectedEnvelope {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 6 + 6 + 8 * 4;
}

#[derive(Clone, Copy)]
struct OrderTranscript {
    lock_root: Digest384,
    beacon: Digest384,
    submission_id: Digest384,
}
impl CanonicalEncode for OrderTranscript {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.lock_root.encode(e)?;
        self.beacon.encode(e)?;
        self.submission_id.encode(e)
    }
}
impl CanonicalDecode for OrderTranscript {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            lock_root: Digest384::decode(d)?,
            beacon: Digest384::decode(d)?,
            submission_id: Digest384::decode(d)?,
        })
    }
}
impl CanonicalType for OrderTranscript {
    const TYPE_TAG: u16 = 0x00ae;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 144;
}

/// In-memory reference scheduler with independent public and protected lanes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedOrdering {
    chain_id: ChainId,
    committee_epoch: u64,
    public_lane: Vec<Digest384>,
    protected_lane: Vec<ProtectedEnvelope>,
    locked: bool,
}

impl ProtectedOrdering {
    #[must_use]
    pub const fn new(chain_id: ChainId, committee_epoch: u64) -> Self {
        Self {
            chain_id,
            committee_epoch,
            public_lane: Vec::new(),
            protected_lane: Vec::new(),
            locked: false,
        }
    }
    pub fn submit_public(&mut self, id: Digest384) -> Result<(), OrderingError> {
        if id == Digest384::ZERO || self.public_lane.contains(&id) {
            return Err(OrderingError::Duplicate);
        }
        if self.public_lane.len() >= MAX_ORDERING_ITEMS {
            return Err(OrderingError::QueueFull);
        }
        self.public_lane.push(id);
        Ok(())
    }
    pub fn submit_protected(
        &mut self,
        envelope: ProtectedEnvelope,
        height: u64,
    ) -> Result<(), OrderingError> {
        if self.locked {
            return Err(OrderingError::SetLocked);
        }
        if envelope.chain_id() != self.chain_id {
            return Err(OrderingError::WrongChain);
        }
        if envelope.committee_epoch() != self.committee_epoch {
            return Err(OrderingError::WrongEpoch);
        }
        if height > envelope.valid_until() {
            return Err(OrderingError::Expired);
        }
        if self.protected_lane.iter().any(|item| item.submission_id() == envelope.submission_id()) {
            return Err(OrderingError::Duplicate);
        }
        if self.protected_lane.len() >= MAX_ORDERING_ITEMS {
            return Err(OrderingError::QueueFull);
        }
        self.protected_lane.push(envelope);
        Ok(())
    }
    /// Locks commitments first, then derives order from the later beacon.
    pub fn lock_and_order(
        &mut self,
        height: u64,
        beacon: Digest384,
    ) -> Result<Vec<Digest384>, OrderingError> {
        if self.locked {
            return Err(OrderingError::SetLocked);
        }
        if beacon == Digest384::ZERO {
            return Err(OrderingError::InvalidValue);
        }
        if self.protected_lane.iter().any(|item| height > item.force_include_by()) {
            return Err(OrderingError::ForcedInclusionOverdue);
        }
        self.protected_lane.sort_by_key(|item| item.submission_id());
        let lock_root = protected_lock_root(&self.protected_lane)?;
        let mut keyed = self
            .protected_lane
            .iter()
            .map(|item| {
                let transcript =
                    OrderTranscript { lock_root, beacon, submission_id: item.submission_id() };
                commit(DomainTag::PROTECTED_ORDER_KEY, &transcript)
                    .map(|key| (key, item.submission_id()))
                    .map_err(|_| OrderingError::Encoding)
            })
            .collect::<Result<Vec<_>, _>>()?;
        keyed.sort_by_key(|pair| pair.0);
        self.locked = true;
        Ok(keyed.into_iter().map(|pair| pair.1).collect())
    }
    /// Public work is drainable regardless of protected lock/decryption state.
    pub fn drain_public(&mut self) -> Vec<Digest384> {
        core::mem::take(&mut self.public_lane)
    }
    pub fn fail_protected_lane(&mut self) {
        self.protected_lane.clear();
        self.locked = false;
    }
}

fn protected_lock_root(items: &[ProtectedEnvelope]) -> Result<Digest384, OrderingError> {
    #[derive(Clone)]
    struct Lock(Vec<Digest384>);
    impl CanonicalEncode for Lock {
        fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
            e.write_length(self.0.len(), MAX_ORDERING_ITEMS)?;
            for id in &self.0 {
                id.encode(e)?;
            }
            Ok(())
        }
    }
    impl CanonicalDecode for Lock {
        fn decode(_: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            unreachable!()
        }
    }
    impl CanonicalType for Lock {
        const TYPE_TAG: u16 = 0x00af;
        const SCHEMA_VERSION: u16 = 1;
        const MAX_ENCODED_LEN: usize = 2 + MAX_ORDERING_ITEMS * 48;
    }
    commit(
        DomainTag::CANONICAL_VALUE,
        &Lock(items.iter().map(ProtectedEnvelope::submission_id).collect()),
    )
    .map_err(|_| OrderingError::Encoding)
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
    fn envelope(id: u8, deadline: u64) -> ProtectedEnvelope {
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
            deadline,
        )
        .unwrap()
    }

    #[test]
    fn committee_and_envelope_are_canonical_and_pq_only() {
        let committee = ProtectedCommittee::new(
            chain(),
            CommitteeKind::Decryption,
            7,
            vec![PrincipalId::new(digest(2)), PrincipalId::new(digest(3))],
            2,
            10,
            20,
            digest(4),
        )
        .unwrap();
        assert!(committee.active_at(10));
        assert!(!committee.active_at(20));
        assert_eq!(
            decode_envelope::<ProtectedCommittee>(&encode_envelope(&committee).unwrap()),
            Ok(committee)
        );
        let item = envelope(10, 50);
        assert_eq!(
            decode_envelope::<ProtectedEnvelope>(&encode_envelope(&item).unwrap()),
            Ok(item)
        );
        assert_eq!(
            ProtectedEnvelope::new(
                chain(),
                digest(10),
                CryptoSuiteId::ML_DSA_44,
                7,
                digest(2),
                digest(3),
                digest(4),
                digest(5),
                10,
                100,
                50
            ),
            Err(OrderingError::InvalidValue)
        );
    }

    #[test]
    fn post_lock_order_is_deterministic_and_submission_order_independent() {
        let mut first = ProtectedOrdering::new(chain(), 7);
        let mut second = ProtectedOrdering::new(chain(), 7);
        for id in [10, 11, 12] {
            first.submit_protected(envelope(id, 50), 10).unwrap();
        }
        for id in [12, 10, 11] {
            second.submit_protected(envelope(id, 50), 10).unwrap();
        }
        assert_eq!(
            first.lock_and_order(20, digest(90)).unwrap(),
            second.lock_and_order(20, digest(90)).unwrap()
        );
        assert_eq!(first.submit_protected(envelope(13, 50), 20), Err(OrderingError::SetLocked));
    }

    #[test]
    fn forced_inclusion_deadline_fails_closed() {
        let mut ordering = ProtectedOrdering::new(chain(), 7);
        ordering.submit_protected(envelope(10, 15), 10).unwrap();
        assert_eq!(
            ordering.lock_and_order(16, digest(90)),
            Err(OrderingError::ForcedInclusionOverdue)
        );
    }

    #[test]
    fn protected_failure_cannot_block_public_lane() {
        let mut ordering = ProtectedOrdering::new(chain(), 7);
        ordering.submit_public(digest(80)).unwrap();
        ordering.submit_public(digest(81)).unwrap();
        ordering.submit_protected(envelope(10, 50), 10).unwrap();
        ordering.fail_protected_lane();
        assert_eq!(ordering.drain_public(), vec![digest(80), digest(81)]);
    }
}
