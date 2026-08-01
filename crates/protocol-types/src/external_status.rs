//! Finalized mirrors of externally authoritative credential status and transparency roots.

extern crate alloc;
use crate::{ChainId, Digest384, Height, PrincipalId};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_EXTERNAL_STATUS_PUBLISHERS: usize = 16;
pub const MAX_EXTERNAL_STATUS_SNAPSHOTS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalStatusError {
    InvalidIdentity,
    InvalidPublishers,
    InvalidThreshold,
    InvalidValidity,
    InvalidSequence,
    UnauthorizedUpdater,
    PreviousMismatch,
    StableContextMismatch,
    InvalidSourceMigration,
    TooManySnapshots,
    SnapshotsNotOrdered,
    FinalityRollback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalStatusPublisherSetV1 {
    issuer_binding_commitment: Digest384,
    publishers: Vec<PrincipalId>,
    threshold: u16,
    generation: u64,
    previous_set_commitment: Option<Digest384>,
    governance_authorization: Digest384,
    active_from_height: Height,
    active_until_height: Option<Height>,
}
impl ExternalStatusPublisherSetV1 {
    pub const TYPE_TAG: u16 = 0x0156;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        48 + 2 + MAX_EXTERNAL_STATUS_PUBLISHERS * 48 + 2 + 8 + 49 + 48 + 8 + 9;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer_binding: Digest384,
        publishers: Vec<PrincipalId>,
        threshold: u16,
        generation: u64,
        previous: Option<Digest384>,
        governance: Digest384,
        active_from: Height,
        active_until: Option<Height>,
    ) -> Result<Self, ExternalStatusError> {
        if issuer_binding == Digest384::ZERO
            || governance == Digest384::ZERO
            || previous == Some(Digest384::ZERO)
        {
            return Err(ExternalStatusError::InvalidIdentity);
        }
        if publishers.is_empty()
            || publishers.len() > MAX_EXTERNAL_STATUS_PUBLISHERS
            || publishers.iter().any(|p| p.digest() == &Digest384::ZERO)
            || !publishers.windows(2).all(|p| p[0] < p[1])
        {
            return Err(ExternalStatusError::InvalidPublishers);
        }
        if threshold == 0 || usize::from(threshold) > publishers.len() {
            return Err(ExternalStatusError::InvalidThreshold);
        }
        if generation == 0 || (generation == 1) != previous.is_none() {
            return Err(ExternalStatusError::InvalidSequence);
        }
        if active_until.is_some_and(|end| end <= active_from) {
            return Err(ExternalStatusError::InvalidValidity);
        }
        Ok(Self {
            issuer_binding_commitment: issuer_binding,
            publishers,
            threshold,
            generation,
            previous_set_commitment: previous,
            governance_authorization: governance,
            active_from_height: active_from,
            active_until_height: active_until,
        })
    }
    pub fn authorizes(&self, updater: PrincipalId, height: Height) -> bool {
        height >= self.active_from_height
            && self.active_until_height.is_none_or(|end| height < end)
            && self.publishers.binary_search(&updater).is_ok()
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(b"ACTIVECHAIN-EXTERNAL-STATUS-PUBLISHERS-V1", self)
    }
    pub fn validate_successor(&self, next: &Self) -> Result<(), ExternalStatusError> {
        if self.issuer_binding_commitment != next.issuer_binding_commitment {
            return Err(ExternalStatusError::StableContextMismatch);
        }
        if next.generation
            != self.generation.checked_add(1).ok_or(ExternalStatusError::InvalidSequence)?
        {
            return Err(ExternalStatusError::InvalidSequence);
        }
        if next.previous_set_commitment
            != Some(self.commitment().map_err(|_| ExternalStatusError::PreviousMismatch)?)
        {
            return Err(ExternalStatusError::PreviousMismatch);
        }
        Ok(())
    }
}
impl CanonicalEncode for ExternalStatusPublisherSetV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.issuer_binding_commitment.encode(e)?;
        e.write_length(self.publishers.len(), MAX_EXTERNAL_STATUS_PUBLISHERS)?;
        for publisher in &self.publishers {
            publisher.encode(e)?;
        }
        self.threshold.encode(e)?;
        self.generation.encode(e)?;
        self.previous_set_commitment.encode(e)?;
        self.governance_authorization.encode(e)?;
        self.active_from_height.encode(e)?;
        self.active_until_height.encode(e)
    }
}
impl CanonicalDecode for ExternalStatusPublisherSetV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let issuer = Digest384::decode(d)?;
        let count = d.read_length(MAX_EXTERNAL_STATUS_PUBLISHERS)?;
        let mut publishers = Vec::with_capacity(count);
        for _ in 0..count {
            publishers.push(PrincipalId::decode(d)?);
        }
        Self::new(
            issuer,
            publishers,
            u16::decode(d)?,
            u64::decode(d)?,
            Option::decode(d)?,
            Digest384::decode(d)?,
            Height::decode(d)?,
            Option::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid external status publisher set"))
    }
}
impl CanonicalType for ExternalStatusPublisherSetV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExternalStatusSnapshotStateV1 {
    Published = 0,
    Suspended = 1,
    SourceMigrated = 2,
}
impl CanonicalEncode for ExternalStatusSnapshotStateV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for ExternalStatusSnapshotStateV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Published),
            1 => Ok(Self::Suspended),
            2 => Ok(Self::SourceMigrated),
            tag => {
                Err(DecodeError::InvalidEnumTag { type_name: "ExternalStatusSnapshotStateV1", tag })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalCredentialStatusSnapshotV1 {
    chain_id: ChainId,
    genesis_commitment: Digest384,
    issuer_binding_commitment: Digest384,
    profile_commitment: Digest384,
    schema_id: Digest384,
    source_mechanism: Digest384,
    source_version: u32,
    source_identifier: Digest384,
    status_root: Digest384,
    sequence: u64,
    observed_at: u64,
    anchor_height: Height,
    valid_from_height: Height,
    fresh_until_height: Height,
    previous_snapshot_commitment: Option<Digest384>,
    updater: PrincipalId,
    publisher_set_commitment: Digest384,
    update_authorization: Digest384,
    issuance_log_root: Option<Digest384>,
    state: ExternalStatusSnapshotStateV1,
}
impl ExternalCredentialStatusSnapshotV1 {
    pub const TYPE_TAG: u16 = 0x0157;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 12 + 4 + 8 * 5 + 49 * 2 + 1;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        genesis: Digest384,
        issuer_binding: Digest384,
        profile: Digest384,
        schema: Digest384,
        source_mechanism: Digest384,
        source_version: u32,
        source_identifier: Digest384,
        status_root: Digest384,
        sequence: u64,
        observed_at: u64,
        anchor_height: Height,
        valid_from: Height,
        fresh_until: Height,
        previous: Option<Digest384>,
        updater: PrincipalId,
        publisher_set: Digest384,
        authorization: Digest384,
        issuance_log: Option<Digest384>,
        state: ExternalStatusSnapshotStateV1,
    ) -> Result<Self, ExternalStatusError> {
        if chain_id.digest() == &Digest384::ZERO
            || updater.digest() == &Digest384::ZERO
            || [
                genesis,
                issuer_binding,
                profile,
                schema,
                source_mechanism,
                source_identifier,
                status_root,
                publisher_set,
                authorization,
            ]
            .into_iter()
            .any(|v| v == Digest384::ZERO)
            || previous == Some(Digest384::ZERO)
            || issuance_log == Some(Digest384::ZERO)
        {
            return Err(ExternalStatusError::InvalidIdentity);
        }
        if source_version == 0 || sequence == 0 || (sequence == 1) != previous.is_none() {
            return Err(ExternalStatusError::InvalidSequence);
        }
        if observed_at == 0
            || anchor_height == 0
            || valid_from < anchor_height
            || fresh_until <= valid_from
        {
            return Err(ExternalStatusError::InvalidValidity);
        }
        Ok(Self {
            chain_id,
            genesis_commitment: genesis,
            issuer_binding_commitment: issuer_binding,
            profile_commitment: profile,
            schema_id: schema,
            source_mechanism,
            source_version,
            source_identifier,
            status_root,
            sequence,
            observed_at,
            anchor_height,
            valid_from_height: valid_from,
            fresh_until_height: fresh_until,
            previous_snapshot_commitment: previous,
            updater,
            publisher_set_commitment: publisher_set,
            update_authorization: authorization,
            issuance_log_root: issuance_log,
            state,
        })
    }
    pub const fn updater(&self) -> PrincipalId {
        self.updater
    }
    pub const fn anchor_height(&self) -> Height {
        self.anchor_height
    }
    pub const fn schema_id(&self) -> Digest384 {
        self.schema_id
    }
    pub fn slot_commitment(&self) -> Result<Digest384, EncodeError> {
        let mut h = Shake256::default();
        h.update(b"ACTIVECHAIN-EXTERNAL-STATUS-SLOT-V1");
        for value in [
            self.chain_id.digest().as_bytes(),
            self.genesis_commitment.as_bytes(),
            self.issuer_binding_commitment.as_bytes(),
            self.profile_commitment.as_bytes(),
            self.schema_id.as_bytes(),
        ] {
            h.update(value);
        }
        let mut out = [0; 48];
        XofReader::read(&mut h.finalize_xof(), &mut out);
        Ok(Digest384::new(out))
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(b"ACTIVECHAIN-EXTERNAL-STATUS-SNAPSHOT-V1", self)
    }
    pub fn admissible_at(
        &self,
        height: Height,
        max_root_age: u64,
        require_issuance_log: bool,
    ) -> bool {
        self.state != ExternalStatusSnapshotStateV1::Suspended
            && height >= self.valid_from_height
            && height < self.fresh_until_height
            && height.saturating_sub(self.anchor_height) <= max_root_age
            && (!require_issuance_log || self.issuance_log_root.is_some())
    }
    pub fn binds_evidence(&self, status_root: Digest384, issuance_log: Option<Digest384>) -> bool {
        self.status_root == status_root && self.issuance_log_root == issuance_log
    }
    pub fn validate_successor(&self, next: &Self) -> Result<(), ExternalStatusError> {
        if self.chain_id != next.chain_id
            || self.genesis_commitment != next.genesis_commitment
            || self.issuer_binding_commitment != next.issuer_binding_commitment
            || self.profile_commitment != next.profile_commitment
            || self.schema_id != next.schema_id
        {
            return Err(ExternalStatusError::StableContextMismatch);
        }
        if next.sequence
            != self.sequence.checked_add(1).ok_or(ExternalStatusError::InvalidSequence)?
            || next.observed_at <= self.observed_at
            || next.anchor_height <= self.anchor_height
        {
            return Err(ExternalStatusError::InvalidSequence);
        }
        if next.previous_snapshot_commitment
            != Some(self.commitment().map_err(|_| ExternalStatusError::PreviousMismatch)?)
        {
            return Err(ExternalStatusError::PreviousMismatch);
        }
        let source_changed = self.source_mechanism != next.source_mechanism
            || self.source_version != next.source_version
            || self.source_identifier != next.source_identifier;
        if source_changed && next.state != ExternalStatusSnapshotStateV1::SourceMigrated {
            return Err(ExternalStatusError::InvalidSourceMigration);
        }
        Ok(())
    }
}
impl CanonicalEncode for ExternalCredentialStatusSnapshotV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.genesis_commitment.encode(e)?;
        self.issuer_binding_commitment.encode(e)?;
        self.profile_commitment.encode(e)?;
        self.schema_id.encode(e)?;
        self.source_mechanism.encode(e)?;
        self.source_version.encode(e)?;
        self.source_identifier.encode(e)?;
        self.status_root.encode(e)?;
        self.sequence.encode(e)?;
        self.observed_at.encode(e)?;
        self.anchor_height.encode(e)?;
        self.valid_from_height.encode(e)?;
        self.fresh_until_height.encode(e)?;
        self.previous_snapshot_commitment.encode(e)?;
        self.updater.encode(e)?;
        self.publisher_set_commitment.encode(e)?;
        self.update_authorization.encode(e)?;
        self.issuance_log_root.encode(e)?;
        self.state.encode(e)
    }
}
impl CanonicalDecode for ExternalCredentialStatusSnapshotV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u32::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            Height::decode(d)?,
            Height::decode(d)?,
            Height::decode(d)?,
            Option::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Option::decode(d)?,
            ExternalStatusSnapshotStateV1::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid external status snapshot"))
    }
}
impl CanonicalType for ExternalCredentialStatusSnapshotV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalCredentialStatusRegistryV1 {
    finalized_height: Height,
    snapshots: Vec<ExternalCredentialStatusSnapshotV1>,
}
impl ExternalCredentialStatusRegistryV1 {
    pub const TYPE_TAG: u16 = 0x0158;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        8 + 2 + MAX_EXTERNAL_STATUS_SNAPSHOTS * ExternalCredentialStatusSnapshotV1::MAX_ENCODED_LEN;
    pub fn new(
        finalized_height: Height,
        snapshots: Vec<ExternalCredentialStatusSnapshotV1>,
    ) -> Result<Self, ExternalStatusError> {
        if snapshots.len() > MAX_EXTERNAL_STATUS_SNAPSHOTS {
            return Err(ExternalStatusError::TooManySnapshots);
        }
        let mut previous = None;
        for snapshot in &snapshots {
            if snapshot.anchor_height() > finalized_height {
                return Err(ExternalStatusError::FinalityRollback);
            }
            let slot =
                snapshot.slot_commitment().map_err(|_| ExternalStatusError::SnapshotsNotOrdered)?;
            if previous.is_some_and(|value| value >= slot) {
                return Err(ExternalStatusError::SnapshotsNotOrdered);
            }
            previous = Some(slot);
        }
        Ok(Self { finalized_height, snapshots })
    }
    pub fn apply(
        &mut self,
        next: ExternalCredentialStatusSnapshotV1,
        publishers: &ExternalStatusPublisherSetV1,
        finalized_height: Height,
    ) -> Result<(), ExternalStatusError> {
        if finalized_height <= self.finalized_height || next.anchor_height() != finalized_height {
            return Err(ExternalStatusError::FinalityRollback);
        }
        if next.publisher_set_commitment
            != publishers.commitment().map_err(|_| ExternalStatusError::UnauthorizedUpdater)?
            || !publishers.authorizes(next.updater(), finalized_height)
        {
            return Err(ExternalStatusError::UnauthorizedUpdater);
        }
        let slot = next.slot_commitment().map_err(|_| ExternalStatusError::SnapshotsNotOrdered)?;
        match self.snapshots.binary_search_by_key(&slot, |snapshot| {
            snapshot.slot_commitment().unwrap_or(Digest384::ZERO)
        }) {
            Ok(index) => {
                self.snapshots[index].validate_successor(&next)?;
                self.snapshots[index] = next;
            }
            Err(index) => {
                if self.snapshots.len() >= MAX_EXTERNAL_STATUS_SNAPSHOTS {
                    return Err(ExternalStatusError::TooManySnapshots);
                }
                if next.sequence != 1 {
                    return Err(ExternalStatusError::InvalidSequence);
                }
                self.snapshots.insert(index, next);
            }
        }
        self.finalized_height = finalized_height;
        Ok(())
    }
    pub fn resolve(
        &self,
        slot: Digest384,
        height: Height,
        max_root_age: u64,
        require_log: bool,
    ) -> Option<&ExternalCredentialStatusSnapshotV1> {
        if height > self.finalized_height {
            return None;
        }
        self.snapshots
            .binary_search_by_key(&slot, |snapshot| {
                snapshot.slot_commitment().unwrap_or(Digest384::ZERO)
            })
            .ok()
            .map(|index| &self.snapshots[index])
            .filter(|snapshot| snapshot.admissible_at(height, max_root_age, require_log))
    }
}
impl CanonicalEncode for ExternalCredentialStatusRegistryV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.finalized_height.encode(e)?;
        e.write_length(self.snapshots.len(), MAX_EXTERNAL_STATUS_SNAPSHOTS)?;
        for s in &self.snapshots {
            s.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for ExternalCredentialStatusRegistryV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let height = Height::decode(d)?;
        let count = d.read_length(MAX_EXTERNAL_STATUS_SNAPSHOTS)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(ExternalCredentialStatusSnapshotV1::decode(d)?);
        }
        Self::new(height, values)
            .map_err(|_| DecodeError::InvalidValue("invalid external status registry"))
    }
}
impl CanonicalType for ExternalCredentialStatusRegistryV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

fn commit<T: CanonicalType>(domain: &[u8], value: &T) -> Result<Digest384, EncodeError> {
    let bytes = activechain_canonical_codec::encode_envelope(value)?;
    let mut h = Shake256::default();
    h.update(domain);
    h.update(&bytes);
    let mut out = [0; 48];
    XofReader::read(&mut h.finalize_xof(), &mut out);
    Ok(Digest384::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::vec;
    fn d(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    fn principal(n: u8) -> PrincipalId {
        PrincipalId::new(d(n))
    }
    fn publishers() -> ExternalStatusPublisherSetV1 {
        ExternalStatusPublisherSetV1::new(
            d(3),
            vec![principal(8), principal(9)],
            1,
            1,
            None,
            d(10),
            1,
            None,
        )
        .unwrap()
    }
    fn policy_matrix() -> impl Iterator<Item = (&'static str, u64, u64, bool, bool)> {
        include_str!("../../../testing/vectors/external-status-snapshot-v1.tsv")
            .lines()
            .skip(1)
            .map(|line| {
                let mut fields = line.split('\t');
                let name = fields.next().unwrap();
                let height = fields.next().unwrap().parse().unwrap();
                let max_age = fields.next().unwrap().parse().unwrap();
                let require_log = fields.next().unwrap() == "true";
                let expected = fields.next().unwrap() == "accept";
                assert!(fields.next().is_none());
                (name, height, max_age, require_log, expected)
            })
    }
    #[allow(clippy::too_many_arguments)]
    fn snapshot(
        sequence: u64,
        previous: Option<Digest384>,
        anchor: u64,
        observed: u64,
        state: ExternalStatusSnapshotStateV1,
        source: u8,
        updater: u8,
        publisher_set: Digest384,
    ) -> ExternalCredentialStatusSnapshotV1 {
        ExternalCredentialStatusSnapshotV1::new(
            ChainId::new(d(1)),
            d(2),
            d(3),
            d(4),
            d(5),
            d(source),
            1,
            d(source + 1),
            d(7),
            sequence,
            observed,
            anchor,
            anchor,
            anchor + 10,
            previous,
            principal(updater),
            publisher_set,
            d(11),
            Some(d(12)),
            state,
        )
        .unwrap()
    }
    #[test]
    fn publisher_and_snapshot_round_trip() {
        let p = publishers();
        assert_eq!(
            decode_envelope::<ExternalStatusPublisherSetV1>(&encode_envelope(&p).unwrap()),
            Ok(p.clone())
        );
        let s = snapshot(
            1,
            None,
            5,
            5,
            ExternalStatusSnapshotStateV1::Published,
            6,
            8,
            p.commitment().unwrap(),
        );
        assert_eq!(
            decode_envelope::<ExternalCredentialStatusSnapshotV1>(&encode_envelope(&s).unwrap()),
            Ok(s)
        );
        assert!(s.admissible_at(6, 3, true));
        assert!(!s.admissible_at(9, 3, true));
        assert!(s.binds_evidence(d(7), Some(d(12))));
    }
    #[test]
    fn registry_is_authorized_monotonic_and_restart_safe() {
        let p = publishers();
        let first = snapshot(
            1,
            None,
            5,
            5,
            ExternalStatusSnapshotStateV1::Published,
            6,
            8,
            p.commitment().unwrap(),
        );
        let slot = first.slot_commitment().unwrap();
        let mut r = ExternalCredentialStatusRegistryV1::new(4, vec![]).unwrap();
        r.apply(first, &p, 5).unwrap();
        assert!(r.resolve(slot, 5, 2, true).is_some());
        let next = snapshot(
            2,
            Some(first.commitment().unwrap()),
            6,
            6,
            ExternalStatusSnapshotStateV1::Published,
            6,
            8,
            p.commitment().unwrap(),
        );
        r.apply(next, &p, 6).unwrap();
        assert_eq!(r.apply(next, &p, 6), Err(ExternalStatusError::FinalityRollback));
        let bytes = encode_envelope(&r).unwrap();
        assert_eq!(decode_envelope::<ExternalCredentialStatusRegistryV1>(&bytes), Ok(r));
    }
    #[test]
    fn source_migration_and_updater_substitution_fail_closed() {
        let p = publishers();
        let first = snapshot(
            1,
            None,
            5,
            5,
            ExternalStatusSnapshotStateV1::Published,
            6,
            8,
            p.commitment().unwrap(),
        );
        let changed = snapshot(
            2,
            Some(first.commitment().unwrap()),
            6,
            6,
            ExternalStatusSnapshotStateV1::Published,
            20,
            8,
            p.commitment().unwrap(),
        );
        assert_eq!(
            first.validate_successor(&changed),
            Err(ExternalStatusError::InvalidSourceMigration)
        );
        let unauthorized = snapshot(
            1,
            None,
            5,
            5,
            ExternalStatusSnapshotStateV1::Published,
            6,
            30,
            p.commitment().unwrap(),
        );
        let mut r = ExternalCredentialStatusRegistryV1::new(4, vec![]).unwrap();
        assert_eq!(r.apply(unauthorized, &p, 5), Err(ExternalStatusError::UnauthorizedUpdater));
    }
    #[test]
    fn shared_policy_matrix_enforces_freshness_and_transparency() {
        let p = publishers();
        let with_log = snapshot(
            1,
            None,
            5,
            5,
            ExternalStatusSnapshotStateV1::Published,
            6,
            8,
            p.commitment().unwrap(),
        );
        let without_log =
            ExternalCredentialStatusSnapshotV1 { issuance_log_root: None, ..with_log };
        for (name, height, max_age, require_log, expected) in policy_matrix() {
            let candidate = if name == "missing-required-log" { &without_log } else { &with_log };
            assert_eq!(candidate.admissible_at(height, max_age, require_log), expected, "{name}");
        }
    }
    #[test]
    fn publisher_sets_reject_malformed_governance() {
        assert_eq!(
            ExternalStatusPublisherSetV1::new(
                d(3),
                vec![principal(9), principal(8)],
                1,
                1,
                None,
                d(10),
                1,
                None,
            ),
            Err(ExternalStatusError::InvalidPublishers)
        );
        assert_eq!(
            ExternalStatusPublisherSetV1::new(d(3), vec![principal(8)], 2, 1, None, d(10), 1, None,),
            Err(ExternalStatusError::InvalidThreshold)
        );

        let p = publishers();
        let future = snapshot(
            1,
            None,
            5,
            5,
            ExternalStatusSnapshotStateV1::Published,
            6,
            8,
            p.commitment().unwrap(),
        );
        assert_eq!(
            ExternalCredentialStatusRegistryV1::new(4, vec![future]),
            Err(ExternalStatusError::FinalityRollback)
        );
    }
}
