use crate::{AssetId, ChainId, Digest384, Height, PrincipalId, ProtocolSignature, TransactionId};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComplianceError {
    ZeroCommitment,
    InvalidValidity,
    WrongChain,
    Mismatch,
    Replay,
    TooManyEntries,
    Unordered,
    InvalidScreening,
}

pub const MAX_COMPLIANCE_REPLAY_KEYS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JurisdictionProfileCandidate {
    pub id: Digest384,
    pub applies: bool,
    pub ambiguous: bool,
    pub active: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileSelection {
    Selected(Vec<Digest384>),
    ManualReview,
    Rejected,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JurisdictionProfileInheritance {
    pub profile: Digest384,
    pub parent: Option<Digest384>,
    pub stricter: bool,
}

/// Selects applicable profiles and expands their signed inheritance chain. A missing parent,
/// duplicate relationship, or cycle is rejected; an inheritance edge marked non-stricter is sent
/// to manual review because a child profile may only narrow its parent's requirements.
#[allow(dead_code)]
pub fn select_profiles_with_inheritance(
    candidates: &[JurisdictionProfileCandidate],
    inheritance: &[JurisdictionProfileInheritance],
) -> ProfileSelection {
    let ProfileSelection::Selected(mut selected) = select_jurisdiction_profiles(candidates) else {
        return select_jurisdiction_profiles(candidates);
    };
    let mut processed = Vec::new();
    let mut changed = true;
    while changed {
        changed = false;
        let current = selected.clone();
        for id in current {
            if processed.contains(&id) {
                continue;
            }
            processed.push(id);
            let Some(edge) = inheritance.iter().find(|edge| edge.profile == id) else { continue };
            if !edge.stricter {
                return ProfileSelection::ManualReview;
            }
            if let Some(parent) = edge.parent {
                if processed.contains(&parent) {
                    return ProfileSelection::Rejected;
                }
                selected.push(parent);
                changed = true;
            }
        }
        if selected.len() > candidates.len().saturating_add(inheritance.len()) {
            return ProfileSelection::Rejected;
        }
    }
    selected.sort();
    if selected.windows(2).any(|pair| pair[0] == pair[1]) {
        ProfileSelection::Rejected
    } else {
        ProfileSelection::Selected(selected)
    }
}
pub fn select_jurisdiction_profiles(
    candidates: &[JurisdictionProfileCandidate],
) -> ProfileSelection {
    let applicable: Vec<_> = candidates.iter().filter(|c| c.applies).collect();
    if applicable.iter().any(|c| !c.active) {
        return ProfileSelection::Rejected;
    }
    if applicable.iter().any(|c| c.ambiguous) || applicable.is_empty() {
        return ProfileSelection::ManualReview;
    }
    let mut ids: Vec<_> = applicable.into_iter().map(|c| c.id).collect();
    ids.sort();
    if ids.windows(2).any(|w| w[0] == w[1]) {
        return ProfileSelection::Rejected;
    }
    ProfileSelection::Selected(ids)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ScreeningOutcome {
    Cleared = 0,
    Match = 1,
    ManualReview = 2,
}
impl CanonicalEncode for ScreeningOutcome {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for ScreeningOutcome {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Cleared),
            1 => Ok(Self::Match),
            2 => Ok(Self::ManualReview),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ScreeningOutcome", tag }),
        }
    }
}

/// Commitment-only sanctions/screening result. Sensitive list matches and analyst evidence stay
/// with the screening provider; this envelope binds the decision to the exact chain action and
/// versioned profile without making the subject publicly identifiable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScreeningDecisionV1 {
    profile: Digest384,
    chain_id: ChainId,
    action: TransactionId,
    subject_commitment: Digest384,
    list_commitment: Digest384,
    provider_commitment: Digest384,
    parameters_commitment: Digest384,
    screened_at: u64,
    expires_at: u64,
    outcome: ScreeningOutcome,
}
impl ScreeningDecisionV1 {
    pub const TYPE_TAG: u16 = 0x00D5;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 8 + 8 * 2 + 1;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: Digest384,
        chain_id: ChainId,
        action: TransactionId,
        subject_commitment: Digest384,
        list_commitment: Digest384,
        provider_commitment: Digest384,
        parameters_commitment: Digest384,
        screened_at: u64,
        expires_at: u64,
        outcome: ScreeningOutcome,
    ) -> Result<Self, ComplianceError> {
        if [
            profile,
            subject_commitment,
            list_commitment,
            provider_commitment,
            parameters_commitment,
        ]
        .into_iter()
        .any(|value| value == Digest384::ZERO)
            || screened_at >= expires_at
        {
            return Err(ComplianceError::InvalidScreening);
        }
        Ok(Self {
            profile,
            chain_id,
            action,
            subject_commitment,
            list_commitment,
            provider_commitment,
            parameters_commitment,
            screened_at,
            expires_at,
            outcome,
        })
    }
    pub const fn outcome(&self) -> ScreeningOutcome {
        self.outcome
    }
    pub const fn screened_at(&self) -> u64 {
        self.screened_at
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}
impl CanonicalEncode for ScreeningDecisionV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.profile.encode(e)?;
        self.chain_id.encode(e)?;
        self.action.encode(e)?;
        self.subject_commitment.encode(e)?;
        self.list_commitment.encode(e)?;
        self.provider_commitment.encode(e)?;
        self.parameters_commitment.encode(e)?;
        self.screened_at.encode(e)?;
        self.expires_at.encode(e)?;
        self.outcome.encode(e)
    }
}
impl CanonicalDecode for ScreeningDecisionV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            ChainId::decode(d)?,
            TransactionId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            ScreeningOutcome::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid screening decision"))
    }
}
impl CanonicalType for ScreeningDecisionV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Versioned screening controls referenced by `ScreeningDecisionV1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScreeningPolicyV1 {
    profile: Digest384,
    list_authority: Digest384,
    matching_parameters: Digest384,
    max_age_seconds: u64,
    override_quorum: u8,
    require_provider_signature: bool,
}
impl ScreeningPolicyV1 {
    pub const TYPE_TAG: u16 = 0x00D6;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 3 + 8 + 1 + 1;
    pub fn new(
        profile: Digest384,
        list_authority: Digest384,
        matching_parameters: Digest384,
        max_age_seconds: u64,
        override_quorum: u8,
        require_provider_signature: bool,
    ) -> Result<Self, ComplianceError> {
        if [profile, list_authority, matching_parameters].into_iter().any(|v| v == Digest384::ZERO)
            || max_age_seconds == 0
            || override_quorum == 0
        {
            return Err(ComplianceError::InvalidScreening);
        }
        Ok(Self {
            profile,
            list_authority,
            matching_parameters,
            max_age_seconds,
            override_quorum,
            require_provider_signature,
        })
    }
    pub const fn profile(&self) -> Digest384 {
        self.profile
    }
    pub const fn max_age_seconds(&self) -> u64 {
        self.max_age_seconds
    }
    pub const fn override_quorum(&self) -> u8 {
        self.override_quorum
    }
    pub const fn require_provider_signature(&self) -> bool {
        self.require_provider_signature
    }
    pub fn accepts(&self, decision: &ScreeningDecisionV1, now: u64) -> bool {
        decision.profile == self.profile
            && decision.list_commitment == self.list_authority
            && decision.parameters_commitment == self.matching_parameters
            && now >= decision.screened_at
            && now.saturating_sub(decision.screened_at) <= self.max_age_seconds
            && now < decision.expires_at
            && matches!(decision.outcome, ScreeningOutcome::Cleared)
    }
}
impl CanonicalEncode for ScreeningPolicyV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.profile.encode(e)?;
        self.list_authority.encode(e)?;
        self.matching_parameters.encode(e)?;
        self.max_age_seconds.encode(e)?;
        self.override_quorum.encode(e)?;
        self.require_provider_signature.encode(e)
    }
}
impl CanonicalDecode for ScreeningPolicyV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u8::decode(d)?,
            bool::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid screening policy"))
    }
}
impl CanonicalType for ScreeningPolicyV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ComplianceReplayKey {
    profile: Digest384,
    operator: PrincipalId,
    action: TransactionId,
    nonce: Digest384,
}
impl ComplianceReplayKey {
    pub const TYPE_TAG: u16 = 0x00D3;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 4;
    pub const fn new(
        profile: Digest384,
        operator: PrincipalId,
        action: TransactionId,
        nonce: Digest384,
    ) -> Self {
        Self { profile, operator, action, nonce }
    }
}
impl CanonicalEncode for ComplianceReplayKey {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.profile.encode(e)?;
        self.operator.encode(e)?;
        self.action.encode(e)?;
        self.nonce.encode(e)
    }
}
impl CanonicalDecode for ComplianceReplayKey {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            TransactionId::decode(d)?,
            Digest384::decode(d)?,
        ))
    }
}
impl CanonicalType for ComplianceReplayKey {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComplianceReplaySet(Vec<ComplianceReplayKey>);
impl ComplianceReplaySet {
    pub fn new(keys: Vec<ComplianceReplayKey>) -> Result<Self, ComplianceError> {
        if keys.len() > MAX_COMPLIANCE_REPLAY_KEYS {
            return Err(ComplianceError::TooManyEntries);
        }
        if keys.windows(2).any(|w| w[0] >= w[1]) {
            return Err(ComplianceError::Unordered);
        }
        Ok(Self(keys))
    }
    pub fn contains(&self, key: ComplianceReplayKey) -> bool {
        self.0.binary_search(&key).is_ok()
    }
    pub fn insert(&mut self, key: ComplianceReplayKey) -> Result<(), ComplianceError> {
        if self.contains(key) {
            return Err(ComplianceError::Replay);
        }
        if self.0.len() >= MAX_COMPLIANCE_REPLAY_KEYS {
            return Err(ComplianceError::TooManyEntries);
        }
        let i = self.0.binary_search(&key).unwrap_or_else(|i| i);
        self.0.insert(i, key);
        Ok(())
    }
    pub fn keys(&self) -> &[ComplianceReplayKey] {
        &self.0
    }
}
impl CanonicalEncode for ComplianceReplaySet {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_length(self.0.len(), MAX_COMPLIANCE_REPLAY_KEYS)?;
        for k in &self.0 {
            k.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for ComplianceReplaySet {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let n = d.read_length(MAX_COMPLIANCE_REPLAY_KEYS)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(ComplianceReplayKey::decode(d)?);
        }
        Self::new(v).map_err(|_| DecodeError::InvalidValue("invalid compliance replay set"))
    }
}
impl CanonicalType for ComplianceReplaySet {
    const TYPE_TAG: u16 = 0x00D4;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        2 + MAX_COMPLIANCE_REPLAY_KEYS * ComplianceReplayKey::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComplianceSignatureEnvelopeV1 {
    profile: Digest384,
    chain_id: ChainId,
    action: TransactionId,
    commitment: Digest384,
    nonce: Digest384,
    signature: ProtocolSignature,
}
impl ComplianceSignatureEnvelopeV1 {
    pub const TYPE_TAG: u16 = 0x00D2;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 5 + ProtocolSignature::MAX_ENCODED_LEN;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: Digest384,
        chain_id: ChainId,
        action: TransactionId,
        commitment: Digest384,
        nonce: Digest384,
        signature: ProtocolSignature,
    ) -> Result<Self, ComplianceError> {
        if profile == Digest384::ZERO
            || *action.digest() == Digest384::ZERO
            || commitment == Digest384::ZERO
            || nonce == Digest384::ZERO
        {
            return Err(ComplianceError::ZeroCommitment);
        }
        Ok(Self { profile, chain_id, action, commitment, nonce, signature })
    }
    pub const fn profile(&self) -> Digest384 {
        self.profile
    }
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn action(&self) -> TransactionId {
        self.action
    }
    pub const fn commitment(&self) -> Digest384 {
        self.commitment
    }
    pub const fn nonce(&self) -> Digest384 {
        self.nonce
    }
    pub const fn signature(&self) -> &ProtocolSignature {
        &self.signature
    }
}
impl CanonicalEncode for ComplianceSignatureEnvelopeV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.profile.encode(e)?;
        self.chain_id.encode(e)?;
        self.action.encode(e)?;
        self.commitment.encode(e)?;
        self.nonce.encode(e)?;
        self.signature.encode(e)
    }
}
impl CanonicalDecode for ComplianceSignatureEnvelopeV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            ChainId::decode(d)?,
            TransactionId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            ProtocolSignature::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid compliance signature envelope"))
    }
}
impl CanonicalType for ComplianceSignatureEnvelopeV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComplianceEvidenceBindingV1 {
    profile: Digest384,
    chain_id: ChainId,
    genesis: Digest384,
    operator: PrincipalId,
    subject: Digest384,
    action: TransactionId,
    screening: Digest384,
    credential: Digest384,
    travel_rule: Digest384,
    valid_from: Height,
    valid_until: Height,
    nonce: Digest384,
}
impl ComplianceEvidenceBindingV1 {
    pub const TYPE_TAG: u16 = 0x00D0;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 10 + 8 * 2;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: Digest384,
        chain_id: ChainId,
        genesis: Digest384,
        operator: PrincipalId,
        subject: Digest384,
        action: TransactionId,
        screening: Digest384,
        credential: Digest384,
        travel_rule: Digest384,
        valid_from: Height,
        valid_until: Height,
        nonce: Digest384,
    ) -> Result<Self, ComplianceError> {
        if profile == Digest384::ZERO
            || genesis == Digest384::ZERO
            || subject == Digest384::ZERO
            || *action.digest() == Digest384::ZERO
            || screening == Digest384::ZERO
            || credential == Digest384::ZERO
            || travel_rule == Digest384::ZERO
            || nonce == Digest384::ZERO
        {
            return Err(ComplianceError::ZeroCommitment);
        }
        if valid_until < valid_from {
            return Err(ComplianceError::InvalidValidity);
        }
        Ok(Self {
            profile,
            chain_id,
            genesis,
            operator,
            subject,
            action,
            screening,
            credential,
            travel_rule,
            valid_from,
            valid_until,
            nonce,
        })
    }
    pub const fn profile(self) -> Digest384 {
        self.profile
    }
    pub const fn chain_id(self) -> ChainId {
        self.chain_id
    }
    pub const fn action(self) -> TransactionId {
        self.action
    }
    pub const fn operator(self) -> PrincipalId {
        self.operator
    }
    pub const fn valid_until(self) -> Height {
        self.valid_until
    }
    pub fn valid_at(self, height: Height) -> bool {
        height >= self.valid_from && height <= self.valid_until
    }
}
impl CanonicalEncode for ComplianceEvidenceBindingV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.profile.encode(e)?;
        self.chain_id.encode(e)?;
        self.genesis.encode(e)?;
        self.operator.encode(e)?;
        self.subject.encode(e)?;
        self.action.encode(e)?;
        self.screening.encode(e)?;
        self.credential.encode(e)?;
        self.travel_rule.encode(e)?;
        self.valid_from.encode(e)?;
        self.valid_until.encode(e)?;
        self.nonce.encode(e)
    }
}
impl CanonicalDecode for ComplianceEvidenceBindingV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            TransactionId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid compliance evidence binding"))
    }
}
impl CanonicalType for ComplianceEvidenceBindingV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TravelRuleBindingV1 {
    chain_id: ChainId,
    transfer: TransactionId,
    asset: AssetId,
    amount: u128,
    originator: PrincipalId,
    beneficiary: PrincipalId,
    message: Digest384,
    acknowledgement: Digest384,
    expires_at: Height,
}
impl TravelRuleBindingV1 {
    pub const TYPE_TAG: u16 = 0x00D1;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 7 + 16 + 8;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        transfer: TransactionId,
        asset: AssetId,
        amount: u128,
        originator: PrincipalId,
        beneficiary: PrincipalId,
        message: Digest384,
        acknowledgement: Digest384,
        expires_at: Height,
    ) -> Result<Self, ComplianceError> {
        if amount == 0
            || message == Digest384::ZERO
            || acknowledgement == Digest384::ZERO
            || expires_at == 0
        {
            return Err(ComplianceError::ZeroCommitment);
        }
        Ok(Self {
            chain_id,
            transfer,
            asset,
            amount,
            originator,
            beneficiary,
            message,
            acknowledgement,
            expires_at,
        })
    }
    pub const fn chain_id(self) -> ChainId {
        self.chain_id
    }
    pub const fn transfer(self) -> TransactionId {
        self.transfer
    }
    pub const fn asset(self) -> AssetId {
        self.asset
    }
    pub const fn amount(self) -> u128 {
        self.amount
    }
    pub const fn expires_at(self) -> Height {
        self.expires_at
    }
}
impl CanonicalEncode for TravelRuleBindingV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.transfer.encode(e)?;
        self.asset.encode(e)?;
        self.amount.encode(e)?;
        self.originator.encode(e)?;
        self.beneficiary.encode(e)?;
        self.message.encode(e)?;
        self.acknowledgement.encode(e)?;
        self.expires_at.encode(e)
    }
}
impl CanonicalDecode for TravelRuleBindingV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            TransactionId::decode(d)?,
            AssetId::decode(d)?,
            u128::decode(d)?,
            PrincipalId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid Travel Rule binding"))
    }
}
impl CanonicalType for TravelRuleBindingV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::vec;
    fn d(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    #[test]
    fn evidence_and_travel_rule_bindings_round_trip_and_expiry_fails_closed() {
        let evidence = ComplianceEvidenceBindingV1::new(
            d(1),
            ChainId::new(d(2)),
            d(3),
            PrincipalId::new(d(4)),
            d(5),
            TransactionId::new(d(6)),
            d(7),
            d(8),
            d(9),
            10,
            20,
            d(10),
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<ComplianceEvidenceBindingV1>(&encode_envelope(&evidence).unwrap()),
            Ok(evidence)
        );
        assert!(!evidence.valid_at(21));
        let travel = TravelRuleBindingV1::new(
            ChainId::new(d(2)),
            TransactionId::new(d(6)),
            AssetId::new(d(11)),
            42,
            PrincipalId::new(d(4)),
            PrincipalId::new(d(5)),
            d(12),
            d(13),
            20,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<TravelRuleBindingV1>(&encode_envelope(&travel).unwrap()),
            Ok(travel)
        );
        assert!(
            TravelRuleBindingV1::new(
                travel.chain_id(),
                travel.transfer(),
                travel.asset(),
                0,
                PrincipalId::new(d(4)),
                PrincipalId::new(d(5)),
                d(12),
                d(13),
                20
            )
            .is_err()
        );
    }

    #[test]
    fn profile_selection_is_sorted_and_fails_closed() {
        let a = JurisdictionProfileCandidate {
            id: d(2),
            applies: true,
            ambiguous: false,
            active: true,
        };
        let b = JurisdictionProfileCandidate {
            id: d(1),
            applies: true,
            ambiguous: false,
            active: true,
        };
        assert_eq!(
            select_jurisdiction_profiles(&[a, b]),
            ProfileSelection::Selected(vec![d(1), d(2)])
        );
        let ambiguous = JurisdictionProfileCandidate { ambiguous: true, ..a };
        assert_eq!(select_jurisdiction_profiles(&[ambiguous]), ProfileSelection::ManualReview);
        let expired = JurisdictionProfileCandidate { active: false, ..a };
        assert_eq!(select_jurisdiction_profiles(&[expired]), ProfileSelection::Rejected);

        let child = JurisdictionProfileCandidate { id: d(3), ..a };
        assert_eq!(
            select_profiles_with_inheritance(
                &[child],
                &[
                    JurisdictionProfileInheritance {
                        profile: d(3),
                        parent: Some(d(4)),
                        stricter: true
                    },
                    JurisdictionProfileInheritance { profile: d(4), parent: None, stricter: true },
                ]
            ),
            ProfileSelection::Selected(vec![d(3), d(4)])
        );
        assert_eq!(
            select_profiles_with_inheritance(
                &[child],
                &[JurisdictionProfileInheritance {
                    profile: d(3),
                    parent: Some(d(4)),
                    stricter: false
                }]
            ),
            ProfileSelection::ManualReview
        );
    }

    #[test]
    fn screening_decision_is_commitment_only_and_time_bounded() {
        let decision = ScreeningDecisionV1::new(
            d(1),
            ChainId::new(d(2)),
            TransactionId::new(d(3)),
            d(4),
            d(5),
            d(6),
            d(7),
            10,
            20,
            ScreeningOutcome::Cleared,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<ScreeningDecisionV1>(&encode_envelope(&decision).unwrap()),
            Ok(decision)
        );
        assert_eq!(decision.outcome(), ScreeningOutcome::Cleared);
        assert!(
            ScreeningDecisionV1::new(
                d(1),
                ChainId::new(d(2)),
                TransactionId::new(d(3)),
                d(4),
                d(5),
                d(6),
                d(7),
                20,
                20,
                ScreeningOutcome::Match,
            )
            .is_err()
        );
        assert!(
            ScreeningDecisionV1::new(
                d(1),
                ChainId::new(d(2)),
                TransactionId::new(d(3)),
                d(4),
                Digest384::ZERO,
                d(6),
                d(7),
                10,
                20,
                ScreeningOutcome::Cleared,
            )
            .is_err()
        );
    }

    #[test]
    fn screening_policy_accepts_only_fresh_matching_clearances() {
        let policy = ScreeningPolicyV1::new(d(1), d(5), d(7), 100, 2, true).unwrap();
        let clear = ScreeningDecisionV1::new(
            d(1),
            ChainId::new(d(2)),
            TransactionId::new(d(3)),
            d(4),
            d(5),
            d(6),
            d(7),
            10,
            200,
            ScreeningOutcome::Cleared,
        )
        .unwrap();
        assert!(policy.accepts(&clear, 50));
        assert!(!policy.accepts(&clear, 111));
        let match_result = ScreeningDecisionV1::new(
            d(1),
            ChainId::new(d(2)),
            TransactionId::new(d(3)),
            d(4),
            d(5),
            d(6),
            d(7),
            10,
            200,
            ScreeningOutcome::Match,
        )
        .unwrap();
        assert!(!policy.accepts(&match_result, 50));
    }
}
