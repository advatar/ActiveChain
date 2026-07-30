use crate::{AssetId, ChainId, Digest384, Height, PrincipalId, ProtocolSignature, TransactionId};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

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
    InvalidRetention,
    InvalidOverride,
    InvalidJurisdictionProfile,
}

/// Activity licensed under Kenya's Virtual Asset Service Providers framework.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KenyaRegulatedActivity {
    VirtualAssetService = 0,
    StablecoinIssuance = 1,
}
impl CanonicalEncode for KenyaRegulatedActivity {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for KenyaRegulatedActivity {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::VirtualAssetService),
            1 => Ok(Self::StablecoinIssuance),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "KenyaRegulatedActivity", tag }),
        }
    }
}

/// Mandatory control families derived from Kenya Legal Notice No. 134 of 2026.
///
/// The bits commit to accountable off-chain controls; they do not represent a licence,
/// regulatory approval, reserve balance, or legal conclusion by themselves.
pub struct KenyaControlSet;
impl KenyaControlSet {
    pub const LICENSING: u32 = 1 << 0;
    pub const ONGOING_OBLIGATIONS: u32 = 1 << 1;
    pub const CDD_AML_AND_TRANSACTION_INFORMATION: u32 = 1 << 2;
    pub const GOVERNANCE_AND_RISK: u32 = 1 << 3;
    pub const CAPITAL_AUDIT_AND_REPORTING: u32 = 1 << 4;
    pub const CYBERSECURITY_AND_CONTINUITY: u32 = 1 << 5;
    pub const ASSET_SAFEKEEPING: u32 = 1 << 6;
    pub const CONSUMER_PROTECTION: u32 = 1 << 7;
    pub const MARKET_CONDUCT: u32 = 1 << 8;
    pub const ADVERTISING: u32 = 1 << 9;
    pub const FREEZING_AND_SEIZURE: u32 = 1 << 10;
    pub const ENFORCEMENT_AND_EXIT: u32 = 1 << 11;
    pub const RECORDS_AND_REGULATOR_ACCESS: u32 = 1 << 12;
    pub const CONFLICTS_AND_OUTSOURCING: u32 = 1 << 13;
    pub const STABLECOIN_WHITE_PAPER: u32 = 1 << 14;
    pub const STABLECOIN_ISSUANCE_AND_REDEMPTION: u32 = 1 << 15;
    pub const STABLECOIN_RESERVES_AND_CUSTODY: u32 = 1 << 16;
    pub const STABLECOIN_AUDIT_REPORTING_AND_HALT: u32 = 1 << 17;
    pub const VASP_REQUIRED: u32 = (1 << 14) - 1;
    pub const STABLECOIN_REQUIRED: u32 = (1 << 18) - 1;
}

/// Canonical activation record for a Kenya-regulated application profile.
///
/// Every digest is a non-enumerable commitment to the named signed approval, policy, or control
/// register. Actual regulated records remain with the responsible operator and authorities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KenyaRegulatedProfileV1 {
    profile_id: Digest384,
    operator: PrincipalId,
    activity: KenyaRegulatedActivity,
    control_set: u32,
    source: Digest384,
    legal_review: Digest384,
    regulatory_authorization: Digest384,
    credential_policy: Digest384,
    screening_policy: Digest384,
    travel_rule_policy: Digest384,
    privacy_policy: Digest384,
    reporting_policy: Digest384,
    governance_policy: Digest384,
    consumer_protection_policy: Digest384,
    cybersecurity_policy: Digest384,
    enforcement_policy: Digest384,
    reserve_policy: Digest384,
    custody_policy: Digest384,
    redemption_policy: Digest384,
    white_paper_approval: Digest384,
    effective_height: Height,
    expires_height: Height,
    revision: u16,
}
impl KenyaRegulatedProfileV1 {
    pub const TYPE_TAG: u16 = 0x0145;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 18 + 1 + 4 + 8 * 2 + 2;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: Digest384,
        operator: PrincipalId,
        activity: KenyaRegulatedActivity,
        control_set: u32,
        source: Digest384,
        legal_review: Digest384,
        regulatory_authorization: Digest384,
        credential_policy: Digest384,
        screening_policy: Digest384,
        travel_rule_policy: Digest384,
        privacy_policy: Digest384,
        reporting_policy: Digest384,
        governance_policy: Digest384,
        consumer_protection_policy: Digest384,
        cybersecurity_policy: Digest384,
        enforcement_policy: Digest384,
        reserve_policy: Digest384,
        custody_policy: Digest384,
        redemption_policy: Digest384,
        white_paper_approval: Digest384,
        effective_height: Height,
        expires_height: Height,
        revision: u16,
    ) -> Result<Self, ComplianceError> {
        let common = [
            profile_id,
            *operator.digest(),
            source,
            legal_review,
            regulatory_authorization,
            credential_policy,
            screening_policy,
            travel_rule_policy,
            privacy_policy,
            reporting_policy,
            governance_policy,
            consumer_protection_policy,
            cybersecurity_policy,
            enforcement_policy,
        ];
        let required_controls = match activity {
            KenyaRegulatedActivity::VirtualAssetService => KenyaControlSet::VASP_REQUIRED,
            KenyaRegulatedActivity::StablecoinIssuance => KenyaControlSet::STABLECOIN_REQUIRED,
        };
        if common.into_iter().any(|value| value == Digest384::ZERO)
            || control_set & required_controls != required_controls
            || control_set & !KenyaControlSet::STABLECOIN_REQUIRED != 0
            || effective_height == 0
            || expires_height <= effective_height
            || revision == 0
            || (activity == KenyaRegulatedActivity::StablecoinIssuance
                && [reserve_policy, custody_policy, redemption_policy, white_paper_approval]
                    .into_iter()
                    .any(|value| value == Digest384::ZERO))
        {
            return Err(ComplianceError::InvalidJurisdictionProfile);
        }
        Ok(Self {
            profile_id,
            operator,
            activity,
            control_set,
            source,
            legal_review,
            regulatory_authorization,
            credential_policy,
            screening_policy,
            travel_rule_policy,
            privacy_policy,
            reporting_policy,
            governance_policy,
            consumer_protection_policy,
            cybersecurity_policy,
            enforcement_policy,
            reserve_policy,
            custody_policy,
            redemption_policy,
            white_paper_approval,
            effective_height,
            expires_height,
            revision,
        })
    }
    pub const fn activity(&self) -> KenyaRegulatedActivity {
        self.activity
    }
    pub const fn control_set(&self) -> u32 {
        self.control_set
    }
    pub const fn active_at(&self, height: Height) -> bool {
        height >= self.effective_height && height < self.expires_height
    }
    pub const fn profile_id(&self) -> Digest384 {
        self.profile_id
    }
}
impl CanonicalEncode for KenyaRegulatedProfileV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.profile_id.encode(e)?;
        self.operator.encode(e)?;
        self.activity.encode(e)?;
        self.control_set.encode(e)?;
        self.source.encode(e)?;
        self.legal_review.encode(e)?;
        self.regulatory_authorization.encode(e)?;
        self.credential_policy.encode(e)?;
        self.screening_policy.encode(e)?;
        self.travel_rule_policy.encode(e)?;
        self.privacy_policy.encode(e)?;
        self.reporting_policy.encode(e)?;
        self.governance_policy.encode(e)?;
        self.consumer_protection_policy.encode(e)?;
        self.cybersecurity_policy.encode(e)?;
        self.enforcement_policy.encode(e)?;
        self.reserve_policy.encode(e)?;
        self.custody_policy.encode(e)?;
        self.redemption_policy.encode(e)?;
        self.white_paper_approval.encode(e)?;
        self.effective_height.encode(e)?;
        self.expires_height.encode(e)?;
        self.revision.encode(e)
    }
}
impl CanonicalDecode for KenyaRegulatedProfileV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            KenyaRegulatedActivity::decode(d)?,
            u32::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Height::decode(d)?,
            Height::decode(d)?,
            u16::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid Kenya regulated profile"))
    }
}
impl CanonicalType for KenyaRegulatedProfileV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
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
    if candidates.iter().any(|candidate| candidate.id == Digest384::ZERO)
        || inheritance.iter().any(|edge| {
            edge.profile == Digest384::ZERO
                || edge.parent == Some(Digest384::ZERO)
                || edge.parent == Some(edge.profile)
        })
        || inheritance.iter().enumerate().any(|(index, edge)| {
            inheritance[index + 1..].iter().any(|other| other.profile == edge.profile)
        })
    {
        return ProfileSelection::Rejected;
    }
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
                let known_parent = candidates.iter().any(|candidate| candidate.id == parent)
                    || inheritance.iter().any(|candidate| candidate.profile == parent);
                if !known_parent {
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
pub enum EvidenceDeletionMode {
    Scheduled = 0,
    OnRequest = 1,
    LegalHold = 2,
}
impl CanonicalEncode for EvidenceDeletionMode {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for EvidenceDeletionMode {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Scheduled),
            1 => Ok(Self::OnRequest),
            2 => Ok(Self::LegalHold),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "EvidenceDeletionMode", tag }),
        }
    }
}

/// Commitment-only regulated evidence handling policy. Raw KYC, sanctions,
/// Travel Rule, and case records never enter this type or the public ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceRetentionPolicyV1 {
    profile: Digest384,
    jurisdiction: Digest384,
    evidence_class: Digest384,
    access_policy: Digest384,
    breach_policy: Digest384,
    offline_verifier: Digest384,
    retention_until: u64,
    deletion_mode: EvidenceDeletionMode,
    version: u16,
}
impl EvidenceRetentionPolicyV1 {
    pub const TYPE_TAG: u16 = 0x00D8;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 6 + 8 + 1 + 2;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: Digest384,
        jurisdiction: Digest384,
        evidence_class: Digest384,
        access_policy: Digest384,
        breach_policy: Digest384,
        offline_verifier: Digest384,
        retention_until: u64,
        deletion_mode: EvidenceDeletionMode,
        version: u16,
    ) -> Result<Self, ComplianceError> {
        if [profile, jurisdiction, evidence_class, access_policy, breach_policy, offline_verifier]
            .into_iter()
            .any(|value| value == Digest384::ZERO)
            || retention_until == 0
            || version == 0
        {
            return Err(ComplianceError::InvalidRetention);
        }
        Ok(Self {
            profile,
            jurisdiction,
            evidence_class,
            access_policy,
            breach_policy,
            offline_verifier,
            retention_until,
            deletion_mode,
            version,
        })
    }
    pub const fn retention_until(&self) -> u64 {
        self.retention_until
    }
    pub const fn deletion_mode(&self) -> EvidenceDeletionMode {
        self.deletion_mode
    }
    pub const fn version(&self) -> u16 {
        self.version
    }
    /// Returns whether evidence may be used at `height` for a disclosure that
    /// must remain valid through `required_until`.
    pub const fn admits_disclosure(&self, height: u64, required_until: u64) -> bool {
        height <= self.retention_until && required_until <= self.retention_until
    }
    /// Retention policies always identify an offline verifier commitment; raw
    /// evidence is never required for independent policy checking.
    pub fn supports_offline_verification(&self) -> bool {
        self.offline_verifier != Digest384::ZERO
    }
}
impl CanonicalEncode for EvidenceRetentionPolicyV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.profile.encode(e)?;
        self.jurisdiction.encode(e)?;
        self.evidence_class.encode(e)?;
        self.access_policy.encode(e)?;
        self.breach_policy.encode(e)?;
        self.offline_verifier.encode(e)?;
        self.retention_until.encode(e)?;
        self.deletion_mode.encode(e)?;
        self.version.encode(e)
    }
}
impl CanonicalDecode for EvidenceRetentionPolicyV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            EvidenceDeletionMode::decode(d)?,
            u16::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid evidence retention policy"))
    }
}
impl CanonicalType for EvidenceRetentionPolicyV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
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
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-SCREENING-DECISION-V1");
        hasher.update(&bytes);
        let mut output = [0_u8; 48];
        XofReader::read(&mut hasher.finalize_xof(), &mut output);
        Ok(Digest384::new(output))
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
    /// Applies the policy to one exact regulated transfer context.
    pub fn accepts_for_action(
        &self,
        decision: &ScreeningDecisionV1,
        chain_id: ChainId,
        action: TransactionId,
        now: u64,
    ) -> bool {
        self.accepts(decision, now) && decision.chain_id == chain_id && decision.action == action
    }
    pub fn accepts_with_signature(
        &self,
        decision: &ScreeningDecisionV1,
        signature: Option<&ComplianceSignatureEnvelopeV2>,
        now: u64,
    ) -> bool {
        if !self.accepts(decision, now) {
            return false;
        }
        if !self.require_provider_signature {
            return true;
        }
        let Some(signature) = signature else { return false };
        signature.profile() == self.profile
            && signature.chain_id() == decision.chain_id
            && signature.action() == decision.action
            && signature.evidence_commitment() == decision.commitment().unwrap_or(Digest384::ZERO)
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

/// Commitment-only dual-control override for a non-clear screening result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScreeningOverrideV1 {
    profile: Digest384,
    decision_commitment: Digest384,
    reviewer_set: Digest384,
    reason_commitment: Digest384,
    reviewer_count: u8,
    expires_at: u64,
}
impl ScreeningOverrideV1 {
    pub const TYPE_TAG: u16 = 0x00D9;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 4 + 1 + 8;
    pub fn new(
        profile: Digest384,
        decision_commitment: Digest384,
        reviewer_set: Digest384,
        reason_commitment: Digest384,
        reviewer_count: u8,
        expires_at: u64,
    ) -> Result<Self, ComplianceError> {
        if [profile, decision_commitment, reviewer_set, reason_commitment]
            .into_iter()
            .any(|value| value == Digest384::ZERO)
            || reviewer_count == 0
            || expires_at == 0
        {
            return Err(ComplianceError::InvalidOverride);
        }
        Ok(Self {
            profile,
            decision_commitment,
            reviewer_set,
            reason_commitment,
            reviewer_count,
            expires_at,
        })
    }
    pub fn admits(
        &self,
        policy: &ScreeningPolicyV1,
        decision: &ScreeningDecisionV1,
        now: u64,
    ) -> bool {
        self.profile == policy.profile
            && self.decision_commitment == decision.commitment().ok().unwrap_or(Digest384::ZERO)
            && self.reviewer_count >= policy.override_quorum
            && now < self.expires_at
            && !matches!(decision.outcome, ScreeningOutcome::Cleared)
    }
}
impl CanonicalEncode for ScreeningOverrideV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.profile.encode(e)?;
        self.decision_commitment.encode(e)?;
        self.reviewer_set.encode(e)?;
        self.reason_commitment.encode(e)?;
        self.reviewer_count.encode(e)?;
        self.expires_at.encode(e)
    }
}
impl CanonicalDecode for ScreeningOverrideV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u8::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid screening override"))
    }
}
impl CanonicalType for ScreeningOverrideV1 {
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

/// Version-two provider attestation over an exact canonical evidence binding and chain context.
///
/// V1 remains decodable for archival inspection but is deliberately not accepted by production
/// admission because it did not bind the evidence body, provider, genesis, revision, or validity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComplianceSignatureEnvelopeV2 {
    provider: PrincipalId,
    profile: Digest384,
    chain_id: ChainId,
    genesis: Digest384,
    protocol_revision: u64,
    subject: Digest384,
    action: TransactionId,
    evidence_commitment: Digest384,
    valid_from: Height,
    valid_until: Height,
    nonce: Digest384,
    signature: ProtocolSignature,
}
impl ComplianceSignatureEnvelopeV2 {
    pub const TYPE_TAG: u16 = 0x0144;
    pub const SCHEMA_VERSION: u16 = 2;
    pub const MAX_ENCODED_LEN: usize = 48 * 9 + 8 * 3 + ProtocolSignature::MAX_ENCODED_LEN;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: PrincipalId,
        profile: Digest384,
        chain_id: ChainId,
        genesis: Digest384,
        protocol_revision: u64,
        subject: Digest384,
        action: TransactionId,
        evidence_commitment: Digest384,
        valid_from: Height,
        valid_until: Height,
        nonce: Digest384,
        signature: ProtocolSignature,
    ) -> Result<Self, ComplianceError> {
        if profile == Digest384::ZERO
            || genesis == Digest384::ZERO
            || subject == Digest384::ZERO
            || *action.digest() == Digest384::ZERO
            || evidence_commitment == Digest384::ZERO
            || nonce == Digest384::ZERO
        {
            return Err(ComplianceError::ZeroCommitment);
        }
        if valid_until < valid_from {
            return Err(ComplianceError::InvalidValidity);
        }
        Ok(Self {
            provider,
            profile,
            chain_id,
            genesis,
            protocol_revision,
            subject,
            action,
            evidence_commitment,
            valid_from,
            valid_until,
            nonce,
            signature,
        })
    }
    pub const fn provider(&self) -> PrincipalId {
        self.provider
    }
    pub const fn profile(&self) -> Digest384 {
        self.profile
    }
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn genesis(&self) -> Digest384 {
        self.genesis
    }
    pub const fn protocol_revision(&self) -> u64 {
        self.protocol_revision
    }
    pub const fn subject(&self) -> Digest384 {
        self.subject
    }
    pub const fn action(&self) -> TransactionId {
        self.action
    }
    pub const fn evidence_commitment(&self) -> Digest384 {
        self.evidence_commitment
    }
    pub const fn valid_from(&self) -> Height {
        self.valid_from
    }
    pub const fn valid_until(&self) -> Height {
        self.valid_until
    }
    pub const fn nonce(&self) -> Digest384 {
        self.nonce
    }
    pub const fn signature(&self) -> &ProtocolSignature {
        &self.signature
    }
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Self::MAX_ENCODED_LEN);
        self.provider.encode(&mut encoder).expect("validated field encodes");
        self.profile.encode(&mut encoder).expect("validated field encodes");
        self.chain_id.encode(&mut encoder).expect("validated field encodes");
        self.genesis.encode(&mut encoder).expect("validated field encodes");
        self.protocol_revision.encode(&mut encoder).expect("validated field encodes");
        self.subject.encode(&mut encoder).expect("validated field encodes");
        self.action.encode(&mut encoder).expect("validated field encodes");
        self.evidence_commitment.encode(&mut encoder).expect("validated field encodes");
        self.valid_from.encode(&mut encoder).expect("validated field encodes");
        self.valid_until.encode(&mut encoder).expect("validated field encodes");
        self.nonce.encode(&mut encoder).expect("validated field encodes");
        let bytes = encoder.finish();
        let mut payload = Vec::with_capacity(38 + bytes.len());
        payload.extend_from_slice(b"ACTIVECHAIN-COMPLIANCE-ATTESTATION-V2");
        payload.extend_from_slice(&bytes);
        payload
    }
    pub fn transcript_commitment(&self) -> Digest384 {
        let mut hasher = Shake256::default();
        hasher.update(&self.signing_payload());
        let mut output = [0_u8; 48];
        XofReader::read(&mut hasher.finalize_xof(), &mut output);
        Digest384::new(output)
    }
}
impl CanonicalEncode for ComplianceSignatureEnvelopeV2 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.provider.encode(e)?;
        self.profile.encode(e)?;
        self.chain_id.encode(e)?;
        self.genesis.encode(e)?;
        self.protocol_revision.encode(e)?;
        self.subject.encode(e)?;
        self.action.encode(e)?;
        self.evidence_commitment.encode(e)?;
        self.valid_from.encode(e)?;
        self.valid_until.encode(e)?;
        self.nonce.encode(e)?;
        self.signature.encode(e)
    }
}
impl CanonicalDecode for ComplianceSignatureEnvelopeV2 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            TransactionId::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            ProtocolSignature::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid v2 compliance attestation"))
    }
}
impl CanonicalType for ComplianceSignatureEnvelopeV2 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
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
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Self::MAX_ENCODED_LEN);
        self.profile.encode(&mut encoder).expect("validated field encodes");
        self.chain_id.encode(&mut encoder).expect("validated field encodes");
        self.action.encode(&mut encoder).expect("validated field encodes");
        self.commitment.encode(&mut encoder).expect("validated field encodes");
        self.nonce.encode(&mut encoder).expect("validated field encodes");
        let bytes = encoder.finish();
        let mut payload = Vec::with_capacity(38 + bytes.len());
        payload.extend_from_slice(b"ACTIVECHAIN-COMPLIANCE-SIGNATURE-V1");
        payload.extend_from_slice(&bytes);
        payload
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
    pub const fn genesis(self) -> Digest384 {
        self.genesis
    }
    pub const fn operator(self) -> PrincipalId {
        self.operator
    }
    pub const fn subject(self) -> Digest384 {
        self.subject
    }
    pub const fn valid_from(self) -> Height {
        self.valid_from
    }
    pub const fn valid_until(self) -> Height {
        self.valid_until
    }
    pub const fn nonce(self) -> Digest384 {
        self.nonce
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
    use crate::CryptoSuiteId;
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
        assert_eq!(
            select_profiles_with_inheritance(
                &[child],
                &[JurisdictionProfileInheritance {
                    profile: d(3),
                    parent: Some(d(99)),
                    stricter: true,
                }]
            ),
            ProfileSelection::Rejected
        );
        assert_eq!(
            select_profiles_with_inheritance(
                &[child],
                &[
                    JurisdictionProfileInheritance { profile: d(3), parent: None, stricter: true },
                    JurisdictionProfileInheritance { profile: d(3), parent: None, stricter: true },
                ]
            ),
            ProfileSelection::Rejected
        );
    }

    fn kenya_profile(
        activity: KenyaRegulatedActivity,
        controls: u32,
        stablecoin_commitments: bool,
    ) -> Result<KenyaRegulatedProfileV1, ComplianceError> {
        KenyaRegulatedProfileV1::new(
            d(1),
            PrincipalId::new(d(2)),
            activity,
            controls,
            d(3),
            d(4),
            d(5),
            d(6),
            d(7),
            d(8),
            d(9),
            d(10),
            d(11),
            d(12),
            d(13),
            d(14),
            if stablecoin_commitments { d(15) } else { Digest384::ZERO },
            if stablecoin_commitments { d(16) } else { Digest384::ZERO },
            if stablecoin_commitments { d(17) } else { Digest384::ZERO },
            if stablecoin_commitments { d(18) } else { Digest384::ZERO },
            100,
            200,
            1,
        )
    }

    #[test]
    fn kenya_vasp_profile_requires_every_cross_cutting_control() {
        let profile = kenya_profile(
            KenyaRegulatedActivity::VirtualAssetService,
            KenyaControlSet::VASP_REQUIRED,
            false,
        )
        .unwrap();
        assert_eq!(profile.activity(), KenyaRegulatedActivity::VirtualAssetService);
        assert!(profile.active_at(100));
        assert!(!profile.active_at(200));
        assert_eq!(
            decode_envelope::<KenyaRegulatedProfileV1>(&encode_envelope(&profile).unwrap()),
            Ok(profile)
        );
        assert_eq!(
            kenya_profile(
                KenyaRegulatedActivity::VirtualAssetService,
                KenyaControlSet::VASP_REQUIRED
                    & !KenyaControlSet::CDD_AML_AND_TRANSACTION_INFORMATION,
                false,
            ),
            Err(ComplianceError::InvalidJurisdictionProfile)
        );
    }

    #[test]
    fn kenya_stablecoin_profile_requires_specific_controls_and_commitments() {
        let profile = kenya_profile(
            KenyaRegulatedActivity::StablecoinIssuance,
            KenyaControlSet::STABLECOIN_REQUIRED,
            true,
        )
        .unwrap();
        assert_eq!(profile.control_set(), KenyaControlSet::STABLECOIN_REQUIRED);
        assert_eq!(
            decode_envelope::<KenyaRegulatedProfileV1>(&encode_envelope(&profile).unwrap()),
            Ok(profile)
        );
        assert_eq!(
            kenya_profile(
                KenyaRegulatedActivity::StablecoinIssuance,
                KenyaControlSet::VASP_REQUIRED,
                true,
            ),
            Err(ComplianceError::InvalidJurisdictionProfile)
        );
        assert_eq!(
            kenya_profile(
                KenyaRegulatedActivity::StablecoinIssuance,
                KenyaControlSet::STABLECOIN_REQUIRED,
                false,
            ),
            Err(ComplianceError::InvalidJurisdictionProfile)
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
        assert!(policy.accepts_for_action(
            &clear,
            ChainId::new(d(2)),
            TransactionId::new(d(3)),
            50,
        ));
        assert!(!policy.accepts_for_action(
            &clear,
            ChainId::new(d(9)),
            TransactionId::new(d(3)),
            50,
        ));

        let signed_policy = ScreeningPolicyV1::new(d(1), d(5), d(7), 100, 2, true).unwrap();
        assert!(!signed_policy.accepts_with_signature(&clear, None, 50));
        let signature = ComplianceSignatureEnvelopeV2::new(
            PrincipalId::new(d(9)),
            d(1),
            ChainId::new(d(2)),
            d(10),
            1,
            d(11),
            TransactionId::new(d(3)),
            clear.commitment().unwrap(),
            1,
            100,
            d(8),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        assert!(signed_policy.accepts_with_signature(&clear, Some(&signature), 50));
    }

    #[test]
    fn compliance_v2_transcript_is_frozen_and_canonical() {
        let attestation = ComplianceSignatureEnvelopeV2::new(
            PrincipalId::new(d(1)),
            d(2),
            ChainId::new(d(3)),
            d(4),
            7,
            d(5),
            TransactionId::new(d(6)),
            d(7),
            10,
            20,
            d(8),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<ComplianceSignatureEnvelopeV2>(
                &encode_envelope(&attestation).unwrap()
            ),
            Ok(attestation.clone())
        );
        assert_eq!(
            attestation.transcript_commitment(),
            Digest384::new([
                148, 230, 19, 108, 251, 162, 145, 142, 94, 155, 101, 2, 217, 167, 212, 197, 107,
                100, 163, 204, 245, 86, 130, 17, 80, 149, 47, 197, 97, 61, 18, 208, 7, 221, 210,
                23, 234, 45, 224, 183, 187, 125, 167, 157, 245, 221, 213, 254,
            ])
        );
        assert_eq!(
            include_str!("../../../testing/vectors/compliance-attestation-v2.txt"),
            "type_tag=0x0144\nschema_version=2\ntranscript_commitment=94e6136cfba2918e5e9b6502d9a7d4c56b64a3ccf556821150952fc5613d12d007ddd217ea2de0b7bb7da79df5ddd5fe\n"
        );
    }

    #[test]
    fn screening_override_requires_quorum_commitment_and_freshness() {
        let policy = ScreeningPolicyV1::new(d(1), d(5), d(7), 100, 2, false).unwrap();
        let decision = ScreeningDecisionV1::new(
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
        let override_record =
            ScreeningOverrideV1::new(d(1), decision.commitment().unwrap(), d(8), d(9), 2, 100)
                .unwrap();
        assert_eq!(
            decode_envelope::<ScreeningOverrideV1>(&encode_envelope(&override_record).unwrap()),
            Ok(override_record)
        );
        assert!(override_record.admits(&policy, &decision, 99));
        assert!(!override_record.admits(&policy, &decision, 100));
        let wrong_policy = ScreeningPolicyV1::new(d(10), d(5), d(7), 100, 2, false).unwrap();
        assert!(!override_record.admits(&wrong_policy, &decision, 50));
        let insufficient =
            ScreeningOverrideV1::new(d(1), decision.commitment().unwrap(), d(8), d(9), 1, 100)
                .unwrap();
        assert!(!insufficient.admits(&policy, &decision, 50));
    }

    #[test]
    fn retention_policy_is_commitment_only_and_strictly_bounded() {
        let policy = EvidenceRetentionPolicyV1::new(
            d(1),
            d(2),
            d(3),
            d(4),
            d(5),
            d(6),
            10_000,
            EvidenceDeletionMode::OnRequest,
            1,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<EvidenceRetentionPolicyV1>(&encode_envelope(&policy).unwrap()),
            Ok(policy)
        );
        assert_eq!(policy.deletion_mode(), EvidenceDeletionMode::OnRequest);
        assert!(policy.admits_disclosure(9_000, 10_000));
        assert!(!policy.admits_disclosure(10_001, 10_001));
        assert!(policy.supports_offline_verification());
        assert!(
            EvidenceRetentionPolicyV1::new(
                d(1),
                d(2),
                d(3),
                d(4),
                d(5),
                Digest384::ZERO,
                10_000,
                EvidenceDeletionMode::Scheduled,
                1,
            )
            .is_err()
        );
    }
}
