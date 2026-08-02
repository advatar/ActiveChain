//! Native post-quantum companions for externally verified credentials.

extern crate alloc;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    ChainId, CredentialAssuranceClassV1, CryptoSuiteId, Digest384, Height, PrincipalId,
    ProtocolSignature,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompanionCredentialError {
    InvalidIdentity,
    InvalidValidity,
    InvalidAssuranceTransition,
    ProfileMismatch,
    IssuerMismatch,
    SubjectMismatch,
    OriginalCredentialMismatch,
    StatusMismatch,
    Stale,
    Revoked,
    WrongNetwork,
    SignatureSuite,
    InvalidSignature,
}

/// Governance rule that alone may authorize an assurance increase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompanionAssurancePolicyV1 {
    chain: ChainId,
    chain_genesis: Digest384,
    external_profile: Digest384,
    external_issuer: PrincipalId,
    companion_issuer: PrincipalId,
    source_assurance: CredentialAssuranceClassV1,
    maximum_assurance: CredentialAssuranceClassV1,
    authorization_commitment: Digest384,
    revision: u64,
}

impl CompanionAssurancePolicyV1 {
    pub const TYPE_TAG: u16 = 0x0193;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 6 + 2 + 8;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: ChainId,
        chain_genesis: Digest384,
        external_profile: Digest384,
        external_issuer: PrincipalId,
        companion_issuer: PrincipalId,
        source_assurance: CredentialAssuranceClassV1,
        maximum_assurance: CredentialAssuranceClassV1,
        authorization_commitment: Digest384,
        revision: u64,
    ) -> Result<Self, CompanionCredentialError> {
        if [chain_genesis, external_profile, authorization_commitment]
            .into_iter()
            .any(|v| v == Digest384::ZERO)
            || external_issuer.digest() == &Digest384::ZERO
            || companion_issuer.digest() == &Digest384::ZERO
            || revision == 0
        {
            return Err(CompanionCredentialError::InvalidIdentity);
        }
        if maximum_assurance < source_assurance {
            return Err(CompanionCredentialError::InvalidAssuranceTransition);
        }
        Ok(Self {
            chain,
            chain_genesis,
            external_profile,
            external_issuer,
            companion_issuer,
            source_assurance,
            maximum_assurance,
            authorization_commitment,
            revision,
        })
    }

    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commitment(b"ACTIVECHAIN-COMPANION-ASSURANCE-POLICY-V1", self)
    }
}

impl CanonicalEncode for CompanionAssurancePolicyV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain.encode(e)?;
        self.chain_genesis.encode(e)?;
        self.external_profile.encode(e)?;
        self.external_issuer.encode(e)?;
        self.companion_issuer.encode(e)?;
        self.source_assurance.encode(e)?;
        self.maximum_assurance.encode(e)?;
        self.authorization_commitment.encode(e)?;
        self.revision.encode(e)
    }
}
impl CanonicalDecode for CompanionAssurancePolicyV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            PrincipalId::decode(d)?,
            CredentialAssuranceClassV1::decode(d)?,
            CredentialAssuranceClassV1::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid companion assurance policy"))
    }
}
impl CanonicalType for CompanionAssurancePolicyV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Unsigned statement covered by the companion issuer's ML-DSA signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalCredentialCompanionV1 {
    chain: ChainId,
    chain_genesis: Digest384,
    original_credential_commitment: Digest384,
    external_profile: Digest384,
    external_issuer: PrincipalId,
    companion_issuer: PrincipalId,
    subject_binding: Digest384,
    schema_id: Digest384,
    claims_commitment: Digest384,
    source_assurance: CredentialAssuranceClassV1,
    assurance: CredentialAssuranceClassV1,
    assurance_policy_commitment: Digest384,
    external_status_commitment: Digest384,
    native_status_commitment: Option<Digest384>,
    terms_commitment: Option<Digest384>,
    issued_at_height: Height,
    valid_until_height: Height,
}

impl ExternalCredentialCompanionV1 {
    pub const TYPE_TAG: u16 = 0x0194;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 8 + 48 * 12 + 2 + 49 * 2 + 16;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: ChainId,
        chain_genesis: Digest384,
        original_credential_commitment: Digest384,
        external_profile: Digest384,
        external_issuer: PrincipalId,
        companion_issuer: PrincipalId,
        subject_binding: Digest384,
        schema_id: Digest384,
        claims_commitment: Digest384,
        source_assurance: CredentialAssuranceClassV1,
        assurance: CredentialAssuranceClassV1,
        assurance_policy_commitment: Digest384,
        external_status_commitment: Digest384,
        native_status_commitment: Option<Digest384>,
        terms_commitment: Option<Digest384>,
        issued_at_height: Height,
        valid_until_height: Height,
    ) -> Result<Self, CompanionCredentialError> {
        if [
            chain_genesis,
            original_credential_commitment,
            external_profile,
            subject_binding,
            schema_id,
            claims_commitment,
            assurance_policy_commitment,
            external_status_commitment,
        ]
        .into_iter()
        .any(|v| v == Digest384::ZERO)
            || external_issuer.digest() == &Digest384::ZERO
            || companion_issuer.digest() == &Digest384::ZERO
            || native_status_commitment == Some(Digest384::ZERO)
            || terms_commitment == Some(Digest384::ZERO)
        {
            return Err(CompanionCredentialError::InvalidIdentity);
        }
        if issued_at_height == 0 || valid_until_height <= issued_at_height {
            return Err(CompanionCredentialError::InvalidValidity);
        }
        if assurance < source_assurance {
            return Err(CompanionCredentialError::InvalidAssuranceTransition);
        }
        Ok(Self {
            chain,
            chain_genesis,
            original_credential_commitment,
            external_profile,
            external_issuer,
            companion_issuer,
            subject_binding,
            schema_id,
            claims_commitment,
            source_assurance,
            assurance,
            assurance_policy_commitment,
            external_status_commitment,
            native_status_commitment,
            terms_commitment,
            issued_at_height,
            valid_until_height,
        })
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commitment(b"ACTIVECHAIN-EXTERNAL-CREDENTIAL-COMPANION-V1", self)
    }
    pub const fn schema_id(&self) -> Digest384 {
        self.schema_id
    }
    pub const fn assurance(&self) -> CredentialAssuranceClassV1 {
        self.assurance
    }
    pub const fn subject_binding(&self) -> Digest384 {
        self.subject_binding
    }
    pub const fn companion_issuer(&self) -> PrincipalId {
        self.companion_issuer
    }
    pub const fn external_issuer(&self) -> PrincipalId {
        self.external_issuer
    }
    pub const fn external_profile(&self) -> Digest384 {
        self.external_profile
    }
    pub const fn claims_commitment(&self) -> Digest384 {
        self.claims_commitment
    }
    pub const fn assurance_policy_commitment(&self) -> Digest384 {
        self.assurance_policy_commitment
    }
    pub const fn external_status_commitment(&self) -> Digest384 {
        self.external_status_commitment
    }
    pub const fn native_status_commitment(&self) -> Option<Digest384> {
        self.native_status_commitment
    }
    pub const fn original_credential_commitment(&self) -> Digest384 {
        self.original_credential_commitment
    }
}

impl CanonicalEncode for ExternalCredentialCompanionV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain.encode(e)?;
        self.chain_genesis.encode(e)?;
        self.original_credential_commitment.encode(e)?;
        self.external_profile.encode(e)?;
        self.external_issuer.encode(e)?;
        self.companion_issuer.encode(e)?;
        self.subject_binding.encode(e)?;
        self.schema_id.encode(e)?;
        self.claims_commitment.encode(e)?;
        self.source_assurance.encode(e)?;
        self.assurance.encode(e)?;
        self.assurance_policy_commitment.encode(e)?;
        self.external_status_commitment.encode(e)?;
        self.native_status_commitment.encode(e)?;
        self.terms_commitment.encode(e)?;
        self.issued_at_height.encode(e)?;
        self.valid_until_height.encode(e)
    }
}
impl CanonicalDecode for ExternalCredentialCompanionV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            CredentialAssuranceClassV1::decode(d)?,
            CredentialAssuranceClassV1::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Option::<Digest384>::decode(d)?,
            Option::<Digest384>::decode(d)?,
            Height::decode(d)?,
            Height::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid external credential companion"))
    }
}
impl CanonicalType for ExternalCredentialCompanionV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedExternalCredentialCompanionV1 {
    statement: ExternalCredentialCompanionV1,
    signature: ProtocolSignature,
}
impl SignedExternalCredentialCompanionV1 {
    pub const TYPE_TAG: u16 = 0x0195;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        ExternalCredentialCompanionV1::MAX_ENCODED_LEN + ProtocolSignature::MAX_ENCODED_LEN;
    pub fn new(
        statement: ExternalCredentialCompanionV1,
        signature: ProtocolSignature,
    ) -> Result<Self, CompanionCredentialError> {
        if !matches!(signature.suite(), CryptoSuiteId::ML_DSA_65 | CryptoSuiteId::ML_DSA_87) {
            return Err(CompanionCredentialError::SignatureSuite);
        }
        Ok(Self { statement, signature })
    }
    pub const fn statement(&self) -> &ExternalCredentialCompanionV1 {
        &self.statement
    }
    pub const fn signature(&self) -> &ProtocolSignature {
        &self.signature
    }
}
impl CanonicalEncode for SignedExternalCredentialCompanionV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.statement.encode(e)?;
        self.signature.encode(e)
    }
}
impl CanonicalDecode for SignedExternalCredentialCompanionV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(ExternalCredentialCompanionV1::decode(d)?, ProtocolSignature::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid signed companion"))
    }
}
impl CanonicalType for SignedExternalCredentialCompanionV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[allow(clippy::too_many_arguments)]
pub fn validate_companion(
    signed: &SignedExternalCredentialCompanionV1,
    policy: &CompanionAssurancePolicyV1,
    chain: ChainId,
    genesis: Digest384,
    original: Digest384,
    subject: Digest384,
    external_status: Digest384,
    native_status: Option<Digest384>,
    height: Height,
    external_revoked: bool,
    native_revoked: bool,
    signature_valid: bool,
) -> Result<(), CompanionCredentialError> {
    let s = signed.statement();
    if s.chain != chain || s.chain_genesis != genesis {
        return Err(CompanionCredentialError::WrongNetwork);
    }
    if s.original_credential_commitment != original {
        return Err(CompanionCredentialError::OriginalCredentialMismatch);
    }
    if s.subject_binding != subject {
        return Err(CompanionCredentialError::SubjectMismatch);
    }
    if s.external_profile != policy.external_profile {
        return Err(CompanionCredentialError::ProfileMismatch);
    }
    if s.external_issuer != policy.external_issuer || s.companion_issuer != policy.companion_issuer
    {
        return Err(CompanionCredentialError::IssuerMismatch);
    }
    if s.assurance_policy_commitment
        != policy.commitment().map_err(|_| CompanionCredentialError::InvalidIdentity)?
        || s.source_assurance != policy.source_assurance
        || s.assurance > policy.maximum_assurance
    {
        return Err(CompanionCredentialError::InvalidAssuranceTransition);
    }
    if s.external_status_commitment != external_status
        || s.native_status_commitment != native_status
    {
        return Err(CompanionCredentialError::StatusMismatch);
    }
    if external_revoked || native_revoked {
        return Err(CompanionCredentialError::Revoked);
    }
    if height < s.issued_at_height || height >= s.valid_until_height {
        return Err(CompanionCredentialError::Stale);
    }
    if !signature_valid {
        return Err(CompanionCredentialError::InvalidSignature);
    }
    Ok(())
}

fn commitment<T: CanonicalType>(domain: &[u8], value: &T) -> Result<Digest384, EncodeError> {
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

    fn d(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    fn p(n: u8) -> PrincipalId {
        PrincipalId::new(d(n))
    }
    fn policy() -> CompanionAssurancePolicyV1 {
        CompanionAssurancePolicyV1::new(
            ChainId::new(d(7)),
            d(1),
            d(2),
            p(3),
            p(4),
            CredentialAssuranceClassV1::HolderSelfIssued,
            CredentialAssuranceClassV1::IssuerUpgraded,
            d(5),
            1,
        )
        .unwrap()
    }
    fn signed() -> SignedExternalCredentialCompanionV1 {
        let policy = policy();
        let statement = ExternalCredentialCompanionV1::new(
            ChainId::new(d(7)),
            d(1),
            d(6),
            d(2),
            p(3),
            p(4),
            d(7),
            d(8),
            d(9),
            CredentialAssuranceClassV1::HolderSelfIssued,
            CredentialAssuranceClassV1::IssuerUpgraded,
            policy.commitment().unwrap(),
            d(10),
            Some(d(11)),
            Some(d(12)),
            20,
            40,
        )
        .unwrap();
        SignedExternalCredentialCompanionV1::new(
            statement,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, alloc::vec![13; 3_309]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_roundtrip_and_exact_binding_accept() {
        let signed = signed();
        assert_eq!(
            decode_envelope::<SignedExternalCredentialCompanionV1>(
                &encode_envelope(&signed).unwrap()
            ),
            Ok(signed.clone())
        );
        assert_eq!(
            validate_companion(
                &signed,
                &policy(),
                ChainId::new(d(7)),
                d(1),
                d(6),
                d(7),
                d(10),
                Some(d(11)),
                30,
                false,
                false,
                true
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_substitution_escalation_status_disagreement_and_revocation() {
        let signed = signed();
        let policy = policy();
        let check = |original, status, native, revoked, signature| {
            validate_companion(
                &signed,
                &policy,
                ChainId::new(d(7)),
                d(1),
                original,
                d(7),
                status,
                native,
                30,
                revoked,
                false,
                signature,
            )
        };
        assert_eq!(
            check(d(99), d(10), Some(d(11)), false, true),
            Err(CompanionCredentialError::OriginalCredentialMismatch)
        );
        assert_eq!(
            check(d(6), d(99), Some(d(11)), false, true),
            Err(CompanionCredentialError::StatusMismatch)
        );
        assert_eq!(
            check(d(6), d(10), None, false, true),
            Err(CompanionCredentialError::StatusMismatch)
        );
        assert_eq!(
            check(d(6), d(10), Some(d(11)), true, true),
            Err(CompanionCredentialError::Revoked)
        );
        assert_eq!(
            check(d(6), d(10), Some(d(11)), false, false),
            Err(CompanionCredentialError::InvalidSignature)
        );
        let too_strong = CompanionAssurancePolicyV1::new(
            ChainId::new(d(7)),
            d(1),
            d(2),
            p(3),
            p(4),
            CredentialAssuranceClassV1::HolderSelfIssued,
            CredentialAssuranceClassV1::RegulatedAttestation,
            d(5),
            1,
        )
        .unwrap();
        assert_eq!(
            validate_companion(
                &signed,
                &too_strong,
                ChainId::new(d(7)),
                d(1),
                d(6),
                d(7),
                d(10),
                Some(d(11)),
                30,
                false,
                false,
                true
            ),
            Err(CompanionCredentialError::InvalidAssuranceTransition)
        );
    }

    #[test]
    fn rejects_non_ml_dsa_and_downgrade() {
        let statement = *signed().statement();
        let es256 =
            ProtocolSignature::new(CryptoSuiteId::SLH_DSA_SHAKE_192S, alloc::vec![0; 16_224])
                .unwrap();
        assert_eq!(
            SignedExternalCredentialCompanionV1::new(statement, es256),
            Err(CompanionCredentialError::SignatureSuite)
        );
        assert_eq!(
            CompanionAssurancePolicyV1::new(
                ChainId::new(d(7)),
                d(1),
                d(2),
                p(3),
                p(4),
                CredentialAssuranceClassV1::RegulatedAttestation,
                CredentialAssuranceClassV1::HolderSelfIssued,
                d(5),
                1
            ),
            Err(CompanionCredentialError::InvalidAssuranceTransition)
        );
    }

    #[test]
    fn published_companion_vector_has_closed_boundaries() {
        let vector = include_str!("../../../testing/vectors/external-companion-credential-v1.tsv");
        let allowed = ["companion", "policy", "status", "signature", "authorization"];
        let mut accepted = 0;
        let mut rejected = 0;
        for line in vector.lines().skip(1) {
            let fields: alloc::vec::Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 4, "{line}");
            assert!(allowed.contains(&fields[2]));
            match fields[1] {
                "accept" => accepted += 1,
                "reject" => rejected += 1,
                other => panic!("unknown vector result {other}"),
            }
        }
        assert_eq!((accepted, rejected), (1, 14));
    }
}
