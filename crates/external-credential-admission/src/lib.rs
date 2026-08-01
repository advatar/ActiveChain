//! Opaque P-021 admission and P-023 fact derivation for external credentials.

use activechain_external_credential_adapter::VerifiedExternalPresentation;
use activechain_policy_kernel::{MAX_CREDENTIAL_FACTS, PolicyRequest, PolicyRequestFields};
use activechain_protocol_types::{
    CredentialAssuranceClassV1, Digest384, PrincipalId, VcIssuerFormatV1,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_EXTERNAL_ADMISSION_ENTRIES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalCredentialAcceptancePolicy {
    issuers: Vec<PrincipalId>,
    configurations: Vec<Digest384>,
    schemas: Vec<Digest384>,
    minimum_assurance: CredentialAssuranceClassV1,
    maximum_status_age: u64,
    require_issuance_log: bool,
    purpose_commitment: Digest384,
    verifier_version: u16,
    proof_version: u16,
    revision: u64,
}
impl ExternalCredentialAcceptancePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuers: Vec<PrincipalId>,
        configurations: Vec<Digest384>,
        schemas: Vec<Digest384>,
        minimum_assurance: CredentialAssuranceClassV1,
        maximum_status_age: u64,
        require_issuance_log: bool,
        purpose_commitment: Digest384,
        verifier_version: u16,
        proof_version: u16,
        revision: u64,
    ) -> Result<Self, ExternalAdmissionError> {
        if issuers.is_empty()
            || configurations.is_empty()
            || schemas.is_empty()
            || [issuers.len(), configurations.len(), schemas.len()]
                .into_iter()
                .any(|n| n > MAX_EXTERNAL_ADMISSION_ENTRIES)
            || !strict(&issuers)
            || !strict(&configurations)
            || !strict(&schemas)
            || purpose_commitment == Digest384::ZERO
            || verifier_version == 0
            || proof_version == 0
            || revision == 0
        {
            return Err(ExternalAdmissionError::MalformedPolicy);
        }
        Ok(Self {
            issuers,
            configurations,
            schemas,
            minimum_assurance,
            maximum_status_age,
            require_issuance_log,
            purpose_commitment,
            verifier_version,
            proof_version,
            revision,
        })
    }
    pub fn commitment(&self) -> Digest384 {
        let mut h = Shake256::default();
        h.update(b"ACTIVECHAIN-EXTERNAL-CREDENTIAL-POLICY-V1");
        for v in &self.issuers {
            h.update(v.digest().as_bytes())
        }
        for v in &self.configurations {
            h.update(v.as_bytes())
        }
        for v in &self.schemas {
            h.update(v.as_bytes())
        }
        h.update(&[self.minimum_assurance as u8]);
        h.update(&self.maximum_status_age.to_be_bytes());
        h.update(&[u8::from(self.require_issuance_log)]);
        h.update(self.purpose_commitment.as_bytes());
        h.update(&self.verifier_version.to_be_bytes());
        h.update(&self.proof_version.to_be_bytes());
        h.update(&self.revision.to_be_bytes());
        let mut out = [0; 48];
        XofReader::read(&mut h.finalize_xof(), &mut out);
        Digest384::new(out)
    }
}
fn strict<T: Ord>(v: &[T]) -> bool {
    v.windows(2).all(|p| p[0] < p[1])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedExternalCredentialFact {
    issuer: PrincipalId,
    schema_id: Digest384,
    subject_binding: Digest384,
    format: VcIssuerFormatV1,
    assurance: CredentialAssuranceClassV1,
    verified_at_height: u64,
    policy_commitment: Digest384,
    replay_nullifier: Digest384,
}
impl VerifiedExternalCredentialFact {
    pub const fn schema_id(self) -> Digest384 {
        self.schema_id
    }
    pub const fn issuer(self) -> PrincipalId {
        self.issuer
    }
    pub const fn subject_binding(self) -> Digest384 {
        self.subject_binding
    }
    pub const fn format(self) -> VcIssuerFormatV1 {
        self.format
    }
    pub const fn assurance(self) -> CredentialAssuranceClassV1 {
        self.assurance
    }
    pub const fn verified_at_height(self) -> u64 {
        self.verified_at_height
    }
    pub const fn policy_commitment(self) -> Digest384 {
        self.policy_commitment
    }
    pub const fn replay_nullifier(self) -> Digest384 {
        self.replay_nullifier
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalAdmissionReceipt {
    pub policy_commitment: Digest384,
    pub issuer_authorization_commitment: Digest384,
    pub status_commitment: Digest384,
    pub replay_nullifier: Digest384,
    pub result: ExternalAdmissionResult,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalAdmissionResult {
    Admitted,
    Rejected(ExternalAdmissionError),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalAdmissionError {
    MalformedPolicy,
    IssuerNotAccepted,
    ProfileNotAccepted,
    SchemaNotAccepted,
    AssuranceTooLow,
    StatusTooOld,
    IssuanceLogRequired,
    PurposeMismatch,
    VerifierVersionMismatch,
    ProofVersionMismatch,
    SubjectMismatch,
    TooManyFacts,
}

pub fn admit_external_presentation(
    verified: VerifiedExternalPresentation,
    policy: &ExternalCredentialAcceptancePolicy,
    expected_subject_binding: Digest384,
) -> Result<(VerifiedExternalCredentialFact, ExternalAdmissionReceipt), ExternalAdmissionReceipt> {
    let p = verified.presentation();
    let policy_commitment = policy.commitment();
    let receipt = |result| ExternalAdmissionReceipt {
        policy_commitment,
        issuer_authorization_commitment: p.issuer_authorization_commitment(),
        status_commitment: p.status_commitment(),
        replay_nullifier: verified.replay_nullifier(),
        result,
    };
    let failure = if policy.issuers.binary_search(&p.issuer()).is_err() {
        Some(ExternalAdmissionError::IssuerNotAccepted)
    } else if policy.configurations.binary_search(&verified.configuration_commitment()).is_err() {
        Some(ExternalAdmissionError::ProfileNotAccepted)
    } else if policy.schemas.binary_search(&p.predicate().schema_id()).is_err() {
        Some(ExternalAdmissionError::SchemaNotAccepted)
    } else if p.assurance() < policy.minimum_assurance {
        Some(ExternalAdmissionError::AssuranceTooLow)
    } else if verified.status_age() > policy.maximum_status_age {
        Some(ExternalAdmissionError::StatusTooOld)
    } else if policy.require_issuance_log && !verified.has_issuance_log() {
        Some(ExternalAdmissionError::IssuanceLogRequired)
    } else if verified.purpose_commitment() != policy.purpose_commitment {
        Some(ExternalAdmissionError::PurposeMismatch)
    } else if verified.verifier_version() != policy.verifier_version {
        Some(ExternalAdmissionError::VerifierVersionMismatch)
    } else if verified.proof_version() != policy.proof_version {
        Some(ExternalAdmissionError::ProofVersionMismatch)
    } else if verified.subject_binding() != expected_subject_binding {
        Some(ExternalAdmissionError::SubjectMismatch)
    } else {
        None
    };
    if let Some(e) = failure {
        return Err(receipt(ExternalAdmissionResult::Rejected(e)));
    }
    let fact = VerifiedExternalCredentialFact {
        issuer: p.issuer(),
        schema_id: p.predicate().schema_id(),
        subject_binding: verified.subject_binding(),
        format: p.format(),
        assurance: p.assurance(),
        verified_at_height: p.verified_at_height(),
        policy_commitment,
        replay_nullifier: verified.replay_nullifier(),
    };
    Ok((fact, receipt(ExternalAdmissionResult::Admitted)))
}
pub fn canonical_external_schema_facts(
    facts: &[VerifiedExternalCredentialFact],
) -> Result<Vec<Digest384>, ExternalAdmissionError> {
    let mut v: Vec<_> = facts.iter().map(|f| f.schema_id()).collect();
    v.sort_unstable();
    v.dedup();
    if v.len() > MAX_CREDENTIAL_FACTS {
        return Err(ExternalAdmissionError::TooManyFacts);
    }
    Ok(v)
}

/// Injects only admitted schema facts while preserving authenticated actor, capability, approval,
/// resource, purpose, limit, and lifecycle facts supplied by their respective verifiers.
pub fn inject_external_schema_facts(
    mut fields: PolicyRequestFields,
    facts: &[VerifiedExternalCredentialFact],
) -> Result<PolicyRequest, ExternalAdmissionError> {
    fields.credential_schemas.extend(canonical_external_schema_facts(facts)?);
    fields.credential_schemas.sort_unstable();
    fields.credential_schemas.dedup();
    if fields.credential_schemas.len() > MAX_CREDENTIAL_FACTS {
        return Err(ExternalAdmissionError::TooManyFacts);
    }
    PolicyRequest::new(fields).map_err(|_| ExternalAdmissionError::MalformedPolicy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_external_credential_adapter::testing_verified_external_presentation;
    use activechain_policy_kernel::{ActorBinding, ApprovalFact, PolicyRequestFields};
    use activechain_protocol_types::{
        ActionId, CapabilityId, ChainId, CredentialPredicateKind, CredentialPredicateV1,
        FreezeState, ObjectId, TransactionId, VcIssuerPresentationV1,
    };
    fn d(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    fn principal(n: u8) -> PrincipalId {
        PrincipalId::new(d(n))
    }
    fn purpose() -> Digest384 {
        let mut h = Shake256::default();
        h.update(b"ACTIVECHAIN-OPENID4VP-PURPOSE-V1");
        h.update(b"age-check");
        let mut out = [0; 48];
        XofReader::read(&mut h.finalize_xof(), &mut out);
        Digest384::new(out)
    }
    fn verified() -> VerifiedExternalPresentation {
        let predicate = CredentialPredicateV1::new(
            d(3),
            d(4),
            d(5),
            ChainId::new(d(6)),
            principal(7),
            TransactionId::new(d(8)),
            d(9),
            1,
            20,
            CredentialPredicateKind::AgeAtLeast,
            d(10),
        )
        .unwrap();
        let p = VcIssuerPresentationV1::new(
            principal(1),
            VcIssuerFormatV1::SdJwtVc,
            d(11),
            d(12),
            d(13),
            CredentialAssuranceClassV1::IssuerUpgraded,
            predicate,
            10,
            ChainId::new(d(6)),
            principal(7),
            TransactionId::new(d(8)),
        )
        .unwrap();
        testing_verified_external_presentation(p, d(2), d(5), purpose(), 8, 2, true, 1, 1, d(14))
    }
    fn policy() -> ExternalCredentialAcceptancePolicy {
        ExternalCredentialAcceptancePolicy::new(
            vec![principal(1)],
            vec![d(2)],
            vec![d(3)],
            CredentialAssuranceClassV1::IssuerUpgraded,
            3,
            true,
            purpose(),
            1,
            1,
            1,
        )
        .unwrap()
    }
    #[test]
    fn opaque_adapter_result_admits_and_derives_only_schema_fact() {
        let (fact, receipt) = admit_external_presentation(verified(), &policy(), d(5)).unwrap();
        assert_eq!(fact.schema_id(), d(3));
        assert_eq!(receipt.result, ExternalAdmissionResult::Admitted);
        assert_eq!(canonical_external_schema_facts(&[fact]).unwrap(), vec![d(3)]);
    }
    #[test]
    fn policy_subject_assurance_and_freshness_substitution_fail_closed() {
        let low = ExternalCredentialAcceptancePolicy::new(
            vec![principal(1)],
            vec![d(2)],
            vec![d(3)],
            CredentialAssuranceClassV1::RegulatedAttestation,
            3,
            true,
            purpose(),
            1,
            1,
            1,
        )
        .unwrap();
        assert_eq!(
            admit_external_presentation(verified(), &low, d(5)).unwrap_err().result,
            ExternalAdmissionResult::Rejected(ExternalAdmissionError::AssuranceTooLow)
        );
        assert_eq!(
            admit_external_presentation(verified(), &policy(), d(40)).unwrap_err().result,
            ExternalAdmissionResult::Rejected(ExternalAdmissionError::SubjectMismatch)
        );
        let stale = ExternalCredentialAcceptancePolicy::new(
            vec![principal(1)],
            vec![d(2)],
            vec![d(3)],
            CredentialAssuranceClassV1::IssuerUpgraded,
            1,
            true,
            purpose(),
            1,
            1,
            1,
        )
        .unwrap();
        assert_eq!(
            admit_external_presentation(verified(), &stale, d(5)).unwrap_err().result,
            ExternalAdmissionResult::Rejected(ExternalAdmissionError::StatusTooOld)
        );
    }
    #[test]
    fn issuer_schema_profile_and_purpose_are_closed_allowlists() {
        for policy in [
            ExternalCredentialAcceptancePolicy::new(
                vec![principal(2)],
                vec![d(2)],
                vec![d(3)],
                CredentialAssuranceClassV1::IssuerUpgraded,
                3,
                true,
                purpose(),
                1,
                1,
                1,
            )
            .unwrap(),
            ExternalCredentialAcceptancePolicy::new(
                vec![principal(1)],
                vec![d(20)],
                vec![d(3)],
                CredentialAssuranceClassV1::IssuerUpgraded,
                3,
                true,
                purpose(),
                1,
                1,
                1,
            )
            .unwrap(),
            ExternalCredentialAcceptancePolicy::new(
                vec![principal(1)],
                vec![d(2)],
                vec![d(30)],
                CredentialAssuranceClassV1::IssuerUpgraded,
                3,
                true,
                purpose(),
                1,
                1,
                1,
            )
            .unwrap(),
        ] {
            assert!(admit_external_presentation(verified(), &policy, d(5)).is_err())
        }
    }
    #[test]
    fn p023_injection_preserves_independent_authority_and_approval_facts() {
        let (fact, _) = admit_external_presentation(verified(), &policy(), d(5)).unwrap();
        let capability = CapabilityId::new(d(41));
        let approval = ApprovalFact::new(d(42), 2).unwrap();
        let request = inject_external_schema_facts(
            PolicyRequestFields {
                actor: ActorBinding::Principal(principal(7)),
                action: ActionId::new(d(43)),
                resource: ObjectId::new(d(44)),
                height: 10,
                value: 5,
                freeze_state: FreezeState::Active,
                declared_purpose: Some(purpose()),
                credential_schemas: vec![],
                capabilities: vec![capability],
                approvals: vec![approval],
            },
            &[fact],
        )
        .unwrap();
        assert_eq!(request.credential_schemas(), &[d(3)]);
        assert_eq!(request.capabilities(), &[capability]);
        assert_eq!(request.approvals(), &[approval]);
    }
}
