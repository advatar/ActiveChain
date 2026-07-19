//! Deterministic binding of external credential evidence to canonical values.

use alloc::vec::Vec;

use activechain_canonical_codec::EncodeError;
use activechain_policy_kernel::MAX_CREDENTIAL_FACTS;
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    Credential, CredentialAcceptancePolicy, CredentialId, CredentialStatement,
    CredentialStatusRegistry, CryptoSuiteId, Digest384, Height, ObjectId, PrincipalId, Timestamp,
};

/// Explicit finalized presentation context; the verifier reads no ambient clock or chain state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresentationContext {
    expected_subject_binding: Digest384,
    height: Height,
    timestamp: Timestamp,
}

impl PresentationContext {
    /// Constructs the exact subject and finalized time context.
    #[must_use]
    pub const fn new(
        expected_subject_binding: Digest384,
        height: Height,
        timestamp: Timestamp,
    ) -> Self {
        Self { expected_subject_binding, height, timestamp }
    }

    /// Returns the subject binding the presentation must open.
    #[must_use]
    pub const fn expected_subject_binding(self) -> Digest384 {
        self.expected_subject_binding
    }

    /// Returns the finalized presentation height.
    #[must_use]
    pub const fn height(self) -> Height {
        self.height
    }

    /// Returns the explicitly admitted presentation timestamp.
    #[must_use]
    pub const fn timestamp(self) -> Timestamp {
        self.timestamp
    }
}

/// Evidence produced only after verifying the exact issuer signature and optional log proof.
///
/// This semantic value is deliberately not a canonical signature verifier. Callers MUST create it
/// only after checking the credential signature with the named issuer's active issuance key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreverifiedIssuerEvidence {
    issuer: PrincipalId,
    issuance_commitment: Digest384,
    signature_suite: CryptoSuiteId,
    verified_issuance_log_root: Option<Digest384>,
}

impl PreverifiedIssuerEvidence {
    /// Binds an external issuer-verification result to one exact issuance transcript.
    #[must_use]
    pub const fn new(
        issuer: PrincipalId,
        issuance_commitment: Digest384,
        signature_suite: CryptoSuiteId,
        verified_issuance_log_root: Option<Digest384>,
    ) -> Self {
        Self { issuer, issuance_commitment, signature_suite, verified_issuance_log_root }
    }
}

/// Externally proven credential status at one exact registry snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialStatus {
    /// The credential is valid according to the issuer registry.
    Active,
    /// The issuer has permanently revoked the credential.
    Revoked,
    /// The issuer has temporarily suspended the credential.
    Suspended,
}

/// Evidence produced only after verifying status inclusion against the exact registry root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreverifiedStatusEvidence {
    registry_id: ObjectId,
    credential_id: CredentialId,
    status_root: Digest384,
    registry_sequence: u64,
    status: CredentialStatus,
}

impl PreverifiedStatusEvidence {
    /// Binds an external status proof to one credential and registry snapshot.
    #[must_use]
    pub const fn new(
        registry_id: ObjectId,
        credential_id: CredentialId,
        status_root: Digest384,
        registry_sequence: u64,
        status: CredentialStatus,
    ) -> Self {
        Self { registry_id, credential_id, status_root, registry_sequence, status }
    }
}

/// Private-constructor fact safe for the current P-023 credential-schema boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedCredentialFact {
    credential_id: CredentialId,
    issuer: PrincipalId,
    subject_binding: Digest384,
    schema_id: Digest384,
    verified_at_height: Height,
    status_registry_sequence: Option<u64>,
}

impl VerifiedCredentialFact {
    /// Returns the complete signed credential identifier.
    #[must_use]
    pub const fn credential_id(self) -> CredentialId {
        self.credential_id
    }

    /// Returns the accepted issuer.
    #[must_use]
    pub const fn issuer(self) -> PrincipalId {
        self.issuer
    }

    /// Returns the exact subject binding verified for this presentation.
    #[must_use]
    pub const fn subject_binding(self) -> Digest384 {
        self.subject_binding
    }

    /// Returns the schema fact accepted by P-021 policy.
    #[must_use]
    pub const fn schema_id(self) -> Digest384 {
        self.schema_id
    }

    /// Returns the finalized height of verification.
    #[must_use]
    pub const fn verified_at_height(self) -> Height {
        self.verified_at_height
    }

    /// Returns the verified status-registry sequence, when status was declared.
    #[must_use]
    pub const fn status_registry_sequence(self) -> Option<u64> {
        self.status_registry_sequence
    }
}

/// Derives the identifier of a complete signed credential.
pub fn credential_id(credential: &Credential) -> Result<CredentialId, EncodeError> {
    commit(DomainTag::CREDENTIAL_ID, credential).map(CredentialId::new)
}

/// Derives the exact unsigned transcript checked by the issuer signature verifier.
pub fn credential_issuance_commitment(
    statement: &CredentialStatement,
) -> Result<Digest384, EncodeError> {
    commit(DomainTag::CREDENTIAL_ISSUANCE, statement)
}

/// Verifies every deterministic credential, policy, time, and evidence binding.
pub fn verify_presentation(
    credential: &Credential,
    policy: &CredentialAcceptancePolicy,
    issuer_evidence: &PreverifiedIssuerEvidence,
    registry: Option<&CredentialStatusRegistry>,
    status_evidence: Option<&PreverifiedStatusEvidence>,
    context: PresentationContext,
) -> Result<VerifiedCredentialFact, CredentialVerificationError> {
    let statement = credential.statement();
    if statement.issuance_height() > context.height {
        return Err(CredentialVerificationError::NotYetIssued {
            issuance_height: statement.issuance_height(),
            presentation_height: context.height,
        });
    }
    if context.timestamp < statement.valid_from() {
        return Err(CredentialVerificationError::NotYetValid {
            valid_from: statement.valid_from(),
            presentation_time: context.timestamp,
        });
    }
    if let Some(valid_until) = statement.valid_until()
        && context.timestamp > valid_until
    {
        return Err(CredentialVerificationError::Expired {
            valid_until,
            presentation_time: context.timestamp,
        });
    }
    if statement.subject_binding() != context.expected_subject_binding {
        return Err(CredentialVerificationError::SubjectBindingMismatch);
    }
    if !policy.accepts_issuer(&statement.issuer()) {
        return Err(CredentialVerificationError::IssuerNotAccepted);
    }
    if !policy.accepts_schema(&statement.schema_id()) {
        return Err(CredentialVerificationError::SchemaNotAccepted);
    }

    let issuance_commitment = credential_issuance_commitment(&statement)
        .map_err(CredentialVerificationError::CommitmentEncoding)?;
    if issuer_evidence.issuer != statement.issuer() {
        return Err(CredentialVerificationError::IssuerEvidenceIssuerMismatch);
    }
    if issuer_evidence.issuance_commitment != issuance_commitment {
        return Err(CredentialVerificationError::IssuerEvidenceCommitmentMismatch);
    }
    if issuer_evidence.signature_suite != credential.issuer_signature().suite() {
        return Err(CredentialVerificationError::IssuerEvidenceSuiteMismatch);
    }
    verify_issuance_log(statement, policy, issuer_evidence)?;

    let id = credential_id(credential).map_err(CredentialVerificationError::CommitmentEncoding)?;
    let status_registry_sequence =
        verify_status(statement, policy, id, registry, status_evidence, context.height)?;

    Ok(VerifiedCredentialFact {
        credential_id: id,
        issuer: statement.issuer(),
        subject_binding: statement.subject_binding(),
        schema_id: statement.schema_id(),
        verified_at_height: context.height,
        status_registry_sequence,
    })
}

fn verify_issuance_log(
    statement: CredentialStatement,
    policy: &CredentialAcceptancePolicy,
    evidence: &PreverifiedIssuerEvidence,
) -> Result<(), CredentialVerificationError> {
    if policy.require_issuance_log() && statement.issuance_log_root().is_none() {
        return Err(CredentialVerificationError::IssuanceLogRequired);
    }
    if let Some(verified_root) = evidence.verified_issuance_log_root
        && statement.issuance_log_root() != Some(verified_root)
    {
        return Err(CredentialVerificationError::IssuanceLogEvidenceMismatch);
    }
    if policy.require_issuance_log()
        && evidence.verified_issuance_log_root != statement.issuance_log_root()
    {
        return Err(CredentialVerificationError::IssuanceLogEvidenceMismatch);
    }
    Ok(())
}

fn verify_status(
    statement: CredentialStatement,
    policy: &CredentialAcceptancePolicy,
    credential_id: CredentialId,
    registry: Option<&CredentialStatusRegistry>,
    evidence: Option<&PreverifiedStatusEvidence>,
    height: Height,
) -> Result<Option<u64>, CredentialVerificationError> {
    let Some(declared_registry_id) = statement.status_registry() else {
        if policy.require_status() {
            return Err(CredentialVerificationError::StatusRequired);
        }
        if registry.is_some() || evidence.is_some() {
            return Err(CredentialVerificationError::UnexpectedStatusMaterial);
        }
        return Ok(None);
    };

    let registry = registry.ok_or(CredentialVerificationError::MissingStatusRegistry)?;
    let evidence = evidence.ok_or(CredentialVerificationError::MissingStatusEvidence)?;
    if registry.registry_id() != declared_registry_id {
        return Err(CredentialVerificationError::RegistryIdMismatch);
    }
    if registry.issuer() != statement.issuer() {
        return Err(CredentialVerificationError::RegistryIssuerMismatch);
    }
    if registry.schema_id() != statement.schema_id() {
        return Err(CredentialVerificationError::RegistrySchemaMismatch);
    }
    if registry.effective_height() > height {
        return Err(CredentialVerificationError::RegistryFromFuture {
            effective_height: registry.effective_height(),
            presentation_height: height,
        });
    }
    let age = height - registry.effective_height();
    if age > policy.maximum_status_age() {
        return Err(CredentialVerificationError::RegistryStale {
            age,
            maximum: policy.maximum_status_age(),
        });
    }
    if evidence.registry_id != registry.registry_id() {
        return Err(CredentialVerificationError::StatusEvidenceRegistryMismatch);
    }
    if evidence.credential_id != credential_id {
        return Err(CredentialVerificationError::StatusEvidenceCredentialMismatch);
    }
    if evidence.status_root != registry.status_root() {
        return Err(CredentialVerificationError::StatusEvidenceRootMismatch);
    }
    if evidence.registry_sequence != registry.sequence() {
        return Err(CredentialVerificationError::StatusEvidenceSequenceMismatch);
    }
    match evidence.status {
        CredentialStatus::Active => Ok(Some(registry.sequence())),
        CredentialStatus::Revoked => Err(CredentialVerificationError::CredentialRevoked),
        CredentialStatus::Suspended => Err(CredentialVerificationError::CredentialSuspended),
    }
}

/// Produces the bounded, sorted, duplicate-free schema fact set required by P-023.
pub fn canonical_schema_facts(
    facts: &[VerifiedCredentialFact],
) -> Result<Vec<Digest384>, CredentialFactError> {
    let mut schemas: Vec<_> = facts.iter().map(|fact| fact.schema_id()).collect();
    schemas.sort_unstable();
    schemas.dedup();
    if schemas.len() > MAX_CREDENTIAL_FACTS {
        return Err(CredentialFactError::TooManyDistinctSchemas {
            actual: schemas.len(),
            maximum: MAX_CREDENTIAL_FACTS,
        });
    }
    Ok(schemas)
}

/// Deterministic credential presentation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialVerificationError {
    /// The credential claims an issuance height after the presentation block.
    NotYetIssued { issuance_height: Height, presentation_height: Height },
    /// The explicit timestamp predates the inclusive validity start.
    NotYetValid { valid_from: Timestamp, presentation_time: Timestamp },
    /// The explicit timestamp exceeds the inclusive validity end.
    Expired { valid_until: Timestamp, presentation_time: Timestamp },
    /// The presentation opens another subject binding.
    SubjectBindingMismatch,
    /// The acceptance policy does not name this issuer.
    IssuerNotAccepted,
    /// The acceptance policy does not name this schema.
    SchemaNotAccepted,
    /// Preverified signature evidence names another issuer.
    IssuerEvidenceIssuerMismatch,
    /// Preverified signature evidence binds another unsigned statement.
    IssuerEvidenceCommitmentMismatch,
    /// Preverified signature evidence names another signature suite.
    IssuerEvidenceSuiteMismatch,
    /// Policy requires an issuance-log root but the credential declares none.
    IssuanceLogRequired,
    /// External issuance-log evidence is missing or binds another root.
    IssuanceLogEvidenceMismatch,
    /// Policy requires status but the credential declares no registry.
    StatusRequired,
    /// Status material was supplied for a credential which declares none.
    UnexpectedStatusMaterial,
    /// A declared status registry snapshot was not supplied.
    MissingStatusRegistry,
    /// A declared status proof result was not supplied.
    MissingStatusEvidence,
    /// The supplied snapshot has another registry identifier.
    RegistryIdMismatch,
    /// The supplied registry is owned by another issuer.
    RegistryIssuerMismatch,
    /// The supplied registry covers another schema.
    RegistrySchemaMismatch,
    /// The registry root is not yet effective at the presentation height.
    RegistryFromFuture { effective_height: Height, presentation_height: Height },
    /// The registry root exceeds the policy's freshness window.
    RegistryStale { age: u64, maximum: u64 },
    /// Status evidence names another registry.
    StatusEvidenceRegistryMismatch,
    /// Status evidence names another signed credential.
    StatusEvidenceCredentialMismatch,
    /// Status evidence was checked against another root.
    StatusEvidenceRootMismatch,
    /// Status evidence was checked against another registry sequence.
    StatusEvidenceSequenceMismatch,
    /// The issuer has revoked this credential.
    CredentialRevoked,
    /// The issuer has suspended this credential.
    CredentialSuspended,
    /// A validated canonical value unexpectedly failed to encode for commitment.
    CommitmentEncoding(EncodeError),
}

/// Failures while adapting verified facts to the bounded P-023 request shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialFactError {
    /// More than 32 distinct verified schemas were supplied.
    TooManyDistinctSchemas { actual: usize, maximum: usize },
}
