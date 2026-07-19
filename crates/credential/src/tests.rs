extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use activechain_protocol_types::{
    CREDENTIAL_FORMAT_VERSION, Credential, CredentialAcceptancePolicy, CredentialStatement,
    CredentialStatusRegistry, CryptoSuiteId, Digest384, ObjectId, PrincipalId, ProtocolSignature,
};
use proptest::prelude::*;

use crate::{
    CredentialFactError, CredentialStatus, CredentialVerificationError, PresentationContext,
    PreverifiedIssuerEvidence, PreverifiedStatusEvidence, canonical_schema_facts, credential_id,
    credential_issuance_commitment, verify_presentation,
};

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn principal(byte: u8) -> PrincipalId {
    PrincipalId::new(digest(byte))
}

fn registry_id() -> ObjectId {
    ObjectId::new(digest(0x50))
}

fn statement(
    schema: Digest384,
    issuance_height: u64,
    valid_from: u64,
    valid_until: Option<u64>,
    status_registry: Option<ObjectId>,
    issuance_log_root: Option<Digest384>,
) -> CredentialStatement {
    CredentialStatement::new(
        CREDENTIAL_FORMAT_VERSION,
        principal(0x10),
        digest(0x20),
        schema,
        digest(0x40),
        issuance_height,
        valid_from,
        valid_until,
        status_registry,
        issuance_log_root,
        Some(digest(0x70)),
    )
    .expect("test credential statement is valid")
}

fn credential_from(statement: CredentialStatement, signature_byte: u8) -> Credential {
    Credential::new(
        statement,
        ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, vec![signature_byte; 3_309])
            .expect("test issuer signature is structurally valid"),
    )
    .expect("test signed credential is valid")
}

fn credential() -> Credential {
    credential_from(
        statement(digest(0x30), 40, 900, Some(1_100), Some(registry_id()), Some(digest(0x60))),
        0x80,
    )
}

fn policy(
    maximum_status_age: u64,
    require_status: bool,
    require_issuance_log: bool,
) -> CredentialAcceptancePolicy {
    CredentialAcceptancePolicy::new(
        vec![principal(0x10)],
        vec![digest(0x30)],
        maximum_status_age,
        require_status,
        require_issuance_log,
    )
    .expect("test acceptance policy is canonical")
}

fn registry(effective_height: u64) -> CredentialStatusRegistry {
    CredentialStatusRegistry::new(
        registry_id(),
        principal(0x10),
        digest(0x30),
        digest(0x90),
        4,
        effective_height,
    )
}

fn issuer_evidence(
    credential: &Credential,
    verified_log: Option<Digest384>,
) -> PreverifiedIssuerEvidence {
    PreverifiedIssuerEvidence::new(
        credential.statement().issuer(),
        credential_issuance_commitment(&credential.statement()).expect("statement commits"),
        credential.issuer_signature().suite(),
        verified_log,
    )
}

fn status_evidence(
    credential: &Credential,
    registry: CredentialStatusRegistry,
    status: CredentialStatus,
) -> PreverifiedStatusEvidence {
    PreverifiedStatusEvidence::new(
        registry.registry_id(),
        credential_id(credential).expect("credential commits"),
        registry.status_root(),
        registry.sequence(),
        status,
    )
}

fn context() -> PresentationContext {
    PresentationContext::new(digest(0x20), 50, 1_000)
}

#[test]
fn valid_presentation_binds_every_fact_and_apl_adapter_is_canonical() {
    let credential = credential();
    let registry = registry(45);
    let fact = verify_presentation(
        &credential,
        &policy(5, true, true),
        &issuer_evidence(&credential, Some(digest(0x60))),
        Some(&registry),
        Some(&status_evidence(&credential, registry, CredentialStatus::Active)),
        context(),
    )
    .expect("valid credential presentation is accepted");

    assert_eq!(fact.credential_id(), credential_id(&credential).expect("credential commits"));
    assert_eq!(fact.issuer(), principal(0x10));
    assert_eq!(fact.subject_binding(), digest(0x20));
    assert_eq!(fact.schema_id(), digest(0x30));
    assert_eq!(fact.verified_at_height(), 50);
    assert_eq!(fact.status_registry_sequence(), Some(4));
    assert_eq!(canonical_schema_facts(&[fact, fact]), Ok(vec![digest(0x30)]));
}

#[test]
fn credential_identifier_binds_signature_while_issuance_commitment_does_not() {
    let base_statement = statement(digest(0x30), 40, 900, Some(1_100), None, None);
    let first = credential_from(base_statement, 0x80);
    let second = credential_from(base_statement, 0x81);
    assert_eq!(
        credential_issuance_commitment(&first.statement()),
        credential_issuance_commitment(&second.statement())
    );
    assert_ne!(credential_id(&first), credential_id(&second));

    let changed = credential_from(statement(digest(0x31), 40, 900, Some(1_100), None, None), 0x80);
    assert_ne!(
        credential_issuance_commitment(&first.statement()),
        credential_issuance_commitment(&changed.statement())
    );
    assert_ne!(credential_id(&first), credential_id(&changed));
}

#[test]
fn height_time_subject_issuer_and_schema_checks_are_total() {
    let no_status_policy = policy(u64::MAX, false, false);
    let cases = [
        (
            credential_from(statement(digest(0x30), 51, 900, None, None, None), 1),
            context(),
            CredentialVerificationError::NotYetIssued {
                issuance_height: 51,
                presentation_height: 50,
            },
        ),
        (
            credential_from(statement(digest(0x30), 40, 1_001, None, None, None), 2),
            context(),
            CredentialVerificationError::NotYetValid {
                valid_from: 1_001,
                presentation_time: 1_000,
            },
        ),
        (
            credential_from(statement(digest(0x30), 40, 900, Some(999), None, None), 3),
            context(),
            CredentialVerificationError::Expired { valid_until: 999, presentation_time: 1_000 },
        ),
        (
            credential_from(statement(digest(0x30), 40, 900, None, None, None), 4),
            PresentationContext::new(digest(0x21), 50, 1_000),
            CredentialVerificationError::SubjectBindingMismatch,
        ),
    ];
    for (credential, context, expected) in cases {
        assert_eq!(
            verify_presentation(
                &credential,
                &no_status_policy,
                &issuer_evidence(&credential, None),
                None,
                None,
                context,
            ),
            Err(expected)
        );
    }

    let credential = credential_from(statement(digest(0x30), 40, 900, None, None, None), 5);
    let wrong_issuer_policy =
        CredentialAcceptancePolicy::new(vec![principal(0x11)], vec![digest(0x30)], 0, false, false)
            .expect("wrong issuer policy is canonical");
    assert_eq!(
        verify_presentation(
            &credential,
            &wrong_issuer_policy,
            &issuer_evidence(&credential, None),
            None,
            None,
            context(),
        ),
        Err(CredentialVerificationError::IssuerNotAccepted)
    );
    let wrong_schema_policy =
        CredentialAcceptancePolicy::new(vec![principal(0x10)], vec![digest(0x31)], 0, false, false)
            .expect("wrong schema policy is canonical");
    assert_eq!(
        verify_presentation(
            &credential,
            &wrong_schema_policy,
            &issuer_evidence(&credential, None),
            None,
            None,
            context(),
        ),
        Err(CredentialVerificationError::SchemaNotAccepted)
    );
}

#[test]
fn issuer_and_issuance_log_evidence_must_bind_exactly() {
    let credential =
        credential_from(statement(digest(0x30), 40, 900, None, None, Some(digest(0x60))), 0x80);
    let base = issuer_evidence(&credential, Some(digest(0x60)));
    let wrong_issuer = PreverifiedIssuerEvidence::new(
        principal(0x11),
        credential_issuance_commitment(&credential.statement()).expect("commits"),
        CryptoSuiteId::ML_DSA_65,
        Some(digest(0x60)),
    );
    assert_eq!(
        verify_presentation(
            &credential,
            &policy(0, false, true),
            &wrong_issuer,
            None,
            None,
            context()
        ),
        Err(CredentialVerificationError::IssuerEvidenceIssuerMismatch)
    );
    let wrong_commitment = PreverifiedIssuerEvidence::new(
        principal(0x10),
        digest(0xff),
        CryptoSuiteId::ML_DSA_65,
        Some(digest(0x60)),
    );
    assert_eq!(
        verify_presentation(
            &credential,
            &policy(0, false, true),
            &wrong_commitment,
            None,
            None,
            context(),
        ),
        Err(CredentialVerificationError::IssuerEvidenceCommitmentMismatch)
    );
    let wrong_suite = PreverifiedIssuerEvidence::new(
        principal(0x10),
        credential_issuance_commitment(&credential.statement()).expect("commits"),
        CryptoSuiteId::ML_DSA_87,
        Some(digest(0x60)),
    );
    assert_eq!(
        verify_presentation(
            &credential,
            &policy(0, false, true),
            &wrong_suite,
            None,
            None,
            context()
        ),
        Err(CredentialVerificationError::IssuerEvidenceSuiteMismatch)
    );
    assert_eq!(
        verify_presentation(
            &credential,
            &policy(0, false, true),
            &issuer_evidence(&credential, None),
            None,
            None,
            context(),
        ),
        Err(CredentialVerificationError::IssuanceLogEvidenceMismatch)
    );

    let no_log = credential_from(statement(digest(0x30), 40, 900, None, None, None), 0x81);
    assert_eq!(
        verify_presentation(
            &no_log,
            &policy(0, false, true),
            &issuer_evidence(&no_log, None),
            None,
            None,
            context(),
        ),
        Err(CredentialVerificationError::IssuanceLogRequired)
    );
    assert!(
        verify_presentation(&credential, &policy(0, false, true), &base, None, None, context(),)
            .is_ok()
    );
}

#[test]
fn declared_and_required_status_material_cannot_be_discarded_or_invented() {
    let no_status = credential_from(statement(digest(0x30), 40, 900, None, None, None), 1);
    assert_eq!(
        verify_presentation(
            &no_status,
            &policy(5, true, false),
            &issuer_evidence(&no_status, None),
            None,
            None,
            context(),
        ),
        Err(CredentialVerificationError::StatusRequired)
    );
    let registry = registry(45);
    let invented = status_evidence(&no_status, registry, CredentialStatus::Active);
    assert_eq!(
        verify_presentation(
            &no_status,
            &policy(5, false, false),
            &issuer_evidence(&no_status, None),
            Some(&registry),
            Some(&invented),
            context(),
        ),
        Err(CredentialVerificationError::UnexpectedStatusMaterial)
    );

    let credential = credential();
    assert_eq!(
        verify_presentation(
            &credential,
            &policy(5, false, true),
            &issuer_evidence(&credential, Some(digest(0x60))),
            None,
            None,
            context(),
        ),
        Err(CredentialVerificationError::MissingStatusRegistry)
    );
    assert_eq!(
        verify_presentation(
            &credential,
            &policy(5, false, true),
            &issuer_evidence(&credential, Some(digest(0x60))),
            Some(&registry),
            None,
            context(),
        ),
        Err(CredentialVerificationError::MissingStatusEvidence)
    );
}

#[test]
fn registry_identity_freshness_and_status_proof_are_exact() {
    let credential = credential();
    let issuer = issuer_evidence(&credential, Some(digest(0x60)));
    let base = registry(45);
    let active = status_evidence(&credential, base, CredentialStatus::Active);

    let wrong_id = CredentialStatusRegistry::new(
        ObjectId::new(digest(0x51)),
        base.issuer(),
        base.schema_id(),
        base.status_root(),
        base.sequence(),
        base.effective_height(),
    );
    assert_eq!(
        verify_presentation(
            &credential,
            &policy(5, true, true),
            &issuer,
            Some(&wrong_id),
            Some(&active),
            context(),
        ),
        Err(CredentialVerificationError::RegistryIdMismatch)
    );
    let wrong_issuer = CredentialStatusRegistry::new(
        base.registry_id(),
        principal(0x11),
        base.schema_id(),
        base.status_root(),
        base.sequence(),
        base.effective_height(),
    );
    assert_eq!(
        verify_presentation(
            &credential,
            &policy(5, true, true),
            &issuer,
            Some(&wrong_issuer),
            Some(&active),
            context(),
        ),
        Err(CredentialVerificationError::RegistryIssuerMismatch)
    );
    let wrong_schema = CredentialStatusRegistry::new(
        base.registry_id(),
        base.issuer(),
        digest(0x31),
        base.status_root(),
        base.sequence(),
        base.effective_height(),
    );
    assert_eq!(
        verify_presentation(
            &credential,
            &policy(5, true, true),
            &issuer,
            Some(&wrong_schema),
            Some(&active),
            context(),
        ),
        Err(CredentialVerificationError::RegistrySchemaMismatch)
    );
    let future = registry(51);
    assert_eq!(
        verify_presentation(
            &credential,
            &policy(5, true, true),
            &issuer,
            Some(&future),
            Some(&status_evidence(&credential, future, CredentialStatus::Active)),
            context(),
        ),
        Err(CredentialVerificationError::RegistryFromFuture {
            effective_height: 51,
            presentation_height: 50,
        })
    );
    let stale = registry(44);
    assert_eq!(
        verify_presentation(
            &credential,
            &policy(5, true, true),
            &issuer,
            Some(&stale),
            Some(&status_evidence(&credential, stale, CredentialStatus::Active)),
            context(),
        ),
        Err(CredentialVerificationError::RegistryStale { age: 6, maximum: 5 })
    );

    for (evidence, error) in [
        (
            PreverifiedStatusEvidence::new(
                ObjectId::new(digest(0x51)),
                credential_id(&credential).expect("commits"),
                base.status_root(),
                base.sequence(),
                CredentialStatus::Active,
            ),
            CredentialVerificationError::StatusEvidenceRegistryMismatch,
        ),
        (
            PreverifiedStatusEvidence::new(
                base.registry_id(),
                activechain_protocol_types::CredentialId::new(digest(0x52)),
                base.status_root(),
                base.sequence(),
                CredentialStatus::Active,
            ),
            CredentialVerificationError::StatusEvidenceCredentialMismatch,
        ),
        (
            PreverifiedStatusEvidence::new(
                base.registry_id(),
                credential_id(&credential).expect("commits"),
                digest(0x91),
                base.sequence(),
                CredentialStatus::Active,
            ),
            CredentialVerificationError::StatusEvidenceRootMismatch,
        ),
        (
            PreverifiedStatusEvidence::new(
                base.registry_id(),
                credential_id(&credential).expect("commits"),
                base.status_root(),
                5,
                CredentialStatus::Active,
            ),
            CredentialVerificationError::StatusEvidenceSequenceMismatch,
        ),
        (
            status_evidence(&credential, base, CredentialStatus::Revoked),
            CredentialVerificationError::CredentialRevoked,
        ),
        (
            status_evidence(&credential, base, CredentialStatus::Suspended),
            CredentialVerificationError::CredentialSuspended,
        ),
    ] {
        assert_eq!(
            verify_presentation(
                &credential,
                &policy(5, true, true),
                &issuer,
                Some(&base),
                Some(&evidence),
                context(),
            ),
            Err(error)
        );
    }
}

#[test]
fn schema_fact_adapter_sorts_deduplicates_and_enforces_the_apl_bound() {
    let mut facts = Vec::new();
    for byte in (0_u8..33).rev() {
        let credential = credential_from(statement(digest(byte), 0, 0, None, None, None), byte);
        let policy = CredentialAcceptancePolicy::new(
            vec![principal(0x10)],
            vec![digest(byte)],
            0,
            false,
            false,
        )
        .expect("single-schema policy is canonical");
        facts.push(
            verify_presentation(
                &credential,
                &policy,
                &issuer_evidence(&credential, None),
                None,
                None,
                context(),
            )
            .expect("fixture credential verifies"),
        );
    }
    assert_eq!(
        canonical_schema_facts(&facts),
        Err(CredentialFactError::TooManyDistinctSchemas { actual: 33, maximum: 32 })
    );
    facts.pop();
    assert_eq!(
        canonical_schema_facts(&facts).expect("32 distinct schemas fit"),
        (1_u8..33).map(digest).collect::<Vec<_>>()
    );
    facts.push(facts[0]);
    assert_eq!(canonical_schema_facts(&facts).expect("duplicates collapse").len(), 32);
}

proptest! {
    #[test]
    fn status_freshness_is_inclusive(age in any::<u64>(), maximum in any::<u64>()) {
        let credential = credential_from(
            statement(
                digest(0x30),
                0,
                900,
                Some(1_100),
                Some(registry_id()),
                Some(digest(0x60)),
            ),
            0x80,
        );
        let registry = registry(0);
        let result = verify_presentation(
            &credential,
            &policy(maximum, true, true),
            &issuer_evidence(&credential, Some(digest(0x60))),
            Some(&registry),
            Some(&status_evidence(&credential, registry, CredentialStatus::Active)),
            PresentationContext::new(digest(0x20), age, 1_000),
        );
        if age <= maximum {
            prop_assert!(result.is_ok());
        } else {
            prop_assert_eq!(
                result,
                Err(CredentialVerificationError::RegistryStale { age, maximum })
            );
        }
    }
}
