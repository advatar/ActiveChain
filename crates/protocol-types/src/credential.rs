//! Canonical off-chain credential, status-registry, and acceptance-policy values.

extern crate alloc;

use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};

use crate::{
    CryptoSuiteId, Digest384, Height, ObjectId, PrincipalId, ProtocolSignature, Timestamp,
};

/// Initial canonical credential format.
pub const CREDENTIAL_FORMAT_VERSION: u16 = 1;
/// Maximum accepted issuers in one development policy.
pub const MAX_ACCEPTED_CREDENTIAL_ISSUERS: usize = 32;
/// Maximum accepted schemas in one development policy.
pub const MAX_ACCEPTED_CREDENTIAL_SCHEMAS: usize = 32;

/// Canonical unsigned statement committed by a credential issuer signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialStatement {
    format_version: u16,
    issuer: PrincipalId,
    subject_binding: Digest384,
    schema_id: Digest384,
    claims_commitment: Digest384,
    issuance_height: Height,
    valid_from: Timestamp,
    valid_until: Option<Timestamp>,
    status_registry: Option<ObjectId>,
    issuance_log_root: Option<Digest384>,
    terms_commitment: Option<Digest384>,
}

impl CredentialStatement {
    /// Registered issuance-statement type tag.
    pub const TYPE_TAG: u16 = 0x0023;
    /// Initial issuance-statement schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Maximum canonical issuance-statement body length.
    pub const MAX_ENCODED_LEN: usize = 366;

    /// Validates the format version and inclusive timestamp interval.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        format_version: u16,
        issuer: PrincipalId,
        subject_binding: Digest384,
        schema_id: Digest384,
        claims_commitment: Digest384,
        issuance_height: Height,
        valid_from: Timestamp,
        valid_until: Option<Timestamp>,
        status_registry: Option<ObjectId>,
        issuance_log_root: Option<Digest384>,
        terms_commitment: Option<Digest384>,
    ) -> Result<Self, CredentialValidationError> {
        if format_version != CREDENTIAL_FORMAT_VERSION {
            return Err(CredentialValidationError::UnsupportedFormatVersion(format_version));
        }
        if let Some(valid_until) = valid_until
            && valid_until < valid_from
        {
            return Err(CredentialValidationError::ValidityEndsBeforeStart);
        }
        Ok(Self {
            format_version,
            issuer,
            subject_binding,
            schema_id,
            claims_commitment,
            issuance_height,
            valid_from,
            valid_until,
            status_registry,
            issuance_log_root,
            terms_commitment,
        })
    }

    /// Returns the versioned credential statement format.
    #[must_use]
    pub const fn format_version(self) -> u16 {
        self.format_version
    }

    /// Returns the issuer principal.
    #[must_use]
    pub const fn issuer(self) -> PrincipalId {
        self.issuer
    }

    /// Returns the opaque holder or private-subject binding.
    #[must_use]
    pub const fn subject_binding(self) -> Digest384 {
        self.subject_binding
    }

    /// Returns the application credential-schema commitment.
    #[must_use]
    pub const fn schema_id(self) -> Digest384 {
        self.schema_id
    }

    /// Returns the commitment to undisclosed or disclosed claims.
    #[must_use]
    pub const fn claims_commitment(self) -> Digest384 {
        self.claims_commitment
    }

    /// Returns the finalized height at which issuance was anchored.
    #[must_use]
    pub const fn issuance_height(self) -> Height {
        self.issuance_height
    }

    /// Returns the first inclusive valid timestamp.
    #[must_use]
    pub const fn valid_from(self) -> Timestamp {
        self.valid_from
    }

    /// Returns the optional final inclusive valid timestamp.
    #[must_use]
    pub const fn valid_until(self) -> Option<Timestamp> {
        self.valid_until
    }

    /// Returns the declared credential-status registry.
    #[must_use]
    pub const fn status_registry(self) -> Option<ObjectId> {
        self.status_registry
    }

    /// Returns the optional issuance-log root requiring external inclusion proof.
    #[must_use]
    pub const fn issuance_log_root(self) -> Option<Digest384> {
        self.issuance_log_root
    }

    /// Returns the optional legal or application terms commitment.
    #[must_use]
    pub const fn terms_commitment(self) -> Option<Digest384> {
        self.terms_commitment
    }
}

impl CanonicalEncode for CredentialStatement {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.format_version.encode(encoder)?;
        self.issuer.encode(encoder)?;
        self.subject_binding.encode(encoder)?;
        self.schema_id.encode(encoder)?;
        self.claims_commitment.encode(encoder)?;
        self.issuance_height.encode(encoder)?;
        self.valid_from.encode(encoder)?;
        self.valid_until.encode(encoder)?;
        self.status_registry.encode(encoder)?;
        self.issuance_log_root.encode(encoder)?;
        self.terms_commitment.encode(encoder)
    }
}

impl CanonicalDecode for CredentialStatement {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            u16::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            Option::<u64>::decode(decoder)?,
            Option::<ObjectId>::decode(decoder)?,
            Option::<Digest384>::decode(decoder)?,
            Option::<Digest384>::decode(decoder)?,
        )
        .map_err(credential_decode_error)
    }
}

impl CanonicalType for CredentialStatement {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Complete canonical signed credential retained off chain by its holder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    statement: CredentialStatement,
    issuer_signature: ProtocolSignature,
}

impl Credential {
    /// Registered signed-credential type tag.
    pub const TYPE_TAG: u16 = 0x0024;
    /// Initial signed-credential schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Maximum canonical signed-credential body length.
    pub const MAX_ENCODED_LEN: usize = 5_001;

    /// Requires a credential-issuance suite from the P-002 development profile.
    pub fn new(
        statement: CredentialStatement,
        issuer_signature: ProtocolSignature,
    ) -> Result<Self, CredentialValidationError> {
        let suite = issuer_signature.suite();
        if suite != CryptoSuiteId::ML_DSA_65 && suite != CryptoSuiteId::ML_DSA_87 {
            return Err(CredentialValidationError::UnsupportedIssuerSignatureSuite);
        }
        Ok(Self { statement, issuer_signature })
    }

    /// Returns the exact unsigned issuance statement.
    #[must_use]
    pub const fn statement(&self) -> CredentialStatement {
        self.statement
    }

    /// Borrows the structurally validated issuer signature.
    #[must_use]
    pub const fn issuer_signature(&self) -> &ProtocolSignature {
        &self.issuer_signature
    }
}

impl CanonicalEncode for Credential {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.statement.encode(encoder)?;
        self.issuer_signature.encode(encoder)
    }
}

impl CanonicalDecode for Credential {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(CredentialStatement::decode(decoder)?, ProtocolSignature::decode(decoder)?)
            .map_err(credential_decode_error)
    }
}

impl CanonicalType for Credential {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Canonical snapshot of one issuer's credential-status commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialStatusRegistry {
    registry_id: ObjectId,
    issuer: PrincipalId,
    schema_id: Digest384,
    status_root: Digest384,
    sequence: u64,
    effective_height: Height,
}

impl CredentialStatusRegistry {
    /// Registered status-registry type tag.
    pub const TYPE_TAG: u16 = 0x0025;
    /// Initial status-registry schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Fixed canonical status-registry body length.
    pub const ENCODED_LENGTH: usize = 208;

    /// Constructs an explicit registry snapshot.
    #[must_use]
    pub const fn new(
        registry_id: ObjectId,
        issuer: PrincipalId,
        schema_id: Digest384,
        status_root: Digest384,
        sequence: u64,
        effective_height: Height,
    ) -> Self {
        Self { registry_id, issuer, schema_id, status_root, sequence, effective_height }
    }

    /// Returns the address named by credential statements.
    #[must_use]
    pub const fn registry_id(self) -> ObjectId {
        self.registry_id
    }

    /// Returns the registry issuer.
    #[must_use]
    pub const fn issuer(self) -> PrincipalId {
        self.issuer
    }

    /// Returns the only schema covered by this version-1 registry.
    #[must_use]
    pub const fn schema_id(self) -> Digest384 {
        self.schema_id
    }

    /// Returns the externally proven status-tree root.
    #[must_use]
    pub const fn status_root(self) -> Digest384 {
        self.status_root
    }

    /// Returns the monotonic registry sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the finalized height at which this root became effective.
    #[must_use]
    pub const fn effective_height(self) -> Height {
        self.effective_height
    }
}

impl CanonicalEncode for CredentialStatusRegistry {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.registry_id.encode(encoder)?;
        self.issuer.encode(encoder)?;
        self.schema_id.encode(encoder)?;
        self.status_root.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.effective_height.encode(encoder)
    }
}

impl CanonicalDecode for CredentialStatusRegistry {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(
            ObjectId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        ))
    }
}

impl CanonicalType for CredentialStatusRegistry {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}

/// Canonical allowlists and evidence requirements for credential presentation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialAcceptancePolicy {
    accepted_issuers: Vec<PrincipalId>,
    accepted_schemas: Vec<Digest384>,
    maximum_status_age: u64,
    require_status: bool,
    require_issuance_log: bool,
}

impl CredentialAcceptancePolicy {
    /// Registered credential-acceptance-policy type tag.
    pub const TYPE_TAG: u16 = 0x0026;
    /// Initial acceptance-policy schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Worst-case canonical acceptance-policy body length.
    pub const MAX_ENCODED_LEN: usize = 3_084;

    /// Enforces bounded, strictly increasing issuer and schema sets.
    pub fn new(
        accepted_issuers: Vec<PrincipalId>,
        accepted_schemas: Vec<Digest384>,
        maximum_status_age: u64,
        require_status: bool,
        require_issuance_log: bool,
    ) -> Result<Self, CredentialValidationError> {
        if accepted_issuers.len() > MAX_ACCEPTED_CREDENTIAL_ISSUERS {
            return Err(CredentialValidationError::TooManyAcceptedIssuers {
                actual: accepted_issuers.len(),
                maximum: MAX_ACCEPTED_CREDENTIAL_ISSUERS,
            });
        }
        if !strictly_increasing(&accepted_issuers) {
            return Err(CredentialValidationError::AcceptedIssuersNotStrictlyIncreasing);
        }
        if accepted_schemas.len() > MAX_ACCEPTED_CREDENTIAL_SCHEMAS {
            return Err(CredentialValidationError::TooManyAcceptedSchemas {
                actual: accepted_schemas.len(),
                maximum: MAX_ACCEPTED_CREDENTIAL_SCHEMAS,
            });
        }
        if !strictly_increasing(&accepted_schemas) {
            return Err(CredentialValidationError::AcceptedSchemasNotStrictlyIncreasing);
        }
        Ok(Self {
            accepted_issuers,
            accepted_schemas,
            maximum_status_age,
            require_status,
            require_issuance_log,
        })
    }

    /// Borrows accepted issuers in canonical order.
    #[must_use]
    pub fn accepted_issuers(&self) -> &[PrincipalId] {
        &self.accepted_issuers
    }

    /// Borrows accepted schemas in canonical order.
    #[must_use]
    pub fn accepted_schemas(&self) -> &[Digest384] {
        &self.accepted_schemas
    }

    /// Returns the maximum status-root age in finalized blocks.
    #[must_use]
    pub const fn maximum_status_age(&self) -> u64 {
        self.maximum_status_age
    }

    /// Returns whether every credential must declare and prove status.
    #[must_use]
    pub const fn require_status(&self) -> bool {
        self.require_status
    }

    /// Returns whether issuance-log inclusion evidence is mandatory.
    #[must_use]
    pub const fn require_issuance_log(&self) -> bool {
        self.require_issuance_log
    }

    /// Checks issuer membership without data-dependent allocation.
    #[must_use]
    pub fn accepts_issuer(&self, issuer: &PrincipalId) -> bool {
        self.accepted_issuers.binary_search(issuer).is_ok()
    }

    /// Checks schema membership without data-dependent allocation.
    #[must_use]
    pub fn accepts_schema(&self, schema: &Digest384) -> bool {
        self.accepted_schemas.binary_search(schema).is_ok()
    }
}

impl CanonicalEncode for CredentialAcceptancePolicy {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.accepted_issuers.len(), MAX_ACCEPTED_CREDENTIAL_ISSUERS)?;
        for issuer in &self.accepted_issuers {
            issuer.encode(encoder)?;
        }
        encoder.write_length(self.accepted_schemas.len(), MAX_ACCEPTED_CREDENTIAL_SCHEMAS)?;
        for schema in &self.accepted_schemas {
            schema.encode(encoder)?;
        }
        self.maximum_status_age.encode(encoder)?;
        self.require_status.encode(encoder)?;
        self.require_issuance_log.encode(encoder)
    }
}

impl CanonicalDecode for CredentialAcceptancePolicy {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let issuer_count = decoder.read_length(MAX_ACCEPTED_CREDENTIAL_ISSUERS)?;
        let mut accepted_issuers = Vec::with_capacity(issuer_count);
        for _ in 0..issuer_count {
            accepted_issuers.push(PrincipalId::decode(decoder)?);
        }
        let schema_count = decoder.read_length(MAX_ACCEPTED_CREDENTIAL_SCHEMAS)?;
        let mut accepted_schemas = Vec::with_capacity(schema_count);
        for _ in 0..schema_count {
            accepted_schemas.push(Digest384::decode(decoder)?);
        }
        Self::new(
            accepted_issuers,
            accepted_schemas,
            u64::decode(decoder)?,
            bool::decode(decoder)?,
            bool::decode(decoder)?,
        )
        .map_err(credential_decode_error)
    }
}

impl CanonicalType for CredentialAcceptancePolicy {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Structural credential and acceptance-policy construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialValidationError {
    /// Only format version 1 is registered.
    UnsupportedFormatVersion(u16),
    /// The final valid timestamp predates the first one.
    ValidityEndsBeforeStart,
    /// Credential issuance permits only ML-DSA-65 and ML-DSA-87.
    UnsupportedIssuerSignatureSuite,
    /// The accepted issuer set exceeds its protocol bound.
    TooManyAcceptedIssuers { actual: usize, maximum: usize },
    /// Accepted issuers are duplicated or not canonically ordered.
    AcceptedIssuersNotStrictlyIncreasing,
    /// The accepted schema set exceeds its protocol bound.
    TooManyAcceptedSchemas { actual: usize, maximum: usize },
    /// Accepted schemas are duplicated or not canonically ordered.
    AcceptedSchemasNotStrictlyIncreasing,
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn credential_decode_error(error: CredentialValidationError) -> DecodeError {
    match error {
        CredentialValidationError::UnsupportedFormatVersion(_) => {
            DecodeError::InvalidValue("credential uses an unsupported format version")
        }
        CredentialValidationError::ValidityEndsBeforeStart => {
            DecodeError::InvalidValue("credential validity ends before it starts")
        }
        CredentialValidationError::UnsupportedIssuerSignatureSuite => {
            DecodeError::InvalidValue("credential uses an unsupported issuer signature suite")
        }
        CredentialValidationError::TooManyAcceptedIssuers { .. } => {
            DecodeError::InvalidValue("credential policy exceeds its issuer bound")
        }
        CredentialValidationError::AcceptedIssuersNotStrictlyIncreasing => {
            DecodeError::InvalidValue("credential policy issuers are not strictly increasing")
        }
        CredentialValidationError::TooManyAcceptedSchemas { .. } => {
            DecodeError::InvalidValue("credential policy exceeds its schema bound")
        }
        CredentialValidationError::AcceptedSchemasNotStrictlyIncreasing => {
            DecodeError::InvalidValue("credential policy schemas are not strictly increasing")
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;

    use activechain_canonical_codec::{decode_envelope, encode_body, encode_envelope};

    use super::{
        CREDENTIAL_FORMAT_VERSION, Credential, CredentialAcceptancePolicy, CredentialStatement,
        CredentialStatusRegistry, CredentialValidationError,
    };
    use crate::{CryptoSuiteId, Digest384, ObjectId, PrincipalId, ProtocolSignature};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }

    fn statement() -> CredentialStatement {
        CredentialStatement::new(
            CREDENTIAL_FORMAT_VERSION,
            principal(0x10),
            digest(0x20),
            digest(0x30),
            digest(0x40),
            7,
            1_000,
            Some(2_000),
            Some(ObjectId::new(digest(0x50))),
            Some(digest(0x60)),
            Some(digest(0x70)),
        )
        .expect("test statement is valid")
    }

    fn credential() -> Credential {
        Credential::new(
            statement(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, vec![0x80; 3_309])
                .expect("test signature is structurally valid"),
        )
        .expect("test credential is valid")
    }

    #[test]
    fn credential_values_round_trip_through_strict_envelopes() {
        let registry = CredentialStatusRegistry::new(
            ObjectId::new(digest(0x50)),
            principal(0x10),
            digest(0x30),
            digest(0x90),
            4,
            8,
        );
        let policy = CredentialAcceptancePolicy::new(
            vec![principal(0x10)],
            vec![digest(0x30)],
            10,
            true,
            true,
        )
        .expect("test policy is canonical");

        let statement_bytes = encode_envelope(&statement()).expect("statement encodes");
        assert_eq!(decode_envelope(&statement_bytes), Ok(statement()));
        let credential_bytes = encode_envelope(&credential()).expect("credential encodes");
        assert_eq!(decode_envelope(&credential_bytes), Ok(credential()));
        let registry_bytes = encode_envelope(&registry).expect("registry encodes");
        assert_eq!(decode_envelope(&registry_bytes), Ok(registry));
        let policy_bytes = encode_envelope(&policy).expect("policy encodes");
        assert_eq!(decode_envelope(&policy_bytes), Ok(policy));
    }

    #[test]
    fn statement_and_signature_profiles_reject_invalid_shapes() {
        assert_eq!(
            CredentialStatement::new(
                2,
                principal(1),
                digest(2),
                digest(3),
                digest(4),
                0,
                0,
                None,
                None,
                None,
                None,
            ),
            Err(CredentialValidationError::UnsupportedFormatVersion(2))
        );
        assert_eq!(
            CredentialStatement::new(
                1,
                principal(1),
                digest(2),
                digest(3),
                digest(4),
                0,
                10,
                Some(9),
                None,
                None,
                None,
            ),
            Err(CredentialValidationError::ValidityEndsBeforeStart)
        );
        let weak_signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420])
            .expect("valid ML-DSA-44");
        assert_eq!(
            Credential::new(statement(), weak_signature),
            Err(CredentialValidationError::UnsupportedIssuerSignatureSuite)
        );
    }

    #[test]
    fn acceptance_policy_requires_bounded_canonical_sets() {
        assert_eq!(
            CredentialAcceptancePolicy::new(
                vec![principal(2), principal(1)],
                vec![],
                0,
                false,
                false,
            ),
            Err(CredentialValidationError::AcceptedIssuersNotStrictlyIncreasing)
        );
        assert_eq!(
            CredentialAcceptancePolicy::new(vec![], vec![digest(1), digest(1)], 0, false, false,),
            Err(CredentialValidationError::AcceptedSchemasNotStrictlyIncreasing)
        );
        let too_many_issuers = (0_u8..33).map(principal).collect();
        assert!(matches!(
            CredentialAcceptancePolicy::new(too_many_issuers, vec![], 0, false, false,),
            Err(CredentialValidationError::TooManyAcceptedIssuers { .. })
        ));
        let too_many_schemas = (0_u8..33).map(digest).collect();
        assert!(matches!(
            CredentialAcceptancePolicy::new(vec![], too_many_schemas, 0, false, false,),
            Err(CredentialValidationError::TooManyAcceptedSchemas { .. })
        ));
    }

    #[test]
    fn published_credential_body_bounds_are_exact() {
        let maximum_statement = CredentialStatement::new(
            1,
            principal(0x10),
            digest(0x20),
            digest(0x30),
            digest(0x40),
            u64::MAX,
            0,
            Some(u64::MAX),
            Some(ObjectId::new(digest(0x50))),
            Some(digest(0x60)),
            Some(digest(0x70)),
        )
        .expect("maximum statement is valid");
        assert_eq!(
            encode_body(&maximum_statement).expect("maximum statement encodes").len(),
            CredentialStatement::MAX_ENCODED_LEN
        );
        let maximum_credential = Credential::new(
            maximum_statement,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_87, vec![0; 4_627])
                .expect("maximum issuance signature is valid"),
        )
        .expect("maximum credential is valid");
        assert_eq!(
            encode_body(&maximum_credential).expect("maximum credential encodes").len(),
            Credential::MAX_ENCODED_LEN
        );

        let maximum_policy = CredentialAcceptancePolicy::new(
            (0_u8..32).map(principal).collect(),
            (32_u8..64).map(digest).collect(),
            u64::MAX,
            true,
            true,
        )
        .expect("maximum policy is canonical");
        assert_eq!(
            encode_body(&maximum_policy).expect("maximum policy encodes").len(),
            CredentialAcceptancePolicy::MAX_ENCODED_LEN
        );

        let registry = CredentialStatusRegistry::new(
            ObjectId::new(digest(1)),
            principal(2),
            digest(3),
            digest(4),
            u64::MAX,
            u64::MAX,
        );
        assert_eq!(
            encode_body(&registry).expect("registry encodes").len(),
            CredentialStatusRegistry::ENCODED_LENGTH
        );
    }
}
