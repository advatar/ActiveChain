//! Canonical off-chain credential, status-registry, and acceptance-policy values.

extern crate alloc;

use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    ChainId, CryptoSuiteId, Digest384, Height, ObjectId, PrincipalId, ProtocolSignature, Timestamp,
    TransactionId,
};

/// Initial canonical credential format.
pub const CREDENTIAL_FORMAT_VERSION: u16 = 1;
/// Maximum accepted issuers in one development policy.
pub const MAX_ACCEPTED_CREDENTIAL_ISSUERS: usize = 32;
/// Maximum accepted schemas in one development policy.
pub const MAX_ACCEPTED_CREDENTIAL_SCHEMAS: usize = 32;

/// Provenance class retained from TLS evidence through credential and predicate verification.
/// Ordering is intentional: a policy may require a minimum class, but adapters cannot construct a
/// stronger class without the corresponding canonical authorization commitment.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CredentialAssuranceClassV1 {
    TlsNotarizedEvidence = 0,
    HolderSelfIssued = 1,
    IssuerUpgraded = 2,
    RegulatedAttestation = 3,
}

impl CanonicalEncode for CredentialAssuranceClassV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for CredentialAssuranceClassV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::TlsNotarizedEvidence),
            1 => Ok(Self::HolderSelfIssued),
            2 => Ok(Self::IssuerUpgraded),
            3 => Ok(Self::RegulatedAttestation),
            tag => {
                Err(DecodeError::InvalidEnumTag { type_name: "CredentialAssuranceClassV1", tag })
            }
        }
    }
}

/// Transcript-free evidence boundary for credentials derived from holder-controlled TLSNotary
/// sessions. Only commitments and provenance needed by a verifier are carried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsCredentialEvidenceV1 {
    notary_identity: Digest384,
    server_identity: Digest384,
    transcript_commitment: Digest384,
    disclosed_fields_commitment: Digest384,
    holder_binding: Digest384,
    schema_id: Digest384,
    observed_height: Height,
    fresh_until_height: Height,
    status_commitment: Digest384,
    assurance: CredentialAssuranceClassV1,
    issuer_authorization_commitment: Option<Digest384>,
}

impl TlsCredentialEvidenceV1 {
    pub const TYPE_TAG: u16 = 0x014d;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 7 + 8 * 2 + 1 + 1 + 48;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        notary_identity: Digest384,
        server_identity: Digest384,
        transcript_commitment: Digest384,
        disclosed_fields_commitment: Digest384,
        holder_binding: Digest384,
        schema_id: Digest384,
        observed_height: Height,
        fresh_until_height: Height,
        status_commitment: Digest384,
        assurance: CredentialAssuranceClassV1,
        issuer_authorization_commitment: Option<Digest384>,
    ) -> Result<Self, CredentialValidationError> {
        if [
            notary_identity,
            server_identity,
            transcript_commitment,
            disclosed_fields_commitment,
            holder_binding,
            schema_id,
            status_commitment,
        ]
        .into_iter()
        .any(|value| value == Digest384::ZERO)
            || observed_height == 0
            || fresh_until_height <= observed_height
            || issuer_authorization_commitment == Some(Digest384::ZERO)
            || (assurance >= CredentialAssuranceClassV1::IssuerUpgraded)
                != issuer_authorization_commitment.is_some()
        {
            return Err(CredentialValidationError::InvalidTlsEvidence);
        }
        Ok(Self {
            notary_identity,
            server_identity,
            transcript_commitment,
            disclosed_fields_commitment,
            holder_binding,
            schema_id,
            observed_height,
            fresh_until_height,
            status_commitment,
            assurance,
            issuer_authorization_commitment,
        })
    }

    pub const fn assurance(&self) -> CredentialAssuranceClassV1 {
        self.assurance
    }
    pub const fn holder_binding(&self) -> Digest384 {
        self.holder_binding
    }
    pub const fn schema_id(&self) -> Digest384 {
        self.schema_id
    }
    pub const fn valid_at(&self, height: Height) -> bool {
        self.observed_height <= height && height < self.fresh_until_height
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-TLS-CREDENTIAL-EVIDENCE-V1");
        hasher.update(&bytes);
        let mut output = [0_u8; 48];
        XofReader::read(&mut hasher.finalize_xof(), &mut output);
        Ok(Digest384::new(output))
    }
}

impl CanonicalEncode for TlsCredentialEvidenceV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.notary_identity.encode(encoder)?;
        self.server_identity.encode(encoder)?;
        self.transcript_commitment.encode(encoder)?;
        self.disclosed_fields_commitment.encode(encoder)?;
        self.holder_binding.encode(encoder)?;
        self.schema_id.encode(encoder)?;
        self.observed_height.encode(encoder)?;
        self.fresh_until_height.encode(encoder)?;
        self.status_commitment.encode(encoder)?;
        self.assurance.encode(encoder)?;
        self.issuer_authorization_commitment.encode(encoder)
    }
}

impl CanonicalDecode for TlsCredentialEvidenceV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Height::decode(decoder)?,
            Height::decode(decoder)?,
            Digest384::decode(decoder)?,
            CredentialAssuranceClassV1::decode(decoder)?,
            Option::<Digest384>::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid TLS credential evidence"))
    }
}

impl CanonicalType for TlsCredentialEvidenceV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

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

    /// Checks the temporal validity window at a verifier timestamp.
    #[must_use]
    pub fn is_valid_at(self, now: Timestamp) -> bool {
        now >= self.valid_from
            && match self.valid_until {
                Some(until) => now <= until,
                None => true,
            }
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

    #[must_use]
    pub fn is_well_formed(self) -> bool {
        self.registry_id.digest() != &Digest384::ZERO
            && self.issuer.digest() != &Digest384::ZERO
            && self.schema_id != Digest384::ZERO
            && self.status_root != Digest384::ZERO
            && self.sequence > 0
    }

    /// Binds a registry snapshot to the exact issuer/schema named by a credential
    /// and requires the snapshot to be effective at the finalized height.
    #[must_use]
    pub fn admits(self, statement: CredentialStatement, finalized_height: Height) -> bool {
        self.is_well_formed()
            && self.issuer == statement.issuer
            && self.schema_id == statement.schema_id
            && match statement.status_registry {
                Some(id) => id == self.registry_id,
                None => false,
            }
            && self.effective_height <= finalized_height
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
        let value = Self::new(
            ObjectId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        );
        if value.is_well_formed() {
            Ok(value)
        } else {
            Err(DecodeError::InvalidValue("malformed credential status registry"))
        }
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

    /// Canonical policy admission for a credential presentation. Status data is
    /// optional only when the policy explicitly permits it; freshness is measured
    /// against finalized heights to avoid local-clock ambiguity.
    #[must_use]
    pub fn accepts(
        &self,
        credential: &Credential,
        registry: Option<&CredentialStatusRegistry>,
        now: Timestamp,
        finalized_height: Height,
    ) -> bool {
        let statement = credential.statement();
        self.accepts_issuer(&statement.issuer)
            && self.accepts_schema(&statement.schema_id)
            && statement.is_valid_at(now)
            && match registry {
                Some(snapshot) => {
                    snapshot.admits(statement, finalized_height)
                        && finalized_height.saturating_sub(snapshot.effective_height)
                            <= self.maximum_status_age
                }
                None => !self.require_status,
            }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CredentialPredicateKind {
    AgeAtLeast = 0,
    JurisdictionNotIn = 1,
    AssetAmountAtLeast = 2,
}
impl CanonicalEncode for CredentialPredicateKind {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for CredentialPredicateKind {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::AgeAtLeast),
            1 => Ok(Self::JurisdictionNotIn),
            2 => Ok(Self::AssetAmountAtLeast),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "CredentialPredicateKind", tag }),
        }
    }
}

/// Public-input boundary for a selective-disclosure or ZK credential predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialPredicateV1 {
    schema_id: Digest384,
    claims_commitment: Digest384,
    holder_binding: Digest384,
    chain_id: ChainId,
    audience: PrincipalId,
    action: TransactionId,
    nonce: Digest384,
    policy_revision: u64,
    expires_height: Height,
    kind: CredentialPredicateKind,
    value_commitment: Digest384,
}
impl CredentialPredicateV1 {
    pub const TYPE_TAG: u16 = 0x0027;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 8 + 8 * 2 + 1;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema_id: Digest384,
        claims_commitment: Digest384,
        holder_binding: Digest384,
        chain_id: ChainId,
        audience: PrincipalId,
        action: TransactionId,
        nonce: Digest384,
        policy_revision: u64,
        expires_height: Height,
        kind: CredentialPredicateKind,
        value_commitment: Digest384,
    ) -> Result<Self, CredentialValidationError> {
        if [schema_id, claims_commitment, holder_binding, nonce, value_commitment]
            .into_iter()
            .any(|v| v == Digest384::ZERO)
            || policy_revision == 0
            || expires_height == 0
        {
            return Err(CredentialValidationError::InvalidPredicateBinding);
        }
        Ok(Self {
            schema_id,
            claims_commitment,
            holder_binding,
            chain_id,
            audience,
            action,
            nonce,
            policy_revision,
            expires_height,
            kind,
            value_commitment,
        })
    }
    pub const fn kind(&self) -> CredentialPredicateKind {
        self.kind
    }
    pub const fn schema_id(&self) -> Digest384 {
        self.schema_id
    }
    pub const fn claims_commitment(&self) -> Digest384 {
        self.claims_commitment
    }
    pub const fn holder_binding(&self) -> Digest384 {
        self.holder_binding
    }
    pub const fn expires_height(&self) -> Height {
        self.expires_height
    }
    pub const fn valid_at(&self, height: Height) -> bool {
        height < self.expires_height
    }
    pub fn binds_action(
        &self,
        chain_id: ChainId,
        audience: PrincipalId,
        action: TransactionId,
    ) -> bool {
        self.chain_id == chain_id && self.audience == audience && self.action == action
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-CREDENTIAL-PREDICATE-V1");
        hasher.update(&bytes);
        let mut output = [0_u8; 48];
        XofReader::read(&mut hasher.finalize_xof(), &mut output);
        Ok(Digest384::new(output))
    }
}
impl CanonicalEncode for CredentialPredicateV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.schema_id.encode(e)?;
        self.claims_commitment.encode(e)?;
        self.holder_binding.encode(e)?;
        self.chain_id.encode(e)?;
        self.audience.encode(e)?;
        self.action.encode(e)?;
        self.nonce.encode(e)?;
        self.policy_revision.encode(e)?;
        self.expires_height.encode(e)?;
        self.kind.encode(e)?;
        self.value_commitment.encode(e)
    }
}
impl CanonicalDecode for CredentialPredicateV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            ChainId::decode(d)?,
            PrincipalId::decode(d)?,
            TransactionId::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            CredentialPredicateKind::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid credential predicate"))
    }
}
impl CanonicalType for CredentialPredicateV1 {
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
    /// Predicate public inputs are zero, expired, or otherwise not action-bound.
    InvalidPredicateBinding,
    /// TLS-derived evidence is zero, stale at construction, or claims an assurance class without
    /// the authorization required for that class.
    InvalidTlsEvidence,
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
        CredentialValidationError::InvalidPredicateBinding => {
            DecodeError::InvalidValue("credential predicate binding is invalid")
        }
        CredentialValidationError::InvalidTlsEvidence => {
            DecodeError::InvalidValue("TLS credential evidence is invalid")
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    extern crate alloc;

    use alloc::vec;

    use activechain_canonical_codec::{decode_envelope, encode_body, encode_envelope};

    use super::{
        CREDENTIAL_FORMAT_VERSION, Credential, CredentialAcceptancePolicy,
        CredentialAssuranceClassV1, CredentialPredicateKind, CredentialPredicateV1,
        CredentialStatement, CredentialStatusRegistry, CredentialValidationError,
        TlsCredentialEvidenceV1,
    };
    use crate::{
        ChainId, CryptoSuiteId, Digest384, ObjectId, PrincipalId, ProtocolSignature, TransactionId,
    };

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }

    #[test]
    fn credential_freshness_binds_registry_issuer_schema_and_height() {
        let registry_id = ObjectId::new(digest(8));
        let statement = CredentialStatement::new(
            CREDENTIAL_FORMAT_VERSION,
            principal(1),
            digest(2),
            digest(3),
            digest(4),
            4,
            10,
            Some(20),
            Some(registry_id),
            None,
            None,
        )
        .unwrap();
        let registry =
            CredentialStatusRegistry::new(registry_id, principal(1), digest(3), digest(5), 2, 6);
        assert!(statement.is_valid_at(10));
        assert!(!statement.is_valid_at(21));
        assert!(registry.admits(statement, 6));
        assert!(!registry.admits(statement, 5));
        let wrong_issuer =
            CredentialStatusRegistry::new(registry_id, principal(9), digest(3), digest(5), 2, 6);
        assert!(!wrong_issuer.admits(statement, 6));
        let zero_root = CredentialStatusRegistry::new(
            registry_id,
            principal(1),
            digest(3),
            Digest384::ZERO,
            2,
            6,
        );
        assert!(!zero_root.admits(statement, 6));
        let zero_sequence =
            CredentialStatusRegistry::new(registry_id, principal(1), digest(3), digest(5), 0, 6);
        assert!(!zero_sequence.admits(statement, 6));
        let zero_identity = CredentialStatusRegistry::new(
            ObjectId::new(Digest384::ZERO),
            PrincipalId::new(Digest384::ZERO),
            Digest384::ZERO,
            digest(5),
            2,
            6,
        );
        assert!(!zero_identity.is_well_formed());
        assert!(
            decode_envelope::<CredentialStatusRegistry>(&encode_envelope(&zero_root).unwrap())
                .is_err()
        );
    }

    #[test]
    fn acceptance_policy_combines_all_boundaries() {
        let statement = statement();
        let credential = credential();
        let registry_id = statement.status_registry.unwrap();
        let registry = CredentialStatusRegistry::new(
            registry_id,
            statement.issuer(),
            statement.schema_id(),
            digest(5),
            1,
            8,
        );
        let policy = CredentialAcceptancePolicy::new(
            vec![statement.issuer()],
            vec![statement.schema_id()],
            4,
            true,
            false,
        )
        .unwrap();
        assert!(policy.accepts(&credential, Some(&registry), 1_500, 10));
        assert!(!policy.accepts(&credential, Some(&registry), 2_001, 10));
        assert!(!policy.accepts(&credential, None, 1_500, 10));
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

    #[test]
    fn predicate_binds_holder_action_and_hidden_value_commitment() {
        let predicate = CredentialPredicateV1::new(
            digest(1),
            digest(2),
            digest(3),
            ChainId::new(digest(4)),
            principal(5),
            TransactionId::new(digest(6)),
            digest(7),
            1,
            100,
            CredentialPredicateKind::JurisdictionNotIn,
            digest(8),
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<CredentialPredicateV1>(&encode_envelope(&predicate).unwrap()),
            Ok(predicate)
        );
        assert!(predicate.valid_at(99));
        assert!(!predicate.valid_at(100));
        assert!(predicate.binds_action(
            ChainId::new(digest(4)),
            principal(5),
            TransactionId::new(digest(6))
        ));
        assert!(!predicate.binds_action(
            ChainId::new(digest(9)),
            principal(5),
            TransactionId::new(digest(6))
        ));
        assert!(
            CredentialPredicateV1::new(
                digest(1),
                digest(2),
                digest(3),
                ChainId::new(digest(4)),
                principal(5),
                TransactionId::new(digest(6)),
                digest(7),
                0,
                100,
                CredentialPredicateKind::AgeAtLeast,
                digest(8),
            )
            .is_err()
        );
    }

    #[test]
    fn tls_evidence_preserves_assurance_and_never_carries_a_transcript() {
        let holder = digest(5);
        let schema = digest(6);
        let self_issued = TlsCredentialEvidenceV1::new(
            digest(1),
            digest(2),
            digest(3),
            digest(4),
            holder,
            schema,
            10,
            20,
            digest(7),
            CredentialAssuranceClassV1::HolderSelfIssued,
            None,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<TlsCredentialEvidenceV1>(&encode_envelope(&self_issued).unwrap()),
            Ok(self_issued)
        );
        assert!(self_issued.valid_at(10));
        assert!(!self_issued.valid_at(20));
        assert_eq!(self_issued.holder_binding(), holder);
        assert_eq!(self_issued.schema_id(), schema);

        assert_eq!(
            TlsCredentialEvidenceV1::new(
                digest(1),
                digest(2),
                digest(3),
                digest(4),
                holder,
                schema,
                10,
                20,
                digest(7),
                CredentialAssuranceClassV1::IssuerUpgraded,
                None,
            ),
            Err(CredentialValidationError::InvalidTlsEvidence)
        );
        assert!(
            TlsCredentialEvidenceV1::new(
                digest(1),
                digest(2),
                digest(3),
                digest(4),
                holder,
                schema,
                10,
                20,
                digest(7),
                CredentialAssuranceClassV1::IssuerUpgraded,
                Some(digest(8)),
            )
            .is_ok()
        );
    }

    #[test]
    fn portable_evidence_conformance_matrix_is_closed_and_consistent() {
        let vector = include_str!("../../../testing/vectors/tls-portable-evidence-v1.tsv");
        let mut lines = vector.lines();
        assert_eq!(
            lines.next(),
            Some(
                "case\tversion\tcommitments\tobserved\tfresh_until\tassurance\tissuer_authorization\texpected\treason"
            )
        );
        let mut cases = 0;
        for line in lines {
            let columns = line.split('\t').collect::<Vec<_>>();
            assert_eq!(columns.len(), 9, "malformed vector row: {line}");
            let assurance_valid = matches!(
                columns[5],
                "tls_notarized_evidence"
                    | "holder_self_issued"
                    | "issuer_upgraded"
                    | "regulated_attestation"
            );
            let elevated = matches!(columns[5], "issuer_upgraded" | "regulated_attestation");
            let authorization_valid =
                if elevated { columns[6] == "nonzero_digest384" } else { columns[6] == "absent" };
            let accepted = columns[1] == "1"
                && columns[2] == "nonzero_digest384"
                && columns[3] == "past"
                && columns[4] == "future"
                && assurance_valid
                && authorization_valid;
            assert_eq!(accepted, columns[7] == "accept", "case {}", columns[0]);
            cases += 1;
        }
        assert_eq!(cases, 17);
    }
}
