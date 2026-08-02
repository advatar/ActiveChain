extern crate alloc;

use alloc::vec::Vec;

use crate::{
    AuthenticatorDescriptor, AuthenticatorId, AuthenticatorPurpose, CryptoSuiteId, Digest384,
    PrincipalId, ProtocolSignature,
};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidRecordError {
    InvalidIdentity,
    InvalidCommitment,
    InvalidSequence,
    PreviousMismatch,
    Inactive,
    InvalidOperation,
    InvalidDocument,
    DuplicateMethod,
    InvalidAuthorizer,
}

pub const MAX_DID_AUTHENTICATION_METHODS: usize = 8;
pub const MAX_DID_KEY_AGREEMENT_METHODS: usize = 4;
pub const ML_KEM_768_PUBLIC_KEY_LENGTH: usize = 1_184;

/// One public ML-KEM agreement method in a DID document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidKeyAgreementMethodV1 {
    method_id: AuthenticatorId,
    suite: CryptoSuiteId,
    public_key: Vec<u8>,
    valid_from: u64,
    valid_until: Option<u64>,
    revoked_at: Option<u64>,
}

impl DidKeyAgreementMethodV1 {
    pub const TYPE_TAG: u16 = 0x0196;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        48 + 7 + 5 + ML_KEM_768_PUBLIC_KEY_LENGTH + 8 + 1 + 8 + 1 + 8;

    pub fn new(
        method_id: AuthenticatorId,
        suite: CryptoSuiteId,
        public_key: Vec<u8>,
        valid_from: u64,
        valid_until: Option<u64>,
        revoked_at: Option<u64>,
    ) -> Result<Self, DidRecordError> {
        if method_id.digest() == &Digest384::ZERO
            || suite != CryptoSuiteId::ML_KEM_768
            || public_key.len() != ML_KEM_768_PUBLIC_KEY_LENGTH
            || valid_until.is_some_and(|height| height < valid_from)
            || revoked_at.is_some_and(|height| height < valid_from)
        {
            return Err(DidRecordError::InvalidDocument);
        }
        Ok(Self { method_id, suite, public_key, valid_from, valid_until, revoked_at })
    }

    pub const fn method_id(&self) -> AuthenticatorId {
        self.method_id
    }
    pub const fn suite(&self) -> CryptoSuiteId {
        self.suite
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    pub fn is_active_at(&self, height: u64) -> bool {
        height >= self.valid_from
            && self.valid_until.is_none_or(|until| height <= until)
            && self.revoked_at.is_none_or(|revoked| height < revoked)
    }
}

impl CanonicalEncode for DidKeyAgreementMethodV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.method_id.encode(e)?;
        self.suite.encode(e)?;
        e.write_bytes(&self.public_key, ML_KEM_768_PUBLIC_KEY_LENGTH)?;
        self.valid_from.encode(e)?;
        self.valid_until.encode(e)?;
        self.revoked_at.encode(e)
    }
}
impl CanonicalDecode for DidKeyAgreementMethodV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AuthenticatorId::decode(d)?,
            CryptoSuiteId::decode(d)?,
            d.read_bytes(ML_KEM_768_PUBLIC_KEY_LENGTH)?.to_vec(),
            u64::decode(d)?,
            Option::<u64>::decode(d)?,
            Option::<u64>::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid DID key-agreement method"))
    }
}
impl CanonicalType for DidKeyAgreementMethodV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Canonical public DID document. Methods are ordered by stable method ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidDocumentV1 {
    principal: PrincipalId,
    authentication: Vec<AuthenticatorDescriptor>,
    key_agreement: Vec<DidKeyAgreementMethodV1>,
    services_commitment: Option<Digest384>,
}

impl DidDocumentV1 {
    pub const TYPE_TAG: u16 = 0x0197;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48
        + 5
        + MAX_DID_AUTHENTICATION_METHODS * AuthenticatorDescriptor::MAX_ENCODED_LEN
        + 5
        + MAX_DID_KEY_AGREEMENT_METHODS * DidKeyAgreementMethodV1::MAX_ENCODED_LEN
        + 1
        + 48;

    pub fn new(
        principal: PrincipalId,
        authentication: Vec<AuthenticatorDescriptor>,
        key_agreement: Vec<DidKeyAgreementMethodV1>,
        services_commitment: Option<Digest384>,
    ) -> Result<Self, DidRecordError> {
        if principal.digest() == &Digest384::ZERO
            || authentication.is_empty()
            || authentication.len() > MAX_DID_AUTHENTICATION_METHODS
            || key_agreement.is_empty()
            || key_agreement.len() > MAX_DID_KEY_AGREEMENT_METHODS
            || services_commitment.is_some_and(|value| value == Digest384::ZERO)
            || authentication.iter().any(|method| {
                !matches!(
                    method.purpose(),
                    AuthenticatorPurpose::Control | AuthenticatorPurpose::Recovery
                )
            })
            || !authentication
                .iter()
                .any(|method| method.purpose() == AuthenticatorPurpose::Control)
        {
            return Err(DidRecordError::InvalidDocument);
        }
        if authentication
            .windows(2)
            .any(|pair| pair[0].authenticator_id() >= pair[1].authenticator_id())
            || key_agreement.windows(2).any(|pair| pair[0].method_id() >= pair[1].method_id())
        {
            return Err(DidRecordError::DuplicateMethod);
        }
        if authentication.iter().any(|auth| {
            key_agreement
                .binary_search_by_key(&auth.authenticator_id(), DidKeyAgreementMethodV1::method_id)
                .is_ok()
        }) {
            return Err(DidRecordError::DuplicateMethod);
        }
        Ok(Self { principal, authentication, key_agreement, services_commitment })
    }

    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }
    pub fn authentication(&self) -> &[AuthenticatorDescriptor] {
        &self.authentication
    }
    pub fn key_agreement(&self) -> &[DidKeyAgreementMethodV1] {
        &self.key_agreement
    }
    pub const fn services_commitment(&self) -> Option<Digest384> {
        self.services_commitment
    }
    pub fn method(&self, id: AuthenticatorId) -> Option<&AuthenticatorDescriptor> {
        self.authentication
            .binary_search_by_key(&id, AuthenticatorDescriptor::authenticator_id)
            .ok()
            .map(|index| &self.authentication[index])
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        domain_envelope_commitment(b"ACTIVECHAIN-DID-DOCUMENT-V1", self)
    }
    fn authentication_commitment(&self) -> Result<Digest384, EncodeError> {
        let mut e = Encoder::new(
            5 + MAX_DID_AUTHENTICATION_METHODS * AuthenticatorDescriptor::MAX_ENCODED_LEN,
        );
        e.write_length(self.authentication.len(), MAX_DID_AUTHENTICATION_METHODS)?;
        for method in &self.authentication {
            method.encode(&mut e)?;
        }
        Ok(domain_bytes_commitment(b"ACTIVECHAIN-DID-AUTHENTICATION-METHODS-V1", &e.finish()))
    }
    fn key_agreement_commitment(&self) -> Result<Digest384, EncodeError> {
        let mut e = Encoder::new(
            5 + MAX_DID_KEY_AGREEMENT_METHODS * DidKeyAgreementMethodV1::MAX_ENCODED_LEN,
        );
        e.write_length(self.key_agreement.len(), MAX_DID_KEY_AGREEMENT_METHODS)?;
        for method in &self.key_agreement {
            method.encode(&mut e)?;
        }
        Ok(domain_bytes_commitment(b"ACTIVECHAIN-DID-KEY-AGREEMENT-METHODS-V1", &e.finish()))
    }
    fn recovery_commitment(&self) -> Result<Option<Digest384>, EncodeError> {
        let recovery = self
            .authentication
            .iter()
            .filter(|method| method.purpose() == AuthenticatorPurpose::Recovery)
            .collect::<Vec<_>>();
        if recovery.is_empty() {
            return Ok(None);
        }
        let mut e = Encoder::new(
            5 + MAX_DID_AUTHENTICATION_METHODS * AuthenticatorDescriptor::MAX_ENCODED_LEN,
        );
        e.write_length(recovery.len(), MAX_DID_AUTHENTICATION_METHODS)?;
        for method in recovery {
            method.encode(&mut e)?;
        }
        Ok(Some(domain_bytes_commitment(b"ACTIVECHAIN-DID-RECOVERY-METHODS-V1", &e.finish())))
    }
}

impl CanonicalEncode for DidDocumentV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.principal.encode(e)?;
        e.write_length(self.authentication.len(), MAX_DID_AUTHENTICATION_METHODS)?;
        for method in &self.authentication {
            method.encode(e)?;
        }
        e.write_length(self.key_agreement.len(), MAX_DID_KEY_AGREEMENT_METHODS)?;
        for method in &self.key_agreement {
            method.encode(e)?;
        }
        self.services_commitment.encode(e)
    }
}
impl CanonicalDecode for DidDocumentV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let principal = PrincipalId::decode(d)?;
        let auth_len = d.read_length(MAX_DID_AUTHENTICATION_METHODS)?;
        let mut authentication = Vec::with_capacity(auth_len);
        for _ in 0..auth_len {
            authentication.push(AuthenticatorDescriptor::decode(d)?);
        }
        let agreement_len = d.read_length(MAX_DID_KEY_AGREEMENT_METHODS)?;
        let mut key_agreement = Vec::with_capacity(agreement_len);
        for _ in 0..agreement_len {
            key_agreement.push(DidKeyAgreementMethodV1::decode(d)?);
        }
        Self::new(principal, authentication, key_agreement, Option::<Digest384>::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid DID document"))
    }
}
impl CanonicalType for DidDocumentV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

fn domain_envelope_commitment<T: CanonicalType>(
    domain: &[u8],
    value: &T,
) -> Result<Digest384, EncodeError> {
    Ok(domain_bytes_commitment(domain, &activechain_canonical_codec::encode_envelope(value)?))
}
fn domain_bytes_commitment(domain: &[u8], bytes: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(bytes);
    let mut digest = [0_u8; 48];
    hasher.finalize_xof().read(&mut digest);
    Digest384::new(digest)
}

/// Derives the stable `did:activechain` method-specific identifier from the
/// principal commitment and method version. Key material and ENS aliases are
/// intentionally excluded from this identity function.
pub fn derive_activechain_did(principal: PrincipalId) -> Result<Digest384, DidRecordError> {
    if principal.digest() == &Digest384::ZERO {
        return Err(DidRecordError::InvalidIdentity);
    }
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-DID-METHOD-V1");
    hasher.update(principal.digest().as_bytes());
    let mut bytes = [0_u8; 48];
    hasher.finalize_xof().read(&mut bytes);
    Ok(Digest384::new(bytes))
}

/// Public controller state for `did:activechain`. Private credentials,
/// transaction history, and key material are represented only by commitments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DidControllerRecordV1 {
    principal: PrincipalId,
    document_commitment: Digest384,
    authentication_commitment: Digest384,
    key_agreement_commitment: Digest384,
    recovery_commitment: Option<Digest384>,
    services_commitment: Option<Digest384>,
    sequence: u64,
    active: bool,
}

impl DidControllerRecordV1 {
    pub const TYPE_TAG: u16 = 0x0130;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 4 + 2 * (1 + 48) + 8 + 1;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal: PrincipalId,
        document_commitment: Digest384,
        authentication_commitment: Digest384,
        key_agreement_commitment: Digest384,
        recovery_commitment: Option<Digest384>,
        services_commitment: Option<Digest384>,
        sequence: u64,
        active: bool,
    ) -> Result<Self, DidRecordError> {
        if principal.digest() == &Digest384::ZERO {
            return Err(DidRecordError::InvalidIdentity);
        }
        if document_commitment == Digest384::ZERO
            || authentication_commitment == Digest384::ZERO
            || key_agreement_commitment == Digest384::ZERO
            || recovery_commitment.is_some_and(|value| value == Digest384::ZERO)
            || services_commitment.is_some_and(|value| value == Digest384::ZERO)
        {
            return Err(DidRecordError::InvalidCommitment);
        }
        if sequence == 0 {
            return Err(DidRecordError::InvalidSequence);
        }
        Ok(Self {
            principal,
            document_commitment,
            authentication_commitment,
            key_agreement_commitment,
            recovery_commitment,
            services_commitment,
            sequence,
            active,
        })
    }

    pub const fn principal(self) -> PrincipalId {
        self.principal
    }
    pub const fn document_commitment(self) -> Digest384 {
        self.document_commitment
    }
    pub const fn authentication_commitment(self) -> Digest384 {
        self.authentication_commitment
    }
    pub const fn key_agreement_commitment(self) -> Digest384 {
        self.key_agreement_commitment
    }
    pub const fn recovery_commitment(self) -> Option<Digest384> {
        self.recovery_commitment
    }
    pub const fn services_commitment(self) -> Option<Digest384> {
        self.services_commitment
    }
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    pub const fn active(self) -> bool {
        self.active
    }

    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-DID-CONTROLLER-RECORD-V1");
        hasher.update(&bytes);
        let mut digest = [0_u8; 48];
        hasher.finalize_xof().read(&mut digest);
        Ok(Digest384::new(digest))
    }

    pub fn from_document(
        document: &DidDocumentV1,
        sequence: u64,
        active: bool,
    ) -> Result<Self, DidRecordError> {
        Self::new(
            document.principal(),
            document.commitment().map_err(|_| DidRecordError::InvalidCommitment)?,
            document.authentication_commitment().map_err(|_| DidRecordError::InvalidCommitment)?,
            document.key_agreement_commitment().map_err(|_| DidRecordError::InvalidCommitment)?,
            document.recovery_commitment().map_err(|_| DidRecordError::InvalidCommitment)?,
            document.services_commitment(),
            sequence,
            active,
        )
    }

    pub fn matches_document(&self, document: &DidDocumentV1) -> bool {
        Self::from_document(document, self.sequence, self.active).is_ok_and(|value| value == *self)
    }

    /// Applies an operation only when both records commit to the supplied canonical documents
    /// and the selected current method has the role required by the operation.
    pub fn apply_document_operation(
        &self,
        current_document: &DidDocumentV1,
        operation: &DidControllerOperationV1,
        next_document: &DidDocumentV1,
        authorizer: AuthenticatorId,
        finalized_height: u64,
    ) -> Result<Self, DidRecordError> {
        if !self.active {
            return Err(DidRecordError::Inactive);
        }
        if !self.matches_document(current_document)
            || operation.principal() != self.principal
            || operation.previous_commitment()
                != Some(self.commitment().map_err(|_| DidRecordError::PreviousMismatch)?)
            || operation.next().sequence() != self.sequence.saturating_add(1)
            || operation.next().principal() != self.principal
            || !operation.next().matches_document(next_document)
        {
            return Err(DidRecordError::PreviousMismatch);
        }
        let method =
            current_document.method(authorizer).ok_or(DidRecordError::InvalidAuthorizer)?;
        if !method.is_active_at(finalized_height) {
            return Err(DidRecordError::InvalidAuthorizer);
        }
        let required = match operation.kind() {
            DidOperationKind::Update | DidOperationKind::Deactivate => {
                AuthenticatorPurpose::Control
            }
            DidOperationKind::Recover => AuthenticatorPurpose::Recovery,
            DidOperationKind::Create => return Err(DidRecordError::InvalidOperation),
        };
        if method.purpose() != required
            || (operation.kind() == DidOperationKind::Deactivate && operation.next().active())
            || (operation.kind() != DidOperationKind::Deactivate && !operation.next().active())
        {
            return Err(DidRecordError::InvalidAuthorizer);
        }
        Ok(*operation.next())
    }

    pub fn apply_update(
        &self,
        previous_commitment: Digest384,
        next: Self,
    ) -> Result<Self, DidRecordError> {
        if !self.active {
            return Err(DidRecordError::Inactive);
        }
        if previous_commitment != self.commitment().map_err(|_| DidRecordError::PreviousMismatch)?
            || next.principal != self.principal
            || next.sequence != self.sequence.saturating_add(1)
        {
            return Err(DidRecordError::PreviousMismatch);
        }
        Ok(next)
    }
}

impl CanonicalEncode for DidControllerRecordV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.principal.encode(e)?;
        self.document_commitment.encode(e)?;
        self.authentication_commitment.encode(e)?;
        self.key_agreement_commitment.encode(e)?;
        self.recovery_commitment.encode(e)?;
        self.services_commitment.encode(e)?;
        self.sequence.encode(e)?;
        self.active.encode(e)
    }
}
impl CanonicalDecode for DidControllerRecordV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Option::<Digest384>::decode(d)?,
            Option::<Digest384>::decode(d)?,
            u64::decode(d)?,
            bool::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid did controller record"))
    }
}
impl CanonicalType for DidControllerRecordV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidResolutionV1 {
    did: Digest384,
    finalized_height: u64,
    record: Option<DidControllerRecordV1>,
}

impl DidResolutionV1 {
    pub const TYPE_TAG: u16 = 0x0131;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 8 + 2 + DidControllerRecordV1::MAX_ENCODED_LEN;

    pub fn new(
        did: Digest384,
        finalized_height: u64,
        record: Option<DidControllerRecordV1>,
    ) -> Result<Self, DidRecordError> {
        if did == Digest384::ZERO {
            return Err(DidRecordError::InvalidIdentity);
        }
        if let Some(value) = record
            && (!value.active() || derive_activechain_did(value.principal()) != Ok(did))
        {
            return Err(DidRecordError::InvalidIdentity);
        }
        Ok(Self { did, finalized_height, record })
    }
    pub const fn did(&self) -> Digest384 {
        self.did
    }
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }
    pub const fn record(&self) -> Option<&DidControllerRecordV1> {
        self.record.as_ref()
    }
}

impl CanonicalEncode for DidResolutionV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.did.encode(e)?;
        self.finalized_height.encode(e)?;
        self.record.encode(e)
    }
}
impl CanonicalDecode for DidResolutionV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            u64::decode(d)?,
            Option::<DidControllerRecordV1>::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid did resolution"))
    }
}
impl CanonicalType for DidResolutionV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Persistable anti-rollback checkpoint for finalized DID resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DidResolutionCheckpointV1 {
    did: Digest384,
    finalized_height: u64,
    sequence: u64,
    record_commitment: Digest384,
    deactivated: bool,
}

impl DidResolutionCheckpointV1 {
    pub const TYPE_TAG: u16 = 0x0199;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 8 + 8 + 48 + 1;

    pub fn bootstrap(resolution: &DidResolutionV1) -> Result<Self, DidRecordError> {
        let record = resolution.record().ok_or(DidRecordError::InvalidOperation)?;
        Ok(Self {
            did: resolution.did(),
            finalized_height: resolution.finalized_height(),
            sequence: record.sequence(),
            record_commitment: record
                .commitment()
                .map_err(|_| DidRecordError::InvalidCommitment)?,
            deactivated: false,
        })
    }
    pub fn advance(&self, resolution: &DidResolutionV1) -> Result<Self, DidRecordError> {
        if self.deactivated {
            return Err(DidRecordError::Inactive);
        }
        if resolution.did() != self.did || resolution.finalized_height() < self.finalized_height {
            return Err(DidRecordError::PreviousMismatch);
        }
        let Some(record) = resolution.record() else {
            return Ok(Self {
                finalized_height: resolution.finalized_height(),
                deactivated: true,
                ..*self
            });
        };
        let commitment = record.commitment().map_err(|_| DidRecordError::InvalidCommitment)?;
        if record.sequence() < self.sequence
            || (record.sequence() == self.sequence && commitment != self.record_commitment)
        {
            return Err(DidRecordError::PreviousMismatch);
        }
        Ok(Self {
            did: self.did,
            finalized_height: resolution.finalized_height(),
            sequence: record.sequence(),
            record_commitment: commitment,
            deactivated: false,
        })
    }
    pub const fn did(self) -> Digest384 {
        self.did
    }
    pub const fn finalized_height(self) -> u64 {
        self.finalized_height
    }
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    pub const fn deactivated(self) -> bool {
        self.deactivated
    }
}

impl CanonicalEncode for DidResolutionCheckpointV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.did.encode(e)?;
        self.finalized_height.encode(e)?;
        self.sequence.encode(e)?;
        self.record_commitment.encode(e)?;
        self.deactivated.encode(e)
    }
}
impl CanonicalDecode for DidResolutionCheckpointV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            did: Digest384::decode(d)?,
            finalized_height: u64::decode(d)?,
            sequence: u64::decode(d)?,
            record_commitment: Digest384::decode(d)?,
            deactivated: bool::decode(d)?,
        };
        if value.did == Digest384::ZERO
            || value.sequence == 0
            || value.record_commitment == Digest384::ZERO
        {
            return Err(DecodeError::InvalidValue("invalid DID resolution checkpoint"));
        }
        Ok(value)
    }
}
impl CanonicalType for DidResolutionCheckpointV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DidOperationKind {
    Create = 0,
    Update = 1,
    Recover = 2,
    Deactivate = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidControllerOperationV1 {
    kind: DidOperationKind,
    principal: PrincipalId,
    previous_commitment: Option<Digest384>,
    next: DidControllerRecordV1,
    authorization_commitment: Digest384,
}

/// Network-bound signature over one exact DID lifecycle operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidOperationAuthorizationV1 {
    chain_genesis: Digest384,
    operation_commitment: Digest384,
    authorizer: AuthenticatorId,
    signature: ProtocolSignature,
}

impl DidOperationAuthorizationV1 {
    pub const TYPE_TAG: u16 = 0x0198;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 48 + 48 + ProtocolSignature::MAX_ENCODED_LEN;

    pub fn new(
        chain_genesis: Digest384,
        operation: &DidControllerOperationV1,
        authorizer: AuthenticatorId,
        signature: ProtocolSignature,
    ) -> Result<Self, DidRecordError> {
        if chain_genesis == Digest384::ZERO || authorizer.digest() == &Digest384::ZERO {
            return Err(DidRecordError::InvalidAuthorizer);
        }
        Ok(Self {
            chain_genesis,
            operation_commitment: operation
                .commitment()
                .map_err(|_| DidRecordError::InvalidCommitment)?,
            authorizer,
            signature,
        })
    }
    pub const fn chain_genesis(&self) -> Digest384 {
        self.chain_genesis
    }
    pub const fn operation_commitment(&self) -> Digest384 {
        self.operation_commitment
    }
    pub const fn authorizer(&self) -> AuthenticatorId {
        self.authorizer
    }
    pub const fn signature(&self) -> &ProtocolSignature {
        &self.signature
    }
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(34 + 48 * 3);
        payload.extend_from_slice(b"ACTIVECHAIN-DID-OPERATION-AUTH-V1");
        payload.extend_from_slice(self.chain_genesis.as_bytes());
        payload.extend_from_slice(self.operation_commitment.as_bytes());
        payload.extend_from_slice(self.authorizer.digest().as_bytes());
        payload
    }
    pub fn binds(&self, chain_genesis: Digest384, operation: &DidControllerOperationV1) -> bool {
        self.chain_genesis == chain_genesis
            && operation.commitment().is_ok_and(|value| value == self.operation_commitment)
    }
}

impl CanonicalEncode for DidOperationAuthorizationV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_genesis.encode(e)?;
        self.operation_commitment.encode(e)?;
        self.authorizer.encode(e)?;
        self.signature.encode(e)
    }
}
impl CanonicalDecode for DidOperationAuthorizationV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_genesis = Digest384::decode(d)?;
        let operation_commitment = Digest384::decode(d)?;
        let authorizer = AuthenticatorId::decode(d)?;
        let signature = ProtocolSignature::decode(d)?;
        if chain_genesis == Digest384::ZERO
            || operation_commitment == Digest384::ZERO
            || authorizer.digest() == &Digest384::ZERO
        {
            return Err(DecodeError::InvalidValue("invalid DID operation authorization"));
        }
        Ok(Self { chain_genesis, operation_commitment, authorizer, signature })
    }
}
impl CanonicalType for DidOperationAuthorizationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

impl DidControllerOperationV1 {
    pub const TYPE_TAG: u16 = 0x0136;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        1 + 48 + 1 + 48 + DidControllerRecordV1::MAX_ENCODED_LEN + 48;

    pub fn new(
        kind: DidOperationKind,
        principal: PrincipalId,
        previous_commitment: Option<Digest384>,
        next: DidControllerRecordV1,
        authorization_commitment: Digest384,
    ) -> Result<Self, DidRecordError> {
        if principal.digest() == &Digest384::ZERO
            || next.principal() != principal
            || authorization_commitment == Digest384::ZERO
            || previous_commitment.is_some_and(|value| value == Digest384::ZERO)
        {
            return Err(DidRecordError::InvalidOperation);
        }
        match kind {
            DidOperationKind::Create if previous_commitment.is_some() || next.sequence() != 1 => {
                Err(DidRecordError::InvalidOperation)
            }
            DidOperationKind::Create if !next.active() => Err(DidRecordError::InvalidOperation),
            DidOperationKind::Deactivate if next.active() || previous_commitment.is_none() => {
                Err(DidRecordError::InvalidOperation)
            }
            DidOperationKind::Update | DidOperationKind::Recover
                if previous_commitment.is_none() || !next.active() =>
            {
                Err(DidRecordError::InvalidOperation)
            }
            _ => Ok(Self { kind, principal, previous_commitment, next, authorization_commitment }),
        }
    }
    pub const fn kind(&self) -> DidOperationKind {
        self.kind
    }
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }
    pub const fn previous_commitment(&self) -> Option<Digest384> {
        self.previous_commitment
    }
    pub const fn next(&self) -> &DidControllerRecordV1 {
        &self.next
    }
    pub const fn authorization_commitment(&self) -> Digest384 {
        self.authorization_commitment
    }

    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-DID-CONTROLLER-OPERATION-V1");
        hasher.update(&bytes);
        let mut digest = [0_u8; 48];
        hasher.finalize_xof().read(&mut digest);
        Ok(Digest384::new(digest))
    }
}

impl CanonicalEncode for DidOperationKind {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for DidOperationKind {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Create),
            1 => Ok(Self::Update),
            2 => Ok(Self::Recover),
            3 => Ok(Self::Deactivate),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "DidOperationKind", tag }),
        }
    }
}
impl CanonicalEncode for DidControllerOperationV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.kind.encode(e)?;
        self.principal.encode(e)?;
        self.previous_commitment.encode(e)?;
        self.next.encode(e)?;
        self.authorization_commitment.encode(e)
    }
}
impl CanonicalDecode for DidControllerOperationV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            DidOperationKind::decode(d)?,
            PrincipalId::decode(d)?,
            Option::<Digest384>::decode(d)?,
            DidControllerRecordV1::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid did controller operation"))
    }
}
impl CanonicalType for DidControllerOperationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::vec;

    fn digest(value: u8) -> Digest384 {
        Digest384::new([value; 48])
    }
    fn principal(value: u8) -> PrincipalId {
        PrincipalId::new(digest(value))
    }
    fn auth(value: u8, purpose: AuthenticatorPurpose) -> AuthenticatorDescriptor {
        let suite = if purpose == AuthenticatorPurpose::Recovery {
            CryptoSuiteId::SLH_DSA_SHAKE_192S
        } else {
            CryptoSuiteId::ML_DSA_65
        };
        AuthenticatorDescriptor::new(
            AuthenticatorId::new(digest(value)),
            suite,
            vec![value; suite.verification_key_length().unwrap()],
            purpose,
            1,
            None,
            None,
        )
        .unwrap()
    }
    fn agreement(value: u8) -> DidKeyAgreementMethodV1 {
        DidKeyAgreementMethodV1::new(
            AuthenticatorId::new(digest(value)),
            CryptoSuiteId::ML_KEM_768,
            vec![value; ML_KEM_768_PUBLIC_KEY_LENGTH],
            1,
            None,
            None,
        )
        .unwrap()
    }
    fn document(auth_byte: u8, recovery_byte: u8, agreement_byte: u8) -> DidDocumentV1 {
        DidDocumentV1::new(
            principal(1),
            vec![
                auth(auth_byte, AuthenticatorPurpose::Control),
                auth(recovery_byte, AuthenticatorPurpose::Recovery),
            ],
            vec![agreement(agreement_byte)],
            Some(digest(40)),
        )
        .unwrap()
    }

    #[test]
    fn controller_record_round_trips_and_updates_monotonically() {
        let first = DidControllerRecordV1::new(
            principal(1),
            digest(2),
            digest(3),
            digest(4),
            Some(digest(5)),
            None,
            1,
            true,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<DidControllerRecordV1>(&encode_envelope(&first).unwrap()),
            Ok(first)
        );
        let second = DidControllerRecordV1::new(
            principal(1),
            digest(6),
            digest(7),
            digest(8),
            Some(digest(9)),
            Some(digest(10)),
            2,
            true,
        )
        .unwrap();
        let previous = first.commitment().unwrap();
        assert_eq!(first.apply_update(previous, second), Ok(second));
        assert_eq!(first.apply_update(digest(99), second), Err(DidRecordError::PreviousMismatch));
        assert_eq!(
            first.apply_update(previous, DidControllerRecordV1 { sequence: 4, ..second }),
            Err(DidRecordError::PreviousMismatch)
        );
    }

    #[test]
    fn controller_record_rejects_zero_identity_and_commitments() {
        assert_eq!(
            DidControllerRecordV1::new(
                PrincipalId::new(Digest384::ZERO),
                digest(2),
                digest(3),
                digest(4),
                None,
                None,
                1,
                true,
            ),
            Err(DidRecordError::InvalidIdentity)
        );
        assert_eq!(
            DidControllerRecordV1::new(
                principal(1),
                Digest384::ZERO,
                digest(3),
                digest(4),
                None,
                None,
                1,
                true,
            ),
            Err(DidRecordError::InvalidCommitment)
        );
    }

    #[test]
    fn method_did_derivation_is_stable_and_domain_separated() {
        assert_eq!(derive_activechain_did(principal(1)), derive_activechain_did(principal(1)));
        assert_ne!(derive_activechain_did(principal(1)), derive_activechain_did(principal(2)));
        assert!(derive_activechain_did(PrincipalId::new(Digest384::ZERO)).is_err());
    }

    #[test]
    fn resolution_round_trips_and_supports_deactivated_absence() {
        let resolution = DidResolutionV1::new(digest(20), 42, None).unwrap();
        assert_eq!(
            decode_envelope::<DidResolutionV1>(&encode_envelope(&resolution).unwrap()),
            Ok(resolution)
        );
        assert!(DidResolutionV1::new(Digest384::ZERO, 42, None).is_err());
    }

    #[test]
    fn resolution_checkpoint_rejects_rollback_and_deactivation_is_terminal() {
        let document = document(10, 11, 12);
        let did = derive_activechain_did(principal(1)).unwrap();
        let first_record = DidControllerRecordV1::from_document(&document, 1, true).unwrap();
        let first = DidResolutionV1::new(did, 10, Some(first_record)).unwrap();
        let checkpoint = DidResolutionCheckpointV1::bootstrap(&first).unwrap();
        assert_eq!(
            decode_envelope::<DidResolutionCheckpointV1>(&encode_envelope(&checkpoint).unwrap()),
            Ok(checkpoint)
        );
        let second_record = DidControllerRecordV1::from_document(&document, 2, true).unwrap();
        let second = DidResolutionV1::new(did, 11, Some(second_record)).unwrap();
        let checkpoint = checkpoint.advance(&second).unwrap();
        assert_eq!(checkpoint.sequence(), 2);
        assert_eq!(
            checkpoint.advance(&DidResolutionV1::new(did, 12, Some(first_record)).unwrap()),
            Err(DidRecordError::PreviousMismatch)
        );
        let deactivated =
            checkpoint.advance(&DidResolutionV1::new(did, 12, None).unwrap()).unwrap();
        assert!(deactivated.deactivated());
        assert_eq!(deactivated.advance(&second), Err(DidRecordError::Inactive));
        assert!(DidResolutionV1::new(digest(99), 12, Some(second_record)).is_err());
    }

    #[test]
    fn operations_bind_kind_sequence_and_authorization() {
        let record = DidControllerRecordV1::new(
            principal(1),
            digest(2),
            digest(3),
            digest(4),
            None,
            None,
            1,
            true,
        )
        .unwrap();
        let operation = DidControllerOperationV1::new(
            DidOperationKind::Create,
            principal(1),
            None,
            record,
            digest(5),
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<DidControllerOperationV1>(&encode_envelope(&operation).unwrap()),
            Ok(operation.clone())
        );
        assert_ne!(operation.commitment().unwrap(), Digest384::ZERO);
        assert!(
            DidControllerOperationV1::new(
                DidOperationKind::Create,
                principal(1),
                Some(digest(6)),
                record,
                digest(5)
            )
            .is_err()
        );
        assert!(
            DidControllerOperationV1::new(
                DidOperationKind::Create,
                principal(1),
                None,
                record,
                Digest384::ZERO
            )
            .is_err()
        );
    }

    #[test]
    fn did_document_binds_pq_methods_and_round_trips() {
        let value = document(10, 11, 12);
        assert_eq!(
            decode_envelope::<DidDocumentV1>(&encode_envelope(&value).unwrap()),
            Ok(value.clone())
        );
        assert!(
            DidControllerRecordV1::from_document(&value, 1, true).unwrap().matches_document(&value)
        );
        assert!(
            DidKeyAgreementMethodV1::new(
                AuthenticatorId::new(digest(12)),
                CryptoSuiteId::ML_DSA_65,
                vec![0; ML_KEM_768_PUBLIC_KEY_LENGTH],
                1,
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn did_document_rejects_duplicate_cross_purpose_and_unsorted_methods() {
        assert_eq!(
            DidDocumentV1::new(
                principal(1),
                vec![
                    auth(10, AuthenticatorPurpose::Control),
                    auth(10, AuthenticatorPurpose::Recovery),
                ],
                vec![agreement(12)],
                None,
            ),
            Err(DidRecordError::DuplicateMethod)
        );
        assert_eq!(
            DidDocumentV1::new(
                principal(1),
                vec![auth(12, AuthenticatorPurpose::Control)],
                vec![agreement(12)],
                None,
            ),
            Err(DidRecordError::DuplicateMethod)
        );
        assert_eq!(
            DidDocumentV1::new(
                principal(1),
                vec![
                    auth(11, AuthenticatorPurpose::Control),
                    auth(10, AuthenticatorPurpose::Recovery),
                ],
                vec![agreement(12)],
                None,
            ),
            Err(DidRecordError::DuplicateMethod)
        );
    }

    #[test]
    fn lifecycle_enforces_control_recovery_and_terminal_deactivation() {
        let first_document = document(10, 11, 12);
        let first = DidControllerRecordV1::from_document(&first_document, 1, true).unwrap();
        let rotated_document = document(13, 14, 15);
        let rotated = DidControllerRecordV1::from_document(&rotated_document, 2, true).unwrap();
        let update = DidControllerOperationV1::new(
            DidOperationKind::Update,
            principal(1),
            Some(first.commitment().unwrap()),
            rotated,
            digest(50),
        )
        .unwrap();
        assert_eq!(
            first.apply_document_operation(
                &first_document,
                &update,
                &rotated_document,
                AuthenticatorId::new(digest(10)),
                1,
            ),
            Ok(rotated)
        );
        assert_eq!(
            first.apply_document_operation(
                &first_document,
                &update,
                &rotated_document,
                AuthenticatorId::new(digest(11)),
                1,
            ),
            Err(DidRecordError::InvalidAuthorizer)
        );

        let recovered_document = document(16, 17, 18);
        let recovered = DidControllerRecordV1::from_document(&recovered_document, 2, true).unwrap();
        let recovery = DidControllerOperationV1::new(
            DidOperationKind::Recover,
            principal(1),
            Some(first.commitment().unwrap()),
            recovered,
            digest(51),
        )
        .unwrap();
        assert_eq!(
            first.apply_document_operation(
                &first_document,
                &recovery,
                &recovered_document,
                AuthenticatorId::new(digest(11)),
                1,
            ),
            Ok(recovered)
        );

        let inactive = DidControllerRecordV1::from_document(&rotated_document, 3, false).unwrap();
        let deactivate = DidControllerOperationV1::new(
            DidOperationKind::Deactivate,
            principal(1),
            Some(rotated.commitment().unwrap()),
            inactive,
            digest(52),
        )
        .unwrap();
        assert_eq!(
            rotated.apply_document_operation(
                &rotated_document,
                &deactivate,
                &rotated_document,
                AuthenticatorId::new(digest(13)),
                1,
            ),
            Ok(inactive)
        );
        assert_eq!(
            inactive.apply_document_operation(
                &rotated_document,
                &deactivate,
                &rotated_document,
                AuthenticatorId::new(digest(13)),
                1,
            ),
            Err(DidRecordError::Inactive)
        );
    }

    #[test]
    fn published_pq_lifecycle_vector_is_closed_and_complete() {
        let rows = include_str!("../../../testing/vectors/did-pq-lifecycle-v1.tsv")
            .lines()
            .skip(1)
            .map(|line| line.split('\t').collect::<Vec<_>>())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 16);
        assert!(rows.iter().all(|row| row.len() == 8));
        for required in [
            "create",
            "rotate-control",
            "recover-slh",
            "deactivate",
            "kem-used-to-sign",
            "cross-genesis",
            "resolver-rollback",
            "post-deactivation-update",
        ] {
            assert!(rows.iter().any(|row| row[0] == required));
        }
        assert_eq!(rows.iter().filter(|row| row[7] == "accept").count(), 5);
        assert_eq!(rows.iter().filter(|row| row[7] == "reject").count(), 11);
    }
}
