//! Canonical cryptographic suite, signature, and authenticator descriptors.

extern crate alloc;

use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};

use crate::{AuthenticatorId, Height};

/// Maximum verification-key bytes admitted by the development schema.
pub const MAX_VERIFICATION_KEY_LENGTH: usize = 4_096;
/// Maximum signature bytes admitted by the development schema.
pub const MAX_SIGNATURE_LENGTH: usize = 20_000;

const MAX_U32_ULEB128_LENGTH: usize = 5;

/// A registered post-quantum primitive family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CryptoFamily {
    /// FIPS 204 ML-DSA signatures.
    MlDsa = 1,
    /// FIPS 205 SLH-DSA using SHAKE parameter sets.
    SlhDsaShake = 2,
    /// FIPS 203 ML-KEM key encapsulation.
    MlKem = 3,
    /// SHAKE-based hashing and extendable output.
    Shake = 4,
}

impl CanonicalEncode for CryptoFamily {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for CryptoFamily {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            1 => Ok(Self::MlDsa),
            2 => Ok(Self::SlhDsaShake),
            3 => Ok(Self::MlKem),
            4 => Ok(Self::Shake),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "CryptoFamily", tag }),
        }
    }
}

/// A fully versioned cryptographic suite registry entry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CryptoSuiteId {
    family: CryptoFamily,
    parameter_set: u16,
    encoding_version: u16,
    security_profile: u8,
}

impl CryptoSuiteId {
    /// ML-DSA-44 with the protocol's first canonical encoding.
    pub const ML_DSA_44: Self = Self {
        family: CryptoFamily::MlDsa,
        parameter_set: 44,
        encoding_version: 1,
        security_profile: 2,
    };
    /// ML-DSA-65 with the protocol's first canonical encoding.
    pub const ML_DSA_65: Self = Self {
        family: CryptoFamily::MlDsa,
        parameter_set: 65,
        encoding_version: 1,
        security_profile: 3,
    };
    /// ML-DSA-87 with the protocol's first canonical encoding.
    pub const ML_DSA_87: Self = Self {
        family: CryptoFamily::MlDsa,
        parameter_set: 87,
        encoding_version: 1,
        security_profile: 5,
    };
    /// SLH-DSA-SHAKE-192s with the protocol's first canonical encoding.
    pub const SLH_DSA_SHAKE_192S: Self = Self {
        family: CryptoFamily::SlhDsaShake,
        parameter_set: 0x0192,
        encoding_version: 1,
        security_profile: 3,
    };
    /// ML-KEM-768 with the protocol's first canonical encoding.
    pub const ML_KEM_768: Self = Self {
        family: CryptoFamily::MlKem,
        parameter_set: 768,
        encoding_version: 1,
        security_profile: 3,
    };
    /// SHAKE256 with a 384-bit protocol output.
    pub const SHAKE256_384: Self = Self {
        family: CryptoFamily::Shake,
        parameter_set: 384,
        encoding_version: 1,
        security_profile: 5,
    };

    /// Reconstructs a suite only when the complete registry entry is known.
    pub fn from_parts(
        family: CryptoFamily,
        parameter_set: u16,
        encoding_version: u16,
        security_profile: u8,
    ) -> Result<Self, CryptoSuiteError> {
        let candidate = Self { family, parameter_set, encoding_version, security_profile };
        if [
            Self::ML_DSA_44,
            Self::ML_DSA_65,
            Self::ML_DSA_87,
            Self::SLH_DSA_SHAKE_192S,
            Self::ML_KEM_768,
            Self::SHAKE256_384,
        ]
        .contains(&candidate)
        {
            Ok(candidate)
        } else {
            Err(CryptoSuiteError::UnregisteredSuite)
        }
    }

    /// Returns the primitive family.
    #[must_use]
    pub const fn family(self) -> CryptoFamily {
        self.family
    }

    /// Returns the family-specific parameter-set registry value.
    #[must_use]
    pub const fn parameter_set(self) -> u16 {
        self.parameter_set
    }

    /// Returns the canonical algorithm encoding version.
    #[must_use]
    pub const fn encoding_version(self) -> u16 {
        self.encoding_version
    }

    /// Returns the suite's protocol security-profile registry value.
    #[must_use]
    pub const fn security_profile(self) -> u8 {
        self.security_profile
    }

    /// Returns the exact public verification-key size for signature suites.
    #[must_use]
    pub fn verification_key_length(self) -> Option<usize> {
        match self {
            Self::ML_DSA_44 => Some(1_312),
            Self::ML_DSA_65 => Some(1_952),
            Self::ML_DSA_87 => Some(2_592),
            Self::SLH_DSA_SHAKE_192S => Some(48),
            Self::ML_KEM_768 | Self::SHAKE256_384 => None,
            _ => None,
        }
    }

    /// Returns the exact canonical signature size for signature suites.
    #[must_use]
    pub fn signature_length(self) -> Option<usize> {
        match self {
            Self::ML_DSA_44 => Some(2_420),
            Self::ML_DSA_65 => Some(3_309),
            Self::ML_DSA_87 => Some(4_627),
            Self::SLH_DSA_SHAKE_192S => Some(16_224),
            Self::ML_KEM_768 | Self::SHAKE256_384 => None,
            _ => None,
        }
    }

    /// Returns whether this suite is a standardized post-quantum primitive.
    #[must_use]
    pub const fn is_post_quantum(self) -> bool {
        matches!(
            self.family,
            CryptoFamily::MlDsa
                | CryptoFamily::SlhDsaShake
                | CryptoFamily::MlKem
                | CryptoFamily::Shake
        )
    }

    /// Rejects a suite at a safety-critical boundary unless it is PQ-enabled.
    pub fn require_post_quantum(self) -> Result<Self, CryptoSuiteError> {
        if self.is_post_quantum() { Ok(self) } else { Err(CryptoSuiteError::NonPostQuantumSuite) }
    }
}

impl CanonicalEncode for CryptoSuiteId {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.family.encode(encoder)?;
        self.parameter_set.encode(encoder)?;
        self.encoding_version.encode(encoder)?;
        self.security_profile.encode(encoder)
    }
}

impl CanonicalDecode for CryptoSuiteId {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::from_parts(
            CryptoFamily::decode(decoder)?,
            u16::decode(decoder)?,
            u16::decode(decoder)?,
            u8::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("unregistered cryptographic suite"))
    }
}

/// Cryptographic-suite registry validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoSuiteError {
    /// No suite is registered for the complete tuple.
    UnregisteredSuite,
    /// A classical suite was presented at a post-quantum safety boundary.
    NonPostQuantumSuite,
}

/// A bounded, suite-tagged canonical signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolSignature {
    suite: CryptoSuiteId,
    bytes: Vec<u8>,
}

/// Structural signature validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// The suite does not define signing and verification operations.
    SuiteDoesNotSign,
    /// The byte length differs from the suite's canonical signature size.
    InvalidLength { expected: usize, actual: usize },
}

impl ProtocolSignature {
    /// Maximum canonical size when nested in another protocol value.
    pub const MAX_ENCODED_LEN: usize = 6 + MAX_U32_ULEB128_LENGTH + MAX_SIGNATURE_LENGTH;

    /// Constructs a structurally valid signature with the suite's exact size.
    pub fn new(suite: CryptoSuiteId, bytes: Vec<u8>) -> Result<Self, SignatureError> {
        let Some(expected) = suite.signature_length() else {
            return Err(SignatureError::SuiteDoesNotSign);
        };
        if bytes.len() != expected {
            return Err(SignatureError::InvalidLength { expected, actual: bytes.len() });
        }
        Ok(Self { suite, bytes })
    }

    /// Returns the signature suite.
    #[must_use]
    pub const fn suite(&self) -> CryptoSuiteId {
        self.suite
    }

    /// Borrows the canonical signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl CanonicalEncode for ProtocolSignature {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.suite.encode(encoder)?;
        encoder.write_bytes(&self.bytes, MAX_SIGNATURE_LENGTH)
    }
}

impl CanonicalDecode for ProtocolSignature {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let suite = CryptoSuiteId::decode(decoder)?;
        let bytes = decoder.read_bytes(MAX_SIGNATURE_LENGTH)?.to_vec();
        Self::new(suite, bytes).map_err(|error| match error {
            SignatureError::SuiteDoesNotSign => {
                DecodeError::InvalidValue("signature uses a non-signature suite")
            }
            SignatureError::InvalidLength { .. } => {
                DecodeError::InvalidValue("signature length does not match its suite")
            }
        })
    }
}

/// A protocol role assigned to an authenticator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthenticatorPurpose {
    /// Principal controller authorization.
    Control = 0,
    /// Principal recovery authorization.
    Recovery = 1,
    /// Short-lived session authorization.
    Session = 2,
    /// Validator consensus messages.
    Validator = 3,
    /// Credential issuance.
    CredentialIssuance = 4,
    /// External tool-gateway receipts.
    ToolReceipt = 5,
}

impl CanonicalEncode for AuthenticatorPurpose {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for AuthenticatorPurpose {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Control),
            1 => Ok(Self::Recovery),
            2 => Ok(Self::Session),
            3 => Ok(Self::Validator),
            4 => Ok(Self::CredentialIssuance),
            5 => Ok(Self::ToolReceipt),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "AuthenticatorPurpose", tag }),
        }
    }
}

/// A canonical, bounded public authenticator descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatorDescriptor {
    authenticator_id: AuthenticatorId,
    scheme: CryptoSuiteId,
    verification_key: Vec<u8>,
    purpose: AuthenticatorPurpose,
    valid_from: Height,
    valid_until: Option<Height>,
    revoked_at: Option<Height>,
}

impl AuthenticatorDescriptor {
    /// Registered top-level type tag.
    pub const TYPE_TAG: u16 = 0x0021;
    /// Initial authenticator schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Maximum canonical body length.
    pub const MAX_ENCODED_LEN: usize = 4_179;

    /// Constructs a descriptor after validating suite, purpose, key size, and time bounds.
    pub fn new(
        authenticator_id: AuthenticatorId,
        scheme: CryptoSuiteId,
        verification_key: Vec<u8>,
        purpose: AuthenticatorPurpose,
        valid_from: Height,
        valid_until: Option<Height>,
        revoked_at: Option<Height>,
    ) -> Result<Self, AuthenticatorValidationError> {
        let Some(expected_key_length) = scheme.verification_key_length() else {
            return Err(AuthenticatorValidationError::SuiteCannotAuthenticate);
        };
        if verification_key.len() != expected_key_length {
            return Err(AuthenticatorValidationError::InvalidKeyLength {
                expected: expected_key_length,
                actual: verification_key.len(),
            });
        }
        if !purpose_accepts_suite(purpose, scheme) {
            return Err(AuthenticatorValidationError::SuiteNotAllowedForPurpose);
        }
        if valid_until.is_some_and(|height| height < valid_from) {
            return Err(AuthenticatorValidationError::ValidityEndsBeforeStart);
        }
        if revoked_at.is_some_and(|height| height < valid_from) {
            return Err(AuthenticatorValidationError::RevocationPredatesValidity);
        }
        Ok(Self {
            authenticator_id,
            scheme,
            verification_key,
            purpose,
            valid_from,
            valid_until,
            revoked_at,
        })
    }

    /// Returns the stable authenticator identifier.
    #[must_use]
    pub const fn authenticator_id(&self) -> AuthenticatorId {
        self.authenticator_id
    }

    /// Returns the cryptographic suite.
    #[must_use]
    pub const fn scheme(&self) -> CryptoSuiteId {
        self.scheme
    }

    /// Borrows the canonical verification key.
    #[must_use]
    pub fn verification_key(&self) -> &[u8] {
        &self.verification_key
    }

    /// Returns the assigned purpose.
    #[must_use]
    pub const fn purpose(&self) -> AuthenticatorPurpose {
        self.purpose
    }

    /// Returns the first valid height.
    #[must_use]
    pub const fn valid_from(&self) -> Height {
        self.valid_from
    }

    /// Returns the optional final valid height.
    #[must_use]
    pub const fn valid_until(&self) -> Option<Height> {
        self.valid_until
    }

    /// Returns the revocation activation height, if any.
    #[must_use]
    pub const fn revoked_at(&self) -> Option<Height> {
        self.revoked_at
    }

    /// Reports whether the descriptor is active for its purpose at `height`.
    #[must_use]
    pub fn is_active_at(&self, height: Height) -> bool {
        height >= self.valid_from
            && self.valid_until.is_none_or(|valid_until| height <= valid_until)
            && self.revoked_at.is_none_or(|revoked_at| height < revoked_at)
    }
}

impl CanonicalEncode for AuthenticatorDescriptor {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.authenticator_id.encode(encoder)?;
        self.scheme.encode(encoder)?;
        encoder.write_bytes(&self.verification_key, MAX_VERIFICATION_KEY_LENGTH)?;
        self.purpose.encode(encoder)?;
        self.valid_from.encode(encoder)?;
        self.valid_until.encode(encoder)?;
        self.revoked_at.encode(encoder)
    }
}

impl CanonicalDecode for AuthenticatorDescriptor {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AuthenticatorId::decode(decoder)?,
            CryptoSuiteId::decode(decoder)?,
            decoder.read_bytes(MAX_VERIFICATION_KEY_LENGTH)?.to_vec(),
            AuthenticatorPurpose::decode(decoder)?,
            u64::decode(decoder)?,
            Option::<u64>::decode(decoder)?,
            Option::<u64>::decode(decoder)?,
        )
        .map_err(authenticator_decode_error)
    }
}

impl CanonicalType for AuthenticatorDescriptor {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Authenticator descriptor validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatorValidationError {
    /// The selected suite does not define signatures and public verification keys.
    SuiteCannotAuthenticate,
    /// The key byte length differs from the selected suite's canonical size.
    InvalidKeyLength { expected: usize, actual: usize },
    /// The security profile is not permitted for the authenticator's role.
    SuiteNotAllowedForPurpose,
    /// The optional validity end precedes the start.
    ValidityEndsBeforeStart,
    /// The revocation height predates the authenticator's validity.
    RevocationPredatesValidity,
}

fn purpose_accepts_suite(purpose: AuthenticatorPurpose, suite: CryptoSuiteId) -> bool {
    match purpose {
        AuthenticatorPurpose::Control | AuthenticatorPurpose::CredentialIssuance => {
            matches!(suite, CryptoSuiteId::ML_DSA_65 | CryptoSuiteId::ML_DSA_87)
        }
        AuthenticatorPurpose::Recovery => matches!(
            suite,
            CryptoSuiteId::ML_DSA_65 | CryptoSuiteId::ML_DSA_87 | CryptoSuiteId::SLH_DSA_SHAKE_192S
        ),
        AuthenticatorPurpose::Session | AuthenticatorPurpose::ToolReceipt => {
            matches!(suite, CryptoSuiteId::ML_DSA_44 | CryptoSuiteId::ML_DSA_65)
        }
        AuthenticatorPurpose::Validator => suite == CryptoSuiteId::ML_DSA_44,
    }
}

fn authenticator_decode_error(error: AuthenticatorValidationError) -> DecodeError {
    match error {
        AuthenticatorValidationError::SuiteCannotAuthenticate => {
            DecodeError::InvalidValue("authenticator suite cannot verify signatures")
        }
        AuthenticatorValidationError::InvalidKeyLength { .. } => {
            DecodeError::InvalidValue("verification-key length does not match its suite")
        }
        AuthenticatorValidationError::SuiteNotAllowedForPurpose => {
            DecodeError::InvalidValue("cryptographic suite is not allowed for this purpose")
        }
        AuthenticatorValidationError::ValidityEndsBeforeStart => {
            DecodeError::InvalidValue("authenticator validity ends before it starts")
        }
        AuthenticatorValidationError::RevocationPredatesValidity => {
            DecodeError::InvalidValue("authenticator revocation predates its validity")
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;

    use activechain_canonical_codec::{decode_envelope, encode_envelope};

    use super::{
        AuthenticatorDescriptor, AuthenticatorPurpose, AuthenticatorValidationError, CryptoFamily,
        CryptoSuiteError, CryptoSuiteId, ProtocolSignature, SignatureError,
    };
    use crate::{AuthenticatorId, Digest384};

    fn authenticator_id(byte: u8) -> AuthenticatorId {
        AuthenticatorId::new(Digest384::new([byte; 48]))
    }

    #[test]
    fn suite_registry_rejects_partial_or_unknown_entries() {
        assert_eq!(
            CryptoSuiteId::from_parts(CryptoFamily::MlDsa, 65, 2, 3),
            Err(CryptoSuiteError::UnregisteredSuite)
        );
    }

    #[test]
    fn registered_suites_are_explicitly_pq_at_safety_boundaries() {
        for suite in [
            CryptoSuiteId::ML_DSA_44,
            CryptoSuiteId::ML_DSA_65,
            CryptoSuiteId::ML_DSA_87,
            CryptoSuiteId::SLH_DSA_SHAKE_192S,
            CryptoSuiteId::ML_KEM_768,
            CryptoSuiteId::SHAKE256_384,
        ] {
            assert!(suite.is_post_quantum());
            assert_eq!(suite.require_post_quantum(), Ok(suite));
        }
    }

    #[test]
    fn signatures_have_suite_exact_lengths() {
        assert_eq!(
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, vec![0; 10]),
            Err(SignatureError::InvalidLength { expected: 3_309, actual: 10 })
        );
        assert_eq!(
            ProtocolSignature::new(CryptoSuiteId::ML_KEM_768, vec![]),
            Err(SignatureError::SuiteDoesNotSign)
        );
    }

    #[test]
    fn authenticator_round_trip_and_activity_are_canonical() {
        let value = AuthenticatorDescriptor::new(
            authenticator_id(0x10),
            CryptoSuiteId::ML_DSA_65,
            vec![0x42; 1_952],
            AuthenticatorPurpose::Control,
            10,
            Some(20),
            Some(18),
        )
        .expect("valid descriptor");

        assert!(!value.is_active_at(9));
        assert!(value.is_active_at(17));
        assert!(!value.is_active_at(18));

        let encoded = encode_envelope(&value).expect("descriptor fits its bound");
        assert_eq!(decode_envelope::<AuthenticatorDescriptor>(&encoded), Ok(value));
    }

    #[test]
    fn purpose_profiles_and_time_bounds_are_enforced() {
        assert_eq!(
            AuthenticatorDescriptor::new(
                authenticator_id(0x20),
                CryptoSuiteId::ML_DSA_44,
                vec![0; 1_312],
                AuthenticatorPurpose::Control,
                10,
                None,
                None,
            ),
            Err(AuthenticatorValidationError::SuiteNotAllowedForPurpose)
        );
        assert_eq!(
            AuthenticatorDescriptor::new(
                authenticator_id(0x20),
                CryptoSuiteId::ML_DSA_65,
                vec![0; 1_952],
                AuthenticatorPurpose::Control,
                10,
                Some(9),
                None,
            ),
            Err(AuthenticatorValidationError::ValidityEndsBeforeStart)
        );
    }
}
