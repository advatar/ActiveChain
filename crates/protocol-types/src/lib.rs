#![no_std]
#![forbid(unsafe_code)]

//! Canonical consensus data types for the ActiveChain semantic kernel.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};

mod authority;
mod consensus;
mod consensus_state;
mod credential;
mod crypto;
mod migration;
mod object;
mod package;

pub use authority::{
    BoundedActionSet, BoundedActionSetError, CapabilityGrant, CapabilityGrantFields,
    CapabilityValidationError, DataSelector, HolderBinding, RateLimit, RateLimitError,
    RecoveryRequest, RecoveryRequestError, ResourceSelector, ScopeSelector, ScopeSelectorError,
};
pub use consensus::{
    BlockProposal, ConsensusVoteContext, EpochTransition, EpochTransitionError,
    MAX_VALIDATORS_PER_EPOCH, ML_DSA44_PUBLIC_KEY_LENGTH, QuorumCertificate,
    QuorumCertificateError, ValidatorGenesis, ValidatorGenesisEntry, ValidatorGenesisError,
    ValidatorSet, ValidatorSetError, ValidatorVote, ValidatorVoteError, ValidatorWeight,
};
pub use consensus_state::{
    ConsensusSnapshot, ConsensusState, ConsensusStateError, GenesisConfig, GenesisConfigError,
};
pub use credential::{
    CREDENTIAL_FORMAT_VERSION, Credential, CredentialAcceptancePolicy, CredentialStatement,
    CredentialStatusRegistry, CredentialValidationError, MAX_ACCEPTED_CREDENTIAL_ISSUERS,
    MAX_ACCEPTED_CREDENTIAL_SCHEMAS,
};
pub use crypto::{
    AuthenticatorDescriptor, AuthenticatorPurpose, AuthenticatorValidationError, CryptoFamily,
    CryptoSuiteError, CryptoSuiteId, ProtocolSignature, SignatureError,
};
pub use migration::{CryptoMigrationError, CryptoMigrationWindow};
pub use object::{
    AccessManifest, AccessManifestError, AccessManifestFields, MAX_CREATED_OBJECTS,
    MAX_CREATION_NAMESPACES, MAX_DYNAMIC_READS, MAX_EXACT_READS, MAX_EXACT_WRITES,
    MAX_IMMUTABLE_READS, MAX_PUBLIC_OBJECT_VALUE, NamespaceGrant, Object, ObjectFields,
    ObjectFlags, ObjectFlagsError, ObjectOwner, ObjectValidationError, ObjectVersionRef,
};
pub use package::{
    MAX_PACKAGE_ENTRIES, MAX_PACKAGE_IMPORTS, PackageManifest, PackageManifestError,
    PackageUpgradeError, UpgradePolicy,
};

/// The fixed size of every protocol digest and identifier.
pub const DIGEST_LENGTH: usize = 48;

/// A raw 384-bit protocol digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Digest384([u8; DIGEST_LENGTH]);

impl Digest384 {
    /// The all-zero digest, useful only where a schema explicitly defines it.
    pub const ZERO: Self = Self([0; DIGEST_LENGTH]);

    /// Wraps exactly 48 digest bytes.
    #[must_use]
    pub const fn new(bytes: [u8; DIGEST_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LENGTH] {
        &self.0
    }

    /// Returns the digest bytes by value.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; DIGEST_LENGTH] {
        self.0
    }
}

impl CanonicalEncode for Digest384 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.0.encode(encoder)
    }
}

impl CanonicalDecode for Digest384 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self(<[u8; DIGEST_LENGTH]>::decode(decoder)?))
    }
}

macro_rules! identifier_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(Digest384);

        impl $name {
            /// Creates a typed identifier from a protocol digest.
            #[must_use]
            pub const fn new(digest: Digest384) -> Self {
                Self(digest)
            }

            /// Borrows the underlying protocol digest.
            #[must_use]
            pub const fn digest(&self) -> &Digest384 {
                &self.0
            }

            /// Returns the underlying protocol digest.
            #[must_use]
            pub const fn into_digest(self) -> Digest384 {
                self.0
            }
        }

        impl CanonicalEncode for $name {
            fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
                self.0.encode(encoder)
            }
        }

        impl CanonicalDecode for $name {
            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                Ok(Self(Digest384::decode(decoder)?))
            }
        }
    };
}

identifier_type!(ObjectId, "A globally unique object identifier.");
identifier_type!(PrincipalId, "A stable principal identifier independent of controller keys.");
identifier_type!(AuthenticatorId, "A principal authenticator identifier.");
identifier_type!(ActionId, "A protocol or application action identifier.");
identifier_type!(CapabilityId, "A capability grant identifier.");
identifier_type!(CredentialId, "A credential identifier.");
identifier_type!(PackageId, "An immutable contract package identifier.");
identifier_type!(JobId, "An asynchronous compute job identifier.");
identifier_type!(TransactionId, "A canonical transaction identifier.");
identifier_type!(ChainId, "A protocol deployment and replay-protection identifier.");
identifier_type!(AssetId, "A canonical native or fixed-profile asset identifier.");
identifier_type!(CoinCellId, "A canonical identifier for one unspent native-money cell.");
identifier_type!(CoinCellSetRoot, "A commitment to the canonical unspent Coin Cell set.");
identifier_type!(SupplyRoot, "A commitment to canonical native-asset supply accounting.");
identifier_type!(GenesisAllocationRoot, "A commitment to the one-time native genesis allocation.");

/// A finalized block height.
pub type Height = u64;
/// A validator-set epoch.
pub type Epoch = u64;
/// A consensus round within an epoch.
pub type Round = u64;
/// A base-asset amount.
pub type Amount = u128;
/// Bounded deterministic compute or protocol work.
pub type ResourceUnits = u128;
/// Unsigned Unix time in seconds, admitted only through bounded block context.
pub type Timestamp = u64;

/// The semantic category of a principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PrincipalKind {
    /// A human-controlled principal.
    Human = 0,
    /// An organization-controlled principal.
    Organization = 1,
    /// A hardware or software device.
    Device = 2,
    /// An automated service.
    Service = 3,
    /// An AI or other delegated agent.
    Agent = 4,
    /// A deliberately pseudonymous principal.
    Pseudonym = 5,
}

impl CanonicalEncode for PrincipalKind {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for PrincipalKind {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Human),
            1 => Ok(Self::Organization),
            2 => Ok(Self::Device),
            3 => Ok(Self::Service),
            4 => Ok(Self::Agent),
            5 => Ok(Self::Pseudonym),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "PrincipalKind", tag }),
        }
    }
}

/// The protocol-enforced freeze and recovery status of a principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FreezeState {
    /// Normal controller authorization is active.
    Active = 0,
    /// A recovery operation is pending its policy-defined delay.
    RecoveryPending = 1,
    /// State-changing controller actions are frozen.
    Frozen = 2,
}

impl CanonicalEncode for FreezeState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for FreezeState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Active),
            1 => Ok(Self::RecoveryPending),
            2 => Ok(Self::Frozen),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "FreezeState", tag }),
        }
    }
}

/// Construction failures for semantically constrained protocol values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// `last_updated_at` predates `created_at`.
    UpdatePredatesCreation,
}

/// Version 1 of a stable protocol principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Principal {
    principal_id: PrincipalId,
    principal_kind: PrincipalKind,
    controller_policy_hash: Digest384,
    recovery_policy_hash: Digest384,
    authenticator_set_root: Digest384,
    sequence: u64,
    freeze_state: FreezeState,
    metadata_commitment: Digest384,
    anchor_deposit: Amount,
    created_at: Height,
    last_updated_at: Height,
}

impl Principal {
    /// The registered top-level type tag for principals.
    pub const TYPE_TAG: u16 = 0x0020;
    /// The initial principal schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Principal version 1 has a fixed 282-byte canonical body.
    pub const ENCODED_LENGTH: usize = 282;

    /// Constructs a principal after checking its cross-field invariants.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        principal_id: PrincipalId,
        principal_kind: PrincipalKind,
        controller_policy_hash: Digest384,
        recovery_policy_hash: Digest384,
        authenticator_set_root: Digest384,
        sequence: u64,
        freeze_state: FreezeState,
        metadata_commitment: Digest384,
        anchor_deposit: Amount,
        created_at: Height,
        last_updated_at: Height,
    ) -> Result<Self, ValidationError> {
        if last_updated_at < created_at {
            return Err(ValidationError::UpdatePredatesCreation);
        }
        Ok(Self {
            principal_id,
            principal_kind,
            controller_policy_hash,
            recovery_policy_hash,
            authenticator_set_root,
            sequence,
            freeze_state,
            metadata_commitment,
            anchor_deposit,
            created_at,
            last_updated_at,
        })
    }

    /// Returns the stable identifier.
    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    /// Returns the declared principal category.
    #[must_use]
    pub const fn principal_kind(&self) -> PrincipalKind {
        self.principal_kind
    }

    /// Returns the controller policy commitment.
    #[must_use]
    pub const fn controller_policy_hash(&self) -> Digest384 {
        self.controller_policy_hash
    }

    /// Returns the recovery policy commitment.
    #[must_use]
    pub const fn recovery_policy_hash(&self) -> Digest384 {
        self.recovery_policy_hash
    }

    /// Returns the authenticator-set root.
    #[must_use]
    pub const fn authenticator_set_root(&self) -> Digest384 {
        self.authenticator_set_root
    }

    /// Returns the replay-protection sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the freeze/recovery state.
    #[must_use]
    pub const fn freeze_state(&self) -> FreezeState {
        self.freeze_state
    }

    /// Returns the privacy-preserving metadata commitment.
    #[must_use]
    pub const fn metadata_commitment(&self) -> Digest384 {
        self.metadata_commitment
    }

    /// Returns the endowment securing the principal anchor.
    #[must_use]
    pub const fn anchor_deposit(&self) -> Amount {
        self.anchor_deposit
    }

    /// Returns the creation height.
    #[must_use]
    pub const fn created_at(&self) -> Height {
        self.created_at
    }

    /// Returns the most recent update height.
    #[must_use]
    pub const fn last_updated_at(&self) -> Height {
        self.last_updated_at
    }
}

impl CanonicalEncode for Principal {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.principal_id.encode(encoder)?;
        self.principal_kind.encode(encoder)?;
        self.controller_policy_hash.encode(encoder)?;
        self.recovery_policy_hash.encode(encoder)?;
        self.authenticator_set_root.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.freeze_state.encode(encoder)?;
        self.metadata_commitment.encode(encoder)?;
        self.anchor_deposit.encode(encoder)?;
        self.created_at.encode(encoder)?;
        self.last_updated_at.encode(encoder)
    }
}

impl CanonicalDecode for Principal {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(decoder)?,
            PrincipalKind::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            FreezeState::decode(decoder)?,
            Digest384::decode(decoder)?,
            u128::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|error| match error {
            ValidationError::UpdatePredatesCreation => {
                DecodeError::InvalidValue("last_updated_at predates created_at")
            }
        })
    }
}

impl CanonicalType for Principal {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}

#[cfg(test)]
mod tests {
    use activechain_canonical_codec::{DecodeError, decode_envelope, encode_body, encode_envelope};
    use proptest::prelude::*;

    use super::{Digest384, FreezeState, Principal, PrincipalId, PrincipalKind, ValidationError};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn principal(created_at: u64, last_updated_at: u64) -> Result<Principal, ValidationError> {
        Principal::new(
            PrincipalId::new(digest(0x11)),
            PrincipalKind::Agent,
            digest(0x22),
            digest(0x33),
            digest(0x44),
            7,
            FreezeState::Active,
            digest(0x55),
            1_000,
            created_at,
            last_updated_at,
        )
    }

    #[test]
    fn principal_body_has_the_frozen_v1_length() {
        let body =
            encode_body(&principal(42, 43).expect("valid principal")).expect("principal encodes");
        assert_eq!(body.len(), Principal::ENCODED_LENGTH);
    }

    #[test]
    fn principal_round_trips_through_strict_envelope() {
        let value = principal(42, 43).expect("valid principal");
        let bytes = encode_envelope(&value).expect("principal encodes");
        assert_eq!(decode_envelope::<Principal>(&bytes), Ok(value));
    }

    #[test]
    fn construction_and_decoding_reject_inverted_heights() {
        assert_eq!(principal(43, 42), Err(ValidationError::UpdatePredatesCreation));

        let value = principal(42, 43).expect("valid principal");
        let mut bytes = encode_envelope(&value).expect("principal encodes");
        let last_updated_offset = bytes.len() - core::mem::size_of::<u64>();
        bytes[last_updated_offset..].copy_from_slice(&41_u64.to_be_bytes());
        assert_eq!(
            decode_envelope::<Principal>(&bytes),
            Err(DecodeError::InvalidValue("last_updated_at predates created_at"))
        );
    }

    proptest! {
        #[test]
        fn all_valid_height_pairs_round_trip(created_at: u64, delta: u16) {
            let last_updated_at = created_at.saturating_add(u64::from(delta));
            let value = principal(created_at, last_updated_at).expect("saturating addition cannot invert heights");
            let bytes = encode_envelope(&value).expect("fixed-size principal fits its bound");
            prop_assert_eq!(decode_envelope::<Principal>(&bytes), Ok(value));
        }
    }
}
