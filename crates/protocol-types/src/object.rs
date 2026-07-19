//! Canonical object and access-manifest protocol types.

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::Ordering;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};

use crate::{
    Amount, CapabilityId, Digest384, Epoch, ObjectId, PackageId, PrincipalId, ResourceSelector,
    ScopeSelector,
};

/// Maximum bytes disclosed in an object's canonical public value.
pub const MAX_PUBLIC_OBJECT_VALUE: usize = 16_384;
/// Maximum exact versioned reads in one access manifest.
pub const MAX_EXACT_READS: usize = 64;
/// Maximum exact versioned writes in one access manifest.
pub const MAX_EXACT_WRITES: usize = 32;
/// Maximum immutable object reads in one access manifest.
pub const MAX_IMMUTABLE_READS: usize = 64;
/// Maximum object-creation namespace grants in one access manifest.
pub const MAX_CREATION_NAMESPACES: usize = 16;
/// Maximum objects a manifest may permit one transaction to create.
pub const MAX_CREATED_OBJECTS: u32 = 16;
/// Maximum policy-governed dynamic reads declared by one manifest.
pub const MAX_DYNAMIC_READS: u32 = 32;

/// The exclusive authority mode committed by an object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectOwner {
    /// A public principal owns the object.
    Principal(PrincipalId),
    /// The object is jointly controlled only by its policies.
    Shared,
    /// The object can never be mutated.
    Immutable,
    /// A named capability controls the object.
    CapabilityControlled(CapabilityId),
    /// A private owner commitment is proven during authorization.
    Shielded(Digest384),
}

impl CanonicalEncode for ObjectOwner {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Principal(principal_id) => {
                0_u8.encode(encoder)?;
                principal_id.encode(encoder)
            }
            Self::Shared => 1_u8.encode(encoder),
            Self::Immutable => 2_u8.encode(encoder),
            Self::CapabilityControlled(capability_id) => {
                3_u8.encode(encoder)?;
                capability_id.encode(encoder)
            }
            Self::Shielded(commitment) => {
                4_u8.encode(encoder)?;
                commitment.encode(encoder)
            }
        }
    }
}

impl CanonicalDecode for ObjectOwner {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Principal(PrincipalId::decode(decoder)?)),
            1 => Ok(Self::Shared),
            2 => Ok(Self::Immutable),
            3 => Ok(Self::CapabilityControlled(CapabilityId::decode(decoder)?)),
            4 => Ok(Self::Shielded(Digest384::decode(decoder)?)),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ObjectOwner", tag }),
        }
    }
}

/// Registered version-1 object behavior flags.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct ObjectFlags(u16);

impl ObjectFlags {
    /// Object ownership may be changed by the P-030 transfer transition.
    pub const TRANSFERABLE: Self = Self(0x0001);
    /// Future VM operations must preserve affine or linear value semantics.
    pub const LINEAR: Self = Self(0x0002);
    /// The object is reserved for protocol-system semantics.
    pub const SYSTEM: Self = Self(0x0004);
    /// No registered behavior flags.
    pub const NONE: Self = Self(0);
    const KNOWN_BITS: u16 = Self::TRANSFERABLE.0 | Self::LINEAR.0 | Self::SYSTEM.0;

    /// Constructs flags only when every set bit is registered in version 1.
    pub const fn from_bits(bits: u16) -> Result<Self, ObjectFlagsError> {
        if bits & !Self::KNOWN_BITS != 0 {
            return Err(ObjectFlagsError::UnknownBits(bits & !Self::KNOWN_BITS));
        }
        Ok(Self(bits))
    }

    /// Returns the canonical raw bit representation.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Combines registered flags.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns whether every bit in `flag` is set.
    #[must_use]
    pub const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }
}

impl CanonicalEncode for ObjectFlags {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.0.encode(encoder)
    }
}

impl CanonicalDecode for ObjectFlags {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::from_bits(u16::decode(decoder)?)
            .map_err(|_| DecodeError::InvalidValue("object flags contain unknown bits"))
    }
}

/// Object-flag construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectFlagsError {
    /// At least one bit has no version-1 meaning.
    UnknownBits(u16),
}

/// Fields used to construct a canonical object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectFields {
    /// Stable object identifier.
    pub object_id: ObjectId,
    /// Exact version consumed by future mutation.
    pub object_version: u64,
    /// Application or protocol type commitment.
    pub type_id: Digest384,
    /// Exclusive authority mode.
    pub owner: ObjectOwner,
    /// APL policy controlling mutations such as transfer.
    pub control_policy_hash: Digest384,
    /// APL policy controlling use without ownership change.
    pub use_policy_hash: Digest384,
    /// Policy controlling value disclosure.
    pub disclosure_policy_hash: Digest384,
    /// Policy controlling package and schema upgrades.
    pub upgrade_policy_hash: Digest384,
    /// Optional immutable code package interpreting the value.
    pub package_id: Option<PackageId>,
    /// Commitment to the authoritative value representation.
    pub value_root: Digest384,
    /// Optional bounded public value bytes.
    pub public_value: Option<Vec<u8>>,
    /// Epoch after which the active lease expires.
    pub lease_expiry_epoch: Epoch,
    /// Storage deposit committed to this object.
    pub storage_deposit: Amount,
    /// Registered behavior flags.
    pub flags: ObjectFlags,
}

/// A versioned ActiveChain object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Object {
    object_id: ObjectId,
    object_version: u64,
    type_id: Digest384,
    owner: ObjectOwner,
    control_policy_hash: Digest384,
    use_policy_hash: Digest384,
    disclosure_policy_hash: Digest384,
    upgrade_policy_hash: Digest384,
    package_id: Option<PackageId>,
    value_root: Digest384,
    public_value: Option<Vec<u8>>,
    lease_expiry_epoch: Epoch,
    storage_deposit: Amount,
    flags: ObjectFlags,
}

impl Object {
    /// Registered top-level object type tag.
    pub const TYPE_TAG: u16 = 0x0050;
    /// Initial canonical object schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Maximum canonical object body length.
    pub const MAX_ENCODED_LEN: usize = 16_856;

    /// Validates cross-field invariants and public-value bounds.
    pub fn new(fields: ObjectFields) -> Result<Self, ObjectValidationError> {
        if let Some(public_value) = &fields.public_value
            && public_value.len() > MAX_PUBLIC_OBJECT_VALUE
        {
            return Err(ObjectValidationError::PublicValueTooLarge {
                actual: public_value.len(),
                maximum: MAX_PUBLIC_OBJECT_VALUE,
            });
        }
        if fields.owner == ObjectOwner::Immutable
            && fields.flags.contains(ObjectFlags::TRANSFERABLE)
        {
            return Err(ObjectValidationError::ImmutableMarkedTransferable);
        }
        Ok(Self {
            object_id: fields.object_id,
            object_version: fields.object_version,
            type_id: fields.type_id,
            owner: fields.owner,
            control_policy_hash: fields.control_policy_hash,
            use_policy_hash: fields.use_policy_hash,
            disclosure_policy_hash: fields.disclosure_policy_hash,
            upgrade_policy_hash: fields.upgrade_policy_hash,
            package_id: fields.package_id,
            value_root: fields.value_root,
            public_value: fields.public_value,
            lease_expiry_epoch: fields.lease_expiry_epoch,
            storage_deposit: fields.storage_deposit,
            flags: fields.flags,
        })
    }

    /// Returns the stable object identifier.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Returns the current object version.
    #[must_use]
    pub const fn object_version(&self) -> u64 {
        self.object_version
    }

    /// Returns the application or protocol type commitment.
    #[must_use]
    pub const fn type_id(&self) -> Digest384 {
        self.type_id
    }

    /// Returns the exclusive authority mode.
    #[must_use]
    pub const fn owner(&self) -> ObjectOwner {
        self.owner
    }

    /// Returns the control-policy commitment.
    #[must_use]
    pub const fn control_policy_hash(&self) -> Digest384 {
        self.control_policy_hash
    }

    /// Returns the use-policy commitment.
    #[must_use]
    pub const fn use_policy_hash(&self) -> Digest384 {
        self.use_policy_hash
    }

    /// Returns the disclosure-policy commitment.
    #[must_use]
    pub const fn disclosure_policy_hash(&self) -> Digest384 {
        self.disclosure_policy_hash
    }

    /// Returns the upgrade-policy commitment.
    #[must_use]
    pub const fn upgrade_policy_hash(&self) -> Digest384 {
        self.upgrade_policy_hash
    }

    /// Returns the optional package identifier.
    #[must_use]
    pub const fn package_id(&self) -> Option<PackageId> {
        self.package_id
    }

    /// Returns the authoritative value commitment.
    #[must_use]
    pub const fn value_root(&self) -> Digest384 {
        self.value_root
    }

    /// Borrows optional public value bytes.
    #[must_use]
    pub fn public_value(&self) -> Option<&[u8]> {
        self.public_value.as_deref()
    }

    /// Returns the lease expiry epoch.
    #[must_use]
    pub const fn lease_expiry_epoch(&self) -> Epoch {
        self.lease_expiry_epoch
    }

    /// Returns the storage deposit.
    #[must_use]
    pub const fn storage_deposit(&self) -> Amount {
        self.storage_deposit
    }

    /// Returns registered object flags.
    #[must_use]
    pub const fn flags(&self) -> ObjectFlags {
        self.flags
    }

    /// Copies every field into a mutation-friendly construction value.
    #[must_use]
    pub fn to_fields(&self) -> ObjectFields {
        ObjectFields {
            object_id: self.object_id,
            object_version: self.object_version,
            type_id: self.type_id,
            owner: self.owner,
            control_policy_hash: self.control_policy_hash,
            use_policy_hash: self.use_policy_hash,
            disclosure_policy_hash: self.disclosure_policy_hash,
            upgrade_policy_hash: self.upgrade_policy_hash,
            package_id: self.package_id,
            value_root: self.value_root,
            public_value: self.public_value.clone(),
            lease_expiry_epoch: self.lease_expiry_epoch,
            storage_deposit: self.storage_deposit,
            flags: self.flags,
        }
    }
}

impl CanonicalEncode for Object {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.object_id.encode(encoder)?;
        self.object_version.encode(encoder)?;
        self.type_id.encode(encoder)?;
        self.owner.encode(encoder)?;
        self.control_policy_hash.encode(encoder)?;
        self.use_policy_hash.encode(encoder)?;
        self.disclosure_policy_hash.encode(encoder)?;
        self.upgrade_policy_hash.encode(encoder)?;
        self.package_id.encode(encoder)?;
        self.value_root.encode(encoder)?;
        match &self.public_value {
            None => 0_u8.encode(encoder)?,
            Some(public_value) => {
                1_u8.encode(encoder)?;
                encoder.write_bytes(public_value, MAX_PUBLIC_OBJECT_VALUE)?;
            }
        }
        self.lease_expiry_epoch.encode(encoder)?;
        self.storage_deposit.encode(encoder)?;
        self.flags.encode(encoder)
    }
}

impl CanonicalDecode for Object {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let object_id = ObjectId::decode(decoder)?;
        let object_version = u64::decode(decoder)?;
        let type_id = Digest384::decode(decoder)?;
        let owner = ObjectOwner::decode(decoder)?;
        let control_policy_hash = Digest384::decode(decoder)?;
        let use_policy_hash = Digest384::decode(decoder)?;
        let disclosure_policy_hash = Digest384::decode(decoder)?;
        let upgrade_policy_hash = Digest384::decode(decoder)?;
        let package_id = Option::<PackageId>::decode(decoder)?;
        let value_root = Digest384::decode(decoder)?;
        let public_value = match u8::decode(decoder)? {
            0 => None,
            1 => Some(Vec::from(decoder.read_bytes(MAX_PUBLIC_OBJECT_VALUE)?)),
            tag => return Err(DecodeError::InvalidEnumTag { type_name: "Option", tag }),
        };
        let lease_expiry_epoch = u64::decode(decoder)?;
        let storage_deposit = u128::decode(decoder)?;
        let flags = ObjectFlags::decode(decoder)?;
        Self::new(ObjectFields {
            object_id,
            object_version,
            type_id,
            owner,
            control_policy_hash,
            use_policy_hash,
            disclosure_policy_hash,
            upgrade_policy_hash,
            package_id,
            value_root,
            public_value,
            lease_expiry_epoch,
            storage_deposit,
            flags,
        })
        .map_err(object_decode_error)
    }
}

impl CanonicalType for Object {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Canonical object construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectValidationError {
    /// Public value bytes exceed the object schema bound.
    PublicValueTooLarge { actual: usize, maximum: usize },
    /// Immutable ownership and transferability are contradictory.
    ImmutableMarkedTransferable,
}

/// An exact object and version consumed by a read or write.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObjectVersionRef {
    object_id: ObjectId,
    version: u64,
}

impl ObjectVersionRef {
    /// Creates an exact object-version reference.
    #[must_use]
    pub const fn new(object_id: ObjectId, version: u64) -> Self {
        Self { object_id, version }
    }

    /// Returns the object identifier.
    #[must_use]
    pub const fn object_id(self) -> ObjectId {
        self.object_id
    }

    /// Returns the exact expected version.
    #[must_use]
    pub const fn version(self) -> u64 {
        self.version
    }
}

impl CanonicalEncode for ObjectVersionRef {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.object_id.encode(encoder)?;
        self.version.encode(encoder)
    }
}

impl CanonicalDecode for ObjectVersionRef {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(ObjectId::decode(decoder)?, u64::decode(decoder)?))
    }
}

/// A capability-authorized namespace in which objects may be created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceGrant {
    namespace: ResourceSelector,
    capability_id: CapabilityId,
}

impl NamespaceGrant {
    /// Maximum canonical namespace-grant body length.
    pub const MAX_ENCODED_LEN: usize = 99;

    /// Constructs a canonical namespace grant.
    #[must_use]
    pub const fn new(namespace: ResourceSelector, capability_id: CapabilityId) -> Self {
        Self { namespace, capability_id }
    }

    /// Returns the resource namespace selector.
    #[must_use]
    pub const fn namespace(self) -> ResourceSelector {
        self.namespace
    }

    /// Returns the capability authorizing creation.
    #[must_use]
    pub const fn capability_id(self) -> CapabilityId {
        self.capability_id
    }

    /// Returns whether this grant covers an exact new object identifier.
    #[must_use]
    pub fn contains(self, object_id: ObjectId) -> bool {
        ResourceSelector::exact(object_id).is_subset_of(&self.namespace)
    }
}

impl Ord for NamespaceGrant {
    fn cmp(&self, other: &Self) -> Ordering {
        scope_cmp(self.namespace.as_scope(), other.namespace.as_scope())
            .then_with(|| self.capability_id.cmp(&other.capability_id))
    }
}

impl PartialOrd for NamespaceGrant {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl CanonicalEncode for NamespaceGrant {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.namespace.encode(encoder)?;
        self.capability_id.encode(encoder)
    }
}

impl CanonicalDecode for NamespaceGrant {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(ResourceSelector::decode(decoder)?, CapabilityId::decode(decoder)?))
    }
}

/// Fields used to construct a bounded canonical access manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessManifestFields {
    /// Strictly increasing exact versioned reads.
    pub exact_reads: Vec<ObjectVersionRef>,
    /// Strictly increasing exact versioned writes.
    pub exact_writes: Vec<ObjectVersionRef>,
    /// Strictly increasing immutable reads without version consumption.
    pub immutable_reads: Vec<ObjectId>,
    /// Strictly increasing creation namespace grants.
    pub creation_namespaces: Vec<NamespaceGrant>,
    /// Maximum objects created by the transaction.
    pub maximum_created_objects: u32,
    /// Maximum policy-governed dynamic reads.
    pub maximum_dynamic_reads: u32,
    /// Required policy commitment for positive dynamic-read allowance.
    pub dynamic_read_policy: Option<Digest384>,
}

/// A bounded declaration of every object access class available to a transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessManifest {
    exact_reads: Vec<ObjectVersionRef>,
    exact_writes: Vec<ObjectVersionRef>,
    immutable_reads: Vec<ObjectId>,
    creation_namespaces: Vec<NamespaceGrant>,
    maximum_created_objects: u32,
    maximum_dynamic_reads: u32,
    dynamic_read_policy: Option<Digest384>,
}

impl AccessManifest {
    /// Registered top-level access-manifest type tag.
    pub const TYPE_TAG: u16 = 0x0051;
    /// Initial canonical access-manifest schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Maximum canonical access-manifest body length.
    pub const MAX_ENCODED_LEN: usize = 10_093;

    /// Checks all bounds, ordering, disjointness, and option invariants.
    pub fn new(fields: AccessManifestFields) -> Result<Self, AccessManifestError> {
        check_manifest_bounds(&fields)?;
        if !object_refs_strictly_increasing(&fields.exact_reads) {
            return Err(AccessManifestError::ExactReadsNotStrictlyIncreasing);
        }
        if !object_refs_strictly_increasing(&fields.exact_writes) {
            return Err(AccessManifestError::ExactWritesNotStrictlyIncreasing);
        }
        if !strictly_increasing(&fields.immutable_reads) {
            return Err(AccessManifestError::ImmutableReadsNotStrictlyIncreasing);
        }
        if !strictly_increasing(&fields.creation_namespaces) {
            return Err(AccessManifestError::CreationNamespacesNotStrictlyIncreasing);
        }
        if access_sets_overlap(&fields) {
            return Err(AccessManifestError::OverlappingAccessDeclarations);
        }
        if (fields.maximum_created_objects == 0) != fields.creation_namespaces.is_empty() {
            return Err(AccessManifestError::CreationNamespaceLimitMismatch);
        }
        if (fields.maximum_dynamic_reads == 0) != fields.dynamic_read_policy.is_none() {
            return Err(AccessManifestError::DynamicReadPolicyMismatch);
        }

        Ok(Self {
            exact_reads: fields.exact_reads,
            exact_writes: fields.exact_writes,
            immutable_reads: fields.immutable_reads,
            creation_namespaces: fields.creation_namespaces,
            maximum_created_objects: fields.maximum_created_objects,
            maximum_dynamic_reads: fields.maximum_dynamic_reads,
            dynamic_read_policy: fields.dynamic_read_policy,
        })
    }

    /// Borrows exact versioned reads.
    #[must_use]
    pub fn exact_reads(&self) -> &[ObjectVersionRef] {
        &self.exact_reads
    }

    /// Borrows exact versioned writes.
    #[must_use]
    pub fn exact_writes(&self) -> &[ObjectVersionRef] {
        &self.exact_writes
    }

    /// Borrows immutable object reads.
    #[must_use]
    pub fn immutable_reads(&self) -> &[ObjectId] {
        &self.immutable_reads
    }

    /// Borrows creation namespace grants.
    #[must_use]
    pub fn creation_namespaces(&self) -> &[NamespaceGrant] {
        &self.creation_namespaces
    }

    /// Returns the declared maximum created object count.
    #[must_use]
    pub const fn maximum_created_objects(&self) -> u32 {
        self.maximum_created_objects
    }

    /// Returns the declared maximum dynamic read count.
    #[must_use]
    pub const fn maximum_dynamic_reads(&self) -> u32 {
        self.maximum_dynamic_reads
    }

    /// Returns the dynamic-read policy commitment.
    #[must_use]
    pub const fn dynamic_read_policy(&self) -> Option<Digest384> {
        self.dynamic_read_policy
    }

    /// Returns whether the exact read reference is declared.
    #[must_use]
    pub fn permits_exact_read(&self, reference: ObjectVersionRef) -> bool {
        self.exact_reads.binary_search(&reference).is_ok()
    }

    /// Returns whether the exact write reference is declared.
    #[must_use]
    pub fn permits_exact_write(&self, reference: ObjectVersionRef) -> bool {
        self.exact_writes.binary_search(&reference).is_ok()
    }

    /// Returns whether an immutable read is declared.
    #[must_use]
    pub fn permits_immutable_read(&self, object_id: ObjectId) -> bool {
        self.immutable_reads.binary_search(&object_id).is_ok()
    }

    /// Returns whether a creation identifier and authority fit any declared namespace.
    #[must_use]
    pub fn permits_creation(&self, object_id: ObjectId, capability_id: CapabilityId) -> bool {
        self.creation_namespaces
            .iter()
            .any(|grant| grant.capability_id == capability_id && grant.contains(object_id))
    }
}

impl CanonicalEncode for AccessManifest {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.exact_reads.len(), MAX_EXACT_READS)?;
        for reference in &self.exact_reads {
            reference.encode(encoder)?;
        }
        encoder.write_length(self.exact_writes.len(), MAX_EXACT_WRITES)?;
        for reference in &self.exact_writes {
            reference.encode(encoder)?;
        }
        encoder.write_length(self.immutable_reads.len(), MAX_IMMUTABLE_READS)?;
        for object_id in &self.immutable_reads {
            object_id.encode(encoder)?;
        }
        encoder.write_length(self.creation_namespaces.len(), MAX_CREATION_NAMESPACES)?;
        for namespace in &self.creation_namespaces {
            namespace.encode(encoder)?;
        }
        self.maximum_created_objects.encode(encoder)?;
        self.maximum_dynamic_reads.encode(encoder)?;
        self.dynamic_read_policy.encode(encoder)
    }
}

impl CanonicalDecode for AccessManifest {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let read_count = decoder.read_length(MAX_EXACT_READS)?;
        let mut exact_reads = Vec::with_capacity(read_count);
        for _ in 0..read_count {
            exact_reads.push(ObjectVersionRef::decode(decoder)?);
        }
        let write_count = decoder.read_length(MAX_EXACT_WRITES)?;
        let mut exact_writes = Vec::with_capacity(write_count);
        for _ in 0..write_count {
            exact_writes.push(ObjectVersionRef::decode(decoder)?);
        }
        let immutable_count = decoder.read_length(MAX_IMMUTABLE_READS)?;
        let mut immutable_reads = Vec::with_capacity(immutable_count);
        for _ in 0..immutable_count {
            immutable_reads.push(ObjectId::decode(decoder)?);
        }
        let namespace_count = decoder.read_length(MAX_CREATION_NAMESPACES)?;
        let mut creation_namespaces = Vec::with_capacity(namespace_count);
        for _ in 0..namespace_count {
            creation_namespaces.push(NamespaceGrant::decode(decoder)?);
        }
        Self::new(AccessManifestFields {
            exact_reads,
            exact_writes,
            immutable_reads,
            creation_namespaces,
            maximum_created_objects: u32::decode(decoder)?,
            maximum_dynamic_reads: u32::decode(decoder)?,
            dynamic_read_policy: Option::<Digest384>::decode(decoder)?,
        })
        .map_err(access_manifest_decode_error)
    }
}

impl CanonicalType for AccessManifest {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Access-manifest construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessManifestError {
    /// Too many exact versioned reads.
    TooManyExactReads { actual: usize, maximum: usize },
    /// Too many exact versioned writes.
    TooManyExactWrites { actual: usize, maximum: usize },
    /// Too many immutable reads.
    TooManyImmutableReads { actual: usize, maximum: usize },
    /// Too many creation namespace grants.
    TooManyCreationNamespaces { actual: usize, maximum: usize },
    /// The maximum created-object count exceeds the version-1 bound.
    TooManyCreatedObjects { actual: u32, maximum: u32 },
    /// The maximum dynamic-read count exceeds the version-1 bound.
    TooManyDynamicReads { actual: u32, maximum: u32 },
    /// Exact reads are duplicate, unordered, or contain two versions of one object.
    ExactReadsNotStrictlyIncreasing,
    /// Exact writes are duplicate, unordered, or contain two versions of one object.
    ExactWritesNotStrictlyIncreasing,
    /// Immutable reads are duplicate or unordered.
    ImmutableReadsNotStrictlyIncreasing,
    /// Creation namespace grants are duplicate or unordered.
    CreationNamespacesNotStrictlyIncreasing,
    /// One object identifier appears in more than one access class.
    OverlappingAccessDeclarations,
    /// Creation grants and the maximum-created count disagree about whether creation is allowed.
    CreationNamespaceLimitMismatch,
    /// Dynamic-read count and policy presence do not form the unique canonical pair.
    DynamicReadPolicyMismatch,
}

fn check_manifest_bounds(fields: &AccessManifestFields) -> Result<(), AccessManifestError> {
    if fields.exact_reads.len() > MAX_EXACT_READS {
        return Err(AccessManifestError::TooManyExactReads {
            actual: fields.exact_reads.len(),
            maximum: MAX_EXACT_READS,
        });
    }
    if fields.exact_writes.len() > MAX_EXACT_WRITES {
        return Err(AccessManifestError::TooManyExactWrites {
            actual: fields.exact_writes.len(),
            maximum: MAX_EXACT_WRITES,
        });
    }
    if fields.immutable_reads.len() > MAX_IMMUTABLE_READS {
        return Err(AccessManifestError::TooManyImmutableReads {
            actual: fields.immutable_reads.len(),
            maximum: MAX_IMMUTABLE_READS,
        });
    }
    if fields.creation_namespaces.len() > MAX_CREATION_NAMESPACES {
        return Err(AccessManifestError::TooManyCreationNamespaces {
            actual: fields.creation_namespaces.len(),
            maximum: MAX_CREATION_NAMESPACES,
        });
    }
    if fields.maximum_created_objects > MAX_CREATED_OBJECTS {
        return Err(AccessManifestError::TooManyCreatedObjects {
            actual: fields.maximum_created_objects,
            maximum: MAX_CREATED_OBJECTS,
        });
    }
    if fields.maximum_dynamic_reads > MAX_DYNAMIC_READS {
        return Err(AccessManifestError::TooManyDynamicReads {
            actual: fields.maximum_dynamic_reads,
            maximum: MAX_DYNAMIC_READS,
        });
    }
    Ok(())
}

fn object_refs_strictly_increasing(references: &[ObjectVersionRef]) -> bool {
    references.windows(2).all(|pair| pair[0].object_id < pair[1].object_id)
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn access_sets_overlap(fields: &AccessManifestFields) -> bool {
    fields.exact_reads.iter().any(|reference| {
        contains_object_ref(&fields.exact_writes, reference.object_id)
            || fields.immutable_reads.binary_search(&reference.object_id).is_ok()
    }) || fields
        .exact_writes
        .iter()
        .any(|reference| fields.immutable_reads.binary_search(&reference.object_id).is_ok())
}

fn contains_object_ref(references: &[ObjectVersionRef], object_id: ObjectId) -> bool {
    references.binary_search_by_key(&object_id, |reference| reference.object_id).is_ok()
}

fn scope_cmp(left: &ScopeSelector, right: &ScopeSelector) -> Ordering {
    match (left, right) {
        (ScopeSelector::Any, ScopeSelector::Any) => Ordering::Equal,
        (ScopeSelector::Any, _) => Ordering::Less,
        (_, ScopeSelector::Any) => Ordering::Greater,
        (ScopeSelector::Exact(left), ScopeSelector::Exact(right)) => left.cmp(right),
        (ScopeSelector::Exact(_), ScopeSelector::Prefix { .. }) => Ordering::Less,
        (ScopeSelector::Prefix { .. }, ScopeSelector::Exact(_)) => Ordering::Greater,
        (
            ScopeSelector::Prefix { bytes: left_bytes, bits: left_bits },
            ScopeSelector::Prefix { bytes: right_bytes, bits: right_bits },
        ) => left_bits.cmp(right_bits).then_with(|| left_bytes.cmp(right_bytes)),
    }
}

fn object_decode_error(error: ObjectValidationError) -> DecodeError {
    match error {
        ObjectValidationError::PublicValueTooLarge { .. } => {
            DecodeError::InvalidValue("object public value exceeds its bound")
        }
        ObjectValidationError::ImmutableMarkedTransferable => {
            DecodeError::InvalidValue("immutable object is marked transferable")
        }
    }
}

fn access_manifest_decode_error(error: AccessManifestError) -> DecodeError {
    match error {
        AccessManifestError::TooManyExactReads { .. } => {
            DecodeError::InvalidValue("manifest exceeds its exact-read bound")
        }
        AccessManifestError::TooManyExactWrites { .. } => {
            DecodeError::InvalidValue("manifest exceeds its exact-write bound")
        }
        AccessManifestError::TooManyImmutableReads { .. } => {
            DecodeError::InvalidValue("manifest exceeds its immutable-read bound")
        }
        AccessManifestError::TooManyCreationNamespaces { .. } => {
            DecodeError::InvalidValue("manifest exceeds its creation-namespace bound")
        }
        AccessManifestError::TooManyCreatedObjects { .. } => {
            DecodeError::InvalidValue("manifest exceeds its object-creation bound")
        }
        AccessManifestError::TooManyDynamicReads { .. } => {
            DecodeError::InvalidValue("manifest exceeds its dynamic-read bound")
        }
        AccessManifestError::ExactReadsNotStrictlyIncreasing => {
            DecodeError::InvalidValue("manifest exact reads are not strictly increasing")
        }
        AccessManifestError::ExactWritesNotStrictlyIncreasing => {
            DecodeError::InvalidValue("manifest exact writes are not strictly increasing")
        }
        AccessManifestError::ImmutableReadsNotStrictlyIncreasing => {
            DecodeError::InvalidValue("manifest immutable reads are not strictly increasing")
        }
        AccessManifestError::CreationNamespacesNotStrictlyIncreasing => {
            DecodeError::InvalidValue("manifest creation namespaces are not strictly increasing")
        }
        AccessManifestError::OverlappingAccessDeclarations => {
            DecodeError::InvalidValue("manifest access declarations overlap")
        }
        AccessManifestError::CreationNamespaceLimitMismatch => {
            DecodeError::InvalidValue("manifest creation namespaces and limit disagree")
        }
        AccessManifestError::DynamicReadPolicyMismatch => {
            DecodeError::InvalidValue("manifest dynamic-read policy and limit disagree")
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;

    use activechain_canonical_codec::{decode_envelope, encode_body, encode_envelope};

    use crate::{CapabilityId, Digest384, ObjectId, PackageId, PrincipalId, ResourceSelector};

    use super::{
        AccessManifest, AccessManifestError, AccessManifestFields, MAX_EXACT_WRITES,
        MAX_PUBLIC_OBJECT_VALUE, NamespaceGrant, Object, ObjectFields, ObjectFlags,
        ObjectFlagsError, ObjectOwner, ObjectValidationError, ObjectVersionRef,
    };

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn prefix_digest(byte: u8) -> Digest384 {
        let mut bytes = [0_u8; 48];
        bytes[0] = byte;
        Digest384::new(bytes)
    }

    fn object(owner: ObjectOwner, flags: ObjectFlags) -> Result<Object, ObjectValidationError> {
        Object::new(ObjectFields {
            object_id: ObjectId::new(digest(0x10)),
            object_version: 7,
            type_id: digest(0x20),
            owner,
            control_policy_hash: digest(0x30),
            use_policy_hash: digest(0x31),
            disclosure_policy_hash: digest(0x32),
            upgrade_policy_hash: digest(0x33),
            package_id: None,
            value_root: digest(0x40),
            public_value: Some(vec![1, 2, 3]),
            lease_expiry_epoch: 100,
            storage_deposit: 500,
            flags,
        })
    }

    fn empty_manifest() -> AccessManifestFields {
        AccessManifestFields {
            exact_reads: vec![],
            exact_writes: vec![],
            immutable_reads: vec![],
            creation_namespaces: vec![],
            maximum_created_objects: 0,
            maximum_dynamic_reads: 0,
            dynamic_read_policy: None,
        }
    }

    #[test]
    fn objects_round_trip_and_reject_contradictory_flags() {
        let value = object(
            ObjectOwner::Principal(PrincipalId::new(digest(0x50))),
            ObjectFlags::TRANSFERABLE.union(ObjectFlags::LINEAR),
        )
        .expect("valid object");
        let encoded = encode_envelope(&value).expect("object fits its bound");
        assert_eq!(decode_envelope(&encoded), Ok(value.clone()));

        assert_eq!(
            object(ObjectOwner::Immutable, ObjectFlags::TRANSFERABLE),
            Err(ObjectValidationError::ImmutableMarkedTransferable)
        );
        assert_eq!(ObjectFlags::from_bits(0x8000), Err(ObjectFlagsError::UnknownBits(0x8000)));

        let mut oversized = value.to_fields();
        oversized.public_value = Some(vec![0; MAX_PUBLIC_OBJECT_VALUE + 1]);
        assert!(matches!(
            Object::new(oversized),
            Err(ObjectValidationError::PublicValueTooLarge { .. })
        ));
    }

    #[test]
    fn manifests_require_ordered_disjoint_access_sets() {
        let first = ObjectVersionRef::new(ObjectId::new(digest(0x10)), 1);
        let second = ObjectVersionRef::new(ObjectId::new(digest(0x20)), 2);

        let mut fields = empty_manifest();
        fields.exact_reads = vec![second, first];
        assert_eq!(
            AccessManifest::new(fields),
            Err(AccessManifestError::ExactReadsNotStrictlyIncreasing)
        );

        let mut fields = empty_manifest();
        fields.exact_reads = vec![first];
        fields.exact_writes = vec![first];
        assert_eq!(
            AccessManifest::new(fields),
            Err(AccessManifestError::OverlappingAccessDeclarations)
        );
    }

    #[test]
    fn manifest_option_pairs_have_one_canonical_form() {
        let mut fields = empty_manifest();
        fields.maximum_dynamic_reads = 1;
        assert_eq!(
            AccessManifest::new(fields),
            Err(AccessManifestError::DynamicReadPolicyMismatch)
        );

        let mut fields = empty_manifest();
        fields.maximum_created_objects = 1;
        assert_eq!(
            AccessManifest::new(fields),
            Err(AccessManifestError::CreationNamespaceLimitMismatch)
        );

        let mut fields = empty_manifest();
        fields.exact_writes =
            (0_u8..=32).map(|byte| ObjectVersionRef::new(ObjectId::new(digest(byte)), 0)).collect();
        assert_eq!(fields.exact_writes.len(), MAX_EXACT_WRITES + 1);
        assert!(matches!(
            AccessManifest::new(fields),
            Err(AccessManifestError::TooManyExactWrites { .. })
        ));
    }

    #[test]
    fn manifest_round_trip_and_access_queries_are_exact() {
        let write = ObjectVersionRef::new(ObjectId::new(digest(0x10)), 7);
        let capability = CapabilityId::new(digest(0x60));
        let created = ObjectId::new(digest(0x70));
        let manifest = AccessManifest::new(AccessManifestFields {
            exact_reads: vec![],
            exact_writes: vec![write],
            immutable_reads: vec![ObjectId::new(digest(0x20))],
            creation_namespaces: vec![NamespaceGrant::new(
                ResourceSelector::exact(created),
                capability,
            )],
            maximum_created_objects: 1,
            maximum_dynamic_reads: 2,
            dynamic_read_policy: Some(digest(0x80)),
        })
        .expect("canonical manifest");

        assert!(manifest.permits_exact_write(write));
        assert!(!manifest.permits_exact_write(ObjectVersionRef::new(write.object_id(), 8)));
        assert!(manifest.permits_immutable_read(ObjectId::new(digest(0x20))));
        assert!(manifest.permits_creation(created, capability));

        let encoded = encode_envelope(&manifest).expect("manifest fits its bound");
        assert_eq!(decode_envelope(&encoded), Ok(manifest));
    }

    #[test]
    fn published_maximum_body_lengths_are_exact() {
        let value = object(
            ObjectOwner::Principal(PrincipalId::new(digest(0x50))),
            ObjectFlags::TRANSFERABLE,
        )
        .expect("valid object");
        let mut fields = value.to_fields();
        fields.package_id = Some(PackageId::new(digest(0x60)));
        fields.public_value = Some(vec![0; MAX_PUBLIC_OBJECT_VALUE]);
        let maximal_object = Object::new(fields).expect("maximal public object is valid");
        assert_eq!(
            encode_body(&maximal_object).expect("maximal object encodes").len(),
            Object::MAX_ENCODED_LEN
        );

        let exact_reads =
            (0_u8..64).map(|byte| ObjectVersionRef::new(ObjectId::new(digest(byte)), 0)).collect();
        let exact_writes =
            (64_u8..96).map(|byte| ObjectVersionRef::new(ObjectId::new(digest(byte)), 0)).collect();
        let immutable_reads = (96_u8..160).map(|byte| ObjectId::new(digest(byte))).collect();
        let creation_namespaces = (160_u8..176)
            .map(|byte| {
                NamespaceGrant::new(
                    ResourceSelector::prefix(prefix_digest(byte), 8).expect("normalized prefix"),
                    CapabilityId::new(digest(byte)),
                )
            })
            .collect();
        let maximal_manifest = AccessManifest::new(AccessManifestFields {
            exact_reads,
            exact_writes,
            immutable_reads,
            creation_namespaces,
            maximum_created_objects: 16,
            maximum_dynamic_reads: 32,
            dynamic_read_policy: Some(digest(0xff)),
        })
        .expect("maximal manifest is canonical");
        assert_eq!(
            encode_body(&maximal_manifest).expect("maximal manifest encodes").len(),
            AccessManifest::MAX_ENCODED_LEN
        );
    }
}
