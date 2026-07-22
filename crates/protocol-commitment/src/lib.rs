#![no_std]
#![forbid(unsafe_code)]

//! Domain-separated SHAKE256 commitments over canonical protocol bodies.

extern crate alloc;

use activechain_canonical_codec::{CanonicalType, EncodeError, encode_body};
use activechain_protocol_types::{
    AssetId, CoinCellId, CoinCellSetRoot, DIGEST_LENGTH, Digest384, GenesisAllocationRoot,
    PackageId, PackageManifest, SupplyRoot, TransactionId,
};
use alloc::vec::Vec;
use sha3::{Shake256, digest::ExtendableOutput, digest::Update, digest::XofReader};

const TRANSCRIPT_PREFIX: &[u8] = b"ACTIVECHAIN-COMMITMENT";
const TRANSCRIPT_VERSION: u16 = 1;

/// A registered purpose for a protocol commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct DomainTag(u16);

impl DomainTag {
    /// Commitment to a canonical value without assigning it another role.
    pub const CANONICAL_VALUE: Self = Self(0x0001);
    /// Derivation of an object identifier from canonical creation material.
    pub const OBJECT_ID_DERIVATION: Self = Self(0x0002);
    /// Bytes committed for a protocol signing operation.
    pub const SIGNING_PAYLOAD: Self = Self(0x0003);
    /// Commitment to a canonical state-tree leaf.
    pub const STATE_LEAF: Self = Self(0x0004);
    /// Derivation of an admitted action identifier.
    pub const ACTION_ID: Self = Self(0x0005);
    /// Derivation of a canonical finalized development block identifier.
    pub const BLOCK_ID: Self = Self(0x0006);
    /// Derivation of a complete signed credential identifier.
    pub const CREDENTIAL_ID: Self = Self(0x0007);
    /// Commitment signed by a credential issuer.
    pub const CREDENTIAL_ISSUANCE: Self = Self(0x0008);
    /// Derivation of an immutable ObjectVM package identifier.
    pub const PACKAGE_ID: Self = Self(0x0009);
    /// Derivation of a native asset identifier from its canonical definition.
    pub const NATIVE_ASSET_ID: Self = Self(0x000a);
    /// Derivation of a native-money transition identifier.
    pub const CASH_TRANSITION_ID: Self = Self(0x000b);
    /// Derivation of a Coin Cell identifier from its transaction origin.
    pub const COIN_CELL_ID: Self = Self(0x000c);
    /// Commitment to the complete canonical unspent Coin Cell set.
    pub const COIN_CELL_SET_ROOT: Self = Self(0x000d);
    /// Commitment to canonical native-asset supply accounting.
    pub const SUPPLY_ROOT: Self = Self(0x000e);
    /// Commitment to the one-time genesis allocation.
    pub const GENESIS_ALLOCATION_ROOT: Self = Self(0x000f);
    /// Commitment to a shielded note's complete private opening.
    pub const SHIELDED_NOTE: Self = Self(0x0010);
    /// Derivation of a one-shot nullifier from its private authorization material.
    pub const NULLIFIER: Self = Self(0x0011);
    /// Commitment to the exact public inputs accepted by a privacy proof.
    pub const PRIVACY_PUBLIC_INPUTS: Self = Self(0x0012);
    /// Derivation of a holder-controlled pseudonym scoped to one application domain and epoch.
    pub const DOMAIN_PSEUDONYM: Self = Self(0x0013);
    /// Commitment to a private-credential proof's complete public statement.
    pub const PRIVATE_CREDENTIAL_PRESENTATION: Self = Self(0x0014);
    /// Commitment to a private-object transition's complete public statement.
    pub const PRIVATE_OBJECT_TRANSITION: Self = Self(0x0015);
    /// Deterministic order key derived only after a protected set is locked.
    pub const PROTECTED_ORDER_KEY: Self = Self(0x0016);

    /// Returns the registered numeric tag.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// Derives the immutable package identifier from its canonical manifest.
pub fn package_id(manifest: &PackageManifest) -> Result<PackageId, EncodeError> {
    commit(DomainTag::PACKAGE_ID, manifest).map(PackageId::new)
}

/// Derives a native asset identifier from a canonical definition.
pub fn native_asset_id<T: CanonicalType>(definition: &T) -> Result<AssetId, EncodeError> {
    commit(DomainTag::NATIVE_ASSET_ID, definition).map(AssetId::new)
}

/// Derives a Coin Cell identifier from its canonical origin.
pub fn coin_cell_id<T: CanonicalType>(origin: &T) -> Result<CoinCellId, EncodeError> {
    commit(DomainTag::COIN_CELL_ID, origin).map(CoinCellId::new)
}

/// Derives a native-money transition identifier from its canonical intent.
pub fn cash_transition_id<T: CanonicalType>(transition: &T) -> Result<TransactionId, EncodeError> {
    commit(DomainTag::CASH_TRANSITION_ID, transition).map(TransactionId::new)
}

/// Commits a canonical unspent Coin Cell set.
pub fn coin_cell_set_root<T: CanonicalType>(set: &T) -> Result<CoinCellSetRoot, EncodeError> {
    commit(DomainTag::COIN_CELL_SET_ROOT, set).map(CoinCellSetRoot::new)
}

/// Commits canonical native-asset supply accounting.
pub fn supply_root<T: CanonicalType>(supply: &T) -> Result<SupplyRoot, EncodeError> {
    commit(DomainTag::SUPPLY_ROOT, supply).map(SupplyRoot::new)
}

/// Commits the one-time deterministic genesis allocation.
pub fn genesis_allocation_root<T: CanonicalType>(
    allocation: &T,
) -> Result<GenesisAllocationRoot, EncodeError> {
    commit(DomainTag::GENESIS_ALLOCATION_ROOT, allocation).map(GenesisAllocationRoot::new)
}

/// Computes a 384-bit SHAKE256 commitment over the P-001 transcript.
///
/// The canonical envelope is deliberately not hashed as part of the body: its
/// type tag and schema version already occupy unambiguous transcript fields.
pub fn commit<T: CanonicalType>(domain: DomainTag, value: &T) -> Result<Digest384, EncodeError> {
    let body = encode_body(value)?;
    let transcript = commitment_transcript(domain, T::TYPE_TAG, T::SCHEMA_VERSION, &body)?;

    let mut hasher = Shake256::default();
    hasher.update(&transcript);

    let mut output = [0_u8; DIGEST_LENGTH];
    hasher.finalize_xof().read(&mut output);
    Ok(Digest384::new(output))
}

fn commitment_transcript(
    domain: DomainTag,
    type_tag: u16,
    schema_version: u16,
    body: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    let body_length = u64::try_from(body.len()).map_err(|_| EncodeError::LengthOverflow)?;
    let mut transcript = Vec::with_capacity(38 + body.len());
    transcript.extend_from_slice(TRANSCRIPT_PREFIX);
    transcript.extend_from_slice(&TRANSCRIPT_VERSION.to_be_bytes());
    transcript.extend_from_slice(&domain.as_u16().to_be_bytes());
    transcript.extend_from_slice(&type_tag.to_be_bytes());
    transcript.extend_from_slice(&schema_version.to_be_bytes());
    transcript.extend_from_slice(&body_length.to_be_bytes());
    transcript.extend_from_slice(body);
    Ok(transcript)
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn transcript_binds_every_header_field_and_bounded_body() {
        let domain: u16 = kani::any();
        let type_tag: u16 = kani::any();
        let version: u16 = kani::any();
        let bytes: [u8; 4] = kani::any();
        let length: usize = kani::any();
        kani::assume(length <= bytes.len());
        let transcript =
            commitment_transcript(DomainTag(domain), type_tag, version, &bytes[..length]).unwrap();
        assert_eq!(transcript.len(), 38 + length);
        assert_eq!(&transcript[..22], TRANSCRIPT_PREFIX);
        assert_eq!(&transcript[22..24], &TRANSCRIPT_VERSION.to_be_bytes());
        assert_eq!(&transcript[24..26], &domain.to_be_bytes());
        assert_eq!(&transcript[26..28], &type_tag.to_be_bytes());
        assert_eq!(&transcript[28..30], &version.to_be_bytes());
        assert_eq!(&transcript[30..38], &(length as u64).to_be_bytes());
        assert_eq!(&transcript[38..], &bytes[..length]);
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use activechain_canonical_codec::{
        CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    };
    use activechain_protocol_types::{
        Digest384, FreezeState, Principal, PrincipalId, PrincipalKind,
    };

    use super::{DomainTag, commit, package_id};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn vector_principal() -> Principal {
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
            42,
            43,
        )
        .expect("vector principal satisfies its invariants")
    }

    #[derive(Clone, Copy)]
    struct AlternatePrincipal(Principal);

    impl CanonicalEncode for AlternatePrincipal {
        fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
            self.0.encode(encoder)
        }
    }

    impl CanonicalDecode for AlternatePrincipal {
        fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            Ok(Self(Principal::decode(decoder)?))
        }
    }

    impl CanonicalType for AlternatePrincipal {
        const TYPE_TAG: u16 = 0x0021;
        const SCHEMA_VERSION: u16 = 1;
        const MAX_ENCODED_LEN: usize = Principal::ENCODED_LENGTH;
    }

    #[test]
    fn domain_separation_changes_the_commitment() {
        let principal = vector_principal();
        let canonical = commit(DomainTag::CANONICAL_VALUE, &principal).expect("principal encodes");
        let signing = commit(DomainTag::SIGNING_PAYLOAD, &principal).expect("principal encodes");
        assert_ne!(canonical, signing);
    }

    #[test]
    fn type_separation_changes_the_commitment_for_identical_bodies() {
        let principal = vector_principal();
        let first = commit(DomainTag::CANONICAL_VALUE, &principal).expect("principal encodes");
        let second = commit(DomainTag::CANONICAL_VALUE, &AlternatePrincipal(principal))
            .expect("alternate principal encodes");
        assert_ne!(first, second);
    }

    #[test]
    fn principal_commitment_matches_the_published_vector() {
        let actual =
            commit(DomainTag::CANONICAL_VALUE, &vector_principal()).expect("principal encodes");
        let expected = Digest384::new([
            182, 199, 121, 144, 243, 2, 35, 121, 164, 99, 147, 157, 12, 122, 68, 48, 13, 141, 87,
            95, 197, 12, 13, 246, 231, 112, 229, 94, 84, 86, 211, 181, 194, 160, 89, 99, 12, 49,
            167, 228, 236, 133, 154, 138, 212, 178, 168, 67,
        ]);
        assert_eq!(actual, expected);
    }

    #[test]
    fn package_identity_binds_the_complete_manifest() {
        use activechain_protocol_types::{PackageManifest, UpgradePolicy};
        use alloc::vec;
        let first =
            PackageManifest::new(digest(0x71), vec![0, 3], vec![], UpgradePolicy::Immutable)
                .expect("manifest is valid");
        let second =
            PackageManifest::new(digest(0x71), vec![0, 4], vec![], UpgradePolicy::Immutable)
                .expect("manifest is valid");
        assert_ne!(package_id(&first).unwrap(), package_id(&second).unwrap());
    }
}
