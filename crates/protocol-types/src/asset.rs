use alloc::vec::Vec;

use crate::{AssetId, Digest384, PrincipalId};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_ASSET_SYMBOL_LENGTH: usize = 12;
pub const MAX_FUNGIBLE_ASSETS: usize = 1024;
pub const MAX_CORPORATE_ACTIONS: usize = 4096;
pub const MAX_NFT_MINT_ITEMS: usize = 1024;
pub const MAX_NFT_TOKENS_PER_SERIES: usize = 65_535;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetDefinitionError {
    InvalidAssetIdentity,
    InvalidSymbol,
    InvalidDecimals,
    ZeroSupplyCap,
    DuplicateAsset,
    TooManyAssets,
    AssetsNotOrdered,
    InvalidLifecycleTransition,
    InvalidSupplyTransition,
    IssuerMismatch,
    SupplyCapExceeded,
    InvalidNftMetadata,
    DuplicateNftToken,
    NftOwnerMismatch,
    SeriesSupplyExceeded,
    InvalidSupplyAttestation,
}

/// Commitment-only finalized supply statement for independent wallets and RPC
/// clients. Reserve evidence stays off-chain while the exact policy context is bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FungibleSupplyAttestationV1 {
    asset_id: AssetId,
    policy_commitment: Digest384,
    issuer: PrincipalId,
    supply_issued: u128,
    finalized_height: u64,
    approval_commitment: Digest384,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FungibleIssuerRegistrationV1 {
    asset_id: AssetId,
    issuer: PrincipalId,
    authority_set: Digest384,
    policy_commitment: Digest384,
    effective_height: u64,
    expires_height: u64,
}
impl FungibleIssuerRegistrationV1 {
    pub const TYPE_TAG: u16 = 0x0135;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 4 + 8 * 2;
    pub fn new(
        asset_id: AssetId,
        issuer: PrincipalId,
        authority_set: Digest384,
        policy_commitment: Digest384,
        effective_height: u64,
        expires_height: u64,
    ) -> Result<Self, AssetDefinitionError> {
        if asset_id.digest() == &Digest384::ZERO
            || issuer.digest() == &Digest384::ZERO
            || authority_set == Digest384::ZERO
            || policy_commitment == Digest384::ZERO
            || effective_height >= expires_height
        {
            return Err(AssetDefinitionError::InvalidSupplyAttestation);
        }
        Ok(Self {
            asset_id,
            issuer,
            authority_set,
            policy_commitment,
            effective_height,
            expires_height,
        })
    }
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    pub const fn issuer(&self) -> PrincipalId {
        self.issuer
    }
    pub const fn authority_set(&self) -> Digest384 {
        self.authority_set
    }
    pub const fn policy_commitment(&self) -> Digest384 {
        self.policy_commitment
    }
    pub const fn active_at(&self, height: u64) -> bool {
        height >= self.effective_height && height < self.expires_height
    }
    pub fn binds_policy(&self, policy: &FungibleAssetPolicyV1) -> bool {
        self.asset_id == policy.asset_id()
            && self.issuer == policy.issuer()
            && self.authority_set == policy.authority_set()
            && self.policy_commitment == policy.commitment().ok().unwrap_or(Digest384::ZERO)
    }
}
impl CanonicalEncode for FungibleIssuerRegistrationV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.issuer.encode(e)?;
        self.authority_set.encode(e)?;
        self.policy_commitment.encode(e)?;
        self.effective_height.encode(e)?;
        self.expires_height.encode(e)
    }
}
impl CanonicalDecode for FungibleIssuerRegistrationV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AssetId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid issuer registration"))
    }
}
impl CanonicalType for FungibleIssuerRegistrationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}
impl FungibleSupplyAttestationV1 {
    pub const TYPE_TAG: u16 = 0x0134;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 4 + 16 + 8;
    pub fn new(
        asset_id: AssetId,
        policy_commitment: Digest384,
        issuer: PrincipalId,
        supply_issued: u128,
        finalized_height: u64,
        approval_commitment: Digest384,
    ) -> Result<Self, AssetDefinitionError> {
        if asset_id.digest() == &Digest384::ZERO
            || policy_commitment == Digest384::ZERO
            || approval_commitment == Digest384::ZERO
            || supply_issued == 0
            || finalized_height == 0
        {
            return Err(AssetDefinitionError::InvalidSupplyAttestation);
        }
        Ok(Self {
            asset_id,
            policy_commitment,
            issuer,
            supply_issued,
            finalized_height,
            approval_commitment,
        })
    }
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    pub const fn policy_commitment(&self) -> Digest384 {
        self.policy_commitment
    }
    pub const fn issuer(&self) -> PrincipalId {
        self.issuer
    }
    pub const fn supply_issued(&self) -> u128 {
        self.supply_issued
    }
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }
    pub const fn approval_commitment(&self) -> Digest384 {
        self.approval_commitment
    }
    fn binds_policy_fields(
        &self,
        policy: &FungibleAssetPolicyV1,
        policy_commitment: Digest384,
    ) -> bool {
        self.asset_id == policy.asset_id()
            && self.issuer == policy.issuer()
            && self.policy_commitment == policy_commitment
            && self.supply_issued == policy.supply_issued()
    }
    pub fn binds_policy(&self, policy: &FungibleAssetPolicyV1) -> bool {
        policy.commitment().is_ok_and(|commitment| self.binds_policy_fields(policy, commitment))
    }
}
impl CanonicalEncode for FungibleSupplyAttestationV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.policy_commitment.encode(e)?;
        self.issuer.encode(e)?;
        self.supply_issued.encode(e)?;
        self.finalized_height.encode(e)?;
        self.approval_commitment.encode(e)
    }
}
impl CanonicalDecode for FungibleSupplyAttestationV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AssetId::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid supply attestation"))
    }
}
impl CanonicalType for FungibleSupplyAttestationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Canonical native non-fungible token record. Metadata is represented only by
/// a commitment; files and mutable off-chain descriptions never enter consensus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonFungibleTokenV1 {
    asset_id: AssetId,
    token_id: Digest384,
    issuer: PrincipalId,
    owner: PrincipalId,
    metadata_commitment: Digest384,
}
impl NonFungibleTokenV1 {
    pub const TYPE_TAG: u16 = 0x011D;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 5;
    pub fn new(
        asset_id: AssetId,
        token_id: Digest384,
        issuer: PrincipalId,
        owner: PrincipalId,
        metadata_commitment: Digest384,
    ) -> Result<Self, AssetDefinitionError> {
        if asset_id.digest() == &Digest384::ZERO
            || issuer.digest() == &Digest384::ZERO
            || owner.digest() == &Digest384::ZERO
        {
            return Err(AssetDefinitionError::InvalidAssetIdentity);
        }
        if token_id == Digest384::ZERO || metadata_commitment == Digest384::ZERO {
            return Err(AssetDefinitionError::InvalidNftMetadata);
        }
        Ok(Self { asset_id, token_id, issuer, owner, metadata_commitment })
    }
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    pub const fn token_id(&self) -> Digest384 {
        self.token_id
    }
    pub const fn issuer(&self) -> PrincipalId {
        self.issuer
    }
    pub const fn owner(&self) -> PrincipalId {
        self.owner
    }
    pub const fn metadata_commitment(&self) -> Digest384 {
        self.metadata_commitment
    }
    pub fn transfer(
        &self,
        from: PrincipalId,
        to: PrincipalId,
    ) -> Result<Self, AssetDefinitionError> {
        if from != self.owner {
            return Err(AssetDefinitionError::NftOwnerMismatch);
        }
        Ok(Self { owner: to, ..*self })
    }
}
impl CanonicalEncode for NonFungibleTokenV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.token_id.encode(e)?;
        self.issuer.encode(e)?;
        self.owner.encode(e)?;
        self.metadata_commitment.encode(e)
    }
}
impl CanonicalDecode for NonFungibleTokenV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AssetId::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid non-fungible token"))
    }
}
impl CanonicalType for NonFungibleTokenV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// A bounded NFT collection with checked finalized mint accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonFungibleSeriesV1 {
    asset_id: AssetId,
    issuer: PrincipalId,
    max_supply: u64,
    minted: u64,
    metadata_schema: Digest384,
}
impl NonFungibleSeriesV1 {
    pub const TYPE_TAG: u16 = 0x011F;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 3 + 8 + 8;
    pub fn new(
        asset_id: AssetId,
        issuer: PrincipalId,
        max_supply: u64,
        minted: u64,
        metadata_schema: Digest384,
    ) -> Result<Self, AssetDefinitionError> {
        if asset_id.digest() == &Digest384::ZERO || issuer.digest() == &Digest384::ZERO {
            return Err(AssetDefinitionError::InvalidAssetIdentity);
        }
        if max_supply == 0 || minted > max_supply || metadata_schema == Digest384::ZERO {
            return Err(AssetDefinitionError::SeriesSupplyExceeded);
        }
        Ok(Self { asset_id, issuer, max_supply, minted, metadata_schema })
    }
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    pub const fn issuer(&self) -> PrincipalId {
        self.issuer
    }
    pub const fn max_supply(&self) -> u64 {
        self.max_supply
    }
    pub const fn minted(&self) -> u64 {
        self.minted
    }
    pub const fn metadata_schema(&self) -> Digest384 {
        self.metadata_schema
    }
    pub fn reserve_mint(&self, quantity: u64) -> Result<Self, AssetDefinitionError> {
        let minted =
            self.minted.checked_add(quantity).ok_or(AssetDefinitionError::SeriesSupplyExceeded)?;
        Self::new(self.asset_id, self.issuer, self.max_supply, minted, self.metadata_schema)
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-NON-FUNGIBLE-SERIES-V1");
        hasher.update(&bytes);
        let mut digest = [0_u8; 48];
        hasher.finalize_xof().read(&mut digest);
        Ok(Digest384::new(digest))
    }
    pub fn mint_approved_manifest(
        &self,
        issuer: PrincipalId,
        authority_set: Digest384,
        approval: &NonFungibleIssuerApprovalV1,
        manifest: &NonFungibleMintManifestV1,
        height: u64,
    ) -> Result<(Self, Vec<NonFungibleTokenV1>), AssetDefinitionError> {
        if issuer != self.issuer
            || !approval.binds_context(self, issuer, authority_set, manifest, height)
        {
            return Err(AssetDefinitionError::IssuerMismatch);
        }
        let next = self.reserve_mint(approval.quantity())?;
        let tokens = manifest
            .items
            .iter()
            .map(|item| {
                NonFungibleTokenV1::new(
                    self.asset_id,
                    item.token_id,
                    self.issuer,
                    item.owner,
                    item.metadata_commitment,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((next, tokens))
    }
}
impl CanonicalEncode for NonFungibleSeriesV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.issuer.encode(e)?;
        self.max_supply.encode(e)?;
        self.minted.encode(e)?;
        self.metadata_schema.encode(e)
    }
}
impl CanonicalDecode for NonFungibleSeriesV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AssetId::decode(d)?,
            PrincipalId::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid non-fungible series"))
    }
}
impl CanonicalType for NonFungibleSeriesV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonFungibleMintItemV1 {
    token_id: Digest384,
    owner: PrincipalId,
    metadata_commitment: Digest384,
}
impl NonFungibleMintItemV1 {
    pub fn new(
        token_id: Digest384,
        owner: PrincipalId,
        metadata_commitment: Digest384,
    ) -> Result<Self, AssetDefinitionError> {
        if token_id == Digest384::ZERO || metadata_commitment == Digest384::ZERO {
            return Err(AssetDefinitionError::InvalidNftMetadata);
        }
        if owner.digest() == &Digest384::ZERO {
            return Err(AssetDefinitionError::InvalidAssetIdentity);
        }
        Ok(Self { token_id, owner, metadata_commitment })
    }
}
impl CanonicalEncode for NonFungibleMintItemV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.token_id.encode(e)?;
        self.owner.encode(e)?;
        self.metadata_commitment.encode(e)
    }
}
impl CanonicalDecode for NonFungibleMintItemV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(Digest384::decode(d)?, PrincipalId::decode(d)?, Digest384::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid non-fungible mint item"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonFungibleMintManifestV1 {
    asset_id: AssetId,
    issuer: PrincipalId,
    items: Vec<NonFungibleMintItemV1>,
}
impl NonFungibleMintManifestV1 {
    pub const TYPE_TAG: u16 = 0x016C;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 2 + 3 + MAX_NFT_MINT_ITEMS * 48 * 3;
    pub fn new(
        asset_id: AssetId,
        issuer: PrincipalId,
        items: Vec<NonFungibleMintItemV1>,
    ) -> Result<Self, AssetDefinitionError> {
        if asset_id.digest() == &Digest384::ZERO || issuer.digest() == &Digest384::ZERO {
            return Err(AssetDefinitionError::InvalidAssetIdentity);
        }
        if items.is_empty()
            || items.len() > MAX_NFT_MINT_ITEMS
            || items.windows(2).any(|pair| pair[0].token_id >= pair[1].token_id)
        {
            return Err(AssetDefinitionError::InvalidSupplyTransition);
        }
        Ok(Self { asset_id, issuer, items })
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-NON-FUNGIBLE-MINT-MANIFEST-V1");
        hasher.update(&bytes);
        let mut digest = [0_u8; 48];
        hasher.finalize_xof().read(&mut digest);
        Ok(Digest384::new(digest))
    }
    pub fn item_count(&self) -> usize {
        self.items.len()
    }
}
impl CanonicalEncode for NonFungibleMintManifestV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.issuer.encode(e)?;
        e.write_length(self.items.len(), MAX_NFT_MINT_ITEMS)?;
        for item in &self.items {
            item.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for NonFungibleMintManifestV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let asset_id = AssetId::decode(d)?;
        let issuer = PrincipalId::decode(d)?;
        let count = d.read_length(MAX_NFT_MINT_ITEMS)?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(NonFungibleMintItemV1::decode(d)?);
        }
        Self::new(asset_id, issuer, items)
            .map_err(|_| DecodeError::InvalidValue("invalid non-fungible mint manifest"))
    }
}
impl CanonicalType for NonFungibleMintManifestV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Canonically ordered token identities already admitted for one NFT series.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonFungibleTokenRegistryV1 {
    asset_id: AssetId,
    token_ids: Vec<Digest384>,
}
impl NonFungibleTokenRegistryV1 {
    pub const TYPE_TAG: u16 = 0x016D;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 3 + MAX_NFT_TOKENS_PER_SERIES * 48;
    pub fn new(asset_id: AssetId, token_ids: Vec<Digest384>) -> Result<Self, AssetDefinitionError> {
        if asset_id.digest() == &Digest384::ZERO {
            return Err(AssetDefinitionError::InvalidAssetIdentity);
        }
        if token_ids.len() > MAX_NFT_TOKENS_PER_SERIES
            || token_ids.iter().any(|token| *token == Digest384::ZERO)
            || token_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(AssetDefinitionError::DuplicateNftToken);
        }
        Ok(Self { asset_id, token_ids })
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-NON-FUNGIBLE-TOKEN-REGISTRY-V1");
        hasher.update(&bytes);
        let mut digest = [0_u8; 48];
        hasher.finalize_xof().read(&mut digest);
        Ok(Digest384::new(digest))
    }
    pub fn token_count(&self) -> usize {
        self.token_ids.len()
    }
    pub fn apply_approved_mint(
        &self,
        series: &NonFungibleSeriesV1,
        issuer: PrincipalId,
        authority_set: Digest384,
        approval: &NonFungibleIssuerApprovalV1,
        manifest: &NonFungibleMintManifestV1,
        height: u64,
    ) -> Result<(NonFungibleSeriesV1, Self, Vec<NonFungibleTokenV1>), AssetDefinitionError> {
        if self.asset_id != series.asset_id()
            || usize::try_from(series.minted()).ok() != Some(self.token_ids.len())
        {
            return Err(AssetDefinitionError::InvalidSupplyTransition);
        }
        let (next_series, tokens) =
            series.mint_approved_manifest(issuer, authority_set, approval, manifest, height)?;
        let mut token_ids = Vec::with_capacity(self.token_ids.len() + manifest.items.len());
        let (mut existing, mut incoming) = (0, 0);
        while existing < self.token_ids.len() || incoming < manifest.items.len() {
            match (self.token_ids.get(existing), manifest.items.get(incoming)) {
                (Some(left), Some(right)) if left < &right.token_id => {
                    token_ids.push(*left);
                    existing += 1;
                }
                (Some(left), Some(right)) if left == &right.token_id => {
                    return Err(AssetDefinitionError::DuplicateNftToken);
                }
                (_, Some(right)) => {
                    token_ids.push(right.token_id);
                    incoming += 1;
                }
                (Some(left), None) => {
                    token_ids.push(*left);
                    existing += 1;
                }
                (None, None) => break,
            }
        }
        let next = Self::new(self.asset_id, token_ids)?;
        if usize::try_from(next_series.minted()).ok() != Some(next.token_ids.len()) {
            return Err(AssetDefinitionError::InvalidSupplyTransition);
        }
        Ok((next_series, next, tokens))
    }
}
impl CanonicalEncode for NonFungibleTokenRegistryV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        e.write_length(self.token_ids.len(), MAX_NFT_TOKENS_PER_SERIES)?;
        for token in &self.token_ids {
            token.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for NonFungibleTokenRegistryV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let asset_id = AssetId::decode(d)?;
        let count = d.read_length(MAX_NFT_TOKENS_PER_SERIES)?;
        let mut token_ids = Vec::with_capacity(count);
        for _ in 0..count {
            token_ids.push(Digest384::decode(d)?);
        }
        Self::new(asset_id, token_ids)
            .map_err(|_| DecodeError::InvalidValue("invalid non-fungible token registry"))
    }
}
impl CanonicalType for NonFungibleTokenRegistryV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Threshold approval for one exact NFT series mint reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonFungibleIssuerApprovalV1 {
    asset_id: AssetId,
    issuer: PrincipalId,
    authority_set: Digest384,
    series_commitment: Digest384,
    approval_commitment: Digest384,
    manifest_commitment: Digest384,
    quantity: u64,
    minted_before: u64,
    effective_height: u64,
    expires_height: u64,
}
impl NonFungibleIssuerApprovalV1 {
    pub const TYPE_TAG: u16 = 0x016B;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 6 + 8 * 4;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asset_id: AssetId,
        issuer: PrincipalId,
        authority_set: Digest384,
        series_commitment: Digest384,
        approval_commitment: Digest384,
        manifest_commitment: Digest384,
        quantity: u64,
        minted_before: u64,
        effective_height: u64,
        expires_height: u64,
    ) -> Result<Self, AssetDefinitionError> {
        if asset_id.digest() == &Digest384::ZERO
            || issuer.digest() == &Digest384::ZERO
            || authority_set == Digest384::ZERO
            || series_commitment == Digest384::ZERO
            || approval_commitment == Digest384::ZERO
            || manifest_commitment == Digest384::ZERO
            || quantity == 0
            || effective_height >= expires_height
        {
            return Err(AssetDefinitionError::InvalidSupplyTransition);
        }
        Ok(Self {
            asset_id,
            issuer,
            authority_set,
            series_commitment,
            approval_commitment,
            manifest_commitment,
            quantity,
            minted_before,
            effective_height,
            expires_height,
        })
    }
    pub const fn quantity(&self) -> u64 {
        self.quantity
    }
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    pub const fn issuer(&self) -> PrincipalId {
        self.issuer
    }
    pub const fn authority_set(&self) -> Digest384 {
        self.authority_set
    }
    pub const fn approval_commitment(&self) -> Digest384 {
        self.approval_commitment
    }
    pub const fn manifest_commitment(&self) -> Digest384 {
        self.manifest_commitment
    }
    pub const fn minted_before(&self) -> u64 {
        self.minted_before
    }
    pub const fn effective_height(&self) -> u64 {
        self.effective_height
    }
    pub const fn expires_height(&self) -> u64 {
        self.expires_height
    }
    pub const fn active_at(&self, height: u64) -> bool {
        height >= self.effective_height && height < self.expires_height
    }
    pub fn binds_context(
        &self,
        series: &NonFungibleSeriesV1,
        issuer: PrincipalId,
        authority_set: Digest384,
        manifest: &NonFungibleMintManifestV1,
        height: u64,
    ) -> bool {
        self.asset_id == series.asset_id()
            && self.issuer == issuer
            && self.authority_set == authority_set
            && manifest.asset_id == series.asset_id()
            && manifest.issuer == issuer
            && self.manifest_commitment == manifest.commitment().ok().unwrap_or(Digest384::ZERO)
            && self.quantity as usize == manifest.items.len()
            && self.series_commitment == series.commitment().ok().unwrap_or(Digest384::ZERO)
            && self.minted_before == series.minted()
            && self.active_at(height)
    }
}
impl CanonicalEncode for NonFungibleIssuerApprovalV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.issuer.encode(e)?;
        self.authority_set.encode(e)?;
        self.series_commitment.encode(e)?;
        self.approval_commitment.encode(e)?;
        self.manifest_commitment.encode(e)?;
        self.quantity.encode(e)?;
        self.minted_before.encode(e)?;
        self.effective_height.encode(e)?;
        self.expires_height.encode(e)
    }
}
impl CanonicalDecode for NonFungibleIssuerApprovalV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AssetId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid non-fungible issuer approval"))
    }
}
impl CanonicalType for NonFungibleIssuerApprovalV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FungibleAssetDefinition {
    asset_id: AssetId,
    issuer: PrincipalId,
    symbol: Vec<u8>,
    decimals: u8,
    supply_cap: u128,
    policy_hash: Digest384,
}

impl FungibleAssetDefinition {
    pub const TYPE_TAG: u16 = 0x0106;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 48 + 2 + MAX_ASSET_SYMBOL_LENGTH + 1 + 16 + 48;
    pub fn new(
        asset_id: AssetId,
        issuer: PrincipalId,
        symbol: Vec<u8>,
        decimals: u8,
        supply_cap: u128,
        policy_hash: Digest384,
    ) -> Result<Self, AssetDefinitionError> {
        if symbol.is_empty()
            || symbol.len() > MAX_ASSET_SYMBOL_LENGTH
            || !symbol.iter().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
        {
            return Err(AssetDefinitionError::InvalidSymbol);
        }
        if decimals > 38 {
            return Err(AssetDefinitionError::InvalidDecimals);
        }
        if supply_cap == 0 {
            return Err(AssetDefinitionError::ZeroSupplyCap);
        }
        if asset_id.digest() == &Digest384::ZERO
            || issuer.digest() == &Digest384::ZERO
            || policy_hash == Digest384::ZERO
        {
            return Err(AssetDefinitionError::InvalidAssetIdentity);
        }
        Ok(Self { asset_id, issuer, symbol, decimals, supply_cap, policy_hash })
    }
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    pub const fn issuer(&self) -> PrincipalId {
        self.issuer
    }
    pub fn symbol(&self) -> &[u8] {
        &self.symbol
    }
    pub const fn decimals(&self) -> u8 {
        self.decimals
    }
    pub const fn supply_cap(&self) -> u128 {
        self.supply_cap
    }
    pub const fn policy_hash(&self) -> Digest384 {
        self.policy_hash
    }
}
impl CanonicalEncode for FungibleAssetDefinition {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.issuer.encode(e)?;
        e.write_bytes(&self.symbol, MAX_ASSET_SYMBOL_LENGTH)?;
        self.decimals.encode(e)?;
        self.supply_cap.encode(e)?;
        self.policy_hash.encode(e)
    }
}
impl CanonicalDecode for FungibleAssetDefinition {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AssetId::decode(d)?,
            PrincipalId::decode(d)?,
            d.read_bytes(MAX_ASSET_SYMBOL_LENGTH)?.to_vec(),
            u8::decode(d)?,
            u128::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid fungible asset definition"))
    }
}
impl CanonicalType for FungibleAssetDefinition {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FungibleAssetRegistry(Vec<FungibleAssetDefinition>);
impl FungibleAssetRegistry {
    pub const TYPE_TAG: u16 = 0x0109;
    pub const SCHEMA_VERSION: u16 = 1;
    pub fn new(entries: Vec<FungibleAssetDefinition>) -> Result<Self, AssetDefinitionError> {
        if entries.len() > MAX_FUNGIBLE_ASSETS {
            return Err(AssetDefinitionError::TooManyAssets);
        }
        if entries.windows(2).any(|w| w[0].asset_id() >= w[1].asset_id()) {
            return Err(AssetDefinitionError::AssetsNotOrdered);
        }
        Ok(Self(entries))
    }
    pub fn entries(&self) -> &[FungibleAssetDefinition] {
        &self.0
    }
    pub fn find(&self, id: AssetId) -> Option<&FungibleAssetDefinition> {
        self.0.binary_search_by_key(&id, |e| e.asset_id()).ok().map(|i| &self.0[i])
    }
}
impl CanonicalEncode for FungibleAssetRegistry {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_length(self.0.len(), MAX_FUNGIBLE_ASSETS)?;
        for x in &self.0 {
            x.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for FungibleAssetRegistry {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let n = d.read_length(MAX_FUNGIBLE_ASSETS)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(FungibleAssetDefinition::decode(d)?);
        }
        Self::new(v)
            .map_err(|_| DecodeError::InvalidValue("asset registry is not strictly ordered"))
    }
}
impl CanonicalType for FungibleAssetRegistry {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize =
        2 + MAX_FUNGIBLE_ASSETS * FungibleAssetDefinition::MAX_ENCODED_LEN;
}

/// Finalized issuer policy and supply state for one registered fungible asset.
///
/// The definition above is immutable presentation metadata. This record is the mutable,
/// finalized control-plane state that binds issuance, redemption, and emergency policy without
/// putting reserve or KYC material on the public chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FungibleAssetLifecycle {
    Registered = 0,
    Paused = 1,
    Retired = 2,
}
impl CanonicalEncode for FungibleAssetLifecycle {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for FungibleAssetLifecycle {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Registered),
            1 => Ok(Self::Paused),
            2 => Ok(Self::Retired),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "FungibleAssetLifecycle", tag }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FungibleAssetPolicyV1 {
    asset_id: AssetId,
    issuer: PrincipalId,
    reserve_commitment: Digest384,
    redemption_policy: Digest384,
    jurisdiction_profile: Digest384,
    authority_set: Digest384,
    supply_cap: u128,
    supply_issued: u128,
    lifecycle: FungibleAssetLifecycle,
}
impl FungibleAssetPolicyV1 {
    pub const TYPE_TAG: u16 = 0x011B;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 6 + 16 * 2 + 1;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asset_id: AssetId,
        issuer: PrincipalId,
        reserve_commitment: Digest384,
        redemption_policy: Digest384,
        jurisdiction_profile: Digest384,
        authority_set: Digest384,
        supply_cap: u128,
        supply_issued: u128,
        lifecycle: FungibleAssetLifecycle,
    ) -> Result<Self, AssetDefinitionError> {
        if asset_id.digest() == &Digest384::ZERO
            || issuer.digest() == &Digest384::ZERO
            || authority_set == Digest384::ZERO
        {
            return Err(AssetDefinitionError::ZeroSupplyCap);
        }
        if supply_cap == 0 || supply_issued > supply_cap {
            return Err(AssetDefinitionError::ZeroSupplyCap);
        }
        Ok(Self {
            asset_id,
            issuer,
            reserve_commitment,
            redemption_policy,
            jurisdiction_profile,
            authority_set,
            supply_cap,
            supply_issued,
            lifecycle,
        })
    }
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    pub const fn issuer(&self) -> PrincipalId {
        self.issuer
    }
    pub const fn supply_cap(&self) -> u128 {
        self.supply_cap
    }
    pub const fn supply_issued(&self) -> u128 {
        self.supply_issued
    }
    pub const fn lifecycle(&self) -> FungibleAssetLifecycle {
        self.lifecycle
    }
    pub const fn authority_set(&self) -> Digest384 {
        self.authority_set
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-FUNGIBLE-ASSET-POLICY-V1");
        hasher.update(&bytes);
        let mut digest = [0_u8; 48];
        hasher.finalize_xof().read(&mut digest);
        Ok(Digest384::new(digest))
    }
    pub fn apply_lifecycle_action(
        &self,
        action: &FungibleAssetLifecycleActionV1,
        height: u64,
    ) -> Result<Self, AssetDefinitionError> {
        if !action.active_at(height)
            || action.asset_id() != self.asset_id
            || action.authority_set() != self.authority_set
            || action.expected_policy()
                != self
                    .commitment()
                    .map_err(|_| AssetDefinitionError::InvalidLifecycleTransition)?
        {
            return Err(AssetDefinitionError::InvalidLifecycleTransition);
        }
        let lifecycle = match (self.lifecycle, action.action()) {
            (FungibleAssetLifecycle::Registered, FungibleAssetLifecycleAction::Pause)
            | (FungibleAssetLifecycle::Paused, FungibleAssetLifecycleAction::Resume) => {
                if matches!(action.action(), FungibleAssetLifecycleAction::Pause) {
                    FungibleAssetLifecycle::Paused
                } else {
                    FungibleAssetLifecycle::Registered
                }
            }
            (FungibleAssetLifecycle::Registered, FungibleAssetLifecycleAction::Retire)
                if self.supply_issued == 0 =>
            {
                FungibleAssetLifecycle::Retired
            }
            _ => return Err(AssetDefinitionError::InvalidLifecycleTransition),
        };
        Ok(Self { lifecycle, ..*self })
    }

    /// Applies one issuer mint to finalized policy state. The caller must
    /// provide the exact supply pre-state observed by consensus; no optimistic
    /// or replayed issuance can advance the policy.
    pub fn apply_mint(
        &self,
        issuer: PrincipalId,
        amount: u128,
        supply_before: u128,
    ) -> Result<Self, AssetDefinitionError> {
        if issuer != self.issuer {
            return Err(AssetDefinitionError::IssuerMismatch);
        }
        if self.lifecycle != FungibleAssetLifecycle::Registered
            || amount == 0
            || supply_before != self.supply_issued
        {
            return Err(AssetDefinitionError::InvalidSupplyTransition);
        }
        let supply_issued =
            supply_before.checked_add(amount).ok_or(AssetDefinitionError::SupplyCapExceeded)?;
        if supply_issued > self.supply_cap {
            return Err(AssetDefinitionError::SupplyCapExceeded);
        }
        Ok(Self { supply_issued, ..*self })
    }

    /// Applies one finalized burn/redemption to policy supply state.
    pub fn apply_burn(
        &self,
        amount: u128,
        supply_before: u128,
    ) -> Result<Self, AssetDefinitionError> {
        if self.lifecycle != FungibleAssetLifecycle::Registered
            || amount == 0
            || supply_before != self.supply_issued
            || amount > supply_before
        {
            return Err(AssetDefinitionError::InvalidSupplyTransition);
        }
        Ok(Self { supply_issued: supply_before - amount, ..*self })
    }

    /// Applies a mint only when a threshold approval binds this exact policy,
    /// authority set, amount, pre-state, operation, and finalized height.
    pub fn apply_approved_mint(
        &self,
        issuer: PrincipalId,
        approval: &FungibleIssuerApprovalV1,
        height: u64,
    ) -> Result<Self, AssetDefinitionError> {
        if issuer != self.issuer
            || !approval.binds_context(
                self,
                FungibleIssuerOperation::Mint,
                approval.amount(),
                self.supply_issued,
                height,
            )
        {
            return Err(AssetDefinitionError::InvalidSupplyTransition);
        }
        self.apply_mint(issuer, approval.amount(), approval.supply_before())
    }

    /// Applies a burn or redemption only when its approval binds the exact
    /// finalized policy context.
    pub fn apply_approved_burn(
        &self,
        approval: &FungibleIssuerApprovalV1,
        operation: FungibleIssuerOperation,
        height: u64,
    ) -> Result<Self, AssetDefinitionError> {
        if !matches!(operation, FungibleIssuerOperation::Burn | FungibleIssuerOperation::Redemption)
            || !approval.binds_context(
                self,
                operation,
                approval.amount(),
                self.supply_issued,
                height,
            )
        {
            return Err(AssetDefinitionError::InvalidSupplyTransition);
        }
        self.apply_burn(approval.amount(), approval.supply_before())
    }
}
impl CanonicalEncode for FungibleAssetPolicyV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.issuer.encode(e)?;
        self.reserve_commitment.encode(e)?;
        self.redemption_policy.encode(e)?;
        self.jurisdiction_profile.encode(e)?;
        self.authority_set.encode(e)?;
        self.supply_cap.encode(e)?;
        self.supply_issued.encode(e)?;
        self.lifecycle.encode(e)
    }
}
impl CanonicalDecode for FungibleAssetPolicyV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AssetId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            FungibleAssetLifecycle::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid fungible asset policy"))
    }
}
impl CanonicalType for FungibleAssetPolicyV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Replay-safe controller revision tracked alongside one mutable asset policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FungibleControllerStateV1 {
    asset_id: AssetId,
    issuer: PrincipalId,
    policy_commitment: Digest384,
    authority_set: Digest384,
    revision: u64,
}
impl FungibleControllerStateV1 {
    pub const TYPE_TAG: u16 = 0x016E;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 4 + 8;
    pub fn from_policy(
        policy: &FungibleAssetPolicyV1,
        revision: u64,
    ) -> Result<Self, AssetDefinitionError> {
        Ok(Self {
            asset_id: policy.asset_id,
            issuer: policy.issuer,
            policy_commitment: policy
                .commitment()
                .map_err(|_| AssetDefinitionError::InvalidSupplyTransition)?,
            authority_set: policy.authority_set,
            revision,
        })
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-FUNGIBLE-CONTROLLER-STATE-V1");
        hasher.update(&bytes);
        let mut digest = [0_u8; 48];
        hasher.finalize_xof().read(&mut digest);
        Ok(Digest384::new(digest))
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub fn apply_rotation(
        &self,
        policy: &FungibleAssetPolicyV1,
        rotation: &FungibleControllerRotationV1,
        height: u64,
    ) -> Result<(FungibleAssetPolicyV1, Self), AssetDefinitionError> {
        if self.asset_id != policy.asset_id
            || self.issuer != policy.issuer
            || self.authority_set != policy.authority_set
            || self.policy_commitment
                != policy.commitment().map_err(|_| AssetDefinitionError::InvalidSupplyTransition)?
            || rotation.asset_id != self.asset_id
            || rotation.issuer != self.issuer
            || rotation.controller_state_commitment
                != self.commitment().map_err(|_| AssetDefinitionError::InvalidSupplyTransition)?
            || rotation.current_authority_set != self.authority_set
            || rotation.expected_revision != self.revision
            || !rotation.active_at(height)
        {
            return Err(AssetDefinitionError::InvalidSupplyTransition);
        }
        let revision =
            self.revision.checked_add(1).ok_or(AssetDefinitionError::InvalidSupplyTransition)?;
        let next_policy =
            FungibleAssetPolicyV1 { authority_set: rotation.replacement_authority_set, ..*policy };
        let next_state = Self::from_policy(&next_policy, revision)?;
        Ok((next_policy, next_state))
    }
}
impl CanonicalEncode for FungibleControllerStateV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.issuer.encode(e)?;
        self.policy_commitment.encode(e)?;
        self.authority_set.encode(e)?;
        self.revision.encode(e)
    }
}
impl CanonicalDecode for FungibleControllerStateV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            asset_id: AssetId::decode(d)?,
            issuer: PrincipalId::decode(d)?,
            policy_commitment: Digest384::decode(d)?,
            authority_set: Digest384::decode(d)?,
            revision: u64::decode(d)?,
        };
        if value.asset_id.digest() == &Digest384::ZERO
            || value.issuer.digest() == &Digest384::ZERO
            || value.policy_commitment == Digest384::ZERO
            || value.authority_set == Digest384::ZERO
        {
            return Err(DecodeError::InvalidValue("invalid fungible controller state"));
        }
        Ok(value)
    }
}
impl CanonicalType for FungibleControllerStateV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FungibleControllerRotationV1 {
    asset_id: AssetId,
    issuer: PrincipalId,
    controller_state_commitment: Digest384,
    current_authority_set: Digest384,
    replacement_authority_set: Digest384,
    approval_commitment: Digest384,
    expected_revision: u64,
    effective_height: u64,
    expires_height: u64,
}
impl FungibleControllerRotationV1 {
    pub const TYPE_TAG: u16 = 0x016F;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 6 + 8 * 3;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asset_id: AssetId,
        issuer: PrincipalId,
        controller_state_commitment: Digest384,
        current_authority_set: Digest384,
        replacement_authority_set: Digest384,
        approval_commitment: Digest384,
        expected_revision: u64,
        effective_height: u64,
        expires_height: u64,
    ) -> Result<Self, AssetDefinitionError> {
        if asset_id.digest() == &Digest384::ZERO
            || issuer.digest() == &Digest384::ZERO
            || controller_state_commitment == Digest384::ZERO
            || current_authority_set == Digest384::ZERO
            || replacement_authority_set == Digest384::ZERO
            || current_authority_set == replacement_authority_set
            || approval_commitment == Digest384::ZERO
            || effective_height >= expires_height
        {
            return Err(AssetDefinitionError::InvalidSupplyTransition);
        }
        Ok(Self {
            asset_id,
            issuer,
            controller_state_commitment,
            current_authority_set,
            replacement_authority_set,
            approval_commitment,
            expected_revision,
            effective_height,
            expires_height,
        })
    }
    pub const fn active_at(&self, height: u64) -> bool {
        height >= self.effective_height && height < self.expires_height
    }
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    pub const fn issuer(&self) -> PrincipalId {
        self.issuer
    }
    pub const fn current_authority_set(&self) -> Digest384 {
        self.current_authority_set
    }
    pub const fn replacement_authority_set(&self) -> Digest384 {
        self.replacement_authority_set
    }
    pub const fn approval_commitment(&self) -> Digest384 {
        self.approval_commitment
    }
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
    pub const fn effective_height(&self) -> u64 {
        self.effective_height
    }
    pub const fn expires_height(&self) -> u64 {
        self.expires_height
    }
}
impl CanonicalEncode for FungibleControllerRotationV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.issuer.encode(e)?;
        self.controller_state_commitment.encode(e)?;
        self.current_authority_set.encode(e)?;
        self.replacement_authority_set.encode(e)?;
        self.approval_commitment.encode(e)?;
        self.expected_revision.encode(e)?;
        self.effective_height.encode(e)?;
        self.expires_height.encode(e)
    }
}
impl CanonicalDecode for FungibleControllerRotationV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AssetId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid fungible controller rotation"))
    }
}
impl CanonicalType for FungibleControllerRotationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Deterministically ordered finalized policy registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FungibleAssetPolicyRegistry(Vec<FungibleAssetPolicyV1>);
impl FungibleAssetPolicyRegistry {
    pub const TYPE_TAG: u16 = 0x011E;
    pub const SCHEMA_VERSION: u16 = 1;
    pub fn new(entries: Vec<FungibleAssetPolicyV1>) -> Result<Self, AssetDefinitionError> {
        if entries.len() > MAX_FUNGIBLE_ASSETS {
            return Err(AssetDefinitionError::TooManyAssets);
        }
        if entries.windows(2).any(|w| w[0].asset_id() >= w[1].asset_id()) {
            return Err(AssetDefinitionError::AssetsNotOrdered);
        }
        Ok(Self(entries))
    }
    pub fn entries(&self) -> &[FungibleAssetPolicyV1] {
        &self.0
    }
    pub fn find(&self, id: AssetId) -> Option<&FungibleAssetPolicyV1> {
        self.0.binary_search_by_key(&id, |entry| entry.asset_id()).ok().map(|i| &self.0[i])
    }
    pub fn apply_action(
        &self,
        action: &FungibleAssetLifecycleActionV1,
        height: u64,
    ) -> Result<Self, AssetDefinitionError> {
        let index = self
            .0
            .binary_search_by_key(&action.asset_id(), |entry| entry.asset_id())
            .map_err(|_| AssetDefinitionError::DuplicateAsset)?;
        let mut entries = self.0.clone();
        entries[index] = entries[index].apply_lifecycle_action(action, height)?;
        Self::new(entries)
    }
}
impl CanonicalEncode for FungibleAssetPolicyRegistry {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_length(self.0.len(), MAX_FUNGIBLE_ASSETS)?;
        for entry in &self.0 {
            entry.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for FungibleAssetPolicyRegistry {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = d.read_length(MAX_FUNGIBLE_ASSETS)?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(FungibleAssetPolicyV1::decode(d)?);
        }
        Self::new(entries).map_err(|_| DecodeError::InvalidValue("policy registry is not ordered"))
    }
}
impl CanonicalType for FungibleAssetPolicyRegistry {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = 2 + MAX_FUNGIBLE_ASSETS * FungibleAssetPolicyV1::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FungibleAssetLifecycleAction {
    Pause = 0,
    Resume = 1,
    Retire = 2,
}
impl CanonicalEncode for FungibleAssetLifecycleAction {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for FungibleAssetLifecycleAction {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Pause),
            1 => Ok(Self::Resume),
            2 => Ok(Self::Retire),
            tag => {
                Err(DecodeError::InvalidEnumTag { type_name: "FungibleAssetLifecycleAction", tag })
            }
        }
    }
}

/// Authority-controlled lifecycle action for one finalized fungible asset policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FungibleAssetLifecycleActionV1 {
    asset_id: AssetId,
    expected_policy: Digest384,
    authority_set: Digest384,
    approval_commitment: Digest384,
    reason_commitment: Digest384,
    action: FungibleAssetLifecycleAction,
    effective_height: u64,
    expires_height: u64,
}
impl FungibleAssetLifecycleActionV1 {
    pub const TYPE_TAG: u16 = 0x0120;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 5 + 1 + 8 + 8;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asset_id: AssetId,
        expected_policy: Digest384,
        authority_set: Digest384,
        approval_commitment: Digest384,
        reason_commitment: Digest384,
        action: FungibleAssetLifecycleAction,
        effective_height: u64,
        expires_height: u64,
    ) -> Result<Self, AssetDefinitionError> {
        if asset_id.digest() == &Digest384::ZERO
            || expected_policy == Digest384::ZERO
            || authority_set == Digest384::ZERO
            || approval_commitment == Digest384::ZERO
            || reason_commitment == Digest384::ZERO
            || effective_height >= expires_height
        {
            return Err(AssetDefinitionError::InvalidDecimals);
        }
        Ok(Self {
            asset_id,
            expected_policy,
            authority_set,
            approval_commitment,
            reason_commitment,
            action,
            effective_height,
            expires_height,
        })
    }
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    pub const fn action(&self) -> FungibleAssetLifecycleAction {
        self.action
    }
    pub const fn expected_policy(&self) -> Digest384 {
        self.expected_policy
    }
    pub const fn authority_set(&self) -> Digest384 {
        self.authority_set
    }
    pub const fn effective_height(&self) -> u64 {
        self.effective_height
    }
    pub const fn expires_height(&self) -> u64 {
        self.expires_height
    }
    pub const fn active_at(&self, height: u64) -> bool {
        height >= self.effective_height && height < self.expires_height
    }
    pub fn binds_context(
        &self,
        asset_id: AssetId,
        expected_policy: Digest384,
        authority_set: Digest384,
    ) -> bool {
        self.asset_id == asset_id
            && self.expected_policy == expected_policy
            && self.authority_set == authority_set
    }
}
impl CanonicalEncode for FungibleAssetLifecycleActionV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.expected_policy.encode(e)?;
        self.authority_set.encode(e)?;
        self.approval_commitment.encode(e)?;
        self.reason_commitment.encode(e)?;
        self.action.encode(e)?;
        self.effective_height.encode(e)?;
        self.expires_height.encode(e)
    }
}
impl CanonicalDecode for FungibleAssetLifecycleActionV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AssetId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            FungibleAssetLifecycleAction::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid asset lifecycle action"))
    }
}
impl CanonicalType for FungibleAssetLifecycleActionV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Native corporate actions share one canonical envelope so wallets and
/// validators never infer economics from an issuer-controlled display label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FungibleCorporateActionKind {
    Distribution = 0,
    Split = 1,
    Consolidation = 2,
    Coupon = 3,
    Maturity = 4,
    RecordDateVote = 5,
    RedemptionOffer = 6,
}
impl CanonicalEncode for FungibleCorporateActionKind {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for FungibleCorporateActionKind {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Distribution),
            1 => Ok(Self::Split),
            2 => Ok(Self::Consolidation),
            3 => Ok(Self::Coupon),
            4 => Ok(Self::Maturity),
            5 => Ok(Self::RecordDateVote),
            6 => Ok(Self::RedemptionOffer),
            tag => {
                Err(DecodeError::InvalidEnumTag { type_name: "FungibleCorporateActionKind", tag })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FungibleCorporateActionV1 {
    asset_id: AssetId,
    issuer: PrincipalId,
    policy_commitment: Digest384,
    authority_set: Digest384,
    approval_commitment: Digest384,
    terms_commitment: Digest384,
    kind: FungibleCorporateActionKind,
    record_height: u64,
    effective_height: u64,
    expires_height: u64,
    amount_per_unit: u128,
    ratio_numerator: u128,
    ratio_denominator: u128,
}
impl FungibleCorporateActionV1 {
    pub const TYPE_TAG: u16 = 0x0159;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 6 + 1 + 8 * 3 + 16 * 3;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asset_id: AssetId,
        issuer: PrincipalId,
        policy_commitment: Digest384,
        authority_set: Digest384,
        approval_commitment: Digest384,
        terms_commitment: Digest384,
        kind: FungibleCorporateActionKind,
        record_height: u64,
        effective_height: u64,
        expires_height: u64,
        amount_per_unit: u128,
        ratio_numerator: u128,
        ratio_denominator: u128,
    ) -> Result<Self, AssetDefinitionError> {
        let identity_bound = asset_id.digest() != &Digest384::ZERO
            && issuer.digest() != &Digest384::ZERO
            && policy_commitment != Digest384::ZERO
            && authority_set != Digest384::ZERO
            && approval_commitment != Digest384::ZERO
            && terms_commitment != Digest384::ZERO;
        let window_bound = record_height > 0
            && record_height <= effective_height
            && effective_height < expires_height;
        let economics_bound = match kind {
            FungibleCorporateActionKind::Split | FungibleCorporateActionKind::Consolidation => {
                amount_per_unit == 0 && ratio_numerator > 0 && ratio_denominator > 0
            }
            FungibleCorporateActionKind::Distribution
            | FungibleCorporateActionKind::Coupon
            | FungibleCorporateActionKind::RedemptionOffer => {
                amount_per_unit > 0 && ratio_numerator == 1 && ratio_denominator == 1
            }
            FungibleCorporateActionKind::Maturity | FungibleCorporateActionKind::RecordDateVote => {
                amount_per_unit == 0 && ratio_numerator == 1 && ratio_denominator == 1
            }
        };
        if !identity_bound || !window_bound || !economics_bound {
            return Err(AssetDefinitionError::InvalidLifecycleTransition);
        }
        Ok(Self {
            asset_id,
            issuer,
            policy_commitment,
            authority_set,
            approval_commitment,
            terms_commitment,
            kind,
            record_height,
            effective_height,
            expires_height,
            amount_per_unit,
            ratio_numerator,
            ratio_denominator,
        })
    }

    pub const fn asset_id(self) -> AssetId {
        self.asset_id
    }
    pub const fn issuer(self) -> PrincipalId {
        self.issuer
    }
    pub const fn kind(self) -> FungibleCorporateActionKind {
        self.kind
    }
    pub const fn policy_commitment(self) -> Digest384 {
        self.policy_commitment
    }
    pub const fn authority_set(self) -> Digest384 {
        self.authority_set
    }
    pub const fn approval_commitment(self) -> Digest384 {
        self.approval_commitment
    }
    pub const fn terms_commitment(self) -> Digest384 {
        self.terms_commitment
    }
    pub const fn record_height(self) -> u64 {
        self.record_height
    }
    pub const fn effective_height(self) -> u64 {
        self.effective_height
    }
    pub const fn expires_height(self) -> u64 {
        self.expires_height
    }
    pub const fn amount_per_unit(self) -> u128 {
        self.amount_per_unit
    }
    pub const fn ratio_numerator(self) -> u128 {
        self.ratio_numerator
    }
    pub const fn ratio_denominator(self) -> u128 {
        self.ratio_denominator
    }
    pub const fn active_at(self, height: u64) -> bool {
        height >= self.effective_height && height < self.expires_height
    }
    fn binds_admission(
        self,
        asset_id: AssetId,
        policy_commitment: Digest384,
        authority_set: Digest384,
        finalized_height: u64,
    ) -> bool {
        self.asset_id == asset_id
            && self.policy_commitment == policy_commitment
            && self.authority_set == authority_set
            && self.active_at(finalized_height)
    }
    pub fn action_id(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-FUNGIBLE-CORPORATE-ACTION-V1");
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
        let mut output = [0_u8; 48];
        hasher.finalize_xof().read(&mut output);
        Ok(Digest384::new(output))
    }
}
impl CanonicalEncode for FungibleCorporateActionV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.issuer.encode(e)?;
        self.policy_commitment.encode(e)?;
        self.authority_set.encode(e)?;
        self.approval_commitment.encode(e)?;
        self.terms_commitment.encode(e)?;
        self.kind.encode(e)?;
        self.record_height.encode(e)?;
        self.effective_height.encode(e)?;
        self.expires_height.encode(e)?;
        self.amount_per_unit.encode(e)?;
        self.ratio_numerator.encode(e)?;
        self.ratio_denominator.encode(e)
    }
}
impl CanonicalDecode for FungibleCorporateActionV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AssetId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            FungibleCorporateActionKind::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid fungible corporate action"))
    }
}
impl CanonicalType for FungibleCorporateActionV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Durable exact-once replay barrier for finalized corporate actions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FungibleCorporateActionRegistryV1(Vec<Digest384>);
impl FungibleCorporateActionRegistryV1 {
    pub const TYPE_TAG: u16 = 0x015B;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 2 + MAX_CORPORATE_ACTIONS * 48;

    pub fn new(action_ids: Vec<Digest384>) -> Result<Self, AssetDefinitionError> {
        if action_ids.len() > MAX_CORPORATE_ACTIONS
            || action_ids.iter().any(|id| *id == Digest384::ZERO)
            || action_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(AssetDefinitionError::InvalidLifecycleTransition);
        }
        Ok(Self(action_ids))
    }
    pub fn action_ids(&self) -> &[Digest384] {
        &self.0
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-FUNGIBLE-CORPORATE-ACTION-REGISTRY-V1");
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
        let mut output = [0_u8; 48];
        hasher.finalize_xof().read(&mut output);
        Ok(Digest384::new(output))
    }
    pub fn admit(
        &mut self,
        action: &FungibleCorporateActionV1,
        asset_id: AssetId,
        policy_commitment: Digest384,
        authority_set: Digest384,
        finalized_height: u64,
    ) -> Result<Digest384, AssetDefinitionError> {
        if !action.binds_admission(asset_id, policy_commitment, authority_set, finalized_height) {
            return Err(AssetDefinitionError::InvalidLifecycleTransition);
        }
        let action_id =
            action.action_id().map_err(|_| AssetDefinitionError::InvalidLifecycleTransition)?;
        match self.0.binary_search(&action_id) {
            Ok(_) => Err(AssetDefinitionError::InvalidLifecycleTransition),
            Err(_) if self.0.len() == MAX_CORPORATE_ACTIONS => {
                Err(AssetDefinitionError::TooManyAssets)
            }
            Err(index) => {
                self.0.insert(index, action_id);
                Ok(action_id)
            }
        }
    }
}
impl CanonicalEncode for FungibleCorporateActionRegistryV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_length(self.0.len(), MAX_CORPORATE_ACTIONS)?;
        for id in &self.0 {
            id.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for FungibleCorporateActionRegistryV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let length = d.read_length(MAX_CORPORATE_ACTIONS)?;
        let mut ids = Vec::with_capacity(length);
        for _ in 0..length {
            ids.push(Digest384::decode(d)?);
        }
        Self::new(ids).map_err(|_| DecodeError::InvalidValue("invalid corporate action registry"))
    }
}
impl CanonicalType for FungibleCorporateActionRegistryV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FungibleIssuerOperation {
    Mint = 0,
    Burn = 1,
    Redemption = 2,
}
impl CanonicalEncode for FungibleIssuerOperation {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for FungibleIssuerOperation {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Mint),
            1 => Ok(Self::Burn),
            2 => Ok(Self::Redemption),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "FungibleIssuerOperation", tag }),
        }
    }
}

/// Threshold approval commitment for one issuer-controlled supply operation.
/// Approval contents and signer identities remain off-chain; this envelope
/// binds their commitment to the exact finalized execution context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FungibleIssuerApprovalV1 {
    asset_id: AssetId,
    policy_commitment: Digest384,
    authority_set: Digest384,
    approval_commitment: Digest384,
    operation: FungibleIssuerOperation,
    amount: u128,
    supply_before: u128,
    effective_height: u64,
    expires_height: u64,
}
impl FungibleIssuerApprovalV1 {
    pub const TYPE_TAG: u16 = 0x0121;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 4 + 1 + 16 * 2 + 8 * 2;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asset_id: AssetId,
        policy_commitment: Digest384,
        authority_set: Digest384,
        approval_commitment: Digest384,
        operation: FungibleIssuerOperation,
        amount: u128,
        supply_before: u128,
        effective_height: u64,
        expires_height: u64,
    ) -> Result<Self, AssetDefinitionError> {
        if asset_id.digest() == &Digest384::ZERO
            || policy_commitment == Digest384::ZERO
            || authority_set == Digest384::ZERO
            || approval_commitment == Digest384::ZERO
            || amount == 0
            || effective_height >= expires_height
        {
            return Err(AssetDefinitionError::InvalidSupplyTransition);
        }
        Ok(Self {
            asset_id,
            policy_commitment,
            authority_set,
            approval_commitment,
            operation,
            amount,
            supply_before,
            effective_height,
            expires_height,
        })
    }
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    pub const fn policy_commitment(&self) -> Digest384 {
        self.policy_commitment
    }
    pub const fn authority_set(&self) -> Digest384 {
        self.authority_set
    }
    pub const fn operation(&self) -> FungibleIssuerOperation {
        self.operation
    }
    pub const fn approval_commitment(&self) -> Digest384 {
        self.approval_commitment
    }
    pub const fn amount(&self) -> u128 {
        self.amount
    }
    pub const fn supply_before(&self) -> u128 {
        self.supply_before
    }
    pub const fn effective_height(&self) -> u64 {
        self.effective_height
    }
    pub const fn expires_height(&self) -> u64 {
        self.expires_height
    }
    pub const fn active_at(&self, height: u64) -> bool {
        height >= self.effective_height && height < self.expires_height
    }
    pub fn binds_context(
        &self,
        policy: &FungibleAssetPolicyV1,
        operation: FungibleIssuerOperation,
        amount: u128,
        supply_before: u128,
        height: u64,
    ) -> bool {
        self.asset_id == policy.asset_id()
            && self.policy_commitment == policy.commitment().ok().unwrap_or(Digest384::ZERO)
            && self.authority_set == policy.authority_set()
            && self.operation == operation
            && self.amount == amount
            && self.supply_before == supply_before
            && self.active_at(height)
    }
}
impl CanonicalEncode for FungibleIssuerApprovalV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.asset_id.encode(e)?;
        self.policy_commitment.encode(e)?;
        self.authority_set.encode(e)?;
        self.approval_commitment.encode(e)?;
        self.operation.encode(e)?;
        self.amount.encode(e)?;
        self.supply_before.encode(e)?;
        self.effective_height.encode(e)?;
        self.expires_height.encode(e)
    }
}
impl CanonicalDecode for FungibleIssuerApprovalV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            AssetId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            FungibleIssuerOperation::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid fungible issuer approval"))
    }
}
impl CanonicalType for FungibleIssuerApprovalV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn policy(supply: u128, cap: u128) -> FungibleAssetPolicyV1 {
        FungibleAssetPolicyV1::new(
            AssetId::new(Digest384::new([1; 48])),
            PrincipalId::new(Digest384::new([2; 48])),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            cap,
            supply,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap()
    }

    #[kani::proof]
    fn mint_transition_preserves_exact_pre_state_and_cap() {
        let cap: u128 = kani::any();
        let supply: u128 = kani::any();
        let amount: u128 = kani::any();
        kani::assume(cap > 0);
        kani::assume(supply <= cap);
        let current = policy(supply, cap);
        if let Ok(next) = current.apply_mint(current.issuer(), amount, supply) {
            assert_eq!(next.supply_issued(), supply + amount);
            assert!(next.supply_issued() <= cap);
        }
    }

    #[kani::proof]
    fn burn_transition_never_underflows_or_changes_other_policy_fields() {
        let supply: u128 = kani::any();
        let amount: u128 = kani::any();
        let current = policy(supply, u128::MAX);
        if let Ok(next) = current.apply_burn(amount, supply) {
            assert_eq!(next.supply_issued(), supply - amount);
            assert_eq!(next.asset_id(), current.asset_id());
            assert_eq!(next.authority_set(), current.authority_set());
        }
    }

    #[kani::proof]
    fn supply_attestation_preserves_policy_identity_and_supply() {
        let supply: u128 = kani::any();
        let cap: u128 = kani::any();
        kani::assume(cap > 0);
        kani::assume(supply > 0 && supply <= cap);
        let current = policy(supply, cap);
        let policy_commitment = Digest384::new([8; 48]);
        let attestation = FungibleSupplyAttestationV1::new(
            current.asset_id(),
            policy_commitment,
            current.issuer(),
            supply,
            1,
            Digest384::new([7; 48]),
        )
        .unwrap();
        assert!(attestation.binds_policy_fields(&current, policy_commitment));
        assert!(!attestation.binds_policy_fields(&current, Digest384::new([9; 48])));
        assert_eq!(attestation.supply_issued(), current.supply_issued());
        assert_eq!(attestation.asset_id(), current.asset_id());
    }

    #[kani::proof]
    fn corporate_action_admission_is_exact_and_half_open() {
        let height: u64 = kani::any();
        let substitute_asset: bool = kani::any();
        let substitute_policy: bool = kani::any();
        let substitute_authority: bool = kani::any();
        let action = FungibleCorporateActionV1::new(
            AssetId::new(Digest384::new([1; 48])),
            PrincipalId::new(Digest384::new([2; 48])),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            FungibleCorporateActionKind::Distribution,
            1,
            10,
            20,
            1,
            1,
            1,
        )
        .unwrap();
        let asset = if substitute_asset {
            AssetId::new(Digest384::new([7; 48]))
        } else {
            action.asset_id()
        };
        let policy =
            if substitute_policy { Digest384::new([8; 48]) } else { action.policy_commitment() };
        let authority =
            if substitute_authority { Digest384::new([9; 48]) } else { action.authority_set() };
        assert_eq!(
            action.binds_admission(asset, policy, authority, height),
            !substitute_asset
                && !substitute_policy
                && !substitute_authority
                && height >= 10
                && height < 20
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::vec;
    fn id(n: u8) -> AssetId {
        AssetId::new(Digest384::new([n; 48]))
    }
    fn principal(n: u8) -> PrincipalId {
        PrincipalId::new(Digest384::new([n; 48]))
    }
    fn asset(n: u8) -> FungibleAssetDefinition {
        FungibleAssetDefinition::new(
            id(n),
            principal(n),
            b"TEST".to_vec(),
            6,
            1_000_000,
            Digest384::new([9; 48]),
        )
        .unwrap()
    }

    #[test]
    fn definitions_round_trip_and_registry_lookup_is_ordered() {
        let registry = FungibleAssetRegistry::new(vec![asset(1), asset(2)]).unwrap();
        let bytes = encode_envelope(&registry).unwrap();
        assert_eq!(decode_envelope::<FungibleAssetRegistry>(&bytes), Ok(registry.clone()));
        assert_eq!(registry.find(id(2)).unwrap().issuer(), principal(2));
    }

    #[test]
    fn nft_round_trip_and_transfer_is_owner_bound() {
        let token = NonFungibleTokenV1::new(
            id(1),
            Digest384::new([2; 48]),
            principal(3),
            principal(4),
            Digest384::new([5; 48]),
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<NonFungibleTokenV1>(&encode_envelope(&token).unwrap()),
            Ok(token)
        );
        assert_eq!(
            token.transfer(principal(3), principal(6)),
            Err(AssetDefinitionError::NftOwnerMismatch)
        );
        assert_eq!(token.transfer(principal(4), principal(6)).unwrap().owner(), principal(6));
        assert!(
            NonFungibleTokenV1::new(
                id(1),
                Digest384::ZERO,
                principal(3),
                principal(4),
                Digest384::new([5; 48])
            )
            .is_err()
        );
        assert_eq!(
            NonFungibleTokenV1::new(
                AssetId::new(Digest384::ZERO),
                Digest384::new([2; 48]),
                principal(3),
                principal(4),
                Digest384::new([5; 48]),
            ),
            Err(AssetDefinitionError::InvalidAssetIdentity)
        );
    }

    #[test]
    fn nft_series_mint_reservation_is_supply_conserving() {
        let series =
            NonFungibleSeriesV1::new(id(1), principal(2), 3, 1, Digest384::new([6; 48])).unwrap();
        assert_eq!(
            decode_envelope::<NonFungibleSeriesV1>(&encode_envelope(&series).unwrap()),
            Ok(series)
        );
        assert_eq!(series.reserve_mint(2).unwrap().minted(), 3);
        assert_eq!(series.reserve_mint(3), Err(AssetDefinitionError::SeriesSupplyExceeded));
        assert!(
            NonFungibleSeriesV1::new(id(1), principal(2), 0, 0, Digest384::new([6; 48])).is_err()
        );
        assert_eq!(
            NonFungibleSeriesV1::new(
                AssetId::new(Digest384::ZERO),
                principal(2),
                1,
                0,
                Digest384::new([6; 48]),
            ),
            Err(AssetDefinitionError::InvalidAssetIdentity)
        );
    }

    #[test]
    fn nft_series_mint_requires_exact_canonical_approval() {
        let issuer = principal(2);
        let authority_set = Digest384::new([7; 48]);
        let series =
            NonFungibleSeriesV1::new(id(1), issuer, 5, 1, Digest384::new([6; 48])).unwrap();
        let manifest = NonFungibleMintManifestV1::new(
            series.asset_id(),
            issuer,
            vec![
                NonFungibleMintItemV1::new(
                    Digest384::new([10; 48]),
                    principal(3),
                    Digest384::new([20; 48]),
                )
                .unwrap(),
                NonFungibleMintItemV1::new(
                    Digest384::new([11; 48]),
                    principal(4),
                    Digest384::new([21; 48]),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let approval = NonFungibleIssuerApprovalV1::new(
            series.asset_id(),
            issuer,
            authority_set,
            series.commitment().unwrap(),
            Digest384::new([8; 48]),
            manifest.commitment().unwrap(),
            2,
            series.minted(),
            10,
            20,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<NonFungibleIssuerApprovalV1>(&encode_envelope(&approval).unwrap()),
            Ok(approval)
        );
        assert_eq!(
            decode_envelope::<NonFungibleMintManifestV1>(&encode_envelope(&manifest).unwrap()),
            Ok(manifest.clone())
        );
        let (next, tokens) =
            series.mint_approved_manifest(issuer, authority_set, &approval, &manifest, 10).unwrap();
        assert_eq!(next.minted(), 3);
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].owner(), principal(3));
        let registry =
            NonFungibleTokenRegistryV1::new(series.asset_id(), vec![Digest384::new([9; 48])])
                .unwrap();
        let (registered_series, registry, registered_tokens) = registry
            .apply_approved_mint(&series, issuer, authority_set, &approval, &manifest, 10)
            .unwrap();
        assert_eq!(registered_series, next);
        assert_eq!(registered_tokens, tokens);
        assert_eq!(registry.token_ids.len(), 3);
        assert_eq!(
            decode_envelope::<NonFungibleTokenRegistryV1>(&encode_envelope(&registry).unwrap()),
            Ok(registry.clone())
        );
        assert_eq!(
            next.mint_approved_manifest(issuer, authority_set, &approval, &manifest, 11),
            Err(AssetDefinitionError::IssuerMismatch)
        );
        assert_eq!(
            series.mint_approved_manifest(principal(9), authority_set, &approval, &manifest, 11),
            Err(AssetDefinitionError::IssuerMismatch)
        );
        assert_eq!(
            series.mint_approved_manifest(
                issuer,
                Digest384::new([9; 48]),
                &approval,
                &manifest,
                11,
            ),
            Err(AssetDefinitionError::IssuerMismatch)
        );
        assert_eq!(
            series.mint_approved_manifest(issuer, authority_set, &approval, &manifest, 20),
            Err(AssetDefinitionError::IssuerMismatch)
        );
        let substituted = NonFungibleMintManifestV1::new(
            series.asset_id(),
            issuer,
            vec![
                NonFungibleMintItemV1::new(
                    Digest384::new([10; 48]),
                    principal(9),
                    Digest384::new([20; 48]),
                )
                .unwrap(),
                manifest.items[1],
            ],
        )
        .unwrap();
        assert_eq!(
            series.mint_approved_manifest(issuer, authority_set, &approval, &substituted, 11),
            Err(AssetDefinitionError::IssuerMismatch)
        );
        let replay_manifest = NonFungibleMintManifestV1::new(
            series.asset_id(),
            issuer,
            vec![
                manifest.items[1],
                NonFungibleMintItemV1::new(
                    Digest384::new([12; 48]),
                    principal(5),
                    Digest384::new([22; 48]),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let replay_approval = NonFungibleIssuerApprovalV1::new(
            next.asset_id(),
            issuer,
            authority_set,
            next.commitment().unwrap(),
            Digest384::new([9; 48]),
            replay_manifest.commitment().unwrap(),
            2,
            next.minted(),
            11,
            20,
        )
        .unwrap();
        assert_eq!(
            registry.apply_approved_mint(
                &next,
                issuer,
                authority_set,
                &replay_approval,
                &replay_manifest,
                11,
            ),
            Err(AssetDefinitionError::DuplicateNftToken)
        );
        let inconsistent = NonFungibleTokenRegistryV1::new(series.asset_id(), vec![]).unwrap();
        assert_eq!(
            inconsistent.apply_approved_mint(
                &series,
                issuer,
                authority_set,
                &approval,
                &manifest,
                10,
            ),
            Err(AssetDefinitionError::InvalidSupplyTransition)
        );
    }

    #[test]
    fn nft_approval_rejects_unbound_or_empty_context() {
        let issuer = principal(2);
        let build = |authority_set, series_commitment, approval_commitment, quantity| {
            NonFungibleIssuerApprovalV1::new(
                id(1),
                issuer,
                authority_set,
                series_commitment,
                approval_commitment,
                Digest384::new([6; 48]),
                quantity,
                0,
                10,
                20,
            )
        };
        assert!(
            build(Digest384::ZERO, Digest384::new([4; 48]), Digest384::new([5; 48]), 1).is_err()
        );
        assert!(
            build(Digest384::new([3; 48]), Digest384::ZERO, Digest384::new([5; 48]), 1).is_err()
        );
        assert!(
            build(Digest384::new([3; 48]), Digest384::new([4; 48]), Digest384::ZERO, 1).is_err()
        );
        assert!(
            build(Digest384::new([3; 48]), Digest384::new([4; 48]), Digest384::new([5; 48]), 0)
                .is_err()
        );
        assert!(
            NonFungibleIssuerApprovalV1::new(
                id(1),
                issuer,
                Digest384::new([3; 48]),
                Digest384::new([4; 48]),
                Digest384::new([5; 48]),
                Digest384::ZERO,
                1,
                0,
                10,
                20,
            )
            .is_err()
        );
        let duplicate = NonFungibleMintItemV1::new(
            Digest384::new([9; 48]),
            principal(3),
            Digest384::new([8; 48]),
        )
        .unwrap();
        assert_eq!(
            NonFungibleMintManifestV1::new(id(1), issuer, vec![duplicate, duplicate]),
            Err(AssetDefinitionError::InvalidSupplyTransition)
        );
    }

    #[test]
    fn supply_attestation_binds_policy_and_rejects_malformed_values() {
        let policy = FungibleAssetPolicyV1::new(
            id(1),
            principal(2),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            100,
            1,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap();
        let attestation = FungibleSupplyAttestationV1::new(
            policy.asset_id(),
            policy.commitment().unwrap(),
            policy.issuer(),
            policy.supply_issued(),
            9,
            Digest384::new([8; 48]),
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<FungibleSupplyAttestationV1>(&encode_envelope(&attestation).unwrap()),
            Ok(attestation)
        );
        assert!(attestation.binds_policy(&policy));
        assert!(
            FungibleSupplyAttestationV1::new(
                policy.asset_id(),
                Digest384::ZERO,
                policy.issuer(),
                1,
                1,
                Digest384::new([8; 48])
            )
            .is_err()
        );
    }

    #[test]
    fn issuer_registration_is_bounded_and_half_open() {
        let registration = FungibleIssuerRegistrationV1::new(
            id(1),
            principal(2),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            10,
            20,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<FungibleIssuerRegistrationV1>(
                &encode_envelope(&registration).unwrap()
            ),
            Ok(registration)
        );
        assert!(registration.active_at(10));
        assert!(!registration.active_at(20));
        assert!(
            FungibleIssuerRegistrationV1::new(
                id(1),
                principal(2),
                Digest384::ZERO,
                Digest384::new([4; 48]),
                10,
                20
            )
            .is_err()
        );
        let policy = FungibleAssetPolicyV1::new(
            id(1),
            principal(2),
            Digest384::new([7; 48]),
            Digest384::new([8; 48]),
            Digest384::new([9; 48]),
            Digest384::new([3; 48]),
            100,
            1,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap();
        let bound = FungibleIssuerRegistrationV1::new(
            id(1),
            principal(2),
            policy.authority_set(),
            policy.commitment().unwrap(),
            10,
            20,
        )
        .unwrap();
        assert!(bound.binds_policy(&policy));
    }

    #[test]
    fn malformed_symbols_and_duplicate_or_unsorted_assets_fail_closed() {
        assert_eq!(
            FungibleAssetDefinition::new(
                id(1),
                principal(1),
                b"eur/usd".to_vec(),
                6,
                1,
                Digest384::ZERO
            ),
            Err(AssetDefinitionError::InvalidSymbol)
        );
        assert_eq!(
            FungibleAssetRegistry::new(vec![asset(2), asset(1)]),
            Err(AssetDefinitionError::AssetsNotOrdered)
        );
        assert_eq!(
            FungibleAssetRegistry::new(vec![asset(1), asset(1)]),
            Err(AssetDefinitionError::AssetsNotOrdered)
        );
        assert_eq!(
            FungibleAssetDefinition::new(
                AssetId::new(Digest384::ZERO),
                principal(1),
                b"TEST".to_vec(),
                6,
                1,
                Digest384::new([9; 48]),
            ),
            Err(AssetDefinitionError::InvalidAssetIdentity)
        );
        assert_eq!(
            FungibleAssetDefinition::new(
                id(1),
                principal(1),
                b"TEST".to_vec(),
                6,
                1,
                Digest384::ZERO,
            ),
            Err(AssetDefinitionError::InvalidAssetIdentity)
        );
    }

    #[test]
    fn issuer_policy_binds_supply_and_lifecycle() {
        let policy = FungibleAssetPolicyV1::new(
            id(1),
            principal(2),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            1_000,
            400,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap();
        let bytes = encode_envelope(&policy).unwrap();
        assert_eq!(decode_envelope::<FungibleAssetPolicyV1>(&bytes), Ok(policy));
        assert_eq!(policy.supply_issued(), 400);
        assert_eq!(policy.lifecycle(), FungibleAssetLifecycle::Registered);
        assert!(
            FungibleAssetPolicyV1::new(
                id(1),
                principal(2),
                Digest384::ZERO,
                Digest384::ZERO,
                Digest384::ZERO,
                Digest384::ZERO,
                10,
                11,
                FungibleAssetLifecycle::Registered,
            )
            .is_err()
        );
        let expected_policy = policy.commitment().unwrap();
        let action = FungibleAssetLifecycleActionV1::new(
            id(1),
            expected_policy,
            Digest384::new([6; 48]),
            Digest384::new([5; 48]),
            Digest384::new([4; 48]),
            FungibleAssetLifecycleAction::Pause,
            10,
            20,
        )
        .unwrap();
        let paused = policy.apply_lifecycle_action(&action, 10).unwrap();
        assert_eq!(paused.lifecycle(), FungibleAssetLifecycle::Paused);
        assert!(policy.apply_lifecycle_action(&action, 20).is_err());

        let minted = policy.apply_mint(principal(2), 100, 400).unwrap();
        assert_eq!(minted.supply_issued(), 500);
        assert_eq!(
            policy.apply_mint(principal(3), 100, 400),
            Err(AssetDefinitionError::IssuerMismatch)
        );
        assert_eq!(
            policy.apply_mint(principal(2), 100, 399),
            Err(AssetDefinitionError::InvalidSupplyTransition)
        );
        assert_eq!(
            policy.apply_mint(principal(2), 700, 400),
            Err(AssetDefinitionError::SupplyCapExceeded)
        );
        let burned = minted.apply_burn(125, 500).unwrap();
        assert_eq!(burned.supply_issued(), 375);
        assert_eq!(minted.apply_burn(501, 500), Err(AssetDefinitionError::InvalidSupplyTransition));
        assert_eq!(minted.apply_burn(1, 499), Err(AssetDefinitionError::InvalidSupplyTransition));
        let approval = FungibleIssuerApprovalV1::new(
            id(1),
            policy.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([7; 48]),
            FungibleIssuerOperation::Mint,
            100,
            400,
            10,
            20,
        )
        .unwrap();
        assert!(approval.binds_context(&policy, FungibleIssuerOperation::Mint, 100, 400, 10));
        assert!(!approval.binds_context(&policy, FungibleIssuerOperation::Burn, 100, 400, 10));
        assert_eq!(
            decode_envelope::<FungibleIssuerApprovalV1>(&encode_envelope(&approval).unwrap()),
            Ok(approval)
        );
        let zero_policy = FungibleAssetPolicyV1::new(
            id(1),
            principal(2),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            1_000,
            0,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap();
        let retire = FungibleAssetLifecycleActionV1::new(
            id(1),
            zero_policy.commitment().unwrap(),
            Digest384::new([6; 48]),
            Digest384::new([5; 48]),
            Digest384::new([4; 48]),
            FungibleAssetLifecycleAction::Retire,
            10,
            20,
        )
        .unwrap();
        assert_eq!(
            zero_policy.apply_lifecycle_action(&retire, 10).unwrap().lifecycle(),
            FungibleAssetLifecycle::Retired
        );
    }

    #[test]
    fn policy_registry_is_ordered_and_lookup_is_deterministic() {
        let make = |n| {
            FungibleAssetPolicyV1::new(
                id(n),
                principal(n),
                Digest384::new([3; 48]),
                Digest384::new([4; 48]),
                Digest384::new([5; 48]),
                Digest384::new([6; 48]),
                1_000,
                0,
                FungibleAssetLifecycle::Registered,
            )
            .unwrap()
        };
        let registry = FungibleAssetPolicyRegistry::new(vec![make(1), make(2)]).unwrap();
        let bytes = encode_envelope(&registry).unwrap();
        assert_eq!(decode_envelope::<FungibleAssetPolicyRegistry>(&bytes), Ok(registry.clone()));
        assert_eq!(registry.find(id(2)).unwrap().asset_id(), id(2));
        assert_eq!(
            FungibleAssetPolicyRegistry::new(vec![make(2), make(1)]),
            Err(AssetDefinitionError::AssetsNotOrdered)
        );
        let policy = make(1);
        let action = FungibleAssetLifecycleActionV1::new(
            id(1),
            policy.commitment().unwrap(),
            Digest384::new([6; 48]),
            Digest384::new([5; 48]),
            Digest384::new([4; 48]),
            FungibleAssetLifecycleAction::Pause,
            10,
            20,
        )
        .unwrap();
        let updated = registry.apply_action(&action, 10).unwrap();
        assert_eq!(updated.find(id(1)).unwrap().lifecycle(), FungibleAssetLifecycle::Paused);
        let wrong_policy = FungibleAssetLifecycleActionV1::new(
            id(1),
            Digest384::new([99; 48]),
            Digest384::new([6; 48]),
            Digest384::new([5; 48]),
            Digest384::new([4; 48]),
            FungibleAssetLifecycleAction::Pause,
            10,
            20,
        )
        .unwrap();
        assert_eq!(
            registry.apply_action(&wrong_policy, 10),
            Err(AssetDefinitionError::InvalidLifecycleTransition)
        );
    }

    #[test]
    fn controller_rotation_is_exact_revision_bound_and_replay_safe() {
        let policy = FungibleAssetPolicyV1::new(
            id(1),
            principal(2),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            1_000,
            100,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap();
        let state = FungibleControllerStateV1::from_policy(&policy, 7).unwrap();
        let rotation = FungibleControllerRotationV1::new(
            policy.asset_id(),
            policy.issuer(),
            state.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([8; 48]),
            Digest384::new([9; 48]),
            state.revision(),
            10,
            20,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<FungibleControllerStateV1>(&encode_envelope(&state).unwrap()),
            Ok(state)
        );
        assert_eq!(
            decode_envelope::<FungibleControllerRotationV1>(&encode_envelope(&rotation).unwrap()),
            Ok(rotation)
        );
        let (next_policy, next_state) = state.apply_rotation(&policy, &rotation, 10).unwrap();
        assert_eq!(next_policy.authority_set(), Digest384::new([8; 48]));
        assert_eq!(next_state.revision(), 8);
        assert_eq!(
            next_state.apply_rotation(&next_policy, &rotation, 11),
            Err(AssetDefinitionError::InvalidSupplyTransition)
        );
        assert_eq!(
            state.apply_rotation(&policy, &rotation, 20),
            Err(AssetDefinitionError::InvalidSupplyTransition)
        );
        let changed_policy = FungibleAssetPolicyV1 { supply_issued: 101, ..policy };
        assert_eq!(
            state.apply_rotation(&changed_policy, &rotation, 11),
            Err(AssetDefinitionError::InvalidSupplyTransition)
        );
        assert!(
            FungibleControllerRotationV1::new(
                policy.asset_id(),
                policy.issuer(),
                state.commitment().unwrap(),
                policy.authority_set(),
                policy.authority_set(),
                Digest384::new([9; 48]),
                state.revision(),
                10,
                20,
            )
            .is_err()
        );
    }

    #[test]
    fn lifecycle_action_is_bounded_and_time_scoped() {
        let action = FungibleAssetLifecycleActionV1::new(
            id(1),
            Digest384::new([2; 48]),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            FungibleAssetLifecycleAction::Pause,
            10,
            20,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<FungibleAssetLifecycleActionV1>(&encode_envelope(&action).unwrap()),
            Ok(action)
        );
        assert!(action.active_at(10));
        assert!(!action.active_at(20));
        assert!(action.binds_context(id(1), Digest384::new([2; 48]), Digest384::new([3; 48])));
        assert!(!action.binds_context(id(2), Digest384::new([2; 48]), Digest384::new([3; 48])));
        assert!(
            FungibleAssetLifecycleActionV1::new(
                id(1),
                Digest384::new([2; 48]),
                Digest384::new([3; 48]),
                Digest384::new([4; 48]),
                Digest384::new([5; 48]),
                FungibleAssetLifecycleAction::Retire,
                20,
                20,
            )
            .is_err()
        );
    }

    #[test]
    fn approved_supply_transition_binds_policy_and_height() {
        let policy = FungibleAssetPolicyV1::new(
            id(1),
            PrincipalId::new(Digest384::new([9; 48])),
            Digest384::new([2; 48]),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            100,
            10,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap();
        let approval = FungibleIssuerApprovalV1::new(
            id(1),
            policy.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([6; 48]),
            FungibleIssuerOperation::Mint,
            5,
            10,
            20,
            30,
        )
        .unwrap();
        let issuer = policy.issuer();
        assert_eq!(policy.apply_approved_mint(issuer, &approval, 20).unwrap().supply_issued(), 15);
        assert_eq!(
            policy.apply_approved_mint(issuer, &approval, 30),
            Err(AssetDefinitionError::InvalidSupplyTransition)
        );
        let wrong = FungibleIssuerApprovalV1::new(
            id(2),
            policy.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([7; 48]),
            FungibleIssuerOperation::Mint,
            5,
            10,
            20,
            30,
        )
        .unwrap();
        assert!(policy.apply_approved_mint(issuer, &wrong, 20).is_err());
        let wrong_authority = FungibleIssuerApprovalV1::new(
            id(1),
            policy.commitment().unwrap(),
            Digest384::new([99; 48]),
            Digest384::new([9; 48]),
            FungibleIssuerOperation::Mint,
            5,
            10,
            20,
            30,
        )
        .unwrap();
        assert!(policy.apply_approved_mint(issuer, &wrong_authority, 20).is_err());

        let burn = FungibleIssuerApprovalV1::new(
            id(1),
            policy.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([8; 48]),
            FungibleIssuerOperation::Redemption,
            3,
            10,
            20,
            30,
        )
        .unwrap();
        assert_eq!(
            policy.apply_approved_burn(&burn, FungibleIssuerOperation::Redemption, 20),
            Ok(FungibleAssetPolicyV1 { supply_issued: 7, ..policy })
        );
        assert!(policy.apply_approved_burn(&burn, FungibleIssuerOperation::Mint, 20).is_err());
        let wrong_burn_authority = FungibleIssuerApprovalV1::new(
            id(1),
            policy.commitment().unwrap(),
            Digest384::new([101; 48]),
            Digest384::new([10; 48]),
            FungibleIssuerOperation::Redemption,
            3,
            10,
            20,
            30,
        )
        .unwrap();
        assert!(
            policy
                .apply_approved_burn(&wrong_burn_authority, FungibleIssuerOperation::Redemption, 20)
                .is_err()
        );
    }

    #[test]
    fn corporate_actions_round_trip_and_bind_exact_economics() {
        let split = FungibleCorporateActionV1::new(
            id(1),
            PrincipalId::new(Digest384::new([2; 48])),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            FungibleCorporateActionKind::Split,
            10,
            20,
            30,
            0,
            2,
            1,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<FungibleCorporateActionV1>(&encode_envelope(&split).unwrap()),
            Ok(split)
        );
        assert_ne!(split.action_id().unwrap(), Digest384::ZERO);

        let invalid_split = FungibleCorporateActionV1::new(
            id(1),
            PrincipalId::new(Digest384::new([2; 48])),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            FungibleCorporateActionKind::Split,
            10,
            20,
            30,
            1,
            2,
            1,
        );
        assert!(invalid_split.is_err());

        let invalid_window = FungibleCorporateActionV1::new(
            id(1),
            PrincipalId::new(Digest384::new([2; 48])),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            FungibleCorporateActionKind::Distribution,
            20,
            10,
            30,
            1,
            1,
            1,
        );
        assert!(invalid_window.is_err());
    }

    #[test]
    fn corporate_action_registry_is_exact_once_policy_bound_and_canonical() {
        let action = FungibleCorporateActionV1::new(
            id(1),
            PrincipalId::new(Digest384::new([2; 48])),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            Digest384::new([6; 48]),
            FungibleCorporateActionKind::Coupon,
            10,
            20,
            30,
            25,
            1,
            1,
        )
        .unwrap();
        let mut registry = FungibleCorporateActionRegistryV1::default();
        let action_id = registry
            .admit(&action, id(1), Digest384::new([3; 48]), Digest384::new([4; 48]), 20)
            .unwrap();
        assert_eq!(registry.action_ids(), &[action_id]);
        assert!(
            registry
                .admit(&action, id(1), Digest384::new([3; 48]), Digest384::new([4; 48]), 20)
                .is_err()
        );
        assert!(
            FungibleCorporateActionRegistryV1::default()
                .admit(&action, id(1), Digest384::new([99; 48]), Digest384::new([4; 48]), 20)
                .is_err()
        );
        assert!(
            FungibleCorporateActionRegistryV1::default()
                .admit(&action, id(1), Digest384::new([3; 48]), Digest384::new([4; 48]), 30)
                .is_err()
        );
        assert_eq!(
            decode_envelope::<FungibleCorporateActionRegistryV1>(
                &encode_envelope(&registry).unwrap()
            ),
            Ok(registry)
        );
    }
}
