use alloc::vec::Vec;

use crate::{AssetId, Digest384, PrincipalId};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};

pub const MAX_ASSET_SYMBOL_LENGTH: usize = 12;
pub const MAX_FUNGIBLE_ASSETS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetDefinitionError {
    InvalidSymbol,
    InvalidDecimals,
    ZeroSupplyCap,
    DuplicateAsset,
    TooManyAssets,
    AssetsNotOrdered,
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
    pub const TYPE_TAG: u16 = 0x00A0;
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
    pub const TYPE_TAG: u16 = 0x00A1;
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
    }
}
