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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetDefinitionError {
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
    pub const TYPE_TAG: u16 = 0x00B0;
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
        if asset_id.digest() == &Digest384::ZERO || issuer.digest() == &Digest384::ZERO {
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

/// Deterministically ordered finalized policy registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FungibleAssetPolicyRegistry(Vec<FungibleAssetPolicyV1>);
impl FungibleAssetPolicyRegistry {
    pub const TYPE_TAG: u16 = 0x00B1;
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
    pub const TYPE_TAG: u16 = 0x00B2;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 5 + 1 + 8 + 8;
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
    pub const TYPE_TAG: u16 = 0x00B3;
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
    pub const fn amount(&self) -> u128 {
        self.amount
    }
    pub const fn supply_before(&self) -> u128 {
        self.supply_before
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
}
