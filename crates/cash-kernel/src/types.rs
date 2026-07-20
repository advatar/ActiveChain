use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{
    Amount, ChainId, CoinCellId, Digest384, Epoch, Height, PrincipalId, TransactionId,
};

/// Maximum number of native cells in the first bounded reference ledger.
pub const MAX_COIN_CELLS: usize = 4_096;
/// Maximum number of inputs in one fixed-semantics transfer or burn.
pub const MAX_TRANSFER_INPUTS: usize = 16;
/// Maximum native symbol length in canonical UTF-8 bytes.
pub const MAX_SYMBOL_LENGTH: usize = 12;
/// Maximum genesis allocation entries in the bounded genesis manifest.
pub const MAX_GENESIS_ALLOCATIONS: usize = 4_096;

/// Immutable native-asset monetary constitution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAssetDefinition {
    chain_id: ChainId,
    symbol: Vec<u8>,
    decimals: u8,
    genesis_supply: Amount,
    maximum_ordinary_annual_issuance_bps: u16,
    issuance_policy_hash: Digest384,
    burn_policy_hash: Digest384,
    reward_policy_hash: Digest384,
}

impl NativeAssetDefinition {
    pub const TYPE_TAG: u16 = 0x0080;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 2 + MAX_SYMBOL_LENGTH + 1 + 16 + 2 + 48 * 3;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        symbol: Vec<u8>,
        decimals: u8,
        genesis_supply: Amount,
        maximum_ordinary_annual_issuance_bps: u16,
        issuance_policy_hash: Digest384,
        burn_policy_hash: Digest384,
        reward_policy_hash: Digest384,
    ) -> Result<Self, NativeMoneyError> {
        if symbol.is_empty() || symbol.len() > MAX_SYMBOL_LENGTH {
            return Err(NativeMoneyError::InvalidSymbol);
        }
        if !symbol
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
        {
            return Err(NativeMoneyError::InvalidSymbol);
        }
        if decimals > 38 {
            return Err(NativeMoneyError::InvalidDecimals);
        }
        if genesis_supply == 0 {
            return Err(NativeMoneyError::ZeroGenesisSupply);
        }
        Ok(Self {
            chain_id,
            symbol,
            decimals,
            genesis_supply,
            maximum_ordinary_annual_issuance_bps,
            issuance_policy_hash,
            burn_policy_hash,
            reward_policy_hash,
        })
    }

    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    #[must_use]
    pub fn symbol(&self) -> &[u8] {
        &self.symbol
    }
    #[must_use]
    pub const fn decimals(&self) -> u8 {
        self.decimals
    }
    #[must_use]
    pub const fn genesis_supply(&self) -> Amount {
        self.genesis_supply
    }
    #[must_use]
    pub const fn maximum_ordinary_annual_issuance_bps(&self) -> u16 {
        self.maximum_ordinary_annual_issuance_bps
    }
    #[must_use]
    pub const fn issuance_policy_hash(&self) -> Digest384 {
        self.issuance_policy_hash
    }
    #[must_use]
    pub const fn burn_policy_hash(&self) -> Digest384 {
        self.burn_policy_hash
    }
    #[must_use]
    pub const fn reward_policy_hash(&self) -> Digest384 {
        self.reward_policy_hash
    }
}

impl CanonicalEncode for NativeAssetDefinition {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(encoder)?;
        encoder.write_bytes(&self.symbol, MAX_SYMBOL_LENGTH)?;
        self.decimals.encode(encoder)?;
        self.genesis_supply.encode(encoder)?;
        self.maximum_ordinary_annual_issuance_bps.encode(encoder)?;
        self.issuance_policy_hash.encode(encoder)?;
        self.burn_policy_hash.encode(encoder)?;
        self.reward_policy_hash.encode(encoder)
    }
}

impl CanonicalDecode for NativeAssetDefinition {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(decoder)?,
            decoder.read_bytes(MAX_SYMBOL_LENGTH)?.to_vec(),
            u8::decode(decoder)?,
            u128::decode(decoder)?,
            u16::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid native asset definition"))
    }
}
impl CanonicalType for NativeAssetDefinition {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// One deterministic genesis allocation. Locked value is represented by a
/// vesting allocation in the economy manifest, not an immediately spendable cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenesisAllocation {
    recipient: PrincipalId,
    liquid_amount: Amount,
    locked_amount: Amount,
}
impl GenesisAllocation {
    pub const MAX_ENCODED_LEN: usize = 48 + 16 + 16;
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        recipient: PrincipalId,
        liquid_amount: Amount,
        locked_amount: Amount,
    ) -> Result<Self, NativeMoneyError> {
        if liquid_amount.checked_add(locked_amount).is_none() {
            return Err(NativeMoneyError::AmountOverflow);
        }
        if liquid_amount == 0 && locked_amount == 0 {
            return Err(NativeMoneyError::ZeroAllocation);
        }
        Ok(Self { recipient, liquid_amount, locked_amount })
    }
    #[must_use]
    pub const fn recipient(self) -> PrincipalId {
        self.recipient
    }
    #[must_use]
    pub const fn liquid_amount(self) -> Amount {
        self.liquid_amount
    }
    #[must_use]
    pub const fn locked_amount(self) -> Amount {
        self.locked_amount
    }
    #[must_use]
    pub fn total(self) -> Amount {
        self.liquid_amount + self.locked_amount
    }
}
impl CanonicalEncode for GenesisAllocation {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.recipient.encode(e)?;
        self.liquid_amount.encode(e)?;
        self.locked_amount.encode(e)
    }
}
impl CanonicalDecode for GenesisAllocation {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(PrincipalId::decode(d)?, u128::decode(d)?, u128::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid genesis allocation"))
    }
}

/// Reproducible one-time genesis economy manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisEconomy {
    definition: NativeAssetDefinition,
    allocations: Vec<GenesisAllocation>,
    security_reserve: Amount,
}
impl GenesisEconomy {
    pub const TYPE_TAG: u16 = 0x0081;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = NativeAssetDefinition::MAX_ENCODED_LEN
        + 2
        + MAX_GENESIS_ALLOCATIONS * GenesisAllocation::MAX_ENCODED_LEN
        + 16;
    pub fn new(
        definition: NativeAssetDefinition,
        allocations: Vec<GenesisAllocation>,
        security_reserve: Amount,
    ) -> Result<Self, NativeMoneyError> {
        if allocations.is_empty() || allocations.len() > MAX_GENESIS_ALLOCATIONS {
            return Err(NativeMoneyError::InvalidGenesisAllocations);
        }
        if allocations.windows(2).any(|pair| pair[0].recipient() >= pair[1].recipient()) {
            return Err(NativeMoneyError::GenesisAllocationsNotOrdered);
        }
        let mut total = security_reserve;
        for allocation in &allocations {
            total =
                total.checked_add(allocation.total()).ok_or(NativeMoneyError::AmountOverflow)?;
        }
        if total != definition.genesis_supply() {
            return Err(NativeMoneyError::GenesisSupplyMismatch);
        }
        Ok(Self { definition, allocations, security_reserve })
    }
    #[must_use]
    pub const fn definition(&self) -> &NativeAssetDefinition {
        &self.definition
    }
    #[must_use]
    pub fn allocations(&self) -> &[GenesisAllocation] {
        &self.allocations
    }
    #[must_use]
    pub const fn security_reserve(&self) -> Amount {
        self.security_reserve
    }
}
impl CanonicalEncode for GenesisEconomy {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.definition.encode(e)?;
        e.write_length(self.allocations.len(), MAX_GENESIS_ALLOCATIONS)?;
        for a in &self.allocations {
            a.encode(e)?;
        }
        self.security_reserve.encode(e)
    }
}
impl CanonicalDecode for GenesisEconomy {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let definition = NativeAssetDefinition::decode(d)?;
        let n = d.read_length(MAX_GENESIS_ALLOCATIONS)?;
        let mut allocations = Vec::with_capacity(n);
        for _ in 0..n {
            allocations.push(GenesisAllocation::decode(d)?);
        }
        Self::new(definition, allocations, u128::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid genesis economy"))
    }
}
impl CanonicalType for GenesisEconomy {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Canonical origin of an output cell.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CoinCellOrigin {
    transition_id: TransactionId,
    output_index: u16,
}
impl CoinCellOrigin {
    pub const MAX_ENCODED_LEN: usize = 50;
    pub const fn new(transition_id: TransactionId, output_index: u16) -> Self {
        Self { transition_id, output_index }
    }
    #[must_use]
    pub const fn transition_id(self) -> TransactionId {
        self.transition_id
    }
    #[must_use]
    pub const fn output_index(self) -> u16 {
        self.output_index
    }
}
impl CanonicalEncode for CoinCellOrigin {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.transition_id.encode(e)?;
        self.output_index.encode(e)
    }
}
impl CanonicalDecode for CoinCellOrigin {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(TransactionId::decode(d)?, u16::decode(d)?))
    }
}
impl CanonicalType for CoinCellOrigin {
    const TYPE_TAG: u16 = 0x0082;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// An unspent native Coin Cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoinCell {
    origin: CoinCellOrigin,
    owner: PrincipalId,
    amount: Amount,
    creation_height: Height,
}
impl CoinCell {
    pub const TYPE_TAG: u16 = 0x0083;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 50 + 48 + 16 + 8;
    pub fn new(
        origin: CoinCellOrigin,
        owner: PrincipalId,
        amount: Amount,
        creation_height: Height,
    ) -> Result<Self, NativeMoneyError> {
        if amount == 0 {
            return Err(NativeMoneyError::ZeroAmount);
        }
        Ok(Self { origin, owner, amount, creation_height })
    }
    #[must_use]
    pub const fn origin(self) -> CoinCellOrigin {
        self.origin
    }
    #[must_use]
    pub const fn owner(self) -> PrincipalId {
        self.owner
    }
    #[must_use]
    pub const fn amount(self) -> Amount {
        self.amount
    }
    #[must_use]
    pub const fn creation_height(self) -> Height {
        self.creation_height
    }
}
impl CanonicalEncode for CoinCell {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.origin.encode(e)?;
        self.owner.encode(e)?;
        self.amount.encode(e)?;
        self.creation_height.encode(e)
    }
}
impl CanonicalDecode for CoinCell {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            CoinCellOrigin::decode(d)?,
            PrincipalId::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("coin cell amount is zero"))
    }
}
impl CanonicalType for CoinCell {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Canonical bounded native supply state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeSupply {
    genesis_supply: Amount,
    cumulative_security_issuance: Amount,
    cumulative_burn: Amount,
    current_total_supply: Amount,
    circulating_supply: Amount,
    locked_vesting_supply: Amount,
    staked_supply: Amount,
    security_reserve_balance: Amount,
    last_settled_epoch: Epoch,
}
impl NativeSupply {
    pub const TYPE_TAG: u16 = 0x0084;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 16 * 8 + 8;
    pub fn genesis(
        genesis_supply: Amount,
        security_reserve: Amount,
        locked_vesting_supply: Amount,
    ) -> Result<Self, NativeMoneyError> {
        let reserved = security_reserve
            .checked_add(locked_vesting_supply)
            .ok_or(NativeMoneyError::AmountOverflow)?;
        if reserved > genesis_supply {
            return Err(NativeMoneyError::InvalidReserve);
        }
        let circulating = genesis_supply - reserved;
        Ok(Self {
            genesis_supply,
            cumulative_security_issuance: 0,
            cumulative_burn: 0,
            current_total_supply: genesis_supply,
            circulating_supply: circulating,
            locked_vesting_supply,
            staked_supply: 0,
            security_reserve_balance: security_reserve,
            last_settled_epoch: 0,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis_supply: Amount,
        cumulative_security_issuance: Amount,
        cumulative_burn: Amount,
        current_total_supply: Amount,
        circulating_supply: Amount,
        locked_vesting_supply: Amount,
        staked_supply: Amount,
        security_reserve_balance: Amount,
        last_settled_epoch: Epoch,
    ) -> Result<Self, NativeMoneyError> {
        let expected = genesis_supply
            .checked_add(cumulative_security_issuance)
            .and_then(|v| v.checked_sub(cumulative_burn))
            .ok_or(NativeMoneyError::AmountOverflow)?;
        if expected != current_total_supply {
            return Err(NativeMoneyError::SupplyEquationMismatch);
        }
        let locked = locked_vesting_supply
            .checked_add(staked_supply)
            .ok_or(NativeMoneyError::AmountOverflow)?;
        let partition = circulating_supply
            .checked_add(locked)
            .and_then(|v| v.checked_add(security_reserve_balance));
        if locked > current_total_supply
            || partition != Some(current_total_supply)
            || security_reserve_balance > current_total_supply
        {
            return Err(NativeMoneyError::SupplyPartitionMismatch);
        }
        Ok(Self {
            genesis_supply,
            cumulative_security_issuance,
            cumulative_burn,
            current_total_supply,
            circulating_supply,
            locked_vesting_supply,
            staked_supply,
            security_reserve_balance,
            last_settled_epoch,
        })
    }
    #[must_use]
    pub const fn genesis_supply(self) -> Amount {
        self.genesis_supply
    }
    #[must_use]
    pub const fn cumulative_security_issuance(self) -> Amount {
        self.cumulative_security_issuance
    }
    #[must_use]
    pub const fn cumulative_burn(self) -> Amount {
        self.cumulative_burn
    }
    #[must_use]
    pub const fn current_total_supply(self) -> Amount {
        self.current_total_supply
    }
    #[must_use]
    pub const fn circulating_supply(self) -> Amount {
        self.circulating_supply
    }
    #[must_use]
    pub const fn locked_vesting_supply(self) -> Amount {
        self.locked_vesting_supply
    }
    #[must_use]
    pub const fn staked_supply(self) -> Amount {
        self.staked_supply
    }
    #[must_use]
    pub const fn security_reserve_balance(self) -> Amount {
        self.security_reserve_balance
    }
    #[must_use]
    pub const fn last_settled_epoch(self) -> Epoch {
        self.last_settled_epoch
    }
}
impl CanonicalEncode for NativeSupply {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.genesis_supply.encode(e)?;
        self.cumulative_security_issuance.encode(e)?;
        self.cumulative_burn.encode(e)?;
        self.current_total_supply.encode(e)?;
        self.circulating_supply.encode(e)?;
        self.locked_vesting_supply.encode(e)?;
        self.staked_supply.encode(e)?;
        self.security_reserve_balance.encode(e)?;
        self.last_settled_epoch.encode(e)
    }
}
impl CanonicalDecode for NativeSupply {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid native supply state"))
    }
}
impl CanonicalType for NativeSupply {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// A strictly ordered native cell record used by the bounded reference ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoinCellRecord {
    id: CoinCellId,
    cell: CoinCell,
}
impl CoinCellRecord {
    pub const MAX_ENCODED_LEN: usize = 48 + CoinCell::MAX_ENCODED_LEN;
    pub const fn new(id: CoinCellId, cell: CoinCell) -> Self {
        Self { id, cell }
    }
    #[must_use]
    pub const fn id(self) -> CoinCellId {
        self.id
    }
    #[must_use]
    pub const fn cell(self) -> CoinCell {
        self.cell
    }
}
impl CanonicalEncode for CoinCellRecord {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.id.encode(e)?;
        self.cell.encode(e)
    }
}
impl CanonicalDecode for CoinCellRecord {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(CoinCellId::decode(d)?, CoinCell::decode(d)?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinCellSet(Vec<CoinCellRecord>);
impl CoinCellSet {
    pub const TYPE_TAG: u16 = 0x0085;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 2 + MAX_COIN_CELLS * CoinCellRecord::MAX_ENCODED_LEN;
    pub fn new(cells: Vec<CoinCellRecord>) -> Result<Self, NativeMoneyError> {
        if cells.len() > MAX_COIN_CELLS {
            return Err(NativeMoneyError::TooManyCells);
        }
        if cells.windows(2).any(|p| p[0].id() >= p[1].id()) {
            return Err(NativeMoneyError::CellsNotOrdered);
        }
        Ok(Self(cells))
    }
    #[must_use]
    pub fn as_slice(&self) -> &[CoinCellRecord] {
        &self.0
    }
}
impl CanonicalEncode for CoinCellSet {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_length(self.0.len(), MAX_COIN_CELLS)?;
        for c in &self.0 {
            c.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for CoinCellSet {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let n = d.read_length(MAX_COIN_CELLS)?;
        let mut cells = Vec::with_capacity(n);
        for _ in 0..n {
            cells.push(CoinCellRecord::decode(d)?);
        }
        Self::new(cells)
            .map_err(|_| DecodeError::InvalidValue("coin cells are not strictly ordered"))
    }
}
impl CanonicalType for CoinCellSet {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinTransfer {
    sender: PrincipalId,
    recipient: PrincipalId,
    inputs: Vec<CoinCellId>,
    fee_reserve: CoinCellId,
    amount: Amount,
    fee: Amount,
    valid_until: Height,
}
impl CoinTransfer {
    pub const TYPE_TAG: u16 = 0x0086;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 48 + 2 + MAX_TRANSFER_INPUTS * 48 + 48 + 16 + 16 + 8;
    pub fn new(
        sender: PrincipalId,
        recipient: PrincipalId,
        inputs: Vec<CoinCellId>,
        fee_reserve: CoinCellId,
        amount: Amount,
        fee: Amount,
        valid_until: Height,
    ) -> Result<Self, NativeMoneyError> {
        if inputs.is_empty() || inputs.len() > MAX_TRANSFER_INPUTS {
            return Err(NativeMoneyError::InvalidInputs);
        }
        if inputs.windows(2).any(|p| p[0] >= p[1]) {
            return Err(NativeMoneyError::InputsNotOrdered);
        }
        if inputs.binary_search(&fee_reserve).is_ok() {
            return Err(NativeMoneyError::FeeReserveAlsoInput);
        }
        if amount == 0 {
            return Err(NativeMoneyError::ZeroAmount);
        }
        Ok(Self { sender, recipient, inputs, fee_reserve, amount, fee, valid_until })
    }
    #[must_use]
    pub const fn sender(&self) -> PrincipalId {
        self.sender
    }
    #[must_use]
    pub const fn recipient(&self) -> PrincipalId {
        self.recipient
    }
    #[must_use]
    pub fn inputs(&self) -> &[CoinCellId] {
        &self.inputs
    }
    #[must_use]
    pub const fn fee_reserve(&self) -> CoinCellId {
        self.fee_reserve
    }
    #[must_use]
    pub const fn amount(&self) -> Amount {
        self.amount
    }
    #[must_use]
    pub const fn fee(&self) -> Amount {
        self.fee
    }
    #[must_use]
    pub const fn valid_until(&self) -> Height {
        self.valid_until
    }
}
impl CanonicalEncode for CoinTransfer {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.sender.encode(e)?;
        self.recipient.encode(e)?;
        e.write_length(self.inputs.len(), MAX_TRANSFER_INPUTS)?;
        for i in &self.inputs {
            i.encode(e)?;
        }
        self.fee_reserve.encode(e)?;
        self.amount.encode(e)?;
        self.fee.encode(e)?;
        self.valid_until.encode(e)
    }
}
impl CanonicalDecode for CoinTransfer {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let sender = PrincipalId::decode(d)?;
        let recipient = PrincipalId::decode(d)?;
        let n = d.read_length(MAX_TRANSFER_INPUTS)?;
        let mut inputs = Vec::with_capacity(n);
        for _ in 0..n {
            inputs.push(CoinCellId::decode(d)?);
        }
        Self::new(
            sender,
            recipient,
            inputs,
            CoinCellId::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid coin transfer"))
    }
}
impl CanonicalType for CoinTransfer {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoinMintTransition {
    issuance_policy_hash: Digest384,
    recipient: PrincipalId,
    amount: Amount,
    sequence: u64,
    height: Height,
}
impl CoinMintTransition {
    pub const TYPE_TAG: u16 = 0x0087;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 48 + 16 + 8 + 8;
    pub fn new(
        issuance_policy_hash: Digest384,
        recipient: PrincipalId,
        amount: Amount,
        sequence: u64,
        height: Height,
    ) -> Result<Self, NativeMoneyError> {
        if amount == 0 {
            return Err(NativeMoneyError::ZeroAmount);
        }
        Ok(Self { issuance_policy_hash, recipient, amount, sequence, height })
    }
    #[must_use]
    pub const fn issuance_policy_hash(self) -> Digest384 {
        self.issuance_policy_hash
    }
    #[must_use]
    pub const fn recipient(self) -> PrincipalId {
        self.recipient
    }
    #[must_use]
    pub const fn amount(self) -> Amount {
        self.amount
    }
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn height(self) -> Height {
        self.height
    }
}
impl CanonicalEncode for CoinMintTransition {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.issuance_policy_hash.encode(e)?;
        self.recipient.encode(e)?;
        self.amount.encode(e)?;
        self.sequence.encode(e)?;
        self.height.encode(e)
    }
}
impl CanonicalDecode for CoinMintTransition {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("mint amount is zero"))
    }
}
impl CanonicalType for CoinMintTransition {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinBurnTransition {
    owner: PrincipalId,
    inputs: Vec<CoinCellId>,
    amount: Amount,
    valid_until: Height,
}
impl CoinBurnTransition {
    pub const TYPE_TAG: u16 = 0x0088;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 2 + MAX_TRANSFER_INPUTS * 48 + 16 + 8;
    pub fn new(
        owner: PrincipalId,
        inputs: Vec<CoinCellId>,
        amount: Amount,
        valid_until: Height,
    ) -> Result<Self, NativeMoneyError> {
        if inputs.is_empty() || inputs.len() > MAX_TRANSFER_INPUTS {
            return Err(NativeMoneyError::InvalidInputs);
        }
        if inputs.windows(2).any(|p| p[0] >= p[1]) {
            return Err(NativeMoneyError::InputsNotOrdered);
        }
        if amount == 0 {
            return Err(NativeMoneyError::ZeroAmount);
        }
        Ok(Self { owner, inputs, amount, valid_until })
    }
    #[must_use]
    pub const fn owner(&self) -> PrincipalId {
        self.owner
    }
    #[must_use]
    pub fn inputs(&self) -> &[CoinCellId] {
        &self.inputs
    }
    #[must_use]
    pub const fn amount(&self) -> Amount {
        self.amount
    }
    #[must_use]
    pub const fn valid_until(&self) -> Height {
        self.valid_until
    }
}
impl CanonicalEncode for CoinBurnTransition {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.owner.encode(e)?;
        e.write_length(self.inputs.len(), MAX_TRANSFER_INPUTS)?;
        for i in &self.inputs {
            i.encode(e)?;
        }
        self.amount.encode(e)?;
        self.valid_until.encode(e)
    }
}
impl CanonicalDecode for CoinBurnTransition {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let owner = PrincipalId::decode(d)?;
        let n = d.read_length(MAX_TRANSFER_INPUTS)?;
        let mut inputs = Vec::with_capacity(n);
        for _ in 0..n {
            inputs.push(CoinCellId::decode(d)?);
        }
        Self::new(owner, inputs, u128::decode(d)?, u64::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid burn transition"))
    }
}
impl CanonicalType for CoinBurnTransition {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Deterministic epoch settlement that authorizes bounded security issuance.
/// No administrator or validator signing authority is embedded in this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochEconomicsTransition {
    epoch: Epoch,
    pre_supply: Amount,
    effective_stake_bps: u16,
    security_fee_revenue: Amount,
    reserve_draw: Amount,
    target_security_budget: Amount,
    authorized_issuance: Amount,
    issuance_cap: Amount,
    burned_amount: Amount,
    validator_reward_root: Digest384,
    audit_reward_root: Digest384,
    challenge_reward_root: Digest384,
    public_goods_reward_root: Digest384,
    post_supply: Amount,
}

impl EpochEconomicsTransition {
    pub const TYPE_TAG: u16 = 0x0089;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 16 * 9 + 2 + 48 * 5;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: Epoch,
        pre_supply: Amount,
        effective_stake_bps: u16,
        security_fee_revenue: Amount,
        reserve_draw: Amount,
        target_security_budget: Amount,
        authorized_issuance: Amount,
        issuance_cap: Amount,
        burned_amount: Amount,
        validator_reward_root: Digest384,
        audit_reward_root: Digest384,
        challenge_reward_root: Digest384,
        public_goods_reward_root: Digest384,
        post_supply: Amount,
    ) -> Result<Self, NativeMoneyError> {
        if epoch == 0 || effective_stake_bps > 10_000 {
            return Err(NativeMoneyError::InvalidEconomicsTransition);
        }
        let covered = security_fee_revenue
            .checked_add(reserve_draw)
            .ok_or(NativeMoneyError::AmountOverflow)?;
        if authorized_issuance != target_security_budget.saturating_sub(covered)
            || authorized_issuance > issuance_cap
        {
            return Err(NativeMoneyError::IssuanceFormulaMismatch);
        }
        let expected_post = pre_supply
            .checked_add(authorized_issuance)
            .and_then(|value| value.checked_sub(burned_amount))
            .ok_or(NativeMoneyError::AmountOverflow)?;
        if post_supply != expected_post {
            return Err(NativeMoneyError::SupplyEquationMismatch);
        }
        Ok(Self {
            epoch,
            pre_supply,
            effective_stake_bps,
            security_fee_revenue,
            reserve_draw,
            target_security_budget,
            authorized_issuance,
            issuance_cap,
            burned_amount,
            validator_reward_root,
            audit_reward_root,
            challenge_reward_root,
            public_goods_reward_root,
            post_supply,
        })
    }
    #[must_use]
    pub const fn epoch(self) -> Epoch {
        self.epoch
    }
    #[must_use]
    pub const fn pre_supply(self) -> Amount {
        self.pre_supply
    }
    #[must_use]
    pub const fn effective_stake_bps(self) -> u16 {
        self.effective_stake_bps
    }
    #[must_use]
    pub const fn security_fee_revenue(self) -> Amount {
        self.security_fee_revenue
    }
    #[must_use]
    pub const fn reserve_draw(self) -> Amount {
        self.reserve_draw
    }
    #[must_use]
    pub const fn target_security_budget(self) -> Amount {
        self.target_security_budget
    }
    #[must_use]
    pub const fn authorized_issuance(self) -> Amount {
        self.authorized_issuance
    }
    #[must_use]
    pub const fn issuance_cap(self) -> Amount {
        self.issuance_cap
    }
    #[must_use]
    pub const fn burned_amount(self) -> Amount {
        self.burned_amount
    }
    #[must_use]
    pub const fn post_supply(self) -> Amount {
        self.post_supply
    }
}

impl CanonicalEncode for EpochEconomicsTransition {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.epoch.encode(e)?;
        self.pre_supply.encode(e)?;
        self.effective_stake_bps.encode(e)?;
        self.security_fee_revenue.encode(e)?;
        self.reserve_draw.encode(e)?;
        self.target_security_budget.encode(e)?;
        self.authorized_issuance.encode(e)?;
        self.issuance_cap.encode(e)?;
        self.burned_amount.encode(e)?;
        self.validator_reward_root.encode(e)?;
        self.audit_reward_root.encode(e)?;
        self.challenge_reward_root.encode(e)?;
        self.public_goods_reward_root.encode(e)?;
        self.post_supply.encode(e)
    }
}
impl CanonicalDecode for EpochEconomicsTransition {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            u64::decode(d)?,
            u128::decode(d)?,
            u16::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            u128::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u128::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid epoch economics transition"))
    }
}
impl CanonicalType for EpochEconomicsTransition {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeMoneyError {
    InvalidSymbol,
    InvalidDecimals,
    ZeroGenesisSupply,
    ZeroAllocation,
    InvalidGenesisAllocations,
    GenesisAllocationsNotOrdered,
    GenesisSupplyMismatch,
    AmountOverflow,
    ZeroAmount,
    InvalidReserve,
    SupplyEquationMismatch,
    SupplyPartitionMismatch,
    TooManyCells,
    CellsNotOrdered,
    InvalidInputs,
    InputsNotOrdered,
    FeeReserveAlsoInput,
    MissingCell,
    WrongOwner,
    Expired,
    InsufficientValue,
    MintAuthorityMismatch,
    MintSequenceMismatch,
    IssuanceCapExceeded,
    BurnExceedsInputs,
    OutputCollision,
    InvalidEconomicsTransition,
    IssuanceFormulaMismatch,
}
