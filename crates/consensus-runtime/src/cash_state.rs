use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_cash_kernel::{CoinCellSet, authenticated_coin_cell_root};
use activechain_protocol_types::Digest384;

/// Authenticated finalized cash state handed from execution to RPC indexing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedCashSnapshot {
    pub chain_genesis: Digest384,
    pub finalized_height: u64,
    pub cash_cell_root: Digest384,
    pub cells: CoinCellSet,
}

impl FinalizedCashSnapshot {
    pub fn new(
        chain_genesis: Digest384,
        finalized_height: u64,
        cells: CoinCellSet,
    ) -> Result<Self, &'static str> {
        if chain_genesis == Digest384::ZERO {
            return Err("zero chain genesis");
        }
        let cash_cell_root = authenticated_coin_cell_root(&cells)
            .map_err(|_| "invalid cash cell set")?
            .into_digest();
        Ok(Self { chain_genesis, finalized_height, cash_cell_root, cells })
    }

    pub fn verify(&self) -> Result<(), &'static str> {
        if self.chain_genesis == Digest384::ZERO {
            return Err("zero chain genesis");
        }
        if authenticated_coin_cell_root(&self.cells)
            .map_err(|_| "invalid cash cell set")?
            .into_digest()
            != self.cash_cell_root
        {
            return Err("cash cell root mismatch");
        }
        Ok(())
    }
}

impl CanonicalEncode for FinalizedCashSnapshot {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_genesis.encode(e)?;
        self.finalized_height.encode(e)?;
        self.cash_cell_root.encode(e)?;
        self.cells.encode(e)
    }
}
impl CanonicalDecode for FinalizedCashSnapshot {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            chain_genesis: Digest384::decode(d)?,
            finalized_height: u64::decode(d)?,
            cash_cell_root: Digest384::decode(d)?,
            cells: CoinCellSet::decode(d)?,
        };
        value.verify().map_err(DecodeError::InvalidValue)?;
        Ok(value)
    }
}
impl CanonicalType for FinalizedCashSnapshot {
    const TYPE_TAG: u16 = 0x008e;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 8 + 48 + CoinCellSet::MAX_ENCODED_LEN;
}
