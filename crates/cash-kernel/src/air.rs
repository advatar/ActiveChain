use alloc::vec::Vec;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{CoinCellSetRoot, Digest384, Height, SupplyRoot};

use crate::types::MAX_TRANSFER_BATCH;
use crate::{CashLedger, CashTransferV1, CashTransitionError, PartitionedCashPlan};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashAirError {
    Transition,
    Encoding,
    InvalidProof,
    UnsupportedRange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashAirPublicInputs {
    batch_commitment: Digest384,
    pre_cells: CoinCellSetRoot,
    post_cells: CoinCellSetRoot,
    pre_supply: SupplyRoot,
    post_supply: SupplyRoot,
    height: Height,
    partitions: u16,
    applied: u16,
    rejected: u16,
}

impl CashAirPublicInputs {
    #[must_use]
    pub const fn pre_cells(&self) -> CoinCellSetRoot {
        self.pre_cells
    }
    #[must_use]
    pub const fn post_cells(&self) -> CoinCellSetRoot {
        self.post_cells
    }
    #[must_use]
    pub const fn applied(&self) -> u16 {
        self.applied
    }
    #[must_use]
    pub const fn rejected(&self) -> u16 {
        self.rejected
    }
}

impl CanonicalEncode for CashAirPublicInputs {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.batch_commitment.encode(e)?;
        self.pre_cells.encode(e)?;
        self.post_cells.encode(e)?;
        self.pre_supply.encode(e)?;
        self.post_supply.encode(e)?;
        self.height.encode(e)?;
        self.partitions.encode(e)?;
        self.applied.encode(e)?;
        self.rejected.encode(e)
    }
}

impl CanonicalDecode for CashAirPublicInputs {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            batch_commitment: Digest384::decode(d)?,
            pre_cells: CoinCellSetRoot::decode(d)?,
            post_cells: CoinCellSetRoot::decode(d)?,
            pre_supply: SupplyRoot::decode(d)?,
            post_supply: SupplyRoot::decode(d)?,
            height: u64::decode(d)?,
            partitions: u16::decode(d)?,
            applied: u16::decode(d)?,
            rejected: u16::decode(d)?,
        };
        if value.partitions == 0
            || usize::from(value.applied) + usize::from(value.rejected) > MAX_TRANSFER_BATCH
        {
            return Err(DecodeError::InvalidValue("invalid CashAIR public inputs"));
        }
        Ok(value)
    }
}

impl CanonicalType for CashAirPublicInputs {
    const TYPE_TAG: u16 = 0x0094;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 5 + 8 + 2 * 3;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashAirRow {
    transfer_index: u16,
    pre_cells: CoinCellSetRoot,
    post_cells: CoinCellSetRoot,
    pre_supply: SupplyRoot,
    post_supply: SupplyRoot,
    accepted: bool,
    input_value: u64,
    output_value: u64,
    fee: u64,
}

impl CashAirRow {
    #[must_use]
    pub const fn post_cells(&self) -> CoinCellSetRoot {
        self.post_cells
    }
    #[must_use]
    pub const fn accepted(&self) -> bool {
        self.accepted
    }
    #[must_use]
    pub const fn input_value(&self) -> u64 {
        self.input_value
    }
    #[must_use]
    pub const fn output_value(&self) -> u64 {
        self.output_value
    }
    #[must_use]
    pub const fn fee(&self) -> u64 {
        self.fee
    }
}

impl CanonicalEncode for CashAirRow {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.transfer_index.encode(e)?;
        self.pre_cells.encode(e)?;
        self.post_cells.encode(e)?;
        self.pre_supply.encode(e)?;
        self.post_supply.encode(e)?;
        self.accepted.encode(e)?;
        self.input_value.encode(e)?;
        self.output_value.encode(e)?;
        self.fee.encode(e)
    }
}

impl CanonicalDecode for CashAirRow {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            transfer_index: u16::decode(d)?,
            pre_cells: CoinCellSetRoot::decode(d)?,
            post_cells: CoinCellSetRoot::decode(d)?,
            pre_supply: SupplyRoot::decode(d)?,
            post_supply: SupplyRoot::decode(d)?,
            accepted: bool::decode(d)?,
            input_value: u64::decode(d)?,
            output_value: u64::decode(d)?,
            fee: u64::decode(d)?,
        })
    }
}

impl CanonicalType for CashAirRow {
    const TYPE_TAG: u16 = 0x0095;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 2 + 48 * 4 + 1 + 8 * 3;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashAirProof {
    public: CashAirPublicInputs,
    plan: PartitionedCashPlan,
    rows: Vec<CashAirRow>,
}

impl CashAirProof {
    #[must_use]
    pub const fn public(&self) -> &CashAirPublicInputs {
        &self.public
    }

    #[must_use]
    pub fn rows(&self) -> &[CashAirRow] {
        &self.rows
    }

    pub fn commitment(&self) -> Result<Digest384, CashAirError> {
        commit(DomainTag::CANONICAL_VALUE, self).map_err(|_| CashAirError::Encoding)
    }
}

impl CanonicalEncode for CashAirProof {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.public.encode(e)?;
        self.plan.encode(e)?;
        e.write_length(self.rows.len(), MAX_TRANSFER_BATCH)?;
        for row in &self.rows {
            row.encode(e)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for CashAirProof {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let public = CashAirPublicInputs::decode(d)?;
        let plan = PartitionedCashPlan::decode(d)?;
        let count = d.read_length(MAX_TRANSFER_BATCH)?;
        let mut rows = Vec::with_capacity(count);
        for _ in 0..count {
            rows.push(CashAirRow::decode(d)?);
        }
        if rows.len() != plan.parallel().len() + plan.fallback().len()
            || usize::from(public.applied) + usize::from(public.rejected) != rows.len()
        {
            return Err(DecodeError::InvalidValue("inconsistent CashAIR proof"));
        }
        Ok(Self { public, plan, rows })
    }
}

impl CanonicalType for CashAirProof {
    const TYPE_TAG: u16 = 0x0096;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = CashAirPublicInputs::MAX_ENCODED_LEN
        + PartitionedCashPlan::MAX_ENCODED_LEN
        + 2
        + MAX_TRANSFER_BATCH * CashAirRow::MAX_ENCODED_LEN;
}

pub fn prove_cash_air(
    pre: &CashLedger,
    batch: &CashTransferV1,
    height: Height,
    partitions: u16,
) -> Result<(CashAirProof, CashLedger), CashAirError> {
    let plan =
        PartitionedCashPlan::build(batch, partitions).map_err(|_| CashAirError::Transition)?;
    let mut state = pre.clone();
    let mut rows = Vec::with_capacity(batch.transfers().len());
    let mut applied = 0_u16;
    let mut rejected = 0_u16;
    for index in plan.parallel().iter().chain(plan.fallback()) {
        let transfer = &batch.transfers()[usize::from(*index)];
        let pre_cells = state.cell_set_root().map_err(map_transition)?;
        let pre_supply = state.supply_root().map_err(map_transition)?;
        let values = bounded_values(&state, transfer)?;
        let accepted = state.apply_transfer(transfer, height).is_ok();
        if accepted {
            applied += 1;
        } else {
            rejected += 1;
        }
        rows.push(CashAirRow {
            transfer_index: *index,
            pre_cells,
            post_cells: state.cell_set_root().map_err(map_transition)?,
            pre_supply,
            post_supply: state.supply_root().map_err(map_transition)?,
            accepted,
            input_value: if accepted { values.0 } else { 0 },
            output_value: if accepted { values.1 } else { 0 },
            fee: if accepted { values.2 } else { 0 },
        });
    }
    let public = CashAirPublicInputs {
        batch_commitment: commit(DomainTag::CANONICAL_VALUE, batch)
            .map_err(|_| CashAirError::Encoding)?,
        pre_cells: pre.cell_set_root().map_err(map_transition)?,
        post_cells: state.cell_set_root().map_err(map_transition)?,
        pre_supply: pre.supply_root().map_err(map_transition)?,
        post_supply: state.supply_root().map_err(map_transition)?,
        height,
        partitions,
        applied,
        rejected,
    };
    Ok((CashAirProof { public, plan, rows }, state))
}

/// Verifies every row by direct deterministic re-execution and returns the exact post-state.
pub fn verify_cash_air(
    pre: &CashLedger,
    batch: &CashTransferV1,
    proof: &CashAirProof,
    expected_height: Height,
    expected_partitions: u16,
) -> Result<CashLedger, CashAirError> {
    if proof.public.height != expected_height || proof.public.partitions != expected_partitions {
        return Err(CashAirError::InvalidProof);
    }
    let (expected, post) = prove_cash_air(pre, batch, expected_height, expected_partitions)?;
    if expected != *proof {
        return Err(CashAirError::InvalidProof);
    }
    Ok(post)
}

fn map_transition(_: CashTransitionError) -> CashAirError {
    CashAirError::Transition
}

fn bounded_values(
    ledger: &CashLedger,
    transfer: &crate::CoinTransfer,
) -> Result<(u64, u64, u64), CashAirError> {
    let mut input = 0_u128;
    for id in transfer.inputs().iter().chain(core::iter::once(&transfer.fee_reserve())) {
        let amount = ledger
            .cells()
            .as_slice()
            .iter()
            .find(|record| record.id() == *id)
            .map(|record| record.cell().amount())
            .unwrap_or(0);
        input = input.checked_add(amount).ok_or(CashAirError::UnsupportedRange)?;
    }
    let fee = transfer.fee();
    let output = input.saturating_sub(fee);
    Ok((
        u64::try_from(input).map_err(|_| CashAirError::UnsupportedRange)?,
        u64::try_from(output).map_err(|_| CashAirError::UnsupportedRange)?,
        u64::try_from(fee).map_err(|_| CashAirError::UnsupportedRange)?,
    ))
}
