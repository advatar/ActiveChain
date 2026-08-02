#![forbid(unsafe_code)]

use std::{collections::BTreeMap, hint::black_box, time::Instant};

use activechain_canonical_codec::encode_envelope;
use activechain_cash_air::{CashAirReceiptV1, prove, verify_bytes};
use activechain_cash_kernel::{
    CashLedger, CashTransferV1, CoinMintTransition, CoinTransfer, EpochEconomicsTransition,
    GenesisAllocation, GenesisEconomy, NativeAssetDefinition, authenticated_coin_cell_root,
    basis_points_amount, epoch_security_budget, prove_cash_air,
};
use activechain_data_availability::AvailabilityBatch;
use activechain_protocol_types::{
    ChainId, CoinCellId, CryptoSuiteId, Digest384, PrincipalId, ProtocolSignature,
};
use activechain_wallet_core::{AuthorizedCashTransferV1, CashAuthorizationRequestV1};
use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
use serde::Serialize;

const DATA_SHARDS: usize = 4;
const PARITY_SHARDS: usize = 2;
const EXECUTION_HEIGHT: u64 = 3;
const TRACE_ROW_LIMIT: u16 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BenchmarkConfig {
    pub iterations: u32,
}

impl BenchmarkConfig {
    pub fn new(iterations: u32) -> Result<Self, BenchmarkError> {
        if iterations == 0 {
            return Err(BenchmarkError::InvalidIterations);
        }
        Ok(Self { iterations })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BenchmarkReport {
    pub schema: &'static str,
    pub iterations: u32,
    pub transfers_per_batch: usize,
    pub verified_transfers: u64,
    pub elapsed_ns: u128,
    pub authorization_ns: u128,
    pub state_trace_ns: u128,
    pub proving_ns: u128,
    pub verification_ns: u128,
    pub availability_ns: u128,
    pub verified_transfers_per_second: f64,
    pub proof_bytes: usize,
    pub receipt_bytes: usize,
    pub availability_bytes: usize,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub trace_row_limit: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkError {
    InvalidIterations,
    Fixture,
    Authorization,
    StateTransition,
    Proof,
    Availability,
}

struct BenchmarkFixture {
    ledger: CashLedger,
    batch: CashTransferV1,
    keys: BTreeMap<PrincipalId, SigningKey<MlDsa44>>,
}

pub fn run(config: BenchmarkConfig) -> Result<BenchmarkReport, BenchmarkError> {
    let BenchmarkFixture { ledger, batch, keys } = fixture()?;
    let transfers_per_batch = batch.transfers().len();
    let started = Instant::now();
    let mut authorization_ns = 0;
    let mut state_trace_ns = 0;
    let mut proving_ns = 0;
    let mut verification_ns = 0;
    let mut availability_ns = 0;
    let mut proof_bytes = 0;
    let mut receipt_bytes = 0;
    let mut availability_bytes = 0;

    for iteration in 0..config.iterations {
        let stage = Instant::now();
        authorize_batch(&batch, &keys, u64::from(iteration))?;
        authorization_ns += stage.elapsed().as_nanos();

        let stage = Instant::now();
        let (trace, post_ledger) = prove_cash_air(
            black_box(&ledger),
            black_box(&batch),
            EXECUTION_HEIGHT,
            TRACE_ROW_LIMIT,
        )
        .map_err(|_| BenchmarkError::StateTransition)?;
        black_box(
            authenticated_coin_cell_root(post_ledger.cells())
                .map_err(|_| BenchmarkError::StateTransition)?,
        );
        state_trace_ns += stage.elapsed().as_nanos();

        let stage = Instant::now();
        let proof = prove(black_box(&trace)).map_err(|_| BenchmarkError::Proof)?;
        let encoded_proof = proof.to_bytes();
        proving_ns += stage.elapsed().as_nanos();

        let stage = Instant::now();
        verify_bytes(black_box(&encoded_proof), black_box(&trace))
            .map_err(|_| BenchmarkError::Proof)?;
        verification_ns += stage.elapsed().as_nanos();

        let receipt = CashAirReceiptV1::new(trace, encoded_proof.clone())
            .map_err(|_| BenchmarkError::Proof)?;
        let encoded_receipt = encode_envelope(&receipt).map_err(|_| BenchmarkError::Proof)?;
        let stage = Instant::now();
        let availability =
            AvailabilityBatch::encode(black_box(&encoded_receipt), DATA_SHARDS, PARITY_SHARDS)
                .map_err(|_| BenchmarkError::Availability)?;
        let encoded_availability =
            availability.serialize().map_err(|_| BenchmarkError::Availability)?;
        let restored = AvailabilityBatch::deserialize(&encoded_availability)
            .and_then(|batch| batch.reconstruct_payload(&[DATA_SHARDS]))
            .map_err(|_| BenchmarkError::Availability)?;
        if restored != encoded_receipt {
            return Err(BenchmarkError::Availability);
        }
        availability_ns += stage.elapsed().as_nanos();

        proof_bytes = encoded_proof.len();
        receipt_bytes = encoded_receipt.len();
        availability_bytes = encoded_availability.len();
    }

    let elapsed_ns = started.elapsed().as_nanos();
    let verified_transfers = u64::from(config.iterations)
        * u64::try_from(transfers_per_batch).map_err(|_| BenchmarkError::Fixture)?;
    let verified_transfers_per_second =
        verified_transfers as f64 * 1_000_000_000_f64 / elapsed_ns as f64;
    Ok(BenchmarkReport {
        schema: "activechain-proof-finalized-cash-throughput-v1",
        iterations: config.iterations,
        transfers_per_batch,
        verified_transfers,
        elapsed_ns,
        authorization_ns,
        state_trace_ns,
        proving_ns,
        verification_ns,
        availability_ns,
        verified_transfers_per_second,
        proof_bytes,
        receipt_bytes,
        availability_bytes,
        data_shards: DATA_SHARDS,
        parity_shards: PARITY_SHARDS,
        trace_row_limit: usize::from(TRACE_ROW_LIMIT),
    })
}

fn authorize_batch(
    batch: &CashTransferV1,
    keys: &BTreeMap<PrincipalId, SigningKey<MlDsa44>>,
    nonce_base: u64,
) -> Result<(), BenchmarkError> {
    for (offset, transfer) in batch.transfers().iter().enumerate() {
        let key = keys.get(&transfer.sender()).ok_or(BenchmarkError::Authorization)?;
        let nonce = nonce_base
            .checked_mul(16)
            .and_then(|value| value.checked_add(offset as u64))
            .ok_or(BenchmarkError::Authorization)?;
        let request = CashAuthorizationRequestV1::new(
            ChainId::new(digest(1)),
            transfer.sender(),
            nonce,
            digest(80 + offset as u8),
            transfer.valid_until(),
            transfer.clone(),
        )
        .map_err(|_| BenchmarkError::Authorization)?;
        let signature =
            key.sign(&request.signing_payload().map_err(|_| BenchmarkError::Authorization)?);
        let authorization = AuthorizedCashTransferV1::new(
            request,
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                signature.encode().as_slice().to_vec(),
            )
            .map_err(|_| BenchmarkError::Authorization)?,
        )
        .map_err(|_| BenchmarkError::Authorization)?;
        authorization
            .verify(key.verifying_key().encode().as_slice())
            .map_err(|_| BenchmarkError::Authorization)?;
    }
    Ok(())
}

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn principal(byte: u8) -> PrincipalId {
    PrincipalId::new(digest(byte))
}

fn settlement(pre_supply: u128, issuance: u128, epoch: u64) -> EpochEconomicsTransition {
    let target = epoch_security_budget(pre_supply, 0).expect("bounded fixture");
    let issued_before = issuance * u128::from(epoch - 1);
    let cap = basis_points_amount(1_000_000, 150).expect("bounded fixture") - issued_before;
    EpochEconomicsTransition::new(
        epoch,
        pre_supply,
        0,
        target - issuance,
        0,
        target,
        issuance,
        cap,
        0,
        digest(20),
        digest(21),
        digest(22),
        digest(23),
        pre_supply + issuance,
    )
    .expect("bounded fixture")
}

fn fixture() -> Result<BenchmarkFixture, BenchmarkError> {
    let definition = NativeAssetDefinition::new(
        ChainId::new(digest(1)),
        b"ACT".to_vec(),
        18,
        1_000_000,
        150,
        digest(2),
        digest(3),
        digest(4),
    )
    .map_err(|_| BenchmarkError::Fixture)?;
    let economy = GenesisEconomy::new(
        definition,
        vec![
            GenesisAllocation::new(principal(10), 700_000, 100_000)
                .map_err(|_| BenchmarkError::Fixture)?,
            GenesisAllocation::new(principal(12), 100_000, 0)
                .map_err(|_| BenchmarkError::Fixture)?,
        ],
        100_000,
    )
    .map_err(|_| BenchmarkError::Fixture)?;
    let mut ledger = CashLedger::from_genesis(&economy).map_err(|_| BenchmarkError::Fixture)?;
    ledger
        .apply_mint(
            &CoinMintTransition::new(digest(2), principal(10), 20, 1, 1)
                .map_err(|_| BenchmarkError::Fixture)?,
            &settlement(1_000_000, 20, 1),
        )
        .map_err(|_| BenchmarkError::Fixture)?;
    ledger
        .apply_mint(
            &CoinMintTransition::new(digest(2), principal(12), 20, 2, 2)
                .map_err(|_| BenchmarkError::Fixture)?,
            &settlement(1_000_020, 20, 2),
        )
        .map_err(|_| BenchmarkError::Fixture)?;
    let mut transfers = [principal(10), principal(12)]
        .into_iter()
        .map(|owner| {
            let ids = ledger
                .cells()
                .as_slice()
                .iter()
                .filter(|record| record.cell().owner() == owner)
                .map(|record| record.id())
                .collect::<Vec<CoinCellId>>();
            CoinTransfer::new(owner, principal(30), vec![ids[0]], ids[1], 25, 1, 20)
                .map_err(|_| BenchmarkError::Fixture)
        })
        .collect::<Result<Vec<_>, _>>()?;
    transfers.sort_by_key(|transfer| transfer.inputs()[0]);
    let batch = CashTransferV1::new(transfers).map_err(|_| BenchmarkError::Fixture)?;
    let keys = [(principal(10), 10_u8), (principal(12), 12_u8)]
        .into_iter()
        .map(|(owner, seed)| (owner, SigningKey::<MlDsa44>::from_seed(&Seed::from([seed; 32]))))
        .collect();
    Ok(BenchmarkFixture { ledger, batch, keys })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_iterations_fail_closed() {
        assert_eq!(BenchmarkConfig::new(0), Err(BenchmarkError::InvalidIterations));
    }

    #[test]
    fn one_iteration_runs_the_real_pipeline() {
        let report = run(BenchmarkConfig::new(1).unwrap()).unwrap();
        assert_eq!(report.verified_transfers, 2);
        assert!(report.proof_bytes > 0);
        assert!(report.receipt_bytes > report.proof_bytes);
        assert!(report.availability_bytes > report.receipt_bytes);
        assert!(report.verified_transfers_per_second.is_finite());
    }
}
