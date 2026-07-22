#![forbid(unsafe_code)]

//! Transparent STARK constraints over the canonical CashAIR execution trace.
//!
//! This first algebraic tranche proves counter progression, outcome booleanity, failed-row
//! atomicity, row count, and pre/post Coin Cell root binding. The cryptographic and membership
//! tables required by `CASH.md` remain separate, explicit roadmap gates.

use activechain_cash_kernel::CashAirProof;
use activechain_protocol_types::{CoinCellSetRoot, Digest384};
use winterfell::{
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree,
    crypto::{DefaultRandomCoin, MerkleTree, hashers::Blake3_256},
    math::{FieldElement, ToElements, fields::f128::BaseElement},
    matrix::ColMatrix,
};

mod session;
mod shake;
pub use session::{
    CashSessionProofError, CashSessionStarkProof, prove_authorized_session, prove_session_budget,
    verify_session_budget,
};
pub use shake::{
    AuthenticatedCashShakeStarkProof, BatchedShake256StarkProof, MAX_CASH_SHAKE_MESSAGE,
    Shake256StarkProof, prove_authenticated_cash_shake, prove_shake256_384,
    prove_shake256_384_batch, verify_authenticated_cash_shake, verify_shake256_384,
    verify_shake256_384_batch,
};

const TRACE_WIDTH: usize = 11;
const STEP: usize = 0;
const APPLIED: usize = 1;
const REJECTED: usize = 2;
const ACTIVE: usize = 3;
const ACCEPTED: usize = 4;
const ROOT_0: usize = 5;
const INPUT_VALUE: usize = 8;
const OUTPUT_VALUE: usize = 9;
const FEE: usize = 10;

#[derive(Clone, Debug)]
pub struct CashStarkPublicInputs {
    pre_root: [BaseElement; 3],
    post_root: [BaseElement; 3],
    applied: BaseElement,
    rejected: BaseElement,
}

impl ToElements<BaseElement> for CashStarkPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.pre_root
            .into_iter()
            .chain(self.post_root)
            .chain([self.applied, self.rejected])
            .collect()
    }
}

pub struct CashAir {
    context: AirContext<BaseElement>,
    public: CashStarkPublicInputs,
}

impl Air for CashAir {
    type BaseField = BaseElement;
    type PublicInputs = CashStarkPublicInputs;

    fn new(trace_info: TraceInfo, public: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), TRACE_WIDTH);
        let mut degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
        ];
        degrees[10] = TransitionConstraintDegree::new(1);
        Self { context: AirContext::new(trace_info, degrees, 14, options), public }
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        let one = E::ONE;
        result[0] = next[STEP] - current[STEP] - next[ACTIVE];
        result[1] = next[APPLIED] - current[APPLIED] - next[ACTIVE] * next[ACCEPTED];
        result[2] = next[REJECTED] - current[REJECTED] - next[ACTIVE] * (one - next[ACCEPTED]);
        result[3] = next[ACTIVE] * (next[ACTIVE] - one);
        result[4] = next[ACTIVE] * (one - current[ACTIVE]);
        result[5] = next[ACCEPTED] * (next[ACCEPTED] - one);
        result[6] = next[ACCEPTED] * (one - next[ACTIVE]);
        let rejected = one - next[ACCEPTED];
        for limb in 0..3 {
            result[7 + limb] = rejected * (next[ROOT_0 + limb] - current[ROOT_0 + limb]);
        }
        result[10] = next[INPUT_VALUE] - next[OUTPUT_VALUE] - next[FEE];
        result[11] = rejected * next[INPUT_VALUE];
        result[12] = rejected * next[OUTPUT_VALUE];
        result[13] = rejected * next[FEE];
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = self.trace_length() - 1;
        let mut assertions = vec![
            Assertion::single(STEP, 0, BaseElement::ZERO),
            Assertion::single(APPLIED, 0, BaseElement::ZERO),
            Assertion::single(REJECTED, 0, BaseElement::ZERO),
            Assertion::single(ACTIVE, 0, BaseElement::ONE),
            Assertion::single(ACCEPTED, 0, BaseElement::ZERO),
            Assertion::single(APPLIED, last, self.public.applied),
            Assertion::single(REJECTED, last, self.public.rejected),
            Assertion::single(ACTIVE, last, BaseElement::ZERO),
        ];
        for limb in 0..3 {
            assertions.push(Assertion::single(ROOT_0 + limb, 0, self.public.pre_root[limb]));
            assertions.push(Assertion::single(ROOT_0 + limb, last, self.public.post_root[limb]));
        }
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct CashProver {
    options: ProofOptions,
}

impl Prover for CashProver {
    type BaseField = BaseElement;
    type Air = CashAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> CashStarkPublicInputs {
        let last = trace.length() - 1;
        CashStarkPublicInputs {
            pre_root: [trace.get(ROOT_0, 0), trace.get(ROOT_0 + 1, 0), trace.get(ROOT_0 + 2, 0)],
            post_root: [
                trace.get(ROOT_0, last),
                trace.get(ROOT_0 + 1, last),
                trace.get(ROOT_0 + 2, last),
            ],
            applied: trace.get(APPLIED, last),
            rejected: trace.get(REJECTED, last),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace: CompositionPolyTrace<E>,
        columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partitions: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(trace, columns, domain, partitions)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        randomness: Option<AuxRandElements<E>>,
        coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, randomness, coefficients)
    }
}

pub struct CashStarkProof {
    proof: Proof,
    public: CashStarkPublicInputs,
}

impl CashStarkProof {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.proof.to_bytes()
    }
}

pub fn prove(trace: &CashAirProof) -> Result<CashStarkProof, &'static str> {
    let execution = build_trace(trace)?;
    let public = public_inputs(trace.public());
    let prover = CashProver { options: proof_options() };
    let proof = prover.prove(execution).map_err(|_| "CashAIR proving failed")?;
    Ok(CashStarkProof { proof, public })
}

pub fn verify(proof: CashStarkProof) -> Result<(), &'static str> {
    winterfell::verify::<
        CashAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof.proof, proof.public, &AcceptableOptions::MinConjecturedSecurity(95))
    .map_err(|_| "CashAIR verification failed")
}

pub fn verify_bytes(bytes: &[u8], trace: &CashAirProof) -> Result<(), &'static str> {
    let proof = Proof::from_bytes(bytes).map_err(|_| "malformed CashAIR STARK proof")?;
    verify(CashStarkProof { proof, public: public_inputs(trace.public()) })
}

fn build_trace(proof: &CashAirProof) -> Result<TraceTable<BaseElement>, &'static str> {
    let length = (proof.rows().len() + 2).next_power_of_two().max(8);
    let mut trace = TraceTable::new(TRACE_WIDTH, length);
    let mut current_root = root_elements(proof.public().pre_cells());
    trace.set(STEP, 0, BaseElement::ZERO);
    trace.set(APPLIED, 0, BaseElement::ZERO);
    trace.set(REJECTED, 0, BaseElement::ZERO);
    trace.set(ACTIVE, 0, BaseElement::ONE);
    trace.set(ACCEPTED, 0, BaseElement::ZERO);
    trace.set(INPUT_VALUE, 0, BaseElement::ZERO);
    trace.set(OUTPUT_VALUE, 0, BaseElement::ZERO);
    trace.set(FEE, 0, BaseElement::ZERO);
    set_root(&mut trace, 0, current_root);
    let mut applied = 0_u64;
    let mut rejected = 0_u64;
    for (offset, row) in proof.rows().iter().enumerate() {
        let index = offset + 1;
        if row.accepted() {
            applied += 1;
        } else {
            rejected += 1;
        }
        current_root = root_elements(row.post_cells());
        trace.set(STEP, index, BaseElement::new(index as u128));
        trace.set(APPLIED, index, BaseElement::new(applied.into()));
        trace.set(REJECTED, index, BaseElement::new(rejected.into()));
        trace.set(ACTIVE, index, BaseElement::ONE);
        trace.set(ACCEPTED, index, BaseElement::new(u128::from(row.accepted())));
        trace.set(INPUT_VALUE, index, BaseElement::new(row.input_value().into()));
        trace.set(OUTPUT_VALUE, index, BaseElement::new(row.output_value().into()));
        trace.set(FEE, index, BaseElement::new(row.fee().into()));
        set_root(&mut trace, index, current_root);
    }
    for index in proof.rows().len() + 1..length {
        trace.set(STEP, index, BaseElement::new(proof.rows().len() as u128));
        trace.set(APPLIED, index, BaseElement::new(applied.into()));
        trace.set(REJECTED, index, BaseElement::new(rejected.into()));
        trace.set(ACTIVE, index, BaseElement::ZERO);
        trace.set(ACCEPTED, index, BaseElement::ZERO);
        trace.set(INPUT_VALUE, index, BaseElement::ZERO);
        trace.set(OUTPUT_VALUE, index, BaseElement::ZERO);
        trace.set(FEE, index, BaseElement::ZERO);
        set_root(&mut trace, index, current_root);
    }
    Ok(trace)
}

fn public_inputs(public: &activechain_cash_kernel::CashAirPublicInputs) -> CashStarkPublicInputs {
    CashStarkPublicInputs {
        pre_root: root_elements(public.pre_cells()),
        post_root: root_elements(public.post_cells()),
        applied: BaseElement::new(public.applied().into()),
        rejected: BaseElement::new(public.rejected().into()),
    }
}

fn root_elements(root: CoinCellSetRoot) -> [BaseElement; 3] {
    let digest: Digest384 = root.into_digest();
    let bytes = digest.as_bytes();
    core::array::from_fn(|index| {
        let mut limb = [0_u8; 16];
        limb.copy_from_slice(&bytes[index * 16..(index + 1) * 16]);
        BaseElement::new(u128::from_be_bytes(limb))
    })
}

fn set_root(trace: &mut TraceTable<BaseElement>, row: usize, root: [BaseElement; 3]) {
    for (limb, value) in root.into_iter().enumerate() {
        trace.set(ROOT_0 + limb, row, value);
    }
}

fn proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(test)]
mod tests {
    use activechain_cash_kernel::{
        CashLedger, CashTransferV1, CoinMintTransition, CoinTransfer, EpochEconomicsTransition,
        GenesisAllocation, GenesisEconomy, NativeAssetDefinition, prove_cash_air,
    };
    use activechain_protocol_types::{ChainId, CoinCellId, Digest384, PrincipalId};

    use super::{BaseElement, prove, verify};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }

    fn settlement(pre_supply: u128, issuance: u128, epoch: u64) -> EpochEconomicsTransition {
        EpochEconomicsTransition::new(
            epoch,
            pre_supply,
            5_000,
            0,
            0,
            issuance,
            issuance,
            issuance * 2,
            0,
            digest(20),
            digest(21),
            digest(22),
            digest(23),
            pre_supply + issuance,
        )
        .unwrap()
    }

    fn fixture() -> (CashLedger, CashTransferV1) {
        let definition = NativeAssetDefinition::new(
            ChainId::new(digest(1)),
            b"ACT".to_vec(),
            18,
            1_000,
            150,
            digest(2),
            digest(3),
            digest(4),
        )
        .unwrap();
        let economy = GenesisEconomy::new(
            definition,
            vec![
                GenesisAllocation::new(principal(10), 700, 100).unwrap(),
                GenesisAllocation::new(principal(12), 100, 0).unwrap(),
            ],
            100,
        )
        .unwrap();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(10), 50, 1, 1).unwrap(),
                &settlement(1_000, 50, 1),
            )
            .unwrap();
        ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(12), 50, 2, 2).unwrap(),
                &settlement(1_050, 50, 2),
            )
            .unwrap();
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
                CoinTransfer::new(owner, principal(30), vec![ids[0]], ids[1], 25, 1, 20).unwrap()
            })
            .collect::<Vec<_>>();
        transfers.sort_by_key(|transfer| transfer.inputs()[0]);
        (ledger, CashTransferV1::new(transfers).unwrap())
    }

    #[test]
    fn specialized_stark_proves_the_direct_cash_trace() {
        let (ledger, batch) = fixture();
        let (trace, _) = prove_cash_air(&ledger, &batch, 3, 16).unwrap();
        let proof = prove(&trace).unwrap();
        let bytes = proof.to_bytes();
        verify(proof).unwrap();
        super::verify_bytes(&bytes, &trace).unwrap();
        assert!(super::verify_bytes(&bytes[..bytes.len() - 1], &trace).is_err());
        let mut tampered = bytes;
        let midpoint = tampered.len() / 2;
        tampered[midpoint] ^= 1;
        assert!(super::verify_bytes(&tampered, &trace).is_err());
    }

    #[test]
    fn substituted_public_outcome_is_rejected() {
        let (ledger, batch) = fixture();
        let (trace, _) = prove_cash_air(&ledger, &batch, 3, 16).unwrap();
        let mut proof = prove(&trace).unwrap();
        proof.public.applied += BaseElement::new(1);
        assert!(verify(proof).is_err());
    }
}
