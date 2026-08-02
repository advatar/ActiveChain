use alloc::{vec, vec::Vec};

use winterfell::{
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree,
    crypto::{DefaultRandomCoin, MerkleTree, hashers::Blake3_256},
    math::{FieldElement, ToElements, fields::f128::BaseElement},
    matrix::ColMatrix,
};

use crate::{ML_DSA_NTT_COEFFICIENTS, ML_DSA_Q};

const TRACE_LENGTH: usize = 512;
const LEFT: usize = 0;
const RIGHT: usize = 1;
const OUTPUT: usize = 2;
const QUOTIENT: usize = 3;
const TRACE_WIDTH: usize = 4;

#[derive(Clone, Debug)]
struct MultiplyPublicInputs {
    rows: Vec<[BaseElement; TRACE_WIDTH]>,
}

impl ToElements<BaseElement> for MultiplyPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.rows.iter().flat_map(|row| row.iter().copied()).collect()
    }
}

struct MultiplyAir {
    context: AirContext<BaseElement>,
    public: MultiplyPublicInputs,
}

impl Air for MultiplyAir {
    type BaseField = BaseElement;
    type PublicInputs = MultiplyPublicInputs;

    fn new(trace_info: TraceInfo, public: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), TRACE_WIDTH);
        assert_eq!(trace_info.length(), TRACE_LENGTH);
        assert_eq!(public.rows.len(), TRACE_LENGTH);
        Self {
            context: AirContext::new(
                trace_info,
                vec![TransitionConstraintDegree::new(2)],
                TRACE_LENGTH * TRACE_WIDTH,
                options,
            ),
            public,
        }
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let q = E::from(BaseElement::new(u128::from(ML_DSA_Q)));
        result[0] = current[LEFT] * current[RIGHT] - current[OUTPUT] - q * current[QUOTIENT];
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::with_capacity(TRACE_LENGTH * TRACE_WIDTH);
        for (row, values) in self.public.rows.iter().enumerate() {
            for (column, value) in values.iter().copied().enumerate() {
                assertions.push(Assertion::single(column, row, value));
            }
        }
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct MultiplyProver {
    options: ProofOptions,
    public: MultiplyPublicInputs,
}

impl Prover for MultiplyProver {
    type BaseField = BaseElement;
    type Air = MultiplyAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> MultiplyPublicInputs {
        self.public.clone()
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

pub struct MlDsaNttMultiplyStarkProof {
    proof: Proof,
    public: MultiplyPublicInputs,
}

pub fn prove_ml_dsa_ntt_multiply(
    left: &[u32; ML_DSA_NTT_COEFFICIENTS],
    right: &[u32; ML_DSA_NTT_COEFFICIENTS],
) -> Result<(MlDsaNttMultiplyStarkProof, [u32; ML_DSA_NTT_COEFFICIENTS]), &'static str> {
    let (public, output) = public_inputs(left, right)?;
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (row, values) in public.rows.iter().enumerate() {
        for (column, value) in values.iter().copied().enumerate() {
            trace.set(column, row, value);
        }
    }
    let prover = MultiplyProver { options: proof_options(), public: public.clone() };
    let proof = prover.prove(trace).map_err(|_| "ML-DSA MultiplyNTT proving failed")?;
    Ok((MlDsaNttMultiplyStarkProof { proof, public }, output))
}

pub fn verify_ml_dsa_ntt_multiply(
    proof: MlDsaNttMultiplyStarkProof,
    left: &[u32; ML_DSA_NTT_COEFFICIENTS],
    right: &[u32; ML_DSA_NTT_COEFFICIENTS],
    output: &[u32; ML_DSA_NTT_COEFFICIENTS],
) -> Result<(), &'static str> {
    let (expected, expected_output) = public_inputs(left, right)?;
    if &expected_output != output || proof.public.to_elements() != expected.to_elements() {
        return Err("ML-DSA MultiplyNTT public inputs mismatch");
    }
    winterfell::verify::<
        MultiplyAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof.proof, expected, &AcceptableOptions::MinConjecturedSecurity(100))
    .map_err(|_| "ML-DSA MultiplyNTT verification failed")
}

fn public_inputs(
    left: &[u32; ML_DSA_NTT_COEFFICIENTS],
    right: &[u32; ML_DSA_NTT_COEFFICIENTS],
) -> Result<(MultiplyPublicInputs, [u32; ML_DSA_NTT_COEFFICIENTS]), &'static str> {
    if left.iter().chain(right).any(|coefficient| *coefficient >= ML_DSA_Q) {
        return Err("ML-DSA MultiplyNTT coefficient is outside Z_q");
    }
    let modulus = u64::from(ML_DSA_Q);
    let mut output = [0_u32; ML_DSA_NTT_COEFFICIENTS];
    let mut rows = Vec::with_capacity(TRACE_LENGTH);
    for index in 0..ML_DSA_NTT_COEFFICIENTS {
        let product = u64::from(left[index]) * u64::from(right[index]);
        let remainder = product % modulus;
        let quotient = product / modulus;
        output[index] = remainder as u32;
        rows.push([
            element(left[index]),
            element(right[index]),
            BaseElement::new(u128::from(remainder)),
            BaseElement::new(u128::from(quotient)),
        ]);
    }
    rows.resize(TRACE_LENGTH, [BaseElement::ZERO; TRACE_WIDTH]);
    Ok((MultiplyPublicInputs { rows }, output))
}

fn element(value: u32) -> BaseElement {
    BaseElement::new(u128::from(value))
}

fn proof_options() -> ProofOptions {
    ProofOptions::new(
        40,
        8,
        16,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operands() -> ([u32; ML_DSA_NTT_COEFFICIENTS], [u32; ML_DSA_NTT_COEFFICIENTS]) {
        (
            core::array::from_fn(|index| (index as u32 * 17 + 3) % ML_DSA_Q),
            core::array::from_fn(|index| (index as u32 * 29 + 5) % ML_DSA_Q),
        )
    }

    #[test]
    fn multiply_ntt_air_proves_all_coefficient_products() {
        let (left, right) = operands();
        let (proof, output) = prove_ml_dsa_ntt_multiply(&left, &right).unwrap();
        verify_ml_dsa_ntt_multiply(proof, &left, &right, &output).unwrap();
    }

    #[test]
    fn multiply_ntt_air_rejects_operand_output_and_range_substitution() {
        let (left, right) = operands();
        let (proof, mut output) = prove_ml_dsa_ntt_multiply(&left, &right).unwrap();
        output[11] = (output[11] + 1) % ML_DSA_Q;
        assert!(verify_ml_dsa_ntt_multiply(proof, &left, &right, &output).is_err());

        let (proof, output) = prove_ml_dsa_ntt_multiply(&left, &right).unwrap();
        let mut substituted = left;
        substituted[11] = (substituted[11] + 1) % ML_DSA_Q;
        assert!(verify_ml_dsa_ntt_multiply(proof, &substituted, &right, &output).is_err());
        substituted[0] = ML_DSA_Q;
        assert!(prove_ml_dsa_ntt_multiply(&substituted, &right).is_err());
    }
}
