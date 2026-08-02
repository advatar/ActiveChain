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

use crate::{
    ML_DSA_NTT_COEFFICIENTS, ML_DSA_Q, MlDsaNttMultiplyStarkProof, prove_ml_dsa_ntt_multiply,
    verify_ml_dsa_ntt_multiply,
};

pub const ML_DSA_44_VECTOR_DIMENSION: usize = 4;

const TRACE_LENGTH: usize = 512;
const PRODUCT_0: usize = 0;
const PRODUCT_1: usize = 1;
const PRODUCT_2: usize = 2;
const PRODUCT_3: usize = 3;
const SUM_01: usize = 4;
const SUM_012: usize = 5;
const OUTPUT: usize = 6;
const WRAP_01: usize = 7;
const WRAP_012: usize = 8;
const WRAP_OUTPUT: usize = 9;
const TRACE_WIDTH: usize = 10;

type Polynomial = [u32; ML_DSA_NTT_COEFFICIENTS];
type Vector = [Polynomial; ML_DSA_44_VECTOR_DIMENSION];

#[derive(Clone, Debug)]
struct AccumulationPublicInputs {
    rows: Vec<[BaseElement; TRACE_WIDTH]>,
}

impl ToElements<BaseElement> for AccumulationPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.rows.iter().flat_map(|row| row.iter().copied()).collect()
    }
}

struct AccumulationAir {
    context: AirContext<BaseElement>,
    public: AccumulationPublicInputs,
}

impl Air for AccumulationAir {
    type BaseField = BaseElement;
    type PublicInputs = AccumulationPublicInputs;

    fn new(trace_info: TraceInfo, public: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), TRACE_WIDTH);
        assert_eq!(trace_info.length(), TRACE_LENGTH);
        assert_eq!(public.rows.len(), TRACE_LENGTH);
        Self {
            context: AirContext::new(
                trace_info,
                vec![
                    TransitionConstraintDegree::new(1),
                    TransitionConstraintDegree::new(1),
                    TransitionConstraintDegree::new(1),
                    TransitionConstraintDegree::new(2),
                    TransitionConstraintDegree::new(2),
                    TransitionConstraintDegree::new(2),
                ],
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
        result[0] =
            current[PRODUCT_0] + current[PRODUCT_1] - current[SUM_01] - q * current[WRAP_01];
        result[1] = current[SUM_01] + current[PRODUCT_2] - current[SUM_012] - q * current[WRAP_012];
        result[2] =
            current[SUM_012] + current[PRODUCT_3] - current[OUTPUT] - q * current[WRAP_OUTPUT];
        result[3] = current[WRAP_01] * (current[WRAP_01] - E::ONE);
        result[4] = current[WRAP_012] * (current[WRAP_012] - E::ONE);
        result[5] = current[WRAP_OUTPUT] * (current[WRAP_OUTPUT] - E::ONE);
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

struct AccumulationProver {
    options: ProofOptions,
    public: AccumulationPublicInputs,
}

impl Prover for AccumulationProver {
    type BaseField = BaseElement;
    type Air = AccumulationAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> AccumulationPublicInputs {
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

#[cfg_attr(test, derive(Clone))]
struct AccumulationProof {
    proof: Proof,
    public: AccumulationPublicInputs,
}

#[cfg_attr(test, derive(Clone))]
pub struct MlDsaVectorAccumulationStarkProof {
    products: [MlDsaNttMultiplyStarkProof; ML_DSA_44_VECTOR_DIMENSION],
    accumulation: AccumulationProof,
}

pub fn prove_ml_dsa_vector_accumulation(
    left: &Vector,
    right: &Vector,
) -> Result<(MlDsaVectorAccumulationStarkProof, Polynomial), &'static str> {
    let (product_0, output_0) = prove_ml_dsa_ntt_multiply(&left[0], &right[0])?;
    let (product_1, output_1) = prove_ml_dsa_ntt_multiply(&left[1], &right[1])?;
    let (product_2, output_2) = prove_ml_dsa_ntt_multiply(&left[2], &right[2])?;
    let (product_3, output_3) = prove_ml_dsa_ntt_multiply(&left[3], &right[3])?;
    let products = [output_0, output_1, output_2, output_3];
    let (public, output) = accumulation_public_inputs(&products);
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (row, values) in public.rows.iter().enumerate() {
        for (column, value) in values.iter().copied().enumerate() {
            trace.set(column, row, value);
        }
    }
    let prover = AccumulationProver { options: proof_options(), public: public.clone() };
    let proof = prover.prove(trace).map_err(|_| "ML-DSA vector accumulation proving failed")?;
    Ok((
        MlDsaVectorAccumulationStarkProof {
            products: [product_0, product_1, product_2, product_3],
            accumulation: AccumulationProof { proof, public },
        },
        output,
    ))
}

pub fn verify_ml_dsa_vector_accumulation(
    proof: MlDsaVectorAccumulationStarkProof,
    left: &Vector,
    right: &Vector,
    output: &Polynomial,
) -> Result<(), &'static str> {
    let MlDsaVectorAccumulationStarkProof { products: product_proofs, accumulation } = proof;
    let mut products = [[0_u32; ML_DSA_NTT_COEFFICIENTS]; ML_DSA_44_VECTOR_DIMENSION];
    for vector_index in 0..ML_DSA_44_VECTOR_DIMENSION {
        let modulus = u64::from(ML_DSA_Q);
        for coefficient in 0..ML_DSA_NTT_COEFFICIENTS {
            if left[vector_index][coefficient] >= ML_DSA_Q
                || right[vector_index][coefficient] >= ML_DSA_Q
            {
                return Err("ML-DSA vector coefficient is outside Z_q");
            }
            products[vector_index][coefficient] = ((u64::from(left[vector_index][coefficient])
                * u64::from(right[vector_index][coefficient]))
                % modulus) as u32;
        }
    }
    for (vector_index, product_proof) in product_proofs.into_iter().enumerate() {
        verify_ml_dsa_ntt_multiply(
            product_proof,
            &left[vector_index],
            &right[vector_index],
            &products[vector_index],
        )?;
    }
    let (expected, expected_output) = accumulation_public_inputs(&products);
    if &expected_output != output || accumulation.public.to_elements() != expected.to_elements() {
        return Err("ML-DSA vector accumulation public inputs mismatch");
    }
    winterfell::verify::<
        AccumulationAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(accumulation.proof, expected, &AcceptableOptions::MinConjecturedSecurity(100))
    .map_err(|_| "ML-DSA vector accumulation verification failed")
}

fn accumulation_public_inputs(products: &Vector) -> (AccumulationPublicInputs, Polynomial) {
    let modulus = u64::from(ML_DSA_Q);
    let mut output = [0_u32; ML_DSA_NTT_COEFFICIENTS];
    let mut rows = Vec::with_capacity(TRACE_LENGTH);
    for index in 0..ML_DSA_NTT_COEFFICIENTS {
        let sum_01_full = u64::from(products[0][index]) + u64::from(products[1][index]);
        let sum_01 = sum_01_full % modulus;
        let sum_012_full = sum_01 + u64::from(products[2][index]);
        let sum_012 = sum_012_full % modulus;
        let output_full = sum_012 + u64::from(products[3][index]);
        let coefficient = output_full % modulus;
        output[index] = coefficient as u32;
        rows.push([
            element(products[0][index]),
            element(products[1][index]),
            element(products[2][index]),
            element(products[3][index]),
            BaseElement::new(u128::from(sum_01)),
            BaseElement::new(u128::from(sum_012)),
            BaseElement::new(u128::from(coefficient)),
            BaseElement::new(u128::from(sum_01_full / modulus)),
            BaseElement::new(u128::from(sum_012_full / modulus)),
            BaseElement::new(u128::from(output_full / modulus)),
        ]);
    }
    rows.resize(TRACE_LENGTH, [BaseElement::ZERO; TRACE_WIDTH]);
    (AccumulationPublicInputs { rows }, output)
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

    fn operands() -> (Vector, Vector) {
        (
            core::array::from_fn(|vector_index| {
                core::array::from_fn(|index| {
                    (index as u32 * 17 + vector_index as u32 * 31 + 3) % ML_DSA_Q
                })
            }),
            core::array::from_fn(|vector_index| {
                core::array::from_fn(|index| {
                    (index as u32 * 29 + vector_index as u32 * 43 + 5) % ML_DSA_Q
                })
            }),
        )
    }

    #[test]
    fn vector_accumulation_composes_four_multiply_ntt_proofs() {
        let (left, right) = operands();
        let (proof, output) = prove_ml_dsa_vector_accumulation(&left, &right).unwrap();
        verify_ml_dsa_vector_accumulation(proof, &left, &right, &output).unwrap();
    }

    #[test]
    fn vector_accumulation_rejects_operand_output_and_range_substitution() {
        let (left, right) = operands();
        let (proof, mut output) = prove_ml_dsa_vector_accumulation(&left, &right).unwrap();
        output[19] = (output[19] + 1) % ML_DSA_Q;
        assert!(verify_ml_dsa_vector_accumulation(proof, &left, &right, &output).is_err());

        let (proof, output) = prove_ml_dsa_vector_accumulation(&left, &right).unwrap();
        let mut substituted = left;
        substituted[2][19] = (substituted[2][19] + 1) % ML_DSA_Q;
        assert!(verify_ml_dsa_vector_accumulation(proof, &substituted, &right, &output).is_err());
        substituted[0][0] = ML_DSA_Q;
        assert!(prove_ml_dsa_vector_accumulation(&substituted, &right).is_err());
    }
}
