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

use crate::{ML_DSA_44_VECTOR_DIMENSION, ML_DSA_NTT_COEFFICIENTS, ML_DSA_Q};

const TRACE_LENGTH: usize = 1024;
const LEFT: usize = 0;
const RIGHT: usize = 1;
const OUTPUT: usize = 2;
const BORROW: usize = 3;
const TRACE_WIDTH: usize = 4;

type Polynomial = [u32; ML_DSA_NTT_COEFFICIENTS];
type Vector = [Polynomial; ML_DSA_44_VECTOR_DIMENSION];

#[derive(Clone, Debug)]
struct SubtractPublicInputs {
    rows: Vec<[BaseElement; TRACE_WIDTH]>,
}

impl ToElements<BaseElement> for SubtractPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.rows.iter().flat_map(|row| row.iter().copied()).collect()
    }
}

struct SubtractAir {
    context: AirContext<BaseElement>,
    public: SubtractPublicInputs,
}

impl Air for SubtractAir {
    type BaseField = BaseElement;
    type PublicInputs = SubtractPublicInputs;

    fn new(trace_info: TraceInfo, public: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), TRACE_WIDTH);
        assert_eq!(trace_info.length(), TRACE_LENGTH);
        assert_eq!(public.rows.len(), TRACE_LENGTH);
        Self {
            context: AirContext::new(
                trace_info,
                vec![TransitionConstraintDegree::new(1), TransitionConstraintDegree::new(2)],
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
        let row = frame.current();
        let q = E::from(BaseElement::new(u128::from(ML_DSA_Q)));
        result[0] = row[LEFT] - row[RIGHT] - row[OUTPUT] + q * row[BORROW];
        result[1] = row[BORROW] * (row[BORROW] - E::ONE);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::with_capacity(TRACE_LENGTH * TRACE_WIDTH);
        for (row_index, row) in self.public.rows.iter().enumerate() {
            for (column, value) in row.iter().copied().enumerate() {
                assertions.push(Assertion::single(column, row_index, value));
            }
        }
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct SubtractProver {
    options: ProofOptions,
    public: SubtractPublicInputs,
}

impl Prover for SubtractProver {
    type BaseField = BaseElement;
    type Air = SubtractAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> SubtractPublicInputs {
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
pub struct MlDsa44VectorSubtractStarkProof {
    proof: Proof,
    public: SubtractPublicInputs,
}

pub fn prove_ml_dsa44_vector_subtract(
    left: &Vector,
    right: &Vector,
) -> Result<(MlDsa44VectorSubtractStarkProof, Vector), &'static str> {
    let (public, output) = public_inputs(left, right)?;
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (row_index, row) in public.rows.iter().enumerate() {
        for (column, value) in row.iter().copied().enumerate() {
            trace.set(column, row_index, value);
        }
    }
    let prover = SubtractProver { options: proof_options(), public: public.clone() };
    let proof = prover.prove(trace).map_err(|_| "ML-DSA vector subtraction proving failed")?;
    Ok((MlDsa44VectorSubtractStarkProof { proof, public }, output))
}

pub fn verify_ml_dsa44_vector_subtract(
    proof: MlDsa44VectorSubtractStarkProof,
    left: &Vector,
    right: &Vector,
    output: &Vector,
) -> Result<(), &'static str> {
    let (expected, expected_output) = public_inputs(left, right)?;
    if &expected_output != output || proof.public.to_elements() != expected.to_elements() {
        return Err("ML-DSA vector subtraction public inputs mismatch");
    }
    winterfell::verify::<
        SubtractAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof.proof, expected, &AcceptableOptions::MinConjecturedSecurity(100))
    .map_err(|_| "ML-DSA vector subtraction verification failed")
}

fn public_inputs(
    left: &Vector,
    right: &Vector,
) -> Result<(SubtractPublicInputs, Vector), &'static str> {
    let mut rows = Vec::with_capacity(TRACE_LENGTH);
    let mut output = [[0_u32; ML_DSA_NTT_COEFFICIENTS]; ML_DSA_44_VECTOR_DIMENSION];
    for polynomial in 0..ML_DSA_44_VECTOR_DIMENSION {
        for coefficient in 0..ML_DSA_NTT_COEFFICIENTS {
            let left_value = left[polynomial][coefficient];
            let right_value = right[polynomial][coefficient];
            if left_value >= ML_DSA_Q || right_value >= ML_DSA_Q {
                return Err("ML-DSA vector subtraction coefficient is outside Z_q");
            }
            let (value, borrow) = if left_value >= right_value {
                (left_value - right_value, false)
            } else {
                (left_value + ML_DSA_Q - right_value, true)
            };
            output[polynomial][coefficient] = value;
            rows.push([
                element(left_value),
                element(right_value),
                element(value),
                element(u32::from(borrow)),
            ]);
        }
    }
    Ok((SubtractPublicInputs { rows }, output))
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
            core::array::from_fn(|polynomial| {
                core::array::from_fn(|index| {
                    (index as u32 * 17 + polynomial as u32 * 101 + 3) % ML_DSA_Q
                })
            }),
            core::array::from_fn(|polynomial| {
                core::array::from_fn(|index| {
                    (index as u32 * 29 + polynomial as u32 * 67 + 5) % ML_DSA_Q
                })
            }),
        )
    }

    #[test]
    fn vector_subtraction_proves_borrow_and_nonborrow_rows() {
        let (left, right) = operands();
        let (proof, output) = prove_ml_dsa44_vector_subtract(&left, &right).unwrap();
        verify_ml_dsa44_vector_subtract(proof, &left, &right, &output).unwrap();
    }

    #[test]
    fn vector_subtraction_rejects_statement_and_range_substitution() {
        let (left, right) = operands();
        let (proof, output) = prove_ml_dsa44_vector_subtract(&left, &right).unwrap();
        let mut substituted = output;
        substituted[2][19] = (substituted[2][19] + 1) % ML_DSA_Q;
        assert!(
            verify_ml_dsa44_vector_subtract(proof.clone(), &left, &right, &substituted).is_err()
        );
        let mut substituted_left = left;
        substituted_left[2][19] = (substituted_left[2][19] + 1) % ML_DSA_Q;
        assert!(
            verify_ml_dsa44_vector_subtract(proof, &substituted_left, &right, &output).is_err()
        );
        substituted_left[0][0] = ML_DSA_Q;
        assert!(prove_ml_dsa44_vector_subtract(&substituted_left, &right).is_err());
    }
}
