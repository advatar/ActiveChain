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

use crate::{ML_DSA_NTT_COEFFICIENTS, ML_DSA_Q, ML_DSA44_VECTOR_DIMENSION};

const TWO_GAMMA_2: u32 = 190_464;
const GAMMA_2: u32 = TWO_GAMMA_2 / 2;
const HIGH_MODULUS: u32 = (ML_DSA_Q - 1) / TWO_GAMMA_2;
const VERIFIER_ROWS: usize = ML_DSA44_VECTOR_DIMENSION * ML_DSA_NTT_COEFFICIENTS;
const TRACE_LENGTH: usize = 2048;
const INPUT: usize = 0;
const HINT: usize = 1;
const HIGH: usize = 2;
const LOW_ABS: usize = 3;
const LOW_POSITIVE: usize = 4;
const EDGE: usize = 5;
const OUTPUT: usize = 6;
const INC_WRAP: usize = 7;
const DEC_WRAP: usize = 8;
const TRACE_WIDTH: usize = 9;

type Polynomial = [u32; ML_DSA_NTT_COEFFICIENTS];
type Vector = [Polynomial; ML_DSA44_VECTOR_DIMENSION];
type HintVector = [[bool; ML_DSA_NTT_COEFFICIENTS]; ML_DSA44_VECTOR_DIMENSION];

#[derive(Clone, Debug)]
struct UseHintPublicInputs {
    rows: Vec<[BaseElement; TRACE_WIDTH]>,
}

impl ToElements<BaseElement> for UseHintPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.rows.iter().flat_map(|row| row.iter().copied()).collect()
    }
}

struct UseHintAir {
    context: AirContext<BaseElement>,
    public: UseHintPublicInputs,
}

impl Air for UseHintAir {
    type BaseField = BaseElement;
    type PublicInputs = UseHintPublicInputs;

    fn new(trace_info: TraceInfo, public: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), TRACE_WIDTH);
        assert_eq!(trace_info.length(), TRACE_LENGTH);
        assert_eq!(public.rows.len(), TRACE_LENGTH);
        Self {
            context: AirContext::new(
                trace_info,
                vec![TransitionConstraintDegree::new(2); 6],
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
        let boolean = |value: E| value * (value - E::ONE);
        result[0] = boolean(row[HINT]);
        result[1] = boolean(row[LOW_POSITIVE]);
        result[2] = boolean(row[INC_WRAP]);
        result[3] = boolean(row[DEC_WRAP]);

        let two_gamma_2 = E::from(element(TWO_GAMMA_2));
        let q = E::from(element(ML_DSA_Q));
        let signed_low = row[LOW_ABS] * (row[LOW_POSITIVE] + row[LOW_POSITIVE] - E::ONE);
        result[4] = row[INPUT] - two_gamma_2 * row[HIGH] - signed_low - q * row[EDGE];

        let high_modulus = E::from(element(HIGH_MODULUS));
        let adjustment = row[HINT] * (row[LOW_POSITIVE] + row[LOW_POSITIVE] - E::ONE);
        result[5] =
            row[OUTPUT] - row[HIGH] - adjustment - high_modulus * (row[DEC_WRAP] - row[INC_WRAP]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::with_capacity(TRACE_LENGTH * TRACE_WIDTH);
        for (index, row) in self.public.rows.iter().enumerate() {
            for (column, value) in row.iter().copied().enumerate() {
                assertions.push(Assertion::single(column, index, value));
            }
        }
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct UseHintProver {
    options: ProofOptions,
    public: UseHintPublicInputs,
}

impl Prover for UseHintProver {
    type BaseField = BaseElement;
    type Air = UseHintAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> UseHintPublicInputs {
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
pub struct MlDsa44UseHintStarkProof {
    proof: Proof,
    public: UseHintPublicInputs,
}

pub fn prove_ml_dsa44_use_hint(
    input: &Vector,
    hints: &HintVector,
) -> Result<(MlDsa44UseHintStarkProof, Vector), &'static str> {
    let (public, output) = use_hint_public_inputs(input, hints)?;
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (row_index, row) in public.rows.iter().enumerate() {
        for (column, value) in row.iter().copied().enumerate() {
            trace.set(column, row_index, value);
        }
    }
    let prover = UseHintProver { options: proof_options(), public: public.clone() };
    let proof = prover.prove(trace).map_err(|_| "ML-DSA UseHint proving failed")?;
    Ok((MlDsa44UseHintStarkProof { proof, public }, output))
}

pub fn verify_ml_dsa44_use_hint(
    proof: MlDsa44UseHintStarkProof,
    input: &Vector,
    hints: &HintVector,
    output: &Vector,
) -> Result<(), &'static str> {
    let (expected, expected_output) = use_hint_public_inputs(input, hints)?;
    if &expected_output != output || proof.public.to_elements() != expected.to_elements() {
        return Err("ML-DSA UseHint public inputs mismatch");
    }
    winterfell::verify::<
        UseHintAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof.proof, expected, &AcceptableOptions::MinConjecturedSecurity(100))
    .map_err(|_| "ML-DSA UseHint verification failed")
}

fn use_hint_public_inputs(
    input: &Vector,
    hints: &HintVector,
) -> Result<(UseHintPublicInputs, Vector), &'static str> {
    let mut output = [[0_u32; ML_DSA_NTT_COEFFICIENTS]; ML_DSA44_VECTOR_DIMENSION];
    let mut rows = Vec::with_capacity(TRACE_LENGTH);
    for vector_index in 0..ML_DSA44_VECTOR_DIMENSION {
        for coefficient in 0..ML_DSA_NTT_COEFFICIENTS {
            let r = input[vector_index][coefficient];
            if r >= ML_DSA_Q {
                return Err("ML-DSA UseHint coefficient is outside Z_q");
            }
            let hint = hints[vector_index][coefficient];
            let (row, adjusted) = hint_row(r, hint);
            output[vector_index][coefficient] = adjusted;
            rows.push(row);
        }
    }
    debug_assert_eq!(rows.len(), VERIFIER_ROWS);
    let padding = [
        hint_row(43 * TWO_GAMMA_2 + 1, true).0,
        hint_row(ML_DSA_Q - 1, true).0,
        hint_row(0, false).0,
        hint_row(GAMMA_2, false).0,
    ];
    while rows.len() < TRACE_LENGTH {
        rows.push(padding[(rows.len() - VERIFIER_ROWS) % padding.len()]);
    }
    Ok((UseHintPublicInputs { rows }, output))
}

fn hint_row(r: u32, hint: bool) -> ([BaseElement; TRACE_WIDTH], u32) {
    let (high, low_abs, low_positive, edge) = decompose(r);
    let inc_wrap = hint && low_positive && high + 1 == HIGH_MODULUS;
    let dec_wrap = hint && !low_positive && high == 0;
    let adjusted = if !hint {
        high
    } else if low_positive {
        (high + 1) % HIGH_MODULUS
    } else {
        (high + HIGH_MODULUS - 1) % HIGH_MODULUS
    };
    (
        [
            element(r),
            element(u32::from(hint)),
            element(high),
            element(low_abs),
            element(u32::from(low_positive)),
            element(u32::from(edge)),
            element(adjusted),
            element(u32::from(inc_wrap)),
            element(u32::from(dec_wrap)),
        ],
        adjusted,
    )
}

fn decompose(r: u32) -> (u32, u32, bool, bool) {
    if r >= ML_DSA_Q - GAMMA_2 {
        return (0, ML_DSA_Q - r, false, true);
    }
    // `mod±` selects the positive representative at the exact gamma2 tie.
    let high = (r + GAMMA_2 - 1) / TWO_GAMMA_2;
    let center = high * TWO_GAMMA_2;
    if r > center { (high, r - center, true, false) } else { (high, center - r, false, false) }
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

    fn inputs() -> (Vector, HintVector) {
        let boundaries = [
            0,
            1,
            GAMMA_2,
            GAMMA_2 + 1,
            TWO_GAMMA_2,
            ML_DSA_Q - GAMMA_2 - 2,
            ML_DSA_Q - 2,
            ML_DSA_Q - 1,
        ];
        (
            core::array::from_fn(|vector| {
                core::array::from_fn(|index| {
                    if index < boundaries.len() {
                        boundaries[index]
                    } else {
                        (index as u32 * 32_771 + vector as u32 * 97_531) % ML_DSA_Q
                    }
                })
            }),
            core::array::from_fn(|vector| core::array::from_fn(|index| (index + vector) % 3 != 0)),
        )
    }

    #[test]
    fn use_hint_proves_all_branches_and_wraparound() {
        let (input, hints) = inputs();
        let (proof, output) = prove_ml_dsa44_use_hint(&input, &hints).unwrap();
        assert_eq!(decompose(GAMMA_2), (0, GAMMA_2, true, false));
        assert_eq!(decompose(GAMMA_2 + 1), (1, GAMMA_2 - 1, false, false));
        assert_eq!(output[1][0], 43);
        assert_eq!(output[0][3], 1);
        assert_eq!(output[0][5], 0);
        assert_eq!(output[0][7], 43);
        verify_ml_dsa44_use_hint(proof, &input, &hints, &output).unwrap();
    }

    #[test]
    fn use_hint_rejects_substitution_and_noncanonical_input() {
        let (input, hints) = inputs();
        let (proof, mut output) = prove_ml_dsa44_use_hint(&input, &hints).unwrap();
        output[2][19] = (output[2][19] + 1) % HIGH_MODULUS;
        assert!(verify_ml_dsa44_use_hint(proof, &input, &hints, &output).is_err());

        let mut invalid = input;
        invalid[1][7] = ML_DSA_Q;
        assert!(prove_ml_dsa44_use_hint(&invalid, &hints).is_err());
    }

    #[test]
    fn decomposition_matches_mod_plus_minus_for_every_field_element() {
        for r in 0..ML_DSA_Q {
            let (high, low_abs, low_positive, edge) = decompose(r);
            let raw = r % TWO_GAMMA_2;
            let (expected_abs, expected_positive) =
                if raw <= GAMMA_2 { (raw, raw != 0) } else { (TWO_GAMMA_2 - raw, false) };
            if r >= ML_DSA_Q - GAMMA_2 {
                assert_eq!((high, low_abs, low_positive, edge), (0, ML_DSA_Q - r, false, true));
            } else {
                assert_eq!((low_abs, low_positive, edge), (expected_abs, expected_positive, false));
                assert!(high < HIGH_MODULUS);
            }
        }
    }
}
