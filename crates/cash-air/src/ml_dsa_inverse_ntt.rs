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

const TRACE_LENGTH: usize = 2048;
const A: usize = 0;
const B: usize = 1;
const ZETA: usize = 2;
const DIFFERENCE: usize = 3;
const OUTPUT_A: usize = 4;
const OUTPUT_B: usize = 5;
const PRODUCT_QUOTIENT: usize = 6;
const ADD_QUOTIENT: usize = 7;
const SUB_QUOTIENT: usize = 8;
const TRACE_WIDTH: usize = 9;
const INVERSE_256: u32 = 8_347_681;

#[derive(Clone, Debug)]
struct InversePublicInputs {
    rows: Vec<[BaseElement; TRACE_WIDTH]>,
}

impl ToElements<BaseElement> for InversePublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.rows.iter().flat_map(|row| row.iter().copied()).collect()
    }
}

struct InverseAir {
    context: AirContext<BaseElement>,
    public: InversePublicInputs,
}

impl Air for InverseAir {
    type BaseField = BaseElement;
    type PublicInputs = InversePublicInputs;

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
        result[0] = current[A] + current[B] - current[OUTPUT_A] - q * current[ADD_QUOTIENT];
        result[1] = current[A] + q * current[SUB_QUOTIENT] - current[B] - current[DIFFERENCE];
        result[2] =
            current[ZETA] * current[DIFFERENCE] - current[OUTPUT_B] - q * current[PRODUCT_QUOTIENT];
        result[3] = current[ADD_QUOTIENT] * (current[ADD_QUOTIENT] - E::ONE);
        result[4] = current[SUB_QUOTIENT] * (current[SUB_QUOTIENT] - E::ONE);
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

struct InverseProver {
    options: ProofOptions,
    public: InversePublicInputs,
}

impl Prover for InverseProver {
    type BaseField = BaseElement;
    type Air = InverseAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> InversePublicInputs {
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

struct InverseButterflyProof {
    proof: Proof,
    public: InversePublicInputs,
}

pub struct MlDsaInverseNttStarkProof {
    butterflies: InverseButterflyProof,
    scaling: MlDsaNttMultiplyStarkProof,
}

pub fn prove_ml_dsa_inverse_ntt(
    input: &[u32; ML_DSA_NTT_COEFFICIENTS],
) -> Result<(MlDsaInverseNttStarkProof, [u32; ML_DSA_NTT_COEFFICIENTS]), &'static str> {
    let (public, unscaled) = inverse_rows(input)?;
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (row, values) in public.rows.iter().enumerate() {
        for (column, value) in values.iter().copied().enumerate() {
            trace.set(column, row, value);
        }
    }
    let prover = InverseProver { options: proof_options(), public: public.clone() };
    let proof = prover.prove(trace).map_err(|_| "ML-DSA inverse NTT proving failed")?;
    let scaling_factors = [INVERSE_256; ML_DSA_NTT_COEFFICIENTS];
    let (scaling, output) = prove_ml_dsa_ntt_multiply(&unscaled, &scaling_factors)?;
    Ok((
        MlDsaInverseNttStarkProof { butterflies: InverseButterflyProof { proof, public }, scaling },
        output,
    ))
}

pub fn verify_ml_dsa_inverse_ntt(
    proof: MlDsaInverseNttStarkProof,
    input: &[u32; ML_DSA_NTT_COEFFICIENTS],
    output: &[u32; ML_DSA_NTT_COEFFICIENTS],
) -> Result<(), &'static str> {
    let (expected, unscaled) = inverse_rows(input)?;
    if proof.butterflies.public.to_elements() != expected.to_elements() {
        return Err("ML-DSA inverse NTT public trace mismatch");
    }
    winterfell::verify::<
        InverseAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof.butterflies.proof, expected, &AcceptableOptions::MinConjecturedSecurity(100))
    .map_err(|_| "ML-DSA inverse NTT verification failed")?;
    let scaling_factors = [INVERSE_256; ML_DSA_NTT_COEFFICIENTS];
    verify_ml_dsa_ntt_multiply(proof.scaling, &unscaled, &scaling_factors, output)
}

fn inverse_rows(
    input: &[u32; ML_DSA_NTT_COEFFICIENTS],
) -> Result<(InversePublicInputs, [u32; ML_DSA_NTT_COEFFICIENTS]), &'static str> {
    if input.iter().any(|coefficient| *coefficient >= ML_DSA_Q) {
        return Err("ML-DSA inverse NTT coefficient is outside Z_q");
    }
    let modulus = u64::from(ML_DSA_Q);
    let zetas = zeta_powers_bit_reversed();
    let mut coefficients = *input;
    let mut rows = Vec::with_capacity(TRACE_LENGTH);
    let mut twiddle = 256_usize;
    let mut length = 1_usize;
    while length <= 128 {
        for start in (0..ML_DSA_NTT_COEFFICIENTS).step_by(2 * length) {
            twiddle -= 1;
            let zeta = (modulus - u64::from(zetas[twiddle])) % modulus;
            for index in start..start + length {
                let a = u64::from(coefficients[index]);
                let b = u64::from(coefficients[index + length]);
                let sum = a + b;
                let output_a = sum % modulus;
                let add_quotient = sum / modulus;
                let sub_quotient = u64::from(a < b);
                let difference = a + sub_quotient * modulus - b;
                let product = zeta * difference;
                let output_b = product % modulus;
                let product_quotient = product / modulus;
                rows.push([
                    element(a),
                    element(b),
                    element(zeta),
                    element(difference),
                    element(output_a),
                    element(output_b),
                    element(product_quotient),
                    element(add_quotient),
                    element(sub_quotient),
                ]);
                coefficients[index] = output_a as u32;
                coefficients[index + length] = output_b as u32;
            }
        }
        length *= 2;
    }
    rows.resize(TRACE_LENGTH, [BaseElement::ZERO; TRACE_WIDTH]);
    Ok((InversePublicInputs { rows }, coefficients))
}

fn element(value: u64) -> BaseElement {
    BaseElement::new(u128::from(value))
}

fn zeta_powers_bit_reversed() -> [u32; ML_DSA_NTT_COEFFICIENTS] {
    let mut powers = [0_u32; ML_DSA_NTT_COEFFICIENTS];
    let mut natural = [0_u32; ML_DSA_NTT_COEFFICIENTS];
    let mut current = 1_u64;
    for value in &mut natural {
        *value = current as u32;
        current = (current * 1753) % u64::from(ML_DSA_Q);
    }
    for index in 1..ML_DSA_NTT_COEFFICIENTS {
        powers[index] = natural[(index as u8).reverse_bits() as usize];
    }
    powers
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
    use crate::{prove_ml_dsa_ntt, verify_ml_dsa_ntt};

    use super::*;

    fn polynomial() -> [u32; ML_DSA_NTT_COEFFICIENTS] {
        core::array::from_fn(|index| ((index as u64 * 41 + 19) % u64::from(ML_DSA_Q)) as u32)
    }

    #[test]
    fn inverse_ntt_air_composes_butterflies_and_scaling() {
        let polynomial = polynomial();
        let (forward_proof, transformed) = prove_ml_dsa_ntt(&polynomial).unwrap();
        verify_ml_dsa_ntt(forward_proof, &polynomial, &transformed).unwrap();
        let (inverse_proof, output) = prove_ml_dsa_inverse_ntt(&transformed).unwrap();
        assert_eq!(output, polynomial);
        verify_ml_dsa_inverse_ntt(inverse_proof, &transformed, &output).unwrap();
    }

    #[test]
    fn inverse_ntt_air_rejects_input_output_and_range_substitution() {
        let polynomial = polynomial();
        let (_, transformed) = prove_ml_dsa_ntt(&polynomial).unwrap();
        let (proof, mut output) = prove_ml_dsa_inverse_ntt(&transformed).unwrap();
        output[13] = (output[13] + 1) % ML_DSA_Q;
        assert!(verify_ml_dsa_inverse_ntt(proof, &transformed, &output).is_err());

        let (proof, output) = prove_ml_dsa_inverse_ntt(&transformed).unwrap();
        let mut substituted = transformed;
        substituted[13] = (substituted[13] + 1) % ML_DSA_Q;
        assert!(verify_ml_dsa_inverse_ntt(proof, &substituted, &output).is_err());
        substituted[0] = ML_DSA_Q;
        assert!(prove_ml_dsa_inverse_ntt(&substituted).is_err());
    }
}
