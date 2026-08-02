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

pub const ML_DSA_Q: u32 = 8_380_417;
pub const ML_DSA_NTT_COEFFICIENTS: usize = 256;
const BUTTERFLIES: usize = 1024;
const TRACE_LENGTH: usize = 2048;
const A: usize = 0;
const B: usize = 1;
const ZETA: usize = 2;
const PRODUCT_REMAINDER: usize = 3;
const OUTPUT_A: usize = 4;
const OUTPUT_B: usize = 5;
const PRODUCT_QUOTIENT: usize = 6;
const ADD_QUOTIENT: usize = 7;
const SUB_QUOTIENT: usize = 8;
const TRACE_WIDTH: usize = 9;

#[derive(Clone, Debug)]
struct NttPublicInputs {
    rows: Vec<[BaseElement; TRACE_WIDTH]>,
}

impl ToElements<BaseElement> for NttPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.rows.iter().flat_map(|row| row.iter().copied()).collect()
    }
}

struct NttAir {
    context: AirContext<BaseElement>,
    public: NttPublicInputs,
}

impl Air for NttAir {
    type BaseField = BaseElement;
    type PublicInputs = NttPublicInputs;

    fn new(trace_info: TraceInfo, public: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), TRACE_WIDTH);
        assert_eq!(trace_info.length(), TRACE_LENGTH);
        assert_eq!(public.rows.len(), TRACE_LENGTH);
        Self {
            context: AirContext::new(
                trace_info,
                vec![
                    TransitionConstraintDegree::new(2),
                    TransitionConstraintDegree::new(1),
                    TransitionConstraintDegree::new(1),
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
            current[ZETA] * current[B] - current[PRODUCT_REMAINDER] - q * current[PRODUCT_QUOTIENT];
        result[1] =
            current[A] + current[PRODUCT_REMAINDER] - current[OUTPUT_A] - q * current[ADD_QUOTIENT];
        result[2] =
            current[A] + q * current[SUB_QUOTIENT] - current[PRODUCT_REMAINDER] - current[OUTPUT_B];
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

struct NttProver {
    options: ProofOptions,
    public: NttPublicInputs,
}

impl Prover for NttProver {
    type BaseField = BaseElement;
    type Air = NttAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> NttPublicInputs {
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

pub struct MlDsaNttStarkProof {
    proof: Proof,
    public: NttPublicInputs,
}

pub fn prove_ml_dsa_ntt(
    input: &[u32; ML_DSA_NTT_COEFFICIENTS],
) -> Result<(MlDsaNttStarkProof, [u32; ML_DSA_NTT_COEFFICIENTS]), &'static str> {
    let (rows, output) = ntt_rows(input)?;
    let public = NttPublicInputs { rows };
    let trace = build_trace(&public);
    let prover = NttProver { options: proof_options(), public: public.clone() };
    let proof = prover.prove(trace).map_err(|_| "ML-DSA NTT proving failed")?;
    Ok((MlDsaNttStarkProof { proof, public }, output))
}

pub fn verify_ml_dsa_ntt(
    proof: MlDsaNttStarkProof,
    input: &[u32; ML_DSA_NTT_COEFFICIENTS],
    output: &[u32; ML_DSA_NTT_COEFFICIENTS],
) -> Result<(), &'static str> {
    let (rows, expected_output) = ntt_rows(input)?;
    if &expected_output != output {
        return Err("ML-DSA NTT output mismatch");
    }
    let expected = NttPublicInputs { rows };
    if proof.public.to_elements() != expected.to_elements() {
        return Err("ML-DSA NTT public trace mismatch");
    }
    winterfell::verify::<
        NttAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof.proof, expected, &AcceptableOptions::MinConjecturedSecurity(100))
    .map_err(|_| "ML-DSA NTT verification failed")
}

fn build_trace(public: &NttPublicInputs) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (row, values) in public.rows.iter().enumerate() {
        for (column, value) in values.iter().copied().enumerate() {
            trace.set(column, row, value);
        }
    }
    trace
}

fn ntt_rows(
    input: &[u32; ML_DSA_NTT_COEFFICIENTS],
) -> Result<(Vec<[BaseElement; TRACE_WIDTH]>, [u32; ML_DSA_NTT_COEFFICIENTS]), &'static str> {
    if input.iter().any(|coefficient| *coefficient >= ML_DSA_Q) {
        return Err("ML-DSA NTT coefficient is outside Z_q");
    }
    let zetas = zeta_powers_bit_reversed();
    let mut coefficients = *input;
    let mut rows = Vec::with_capacity(TRACE_LENGTH);
    let mut twiddle = 0_usize;
    let mut length = 128_usize;
    while length >= 1 {
        for start in (0..ML_DSA_NTT_COEFFICIENTS).step_by(2 * length) {
            twiddle += 1;
            let zeta = u64::from(zetas[twiddle]);
            for index in start..start + length {
                let a = u64::from(coefficients[index]);
                let b = u64::from(coefficients[index + length]);
                let product = zeta * b;
                let remainder = product % u64::from(ML_DSA_Q);
                let product_quotient = product / u64::from(ML_DSA_Q);
                let sum = a + remainder;
                let output_a = sum % u64::from(ML_DSA_Q);
                let add_quotient = sum / u64::from(ML_DSA_Q);
                let sub_quotient = u64::from(a < remainder);
                let output_b = a + sub_quotient * u64::from(ML_DSA_Q) - remainder;
                rows.push([
                    element(a),
                    element(b),
                    element(zeta),
                    element(remainder),
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
        length /= 2;
    }
    debug_assert_eq!(rows.len(), BUTTERFLIES);
    rows.resize(TRACE_LENGTH, [BaseElement::ZERO; TRACE_WIDTH]);
    Ok((rows, coefficients))
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
    use super::*;

    fn input() -> [u32; ML_DSA_NTT_COEFFICIENTS] {
        core::array::from_fn(|index| {
            ((index as u64 * index as u64 + 17) % u64::from(ML_DSA_Q)) as u32
        })
    }

    fn inverse_ntt_reference(
        input: &[u32; ML_DSA_NTT_COEFFICIENTS],
    ) -> [u32; ML_DSA_NTT_COEFFICIENTS] {
        let zetas = zeta_powers_bit_reversed();
        let modulus = u64::from(ML_DSA_Q);
        let mut coefficients = *input;
        let mut twiddle = 256_usize;
        let mut length = 1_usize;
        while length <= 128 {
            for start in (0..ML_DSA_NTT_COEFFICIENTS).step_by(2 * length) {
                twiddle -= 1;
                let zeta = (modulus - u64::from(zetas[twiddle])) % modulus;
                for index in start..start + length {
                    let a = u64::from(coefficients[index]);
                    let b = u64::from(coefficients[index + length]);
                    coefficients[index] = ((a + b) % modulus) as u32;
                    coefficients[index + length] =
                        (zeta * ((a + modulus - b) % modulus) % modulus) as u32;
                }
            }
            length *= 2;
        }
        for coefficient in &mut coefficients {
            *coefficient = (u64::from(*coefficient) * 8_347_681 % modulus) as u32;
        }
        coefficients
    }

    #[test]
    fn forward_ntt_air_proves_exact_fips_butterfly_schedule() {
        let input = input();
        let (proof, output) = prove_ml_dsa_ntt(&input).unwrap();
        assert_eq!(inverse_ntt_reference(&output), input);
        verify_ml_dsa_ntt(proof, &input, &output).unwrap();
    }

    #[test]
    fn forward_ntt_air_rejects_input_and_output_substitution() {
        let input = input();
        let (proof, output) = prove_ml_dsa_ntt(&input).unwrap();
        let mut substituted_output = output;
        substituted_output[7] = (substituted_output[7] + 1) % ML_DSA_Q;
        assert!(verify_ml_dsa_ntt(proof, &input, &substituted_output).is_err());

        let (proof, output) = prove_ml_dsa_ntt(&input).unwrap();
        let mut substituted_input = input;
        substituted_input[7] = (substituted_input[7] + 1) % ML_DSA_Q;
        assert!(verify_ml_dsa_ntt(proof, &substituted_input, &output).is_err());
        let (mut proof, output) = prove_ml_dsa_ntt(&input).unwrap();
        proof.public.rows[0][ZETA] += BaseElement::ONE;
        assert!(verify_ml_dsa_ntt(proof, &input, &output).is_err());
        let mut invalid = input;
        invalid[0] = ML_DSA_Q;
        assert!(prove_ml_dsa_ntt(&invalid).is_err());
    }
}
