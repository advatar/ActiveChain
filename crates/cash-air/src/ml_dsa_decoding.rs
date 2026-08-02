use alloc::{vec, vec::Vec};

use activechain_protocol_types::ML_DSA44_PUBLIC_KEY_LENGTH;
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

pub const ML_DSA44_SIGNATURE_LENGTH: usize = 2_420;
pub const ML_DSA44_VECTOR_DIMENSION: usize = 4;

const SEED_LENGTH: usize = 32;
const HINT_WEIGHT_LIMIT: usize = 80;
const HINT_ENCODING_LENGTH: usize = HINT_WEIGHT_LIMIT + ML_DSA44_VECTOR_DIMENSION;
const T1_BITS: usize = 10;
const Z_BITS: usize = 18;
const SLACK_BIT_COUNT: usize = 17;
const Z_ENCODED_LENGTH: usize = ML_DSA44_VECTOR_DIMENSION * ML_DSA_NTT_COEFFICIENTS * Z_BITS / 8;
const Z_OFFSET: usize = SEED_LENGTH;
const HINT_OFFSET: usize = Z_OFFSET + Z_ENCODED_LENGTH;
const GAMMA1: u32 = 1 << 17;
const BETA: u32 = 39 * 2;
const Z_MAGNITUDE_LIMIT: u32 = GAMMA1 - BETA - 1;
const TRACE_LENGTH: usize = 2_048;

const IS_Z: usize = 0;
const COEFFICIENT: usize = 1;
const SIGN: usize = 2;
const MAGNITUDE: usize = 3;
const ENCODED_BITS: usize = 4;
const SLACK_BITS: usize = ENCODED_BITS + Z_BITS;
const TRACE_WIDTH: usize = SLACK_BITS + SLACK_BIT_COUNT;
const CONSTRAINTS: usize = 49;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsa44DecodedVerifierInputs {
    pub rho: [u8; SEED_LENGTH],
    pub challenge_seed: [u8; SEED_LENGTH],
    pub t1: [[u16; ML_DSA_NTT_COEFFICIENTS]; ML_DSA44_VECTOR_DIMENSION],
    pub z: [[u32; ML_DSA_NTT_COEFFICIENTS]; ML_DSA44_VECTOR_DIMENSION],
    pub hints: [[bool; ML_DSA_NTT_COEFFICIENTS]; ML_DSA44_VECTOR_DIMENSION],
    pub hint_weight: u8,
}

#[derive(Clone, Debug)]
struct DecodePublicInputs {
    key: Vec<BaseElement>,
    signature: Vec<BaseElement>,
    rows: Vec<[BaseElement; TRACE_WIDTH]>,
}

impl ToElements<BaseElement> for DecodePublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.key
            .iter()
            .chain(&self.signature)
            .copied()
            .chain(self.rows.iter().flat_map(|row| row.iter().copied()))
            .collect()
    }
}

struct DecodeAir {
    context: AirContext<BaseElement>,
    public: DecodePublicInputs,
}

impl Air for DecodeAir {
    type BaseField = BaseElement;
    type PublicInputs = DecodePublicInputs;

    fn new(trace_info: TraceInfo, public: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), TRACE_WIDTH);
        assert_eq!(trace_info.length(), TRACE_LENGTH);
        assert_eq!(public.key.len(), ML_DSA44_PUBLIC_KEY_LENGTH);
        assert_eq!(public.signature.len(), ML_DSA44_SIGNATURE_LENGTH);
        assert_eq!(public.rows.len(), TRACE_LENGTH);
        Self {
            context: AirContext::new(
                trace_info,
                constraint_degrees(),
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
        let one_minus_z = E::ONE - current[IS_Z];
        let two = E::from(2_u32);
        let gamma1 = E::from(GAMMA1);
        let modulus = E::from(ML_DSA_Q);
        let magnitude_limit = E::from(Z_MAGNITUDE_LIMIT);

        result[0] = current[IS_Z] * (current[IS_Z] - E::ONE);
        result[1] = current[SIGN] * (current[SIGN] - E::ONE);

        let mut encoded = E::ZERO;
        let mut slack = E::ZERO;
        let mut weight = E::ONE;
        for bit in 0..Z_BITS {
            encoded += current[ENCODED_BITS + bit] * weight;
            if bit < SLACK_BIT_COUNT {
                slack += current[SLACK_BITS + bit] * weight;
            }
            weight = weight.double();
        }
        result[2] = current[IS_Z]
            * (encoded - gamma1 - two * current[SIGN] * current[MAGNITUDE] + current[MAGNITUDE]);
        result[3] = current[IS_Z]
            * (current[COEFFICIENT] - current[MAGNITUDE] - current[SIGN] * modulus
                + two * current[SIGN] * current[MAGNITUDE]);
        result[4] = current[IS_Z] * (current[MAGNITUDE] + slack - magnitude_limit);
        result[5] = one_minus_z * (current[COEFFICIENT] - encoded);

        for bit in T1_BITS..Z_BITS {
            result[6 + bit - T1_BITS] = one_minus_z * current[ENCODED_BITS + bit];
        }
        let boolean_start = 6 + (Z_BITS - T1_BITS);
        for bit in 0..Z_BITS {
            let encoded_bit = current[ENCODED_BITS + bit];
            result[boolean_start + bit] = encoded_bit * (encoded_bit - E::ONE);
        }
        for bit in 0..SLACK_BIT_COUNT {
            let slack_bit = current[SLACK_BITS + bit];
            result[boolean_start + Z_BITS + bit] = slack_bit * (slack_bit - E::ONE);
        }
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

struct DecodeProver {
    options: ProofOptions,
    public: DecodePublicInputs,
}

impl Prover for DecodeProver {
    type BaseField = BaseElement;
    type Air = DecodeAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> DecodePublicInputs {
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

#[derive(Clone)]
pub struct MlDsa44DecodingStarkProof {
    proof: Proof,
    public: DecodePublicInputs,
}

pub fn prove_ml_dsa44_decoding(
    key: &[u8; ML_DSA44_PUBLIC_KEY_LENGTH],
    signature: &[u8; ML_DSA44_SIGNATURE_LENGTH],
) -> Result<(MlDsa44DecodingStarkProof, MlDsa44DecodedVerifierInputs), &'static str> {
    let (public, decoded) = public_inputs(key, signature)?;
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (row, values) in public.rows.iter().enumerate() {
        for (column, value) in values.iter().copied().enumerate() {
            trace.set(column, row, value);
        }
    }
    let prover = DecodeProver { options: proof_options(), public: public.clone() };
    let proof = prover.prove(trace).map_err(|_| "ML-DSA-44 decoding proving failed")?;
    Ok((MlDsa44DecodingStarkProof { proof, public }, decoded))
}

pub fn verify_ml_dsa44_decoding(
    proof: MlDsa44DecodingStarkProof,
    key: &[u8; ML_DSA44_PUBLIC_KEY_LENGTH],
    signature: &[u8; ML_DSA44_SIGNATURE_LENGTH],
    decoded: &MlDsa44DecodedVerifierInputs,
) -> Result<(), &'static str> {
    let (expected, expected_decoded) = public_inputs(key, signature)?;
    if &expected_decoded != decoded || proof.public.to_elements() != expected.to_elements() {
        return Err("ML-DSA-44 decoding public inputs mismatch");
    }
    winterfell::verify::<
        DecodeAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof.proof, expected, &AcceptableOptions::MinConjecturedSecurity(100))
    .map_err(|_| "ML-DSA-44 decoding verification failed")
}

fn public_inputs(
    key: &[u8; ML_DSA44_PUBLIC_KEY_LENGTH],
    signature: &[u8; ML_DSA44_SIGNATURE_LENGTH],
) -> Result<(DecodePublicInputs, MlDsa44DecodedVerifierInputs), &'static str> {
    let mut rho = [0_u8; SEED_LENGTH];
    rho.copy_from_slice(&key[..SEED_LENGTH]);
    let mut challenge_seed = [0_u8; SEED_LENGTH];
    challenge_seed.copy_from_slice(&signature[..SEED_LENGTH]);
    let mut t1 = [[0_u16; ML_DSA_NTT_COEFFICIENTS]; ML_DSA44_VECTOR_DIMENSION];
    let mut z = [[0_u32; ML_DSA_NTT_COEFFICIENTS]; ML_DSA44_VECTOR_DIMENSION];
    let mut rows = Vec::with_capacity(TRACE_LENGTH);

    let packed_t1 = &key[SEED_LENGTH..];
    for (vector_index, polynomial) in t1.iter_mut().enumerate() {
        for (coefficient_index, coefficient) in polynomial.iter_mut().enumerate() {
            let flat_index = vector_index * ML_DSA_NTT_COEFFICIENTS + coefficient_index;
            let encoded = read_bits(packed_t1, flat_index * T1_BITS, T1_BITS);
            *coefficient = encoded as u16;
            rows.push(row(false, encoded, encoded, false, 0, 0));
        }
    }

    let packed_z = &signature[Z_OFFSET..HINT_OFFSET];
    for (vector_index, polynomial) in z.iter_mut().enumerate() {
        for (coefficient_index, coefficient_slot) in polynomial.iter_mut().enumerate() {
            let flat_index = vector_index * ML_DSA_NTT_COEFFICIENTS + coefficient_index;
            let encoded = read_bits(packed_z, flat_index * Z_BITS, Z_BITS);
            let negative = encoded > GAMMA1;
            let magnitude = if negative { encoded - GAMMA1 } else { GAMMA1 - encoded };
            if magnitude > Z_MAGNITUDE_LIMIT {
                return Err("ML-DSA-44 z coefficient violates the infinity-norm bound");
            }
            let coefficient = if negative { ML_DSA_Q - magnitude } else { magnitude };
            let slack = Z_MAGNITUDE_LIMIT - magnitude;
            *coefficient_slot = coefficient;
            rows.push(row(true, encoded, coefficient, negative, magnitude, slack));
        }
    }

    let (hints, hint_weight) = decode_hints(&signature[HINT_OFFSET..])?;
    let decoded = MlDsa44DecodedVerifierInputs {
        rho,
        challenge_seed,
        t1,
        z,
        hints,
        hint_weight: hint_weight as u8,
    };
    let public = DecodePublicInputs {
        key: key.iter().copied().map(element).collect(),
        signature: signature.iter().copied().map(element).collect(),
        rows,
    };
    Ok((public, decoded))
}

fn decode_hints(
    encoded: &[u8],
) -> Result<([[bool; ML_DSA_NTT_COEFFICIENTS]; ML_DSA44_VECTOR_DIMENSION], usize), &'static str> {
    if encoded.len() != HINT_ENCODING_LENGTH {
        return Err("invalid ML-DSA-44 hint encoding length");
    }
    let (indices, cuts) = encoded.split_at(HINT_WEIGHT_LIMIT);
    if !cuts.windows(2).all(|window| window[0] <= window[1]) {
        return Err("ML-DSA-44 hint cuts are not monotonic");
    }
    let weight = usize::from(cuts[ML_DSA44_VECTOR_DIMENSION - 1]);
    if weight > HINT_WEIGHT_LIMIT || indices[weight..].iter().any(|index| *index != 0) {
        return Err("ML-DSA-44 hint weight or padding is non-canonical");
    }
    let mut hints = [[false; ML_DSA_NTT_COEFFICIENTS]; ML_DSA44_VECTOR_DIMENSION];
    let mut start = 0_usize;
    for (polynomial, end) in cuts.iter().copied().map(usize::from).enumerate() {
        if !indices[start..end].windows(2).all(|window| window[0] < window[1]) {
            return Err("ML-DSA-44 hint indices are not strictly increasing");
        }
        for index in indices[start..end].iter().copied().map(usize::from) {
            hints[polynomial][index] = true;
        }
        start = end;
    }
    Ok((hints, weight))
}

fn row(
    is_z: bool,
    encoded: u32,
    coefficient: u32,
    negative: bool,
    magnitude: u32,
    slack: u32,
) -> [BaseElement; TRACE_WIDTH] {
    let mut row = [BaseElement::ZERO; TRACE_WIDTH];
    row[IS_Z] = element(u8::from(is_z));
    row[COEFFICIENT] = element(coefficient);
    row[SIGN] = element(u8::from(negative));
    row[MAGNITUDE] = element(magnitude);
    for bit in 0..Z_BITS {
        row[ENCODED_BITS + bit] = element((encoded >> bit) & 1);
    }
    for bit in 0..SLACK_BIT_COUNT {
        row[SLACK_BITS + bit] = element((slack >> bit) & 1);
    }
    row
}

fn read_bits(bytes: &[u8], bit_offset: usize, bit_count: usize) -> u32 {
    let mut value = 0_u32;
    for bit in 0..bit_count {
        let source = bit_offset + bit;
        let set = (bytes[source / 8] >> (source % 8)) & 1;
        value |= u32::from(set) << bit;
    }
    value
}

fn element(value: impl Into<u128>) -> BaseElement {
    BaseElement::new(value.into())
}

fn constraint_degrees() -> Vec<TransitionConstraintDegree> {
    let mut degrees = vec![TransitionConstraintDegree::new(2); CONSTRAINTS];
    degrees[2] = TransitionConstraintDegree::new(3);
    degrees[3] = TransitionConstraintDegree::new(3);
    degrees
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

    fn encoded_inputs() -> ([u8; ML_DSA44_PUBLIC_KEY_LENGTH], [u8; ML_DSA44_SIGNATURE_LENGTH]) {
        let mut key = [0_u8; ML_DSA44_PUBLIC_KEY_LENGTH];
        for (index, byte) in key[..SEED_LENGTH].iter_mut().enumerate() {
            *byte = index as u8;
        }
        for index in 0..ML_DSA44_VECTOR_DIMENSION * ML_DSA_NTT_COEFFICIENTS {
            let code = ((index as u32).wrapping_mul(747).wrapping_add(331)) & 1_023;
            write_bits(&mut key[SEED_LENGTH..], index * T1_BITS, T1_BITS, code);
        }

        let mut signature = [0_u8; ML_DSA44_SIGNATURE_LENGTH];
        for (index, byte) in signature[..SEED_LENGTH].iter_mut().enumerate() {
            *byte = (255 - index) as u8;
        }
        for index in 0..ML_DSA44_VECTOR_DIMENSION * ML_DSA_NTT_COEFFICIENTS {
            let mixed = (index as u32).wrapping_mul(65_537).wrapping_add(17_123);
            let offset = (mixed % 260_001) as i32 - 130_000;
            let code = (GAMMA1 as i32 - offset) as u32;
            write_bits(&mut signature[Z_OFFSET..HINT_OFFSET], index * Z_BITS, Z_BITS, code);
        }
        signature[HINT_OFFSET] = 1;
        signature[HINT_OFFSET + 1] = 9;
        signature[HINT_OFFSET + HINT_WEIGHT_LIMIT..].copy_from_slice(&[2, 2, 2, 2]);
        (key, signature)
    }

    fn write_bits(bytes: &mut [u8], bit_offset: usize, bit_count: usize, value: u32) {
        for bit in 0..bit_count {
            let target = bit_offset + bit;
            let mask = 1_u8 << (target % 8);
            if (value >> bit) & 1 == 1 {
                bytes[target / 8] |= mask;
            } else {
                bytes[target / 8] &= !mask;
            }
        }
    }

    #[test]
    fn decoding_air_binds_key_signature_ranges_and_hints() {
        let (key, signature) = encoded_inputs();
        let (proof, decoded) = prove_ml_dsa44_decoding(&key, &signature).unwrap();
        assert_eq!(decoded.rho[7], 7);
        assert_eq!(decoded.challenge_seed[7], 248);
        assert_eq!(decoded.t1[3][255], ((1_023_u32 * 747 + 331) & 1_023) as u16);
        assert!(decoded.hints[0][1]);
        assert!(decoded.hints[0][9]);
        assert_eq!(decoded.hint_weight, 2);
        verify_ml_dsa44_decoding(proof.clone(), &key, &signature, &decoded).unwrap();
        let mut substituted_key = key;
        substituted_key[77] ^= 1;
        assert!(verify_ml_dsa44_decoding(proof, &substituted_key, &signature, &decoded).is_err());
    }

    #[test]
    fn decoding_rejects_substitution_norm_and_noncanonical_hints() {
        let (key, signature) = encoded_inputs();
        let mut out_of_range = signature;
        write_bits(&mut out_of_range[Z_OFFSET..HINT_OFFSET], 0, Z_BITS, 0);
        assert!(prove_ml_dsa44_decoding(&key, &out_of_range).is_err());

        let mut repeated_hint = signature;
        repeated_hint[HINT_OFFSET + 1] = repeated_hint[HINT_OFFSET];
        assert!(prove_ml_dsa44_decoding(&key, &repeated_hint).is_err());

        let mut nonzero_padding = signature;
        nonzero_padding[HINT_OFFSET + 79] = 1;
        assert!(prove_ml_dsa44_decoding(&key, &nonzero_padding).is_err());
    }
}
