use crate::{
    ML_DSA_44_VECTOR_DIMENSION, ML_DSA_NTT_COEFFICIENTS, ML_DSA_Q,
    MlDsa44ChallengeProductStarkProof, MlDsa44MatrixVectorStarkProof, MlDsa44UseHintStarkProof,
    MlDsa44VectorSubtractStarkProof, MlDsaInverseNttStarkProof, MlDsaNttStarkProof,
    prove_ml_dsa_inverse_ntt, prove_ml_dsa_ntt, prove_ml_dsa44_challenge_product,
    prove_ml_dsa44_matrix_vector, prove_ml_dsa44_use_hint, prove_ml_dsa44_vector_subtract,
    verify_ml_dsa_inverse_ntt, verify_ml_dsa_ntt, verify_ml_dsa44_challenge_product,
    verify_ml_dsa44_matrix_vector, verify_ml_dsa44_use_hint, verify_ml_dsa44_vector_subtract,
};

const GAMMA_1: u32 = 1 << 17;
const BETA: u32 = 39 * 2;
const Z_MAGNITUDE_LIMIT: u32 = GAMMA_1 - BETA - 1;

type Polynomial = [u32; ML_DSA_NTT_COEFFICIENTS];
type Vector = [Polynomial; ML_DSA_44_VECTOR_DIMENSION];
type Matrix = [Vector; ML_DSA_44_VECTOR_DIMENSION];
type HintVector = [[bool; ML_DSA_NTT_COEFFICIENTS]; ML_DSA_44_VECTOR_DIMENSION];

/// Complete arithmetic reconstruction for FIPS 204 Algorithm 8, excluding SHAKE derivation and
/// final challenge hashing.
#[cfg_attr(test, derive(Clone))]
pub struct MlDsa44ReconstructionStarkProof {
    z_ntt: [MlDsaNttStarkProof; ML_DSA_44_VECTOR_DIMENSION],
    z_hat: Vector,
    matrix_product: MlDsa44MatrixVectorStarkProof,
    az_hat: Vector,
    challenge_product: MlDsa44ChallengeProductStarkProof,
    ct1_hat: Vector,
    subtraction: MlDsa44VectorSubtractStarkProof,
    difference_hat: Vector,
    inverse_ntt: [MlDsaInverseNttStarkProof; ML_DSA_44_VECTOR_DIMENSION],
    approximation: Vector,
    use_hint: MlDsa44UseHintStarkProof,
}

pub fn prove_ml_dsa44_reconstruction(
    matrix: &Matrix,
    t1: &Vector,
    z: &Vector,
    challenge_seed: &[u8; 32],
    hints: &HintVector,
) -> Result<(MlDsa44ReconstructionStarkProof, Vector), &'static str> {
    validate_z(z)?;
    let (z_ntt_0, z_hat_0) = prove_ml_dsa_ntt(&z[0])?;
    let (z_ntt_1, z_hat_1) = prove_ml_dsa_ntt(&z[1])?;
    let (z_ntt_2, z_hat_2) = prove_ml_dsa_ntt(&z[2])?;
    let (z_ntt_3, z_hat_3) = prove_ml_dsa_ntt(&z[3])?;
    let z_hat = [z_hat_0, z_hat_1, z_hat_2, z_hat_3];
    let (matrix_product, az_hat) = prove_ml_dsa44_matrix_vector(matrix, &z_hat)?;
    let (challenge_product, ct1_hat) = prove_ml_dsa44_challenge_product(t1, challenge_seed)?;
    let (subtraction, difference_hat) = prove_ml_dsa44_vector_subtract(&az_hat, &ct1_hat)?;
    let (inverse_0, approximation_0) = prove_ml_dsa_inverse_ntt(&difference_hat[0])?;
    let (inverse_1, approximation_1) = prove_ml_dsa_inverse_ntt(&difference_hat[1])?;
    let (inverse_2, approximation_2) = prove_ml_dsa_inverse_ntt(&difference_hat[2])?;
    let (inverse_3, approximation_3) = prove_ml_dsa_inverse_ntt(&difference_hat[3])?;
    let approximation = [approximation_0, approximation_1, approximation_2, approximation_3];
    let (use_hint, output) = prove_ml_dsa44_use_hint(&approximation, hints)?;
    Ok((
        MlDsa44ReconstructionStarkProof {
            z_ntt: [z_ntt_0, z_ntt_1, z_ntt_2, z_ntt_3],
            z_hat,
            matrix_product,
            az_hat,
            challenge_product,
            ct1_hat,
            subtraction,
            difference_hat,
            inverse_ntt: [inverse_0, inverse_1, inverse_2, inverse_3],
            approximation,
            use_hint,
        },
        output,
    ))
}

pub fn verify_ml_dsa44_reconstruction(
    proof: MlDsa44ReconstructionStarkProof,
    matrix: &Matrix,
    t1: &Vector,
    z: &Vector,
    challenge_seed: &[u8; 32],
    hints: &HintVector,
    output: &Vector,
) -> Result<(), &'static str> {
    validate_z(z)?;
    for (index, ntt_proof) in proof.z_ntt.into_iter().enumerate() {
        verify_ml_dsa_ntt(ntt_proof, &z[index], &proof.z_hat[index])?;
    }
    verify_ml_dsa44_matrix_vector(proof.matrix_product, matrix, &proof.z_hat, &proof.az_hat)?;
    verify_ml_dsa44_challenge_product(proof.challenge_product, t1, challenge_seed, &proof.ct1_hat)?;
    verify_ml_dsa44_vector_subtract(
        proof.subtraction,
        &proof.az_hat,
        &proof.ct1_hat,
        &proof.difference_hat,
    )?;
    for (index, inverse_proof) in proof.inverse_ntt.into_iter().enumerate() {
        verify_ml_dsa_inverse_ntt(
            inverse_proof,
            &proof.difference_hat[index],
            &proof.approximation[index],
        )?;
    }
    verify_ml_dsa44_use_hint(proof.use_hint, &proof.approximation, hints, output)
}

fn validate_z(z: &Vector) -> Result<(), &'static str> {
    if z.iter().flatten().any(|coefficient| {
        *coefficient >= ML_DSA_Q
            || (*coefficient > Z_MAGNITUDE_LIMIT && *coefficient < ML_DSA_Q - Z_MAGNITUDE_LIMIT)
    }) {
        return Err("ML-DSA-44 z coefficient violates its canonical infinity-norm bound");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Matrix, Vector, Vector, [u8; 32], HintVector) {
        let matrix = core::array::from_fn(|row| {
            core::array::from_fn(|column| {
                core::array::from_fn(|index| {
                    (index as u32 * 17 + row as u32 * 101 + column as u32 * 43 + 3) % ML_DSA_Q
                })
            })
        });
        let t1 = core::array::from_fn(|polynomial| {
            core::array::from_fn(|index| (index as u32 * 13 + polynomial as u32 * 37 + 5) % 1024)
        });
        let z = core::array::from_fn(|polynomial| {
            core::array::from_fn(|index| {
                let magnitude =
                    (index as u32 * 29 + polynomial as u32 * 71 + 1) % (Z_MAGNITUDE_LIMIT + 1);
                if (index + polynomial) % 2 == 0 || magnitude == 0 {
                    magnitude
                } else {
                    ML_DSA_Q - magnitude
                }
            })
        });
        let challenge_seed = core::array::from_fn(|index| (index * 13 + 7) as u8);
        let hints = core::array::from_fn(|polynomial| {
            core::array::from_fn(|index| (index + polynomial) % 11 == 0)
        });
        (matrix, t1, z, challenge_seed, hints)
    }

    #[test]
    fn reconstruction_composes_the_complete_mldsa44_arithmetic_path() {
        let (matrix, t1, z, challenge, hints) = fixture();
        let (proof, output) =
            prove_ml_dsa44_reconstruction(&matrix, &t1, &z, &challenge, &hints).unwrap();
        verify_ml_dsa44_reconstruction(proof, &matrix, &t1, &z, &challenge, &hints, &output)
            .unwrap();
    }

    #[test]
    fn reconstruction_rejects_statement_output_and_z_range_substitution() {
        let (matrix, t1, z, challenge, hints) = fixture();
        let (proof, output) =
            prove_ml_dsa44_reconstruction(&matrix, &t1, &z, &challenge, &hints).unwrap();

        let mut substituted_matrix = matrix;
        substituted_matrix[2][1][19] = (substituted_matrix[2][1][19] + 1) % ML_DSA_Q;
        assert!(
            verify_ml_dsa44_reconstruction(
                proof.clone(),
                &substituted_matrix,
                &t1,
                &z,
                &challenge,
                &hints,
                &output,
            )
            .is_err()
        );

        let mut substituted_hints = hints;
        substituted_hints[3][7] = !substituted_hints[3][7];
        assert!(
            verify_ml_dsa44_reconstruction(
                proof.clone(),
                &matrix,
                &t1,
                &z,
                &challenge,
                &substituted_hints,
                &output,
            )
            .is_err()
        );

        let mut substituted_output = output;
        substituted_output[3][7] = (substituted_output[3][7] + 1) % 44;
        assert!(
            verify_ml_dsa44_reconstruction(
                proof,
                &matrix,
                &t1,
                &z,
                &challenge,
                &hints,
                &substituted_output,
            )
            .is_err()
        );

        let mut invalid_z = z;
        invalid_z[0][0] = Z_MAGNITUDE_LIMIT + 1;
        assert!(
            prove_ml_dsa44_reconstruction(&matrix, &t1, &invalid_z, &challenge, &hints).is_err()
        );
    }
}
