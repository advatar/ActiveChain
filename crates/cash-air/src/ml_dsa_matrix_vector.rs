use crate::{
    ML_DSA_44_VECTOR_DIMENSION, ML_DSA_NTT_COEFFICIENTS, ML_DSA_Q,
    MlDsaVectorAccumulationStarkProof, prove_ml_dsa_vector_accumulation,
    verify_ml_dsa_vector_accumulation,
};

type Polynomial = [u32; ML_DSA_NTT_COEFFICIENTS];
type Vector = [Polynomial; ML_DSA_44_VECTOR_DIMENSION];
type Matrix = [Vector; ML_DSA_44_VECTOR_DIMENSION];

/// Four fixed-dimension row proofs for the ML-DSA-44 `A * v` operation in the NTT domain.
#[cfg_attr(test, derive(Clone))]
pub struct MlDsa44MatrixVectorStarkProof {
    rows: [MlDsaVectorAccumulationStarkProof; ML_DSA_44_VECTOR_DIMENSION],
}

pub fn prove_ml_dsa44_matrix_vector(
    matrix: &Matrix,
    vector: &Vector,
) -> Result<(MlDsa44MatrixVectorStarkProof, Vector), &'static str> {
    validate_inputs(matrix, vector)?;
    let (row_0, output_0) = prove_ml_dsa_vector_accumulation(&matrix[0], vector)?;
    let (row_1, output_1) = prove_ml_dsa_vector_accumulation(&matrix[1], vector)?;
    let (row_2, output_2) = prove_ml_dsa_vector_accumulation(&matrix[2], vector)?;
    let (row_3, output_3) = prove_ml_dsa_vector_accumulation(&matrix[3], vector)?;
    Ok((
        MlDsa44MatrixVectorStarkProof { rows: [row_0, row_1, row_2, row_3] },
        [output_0, output_1, output_2, output_3],
    ))
}

pub fn verify_ml_dsa44_matrix_vector(
    proof: MlDsa44MatrixVectorStarkProof,
    matrix: &Matrix,
    vector: &Vector,
    output: &Vector,
) -> Result<(), &'static str> {
    validate_inputs(matrix, vector)?;
    for (row_index, row_proof) in proof.rows.into_iter().enumerate() {
        verify_ml_dsa_vector_accumulation(
            row_proof,
            &matrix[row_index],
            vector,
            &output[row_index],
        )?;
    }
    Ok(())
}

fn validate_inputs(matrix: &Matrix, vector: &Vector) -> Result<(), &'static str> {
    if matrix
        .iter()
        .flatten()
        .flatten()
        .chain(vector.iter().flatten())
        .any(|coefficient| *coefficient >= ML_DSA_Q)
    {
        return Err("ML-DSA matrix-vector coefficient is outside Z_q");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operands() -> (Matrix, Vector) {
        (
            core::array::from_fn(|row| {
                core::array::from_fn(|column| {
                    core::array::from_fn(|index| {
                        (index as u32 * 17 + row as u32 * 101 + column as u32 * 43 + 3) % ML_DSA_Q
                    })
                })
            }),
            core::array::from_fn(|column| {
                core::array::from_fn(|index| {
                    (index as u32 * 29 + column as u32 * 67 + 5) % ML_DSA_Q
                })
            }),
        )
    }

    #[test]
    fn matrix_vector_composes_all_four_proven_rows() {
        let (matrix, vector) = operands();
        let (proof, output) = prove_ml_dsa44_matrix_vector(&matrix, &vector).unwrap();
        verify_ml_dsa44_matrix_vector(proof, &matrix, &vector, &output).unwrap();
    }

    #[test]
    fn matrix_vector_rejects_matrix_vector_output_and_range_substitution() {
        let (matrix, vector) = operands();
        let (proof, mut output) = prove_ml_dsa44_matrix_vector(&matrix, &vector).unwrap();
        output[2][19] = (output[2][19] + 1) % ML_DSA_Q;
        assert!(verify_ml_dsa44_matrix_vector(proof, &matrix, &vector, &output).is_err());

        let (proof, output) = prove_ml_dsa44_matrix_vector(&matrix, &vector).unwrap();
        let mut substituted_matrix = matrix;
        substituted_matrix[3][1][7] = (substituted_matrix[3][1][7] + 1) % ML_DSA_Q;
        assert!(
            verify_ml_dsa44_matrix_vector(proof, &substituted_matrix, &vector, &output).is_err()
        );

        let (proof, output) = prove_ml_dsa44_matrix_vector(&matrix, &vector).unwrap();
        let mut substituted_vector = vector;
        substituted_vector[1][7] = (substituted_vector[1][7] + 1) % ML_DSA_Q;
        assert!(
            verify_ml_dsa44_matrix_vector(proof, &matrix, &substituted_vector, &output).is_err()
        );

        let mut invalid = matrix;
        invalid[3][1][7] = ML_DSA_Q;
        assert!(prove_ml_dsa44_matrix_vector(&invalid, &vector).is_err());
    }
}
