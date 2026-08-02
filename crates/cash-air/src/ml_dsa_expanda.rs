use alloc::{vec, vec::Vec};

use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    MAX_CASH_SHAKE_XOF_OUTPUT, ML_DSA_44_VECTOR_DIMENSION, ML_DSA_NTT_COEFFICIENTS, ML_DSA_Q,
    Shake128XofStarkProof, prove_shake128_xof, verify_shake128_xof,
};

const INITIAL_REJECTION_BYTES: usize = 840;
const CANDIDATE_BYTES: usize = 3;
const MATRIX_POLYNOMIALS: usize = ML_DSA_44_VECTOR_DIMENSION * ML_DSA_44_VECTOR_DIMENSION;

type Polynomial = [u32; ML_DSA_NTT_COEFFICIENTS];
type Vector = [Polynomial; ML_DSA_44_VECTOR_DIMENSION];
type Matrix = [Vector; ML_DSA_44_VECTOR_DIMENSION];

pub struct MlDsa44ExpandAStarkProof {
    streams: Vec<Shake128XofStarkProof>,
}

pub fn prove_ml_dsa44_expand_a(
    rho: &[u8; 32],
) -> Result<(MlDsa44ExpandAStarkProof, Matrix), &'static str> {
    let mut streams = Vec::with_capacity(MATRIX_POLYNOMIALS);
    let mut matrix = [[[0_u32; ML_DSA_NTT_COEFFICIENTS]; ML_DSA_44_VECTOR_DIMENSION];
        ML_DSA_44_VECTOR_DIMENSION];
    for (row, matrix_row) in matrix.iter_mut().enumerate() {
        for (column, polynomial) in matrix_row.iter_mut().enumerate() {
            let message = matrix_message(rho, row, column);
            let output_length = rejection_output_length(&message)?;
            let proof = prove_shake128_xof(&message, output_length)?;
            *polynomial = decode_rejection_stream(proof.output())?;
            streams.push(proof);
        }
    }
    Ok((MlDsa44ExpandAStarkProof { streams }, matrix))
}

pub fn verify_ml_dsa44_expand_a(
    proof: &MlDsa44ExpandAStarkProof,
    rho: &[u8; 32],
    matrix: &Matrix,
) -> Result<(), &'static str> {
    if proof.streams.len() != MATRIX_POLYNOMIALS {
        return Err("ML-DSA ExpandA stream count mismatch");
    }
    for (row, matrix_row) in matrix.iter().enumerate() {
        for (column, expected_polynomial) in matrix_row.iter().enumerate() {
            let stream_index = row * ML_DSA_44_VECTOR_DIMENSION + column;
            let stream = &proof.streams[stream_index];
            let message = matrix_message(rho, row, column);
            if stream.output().len() != rejection_output_length(&message)? {
                return Err("ML-DSA ExpandA rejection stream length is noncanonical");
            }
            verify_shake128_xof(stream, &message, stream.output())?;
            if decode_rejection_stream(stream.output())? != *expected_polynomial {
                return Err("ML-DSA ExpandA matrix mismatch");
            }
        }
    }
    Ok(())
}

fn matrix_message(rho: &[u8; 32], row: usize, column: usize) -> Vec<u8> {
    let mut message = Vec::with_capacity(34);
    message.extend_from_slice(rho);
    message.push(column as u8);
    message.push(row as u8);
    message
}

fn rejection_output_length(message: &[u8]) -> Result<usize, &'static str> {
    let mut hasher = Shake128::default();
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    let mut bytes = vec![0_u8; INITIAL_REJECTION_BYTES];
    reader.read(&mut bytes);
    let mut accepted = accepted_count(&bytes);
    while accepted < ML_DSA_NTT_COEFFICIENTS {
        if bytes.len() + CANDIDATE_BYTES > MAX_CASH_SHAKE_XOF_OUTPUT {
            return Err("ML-DSA ExpandA rejection stream exceeds its proof bound");
        }
        let mut candidate = [0_u8; CANDIDATE_BYTES];
        reader.read(&mut candidate);
        accepted += usize::from(decode_candidate(candidate).is_some());
        bytes.extend_from_slice(&candidate);
    }
    Ok(bytes.len())
}

fn decode_rejection_stream(bytes: &[u8]) -> Result<Polynomial, &'static str> {
    if bytes.len() < INITIAL_REJECTION_BYTES
        || bytes.len() > MAX_CASH_SHAKE_XOF_OUTPUT
        || !bytes.len().is_multiple_of(CANDIDATE_BYTES)
    {
        return Err("ML-DSA ExpandA rejection stream length is invalid");
    }
    let mut polynomial = [0_u32; ML_DSA_NTT_COEFFICIENTS];
    let mut accepted = 0_usize;
    for chunk in bytes.chunks_exact(CANDIDATE_BYTES) {
        if let Some(coefficient) = decode_candidate([chunk[0], chunk[1], chunk[2]]) {
            polynomial[accepted] = coefficient;
            accepted += 1;
            if accepted == ML_DSA_NTT_COEFFICIENTS {
                return Ok(polynomial);
            }
        }
    }
    Err("ML-DSA ExpandA rejection stream is incomplete")
}

fn accepted_count(bytes: &[u8]) -> usize {
    bytes
        .chunks_exact(CANDIDATE_BYTES)
        .filter(|chunk| decode_candidate([chunk[0], chunk[1], chunk[2]]).is_some())
        .count()
}

fn decode_candidate(bytes: [u8; CANDIDATE_BYTES]) -> Option<u32> {
    let value =
        (u32::from(bytes[2] & 0x7f) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[0]);
    (value < ML_DSA_Q).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expanda_proves_all_sixteen_coordinate_bound_streams() {
        let rho = core::array::from_fn(|index| (index * 7 + 3) as u8);
        let (proof, matrix) = prove_ml_dsa44_expand_a(&rho).unwrap();
        assert_eq!(proof.streams.len(), MATRIX_POLYNOMIALS);
        assert!(proof.streams.iter().all(|stream| stream.output().len() >= 840));
        verify_ml_dsa44_expand_a(&proof, &rho, &matrix).unwrap();
    }

    #[test]
    fn expanda_rejects_rho_matrix_and_stream_shape_substitution() {
        let rho = [0x5a_u8; 32];
        let (mut proof, matrix) = prove_ml_dsa44_expand_a(&rho).unwrap();
        let mut substituted_rho = rho;
        substituted_rho[7] ^= 1;
        assert!(verify_ml_dsa44_expand_a(&proof, &substituted_rho, &matrix).is_err());

        let mut substituted_matrix = matrix;
        substituted_matrix[2][1][19] = (substituted_matrix[2][1][19] + 1) % ML_DSA_Q;
        assert!(verify_ml_dsa44_expand_a(&proof, &rho, &substituted_matrix).is_err());

        proof.streams.pop();
        assert!(verify_ml_dsa44_expand_a(&proof, &rho, &matrix).is_err());
    }

    #[test]
    fn rejection_decoder_supports_the_bounded_fallback_path() {
        let mut bytes = vec![0xff; INITIAL_REJECTION_BYTES];
        bytes.extend(core::iter::repeat_n(0_u8, ML_DSA_NTT_COEFFICIENTS * CANDIDATE_BYTES));
        let polynomial = decode_rejection_stream(&bytes).unwrap();
        assert_eq!(polynomial, [0_u32; ML_DSA_NTT_COEFFICIENTS]);

        assert!(decode_rejection_stream(&vec![0xff; INITIAL_REJECTION_BYTES]).is_err());
    }
}
