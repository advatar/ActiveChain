use alloc::vec::Vec;

use crate::{
    ML_DSA_44_VECTOR_DIMENSION, ML_DSA_NTT_COEFFICIENTS, MlDsa44ReconstructionStarkProof,
    Shake256XofStarkProof, prove_ml_dsa44_reconstruction, prove_shake256_xof,
    verify_ml_dsa44_reconstruction, verify_shake256_xof,
};

const HIGH_BITS_MODULUS: u32 = 44;
const W1_BITS: usize = 6;
const W1_ENCODED_BYTES: usize = ML_DSA_44_VECTOR_DIMENSION * ML_DSA_NTT_COEFFICIENTS * W1_BITS / 8;
const MU_BYTES: usize = 64;
const CHALLENGE_BYTES: usize = 32;

type Polynomial = [u32; ML_DSA_NTT_COEFFICIENTS];
type Vector = [Polynomial; ML_DSA_44_VECTOR_DIMENSION];
type Matrix = [Vector; ML_DSA_44_VECTOR_DIMENSION];
type HintVector = [[bool; ML_DSA_NTT_COEFFICIENTS]; ML_DSA_44_VECTOR_DIMENSION];

/// Proof of the final FIPS 204 verifier challenge equality.
pub struct MlDsa44FinalChallengeStarkProof {
    shake: Shake256XofStarkProof,
}

/// End-to-end composition from ML-DSA arithmetic reconstruction through the final challenge hash.
pub struct MlDsa44VerifierStarkProof {
    reconstruction: MlDsa44ReconstructionStarkProof,
    w1: Vector,
    final_challenge: MlDsa44FinalChallengeStarkProof,
}

pub fn prove_ml_dsa44_final_challenge(
    mu: &[u8; MU_BYTES],
    challenge_seed: &[u8; CHALLENGE_BYTES],
    w1: &Vector,
) -> Result<MlDsa44FinalChallengeStarkProof, &'static str> {
    let transcript = challenge_transcript(mu, w1)?;
    let shake = prove_shake256_xof(&transcript, CHALLENGE_BYTES)?;
    if shake.output() != challenge_seed {
        return Err("ML-DSA final challenge does not match c_tilde");
    }
    Ok(MlDsa44FinalChallengeStarkProof { shake })
}

pub fn verify_ml_dsa44_final_challenge(
    proof: &MlDsa44FinalChallengeStarkProof,
    mu: &[u8; MU_BYTES],
    challenge_seed: &[u8; CHALLENGE_BYTES],
    w1: &Vector,
) -> Result<(), &'static str> {
    let transcript = challenge_transcript(mu, w1)?;
    verify_shake256_xof(&proof.shake, &transcript, challenge_seed)
        .map_err(|_| "ML-DSA final challenge proof verification failed")
}

pub fn prove_ml_dsa44_verifier(
    matrix: &Matrix,
    t1: &Vector,
    z: &Vector,
    challenge_seed: &[u8; CHALLENGE_BYTES],
    hints: &HintVector,
    mu: &[u8; MU_BYTES],
) -> Result<MlDsa44VerifierStarkProof, &'static str> {
    let (reconstruction, w1) = prove_ml_dsa44_reconstruction(matrix, t1, z, challenge_seed, hints)?;
    let final_challenge = prove_ml_dsa44_final_challenge(mu, challenge_seed, &w1)?;
    Ok(MlDsa44VerifierStarkProof { reconstruction, w1, final_challenge })
}

pub fn verify_ml_dsa44_verifier(
    proof: MlDsa44VerifierStarkProof,
    matrix: &Matrix,
    t1: &Vector,
    z: &Vector,
    challenge_seed: &[u8; CHALLENGE_BYTES],
    hints: &HintVector,
    mu: &[u8; MU_BYTES],
) -> Result<(), &'static str> {
    verify_ml_dsa44_reconstruction(
        proof.reconstruction,
        matrix,
        t1,
        z,
        challenge_seed,
        hints,
        &proof.w1,
    )?;
    verify_ml_dsa44_final_challenge(&proof.final_challenge, mu, challenge_seed, &proof.w1)
}

fn challenge_transcript(mu: &[u8; MU_BYTES], w1: &Vector) -> Result<Vec<u8>, &'static str> {
    let encoded = encode_w1(w1)?;
    let mut transcript = Vec::with_capacity(MU_BYTES + W1_ENCODED_BYTES);
    transcript.extend_from_slice(mu);
    transcript.extend_from_slice(&encoded);
    Ok(transcript)
}

fn encode_w1(w1: &Vector) -> Result<[u8; W1_ENCODED_BYTES], &'static str> {
    let mut encoded = [0_u8; W1_ENCODED_BYTES];
    let mut bit_offset = 0_usize;
    for coefficient in w1.iter().flatten().copied() {
        if coefficient >= HIGH_BITS_MODULUS {
            return Err("ML-DSA-44 w1 coefficient is outside its canonical range");
        }
        for bit in 0..W1_BITS {
            if coefficient & (1 << bit) != 0 {
                encoded[bit_offset >> 3] |= 1 << (bit_offset & 7);
            }
            bit_offset += 1;
        }
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    use super::*;

    fn fixture() -> ([u8; MU_BYTES], Vector, [u8; CHALLENGE_BYTES]) {
        let mu = core::array::from_fn(|index| (index * 7 + 3) as u8);
        let w1 = core::array::from_fn(|polynomial| {
            core::array::from_fn(|index| (index as u32 * 13 + polynomial as u32 * 17 + 5) % 44)
        });
        let transcript = challenge_transcript(&mu, &w1).unwrap();
        let mut hasher = Shake256::default();
        hasher.update(&transcript);
        let mut challenge = [0_u8; CHALLENGE_BYTES];
        hasher.finalize_xof().read(&mut challenge);
        (mu, w1, challenge)
    }

    #[test]
    fn w1_encoding_is_six_bit_little_endian_and_polynomial_ordered() {
        let mut w1 = [[0_u32; ML_DSA_NTT_COEFFICIENTS]; ML_DSA_44_VECTOR_DIMENSION];
        w1[0][0] = 1;
        w1[0][1] = 2;
        w1[0][2] = 43;
        assert_eq!(&encode_w1(&w1).unwrap()[..3], &[0x81, 0xb0, 0x02]);

        w1[3][255] = 44;
        assert!(encode_w1(&w1).is_err());
    }

    #[test]
    fn final_challenge_proves_exact_mu_w1_and_c_tilde() {
        let (mu, w1, challenge) = fixture();
        let proof = prove_ml_dsa44_final_challenge(&mu, &challenge, &w1).unwrap();
        verify_ml_dsa44_final_challenge(&proof, &mu, &challenge, &w1).unwrap();
    }

    #[test]
    fn final_challenge_rejects_mu_w1_and_c_tilde_substitution() {
        let (mu, w1, challenge) = fixture();
        let proof = prove_ml_dsa44_final_challenge(&mu, &challenge, &w1).unwrap();
        let mut other_mu = mu;
        other_mu[7] ^= 1;
        assert!(verify_ml_dsa44_final_challenge(&proof, &other_mu, &challenge, &w1).is_err());

        let mut other_w1 = w1;
        other_w1[2][19] = (other_w1[2][19] + 1) % HIGH_BITS_MODULUS;
        assert!(verify_ml_dsa44_final_challenge(&proof, &mu, &challenge, &other_w1).is_err());

        let mut other_challenge = challenge;
        other_challenge[11] ^= 1;
        assert!(verify_ml_dsa44_final_challenge(&proof, &mu, &other_challenge, &w1).is_err());
    }
}
