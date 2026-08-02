#[cfg(test)]
use alloc::vec;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    MAX_CASH_SHAKE_XOF_OUTPUT, ML_DSA_NTT_COEFFICIENTS, ML_DSA_Q, Shake256XofStarkProof,
    prove_shake256_xof, verify_shake256_xof,
};

const CHALLENGE_WEIGHT: usize = 39;
const SIGN_BYTES: usize = 8;
const FIRST_POSITION: usize = ML_DSA_NTT_COEFFICIENTS - CHALLENGE_WEIGHT;

type Polynomial = [u32; ML_DSA_NTT_COEFFICIENTS];

/// SHAKE256 proof and deterministic decoder for FIPS 204 Algorithm 29.
pub struct MlDsa44SampleInBallStarkProof {
    stream: Shake256XofStarkProof,
}

pub fn prove_ml_dsa44_sample_in_ball(
    challenge_seed: &[u8; 32],
) -> Result<(MlDsa44SampleInBallStarkProof, Polynomial), &'static str> {
    let output_length = sample_output_length(challenge_seed)?;
    let stream = prove_shake256_xof(challenge_seed, output_length)?;
    let challenge = decode_sample_stream(stream.output())?;
    Ok((MlDsa44SampleInBallStarkProof { stream }, challenge))
}

pub fn verify_ml_dsa44_sample_in_ball(
    proof: &MlDsa44SampleInBallStarkProof,
    challenge_seed: &[u8; 32],
    challenge: &Polynomial,
) -> Result<(), &'static str> {
    if proof.stream.output().len() != sample_output_length(challenge_seed)? {
        return Err("ML-DSA SampleInBall stream length is noncanonical");
    }
    verify_shake256_xof(&proof.stream, challenge_seed, proof.stream.output())?;
    if decode_sample_stream(proof.stream.output())? != *challenge {
        return Err("ML-DSA SampleInBall challenge mismatch");
    }
    Ok(())
}

fn sample_output_length(challenge_seed: &[u8; 32]) -> Result<usize, &'static str> {
    let mut hasher = Shake256::default();
    hasher.update(challenge_seed);
    let mut reader = hasher.finalize_xof();
    let mut signs = [0_u8; SIGN_BYTES];
    reader.read(&mut signs);
    let mut length = SIGN_BYTES;
    for position in FIRST_POSITION..ML_DSA_NTT_COEFFICIENTS {
        loop {
            if length == MAX_CASH_SHAKE_XOF_OUTPUT {
                return Err("ML-DSA SampleInBall rejection stream exceeds its proof bound");
            }
            let mut candidate = [0_u8; 1];
            reader.read(&mut candidate);
            length += 1;
            if usize::from(candidate[0]) <= position {
                break;
            }
        }
    }
    Ok(length)
}

fn decode_sample_stream(bytes: &[u8]) -> Result<Polynomial, &'static str> {
    if bytes.len() < SIGN_BYTES + CHALLENGE_WEIGHT || bytes.len() > MAX_CASH_SHAKE_XOF_OUTPUT {
        return Err("ML-DSA SampleInBall stream length is invalid");
    }
    let signs = &bytes[..SIGN_BYTES];
    let mut cursor = SIGN_BYTES;
    let mut challenge = [0_u32; ML_DSA_NTT_COEFFICIENTS];
    for position in FIRST_POSITION..ML_DSA_NTT_COEFFICIENTS {
        let selected = loop {
            let candidate =
                *bytes.get(cursor).ok_or("ML-DSA SampleInBall rejection stream is incomplete")?;
            cursor += 1;
            if usize::from(candidate) <= position {
                break usize::from(candidate);
            }
        };
        challenge[position] = challenge[selected];
        let sign_index = position - FIRST_POSITION;
        challenge[selected] =
            if signs[sign_index >> 3] & (1 << (sign_index & 7)) == 0 { 1 } else { ML_DSA_Q - 1 };
    }
    if cursor != bytes.len() {
        return Err("ML-DSA SampleInBall stream has trailing bytes");
    }
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_in_ball_proves_exact_seed_stream_and_sparse_polynomial() {
        let seed = core::array::from_fn(|index| (index * 11 + 5) as u8);
        let (proof, challenge) = prove_ml_dsa44_sample_in_ball(&seed).unwrap();
        assert_eq!(
            challenge.iter().filter(|coefficient| **coefficient != 0).count(),
            CHALLENGE_WEIGHT
        );
        verify_ml_dsa44_sample_in_ball(&proof, &seed, &challenge).unwrap();
    }

    #[test]
    fn sample_in_ball_rejects_seed_and_polynomial_substitution() {
        let seed = [0x5a_u8; 32];
        let (proof, challenge) = prove_ml_dsa44_sample_in_ball(&seed).unwrap();
        let mut other_seed = seed;
        other_seed[9] ^= 1;
        assert!(verify_ml_dsa44_sample_in_ball(&proof, &other_seed, &challenge).is_err());

        let mut other_challenge = challenge;
        let occupied = other_challenge.iter().position(|coefficient| *coefficient != 0).unwrap();
        other_challenge[occupied] = if other_challenge[occupied] == 1 { ML_DSA_Q - 1 } else { 1 };
        assert!(verify_ml_dsa44_sample_in_ball(&proof, &seed, &other_challenge).is_err());
    }

    #[test]
    fn decoder_covers_rejections_swaps_signs_and_rejects_trailing_bytes() {
        let mut bytes = vec![0_u8; SIGN_BYTES];
        bytes[0] = 1;
        for position in FIRST_POSITION..ML_DSA_NTT_COEFFICIENTS {
            if position < u8::MAX as usize {
                bytes.push(u8::MAX);
            }
            bytes.push(position as u8);
        }
        let challenge = decode_sample_stream(&bytes).unwrap();
        assert_eq!(challenge[FIRST_POSITION], ML_DSA_Q - 1);
        assert_eq!(challenge.iter().filter(|coefficient| **coefficient != 0).count(), 39);

        bytes.push(0);
        assert!(decode_sample_stream(&bytes).is_err());
    }
}
