#[cfg(test)]
use alloc::sync::Arc;

#[cfg(test)]
use crate::ML_DSA_Q;
use crate::{
    ML_DSA_44_VECTOR_DIMENSION, ML_DSA_NTT_COEFFICIENTS, MlDsa44SampleInBallStarkProof,
    MlDsa44T1PrecomputeStarkProof, MlDsaNttMultiplyStarkProof, MlDsaNttStarkProof,
    prove_ml_dsa_ntt, prove_ml_dsa_ntt_multiply, prove_ml_dsa44_sample_in_ball,
    prove_ml_dsa44_t1_precompute, verify_ml_dsa_ntt, verify_ml_dsa_ntt_multiply,
    verify_ml_dsa44_sample_in_ball, verify_ml_dsa44_t1_precompute,
};

#[cfg(test)]
const T1_COEFFICIENT_BOUND: u32 = 1 << 10;

type Polynomial = [u32; ML_DSA_NTT_COEFFICIENTS];
type Vector = [Polynomial; ML_DSA_44_VECTOR_DIMENSION];

/// Proof composition for the FIPS verifier value `c_hat * t1_2d_hat`.
#[cfg_attr(test, derive(Clone))]
pub struct MlDsa44ChallengeProductStarkProof {
    #[cfg(test)]
    sampling: Arc<MlDsa44SampleInBallStarkProof>,
    #[cfg(not(test))]
    sampling: MlDsa44SampleInBallStarkProof,
    challenge: Polynomial,
    t1_precompute: MlDsa44T1PrecomputeStarkProof,
    t1_hat: Vector,
    challenge_ntt: MlDsaNttStarkProof,
    challenge_hat: Polynomial,
    products: [MlDsaNttMultiplyStarkProof; ML_DSA_44_VECTOR_DIMENSION],
}

pub fn prove_ml_dsa44_challenge_product(
    t1: &Vector,
    challenge_seed: &[u8; 32],
) -> Result<(MlDsa44ChallengeProductStarkProof, Vector), &'static str> {
    let (sampling, challenge) = prove_ml_dsa44_sample_in_ball(challenge_seed)?;
    let (t1_precompute, t1_hat) = prove_ml_dsa44_t1_precompute(t1)?;
    let (challenge_ntt, challenge_hat) = prove_ml_dsa_ntt(&challenge)?;
    let (product_0, output_0) = prove_ml_dsa_ntt_multiply(&challenge_hat, &t1_hat[0])?;
    let (product_1, output_1) = prove_ml_dsa_ntt_multiply(&challenge_hat, &t1_hat[1])?;
    let (product_2, output_2) = prove_ml_dsa_ntt_multiply(&challenge_hat, &t1_hat[2])?;
    let (product_3, output_3) = prove_ml_dsa_ntt_multiply(&challenge_hat, &t1_hat[3])?;
    Ok((
        MlDsa44ChallengeProductStarkProof {
            #[cfg(test)]
            sampling: Arc::new(sampling),
            #[cfg(not(test))]
            sampling,
            challenge,
            t1_precompute,
            t1_hat,
            challenge_ntt,
            challenge_hat,
            products: [product_0, product_1, product_2, product_3],
        },
        [output_0, output_1, output_2, output_3],
    ))
}

pub fn verify_ml_dsa44_challenge_product(
    proof: MlDsa44ChallengeProductStarkProof,
    t1: &Vector,
    challenge_seed: &[u8; 32],
    output: &Vector,
) -> Result<(), &'static str> {
    verify_ml_dsa44_sample_in_ball(&proof.sampling, challenge_seed, &proof.challenge)?;
    verify_ml_dsa44_t1_precompute(proof.t1_precompute, t1, &proof.t1_hat)?;
    verify_ml_dsa_ntt(proof.challenge_ntt, &proof.challenge, &proof.challenge_hat)?;
    for (index, product) in proof.products.into_iter().enumerate() {
        verify_ml_dsa_ntt_multiply(
            product,
            &proof.challenge_hat,
            &proof.t1_hat[index],
            &output[index],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t1_fixture() -> Vector {
        core::array::from_fn(|polynomial| {
            core::array::from_fn(|index| {
                (index as u32 * 17 + polynomial as u32 * 101 + 3) % T1_COEFFICIENT_BOUND
            })
        })
    }

    fn seed_fixture() -> [u8; 32] {
        core::array::from_fn(|index| (index * 13 + 7) as u8)
    }

    #[test]
    fn challenge_product_composes_t1_challenge_ntt_and_four_products() {
        let t1 = t1_fixture();
        let seed = seed_fixture();
        let (proof, output) = prove_ml_dsa44_challenge_product(&t1, &seed).unwrap();
        verify_ml_dsa44_challenge_product(proof, &t1, &seed, &output).unwrap();
    }

    #[test]
    fn challenge_product_rejects_statement_and_shape_substitution() {
        let t1 = t1_fixture();
        let seed = seed_fixture();
        let (proof, output) = prove_ml_dsa44_challenge_product(&t1, &seed).unwrap();

        let mut substituted_t1 = t1;
        substituted_t1[2][19] = (substituted_t1[2][19] + 1) % T1_COEFFICIENT_BOUND;
        assert!(
            verify_ml_dsa44_challenge_product(proof.clone(), &substituted_t1, &seed, &output,)
                .is_err()
        );

        let mut substituted_seed = seed;
        substituted_seed[7] ^= 1;
        assert!(
            verify_ml_dsa44_challenge_product(proof.clone(), &t1, &substituted_seed, &output,)
                .is_err()
        );

        let mut substituted_output = output;
        substituted_output[3][7] = (substituted_output[3][7] + 1) % ML_DSA_Q;
        assert!(
            verify_ml_dsa44_challenge_product(proof, &t1, &seed, &substituted_output,).is_err()
        );
    }
}
