use crate::{
    ML_DSA_44_VECTOR_DIMENSION, ML_DSA_NTT_COEFFICIENTS, ML_DSA_Q, MlDsa44T1PrecomputeStarkProof,
    MlDsaNttMultiplyStarkProof, MlDsaNttStarkProof, prove_ml_dsa_ntt, prove_ml_dsa_ntt_multiply,
    prove_ml_dsa44_t1_precompute, verify_ml_dsa_ntt, verify_ml_dsa_ntt_multiply,
    verify_ml_dsa44_t1_precompute,
};

const ML_DSA44_CHALLENGE_WEIGHT: usize = 39;
#[cfg(test)]
const T1_COEFFICIENT_BOUND: u32 = 1 << 10;

type Polynomial = [u32; ML_DSA_NTT_COEFFICIENTS];
type Vector = [Polynomial; ML_DSA_44_VECTOR_DIMENSION];

/// Proof composition for the FIPS verifier value `c_hat * t1_2d_hat`.
#[cfg_attr(test, derive(Clone))]
pub struct MlDsa44ChallengeProductStarkProof {
    t1_precompute: MlDsa44T1PrecomputeStarkProof,
    t1_hat: Vector,
    challenge_ntt: MlDsaNttStarkProof,
    challenge_hat: Polynomial,
    products: [MlDsaNttMultiplyStarkProof; ML_DSA_44_VECTOR_DIMENSION],
}

pub fn prove_ml_dsa44_challenge_product(
    t1: &Vector,
    challenge: &Polynomial,
) -> Result<(MlDsa44ChallengeProductStarkProof, Vector), &'static str> {
    validate_challenge(challenge)?;
    let (t1_precompute, t1_hat) = prove_ml_dsa44_t1_precompute(t1)?;
    let (challenge_ntt, challenge_hat) = prove_ml_dsa_ntt(challenge)?;
    let (product_0, output_0) = prove_ml_dsa_ntt_multiply(&challenge_hat, &t1_hat[0])?;
    let (product_1, output_1) = prove_ml_dsa_ntt_multiply(&challenge_hat, &t1_hat[1])?;
    let (product_2, output_2) = prove_ml_dsa_ntt_multiply(&challenge_hat, &t1_hat[2])?;
    let (product_3, output_3) = prove_ml_dsa_ntt_multiply(&challenge_hat, &t1_hat[3])?;
    Ok((
        MlDsa44ChallengeProductStarkProof {
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
    challenge: &Polynomial,
    output: &Vector,
) -> Result<(), &'static str> {
    validate_challenge(challenge)?;
    verify_ml_dsa44_t1_precompute(proof.t1_precompute, t1, &proof.t1_hat)?;
    verify_ml_dsa_ntt(proof.challenge_ntt, challenge, &proof.challenge_hat)?;
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

fn validate_challenge(challenge: &Polynomial) -> Result<(), &'static str> {
    let mut weight = 0_usize;
    for coefficient in challenge {
        match *coefficient {
            0 => {}
            1 => weight += 1,
            value if value == ML_DSA_Q - 1 => weight += 1,
            _ => return Err("ML-DSA challenge coefficient is not canonical"),
        }
    }
    if weight != ML_DSA44_CHALLENGE_WEIGHT {
        return Err("ML-DSA-44 challenge does not have weight 39");
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

    fn challenge_fixture() -> Polynomial {
        let mut challenge = [0_u32; ML_DSA_NTT_COEFFICIENTS];
        for index in 0..ML_DSA44_CHALLENGE_WEIGHT {
            let position = (index * 53 + 7) % ML_DSA_NTT_COEFFICIENTS;
            challenge[position] = if index % 2 == 0 { 1 } else { ML_DSA_Q - 1 };
        }
        challenge
    }

    #[test]
    fn challenge_product_composes_t1_challenge_ntt_and_four_products() {
        let t1 = t1_fixture();
        let challenge = challenge_fixture();
        let (proof, output) = prove_ml_dsa44_challenge_product(&t1, &challenge).unwrap();
        verify_ml_dsa44_challenge_product(proof, &t1, &challenge, &output).unwrap();
    }

    #[test]
    fn challenge_product_rejects_statement_and_shape_substitution() {
        let t1 = t1_fixture();
        let challenge = challenge_fixture();
        let (proof, output) = prove_ml_dsa44_challenge_product(&t1, &challenge).unwrap();

        let mut substituted_t1 = t1;
        substituted_t1[2][19] = (substituted_t1[2][19] + 1) % T1_COEFFICIENT_BOUND;
        assert!(
            verify_ml_dsa44_challenge_product(proof.clone(), &substituted_t1, &challenge, &output,)
                .is_err()
        );

        let mut substituted_challenge = challenge;
        substituted_challenge.swap(7, 8);
        assert!(
            verify_ml_dsa44_challenge_product(proof.clone(), &t1, &substituted_challenge, &output,)
                .is_err()
        );

        let mut substituted_output = output;
        substituted_output[3][7] = (substituted_output[3][7] + 1) % ML_DSA_Q;
        assert!(
            verify_ml_dsa44_challenge_product(proof, &t1, &challenge, &substituted_output,)
                .is_err()
        );

        let mut wrong_weight = challenge;
        wrong_weight[7] = 0;
        assert!(prove_ml_dsa44_challenge_product(&t1, &wrong_weight).is_err());

        let mut invalid_coefficient = challenge;
        invalid_coefficient[7] = 2;
        assert!(prove_ml_dsa44_challenge_product(&t1, &invalid_coefficient).is_err());
    }
}
