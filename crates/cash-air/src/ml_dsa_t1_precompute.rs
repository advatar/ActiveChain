use crate::{
    ML_DSA_44_VECTOR_DIMENSION, ML_DSA_NTT_COEFFICIENTS, ML_DSA_Q, MlDsaNttMultiplyStarkProof,
    MlDsaNttStarkProof, prove_ml_dsa_ntt, prove_ml_dsa_ntt_multiply, verify_ml_dsa_ntt,
    verify_ml_dsa_ntt_multiply,
};

const T1_COEFFICIENT_BOUND: u32 = 1 << 10;
const POWER_2_D: u32 = 1 << 13;

type Polynomial = [u32; ML_DSA_NTT_COEFFICIENTS];
type Vector = [Polynomial; ML_DSA_44_VECTOR_DIMENSION];

#[cfg_attr(test, derive(Clone))]
struct T1PolynomialProof {
    scale: MlDsaNttMultiplyStarkProof,
    ntt: MlDsaNttStarkProof,
}

/// Proof composition for the cached FIPS verifier value `NTT(2^d * t1)`.
#[cfg_attr(test, derive(Clone))]
pub struct MlDsa44T1PrecomputeStarkProof {
    polynomials: [T1PolynomialProof; ML_DSA_44_VECTOR_DIMENSION],
}

pub fn prove_ml_dsa44_t1_precompute(
    t1: &Vector,
) -> Result<(MlDsa44T1PrecomputeStarkProof, Vector), &'static str> {
    validate_t1(t1)?;
    let (proof_0, output_0) = prove_polynomial(&t1[0])?;
    let (proof_1, output_1) = prove_polynomial(&t1[1])?;
    let (proof_2, output_2) = prove_polynomial(&t1[2])?;
    let (proof_3, output_3) = prove_polynomial(&t1[3])?;
    Ok((
        MlDsa44T1PrecomputeStarkProof { polynomials: [proof_0, proof_1, proof_2, proof_3] },
        [output_0, output_1, output_2, output_3],
    ))
}

pub fn verify_ml_dsa44_t1_precompute(
    proof: MlDsa44T1PrecomputeStarkProof,
    t1: &Vector,
    output: &Vector,
) -> Result<(), &'static str> {
    validate_t1(t1)?;
    for (index, polynomial_proof) in proof.polynomials.into_iter().enumerate() {
        let scaled = scaled_polynomial(&t1[index]);
        let multiplier = [POWER_2_D; ML_DSA_NTT_COEFFICIENTS];
        verify_ml_dsa_ntt_multiply(polynomial_proof.scale, &t1[index], &multiplier, &scaled)?;
        verify_ml_dsa_ntt(polynomial_proof.ntt, &scaled, &output[index])?;
    }
    Ok(())
}

fn prove_polynomial(t1: &Polynomial) -> Result<(T1PolynomialProof, Polynomial), &'static str> {
    let multiplier = [POWER_2_D; ML_DSA_NTT_COEFFICIENTS];
    let (scale, scaled) = prove_ml_dsa_ntt_multiply(t1, &multiplier)?;
    let (ntt, output) = prove_ml_dsa_ntt(&scaled)?;
    Ok((T1PolynomialProof { scale, ntt }, output))
}

fn scaled_polynomial(t1: &Polynomial) -> Polynomial {
    t1.map(|coefficient| {
        ((u64::from(coefficient) * u64::from(POWER_2_D)) % u64::from(ML_DSA_Q)) as u32
    })
}

fn validate_t1(t1: &Vector) -> Result<(), &'static str> {
    if t1.iter().flatten().any(|coefficient| *coefficient >= T1_COEFFICIENT_BOUND) {
        return Err("ML-DSA t1 coefficient exceeds its canonical 10-bit range");
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

    #[test]
    fn t1_precompute_composes_scaling_and_forward_ntt_for_all_polynomials() {
        let t1 = t1_fixture();
        let (proof, output) = prove_ml_dsa44_t1_precompute(&t1).unwrap();
        verify_ml_dsa44_t1_precompute(proof, &t1, &output).unwrap();
    }

    #[test]
    fn t1_precompute_rejects_input_output_and_range_substitution() {
        let t1 = t1_fixture();
        let (proof, output) = prove_ml_dsa44_t1_precompute(&t1).unwrap();
        let mut substituted_t1 = t1;
        substituted_t1[2][19] = (substituted_t1[2][19] + 1) % T1_COEFFICIENT_BOUND;
        assert!(verify_ml_dsa44_t1_precompute(proof, &substituted_t1, &output).is_err());

        let (proof, mut output) = prove_ml_dsa44_t1_precompute(&t1).unwrap();
        output[3][7] = (output[3][7] + 1) % ML_DSA_Q;
        assert!(verify_ml_dsa44_t1_precompute(proof, &t1, &output).is_err());

        let mut invalid = t1;
        invalid[0][0] = T1_COEFFICIENT_BOUND;
        assert!(prove_ml_dsa44_t1_precompute(&invalid).is_err());
    }
}
