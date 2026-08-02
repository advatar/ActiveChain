use alloc::vec::Vec;

use activechain_protocol_types::ML_DSA44_PUBLIC_KEY_LENGTH;

use crate::{
    ML_DSA_44_VECTOR_DIMENSION, ML_DSA_NTT_COEFFICIENTS, ML_DSA44_SIGNATURE_LENGTH,
    MlDsa44DecodedVerifierInputs, MlDsa44DecodingStarkProof, MlDsa44ExpandAStarkProof,
    MlDsa44VerifierStarkProof, Shake256XofStarkProof, prove_ml_dsa44_decoding,
    prove_ml_dsa44_expand_a, prove_ml_dsa44_verifier, prove_shake256_xof, verify_ml_dsa44_decoding,
    verify_ml_dsa44_expand_a, verify_ml_dsa44_verifier, verify_shake256_xof,
};

const TR_BYTES: usize = 64;
const MU_BYTES: usize = 64;
const NORMAL_MODE_PREFIX: [u8; 2] = [0, 0];

type Polynomial = [u32; ML_DSA_NTT_COEFFICIENTS];
type Vector = [Polynomial; ML_DSA_44_VECTOR_DIMENSION];
type Matrix = [Vector; ML_DSA_44_VECTOR_DIMENSION];

/// One composed ML-DSA-44 verifier statement with every intermediate table explicitly bound.
pub struct MlDsa44CrossTableStarkProof {
    decoding: MlDsa44DecodingStarkProof,
    decoded: MlDsa44DecodedVerifierInputs,
    tr_hash: Shake256XofStarkProof,
    tr: [u8; TR_BYTES],
    mu_hash: Shake256XofStarkProof,
    mu: [u8; MU_BYTES],
    expand_a: MlDsa44ExpandAStarkProof,
    matrix: Matrix,
    verifier: MlDsa44VerifierStarkProof,
}

pub fn prove_ml_dsa44_cross_table(
    key: &[u8; ML_DSA44_PUBLIC_KEY_LENGTH],
    signature: &[u8; ML_DSA44_SIGNATURE_LENGTH],
    payload: &[u8],
) -> Result<MlDsa44CrossTableStarkProof, &'static str> {
    let (decoding, decoded) = prove_ml_dsa44_decoding(key, signature)?;

    let tr_hash = prove_shake256_xof(key, TR_BYTES)?;
    let tr: [u8; TR_BYTES] =
        tr_hash.output().try_into().map_err(|_| "ML-DSA tr length mismatch")?;
    let mu_transcript = mu_transcript(&tr, payload)?;
    let mu_hash = prove_shake256_xof(&mu_transcript, MU_BYTES)?;
    let mu: [u8; MU_BYTES] =
        mu_hash.output().try_into().map_err(|_| "ML-DSA mu length mismatch")?;

    let (expand_a, matrix) = prove_ml_dsa44_expand_a(&decoded.rho)?;
    let t1 = decoded.t1.map(|polynomial| polynomial.map(u32::from));
    let verifier = prove_ml_dsa44_verifier(
        &matrix,
        &t1,
        &decoded.z,
        &decoded.challenge_seed,
        &decoded.hints,
        &mu,
    )?;
    Ok(MlDsa44CrossTableStarkProof {
        decoding,
        decoded,
        tr_hash,
        tr,
        mu_hash,
        mu,
        expand_a,
        matrix,
        verifier,
    })
}

pub fn verify_ml_dsa44_cross_table(
    proof: MlDsa44CrossTableStarkProof,
    key: &[u8; ML_DSA44_PUBLIC_KEY_LENGTH],
    signature: &[u8; ML_DSA44_SIGNATURE_LENGTH],
    payload: &[u8],
) -> Result<(), &'static str> {
    verify_ml_dsa44_decoding(proof.decoding, key, signature, &proof.decoded)?;
    verify_shake256_xof(&proof.tr_hash, key, &proof.tr)?;
    let mu_transcript = mu_transcript(&proof.tr, payload)?;
    verify_shake256_xof(&proof.mu_hash, &mu_transcript, &proof.mu)?;
    verify_ml_dsa44_expand_a(&proof.expand_a, &proof.decoded.rho, &proof.matrix)?;
    let t1 = proof.decoded.t1.map(|polynomial| polynomial.map(u32::from));
    verify_ml_dsa44_verifier(
        proof.verifier,
        &proof.matrix,
        &t1,
        &proof.decoded.z,
        &proof.decoded.challenge_seed,
        &proof.decoded.hints,
        &proof.mu,
    )
}

fn mu_transcript(tr: &[u8; TR_BYTES], payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    let capacity = TR_BYTES
        .checked_add(NORMAL_MODE_PREFIX.len())
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or("ML-DSA mu transcript length overflow")?;
    let mut transcript = Vec::with_capacity(capacity);
    transcript.extend_from_slice(tr);
    transcript.extend_from_slice(&NORMAL_MODE_PREFIX);
    transcript.extend_from_slice(payload);
    Ok(transcript)
}

#[cfg(test)]
mod tests {
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};

    use super::*;

    #[test]
    #[ignore = "full ML-DSA cross-table proof is intentionally expensive"]
    fn real_mldsa44_signature_composes_every_verifier_table() {
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([0x42; 32]));
        let payload = b"ActiveChain cross-table ML-DSA proof";
        let signature = key.sign(payload).encode();
        let public_key = key.verifying_key().encode();
        let public_key: &[u8; ML_DSA44_PUBLIC_KEY_LENGTH] =
            public_key.as_slice().try_into().unwrap();
        let signature: &[u8; ML_DSA44_SIGNATURE_LENGTH] = signature.as_slice().try_into().unwrap();

        let proof = prove_ml_dsa44_cross_table(public_key, signature, payload).unwrap();
        verify_ml_dsa44_cross_table(proof, public_key, signature, payload).unwrap();
    }

    #[test]
    fn mu_transcript_uses_fips_normal_mode_empty_context_prefix() {
        let tr = [0x5a; TR_BYTES];
        let transcript = mu_transcript(&tr, b"payload").unwrap();
        assert_eq!(&transcript[..TR_BYTES], &tr);
        assert_eq!(&transcript[TR_BYTES..TR_BYTES + 2], &[0, 0]);
        assert_eq!(&transcript[TR_BYTES + 2..], b"payload");
    }
}
