#![forbid(unsafe_code)]

//! Cryptographic provider boundary for authoritative PQ verification.

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature, Verifier, VerifyingKey};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    InvalidKeyLength,
    InvalidSignatureLength,
    MalformedKey,
    MalformedSignature,
    InvalidSignature,
}

pub fn verify_ml_dsa44(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerificationError> {
    let key: EncodedVerifyingKey<MlDsa44> =
        public_key.try_into().map_err(|_| VerificationError::InvalidKeyLength)?;
    let sig: EncodedSignature<MlDsa44> =
        signature.try_into().map_err(|_| VerificationError::InvalidSignatureLength)?;
    let verifying_key = VerifyingKey::<MlDsa44>::decode(&key);
    let signature =
        Signature::<MlDsa44>::decode(&sig).ok_or(VerificationError::MalformedSignature)?;
    verifying_key.verify(message, &signature).map_err(|_| VerificationError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    #[test]
    fn verifies_a_real_ml_dsa44_signature() {
        let seed = Seed::default();
        let signing_key = SigningKey::<MlDsa44>::from_seed(&seed);
        let message = b"activechain-pq-testnet";
        let signature = signing_key.sign(message);
        assert!(
            verify_ml_dsa44(
                signing_key.verifying_key().encode().as_slice(),
                message,
                signature.encode().as_slice()
            )
            .is_ok()
        );
        assert_eq!(
            verify_ml_dsa44(
                signing_key.verifying_key().encode().as_slice(),
                b"tampered",
                signature.encode().as_slice()
            ),
            Err(VerificationError::InvalidSignature)
        );
    }
}
