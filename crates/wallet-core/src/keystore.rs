//! Passphrase-protected local keystore for testnet wallet seeds.
//!
//! Version 2 deliberately replaces the former bespoke SHAKE stream/tag construction with
//! standardized primitives: PBKDF2-HMAC-SHA256 for password derivation and
//! ChaCha20-Poly1305 for authenticated encryption. The format is local wallet state, not a
//! canonical protocol value. Production mobile custody should still prefer a hardware-bound
//! wrapping key supplied by the platform keystore rather than a human passphrase alone.

use activechain_crypto_provider::{AEAD_TAG_LENGTH, aead_open, aead_seal};
use alloc::vec::Vec;
use core::num::NonZeroU32;
use ring::pbkdf2::{self, PBKDF2_HMAC_SHA256};
use zeroize::{Zeroize, Zeroizing};

use crate::WalletError;

const KEYSTORE_MAGIC: &[u8; 8] = b"ACWKS02\0";
const KEYSTORE_NONCE_LENGTH: usize = 12;

pub const KEYSTORE_SALT_LENGTH: usize = 32;
pub const KEYSTORE_SEED_LENGTH: usize = 32;
pub const KEYSTORE_MIN_ITERATIONS: u32 = 100_000;
pub const KEYSTORE_MAX_ITERATIONS: u32 = 100_000_000;
pub const KEYSTORE_ENCODED_LENGTH: usize =
    8 + KEYSTORE_SALT_LENGTH + 4 + KEYSTORE_NONCE_LENGTH + KEYSTORE_SEED_LENGTH + AEAD_TAG_LENGTH;

fn derive_key(
    passphrase: &[u8],
    salt: &[u8; KEYSTORE_SALT_LENGTH],
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let iterations = NonZeroU32::new(iterations).ok_or(WalletError::MalformedAuthorization)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    pbkdf2::derive(PBKDF2_HMAC_SHA256, iterations, salt, passphrase, key.as_mut());
    Ok(key)
}

fn associated_data(
    salt: &[u8; KEYSTORE_SALT_LENGTH],
    iterations: u32,
    nonce: &[u8; KEYSTORE_NONCE_LENGTH],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + KEYSTORE_SALT_LENGTH + 4 + KEYSTORE_NONCE_LENGTH);
    aad.extend_from_slice(KEYSTORE_MAGIC);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(&iterations.to_be_bytes());
    aad.extend_from_slice(nonce);
    aad
}

/// Seals one 32-byte signing seed under a passphrase and caller-supplied random salt.
///
/// A fresh AEAD nonce is generated internally even when callers accidentally reuse a salt.
pub fn seal_seed(
    seed: &[u8; KEYSTORE_SEED_LENGTH],
    passphrase: &[u8],
    salt: [u8; KEYSTORE_SALT_LENGTH],
    iterations: u32,
) -> Result<Vec<u8>, WalletError> {
    if passphrase.is_empty()
        || !(KEYSTORE_MIN_ITERATIONS..=KEYSTORE_MAX_ITERATIONS).contains(&iterations)
    {
        return Err(WalletError::MalformedAuthorization);
    }

    let key = derive_key(passphrase, &salt, iterations)?;
    let mut nonce = [0_u8; KEYSTORE_NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|_| WalletError::Persistence)?;
    let aad = associated_data(&salt, iterations, &nonce);
    let encrypted =
        aead_seal(&key, nonce, &aad, seed).map_err(|_| WalletError::MalformedAuthorization)?;

    let mut bytes = Vec::with_capacity(KEYSTORE_ENCODED_LENGTH);
    bytes.extend_from_slice(KEYSTORE_MAGIC);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&iterations.to_be_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&encrypted);
    nonce.zeroize();
    Ok(bytes)
}

/// Returns whether the bytes carry the version-2 protected keystore magic.
#[must_use]
pub fn is_keystore(bytes: &[u8]) -> bool {
    bytes.len() >= KEYSTORE_MAGIC.len() && &bytes[..KEYSTORE_MAGIC.len()] == KEYSTORE_MAGIC
}

/// Opens a sealed keystore, failing closed on truncation, tampering, legacy v1 data, or a wrong
/// passphrase.
pub fn open_seed(
    bytes: &[u8],
    passphrase: &[u8],
) -> Result<[u8; KEYSTORE_SEED_LENGTH], WalletError> {
    if bytes.len() != KEYSTORE_ENCODED_LENGTH || !is_keystore(bytes) || passphrase.is_empty() {
        return Err(WalletError::MalformedAuthorization);
    }

    let salt: [u8; KEYSTORE_SALT_LENGTH] = bytes[8..8 + KEYSTORE_SALT_LENGTH]
        .try_into()
        .map_err(|_| WalletError::MalformedAuthorization)?;
    let iteration_start = 8 + KEYSTORE_SALT_LENGTH;
    let iterations = u32::from_be_bytes(
        bytes[iteration_start..iteration_start + 4]
            .try_into()
            .map_err(|_| WalletError::MalformedAuthorization)?,
    );
    if !(KEYSTORE_MIN_ITERATIONS..=KEYSTORE_MAX_ITERATIONS).contains(&iterations) {
        return Err(WalletError::MalformedAuthorization);
    }

    let nonce_start = iteration_start + 4;
    let nonce: [u8; KEYSTORE_NONCE_LENGTH] = bytes
        [nonce_start..nonce_start + KEYSTORE_NONCE_LENGTH]
        .try_into()
        .map_err(|_| WalletError::MalformedAuthorization)?;
    let encrypted = &bytes[nonce_start + KEYSTORE_NONCE_LENGTH..];
    if encrypted.len() != KEYSTORE_SEED_LENGTH + AEAD_TAG_LENGTH {
        return Err(WalletError::MalformedAuthorization);
    }

    let key = derive_key(passphrase, &salt, iterations)?;
    let aad = associated_data(&salt, iterations, &nonce);
    let mut seed =
        aead_open(&key, nonce, &aad, encrypted).map_err(|_| WalletError::InvalidSignature)?;
    if seed.len() != KEYSTORE_SEED_LENGTH {
        seed.zeroize();
        return Err(WalletError::MalformedAuthorization);
    }
    let output: [u8; KEYSTORE_SEED_LENGTH] =
        seed.as_slice().try_into().map_err(|_| WalletError::MalformedAuthorization)?;
    seed.zeroize();
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keystore_round_trips_and_fails_closed() {
        let seed = [7_u8; KEYSTORE_SEED_LENGTH];
        let salt = [9_u8; KEYSTORE_SALT_LENGTH];
        let sealed = seal_seed(&seed, b"correct horse", salt, KEYSTORE_MIN_ITERATIONS).unwrap();
        assert_eq!(sealed.len(), KEYSTORE_ENCODED_LENGTH);
        assert!(is_keystore(&sealed));
        assert_eq!(open_seed(&sealed, b"correct horse"), Ok(seed));

        assert_eq!(open_seed(&sealed, b"wrong passphrase"), Err(WalletError::InvalidSignature));
        let mut tampered = sealed.clone();
        tampered[KEYSTORE_ENCODED_LENGTH - 1] ^= 1;
        assert_eq!(open_seed(&tampered, b"correct horse"), Err(WalletError::InvalidSignature));
        let mut wrong_magic = sealed.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            open_seed(&wrong_magic, b"correct horse"),
            Err(WalletError::MalformedAuthorization)
        );
        assert_eq!(
            open_seed(&sealed[..KEYSTORE_ENCODED_LENGTH - 1], b"correct horse"),
            Err(WalletError::MalformedAuthorization)
        );
        assert_eq!(
            seal_seed(&seed, b"", salt, KEYSTORE_MIN_ITERATIONS),
            Err(WalletError::MalformedAuthorization)
        );
        assert_eq!(
            seal_seed(&seed, b"pass", salt, KEYSTORE_MIN_ITERATIONS - 1),
            Err(WalletError::MalformedAuthorization)
        );
    }

    #[test]
    fn repeated_salt_still_gets_fresh_nonce_and_ciphertext() {
        let seed = [7_u8; KEYSTORE_SEED_LENGTH];
        let salt = [1_u8; KEYSTORE_SALT_LENGTH];
        let first = seal_seed(&seed, b"pass", salt, KEYSTORE_MIN_ITERATIONS).unwrap();
        let second = seal_seed(&seed, b"pass", salt, KEYSTORE_MIN_ITERATIONS).unwrap();
        assert_ne!(first, second);
        assert_eq!(open_seed(&first, b"pass"), Ok(seed));
        assert_eq!(open_seed(&second, b"pass"), Ok(seed));
    }

    #[test]
    fn legacy_v1_magic_is_rejected() {
        let mut legacy = vec![0_u8; KEYSTORE_ENCODED_LENGTH];
        legacy[..8].copy_from_slice(b"ACWKS01\0");
        assert!(!is_keystore(&legacy));
        assert_eq!(open_seed(&legacy, b"pass"), Err(WalletError::MalformedAuthorization));
    }
}
