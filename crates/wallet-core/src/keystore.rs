//! Passphrase-protected local keystore for testnet wallet seeds.
//!
//! The format is a local operator artifact, not a canonical protocol value: a salted,
//! iterated SHAKE256 key derivation feeds the same domain-separated stream-and-tag
//! discipline used by the crypto-provider `ProtectedEnvelope`. The derivation is
//! deliberately simple and deterministic; it is not a memory-hard KDF, and the iteration
//! floor exists to keep offline guessing costly rather than to claim hardware resistance.

use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::WalletError;

const KEYSTORE_MAGIC: &[u8; 8] = b"ACWKS01\0";
const KDF_DOMAIN: &[u8] = b"ACTIVECHAIN-WALLET-KEYSTORE-KDF-V1";
const STREAM_DOMAIN: &[u8] = b"ACTIVECHAIN-WALLET-KEYSTORE-STREAM-V1";
const TAG_DOMAIN: &[u8] = b"ACTIVECHAIN-WALLET-KEYSTORE-TAG-V1";

pub const KEYSTORE_SALT_LENGTH: usize = 32;
pub const KEYSTORE_SEED_LENGTH: usize = 32;
pub const KEYSTORE_TAG_LENGTH: usize = 48;
pub const KEYSTORE_MIN_ITERATIONS: u32 = 100_000;
pub const KEYSTORE_MAX_ITERATIONS: u32 = 100_000_000;
pub const KEYSTORE_ENCODED_LENGTH: usize =
    8 + KEYSTORE_SALT_LENGTH + 4 + KEYSTORE_SEED_LENGTH + KEYSTORE_TAG_LENGTH;

fn derive_key(passphrase: &[u8], salt: &[u8; KEYSTORE_SALT_LENGTH], iterations: u32) -> [u8; 32] {
    let mut key = [0_u8; 32];
    let mut hasher = Shake256::default();
    hasher.update(KDF_DOMAIN);
    hasher.update(salt);
    hasher.update(&iterations.to_be_bytes());
    hasher.update(&(passphrase.len() as u64).to_be_bytes());
    hasher.update(passphrase);
    hasher.finalize_xof().read(&mut key);
    for _ in 1..iterations {
        let mut round = Shake256::default();
        round.update(KDF_DOMAIN);
        round.update(salt);
        round.update(&key);
        round.finalize_xof().read(&mut key);
    }
    key
}

fn stream(key: &[u8; 32], salt: &[u8; KEYSTORE_SALT_LENGTH], input: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(STREAM_DOMAIN);
    hasher.update(key);
    hasher.update(salt);
    let mut pad = alloc::vec![0; input.len()];
    hasher.finalize_xof().read(&mut pad);
    input.iter().zip(pad).map(|(left, right)| left ^ right).collect()
}

fn tag(
    key: &[u8; 32],
    salt: &[u8; KEYSTORE_SALT_LENGTH],
    iterations: u32,
    encrypted: &[u8],
) -> [u8; KEYSTORE_TAG_LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(TAG_DOMAIN);
    hasher.update(key);
    hasher.update(salt);
    hasher.update(&iterations.to_be_bytes());
    hasher.update(&(encrypted.len() as u64).to_be_bytes());
    hasher.update(encrypted);
    let mut output = [0; KEYSTORE_TAG_LENGTH];
    hasher.finalize_xof().read(&mut output);
    output
}

fn constant_time_equal(
    left: &[u8; KEYSTORE_TAG_LENGTH],
    right: &[u8; KEYSTORE_TAG_LENGTH],
) -> bool {
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Seals one 32-byte signing seed under a passphrase and caller-supplied random salt.
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
    let mut key = derive_key(passphrase, &salt, iterations);
    let encrypted = stream(&key, &salt, seed);
    let tag = tag(&key, &salt, iterations, &encrypted);
    key.fill(0);
    let mut bytes = Vec::with_capacity(KEYSTORE_ENCODED_LENGTH);
    bytes.extend_from_slice(KEYSTORE_MAGIC);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&iterations.to_be_bytes());
    bytes.extend_from_slice(&encrypted);
    bytes.extend_from_slice(&tag);
    Ok(bytes)
}

/// Returns whether the bytes carry the protected keystore magic.
#[must_use]
pub fn is_keystore(bytes: &[u8]) -> bool {
    bytes.len() >= KEYSTORE_MAGIC.len() && &bytes[..KEYSTORE_MAGIC.len()] == KEYSTORE_MAGIC
}

/// Opens a sealed keystore, failing closed on truncation, tampering, or a wrong passphrase.
pub fn open_seed(
    bytes: &[u8],
    passphrase: &[u8],
) -> Result<[u8; KEYSTORE_SEED_LENGTH], WalletError> {
    if bytes.len() != KEYSTORE_ENCODED_LENGTH || !is_keystore(bytes) {
        return Err(WalletError::MalformedAuthorization);
    }
    let salt: [u8; KEYSTORE_SALT_LENGTH] =
        bytes[8..8 + KEYSTORE_SALT_LENGTH].try_into().expect("checked length");
    let iteration_start = 8 + KEYSTORE_SALT_LENGTH;
    let iterations = u32::from_be_bytes(
        bytes[iteration_start..iteration_start + 4].try_into().expect("checked length"),
    );
    if !(KEYSTORE_MIN_ITERATIONS..=KEYSTORE_MAX_ITERATIONS).contains(&iterations) {
        return Err(WalletError::MalformedAuthorization);
    }
    let encrypted_start = iteration_start + 4;
    let encrypted = &bytes[encrypted_start..encrypted_start + KEYSTORE_SEED_LENGTH];
    let stored_tag: [u8; KEYSTORE_TAG_LENGTH] =
        bytes[encrypted_start + KEYSTORE_SEED_LENGTH..].try_into().expect("checked length");
    let mut key = derive_key(passphrase, &salt, iterations);
    let expected = tag(&key, &salt, iterations, encrypted);
    if !constant_time_equal(&expected, &stored_tag) {
        key.fill(0);
        return Err(WalletError::InvalidSignature);
    }
    let seed = stream(&key, &salt, encrypted);
    key.fill(0);
    Ok(seed.try_into().expect("checked length"))
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
    fn distinct_salts_and_passphrases_change_every_component() {
        let seed = [7_u8; KEYSTORE_SEED_LENGTH];
        let first = seal_seed(&seed, b"pass", [1; 32], KEYSTORE_MIN_ITERATIONS).unwrap();
        let second = seal_seed(&seed, b"pass", [2; 32], KEYSTORE_MIN_ITERATIONS).unwrap();
        let third = seal_seed(&seed, b"other", [1; 32], KEYSTORE_MIN_ITERATIONS).unwrap();
        assert_ne!(first, second);
        assert_ne!(first, third);
    }
}
