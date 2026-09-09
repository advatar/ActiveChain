use crate::model::Signed;
use crate::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub fn random_key() -> Result<SigningKey> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut())
        .map_err(|_| Error::new("entropy", "OS randomness unavailable"))?;
    Ok(SigningKey::from_bytes(&seed))
}
pub fn public_key(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}
pub fn parse_public(value: &str) -> Result<VerifyingKey> {
    let bytes = decode::<32>(value)?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| Error::invalid("invalid Ed25519 public key"))?;
    if key.is_weak() {
        return Err(Error::invalid("weak Ed25519 public key"));
    }
    Ok(key)
}
pub fn decode<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N * 2
        || s.bytes()
            .any(|c| !c.is_ascii_digit() && !(b'a'..=b'f').contains(&c))
    {
        return Err(Error::invalid(
            "expected fixed-length lowercase hexadecimal",
        ));
    }
    let mut out = [0; N];
    hex::decode_to_slice(s, &mut out).map_err(|_| Error::invalid("invalid hex"))?;
    Ok(out)
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn authority_id(key: &str) -> Result<String> {
    parse_public(key)?;
    Ok(digest(
        format!("AnyIdentity/authority/v1\0{key}").as_bytes(),
    ))
}
// This protocol uses its own versioned restricted JSON encoding, not RFC 8785 JCS.
// Round-trip through Value sorts object keys recursively. Model fields use integers,
// strings, booleans, ordered sets, arrays and null; there are no floats.
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let v = serde_json::to_value(value).map_err(Error::json)?;
    serde_json::to_vec(&v).map_err(Error::json)
}
fn transcript<T: Serialize>(kind: &str, signer: &str, payload: &T) -> Result<Vec<u8>> {
    canonical(&serde_json::json!({"protocol":"AnyIdentity", "version":1,
        "kind":kind, "signer":signer, "payload":payload}))
}
pub fn sign<T: Serialize>(key: &SigningKey, kind: &str, payload: T) -> Result<Signed<T>> {
    let signer = public_key(key);
    let signature = hex::encode(key.sign(&transcript(kind, &signer, &payload)?).to_bytes());
    Ok(Signed {
        version: 1,
        kind: kind.into(),
        signer,
        payload,
        signature,
    })
}
pub fn verify<T: Serialize>(value: &Signed<T>, kind: &str, expected: &str) -> Result<()> {
    if value.version != 1 || value.kind != kind || value.signer != expected {
        return Err(Error::new(
            "signature",
            "signature context or signer mismatch",
        ));
    }
    let public = parse_public(expected)?;
    let signature = Signature::from_bytes(&decode::<64>(&value.signature)?);
    public
        .verify_strict(&transcript(kind, expected, &value.payload)?, &signature)
        .map_err(|_| Error::new("signature", "invalid signature"))
}
pub fn signed_digest<T: Serialize>(value: &Signed<T>) -> Result<String> {
    let mut bytes = b"AnyIdentity/envelope/v1\0".to_vec();
    bytes.extend(canonical(value)?);
    Ok(digest(&bytes))
}
pub fn derive(key: &SigningKey, audience: &str) -> Result<SigningKey> {
    crate::protocol::nonempty(audience)?;
    let secret = Zeroizing::new(key.to_bytes());
    let hk = Hkdf::<Sha256>::new(Some(b"AnyIdentity/pairwise/v1"), secret.as_ref());
    let mut seed = Zeroizing::new([0u8; 32]);
    hk.expand(audience.as_bytes(), seed.as_mut())
        .map_err(|_| Error::invalid("derivation failed"))?;
    Ok(SigningKey::from_bytes(&seed))
}
