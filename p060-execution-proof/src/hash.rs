//! The suite's 384-bit SHAKE256 transcript and Merkle hasher.
//!
//! Winterfell's `Digest::as_bytes()` API exposes 32 bytes to its random coin. Merkle roots and
//! serialized commitments retain all 48 bytes. Thus commitment collision resistance is 192 bits
//! classically (about 128 bits against generic quantum collision search), while the transcript
//! coin exposes 256 bits (128 bits against generic quantum preimage search).

use core::fmt;
use core::marker::PhantomData;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use winterfell::crypto::{Digest, ElementHasher, Hasher};
use winterfell::math::{FieldElement, StarkField};

/// A full 384-bit digest. Serialization never truncates this value.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Digest384([u8; 48]);

impl Digest384 {
    pub const LEN: usize = 48;

    pub const fn new(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }

    pub const fn into_bytes(self) -> [u8; 48] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Default for Digest384 {
    fn default() -> Self {
        Self([0; 48])
    }
}

impl fmt::Debug for Digest384 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest384({})", hex::encode(self.0))
    }
}

impl Digest for Digest384 {
    fn as_bytes(&self) -> [u8; 32] {
        self.0[..32].try_into().expect("fixed-size slice")
    }
}

impl Serializable for Digest384 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }

    fn get_size_hint(&self) -> usize {
        Self::LEN
    }
}

impl Deserializable for Digest384 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(source.read_array()?))
    }
}

/// SHAKE256 with 384-bit output, domain-separated for every Winterfell hashing operation.
pub struct Shake256_384<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Shake256_384<B> {
    fn digest(parts: &[&[u8]]) -> Digest384 {
        let mut h = Shake256::default();
        for part in parts {
            h.update(part);
        }
        let mut reader = h.finalize_xof();
        let mut out = [0_u8; 48];
        reader.read(&mut out);
        Digest384(out)
    }
}

impl<B: StarkField> Hasher for Shake256_384<B> {
    type Digest = Digest384;

    // Classical collision resistance. The generic quantum collision cost is about 2^128.
    const COLLISION_RESISTANCE: u32 = 192;

    fn hash(bytes: &[u8]) -> Self::Digest {
        Self::digest(&[
            b"P060-WF-HASH-v1\0",
            &(bytes.len() as u64).to_be_bytes(),
            bytes,
        ])
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        Self::digest(&[
            b"P060-WF-MERGE2-v1\0",
            values[0].as_slice(),
            values[1].as_slice(),
        ])
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        let mut h = Shake256::default();
        h.update(b"P060-WF-MERGEN-v1\0");
        h.update(&(values.len() as u64).to_be_bytes());
        for value in values {
            h.update(value.as_slice());
        }
        let mut reader = h.finalize_xof();
        let mut out = [0_u8; 48];
        reader.read(&mut out);
        Digest384(out)
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        Self::digest(&[
            b"P060-WF-MERGE-U64-v1\0",
            seed.as_slice(),
            &value.to_be_bytes(),
        ])
    }
}

impl<B: StarkField> ElementHasher for Shake256_384<B> {
    type BaseField = B;

    fn hash_elements<E>(elements: &[E]) -> Self::Digest
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let mut encoded = Vec::with_capacity(elements.len() * E::ELEMENT_BYTES);
        encoded.write_many(elements);
        Self::digest(&[
            b"P060-WF-ELEMENTS-v1\0",
            &(elements.len() as u64).to_be_bytes(),
            &encoded,
        ])
    }
}

/// Protocol-boundary SHAKE256/384 with a required domain string and length binding.
pub fn boundary_hash(domain: &[u8], payload: &[u8]) -> [u8; 48] {
    let mut h = Shake256::default();
    h.update(b"P060-BOUNDARY-v1\0");
    h.update(&(domain.len() as u16).to_be_bytes());
    h.update(domain);
    h.update(&(payload.len() as u64).to_be_bytes());
    h.update(payload);
    let mut reader = h.finalize_xof();
    let mut out = [0_u8; 48];
    reader.read(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::math::fields::f64::BaseElement;

    #[test]
    fn domains_and_lengths_are_bound() {
        assert_ne!(boundary_hash(b"a", b"bc"), boundary_hash(b"ab", b"c"));
        assert_ne!(
            Shake256_384::<BaseElement>::hash(b"x"),
            Shake256_384::<BaseElement>::hash(b"x\0")
        );
    }

    #[test]
    fn digest_serialization_is_48_bytes() {
        let digest = Shake256_384::<BaseElement>::hash(b"test");
        let bytes = Serializable::to_bytes(&digest);
        assert_eq!(48, bytes.len());
        assert_eq!(digest, Digest384::read_from_bytes(&bytes).unwrap());
    }
}
