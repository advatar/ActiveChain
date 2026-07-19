#![no_std]
#![forbid(unsafe_code)]

//! ActiveChain's bounded canonical binary codec.
//!
//! Consensus encodings are implemented explicitly rather than through a
//! general serialization framework. Every top-level value carries a type tag,
//! schema version, and minimally encoded bounded body length.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// The largest body length representable by the canonical length encoding.
pub const MAX_BODY_LENGTH: usize = u32::MAX as usize;

const TYPE_TAG_LENGTH: usize = core::mem::size_of::<u16>();
const SCHEMA_VERSION_LENGTH: usize = core::mem::size_of::<u16>();
const MAX_LENGTH_PREFIX_LENGTH: usize = 5;

/// A failure while producing canonical bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// A field length exceeds its schema-declared maximum.
    LengthLimitExceeded { length: usize, maximum: usize },
    /// The output would exceed the enclosing type's bound.
    OutputLimitExceeded { attempted: usize, maximum: usize },
    /// Checked length arithmetic overflowed the host `usize`.
    LengthOverflow,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthLimitExceeded { length, maximum } => {
                write!(formatter, "length {length} exceeds maximum {maximum}")
            }
            Self::OutputLimitExceeded { attempted, maximum } => {
                write!(formatter, "output length {attempted} exceeds maximum {maximum}")
            }
            Self::LengthOverflow => formatter.write_str("length arithmetic overflowed"),
        }
    }
}

/// A failure while decoding canonical bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The input ended before the requested value was complete.
    UnexpectedEnd { needed: usize, remaining: usize },
    /// The envelope does not contain the requested consensus type.
    InvalidTypeTag { expected: u16, actual: u16 },
    /// The envelope uses a schema version unsupported by this decoder.
    UnsupportedSchemaVersion { expected: u16, actual: u16 },
    /// A ULEB128 length used more bytes than its value requires.
    NonMinimalLength,
    /// A ULEB128 length does not fit the protocol's `u32` length space.
    LengthOverflow,
    /// A decoded field length exceeds its schema-declared maximum.
    LengthLimitExceeded { length: usize, maximum: usize },
    /// A Boolean byte was neither zero nor one.
    InvalidBoolean(u8),
    /// An enum discriminant is not registered for the named type.
    InvalidEnumTag { type_name: &'static str, tag: u8 },
    /// A decoded value violates a semantic invariant of its schema.
    InvalidValue(&'static str),
    /// Bytes remained after the requested value was decoded.
    TrailingData { remaining: usize },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd { needed, remaining } => {
                write!(formatter, "needed {needed} bytes, but only {remaining} remain")
            }
            Self::InvalidTypeTag { expected, actual } => {
                write!(formatter, "expected type tag {expected:#06x}, got {actual:#06x}")
            }
            Self::UnsupportedSchemaVersion { expected, actual } => {
                write!(formatter, "expected schema version {expected}, got {actual}")
            }
            Self::NonMinimalLength => formatter.write_str("length is not minimally encoded"),
            Self::LengthOverflow => formatter.write_str("length does not fit in u32"),
            Self::LengthLimitExceeded { length, maximum } => {
                write!(formatter, "length {length} exceeds maximum {maximum}")
            }
            Self::InvalidBoolean(tag) => write!(formatter, "invalid Boolean tag {tag}"),
            Self::InvalidEnumTag { type_name, tag } => {
                write!(formatter, "invalid {type_name} tag {tag}")
            }
            Self::InvalidValue(reason) => write!(formatter, "invalid value: {reason}"),
            Self::TrailingData { remaining } => {
                write!(formatter, "{remaining} trailing bytes remain")
            }
        }
    }
}

/// A value that can append its canonical body encoding to an [`Encoder`].
pub trait CanonicalEncode {
    /// Writes this value in canonical field order.
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError>;
}

/// A value that can be decoded from a canonical body.
pub trait CanonicalDecode: Sized {
    /// Decodes one value, advancing the decoder exactly past its fields.
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError>;
}

/// Metadata required for a top-level consensus value.
pub trait CanonicalType: CanonicalEncode + CanonicalDecode {
    /// Globally registered type tag.
    const TYPE_TAG: u16;
    /// Schema version interpreted by this Rust type.
    const SCHEMA_VERSION: u16;
    /// Maximum canonical body size, checked before decoding.
    const MAX_ENCODED_LEN: usize;
}

/// A bounded append-only canonical encoder.
#[derive(Debug)]
pub struct Encoder {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Encoder {
    /// Creates an empty encoder which will never grow beyond `maximum` bytes.
    #[must_use]
    pub fn new(maximum: usize) -> Self {
        Self { bytes: Vec::new(), maximum }
    }

    /// Returns the number of bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when no bytes have been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Appends a single byte.
    pub fn write_u8(&mut self, value: u8) -> Result<(), EncodeError> {
        self.write_raw(&[value])
    }

    /// Appends a big-endian `u16`.
    pub fn write_u16(&mut self, value: u16) -> Result<(), EncodeError> {
        self.write_raw(&value.to_be_bytes())
    }

    /// Appends a big-endian `u32`.
    pub fn write_u32(&mut self, value: u32) -> Result<(), EncodeError> {
        self.write_raw(&value.to_be_bytes())
    }

    /// Appends a big-endian `u64`.
    pub fn write_u64(&mut self, value: u64) -> Result<(), EncodeError> {
        self.write_raw(&value.to_be_bytes())
    }

    /// Appends a big-endian `u128`.
    pub fn write_u128(&mut self, value: u128) -> Result<(), EncodeError> {
        self.write_raw(&value.to_be_bytes())
    }

    /// Appends a canonical Boolean byte.
    pub fn write_bool(&mut self, value: bool) -> Result<(), EncodeError> {
        self.write_u8(u8::from(value))
    }

    /// Appends an already-canonical fixed-size byte sequence.
    pub fn write_raw(&mut self, value: &[u8]) -> Result<(), EncodeError> {
        let attempted =
            self.bytes.len().checked_add(value.len()).ok_or(EncodeError::LengthOverflow)?;
        if attempted > self.maximum {
            return Err(EncodeError::OutputLimitExceeded { attempted, maximum: self.maximum });
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    /// Appends a minimally encoded `u32` ULEB128 length after checking `maximum`.
    pub fn write_length(&mut self, length: usize, maximum: usize) -> Result<(), EncodeError> {
        if length > maximum || length > MAX_BODY_LENGTH {
            return Err(EncodeError::LengthLimitExceeded {
                length,
                maximum: maximum.min(MAX_BODY_LENGTH),
            });
        }

        let mut value = u32::try_from(length).map_err(|_| EncodeError::LengthOverflow)?;
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.write_u8(byte)?;
            if value == 0 {
                return Ok(());
            }
        }
    }

    /// Appends a bounded length-prefixed byte string.
    pub fn write_bytes(&mut self, value: &[u8], maximum: usize) -> Result<(), EncodeError> {
        self.write_length(value.len(), maximum)?;
        self.write_raw(value)
    }

    /// Finishes encoding and returns the bounded byte buffer.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// A non-allocating cursor over untrusted canonical bytes.
#[derive(Clone, Debug)]
pub struct Decoder<'input> {
    input: &'input [u8],
    offset: usize,
}

impl<'input> Decoder<'input> {
    /// Creates a decoder positioned at the start of `input`.
    #[must_use]
    pub const fn new(input: &'input [u8]) -> Self {
        Self { input, offset: 0 }
    }

    /// Returns the number of unread bytes.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }

    /// Reads a single byte.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_raw(1)?[0])
    }

    /// Reads a big-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    /// Reads a big-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    /// Reads a big-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    /// Reads a big-endian `u128`.
    pub fn read_u128(&mut self) -> Result<u128, DecodeError> {
        Ok(u128::from_be_bytes(self.read_array()?))
    }

    /// Reads a canonical Boolean byte.
    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(DecodeError::InvalidBoolean(tag)),
        }
    }

    /// Reads exactly `length` bytes without allocating.
    pub fn read_raw(&mut self, length: usize) -> Result<&'input [u8], DecodeError> {
        let remaining = self.remaining();
        if length > remaining {
            return Err(DecodeError::UnexpectedEnd { needed: length, remaining });
        }
        let end = self.offset.checked_add(length).ok_or(DecodeError::LengthOverflow)?;
        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    /// Reads a fixed-size byte array.
    pub fn read_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], DecodeError> {
        let mut value = [0_u8; LENGTH];
        value.copy_from_slice(self.read_raw(LENGTH)?);
        Ok(value)
    }

    /// Reads a minimal `u32` ULEB128 length and checks it against `maximum`.
    pub fn read_length(&mut self, maximum: usize) -> Result<usize, DecodeError> {
        let mut value = 0_u32;
        for index in 0..MAX_LENGTH_PREFIX_LENGTH {
            let byte = self.read_u8()?;
            if index == MAX_LENGTH_PREFIX_LENGTH - 1 && byte > 0x0f {
                return Err(DecodeError::LengthOverflow);
            }

            value |= u32::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                if index > 0 && byte == 0 {
                    return Err(DecodeError::NonMinimalLength);
                }
                let length = value as usize;
                if length > maximum {
                    return Err(DecodeError::LengthLimitExceeded { length, maximum });
                }
                return Ok(length);
            }
        }
        Err(DecodeError::LengthOverflow)
    }

    /// Reads a bounded length-prefixed byte string without allocating.
    pub fn read_bytes(&mut self, maximum: usize) -> Result<&'input [u8], DecodeError> {
        let length = self.read_length(maximum)?;
        self.read_raw(length)
    }

    /// Succeeds only if the input has been consumed exactly.
    pub fn finish(self) -> Result<(), DecodeError> {
        let remaining = self.remaining();
        if remaining == 0 { Ok(()) } else { Err(DecodeError::TrailingData { remaining }) }
    }
}

/// Encodes only the canonical body of a typed value.
pub fn encode_body<T: CanonicalType>(value: &T) -> Result<Vec<u8>, EncodeError> {
    if T::MAX_ENCODED_LEN > MAX_BODY_LENGTH {
        return Err(EncodeError::LengthLimitExceeded {
            length: T::MAX_ENCODED_LEN,
            maximum: MAX_BODY_LENGTH,
        });
    }
    let mut encoder = Encoder::new(T::MAX_ENCODED_LEN);
    value.encode(&mut encoder)?;
    Ok(encoder.finish())
}

/// Encodes a value with its type tag, schema version, and bounded body length.
pub fn encode_envelope<T: CanonicalType>(value: &T) -> Result<Vec<u8>, EncodeError> {
    let body = encode_body(value)?;
    let maximum = T::MAX_ENCODED_LEN
        .checked_add(TYPE_TAG_LENGTH + SCHEMA_VERSION_LENGTH + MAX_LENGTH_PREFIX_LENGTH)
        .ok_or(EncodeError::LengthOverflow)?;
    let mut encoder = Encoder::new(maximum);
    encoder.write_u16(T::TYPE_TAG)?;
    encoder.write_u16(T::SCHEMA_VERSION)?;
    encoder.write_length(body.len(), T::MAX_ENCODED_LEN)?;
    encoder.write_raw(&body)?;
    Ok(encoder.finish())
}

/// Strictly decodes exactly one enveloped value of `T`.
pub fn decode_envelope<T: CanonicalType>(input: &[u8]) -> Result<T, DecodeError> {
    let mut envelope = Decoder::new(input);

    let type_tag = envelope.read_u16()?;
    if type_tag != T::TYPE_TAG {
        return Err(DecodeError::InvalidTypeTag { expected: T::TYPE_TAG, actual: type_tag });
    }

    let schema_version = envelope.read_u16()?;
    if schema_version != T::SCHEMA_VERSION {
        return Err(DecodeError::UnsupportedSchemaVersion {
            expected: T::SCHEMA_VERSION,
            actual: schema_version,
        });
    }

    let body_length = envelope.read_length(T::MAX_ENCODED_LEN)?;
    let body = envelope.read_raw(body_length)?;
    envelope.finish()?;

    let mut decoder = Decoder::new(body);
    let value = T::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(value)
}

macro_rules! impl_fixed_integer {
    ($integer:ty, $write:ident, $read:ident) => {
        impl CanonicalEncode for $integer {
            fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
                encoder.$write(*self)
            }
        }

        impl CanonicalDecode for $integer {
            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                decoder.$read()
            }
        }
    };
}

impl_fixed_integer!(u8, write_u8, read_u8);
impl_fixed_integer!(u16, write_u16, read_u16);
impl_fixed_integer!(u32, write_u32, read_u32);
impl_fixed_integer!(u64, write_u64, read_u64);
impl_fixed_integer!(u128, write_u128, read_u128);

impl CanonicalEncode for bool {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_bool(*self)
    }
}

impl CanonicalDecode for bool {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_bool()
    }
}

impl<T: CanonicalEncode> CanonicalEncode for Option<T> {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            None => 0_u8.encode(encoder),
            Some(value) => {
                1_u8.encode(encoder)?;
                value.encode(encoder)
            }
        }
    }
}

impl<T: CanonicalDecode> CanonicalDecode for Option<T> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(None),
            1 => Ok(Some(T::decode(decoder)?)),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "Option", tag }),
        }
    }
}

impl<const LENGTH: usize> CanonicalEncode for [u8; LENGTH] {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_raw(self)
    }
}

impl<const LENGTH: usize> CanonicalDecode for [u8; LENGTH] {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_array()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;

    use proptest::prelude::*;

    use super::{
        CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError,
        Encoder, decode_envelope, encode_envelope,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Example {
        number: u64,
        enabled: bool,
    }

    impl CanonicalEncode for Example {
        fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
            self.number.encode(encoder)?;
            self.enabled.encode(encoder)
        }
    }

    impl CanonicalDecode for Example {
        fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            Ok(Self { number: u64::decode(decoder)?, enabled: bool::decode(decoder)? })
        }
    }

    impl CanonicalType for Example {
        const TYPE_TAG: u16 = 0x1234;
        const SCHEMA_VERSION: u16 = 1;
        const MAX_ENCODED_LEN: usize = 9;
    }

    #[test]
    fn envelope_has_exact_declared_layout() {
        let encoded = encode_envelope(&Example { number: 0x0102_0304_0506_0708, enabled: true })
            .expect("bounded example encodes");
        assert_eq!(
            encoded,
            vec![
                0x12, 0x34, 0x00, 0x01, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01
            ]
        );
    }

    #[test]
    fn decoder_rejects_wrong_type_version_and_trailing_data() {
        let encoded = encode_envelope(&Example { number: 7, enabled: false }).expect("encodes");

        let mut wrong_type = encoded.clone();
        wrong_type[1] ^= 1;
        assert!(matches!(
            decode_envelope::<Example>(&wrong_type),
            Err(DecodeError::InvalidTypeTag { .. })
        ));

        let mut wrong_version = encoded.clone();
        wrong_version[3] = 2;
        assert!(matches!(
            decode_envelope::<Example>(&wrong_version),
            Err(DecodeError::UnsupportedSchemaVersion { .. })
        ));

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_envelope::<Example>(&trailing),
            Err(DecodeError::TrailingData { remaining: 1 })
        );
    }

    #[test]
    fn decoder_rejects_non_minimal_and_overflowing_lengths() {
        let non_minimal = [0x12, 0x34, 0x00, 0x01, 0x89, 0x00];
        assert_eq!(decode_envelope::<Example>(&non_minimal), Err(DecodeError::NonMinimalLength));

        let overflowing = [0x12, 0x34, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x10];
        assert_eq!(decode_envelope::<Example>(&overflowing), Err(DecodeError::LengthOverflow));
    }

    #[test]
    fn byte_strings_are_bounded_before_their_payload_is_read() {
        let mut decoder = Decoder::new(&[0x04, 1, 2, 3, 4]);
        assert_eq!(
            decoder.read_bytes(3),
            Err(DecodeError::LengthLimitExceeded { length: 4, maximum: 3 })
        );
        assert_eq!(decoder.remaining(), 4);
    }

    #[test]
    fn options_have_one_canonical_presence_tag() {
        let mut encoder = Encoder::new(9);
        Some(9_u64).encode(&mut encoder).expect("option fits");
        assert_eq!(encoder.finish(), vec![1, 0, 0, 0, 0, 0, 0, 0, 9]);

        let mut decoder = Decoder::new(&[2]);
        assert_eq!(
            Option::<u64>::decode(&mut decoder),
            Err(DecodeError::InvalidEnumTag { type_name: "Option", tag: 2 })
        );
    }

    proptest! {
        #[test]
        fn arbitrary_examples_round_trip(number: u64, enabled: bool) {
            let value = Example { number, enabled };
            let bytes = encode_envelope(&value).expect("fixed-size value fits its bound");
            prop_assert_eq!(decode_envelope::<Example>(&bytes), Ok(value));
        }
    }
}
