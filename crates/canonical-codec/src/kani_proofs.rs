//! Bounded Kani proofs for the concrete canonical envelope implementation.
//!
//! These harnesses deliberately use a two-byte body and bounded adversarial
//! inputs. They establish safety and strictness for that finite state space;
//! they are not a proof for every schema or arbitrarily large input.

use alloc::vec::Vec;

use super::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    canonical_length_prefix_len, decode_envelope, encode_envelope,
};

const COMPLETE_ENVELOPE_LENGTH: usize = 7;
const MAX_ADVERSARIAL_INPUT_LENGTH: usize = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KaniValue {
    number: u8,
    enabled: bool,
}

impl CanonicalEncode for KaniValue {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.number.encode(encoder)?;
        self.enabled.encode(encoder)
    }
}

impl CanonicalDecode for KaniValue {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { number: u8::decode(decoder)?, enabled: bool::decode(decoder)? })
    }
}

impl CanonicalType for KaniValue {
    const TYPE_TAG: u16 = 0x4b41;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 2;
}

#[kani::proof]
fn fixed_value_round_trips_through_strict_envelope() {
    let value = KaniValue { number: kani::any(), enabled: kani::any() };
    let encoded = encode_envelope(&value).expect("the fixed-size body fits its declared bound");

    assert_eq!(encoded.len(), COMPLETE_ENVELOPE_LENGTH);
    assert_eq!(decode_envelope::<KaniValue>(&encoded), Ok(value));
}

#[kani::proof]
fn every_truncation_of_a_valid_envelope_is_rejected() {
    let value = KaniValue { number: kani::any(), enabled: kani::any() };
    let encoded = encode_envelope(&value).expect("the fixed-size body fits its declared bound");
    let truncated_length: usize = kani::any();
    kani::assume(truncated_length < encoded.len());

    assert!(decode_envelope::<KaniValue>(&encoded[..truncated_length]).is_err());
}

#[kani::proof]
fn every_single_trailing_byte_is_rejected() {
    let value = KaniValue { number: kani::any(), enabled: kani::any() };
    let trailing_byte: u8 = kani::any();
    let mut encoded = encode_envelope(&value).expect("the fixed-size body fits its declared bound");
    encoded.push(trailing_byte);

    assert_eq!(
        decode_envelope::<KaniValue>(&encoded),
        Err(DecodeError::TrailingData { remaining: 1 })
    );
}

#[kani::proof]
fn bounded_adversarial_input_is_safe_and_success_is_canonical() {
    let bytes: [u8; MAX_ADVERSARIAL_INPUT_LENGTH] = kani::any();
    let input_length: usize = kani::any();
    kani::assume(input_length <= MAX_ADVERSARIAL_INPUT_LENGTH);
    let input = &bytes[..input_length];

    if let Ok(value) = decode_envelope::<KaniValue>(input) {
        let canonical = encode_envelope(&value).expect("a decoded fixed-size value re-encodes");
        assert_eq!(input, canonical.as_slice());
        assert_eq!(input.len(), COMPLETE_ENVELOPE_LENGTH);
    }
}

#[kani::proof]
fn bounded_length_prefix_decoding_is_safe_and_respects_maximum() {
    let bytes: [u8; 6] = kani::any();
    let input_length: usize = kani::any();
    let maximum: usize = kani::any();
    kani::assume(input_length <= bytes.len());
    kani::assume(maximum <= 16);
    let mut decoder = Decoder::new(&bytes[..input_length]);

    if let Ok(length) = decoder.read_length(maximum) {
        assert!(length <= maximum);
        assert!(decoder.remaining() < input_length);
    }
}

#[kani::proof]
fn raw_read_with_arbitrary_length_never_indexes_out_of_bounds() {
    let bytes: [u8; 8] = kani::any();
    let input_length: usize = kani::any();
    let requested_length: usize = kani::any();
    kani::assume(input_length <= bytes.len());
    let mut decoder = Decoder::new(&bytes[..input_length]);

    match decoder.read_raw(requested_length) {
        Ok(value) => {
            assert_eq!(value.len(), requested_length);
            assert_eq!(decoder.remaining(), input_length - requested_length);
        }
        Err(DecodeError::UnexpectedEnd { needed, remaining }) => {
            assert_eq!(needed, requested_length);
            assert_eq!(remaining, input_length);
            assert!(requested_length > input_length);
        }
        Err(error) => panic!("unexpected raw-read error: {error:?}"),
    }
}

#[kani::proof]
fn bounded_encoder_appends_are_safe_and_never_exceed_the_limit() {
    let first: [u8; 4] = kani::any();
    let second: [u8; 4] = kani::any();
    let first_length: usize = kani::any();
    let second_length: usize = kani::any();
    let maximum: usize = kani::any();
    kani::assume(first_length <= first.len());
    kani::assume(second_length <= second.len());
    kani::assume(maximum <= 8);

    let mut encoder = Encoder::new(maximum);
    let _ = encoder.write_raw(&first[..first_length]);
    let _ = encoder.write_raw(&second[..second_length]);
    let output: Vec<u8> = encoder.finish();
    assert!(output.len() <= maximum);
}

#[kani::proof]
fn every_u32_length_has_one_exact_minimal_prefix_width() {
    let value: u32 = kani::any();
    let mut encoder = Encoder::new(5);
    encoder
        .write_length(value as usize, u32::MAX as usize)
        .expect("every u32 length fits the protocol length space");
    let bytes = encoder.finish();
    assert_eq!(bytes.len(), canonical_length_prefix_len(value));

    let mut decoder = Decoder::new(&bytes);
    assert_eq!(decoder.read_length(u32::MAX as usize), Ok(value as usize));
    assert_eq!(decoder.finish(), Ok(()));
}
