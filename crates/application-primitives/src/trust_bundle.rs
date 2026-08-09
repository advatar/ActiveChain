use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::Digest384;
use alloc::vec::Vec;
use sha3::{Digest as _, Sha3_384};

const BUNDLE_DOMAIN: &[u8] = b"ACTUM-VERIFIER-TRUST-BUNDLE-V1";
const SIGNER_SET_DOMAIN: &[u8] = b"ACTUM-TRUST-SIGNER-SET-V1";
pub const MAX_TRUST_SIGNERS: usize = 16;
pub const MAX_TRUST_SIGNATURES: usize = MAX_TRUST_SIGNERS * 2;
pub const MAX_TRUST_PUBLIC_KEY_BYTES: usize = 1_312;
pub const MAX_TRUST_SIGNATURE_BYTES: usize = 2_420;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustSignatureAlgorithmV1 {
    MlDsa44 = 1,
}

impl CanonicalEncode for TrustSignatureAlgorithmV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}
impl CanonicalDecode for TrustSignatureAlgorithmV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            1 => Ok(Self::MlDsa44),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "TrustSignatureAlgorithmV1", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustSignerV1 {
    pub signer_id: Digest384,
    pub algorithm: TrustSignatureAlgorithmV1,
    pub public_key: Vec<u8>,
    pub valid_from_sequence: u64,
    pub valid_until_sequence: u64,
}

impl TrustSignerV1 {
    pub fn validate(&self) -> Result<(), TrustBundleError> {
        if self.signer_id == Digest384::ZERO
            || self.public_key.len() != MAX_TRUST_PUBLIC_KEY_BYTES
            || self.valid_from_sequence == 0
            || self.valid_until_sequence < self.valid_from_sequence
        {
            return Err(TrustBundleError::InvalidSignerSet);
        }
        Ok(())
    }
}
impl CanonicalEncode for TrustSignerV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.signer_id.encode(encoder)?;
        self.algorithm.encode(encoder)?;
        encoder.write_bytes(&self.public_key, MAX_TRUST_PUBLIC_KEY_BYTES)?;
        self.valid_from_sequence.encode(encoder)?;
        self.valid_until_sequence.encode(encoder)
    }
}
impl CanonicalDecode for TrustSignerV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            signer_id: Digest384::decode(decoder)?,
            algorithm: TrustSignatureAlgorithmV1::decode(decoder)?,
            public_key: decoder.read_bytes(MAX_TRUST_PUBLIC_KEY_BYTES)?.to_vec(),
            valid_from_sequence: u64::decode(decoder)?,
            valid_until_sequence: u64::decode(decoder)?,
        };
        value.validate().map_err(|_| DecodeError::InvalidValue("invalid trust signer"))?;
        Ok(value)
    }
}
impl CanonicalType for TrustSignerV1 {
    const TYPE_TAG: u16 = 0x01B5;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 1 + 2 + MAX_TRUST_PUBLIC_KEY_BYTES + 8 + 8;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustSignerSetV1 {
    pub revision: u32,
    pub signers: Vec<TrustSignerV1>,
    pub threshold: u16,
}

impl TrustSignerSetV1 {
    pub fn validate(&self) -> Result<(), TrustBundleError> {
        if self.revision == 0
            || self.signers.is_empty()
            || self.signers.len() > MAX_TRUST_SIGNERS
            || self.threshold == 0
            || usize::from(self.threshold) > self.signers.len()
            || self.signers.windows(2).any(|pair| pair[0].signer_id >= pair[1].signer_id)
            || self.signers.iter().any(|signer| signer.validate().is_err())
        {
            return Err(TrustBundleError::InvalidSignerSet);
        }
        Ok(())
    }

    pub fn signer_set_id(&self) -> Result<Digest384, TrustBundleError> {
        self.validate()?;
        let mut encoder = Encoder::new(2 + MAX_TRUST_SIGNERS * TrustSignerV1::MAX_ENCODED_LEN + 2);
        encoder
            .write_length(self.signers.len(), MAX_TRUST_SIGNERS)
            .map_err(|_| TrustBundleError::Encoding)?;
        for signer in &self.signers {
            signer.encode(&mut encoder).map_err(|_| TrustBundleError::Encoding)?;
        }
        self.threshold.encode(&mut encoder).map_err(|_| TrustBundleError::Encoding)?;
        Ok(domain_hash(SIGNER_SET_DOMAIN, &encoder.finish()))
    }
}
impl CanonicalEncode for TrustSignerSetV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.revision.encode(encoder)?;
        encoder.write_length(self.signers.len(), MAX_TRUST_SIGNERS)?;
        for signer in &self.signers {
            signer.encode(encoder)?;
        }
        self.threshold.encode(encoder)
    }
}
impl CanonicalDecode for TrustSignerSetV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let revision = u32::decode(decoder)?;
        let count = decoder.read_length(MAX_TRUST_SIGNERS)?;
        let mut signers = Vec::with_capacity(count);
        for _ in 0..count {
            signers.push(TrustSignerV1::decode(decoder)?);
        }
        let value = Self { revision, signers, threshold: u16::decode(decoder)? };
        value.validate().map_err(|_| DecodeError::InvalidValue("invalid trust signer set"))?;
        Ok(value)
    }
}
impl CanonicalType for TrustSignerSetV1 {
    const TYPE_TAG: u16 = 0x01B6;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 4 + 2 + MAX_TRUST_SIGNERS * TrustSignerV1::MAX_ENCODED_LEN + 2;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActumVerifierTrustBundleV1 {
    pub schema_revision: u16,
    pub bundle_sequence: u64,
    pub previous_bundle_id: Digest384,
    pub chain_id: Digest384,
    pub genesis_commitment: Digest384,
    pub protocol_revision: u32,
    pub checkpoint_height: u64,
    pub checkpoint_block_id: Digest384,
    pub checkpoint_state_root: Digest384,
    pub checkpoint_finality_commitment: Digest384,
    pub validator_set_root: Digest384,
    pub proof_profile_id: Digest384,
    pub proof_system_revision: u32,
    pub verifier_revision: u32,
    pub risc0_image_id: [u8; 32],
    pub policy_id: Digest384,
    pub policy_revision: u32,
    pub issued_at_ms: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub signer_set_id: Digest384,
    pub signer_set_revision: u32,
    pub signer_threshold: u16,
    pub next_signer_set_id: Digest384,
    pub next_signer_set_revision: u32,
    pub next_signer_threshold: u16,
    pub next_signer_activation_sequence: u64,
}

impl ActumVerifierTrustBundleV1 {
    pub fn validate(&self) -> Result<(), TrustBundleError> {
        let bootstrap = self.bundle_sequence == 1;
        let rotation = self.next_signer_set_id != Digest384::ZERO;
        if self.schema_revision != 1
            || self.bundle_sequence == 0
            || bootstrap != (self.previous_bundle_id == Digest384::ZERO)
            || self.chain_id == Digest384::ZERO
            || self.genesis_commitment == Digest384::ZERO
            || self.protocol_revision == 0
            || self.checkpoint_height == 0
            || self.checkpoint_block_id == Digest384::ZERO
            || self.checkpoint_state_root == Digest384::ZERO
            || self.checkpoint_finality_commitment == Digest384::ZERO
            || self.validator_set_root == Digest384::ZERO
            || self.proof_profile_id == Digest384::ZERO
            || self.proof_system_revision == 0
            || self.verifier_revision == 0
            || self.risc0_image_id == [0; 32]
            || self.policy_id == Digest384::ZERO
            || self.policy_revision == 0
            || self.issued_at_ms > self.not_before_ms
            || self.not_before_ms >= self.not_after_ms
            || self.signer_set_id == Digest384::ZERO
            || self.signer_set_revision == 0
            || self.signer_threshold == 0
            || rotation
                != (self.next_signer_set_revision != 0
                    && self.next_signer_threshold != 0
                    && self.next_signer_activation_sequence != 0)
            || rotation
                && (self.next_signer_set_revision <= self.signer_set_revision
                    || self.next_signer_activation_sequence != self.bundle_sequence + 1)
        {
            return Err(TrustBundleError::InvalidBundle);
        }
        Ok(())
    }

    pub fn bundle_id(&self) -> Result<Digest384, TrustBundleError> {
        self.validate()?;
        Ok(domain_hash(BUNDLE_DOMAIN, &canonical_body(self, Self::MAX_ENCODED_LEN)?))
    }
}

impl CanonicalEncode for ActumVerifierTrustBundleV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.schema_revision.encode(e)?;
        self.bundle_sequence.encode(e)?;
        self.previous_bundle_id.encode(e)?;
        self.chain_id.encode(e)?;
        self.genesis_commitment.encode(e)?;
        self.protocol_revision.encode(e)?;
        self.checkpoint_height.encode(e)?;
        self.checkpoint_block_id.encode(e)?;
        self.checkpoint_state_root.encode(e)?;
        self.checkpoint_finality_commitment.encode(e)?;
        self.validator_set_root.encode(e)?;
        self.proof_profile_id.encode(e)?;
        self.proof_system_revision.encode(e)?;
        self.verifier_revision.encode(e)?;
        self.risc0_image_id.encode(e)?;
        self.policy_id.encode(e)?;
        self.policy_revision.encode(e)?;
        self.issued_at_ms.encode(e)?;
        self.not_before_ms.encode(e)?;
        self.not_after_ms.encode(e)?;
        self.signer_set_id.encode(e)?;
        self.signer_set_revision.encode(e)?;
        self.signer_threshold.encode(e)?;
        self.next_signer_set_id.encode(e)?;
        self.next_signer_set_revision.encode(e)?;
        self.next_signer_threshold.encode(e)?;
        self.next_signer_activation_sequence.encode(e)
    }
}
impl CanonicalDecode for ActumVerifierTrustBundleV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            schema_revision: u16::decode(d)?,
            bundle_sequence: u64::decode(d)?,
            previous_bundle_id: Digest384::decode(d)?,
            chain_id: Digest384::decode(d)?,
            genesis_commitment: Digest384::decode(d)?,
            protocol_revision: u32::decode(d)?,
            checkpoint_height: u64::decode(d)?,
            checkpoint_block_id: Digest384::decode(d)?,
            checkpoint_state_root: Digest384::decode(d)?,
            checkpoint_finality_commitment: Digest384::decode(d)?,
            validator_set_root: Digest384::decode(d)?,
            proof_profile_id: Digest384::decode(d)?,
            proof_system_revision: u32::decode(d)?,
            verifier_revision: u32::decode(d)?,
            risc0_image_id: <[u8; 32]>::decode(d)?,
            policy_id: Digest384::decode(d)?,
            policy_revision: u32::decode(d)?,
            issued_at_ms: u64::decode(d)?,
            not_before_ms: u64::decode(d)?,
            not_after_ms: u64::decode(d)?,
            signer_set_id: Digest384::decode(d)?,
            signer_set_revision: u32::decode(d)?,
            signer_threshold: u16::decode(d)?,
            next_signer_set_id: Digest384::decode(d)?,
            next_signer_set_revision: u32::decode(d)?,
            next_signer_threshold: u16::decode(d)?,
            next_signer_activation_sequence: u64::decode(d)?,
        };
        value.validate().map_err(|_| DecodeError::InvalidValue("invalid verifier trust bundle"))?;
        Ok(value)
    }
}
impl CanonicalType for ActumVerifierTrustBundleV1 {
    const TYPE_TAG: u16 = 0x01B7;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 11 + 32 + 8 * 6 + 4 * 6 + 2 * 3;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustBundleSignatureV1 {
    pub signer_set_id: Digest384,
    pub signer_id: Digest384,
    pub algorithm: TrustSignatureAlgorithmV1,
    pub signature: Vec<u8>,
}
impl TrustBundleSignatureV1 {
    fn validate(&self) -> Result<(), TrustBundleError> {
        if self.signer_set_id == Digest384::ZERO
            || self.signer_id == Digest384::ZERO
            || self.signature.len() != MAX_TRUST_SIGNATURE_BYTES
        {
            return Err(TrustBundleError::InvalidSignature);
        }
        Ok(())
    }
}
impl CanonicalEncode for TrustBundleSignatureV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.signer_set_id.encode(e)?;
        self.signer_id.encode(e)?;
        self.algorithm.encode(e)?;
        e.write_bytes(&self.signature, MAX_TRUST_SIGNATURE_BYTES)
    }
}
impl CanonicalDecode for TrustBundleSignatureV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            signer_set_id: Digest384::decode(d)?,
            signer_id: Digest384::decode(d)?,
            algorithm: TrustSignatureAlgorithmV1::decode(d)?,
            signature: d.read_bytes(MAX_TRUST_SIGNATURE_BYTES)?.to_vec(),
        };
        value
            .validate()
            .map_err(|_| DecodeError::InvalidValue("invalid trust bundle signature"))?;
        Ok(value)
    }
}
impl CanonicalType for TrustBundleSignatureV1 {
    const TYPE_TAG: u16 = 0x01B8;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 2 + 1 + 2 + MAX_TRUST_SIGNATURE_BYTES;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedActumVerifierTrustBundleV1 {
    pub body: ActumVerifierTrustBundleV1,
    pub bundle_id: Digest384,
    pub signatures: Vec<TrustBundleSignatureV1>,
}
impl SignedActumVerifierTrustBundleV1 {
    pub fn validate(&self) -> Result<(), TrustBundleError> {
        if self.body.bundle_id()? != self.bundle_id
            || self.signatures.is_empty()
            || self.signatures.len() > MAX_TRUST_SIGNATURES
            || self.signatures.windows(2).any(|pair| {
                (pair[0].signer_set_id, pair[0].signer_id)
                    >= (pair[1].signer_set_id, pair[1].signer_id)
            })
            || self.signatures.iter().any(|signature| signature.validate().is_err())
        {
            return Err(TrustBundleError::InvalidSignature);
        }
        Ok(())
    }
}
impl CanonicalEncode for SignedActumVerifierTrustBundleV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.body.encode(e)?;
        self.bundle_id.encode(e)?;
        e.write_length(self.signatures.len(), MAX_TRUST_SIGNATURES)?;
        for signature in &self.signatures {
            signature.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for SignedActumVerifierTrustBundleV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let body = ActumVerifierTrustBundleV1::decode(d)?;
        let bundle_id = Digest384::decode(d)?;
        let count = d.read_length(MAX_TRUST_SIGNATURES)?;
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(TrustBundleSignatureV1::decode(d)?);
        }
        let value = Self { body, bundle_id, signatures };
        value
            .validate()
            .map_err(|_| DecodeError::InvalidValue("invalid signed verifier trust bundle"))?;
        Ok(value)
    }
}
impl CanonicalType for SignedActumVerifierTrustBundleV1 {
    const TYPE_TAG: u16 = 0x01B9;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = ActumVerifierTrustBundleV1::MAX_ENCODED_LEN
        + 48
        + 2
        + MAX_TRUST_SIGNATURES * TrustBundleSignatureV1::MAX_ENCODED_LEN;
}

pub fn verify_trust_bundle_bootstrap(
    bundle: &SignedActumVerifierTrustBundleV1,
    signer_set: &TrustSignerSetV1,
    now_ms: u64,
    verify: &impl Fn(TrustSignatureAlgorithmV1, &[u8], Digest384, &[u8]) -> bool,
) -> Result<(), TrustBundleError> {
    bundle.validate()?;
    signer_set.validate()?;
    if bundle.body.bundle_sequence != 1 || bundle.body.previous_bundle_id != Digest384::ZERO {
        return Err(TrustBundleError::InvalidTransition);
    }
    verify_time_and_set(&bundle.body, signer_set, now_ms)?;
    let set_id = signer_set.signer_set_id()?;
    if bundle.signatures.iter().any(|signature| signature.signer_set_id != set_id) {
        return Err(TrustBundleError::InvalidSignature);
    }
    verify_threshold(bundle, signer_set, verify)
}

pub fn verify_trust_bundle_transition(
    previous: &SignedActumVerifierTrustBundleV1,
    next: &SignedActumVerifierTrustBundleV1,
    current_set: &TrustSignerSetV1,
    activated_set: Option<&TrustSignerSetV1>,
    now_ms: u64,
    verify: &impl Fn(TrustSignatureAlgorithmV1, &[u8], Digest384, &[u8]) -> bool,
) -> Result<(), TrustBundleError> {
    previous.validate()?;
    next.validate()?;
    current_set.validate()?;
    if next.body.bundle_sequence != previous.body.bundle_sequence + 1
        || next.body.previous_bundle_id != previous.bundle_id
        || next.body.chain_id != previous.body.chain_id
        || next.body.genesis_commitment != previous.body.genesis_commitment
        || next.body.checkpoint_height < previous.body.checkpoint_height
        || previous.body.signer_set_id != current_set.signer_set_id()?
        || previous.body.signer_set_revision != current_set.revision
        || previous.body.signer_threshold != current_set.threshold
    {
        return Err(TrustBundleError::InvalidTransition);
    }
    let rotating = previous.body.next_signer_set_id != Digest384::ZERO
        && previous.body.next_signer_activation_sequence == next.body.bundle_sequence;
    if rotating {
        let new_set = activated_set.ok_or(TrustBundleError::InvalidTransition)?;
        new_set.validate()?;
        if previous.body.next_signer_set_id != new_set.signer_set_id()?
            || previous.body.next_signer_set_revision != new_set.revision
            || previous.body.next_signer_threshold != new_set.threshold
        {
            return Err(TrustBundleError::InvalidTransition);
        }
        verify_time_and_set(&next.body, new_set, now_ms)?;
        let current_id = current_set.signer_set_id()?;
        let new_id = new_set.signer_set_id()?;
        if next.signatures.iter().any(|signature| {
            signature.signer_set_id != current_id && signature.signer_set_id != new_id
        }) {
            return Err(TrustBundleError::InvalidSignature);
        }
        verify_threshold(next, current_set, verify)?;
        verify_threshold(next, new_set, verify)
    } else {
        if activated_set.is_some() {
            return Err(TrustBundleError::InvalidTransition);
        }
        verify_time_and_set(&next.body, current_set, now_ms)?;
        let current_id = current_set.signer_set_id()?;
        if next.signatures.iter().any(|signature| signature.signer_set_id != current_id) {
            return Err(TrustBundleError::InvalidSignature);
        }
        verify_threshold(next, current_set, verify)
    }
}

fn verify_time_and_set(
    body: &ActumVerifierTrustBundleV1,
    signer_set: &TrustSignerSetV1,
    now_ms: u64,
) -> Result<(), TrustBundleError> {
    if now_ms < body.not_before_ms
        || now_ms > body.not_after_ms
        || body.signer_set_id != signer_set.signer_set_id()?
        || body.signer_set_revision != signer_set.revision
        || body.signer_threshold != signer_set.threshold
    {
        return Err(TrustBundleError::InvalidTransition);
    }
    Ok(())
}

fn verify_threshold(
    bundle: &SignedActumVerifierTrustBundleV1,
    signer_set: &TrustSignerSetV1,
    verify: &impl Fn(TrustSignatureAlgorithmV1, &[u8], Digest384, &[u8]) -> bool,
) -> Result<(), TrustBundleError> {
    let set_id = signer_set.signer_set_id()?;
    let mut accepted = 0usize;
    for signature in bundle.signatures.iter().filter(|signature| signature.signer_set_id == set_id)
    {
        let signer = signer_set
            .signers
            .iter()
            .find(|signer| signer.signer_id == signature.signer_id)
            .ok_or(TrustBundleError::InvalidSignature)?;
        if signature.algorithm != signer.algorithm
            || bundle.body.bundle_sequence < signer.valid_from_sequence
            || bundle.body.bundle_sequence > signer.valid_until_sequence
            || !verify(
                signature.algorithm,
                &signer.public_key,
                bundle.bundle_id,
                &signature.signature,
            )
        {
            return Err(TrustBundleError::InvalidSignature);
        }
        accepted += 1;
    }
    if accepted < usize::from(signer_set.threshold) {
        return Err(TrustBundleError::ThresholdNotMet);
    }
    Ok(())
}

fn canonical_body(
    value: &impl CanonicalEncode,
    maximum: usize,
) -> Result<Vec<u8>, TrustBundleError> {
    let mut encoder = Encoder::new(maximum);
    value.encode(&mut encoder).map_err(|_| TrustBundleError::Encoding)?;
    Ok(encoder.finish())
}
fn domain_hash(domain: &[u8], body: &[u8]) -> Digest384 {
    let mut hash = Sha3_384::new();
    hash.update(domain);
    hash.update(body);
    Digest384::new(hash.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustBundleError {
    InvalidSignerSet,
    InvalidBundle,
    InvalidSignature,
    InvalidTransition,
    ThresholdNotMet,
    Encoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::{vec, vec::Vec};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn signer(byte: u8, from: u64) -> TrustSignerV1 {
        TrustSignerV1 {
            signer_id: digest(byte),
            algorithm: TrustSignatureAlgorithmV1::MlDsa44,
            public_key: vec![byte; MAX_TRUST_PUBLIC_KEY_BYTES],
            valid_from_sequence: from,
            valid_until_sequence: 100,
        }
    }
    fn signer_set(revision: u32, bytes: &[u8]) -> TrustSignerSetV1 {
        let mut signers: Vec<_> =
            bytes.iter().map(|byte| signer(*byte, u64::from(revision))).collect();
        signers.sort_by_key(|value| value.signer_id);
        TrustSignerSetV1 { revision, signers, threshold: 1 }
    }
    fn body(
        sequence: u64,
        previous: Digest384,
        checkpoint_height: u64,
        current: &TrustSignerSetV1,
        next: Option<&TrustSignerSetV1>,
    ) -> ActumVerifierTrustBundleV1 {
        ActumVerifierTrustBundleV1 {
            schema_revision: 1,
            bundle_sequence: sequence,
            previous_bundle_id: previous,
            chain_id: digest(10),
            genesis_commitment: digest(11),
            protocol_revision: 1,
            checkpoint_height,
            checkpoint_block_id: digest(12),
            checkpoint_state_root: digest(13),
            checkpoint_finality_commitment: digest(14),
            validator_set_root: digest(15),
            proof_profile_id: digest(16),
            proof_system_revision: 1,
            verifier_revision: 1,
            risc0_image_id: [17; 32],
            policy_id: digest(18),
            policy_revision: 1,
            issued_at_ms: 100,
            not_before_ms: 100,
            not_after_ms: 1_000,
            signer_set_id: current.signer_set_id().unwrap(),
            signer_set_revision: current.revision,
            signer_threshold: current.threshold,
            next_signer_set_id: next
                .map_or(Digest384::ZERO, |value| value.signer_set_id().unwrap()),
            next_signer_set_revision: next.map_or(0, |value| value.revision),
            next_signer_threshold: next.map_or(0, |value| value.threshold),
            next_signer_activation_sequence: next.map_or(0, |_| sequence + 1),
        }
    }
    fn signature(
        set: &TrustSignerSetV1,
        signer: &TrustSignerV1,
        id: Digest384,
    ) -> TrustBundleSignatureV1 {
        let mut bytes = vec![signer.public_key[0]; MAX_TRUST_SIGNATURE_BYTES];
        bytes[..48].copy_from_slice(id.as_bytes());
        TrustBundleSignatureV1 {
            signer_set_id: set.signer_set_id().unwrap(),
            signer_id: signer.signer_id,
            algorithm: signer.algorithm,
            signature: bytes,
        }
    }
    fn signed(
        body: ActumVerifierTrustBundleV1,
        sets: &[&TrustSignerSetV1],
    ) -> SignedActumVerifierTrustBundleV1 {
        let id = body.bundle_id().unwrap();
        let mut signatures: Vec<_> =
            sets.iter().map(|set| signature(set, &set.signers[0], id)).collect();
        signatures.sort_by_key(|value| (value.signer_set_id, value.signer_id));
        SignedActumVerifierTrustBundleV1 { body, bundle_id: id, signatures }
    }
    fn verify(_: TrustSignatureAlgorithmV1, key: &[u8], id: Digest384, signature: &[u8]) -> bool {
        signature.len() == MAX_TRUST_SIGNATURE_BYTES
            && signature[..48] == *id.as_bytes()
            && signature[48..].iter().all(|byte| *byte == key[0])
    }

    #[test]
    fn bootstrap_round_trips_and_requires_current_threshold() {
        let set = signer_set(1, &[1, 2]);
        let bundle = signed(body(1, Digest384::ZERO, 10, &set, None), &[&set]);
        assert_eq!(verify_trust_bundle_bootstrap(&bundle, &set, 200, &verify), Ok(()));
        assert_eq!(
            decode_envelope::<SignedActumVerifierTrustBundleV1>(&encode_envelope(&bundle).unwrap()),
            Ok(bundle)
        );
    }

    #[test]
    fn planned_rotation_requires_old_and_new_thresholds() {
        let old = signer_set(1, &[1]);
        let new = signer_set(2, &[2]);
        let previous = signed(body(1, Digest384::ZERO, 10, &old, Some(&new)), &[&old]);
        let next = signed(body(2, previous.bundle_id, 11, &new, None), &[&old, &new]);
        assert_eq!(
            verify_trust_bundle_transition(&previous, &next, &old, Some(&new), 200, &verify),
            Ok(())
        );
        let missing_old = signed(next.body.clone(), &[&new]);
        assert_eq!(
            verify_trust_bundle_transition(&previous, &missing_old, &old, Some(&new), 200, &verify),
            Err(TrustBundleError::ThresholdNotMet)
        );
    }

    #[test]
    fn rollback_fork_expiry_and_image_substitution_fail_closed() {
        let set = signer_set(1, &[1]);
        let previous = signed(body(1, Digest384::ZERO, 10, &set, None), &[&set]);
        let rollback = signed(body(2, previous.bundle_id, 9, &set, None), &[&set]);
        assert_eq!(
            verify_trust_bundle_transition(&previous, &rollback, &set, None, 200, &verify),
            Err(TrustBundleError::InvalidTransition)
        );
        let fork = signed(body(2, digest(99), 11, &set, None), &[&set]);
        assert_eq!(
            verify_trust_bundle_transition(&previous, &fork, &set, None, 200, &verify),
            Err(TrustBundleError::InvalidTransition)
        );
        assert_eq!(
            verify_trust_bundle_bootstrap(&previous, &set, 2_000, &verify),
            Err(TrustBundleError::InvalidTransition)
        );
        let mut substituted = previous.clone();
        substituted.body.risc0_image_id = [99; 32];
        assert_eq!(substituted.validate(), Err(TrustBundleError::InvalidSignature));
    }
}
