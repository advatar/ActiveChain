//! Application-layer compute escrow and assurance records.
//!
//! These types settle funds and bind provenance. They do not make a compute result consensus
//! truth, and the future verifier trait below has no v1 consensus implementation.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    Amount, AssetId, CapabilityId, ChainId, CryptoSuiteId, Digest384, Height, JobId, PrincipalId,
    ProtocolSignature,
};

pub const MAX_FUTURE_COMPUTE_PROOF_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FUTURE_COMPUTE_VERIFIER_UNITS: u128 = 1_000_000_000;

/// Application escrow for one compute request. The base layer only settles these bound fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComputeEscrowV1 {
    job: JobId,
    chain: ChainId,
    requester: PrincipalId,
    provider: PrincipalId,
    capability: CapabilityId,
    input_commitment: Digest384,
    escrow_asset: AssetId,
    escrow_amount: Amount,
    expires_at: Height,
    refund_to: PrincipalId,
}

impl ComputeEscrowV1 {
    pub const TYPE_TAG: u16 = 0x0146;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const ENCODED_LENGTH: usize = 48 * 8 + 16 + 8;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: JobId,
        chain: ChainId,
        requester: PrincipalId,
        provider: PrincipalId,
        capability: CapabilityId,
        input_commitment: Digest384,
        escrow_asset: AssetId,
        escrow_amount: Amount,
        expires_at: Height,
        refund_to: PrincipalId,
    ) -> Result<Self, ComputeBoundaryError> {
        if requester == provider
            || refund_to != requester
            || input_commitment == Digest384::ZERO
            || escrow_amount == 0
            || expires_at == 0
        {
            return Err(ComputeBoundaryError::InvalidEscrow);
        }
        Ok(Self {
            job,
            chain,
            requester,
            provider,
            capability,
            input_commitment,
            escrow_asset,
            escrow_amount,
            expires_at,
            refund_to,
        })
    }

    pub const fn job(&self) -> JobId {
        self.job
    }
    pub const fn provider(&self) -> PrincipalId {
        self.provider
    }
    pub const fn escrow_amount(&self) -> Amount {
        self.escrow_amount
    }
    pub const fn expires_at(&self) -> Height {
        self.expires_at
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }
}

impl CanonicalEncode for ComputeEscrowV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.job.encode(e)?;
        self.chain.encode(e)?;
        self.requester.encode(e)?;
        self.provider.encode(e)?;
        self.capability.encode(e)?;
        self.input_commitment.encode(e)?;
        self.escrow_asset.encode(e)?;
        self.escrow_amount.encode(e)?;
        self.expires_at.encode(e)?;
        self.refund_to.encode(e)
    }
}

impl CanonicalDecode for ComputeEscrowV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            JobId::decode(d)?,
            ChainId::decode(d)?,
            PrincipalId::decode(d)?,
            PrincipalId::decode(d)?,
            CapabilityId::decode(d)?,
            Digest384::decode(d)?,
            AssetId::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
            PrincipalId::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid compute escrow"))
    }
}

impl CanonicalType for ComputeEscrowV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::ENCODED_LENGTH;
}

/// What a provider claims its evidence establishes. None of these imply usefulness or safety.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ComputeAssuranceClassV1 {
    ProviderSigned = 0,
    ReplicatedExecution = 1,
    HardwareAttested = 2,
    ReproducibleExecution = 3,
}

impl CanonicalEncode for ComputeAssuranceClassV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}

impl CanonicalDecode for ComputeAssuranceClassV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::ProviderSigned),
            1 => Ok(Self::ReplicatedExecution),
            2 => Ok(Self::HardwareAttested),
            3 => Ok(Self::ReproducibleExecution),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ComputeAssuranceClassV1", tag }),
        }
    }
}

/// Exact unsigned claim covered by a provider's application-layer signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComputeAssuranceStatementV1 {
    job: JobId,
    escrow_commitment: Digest384,
    provider: PrincipalId,
    evidence_commitment: Digest384,
    output_commitment: Digest384,
    assurance: ComputeAssuranceClassV1,
    verifier_profile: Option<Digest384>,
    attested_at: Height,
}

impl ComputeAssuranceStatementV1 {
    pub const TYPE_TAG: u16 = 0x0147;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 * 5 + 1 + 1 + 48 + 8;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: JobId,
        escrow_commitment: Digest384,
        provider: PrincipalId,
        evidence_commitment: Digest384,
        output_commitment: Digest384,
        assurance: ComputeAssuranceClassV1,
        verifier_profile: Option<Digest384>,
        attested_at: Height,
    ) -> Result<Self, ComputeBoundaryError> {
        let profile_shape_valid = match assurance {
            ComputeAssuranceClassV1::ProviderSigned => verifier_profile.is_none(),
            _ => verifier_profile.is_some_and(|profile| profile != Digest384::ZERO),
        };
        if escrow_commitment == Digest384::ZERO
            || evidence_commitment == Digest384::ZERO
            || output_commitment == Digest384::ZERO
            || attested_at == 0
            || !profile_shape_valid
        {
            return Err(ComputeBoundaryError::InvalidAttestation);
        }
        Ok(Self {
            job,
            escrow_commitment,
            provider,
            evidence_commitment,
            output_commitment,
            assurance,
            verifier_profile,
            attested_at,
        })
    }

    pub const fn job(&self) -> JobId {
        self.job
    }
    pub const fn provider(&self) -> PrincipalId {
        self.provider
    }
    pub const fn assurance(&self) -> ComputeAssuranceClassV1 {
        self.assurance
    }
    pub const fn verifier_profile(&self) -> Option<Digest384> {
        self.verifier_profile
    }
    pub fn binds_escrow(&self, escrow: &ComputeEscrowV1) -> bool {
        self.job == escrow.job
            && escrow.commitment().is_ok_and(|value| value == self.escrow_commitment)
            && self.provider == escrow.provider
            && self.attested_at <= escrow.expires_at
    }
    pub fn signing_payload(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::SIGNING_PAYLOAD, self)
    }
}

impl CanonicalEncode for ComputeAssuranceStatementV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.job.encode(e)?;
        self.escrow_commitment.encode(e)?;
        self.provider.encode(e)?;
        self.evidence_commitment.encode(e)?;
        self.output_commitment.encode(e)?;
        self.assurance.encode(e)?;
        self.verifier_profile.encode(e)?;
        self.attested_at.encode(e)
    }
}

impl CanonicalDecode for ComputeAssuranceStatementV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            JobId::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            ComputeAssuranceClassV1::decode(d)?,
            Option::<Digest384>::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid compute assurance statement"))
    }
}

impl CanonicalType for ComputeAssuranceStatementV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Signed application-layer assurance. Signature validity does not elevate the claim to truth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComputeAssuranceAttestationV1 {
    statement: ComputeAssuranceStatementV1,
    signature: ProtocolSignature,
}

impl ComputeAssuranceAttestationV1 {
    pub const TYPE_TAG: u16 = 0x0148;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize =
        ComputeAssuranceStatementV1::MAX_ENCODED_LEN + ProtocolSignature::MAX_ENCODED_LEN;

    pub fn new(
        statement: ComputeAssuranceStatementV1,
        signature: ProtocolSignature,
    ) -> Result<Self, ComputeBoundaryError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(ComputeBoundaryError::InvalidSignatureSuite);
        }
        Ok(Self { statement, signature })
    }

    pub const fn statement(&self) -> ComputeAssuranceStatementV1 {
        self.statement
    }
    pub fn signature(&self) -> &ProtocolSignature {
        &self.signature
    }
}

impl CanonicalEncode for ComputeAssuranceAttestationV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.statement.encode(e)?;
        self.signature.encode(e)
    }
}

impl CanonicalDecode for ComputeAssuranceAttestationV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(ComputeAssuranceStatementV1::decode(d)?, ProtocolSignature::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid compute assurance attestation"))
    }
}

impl CanonicalType for ComputeAssuranceAttestationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Verifies the provider's ML-DSA-44 signature over the exact assurance statement.
pub fn verify_compute_assurance_signature(
    public_key: &[u8],
    attestation: &ComputeAssuranceAttestationV1,
) -> bool {
    let Ok(payload) = attestation.statement.signing_payload() else {
        return false;
    };
    activechain_crypto_provider::verify_ml_dsa44(
        public_key,
        payload.as_bytes(),
        attestation.signature.as_bytes(),
    )
    .is_ok()
}

/// Explicit resource ceiling for any future independently implemented compute verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutureComputeVerifierLimits {
    pub max_proof_bytes: usize,
    pub max_verifier_units: u128,
}

impl FutureComputeVerifierLimits {
    pub const fn new(
        max_proof_bytes: usize,
        max_verifier_units: u128,
    ) -> Result<Self, ComputeBoundaryError> {
        if max_proof_bytes == 0
            || max_proof_bytes > MAX_FUTURE_COMPUTE_PROOF_BYTES
            || max_verifier_units == 0
            || max_verifier_units > MAX_FUTURE_COMPUTE_VERIFIER_UNITS
        {
            return Err(ComputeBoundaryError::InvalidVerifierLimits);
        }
        Ok(Self { max_proof_bytes, max_verifier_units })
    }
}

/// Reserved interface for a future protocol revision. v1 consensus has no implementation.
pub trait FutureComputeVerifier {
    type Error;

    fn verify_bounded_execution(
        &self,
        statement: &ComputeAssuranceStatementV1,
        proof: &[u8],
        limits: FutureComputeVerifierLimits,
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComputeBoundaryError {
    InvalidEscrow,
    InvalidAttestation,
    InvalidSignatureSuite,
    InvalidVerifierLimits,
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::{format, string::String, vec};
    use core::fmt::Write as _;
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }
    fn hex_digest(value: Digest384) -> String {
        let mut output = String::with_capacity(96);
        for byte in value.as_bytes() {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }
    fn escrow() -> ComputeEscrowV1 {
        ComputeEscrowV1::new(
            JobId::new(digest(1)),
            ChainId::new(digest(2)),
            principal(3),
            principal(4),
            CapabilityId::new(digest(5)),
            digest(6),
            AssetId::new(digest(7)),
            50,
            100,
            principal(3),
        )
        .unwrap()
    }
    fn statement() -> ComputeAssuranceStatementV1 {
        let escrow = escrow();
        ComputeAssuranceStatementV1::new(
            escrow.job(),
            escrow.commitment().unwrap(),
            escrow.provider(),
            digest(8),
            digest(9),
            ComputeAssuranceClassV1::ReproducibleExecution,
            Some(digest(10)),
            90,
        )
        .unwrap()
    }

    #[test]
    fn canonical_compute_boundary_matches_frozen_commitments() {
        let escrow = escrow();
        let statement = statement();
        let attestation = ComputeAssuranceAttestationV1::new(
            statement,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![11; 2420]).unwrap(),
        )
        .unwrap();
        assert_eq!(decode_envelope(&encode_envelope(&escrow).unwrap()), Ok(escrow));
        assert_eq!(decode_envelope(&encode_envelope(&statement).unwrap()), Ok(statement));
        assert_eq!(decode_envelope(&encode_envelope(&attestation).unwrap()), Ok(attestation));

        let actual = format!(
            "escrow_commitment={}\nstatement_signing_payload={}\n",
            hex_digest(escrow.commitment().unwrap()),
            hex_digest(statement.signing_payload().unwrap())
        );
        assert_eq!(include_str!("../../../testing/vectors/compute-boundary-v1.txt"), actual);
    }

    #[test]
    fn substitution_and_unbounded_profiles_fail_closed() {
        let base = escrow();
        assert_eq!(
            ComputeEscrowV1::new(
                base.job(),
                ChainId::new(digest(2)),
                principal(3),
                principal(4),
                CapabilityId::new(digest(5)),
                digest(6),
                AssetId::new(digest(7)),
                0,
                100,
                principal(3),
            ),
            Err(ComputeBoundaryError::InvalidEscrow)
        );
        assert_eq!(
            ComputeAssuranceStatementV1::new(
                base.job(),
                base.commitment().unwrap(),
                base.provider(),
                digest(8),
                digest(9),
                ComputeAssuranceClassV1::ReproducibleExecution,
                None,
                90,
            ),
            Err(ComputeBoundaryError::InvalidAttestation)
        );
        assert_eq!(
            FutureComputeVerifierLimits::new(MAX_FUTURE_COMPUTE_PROOF_BYTES + 1, 1),
            Err(ComputeBoundaryError::InvalidVerifierLimits)
        );
        let statement = statement();
        assert!(statement.binds_escrow(&base));
        let substituted = ComputeEscrowV1::new(
            JobId::new(digest(20)),
            ChainId::new(digest(2)),
            principal(3),
            principal(4),
            CapabilityId::new(digest(5)),
            digest(6),
            AssetId::new(digest(7)),
            50,
            100,
            principal(3),
        )
        .unwrap();
        assert!(!statement.binds_escrow(&substituted));
    }

    #[test]
    fn assurance_signature_is_cryptographically_checked() {
        let statement = statement();
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([42; 32]));
        let payload = statement.signing_payload().unwrap();
        let signature = key.sign(payload.as_bytes()).encode().to_vec();
        let attestation = ComputeAssuranceAttestationV1::new(
            statement,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature).unwrap(),
        )
        .unwrap();
        assert!(verify_compute_assurance_signature(&key.verifying_key().encode(), &attestation));

        let other = SigningKey::<MlDsa44>::from_seed(&Seed::from([43; 32]));
        assert!(!verify_compute_assurance_signature(&other.verifying_key().encode(), &attestation));
    }
}
