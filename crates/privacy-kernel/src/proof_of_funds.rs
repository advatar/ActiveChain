//! Private single-observation proof-of-funds relation and verifier boundary.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{
    CredentialAssuranceClassV1, Digest384, PrincipalId, ProofOfFundsPredicateV1,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofOfFundsError {
    PublicInputEncoding,
    EvidenceMismatch,
    HolderMismatch,
    CurrencyMismatch,
    DecimalMismatch,
    InstitutionMismatch,
    AggregationNotSingleObservation,
    AmountOutsideRange,
    StaleOrRevoked,
    Replay,
    MalformedProof,
}

/// Private circuit witness. It is never encoded into a public receipt or error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofOfFundsWitnessV1 {
    pub amount_units: u128,
    pub decimals: u8,
    pub currency_commitment: Digest384,
    pub institution_set_commitment: Digest384,
    pub holder_binding: Digest384,
    pub evidence_commitment: Digest384,
    pub aggregation_rule_commitment: Digest384,
    pub observation_count: u16,
}
impl CanonicalEncode for ProofOfFundsWitnessV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.amount_units.encode(e)?;
        self.decimals.encode(e)?;
        self.currency_commitment.encode(e)?;
        self.institution_set_commitment.encode(e)?;
        self.holder_binding.encode(e)?;
        self.evidence_commitment.encode(e)?;
        self.aggregation_rule_commitment.encode(e)?;
        self.observation_count.encode(e)
    }
}
impl CanonicalDecode for ProofOfFundsWitnessV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            amount_units: u128::decode(d)?,
            decimals: u8::decode(d)?,
            currency_commitment: Digest384::decode(d)?,
            institution_set_commitment: Digest384::decode(d)?,
            holder_binding: Digest384::decode(d)?,
            evidence_commitment: Digest384::decode(d)?,
            aggregation_rule_commitment: Digest384::decode(d)?,
            observation_count: u16::decode(d)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofOfFundsPublicInputsV1 {
    pub predicate: ProofOfFundsPredicateV1,
    pub chain_genesis: Digest384,
    pub verifier: PrincipalId,
    pub purpose_commitment: Digest384,
    pub finalized_status_root: Digest384,
    pub assurance: CredentialAssuranceClassV1,
    pub issuer_authorization_commitment: Option<Digest384>,
    pub finalized_height: u64,
}
impl ProofOfFundsPublicInputsV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        predicate: ProofOfFundsPredicateV1,
        chain_genesis: Digest384,
        verifier: PrincipalId,
        purpose: Digest384,
        status: Digest384,
        assurance: CredentialAssuranceClassV1,
        issuer_authorization: Option<Digest384>,
        finalized_height: u64,
    ) -> Result<Self, ProofOfFundsError> {
        if [chain_genesis, purpose, status].into_iter().any(|v| v == Digest384::ZERO)
            || verifier.digest() == &Digest384::ZERO
            || issuer_authorization == Some(Digest384::ZERO)
            || (assurance >= CredentialAssuranceClassV1::IssuerUpgraded)
                != issuer_authorization.is_some()
            || !predicate.valid_at(finalized_height)
        {
            return Err(ProofOfFundsError::StaleOrRevoked);
        }
        Ok(Self {
            predicate,
            chain_genesis,
            verifier,
            purpose_commitment: purpose,
            finalized_status_root: status,
            assurance,
            issuer_authorization_commitment: issuer_authorization,
            finalized_height,
        })
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut h = Shake256::default();
        h.update(b"ACTIVECHAIN-PROOF-OF-FUNDS-PUBLIC-V1");
        h.update(&bytes);
        let mut out = [0; 48];
        XofReader::read(&mut h.finalize_xof(), &mut out);
        Ok(Digest384::new(out))
    }
}
impl CanonicalEncode for ProofOfFundsPublicInputsV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.predicate.encode(e)?;
        self.chain_genesis.encode(e)?;
        self.verifier.encode(e)?;
        self.purpose_commitment.encode(e)?;
        self.finalized_status_root.encode(e)?;
        self.assurance.encode(e)?;
        self.issuer_authorization_commitment.encode(e)?;
        self.finalized_height.encode(e)
    }
}
impl CanonicalDecode for ProofOfFundsPublicInputsV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ProofOfFundsPredicateV1::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            CredentialAssuranceClassV1::decode(d)?,
            Option::<Digest384>::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid proof-of-funds public inputs"))
    }
}
impl CanonicalType for ProofOfFundsPublicInputsV1 {
    const TYPE_TAG: u16 = 0x019E;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = ProofOfFundsPredicateV1::MAX_ENCODED_LEN + 48 * 4 + 1 + 49 + 8;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofOfFundsRelationInputV1 {
    pub public: ProofOfFundsPublicInputsV1,
    pub witness: ProofOfFundsWitnessV1,
}
impl CanonicalEncode for ProofOfFundsRelationInputV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.public.encode(e)?;
        self.witness.encode(e)
    }
}
impl CanonicalDecode for ProofOfFundsRelationInputV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            public: ProofOfFundsPublicInputsV1::decode(d)?,
            witness: ProofOfFundsWitnessV1::decode(d)?,
        })
    }
}
impl CanonicalType for ProofOfFundsRelationInputV1 {
    const TYPE_TAG: u16 = 0x019F;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        ProofOfFundsPublicInputsV1::MAX_ENCODED_LEN + 16 + 1 + 48 * 5 + 2;
}

/// Cryptographic backend adapter. Implementations must prove the same relation as
/// `witness_satisfies`; the only public statement is the canonical predicate commitment.
pub trait ProofOfFundsProofVerifier {
    fn verify(&self, public_input: Digest384, proof: &[u8]) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedProofOfFundsV1 {
    public_inputs_commitment: Digest384,
    nullifier: Digest384,
    assurance: CredentialAssuranceClassV1,
    status_root: Digest384,
    policy_revision: u64,
}
impl VerifiedProofOfFundsV1 {
    pub const fn public_inputs_commitment(self) -> Digest384 {
        self.public_inputs_commitment
    }
    pub const fn nullifier(self) -> Digest384 {
        self.nullifier
    }
    pub const fn assurance(self) -> CredentialAssuranceClassV1 {
        self.assurance
    }
    pub const fn status_root(self) -> Digest384 {
        self.status_root
    }
    pub const fn policy_revision(self) -> u64 {
        self.policy_revision
    }
}

pub fn witness_satisfies(
    predicate: ProofOfFundsPredicateV1,
    witness: ProofOfFundsWitnessV1,
) -> Result<(), ProofOfFundsError> {
    if witness.evidence_commitment != predicate.evidence_commitment() {
        return Err(ProofOfFundsError::EvidenceMismatch);
    }
    if witness.holder_binding != predicate.holder_binding() {
        return Err(ProofOfFundsError::HolderMismatch);
    }
    if witness.currency_commitment != predicate.currency_commitment() {
        return Err(ProofOfFundsError::CurrencyMismatch);
    }
    if witness.decimals != predicate.decimals() {
        return Err(ProofOfFundsError::DecimalMismatch);
    }
    if witness.institution_set_commitment != predicate.institution_set_commitment() {
        return Err(ProofOfFundsError::InstitutionMismatch);
    }
    if witness.observation_count != 1
        || witness.aggregation_rule_commitment != predicate.aggregation_rule_commitment()
    {
        return Err(ProofOfFundsError::AggregationNotSingleObservation);
    }
    if witness.amount_units < predicate.minimum_amount()
        || predicate.maximum_amount().is_some_and(|max| witness.amount_units > max)
    {
        return Err(ProofOfFundsError::AmountOutsideRange);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_proof_of_funds(
    public: ProofOfFundsPublicInputsV1,
    proof: &[u8],
    verifier: &impl ProofOfFundsProofVerifier,
    status_fresh: bool,
    revoked: bool,
    nullifier_unused: bool,
) -> Result<VerifiedProofOfFundsV1, ProofOfFundsError> {
    if !public.predicate.valid_at(public.finalized_height) || !status_fresh || revoked {
        return Err(ProofOfFundsError::StaleOrRevoked);
    }
    if !nullifier_unused {
        return Err(ProofOfFundsError::Replay);
    }
    let public_input = public.commitment().map_err(map_encode)?;
    if proof.is_empty() || !verifier.verify(public_input, proof) {
        return Err(ProofOfFundsError::MalformedProof);
    }
    Ok(VerifiedProofOfFundsV1 {
        public_inputs_commitment: public_input,
        nullifier: public.predicate.nonce(),
        assurance: public.assurance,
        status_root: public.finalized_status_root,
        policy_revision: public.predicate.policy_revision(),
    })
}

fn map_encode(_: EncodeError) -> ProofOfFundsError {
    ProofOfFundsError::PublicInputEncoding
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{AssetId, ChainId, PrincipalId, TransactionId};
    fn d(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    fn predicate() -> ProofOfFundsPredicateV1 {
        ProofOfFundsPredicateV1::new(
            d(1),
            d(2),
            d(3),
            ChainId::new(d(4)),
            PrincipalId::new(d(5)),
            TransactionId::new(d(6)),
            d(7),
            d(8),
            Some(AssetId::new(d(9))),
            2,
            10_000,
            Some(20_000),
            d(10),
            d(11),
            1,
            80,
            90,
            110,
        )
        .unwrap()
    }
    fn witness(amount: u128) -> ProofOfFundsWitnessV1 {
        ProofOfFundsWitnessV1 {
            amount_units: amount,
            decimals: 2,
            currency_commitment: d(8),
            institution_set_commitment: d(10),
            holder_binding: d(3),
            evidence_commitment: d(1),
            aggregation_rule_commitment: d(11),
            observation_count: 1,
        }
    }
    fn public(height: u64) -> ProofOfFundsPublicInputsV1 {
        ProofOfFundsPublicInputsV1::new(
            predicate(),
            d(12),
            PrincipalId::new(d(13)),
            d(14),
            d(15),
            CredentialAssuranceClassV1::HolderSelfIssued,
            None,
            height,
        )
        .unwrap()
    }
    struct Exact(Digest384);
    impl ProofOfFundsProofVerifier for Exact {
        fn verify(&self, public: Digest384, proof: &[u8]) -> bool {
            public == self.0 && proof == b"proof"
        }
    }
    #[test]
    fn relation_accepts_inclusive_boundaries_and_rejects_substitution() {
        assert_eq!(witness_satisfies(predicate(), witness(10_000)), Ok(()));
        assert_eq!(witness_satisfies(predicate(), witness(20_000)), Ok(()));
        assert_eq!(
            witness_satisfies(predicate(), witness(9_999)),
            Err(ProofOfFundsError::AmountOutsideRange)
        );
        let mut wrong = witness(15_000);
        wrong.decimals = 3;
        assert_eq!(witness_satisfies(predicate(), wrong), Err(ProofOfFundsError::DecimalMismatch));
        wrong = witness(15_000);
        wrong.observation_count = 2;
        assert_eq!(
            witness_satisfies(predicate(), wrong),
            Err(ProofOfFundsError::AggregationNotSingleObservation)
        );
    }
    #[test]
    fn verifier_binds_exact_public_inputs_freshness_status_and_replay() {
        let p = public(100);
        let exact = Exact(p.commitment().unwrap());
        assert!(verify_proof_of_funds(p, b"proof", &exact, true, false, true).is_ok());
        assert_eq!(
            ProofOfFundsPublicInputsV1::new(
                predicate(),
                d(12),
                PrincipalId::new(d(13)),
                d(14),
                d(15),
                CredentialAssuranceClassV1::HolderSelfIssued,
                None,
                110
            ),
            Err(ProofOfFundsError::StaleOrRevoked)
        );
        assert_eq!(
            verify_proof_of_funds(p, b"proof", &exact, true, true, true),
            Err(ProofOfFundsError::StaleOrRevoked)
        );
        assert_eq!(
            verify_proof_of_funds(p, b"proof", &exact, true, false, false),
            Err(ProofOfFundsError::Replay)
        );
        assert_eq!(
            verify_proof_of_funds(p, b"bad", &exact, true, false, true),
            Err(ProofOfFundsError::MalformedProof)
        );
    }
    #[test]
    fn published_adversarial_corpus_is_closed_and_private() {
        let vector = include_str!("../../../testing/vectors/proof-of-funds-risc0-v1.tsv");
        let mut accepted = 0;
        let mut rejected = 0;
        for line in vector.lines().skip(1) {
            let fields: alloc::vec::Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 3);
            match fields[1] {
                "accept" => accepted += 1,
                "reject" => rejected += 1,
                value => panic!("unknown {value}"),
            }
        }
        assert_eq!((accepted, rejected), (2, 19));
        for private in ["account_identifier", "institution_name", "full_balance", "tls_transcript"]
        {
            assert!(!vector.contains(private));
        }
    }
}
