//! First registration of a key-derived cash wallet. This proves key ownership, not human identity.
use crate::{CashAuthorizationLane, TransactionIngress, WalletError, wallet_principal_id};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope,
};
use activechain_protocol_types::{
    AuthenticatorId, ChainId, CryptoSuiteId, Digest384, PrincipalId, ProtocolSignature,
    TransactionId,
};
use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

const SIGNING_DOMAIN: &[u8] = b"ACTIVECHAIN-CASH-KEY-ENROLLMENT-ML-DSA-44-V1";
pub const MAX_CASH_ENROLLMENT_LENGTH: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashKeyEnrollmentV1 {
    chain_id: ChainId,
    public_key: Vec<u8>,
    valid_from: u64,
    expires_at: u64,
    signature: ProtocolSignature,
}

fn commit(domain: &[u8], bytes: &[u8]) -> Digest384 {
    let mut h = Shake256::default();
    h.update(domain);
    h.update(bytes);
    let mut result = [0; 48];
    h.finalize_xof().read(&mut result);
    Digest384::new(result)
}

impl CashKeyEnrollmentV1 {
    pub fn signing_payload(
        chain_id: ChainId,
        public_key: &[u8],
        valid_from: u64,
        expires_at: u64,
    ) -> Result<Vec<u8>, WalletError> {
        if public_key.len() != 1312
            || valid_from == 0
            || expires_at < valid_from
            || expires_at - valid_from > 120
        {
            return Err(WalletError::MalformedAuthorization);
        }
        let mut payload = SIGNING_DOMAIN.to_vec();
        payload.extend_from_slice(chain_id.digest().as_bytes());
        payload.extend_from_slice(public_key);
        payload.extend_from_slice(&valid_from.to_be_bytes());
        payload.extend_from_slice(&expires_at.to_be_bytes());
        Ok(payload)
    }
    pub fn new(
        chain_id: ChainId,
        public_key: Vec<u8>,
        valid_from: u64,
        expires_at: u64,
        signature: ProtocolSignature,
    ) -> Result<Self, WalletError> {
        let value = Self { chain_id, public_key, valid_from, expires_at, signature };
        value.verify()?;
        Ok(value)
    }
    pub fn verify(&self) -> Result<(), WalletError> {
        if self.signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(WalletError::InvalidSignature);
        }
        crate::cash_authorization::verify_ml_dsa(
            &self.public_key,
            &self.signature,
            &Self::signing_payload(
                self.chain_id,
                &self.public_key,
                self.valid_from,
                self.expires_at,
            )?,
        )
    }
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub fn signer(&self) -> PrincipalId {
        wallet_principal_id(&self.public_key)
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn reference(&self) -> Result<Digest384, WalletError> {
        // Stable across ML-DSA signature randomization and retransmission.
        Ok(commit(
            b"ACTIVECHAIN-CASH-KEY-ENROLLMENT-ID-V1",
            &Self::signing_payload(
                self.chain_id,
                &self.public_key,
                self.valid_from,
                self.expires_at,
            )?,
        ))
    }
}
impl CanonicalEncode for CashKeyEnrollmentV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        e.write_bytes(&self.public_key, 1312)?;
        self.valid_from.encode(e)?;
        self.expires_at.encode(e)?;
        self.signature.encode(e)
    }
}
impl CanonicalDecode for CashKeyEnrollmentV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            d.read_bytes(1312)?.to_vec(),
            u64::decode(d)?,
            u64::decode(d)?,
            ProtocolSignature::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid wallet-key enrollment"))
    }
}
impl CanonicalType for CashKeyEnrollmentV1 {
    const TYPE_TAG: u16 = 0x01D3;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = MAX_CASH_ENROLLMENT_LENGTH;
}

fn authenticator(chain: ChainId, key: &[u8]) -> AuthenticatorId {
    let mut bytes = chain.digest().as_bytes().to_vec();
    bytes.extend_from_slice(key);
    AuthenticatorId::new(commit(b"ACTIVECHAIN-KEY-DERIVED-CASH-AUTHENTICATOR-V1", &bytes))
}
impl TransactionIngress {
    /// Stages registration on the consensus candidate. Publish only after the exact action root
    /// is finalized. Existing lanes are never replaced, even by the same key. A funded owner is
    /// required, bounding anonymous registration by the testnet's funding admission policy.
    pub fn stage_cash_key_enrollment(
        &mut self,
        enrollment: &CashKeyEnrollmentV1,
        height: u64,
    ) -> Result<(), WalletError> {
        enrollment.verify()?;
        if enrollment.chain_id != self.chain_id {
            return Err(WalletError::WrongChain);
        }
        if height < enrollment.valid_from || height > enrollment.expires_at {
            return Err(WalletError::Expired);
        }
        let signer = enrollment.signer();
        let position = self
            .authorization_lanes
            .binary_search_by_key(&signer, |lane| lane.sender)
            .err()
            .ok_or(WalletError::Replay)?;
        if self.authorization_lanes.len() >= crate::cash_persistence::MAX_AUTHORIZATION_LANES {
            return Err(WalletError::StateLimit);
        }
        if !self.ledger.cells().as_slice().iter().any(|cell| cell.cell().owner() == signer) {
            return Err(WalletError::InsufficientFunds);
        }
        let reference = enrollment.reference()?;
        if self.non_authoritative_accepted.len()
            >= crate::cash_persistence::MAX_NON_AUTHORITATIVE_ACCEPTED
        {
            return Err(WalletError::StateLimit);
        }
        self.authorization_lanes.insert(
            position,
            CashAuthorizationLane {
                sender: signer,
                public_key: enrollment
                    .public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| WalletError::InvalidAuthorizationKey)?,
                next_nonce: 0,
                consumed_sessions: Vec::new(),
                session_budgets: Vec::new(),
                identity_sequence: 0,
                authenticator_id: authenticator(self.chain_id, &enrollment.public_key),
                // These legacy fields carry the enrollment action commitment, not invented identity
                // credentials. The containing consensus certificate proves its cash-action root.
                finalized_state_root: reference,
                finalized_height: height,
                finality_proof: reference,
            },
        );
        self.non_authoritative_accepted.push(TransactionId::new(reference));
        self.non_authoritative_accepted.sort_unstable();
        Ok(())
    }
    pub(crate) fn ensure_enrollment_precedes_payment(
        &self,
        lane: &CashAuthorizationLane,
        height: u64,
    ) -> Result<(), WalletError> {
        if lane.authenticator_id == authenticator(self.chain_id, &lane.public_key)
            && height <= lane.finalized_height
        {
            return Err(WalletError::InvalidIdentityProof);
        }
        Ok(())
    }
}

/// Uniform identifier committed by the finalized cash-action root.
pub fn cash_action_id(bytes: &[u8]) -> Result<TransactionId, WalletError> {
    let reference = if let Ok(enrollment) = decode_envelope::<CashKeyEnrollmentV1>(bytes) {
        enrollment.reference()?
    } else if let Ok(bundle) = decode_envelope::<crate::OperatorFaucetAuthorizationV1>(bytes) {
        bundle.transfer().request().intent_id().map_err(|_| WalletError::MalformedAuthorization)?
    } else {
        decode_envelope::<crate::AuthorizedCashTransferV1>(bytes)
            .map_err(|_| WalletError::MalformedAuthorization)?
            .request()
            .intent_id()
            .map_err(|_| WalletError::MalformedAuthorization)?
    };
    Ok(TransactionId::new(reference))
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::encode_envelope;
    use activechain_cash_kernel::{GenesisAllocation, GenesisEconomy, NativeAssetDefinition};
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    fn fixture() -> (TransactionIngress, CashKeyEnrollmentV1) {
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([42; 32]));
        let public = key.verifying_key().encode().as_slice().to_vec();
        let chain = ChainId::new(Digest384::new([1; 48]));
        let signature =
            key.sign(&CashKeyEnrollmentV1::signing_payload(chain, &public, 10, 100).unwrap());
        let enrollment = CashKeyEnrollmentV1::new(
            chain,
            public,
            10,
            100,
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                signature.encode().as_slice().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let definition = NativeAssetDefinition::new(
            chain,
            b"ACT".to_vec(),
            18,
            1000,
            150,
            Digest384::new([2; 48]),
            Digest384::new([3; 48]),
            Digest384::new([4; 48]),
        )
        .unwrap();
        let economy = GenesisEconomy::new(
            definition,
            vec![GenesisAllocation::new(enrollment.signer(), 800, 100).unwrap()],
            100,
        )
        .unwrap();
        (TransactionIngress::from_genesis(&economy).unwrap(), enrollment)
    }
    #[test]
    fn enrollment_is_signed_canonical_and_cannot_reset_a_lane() {
        let (mut ingress, enrollment) = fixture();
        let wire = encode_envelope(&enrollment).unwrap();
        assert_eq!(decode_envelope::<CashKeyEnrollmentV1>(&wire).unwrap(), enrollment);
        let before = ingress.clone();
        let mut forged = wire.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(decode_envelope::<CashKeyEnrollmentV1>(&forged).is_err());
        assert_eq!(ingress.stage_cash_key_enrollment(&enrollment, 9), Err(WalletError::Expired));
        assert_eq!(ingress, before);
        ingress.stage_cash_key_enrollment(&enrollment, 11).unwrap();
        assert_eq!(ingress.next_nonce(enrollment.signer()), Some(0));
        assert_eq!(
            ingress.ensure_enrollment_precedes_payment(&ingress.authorization_lanes[0], 11),
            Err(WalletError::InvalidIdentityProof)
        );
        ingress.ensure_enrollment_precedes_payment(&ingress.authorization_lanes[0], 12).unwrap();
        ingress.authorization_lanes[0].next_nonce = 7;
        let enrolled = ingress.clone();
        assert_eq!(ingress.stage_cash_key_enrollment(&enrollment, 12), Err(WalletError::Replay));
        assert_eq!(ingress, enrolled);
        let restored =
            decode_envelope::<TransactionIngress>(&encode_envelope(&ingress).unwrap()).unwrap();
        assert_eq!(restored, enrolled);
    }
    #[test]
    fn enrollment_rejects_wrong_chain_unfunded_owner_and_expiry() {
        let (ingress, enrollment) = fixture();
        let mut wrong = ingress.clone();
        wrong.chain_id = ChainId::new(Digest384::new([9; 48]));
        assert_eq!(wrong.stage_cash_key_enrollment(&enrollment, 11), Err(WalletError::WrongChain));
        let mut expired = ingress.clone();
        assert_eq!(expired.stage_cash_key_enrollment(&enrollment, 101), Err(WalletError::Expired));
        let mut changed = enrollment.clone();
        changed.public_key[0] ^= 1;
        assert!(changed.verify().is_err());
        assert!(
            CashKeyEnrollmentV1::signing_payload(
                enrollment.chain_id,
                &enrollment.public_key,
                10,
                131
            )
            .is_err()
        );
    }
}
