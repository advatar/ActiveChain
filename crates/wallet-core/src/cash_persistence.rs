use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_types::{
    AuthenticatorDescriptor, AuthenticatorPurpose, ChainId, CoinCellId, CryptoSuiteId, Digest384,
    Principal, PrincipalId, TransactionId,
};
use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::io::Write;
use std::path::Path;

use crate::{CashAuthorizationLane, TransactionIngress, WalletError};

const AUTHENTICATOR_SET_DOMAIN: &[u8] = b"ACTIVECHAIN-AUTHENTICATOR-SET-V1";
pub(crate) const MAX_AUTHORIZATION_LANES: usize = 256;
pub(crate) const MAX_CONSUMED_SESSIONS_PER_LANE: usize = 4_096;
pub(crate) const MAX_SESSION_BUDGETS_PER_LANE: usize = 4_096;
pub(crate) const MAX_CONSUMED_INPUTS: usize = 65_535;
pub(crate) const MAX_NON_AUTHORITATIVE_ACCEPTED: usize = 65_535;

/// Finalized principal/authenticator evidence consumed by the cash ingress key boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedIdentityKeyProof {
    principal: Principal,
    authenticator: AuthenticatorDescriptor,
    finalized_state_root: Digest384,
    finalized_height: u64,
    finality_proof: Digest384,
}

impl FinalizedIdentityKeyProof {
    #[must_use]
    pub const fn new(
        principal: Principal,
        authenticator: AuthenticatorDescriptor,
        finalized_state_root: Digest384,
        finalized_height: u64,
        finality_proof: Digest384,
    ) -> Self {
        Self { principal, authenticator, finalized_state_root, finalized_height, finality_proof }
    }

    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    #[must_use]
    pub const fn authenticator(&self) -> &AuthenticatorDescriptor {
        &self.authenticator
    }

    #[must_use]
    pub const fn finalized_state_root(&self) -> Digest384 {
        self.finalized_state_root
    }

    #[must_use]
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    #[must_use]
    pub const fn finality_proof(&self) -> Digest384 {
        self.finality_proof
    }

    pub(crate) fn validate<V: FinalizedIdentityKeyVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), WalletError> {
        if self.finalized_state_root == Digest384::ZERO
            || self.finality_proof == Digest384::ZERO
            || self.principal.last_updated_at() > self.finalized_height
            || self.authenticator.scheme() != CryptoSuiteId::ML_DSA_44
            || self.authenticator.purpose() != AuthenticatorPurpose::Session
            || !self.authenticator.is_active_at(self.finalized_height)
            || authenticator_set_root(core::slice::from_ref(&self.authenticator))?
                != self.principal.authenticator_set_root()
            || !verifier.verify_finalized_identity_key(self)
        {
            return Err(WalletError::InvalidIdentityProof);
        }
        Ok(())
    }
}

/// Consensus/light-client boundary which proves the principal value belongs to a finalized root.
pub trait FinalizedIdentityKeyVerifier {
    fn verify_finalized_identity_key(&self, proof: &FinalizedIdentityKeyProof) -> bool;
}

/// Commits a strictly ordered bounded authenticator set. Cash v1 admits a singleton set so the
/// principal root proves there is no hidden alternate cash-control key.
pub fn authenticator_set_root(
    authenticators: &[AuthenticatorDescriptor],
) -> Result<Digest384, WalletError> {
    if authenticators.len() != 1 {
        return Err(WalletError::InvalidIdentityProof);
    }
    let encoded =
        encode_envelope(&authenticators[0]).map_err(|_| WalletError::InvalidIdentityProof)?;
    let mut hasher = Shake256::default();
    hasher.update(AUTHENTICATOR_SET_DOMAIN);
    hasher.update(&(authenticators.len() as u16).to_be_bytes());
    hasher.update(&(encoded.len() as u32).to_be_bytes());
    hasher.update(&encoded);
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    Ok(Digest384::new(output))
}

impl TransactionIngress {
    /// Saves the complete ledger and authorization state using temp-file, fsync, and rename.
    pub fn save_atomic(&self, path: &Path) -> Result<(), WalletError> {
        let bytes = encode_envelope(self).map_err(|_| WalletError::Persistence)?;
        let parent = path.parent().ok_or(WalletError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| WalletError::Persistence)?;
        let file_name = path.file_name().ok_or(WalletError::Persistence)?.to_string_lossy();
        let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
        let result = (|| {
            let mut file =
                std::fs::File::create(&temporary).map_err(|_| WalletError::Persistence)?;
            file.write_all(&bytes).map_err(|_| WalletError::Persistence)?;
            file.sync_all().map_err(|_| WalletError::Persistence)?;
            std::fs::rename(&temporary, path).map_err(|_| WalletError::Persistence)?;
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| WalletError::Persistence)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    /// Loads a strict canonical snapshot and checks it belongs to the expected chain.
    pub fn load(path: &Path, expected_chain: ChainId) -> Result<Self, WalletError> {
        let bytes = std::fs::read(path).map_err(|_| WalletError::Persistence)?;
        let ingress = decode_envelope::<Self>(&bytes).map_err(|_| WalletError::Persistence)?;
        if ingress.chain_id != expected_chain {
            return Err(WalletError::WrongChain);
        }
        Ok(ingress)
    }

    /// Applies admission to a clone, durably publishes the complete result, then exposes it.
    pub fn submit_envelope_durable(
        &mut self,
        bytes: &[u8],
        height: u64,
        path: &Path,
    ) -> Result<(), WalletError> {
        let mut next = self.clone();
        next.submit_envelope(bytes, height)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    /// Registers a session grant only after its complete next state is durably published.
    pub fn register_session_envelope_durable(
        &mut self,
        bytes: &[u8],
        path: &Path,
    ) -> Result<(), WalletError> {
        let mut next = self.clone();
        next.register_session_envelope(bytes)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }
}

impl CanonicalEncode for TransactionIngress {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.ledger.encode(encoder)?;
        self.chain_id.encode(encoder)?;
        encoder.write_length(self.authorization_lanes.len(), MAX_AUTHORIZATION_LANES)?;
        for lane in &self.authorization_lanes {
            lane.sender.encode(encoder)?;
            lane.public_key.encode(encoder)?;
            lane.next_nonce.encode(encoder)?;
            encoder.write_length(lane.consumed_sessions.len(), MAX_CONSUMED_SESSIONS_PER_LANE)?;
            for session in &lane.consumed_sessions {
                session.encode(encoder)?;
            }
            encoder.write_length(lane.session_budgets.len(), MAX_SESSION_BUDGETS_PER_LANE)?;
            for session in &lane.session_budgets {
                session.session_id.encode(encoder)?;
                session.valid_from.encode(encoder)?;
                session.expires_at.encode(encoder)?;
                session.max_spend.encode(encoder)?;
                session.spent.encode(encoder)?;
            }
            lane.identity_sequence.encode(encoder)?;
            lane.authenticator_id.encode(encoder)?;
            lane.finalized_state_root.encode(encoder)?;
            lane.finalized_height.encode(encoder)?;
            lane.finality_proof.encode(encoder)?;
        }
        encoder.write_length(self.consumed_inputs.len(), MAX_CONSUMED_INPUTS)?;
        for input in &self.consumed_inputs {
            input.encode(encoder)?;
        }
        encoder
            .write_length(self.non_authoritative_accepted.len(), MAX_NON_AUTHORITATIVE_ACCEPTED)?;
        for transaction in &self.non_authoritative_accepted {
            transaction.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for TransactionIngress {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let ledger = activechain_cash_kernel::CashLedger::decode(decoder)?;
        let chain_id = ChainId::decode(decoder)?;
        if ledger.definition().chain_id() != chain_id {
            return Err(DecodeError::InvalidValue("cash snapshot chain mismatch"));
        }
        let lane_count = decoder.read_length(MAX_AUTHORIZATION_LANES)?;
        let mut authorization_lanes = Vec::with_capacity(lane_count);
        let mut previous_sender = None;
        for _ in 0..lane_count {
            let sender = PrincipalId::decode(decoder)?;
            if previous_sender.is_some_and(|previous| sender <= previous) {
                return Err(DecodeError::InvalidValue("cash lanes are not strictly ordered"));
            }
            let public_key =
                <[u8; activechain_protocol_types::ML_DSA44_PUBLIC_KEY_LENGTH]>::decode(decoder)?;
            let next_nonce = u64::decode(decoder)?;
            let session_count = decoder.read_length(MAX_CONSUMED_SESSIONS_PER_LANE)?;
            let mut consumed_sessions = Vec::with_capacity(session_count);
            let mut previous_session = None;
            for _ in 0..session_count {
                let session = Digest384::decode(decoder)?;
                if previous_session.is_some_and(|previous| session <= previous) {
                    return Err(DecodeError::InvalidValue(
                        "cash sessions are not strictly ordered",
                    ));
                }
                consumed_sessions.push(session);
                previous_session = Some(session);
            }
            let budget_count = decoder.read_length(MAX_SESSION_BUDGETS_PER_LANE)?;
            let mut session_budgets = Vec::with_capacity(budget_count);
            let mut previous_budget = None;
            for _ in 0..budget_count {
                let session_id = Digest384::decode(decoder)?;
                if previous_budget.is_some_and(|previous| session_id <= previous) {
                    return Err(DecodeError::InvalidValue(
                        "cash session budgets are not strictly ordered",
                    ));
                }
                let valid_from = u64::decode(decoder)?;
                let expires_at = u64::decode(decoder)?;
                let max_spend = u128::decode(decoder)?;
                let spent = u128::decode(decoder)?;
                if valid_from > expires_at || expires_at == 0 || max_spend == 0 || spent > max_spend
                {
                    return Err(DecodeError::InvalidValue("invalid cash session budget"));
                }
                session_budgets.push(crate::CashSessionBudget {
                    session_id,
                    valid_from,
                    expires_at,
                    max_spend,
                    spent,
                });
                previous_budget = Some(session_id);
            }
            let identity_sequence = u64::decode(decoder)?;
            let authenticator_id = activechain_protocol_types::AuthenticatorId::decode(decoder)?;
            let finalized_state_root = Digest384::decode(decoder)?;
            let finalized_height = u64::decode(decoder)?;
            let finality_proof = Digest384::decode(decoder)?;
            if finalized_state_root == Digest384::ZERO || finality_proof == Digest384::ZERO {
                return Err(DecodeError::InvalidValue("cash lane has unbound identity provenance"));
            }
            authorization_lanes.push(CashAuthorizationLane {
                sender,
                public_key,
                next_nonce,
                consumed_sessions,
                session_budgets,
                identity_sequence,
                authenticator_id,
                finalized_state_root,
                finalized_height,
                finality_proof,
            });
            previous_sender = Some(sender);
        }
        let consumed_inputs = decode_ordered_ids::<CoinCellId>(decoder, MAX_CONSUMED_INPUTS)?;
        let non_authoritative_accepted =
            decode_ordered_ids::<TransactionId>(decoder, MAX_NON_AUTHORITATIVE_ACCEPTED)?;
        Ok(Self {
            ledger,
            chain_id,
            authorization_lanes,
            consumed_inputs,
            non_authoritative_accepted,
        })
    }
}

fn decode_ordered_ids<T>(decoder: &mut Decoder<'_>, maximum: usize) -> Result<Vec<T>, DecodeError>
where
    T: CanonicalDecode + Copy + Ord,
{
    let count = decoder.read_length(maximum)?;
    let mut values = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let value = T::decode(decoder)?;
        if previous.is_some_and(|prior| value <= prior) {
            return Err(DecodeError::InvalidValue("cash replay set is not strictly ordered"));
        }
        values.push(value);
        previous = Some(value);
    }
    Ok(values)
}

impl CanonicalType for TransactionIngress {
    const TYPE_TAG: u16 = 0x0090;
    const SCHEMA_VERSION: u16 = 2;
    const MAX_ENCODED_LEN: usize = activechain_cash_kernel::CashLedger::MAX_ENCODED_LEN
        + 48
        + 2
        + MAX_AUTHORIZATION_LANES
            * (48
                + activechain_protocol_types::ML_DSA44_PUBLIC_KEY_LENGTH
                + 8
                + 2
                + MAX_CONSUMED_SESSIONS_PER_LANE * 48
                + 2
                + MAX_SESSION_BUDGETS_PER_LANE * (48 + 8 + 8 + 16 + 16)
                + 8
                + 48
                + 48
                + 8
                + 48)
        + 2
        + MAX_CONSUMED_INPUTS * 48
        + 2
        + MAX_NON_AUTHORITATIVE_ACCEPTED * 48;
}
