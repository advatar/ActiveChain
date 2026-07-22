#![forbid(unsafe_code)]

//! Reference native-token private billboard lifecycle.
//!
//! The public action types contain no principal or public fee ticket. Secret permit openings are
//! checked by a verifier boundary which returns a receipt whose fields are private to this crate.
//! This reference verifier validates semantics directly; a production deployment must replace it
//! with a zero-knowledge verifier while preserving the same public statement.

#[cfg(feature = "runtime")]
use activechain_canonical_codec::decode_envelope;
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    encode_envelope,
};
#[cfg(feature = "runtime")]
use activechain_cash_kernel::{CashLedger, CashTransitionError};
#[cfg(feature = "runtime")]
use activechain_crypto_provider::{KemError, MlKem768Recipient, ProtectedEnvelope};
#[cfg(feature = "runtime")]
use activechain_privacy_kernel::{ShieldIntent, UnshieldIntent, VerifiedPrivacyProof};
#[cfg(feature = "runtime")]
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{AssetId, ChainId, Digest384, PrincipalId};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_MESSAGE_BYTES: usize = 280;
/// A permit carries at most two pending screening decisions.
pub const MAX_RELATION_DECISIONS: usize = 2;
pub const MAX_POSTS: usize = 4_096;
pub const MAX_DECISIONS: usize = 4_096;
pub const MAX_PERMITS: usize = 4_096;
pub const MAX_NULLIFIERS: usize = 4_096;
#[cfg(feature = "runtime")]
const NOTE_AAD: &[u8] = b"ACTIVECHAIN-PRIVATE-BILLBOARD-NOTE-V1";
#[cfg(feature = "runtime")]
const POST_AAD: &[u8] = b"ACTIVECHAIN-PRIVATE-BILLBOARD-POST-V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BillboardError {
    ZeroParameter,
    InvalidBounds,
    MessageTooLarge,
    WrongChain,
    WrongAsset,
    WrongAnchor,
    WrongPolicy,
    WrongPermit,
    InvalidProof,
    NullifierSpent,
    CapacityExceeded,
    Cooldown,
    ScreeningRequired,
    DecisionMissing,
    AlreadyDecided,
    WithdrawalNotReady,
    ArithmeticOverflow,
    InsufficientValue,
    NoteEncryption,
    NoteDecryption,
    NoteEncoding,
    CashTransition,
}

#[cfg(feature = "runtime")]
impl From<CashTransitionError> for BillboardError {
    fn from(_: CashTransitionError) -> Self {
        Self::CashTransition
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BillboardConfig {
    chain_id: ChainId,
    asset_id: AssetId,
    minimum_deposit: u128,
    base_cooldown: u64,
    maximum_save_up: u8,
    penalty_slots: u64,
    screening_window: u64,
    post_fee: u128,
    policy_revision: u64,
}

impl BillboardConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        asset_id: AssetId,
        minimum_deposit: u128,
        base_cooldown: u64,
        maximum_save_up: u8,
        penalty_slots: u64,
        screening_window: u64,
        post_fee: u128,
        policy_revision: u64,
    ) -> Result<Self, BillboardError> {
        if minimum_deposit == 0
            || base_cooldown == 0
            || maximum_save_up == 0
            || screening_window == 0
            || policy_revision == 0
        {
            return Err(BillboardError::ZeroParameter);
        }
        Ok(Self {
            chain_id,
            asset_id,
            minimum_deposit,
            base_cooldown,
            maximum_save_up,
            penalty_slots,
            screening_window,
            post_fee,
            policy_revision,
        })
    }

    #[must_use]
    pub const fn chain_id(self) -> ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn asset_id(self) -> AssetId {
        self.asset_id
    }

    fn cooldown(self, amount: u128) -> Result<u64, BillboardError> {
        if amount < self.minimum_deposit {
            return Err(BillboardError::InsufficientValue);
        }
        let numerator = u128::from(self.base_cooldown)
            .checked_mul(self.minimum_deposit)
            .ok_or(BillboardError::ArithmeticOverflow)?;
        let value = numerator / amount;
        u64::try_from(value.max(1)).map_err(|_| BillboardError::ArithmeticOverflow)
    }
}

impl CanonicalEncode for BillboardConfig {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.asset_id.encode(e)?;
        self.minimum_deposit.encode(e)?;
        self.base_cooldown.encode(e)?;
        self.maximum_save_up.encode(e)?;
        self.penalty_slots.encode(e)?;
        self.screening_window.encode(e)?;
        self.post_fee.encode(e)?;
        self.policy_revision.encode(e)
    }
}

impl CanonicalDecode for BillboardConfig {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(d)?,
            AssetId::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
            u8::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid billboard configuration"))
    }
}

impl CanonicalType for BillboardConfig {
    const TYPE_TAG: u16 = 0x00b3;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 2 + 16 * 2 + 8 * 4 + 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingScreen {
    post_id: Digest384,
    eligible_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BillboardPermit {
    chain_id: ChainId,
    asset_id: AssetId,
    owner_key: Digest384,
    amount: u128,
    next_allowed_height: u64,
    saved_posts: u8,
    sequence: u64,
    pending: Vec<PendingScreen>,
    policy_revision: u64,
    blinding: Digest384,
}

impl BillboardPermit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: BillboardConfig,
        owner_key: Digest384,
        amount: u128,
        height: u64,
        blinding: Digest384,
    ) -> Result<Self, BillboardError> {
        if owner_key == Digest384::ZERO || blinding == Digest384::ZERO {
            return Err(BillboardError::InvalidBounds);
        }
        config.cooldown(amount)?;
        Ok(Self {
            chain_id: config.chain_id,
            asset_id: config.asset_id,
            owner_key,
            amount,
            next_allowed_height: height,
            saved_posts: 0,
            sequence: 0,
            pending: Vec::new(),
            policy_revision: config.policy_revision,
            blinding,
        })
    }

    #[must_use]
    pub const fn amount(&self) -> u128 {
        self.amount
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn commitment(&self) -> Result<Digest384, BillboardError> {
        hash_parts(
            b"ACTIVECHAIN-BILLBOARD-PERMIT-V1",
            &[&encode_envelope(self).map_err(|_| BillboardError::NoteEncoding)?],
        )
    }

    pub fn nullifier(&self, nullifier_key: Digest384) -> Result<Digest384, BillboardError> {
        hash_parts(
            b"ACTIVECHAIN-BILLBOARD-NULLIFIER-V1",
            &[self.commitment()?.as_bytes(), nullifier_key.as_bytes()],
        )
    }
}

impl CanonicalEncode for BillboardPermit {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.asset_id.encode(e)?;
        self.owner_key.encode(e)?;
        self.amount.encode(e)?;
        self.next_allowed_height.encode(e)?;
        self.saved_posts.encode(e)?;
        self.sequence.encode(e)?;
        e.write_length(self.pending.len(), 2)?;
        for item in &self.pending {
            item.post_id.encode(e)?;
            item.eligible_at.encode(e)?;
        }
        self.policy_revision.encode(e)?;
        self.blinding.encode(e)
    }
}

impl CanonicalDecode for BillboardPermit {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(d)?;
        let asset_id = AssetId::decode(d)?;
        let owner_key = Digest384::decode(d)?;
        let amount = u128::decode(d)?;
        let next_allowed_height = u64::decode(d)?;
        let saved_posts = u8::decode(d)?;
        let sequence = u64::decode(d)?;
        let count = d.read_length(2)?;
        let mut pending = Vec::with_capacity(count);
        for _ in 0..count {
            pending.push(PendingScreen {
                post_id: Digest384::decode(d)?,
                eligible_at: u64::decode(d)?,
            });
        }
        let policy_revision = u64::decode(d)?;
        let blinding = Digest384::decode(d)?;
        if owner_key == Digest384::ZERO || blinding == Digest384::ZERO || amount == 0 {
            return Err(DecodeError::InvalidValue("invalid billboard permit"));
        }
        Ok(Self {
            chain_id,
            asset_id,
            owner_key,
            amount,
            next_allowed_height,
            saved_posts,
            sequence,
            pending,
            policy_revision,
            blinding,
        })
    }
}

impl CanonicalType for BillboardPermit {
    const TYPE_TAG: u16 = 0x00b0;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 4 + 16 + 8 * 3 + 1 + 2 + 2 * (48 + 8);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicPost {
    pub id: Digest384,
    pub content: Vec<u8>,
    pub height: u64,
    pub dummy: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModerationDecision {
    pub post_id: Digest384,
    pub policy_revision: u64,
    pub flagged: bool,
}

impl CanonicalEncode for ModerationDecision {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.post_id.encode(e)?;
        self.policy_revision.encode(e)?;
        self.flagged.encode(e)
    }
}

impl CanonicalDecode for ModerationDecision {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            post_id: Digest384::decode(d)?,
            policy_revision: u64::decode(d)?,
            flagged: bool::decode(d)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostPublicInputs {
    pub chain_id: ChainId,
    pub asset_id: AssetId,
    pub anchor: Digest384,
    pub nullifier: Digest384,
    pub successor_commitment: Digest384,
    pub post_id: Digest384,
    pub content: Vec<u8>,
    pub height: u64,
    pub fee: u128,
    pub dummy: bool,
    pub policy_revision: u64,
}

impl PostPublicInputs {
    pub fn commitment(&self) -> Result<Digest384, BillboardError> {
        if self.content.len() > MAX_MESSAGE_BYTES {
            return Err(BillboardError::MessageTooLarge);
        }
        let mut scalar = Vec::new();
        scalar.extend_from_slice(&self.height.to_be_bytes());
        scalar.extend_from_slice(&self.fee.to_be_bytes());
        scalar.push(u8::from(self.dummy));
        scalar.extend_from_slice(&self.policy_revision.to_be_bytes());
        hash_parts(
            b"ACTIVECHAIN-BILLBOARD-POST-PUBLIC-V1",
            &[
                self.chain_id.digest().as_bytes(),
                self.asset_id.digest().as_bytes(),
                self.anchor.as_bytes(),
                self.nullifier.as_bytes(),
                self.successor_commitment.as_bytes(),
                self.post_id.as_bytes(),
                &self.content,
                &scalar,
            ],
        )
    }
}

impl CanonicalEncode for PostPublicInputs {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.asset_id.encode(e)?;
        self.anchor.encode(e)?;
        self.nullifier.encode(e)?;
        self.successor_commitment.encode(e)?;
        self.post_id.encode(e)?;
        e.write_bytes(&self.content, MAX_MESSAGE_BYTES)?;
        self.height.encode(e)?;
        self.fee.encode(e)?;
        u8::from(self.dummy).encode(e)?;
        self.policy_revision.encode(e)
    }
}

impl CanonicalDecode for PostPublicInputs {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            chain_id: ChainId::decode(d)?,
            asset_id: AssetId::decode(d)?,
            anchor: Digest384::decode(d)?,
            nullifier: Digest384::decode(d)?,
            successor_commitment: Digest384::decode(d)?,
            post_id: Digest384::decode(d)?,
            content: d.read_bytes(MAX_MESSAGE_BYTES)?.to_vec(),
            height: u64::decode(d)?,
            fee: u128::decode(d)?,
            dummy: match u8::decode(d)? {
                0 => false,
                1 => true,
                _ => return Err(DecodeError::InvalidValue("invalid dummy tag")),
            },
            policy_revision: u64::decode(d)?,
        };
        if value.dummy && !value.content.is_empty() {
            return Err(DecodeError::InvalidValue("dummy post contains content"));
        }
        Ok(value)
    }
}

impl CanonicalType for PostPublicInputs {
    const TYPE_TAG: u16 = 0x00b1;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 6 + 2 + MAX_MESSAGE_BYTES + 8 + 16 + 1 + 8;
}

/// ML-KEM protected senderless action payload for the existing protected-ordering lane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedPostSubmission {
    envelope: Vec<u8>,
}

#[cfg(feature = "runtime")]
impl EncryptedPostSubmission {
    pub fn seal(
        public: &PostPublicInputs,
        ordering_public_key: &[u8],
    ) -> Result<Self, BillboardError> {
        let payload = encode_envelope(public).map_err(|_| BillboardError::NoteEncoding)?;
        let envelope = ProtectedEnvelope::seal(ordering_public_key, &payload, POST_AAD)
            .and_then(|value| value.encode())
            .map_err(|_| BillboardError::NoteEncryption)?;
        Ok(Self { envelope })
    }

    pub fn open(
        &self,
        ordering_recipient: &MlKem768Recipient,
    ) -> Result<PostPublicInputs, BillboardError> {
        let envelope = ProtectedEnvelope::decode(&self.envelope)
            .map_err(|_| BillboardError::NoteDecryption)?;
        let payload = envelope
            .open(ordering_recipient, POST_AAD)
            .map_err(|_| BillboardError::NoteDecryption)?;
        decode_envelope(&payload).map_err(|_| BillboardError::NoteEncoding)
    }
}

#[derive(Clone, Debug)]
pub struct PostWitness {
    pub prior: BillboardPermit,
    pub successor: BillboardPermit,
    pub nullifier_key: Digest384,
}

impl CanonicalEncode for PostWitness {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.prior.encode(e)?;
        self.successor.encode(e)?;
        self.nullifier_key.encode(e)
    }
}

impl CanonicalDecode for PostWitness {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            prior: BillboardPermit::decode(d)?,
            successor: BillboardPermit::decode(d)?,
            nullifier_key: Digest384::decode(d)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WithdrawalPublicInputs {
    pub chain_id: ChainId,
    pub asset_id: AssetId,
    pub anchor: Digest384,
    pub nullifier: Digest384,
    pub recipient: PrincipalId,
    pub amount: u128,
    pub fee: u128,
    pub height: u64,
    pub policy_revision: u64,
}

impl WithdrawalPublicInputs {
    pub fn commitment(self) -> Result<Digest384, BillboardError> {
        let mut scalar = Vec::new();
        scalar.extend_from_slice(&self.amount.to_be_bytes());
        scalar.extend_from_slice(&self.fee.to_be_bytes());
        scalar.extend_from_slice(&self.height.to_be_bytes());
        scalar.extend_from_slice(&self.policy_revision.to_be_bytes());
        hash_parts(
            b"ACTIVECHAIN-BILLBOARD-WITHDRAW-PUBLIC-V1",
            &[
                self.chain_id.digest().as_bytes(),
                self.asset_id.digest().as_bytes(),
                self.anchor.as_bytes(),
                self.nullifier.as_bytes(),
                self.recipient.digest().as_bytes(),
                &scalar,
            ],
        )
    }
}

#[derive(Clone, Debug)]
pub struct WithdrawalWitness {
    pub permit: BillboardPermit,
    pub nullifier_key: Digest384,
}

impl CanonicalEncode for WithdrawalPublicInputs {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(e)?;
        self.asset_id.encode(e)?;
        self.anchor.encode(e)?;
        self.nullifier.encode(e)?;
        self.recipient.encode(e)?;
        self.amount.encode(e)?;
        self.fee.encode(e)?;
        self.height.encode(e)?;
        self.policy_revision.encode(e)
    }
}

impl CanonicalDecode for WithdrawalPublicInputs {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            chain_id: ChainId::decode(d)?,
            asset_id: AssetId::decode(d)?,
            anchor: Digest384::decode(d)?,
            nullifier: Digest384::decode(d)?,
            recipient: PrincipalId::decode(d)?,
            amount: u128::decode(d)?,
            fee: u128::decode(d)?,
            height: u64::decode(d)?,
            policy_revision: u64::decode(d)?,
        })
    }
}

impl CanonicalType for WithdrawalPublicInputs {
    const TYPE_TAG: u16 = 0x00b2;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 5 + 16 * 2 + 8 * 2;
}

impl CanonicalEncode for WithdrawalWitness {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.permit.encode(e)?;
        self.nullifier_key.encode(e)
    }
}

impl CanonicalDecode for WithdrawalWitness {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { permit: BillboardPermit::decode(d)?, nullifier_key: Digest384::decode(d)? })
    }
}

#[derive(Clone, Debug)]
pub struct PostRelationInput {
    pub config: BillboardConfig,
    pub public: PostPublicInputs,
    pub witness: PostWitness,
    pub decisions: Vec<ModerationDecision>,
}

#[derive(Clone, Debug)]
pub struct WithdrawalRelationInput {
    pub config: BillboardConfig,
    pub public: WithdrawalPublicInputs,
    pub witness: WithdrawalWitness,
    pub decisions: Vec<ModerationDecision>,
}

macro_rules! relation_codec {
    ($ty:ty, $tag:expr, $public:ty, $witness:ty) => {
        impl CanonicalEncode for $ty {
            fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
                self.config.encode(e)?;
                self.public.encode(e)?;
                self.witness.encode(e)?;
                e.write_length(self.decisions.len(), MAX_RELATION_DECISIONS)?;
                for decision in &self.decisions {
                    decision.encode(e)?;
                }
                Ok(())
            }
        }
        impl CanonicalDecode for $ty {
            fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                let config = BillboardConfig::decode(d)?;
                let public = <$public>::decode(d)?;
                let witness = <$witness>::decode(d)?;
                let count = d.read_length(MAX_RELATION_DECISIONS)?;
                let mut decisions = Vec::with_capacity(count);
                for _ in 0..count {
                    decisions.push(ModerationDecision::decode(d)?);
                }
                Ok(Self { config, public, witness, decisions })
            }
        }
        impl CanonicalType for $ty {
            const TYPE_TAG: u16 = $tag;
            const SCHEMA_VERSION: u16 = 1;
            const MAX_ENCODED_LEN: usize = 4096;
        }
    };
}

relation_codec!(PostRelationInput, 0x00b4, PostPublicInputs, PostWitness);
relation_codec!(WithdrawalRelationInput, 0x00b5, WithdrawalPublicInputs, WithdrawalWitness);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedBillboardProof {
    public_inputs_commitment: Digest384,
    permit_commitment: Digest384,
}

impl VerifiedBillboardProof {
    #[must_use]
    pub const fn public_inputs_commitment(self) -> Digest384 {
        self.public_inputs_commitment
    }

    #[must_use]
    pub const fn permit_commitment(self) -> Digest384 {
        self.permit_commitment
    }
}

pub struct BillboardVerifier;

pub fn derive_post_successor(
    config: BillboardConfig,
    prior: &BillboardPermit,
    content: &[u8],
    post_id: Digest384,
    height: u64,
    blinding: Digest384,
    decisions: &[ModerationDecision],
) -> Result<BillboardPermit, BillboardError> {
    let mut expected = prior.clone();
    screen_matured(&mut expected, decisions, height, config.penalty_slots)?;
    accrue_save_up(&mut expected, config, height)?;
    if expected.saved_posts == 0 || height < expected.next_allowed_height {
        return Err(BillboardError::Cooldown);
    }
    if expected.amount < config.post_fee {
        return Err(BillboardError::InsufficientValue);
    }
    expected.amount -= config.post_fee;
    expected.saved_posts -= 1;
    expected.sequence =
        expected.sequence.checked_add(1).ok_or(BillboardError::ArithmeticOverflow)?;
    expected.next_allowed_height = height
        .checked_add(config.cooldown(expected.amount.max(config.minimum_deposit))?)
        .ok_or(BillboardError::ArithmeticOverflow)?;
    if !content.is_empty() {
        if expected.pending.len() >= MAX_RELATION_DECISIONS {
            return Err(BillboardError::ScreeningRequired);
        }
        expected.pending.push(PendingScreen {
            post_id,
            eligible_at: height
                .checked_add(config.screening_window)
                .ok_or(BillboardError::ArithmeticOverflow)?,
        });
    }
    expected.blinding = blinding;
    Ok(expected)
}

impl BillboardVerifier {
    pub fn verify_post(
        config: BillboardConfig,
        public: &PostPublicInputs,
        witness: &PostWitness,
        decisions: &[ModerationDecision],
    ) -> Result<VerifiedBillboardProof, BillboardError> {
        verify_context(config, public.chain_id, public.asset_id, public.policy_revision)?;
        if public.content.len() > MAX_MESSAGE_BYTES || (public.dummy && !public.content.is_empty())
        {
            return Err(BillboardError::MessageTooLarge);
        }
        let prior = &witness.prior;
        let successor = &witness.successor;
        let prior_commitment = prior.commitment()?;
        if public.nullifier != prior.nullifier(witness.nullifier_key)?
            || successor.commitment()? != public.successor_commitment
            || prior.chain_id != config.chain_id
            || prior.asset_id != config.asset_id
            || prior.policy_revision != config.policy_revision
            || successor.owner_key != prior.owner_key
            || successor.chain_id != prior.chain_id
            || successor.asset_id != prior.asset_id
            || successor.policy_revision != prior.policy_revision
            || successor.sequence
                != prior.sequence.checked_add(1).ok_or(BillboardError::ArithmeticOverflow)?
        {
            return Err(BillboardError::WrongPermit);
        }
        if public.fee != config.post_fee {
            return Err(BillboardError::InsufficientValue);
        }
        let expected = derive_post_successor(
            config,
            prior,
            if public.dummy { &[] } else { &public.content },
            public.post_id,
            public.height,
            successor.blinding,
            decisions,
        )?;
        if expected != *successor {
            return Err(BillboardError::WrongPermit);
        }
        Ok(VerifiedBillboardProof {
            public_inputs_commitment: public.commitment()?,
            permit_commitment: prior_commitment,
        })
    }

    pub fn verify_withdrawal(
        config: BillboardConfig,
        public: WithdrawalPublicInputs,
        witness: &WithdrawalWitness,
        decisions: &[ModerationDecision],
    ) -> Result<VerifiedBillboardProof, BillboardError> {
        verify_context(config, public.chain_id, public.asset_id, public.policy_revision)?;
        let mut permit = witness.permit.clone();
        screen_matured(&mut permit, decisions, public.height, config.penalty_slots)?;
        if !permit.pending.is_empty() {
            return Err(BillboardError::WithdrawalNotReady);
        }
        if public.nullifier != witness.permit.nullifier(witness.nullifier_key)?
            || public.amount.checked_add(public.fee).ok_or(BillboardError::ArithmeticOverflow)?
                != witness.permit.amount
        {
            return Err(BillboardError::WrongPermit);
        }
        Ok(VerifiedBillboardProof {
            public_inputs_commitment: public.commitment()?,
            permit_commitment: witness.permit.commitment()?,
        })
    }
}

#[cfg(feature = "runtime")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BillboardState {
    config: BillboardConfig,
    anchor: Digest384,
    pool_balance: u128,
    fee_reserve: u128,
    permits: Vec<Digest384>,
    spent_nullifiers: Vec<Digest384>,
    posts: Vec<PublicPost>,
    decisions: Vec<ModerationDecision>,
    withdrawals: Vec<(PrincipalId, u128)>,
}

/// Atomic composition of the public native ledger and private billboard application state.
#[cfg(feature = "runtime")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBillboardLedger {
    cash: CashLedger,
    billboard: BillboardState,
}

#[cfg(feature = "runtime")]
impl NativeBillboardLedger {
    #[must_use]
    pub fn new(cash: CashLedger, config: BillboardConfig) -> Self {
        Self { cash, billboard: BillboardState::new(config) }
    }

    #[must_use]
    pub const fn cash(&self) -> &CashLedger {
        &self.cash
    }

    #[must_use]
    pub const fn billboard(&self) -> &BillboardState {
        &self.billboard
    }

    /// Atomically consumes public native cells and creates the first private permit.
    pub fn shield(
        &mut self,
        intent: &ShieldIntent,
        permit: &BillboardPermit,
        height: u64,
    ) -> Result<(), BillboardError> {
        if intent.chain_id() != self.billboard.config.chain_id
            || intent.asset_id() != self.billboard.config.asset_id
            || intent.amount() != permit.amount
            || intent.output_commitments().binary_search(&permit.commitment()?).is_err()
        {
            return Err(BillboardError::WrongPermit);
        }
        let mut next = self.clone();
        let proof = privacy_receipt(intent)?;
        next.cash.apply_shield(intent, proof, height)?;
        next.billboard.shield(permit)?;
        next.verify_balances()?;
        *self = next;
        Ok(())
    }

    /// Atomically pays the post fee from shielded value and advances the billboard permit.
    pub fn post(
        &mut self,
        public: PostPublicInputs,
        proof: VerifiedBillboardProof,
        fee_intent: &UnshieldIntent,
    ) -> Result<(), BillboardError> {
        let paid = fee_intent
            .amount()
            .checked_add(fee_intent.fee())
            .ok_or(BillboardError::ArithmeticOverflow)?;
        if fee_intent.chain_id() != public.chain_id
            || fee_intent.asset_id() != public.asset_id
            || fee_intent.anchor() != self.cash.shielded_state().anchor()
            || fee_intent.nullifiers() != [public.nullifier]
            || fee_intent.change_commitments() != [public.successor_commitment]
            || paid != public.fee
        {
            return Err(BillboardError::InvalidProof);
        }
        let mut next = self.clone();
        let cash_proof = privacy_receipt(fee_intent)?;
        next.cash.apply_unshield(fee_intent, cash_proof, public.height)?;
        next.billboard.apply_post(public, proof)?;
        next.verify_balances()?;
        *self = next;
        Ok(())
    }

    /// Atomically consumes the terminal permit and creates the public native withdrawal cell.
    pub fn withdraw(
        &mut self,
        public: WithdrawalPublicInputs,
        proof: VerifiedBillboardProof,
        intent: &UnshieldIntent,
    ) -> Result<(), BillboardError> {
        if intent.chain_id() != public.chain_id
            || intent.asset_id() != public.asset_id
            || intent.anchor() != self.cash.shielded_state().anchor()
            || intent.recipient() != public.recipient
            || intent.amount() != public.amount
            || intent.fee() != public.fee
            || intent.nullifiers() != [public.nullifier]
            || !intent.change_commitments().is_empty()
        {
            return Err(BillboardError::InvalidProof);
        }
        let mut next = self.clone();
        let cash_proof = privacy_receipt(intent)?;
        next.cash.apply_unshield(intent, cash_proof, public.height)?;
        next.billboard.apply_withdrawal(public, proof)?;
        next.verify_balances()?;
        *self = next;
        Ok(())
    }

    fn verify_balances(&self) -> Result<(), BillboardError> {
        if self.cash.shielded_state().pool_balance() != self.billboard.pool_balance {
            return Err(BillboardError::CashTransition);
        }
        Ok(())
    }
}

#[cfg(feature = "runtime")]
impl BillboardState {
    #[must_use]
    pub fn new(config: BillboardConfig) -> Self {
        Self {
            config,
            anchor: Digest384::ZERO,
            pool_balance: 0,
            fee_reserve: 0,
            permits: Vec::new(),
            spent_nullifiers: Vec::new(),
            posts: Vec::new(),
            decisions: Vec::new(),
            withdrawals: Vec::new(),
        }
    }

    #[must_use]
    pub const fn anchor(&self) -> Digest384 {
        self.anchor
    }

    #[must_use]
    pub fn posts(&self) -> &[PublicPost] {
        &self.posts
    }

    #[must_use]
    pub fn withdrawals(&self) -> &[(PrincipalId, u128)] {
        &self.withdrawals
    }

    fn shield(&mut self, permit: &BillboardPermit) -> Result<(), BillboardError> {
        verify_context(self.config, permit.chain_id, permit.asset_id, permit.policy_revision)?;
        if self.permits.len() >= MAX_PERMITS {
            return Err(BillboardError::CapacityExceeded);
        }
        let commitment = permit.commitment()?;
        let mut next = self.clone();
        insert_unique(&mut next.permits, commitment, MAX_PERMITS)?;
        next.pool_balance = next
            .pool_balance
            .checked_add(permit.amount)
            .ok_or(BillboardError::ArithmeticOverflow)?;
        next.reanchor()?;
        *self = next;
        Ok(())
    }

    pub fn decide(&mut self, decision: ModerationDecision) -> Result<(), BillboardError> {
        if decision.policy_revision != self.config.policy_revision {
            return Err(BillboardError::WrongPolicy);
        }
        if !self.posts.iter().any(|post| post.id == decision.post_id) {
            return Err(BillboardError::DecisionMissing);
        }
        if self.decisions.iter().any(|item| item.post_id == decision.post_id) {
            return Err(BillboardError::AlreadyDecided);
        }
        if self.decisions.len() >= MAX_DECISIONS {
            return Err(BillboardError::CapacityExceeded);
        }
        self.decisions.push(decision);
        Ok(())
    }

    pub fn apply_post(
        &mut self,
        public: PostPublicInputs,
        proof: VerifiedBillboardProof,
    ) -> Result<(), BillboardError> {
        let mut next = self.clone();
        if public.anchor != next.anchor
            || proof.public_inputs_commitment != public.commitment()?
            || next.permits.binary_search(&proof.permit_commitment).is_err()
        {
            return Err(BillboardError::InvalidProof);
        }
        next.consume(proof.permit_commitment, public.nullifier)?;
        insert_unique(&mut next.permits, public.successor_commitment, MAX_PERMITS)?;
        next.pool_balance =
            next.pool_balance.checked_sub(public.fee).ok_or(BillboardError::InsufficientValue)?;
        next.fee_reserve =
            next.fee_reserve.checked_add(public.fee).ok_or(BillboardError::ArithmeticOverflow)?;
        if !public.dummy {
            if next.posts.len() >= MAX_POSTS {
                return Err(BillboardError::CapacityExceeded);
            }
            next.posts.push(PublicPost {
                id: public.post_id,
                content: public.content,
                height: public.height,
                dummy: false,
            });
        }
        next.reanchor()?;
        *self = next;
        Ok(())
    }

    pub fn apply_withdrawal(
        &mut self,
        public: WithdrawalPublicInputs,
        proof: VerifiedBillboardProof,
    ) -> Result<(), BillboardError> {
        let mut next = self.clone();
        if public.anchor != next.anchor
            || proof.public_inputs_commitment != public.commitment()?
            || next.permits.binary_search(&proof.permit_commitment).is_err()
        {
            return Err(BillboardError::InvalidProof);
        }
        next.consume(proof.permit_commitment, public.nullifier)?;
        let debit =
            public.amount.checked_add(public.fee).ok_or(BillboardError::ArithmeticOverflow)?;
        next.pool_balance =
            next.pool_balance.checked_sub(debit).ok_or(BillboardError::InsufficientValue)?;
        next.fee_reserve =
            next.fee_reserve.checked_add(public.fee).ok_or(BillboardError::ArithmeticOverflow)?;
        next.withdrawals.push((public.recipient, public.amount));
        next.reanchor()?;
        *self = next;
        Ok(())
    }

    fn consume(&mut self, permit: Digest384, nullifier: Digest384) -> Result<(), BillboardError> {
        if self.spent_nullifiers.binary_search(&nullifier).is_ok() {
            return Err(BillboardError::NullifierSpent);
        }
        if self.spent_nullifiers.len() >= MAX_NULLIFIERS {
            return Err(BillboardError::CapacityExceeded);
        }
        let position =
            self.permits.binary_search(&permit).map_err(|_| BillboardError::WrongPermit)?;
        self.permits.remove(position);
        insert_unique(&mut self.spent_nullifiers, nullifier, MAX_NULLIFIERS)
    }

    fn reanchor(&mut self) -> Result<(), BillboardError> {
        let mut scalar = Vec::new();
        scalar.extend_from_slice(&self.pool_balance.to_be_bytes());
        scalar.extend_from_slice(&self.fee_reserve.to_be_bytes());
        let permit_bytes = flatten_digests(&self.permits);
        let nullifier_bytes = flatten_digests(&self.spent_nullifiers);
        self.anchor = hash_parts(
            b"ACTIVECHAIN-BILLBOARD-STATE-V1",
            &[&scalar, &permit_bytes, &nullifier_bytes],
        )?;
        Ok(())
    }
}

#[cfg(feature = "runtime")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedPermit {
    commitment: Digest384,
    envelope: Vec<u8>,
}

#[cfg(feature = "runtime")]
impl EncryptedPermit {
    pub fn seal(
        permit: &BillboardPermit,
        recipient_public_key: &[u8],
    ) -> Result<Self, BillboardError> {
        let commitment = permit.commitment()?;
        let bytes = encode_envelope(permit).map_err(|_| BillboardError::NoteEncoding)?;
        let envelope = ProtectedEnvelope::seal(recipient_public_key, &bytes, NOTE_AAD)
            .and_then(|value| value.encode())
            .map_err(|_| BillboardError::NoteEncryption)?;
        Ok(Self { commitment, envelope })
    }
}

#[cfg(feature = "runtime")]
pub struct BillboardWallet {
    recipient: MlKem768Recipient,
    permits: Vec<BillboardPermit>,
    spent: Vec<Digest384>,
}

#[cfg(feature = "runtime")]
impl BillboardWallet {
    #[must_use]
    pub fn from_seed(seed: [u8; 64]) -> Self {
        Self {
            recipient: MlKem768Recipient::from_seed(seed),
            permits: Vec::new(),
            spent: Vec::new(),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.recipient.public_key()
    }

    pub fn discover(&mut self, note: &EncryptedPermit) -> Result<Digest384, BillboardError> {
        let envelope = ProtectedEnvelope::decode(&note.envelope)
            .map_err(|_| BillboardError::NoteDecryption)?;
        let bytes =
            envelope.open(&self.recipient, NOTE_AAD).map_err(|_| BillboardError::NoteDecryption)?;
        let permit =
            decode_envelope::<BillboardPermit>(&bytes).map_err(|_| BillboardError::NoteEncoding)?;
        if permit.commitment()? != note.commitment {
            return Err(BillboardError::WrongPermit);
        }
        if !self.permits.iter().any(|item| item.commitment().ok() == Some(note.commitment)) {
            self.permits.push(permit);
        }
        Ok(note.commitment)
    }

    #[must_use]
    pub fn permits(&self) -> &[BillboardPermit] {
        &self.permits
    }

    pub fn replace(
        &mut self,
        prior: Digest384,
        successor: BillboardPermit,
        nullifier: Digest384,
    ) -> Result<(), BillboardError> {
        let position = self
            .permits
            .iter()
            .position(|permit| permit.commitment().ok() == Some(prior))
            .ok_or(BillboardError::WrongPermit)?;
        self.permits.remove(position);
        self.permits.push(successor);
        insert_unique(&mut self.spent, nullifier, MAX_NULLIFIERS)
    }

    pub fn remove(
        &mut self,
        commitment: Digest384,
        nullifier: Digest384,
    ) -> Result<(), BillboardError> {
        let position = self
            .permits
            .iter()
            .position(|permit| permit.commitment().ok() == Some(commitment))
            .ok_or(BillboardError::WrongPermit)?;
        self.permits.remove(position);
        insert_unique(&mut self.spent, nullifier, MAX_NULLIFIERS)
    }
}

#[cfg(feature = "runtime")]
impl From<KemError> for BillboardError {
    fn from(_: KemError) -> Self {
        Self::NoteEncryption
    }
}

fn verify_context(
    config: BillboardConfig,
    chain_id: ChainId,
    asset_id: AssetId,
    policy_revision: u64,
) -> Result<(), BillboardError> {
    if chain_id != config.chain_id {
        return Err(BillboardError::WrongChain);
    }
    if asset_id != config.asset_id {
        return Err(BillboardError::WrongAsset);
    }
    if policy_revision != config.policy_revision {
        return Err(BillboardError::WrongPolicy);
    }
    Ok(())
}

fn accrue_save_up(
    permit: &mut BillboardPermit,
    config: BillboardConfig,
    height: u64,
) -> Result<(), BillboardError> {
    let cooldown = config.cooldown(permit.amount)?;
    if height >= permit.next_allowed_height {
        let elapsed = height - permit.next_allowed_height;
        let additional = elapsed / cooldown + 1;
        let total = u64::from(permit.saved_posts)
            .checked_add(additional)
            .ok_or(BillboardError::ArithmeticOverflow)?
            .min(u64::from(config.maximum_save_up));
        permit.saved_posts = u8::try_from(total).map_err(|_| BillboardError::ArithmeticOverflow)?;
    }
    Ok(())
}

fn screen_matured(
    permit: &mut BillboardPermit,
    decisions: &[ModerationDecision],
    height: u64,
    penalty_slots: u64,
) -> Result<(), BillboardError> {
    let mut retained = Vec::new();
    for pending in &permit.pending {
        if pending.eligible_at > height {
            retained.push(*pending);
            continue;
        }
        let decision = decisions
            .iter()
            .find(|item| item.post_id == pending.post_id)
            .ok_or(BillboardError::DecisionMissing)?;
        if decision.policy_revision != permit.policy_revision {
            return Err(BillboardError::WrongPolicy);
        }
        if decision.flagged {
            permit.next_allowed_height = permit
                .next_allowed_height
                .checked_add(penalty_slots)
                .ok_or(BillboardError::ArithmeticOverflow)?;
        }
    }
    permit.pending = retained;
    Ok(())
}

#[cfg(feature = "runtime")]
fn insert_unique(
    values: &mut Vec<Digest384>,
    value: Digest384,
    maximum: usize,
) -> Result<(), BillboardError> {
    if values.len() >= maximum {
        return Err(BillboardError::CapacityExceeded);
    }
    match values.binary_search(&value) {
        Ok(_) => Err(BillboardError::NullifierSpent),
        Err(position) => {
            values.insert(position, value);
            Ok(())
        }
    }
}

#[cfg(feature = "runtime")]
fn flatten_digests(values: &[Digest384]) -> Vec<u8> {
    values.iter().flat_map(|value| value.as_bytes().iter().copied()).collect()
}

#[cfg(feature = "runtime")]
fn privacy_receipt<T: CanonicalType>(
    statement: &T,
) -> Result<VerifiedPrivacyProof, BillboardError> {
    Ok(VerifiedPrivacyProof {
        public_inputs_commitment: commit(DomainTag::PRIVACY_PUBLIC_INPUTS, statement)
            .map_err(|_| BillboardError::NoteEncoding)?,
        verified: true,
    })
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest384, BillboardError> {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| BillboardError::ArithmeticOverflow)?;
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    Ok(Digest384::new(output))
}

#[cfg(test)]
mod tests;
