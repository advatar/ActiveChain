use activechain_accumulator::KEY_BITS;
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{CoinCellId, Digest384, PrincipalId, fee_total, next_base_fee};
use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifierRole {
    Finality,
    Availability,
    Audit,
    Assurance,
    PublicGoods,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DutyAssignment {
    pub id: Digest384,
    pub verifier: PrincipalId,
    pub role: VerifierRole,
    pub target: Digest384,
    pub bond: CoinCellId,
    pub bond_amount: u128,
    pub reward: u128,
    pub deadline: u64,
    pub settled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DutyReceipt {
    pub assignment: Digest384,
    pub evidence: Digest384,
    pub height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectiveFault {
    pub assignment: Digest384,
    pub evidence: Digest384,
    pub slash_amount: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardSettlement {
    pub assignment: Digest384,
    pub verifier: PrincipalId,
    pub reward: u128,
    pub bond_return: u128,
    pub slash_amount: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardRedemption {
    pub settlement: Digest384,
    pub replay_witness: RewardReplayWitness,
    pub pool_owner: PrincipalId,
    pub pool_cell: CoinCellId,
    pub fee_reserve: CoinCellId,
    pub height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardReplayWitness {
    assignment: Digest384,
    siblings: Vec<Digest384>,
}

impl RewardReplayWitness {
    pub const TYPE_TAG: u16 = 0x014f;

    pub fn new(assignment: Digest384, siblings: Vec<Digest384>) -> Result<Self, DecodeError> {
        if assignment == Digest384::ZERO || siblings.len() != KEY_BITS {
            return Err(DecodeError::InvalidValue("invalid reward replay witness"));
        }
        Ok(Self { assignment, siblings })
    }

    #[must_use]
    pub const fn assignment(&self) -> Digest384 {
        self.assignment
    }

    #[must_use]
    pub fn siblings(&self) -> &[Digest384] {
        &self.siblings
    }
}

impl CanonicalEncode for RewardReplayWitness {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.assignment.encode(encoder)?;
        for sibling in &self.siblings {
            sibling.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for RewardReplayWitness {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let assignment = Digest384::decode(decoder)?;
        let mut siblings = Vec::with_capacity(KEY_BITS);
        for _ in 0..KEY_BITS {
            siblings.push(Digest384::decode(decoder)?);
        }
        Self::new(assignment, siblings)
    }
}

impl CanonicalType for RewardReplayWitness {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * (1 + KEY_BITS);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeAssignment {
    id: Digest384,
    duty: Digest384,
    challenger: PrincipalId,
    bond: CoinCellId,
    evidence: Digest384,
    reward: u128,
    deadline: u64,
    resolved: bool,
}

/// Sealed challenge admission that prevents another participant from copying
/// disclosed fault evidence before the original challenger is registered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeCommitmentV1 {
    id: Digest384,
    duty: Digest384,
    challenger: PrincipalId,
    bond: CoinCellId,
    reward: u128,
    commitment: Digest384,
    reveal_deadline: u64,
    resolution_deadline: u64,
}

impl ChallengeCommitmentV1 {
    pub const TYPE_TAG: u16 = 0x015F;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Digest384,
        duty: Digest384,
        challenger: PrincipalId,
        bond: CoinCellId,
        reward: u128,
        commitment: Digest384,
        reveal_deadline: u64,
        resolution_deadline: u64,
    ) -> Result<Self, EconomicsError> {
        if id == Digest384::ZERO
            || duty == Digest384::ZERO
            || challenger.digest() == &Digest384::ZERO
            || bond.digest() == &Digest384::ZERO
            || reward == 0
            || commitment == Digest384::ZERO
            || reveal_deadline == 0
            || reveal_deadline >= resolution_deadline
        {
            return Err(EconomicsError::InvalidChallenge);
        }
        Ok(Self {
            id,
            duty,
            challenger,
            bond,
            reward,
            commitment,
            reveal_deadline,
            resolution_deadline,
        })
    }

    pub fn reveal(
        self,
        evidence: Digest384,
        nonce: Digest384,
        height: u64,
    ) -> Result<ChallengeAssignment, EconomicsError> {
        if height > self.reveal_deadline
            || evidence == Digest384::ZERO
            || nonce == Digest384::ZERO
            || challenge_commitment(self.id, self.duty, self.challenger, evidence, nonce)
                != self.commitment
        {
            return Err(EconomicsError::InvalidChallengeReveal);
        }
        Ok(ChallengeAssignment {
            id: self.id,
            duty: self.duty,
            challenger: self.challenger,
            bond: self.bond,
            evidence,
            reward: self.reward,
            deadline: self.resolution_deadline,
            resolved: false,
        })
    }
}

impl CanonicalEncode for ChallengeCommitmentV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.id.encode(encoder)?;
        self.duty.encode(encoder)?;
        self.challenger.encode(encoder)?;
        self.bond.encode(encoder)?;
        self.reward.encode(encoder)?;
        self.commitment.encode(encoder)?;
        self.reveal_deadline.encode(encoder)?;
        self.resolution_deadline.encode(encoder)
    }
}

impl CanonicalDecode for ChallengeCommitmentV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            CoinCellId::decode(decoder)?,
            u128::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid challenge commitment"))
    }
}

impl CanonicalType for ChallengeCommitmentV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 5 + 16 + 8 * 2;
}

pub fn challenge_commitment(
    id: Digest384,
    duty: Digest384,
    challenger: PrincipalId,
    evidence: Digest384,
    nonce: Digest384,
) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-VERIFIER-CHALLENGE-COMMITMENT-V1");
    hasher.update(id.as_bytes());
    hasher.update(duty.as_bytes());
    hasher.update(challenger.digest().as_bytes());
    hasher.update(evidence.as_bytes());
    hasher.update(nonce.as_bytes());
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeQuote {
    pub base: u128,
    pub resource_units: u64,
    pub resource_price: u128,
    pub congestion_price: u128,
}

impl FeeQuote {
    pub fn total(self) -> Option<u128> {
        fee_total(self.base, self.resource_units, self.resource_price, self.congestion_price)
    }
}

pub const FINALITY_POOL_BPS: u16 = 7_000;
pub const AVAILABILITY_POOL_BPS: u16 = 1_500;
pub const AUDIT_POOL_BPS: u16 = 1_000;
pub const PUBLIC_GOODS_POOL_BPS: u16 = 500;
pub const USER_SLASH_BPS: u16 = 4_000;
pub const SECURITY_SLASH_BPS: u16 = 4_000;
pub const CHALLENGER_SLASH_BPS: u16 = 2_000;
pub const MAX_AUDIT_VERIFIERS: usize = 4_096;

/// Selects one auditor without modulo bias. Candidate ordering is part of the
/// consensus input and must already be canonical; callers cannot gain an
/// advantage by permuting or duplicating identities.
pub fn select_auditor(
    finalized_randomness: Digest384,
    target: Digest384,
    eligible: &[PrincipalId],
) -> Result<PrincipalId, EconomicsError> {
    if finalized_randomness == Digest384::ZERO
        || target == Digest384::ZERO
        || eligible.is_empty()
        || eligible.len() > MAX_AUDIT_VERIFIERS
        || eligible.iter().any(|candidate| candidate.digest() == &Digest384::ZERO)
        || eligible.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(EconomicsError::InvalidAuditSet);
    }
    let count = u64::try_from(eligible.len()).map_err(|_| EconomicsError::InvalidAuditSet)?;
    let acceptance_zone = u64::MAX - (u64::MAX % count);
    for counter in 0..=u64::MAX {
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-RANDOM-AUDIT-ASSIGNMENT-V1");
        hasher.update(finalized_randomness.as_bytes());
        hasher.update(target.as_bytes());
        hasher.update(&counter.to_be_bytes());
        let mut sample = [0_u8; 8];
        hasher.finalize_xof().read(&mut sample);
        let sample = u64::from_be_bytes(sample);
        if sample < acceptance_zone {
            let index =
                usize::try_from(sample % count).map_err(|_| EconomicsError::InvalidAuditSet)?;
            return Ok(eligible[index]);
        }
    }
    Err(EconomicsError::InvalidAuditSet)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityPoolAllocation {
    pub finality: u128,
    pub availability: u128,
    pub audit: u128,
    pub public_goods: u128,
}
impl SecurityPoolAllocation {
    pub fn split(amount: u128) -> Option<Self> {
        let finality = amount.checked_mul(FINALITY_POOL_BPS as u128)?.checked_div(10_000)?;
        let availability =
            amount.checked_mul(AVAILABILITY_POOL_BPS as u128)?.checked_div(10_000)?;
        let audit = amount.checked_mul(AUDIT_POOL_BPS as u128)?.checked_div(10_000)?;
        let public_goods =
            amount.checked_mul(PUBLIC_GOODS_POOL_BPS as u128)?.checked_div(10_000)?;
        Some(Self { finality, availability, audit, public_goods })
    }
    pub fn total(self) -> Option<u128> {
        self.finality
            .checked_add(self.availability)?
            .checked_add(self.audit)?
            .checked_add(self.public_goods)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlashSplit {
    pub user: u128,
    pub security_pool: u128,
    pub challenger: u128,
}
impl SlashSplit {
    pub fn split(amount: u128) -> Option<Self> {
        let user = amount.checked_mul(USER_SLASH_BPS as u128)?.checked_div(10_000);
        let security_pool = amount.checked_mul(SECURITY_SLASH_BPS as u128)?.checked_div(10_000);
        let challenger = amount.checked_mul(CHALLENGER_SLASH_BPS as u128)?.checked_div(10_000)?;
        Some(Self { user: user?, security_pool: security_pool?, challenger })
    }
    pub fn total(self) -> Option<u128> {
        self.user.checked_add(self.security_pool)?.checked_add(self.challenger)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeMarket {
    pub base_fee: u128,
    pub target_units: u64,
    pub max_change_bps: u16,
}
impl FeeMarket {
    pub fn new(base_fee: u128, target_units: u64, max_change_bps: u16) -> Option<Self> {
        (base_fee > 0 && target_units > 0 && max_change_bps <= 10_000).then_some(Self {
            base_fee,
            target_units,
            max_change_bps,
        })
    }
    pub fn next(self, used_units: u64) -> Option<Self> {
        let next =
            next_base_fee(self.base_fee, self.target_units, self.max_change_bps, used_units)?;
        Some(Self { base_fee: next, ..self })
    }
}

/// A prepaid resource-capacity reservation. The deposit is exactly the maximum
/// fee implied by the quote, so unused capacity can be refunded without an
/// operator-selected accounting rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityReservationV1 {
    id: Digest384,
    payer: PrincipalId,
    quote: FeeQuote,
    deposit: u128,
    expires_height: u64,
    settled: bool,
}

impl CapacityReservationV1 {
    pub const TYPE_TAG: u16 = 0x015D;

    pub fn new(
        id: Digest384,
        payer: PrincipalId,
        quote: FeeQuote,
        deposit: u128,
        expires_height: u64,
    ) -> Result<Self, EconomicsError> {
        let required = quote.total().ok_or(EconomicsError::InvalidCapacityReservation)?;
        if id == Digest384::ZERO
            || payer.digest() == &Digest384::ZERO
            || quote.resource_units == 0
            || quote.resource_price == 0
            || required == 0
            || deposit != required
            || expires_height == 0
        {
            return Err(EconomicsError::InvalidCapacityReservation);
        }
        Ok(Self { id, payer, quote, deposit, expires_height, settled: false })
    }

    pub const fn id(&self) -> Digest384 {
        self.id
    }

    pub const fn deposit(&self) -> u128 {
        self.deposit
    }

    pub const fn settled(&self) -> bool {
        self.settled
    }

    pub fn settle(
        &mut self,
        used_units: u64,
        height: u64,
    ) -> Result<CapacitySettlementV1, EconomicsError> {
        if self.settled {
            return Err(EconomicsError::AlreadySettled);
        }
        if height > self.expires_height {
            return Err(EconomicsError::Expired);
        }
        if used_units > self.quote.resource_units {
            return Err(EconomicsError::CapacityExceeded);
        }
        let charged = fee_total(
            self.quote.base,
            used_units,
            self.quote.resource_price,
            self.quote.congestion_price,
        )
        .ok_or(EconomicsError::InvalidCapacityReservation)?;
        let refund =
            self.deposit.checked_sub(charged).ok_or(EconomicsError::InvalidCapacityReservation)?;
        self.settled = true;
        Ok(CapacitySettlementV1 {
            reservation: self.id,
            payer: self.payer,
            used_units,
            deposit: self.deposit,
            charged,
            refund,
            settled_height: height,
        })
    }
}

impl CanonicalEncode for CapacityReservationV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.id.encode(encoder)?;
        self.payer.encode(encoder)?;
        self.quote.base.encode(encoder)?;
        self.quote.resource_units.encode(encoder)?;
        self.quote.resource_price.encode(encoder)?;
        self.quote.congestion_price.encode(encoder)?;
        self.deposit.encode(encoder)?;
        self.expires_height.encode(encoder)?;
        self.settled.encode(encoder)
    }
}

impl CanonicalDecode for CapacityReservationV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let id = Digest384::decode(decoder)?;
        let payer = PrincipalId::decode(decoder)?;
        let quote = FeeQuote {
            base: u128::decode(decoder)?,
            resource_units: u64::decode(decoder)?,
            resource_price: u128::decode(decoder)?,
            congestion_price: u128::decode(decoder)?,
        };
        let deposit = u128::decode(decoder)?;
        let expires_height = u64::decode(decoder)?;
        let settled = bool::decode(decoder)?;
        let mut reservation = Self::new(id, payer, quote, deposit, expires_height)
            .map_err(|_| DecodeError::InvalidValue("invalid capacity reservation"))?;
        reservation.settled = settled;
        Ok(reservation)
    }
}

impl CanonicalType for CapacityReservationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 2 + 16 * 4 + 8 * 2 + 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacitySettlementV1 {
    reservation: Digest384,
    payer: PrincipalId,
    used_units: u64,
    deposit: u128,
    charged: u128,
    refund: u128,
    settled_height: u64,
}

impl CapacitySettlementV1 {
    pub const TYPE_TAG: u16 = 0x015E;

    pub const fn charged(self) -> u128 {
        self.charged
    }

    pub const fn refund(self) -> u128 {
        self.refund
    }
}

impl CanonicalEncode for CapacitySettlementV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.reservation.encode(encoder)?;
        self.payer.encode(encoder)?;
        self.used_units.encode(encoder)?;
        self.deposit.encode(encoder)?;
        self.charged.encode(encoder)?;
        self.refund.encode(encoder)?;
        self.settled_height.encode(encoder)
    }
}

impl CanonicalDecode for CapacitySettlementV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            reservation: Digest384::decode(decoder)?,
            payer: PrincipalId::decode(decoder)?,
            used_units: u64::decode(decoder)?,
            deposit: u128::decode(decoder)?,
            charged: u128::decode(decoder)?,
            refund: u128::decode(decoder)?,
            settled_height: u64::decode(decoder)?,
        };
        if value.reservation == Digest384::ZERO
            || value.payer.digest() == &Digest384::ZERO
            || value.deposit == 0
            || value.settled_height == 0
            || value.charged.checked_add(value.refund) != Some(value.deposit)
        {
            return Err(DecodeError::InvalidValue("invalid capacity settlement"));
        }
        Ok(value)
    }
}

impl CanonicalType for CapacitySettlementV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 2 + 8 * 2 + 16 * 3;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EconomicsError {
    DuplicateAssignment,
    UnknownAssignment,
    WrongVerifier,
    Expired,
    AlreadySettled,
    EmptyEvidence,
    InvalidSlash,
    InvalidChallenge,
    InvalidChallengeReveal,
    InvalidAuditSet,
    InvalidCapacityReservation,
    CapacityExceeded,
}

pub fn assign_challenge(
    challenges: &mut Vec<ChallengeAssignment>,
    commitment: ChallengeCommitmentV1,
    evidence: Digest384,
    nonce: Digest384,
    height: u64,
) -> Result<(), EconomicsError> {
    let challenge = commitment.reveal(evidence, nonce, height)?;
    if challenges.iter().any(|c| c.id == challenge.id) {
        return Err(EconomicsError::DuplicateAssignment);
    }
    challenges.push(challenge);
    Ok(())
}

pub fn resolve_challenge(
    challenges: &mut [ChallengeAssignment],
    id: Digest384,
    challenger: PrincipalId,
    height: u64,
) -> Result<u128, EconomicsError> {
    let challenge =
        challenges.iter_mut().find(|c| c.id == id).ok_or(EconomicsError::UnknownAssignment)?;
    if challenge.challenger != challenger {
        return Err(EconomicsError::WrongVerifier);
    }
    if challenge.resolved {
        return Err(EconomicsError::AlreadySettled);
    }
    if height > challenge.deadline {
        return Err(EconomicsError::Expired);
    }
    challenge.resolved = true;
    Ok(challenge.reward)
}

pub fn settle_duty(
    assignments: &mut [DutyAssignment],
    receipt: &DutyReceipt,
    verifier: PrincipalId,
    fault: Option<ObjectiveFault>,
) -> Result<RewardSettlement, EconomicsError> {
    let assignment = assignments
        .iter_mut()
        .find(|a| a.id == receipt.assignment)
        .ok_or(EconomicsError::UnknownAssignment)?;
    if assignment.verifier != verifier {
        return Err(EconomicsError::WrongVerifier);
    }
    if assignment.settled {
        return Err(EconomicsError::AlreadySettled);
    }
    if receipt.evidence == Digest384::new([0; 48]) {
        return Err(EconomicsError::EmptyEvidence);
    }
    if receipt.height > assignment.deadline {
        return Err(EconomicsError::Expired);
    }
    let slash_amount = match fault {
        Some(f) if f.assignment != assignment.id || f.slash_amount > assignment.bond_amount => {
            return Err(EconomicsError::InvalidSlash);
        }
        Some(f) => f.slash_amount,
        None => 0,
    };
    assignment.settled = true;
    Ok(RewardSettlement {
        assignment: assignment.id,
        verifier,
        reward: assignment.reward,
        bond_return: assignment.bond_amount - slash_amount,
        slash_amount,
    })
}

pub fn register_assignment(
    assignments: &mut Vec<DutyAssignment>,
    assignment: DutyAssignment,
) -> Result<(), EconomicsError> {
    if assignments.iter().any(|a| a.id == assignment.id) {
        return Err(EconomicsError::DuplicateAssignment);
    }
    if assignment.reward == 0 || assignment.bond_amount == 0 || assignment.deadline == 0 {
        return Err(EconomicsError::InvalidSlash);
    }
    assignments.push(assignment);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use alloc::vec;
    fn id(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(id(byte))
    }
    fn assignment() -> DutyAssignment {
        DutyAssignment {
            id: id(1),
            verifier: principal(2),
            role: VerifierRole::Finality,
            target: id(3),
            bond: CoinCellId::new(id(4)),
            bond_amount: 100,
            reward: 7,
            deadline: 10,
            settled: false,
        }
    }

    #[test]
    fn fixed_reward_is_independent_of_bond_size() {
        let mut a = vec![assignment()];
        let result = settle_duty(
            &mut a,
            &DutyReceipt { assignment: id(1), evidence: id(9), height: 10 },
            principal(2),
            None,
        )
        .unwrap();
        assert_eq!(result.reward, 7);
        assert_eq!(result.bond_return, 100);
    }

    #[test]
    fn settlement_is_one_shot_and_slash_is_bounded() {
        let mut a = vec![assignment()];
        let result = settle_duty(
            &mut a,
            &DutyReceipt { assignment: id(1), evidence: id(9), height: 5 },
            principal(2),
            Some(ObjectiveFault { assignment: id(1), evidence: id(8), slash_amount: 30 }),
        )
        .unwrap();
        assert_eq!(result.bond_return, 70);
        assert_eq!(result.slash_amount, 30);
        assert_eq!(
            settle_duty(
                &mut a,
                &DutyReceipt { assignment: id(1), evidence: id(9), height: 5 },
                principal(2),
                None
            ),
            Err(EconomicsError::AlreadySettled)
        );
    }

    #[test]
    fn invalid_receipts_cannot_settle() {
        let mut a = vec![assignment()];
        assert_eq!(
            settle_duty(
                &mut a,
                &DutyReceipt { assignment: id(1), evidence: id(0), height: 1 },
                principal(2),
                None
            ),
            Err(EconomicsError::EmptyEvidence)
        );
        assert_eq!(
            settle_duty(
                &mut a,
                &DutyReceipt { assignment: id(1), evidence: id(9), height: 11 },
                principal(2),
                None
            ),
            Err(EconomicsError::Expired)
        );
        assert_eq!(
            register_assignment(&mut a, assignment()),
            Err(EconomicsError::DuplicateAssignment)
        );
    }

    #[test]
    fn challenge_is_one_shot_and_fee_quote_is_checked() {
        let mut challenges = Vec::new();
        let nonce = id(10);
        let challenge = ChallengeCommitmentV1::new(
            id(5),
            id(1),
            principal(8),
            CoinCellId::new(id(7)),
            9,
            challenge_commitment(id(5), id(1), principal(8), id(6), nonce),
            10,
            20,
        )
        .unwrap();
        assign_challenge(&mut challenges, challenge, id(6), nonce, 10).unwrap();
        assert_eq!(resolve_challenge(&mut challenges, id(5), principal(8), 20), Ok(9));
        assert_eq!(
            resolve_challenge(&mut challenges, id(5), principal(8), 20),
            Err(EconomicsError::AlreadySettled)
        );
        assert_eq!(
            FeeQuote { base: 3, resource_units: 4, resource_price: 5, congestion_price: 2 }.total(),
            Some(25)
        );
        assert_eq!(SecurityPoolAllocation::split(10_000).unwrap().total(), Some(10_000));
        assert_eq!(SlashSplit::split(10_000).unwrap().total(), Some(10_000));
        let market = FeeMarket::new(100, 10, 1_000).unwrap();
        assert!(market.next(20).unwrap().base_fee > market.base_fee);
        assert!(market.next(1).unwrap().base_fee < market.base_fee);
    }

    #[test]
    fn challenge_reveal_binds_challenger_duty_evidence_and_nonce() {
        let challenge_id = id(30);
        let duty = id(31);
        let challenger = principal(32);
        let evidence = id(33);
        let nonce = id(34);
        let sealed = ChallengeCommitmentV1::new(
            challenge_id,
            duty,
            challenger,
            CoinCellId::new(id(35)),
            9,
            challenge_commitment(challenge_id, duty, challenger, evidence, nonce),
            20,
            30,
        )
        .unwrap();
        assert_eq!(
            decode_envelope::<ChallengeCommitmentV1>(&encode_envelope(&sealed).unwrap()),
            Ok(sealed)
        );
        let revealed = sealed.reveal(evidence, nonce, 20).unwrap();
        assert_eq!(revealed.evidence, evidence);
        assert_eq!(revealed.deadline, 30);
        assert!(!revealed.resolved);
        assert_eq!(sealed.reveal(id(36), nonce, 20), Err(EconomicsError::InvalidChallengeReveal));
        assert_eq!(
            sealed.reveal(evidence, id(37), 20),
            Err(EconomicsError::InvalidChallengeReveal)
        );
        assert_eq!(sealed.reveal(evidence, nonce, 21), Err(EconomicsError::InvalidChallengeReveal));
    }

    #[test]
    fn copied_challenge_commitment_cannot_be_revealed_by_another_principal() {
        let challenge_id = id(40);
        let duty = id(41);
        let original = principal(42);
        let copier = principal(43);
        let evidence = id(44);
        let nonce = id(45);
        let copied = ChallengeCommitmentV1::new(
            challenge_id,
            duty,
            copier,
            CoinCellId::new(id(46)),
            7,
            challenge_commitment(challenge_id, duty, original, evidence, nonce),
            20,
            30,
        )
        .unwrap();
        assert_eq!(copied.reveal(evidence, nonce, 20), Err(EconomicsError::InvalidChallengeReveal));
    }

    #[test]
    fn audit_selection_is_deterministic_and_target_bound() {
        let eligible = vec![principal(10), principal(20), principal(30), principal(40)];
        let first = select_auditor(id(50), id(51), &eligible).unwrap();
        assert_eq!(select_auditor(id(50), id(51), &eligible), Ok(first));
        assert_ne!(
            (0_u8..32)
                .map(|offset| select_auditor(id(50), id(60 + offset), &eligible).unwrap())
                .collect::<Vec<_>>(),
            vec![first; 32]
        );
    }

    #[test]
    fn audit_selection_rejects_noncanonical_or_zero_inputs() {
        assert_eq!(select_auditor(id(50), id(51), &[]), Err(EconomicsError::InvalidAuditSet));
        assert_eq!(
            select_auditor(id(50), id(51), &[principal(20), principal(10)]),
            Err(EconomicsError::InvalidAuditSet)
        );
        assert_eq!(
            select_auditor(id(50), id(51), &[principal(10), principal(10)]),
            Err(EconomicsError::InvalidAuditSet)
        );
        assert_eq!(
            select_auditor(Digest384::ZERO, id(51), &[principal(10)]),
            Err(EconomicsError::InvalidAuditSet)
        );
        assert_eq!(
            select_auditor(id(50), Digest384::ZERO, &[principal(10)]),
            Err(EconomicsError::InvalidAuditSet)
        );
    }

    #[test]
    fn unused_capacity_is_refunded_exactly_and_settlement_is_one_shot() {
        let quote =
            FeeQuote { base: 10, resource_units: 100, resource_price: 2, congestion_price: 5 };
        let mut reservation =
            CapacityReservationV1::new(id(20), principal(21), quote, 215, 50).unwrap();
        assert_eq!(
            decode_envelope::<CapacityReservationV1>(&encode_envelope(&reservation).unwrap()),
            Ok(reservation)
        );
        let settlement = reservation.settle(40, 49).unwrap();
        assert_eq!(settlement.charged(), 95);
        assert_eq!(settlement.refund(), 120);
        assert_eq!(settlement.charged() + settlement.refund(), reservation.deposit());
        assert_eq!(
            decode_envelope::<CapacitySettlementV1>(&encode_envelope(&settlement).unwrap()),
            Ok(settlement)
        );
        assert!(reservation.settled());
        assert_eq!(reservation.settle(40, 49), Err(EconomicsError::AlreadySettled));
    }

    #[test]
    fn capacity_reservation_rejects_underfunding_overflow_expiry_and_overuse() {
        let quote =
            FeeQuote { base: 10, resource_units: 100, resource_price: 2, congestion_price: 5 };
        assert_eq!(
            CapacityReservationV1::new(id(20), principal(21), quote, 214, 50),
            Err(EconomicsError::InvalidCapacityReservation)
        );
        assert_eq!(
            CapacityReservationV1::new(
                id(20),
                principal(21),
                FeeQuote {
                    base: u128::MAX,
                    resource_units: 2,
                    resource_price: u128::MAX,
                    congestion_price: 1,
                },
                u128::MAX,
                50,
            ),
            Err(EconomicsError::InvalidCapacityReservation)
        );
        let mut expired =
            CapacityReservationV1::new(id(20), principal(21), quote, 215, 50).unwrap();
        assert_eq!(expired.settle(1, 51), Err(EconomicsError::Expired));
        assert!(!expired.settled());
        assert_eq!(expired.settle(101, 50), Err(EconomicsError::CapacityExceeded));
        assert!(!expired.settled());
    }
}
