use activechain_protocol_types::{CoinCellId, Digest384, PrincipalId};
use alloc::vec::Vec;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RewardRedemption {
    pub settlement: Digest384,
    pub pool_owner: PrincipalId,
    pub pool_cell: CoinCellId,
    pub fee_reserve: CoinCellId,
    pub height: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeAssignment {
    pub id: Digest384,
    pub duty: Digest384,
    pub challenger: PrincipalId,
    pub bond: CoinCellId,
    pub reward: u128,
    pub deadline: u64,
    pub resolved: bool,
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
        self.base
            .checked_add((self.resource_units as u128).checked_mul(self.resource_price)?)
            .and_then(|v| v.checked_add(self.congestion_price))
    }
}

pub const FINALITY_POOL_BPS: u16 = 7_000;
pub const AVAILABILITY_POOL_BPS: u16 = 1_500;
pub const AUDIT_POOL_BPS: u16 = 1_000;
pub const PUBLIC_GOODS_POOL_BPS: u16 = 500;
pub const USER_SLASH_BPS: u16 = 4_000;
pub const SECURITY_SLASH_BPS: u16 = 4_000;
pub const CHALLENGER_SLASH_BPS: u16 = 2_000;

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
        let delta = self.base_fee.checked_mul(self.max_change_bps as u128)?.checked_div(10_000)?;
        let next = if used_units > self.target_units {
            self.base_fee.checked_add(delta)?
        } else if used_units < self.target_units {
            self.base_fee.saturating_sub(delta).max(1)
        } else {
            self.base_fee
        };
        Some(Self { base_fee: next, ..self })
    }
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
}

pub fn assign_challenge(
    challenges: &mut Vec<ChallengeAssignment>,
    challenge: ChallengeAssignment,
) -> Result<(), EconomicsError> {
    if challenge.reward == 0
        || challenge.deadline == 0
        || challenge.bond == CoinCellId::new(Digest384::new([0; 48]))
    {
        return Err(EconomicsError::InvalidChallenge);
    }
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
        let challenge = ChallengeAssignment {
            id: id(5),
            duty: id(1),
            challenger: principal(8),
            bond: CoinCellId::new(id(7)),
            reward: 9,
            deadline: 20,
            resolved: false,
        };
        assign_challenge(&mut challenges, challenge).unwrap();
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
}
