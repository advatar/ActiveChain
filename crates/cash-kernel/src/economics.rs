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
pub enum EconomicsError {
    DuplicateAssignment,
    UnknownAssignment,
    WrongVerifier,
    Expired,
    AlreadySettled,
    EmptyEvidence,
    InvalidSlash,
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
}
