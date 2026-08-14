use crate::AdapterError;

/// Durable phase the connector host must persist before/after each provider effect.
///
/// The crucial invariant is that an ambiguous create or confirm result is never retried blindly.
/// Recovery proceeds through Thunes' external-id lookup, which is specifically documented for
/// recovering transactions when the original response is unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ThunesAttemptPhase {
    PlannedCreate = 1,
    CreateInFlight = 2,
    CreateAmbiguous = 3,
    Created = 4,
    ConfirmInFlight = 5,
    ConfirmAmbiguous = 6,
    Confirmed = 7,
    Terminal = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    DispatchCreate,
    LookupByExternalId,
    DispatchConfirm,
    PollByExternalId,
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThunesRecoveryState {
    phase: ThunesAttemptPhase,
}

impl Default for ThunesRecoveryState {
    fn default() -> Self {
        Self { phase: ThunesAttemptPhase::PlannedCreate }
    }
}

impl ThunesRecoveryState {
    #[must_use]
    pub const fn phase(self) -> ThunesAttemptPhase {
        self.phase
    }

    /// Action allowed from the persisted phase. Hosts must persist the successor returned by
    /// `before_*` before performing the corresponding provider request.
    #[must_use]
    pub const fn action(self) -> RecoveryAction {
        match self.phase {
            ThunesAttemptPhase::PlannedCreate => RecoveryAction::DispatchCreate,
            ThunesAttemptPhase::CreateInFlight | ThunesAttemptPhase::CreateAmbiguous => {
                RecoveryAction::LookupByExternalId
            }
            ThunesAttemptPhase::Created => RecoveryAction::DispatchConfirm,
            ThunesAttemptPhase::ConfirmInFlight | ThunesAttemptPhase::ConfirmAmbiguous => {
                RecoveryAction::LookupByExternalId
            }
            ThunesAttemptPhase::Confirmed => RecoveryAction::PollByExternalId,
            ThunesAttemptPhase::Terminal => RecoveryAction::Stop,
        }
    }

    pub fn before_create(self) -> Result<Self, AdapterError> {
        if self.phase != ThunesAttemptPhase::PlannedCreate {
            return Err(AdapterError::InvalidRequest);
        }
        Ok(Self { phase: ThunesAttemptPhase::CreateInFlight })
    }

    pub fn create_response(self) -> Result<Self, AdapterError> {
        if self.phase != ThunesAttemptPhase::CreateInFlight {
            return Err(AdapterError::InvalidResponse);
        }
        Ok(Self { phase: ThunesAttemptPhase::Created })
    }

    pub fn create_transport_ambiguous(self) -> Result<Self, AdapterError> {
        if self.phase != ThunesAttemptPhase::CreateInFlight {
            return Err(AdapterError::InvalidResponse);
        }
        Ok(Self { phase: ThunesAttemptPhase::CreateAmbiguous })
    }

    /// A successful authenticated lookup proves that the create reached Thunes. A not-found
    /// lookup deliberately remains ambiguous: an operator retry policy may poll again, but this
    /// state machine never authorizes a second create dispatch.
    pub fn recover_created(self, found: bool) -> Result<Self, AdapterError> {
        if !matches!(
            self.phase,
            ThunesAttemptPhase::CreateInFlight | ThunesAttemptPhase::CreateAmbiguous
        ) {
            return Err(AdapterError::InvalidResponse);
        }
        Ok(if found {
            Self { phase: ThunesAttemptPhase::Created }
        } else {
            Self { phase: ThunesAttemptPhase::CreateAmbiguous }
        })
    }

    pub fn before_confirm(self) -> Result<Self, AdapterError> {
        if self.phase != ThunesAttemptPhase::Created {
            return Err(AdapterError::InvalidRequest);
        }
        Ok(Self { phase: ThunesAttemptPhase::ConfirmInFlight })
    }

    pub fn confirm_response(self) -> Result<Self, AdapterError> {
        if self.phase != ThunesAttemptPhase::ConfirmInFlight {
            return Err(AdapterError::InvalidResponse);
        }
        Ok(Self { phase: ThunesAttemptPhase::Confirmed })
    }

    pub fn confirm_transport_ambiguous(self) -> Result<Self, AdapterError> {
        if self.phase != ThunesAttemptPhase::ConfirmInFlight {
            return Err(AdapterError::InvalidResponse);
        }
        Ok(Self { phase: ThunesAttemptPhase::ConfirmAmbiguous })
    }

    /// Any authenticated lookup after an ambiguous confirm can establish whether the transaction
    /// advanced beyond CREATED. Callers pass `confirmed_or_later` from the normalized status class.
    pub fn recover_confirmed(self, confirmed_or_later: bool) -> Result<Self, AdapterError> {
        if !matches!(
            self.phase,
            ThunesAttemptPhase::ConfirmInFlight | ThunesAttemptPhase::ConfirmAmbiguous
        ) {
            return Err(AdapterError::InvalidResponse);
        }
        Ok(if confirmed_or_later {
            Self { phase: ThunesAttemptPhase::Confirmed }
        } else {
            Self { phase: ThunesAttemptPhase::ConfirmAmbiguous }
        })
    }

    #[must_use]
    pub const fn terminal(self) -> Self {
        Self { phase: ThunesAttemptPhase::Terminal }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambiguous_create_can_only_recover_by_lookup() {
        let state = ThunesRecoveryState::default()
            .before_create()
            .unwrap()
            .create_transport_ambiguous()
            .unwrap();
        assert_eq!(state.action(), RecoveryAction::LookupByExternalId);
        assert!(state.before_create().is_err());
        assert_eq!(state.recover_created(false).unwrap().action(), RecoveryAction::LookupByExternalId);
        assert_eq!(state.recover_created(true).unwrap().action(), RecoveryAction::DispatchConfirm);
    }

    #[test]
    fn ambiguous_confirm_never_dispatches_confirm_twice() {
        let state = ThunesRecoveryState::default()
            .before_create()
            .unwrap()
            .create_response()
            .unwrap()
            .before_confirm()
            .unwrap()
            .confirm_transport_ambiguous()
            .unwrap();
        assert_eq!(state.action(), RecoveryAction::LookupByExternalId);
        assert!(state.before_confirm().is_err());
        assert_eq!(state.recover_confirmed(true).unwrap().action(), RecoveryAction::PollByExternalId);
    }
}
