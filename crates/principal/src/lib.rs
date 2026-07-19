#![no_std]
#![forbid(unsafe_code)]

//! Pure, deterministic principal lifecycle transitions.
//!
//! Cryptographic and policy verification produces a pre-verified authorization
//! binding. This crate checks that binding against the exact principal, policy,
//! sequence, command, and lifecycle state before creating an updated value.

use activechain_protocol_types::{
    Amount, Digest384, FreezeState, Height, Principal, PrincipalId, PrincipalKind, RecoveryRequest,
};

/// Inputs admitted when creating a principal anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrincipalGenesis {
    /// Stable identifier not derived from a controller key.
    pub principal_id: PrincipalId,
    /// Semantic principal category.
    pub principal_kind: PrincipalKind,
    /// Initial controller-policy commitment.
    pub controller_policy_hash: Digest384,
    /// Initial recovery-policy commitment.
    pub recovery_policy_hash: Digest384,
    /// Initial authenticator-set root.
    pub authenticator_set_root: Digest384,
    /// Privacy-preserving metadata commitment.
    pub metadata_commitment: Digest384,
    /// Endowment securing the principal anchor.
    pub anchor_deposit: Amount,
}

/// The policy class which produced a lifecycle authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAuthorityKind {
    /// The current controller policy permitted an ordinary control operation.
    Controller,
    /// The current recovery policy permitted a recovery operation.
    Recovery,
}

/// A state-root-bound authorization fact produced by the authorization kernel.
///
/// This value is a semantic input, not a signature or proof. Consensus callers
/// MUST create it only after authenticating the actor and evaluating the named
/// policy against the same state and sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleAuthorization {
    kind: LifecycleAuthorityKind,
    principal_id: PrincipalId,
    sequence: u64,
    policy_hash: Digest384,
}

impl LifecycleAuthorization {
    /// Binds a controller authorization result to one principal version.
    #[must_use]
    pub const fn controller(
        principal_id: PrincipalId,
        sequence: u64,
        policy_hash: Digest384,
    ) -> Self {
        Self { kind: LifecycleAuthorityKind::Controller, principal_id, sequence, policy_hash }
    }

    /// Binds a recovery authorization result to one principal version.
    #[must_use]
    pub const fn recovery(
        principal_id: PrincipalId,
        sequence: u64,
        policy_hash: Digest384,
    ) -> Self {
        Self { kind: LifecycleAuthorityKind::Recovery, principal_id, sequence, policy_hash }
    }
}

/// A principal lifecycle command after canonical transaction decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalCommand {
    /// Atomically replace controller policy and authenticator commitments.
    RotateController {
        /// Sequence the command expects to consume.
        expected_sequence: u64,
        /// Replacement controller-policy commitment.
        new_controller_policy_hash: Digest384,
        /// Replacement authenticator-set root.
        new_authenticator_set_root: Digest384,
    },
    /// Freeze ordinary controller operations.
    Freeze {
        /// Sequence the command expects to consume.
        expected_sequence: u64,
    },
    /// Enter recovery pending and create a challengeable recovery request.
    InitiateRecovery {
        /// Sequence the command expects to consume.
        expected_sequence: u64,
        /// Proposed replacement controller-policy commitment.
        proposed_controller_policy_hash: Digest384,
        /// Proposed replacement authenticator-set root.
        proposed_authenticator_set_root: Digest384,
        /// Commitment to policy-specific recovery evidence.
        recovery_evidence_commitment: Digest384,
        /// First height after the challenge period.
        challenge_deadline: Height,
        /// Bond escrowed by the initiator.
        recovery_bond: Amount,
    },
}

impl PrincipalCommand {
    const fn expected_sequence(self) -> u64 {
        match self {
            Self::RotateController { expected_sequence, .. }
            | Self::Freeze { expected_sequence }
            | Self::InitiateRecovery { expected_sequence, .. } => expected_sequence,
        }
    }

    const fn required_authority(self) -> LifecycleAuthorityKind {
        match self {
            Self::RotateController { .. } | Self::Freeze { .. } => {
                LifecycleAuthorityKind::Controller
            }
            Self::InitiateRecovery { .. } => LifecycleAuthorityKind::Recovery,
        }
    }
}

/// The atomic output of one successful lifecycle command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleOutput {
    principal: Principal,
    recovery_request: Option<RecoveryRequest>,
}

impl LifecycleOutput {
    /// Returns the updated principal.
    #[must_use]
    pub const fn principal(&self) -> Principal {
        self.principal
    }

    /// Returns the recovery request created by initiation, if any.
    #[must_use]
    pub const fn recovery_request(&self) -> Option<RecoveryRequest> {
        self.recovery_request
    }
}

/// Deterministic principal lifecycle failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// The genesis anchor deposit is below the protocol-version minimum.
    AnchorDepositBelowMinimum { minimum: Amount, actual: Amount },
    /// A block height predates the principal's most recent update.
    HeightRegression { last_updated_at: Height, attempted: Height },
    /// The command does not consume the current principal sequence.
    StaleSequence { expected: u64, actual: u64 },
    /// Incrementing the sequence would overflow.
    SequenceExhausted,
    /// The command requires an authorization fact but none was supplied.
    MissingAuthorization,
    /// The supplied authorization names a different principal.
    AuthorizationPrincipalMismatch,
    /// The supplied authorization binds a stale or future sequence.
    AuthorizationSequenceMismatch,
    /// Controller authority was supplied where recovery was required or vice versa.
    WrongAuthorityKind,
    /// The authorization is bound to a different policy commitment.
    AuthorizationPolicyMismatch,
    /// Ordinary controller actions are not available in the current state.
    ControllerOperationRequiresActivePrincipal,
    /// A second recovery cannot start while one is already pending.
    RecoveryAlreadyPending,
    /// The recovery challenge period is empty or inverted.
    InvalidRecoveryChallengeDeadline,
    /// Constructing the resulting principal violated an internal invariant.
    InvalidResultingPrincipal,
}

/// Creates the initial active, sequence-zero principal at `height`.
pub fn create_principal(
    genesis: PrincipalGenesis,
    height: Height,
    minimum_anchor_deposit: Amount,
) -> Result<Principal, LifecycleError> {
    if genesis.anchor_deposit < minimum_anchor_deposit {
        return Err(LifecycleError::AnchorDepositBelowMinimum {
            minimum: minimum_anchor_deposit,
            actual: genesis.anchor_deposit,
        });
    }
    Principal::new(
        genesis.principal_id,
        genesis.principal_kind,
        genesis.controller_policy_hash,
        genesis.recovery_policy_hash,
        genesis.authenticator_set_root,
        0,
        FreezeState::Active,
        genesis.metadata_commitment,
        genesis.anchor_deposit,
        height,
        height,
    )
    .map_err(|_| LifecycleError::InvalidResultingPrincipal)
}

/// Applies exactly one principal command without clocks, I/O, or ambient state.
pub fn apply_lifecycle_command(
    principal: &Principal,
    command: PrincipalCommand,
    authorization: Option<&LifecycleAuthorization>,
    height: Height,
) -> Result<LifecycleOutput, LifecycleError> {
    if height < principal.last_updated_at() {
        return Err(LifecycleError::HeightRegression {
            last_updated_at: principal.last_updated_at(),
            attempted: height,
        });
    }

    let expected_sequence = command.expected_sequence();
    if expected_sequence != principal.sequence() {
        return Err(LifecycleError::StaleSequence {
            expected: principal.sequence(),
            actual: expected_sequence,
        });
    }

    validate_state(principal, command)?;
    validate_authorization(principal, command, authorization)?;

    let next_sequence =
        principal.sequence().checked_add(1).ok_or(LifecycleError::SequenceExhausted)?;

    match command {
        PrincipalCommand::RotateController {
            new_controller_policy_hash,
            new_authenticator_set_root,
            ..
        } => {
            let updated = rebuild_principal(
                principal,
                new_controller_policy_hash,
                new_authenticator_set_root,
                next_sequence,
                FreezeState::Active,
                height,
            )?;
            Ok(LifecycleOutput { principal: updated, recovery_request: None })
        }
        PrincipalCommand::Freeze { .. } => {
            let updated = rebuild_principal(
                principal,
                principal.controller_policy_hash(),
                principal.authenticator_set_root(),
                next_sequence,
                FreezeState::Frozen,
                height,
            )?;
            Ok(LifecycleOutput { principal: updated, recovery_request: None })
        }
        PrincipalCommand::InitiateRecovery {
            proposed_controller_policy_hash,
            proposed_authenticator_set_root,
            recovery_evidence_commitment,
            challenge_deadline,
            recovery_bond,
            ..
        } => {
            let request = RecoveryRequest::new(
                principal.principal_id(),
                principal.sequence(),
                proposed_controller_policy_hash,
                proposed_authenticator_set_root,
                recovery_evidence_commitment,
                height,
                challenge_deadline,
                recovery_bond,
            )
            .map_err(|_| LifecycleError::InvalidRecoveryChallengeDeadline)?;
            let updated = rebuild_principal(
                principal,
                principal.controller_policy_hash(),
                principal.authenticator_set_root(),
                next_sequence,
                FreezeState::RecoveryPending,
                height,
            )?;
            Ok(LifecycleOutput { principal: updated, recovery_request: Some(request) })
        }
    }
}

fn validate_state(principal: &Principal, command: PrincipalCommand) -> Result<(), LifecycleError> {
    match command {
        PrincipalCommand::RotateController { .. } | PrincipalCommand::Freeze { .. } => {
            if principal.freeze_state() != FreezeState::Active {
                return Err(LifecycleError::ControllerOperationRequiresActivePrincipal);
            }
        }
        PrincipalCommand::InitiateRecovery { .. } => {
            if principal.freeze_state() == FreezeState::RecoveryPending {
                return Err(LifecycleError::RecoveryAlreadyPending);
            }
        }
    }
    Ok(())
}

fn validate_authorization(
    principal: &Principal,
    command: PrincipalCommand,
    authorization: Option<&LifecycleAuthorization>,
) -> Result<(), LifecycleError> {
    let authorization = authorization.ok_or(LifecycleError::MissingAuthorization)?;
    if authorization.principal_id != principal.principal_id() {
        return Err(LifecycleError::AuthorizationPrincipalMismatch);
    }
    if authorization.sequence != principal.sequence() {
        return Err(LifecycleError::AuthorizationSequenceMismatch);
    }

    let required_kind = command.required_authority();
    if authorization.kind != required_kind {
        return Err(LifecycleError::WrongAuthorityKind);
    }
    let required_policy = match required_kind {
        LifecycleAuthorityKind::Controller => principal.controller_policy_hash(),
        LifecycleAuthorityKind::Recovery => principal.recovery_policy_hash(),
    };
    if authorization.policy_hash != required_policy {
        return Err(LifecycleError::AuthorizationPolicyMismatch);
    }
    Ok(())
}

fn rebuild_principal(
    current: &Principal,
    controller_policy_hash: Digest384,
    authenticator_set_root: Digest384,
    sequence: u64,
    freeze_state: FreezeState,
    height: Height,
) -> Result<Principal, LifecycleError> {
    Principal::new(
        current.principal_id(),
        current.principal_kind(),
        controller_policy_hash,
        current.recovery_policy_hash(),
        authenticator_set_root,
        sequence,
        freeze_state,
        current.metadata_commitment(),
        current.anchor_deposit(),
        current.created_at(),
        height,
    )
    .map_err(|_| LifecycleError::InvalidResultingPrincipal)
}

#[cfg(test)]
mod tests {
    use activechain_protocol_types::{Digest384, FreezeState, PrincipalId, PrincipalKind};
    use proptest::prelude::*;

    use super::{
        LifecycleAuthorization, LifecycleError, PrincipalCommand, PrincipalGenesis,
        apply_lifecycle_command, create_principal,
    };

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn genesis() -> PrincipalGenesis {
        PrincipalGenesis {
            principal_id: PrincipalId::new(digest(1)),
            principal_kind: PrincipalKind::Human,
            controller_policy_hash: digest(2),
            recovery_policy_hash: digest(3),
            authenticator_set_root: digest(4),
            metadata_commitment: digest(5),
            anchor_deposit: 1_000,
        }
    }

    fn principal() -> activechain_protocol_types::Principal {
        create_principal(genesis(), 10, 500).expect("valid genesis")
    }

    fn controller_authorization(
        principal: &activechain_protocol_types::Principal,
    ) -> LifecycleAuthorization {
        LifecycleAuthorization::controller(
            principal.principal_id(),
            principal.sequence(),
            principal.controller_policy_hash(),
        )
    }

    fn recovery_authorization(
        principal: &activechain_protocol_types::Principal,
    ) -> LifecycleAuthorization {
        LifecycleAuthorization::recovery(
            principal.principal_id(),
            principal.sequence(),
            principal.recovery_policy_hash(),
        )
    }

    #[test]
    fn creation_fixes_sequence_state_and_height() {
        let principal = principal();
        assert_eq!(principal.sequence(), 0);
        assert_eq!(principal.freeze_state(), FreezeState::Active);
        assert_eq!(principal.created_at(), 10);
        assert_eq!(principal.last_updated_at(), 10);
    }

    #[test]
    fn creation_enforces_the_versioned_anchor_minimum() {
        assert_eq!(
            create_principal(genesis(), 10, 1_001),
            Err(LifecycleError::AnchorDepositBelowMinimum { minimum: 1_001, actual: 1_000 })
        );
    }

    #[test]
    fn rotation_requires_exact_controller_authority_and_sequence() {
        let principal = principal();
        let command = PrincipalCommand::RotateController {
            expected_sequence: 0,
            new_controller_policy_hash: digest(6),
            new_authenticator_set_root: digest(7),
        };
        assert_eq!(
            apply_lifecycle_command(&principal, command, None, 11),
            Err(LifecycleError::MissingAuthorization)
        );

        let stale = PrincipalCommand::RotateController {
            expected_sequence: 1,
            new_controller_policy_hash: digest(6),
            new_authenticator_set_root: digest(7),
        };
        assert_eq!(
            apply_lifecycle_command(
                &principal,
                stale,
                Some(&controller_authorization(&principal)),
                11,
            ),
            Err(LifecycleError::StaleSequence { expected: 0, actual: 1 })
        );

        let output = apply_lifecycle_command(
            &principal,
            command,
            Some(&controller_authorization(&principal)),
            11,
        )
        .expect("authorized rotation");
        let updated = output.principal();
        assert_eq!(output.recovery_request(), None);
        assert_eq!(updated.sequence(), 1);
        assert_eq!(updated.controller_policy_hash(), digest(6));
        assert_eq!(updated.authenticator_set_root(), digest(7));
    }

    #[test]
    fn authorization_is_bound_to_principal_sequence_kind_and_policy() {
        let principal = principal();
        let command = PrincipalCommand::RotateController {
            expected_sequence: 0,
            new_controller_policy_hash: digest(6),
            new_authenticator_set_root: digest(7),
        };

        let wrong_principal = LifecycleAuthorization::controller(
            PrincipalId::new(digest(99)),
            0,
            principal.controller_policy_hash(),
        );
        assert_eq!(
            apply_lifecycle_command(&principal, command, Some(&wrong_principal), 11),
            Err(LifecycleError::AuthorizationPrincipalMismatch)
        );

        let wrong_sequence = LifecycleAuthorization::controller(
            principal.principal_id(),
            1,
            principal.controller_policy_hash(),
        );
        assert_eq!(
            apply_lifecycle_command(&principal, command, Some(&wrong_sequence), 11),
            Err(LifecycleError::AuthorizationSequenceMismatch)
        );

        let wrong_kind = recovery_authorization(&principal);
        assert_eq!(
            apply_lifecycle_command(&principal, command, Some(&wrong_kind), 11),
            Err(LifecycleError::WrongAuthorityKind)
        );

        let wrong_policy =
            LifecycleAuthorization::controller(principal.principal_id(), 0, digest(99));
        assert_eq!(
            apply_lifecycle_command(&principal, command, Some(&wrong_policy), 11),
            Err(LifecycleError::AuthorizationPolicyMismatch)
        );
    }

    #[test]
    fn heights_and_sequences_never_wrap_or_regress() {
        let principal = principal();
        let command = PrincipalCommand::Freeze { expected_sequence: 0 };
        assert_eq!(
            apply_lifecycle_command(
                &principal,
                command,
                Some(&controller_authorization(&principal)),
                9,
            ),
            Err(LifecycleError::HeightRegression { last_updated_at: 10, attempted: 9 })
        );

        let exhausted = activechain_protocol_types::Principal::new(
            principal.principal_id(),
            principal.principal_kind(),
            principal.controller_policy_hash(),
            principal.recovery_policy_hash(),
            principal.authenticator_set_root(),
            u64::MAX,
            FreezeState::Active,
            principal.metadata_commitment(),
            principal.anchor_deposit(),
            principal.created_at(),
            principal.last_updated_at(),
        )
        .expect("maximum sequence is representable but not consumable");
        assert_eq!(
            apply_lifecycle_command(
                &exhausted,
                PrincipalCommand::Freeze { expected_sequence: u64::MAX },
                Some(&controller_authorization(&exhausted)),
                11,
            ),
            Err(LifecycleError::SequenceExhausted)
        );
    }

    #[test]
    fn freeze_blocks_controller_rotation_but_recovery_can_start() {
        let principal = principal();
        let freeze_output = apply_lifecycle_command(
            &principal,
            PrincipalCommand::Freeze { expected_sequence: 0 },
            Some(&controller_authorization(&principal)),
            11,
        )
        .expect("controller can freeze active principal");
        let frozen = freeze_output.principal();
        assert_eq!(freeze_output.recovery_request(), None);

        let rotation = PrincipalCommand::RotateController {
            expected_sequence: 1,
            new_controller_policy_hash: digest(6),
            new_authenticator_set_root: digest(7),
        };
        assert_eq!(
            apply_lifecycle_command(
                &frozen,
                rotation,
                Some(&controller_authorization(&frozen)),
                12,
            ),
            Err(LifecycleError::ControllerOperationRequiresActivePrincipal)
        );

        let recovery = PrincipalCommand::InitiateRecovery {
            expected_sequence: 1,
            proposed_controller_policy_hash: digest(8),
            proposed_authenticator_set_root: digest(9),
            recovery_evidence_commitment: digest(10),
            challenge_deadline: 20,
            recovery_bond: 100,
        };
        let recovery_output =
            apply_lifecycle_command(&frozen, recovery, Some(&recovery_authorization(&frozen)), 12)
                .expect("recovery policy can act while frozen");
        let pending = recovery_output.principal();
        let request = recovery_output.recovery_request().expect("recovery must produce a request");
        assert_eq!(pending.freeze_state(), FreezeState::RecoveryPending);
        assert_eq!(pending.sequence(), 2);
        assert_eq!(request.expected_sequence(), 1);

        let second_recovery = PrincipalCommand::InitiateRecovery {
            expected_sequence: 2,
            proposed_controller_policy_hash: digest(8),
            proposed_authenticator_set_root: digest(9),
            recovery_evidence_commitment: digest(10),
            challenge_deadline: 21,
            recovery_bond: 100,
        };
        assert_eq!(
            apply_lifecycle_command(
                &pending,
                second_recovery,
                Some(&recovery_authorization(&pending)),
                13,
            ),
            Err(LifecycleError::RecoveryAlreadyPending)
        );
    }

    proptest! {
        #[test]
        fn successful_rotation_consumes_exactly_one_sequence(sequence in 0_u64..u64::MAX) {
            let base = principal();
            let principal = activechain_protocol_types::Principal::new(
                base.principal_id(),
                base.principal_kind(),
                base.controller_policy_hash(),
                base.recovery_policy_hash(),
                base.authenticator_set_root(),
                sequence,
                FreezeState::Active,
                base.metadata_commitment(),
                base.anchor_deposit(),
                base.created_at(),
                base.last_updated_at(),
            ).expect("valid principal");
            let command = PrincipalCommand::RotateController {
                expected_sequence: sequence,
                new_controller_policy_hash: digest(6),
                new_authenticator_set_root: digest(7),
            };
            let output = apply_lifecycle_command(
                &principal,
                command,
                Some(&controller_authorization(&principal)),
                11,
            ).expect("authorized active rotation");
            let updated = output.principal();
            prop_assert_eq!(output.recovery_request(), None);
            prop_assert_eq!(updated.sequence(), sequence + 1);
            prop_assert_eq!(updated.principal_id(), principal.principal_id());
        }
    }
}
