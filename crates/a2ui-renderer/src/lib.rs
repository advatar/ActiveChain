#![forbid(unsafe_code)]

//! Presentation-only A2UI rendering over wallet-reconstructed approval facts.

use std::collections::BTreeMap;

use activechain_agent_interfaces::{
    A2UI_VERSION, A2uiActionV1, A2uiComponentV1, A2uiSurfaceV1, BindingV1, INTERFACE_VERSION,
};
use activechain_cash_kernel::FungibleCoinCell;
use activechain_principal::{LifecycleAuthorization, PrincipalCommand, apply_lifecycle_command};
use activechain_proposal_gateway::{ActionIntentV1, ActionKindV1};
use activechain_protocol_types::{
    FungibleAssetDefinition, FungibleAssetPolicyV1, FungibleControllerRotationV1,
    FungibleControllerStateV1, FungibleCorporateActionKind, FungibleCorporateActionRegistryV1,
    FungibleCorporateActionV1, FungibleExceptionalControlActionV1, FungibleExceptionalControlKind,
    FungibleExceptionalControlPolicyV1, FungibleHolderControlStateV1, FungibleIssuerApprovalV1,
    FungibleIssuerOperation, NonFungibleIssuerApprovalV1, NonFungibleMintManifestV1,
    NonFungibleSeriesV1, NonFungibleTokenRegistryV1, Principal, RecoveryRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const MAX_DISPLAY_TEXT_BYTES: usize = 512;
pub const MAX_AGENT_EXPLANATION_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenderError {
    InvalidCanonicalFacts,
    DeceptiveText,
    InvalidSurface,
    ActionMismatch,
}

/// Security-critical facts reconstructed by the native wallet, never supplied by A2UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferApprovalFacts {
    pub intent_commitment: String,
    pub asset: String,
    pub amount: String,
    pub recipient: String,
    pub network: String,
    pub maximum_fee: String,
    pub expires_at_height: u64,
}

impl TryFrom<&ActionIntentV1> for TransferApprovalFacts {
    type Error = RenderError;

    fn try_from(intent: &ActionIntentV1) -> Result<Self, Self::Error> {
        if intent.action != ActionKindV1::Transfer {
            return Err(RenderError::InvalidCanonicalFacts);
        }
        let network = String::from_utf8(intent.chain_id.clone())
            .map_err(|_| RenderError::InvalidCanonicalFacts)?;
        Ok(Self {
            intent_commitment: lower_hex(
                intent.commitment().map_err(|_| RenderError::InvalidCanonicalFacts)?.as_bytes(),
            ),
            asset: lower_hex(intent.resource.as_bytes()),
            amount: intent.amount.to_string(),
            recipient: lower_hex(intent.recipient.as_bytes()),
            network,
            maximum_fee: intent.maximum_fee.to_string(),
            expires_at_height: intent.expires_at_height,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultState {
    Submitted,
    Finalized,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferResultFacts {
    pub intent_commitment: String,
    pub transaction_id: String,
    pub state: ResultState,
    pub finalized_height: Option<u64>,
    pub receipt_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityGrantFacts {
    pub intent_commitment: String,
    pub agent_principal: String,
    pub capability_id: String,
    pub resource: String,
    pub budget: String,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentEnrollmentFacts {
    pub intent_commitment: String,
    pub agent_principal: String,
    pub capabilities: Vec<String>,
    pub budget: String,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialDisclosureFacts {
    pub intent_commitment: String,
    pub issuer: String,
    pub verifier: String,
    pub credential_type: String,
    pub disclosed_fields: Vec<String>,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobProofFacts {
    pub job_id: String,
    pub verifier: String,
    pub proof_commitment: String,
    pub status: String,
    pub finalized_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerOperationFacts {
    pub approval_commitment: String,
    pub asset: String,
    pub operation: String,
    pub amount: String,
    pub supply_before: String,
    pub supply_after: String,
    pub authority_set: String,
    pub policy_before: String,
    pub policy_after: String,
    pub effective_height: u64,
    pub expires_height: u64,
}

impl IssuerOperationFacts {
    pub fn from_approved_supply_operation(
        policy: &FungibleAssetPolicyV1,
        approval: &FungibleIssuerApprovalV1,
        finalized_height: u64,
    ) -> Result<Self, RenderError> {
        let next = match approval.operation() {
            FungibleIssuerOperation::Mint => {
                policy.apply_approved_mint(policy.issuer(), approval, finalized_height)
            }
            operation @ (FungibleIssuerOperation::Burn | FungibleIssuerOperation::Redemption) => {
                policy.apply_approved_burn(approval, operation, finalized_height)
            }
        }
        .map_err(|_| RenderError::InvalidCanonicalFacts)?;
        let operation = match approval.operation() {
            FungibleIssuerOperation::Mint => "Mint",
            FungibleIssuerOperation::Burn => "Burn",
            FungibleIssuerOperation::Redemption => "Redemption",
        };
        Ok(Self {
            approval_commitment: lower_hex(approval.approval_commitment().as_bytes()),
            asset: lower_hex(approval.asset_id().digest().as_bytes()),
            operation: operation.into(),
            amount: approval.amount().to_string(),
            supply_before: approval.supply_before().to_string(),
            supply_after: next.supply_issued().to_string(),
            authority_set: lower_hex(approval.authority_set().as_bytes()),
            policy_before: lower_hex(
                policy.commitment().map_err(|_| RenderError::InvalidCanonicalFacts)?.as_bytes(),
            ),
            policy_after: lower_hex(
                next.commitment().map_err(|_| RenderError::InvalidCanonicalFacts)?.as_bytes(),
            ),
            effective_height: approval.effective_height(),
            expires_height: approval.expires_height(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NftIssuerOperationFacts {
    pub approval_commitment: String,
    pub asset: String,
    pub issuer: String,
    pub authority_set: String,
    pub manifest_commitment: String,
    pub item_count: String,
    pub supply_before: String,
    pub supply_after: String,
    pub series_before: String,
    pub series_after: String,
    pub registry_before: String,
    pub registry_after: String,
    pub effective_height: u64,
    pub expires_height: u64,
}

impl NftIssuerOperationFacts {
    pub fn from_approved_mint(
        series: &NonFungibleSeriesV1,
        registry: &NonFungibleTokenRegistryV1,
        authority_set: activechain_protocol_types::Digest384,
        approval: &NonFungibleIssuerApprovalV1,
        manifest: &NonFungibleMintManifestV1,
        finalized_height: u64,
    ) -> Result<Self, RenderError> {
        let (next_series, next_registry, tokens) = registry
            .apply_approved_mint(
                series,
                series.issuer(),
                authority_set,
                approval,
                manifest,
                finalized_height,
            )
            .map_err(|_| RenderError::InvalidCanonicalFacts)?;
        if tokens.len() != manifest.item_count() {
            return Err(RenderError::InvalidCanonicalFacts);
        }
        Ok(Self {
            approval_commitment: lower_hex(approval.approval_commitment().as_bytes()),
            asset: lower_hex(approval.asset_id().digest().as_bytes()),
            issuer: lower_hex(approval.issuer().digest().as_bytes()),
            authority_set: lower_hex(approval.authority_set().as_bytes()),
            manifest_commitment: lower_hex(approval.manifest_commitment().as_bytes()),
            item_count: manifest.item_count().to_string(),
            supply_before: approval.minted_before().to_string(),
            supply_after: next_series.minted().to_string(),
            series_before: lower_hex(
                series.commitment().map_err(|_| RenderError::InvalidCanonicalFacts)?.as_bytes(),
            ),
            series_after: lower_hex(
                next_series
                    .commitment()
                    .map_err(|_| RenderError::InvalidCanonicalFacts)?
                    .as_bytes(),
            ),
            registry_before: lower_hex(
                registry.commitment().map_err(|_| RenderError::InvalidCanonicalFacts)?.as_bytes(),
            ),
            registry_after: lower_hex(
                next_registry
                    .commitment()
                    .map_err(|_| RenderError::InvalidCanonicalFacts)?
                    .as_bytes(),
            ),
            effective_height: approval.effective_height(),
            expires_height: approval.expires_height(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerRotationFacts {
    pub approval_commitment: String,
    pub asset: String,
    pub issuer: String,
    pub current_authority: String,
    pub replacement_authority: String,
    pub policy_before: String,
    pub policy_after: String,
    pub controller_before: String,
    pub controller_after: String,
    pub revision_before: u64,
    pub revision_after: u64,
    pub effective_height: u64,
    pub expires_height: u64,
}

impl ControllerRotationFacts {
    pub fn from_approved_rotation(
        policy: &FungibleAssetPolicyV1,
        state: &FungibleControllerStateV1,
        rotation: &FungibleControllerRotationV1,
        finalized_height: u64,
    ) -> Result<Self, RenderError> {
        let (next_policy, next_state) = state
            .apply_rotation(policy, rotation, finalized_height)
            .map_err(|_| RenderError::InvalidCanonicalFacts)?;
        Ok(Self {
            approval_commitment: lower_hex(rotation.approval_commitment().as_bytes()),
            asset: lower_hex(rotation.asset_id().digest().as_bytes()),
            issuer: lower_hex(rotation.issuer().digest().as_bytes()),
            current_authority: lower_hex(rotation.current_authority_set().as_bytes()),
            replacement_authority: lower_hex(rotation.replacement_authority_set().as_bytes()),
            policy_before: lower_hex(
                policy.commitment().map_err(|_| RenderError::InvalidCanonicalFacts)?.as_bytes(),
            ),
            policy_after: lower_hex(
                next_policy
                    .commitment()
                    .map_err(|_| RenderError::InvalidCanonicalFacts)?
                    .as_bytes(),
            ),
            controller_before: lower_hex(
                state.commitment().map_err(|_| RenderError::InvalidCanonicalFacts)?.as_bytes(),
            ),
            controller_after: lower_hex(
                next_state.commitment().map_err(|_| RenderError::InvalidCanonicalFacts)?.as_bytes(),
            ),
            revision_before: rotation.expected_revision(),
            revision_after: next_state.revision(),
            effective_height: rotation.effective_height(),
            expires_height: rotation.expires_height(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRecoveryInitiationFacts {
    pub approval_commitment: String,
    pub asset: String,
    pub issuer: String,
    pub current_authority: String,
    pub replacement_authority: String,
    pub proposed_controller_policy: String,
    pub recovery_policy: String,
    pub recovery_evidence: String,
    pub sequence_before: u64,
    pub sequence_after: u64,
    pub recovery_bond: u128,
    pub initiated_at: u64,
    pub challenge_deadline: u64,
    pub rotation_expires_height: u64,
}

impl IssuerRecoveryInitiationFacts {
    pub fn from_initiation(
        principal: &Principal,
        policy: &FungibleAssetPolicyV1,
        state: &FungibleControllerStateV1,
        request: &RecoveryRequest,
        rotation: &FungibleControllerRotationV1,
    ) -> Result<Self, RenderError> {
        if principal.principal_id() != policy.issuer()
            || principal.authenticator_set_root() != policy.authority_set()
        {
            return Err(RenderError::InvalidCanonicalFacts);
        }
        let authorization = LifecycleAuthorization::recovery(
            principal.principal_id(),
            principal.sequence(),
            principal.recovery_policy_hash(),
        );
        let output = apply_lifecycle_command(
            principal,
            PrincipalCommand::InitiateRecovery {
                expected_sequence: request.expected_sequence(),
                proposed_controller_policy_hash: request.proposed_controller_policy_hash(),
                proposed_authenticator_set_root: request.proposed_authenticator_set_root(),
                recovery_evidence_commitment: request.recovery_evidence_commitment(),
                challenge_deadline: request.challenge_deadline(),
                recovery_bond: request.recovery_bond(),
            },
            Some(&authorization),
            request.initiated_at(),
        )
        .map_err(|_| RenderError::InvalidCanonicalFacts)?;
        if output.recovery_request() != Some(*request)
            || rotation.replacement_authority_set() != request.proposed_authenticator_set_root()
            || rotation.effective_height() != request.challenge_deadline()
        {
            return Err(RenderError::InvalidCanonicalFacts);
        }
        state
            .apply_rotation(policy, rotation, request.challenge_deadline())
            .map_err(|_| RenderError::InvalidCanonicalFacts)?;
        Ok(Self {
            approval_commitment: lower_hex(rotation.approval_commitment().as_bytes()),
            asset: lower_hex(policy.asset_id().digest().as_bytes()),
            issuer: lower_hex(policy.issuer().digest().as_bytes()),
            current_authority: lower_hex(policy.authority_set().as_bytes()),
            replacement_authority: lower_hex(request.proposed_authenticator_set_root().as_bytes()),
            proposed_controller_policy: lower_hex(
                request.proposed_controller_policy_hash().as_bytes(),
            ),
            recovery_policy: lower_hex(principal.recovery_policy_hash().as_bytes()),
            recovery_evidence: lower_hex(request.recovery_evidence_commitment().as_bytes()),
            sequence_before: principal.sequence(),
            sequence_after: output.principal().sequence(),
            recovery_bond: request.recovery_bond(),
            initiated_at: request.initiated_at(),
            challenge_deadline: request.challenge_deadline(),
            rotation_expires_height: rotation.expires_height(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorporateActionFacts {
    pub action_id: String,
    pub asset: String,
    pub issuer: String,
    pub kind: String,
    pub approval_commitment: String,
    pub terms_commitment: String,
    pub registry_before: String,
    pub registry_after: String,
    pub record_height: u64,
    pub effective_height: u64,
    pub expires_height: u64,
    pub amount_per_unit: String,
    pub ratio: String,
}

impl CorporateActionFacts {
    pub fn from_approved_action(
        policy: &FungibleAssetPolicyV1,
        registry: &FungibleCorporateActionRegistryV1,
        action: &FungibleCorporateActionV1,
        finalized_height: u64,
    ) -> Result<Self, RenderError> {
        let registry_before = lower_hex(
            registry.commitment().map_err(|_| RenderError::InvalidCanonicalFacts)?.as_bytes(),
        );
        let mut next_registry = registry.clone();
        let action_id = next_registry
            .admit(
                action,
                policy.asset_id(),
                policy.commitment().map_err(|_| RenderError::InvalidCanonicalFacts)?,
                policy.authority_set(),
                finalized_height,
            )
            .map_err(|_| RenderError::InvalidCanonicalFacts)?;
        let registry_after = lower_hex(
            next_registry.commitment().map_err(|_| RenderError::InvalidCanonicalFacts)?.as_bytes(),
        );
        let kind = match action.kind() {
            FungibleCorporateActionKind::Distribution => "Distribution",
            FungibleCorporateActionKind::Split => "Split",
            FungibleCorporateActionKind::Consolidation => "Consolidation",
            FungibleCorporateActionKind::Coupon => "Coupon",
            FungibleCorporateActionKind::Maturity => "Maturity",
            FungibleCorporateActionKind::RecordDateVote => "Record-date vote",
            FungibleCorporateActionKind::RedemptionOffer => "Redemption offer",
        };
        Ok(Self {
            action_id: lower_hex(action_id.as_bytes()),
            asset: lower_hex(action.asset_id().digest().as_bytes()),
            issuer: lower_hex(action.issuer().digest().as_bytes()),
            kind: kind.into(),
            approval_commitment: lower_hex(action.approval_commitment().as_bytes()),
            terms_commitment: lower_hex(action.terms_commitment().as_bytes()),
            registry_before,
            registry_after,
            record_height: action.record_height(),
            effective_height: action.effective_height(),
            expires_height: action.expires_height(),
            amount_per_unit: action.amount_per_unit().to_string(),
            ratio: format!("{}:{}", action.ratio_numerator(), action.ratio_denominator()),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HolderControlFacts {
    pub approval_commitment: String,
    pub asset: String,
    pub holder: String,
    pub recipient: String,
    pub control_policy: String,
    pub authority_set: String,
    pub reason_commitment: String,
    pub action: String,
    pub amount: String,
    pub revision_before: u64,
    pub revision_after: u64,
    pub frozen_before: bool,
    pub frozen_after: bool,
    pub cell_owner_before: String,
    pub cell_owner_after: String,
    pub effective_height: u64,
    pub expires_height: u64,
}

impl HolderControlFacts {
    pub fn from_approved_action(
        definition: &FungibleAssetDefinition,
        policy: &FungibleExceptionalControlPolicyV1,
        state: &FungibleHolderControlStateV1,
        action: &FungibleExceptionalControlActionV1,
        cell: Option<FungibleCoinCell>,
        finalized_height: u64,
    ) -> Result<Self, RenderError> {
        let (next_state, cell_owner_before, cell_owner_after) = match action.kind() {
            FungibleExceptionalControlKind::Clawback => {
                let cell = cell.ok_or(RenderError::InvalidCanonicalFacts)?;
                let (next_cell, next_state) = cell
                    .apply_declared_clawback(definition, policy, state, action, finalized_height)
                    .map_err(|_| RenderError::InvalidCanonicalFacts)?;
                (
                    next_state,
                    lower_hex(cell.owner().digest().as_bytes()),
                    lower_hex(next_cell.owner().digest().as_bytes()),
                )
            }
            FungibleExceptionalControlKind::Freeze | FungibleExceptionalControlKind::Unfreeze => {
                if cell.is_some() {
                    return Err(RenderError::InvalidCanonicalFacts);
                }
                (
                    state
                        .apply(definition, policy, action, finalized_height)
                        .map_err(|_| RenderError::InvalidCanonicalFacts)?,
                    "No Coin Cell movement".into(),
                    "No Coin Cell movement".into(),
                )
            }
        };
        let action_name = match action.kind() {
            FungibleExceptionalControlKind::Freeze => "Freeze",
            FungibleExceptionalControlKind::Unfreeze => "Unfreeze",
            FungibleExceptionalControlKind::Clawback => "Clawback",
        };
        Ok(Self {
            approval_commitment: lower_hex(action.approval_commitment().as_bytes()),
            asset: lower_hex(action.asset_id().digest().as_bytes()),
            holder: lower_hex(action.holder().digest().as_bytes()),
            recipient: lower_hex(action.recipient().digest().as_bytes()),
            control_policy: lower_hex(action.control_policy_commitment().as_bytes()),
            authority_set: lower_hex(action.authority_set().as_bytes()),
            reason_commitment: lower_hex(action.reason_commitment().as_bytes()),
            action: action_name.into(),
            amount: action.amount().to_string(),
            revision_before: action.expected_revision(),
            revision_after: next_state.revision(),
            frozen_before: state.frozen(),
            frozen_after: next_state.frozen(),
            cell_owner_before,
            cell_owner_after,
            effective_height: action.effective_height(),
            expires_height: action.expires_height(),
        })
    }
}

pub trait NativeWalletApprovalDispatch {
    type Error;
    fn begin_authenticated_approval(&mut self, intent_commitment: &str) -> Result<(), Self::Error>;
    fn persist_rejection(&mut self, intent_commitment: &str) -> Result<(), Self::Error>;
}

pub fn dispatch_wallet_action<D: NativeWalletApprovalDispatch>(
    command: &WalletApprovalCommand,
    dispatcher: &mut D,
) -> Result<(), D::Error> {
    match command.decision {
        ApprovalDecision::Approve => {
            dispatcher.begin_authenticated_approval(&command.intent_commitment)
        }
        ApprovalDecision::Reject => dispatcher.persist_rejection(&command.intent_commitment),
        ApprovalDecision::OpenDetails => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Reject,
    OpenDetails,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletApprovalCommand {
    pub intent_commitment: String,
    pub decision: ApprovalDecision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFallback {
    pub title: String,
    pub verified_rows: Vec<(String, String)>,
    pub explanation_label: String,
    pub agent_explanation: String,
    pub warning: String,
    pub approve_label: String,
    pub reject_label: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RenderedApproval {
    pub surface: Option<A2uiSurfaceV1>,
    pub fallback: NativeFallback,
}

pub fn render_transfer_approval(
    facts: &TransferApprovalFacts,
    agent_explanation: &str,
) -> Result<RenderedApproval, RenderError> {
    validate_facts(facts)?;
    validate_display_text(agent_explanation, MAX_AGENT_EXPLANATION_BYTES)?;
    let fallback = native_fallback(facts, agent_explanation);
    let surface = transfer_surface(facts, agent_explanation);
    if surface.validate().is_err() {
        return Ok(RenderedApproval { surface: None, fallback });
    }
    Ok(RenderedApproval { surface: Some(surface), fallback })
}

pub fn authorize_action(
    surface: &A2uiSurfaceV1,
    expected_intent_commitment: &str,
    action_name: &str,
) -> Result<WalletApprovalCommand, RenderError> {
    surface.validate().map_err(|_| RenderError::InvalidSurface)?;
    if surface.intent_commitment != expected_intent_commitment {
        return Err(RenderError::ActionMismatch);
    }
    let decision = match action_name {
        "activechain.approve" => ApprovalDecision::Approve,
        "activechain.reject" => ApprovalDecision::Reject,
        "activechain.open_details" => ApprovalDecision::OpenDetails,
        _ => return Err(RenderError::ActionMismatch),
    };
    let bound = surface.components.iter().any(|component| {
        component.action.as_ref().is_some_and(|action| {
            action.name == action_name
                && action.context.get("intent_commitment").map(String::as_str)
                    == Some(expected_intent_commitment)
        })
    });
    if !bound {
        return Err(RenderError::ActionMismatch);
    }
    Ok(WalletApprovalCommand { intent_commitment: expected_intent_commitment.into(), decision })
}

pub fn render_transfer_result(
    facts: &TransferResultFacts,
) -> Result<RenderedApproval, RenderError> {
    require_commitment_text(&facts.intent_commitment)?;
    require_digest_text(&facts.transaction_id)?;
    if facts.state == ResultState::Finalized
        && (!facts.receipt_verified || facts.finalized_height.is_none_or(|height| height == 0))
    {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    let state = match facts.state {
        ResultState::Submitted => "Submitted",
        ResultState::Finalized => "Finalized",
        ResultState::Failed => "Failed",
    };
    let mut rows = vec![
        ("Transaction".into(), facts.transaction_id.clone()),
        ("Status".into(), state.into()),
        (
            "Receipt verification".into(),
            if facts.receipt_verified { "Verified" } else { "Pending" }.into(),
        ),
    ];
    if let Some(height) = facts.finalized_height {
        rows.push(("Finalized height".into(), height.to_string()));
    }
    render_fact_surface(
        "activechain.transfer_result.v1",
        "Transfer result",
        &facts.intent_commitment,
        &rows,
        None,
        false,
    )
}

pub fn render_capability_grant(
    facts: &CapabilityGrantFacts,
    explanation: &str,
) -> Result<RenderedApproval, RenderError> {
    validate_approval_fields(
        &facts.intent_commitment,
        facts.expires_at_height,
        &[&facts.agent_principal, &facts.capability_id, &facts.resource, &facts.budget],
    )?;
    render_fact_surface(
        "activechain.capability_grant.v1",
        "Review capability grant",
        &facts.intent_commitment,
        &[
            ("Agent".into(), facts.agent_principal.clone()),
            ("Capability".into(), facts.capability_id.clone()),
            ("Resource".into(), facts.resource.clone()),
            ("Budget".into(), facts.budget.clone()),
            ("Expiry".into(), facts.expires_at_height.to_string()),
        ],
        Some(explanation),
        true,
    )
}

pub fn render_agent_enrollment(
    facts: &AgentEnrollmentFacts,
    explanation: &str,
) -> Result<RenderedApproval, RenderError> {
    if facts.capabilities.is_empty() || facts.capabilities.len() > 32 {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    validate_approval_fields(
        &facts.intent_commitment,
        facts.expires_at_height,
        &[&facts.agent_principal, &facts.budget],
    )?;
    for capability in &facts.capabilities {
        validate_fact(capability)?;
    }
    render_fact_surface(
        "activechain.agent_enrollment.v1",
        "Review agent enrollment",
        &facts.intent_commitment,
        &[
            ("Agent".into(), facts.agent_principal.clone()),
            ("Capabilities".into(), facts.capabilities.join(", ")),
            ("Budget".into(), facts.budget.clone()),
            ("Expiry".into(), facts.expires_at_height.to_string()),
        ],
        Some(explanation),
        true,
    )
}

pub fn render_credential_disclosure(
    facts: &CredentialDisclosureFacts,
    explanation: &str,
) -> Result<RenderedApproval, RenderError> {
    if facts.disclosed_fields.is_empty() || facts.disclosed_fields.len() > 32 {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    validate_approval_fields(
        &facts.intent_commitment,
        facts.expires_at_height,
        &[&facts.issuer, &facts.verifier, &facts.credential_type],
    )?;
    for field in &facts.disclosed_fields {
        validate_fact(field)?;
    }
    render_fact_surface(
        "activechain.credential_disclosure.v1",
        "Review credential disclosure",
        &facts.intent_commitment,
        &[
            ("Credential".into(), facts.credential_type.clone()),
            ("Issuer".into(), facts.issuer.clone()),
            ("Verifier".into(), facts.verifier.clone()),
            ("Disclosed fields".into(), facts.disclosed_fields.join(", ")),
            ("Expiry".into(), facts.expires_at_height.to_string()),
        ],
        Some(explanation),
        true,
    )
}

pub fn render_job_proof_status(facts: &JobProofFacts) -> Result<RenderedApproval, RenderError> {
    require_digest_text(&facts.job_id)?;
    require_digest_text(&facts.proof_commitment)?;
    if facts.finalized_height == 0 {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    validate_fact(&facts.verifier)?;
    validate_fact(&facts.status)?;
    render_fact_surface(
        "activechain.job_proof_status.v1",
        "Job proof status",
        &facts.proof_commitment,
        &[
            ("Job".into(), facts.job_id.clone()),
            ("Verifier".into(), facts.verifier.clone()),
            ("Status".into(), facts.status.clone()),
            ("Finalized height".into(), facts.finalized_height.to_string()),
        ],
        None,
        false,
    )
}

pub fn render_issuer_operation(
    facts: &IssuerOperationFacts,
    explanation: &str,
) -> Result<RenderedApproval, RenderError> {
    for digest in [
        &facts.approval_commitment,
        &facts.asset,
        &facts.authority_set,
        &facts.policy_before,
        &facts.policy_after,
    ] {
        require_digest_text(digest)?;
    }
    if facts.effective_height >= facts.expires_height
        || facts.amount.parse::<u128>().is_err()
        || facts.supply_before.parse::<u128>().is_err()
        || facts.supply_after.parse::<u128>().is_err()
    {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    render_fact_surface(
        "activechain.issuer_operation.v1",
        "Review issuer operation",
        &facts.approval_commitment,
        &[
            ("Asset ID".into(), facts.asset.clone()),
            ("Operation".into(), facts.operation.clone()),
            ("Amount".into(), facts.amount.clone()),
            ("Supply before".into(), facts.supply_before.clone()),
            ("Supply after".into(), facts.supply_after.clone()),
            ("Authority set".into(), facts.authority_set.clone()),
            ("Policy before".into(), facts.policy_before.clone()),
            ("Policy after".into(), facts.policy_after.clone()),
            ("Effective height".into(), facts.effective_height.to_string()),
            ("Expiry height".into(), facts.expires_height.to_string()),
        ],
        Some(explanation),
        true,
    )
}

/// What a reserve attestation supports, as a surface may state it.
///
/// A closed set with no "verified" member, and that absence is the design.
/// Anchoring an attestation establishes that a statement existed and has not
/// changed; it establishes nothing about reserves. A caller cannot render a
/// verification claim here because there is no value that means one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveClaimState {
    /// No attestation covers this moment.
    Uncovered,
    /// The attestation has lapsed.
    Expired,
    /// Supply now exceeds the figure the attestor examined.
    ClaimExceeded,
    /// An attestation covers this moment and figure.
    Attested,
}

impl ReserveClaimState {
    const fn label(self) -> &'static str {
        match self {
            Self::Uncovered => "No attestation covers this",
            Self::Expired => "Attestation expired",
            Self::ClaimExceeded => "Supply exceeds the attested figure",
            Self::Attested => "Attested",
        }
    }
}

/// Facts about a reserve attestation, reconstructed by the wallet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveClaimFacts {
    pub attestation_commitment: String,
    pub asset: String,
    pub attestor: String,
    pub state: ReserveClaimState,
    pub claimed_against: String,
    pub supply: String,
    /// Whether the issuer attested to its own reserves. Rendered always, not
    /// only when true, so its absence is a statement rather than a gap.
    pub self_attested: bool,
    pub expires: u64,
}

/// The caveat every reserve surface carries, which no caller can replace.
///
/// It is a fixed row rather than part of the agent's explanation because the
/// explanation is untrusted text: a surface that let the caller word this could
/// let it be worded away.
pub const RESERVE_ANCHOR_CAVEAT: &str = "An anchored attestation establishes who stated what, when, and that it has not changed. \
     It does not establish that the reserves exist.";

/// Renders a reserve attestation without asserting the reserves were checked.
///
/// # Errors
/// Refuses malformed digests, unparsable figures, and deceptive display text.
pub fn render_reserve_claim(
    facts: &ReserveClaimFacts,
    agent_explanation: &str,
) -> Result<RenderedApproval, RenderError> {
    for digest in [&facts.attestation_commitment, &facts.asset, &facts.attestor] {
        require_digest_text(digest)?;
    }
    if facts.claimed_against.parse::<u128>().is_err() || facts.supply.parse::<u128>().is_err() {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    render_fact_surface(
        "activechain.reserve_claim.v1",
        "Reserve attestation",
        &facts.attestation_commitment,
        &[
            ("Asset ID".into(), facts.asset.clone()),
            ("State".into(), facts.state.label().into()),
            ("Attestor".into(), facts.attestor.clone()),
            (
                "Attested by the issuer itself".into(),
                if facts.self_attested { "yes" } else { "no" }.into(),
            ),
            ("Figure attested against".into(), facts.claimed_against.clone()),
            ("Supply now".into(), facts.supply.clone()),
            ("Expires".into(), facts.expires.to_string()),
            ("What this establishes".into(), RESERVE_ANCHOR_CAVEAT.into()),
        ],
        Some(agent_explanation),
        false,
    )
}

pub fn render_nft_issuer_operation(
    facts: &NftIssuerOperationFacts,
    explanation: &str,
) -> Result<RenderedApproval, RenderError> {
    for digest in [
        &facts.approval_commitment,
        &facts.asset,
        &facts.issuer,
        &facts.authority_set,
        &facts.manifest_commitment,
        &facts.series_before,
        &facts.series_after,
        &facts.registry_before,
        &facts.registry_after,
    ] {
        require_digest_text(digest)?;
    }
    if facts.effective_height >= facts.expires_height
        || facts.item_count.parse::<u64>().ok().filter(|count| *count > 0).is_none()
        || facts.supply_before.parse::<u64>().is_err()
        || facts.supply_after.parse::<u64>().is_err()
    {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    render_fact_surface(
        "activechain.nft_issuer_operation.v1",
        "Review NFT mint operation",
        &facts.approval_commitment,
        &[
            ("Asset ID".into(), facts.asset.clone()),
            ("Issuer".into(), facts.issuer.clone()),
            ("Authority set".into(), facts.authority_set.clone()),
            ("Manifest".into(), facts.manifest_commitment.clone()),
            ("Token count".into(), facts.item_count.clone()),
            ("Supply before".into(), facts.supply_before.clone()),
            ("Supply after".into(), facts.supply_after.clone()),
            ("Series before".into(), facts.series_before.clone()),
            ("Series after".into(), facts.series_after.clone()),
            ("Registry before".into(), facts.registry_before.clone()),
            ("Registry after".into(), facts.registry_after.clone()),
            ("Effective height".into(), facts.effective_height.to_string()),
            ("Expiry height".into(), facts.expires_height.to_string()),
        ],
        Some(explanation),
        true,
    )
}

pub fn render_controller_rotation(
    facts: &ControllerRotationFacts,
    explanation: &str,
) -> Result<RenderedApproval, RenderError> {
    for digest in [
        &facts.approval_commitment,
        &facts.asset,
        &facts.issuer,
        &facts.current_authority,
        &facts.replacement_authority,
        &facts.policy_before,
        &facts.policy_after,
        &facts.controller_before,
        &facts.controller_after,
    ] {
        require_digest_text(digest)?;
    }
    if facts.current_authority == facts.replacement_authority
        || facts.revision_before.checked_add(1) != Some(facts.revision_after)
        || facts.effective_height >= facts.expires_height
    {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    render_fact_surface(
        "activechain.controller_rotation.v1",
        "Review controller rotation",
        &facts.approval_commitment,
        &[
            ("Asset ID".into(), facts.asset.clone()),
            ("Issuer".into(), facts.issuer.clone()),
            ("Current authority".into(), facts.current_authority.clone()),
            ("Replacement authority".into(), facts.replacement_authority.clone()),
            ("Policy before".into(), facts.policy_before.clone()),
            ("Policy after".into(), facts.policy_after.clone()),
            ("Controller state before".into(), facts.controller_before.clone()),
            ("Controller state after".into(), facts.controller_after.clone()),
            ("Revision before".into(), facts.revision_before.to_string()),
            ("Revision after".into(), facts.revision_after.to_string()),
            ("Effective height".into(), facts.effective_height.to_string()),
            ("Expiry height".into(), facts.expires_height.to_string()),
        ],
        Some(explanation),
        true,
    )
}

pub fn render_issuer_recovery_initiation(
    facts: &IssuerRecoveryInitiationFacts,
    explanation: &str,
) -> Result<RenderedApproval, RenderError> {
    for digest in [
        &facts.approval_commitment,
        &facts.asset,
        &facts.issuer,
        &facts.current_authority,
        &facts.replacement_authority,
        &facts.proposed_controller_policy,
        &facts.recovery_policy,
        &facts.recovery_evidence,
    ] {
        require_digest_text(digest)?;
    }
    if facts.current_authority == facts.replacement_authority
        || facts.sequence_before.checked_add(1) != Some(facts.sequence_after)
        || facts.recovery_bond == 0
        || facts.initiated_at >= facts.challenge_deadline
        || facts.challenge_deadline >= facts.rotation_expires_height
    {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    render_fact_surface(
        "activechain.issuer_recovery_initiation.v1",
        "Review issuer recovery initiation",
        &facts.approval_commitment,
        &[
            ("Asset ID".into(), facts.asset.clone()),
            ("Issuer principal".into(), facts.issuer.clone()),
            ("Current authority".into(), facts.current_authority.clone()),
            ("Proposed authority".into(), facts.replacement_authority.clone()),
            ("Proposed controller policy".into(), facts.proposed_controller_policy.clone()),
            ("Recovery policy".into(), facts.recovery_policy.clone()),
            ("Recovery evidence".into(), facts.recovery_evidence.clone()),
            ("Sequence before".into(), facts.sequence_before.to_string()),
            ("Sequence after initiation".into(), facts.sequence_after.to_string()),
            ("Recovery bond".into(), facts.recovery_bond.to_string()),
            ("Initiated at".into(), facts.initiated_at.to_string()),
            ("Challenge deadline".into(), facts.challenge_deadline.to_string()),
            ("Rotation expiry".into(), facts.rotation_expires_height.to_string()),
            ("Recovery status".into(), "Pending challenge period; not completed".into()),
        ],
        Some(explanation),
        true,
    )
}

pub fn render_corporate_action(
    facts: &CorporateActionFacts,
    explanation: &str,
) -> Result<RenderedApproval, RenderError> {
    for digest in [
        &facts.action_id,
        &facts.asset,
        &facts.issuer,
        &facts.approval_commitment,
        &facts.terms_commitment,
        &facts.registry_before,
        &facts.registry_after,
    ] {
        require_digest_text(digest)?;
    }
    if facts.registry_before == facts.registry_after
        || facts.record_height > facts.effective_height
        || facts.effective_height >= facts.expires_height
        || facts.amount_per_unit.parse::<u128>().is_err()
        || !matches!(facts.ratio.split_once(':'), Some((left, right)) if left.parse::<u128>().is_ok() && right.parse::<u128>().is_ok())
    {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    render_fact_surface(
        "activechain.corporate_action.v1",
        "Review corporate action",
        &facts.action_id,
        &[
            ("Asset ID".into(), facts.asset.clone()),
            ("Issuer".into(), facts.issuer.clone()),
            ("Action".into(), facts.kind.clone()),
            ("Approval".into(), facts.approval_commitment.clone()),
            ("Terms".into(), facts.terms_commitment.clone()),
            ("Registry before".into(), facts.registry_before.clone()),
            ("Registry after".into(), facts.registry_after.clone()),
            ("Record height".into(), facts.record_height.to_string()),
            ("Effective height".into(), facts.effective_height.to_string()),
            ("Expiry height".into(), facts.expires_height.to_string()),
            ("Amount per unit".into(), facts.amount_per_unit.clone()),
            ("Ratio".into(), facts.ratio.clone()),
        ],
        Some(explanation),
        true,
    )
}

pub fn render_holder_control(
    facts: &HolderControlFacts,
    explanation: &str,
) -> Result<RenderedApproval, RenderError> {
    for digest in [
        &facts.approval_commitment,
        &facts.asset,
        &facts.holder,
        &facts.recipient,
        &facts.control_policy,
        &facts.authority_set,
        &facts.reason_commitment,
    ] {
        require_digest_text(digest)?;
    }
    if facts.revision_before.checked_add(1) != Some(facts.revision_after)
        || facts.effective_height >= facts.expires_height
        || facts.amount.parse::<u128>().is_err()
        || !matches!(facts.action.as_str(), "Freeze" | "Unfreeze" | "Clawback")
    {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    render_fact_surface(
        "activechain.holder_control.v1",
        "Review exceptional holder control",
        &facts.approval_commitment,
        &[
            ("Asset ID".into(), facts.asset.clone()),
            ("Action".into(), facts.action.clone()),
            ("Holder".into(), facts.holder.clone()),
            ("Destination".into(), facts.recipient.clone()),
            ("Amount".into(), facts.amount.clone()),
            ("Declared policy".into(), facts.control_policy.clone()),
            ("Authority set".into(), facts.authority_set.clone()),
            ("Reason".into(), facts.reason_commitment.clone()),
            ("Revision before".into(), facts.revision_before.to_string()),
            ("Revision after".into(), facts.revision_after.to_string()),
            ("Frozen before".into(), facts.frozen_before.to_string()),
            ("Frozen after".into(), facts.frozen_after.to_string()),
            ("Coin Cell owner before".into(), facts.cell_owner_before.clone()),
            ("Coin Cell owner after".into(), facts.cell_owner_after.clone()),
            ("Effective height".into(), facts.effective_height.to_string()),
            ("Expiry height".into(), facts.expires_height.to_string()),
        ],
        Some(explanation),
        true,
    )
}

fn render_fact_surface(
    surface_id: &str,
    title: &str,
    commitment: &str,
    rows: &[(String, String)],
    explanation: Option<&str>,
    actions: bool,
) -> Result<RenderedApproval, RenderError> {
    require_commitment_text(commitment)?;
    validate_display_text(title, MAX_DISPLAY_TEXT_BYTES)?;
    if rows.is_empty() || rows.len() > 16 {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    for (label, value) in rows {
        validate_fact(label)?;
        validate_fact(value)?;
    }
    if let Some(value) = explanation {
        validate_display_text(value, MAX_AGENT_EXPLANATION_BYTES)?;
    }
    let fallback = NativeFallback {
        title: title.into(),
        verified_rows: rows.to_vec(),
        explanation_label: "Agent explanation — unverified".into(),
        agent_explanation: explanation.unwrap_or("").into(),
        warning: "Generated UI is presentation-only; wallet verification remains authoritative."
            .into(),
        approve_label: if actions { "Approve in wallet".into() } else { String::new() },
        reject_label: if actions { "Reject".into() } else { String::new() },
    };
    let fact_ids: Vec<String> = (0..rows.len()).map(|index| format!("fact_{index}")).collect();
    let mut verified_children = vec!["title".to_owned()];
    verified_children.extend(fact_ids.iter().cloned());
    verified_children.push("warning".into());
    let mut body_children = vec!["verified_facts".to_owned()];
    if explanation.is_some() {
        body_children.push("agent_content".into());
    }
    if actions {
        body_children.push("action_column".into());
    }
    let mut components = vec![single_child("root", "Card", "body")];
    components.push(container_owned("body", "Column", &body_children));
    components.push(container_owned("verified_facts", "Column", &verified_children));
    components.push(text("title", "/view/title"));
    for (index, id) in fact_ids.iter().enumerate() {
        components.push(text(id, &format!("/view/facts/{index}")));
    }
    components.push(text("warning", "/view/warning"));
    if explanation.is_some() {
        components.push(container(
            "agent_content",
            "Column",
            &["agent_label", "agent_explanation"],
        ));
        components.push(text("agent_label", "/view/agent_label"));
        components.push(text("agent_explanation", "/view/agent_explanation"));
    }
    if actions {
        components.push(container("action_column", "Column", &["reject", "approve"]));
        components.push(button("reject", "reject_label", "activechain.reject", commitment));
        components.push(text("reject_label", "/view/reject_label"));
        components.push(button("approve", "approve_label", "activechain.approve", commitment));
        components.push(text("approve_label", "/view/approve_label"));
    }
    let surface = A2uiSurfaceV1 {
        version: A2UI_VERSION.into(),
        interface_version: INTERFACE_VERSION.into(),
        surface_id: surface_id.into(),
        root: "root".into(),
        intent_commitment: commitment.into(),
        components,
        data_model: json!({"view": {
            "title": title,
            "facts": rows.iter().map(|(label, value)| format!("{label}: {value}")).collect::<Vec<_>>(),
            "warning": "Verified facts are wallet-owned. Generated UI cannot sign or submit.",
            "agent_label": if explanation.is_some() { "Agent explanation — unverified" } else { "" },
            "agent_explanation": explanation.unwrap_or(""),
            "reject_label": if actions { "Reject" } else { "" },
            "approve_label": if actions { "Approve in wallet" } else { "" }
        }}),
    };
    if surface.validate().is_err() {
        return Ok(RenderedApproval { surface: None, fallback });
    }
    Ok(RenderedApproval { surface: Some(surface), fallback })
}

fn transfer_surface(facts: &TransferApprovalFacts, agent_explanation: &str) -> A2uiSurfaceV1 {
    let commitment = &facts.intent_commitment;
    A2uiSurfaceV1 {
        version: A2UI_VERSION.into(),
        interface_version: INTERFACE_VERSION.into(),
        surface_id: "activechain.transfer_review.v1".into(),
        root: "root".into(),
        intent_commitment: commitment.clone(),
        components: vec![
            single_child("root", "Card", "approval_body"),
            container(
                "approval_body",
                "Column",
                &["verified_facts", "agent_content", "action_column"],
            ),
            container(
                "verified_facts",
                "Column",
                &["title", "amount", "recipient", "network", "fee", "expiry", "warning"],
            ),
            text("title", "/approval/title"),
            text("amount", "/approval/verified/amount"),
            text("recipient", "/approval/verified/recipient"),
            text("network", "/approval/verified/network"),
            text("fee", "/approval/verified/maximum_fee"),
            text("expiry", "/approval/verified/expiry"),
            text("warning", "/approval/warning"),
            container("agent_content", "Column", &["agent_label", "agent_explanation"]),
            text("agent_label", "/approval/agent/label"),
            text("agent_explanation", "/approval/agent/explanation"),
            container("action_column", "Column", &["reject", "approve"]),
            button("reject", "reject_label", "activechain.reject", commitment),
            text("reject_label", "/approval/actions/reject"),
            button("approve", "approve_label", "activechain.approve", commitment),
            text("approve_label", "/approval/actions/approve"),
        ],
        data_model: json!({
            "approval": {
                "title": "Review transfer",
                "verified": {
                    "amount": format!("{} {}", facts.amount, facts.asset),
                    "recipient": format!("Recipient: {}", facts.recipient),
                    "network": format!("Network: {}", facts.network),
                    "maximum_fee": format!("Maximum fee: {}", facts.maximum_fee),
                    "expiry": format!("Expires at finalized height {}", facts.expires_at_height)
                },
                "warning": "Verify these wallet-reconstructed facts. The agent explanation below is untrusted.",
                "agent": { "label": "Agent explanation — unverified", "explanation": agent_explanation },
                "actions": { "reject": "Reject", "approve": "Approve in wallet" }
            }
        }),
    }
}

fn native_fallback(facts: &TransferApprovalFacts, explanation: &str) -> NativeFallback {
    NativeFallback {
        title: "Review transfer".into(),
        verified_rows: vec![
            ("Amount".into(), format!("{} {}", facts.amount, facts.asset)),
            ("Recipient".into(), facts.recipient.clone()),
            ("Network".into(), facts.network.clone()),
            ("Maximum fee".into(), facts.maximum_fee.clone()),
            ("Expiry".into(), facts.expires_at_height.to_string()),
        ],
        explanation_label: "Agent explanation — unverified".into(),
        agent_explanation: explanation.into(),
        warning: "A generated interface cannot approve, sign, or submit this transfer.".into(),
        approve_label: "Approve in wallet".into(),
        reject_label: "Reject".into(),
    }
}

fn validate_facts(facts: &TransferApprovalFacts) -> Result<(), RenderError> {
    if facts.intent_commitment.len() != 96
        || !facts.intent_commitment.bytes().all(|byte| byte.is_ascii_hexdigit())
        || facts.expires_at_height == 0
    {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    for value in [
        facts.asset.as_str(),
        facts.amount.as_str(),
        facts.recipient.as_str(),
        facts.network.as_str(),
        facts.maximum_fee.as_str(),
    ] {
        validate_display_text(value, MAX_DISPLAY_TEXT_BYTES)
            .map_err(|_| RenderError::InvalidCanonicalFacts)?;
    }
    Ok(())
}

fn validate_approval_fields(
    commitment: &str,
    expires_at_height: u64,
    values: &[&String],
) -> Result<(), RenderError> {
    require_commitment_text(commitment)?;
    if expires_at_height == 0 {
        return Err(RenderError::InvalidCanonicalFacts);
    }
    for value in values {
        validate_fact(value)?;
    }
    Ok(())
}

fn validate_fact(value: &str) -> Result<(), RenderError> {
    validate_display_text(value, MAX_DISPLAY_TEXT_BYTES)
        .map_err(|_| RenderError::InvalidCanonicalFacts)
}

fn require_commitment_text(value: &str) -> Result<(), RenderError> {
    require_digest_text(value)
}

fn require_digest_text(value: &str) -> Result<(), RenderError> {
    if value.len() != 96
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Err(RenderError::InvalidCanonicalFacts)
    } else {
        Ok(())
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_display_text(value: &str, maximum: usize) -> Result<(), RenderError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(is_deceptive_character) {
        Err(RenderError::DeceptiveText)
    } else {
        Ok(())
    }
}

fn is_deceptive_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        )
}

fn container(id: &str, component: &str, children: &[&str]) -> A2uiComponentV1 {
    A2uiComponentV1 {
        id: id.into(),
        component: component.into(),
        children: children.iter().map(|child| (*child).into()).collect(),
        child: None,
        text: None,
        action: None,
    }
}

fn container_owned(id: &str, component: &str, children: &[String]) -> A2uiComponentV1 {
    A2uiComponentV1 {
        id: id.into(),
        component: component.into(),
        children: children.to_vec(),
        child: None,
        text: None,
        action: None,
    }
}

fn single_child(id: &str, component: &str, child: &str) -> A2uiComponentV1 {
    A2uiComponentV1 {
        id: id.into(),
        component: component.into(),
        children: Vec::new(),
        child: Some(child.into()),
        text: None,
        action: None,
    }
}

fn text(id: &str, path: &str) -> A2uiComponentV1 {
    A2uiComponentV1 {
        id: id.into(),
        component: "Text".into(),
        children: Vec::new(),
        child: None,
        text: Some(BindingV1 { path: path.into() }),
        action: None,
    }
}

fn button(id: &str, child: &str, action_name: &str, commitment: &str) -> A2uiComponentV1 {
    let context = BTreeMap::from([("intent_commitment".into(), commitment.into())]);
    A2uiComponentV1 {
        id: id.into(),
        component: "Button".into(),
        children: Vec::new(),
        child: Some(child.into()),
        text: None,
        action: Some(A2uiActionV1 { name: action_name.into(), context }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_cash_kernel::CoinCellOrigin;
    use activechain_protocol_types::{
        AssetId, Digest384, FreezeState, FungibleAssetLifecycle, NonFungibleMintItemV1,
        PrincipalId, PrincipalKind, TransactionId,
    };

    fn facts() -> TransferApprovalFacts {
        TransferApprovalFacts {
            intent_commitment: "ab".repeat(48),
            asset: "AC EUR".into(),
            amount: "125.00".into(),
            recipient: "merchant.ke.001".into(),
            network: "ActiveChain testnet".into(),
            maximum_fee: "0.04 AC EUR".into(),
            expires_at_height: 42,
        }
    }

    #[test]
    fn renders_verified_facts_untrusted_explanation_and_wallet_owned_actions() {
        let rendered = render_transfer_approval(&facts(), "Pay the invoice").unwrap();
        let surface = rendered.surface.unwrap();
        assert_eq!(surface.data_model["approval"]["verified"]["amount"], "125.00 AC EUR");
        assert_eq!(
            surface.data_model["approval"]["agent"]["label"],
            "Agent explanation — unverified"
        );
        assert_eq!(surface.components.iter().filter(|item| item.action.is_some()).count(), 2);
        assert_eq!(rendered.fallback.approve_label, "Approve in wallet");
    }

    #[test]
    fn actions_only_translate_to_commitment_bound_wallet_commands() {
        let rendered = render_transfer_approval(&facts(), "Expected purchase").unwrap();
        let surface = rendered.surface.unwrap();
        let command =
            authorize_action(&surface, &facts().intent_commitment, "activechain.approve").unwrap();
        assert_eq!(command.decision, ApprovalDecision::Approve);
        assert!(authorize_action(&surface, &"cd".repeat(48), "activechain.approve").is_err());
        assert!(
            authorize_action(&surface, &facts().intent_commitment, "activechain.sign").is_err()
        );
    }

    #[test]
    fn rejects_bidi_controls_control_characters_and_oversized_explanations() {
        for explanation in
            ["pay \u{202e}001", "pay\nnow", &"x".repeat(MAX_AGENT_EXPLANATION_BYTES + 1)]
        {
            assert_eq!(
                render_transfer_approval(&facts(), explanation),
                Err(RenderError::DeceptiveText)
            );
        }
    }

    #[test]
    fn malformed_canonical_facts_never_reach_a_surface() {
        let mut invalid = facts();
        invalid.intent_commitment = "agent chosen".into();
        assert_eq!(
            render_transfer_approval(&invalid, "Looks fine"),
            Err(RenderError::InvalidCanonicalFacts)
        );
    }

    #[test]
    fn frozen_a2ui_updates_keep_structure_before_data_and_share_surface_identity() {
        let components: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testing/vectors/a2ui-transfer-review-components.json"
        ))
        .unwrap();
        let data: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testing/vectors/a2ui-transfer-review-datamodel.json"
        ))
        .unwrap();
        assert_eq!(components["version"], A2UI_VERSION);
        assert_eq!(data["version"], A2UI_VERSION);
        assert_eq!(
            components["updateComponents"]["surfaceId"],
            data["updateDataModel"]["surfaceId"]
        );
        assert_eq!(components["updateComponents"]["components"][0]["id"], "root");
    }

    #[test]
    fn transfer_facts_are_reconstructed_from_the_exact_canonical_proposal() {
        let intent = ActionIntentV1 {
            request_id: b"request-7".to_vec(),
            chain_id: b"activechain-devnet".to_vec(),
            wallet_id: b"wallet-primary".to_vec(),
            agent_principal: Digest384::new([1; 48]),
            capability_id: Digest384::new([2; 48]),
            request_nonce: b"nonce-7".to_vec(),
            action: ActionKindV1::Transfer,
            resource: Digest384::new([3; 48]),
            recipient: Digest384::new([4; 48]),
            amount: 125,
            maximum_fee: 4,
            expires_at_height: 42,
            replay_domain: Digest384::new([5; 48]),
        };
        let facts = TransferApprovalFacts::try_from(&intent).unwrap();
        assert_eq!(facts.asset, "03".repeat(48));
        assert_eq!(facts.recipient, "04".repeat(48));
        assert_eq!(facts.network, "activechain-devnet");
        assert_eq!(facts.amount, "125");
        assert_eq!(facts.intent_commitment, lower_hex(intent.commitment().unwrap().as_bytes()));
    }

    #[test]
    fn renders_every_initial_surface_with_wallet_owned_facts_and_safe_fallbacks() {
        let commitment = "ab".repeat(48);
        let result = render_transfer_result(&TransferResultFacts {
            intent_commitment: commitment.clone(),
            transaction_id: "cd".repeat(48),
            state: ResultState::Finalized,
            finalized_height: Some(99),
            receipt_verified: true,
        })
        .unwrap();
        assert!(result.surface.is_some());
        assert!(result.fallback.approve_label.is_empty());

        let grant = render_capability_grant(
            &CapabilityGrantFacts {
                intent_commitment: commitment.clone(),
                agent_principal: "agent-1".into(),
                capability_id: "transfer".into(),
                resource: "asset-1".into(),
                budget: "1000".into(),
                expires_at_height: 88,
            },
            "Automate payroll",
        )
        .unwrap();
        assert!(grant.surface.as_ref().unwrap().components.iter().any(|component| {
            component.action.as_ref().is_some_and(|action| action.name == "activechain.approve")
        }));
        assert!(
            render_agent_enrollment(
                &AgentEnrollmentFacts {
                    intent_commitment: commitment.clone(),
                    agent_principal: "agent-1".into(),
                    capabilities: vec!["read".into(), "transfer".into()],
                    budget: "1000".into(),
                    expires_at_height: 88,
                },
                "Install payroll agent"
            )
            .unwrap()
            .surface
            .is_some()
        );
        assert!(
            render_credential_disclosure(
                &CredentialDisclosureFacts {
                    intent_commitment: commitment,
                    issuer: "issuer-1".into(),
                    verifier: "verifier-1".into(),
                    credential_type: "age-over-18".into(),
                    disclosed_fields: vec!["age predicate".into()],
                    expires_at_height: 88,
                },
                "Enter regulated venue"
            )
            .unwrap()
            .surface
            .is_some()
        );
        assert!(
            render_job_proof_status(&JobProofFacts {
                job_id: "11".repeat(48),
                verifier: "verifier-1".into(),
                proof_commitment: "22".repeat(48),
                status: "verified".into(),
                finalized_height: 77,
            })
            .unwrap()
            .surface
            .is_some()
        );
    }

    #[test]
    fn finalized_receipts_and_generated_actions_fail_closed() {
        let commitment = "ab".repeat(48);
        assert_eq!(
            render_transfer_result(&TransferResultFacts {
                intent_commitment: commitment.clone(),
                transaction_id: "cd".repeat(48),
                state: ResultState::Finalized,
                finalized_height: Some(99),
                receipt_verified: false,
            }),
            Err(RenderError::InvalidCanonicalFacts)
        );
        let oversized = vec!["capability".to_owned(); 33];
        assert_eq!(
            render_agent_enrollment(
                &AgentEnrollmentFacts {
                    intent_commitment: commitment,
                    agent_principal: "agent".into(),
                    capabilities: oversized,
                    budget: "1".into(),
                    expires_at_height: 2,
                },
                "explanation"
            ),
            Err(RenderError::InvalidCanonicalFacts)
        );
    }

    #[derive(Default)]
    struct NativeDispatch {
        approved: Vec<String>,
        rejected: Vec<String>,
    }
    impl NativeWalletApprovalDispatch for NativeDispatch {
        type Error = ();
        fn begin_authenticated_approval(&mut self, commitment: &str) -> Result<(), Self::Error> {
            self.approved.push(commitment.into());
            Ok(())
        }
        fn persist_rejection(&mut self, commitment: &str) -> Result<(), Self::Error> {
            self.rejected.push(commitment.into());
            Ok(())
        }
    }

    #[test]
    fn only_an_authorized_commitment_bound_command_reaches_native_dispatch() {
        let rendered = render_transfer_approval(&facts(), "Expected purchase").unwrap();
        let surface = rendered.surface.unwrap();
        let command =
            authorize_action(&surface, &facts().intent_commitment, "activechain.approve").unwrap();
        let mut native = NativeDispatch::default();
        dispatch_wallet_action(&command, &mut native).unwrap();
        assert_eq!(native.approved, vec![facts().intent_commitment]);
        assert!(native.rejected.is_empty());
        assert!(authorize_action(&surface, &"00".repeat(48), "activechain.approve").is_err());
        assert_eq!(native.approved.len(), 1);
    }

    fn issuer_policy() -> FungibleAssetPolicyV1 {
        FungibleAssetPolicyV1::new(
            AssetId::new(Digest384::new([81; 48])),
            PrincipalId::new(Digest384::new([82; 48])),
            Digest384::ZERO,
            Digest384::ZERO,
            Digest384::ZERO,
            Digest384::new([83; 48]),
            1_000,
            100,
            FungibleAssetLifecycle::Registered,
        )
        .unwrap()
    }

    fn issuer_approval(
        policy: &FungibleAssetPolicyV1,
        operation: FungibleIssuerOperation,
    ) -> FungibleIssuerApprovalV1 {
        FungibleIssuerApprovalV1::new(
            policy.asset_id(),
            policy.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([84; 48]),
            operation,
            25,
            100,
            10,
            20,
        )
        .unwrap()
    }

    #[test]
    fn issuer_review_is_derived_from_exact_approved_transition() {
        let policy = issuer_policy();
        let approval = issuer_approval(&policy, FungibleIssuerOperation::Mint);
        let facts =
            IssuerOperationFacts::from_approved_supply_operation(&policy, &approval, 15).unwrap();
        assert_eq!(facts.operation, "Mint");
        assert_eq!(facts.supply_before, "100");
        assert_eq!(facts.supply_after, "125");
        let rendered =
            render_issuer_operation(&facts, "Issue the approved treasury tranche").unwrap();
        let surface = rendered.surface.unwrap();
        assert_eq!(surface.surface_id, "activechain.issuer_operation.v1");
        assert_eq!(surface.intent_commitment, "54".repeat(48));
        assert!(surface.components.iter().any(|component| {
            component.action.as_ref().is_some_and(|action| {
                action.name == "activechain.approve"
                    && action.context.get("intent_commitment") == Some(&"54".repeat(48))
            })
        }));
    }

    #[test]
    fn issuer_review_rejects_stale_or_substituted_approval() {
        let policy = issuer_policy();
        let approval = issuer_approval(&policy, FungibleIssuerOperation::Redemption);
        assert_eq!(
            IssuerOperationFacts::from_approved_supply_operation(&policy, &approval, 20),
            Err(RenderError::InvalidCanonicalFacts)
        );
        let changed = FungibleAssetPolicyV1::new(
            policy.asset_id(),
            policy.issuer(),
            Digest384::ZERO,
            Digest384::ZERO,
            Digest384::ZERO,
            policy.authority_set(),
            policy.supply_cap(),
            99,
            policy.lifecycle(),
        )
        .unwrap();
        assert_eq!(
            IssuerOperationFacts::from_approved_supply_operation(&changed, &approval, 15),
            Err(RenderError::InvalidCanonicalFacts)
        );
    }

    fn nft_review_inputs() -> (
        NonFungibleSeriesV1,
        NonFungibleTokenRegistryV1,
        Digest384,
        NonFungibleIssuerApprovalV1,
        NonFungibleMintManifestV1,
    ) {
        let asset = AssetId::new(Digest384::new([90; 48]));
        let issuer = PrincipalId::new(Digest384::new([91; 48]));
        let authority = Digest384::new([92; 48]);
        let series =
            NonFungibleSeriesV1::new(asset, issuer, 10, 0, Digest384::new([93; 48])).unwrap();
        let registry = NonFungibleTokenRegistryV1::new(asset, vec![]).unwrap();
        let manifest = NonFungibleMintManifestV1::new(
            asset,
            issuer,
            vec![
                NonFungibleMintItemV1::new(
                    Digest384::new([94; 48]),
                    PrincipalId::new(Digest384::new([95; 48])),
                    Digest384::new([96; 48]),
                )
                .unwrap(),
                NonFungibleMintItemV1::new(
                    Digest384::new([97; 48]),
                    PrincipalId::new(Digest384::new([98; 48])),
                    Digest384::new([99; 48]),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let approval = NonFungibleIssuerApprovalV1::new(
            asset,
            issuer,
            authority,
            series.commitment().unwrap(),
            Digest384::new([100; 48]),
            manifest.commitment().unwrap(),
            2,
            0,
            10,
            20,
        )
        .unwrap();
        (series, registry, authority, approval, manifest)
    }

    #[test]
    fn nft_issuer_review_is_derived_from_exact_transition() {
        let (series, registry, authority, approval, manifest) = nft_review_inputs();
        let facts = NftIssuerOperationFacts::from_approved_mint(
            &series, &registry, authority, &approval, &manifest, 15,
        )
        .unwrap();
        assert_eq!(facts.item_count, "2");
        assert_eq!(facts.supply_before, "0");
        assert_eq!(facts.supply_after, "2");
        let rendered = render_nft_issuer_operation(&facts, "Mint the approved NFT batch").unwrap();
        let surface = rendered.surface.unwrap();
        assert_eq!(surface.surface_id, "activechain.nft_issuer_operation.v1");
        assert_eq!(surface.intent_commitment, "64".repeat(48));
    }

    #[test]
    fn nft_issuer_review_rejects_stale_or_substituted_state() {
        let (series, registry, authority, approval, manifest) = nft_review_inputs();
        assert_eq!(
            NftIssuerOperationFacts::from_approved_mint(
                &series, &registry, authority, &approval, &manifest, 20,
            ),
            Err(RenderError::InvalidCanonicalFacts)
        );
        let changed_registry =
            NonFungibleTokenRegistryV1::new(series.asset_id(), vec![Digest384::new([1; 48])])
                .unwrap();
        assert_eq!(
            NftIssuerOperationFacts::from_approved_mint(
                &series,
                &changed_registry,
                authority,
                &approval,
                &manifest,
                15,
            ),
            Err(RenderError::InvalidCanonicalFacts)
        );
    }

    #[test]
    fn controller_rotation_review_is_derived_from_exact_transition() {
        let policy = issuer_policy();
        let state = FungibleControllerStateV1::from_policy(&policy, 7).unwrap();
        let rotation = FungibleControllerRotationV1::new(
            policy.asset_id(),
            policy.issuer(),
            state.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([85; 48]),
            Digest384::new([86; 48]),
            state.revision(),
            10,
            20,
        )
        .unwrap();
        let facts = ControllerRotationFacts::from_approved_rotation(&policy, &state, &rotation, 15)
            .unwrap();
        assert_eq!(facts.revision_before, 7);
        assert_eq!(facts.revision_after, 8);
        assert_eq!(facts.replacement_authority, "55".repeat(48));
        let rendered = render_controller_rotation(&facts, "Rotate the issuer quorum").unwrap();
        let surface = rendered.surface.unwrap();
        assert_eq!(surface.surface_id, "activechain.controller_rotation.v1");
        assert_eq!(surface.intent_commitment, "56".repeat(48));
    }

    #[test]
    fn controller_rotation_review_rejects_stale_replay_and_changed_policy() {
        let policy = issuer_policy();
        let state = FungibleControllerStateV1::from_policy(&policy, 7).unwrap();
        let rotation = FungibleControllerRotationV1::new(
            policy.asset_id(),
            policy.issuer(),
            state.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([85; 48]),
            Digest384::new([86; 48]),
            state.revision(),
            10,
            20,
        )
        .unwrap();
        assert_eq!(
            ControllerRotationFacts::from_approved_rotation(&policy, &state, &rotation, 20),
            Err(RenderError::InvalidCanonicalFacts)
        );
        let (next_policy, next_state) = state.apply_rotation(&policy, &rotation, 15).unwrap();
        assert_eq!(
            ControllerRotationFacts::from_approved_rotation(
                &next_policy,
                &next_state,
                &rotation,
                15,
            ),
            Err(RenderError::InvalidCanonicalFacts)
        );
        let changed = FungibleAssetPolicyV1::new(
            policy.asset_id(),
            policy.issuer(),
            Digest384::ZERO,
            Digest384::ZERO,
            Digest384::ZERO,
            policy.authority_set(),
            policy.supply_cap(),
            99,
            policy.lifecycle(),
        )
        .unwrap();
        assert_eq!(
            ControllerRotationFacts::from_approved_rotation(&changed, &state, &rotation, 15),
            Err(RenderError::InvalidCanonicalFacts)
        );
    }

    fn issuer_recovery_fixture() -> (
        Principal,
        FungibleAssetPolicyV1,
        FungibleControllerStateV1,
        RecoveryRequest,
        FungibleControllerRotationV1,
    ) {
        let policy = issuer_policy();
        let principal = Principal::new(
            policy.issuer(),
            PrincipalKind::Organization,
            Digest384::new([70; 48]),
            Digest384::new([71; 48]),
            policy.authority_set(),
            7,
            FreezeState::Active,
            Digest384::new([72; 48]),
            100,
            1,
            5,
        )
        .unwrap();
        let state = FungibleControllerStateV1::from_policy(&policy, 3).unwrap();
        let request = RecoveryRequest::new(
            policy.issuer(),
            7,
            Digest384::new([73; 48]),
            Digest384::new([74; 48]),
            Digest384::new([75; 48]),
            10,
            20,
            500,
        )
        .unwrap();
        let rotation = FungibleControllerRotationV1::new(
            policy.asset_id(),
            policy.issuer(),
            state.commitment().unwrap(),
            policy.authority_set(),
            request.proposed_authenticator_set_root(),
            Digest384::new([76; 48]),
            state.revision(),
            request.challenge_deadline(),
            30,
        )
        .unwrap();
        (principal, policy, state, request, rotation)
    }

    #[test]
    fn issuer_recovery_review_is_exact_and_explicitly_pending() {
        let (principal, policy, state, request, rotation) = issuer_recovery_fixture();
        let facts = IssuerRecoveryInitiationFacts::from_initiation(
            &principal, &policy, &state, &request, &rotation,
        )
        .unwrap();
        assert_eq!(facts.sequence_before, 7);
        assert_eq!(facts.sequence_after, 8);
        assert_eq!(facts.challenge_deadline, 20);
        let rendered = render_issuer_recovery_initiation(
            &facts,
            "Initiate issuer recovery; challenge period remains open",
        )
        .unwrap();
        let surface = rendered.surface.unwrap();
        assert_eq!(surface.surface_id, "activechain.issuer_recovery_initiation.v1");
        assert_eq!(surface.intent_commitment, "4c".repeat(48));
        assert_eq!(
            surface.data_model["view"]["facts"][13],
            "Recovery status: Pending challenge period; not completed"
        );
    }

    #[test]
    fn issuer_recovery_review_rejects_stale_request_and_changed_rotation() {
        let (principal, policy, state, request, rotation) = issuer_recovery_fixture();
        let stale = RecoveryRequest::new(
            request.principal_id(),
            6,
            request.proposed_controller_policy_hash(),
            request.proposed_authenticator_set_root(),
            request.recovery_evidence_commitment(),
            request.initiated_at(),
            request.challenge_deadline(),
            request.recovery_bond(),
        )
        .unwrap();
        assert_eq!(
            IssuerRecoveryInitiationFacts::from_initiation(
                &principal, &policy, &state, &stale, &rotation,
            ),
            Err(RenderError::InvalidCanonicalFacts)
        );
        let changed_rotation = FungibleControllerRotationV1::new(
            policy.asset_id(),
            policy.issuer(),
            state.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([77; 48]),
            rotation.approval_commitment(),
            state.revision(),
            request.challenge_deadline(),
            30,
        )
        .unwrap();
        assert_eq!(
            IssuerRecoveryInitiationFacts::from_initiation(
                &principal,
                &policy,
                &state,
                &request,
                &changed_rotation,
            ),
            Err(RenderError::InvalidCanonicalFacts)
        );
    }

    fn corporate_action(policy: &FungibleAssetPolicyV1) -> FungibleCorporateActionV1 {
        FungibleCorporateActionV1::new(
            policy.asset_id(),
            policy.issuer(),
            policy.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([87; 48]),
            Digest384::new([88; 48]),
            FungibleCorporateActionKind::Distribution,
            10,
            12,
            20,
            5,
            1,
            1,
        )
        .unwrap()
    }

    #[test]
    fn corporate_action_review_is_derived_from_exact_once_transition() {
        let policy = issuer_policy();
        let registry = FungibleCorporateActionRegistryV1::default();
        let action = corporate_action(&policy);
        let facts =
            CorporateActionFacts::from_approved_action(&policy, &registry, &action, 12).unwrap();
        assert_eq!(facts.kind, "Distribution");
        assert_eq!(facts.amount_per_unit, "5");
        assert_ne!(facts.registry_before, facts.registry_after);
        let rendered = render_corporate_action(&facts, "Distribute the approved proceeds").unwrap();
        let surface = rendered.surface.unwrap();
        assert_eq!(surface.surface_id, "activechain.corporate_action.v1");
        assert_eq!(surface.intent_commitment, facts.action_id);
    }

    #[test]
    fn corporate_action_review_rejects_stale_and_replayed_actions() {
        let policy = issuer_policy();
        let mut registry = FungibleCorporateActionRegistryV1::default();
        let action = corporate_action(&policy);
        assert_eq!(
            CorporateActionFacts::from_approved_action(&policy, &registry, &action, 20),
            Err(RenderError::InvalidCanonicalFacts)
        );
        registry
            .admit(
                &action,
                policy.asset_id(),
                policy.commitment().unwrap(),
                policy.authority_set(),
                12,
            )
            .unwrap();
        assert_eq!(
            CorporateActionFacts::from_approved_action(&policy, &registry, &action, 12),
            Err(RenderError::InvalidCanonicalFacts)
        );
    }

    fn holder_control_inputs() -> (
        FungibleAssetDefinition,
        FungibleExceptionalControlPolicyV1,
        FungibleHolderControlStateV1,
        FungibleCoinCell,
    ) {
        let asset = AssetId::new(Digest384::new([101; 48]));
        let issuer = PrincipalId::new(Digest384::new([102; 48]));
        let holder = PrincipalId::new(Digest384::new([103; 48]));
        let policy = FungibleExceptionalControlPolicyV1::new(
            asset,
            issuer,
            Digest384::new([104; 48]),
            true,
            true,
        )
        .unwrap();
        let definition = FungibleAssetDefinition::new(
            asset,
            issuer,
            b"TEST".to_vec(),
            2,
            1_000,
            policy.commitment().unwrap(),
        )
        .unwrap();
        let state = FungibleHolderControlStateV1::new(asset, holder).unwrap();
        let cell = FungibleCoinCell::new(
            CoinCellOrigin::new(TransactionId::new(Digest384::new([105; 48])), 0),
            asset,
            holder,
            42,
            7,
        )
        .unwrap();
        (definition, policy, state, cell)
    }

    #[test]
    fn holder_control_review_is_derived_from_conserved_clawback() {
        let (definition, policy, state, cell) = holder_control_inputs();
        let action = FungibleExceptionalControlActionV1::new(
            cell.asset_id(),
            cell.owner(),
            PrincipalId::new(Digest384::new([106; 48])),
            policy.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([107; 48]),
            Digest384::new([108; 48]),
            FungibleExceptionalControlKind::Clawback,
            42,
            0,
            10,
            20,
        )
        .unwrap();
        let facts = HolderControlFacts::from_approved_action(
            &definition,
            &policy,
            &state,
            &action,
            Some(cell),
            10,
        )
        .unwrap();
        assert_eq!(facts.action, "Clawback");
        assert_eq!(facts.amount, "42");
        assert_ne!(facts.cell_owner_before, facts.cell_owner_after);
        let rendered = render_holder_control(&facts, "Execute the approved recovery").unwrap();
        let surface = rendered.surface.unwrap();
        assert_eq!(surface.surface_id, "activechain.holder_control.v1");
        assert_eq!(surface.intent_commitment, "6b".repeat(48));
    }

    #[test]
    fn holder_control_review_rejects_missing_extra_or_stale_cell_context() {
        let (definition, policy, state, cell) = holder_control_inputs();
        let clawback = FungibleExceptionalControlActionV1::new(
            cell.asset_id(),
            cell.owner(),
            PrincipalId::new(Digest384::new([106; 48])),
            policy.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([107; 48]),
            Digest384::new([108; 48]),
            FungibleExceptionalControlKind::Clawback,
            42,
            0,
            10,
            20,
        )
        .unwrap();
        assert_eq!(
            HolderControlFacts::from_approved_action(
                &definition,
                &policy,
                &state,
                &clawback,
                None,
                10,
            ),
            Err(RenderError::InvalidCanonicalFacts)
        );
        let freeze = FungibleExceptionalControlActionV1::new(
            cell.asset_id(),
            cell.owner(),
            cell.owner(),
            policy.commitment().unwrap(),
            policy.authority_set(),
            Digest384::new([109; 48]),
            Digest384::new([110; 48]),
            FungibleExceptionalControlKind::Freeze,
            0,
            0,
            10,
            20,
        )
        .unwrap();
        assert_eq!(
            HolderControlFacts::from_approved_action(
                &definition,
                &policy,
                &state,
                &freeze,
                Some(cell),
                10,
            ),
            Err(RenderError::InvalidCanonicalFacts)
        );
        assert_eq!(
            HolderControlFacts::from_approved_action(
                &definition,
                &policy,
                &state,
                &freeze,
                None,
                20,
            ),
            Err(RenderError::InvalidCanonicalFacts)
        );
    }

    fn reserve_facts(state: ReserveClaimState) -> ReserveClaimFacts {
        ReserveClaimFacts {
            attestation_commitment: "11".repeat(48),
            asset: "22".repeat(48),
            attestor: "33".repeat(48),
            state,
            claimed_against: "1000".into(),
            supply: "900".into(),
            self_attested: false,
            expires: 300,
        }
    }

    /// The property the type exists to hold, checked against what is actually
    /// rendered rather than against the enum: no reachable surface tells a
    /// reader the reserves were checked.
    #[test]
    fn no_rendered_reserve_state_claims_the_reserves_were_verified() {
        for state in [
            ReserveClaimState::Uncovered,
            ReserveClaimState::Expired,
            ReserveClaimState::ClaimExceeded,
            ReserveClaimState::Attested,
        ] {
            let rendered = render_reserve_claim(&reserve_facts(state), "issuer published a report")
                .expect("valid facts render");
            for (label, value) in &rendered.fallback.verified_rows {
                let text = format!("{label} {value}").to_lowercase();
                assert!(
                    !text.contains("reserves verified") && !text.contains("reserves confirmed"),
                    "a surface claimed verification: {label} = {value}"
                );
            }
        }
    }

    /// The caveat is the renderer's, not the agent's. An untrusted explanation
    /// must not be able to displace it.
    #[test]
    fn the_anchor_caveat_is_carried_whatever_the_explanation_says() {
        for explanation in ["reserves are fully verified and audited", "x"] {
            let rendered =
                render_reserve_claim(&reserve_facts(ReserveClaimState::Attested), explanation)
                    .expect("renders");
            let caveat = rendered
                .fallback
                .verified_rows
                .iter()
                .find(|(label, _)| label == "What this establishes")
                .expect("the caveat row is always present");
            assert_eq!(caveat.1, RESERVE_ANCHOR_CAVEAT, "the caveat is fixed, not caller-supplied");
            assert!(
                caveat.1.contains("does not establish that the reserves exist"),
                "the caveat must say what anchoring does not do"
            );
        }
    }

    /// A self-attestation must be visible as one, and its absence stated
    /// rather than left to inference.
    #[test]
    fn self_attestation_is_always_stated_either_way() {
        let mut facts = reserve_facts(ReserveClaimState::Attested);
        facts.self_attested = true;
        let rendered = render_reserve_claim(&facts, "x").unwrap();
        let row = rendered
            .fallback
            .verified_rows
            .iter()
            .find(|(label, _)| label == "Attested by the issuer itself")
            .expect("always rendered");
        assert_eq!(row.1, "yes");

        facts.self_attested = false;
        let rendered = render_reserve_claim(&facts, "x").unwrap();
        let row = rendered
            .fallback
            .verified_rows
            .iter()
            .find(|(label, _)| label == "Attested by the issuer itself")
            .expect("rendered even when false");
        assert_eq!(row.1, "no");
    }

    #[test]
    fn malformed_reserve_facts_are_refused() {
        let mut facts = reserve_facts(ReserveClaimState::Attested);
        facts.asset = "not a digest".into();
        assert!(render_reserve_claim(&facts, "x").is_err());

        let mut facts = reserve_facts(ReserveClaimState::Attested);
        facts.supply = "many".into();
        assert_eq!(
            render_reserve_claim(&facts, "x"),
            Err(RenderError::InvalidCanonicalFacts),
            "a figure that does not parse is not a figure"
        );
    }

    /// Reviewing an attestation is not approving a transaction, so the surface
    /// must not offer approve and reject controls.
    #[test]
    fn a_reserve_surface_offers_no_approval_actions() {
        let rendered =
            render_reserve_claim(&reserve_facts(ReserveClaimState::Attested), "x").unwrap();
        assert!(rendered.fallback.approve_label.is_empty());
        assert!(rendered.fallback.reject_label.is_empty());
    }
}
