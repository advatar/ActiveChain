#![forbid(unsafe_code)]

//! Presentation-only A2UI rendering over wallet-reconstructed approval facts.

use std::collections::BTreeMap;

use activechain_agent_interfaces::{
    A2UI_VERSION, A2uiActionV1, A2uiComponentV1, A2uiSurfaceV1, BindingV1, INTERFACE_VERSION,
};
use activechain_proposal_gateway::{ActionIntentV1, ActionKindV1};
use activechain_protocol_types::{
    FungibleAssetPolicyV1, FungibleIssuerApprovalV1, FungibleIssuerOperation,
    NonFungibleIssuerApprovalV1, NonFungibleMintManifestV1, NonFungibleSeriesV1,
    NonFungibleTokenRegistryV1,
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
    use activechain_protocol_types::{
        AssetId, Digest384, FungibleAssetLifecycle, NonFungibleMintItemV1, PrincipalId,
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
}
