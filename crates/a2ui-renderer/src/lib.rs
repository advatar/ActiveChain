#![forbid(unsafe_code)]

//! Presentation-only A2UI rendering over wallet-reconstructed approval facts.

use std::collections::BTreeMap;

use activechain_agent_interfaces::{
    A2UI_VERSION, A2uiActionV1, A2uiComponentV1, A2uiSurfaceV1, BindingV1, INTERFACE_VERSION,
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
}
