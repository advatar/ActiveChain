#![forbid(unsafe_code)]

//! Host-only transport contracts for MCP clients and constrained A2UI renderers.
//!
//! These DTOs are not canonical protocol values and never confer authority. A
//! validated proposal must still be reconstructed as an exact ActiveChain
//! intent and pass the wallet, capability, policy, signing, and consensus
//! boundaries.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const INTERFACE_VERSION: &str = "activechain.agent-interfaces.v1";
pub const A2UI_VERSION: &str = "v0.9";
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
pub const MAX_COMPONENTS: usize = 64;
pub const MAX_COMPONENT_DEPTH: usize = 12;
pub const MAX_COMPONENT_CHILDREN: usize = 32;
pub const MAX_TEXT_BYTES: usize = 4 * 1024;
pub const MAX_DATA_MODEL_BYTES: usize = 64 * 1024;
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_JSON_MEMBERS: usize = 256;

const ALLOWED_COMPONENTS: [&str; 12] = [
    "Button", "Card", "CheckBox", "Column", "Divider", "Icon", "List", "Modal", "RichText", "Row",
    "Table", "Text",
];

const ALLOWED_ACTIONS: [&str; 3] =
    ["activechain.approve", "activechain.reject", "activechain.open_details"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceError {
    Malformed,
    UnsupportedVersion,
    UnknownField,
    InvalidIdentifier,
    InvalidTool,
    MissingAuthority,
    InvalidAuthority,
    InvalidArguments,
    InvalidSurface,
    InvalidComponent,
    InvalidBinding,
    InvalidAction,
    LimitExceeded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBindingV1 {
    pub chain_id: String,
    pub wallet_id: String,
    pub agent_principal: String,
    pub capability_id: String,
    pub request_nonce: String,
    pub expires_at_height: u64,
    pub intent_commitment: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpToolV1 {
    GetStatus,
    ListAssets,
    VerifyRecord,
    GetPendingApprovals,
    ResolveReceipt,
    ProposeTransfer,
    SubmitAnchorProposal,
}

impl McpToolV1 {
    #[must_use]
    pub const fn is_consequential(self) -> bool {
        matches!(self, Self::ProposeTransfer | Self::SubmitAnchorProposal)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpRequestV1 {
    pub version: String,
    pub request_id: String,
    pub tool: McpToolV1,
    pub authority: Option<AuthorityBindingV1>,
    pub arguments: Value,
}

impl McpRequestV1 {
    pub fn decode(frame: &[u8]) -> Result<Self, InterfaceError> {
        if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
            return Err(InterfaceError::LimitExceeded);
        }
        let value: Self = serde_json::from_slice(frame).map_err(classify_json_error)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), InterfaceError> {
        require_version(&self.version)?;
        require_identifier(&self.request_id)?;
        let argument_length = serde_json::to_vec(&self.arguments)
            .map_err(|_| InterfaceError::InvalidArguments)?
            .len();
        if !self.arguments.is_object() || argument_length > MAX_ARGUMENT_BYTES {
            return Err(InterfaceError::InvalidArguments);
        }
        validate_json(&self.arguments, 1).map_err(|_| InterfaceError::InvalidArguments)?;
        match (&self.authority, self.tool.is_consequential()) {
            (None, true) => Err(InterfaceError::MissingAuthority),
            (Some(authority), _) => validate_authority(authority),
            (None, false) => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingV1 {
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct A2uiActionV1 {
    pub name: String,
    #[serde(default)]
    pub context: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct A2uiComponentV1 {
    pub id: String,
    pub component: String,
    #[serde(default)]
    pub children: Vec<String>,
    pub child: Option<String>,
    pub text: Option<BindingV1>,
    pub action: Option<A2uiActionV1>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct A2uiSurfaceV1 {
    pub version: String,
    pub interface_version: String,
    pub surface_id: String,
    pub root: String,
    pub intent_commitment: String,
    pub components: Vec<A2uiComponentV1>,
    pub data_model: Value,
}

impl A2uiSurfaceV1 {
    pub fn decode(frame: &[u8]) -> Result<Self, InterfaceError> {
        if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
            return Err(InterfaceError::LimitExceeded);
        }
        let value: Self = serde_json::from_slice(frame).map_err(classify_json_error)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), InterfaceError> {
        if self.version != A2UI_VERSION {
            return Err(InterfaceError::UnsupportedVersion);
        }
        require_version(&self.interface_version)?;
        require_identifier(&self.surface_id)?;
        require_commitment(&self.intent_commitment)?;
        if self.components.is_empty() || self.components.len() > MAX_COMPONENTS {
            return Err(InterfaceError::LimitExceeded);
        }
        if !self.data_model.is_object()
            || serde_json::to_vec(&self.data_model)
                .map_err(|_| InterfaceError::InvalidSurface)?
                .len()
                > MAX_DATA_MODEL_BYTES
        {
            return Err(InterfaceError::LimitExceeded);
        }
        validate_json(&self.data_model, 1)?;

        let mut ids = BTreeSet::new();
        for component in &self.components {
            require_identifier(&component.id)?;
            if !ids.insert(component.id.as_str())
                || !ALLOWED_COMPONENTS.contains(&component.component.as_str())
                || component.children.len() > MAX_COMPONENT_CHILDREN
            {
                return Err(InterfaceError::InvalidComponent);
            }
            if let Some(text) = &component.text {
                validate_binding(&text.path)?;
            }
            if let Some(action) = &component.action {
                if component.component != "Button"
                    || !ALLOWED_ACTIONS.contains(&action.name.as_str())
                {
                    return Err(InterfaceError::InvalidAction);
                }
                let commitment =
                    action.context.get("intent_commitment").ok_or(InterfaceError::InvalidAction)?;
                if commitment != &self.intent_commitment {
                    return Err(InterfaceError::InvalidAction);
                }
            }
        }
        if !ids.contains(self.root.as_str()) {
            return Err(InterfaceError::InvalidSurface);
        }
        for component in &self.components {
            for child in component.children.iter().chain(component.child.iter()) {
                if !ids.contains(child.as_str()) {
                    return Err(InterfaceError::InvalidComponent);
                }
            }
        }
        validate_depth(&self.root, &self.components, &mut BTreeSet::new(), 1)
    }
}

fn require_version(version: &str) -> Result<(), InterfaceError> {
    if version == INTERFACE_VERSION { Ok(()) } else { Err(InterfaceError::UnsupportedVersion) }
}

fn require_identifier(value: &str) -> Result<(), InterfaceError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        Err(InterfaceError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn require_commitment(value: &str) -> Result<(), InterfaceError> {
    if value.len() == 96 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(InterfaceError::InvalidAuthority)
    }
}

fn validate_authority(value: &AuthorityBindingV1) -> Result<(), InterfaceError> {
    require_identifier(&value.chain_id)?;
    require_identifier(&value.wallet_id)?;
    require_commitment(&value.agent_principal)?;
    require_commitment(&value.capability_id)?;
    require_identifier(&value.request_nonce)?;
    require_commitment(&value.intent_commitment)?;
    if value.expires_at_height == 0 {
        return Err(InterfaceError::InvalidAuthority);
    }
    Ok(())
}

fn validate_binding(path: &str) -> Result<(), InterfaceError> {
    if path.len() > MAX_IDENTIFIER_BYTES
        || !path.starts_with('/')
        || path.contains('.')
        || path.contains("//")
        || path.split('/').skip(1).any(|part| part.is_empty())
    {
        Err(InterfaceError::InvalidBinding)
    } else {
        Ok(())
    }
}

fn validate_json(value: &Value, depth: usize) -> Result<(), InterfaceError> {
    if depth > MAX_JSON_DEPTH {
        return Err(InterfaceError::LimitExceeded);
    }
    match value {
        Value::String(text) if text.len() > MAX_TEXT_BYTES => Err(InterfaceError::LimitExceeded),
        Value::Array(items) => {
            if items.len() > MAX_JSON_MEMBERS {
                return Err(InterfaceError::LimitExceeded);
            }
            for item in items {
                validate_json(item, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(fields) => {
            if fields.len() > MAX_JSON_MEMBERS {
                return Err(InterfaceError::LimitExceeded);
            }
            for (key, item) in fields {
                require_identifier(key)?;
                validate_json(item, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_depth<'a>(
    id: &'a str,
    components: &'a [A2uiComponentV1],
    active: &mut BTreeSet<&'a str>,
    depth: usize,
) -> Result<(), InterfaceError> {
    if depth > MAX_COMPONENT_DEPTH || !active.insert(id) {
        return Err(InterfaceError::LimitExceeded);
    }
    let component = components
        .iter()
        .find(|component| component.id == id)
        .ok_or(InterfaceError::InvalidComponent)?;
    for child in component.children.iter().chain(component.child.iter()) {
        validate_depth(child, components, active, depth + 1)?;
    }
    active.remove(id);
    Ok(())
}

fn classify_json_error(error: serde_json::Error) -> InterfaceError {
    if error.to_string().contains("unknown field") {
        InterfaceError::UnknownField
    } else {
        InterfaceError::Malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMITMENT: &str = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn read_only_request_needs_no_authority_but_proposal_does() {
        let read = format!(
            r#"{{"version":"{INTERFACE_VERSION}","request_id":"request-1","tool":"get_status","authority":null,"arguments":{{}}}}"#
        );
        assert!(McpRequestV1::decode(read.as_bytes()).is_ok());

        let proposal = read.replace("get_status", "propose_transfer");
        assert_eq!(
            McpRequestV1::decode(proposal.as_bytes()),
            Err(InterfaceError::MissingAuthority)
        );
    }

    #[test]
    fn unknown_and_oversized_inputs_fail_closed() {
        let unknown = format!(
            r#"{{"version":"{INTERFACE_VERSION}","request_id":"request-1","tool":"get_status","authority":null,"arguments":{{}},"sign":true}}"#
        );
        assert_eq!(McpRequestV1::decode(unknown.as_bytes()), Err(InterfaceError::UnknownField));
        assert_eq!(
            McpRequestV1::decode(&vec![b' '; MAX_FRAME_BYTES + 1]),
            Err(InterfaceError::LimitExceeded)
        );
    }

    #[test]
    fn constrained_surface_binds_actions_to_the_reviewed_intent() {
        let surface = format!(
            r#"{{"version":"v0.9","interface_version":"{INTERFACE_VERSION}","surface_id":"transfer-review","root":"root","intent_commitment":"{COMMITMENT}","components":[{{"id":"root","component":"Column","children":["title","approve"],"child":null,"text":null,"action":null}},{{"id":"title","component":"Text","children":[],"child":null,"text":{{"path":"/verified/summary"}},"action":null}},{{"id":"approve","component":"Button","children":[],"child":"approve-label","text":null,"action":{{"name":"activechain.approve","context":{{"intent_commitment":"{COMMITMENT}"}}}}}},{{"id":"approve-label","component":"Text","children":[],"child":null,"text":{{"path":"/labels/approve"}},"action":null}}],"data_model":{{"verified":{{"summary":"Send 1 ACT"}},"labels":{{"approve":"Approve"}}}}}}"#
        );
        assert!(A2uiSurfaceV1::decode(surface.as_bytes()).is_ok());
        let substituted =
            surface.replace(COMMITMENT, &"2".repeat(96)).replacen(&"2".repeat(96), COMMITMENT, 1);
        assert_eq!(
            A2uiSurfaceV1::decode(substituted.as_bytes()),
            Err(InterfaceError::InvalidAction)
        );
    }

    #[test]
    fn surface_rejects_unsafe_components_bindings_and_cycles() {
        let base = A2uiSurfaceV1 {
            version: A2UI_VERSION.into(),
            interface_version: INTERFACE_VERSION.into(),
            surface_id: "review".into(),
            root: "root".into(),
            intent_commitment: COMMITMENT.into(),
            components: vec![A2uiComponentV1 {
                id: "root".into(),
                component: "Web".into(),
                children: vec![],
                child: None,
                text: None,
                action: None,
            }],
            data_model: serde_json::json!({}),
        };
        assert_eq!(base.validate(), Err(InterfaceError::InvalidComponent));

        let mut cyclic = base;
        cyclic.components[0].component = "Column".into();
        cyclic.components[0].children.push("root".into());
        assert_eq!(cyclic.validate(), Err(InterfaceError::LimitExceeded));
    }

    #[test]
    fn checked_in_vectors_match_expected_results() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../testing/vectors/agent-interfaces-v1.json"))
                .expect("valid fixture JSON");
        assert_eq!(fixture["version"], INTERFACE_VERSION);
        for case in fixture["cases"].as_array().expect("cases") {
            let payload = serde_json::to_vec(&case["payload"]).expect("payload JSON");
            let accepted = match case["kind"].as_str().expect("kind") {
                "mcp_request" => McpRequestV1::decode(&payload).is_ok(),
                "a2ui_surface" => A2uiSurfaceV1::decode(&payload).is_ok(),
                kind => panic!("unknown fixture kind {kind}"),
            };
            assert_eq!(accepted, case["accepted"].as_bool().expect("accepted"));
        }
    }

    #[test]
    fn deeply_nested_or_long_text_data_fails_closed() {
        let mut nested = serde_json::json!({});
        for _ in 0..MAX_JSON_DEPTH {
            nested = serde_json::json!({"next": nested});
        }
        assert_eq!(validate_json(&nested, 1), Err(InterfaceError::LimitExceeded));
        assert_eq!(
            validate_json(&Value::String("x".repeat(MAX_TEXT_BYTES + 1)), 1),
            Err(InterfaceError::LimitExceeded)
        );
    }
}
