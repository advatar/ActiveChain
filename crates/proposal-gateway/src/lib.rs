#![forbid(unsafe_code)]

//! Durable proposal admission. This crate cannot sign, approve, submit, or forward RPC calls.

use std::{collections::BTreeMap, fs::File, io::Write, path::Path};

use activechain_agent_interfaces::AuthorityBindingV1;
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_types::Digest384;
use serde::{Deserialize, Serialize};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

const INTENT_DOMAIN: &[u8] = b"ACTIVECHAIN-MCP-ACTION-INTENT-V1";
const PROPOSAL_DOMAIN: &[u8] = b"ACTIVECHAIN-MCP-PROPOSAL-ID-V1";
const SNAPSHOT_DOMAIN: &[u8] = b"ACTIVECHAIN-MCP-PROPOSAL-JOURNAL-V1";
const SNAPSHOT_TAG_BYTES: usize = 48;
const MAX_IDENTIFIER: usize = 128;
const MAX_PROPOSALS: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayError {
    InvalidArguments,
    InvalidAuthority,
    Expired,
    PolicyDenied,
    BudgetExceeded,
    ReplayConflict,
    Capacity,
    Persistence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionKindV1 {
    Transfer,
    SubmitAnchor,
}

impl CanonicalEncode for ActionKindV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Transfer => 0_u8.encode(encoder),
            Self::SubmitAnchor => 1_u8.encode(encoder),
        }
    }
}

impl CanonicalDecode for ActionKindV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Transfer),
            1 => Ok(Self::SubmitAnchor),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ActionKindV1", tag }),
        }
    }
}

/// Canonical exact action proposed for later native-wallet approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionIntentV1 {
    pub request_id: Vec<u8>,
    pub chain_id: Vec<u8>,
    pub wallet_id: Vec<u8>,
    pub agent_principal: Digest384,
    pub capability_id: Digest384,
    pub request_nonce: Vec<u8>,
    pub action: ActionKindV1,
    pub resource: Digest384,
    pub recipient: Digest384,
    pub amount: u128,
    pub maximum_fee: u128,
    pub expires_at_height: u64,
    pub replay_domain: Digest384,
}

impl ActionIntentV1 {
    pub fn commitment(&self) -> Result<Digest384, GatewayError> {
        let encoded = encode_envelope(self).map_err(|_| GatewayError::InvalidArguments)?;
        Ok(domain_digest(INTENT_DOMAIN, &encoded))
    }

    pub fn proposal_id(&self) -> Result<Digest384, GatewayError> {
        Ok(domain_digest(PROPOSAL_DOMAIN, self.commitment()?.as_bytes()))
    }
}

impl CanonicalEncode for ActionIntentV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_bytes(&self.request_id, MAX_IDENTIFIER)?;
        e.write_bytes(&self.chain_id, MAX_IDENTIFIER)?;
        e.write_bytes(&self.wallet_id, MAX_IDENTIFIER)?;
        self.agent_principal.encode(e)?;
        self.capability_id.encode(e)?;
        e.write_bytes(&self.request_nonce, MAX_IDENTIFIER)?;
        self.action.encode(e)?;
        self.resource.encode(e)?;
        self.recipient.encode(e)?;
        self.amount.encode(e)?;
        self.maximum_fee.encode(e)?;
        self.expires_at_height.encode(e)?;
        self.replay_domain.encode(e)
    }
}

impl CanonicalDecode for ActionIntentV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            request_id: d.read_bytes(MAX_IDENTIFIER)?.to_vec(),
            chain_id: d.read_bytes(MAX_IDENTIFIER)?.to_vec(),
            wallet_id: d.read_bytes(MAX_IDENTIFIER)?.to_vec(),
            agent_principal: Digest384::decode(d)?,
            capability_id: Digest384::decode(d)?,
            request_nonce: d.read_bytes(MAX_IDENTIFIER)?.to_vec(),
            action: ActionKindV1::decode(d)?,
            resource: Digest384::decode(d)?,
            recipient: Digest384::decode(d)?,
            amount: u128::decode(d)?,
            maximum_fee: u128::decode(d)?,
            expires_at_height: u64::decode(d)?,
            replay_domain: Digest384::decode(d)?,
        };
        validate_identifier_bytes(&value.request_id)
            .map_err(|_| DecodeError::InvalidValue("request id"))?;
        validate_identifier_bytes(&value.chain_id)
            .map_err(|_| DecodeError::InvalidValue("chain id"))?;
        validate_identifier_bytes(&value.wallet_id)
            .map_err(|_| DecodeError::InvalidValue("wallet id"))?;
        validate_identifier_bytes(&value.request_nonce)
            .map_err(|_| DecodeError::InvalidValue("nonce"))?;
        if value.agent_principal == Digest384::ZERO
            || value.capability_id == Digest384::ZERO
            || value.resource == Digest384::ZERO
            || value.recipient == Digest384::ZERO
            || value.amount == 0
            || value.expires_at_height == 0
            || value.replay_domain == Digest384::ZERO
        {
            return Err(DecodeError::InvalidValue("invalid action intent"));
        }
        Ok(value)
    }
}

impl CanonicalType for ActionIntentV1 {
    const TYPE_TAG: u16 = 0x0149;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 3 + 4 * (3 + MAX_IDENTIFIER) + 48 * 5 + 1 + 16 * 2 + 8;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferProposalArgumentsV1 {
    pub asset_commitment: String,
    pub recipient_commitment: String,
    pub amount: u128,
    pub maximum_fee: u128,
    pub replay_domain: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedProposalContext {
    pub chain_id: String,
    pub wallet_id: String,
    pub agent_principal: Digest384,
    pub capability_id: Digest384,
    pub permitted_resource: Digest384,
    pub permitted_recipient: Option<Digest384>,
    pub maximum_single_amount: u128,
    pub remaining_budget: u128,
    pub maximum_fee: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalRequirement {
    NativeWalletReview,
    NativeWalletReviewWithWarning,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalReceipt {
    pub proposal_id: Digest384,
    pub intent_commitment: Digest384,
    pub approval: ApprovalRequirement,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub proposal_id: Digest384,
    pub action: ActionKindV1,
    pub approval: ApprovalRequirement,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProposalJournalV1 {
    proposals: BTreeMap<Vec<u8>, ActionIntentV1>,
}

impl ProposalJournalV1 {
    pub fn propose_transfer_durable(
        &mut self,
        request_id: &str,
        authority: &AuthorityBindingV1,
        arguments: &TransferProposalArgumentsV1,
        context: &AuthenticatedProposalContext,
        current_height: u64,
        path: &Path,
    ) -> Result<(ProposalReceipt, AuditEvent), GatewayError> {
        let intent =
            build_transfer_intent(request_id, authority, arguments, context, current_height)?;
        let key = request_id.as_bytes();
        if let Some(existing) = self.proposals.get(key) {
            if existing != &intent {
                return Err(GatewayError::ReplayConflict);
            }
            return result_for(existing, true);
        }
        if self.proposals.values().any(|existing| {
            existing.agent_principal == intent.agent_principal
                && existing.request_nonce == intent.request_nonce
                && existing.replay_domain == intent.replay_domain
        }) {
            return Err(GatewayError::ReplayConflict);
        }
        let used_budget = self
            .proposals
            .values()
            .filter(|existing| existing.capability_id == intent.capability_id)
            .try_fold(0_u128, |used, existing| used.checked_add(existing.amount))
            .ok_or(GatewayError::BudgetExceeded)?;
        if used_budget
            .checked_add(intent.amount)
            .is_none_or(|total| total > context.remaining_budget)
        {
            return Err(GatewayError::BudgetExceeded);
        }
        if self.proposals.len() >= MAX_PROPOSALS {
            return Err(GatewayError::Capacity);
        }
        let mut next = self.clone();
        next.proposals.insert(key.to_vec(), intent.clone());
        next.save_atomic(path)?;
        *self = next;
        result_for(&intent, false)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), GatewayError> {
        let body = encode_envelope(self).map_err(|_| GatewayError::Persistence)?;
        let tag = domain_digest(SNAPSHOT_DOMAIN, &body);
        let parent = path.parent().ok_or(GatewayError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| GatewayError::Persistence)?;
        let name = path.file_name().ok_or(GatewayError::Persistence)?.to_string_lossy();
        let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
        let result = (|| {
            let mut file = File::create(&temporary).map_err(|_| GatewayError::Persistence)?;
            file.write_all(&body)
                .and_then(|_| file.write_all(tag.as_bytes()))
                .and_then(|_| file.sync_all())
                .map_err(|_| GatewayError::Persistence)?;
            std::fs::rename(&temporary, path).map_err(|_| GatewayError::Persistence)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| GatewayError::Persistence)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }

    pub fn load(path: &Path) -> Result<Self, GatewayError> {
        let bytes = std::fs::read(path).map_err(|_| GatewayError::Persistence)?;
        if bytes.len() < SNAPSHOT_TAG_BYTES {
            return Err(GatewayError::Persistence);
        }
        let body_length = bytes.len() - SNAPSHOT_TAG_BYTES;
        if domain_digest(SNAPSHOT_DOMAIN, &bytes[..body_length]).as_bytes() != &bytes[body_length..]
        {
            return Err(GatewayError::Persistence);
        }
        decode_envelope(&bytes[..body_length]).map_err(|_| GatewayError::Persistence)
    }
}

impl CanonicalEncode for ProposalJournalV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        e.write_length(self.proposals.len(), MAX_PROPOSALS)?;
        for (request_id, intent) in &self.proposals {
            e.write_bytes(request_id, MAX_IDENTIFIER)?;
            intent.encode(e)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for ProposalJournalV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = d.read_length(MAX_PROPOSALS)?;
        let mut proposals = BTreeMap::new();
        let mut previous: Option<Vec<u8>> = None;
        for _ in 0..count {
            let key = d.read_bytes(MAX_IDENTIFIER)?.to_vec();
            validate_identifier_bytes(&key).map_err(|_| DecodeError::InvalidValue("request id"))?;
            let intent = ActionIntentV1::decode(d)?;
            if key != intent.request_id
                || previous.as_ref().is_some_and(|prior| prior >= &key)
                || proposals.insert(key.clone(), intent).is_some()
            {
                return Err(DecodeError::InvalidValue("proposal order or binding"));
            }
            previous = Some(key);
        }
        Ok(Self { proposals })
    }
}

impl CanonicalType for ProposalJournalV1 {
    const TYPE_TAG: u16 = 0x014A;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        3 + MAX_PROPOSALS * (3 + MAX_IDENTIFIER + ActionIntentV1::MAX_ENCODED_LEN);
}

fn build_transfer_intent(
    request_id: &str,
    authority: &AuthorityBindingV1,
    arguments: &TransferProposalArgumentsV1,
    context: &AuthenticatedProposalContext,
    current_height: u64,
) -> Result<ActionIntentV1, GatewayError> {
    validate_identifier(request_id)?;
    validate_identifier(&authority.chain_id)?;
    validate_identifier(&authority.wallet_id)?;
    validate_identifier(&authority.request_nonce)?;
    let agent = parse_digest(&authority.agent_principal)?;
    let capability = parse_digest(&authority.capability_id)?;
    if authority.chain_id != context.chain_id
        || authority.wallet_id != context.wallet_id
        || agent != context.agent_principal
        || capability != context.capability_id
    {
        return Err(GatewayError::InvalidAuthority);
    }
    if authority.expires_at_height <= current_height {
        return Err(GatewayError::Expired);
    }
    let resource = parse_digest(&arguments.asset_commitment)?;
    let recipient = parse_digest(&arguments.recipient_commitment)?;
    let replay_domain = parse_digest(&arguments.replay_domain)?;
    if resource != context.permitted_resource
        || context.permitted_recipient.is_some_and(|allowed| allowed != recipient)
    {
        return Err(GatewayError::PolicyDenied);
    }
    if arguments.amount == 0 || arguments.amount > context.maximum_single_amount {
        return Err(GatewayError::PolicyDenied);
    }
    if arguments.amount > context.remaining_budget || arguments.maximum_fee > context.maximum_fee {
        return Err(GatewayError::BudgetExceeded);
    }
    let intent = ActionIntentV1 {
        request_id: request_id.as_bytes().to_vec(),
        chain_id: authority.chain_id.as_bytes().to_vec(),
        wallet_id: authority.wallet_id.as_bytes().to_vec(),
        agent_principal: agent,
        capability_id: capability,
        request_nonce: authority.request_nonce.as_bytes().to_vec(),
        action: ActionKindV1::Transfer,
        resource,
        recipient,
        amount: arguments.amount,
        maximum_fee: arguments.maximum_fee,
        expires_at_height: authority.expires_at_height,
        replay_domain,
    };
    if intent.commitment()? != parse_digest(&authority.intent_commitment)? {
        return Err(GatewayError::InvalidAuthority);
    }
    Ok(intent)
}

fn result_for(
    intent: &ActionIntentV1,
    duplicate: bool,
) -> Result<(ProposalReceipt, AuditEvent), GatewayError> {
    let proposal_id = intent.proposal_id()?;
    let intent_commitment = intent.commitment()?;
    let approval = if intent.amount > 1_000_000 {
        ApprovalRequirement::NativeWalletReviewWithWarning
    } else {
        ApprovalRequirement::NativeWalletReview
    };
    Ok((
        ProposalReceipt { proposal_id, intent_commitment, approval, duplicate },
        AuditEvent { proposal_id, action: intent.action, approval, duplicate },
    ))
}

fn validate_identifier(value: &str) -> Result<(), GatewayError> {
    validate_identifier_bytes(value.as_bytes())
}

fn validate_identifier_bytes(value: &[u8]) -> Result<(), GatewayError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER
        || !value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        Err(GatewayError::InvalidArguments)
    } else {
        Ok(())
    }
}

fn parse_digest(value: &str) -> Result<Digest384, GatewayError> {
    if value.len() != 96 {
        return Err(GatewayError::InvalidArguments);
    }
    let mut output = [0_u8; 48];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    let digest = Digest384::new(output);
    if digest == Digest384::ZERO { Err(GatewayError::InvalidArguments) } else { Ok(digest) }
}

fn hex_nibble(value: u8) -> Result<u8, GatewayError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(GatewayError::InvalidArguments),
    }
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn hex(value: Digest384) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(96);
        for byte in value.as_bytes() {
            output.push(char::from(HEX[(byte >> 4) as usize]));
            output.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
        output
    }

    fn context() -> AuthenticatedProposalContext {
        AuthenticatedProposalContext {
            chain_id: "activechain.test".into(),
            wallet_id: "wallet.1".into(),
            agent_principal: digest(1),
            capability_id: digest(2),
            permitted_resource: digest(3),
            permitted_recipient: Some(digest(4)),
            maximum_single_amount: 2_000_000,
            remaining_budget: 3_000_000,
            maximum_fee: 100,
        }
    }

    fn arguments() -> TransferProposalArgumentsV1 {
        TransferProposalArgumentsV1 {
            asset_commitment: hex(digest(3)),
            recipient_commitment: hex(digest(4)),
            amount: 500,
            maximum_fee: 10,
            replay_domain: hex(digest(5)),
        }
    }

    fn authority(arguments: &TransferProposalArgumentsV1) -> AuthorityBindingV1 {
        let context = context();
        let mut authority = AuthorityBindingV1 {
            chain_id: context.chain_id.clone(),
            wallet_id: context.wallet_id.clone(),
            agent_principal: hex(context.agent_principal),
            capability_id: hex(context.capability_id),
            request_nonce: "nonce.1".into(),
            expires_at_height: 50,
            intent_commitment: hex(digest(9)),
        };
        let intent = ActionIntentV1 {
            request_id: b"request.1".to_vec(),
            chain_id: authority.chain_id.as_bytes().to_vec(),
            wallet_id: authority.wallet_id.as_bytes().to_vec(),
            agent_principal: context.agent_principal,
            capability_id: context.capability_id,
            request_nonce: authority.request_nonce.as_bytes().to_vec(),
            action: ActionKindV1::Transfer,
            resource: digest(3),
            recipient: digest(4),
            amount: arguments.amount,
            maximum_fee: arguments.maximum_fee,
            expires_at_height: authority.expires_at_height,
            replay_domain: digest(5),
        };
        authority.intent_commitment = hex(intent.commitment().unwrap());
        authority
    }

    fn path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir()
            .join(format!("activechain-proposal-gateway-{}-{label}.snapshot", std::process::id()))
    }

    #[test]
    fn exact_retry_is_idempotent_and_restart_safe() {
        let path = path("restart");
        let args = arguments();
        let authority = authority(&args);
        let mut journal = ProposalJournalV1::default();
        let (first, _) = journal
            .propose_transfer_durable("request.1", &authority, &args, &context(), 10, &path)
            .unwrap();
        assert!(!first.duplicate);
        let mut restarted = ProposalJournalV1::load(&path).unwrap();
        let (retry, audit) = restarted
            .propose_transfer_durable("request.1", &authority, &args, &context(), 10, &path)
            .unwrap();
        assert!(retry.duplicate);
        assert_eq!(retry.proposal_id, first.proposal_id);
        assert!(audit.duplicate);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn conflicting_retry_and_substitution_fail_closed() {
        let path = path("conflict");
        let args = arguments();
        let authority = authority(&args);
        let mut journal = ProposalJournalV1::default();
        journal
            .propose_transfer_durable("request.1", &authority, &args, &context(), 10, &path)
            .unwrap();
        let mut changed = args.clone();
        changed.amount += 1;
        assert_eq!(
            journal.propose_transfer_durable(
                "request.1",
                &authority,
                &changed,
                &context(),
                10,
                &path
            ),
            Err(GatewayError::InvalidAuthority)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn wrong_authority_expiry_scope_and_budget_are_rejected() {
        let path = path("authority");
        let args = arguments();
        let authority = authority(&args);
        let mut journal = ProposalJournalV1::default();
        let mut wrong_context = context();
        wrong_context.wallet_id = "wallet.2".into();
        assert_eq!(
            journal.propose_transfer_durable(
                "request.1",
                &authority,
                &args,
                &wrong_context,
                10,
                &path
            ),
            Err(GatewayError::InvalidAuthority)
        );
        assert_eq!(
            journal.propose_transfer_durable("request.1", &authority, &args, &context(), 50, &path),
            Err(GatewayError::Expired)
        );
        let mut denied = context();
        denied.permitted_recipient = Some(digest(8));
        assert_eq!(
            journal.propose_transfer_durable("request.1", &authority, &args, &denied, 10, &path),
            Err(GatewayError::PolicyDenied)
        );
        let mut exhausted = context();
        exhausted.remaining_budget = 100;
        assert_eq!(
            journal.propose_transfer_durable("request.1", &authority, &args, &exhausted, 10, &path),
            Err(GatewayError::BudgetExceeded)
        );
    }

    #[test]
    fn corrupted_snapshot_and_malformed_input_fail_closed() {
        let corrupt_path = path("corrupt");
        let args = arguments();
        let authority = authority(&args);
        let mut journal = ProposalJournalV1::default();
        journal
            .propose_transfer_durable("request.1", &authority, &args, &context(), 10, &corrupt_path)
            .unwrap();
        let mut bytes = std::fs::read(&corrupt_path).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&corrupt_path, bytes).unwrap();
        assert_eq!(ProposalJournalV1::load(&corrupt_path), Err(GatewayError::Persistence));
        std::fs::remove_file(corrupt_path).unwrap();

        let mut malformed = args;
        malformed.recipient_commitment = "not-a-digest".into();
        assert_eq!(
            ProposalJournalV1::default().propose_transfer_durable(
                "request.1",
                &authority,
                &malformed,
                &context(),
                10,
                &path("malformed")
            ),
            Err(GatewayError::InvalidArguments)
        );
    }

    #[test]
    fn nonce_replay_and_cumulative_budget_exhaustion_survive_distinct_request_ids() {
        let path = path("budget");
        let mut args = arguments();
        args.amount = 400;
        let first_authority = authority(&args);
        let mut budget = context();
        budget.remaining_budget = 700;
        let mut journal = ProposalJournalV1::default();
        journal
            .propose_transfer_durable("request.1", &first_authority, &args, &budget, 10, &path)
            .unwrap();

        let mut replay = first_authority.clone();
        let replay_intent = ActionIntentV1 {
            request_id: b"request.2".to_vec(),
            chain_id: replay.chain_id.as_bytes().to_vec(),
            wallet_id: replay.wallet_id.as_bytes().to_vec(),
            agent_principal: digest(1),
            capability_id: digest(2),
            request_nonce: replay.request_nonce.as_bytes().to_vec(),
            action: ActionKindV1::Transfer,
            resource: digest(3),
            recipient: digest(4),
            amount: args.amount,
            maximum_fee: args.maximum_fee,
            expires_at_height: replay.expires_at_height,
            replay_domain: digest(5),
        };
        replay.intent_commitment = hex(replay_intent.commitment().unwrap());
        assert_eq!(
            journal.propose_transfer_durable("request.2", &replay, &args, &budget, 10, &path),
            Err(GatewayError::ReplayConflict)
        );

        let mut second_authority = first_authority;
        second_authority.request_nonce = "nonce.2".into();
        let second_intent = ActionIntentV1 {
            request_id: b"request.2".to_vec(),
            chain_id: second_authority.chain_id.as_bytes().to_vec(),
            wallet_id: second_authority.wallet_id.as_bytes().to_vec(),
            agent_principal: digest(1),
            capability_id: digest(2),
            request_nonce: second_authority.request_nonce.as_bytes().to_vec(),
            action: ActionKindV1::Transfer,
            resource: digest(3),
            recipient: digest(4),
            amount: args.amount,
            maximum_fee: args.maximum_fee,
            expires_at_height: second_authority.expires_at_height,
            replay_domain: digest(5),
        };
        second_authority.intent_commitment = hex(second_intent.commitment().unwrap());
        assert_eq!(
            journal.propose_transfer_durable(
                "request.2",
                &second_authority,
                &args,
                &budget,
                10,
                &path
            ),
            Err(GatewayError::BudgetExceeded)
        );
        std::fs::remove_file(path).unwrap();
    }
}
