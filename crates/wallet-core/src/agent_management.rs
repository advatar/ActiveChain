use crate::WalletError;
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_types::{CapabilityId, Digest384, PrincipalId, TransactionId};
use alloc::vec::Vec;
use std::io::Write;
use std::path::Path;

pub const MAX_MANAGED_AGENTS: usize = 256;
pub const MAX_AGENT_CAPABILITIES: usize = 32;
pub const MAX_AGENT_LABEL: usize = 96;
pub const MAX_AGENT_REQUEST_REPLAYS: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AgentConnectionKind {
    SameTeamAppGroup = 0,
    ThirdPartyProtocol = 1,
    RemoteService = 2,
    ManagedDeviceExtension = 3,
}

impl CanonicalEncode for AgentConnectionKind {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for AgentConnectionKind {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::SameTeamAppGroup),
            1 => Ok(Self::ThirdPartyProtocol),
            2 => Ok(Self::RemoteService),
            3 => Ok(Self::ManagedDeviceExtension),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "AgentConnectionKind", tag }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentLifecycle {
    Active,
    Paused,
    RevocationPending { transaction: TransactionId },
    Revoked { transaction: TransactionId, finalized_height: u64 },
}

impl CanonicalEncode for AgentLifecycle {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Active => 0_u8.encode(encoder),
            Self::Paused => 1_u8.encode(encoder),
            Self::RevocationPending { transaction } => {
                2_u8.encode(encoder)?;
                transaction.encode(encoder)
            }
            Self::Revoked { transaction, finalized_height } => {
                3_u8.encode(encoder)?;
                transaction.encode(encoder)?;
                finalized_height.encode(encoder)
            }
        }
    }
}

impl CanonicalDecode for AgentLifecycle {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Active),
            1 => Ok(Self::Paused),
            2 => Ok(Self::RevocationPending { transaction: TransactionId::decode(decoder)? }),
            3 => {
                let transaction = TransactionId::decode(decoder)?;
                let finalized_height = u64::decode(decoder)?;
                if finalized_height == 0 {
                    return Err(DecodeError::InvalidValue(
                        "finalized agent revocation has zero height",
                    ));
                }
                Ok(Self::Revoked { transaction, finalized_height })
            }
            tag => Err(DecodeError::InvalidEnumTag { type_name: "AgentLifecycle", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedAgentV1 {
    principal: PrincipalId,
    label: Vec<u8>,
    connection: AgentConnectionKind,
    capabilities: Vec<CapabilityId>,
    budget_limit: u128,
    budget_spent: u128,
    expires_at: u64,
    lifecycle: AgentLifecycle,
}

impl ManagedAgentV1 {
    pub fn new(
        principal: PrincipalId,
        label: Vec<u8>,
        connection: AgentConnectionKind,
        capabilities: Vec<CapabilityId>,
        budget_limit: u128,
        expires_at: u64,
    ) -> Result<Self, WalletError> {
        if principal.into_digest() == Digest384::ZERO
            || label.is_empty()
            || label.len() > MAX_AGENT_LABEL
            || core::str::from_utf8(&label).is_err()
            || capabilities.is_empty()
            || capabilities.len() > MAX_AGENT_CAPABILITIES
            || capabilities.windows(2).any(|pair| pair[0] >= pair[1])
            || budget_limit == 0
            || expires_at == 0
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self {
            principal,
            label,
            connection,
            capabilities,
            budget_limit,
            budget_spent: 0,
            expires_at,
            lifecycle: AgentLifecycle::Active,
        })
    }

    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }
    pub fn label(&self) -> &[u8] {
        &self.label
    }
    pub const fn connection(&self) -> AgentConnectionKind {
        self.connection
    }
    pub fn capabilities(&self) -> &[CapabilityId] {
        &self.capabilities
    }
    pub const fn budget_limit(&self) -> u128 {
        self.budget_limit
    }
    pub const fn budget_spent(&self) -> u128 {
        self.budget_spent
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub const fn lifecycle(&self) -> AgentLifecycle {
        self.lifecycle
    }
}

impl CanonicalEncode for ManagedAgentV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.principal.encode(encoder)?;
        encoder.write_bytes(&self.label, MAX_AGENT_LABEL)?;
        self.connection.encode(encoder)?;
        encoder.write_length(self.capabilities.len(), MAX_AGENT_CAPABILITIES)?;
        for capability in &self.capabilities {
            capability.encode(encoder)?;
        }
        self.budget_limit.encode(encoder)?;
        self.budget_spent.encode(encoder)?;
        self.expires_at.encode(encoder)?;
        self.lifecycle.encode(encoder)
    }
}

impl CanonicalDecode for ManagedAgentV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let principal = PrincipalId::decode(decoder)?;
        let label = decoder.read_bytes(MAX_AGENT_LABEL)?.to_vec();
        let connection = AgentConnectionKind::decode(decoder)?;
        let count = decoder.read_length(MAX_AGENT_CAPABILITIES)?;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(CapabilityId::decode(decoder)?);
        }
        let budget_limit = u128::decode(decoder)?;
        let budget_spent = u128::decode(decoder)?;
        let expires_at = u64::decode(decoder)?;
        let lifecycle = AgentLifecycle::decode(decoder)?;
        let mut agent =
            Self::new(principal, label, connection, capabilities, budget_limit, expires_at)
                .map_err(|_| DecodeError::InvalidValue("invalid managed agent"))?;
        if budget_spent > budget_limit {
            return Err(DecodeError::InvalidValue("managed agent budget exceeded"));
        }
        agent.budget_spent = budget_spent;
        agent.lifecycle = lifecycle;
        Ok(agent)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentActionRequestV1 {
    pub request_id: Digest384,
    pub agent: PrincipalId,
    pub capability: CapabilityId,
    pub budget: u128,
    pub expires_at: u64,
}

impl AgentActionRequestV1 {
    fn validate(&self) -> Result<(), WalletError> {
        if self.request_id == Digest384::ZERO || self.expires_at == 0 {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(())
    }
}

impl CanonicalEncode for AgentActionRequestV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.request_id.encode(encoder)?;
        self.agent.encode(encoder)?;
        self.capability.encode(encoder)?;
        self.budget.encode(encoder)?;
        self.expires_at.encode(encoder)
    }
}

impl CanonicalDecode for AgentActionRequestV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let request = Self {
            request_id: Digest384::decode(decoder)?,
            agent: PrincipalId::decode(decoder)?,
            capability: CapabilityId::decode(decoder)?,
            budget: u128::decode(decoder)?,
            expires_at: u64::decode(decoder)?,
        };
        request
            .validate()
            .map_err(|_| DecodeError::InvalidValue("invalid agent action request"))?;
        Ok(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentRegistryCommandV1 {
    Register(ManagedAgentV1),
    Pause(PrincipalId),
    Resume(PrincipalId),
    BeginRevocation { principal: PrincipalId, transaction: TransactionId },
    FinalizeRevocation { principal: PrincipalId, transaction: TransactionId, finalized_height: u64 },
    Authorize { request: AgentActionRequestV1, current_height: u64 },
}

impl CanonicalEncode for AgentRegistryCommandV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Register(agent) => {
                0_u8.encode(encoder)?;
                agent.encode(encoder)
            }
            Self::Pause(principal) => {
                1_u8.encode(encoder)?;
                principal.encode(encoder)
            }
            Self::Resume(principal) => {
                2_u8.encode(encoder)?;
                principal.encode(encoder)
            }
            Self::BeginRevocation { principal, transaction } => {
                3_u8.encode(encoder)?;
                principal.encode(encoder)?;
                transaction.encode(encoder)
            }
            Self::FinalizeRevocation { principal, transaction, finalized_height } => {
                4_u8.encode(encoder)?;
                principal.encode(encoder)?;
                transaction.encode(encoder)?;
                finalized_height.encode(encoder)
            }
            Self::Authorize { request, current_height } => {
                5_u8.encode(encoder)?;
                request.encode(encoder)?;
                current_height.encode(encoder)
            }
        }
    }
}

impl CanonicalDecode for AgentRegistryCommandV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            0 => Ok(Self::Register(ManagedAgentV1::decode(decoder)?)),
            1 => Ok(Self::Pause(PrincipalId::decode(decoder)?)),
            2 => Ok(Self::Resume(PrincipalId::decode(decoder)?)),
            3 => Ok(Self::BeginRevocation {
                principal: PrincipalId::decode(decoder)?,
                transaction: TransactionId::decode(decoder)?,
            }),
            4 => {
                let principal = PrincipalId::decode(decoder)?;
                let transaction = TransactionId::decode(decoder)?;
                let finalized_height = u64::decode(decoder)?;
                if finalized_height == 0 {
                    return Err(DecodeError::InvalidValue(
                        "agent revocation finality height is zero",
                    ));
                }
                Ok(Self::FinalizeRevocation { principal, transaction, finalized_height })
            }
            5 => Ok(Self::Authorize {
                request: AgentActionRequestV1::decode(decoder)?,
                current_height: u64::decode(decoder)?,
            }),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "AgentRegistryCommandV1", tag }),
        }
    }
}

impl CanonicalType for AgentRegistryCommandV1 {
    const TYPE_TAG: u16 = 0x00d4;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 1
        + 48
        + 3
        + MAX_AGENT_LABEL
        + 1
        + 1
        + MAX_AGENT_CAPABILITIES * 48
        + 16
        + 16
        + 8
        + 1
        + 48
        + 8;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentRegistryV1 {
    agents: Vec<ManagedAgentV1>,
    consumed_requests: Vec<Digest384>,
}

impl AgentRegistryV1 {
    pub fn agents(&self) -> &[ManagedAgentV1] {
        &self.agents
    }

    pub fn register(&mut self, agent: ManagedAgentV1) -> Result<(), WalletError> {
        match self.agents.binary_search_by_key(&agent.principal, |value| value.principal) {
            Ok(_) => Err(WalletError::AgentExists),
            Err(_) if self.agents.len() >= MAX_MANAGED_AGENTS => Err(WalletError::StateLimit),
            Err(index) => {
                self.agents.insert(index, agent);
                Ok(())
            }
        }
    }

    pub fn apply(&mut self, command: AgentRegistryCommandV1) -> Result<(), WalletError> {
        match command {
            AgentRegistryCommandV1::Register(agent) => self.register(agent),
            AgentRegistryCommandV1::Pause(principal) => self.pause(principal),
            AgentRegistryCommandV1::Resume(principal) => self.resume(principal),
            AgentRegistryCommandV1::BeginRevocation { principal, transaction } => {
                self.begin_revocation(principal, transaction)
            }
            AgentRegistryCommandV1::FinalizeRevocation {
                principal,
                transaction,
                finalized_height,
            } => self.finalize_revocation(principal, transaction, finalized_height),
            AgentRegistryCommandV1::Authorize { request, current_height } => {
                self.authorize_and_record(request, current_height)
            }
        }
    }

    pub fn pause(&mut self, principal: PrincipalId) -> Result<(), WalletError> {
        let agent = self.agent_mut(principal)?;
        match agent.lifecycle {
            AgentLifecycle::Active => {
                agent.lifecycle = AgentLifecycle::Paused;
                Ok(())
            }
            AgentLifecycle::Paused => Ok(()),
            AgentLifecycle::RevocationPending { .. } | AgentLifecycle::Revoked { .. } => {
                Err(WalletError::AgentRevoked)
            }
        }
    }

    pub fn resume(&mut self, principal: PrincipalId) -> Result<(), WalletError> {
        let agent = self.agent_mut(principal)?;
        match agent.lifecycle {
            AgentLifecycle::Paused => {
                agent.lifecycle = AgentLifecycle::Active;
                Ok(())
            }
            AgentLifecycle::Active => Ok(()),
            AgentLifecycle::RevocationPending { .. } | AgentLifecycle::Revoked { .. } => {
                Err(WalletError::AgentRevoked)
            }
        }
    }

    pub fn begin_revocation(
        &mut self,
        principal: PrincipalId,
        transaction: TransactionId,
    ) -> Result<(), WalletError> {
        if transaction.into_digest() == Digest384::ZERO {
            return Err(WalletError::MalformedAuthorization);
        }
        let agent = self.agent_mut(principal)?;
        match agent.lifecycle {
            AgentLifecycle::Revoked { .. } => Err(WalletError::AgentRevoked),
            AgentLifecycle::RevocationPending { transaction: existing }
                if existing != transaction =>
            {
                Err(WalletError::MalformedAuthorization)
            }
            _ => {
                agent.lifecycle = AgentLifecycle::RevocationPending { transaction };
                Ok(())
            }
        }
    }

    pub fn finalize_revocation(
        &mut self,
        principal: PrincipalId,
        transaction: TransactionId,
        finalized_height: u64,
    ) -> Result<(), WalletError> {
        if finalized_height == 0 {
            return Err(WalletError::MalformedAuthorization);
        }
        let agent = self.agent_mut(principal)?;
        match agent.lifecycle {
            AgentLifecycle::RevocationPending { transaction: expected }
                if expected == transaction =>
            {
                agent.lifecycle = AgentLifecycle::Revoked { transaction, finalized_height };
                Ok(())
            }
            AgentLifecycle::Revoked {
                transaction: existing,
                finalized_height: existing_height,
            } if existing == transaction && existing_height == finalized_height => Ok(()),
            _ => Err(WalletError::MalformedAuthorization),
        }
    }

    pub fn authorize_and_record(
        &mut self,
        request: AgentActionRequestV1,
        current_height: u64,
    ) -> Result<(), WalletError> {
        request.validate()?;
        if current_height > request.expires_at {
            return Err(WalletError::Expired);
        }
        if self.consumed_requests.binary_search(&request.request_id).is_ok() {
            return Err(WalletError::Replay);
        }
        if self.consumed_requests.len() >= MAX_AGENT_REQUEST_REPLAYS {
            return Err(WalletError::StateLimit);
        }
        let agent = self.agent_mut(request.agent)?;
        match agent.lifecycle {
            AgentLifecycle::Active => {}
            AgentLifecycle::Paused => return Err(WalletError::AgentPaused),
            AgentLifecycle::RevocationPending { .. } | AgentLifecycle::Revoked { .. } => {
                return Err(WalletError::AgentRevoked);
            }
        }
        if current_height > agent.expires_at {
            return Err(WalletError::Expired);
        }
        if agent.capabilities.binary_search(&request.capability).is_err() {
            return Err(WalletError::MissingCapability);
        }
        let spent = agent
            .budget_spent
            .checked_add(request.budget)
            .ok_or(WalletError::AgentBudgetExceeded)?;
        if spent > agent.budget_limit {
            return Err(WalletError::AgentBudgetExceeded);
        }
        agent.budget_spent = spent;
        let index = self
            .consumed_requests
            .binary_search(&request.request_id)
            .expect_err("replay was rejected above");
        self.consumed_requests.insert(index, request.request_id);
        Ok(())
    }

    pub fn authorize_and_record_durable(
        &mut self,
        request: AgentActionRequestV1,
        current_height: u64,
        path: &Path,
    ) -> Result<(), WalletError> {
        let mut next = self.clone();
        next.authorize_and_record(request, current_height)?;
        next.save_atomic(path)?;
        *self = next;
        Ok(())
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), WalletError> {
        let bytes = encode_envelope(self).map_err(|_| WalletError::Persistence)?;
        let parent = path.parent().ok_or(WalletError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| WalletError::Persistence)?;
        let name = path.file_name().ok_or(WalletError::Persistence)?.to_string_lossy();
        let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
        let result = (|| {
            let mut file =
                std::fs::File::create(&temporary).map_err(|_| WalletError::Persistence)?;
            file.write_all(&bytes).map_err(|_| WalletError::Persistence)?;
            file.sync_all().map_err(|_| WalletError::Persistence)?;
            std::fs::rename(&temporary, path).map_err(|_| WalletError::Persistence)?;
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| WalletError::Persistence)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }

    pub fn load(path: &Path) -> Result<Self, WalletError> {
        let bytes = std::fs::read(path).map_err(|_| WalletError::Persistence)?;
        decode_envelope(&bytes).map_err(|_| WalletError::Persistence)
    }

    fn agent_mut(&mut self, principal: PrincipalId) -> Result<&mut ManagedAgentV1, WalletError> {
        let index = self
            .agents
            .binary_search_by_key(&principal, |agent| agent.principal)
            .map_err(|_| WalletError::UnknownAgent)?;
        Ok(&mut self.agents[index])
    }
}

impl CanonicalEncode for AgentRegistryV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.agents.len(), MAX_MANAGED_AGENTS)?;
        for agent in &self.agents {
            agent.encode(encoder)?;
        }
        encoder.write_length(self.consumed_requests.len(), MAX_AGENT_REQUEST_REPLAYS)?;
        for request in &self.consumed_requests {
            request.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for AgentRegistryV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_MANAGED_AGENTS)?;
        let mut agents = Vec::with_capacity(count);
        for _ in 0..count {
            let agent = ManagedAgentV1::decode(decoder)?;
            if agents
                .last()
                .is_some_and(|previous: &ManagedAgentV1| previous.principal >= agent.principal)
            {
                return Err(DecodeError::InvalidValue("managed agents are not strictly ordered"));
            }
            agents.push(agent);
        }
        let replay_count = decoder.read_length(MAX_AGENT_REQUEST_REPLAYS)?;
        let mut consumed_requests = Vec::with_capacity(replay_count);
        for _ in 0..replay_count {
            let request = Digest384::decode(decoder)?;
            if request == Digest384::ZERO
                || consumed_requests.last().is_some_and(|previous| *previous >= request)
            {
                return Err(DecodeError::InvalidValue(
                    "agent request replays are not strictly ordered",
                ));
            }
            consumed_requests.push(request);
        }
        Ok(Self { agents, consumed_requests })
    }
}

impl CanonicalType for AgentRegistryV1 {
    const TYPE_TAG: u16 = 0x00d3;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 3
        + MAX_MANAGED_AGENTS
            * (48
                + 3
                + MAX_AGENT_LABEL
                + 1
                + 1
                + MAX_AGENT_CAPABILITIES * 48
                + 16
                + 16
                + 8
                + 1
                + 48
                + 8)
        + 3
        + MAX_AGENT_REQUEST_REPLAYS * 48;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }
    fn capability(byte: u8) -> CapabilityId {
        CapabilityId::new(digest(byte))
    }
    fn request(byte: u8) -> AgentActionRequestV1 {
        AgentActionRequestV1 {
            request_id: digest(byte),
            agent: principal(1),
            capability: capability(2),
            budget: 10,
            expires_at: 50,
        }
    }

    #[test]
    fn lifecycle_budget_capability_and_replay_checks_fail_closed() {
        let mut registry = AgentRegistryV1::default();
        registry
            .register(
                ManagedAgentV1::new(
                    principal(1),
                    b"Research agent".to_vec(),
                    AgentConnectionKind::ThirdPartyProtocol,
                    vec![capability(2)],
                    20,
                    40,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(registry.authorize_and_record(request(10), 5), Ok(()));
        assert_eq!(registry.authorize_and_record(request(10), 5), Err(WalletError::Replay));
        let mut wrong_capability = request(11);
        wrong_capability.capability = capability(3);
        assert_eq!(
            registry.authorize_and_record(wrong_capability, 5),
            Err(WalletError::MissingCapability)
        );
        let mut over_budget = request(12);
        over_budget.budget = 11;
        assert_eq!(
            registry.authorize_and_record(over_budget, 5),
            Err(WalletError::AgentBudgetExceeded)
        );
        registry.pause(principal(1)).unwrap();
        assert_eq!(registry.authorize_and_record(request(13), 5), Err(WalletError::AgentPaused));
        registry.resume(principal(1)).unwrap();
        assert_eq!(registry.authorize_and_record(request(13), 41), Err(WalletError::Expired));
    }

    #[test]
    fn pending_revocation_blocks_immediately_and_finality_is_explicit() {
        let mut registry = AgentRegistryV1::default();
        registry
            .register(
                ManagedAgentV1::new(
                    principal(1),
                    b"Travel planner".to_vec(),
                    AgentConnectionKind::RemoteService,
                    vec![capability(2)],
                    100,
                    100,
                )
                .unwrap(),
            )
            .unwrap();
        let transaction = TransactionId::new(digest(9));
        registry.begin_revocation(principal(1), transaction).unwrap();
        assert_eq!(registry.authorize_and_record(request(20), 5), Err(WalletError::AgentRevoked));
        assert_eq!(
            registry.finalize_revocation(principal(1), TransactionId::new(digest(8)), 7),
            Err(WalletError::MalformedAuthorization)
        );
        registry.finalize_revocation(principal(1), transaction, 7).unwrap();
        assert_eq!(
            registry.agents()[0].lifecycle(),
            AgentLifecycle::Revoked { transaction, finalized_height: 7 }
        );
    }

    #[test]
    fn durable_registry_preserves_budget_replay_and_revocation_state() {
        let directory = std::env::temp_dir().join(format!(
            "activechain-agent-registry-{}-{}",
            std::process::id(),
            31
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("agents.bin");
        let mut registry = AgentRegistryV1::default();
        registry
            .register(
                ManagedAgentV1::new(
                    principal(1),
                    b"Local extension".to_vec(),
                    AgentConnectionKind::SameTeamAppGroup,
                    vec![capability(2)],
                    100,
                    100,
                )
                .unwrap(),
            )
            .unwrap();
        registry.authorize_and_record_durable(request(30), 5, &path).unwrap();
        let restored = AgentRegistryV1::load(&path).unwrap();
        assert_eq!(restored, registry);
        let mut restored = restored;
        assert_eq!(restored.authorize_and_record(request(30), 5), Err(WalletError::Replay));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(0);
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(AgentRegistryV1::load(&path), Err(WalletError::Persistence));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
