//! Deterministic accounting settlement over finalized verified-execution evidence.
//!
//! This is deliberately an accounting ledger, not a token or a second consensus system. One
//! transition independently verifies an existing native Actum evidence-anchor finality envelope,
//! conserves one integer-denominated accounting unit, and emits an immutable reputation fact.
//! The resulting state commitment can then be anchored through Actum's existing consensus path.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{ChainId, Digest384, PrincipalId, TransactionId};
use alloc::{collections::BTreeMap, vec::Vec};

use crate::{AnchorFinalizedEvidenceV1, DigestAnchorStatementV1, verify_anchor_evidence};

pub const DCN_VERIFIED_EVIDENCE_DOMAIN: &[u8] = b"dcn.generation-attestation.evidence-anchor.v1";
pub const DCN_SETTLEMENT_STATE_DOMAIN: &[u8] = b"dcn.generation-attestation.settlement-state.v1";
const MAX_ACCOUNTS: usize = 1_024;
const MAX_SETTLEMENTS: usize = 4_096;
const MAX_REPUTATION_EVENTS: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SettlementAssuranceClassV1 {
    Cryptographic = 1,
}

impl CanonicalEncode for SettlementAssuranceClassV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(encoder)
    }
}

impl CanonicalDecode for SettlementAssuranceClassV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(decoder)? {
            1 => Ok(Self::Cryptographic),
            tag => {
                Err(DecodeError::InvalidEnumTag { type_name: "SettlementAssuranceClassV1", tag })
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceFinalityReferenceV1 {
    chain: ChainId,
    genesis: Digest384,
    evidence_anchor_commitment: [u8; 32],
    statement_reference: Digest384,
    transaction: TransactionId,
    finalized_height: u64,
    finalized_block: Digest384,
    protocol_revision: u64,
    verifier_revision: u32,
}

impl EvidenceFinalityReferenceV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: ChainId,
        genesis: Digest384,
        evidence_anchor_commitment: [u8; 32],
        statement_reference: Digest384,
        transaction: TransactionId,
        finalized_height: u64,
        finalized_block: Digest384,
        protocol_revision: u64,
        verifier_revision: u32,
    ) -> Result<Self, EvidenceSettlementError> {
        let value = Self {
            chain,
            genesis,
            evidence_anchor_commitment,
            statement_reference,
            transaction,
            finalized_height,
            finalized_block,
            protocol_revision,
            verifier_revision,
        };
        if value.chain.digest() == &Digest384::ZERO
            || value.genesis == Digest384::ZERO
            || value.evidence_anchor_commitment == [0; 32]
            || value.statement_reference == Digest384::ZERO
            || value.transaction == TransactionId::new(Digest384::ZERO)
            || value.finalized_height == 0
            || value.finalized_block == Digest384::ZERO
            || value.protocol_revision == 0
            || value.verifier_revision == 0
        {
            return Err(EvidenceSettlementError::InvalidInstruction);
        }
        if value.expected_statement()?.submission_reference()? != value.statement_reference {
            return Err(EvidenceSettlementError::InvalidInstruction);
        }
        Ok(value)
    }

    pub fn expected_statement(&self) -> Result<DigestAnchorStatementV1, EvidenceSettlementError> {
        DigestAnchorStatementV1::new(
            DCN_VERIFIED_EVIDENCE_DOMAIN.to_vec(),
            self.evidence_anchor_commitment,
        )
        .map_err(|_| EvidenceSettlementError::InvalidInstruction)
    }

    pub const fn chain(&self) -> ChainId {
        self.chain
    }
    pub const fn genesis(&self) -> Digest384 {
        self.genesis
    }
    pub const fn evidence_anchor_commitment(&self) -> &[u8; 32] {
        &self.evidence_anchor_commitment
    }
    pub const fn statement_reference(&self) -> Digest384 {
        self.statement_reference
    }
    pub const fn transaction(&self) -> TransactionId {
        self.transaction
    }
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }
    pub const fn finalized_block(&self) -> Digest384 {
        self.finalized_block
    }
    pub const fn protocol_revision(&self) -> u64 {
        self.protocol_revision
    }
    pub const fn verifier_revision(&self) -> u32 {
        self.verifier_revision
    }
}

impl CanonicalEncode for EvidenceFinalityReferenceV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain.encode(encoder)?;
        self.genesis.encode(encoder)?;
        encoder.write_raw(&self.evidence_anchor_commitment)?;
        self.statement_reference.encode(encoder)?;
        self.transaction.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        self.finalized_block.encode(encoder)?;
        self.protocol_revision.encode(encoder)?;
        self.verifier_revision.encode(encoder)
    }
}

impl CanonicalDecode for EvidenceFinalityReferenceV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            ChainId::decode(decoder)?,
            Digest384::decode(decoder)?,
            decoder.read_array()?,
            Digest384::decode(decoder)?,
            TransactionId::decode(decoder)?,
            u64::decode(decoder)?,
            Digest384::decode(decoder)?,
            u64::decode(decoder)?,
            u32::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid finalized evidence reference"))
    }
}

impl CanonicalType for EvidenceFinalityReferenceV1 {
    const TYPE_TAG: u16 = 0x01ca;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 48 + 32 + 48 + 48 + 8 + 48 + 8 + 4;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementInstructionV1 {
    finality: EvidenceFinalityReferenceV1,
    submitter: PrincipalId,
    payer: PrincipalId,
    executor: PrincipalId,
    agreement: Digest384,
    capability: Digest384,
    authorization_scope_commitment: [u8; 32],
    assurance: SettlementAssuranceClassV1,
    amount: u128,
    unit: Digest384,
    settlement_policy_version: u16,
    reputation_policy_version: u16,
    logical_time: u64,
}

impl SettlementInstructionV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        finality: EvidenceFinalityReferenceV1,
        submitter: PrincipalId,
        payer: PrincipalId,
        executor: PrincipalId,
        agreement: Digest384,
        capability: Digest384,
        authorization_scope_commitment: [u8; 32],
        assurance: SettlementAssuranceClassV1,
        amount: u128,
        unit: Digest384,
        settlement_policy_version: u16,
        reputation_policy_version: u16,
        logical_time: u64,
    ) -> Result<Self, EvidenceSettlementError> {
        if submitter.digest() == &Digest384::ZERO
            || payer.digest() == &Digest384::ZERO
            || executor.digest() == &Digest384::ZERO
            || payer == executor
            || agreement == Digest384::ZERO
            || capability == Digest384::ZERO
            || authorization_scope_commitment == [0; 32]
            || amount == 0
            || unit == Digest384::ZERO
            || settlement_policy_version == 0
            || reputation_policy_version == 0
            || logical_time == 0
        {
            return Err(EvidenceSettlementError::InvalidInstruction);
        }
        Ok(Self {
            finality,
            submitter,
            payer,
            executor,
            agreement,
            capability,
            authorization_scope_commitment,
            assurance,
            amount,
            unit,
            settlement_policy_version,
            reputation_policy_version,
            logical_time,
        })
    }

    pub fn settlement_id(&self) -> Result<Digest384, EvidenceSettlementError> {
        commit(DomainTag::CANONICAL_VALUE, self).map_err(|_| EvidenceSettlementError::Encoding)
    }

    pub fn idempotency_id(&self) -> Result<Digest384, EvidenceSettlementError> {
        commit(
            DomainTag::CANONICAL_VALUE,
            &SettlementIdempotencyKeyV1 {
                evidence_anchor_commitment: self.finality.evidence_anchor_commitment,
                agreement: self.agreement,
                settlement_policy_version: self.settlement_policy_version,
            },
        )
        .map_err(|_| EvidenceSettlementError::Encoding)
    }

    pub const fn finality(&self) -> &EvidenceFinalityReferenceV1 {
        &self.finality
    }
    pub const fn submitter(&self) -> PrincipalId {
        self.submitter
    }
    pub const fn payer(&self) -> PrincipalId {
        self.payer
    }
    pub const fn executor(&self) -> PrincipalId {
        self.executor
    }
    pub const fn agreement(&self) -> Digest384 {
        self.agreement
    }
    pub const fn capability(&self) -> Digest384 {
        self.capability
    }
    pub const fn assurance(&self) -> SettlementAssuranceClassV1 {
        self.assurance
    }
    pub const fn amount(&self) -> u128 {
        self.amount
    }
    pub const fn unit(&self) -> Digest384 {
        self.unit
    }
    pub const fn settlement_policy_version(&self) -> u16 {
        self.settlement_policy_version
    }
    pub const fn reputation_policy_version(&self) -> u16 {
        self.reputation_policy_version
    }
    pub const fn logical_time(&self) -> u64 {
        self.logical_time
    }

    pub const fn authorization_scope_commitment(&self) -> &[u8; 32] {
        &self.authorization_scope_commitment
    }
}

impl CanonicalEncode for SettlementInstructionV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.finality.encode(encoder)?;
        self.submitter.encode(encoder)?;
        self.payer.encode(encoder)?;
        self.executor.encode(encoder)?;
        self.agreement.encode(encoder)?;
        self.capability.encode(encoder)?;
        encoder.write_raw(&self.authorization_scope_commitment)?;
        self.assurance.encode(encoder)?;
        self.amount.encode(encoder)?;
        self.unit.encode(encoder)?;
        self.settlement_policy_version.encode(encoder)?;
        self.reputation_policy_version.encode(encoder)?;
        self.logical_time.encode(encoder)
    }
}

impl CanonicalDecode for SettlementInstructionV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            EvidenceFinalityReferenceV1::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            PrincipalId::decode(decoder)?,
            Digest384::decode(decoder)?,
            Digest384::decode(decoder)?,
            decoder.read_array()?,
            SettlementAssuranceClassV1::decode(decoder)?,
            u128::decode(decoder)?,
            Digest384::decode(decoder)?,
            u16::decode(decoder)?,
            u16::decode(decoder)?,
            u64::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid settlement instruction"))
    }
}

impl CanonicalType for SettlementInstructionV1 {
    const TYPE_TAG: u16 = 0x01cb;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        EvidenceFinalityReferenceV1::MAX_ENCODED_LEN + 48 * 6 + 32 + 1 + 16 + 2 + 2 + 8;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SettlementIdempotencyKeyV1 {
    evidence_anchor_commitment: [u8; 32],
    agreement: Digest384,
    settlement_policy_version: u16,
}

impl CanonicalEncode for SettlementIdempotencyKeyV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_raw(&self.evidence_anchor_commitment)?;
        self.agreement.encode(encoder)?;
        self.settlement_policy_version.encode(encoder)
    }
}

impl CanonicalDecode for SettlementIdempotencyKeyV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            evidence_anchor_commitment: decoder.read_array()?,
            agreement: Digest384::decode(decoder)?,
            settlement_policy_version: u16::decode(decoder)?,
        };
        if value.evidence_anchor_commitment == [0; 32]
            || value.agreement == Digest384::ZERO
            || value.settlement_policy_version == 0
        {
            return Err(DecodeError::InvalidValue("invalid settlement idempotency key"));
        }
        Ok(value)
    }
}

impl CanonicalType for SettlementIdempotencyKeyV1 {
    const TYPE_TAG: u16 = 0x01cc;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 32 + 48 + 2;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountBalanceV1 {
    owner: PrincipalId,
    unit: Digest384,
    balance: u128,
}

impl AccountBalanceV1 {
    pub fn new(
        owner: PrincipalId,
        unit: Digest384,
        balance: u128,
    ) -> Result<Self, EvidenceSettlementError> {
        if owner.digest() == &Digest384::ZERO || unit == Digest384::ZERO {
            return Err(EvidenceSettlementError::InvalidAccount);
        }
        Ok(Self { owner, unit, balance })
    }
    pub const fn owner(&self) -> PrincipalId {
        self.owner
    }
    pub const fn unit(&self) -> Digest384 {
        self.unit
    }
    pub const fn balance(&self) -> u128 {
        self.balance
    }
}

impl CanonicalEncode for AccountBalanceV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.owner.encode(encoder)?;
        self.unit.encode(encoder)?;
        self.balance.encode(encoder)
    }
}

impl CanonicalDecode for AccountBalanceV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(decoder)?,
            Digest384::decode(decoder)?,
            u128::decode(decoder)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid accounting account"))
    }
}

impl CanonicalType for AccountBalanceV1 {
    const TYPE_TAG: u16 = 0x01cd;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 48 + 16;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementRecordV1 {
    settlement_id: Digest384,
    idempotency_id: Digest384,
    instruction: SettlementInstructionV1,
    sequence: u64,
    payer_before: u128,
    payer_after: u128,
    executor_before: u128,
    executor_after: u128,
    previous_accounting_commitment: Digest384,
    resulting_accounting_commitment: Digest384,
}

impl SettlementRecordV1 {
    pub const fn settlement_id(&self) -> Digest384 {
        self.settlement_id
    }
    pub const fn idempotency_id(&self) -> Digest384 {
        self.idempotency_id
    }
    pub const fn instruction(&self) -> &SettlementInstructionV1 {
        &self.instruction
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn payer_before(&self) -> u128 {
        self.payer_before
    }
    pub const fn payer_after(&self) -> u128 {
        self.payer_after
    }
    pub const fn executor_before(&self) -> u128 {
        self.executor_before
    }
    pub const fn executor_after(&self) -> u128 {
        self.executor_after
    }
    pub const fn previous_accounting_commitment(&self) -> Digest384 {
        self.previous_accounting_commitment
    }
    pub const fn resulting_accounting_commitment(&self) -> Digest384 {
        self.resulting_accounting_commitment
    }
}

impl CanonicalEncode for SettlementRecordV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.settlement_id.encode(encoder)?;
        self.idempotency_id.encode(encoder)?;
        self.instruction.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.payer_before.encode(encoder)?;
        self.payer_after.encode(encoder)?;
        self.executor_before.encode(encoder)?;
        self.executor_after.encode(encoder)?;
        self.previous_accounting_commitment.encode(encoder)?;
        self.resulting_accounting_commitment.encode(encoder)
    }
}

impl CanonicalDecode for SettlementRecordV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            settlement_id: Digest384::decode(decoder)?,
            idempotency_id: Digest384::decode(decoder)?,
            instruction: SettlementInstructionV1::decode(decoder)?,
            sequence: u64::decode(decoder)?,
            payer_before: u128::decode(decoder)?,
            payer_after: u128::decode(decoder)?,
            executor_before: u128::decode(decoder)?,
            executor_after: u128::decode(decoder)?,
            previous_accounting_commitment: Digest384::decode(decoder)?,
            resulting_accounting_commitment: Digest384::decode(decoder)?,
        };
        if value.sequence == 0
            || value.settlement_id
                != value
                    .instruction
                    .settlement_id()
                    .map_err(|_| DecodeError::InvalidValue("invalid settlement ID"))?
            || value.idempotency_id
                != value
                    .instruction
                    .idempotency_id()
                    .map_err(|_| DecodeError::InvalidValue("invalid idempotency ID"))?
            || value.payer_before.checked_sub(value.instruction.amount()) != Some(value.payer_after)
            || value.executor_before.checked_add(value.instruction.amount())
                != Some(value.executor_after)
            || value.previous_accounting_commitment == Digest384::ZERO
            || value.resulting_accounting_commitment == Digest384::ZERO
        {
            return Err(DecodeError::InvalidValue("invalid settlement record"));
        }
        Ok(value)
    }
}

impl CanonicalType for SettlementRecordV1 {
    const TYPE_TAG: u16 = 0x01ce;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 4 + SettlementInstructionV1::MAX_ENCODED_LEN + 8 + 16 * 4;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReputationEventV1 {
    event_id: Digest384,
    settlement_id: Digest384,
    evidence_anchor_commitment: [u8; 32],
    executor: PrincipalId,
    capability: Digest384,
    assurance: SettlementAssuranceClassV1,
    settlement_completed: bool,
    sequence: u64,
    policy_version: u16,
}

impl ReputationEventV1 {
    pub const fn event_id(&self) -> Digest384 {
        self.event_id
    }
    pub const fn settlement_id(&self) -> Digest384 {
        self.settlement_id
    }
    pub const fn executor(&self) -> PrincipalId {
        self.executor
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn evidence_anchor_commitment(&self) -> &[u8; 32] {
        &self.evidence_anchor_commitment
    }
    pub const fn capability(&self) -> Digest384 {
        self.capability
    }
    pub const fn assurance(&self) -> SettlementAssuranceClassV1 {
        self.assurance
    }
    pub const fn settlement_completed(&self) -> bool {
        self.settlement_completed
    }
    pub const fn policy_version(&self) -> u16 {
        self.policy_version
    }
}

impl CanonicalEncode for ReputationEventV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.event_id.encode(encoder)?;
        self.settlement_id.encode(encoder)?;
        encoder.write_raw(&self.evidence_anchor_commitment)?;
        self.executor.encode(encoder)?;
        self.capability.encode(encoder)?;
        self.assurance.encode(encoder)?;
        self.settlement_completed.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.policy_version.encode(encoder)
    }
}

impl CanonicalDecode for ReputationEventV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            event_id: Digest384::decode(decoder)?,
            settlement_id: Digest384::decode(decoder)?,
            evidence_anchor_commitment: decoder.read_array()?,
            executor: PrincipalId::decode(decoder)?,
            capability: Digest384::decode(decoder)?,
            assurance: SettlementAssuranceClassV1::decode(decoder)?,
            settlement_completed: bool::decode(decoder)?,
            sequence: u64::decode(decoder)?,
            policy_version: u16::decode(decoder)?,
        };
        if !value.settlement_completed
            || value.event_id == Digest384::ZERO
            || value.settlement_id == Digest384::ZERO
            || value.evidence_anchor_commitment == [0; 32]
            || value.executor.digest() == &Digest384::ZERO
            || value.capability == Digest384::ZERO
            || value.sequence == 0
            || value.policy_version == 0
        {
            return Err(DecodeError::InvalidValue("invalid reputation event"));
        }
        Ok(value)
    }
}

impl CanonicalType for ReputationEventV1 {
    const TYPE_TAG: u16 = 0x01cf;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 4 + 32 + 1 + 1 + 8 + 2;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementOutcomeV1 {
    pub record: SettlementRecordV1,
    pub reputation_event: ReputationEventV1,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceSettlementLedger {
    chain: ChainId,
    unit: Digest384,
    settlement_authority: PrincipalId,
    accounts: BTreeMap<PrincipalId, u128>,
    settlements: BTreeMap<Digest384, SettlementRecordV1>,
    idempotency: BTreeMap<Digest384, Digest384>,
    reputation_events: Vec<ReputationEventV1>,
    sequence: u64,
}

impl EvidenceSettlementLedger {
    pub fn new(
        chain: ChainId,
        unit: Digest384,
        settlement_authority: PrincipalId,
        accounts: Vec<AccountBalanceV1>,
    ) -> Result<Self, EvidenceSettlementError> {
        if chain.digest() == &Digest384::ZERO
            || unit == Digest384::ZERO
            || settlement_authority.digest() == &Digest384::ZERO
            || accounts.is_empty()
            || accounts.len() > MAX_ACCOUNTS
        {
            return Err(EvidenceSettlementError::InvalidAccount);
        }
        let mut balances = BTreeMap::new();
        for account in accounts {
            if account.unit != unit || balances.insert(account.owner, account.balance).is_some() {
                return Err(EvidenceSettlementError::InvalidAccount);
            }
        }
        Ok(Self {
            chain,
            unit,
            settlement_authority,
            accounts: balances,
            settlements: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            reputation_events: Vec::new(),
            sequence: 0,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn settle(
        &mut self,
        instruction: SettlementInstructionV1,
        evidence: &AnchorFinalizedEvidenceV1,
        authenticated_submitter: PrincipalId,
        verify_proofs: impl FnOnce(&[u8], &[u8], TransactionId, u64, Digest384) -> bool,
    ) -> Result<SettlementOutcomeV1, EvidenceSettlementError> {
        if instruction.submitter != authenticated_submitter
            || authenticated_submitter != self.settlement_authority
            || instruction.finality.chain != self.chain
            || instruction.unit != self.unit
            || instruction.assurance != SettlementAssuranceClassV1::Cryptographic
        {
            return Err(EvidenceSettlementError::AuthorityDenied);
        }
        let expected_statement = instruction.finality.expected_statement()?;
        verify_anchor_evidence(
            evidence,
            &expected_statement,
            instruction.finality.chain,
            instruction.finality.genesis,
            instruction.finality.protocol_revision,
            instruction.finality.verifier_revision,
            verify_proofs,
        )
        .map_err(|_| EvidenceSettlementError::InvalidFinality)?;
        if evidence.transaction() != instruction.finality.transaction
            || evidence.finalized_height() != instruction.finality.finalized_height
            || evidence.finalized_block() != instruction.finality.finalized_block
        {
            return Err(EvidenceSettlementError::InvalidFinality);
        }

        let settlement_id = instruction.settlement_id()?;
        let idempotency_id = instruction.idempotency_id()?;
        if let Some(existing_id) = self.idempotency.get(&idempotency_id) {
            if *existing_id != settlement_id {
                return Err(EvidenceSettlementError::IdempotencyConflict);
            }
            let record = self
                .settlements
                .get(existing_id)
                .cloned()
                .ok_or(EvidenceSettlementError::InvalidState)?;
            let reputation_event = self
                .reputation_events
                .iter()
                .find(|event| event.settlement_id == *existing_id)
                .cloned()
                .ok_or(EvidenceSettlementError::InvalidState)?;
            return Ok(SettlementOutcomeV1 { record, reputation_event, duplicate: true });
        }
        if self.settlements.len() >= MAX_SETTLEMENTS
            || self.reputation_events.len() >= MAX_REPUTATION_EVENTS
        {
            return Err(EvidenceSettlementError::Capacity);
        }

        let payer_before = *self
            .accounts
            .get(&instruction.payer)
            .ok_or(EvidenceSettlementError::UnknownAccount)?;
        let executor_before = *self
            .accounts
            .get(&instruction.executor)
            .ok_or(EvidenceSettlementError::UnknownAccount)?;
        let payer_after = payer_before
            .checked_sub(instruction.amount)
            .ok_or(EvidenceSettlementError::InsufficientBalance)?;
        let executor_after = executor_before
            .checked_add(instruction.amount)
            .ok_or(EvidenceSettlementError::Overflow)?;
        let previous_accounting_commitment = self.accounting_commitment()?;
        let mut next_accounts = self.accounts.clone();
        next_accounts.insert(instruction.payer, payer_after);
        next_accounts.insert(instruction.executor, executor_after);
        let next_sequence =
            self.sequence.checked_add(1).ok_or(EvidenceSettlementError::Overflow)?;
        let resulting_accounting_commitment =
            Self::accounting_commitment_for(self.chain, self.unit, next_sequence, &next_accounts)?;
        let record = SettlementRecordV1 {
            settlement_id,
            idempotency_id,
            instruction: instruction.clone(),
            sequence: next_sequence,
            payer_before,
            payer_after,
            executor_before,
            executor_after,
            previous_accounting_commitment,
            resulting_accounting_commitment,
        };
        let event_id = commit(
            DomainTag::CANONICAL_VALUE,
            &ReputationEventKeyV1 {
                settlement_id,
                executor: instruction.executor,
                sequence: next_sequence,
                policy_version: instruction.reputation_policy_version,
            },
        )
        .map_err(|_| EvidenceSettlementError::Encoding)?;
        let reputation_event = ReputationEventV1 {
            event_id,
            settlement_id,
            evidence_anchor_commitment: instruction.finality.evidence_anchor_commitment,
            executor: instruction.executor,
            capability: instruction.capability,
            assurance: instruction.assurance,
            settlement_completed: true,
            sequence: next_sequence,
            policy_version: instruction.reputation_policy_version,
        };
        self.accounts = next_accounts;
        self.sequence = next_sequence;
        self.idempotency.insert(idempotency_id, settlement_id);
        self.settlements.insert(settlement_id, record.clone());
        self.reputation_events.push(reputation_event.clone());
        Ok(SettlementOutcomeV1 { record, reputation_event, duplicate: false })
    }

    pub fn balance(&self, owner: PrincipalId) -> Option<AccountBalanceV1> {
        self.accounts
            .get(&owner)
            .copied()
            .and_then(|balance| AccountBalanceV1::new(owner, self.unit, balance).ok())
    }

    pub fn settlement(&self, settlement_id: Digest384) -> Option<&SettlementRecordV1> {
        self.settlements.get(&settlement_id)
    }

    pub fn settlements_for_evidence(&self, commitment: &[u8; 32]) -> Vec<&SettlementRecordV1> {
        self.settlements
            .values()
            .filter(|record| record.instruction.finality.evidence_anchor_commitment() == commitment)
            .collect()
    }

    pub fn settlements_for_account(&self, owner: PrincipalId) -> Vec<&SettlementRecordV1> {
        self.settlements
            .values()
            .filter(|record| {
                record.instruction.payer == owner || record.instruction.executor == owner
            })
            .collect()
    }

    pub fn reputation_events_for_executor(&self, executor: PrincipalId) -> Vec<&ReputationEventV1> {
        self.reputation_events.iter().filter(|event| event.executor == executor).collect()
    }

    pub fn total_balance(&self) -> Result<u128, EvidenceSettlementError> {
        self.accounts.values().try_fold(0_u128, |total, balance| {
            total.checked_add(*balance).ok_or(EvidenceSettlementError::Overflow)
        })
    }

    pub fn accounting_commitment(&self) -> Result<Digest384, EvidenceSettlementError> {
        Self::accounting_commitment_for(self.chain, self.unit, self.sequence, &self.accounts)
    }

    fn accounting_commitment_for(
        chain: ChainId,
        unit: Digest384,
        sequence: u64,
        accounts: &BTreeMap<PrincipalId, u128>,
    ) -> Result<Digest384, EvidenceSettlementError> {
        commit(
            DomainTag::CANONICAL_VALUE,
            &AccountingViewV1 {
                chain,
                unit,
                sequence,
                accounts: accounts.iter().map(|(owner, balance)| (*owner, *balance)).collect(),
            },
        )
        .map_err(|_| EvidenceSettlementError::Encoding)
    }

    pub fn state_commitment(&self) -> Result<Digest384, EvidenceSettlementError> {
        commit(DomainTag::CANONICAL_VALUE, &self.snapshot_value())
            .map_err(|_| EvidenceSettlementError::Encoding)
    }

    pub fn settlement_anchor_statement(
        &self,
    ) -> Result<DigestAnchorStatementV1, EvidenceSettlementError> {
        let state = self.state_commitment()?;
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&state.as_bytes()[..32]);
        DigestAnchorStatementV1::new(DCN_SETTLEMENT_STATE_DOMAIN.to_vec(), digest)
            .map_err(|_| EvidenceSettlementError::Encoding)
    }

    fn snapshot_value(&self) -> SettlementLedgerSnapshotV1 {
        SettlementLedgerSnapshotV1 {
            chain: self.chain,
            unit: self.unit,
            settlement_authority: self.settlement_authority,
            accounts: self.accounts.iter().map(|(owner, balance)| (*owner, *balance)).collect(),
            settlements: self
                .settlements
                .iter()
                .map(|(id, record)| (*id, record.clone()))
                .collect(),
            idempotency: self.idempotency.iter().map(|(key, value)| (*key, *value)).collect(),
            reputation_events: self.reputation_events.clone(),
            sequence: self.sequence,
        }
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, EvidenceSettlementError> {
        encode_envelope(&self.snapshot_value()).map_err(|_| EvidenceSettlementError::Encoding)
    }

    pub fn restore(bytes: &[u8]) -> Result<Self, EvidenceSettlementError> {
        let snapshot = decode_envelope::<SettlementLedgerSnapshotV1>(bytes)
            .map_err(|_| EvidenceSettlementError::InvalidState)?;
        snapshot.into_ledger()
    }

    fn validate_restored_state(&self) -> Result<(), EvidenceSettlementError> {
        let mut records: Vec<&SettlementRecordV1> = self.settlements.values().collect();
        records.sort_by_key(|record| record.sequence);
        if records.iter().enumerate().any(|(index, record)| {
            record.sequence != index as u64 + 1
                || record.instruction.finality.chain != self.chain
                || record.instruction.unit != self.unit
                || record.instruction.submitter != self.settlement_authority
        }) {
            return Err(EvidenceSettlementError::InvalidState);
        }

        let mut accounts = self.accounts.clone();
        let mut sequence = self.sequence;
        for record in records.into_iter().rev() {
            let instruction = &record.instruction;
            if Self::accounting_commitment_for(self.chain, self.unit, sequence, &accounts)?
                != record.resulting_accounting_commitment
                || accounts.get(&instruction.payer) != Some(&record.payer_after)
                || accounts.get(&instruction.executor) != Some(&record.executor_after)
            {
                return Err(EvidenceSettlementError::InvalidState);
            }
            accounts.insert(instruction.payer, record.payer_before);
            accounts.insert(instruction.executor, record.executor_before);
            sequence = sequence.checked_sub(1).ok_or(EvidenceSettlementError::InvalidState)?;
            if Self::accounting_commitment_for(self.chain, self.unit, sequence, &accounts)?
                != record.previous_accounting_commitment
            {
                return Err(EvidenceSettlementError::InvalidState);
            }

            let event = self
                .reputation_events
                .get(record.sequence as usize - 1)
                .ok_or(EvidenceSettlementError::InvalidState)?;
            let expected_event_id = commit(
                DomainTag::CANONICAL_VALUE,
                &ReputationEventKeyV1 {
                    settlement_id: record.settlement_id,
                    executor: instruction.executor,
                    sequence: record.sequence,
                    policy_version: instruction.reputation_policy_version,
                },
            )
            .map_err(|_| EvidenceSettlementError::Encoding)?;
            if event.event_id != expected_event_id
                || event.settlement_id != record.settlement_id
                || event.evidence_anchor_commitment
                    != instruction.finality.evidence_anchor_commitment
                || event.executor != instruction.executor
                || event.capability != instruction.capability
                || event.assurance != instruction.assurance
                || !event.settlement_completed
                || event.sequence != record.sequence
                || event.policy_version != instruction.reputation_policy_version
            {
                return Err(EvidenceSettlementError::InvalidState);
            }
        }
        if sequence != 0 {
            return Err(EvidenceSettlementError::InvalidState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReputationEventKeyV1 {
    settlement_id: Digest384,
    executor: PrincipalId,
    sequence: u64,
    policy_version: u16,
}

impl CanonicalEncode for ReputationEventKeyV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.settlement_id.encode(encoder)?;
        self.executor.encode(encoder)?;
        self.sequence.encode(encoder)?;
        self.policy_version.encode(encoder)
    }
}

impl CanonicalDecode for ReputationEventKeyV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            settlement_id: Digest384::decode(decoder)?,
            executor: PrincipalId::decode(decoder)?,
            sequence: u64::decode(decoder)?,
            policy_version: u16::decode(decoder)?,
        };
        if value.settlement_id == Digest384::ZERO
            || value.executor.digest() == &Digest384::ZERO
            || value.sequence == 0
            || value.policy_version == 0
        {
            return Err(DecodeError::InvalidValue("invalid reputation event key"));
        }
        Ok(value)
    }
}

impl CanonicalType for ReputationEventKeyV1 {
    const TYPE_TAG: u16 = 0x01d0;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 48 + 8 + 2;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AccountingViewV1 {
    chain: ChainId,
    unit: Digest384,
    sequence: u64,
    accounts: Vec<(PrincipalId, u128)>,
}

impl CanonicalEncode for AccountingViewV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain.encode(encoder)?;
        self.unit.encode(encoder)?;
        self.sequence.encode(encoder)?;
        encoder.write_length(self.accounts.len(), MAX_ACCOUNTS)?;
        for (owner, balance) in &self.accounts {
            owner.encode(encoder)?;
            balance.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for AccountingViewV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain = ChainId::decode(decoder)?;
        let unit = Digest384::decode(decoder)?;
        let sequence = u64::decode(decoder)?;
        let count = decoder.read_length(MAX_ACCOUNTS)?;
        let mut accounts = Vec::with_capacity(count);
        for _ in 0..count {
            accounts.push((PrincipalId::decode(decoder)?, u128::decode(decoder)?));
        }
        if chain.digest() == &Digest384::ZERO
            || unit == Digest384::ZERO
            || accounts.is_empty()
            || !strictly_ordered(&accounts)
        {
            return Err(DecodeError::InvalidValue("invalid accounting view"));
        }
        Ok(Self { chain, unit, sequence, accounts })
    }
}

impl CanonicalType for AccountingViewV1 {
    const TYPE_TAG: u16 = 0x01d1;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 48 + 8 + 3 + MAX_ACCOUNTS * (48 + 16);
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SettlementLedgerSnapshotV1 {
    chain: ChainId,
    unit: Digest384,
    settlement_authority: PrincipalId,
    accounts: Vec<(PrincipalId, u128)>,
    settlements: Vec<(Digest384, SettlementRecordV1)>,
    idempotency: Vec<(Digest384, Digest384)>,
    reputation_events: Vec<ReputationEventV1>,
    sequence: u64,
}

impl SettlementLedgerSnapshotV1 {
    fn into_ledger(self) -> Result<EvidenceSettlementLedger, EvidenceSettlementError> {
        if self.accounts.is_empty()
            || self.accounts.len() > MAX_ACCOUNTS
            || self.settlements.len() > MAX_SETTLEMENTS
            || self.idempotency.len() != self.settlements.len()
            || self.reputation_events.len() != self.settlements.len()
            || self.sequence != self.settlements.len() as u64
            || !strictly_ordered(&self.accounts)
            || !strictly_ordered(&self.settlements)
            || !strictly_ordered(&self.idempotency)
        {
            return Err(EvidenceSettlementError::InvalidState);
        }
        let ledger = EvidenceSettlementLedger {
            chain: self.chain,
            unit: self.unit,
            settlement_authority: self.settlement_authority,
            accounts: self.accounts.into_iter().collect(),
            settlements: self.settlements.into_iter().collect(),
            idempotency: self.idempotency.into_iter().collect(),
            reputation_events: self.reputation_events,
            sequence: self.sequence,
        };
        if ledger.chain.digest() == &Digest384::ZERO
            || ledger.unit == Digest384::ZERO
            || ledger.settlement_authority.digest() == &Digest384::ZERO
            || ledger.settlements.iter().any(|(id, record)| {
                *id != record.settlement_id
                    || ledger.idempotency.get(&record.idempotency_id) != Some(id)
            })
            || ledger.reputation_events.iter().enumerate().any(|(index, event)| {
                event.sequence != index as u64 + 1
                    || !ledger.settlements.contains_key(&event.settlement_id)
            })
        {
            return Err(EvidenceSettlementError::InvalidState);
        }
        ledger.validate_restored_state()?;
        Ok(ledger)
    }
}

fn strictly_ordered<K: Ord, V>(entries: &[(K, V)]) -> bool {
    entries.windows(2).all(|pair| pair[0].0 < pair[1].0)
}

impl CanonicalEncode for SettlementLedgerSnapshotV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain.encode(encoder)?;
        self.unit.encode(encoder)?;
        self.settlement_authority.encode(encoder)?;
        encoder.write_length(self.accounts.len(), MAX_ACCOUNTS)?;
        for (owner, balance) in &self.accounts {
            owner.encode(encoder)?;
            balance.encode(encoder)?;
        }
        encoder.write_length(self.settlements.len(), MAX_SETTLEMENTS)?;
        for (id, record) in &self.settlements {
            id.encode(encoder)?;
            record.encode(encoder)?;
        }
        encoder.write_length(self.idempotency.len(), MAX_SETTLEMENTS)?;
        for (key, value) in &self.idempotency {
            key.encode(encoder)?;
            value.encode(encoder)?;
        }
        encoder.write_length(self.reputation_events.len(), MAX_REPUTATION_EVENTS)?;
        for event in &self.reputation_events {
            event.encode(encoder)?;
        }
        self.sequence.encode(encoder)
    }
}

impl CanonicalDecode for SettlementLedgerSnapshotV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain = ChainId::decode(decoder)?;
        let unit = Digest384::decode(decoder)?;
        let settlement_authority = PrincipalId::decode(decoder)?;
        let account_count = decoder.read_length(MAX_ACCOUNTS)?;
        let mut accounts = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            accounts.push((PrincipalId::decode(decoder)?, u128::decode(decoder)?));
        }
        let settlement_count = decoder.read_length(MAX_SETTLEMENTS)?;
        let mut settlements = Vec::with_capacity(settlement_count);
        for _ in 0..settlement_count {
            settlements.push((Digest384::decode(decoder)?, SettlementRecordV1::decode(decoder)?));
        }
        let idempotency_count = decoder.read_length(MAX_SETTLEMENTS)?;
        let mut idempotency = Vec::with_capacity(idempotency_count);
        for _ in 0..idempotency_count {
            idempotency.push((Digest384::decode(decoder)?, Digest384::decode(decoder)?));
        }
        let event_count = decoder.read_length(MAX_REPUTATION_EVENTS)?;
        let mut reputation_events = Vec::with_capacity(event_count);
        for _ in 0..event_count {
            reputation_events.push(ReputationEventV1::decode(decoder)?);
        }
        let snapshot = Self {
            chain,
            unit,
            settlement_authority,
            accounts,
            settlements,
            idempotency,
            reputation_events,
            sequence: u64::decode(decoder)?,
        };
        snapshot
            .clone()
            .into_ledger()
            .map_err(|_| DecodeError::InvalidValue("invalid settlement ledger snapshot"))?;
        Ok(snapshot)
    }
}

impl CanonicalType for SettlementLedgerSnapshotV1 {
    const TYPE_TAG: u16 = 0x01d2;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 * 3
        + 3
        + MAX_ACCOUNTS * (48 + 16)
        + 3
        + MAX_SETTLEMENTS * (48 + SettlementRecordV1::MAX_ENCODED_LEN)
        + 3
        + MAX_SETTLEMENTS * 96
        + 3
        + MAX_REPUTATION_EVENTS * ReputationEventV1::MAX_ENCODED_LEN
        + 8;
}

#[cfg(feature = "std")]
pub struct DurableEvidenceSettlementLedger {
    path: std::path::PathBuf,
    ledger: EvidenceSettlementLedger,
}

#[cfg(feature = "std")]
impl DurableEvidenceSettlementLedger {
    pub fn create(
        path: impl AsRef<std::path::Path>,
        ledger: EvidenceSettlementLedger,
    ) -> Result<Self, EvidenceSettlementError> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(EvidenceSettlementError::Persistence);
        }
        let value = Self { path, ledger };
        value.persist(&value.ledger)?;
        Ok(value)
    }

    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, EvidenceSettlementError> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path).map_err(|_| EvidenceSettlementError::Persistence)?;
        let ledger = EvidenceSettlementLedger::restore(&bytes)?;
        Ok(Self { path, ledger })
    }

    pub const fn ledger(&self) -> &EvidenceSettlementLedger {
        &self.ledger
    }

    pub fn settle(
        &mut self,
        instruction: SettlementInstructionV1,
        evidence: &AnchorFinalizedEvidenceV1,
        authenticated_submitter: PrincipalId,
        verify_proofs: impl FnOnce(&[u8], &[u8], TransactionId, u64, Digest384) -> bool,
    ) -> Result<SettlementOutcomeV1, EvidenceSettlementError> {
        let mut candidate = self.ledger.clone();
        let outcome =
            candidate.settle(instruction, evidence, authenticated_submitter, verify_proofs)?;
        self.persist(&candidate)?;
        self.ledger = candidate;
        Ok(outcome)
    }

    fn persist(&self, ledger: &EvidenceSettlementLedger) -> Result<(), EvidenceSettlementError> {
        let bytes = ledger.snapshot()?;
        let parent = self.path.parent().ok_or(EvidenceSettlementError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| EvidenceSettlementError::Persistence)?;
        let temporary = self.path.with_extension("tmp");
        {
            use std::io::Write as _;
            let mut file = std::fs::File::create(&temporary)
                .map_err(|_| EvidenceSettlementError::Persistence)?;
            file.write_all(&bytes).map_err(|_| EvidenceSettlementError::Persistence)?;
            file.sync_all().map_err(|_| EvidenceSettlementError::Persistence)?;
        }
        std::fs::rename(&temporary, &self.path)
            .map_err(|_| EvidenceSettlementError::Persistence)?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| EvidenceSettlementError::Persistence)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceSettlementError {
    InvalidInstruction,
    InvalidAccount,
    InvalidFinality,
    AuthorityDenied,
    UnknownAccount,
    InsufficientBalance,
    IdempotencyConflict,
    Capacity,
    Overflow,
    Encoding,
    InvalidState,
    Persistence,
}

impl From<crate::AnchorError> for EvidenceSettlementError {
    fn from(_: crate::AnchorError) -> Self {
        Self::InvalidInstruction
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnchorFinalizedEvidenceV1;
    use alloc::vec;

    fn d(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn p(byte: u8) -> PrincipalId {
        PrincipalId::new(d(byte))
    }

    fn fixture() -> (EvidenceSettlementLedger, SettlementInstructionV1, AnchorFinalizedEvidenceV1) {
        let chain = ChainId::new(d(1));
        let genesis = d(2);
        let anchor_commitment = [0xca; 32];
        let statement =
            DigestAnchorStatementV1::new(DCN_VERIFIED_EVIDENCE_DOMAIN.to_vec(), anchor_commitment)
                .unwrap();
        let reference = statement.submission_reference().unwrap();
        let transaction = TransactionId::new(d(3));
        let finality = EvidenceFinalityReferenceV1::new(
            chain,
            genesis,
            anchor_commitment,
            reference,
            transaction,
            2,
            d(4),
            1,
            1,
        )
        .unwrap();
        let instruction = SettlementInstructionV1::new(
            finality,
            p(5),
            p(6),
            p(7),
            d(8),
            d(9),
            [10; 32],
            SettlementAssuranceClassV1::Cryptographic,
            125,
            d(11),
            1,
            1,
            3,
        )
        .unwrap();
        let evidence = AnchorFinalizedEvidenceV1::new(
            chain,
            genesis,
            transaction,
            vec![3],
            2,
            d(4),
            statement,
            None,
            None,
            1,
            1,
            vec![1],
            vec![2],
        )
        .unwrap();
        let ledger = EvidenceSettlementLedger::new(
            chain,
            d(11),
            p(5),
            vec![
                AccountBalanceV1::new(p(6), d(11), 1_000).unwrap(),
                AccountBalanceV1::new(p(7), d(11), 50).unwrap(),
            ],
        )
        .unwrap();
        (ledger, instruction, evidence)
    }

    #[test]
    fn finalized_evidence_settlement_conserves_value_and_emits_one_event() {
        let (mut ledger, instruction, evidence) = fixture();
        let before = ledger.total_balance().unwrap();
        let outcome =
            ledger.settle(instruction.clone(), &evidence, p(5), |_, _, _, _, _| true).unwrap();
        assert!(!outcome.duplicate);
        assert_eq!(ledger.balance(p(6)).unwrap().balance(), 875);
        assert_eq!(ledger.balance(p(7)).unwrap().balance(), 175);
        assert_eq!(ledger.total_balance().unwrap(), before);
        assert_eq!(
            ledger
                .settlements_for_evidence(instruction.finality.evidence_anchor_commitment())
                .len(),
            1
        );
        assert_eq!(ledger.settlement(outcome.record.settlement_id()), Some(&outcome.record));
        assert_eq!(ledger.settlements_for_account(p(6)), vec![&outcome.record]);
        assert_eq!(ledger.settlements_for_account(p(7)), vec![&outcome.record]);
        assert_eq!(ledger.reputation_events_for_executor(p(7)).len(), 1);
        let duplicate = ledger.settle(instruction, &evidence, p(5), |_, _, _, _, _| true).unwrap();
        assert!(duplicate.duplicate);
        assert_eq!(ledger.total_balance().unwrap(), before);
    }

    #[test]
    fn finality_authority_balance_and_replay_substitutions_fail_closed() {
        let (ledger, instruction, evidence) = fixture();
        let mut wrong_authority = ledger.clone();
        assert_eq!(
            wrong_authority.settle(instruction.clone(), &evidence, p(12), |_, _, _, _, _| true),
            Err(EvidenceSettlementError::AuthorityDenied)
        );
        let mut bad_finality = ledger.clone();
        assert_eq!(
            bad_finality.settle(instruction.clone(), &evidence, p(5), |_, _, _, _, _| false),
            Err(EvidenceSettlementError::InvalidFinality)
        );
        let mut settled = ledger;
        settled.settle(instruction.clone(), &evidence, p(5), |_, _, _, _, _| true).unwrap();
        let mut changed = instruction.clone();
        changed.amount = 126;
        assert_eq!(
            settled.settle(changed, &evidence, p(5), |_, _, _, _, _| true),
            Err(EvidenceSettlementError::IdempotencyConflict)
        );
    }

    #[test]
    fn evidence_account_and_finality_substitutions_are_atomic() {
        let (ledger, instruction, evidence) = fixture();
        let mut cases = Vec::new();

        let mut insufficient = instruction.clone();
        insufficient.amount = 2_000;
        cases.push((insufficient, EvidenceSettlementError::InsufficientBalance));

        let mut wrong_payer = instruction.clone();
        wrong_payer.payer = p(12);
        cases.push((wrong_payer, EvidenceSettlementError::UnknownAccount));

        let mut wrong_executor = instruction.clone();
        wrong_executor.executor = p(13);
        cases.push((wrong_executor, EvidenceSettlementError::UnknownAccount));

        let mut wrong_unit = instruction.clone();
        wrong_unit.unit = d(14);
        cases.push((wrong_unit, EvidenceSettlementError::AuthorityDenied));

        let mut wrong_chain = instruction.clone();
        wrong_chain.finality.chain = ChainId::new(d(15));
        cases.push((wrong_chain, EvidenceSettlementError::AuthorityDenied));

        let mut wrong_height = instruction.clone();
        wrong_height.finality.finalized_height = 3;
        cases.push((wrong_height, EvidenceSettlementError::InvalidFinality));

        let mut wrong_block = instruction.clone();
        wrong_block.finality.finalized_block = d(16);
        cases.push((wrong_block, EvidenceSettlementError::InvalidFinality));

        let mut wrong_evidence = instruction.clone();
        wrong_evidence.finality.evidence_anchor_commitment[0] ^= 1;
        cases.push((wrong_evidence, EvidenceSettlementError::InvalidFinality));

        for (candidate, expected_error) in cases {
            let mut candidate_ledger = ledger.clone();
            let before = candidate_ledger.snapshot().unwrap();
            assert_eq!(
                candidate_ledger.settle(candidate, &evidence, p(5), |_, _, _, _, _| true),
                Err(expected_error)
            );
            assert_eq!(candidate_ledger.snapshot().unwrap(), before);
        }
    }

    #[test]
    fn unsupported_assurance_and_canonical_state_corruption_are_rejected() {
        let mut decoder = Decoder::new(&[2]);
        assert!(SettlementAssuranceClassV1::decode(&mut decoder).is_err());

        let (mut ledger, instruction, evidence) = fixture();
        ledger.settle(instruction, &evidence, p(5), |_, _, _, _, _| true).unwrap();

        let mut corrupted_event = ledger.snapshot_value();
        corrupted_event.reputation_events[0].capability = d(17);
        let bytes = encode_envelope(&corrupted_event).unwrap();
        assert_eq!(
            EvidenceSettlementLedger::restore(&bytes),
            Err(EvidenceSettlementError::InvalidState)
        );

        let mut corrupted_balance = ledger.snapshot_value();
        corrupted_balance.accounts[0].1 += 1;
        let bytes = encode_envelope(&corrupted_balance).unwrap();
        assert_eq!(
            EvidenceSettlementLedger::restore(&bytes),
            Err(EvidenceSettlementError::InvalidState)
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn durable_restart_keeps_exactly_once_settlement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settlement.bin");
        let (ledger, instruction, evidence) = fixture();
        let mut durable = DurableEvidenceSettlementLedger::create(&path, ledger).unwrap();
        let first =
            durable.settle(instruction.clone(), &evidence, p(5), |_, _, _, _, _| true).unwrap();
        drop(durable);
        let mut reopened = DurableEvidenceSettlementLedger::open(&path).unwrap();
        let second = reopened.settle(instruction, &evidence, p(5), |_, _, _, _, _| true).unwrap();
        assert!(second.duplicate);
        assert_eq!(first.record, second.record);
        assert_eq!(reopened.ledger().total_balance().unwrap(), 1_050);
    }
}
