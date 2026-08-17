use activechain_action_kernel::{
    ACTION_PROTOCOL_VERSION, ActionEnvelope, ActionPayloadV2, FeeTicket, ResourceVector,
    ValidityInterval, action_id,
};
use activechain_application_primitives::{AnchorError, DigestAnchorStatementV1};
use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_devnet_kernel::{ChainState, FEE_TICKET_ADMISSION_CHARGE};
use activechain_finality_types::commit_parts;
use activechain_protocol_types::{Digest384, ObjectId, PrincipalId, TransactionId};
use activechain_rpc_types::MAX_ANCHOR_ACTION_LENGTH;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Exact proposal material created by the operator-owned native-action boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedAnchorAction {
    action: Vec<u8>,
    transaction: TransactionId,
}

impl ProposedAnchorAction {
    pub fn new(action: Vec<u8>, transaction: TransactionId) -> Result<Self, AnchorError> {
        if action.is_empty() || action.len() > MAX_ANCHOR_ACTION_LENGTH {
            return Err(AnchorError::InvalidTransition);
        }
        Ok(Self { action, transaction })
    }

    pub fn action(&self) -> &[u8] {
        &self.action
    }

    pub const fn transaction(&self) -> TransactionId {
        self.transaction
    }
}

/// Semantic production boundary for operator-owned anchor proposal construction.
pub trait AnchorProposalAdapter: Send + Sync {
    fn ready(&self) -> bool;

    fn propose_anchor(
        &self,
        statement: &DigestAnchorStatementV1,
        reference: Digest384,
    ) -> Result<ProposedAnchorAction, AnchorError>;
}

impl<F> AnchorProposalAdapter for F
where
    F: Fn(&DigestAnchorStatementV1, Digest384) -> Result<ProposedAnchorAction, AnchorError>
        + Send
        + Sync,
{
    fn ready(&self) -> bool {
        true
    }

    fn propose_anchor(
        &self,
        statement: &DigestAnchorStatementV1,
        reference: Digest384,
    ) -> Result<ProposedAnchorAction, AnchorError> {
        self(statement, reference)
    }
}

/// Crash-atomic single-round native anchor spool. The validator archives and removes the spool
/// only after the exact action reaches a finalized block, so a second statement fails closed
/// rather than racing the fee-account and nonce state reserved by the first proposal.
pub struct SpoolAnchorProposalAdapter {
    spool_path: PathBuf,
    execution_state_path: PathBuf,
    operator: PrincipalId,
    nonce_channel: u16,
    lock: Mutex<()>,
}

impl SpoolAnchorProposalAdapter {
    pub fn new(
        spool_path: PathBuf,
        execution_state_path: PathBuf,
        operator: PrincipalId,
        nonce_channel: u16,
    ) -> Result<Self, AnchorError> {
        if spool_path == execution_state_path || operator.digest() == &Digest384::ZERO {
            return Err(AnchorError::InvalidTransition);
        }
        Ok(Self { spool_path, execution_state_path, operator, nonce_channel, lock: Mutex::new(()) })
    }

    fn load_existing(&self) -> Result<Option<Vec<u8>>, AnchorError> {
        if !self.spool_path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&self.spool_path).map_err(|_| AnchorError::Persistence)?;
        if bytes.len() < 4 {
            return Err(AnchorError::Persistence);
        }
        let length =
            u32::from_be_bytes(bytes[..4].try_into().map_err(|_| AnchorError::Persistence)?)
                as usize;
        if length == 0
            || length > MAX_ANCHOR_ACTION_LENGTH
            || bytes.len() != length.checked_add(4).ok_or(AnchorError::Persistence)?
        {
            return Err(AnchorError::Persistence);
        }
        Ok(Some(bytes[4..].to_vec()))
    }

    fn persist(&self, action: &[u8]) -> Result<(), AnchorError> {
        let parent = self
            .spool_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|_| AnchorError::Persistence)?;
        let length = u32::try_from(action.len()).map_err(|_| AnchorError::Persistence)?;
        let temporary = self.spool_path.with_extension("tmp");
        let mut file = fs::File::create(&temporary).map_err(|_| AnchorError::Persistence)?;
        file.write_all(&length.to_be_bytes()).map_err(|_| AnchorError::Persistence)?;
        file.write_all(action).map_err(|_| AnchorError::Persistence)?;
        file.sync_all().map_err(|_| AnchorError::Persistence)?;
        fs::rename(&temporary, &self.spool_path).map_err(|_| AnchorError::Persistence)?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AnchorError::Persistence)
    }
}

impl AnchorProposalAdapter for SpoolAnchorProposalAdapter {
    fn ready(&self) -> bool {
        let Ok(_guard) = self.lock.lock() else {
            return false;
        };
        let Ok(bytes) = fs::read(&self.execution_state_path) else {
            return false;
        };
        let Ok(state) = decode_envelope::<ChainState>(&bytes) else {
            return false;
        };
        let Ok(encoded_ceiling) = u64::try_from(MAX_ANCHOR_ACTION_LENGTH) else {
            return false;
        };
        let resources = ResourceVector::new(1, 1, 1, 0, 0, encoded_ceiling);
        let Some(reservation) = resources
            .checked_charge(state.resource_prices())
            .and_then(|charge| charge.checked_add(FEE_TICKET_ADMISSION_CHARGE))
        else {
            return false;
        };
        state
            .fee_accounts()
            .iter()
            .any(|account| account.payer() == self.operator && account.balance() >= reservation)
            && state.nonce_channels().iter().any(|channel| {
                channel.sender() == self.operator && channel.channel() == self.nonce_channel
            })
            && state.height().checked_add(1).is_some()
            && matches!(self.load_existing(), Ok(None))
    }

    fn propose_anchor(
        &self,
        statement: &DigestAnchorStatementV1,
        reference: Digest384,
    ) -> Result<ProposedAnchorAction, AnchorError> {
        let _guard = self.lock.lock().map_err(|_| AnchorError::Persistence)?;
        if statement.submission_reference()? != reference {
            return Err(AnchorError::InvalidStatement);
        }
        if let Some(action) = self.load_existing()? {
            let envelope =
                decode_envelope::<ActionEnvelope>(&action).map_err(|_| AnchorError::Persistence)?;
            let ActionPayloadV2::SubmitAnchor { statement: existing, .. } = envelope.payload()
            else {
                return Err(AnchorError::Persistence);
            };
            if existing != statement || envelope.authorization_commitment() != reference {
                return Err(AnchorError::Capacity);
            }
            let transaction = action_id(&envelope).map_err(|_| AnchorError::Encoding)?;
            return ProposedAnchorAction::new(action, transaction);
        }

        let state_bytes =
            fs::read(&self.execution_state_path).map_err(|_| AnchorError::Persistence)?;
        let state =
            decode_envelope::<ChainState>(&state_bytes).map_err(|_| AnchorError::Persistence)?;
        let height = state.height().checked_add(1).ok_or(AnchorError::InvalidTransition)?;
        let account = state
            .fee_accounts()
            .iter()
            .find(|account| account.payer() == self.operator)
            .copied()
            .ok_or(AnchorError::InvalidTransition)?;
        let channel = state
            .nonce_channels()
            .iter()
            .find(|channel| {
                channel.sender() == self.operator && channel.channel() == self.nonce_channel
            })
            .copied()
            .ok_or(AnchorError::InvalidTransition)?;
        let encoded_ceiling =
            u64::try_from(MAX_ANCHOR_ACTION_LENGTH).map_err(|_| AnchorError::Encoding)?;
        // SubmitAnchor derives one immutable state object, so execution charges
        // one object read and one object write. Keep the declared ceiling
        // aligned with `ready()` and consensus resource accounting.
        let resources = ResourceVector::new(1, 1, 1, 0, 0, encoded_ceiling);
        let reservation = resources
            .checked_charge(state.resource_prices())
            .and_then(|charge| charge.checked_add(FEE_TICKET_ADMISSION_CHARGE))
            .ok_or(AnchorError::InvalidTransition)?;
        if account.balance() < reservation {
            return Err(AnchorError::InvalidTransition);
        }
        let ticket_digest = commit_parts(
            b"ACTIVECHAIN-ANCHOR-FEE-TICKET-V1",
            &[
                reference.as_bytes(),
                self.operator.digest().as_bytes(),
                &height.to_be_bytes(),
                &account.next_nonce().to_be_bytes(),
                &channel.next_sequence().to_be_bytes(),
            ],
        );
        let payload = ActionPayloadV2::submit_anchor(height, statement.clone());
        let payload_commitment = payload.commitment().map_err(|_| AnchorError::Encoding)?;
        let action = ActionEnvelope::new_payload(
            ACTION_PROTOCOL_VERSION,
            state.chain_id(),
            self.operator,
            FeeTicket::new(
                ObjectId::new(ticket_digest),
                self.operator,
                reservation,
                height,
                account.next_nonce(),
                resources,
            )
            .map_err(|_| AnchorError::InvalidTransition)?,
            self.nonce_channel,
            channel.next_sequence(),
            ValidityInterval::new(height, height).map_err(|_| AnchorError::InvalidTransition)?,
            resources,
            payload_commitment,
            payload,
            reference,
        )
        .map_err(|_| AnchorError::InvalidTransition)?;
        let transaction = action_id(&action).map_err(|_| AnchorError::Encoding)?;
        let action = encode_envelope(&action).map_err(|_| AnchorError::Encoding)?;
        if action.len() > MAX_ANCHOR_ACTION_LENGTH {
            return Err(AnchorError::InvalidTransition);
        }
        self.persist(&action)?;
        ProposedAnchorAction::new(action, transaction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_action_kernel::{NonceChannel, ResourcePrices};
    use activechain_devnet_kernel::FeeAccount;
    use activechain_protocol_types::ChainId;
    use activechain_transition::ObjectState;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn spool_proposal_is_operator_owned_atomic_and_idempotent() {
        let root = std::env::temp_dir()
            .join(format!("activechain-anchor-proposal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("execution.snapshot");
        let spool_path = root.join("anchor-actions.batch");
        let operator = PrincipalId::new(digest(2));
        let state = ChainState::genesis_with_fee_accounts(
            ChainId::new(digest(1)),
            ObjectState::new(vec![]).unwrap(),
            vec![NonceChannel::new(operator, 7, 11)],
            vec![FeeAccount::new(operator, 100_000, 13)],
            ResourcePrices::new(1, 1, 1, 1, 1, 1),
        )
        .unwrap();
        fs::write(&state_path, encode_envelope(&state).unwrap()).unwrap();
        let adapter =
            SpoolAnchorProposalAdapter::new(spool_path.clone(), state_path, operator, 7).unwrap();
        assert!(adapter.ready());
        let statement =
            DigestAnchorStatementV1::new(b"actum.test.anchor".to_vec(), [3; 32]).unwrap();
        let reference = statement.submission_reference().unwrap();
        let first = adapter.propose_anchor(&statement, reference).unwrap();
        assert!(!adapter.ready());
        assert_eq!(adapter.propose_anchor(&statement, reference).unwrap(), first);
        let action = decode_envelope::<ActionEnvelope>(first.action()).unwrap();
        assert_eq!(action.chain_id(), state.chain_id());
        assert_eq!(action.sender(), operator);
        assert_eq!(action.authorization_commitment(), reference);
        assert_eq!(action_id(&action).unwrap(), first.transaction());
        assert_eq!(action.maximum_resources().object_reads(), 1);
        assert_eq!(action.maximum_resources().object_writes(), 1);
        assert_eq!(
            adapter.propose_anchor(
                &DigestAnchorStatementV1::new(b"actum.test.anchor".to_vec(), [4; 32]).unwrap(),
                digest(5),
            ),
            Err(AnchorError::InvalidStatement)
        );
        let second = DigestAnchorStatementV1::new(b"actum.test.anchor".to_vec(), [4; 32]).unwrap();
        assert_eq!(
            adapter.propose_anchor(&second, second.submission_reference().unwrap()),
            Err(AnchorError::Capacity)
        );
        assert!(spool_path.is_file());
        fs::remove_dir_all(root).unwrap();
    }
}
