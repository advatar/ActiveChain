use activechain_payment_types::{
    AssetAmountV1, ConnectorId, EvidenceClass, PaymentAttemptId, PaymentIntentId,
    ProviderObservationV1, ProviderOperationState,
};
use activechain_protocol_types::{ChainId, Digest384};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::collections::BTreeMap;

const MAX_SCENARIO_STATES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorError {
    InvalidScenario,
    DuplicateAttempt,
    UnknownAttempt,
    InvalidRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulatorRequest {
    pub chain: ChainId,
    pub connector: ConnectorId,
    pub attempt: PaymentAttemptId,
    pub intent: PaymentIntentId,
    pub provider_account_commitment: Digest384,
    pub provider_reference_commitment: Digest384,
    pub amount: AssetAmountV1,
    pub initial_time: u64,
}

impl SimulatorRequest {
    fn validate(&self) -> Result<(), ConnectorError> {
        if self.chain.digest() == &Digest384::ZERO
            || self.provider_account_commitment == Digest384::ZERO
            || self.provider_reference_commitment == Digest384::ZERO
            || self.initial_time == 0
        {
            return Err(ConnectorError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulatorScenario {
    states: Vec<ProviderOperationState>,
}

impl SimulatorScenario {
    pub fn new(states: Vec<ProviderOperationState>) -> Result<Self, ConnectorError> {
        if states.is_empty()
            || states.len() > MAX_SCENARIO_STATES
            || states[0] != ProviderOperationState::Pending
            || states.windows(2).any(|edge| !permits(edge[0], edge[1]))
        {
            return Err(ConnectorError::InvalidScenario);
        }
        Ok(Self { states })
    }

    pub fn success() -> Self {
        Self::new(vec![ProviderOperationState::Pending, ProviderOperationState::Succeeded])
            .expect("fixed success scenario")
    }

    pub fn rejected() -> Self {
        Self::new(vec![ProviderOperationState::Pending, ProviderOperationState::Rejected])
            .expect("fixed rejection scenario")
    }

    pub fn reversed() -> Self {
        Self::new(vec![
            ProviderOperationState::Pending,
            ProviderOperationState::Succeeded,
            ProviderOperationState::Reversed,
        ])
        .expect("fixed reversal scenario")
    }

    pub fn unknown_then_success() -> Self {
        Self::new(vec![
            ProviderOperationState::Pending,
            ProviderOperationState::Unknown,
            ProviderOperationState::Succeeded,
        ])
        .expect("fixed unknown scenario")
    }
}

fn permits(previous: ProviderOperationState, next: ProviderOperationState) -> bool {
    match previous {
        ProviderOperationState::Pending => matches!(
            next,
            ProviderOperationState::Pending
                | ProviderOperationState::Succeeded
                | ProviderOperationState::Rejected
                | ProviderOperationState::Cancelled
                | ProviderOperationState::Unknown
        ),
        ProviderOperationState::Unknown => matches!(
            next,
            ProviderOperationState::Pending
                | ProviderOperationState::Succeeded
                | ProviderOperationState::Rejected
                | ProviderOperationState::Cancelled
        ),
        ProviderOperationState::Succeeded => next == ProviderOperationState::Reversed,
        ProviderOperationState::Rejected
        | ProviderOperationState::Reversed
        | ProviderOperationState::Cancelled => false,
    }
}

pub trait ConnectorContract {
    fn begin(
        &mut self,
        request: SimulatorRequest,
        scenario: SimulatorScenario,
    ) -> Result<ProviderObservationV1, ConnectorError>;

    fn poll(&mut self, attempt: PaymentAttemptId) -> Result<ProviderObservationV1, ConnectorError>;
}

#[derive(Clone, Debug)]
struct SimulatedOperation {
    request: SimulatorRequest,
    scenario: SimulatorScenario,
    cursor: usize,
}

#[derive(Clone, Debug, Default)]
pub struct DeterministicConnector {
    operations: BTreeMap<PaymentAttemptId, SimulatedOperation>,
}

impl ConnectorContract for DeterministicConnector {
    fn begin(
        &mut self,
        request: SimulatorRequest,
        scenario: SimulatorScenario,
    ) -> Result<ProviderObservationV1, ConnectorError> {
        request.validate()?;
        if let Some(existing) = self.operations.get(&request.attempt) {
            if existing.request == request && existing.scenario == scenario {
                return observation(existing);
            }
            return Err(ConnectorError::DuplicateAttempt);
        }
        let attempt = request.attempt;
        self.operations.insert(attempt, SimulatedOperation { request, scenario, cursor: 0 });
        observation(self.operations.get(&attempt).expect("inserted operation"))
    }

    fn poll(&mut self, attempt: PaymentAttemptId) -> Result<ProviderObservationV1, ConnectorError> {
        let operation = self.operations.get_mut(&attempt).ok_or(ConnectorError::UnknownAttempt)?;
        if operation.cursor + 1 < operation.scenario.states.len() {
            operation.cursor += 1;
        }
        observation(operation)
    }
}

fn observation(operation: &SimulatedOperation) -> Result<ProviderObservationV1, ConnectorError> {
    let sequence =
        u64::try_from(operation.cursor + 1).map_err(|_| ConnectorError::InvalidScenario)?;
    let state = operation.scenario.states[operation.cursor];
    let timestamp = operation
        .request
        .initial_time
        .checked_add(sequence)
        .ok_or(ConnectorError::InvalidRequest)?;
    ProviderObservationV1::new(
        operation.request.chain,
        operation.request.connector,
        operation.request.attempt,
        operation.request.intent,
        operation.request.provider_account_commitment,
        operation.request.provider_reference_commitment,
        sequence,
        state,
        operation.request.amount,
        timestamp,
        timestamp,
        EvidenceClass::ProviderSigned,
        payload_commitment(operation.request.attempt, sequence, state),
    )
    .map_err(|_| ConnectorError::InvalidRequest)
}

fn payload_commitment(
    attempt: PaymentAttemptId,
    sequence: u64,
    state: ProviderOperationState,
) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-CONNECTOR-SIMULATOR-V1");
    hasher.update(attempt.digest().as_bytes());
    hasher.update(&sequence.to_be_bytes());
    hasher.update(&[state as u8]);
    let mut output = [0; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectorJournalV1, JournalError};
    use activechain_protocol_types::AssetId;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn request(attempt: u8) -> SimulatorRequest {
        SimulatorRequest {
            chain: ChainId::new(digest(1)),
            connector: ConnectorId::new(digest(2)).unwrap(),
            attempt: PaymentAttemptId::new(digest(attempt)).unwrap(),
            intent: PaymentIntentId::new(digest(4)).unwrap(),
            provider_account_commitment: digest(5),
            provider_reference_commitment: digest(6),
            amount: AssetAmountV1::new(AssetId::new(digest(7)), 100).unwrap(),
            initial_time: 100,
        }
    }

    fn run(scenario: SimulatorScenario) -> Vec<ProviderOperationState> {
        let mut connector = DeterministicConnector::default();
        let request = request(10);
        let attempt = request.attempt;
        let mut journal = ConnectorJournalV1::default();
        let first = connector.begin(request, scenario).unwrap();
        journal.record(first.clone()).unwrap();
        let mut states = vec![first.state()];
        loop {
            let next = connector.poll(attempt).unwrap();
            match journal.record(next.clone()) {
                Ok(true) => states.push(next.state()),
                Ok(false) => break,
                Err(error) => panic!("contract violation: {error:?}"),
            }
        }
        states
    }

    #[test]
    fn contract_suite_covers_success_rejection_reversal_and_unknown() {
        assert_eq!(
            run(SimulatorScenario::success()),
            vec![ProviderOperationState::Pending, ProviderOperationState::Succeeded]
        );
        assert_eq!(
            run(SimulatorScenario::rejected()),
            vec![ProviderOperationState::Pending, ProviderOperationState::Rejected]
        );
        assert_eq!(
            run(SimulatorScenario::reversed()),
            vec![
                ProviderOperationState::Pending,
                ProviderOperationState::Succeeded,
                ProviderOperationState::Reversed,
            ]
        );
        assert_eq!(
            run(SimulatorScenario::unknown_then_success()),
            vec![
                ProviderOperationState::Pending,
                ProviderOperationState::Unknown,
                ProviderOperationState::Succeeded,
            ]
        );
    }

    #[test]
    fn duplicate_begin_is_idempotent_but_changed_attempt_body_is_rejected() {
        let mut connector = DeterministicConnector::default();
        let request = request(10);
        let first = connector.begin(request.clone(), SimulatorScenario::success()).unwrap();
        assert_eq!(connector.begin(request.clone(), SimulatorScenario::success()), Ok(first));
        let mut changed = request;
        changed.provider_reference_commitment = digest(30);
        assert_eq!(
            connector.begin(changed, SimulatorScenario::success()),
            Err(ConnectorError::DuplicateAttempt)
        );
    }

    #[test]
    fn invalid_terminal_edges_and_sequence_faults_fail_closed() {
        assert_eq!(
            SimulatorScenario::new(vec![
                ProviderOperationState::Pending,
                ProviderOperationState::Rejected,
                ProviderOperationState::Succeeded,
            ]),
            Err(ConnectorError::InvalidScenario)
        );
        let mut journal = ConnectorJournalV1::default();
        let mut connector = DeterministicConnector::default();
        let request = request(10);
        let mut skipped = connector.begin(request.clone(), SimulatorScenario::reversed()).unwrap();
        journal.record(skipped.clone()).unwrap();
        let _ = connector.poll(request.attempt).unwrap();
        skipped = connector.poll(request.attempt).unwrap();
        assert_eq!(journal.record(skipped), Err(JournalError::InvalidObservation));
    }
}
