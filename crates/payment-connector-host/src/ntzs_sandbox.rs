//! Deterministic local nTZS sandbox mapping; it makes no external-provider or regulatory claim.

use std::collections::BTreeMap;

use activechain_payment_types::{
    AssetAmountV1, ConnectorId, PaymentAttemptId, PaymentQuoteId, PaymentQuoteV1,
    ProviderObservationV1, ProviderOperationState, RailId,
};
use activechain_protocol_types::{AssetId, ChainId, Digest384, PrincipalId};

use crate::{
    ConnectorContract, ConnectorError, ConnectorHostPolicyV1, ConnectorJournalV1,
    ConnectorPolicyError, DeterministicConnector, JournalError, SimulatorRequest,
    SimulatorScenario,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtzsOperationKind {
    Collection,
    Payout,
    Conversion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtzsSandboxQuoteRequest {
    pub chain: ChainId,
    pub quote: PaymentQuoteId,
    pub merchant: PrincipalId,
    pub source_amount: AssetAmountV1,
    pub settlement_amount: AssetAmountV1,
    pub provider_fee: AssetAmountV1,
    pub connector_fee: AssetAmountV1,
    pub network_fee_limit: AssetAmountV1,
    pub exchange_rate_numerator: u128,
    pub exchange_rate_denominator: u128,
    pub asset_policy_revision: Digest384,
    pub valid_from: u64,
    pub expires_at: u64,
    pub nonce: Digest384,
    pub terms_commitment: Digest384,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtzsReconciliationEntry {
    pub attempt: PaymentAttemptId,
    pub sequence: u64,
    pub state: ProviderOperationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtzsSandboxError {
    InvalidConfiguration,
    Unauthorized,
    InvalidAsset,
    InvalidOperation,
    Connector,
    Journal,
    Reconciliation,
    Quote,
}

impl From<ConnectorPolicyError> for NtzsSandboxError {
    fn from(_: ConnectorPolicyError) -> Self {
        Self::Unauthorized
    }
}
impl From<ConnectorError> for NtzsSandboxError {
    fn from(_: ConnectorError) -> Self {
        Self::Connector
    }
}
impl From<JournalError> for NtzsSandboxError {
    fn from(_: JournalError) -> Self {
        Self::Journal
    }
}

pub struct NtzsSandboxConnector {
    connector: ConnectorId,
    rail: RailId,
    ntzs_asset: AssetId,
    origin: Vec<u8>,
    policy: ConnectorHostPolicyV1,
    simulator: DeterministicConnector,
    journal: ConnectorJournalV1,
    operations: BTreeMap<PaymentAttemptId, NtzsOperationKind>,
}

impl NtzsSandboxConnector {
    pub fn new(
        connector: ConnectorId,
        rail: RailId,
        ntzs_asset: AssetId,
        origin: Vec<u8>,
        policy: ConnectorHostPolicyV1,
    ) -> Result<Self, NtzsSandboxError> {
        if connector.digest() == Digest384::ZERO
            || rail.digest() == Digest384::ZERO
            || ntzs_asset.digest() == &Digest384::ZERO
            || !origin.starts_with(b"https://")
        {
            return Err(NtzsSandboxError::InvalidConfiguration);
        }
        Ok(Self {
            connector,
            rail,
            ntzs_asset,
            origin,
            policy,
            simulator: DeterministicConnector::default(),
            journal: ConnectorJournalV1::default(),
            operations: BTreeMap::new(),
        })
    }

    pub fn quote(
        &self,
        request: NtzsSandboxQuoteRequest,
    ) -> Result<PaymentQuoteV1, NtzsSandboxError> {
        self.policy.authorize(
            self.connector,
            &self.origin,
            self.rail,
            request.source_amount.asset(),
            request.source_amount.atomic_units(),
        )?;
        if request.settlement_amount.asset() != self.ntzs_asset {
            return Err(NtzsSandboxError::InvalidAsset);
        }
        PaymentQuoteV1::new(
            request.chain,
            request.quote,
            request.merchant,
            self.connector,
            self.rail,
            request.source_amount,
            request.settlement_amount,
            request.provider_fee,
            request.connector_fee,
            request.network_fee_limit,
            request.exchange_rate_numerator,
            request.exchange_rate_denominator,
            request.asset_policy_revision,
            request.valid_from,
            request.expires_at,
            request.nonce,
            request.terms_commitment,
        )
        .map_err(|_| NtzsSandboxError::Quote)
    }

    pub fn begin_collection(
        &mut self,
        request: SimulatorRequest,
        scenario: SimulatorScenario,
    ) -> Result<ProviderObservationV1, NtzsSandboxError> {
        self.begin(NtzsOperationKind::Collection, request, scenario)
    }

    pub fn begin_payout(
        &mut self,
        request: SimulatorRequest,
        scenario: SimulatorScenario,
    ) -> Result<ProviderObservationV1, NtzsSandboxError> {
        self.begin(NtzsOperationKind::Payout, request, scenario)
    }

    pub fn begin_conversion(
        &mut self,
        request: SimulatorRequest,
        scenario: SimulatorScenario,
    ) -> Result<ProviderObservationV1, NtzsSandboxError> {
        self.begin(NtzsOperationKind::Conversion, request, scenario)
    }

    fn begin(
        &mut self,
        operation: NtzsOperationKind,
        request: SimulatorRequest,
        scenario: SimulatorScenario,
    ) -> Result<ProviderObservationV1, NtzsSandboxError> {
        self.policy.authorize(
            self.connector,
            &self.origin,
            self.rail,
            request.amount.asset(),
            request.amount.atomic_units(),
        )?;
        if request.connector != self.connector
            || (operation == NtzsOperationKind::Conversion
                && request.amount.asset() == self.ntzs_asset)
            || (operation != NtzsOperationKind::Conversion
                && request.amount.asset() != self.ntzs_asset)
        {
            return Err(NtzsSandboxError::InvalidAsset);
        }
        if self.operations.get(&request.attempt).is_some_and(|existing| *existing != operation) {
            return Err(NtzsSandboxError::InvalidOperation);
        }
        let attempt = request.attempt;
        let observation = self.simulator.begin(request, scenario)?;
        self.journal.record(observation.clone())?;
        self.operations.insert(attempt, operation);
        Ok(observation)
    }

    pub fn status(
        &mut self,
        attempt: PaymentAttemptId,
    ) -> Result<ProviderObservationV1, NtzsSandboxError> {
        if !self.operations.contains_key(&attempt) {
            return Err(NtzsSandboxError::InvalidOperation);
        }
        let observation = self.simulator.poll(attempt)?;
        self.journal.record(observation.clone())?;
        Ok(observation)
    }

    pub fn reconcile(&self, entries: &[NtzsReconciliationEntry]) -> Result<(), NtzsSandboxError> {
        if entries.len() != self.journal.observations().len()
            || entries.windows(2).any(|pair| pair[0].attempt >= pair[1].attempt)
            || !entries.iter().zip(self.journal.observations()).all(|(entry, observation)| {
                entry.attempt == observation.attempt()
                    && entry.sequence == observation.sequence()
                    && entry.state == observation.state()
            })
        {
            return Err(NtzsSandboxError::Reconciliation);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_payment_types::{PaymentIntentId, PaymentQuoteId};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn asset(byte: u8) -> AssetId {
        AssetId::new(digest(byte))
    }

    fn connector() -> NtzsSandboxConnector {
        let connector = ConnectorId::new(digest(2)).unwrap();
        let rail = RailId::new(digest(3)).unwrap();
        let routes = vec![
            crate::ConnectorRouteV1::new(rail, asset(7), 1_000).unwrap(),
            crate::ConnectorRouteV1::new(rail, asset(8), 1_000).unwrap(),
        ];
        let policy = ConnectorHostPolicyV1::new(
            connector,
            vec![b"https://ntzs.sandbox.local".to_vec()],
            digest(4),
            routes,
            1_000,
            5_000,
        )
        .unwrap();
        NtzsSandboxConnector::new(
            connector,
            rail,
            asset(7),
            b"https://ntzs.sandbox.local".to_vec(),
            policy,
        )
        .unwrap()
    }

    fn operation(attempt: u8, asset_byte: u8) -> SimulatorRequest {
        SimulatorRequest {
            chain: ChainId::new(digest(1)),
            connector: ConnectorId::new(digest(2)).unwrap(),
            attempt: PaymentAttemptId::new(digest(attempt)).unwrap(),
            intent: PaymentIntentId::new(digest(5)).unwrap(),
            provider_account_commitment: digest(6),
            provider_reference_commitment: digest(9),
            amount: AssetAmountV1::new(asset(asset_byte), 100).unwrap(),
            initial_time: 100,
        }
    }

    #[test]
    fn quote_maps_exact_ntzs_economics_and_policy() {
        let connector = connector();
        let quote = connector
            .quote(NtzsSandboxQuoteRequest {
                chain: ChainId::new(digest(1)),
                quote: PaymentQuoteId::new(digest(10)).unwrap(),
                merchant: PrincipalId::new(digest(11)),
                source_amount: AssetAmountV1::new(asset(8), 110).unwrap(),
                settlement_amount: AssetAmountV1::new(asset(7), 100).unwrap(),
                provider_fee: AssetAmountV1::new(asset(7), 1).unwrap(),
                connector_fee: AssetAmountV1::new(asset(7), 1).unwrap(),
                network_fee_limit: AssetAmountV1::new(asset(7), 1).unwrap(),
                exchange_rate_numerator: 10,
                exchange_rate_denominator: 11,
                asset_policy_revision: digest(12),
                valid_from: 100,
                expires_at: 200,
                nonce: digest(13),
                terms_commitment: digest(14),
            })
            .unwrap();
        assert_eq!(quote.settlement_amount().asset(), asset(7));
        assert_eq!(quote.settlement_amount().atomic_units(), 100);
        assert_eq!(quote.expires_at(), 200);
    }

    #[test]
    fn collection_payout_conversion_status_and_reconciliation_are_exact() {
        let mut connector = connector();
        let collection =
            connector.begin_collection(operation(20, 7), SimulatorScenario::success()).unwrap();
        let payout =
            connector.begin_payout(operation(21, 7), SimulatorScenario::rejected()).unwrap();
        let conversion =
            connector.begin_conversion(operation(22, 8), SimulatorScenario::success()).unwrap();
        assert_eq!(collection.state(), ProviderOperationState::Pending);
        assert_eq!(payout.state(), ProviderOperationState::Pending);
        assert_eq!(conversion.state(), ProviderOperationState::Pending);
        let collection = connector.status(collection.attempt()).unwrap();
        let payout = connector.status(payout.attempt()).unwrap();
        let conversion = connector.status(conversion.attempt()).unwrap();
        assert_eq!(collection.state(), ProviderOperationState::Succeeded);
        assert_eq!(payout.state(), ProviderOperationState::Rejected);
        assert_eq!(conversion.state(), ProviderOperationState::Succeeded);
        let entries = [collection, payout, conversion].map(|observation| NtzsReconciliationEntry {
            attempt: observation.attempt(),
            sequence: observation.sequence(),
            state: observation.state(),
        });
        assert_eq!(connector.reconcile(&entries), Ok(()));
        let mut wrong = entries;
        wrong[1].sequence = 1;
        assert_eq!(connector.reconcile(&wrong), Err(NtzsSandboxError::Reconciliation));
    }

    #[test]
    fn sandbox_rejects_wrong_asset_operation_reuse_and_policy_overrun() {
        let mut connector = connector();
        assert_eq!(
            connector.begin_collection(operation(20, 8), SimulatorScenario::success()),
            Err(NtzsSandboxError::InvalidAsset)
        );
        assert_eq!(
            connector.begin_conversion(operation(20, 7), SimulatorScenario::success()),
            Err(NtzsSandboxError::InvalidAsset)
        );
        connector.begin_collection(operation(20, 7), SimulatorScenario::success()).unwrap();
        assert_eq!(
            connector.begin_payout(operation(20, 7), SimulatorScenario::success()),
            Err(NtzsSandboxError::InvalidOperation)
        );
        let mut too_large = operation(30, 7);
        too_large.amount = AssetAmountV1::new(asset(7), 1_001).unwrap();
        assert_eq!(
            connector.begin_collection(too_large, SimulatorScenario::success()),
            Err(NtzsSandboxError::Unauthorized)
        );
    }
}
