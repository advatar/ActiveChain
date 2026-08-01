use crate::WalletError;
use activechain_protocol_types::{
    ChainId, CredentialAssuranceClassV1, Digest384, PrincipalId, TransactionId,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_PRESENTATION_DISCLOSURES: usize = 32;
pub const MAX_PRESENTATION_AUDIT_ENTRIES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresentationLinkabilityV1 {
    Account,
    Pairwise,
    PrivateProof,
    Device,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresentationAuditOutcomeV1 {
    Approved,
    Cancelled,
    Expired,
    UserPresenceFailed,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalPresentationDisplayV1 {
    session_id: Digest384,
    request_commitment: Digest384,
    verified_requester: PrincipalId,
    issuer_binding: Digest384,
    credential_profile: Digest384,
    principal: PrincipalId,
    chain_id: ChainId,
    resource: Digest384,
    action: TransactionId,
    purpose: Digest384,
    audience: PrincipalId,
    disclosures: Vec<Digest384>,
    assurance: CredentialAssuranceClassV1,
    retention: Digest384,
    policy_revision: u64,
    nonce: Digest384,
    expires_at: u64,
    linkability: PresentationLinkabilityV1,
    value: u128,
    fees: u128,
    capability_action: Digest384,
}
impl ExternalPresentationDisplayV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: Digest384,
        request_commitment: Digest384,
        verified_requester: PrincipalId,
        issuer_binding: Digest384,
        credential_profile: Digest384,
        principal: PrincipalId,
        chain_id: ChainId,
        resource: Digest384,
        action: TransactionId,
        purpose: Digest384,
        audience: PrincipalId,
        disclosures: Vec<Digest384>,
        assurance: CredentialAssuranceClassV1,
        retention: Digest384,
        policy_revision: u64,
        nonce: Digest384,
        expires_at: u64,
        linkability: PresentationLinkabilityV1,
        value: u128,
        fees: u128,
        capability_action: Digest384,
    ) -> Result<Self, WalletError> {
        if [
            session_id,
            request_commitment,
            issuer_binding,
            credential_profile,
            resource,
            purpose,
            retention,
            nonce,
            capability_action,
        ]
        .into_iter()
        .any(|v| v == Digest384::ZERO)
            || verified_requester.digest() == &Digest384::ZERO
            || principal.digest() == &Digest384::ZERO
            || audience.digest() == &Digest384::ZERO
            || chain_id.digest() == &Digest384::ZERO
            || policy_revision == 0
            || expires_at == 0
            || disclosures.is_empty()
            || disclosures.len() > MAX_PRESENTATION_DISCLOSURES
            || !disclosures.windows(2).all(|p| p[0] < p[1])
        {
            return Err(WalletError::MalformedAuthorization);
        }
        Ok(Self {
            session_id,
            request_commitment,
            verified_requester,
            issuer_binding,
            credential_profile,
            principal,
            chain_id,
            resource,
            action,
            purpose,
            audience,
            disclosures,
            assurance,
            retention,
            policy_revision,
            nonce,
            expires_at,
            linkability,
            value,
            fees,
            capability_action,
        })
    }
    pub fn commitment(&self) -> Digest384 {
        let mut h = Shake256::default();
        h.update(b"ACTIVECHAIN-WALLET-PRESENTATION-DISPLAY-V1");
        for v in [
            self.session_id,
            self.request_commitment,
            *self.verified_requester.digest(),
            self.issuer_binding,
            self.credential_profile,
            *self.principal.digest(),
            *self.chain_id.digest(),
            self.resource,
            *self.action.digest(),
            self.purpose,
            *self.audience.digest(),
        ] {
            h.update(v.as_bytes())
        }
        for v in &self.disclosures {
            h.update(v.as_bytes())
        }
        h.update(&[self.assurance as u8, self.linkability as u8]);
        h.update(self.retention.as_bytes());
        h.update(&self.policy_revision.to_be_bytes());
        h.update(self.nonce.as_bytes());
        h.update(&self.expires_at.to_be_bytes());
        h.update(&self.value.to_be_bytes());
        h.update(&self.fees.to_be_bytes());
        h.update(self.capability_action.as_bytes());
        let mut out = [0; 48];
        XofReader::read(&mut h.finalize_xof(), &mut out);
        Digest384::new(out)
    }
    pub const fn session_id(&self) -> Digest384 {
        self.session_id
    }
    pub const fn request_commitment(&self) -> Digest384 {
        self.request_commitment
    }
    pub const fn nonce(&self) -> Digest384 {
        self.nonce
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn disclosures(&self) -> &[Digest384] {
        &self.disclosures
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedExternalPresentationV1 {
    session_id: Digest384,
    request_commitment: Digest384,
    display_commitment: Digest384,
    user_presence_commitment: Digest384,
    audit_commitment: Digest384,
}
impl AuthorizedExternalPresentationV1 {
    pub const fn request_commitment(self) -> Digest384 {
        self.request_commitment
    }
    pub const fn display_commitment(self) -> Digest384 {
        self.display_commitment
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalPresentationAuditV1 {
    session_id: Digest384,
    display_commitment: Digest384,
    assurance: CredentialAssuranceClassV1,
    outcome: PresentationAuditOutcomeV1,
    recorded_at: u64,
}

#[derive(Default)]
pub struct ExternalPresentationConsentCoordinatorV1 {
    pending: Vec<ExternalPresentationDisplayV1>,
    consumed_nonces: Vec<Digest384>,
    audit: Vec<ExternalPresentationAuditV1>,
    generation: u64,
}
impl ExternalPresentationConsentCoordinatorV1 {
    pub fn begin(
        &mut self,
        display: ExternalPresentationDisplayV1,
        now: u64,
    ) -> Result<Digest384, WalletError> {
        if now > display.expires_at()
            || self.consumed_nonces.binary_search(&display.nonce()).is_ok()
            || self.pending.iter().any(|p| p.session_id() == display.session_id())
        {
            return Err(WalletError::Replay);
        }
        let commitment = display.commitment();
        self.pending.push(display);
        self.pending.sort_by_key(ExternalPresentationDisplayV1::session_id);
        Ok(commitment)
    }
    pub fn approve(
        &mut self,
        session: Digest384,
        displayed: Digest384,
        user_presence: Digest384,
        selected: &[Digest384],
        now: u64,
    ) -> Result<AuthorizedExternalPresentationV1, WalletError> {
        let index = self
            .pending
            .binary_search_by_key(&session, ExternalPresentationDisplayV1::session_id)
            .map_err(|_| WalletError::UnknownSession)?;
        let display = &self.pending[index];
        if now > display.expires_at() {
            self.record(index, PresentationAuditOutcomeV1::Expired, now)?;
            return Err(WalletError::Expired);
        }
        if displayed != display.commitment()
            || user_presence == Digest384::ZERO
            || selected != display.disclosures()
        {
            self.record(
                index,
                if user_presence == Digest384::ZERO {
                    PresentationAuditOutcomeV1::UserPresenceFailed
                } else {
                    PresentationAuditOutcomeV1::Rejected
                },
                now,
            )?;
            return Err(WalletError::PolicyDenied);
        }
        let nonce = display.nonce();
        let request = display.request_commitment();
        let display_commitment = display.commitment();
        self.record(index, PresentationAuditOutcomeV1::Approved, now)?;
        let position = self.consumed_nonces.binary_search(&nonce).unwrap_err();
        self.consumed_nonces.insert(position, nonce);
        self.generation = self.generation.saturating_add(1);
        let audit_commitment = self.state_commitment();
        Ok(AuthorizedExternalPresentationV1 {
            session_id: session,
            request_commitment: request,
            display_commitment,
            user_presence_commitment: user_presence,
            audit_commitment,
        })
    }
    pub fn cancel(&mut self, session: Digest384, now: u64) -> Result<(), WalletError> {
        let index = self
            .pending
            .binary_search_by_key(&session, ExternalPresentationDisplayV1::session_id)
            .map_err(|_| WalletError::UnknownSession)?;
        self.record(index, PresentationAuditOutcomeV1::Cancelled, now)
    }
    fn record(
        &mut self,
        index: usize,
        outcome: PresentationAuditOutcomeV1,
        now: u64,
    ) -> Result<(), WalletError> {
        if self.audit.len() >= MAX_PRESENTATION_AUDIT_ENTRIES {
            return Err(WalletError::StateLimit);
        }
        let display = self.pending.remove(index);
        self.audit.push(ExternalPresentationAuditV1 {
            session_id: display.session_id(),
            display_commitment: display.commitment(),
            assurance: display.assurance,
            outcome,
            recorded_at: now,
        });
        Ok(())
    }
    pub fn audit(&self) -> &[ExternalPresentationAuditV1] {
        &self.audit
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub fn state_commitment(&self) -> Digest384 {
        let mut h = Shake256::default();
        h.update(b"ACTIVECHAIN-WALLET-PRESENTATION-STATE-V1");
        h.update(&self.generation.to_be_bytes());
        for n in &self.consumed_nonces {
            h.update(n.as_bytes())
        }
        for a in &self.audit {
            h.update(a.session_id.as_bytes());
            h.update(a.display_commitment.as_bytes());
            h.update(&[a.assurance as u8, a.outcome as u8]);
            h.update(&a.recorded_at.to_be_bytes())
        }
        let mut out = [0; 48];
        XofReader::read(&mut h.finalize_xof(), &mut out);
        Digest384::new(out)
    }
    pub fn verify_restored_state(
        &self,
        minimum_generation: u64,
        expected: Digest384,
    ) -> Result<(), WalletError> {
        if self.generation < minimum_generation || self.state_commitment() != expected {
            return Err(WalletError::Persistence);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn d(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    fn display() -> ExternalPresentationDisplayV1 {
        ExternalPresentationDisplayV1::new(
            d(1),
            d(2),
            PrincipalId::new(d(3)),
            d(4),
            d(5),
            PrincipalId::new(d(6)),
            ChainId::new(d(7)),
            d(8),
            TransactionId::new(d(9)),
            d(10),
            PrincipalId::new(d(11)),
            vec![d(12), d(13)],
            CredentialAssuranceClassV1::IssuerUpgraded,
            d(14),
            1,
            d(15),
            20,
            PresentationLinkabilityV1::Pairwise,
            100,
            2,
            d(16),
        )
        .unwrap()
    }
    #[test]
    fn exact_display_and_user_presence_gate_one_presentation() {
        let mut c = ExternalPresentationConsentCoordinatorV1::default();
        let shown = c.begin(display(), 10).unwrap();
        let authorized = c.approve(d(1), shown, d(20), &[d(12), d(13)], 11).unwrap();
        assert_eq!(authorized.display_commitment(), shown);
        assert_eq!(c.audit.len(), 1);
        assert_eq!(c.begin(display(), 12), Err(WalletError::Replay));
    }
    #[test]
    fn changed_request_overdisclosure_cancel_and_biometric_failure_emit_nothing() {
        let mut c = ExternalPresentationConsentCoordinatorV1::default();
        let shown = c.begin(display(), 10).unwrap();
        assert_eq!(
            c.approve(d(1), d(99), d(20), &[d(12), d(13)], 11),
            Err(WalletError::PolicyDenied)
        );
        let mut c = ExternalPresentationConsentCoordinatorV1::default();
        c.begin(display(), 10).unwrap();
        assert_eq!(
            c.approve(d(1), shown, Digest384::ZERO, &[d(12), d(13)], 11),
            Err(WalletError::PolicyDenied)
        );
        let mut c = ExternalPresentationConsentCoordinatorV1::default();
        c.begin(display(), 10).unwrap();
        c.cancel(d(1), 11).unwrap();
        assert_eq!(
            c.approve(d(1), shown, d(20), &[d(12), d(13)], 11),
            Err(WalletError::UnknownSession)
        );
    }
    #[test]
    fn rollback_detection_preserves_commitment_only_audit() {
        let mut c = ExternalPresentationConsentCoordinatorV1::default();
        let shown = c.begin(display(), 10).unwrap();
        c.approve(d(1), shown, d(20), &[d(12), d(13)], 11).unwrap();
        let checkpoint = c.state_commitment();
        assert_eq!(c.verify_restored_state(1, checkpoint), Ok(()));
        assert_eq!(c.verify_restored_state(2, checkpoint), Err(WalletError::Persistence));
    }
}
