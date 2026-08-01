use activechain_protocol_types::{Digest384, ExternalSubjectBindingV1};

use crate::{OpenWalletConsentV1, WalletError};

pub const MAX_EXTERNAL_SUBJECT_ASSOCIATIONS: usize = 64;

/// Wallet-owned replay and recovery journal for externally governed subject associations.
#[derive(Default)]
pub struct ExternalSubjectAssociationStoreV1 {
    bindings: Vec<(Digest384, ExternalSubjectBindingV1)>,
    consumed_replay_keys: Vec<Digest384>,
}

impl ExternalSubjectAssociationStoreV1 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn admit(
        &mut self,
        binding: ExternalSubjectBindingV1,
        consent: &OpenWalletConsentV1,
        height: u64,
    ) -> Result<(), WalletError> {
        let consent_commitment =
            consent.commitment().map_err(|_| WalletError::MalformedAuthorization)?;
        if binding.wallet_authorization_commitment() != consent_commitment {
            return Err(WalletError::MalformedAuthorization);
        }
        if !binding.active_at(height) {
            return Err(WalletError::Expired);
        }
        let replay_key = binding.replay_key().map_err(|_| WalletError::MalformedAuthorization)?;
        if self.consumed_replay_keys.binary_search(&replay_key).is_ok() {
            return Err(WalletError::Replay);
        }
        let slot = binding.slot_commitment().map_err(|_| WalletError::MalformedAuthorization)?;
        match self.bindings.binary_search_by_key(&slot, |entry| entry.0) {
            Ok(index) => self.bindings[index]
                .1
                .validate_successor(&binding)
                .map_err(|_| WalletError::MalformedAuthorization)?,
            Err(_) if self.bindings.len() >= MAX_EXTERNAL_SUBJECT_ASSOCIATIONS => {
                return Err(WalletError::StateLimit);
            }
            Err(_) => {}
        }
        match self.bindings.binary_search_by_key(&slot, |entry| entry.0) {
            Ok(index) => self.bindings[index] = (slot, binding),
            Err(index) => self.bindings.insert(index, (slot, binding)),
        }
        let replay_index = self.consumed_replay_keys.binary_search(&replay_key).unwrap_err();
        self.consumed_replay_keys.insert(replay_index, replay_key);
        Ok(())
    }

    pub fn resolve(&self, slot: Digest384, height: u64) -> Option<&ExternalSubjectBindingV1> {
        self.bindings
            .binary_search_by_key(&slot, |entry| entry.0)
            .ok()
            .map(|index| &self.bindings[index].1)
            .filter(|binding| binding.active_at(height))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{ChainId, ExternalSubjectBindingKindV1, PrincipalId};

    fn d(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    fn consent(n: u8) -> OpenWalletConsentV1 {
        OpenWalletConsentV1::new(d(n), d(n + 1), vec![d(n + 2)], vec![d(n + 3)], 10, 20).unwrap()
    }
    fn binding(
        consent: &OpenWalletConsentV1,
        sequence: u64,
        version: u32,
        previous: Option<Digest384>,
        holder: u8,
    ) -> ExternalSubjectBindingV1 {
        ExternalSubjectBindingV1::new(
            ChainId::new(d(1)),
            d(2),
            d(3),
            d(4),
            PrincipalId::new(d(5)),
            d(holder),
            None,
            ExternalSubjectBindingKindV1::Account,
            None,
            None,
            None,
            d(7),
            PrincipalId::new(d(8)),
            d(9 + sequence as u8),
            version,
            sequence,
            9 + sequence,
            30,
            previous,
            d(11),
            consent.commitment().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn consent_is_required_and_replay_fails_closed() {
        let approved = consent(20);
        let wrong = consent(30);
        let value = binding(&approved, 1, 1, None, 6);
        let mut store = ExternalSubjectAssociationStoreV1::new();
        assert_eq!(store.admit(value, &wrong, 10), Err(WalletError::MalformedAuthorization));
        assert_eq!(store.admit(value, &approved, 10), Ok(()));
        assert_eq!(store.admit(value, &approved, 10), Err(WalletError::Replay));
        assert_eq!(store.resolve(value.slot_commitment().unwrap(), 10), Some(&value));
    }

    #[test]
    fn recovery_requires_a_new_consent_and_exact_previous_state() {
        let first_consent = consent(20);
        let first = binding(&first_consent, 1, 1, None, 6);
        let next_consent = consent(30);
        let next = binding(&next_consent, 2, 2, Some(first.commitment().unwrap()), 14);
        let mut store = ExternalSubjectAssociationStoreV1::new();
        store.admit(first, &first_consent, 10).unwrap();
        store.admit(next, &next_consent, 11).unwrap();
        assert_eq!(store.resolve(next.slot_commitment().unwrap(), 11), Some(&next));

        let stale_consent = consent(40);
        let stale = binding(&stale_consent, 3, 3, Some(d(99)), 15);
        assert_eq!(
            store.admit(stale, &stale_consent, 12),
            Err(WalletError::MalformedAuthorization)
        );
    }

    #[test]
    fn wallet_consumes_the_protocol_subject_binding_matrix() {
        let vector = include_str!("../../../testing/vectors/external-subject-binding-v1.tsv");
        assert_eq!(vector.lines().count(), 13);
        assert!(vector.contains("pairwise_missing_scope\tpairwise\tabsent"));
        assert!(vector.contains("replayed_authorization\tdevice"));
        assert!(vector.contains("scope_migration\tpairwise\tasset"));
    }
}
