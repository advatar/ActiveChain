extern crate alloc;

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    encode_envelope,
};
use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{Digest384, PrincipalId, derive_activechain_did};

pub const MAX_ENS_ALIASES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnsAliasError {
    InvalidEvidence,
    InvalidAlias,
    WrongChain,
    WrongPrincipal,
    PreviousMismatch,
    InvalidSequence,
    StaleEvidence,
    DuplicateAlias,
    AliasMissing,
    Inactive,
    Capacity,
}

/// Commitment-only external ENS ownership observation. This value is display evidence only and
/// never carries ActiveChain controller authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnsAliasEvidenceV1 {
    source_chain_id: u64,
    namehash: [u8; 32],
    resolver_commitment: Digest384,
    ownership_proof_commitment: Digest384,
    observed_block: u64,
    valid_until_block: u64,
}

impl EnsAliasEvidenceV1 {
    pub const TYPE_TAG: u16 = 0x019A;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 8 + 32 + 48 + 48 + 8 + 8;

    pub fn new(
        source_chain_id: u64,
        namehash: [u8; 32],
        resolver_commitment: Digest384,
        ownership_proof_commitment: Digest384,
        observed_block: u64,
        valid_until_block: u64,
    ) -> Result<Self, EnsAliasError> {
        if source_chain_id == 0
            || namehash == [0; 32]
            || resolver_commitment == Digest384::ZERO
            || ownership_proof_commitment == Digest384::ZERO
            || observed_block == 0
            || valid_until_block < observed_block
        {
            return Err(EnsAliasError::InvalidEvidence);
        }
        Ok(Self {
            source_chain_id,
            namehash,
            resolver_commitment,
            ownership_proof_commitment,
            observed_block,
            valid_until_block,
        })
    }
    pub const fn namehash(&self) -> [u8; 32] {
        self.namehash
    }
    pub const fn valid_until_block(self) -> u64 {
        self.valid_until_block
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        domain_commitment(b"ACTIVECHAIN-ENS-ALIAS-EVIDENCE-V1", &encode_envelope(self)?)
    }
}

impl CanonicalEncode for EnsAliasEvidenceV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.source_chain_id.encode(e)?;
        self.namehash.encode(e)?;
        self.resolver_commitment.encode(e)?;
        self.ownership_proof_commitment.encode(e)?;
        self.observed_block.encode(e)?;
        self.valid_until_block.encode(e)
    }
}
impl CanonicalDecode for EnsAliasEvidenceV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            u64::decode(d)?,
            <[u8; 32]>::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid ENS alias evidence"))
    }
}
impl CanonicalType for EnsAliasEvidenceV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

/// Finalized non-authoritative discovery alias for one stable ActiveChain principal and DID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnsAliasRecordV1 {
    chain_genesis: Digest384,
    namehash: [u8; 32],
    principal: PrincipalId,
    did: Digest384,
    evidence_commitment: Digest384,
    evidence_valid_until: u64,
    sequence: u64,
    active: bool,
}

impl EnsAliasRecordV1 {
    pub const TYPE_TAG: u16 = 0x019B;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 32 + 48 + 48 + 48 + 8 + 8 + 1;

    pub fn new(
        chain_genesis: Digest384,
        principal: PrincipalId,
        evidence: &EnsAliasEvidenceV1,
        sequence: u64,
        active: bool,
    ) -> Result<Self, EnsAliasError> {
        let did = derive_activechain_did(principal).map_err(|_| EnsAliasError::InvalidAlias)?;
        if chain_genesis == Digest384::ZERO || sequence == 0 {
            return Err(EnsAliasError::InvalidAlias);
        }
        Ok(Self {
            chain_genesis,
            namehash: evidence.namehash(),
            principal,
            did,
            evidence_commitment: evidence
                .commitment()
                .map_err(|_| EnsAliasError::InvalidEvidence)?,
            evidence_valid_until: evidence.valid_until_block(),
            sequence,
            active,
        })
    }
    pub const fn chain_genesis(self) -> Digest384 {
        self.chain_genesis
    }
    pub const fn namehash(&self) -> [u8; 32] {
        self.namehash
    }
    pub const fn principal(self) -> PrincipalId {
        self.principal
    }
    pub const fn did(self) -> Digest384 {
        self.did
    }
    pub const fn evidence_commitment(self) -> Digest384 {
        self.evidence_commitment
    }
    pub const fn evidence_valid_until(self) -> u64 {
        self.evidence_valid_until
    }
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    pub const fn active(self) -> bool {
        self.active
    }
    pub const fn evidence_is_fresh_at(self, source_block: u64) -> bool {
        source_block <= self.evidence_valid_until
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        domain_commitment(b"ACTIVECHAIN-ENS-ALIAS-RECORD-V1", &encode_envelope(self)?)
    }
    pub fn object_id(&self) -> Digest384 {
        let mut bytes = [0_u8; 80];
        bytes[..48].copy_from_slice(self.chain_genesis.as_bytes());
        bytes[48..].copy_from_slice(&self.namehash);
        domain_commitment(b"ACTIVECHAIN-ENS-ALIAS-OBJECT-ID-V1", &bytes)
            .expect("fixed digest input commits")
    }
    pub fn verifies_evidence(&self, evidence: &EnsAliasEvidenceV1) -> bool {
        evidence.namehash() == self.namehash
            && evidence.valid_until_block() == self.evidence_valid_until
            && evidence.commitment().is_ok_and(|value| value == self.evidence_commitment)
    }
}

impl CanonicalEncode for EnsAliasRecordV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_genesis.encode(e)?;
        self.namehash.encode(e)?;
        self.principal.encode(e)?;
        self.did.encode(e)?;
        self.evidence_commitment.encode(e)?;
        self.evidence_valid_until.encode(e)?;
        self.sequence.encode(e)?;
        self.active.encode(e)
    }
}
impl CanonicalDecode for EnsAliasRecordV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            chain_genesis: Digest384::decode(d)?,
            namehash: <[u8; 32]>::decode(d)?,
            principal: PrincipalId::decode(d)?,
            did: Digest384::decode(d)?,
            evidence_commitment: Digest384::decode(d)?,
            evidence_valid_until: u64::decode(d)?,
            sequence: u64::decode(d)?,
            active: bool::decode(d)?,
        };
        if value.chain_genesis == Digest384::ZERO
            || value.namehash == [0; 32]
            || value.evidence_commitment == Digest384::ZERO
            || value.evidence_valid_until == 0
            || value.sequence == 0
            || derive_activechain_did(value.principal) != Ok(value.did)
        {
            return Err(DecodeError::InvalidValue("invalid ENS alias record"));
        }
        Ok(value)
    }
}
impl CanonicalType for EnsAliasRecordV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EnsAliasOperationKind {
    Create = 0,
    Update = 1,
    Remove = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnsAliasOperationV1 {
    kind: EnsAliasOperationKind,
    previous_commitment: Option<Digest384>,
    next: EnsAliasRecordV1,
    principal_authorization_commitment: Digest384,
}

impl EnsAliasOperationV1 {
    pub const TYPE_TAG: u16 = 0x019C;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 1 + 1 + 48 + EnsAliasRecordV1::MAX_ENCODED_LEN + 48;

    pub fn new(
        kind: EnsAliasOperationKind,
        previous_commitment: Option<Digest384>,
        next: EnsAliasRecordV1,
        principal_authorization_commitment: Digest384,
    ) -> Result<Self, EnsAliasError> {
        if previous_commitment.is_some_and(|value| value == Digest384::ZERO)
            || principal_authorization_commitment == Digest384::ZERO
        {
            return Err(EnsAliasError::InvalidAlias);
        }
        match kind {
            EnsAliasOperationKind::Create
                if previous_commitment.is_some() || next.sequence() != 1 || !next.active() =>
            {
                Err(EnsAliasError::InvalidSequence)
            }
            EnsAliasOperationKind::Update if previous_commitment.is_none() || !next.active() => {
                Err(EnsAliasError::InvalidSequence)
            }
            EnsAliasOperationKind::Remove if previous_commitment.is_none() || next.active() => {
                Err(EnsAliasError::InvalidSequence)
            }
            _ => Ok(Self { kind, previous_commitment, next, principal_authorization_commitment }),
        }
    }
    pub const fn kind(self) -> EnsAliasOperationKind {
        self.kind
    }
    pub const fn next(self) -> EnsAliasRecordV1 {
        self.next
    }
    pub const fn authorization_principal(self) -> PrincipalId {
        self.next.principal()
    }
    pub fn apply(
        &self,
        current: EnsAliasRecordV1,
        expected_chain_genesis: Digest384,
        observed_source_block: u64,
    ) -> Result<EnsAliasRecordV1, EnsAliasError> {
        if !current.active() {
            return Err(EnsAliasError::Inactive);
        }
        if current.chain_genesis() != expected_chain_genesis
            || self.next.chain_genesis() != expected_chain_genesis
        {
            return Err(EnsAliasError::WrongChain);
        }
        if self.previous_commitment
            != Some(current.commitment().map_err(|_| EnsAliasError::PreviousMismatch)?)
        {
            return Err(EnsAliasError::PreviousMismatch);
        }
        if self.next.principal() != current.principal()
            || self.next.did() != current.did()
            || self.next.namehash() != current.namehash()
        {
            return Err(EnsAliasError::WrongPrincipal);
        }
        if self.next.sequence() != current.sequence().saturating_add(1) {
            return Err(EnsAliasError::InvalidSequence);
        }
        if self.kind != EnsAliasOperationKind::Remove
            && !self.next.evidence_is_fresh_at(observed_source_block)
        {
            return Err(EnsAliasError::StaleEvidence);
        }
        Ok(self.next)
    }
}

impl CanonicalEncode for EnsAliasOperationKind {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for EnsAliasOperationKind {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Create),
            1 => Ok(Self::Update),
            2 => Ok(Self::Remove),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "EnsAliasOperationKind", tag }),
        }
    }
}
impl CanonicalEncode for EnsAliasOperationV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.kind.encode(e)?;
        self.previous_commitment.encode(e)?;
        self.next.encode(e)?;
        self.principal_authorization_commitment.encode(e)
    }
}
impl CanonicalDecode for EnsAliasOperationV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            EnsAliasOperationKind::decode(d)?,
            Option::<Digest384>::decode(d)?,
            EnsAliasRecordV1::decode(d)?,
            Digest384::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid ENS alias operation"))
    }
}
impl CanonicalType for EnsAliasOperationV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnsAliasRegistryV1 {
    chain_genesis: Digest384,
    records: Vec<EnsAliasRecordV1>,
}

impl EnsAliasRegistryV1 {
    pub const TYPE_TAG: u16 = 0x019D;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = 48 + 5 + MAX_ENS_ALIASES * EnsAliasRecordV1::MAX_ENCODED_LEN;

    pub fn new(
        chain_genesis: Digest384,
        records: Vec<EnsAliasRecordV1>,
    ) -> Result<Self, EnsAliasError> {
        if chain_genesis == Digest384::ZERO
            || records.len() > MAX_ENS_ALIASES
            || records.iter().any(|record| record.chain_genesis() != chain_genesis)
            || records.windows(2).any(|pair| pair[0].namehash() >= pair[1].namehash())
        {
            return Err(EnsAliasError::InvalidAlias);
        }
        Ok(Self { chain_genesis, records })
    }
    pub fn empty(chain_genesis: Digest384) -> Result<Self, EnsAliasError> {
        Self::new(chain_genesis, Vec::new())
    }
    pub fn get(&self, namehash: [u8; 32]) -> Option<EnsAliasRecordV1> {
        self.records
            .binary_search_by_key(&namehash, EnsAliasRecordV1::namehash)
            .ok()
            .map(|index| self.records[index])
    }
    pub fn apply(
        &self,
        operation: EnsAliasOperationV1,
        observed_source_block: u64,
    ) -> Result<Self, EnsAliasError> {
        let next = operation.next();
        match self.records.binary_search_by_key(&next.namehash(), EnsAliasRecordV1::namehash) {
            Ok(index) => {
                if operation.kind() == EnsAliasOperationKind::Create {
                    return Err(EnsAliasError::DuplicateAlias);
                }
                let mut records = self.records.clone();
                records[index] =
                    operation.apply(records[index], self.chain_genesis, observed_source_block)?;
                Self::new(self.chain_genesis, records)
            }
            Err(index) => {
                if operation.kind() != EnsAliasOperationKind::Create {
                    return Err(EnsAliasError::AliasMissing);
                }
                if self.records.len() == MAX_ENS_ALIASES {
                    return Err(EnsAliasError::Capacity);
                }
                if next.chain_genesis() != self.chain_genesis {
                    return Err(EnsAliasError::WrongChain);
                }
                if !next.evidence_is_fresh_at(observed_source_block) {
                    return Err(EnsAliasError::StaleEvidence);
                }
                let mut records = self.records.clone();
                records.insert(index, next);
                Self::new(self.chain_genesis, records)
            }
        }
    }
}

impl CanonicalEncode for EnsAliasRegistryV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_genesis.encode(e)?;
        e.write_length(self.records.len(), MAX_ENS_ALIASES)?;
        for record in &self.records {
            record.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for EnsAliasRegistryV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_genesis = Digest384::decode(d)?;
        let len = d.read_length(MAX_ENS_ALIASES)?;
        let mut records = Vec::with_capacity(len);
        for _ in 0..len {
            records.push(EnsAliasRecordV1::decode(d)?);
        }
        Self::new(chain_genesis, records)
            .map_err(|_| DecodeError::InvalidValue("invalid ENS alias registry"))
    }
}
impl CanonicalType for EnsAliasRegistryV1 {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

fn domain_commitment(domain: &[u8], bytes: &[u8]) -> Result<Digest384, EncodeError> {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(bytes);
    let mut digest = [0; 48];
    hasher.finalize_xof().read(&mut digest);
    Ok(Digest384::new(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn evidence(name: u8, until: u64) -> EnsAliasEvidenceV1 {
        EnsAliasEvidenceV1::new(1, [name; 32], digest(2), digest(3), 10, until).unwrap()
    }

    #[test]
    fn alias_lifecycle_is_principal_bound_fresh_and_non_reassignable() {
        let genesis = digest(9);
        let principal = PrincipalId::new(digest(1));
        let first = EnsAliasRecordV1::new(genesis, principal, &evidence(7, 20), 1, true).unwrap();
        let create =
            EnsAliasOperationV1::new(EnsAliasOperationKind::Create, None, first, digest(8))
                .unwrap();
        let registry = EnsAliasRegistryV1::empty(genesis).unwrap().apply(create, 15).unwrap();
        assert_eq!(registry.get([7; 32]), Some(first));

        let updated = EnsAliasRecordV1::new(genesis, principal, &evidence(7, 30), 2, true).unwrap();
        let update = EnsAliasOperationV1::new(
            EnsAliasOperationKind::Update,
            Some(first.commitment().unwrap()),
            updated,
            digest(8),
        )
        .unwrap();
        assert!(registry.apply(update, 31).is_err());
        let registry = registry.apply(update, 25).unwrap();

        let attacker =
            EnsAliasRecordV1::new(genesis, PrincipalId::new(digest(4)), &evidence(7, 40), 3, true)
                .unwrap();
        let takeover = EnsAliasOperationV1::new(
            EnsAliasOperationKind::Update,
            Some(updated.commitment().unwrap()),
            attacker,
            digest(5),
        )
        .unwrap();
        assert_eq!(registry.apply(takeover, 35), Err(EnsAliasError::WrongPrincipal));

        let removed =
            EnsAliasRecordV1::new(genesis, principal, &evidence(7, 30), 3, false).unwrap();
        let remove = EnsAliasOperationV1::new(
            EnsAliasOperationKind::Remove,
            Some(updated.commitment().unwrap()),
            removed,
            digest(8),
        )
        .unwrap();
        let registry = registry.apply(remove, 99).unwrap();
        assert!(!registry.get([7; 32]).unwrap().active());
        assert_eq!(registry.apply(create, 15), Err(EnsAliasError::DuplicateAlias));
    }

    #[test]
    fn alias_values_are_canonical_and_external_evidence_never_names_authority() {
        let evidence = evidence(7, 20);
        let record =
            EnsAliasRecordV1::new(digest(9), PrincipalId::new(digest(1)), &evidence, 1, true)
                .unwrap();
        assert_eq!(
            decode_envelope::<EnsAliasEvidenceV1>(&encode_envelope(&evidence).unwrap()),
            Ok(evidence)
        );
        assert_eq!(
            decode_envelope::<EnsAliasRecordV1>(&encode_envelope(&record).unwrap()),
            Ok(record)
        );
        assert!(record.verifies_evidence(&evidence));
        assert_ne!(record.object_id(), record.did());
        assert_eq!(record.principal(), PrincipalId::new(digest(1)));
    }

    #[test]
    fn published_alias_vector_covers_authority_normalization_and_rollback_boundaries() {
        let rows = include_str!("../../../testing/vectors/did-ens-alias-v1.tsv")
            .lines()
            .skip(1)
            .map(|line| line.split('\t').collect::<Vec<_>>())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 12);
        assert!(rows.iter().all(|row| row.len() == 7));
        for required in [
            "unicode-normalization-substitution",
            "namehash-collision-substitution",
            "alias-takeover",
            "cross-chain-replay",
            "resolver-rollback",
            "ens-control-as-authorization",
        ] {
            assert!(rows.iter().any(|row| row[0] == required));
        }
        assert_eq!(rows.iter().filter(|row| row[6] == "accept").count(), 3);
        assert_eq!(rows.iter().filter(|row| row[6] == "reject").count(), 9);
    }
}
