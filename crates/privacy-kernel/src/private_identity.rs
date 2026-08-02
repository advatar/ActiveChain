//! Private age and jurisdiction predicates with bounded canonical witnesses.

extern crate alloc;
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_types::{AssetId, ChainId, Digest384, PrincipalId, TransactionId};
use alloc::vec::Vec;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_JURISDICTION_SET: usize = 64;
pub const MAX_PRIVATE_IDENTITY_CONJUNCTIONS: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateIdentityError {
    InvalidDate,
    InvalidJurisdiction,
    InvalidPublicInput,
    InvalidWitness,
    RegistryNotCanonical,
    RegistryRootMismatch,
    PredicateFalse,
    Expired,
    Replay,
    MalformedProof,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CanonicalDateV1 {
    year: u16,
    month: u8,
    day: u8,
}
impl CanonicalDateV1 {
    pub fn new(year: u16, month: u8, day: u8) -> Result<Self, PrivateIdentityError> {
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if is_leap(year) => 29,
            2 => 28,
            _ => 0,
        };
        if year < 1900 || day == 0 || day > days {
            return Err(PrivateIdentityError::InvalidDate);
        }
        Ok(Self { year, month, day })
    }
    fn age_at(self, reference: Self) -> Result<u16, PrivateIdentityError> {
        if reference < self {
            return Err(PrivateIdentityError::InvalidDate);
        }
        let before_birthday = (reference.month, reference.day) < (self.month, self.day);
        Ok(reference.year - self.year - u16::from(before_birthday))
    }
}
const fn is_leap(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}
impl CanonicalEncode for CanonicalDateV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.year.encode(e)?;
        self.month.encode(e)?;
        self.day.encode(e)
    }
}
impl CanonicalDecode for CanonicalDateV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(u16::decode(d)?, u8::decode(d)?, u8::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid canonical date"))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JurisdictionCodeV1([u8; 2]);
impl JurisdictionCodeV1 {
    pub fn new(code: [u8; 2]) -> Result<Self, PrivateIdentityError> {
        if !code.iter().all(u8::is_ascii_uppercase) {
            return Err(PrivateIdentityError::InvalidJurisdiction);
        }
        Ok(Self(code))
    }
}
impl CanonicalEncode for JurisdictionCodeV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.0.encode(e)
    }
}
impl CanonicalDecode for JurisdictionCodeV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(<[u8; 2]>::decode(d)?)
            .map_err(|_| DecodeError::InvalidValue("invalid jurisdiction code"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PrivateIdentityPredicateKindV1 {
    AgeAtLeast = 0,
    AgeInRange = 1,
    ResidencyIn = 2,
    ResidencyNotIn = 3,
    NationalityIn = 4,
    JurisdictionNotIn = 5,
}
impl CanonicalEncode for PrivateIdentityPredicateKindV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for PrivateIdentityPredicateKindV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::AgeAtLeast),
            1 => Ok(Self::AgeInRange),
            2 => Ok(Self::ResidencyIn),
            3 => Ok(Self::ResidencyNotIn),
            4 => Ok(Self::NationalityIn),
            5 => Ok(Self::JurisdictionNotIn),
            tag => Err(DecodeError::InvalidEnumTag {
                type_name: "PrivateIdentityPredicateKindV1",
                tag,
            }),
        }
    }
}

/// Complete public statement; it contains no date of birth or demographic value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateIdentityPublicInputsV1 {
    pub kind: PrivateIdentityPredicateKindV1,
    pub minimum_age: Option<u8>,
    pub maximum_age: Option<u8>,
    pub reference_date: Option<CanonicalDateV1>,
    pub jurisdiction_set_root: Option<Digest384>,
    pub registry_revision: Option<u64>,
    pub chain: ChainId,
    pub chain_genesis: Digest384,
    pub asset: Option<AssetId>,
    pub action: TransactionId,
    pub audience: PrincipalId,
    pub verifier: PrincipalId,
    pub purpose: Digest384,
    pub policy_revision: u64,
    pub nonce: Digest384,
    pub expires_height: u64,
    pub finalized_height: u64,
    pub status_root: Digest384,
    pub issuer: PrincipalId,
    pub schema: Digest384,
    pub holder_binding: Digest384,
    pub linkability_scope: Digest384,
    pub conjunction_count: u8,
}
impl PrivateIdentityPublicInputsV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: PrivateIdentityPredicateKindV1,
        minimum_age: Option<u8>,
        maximum_age: Option<u8>,
        reference_date: Option<CanonicalDateV1>,
        jurisdiction_set_root: Option<Digest384>,
        registry_revision: Option<u64>,
        chain: ChainId,
        chain_genesis: Digest384,
        asset: Option<AssetId>,
        action: TransactionId,
        audience: PrincipalId,
        verifier: PrincipalId,
        purpose: Digest384,
        policy_revision: u64,
        nonce: Digest384,
        expires_height: u64,
        finalized_height: u64,
        status_root: Digest384,
        issuer: PrincipalId,
        schema: Digest384,
        holder_binding: Digest384,
        linkability_scope: Digest384,
        conjunction_count: u8,
    ) -> Result<Self, PrivateIdentityError> {
        let age = matches!(
            kind,
            PrivateIdentityPredicateKindV1::AgeAtLeast | PrivateIdentityPredicateKindV1::AgeInRange
        );
        if age != reference_date.is_some()
            || age != minimum_age.is_some()
            || (kind == PrivateIdentityPredicateKindV1::AgeInRange) != maximum_age.is_some()
            || minimum_age == Some(0)
            || maximum_age.is_some_and(|m| m < minimum_age.unwrap_or(0))
            || age == jurisdiction_set_root.is_some()
            || age == registry_revision.is_some()
            || jurisdiction_set_root == Some(Digest384::ZERO)
            || registry_revision == Some(0)
            || [
                chain_genesis,
                purpose,
                nonce,
                status_root,
                schema,
                holder_binding,
                linkability_scope,
            ]
            .into_iter()
            .any(|v| v == Digest384::ZERO)
            || audience.digest() == &Digest384::ZERO
            || verifier.digest() == &Digest384::ZERO
            || issuer.digest() == &Digest384::ZERO
            || asset.is_some_and(|a| a.digest() == &Digest384::ZERO)
            || policy_revision == 0
            || finalized_height == 0
            || expires_height <= finalized_height
            || conjunction_count == 0
            || conjunction_count > MAX_PRIVATE_IDENTITY_CONJUNCTIONS
        {
            return Err(PrivateIdentityError::InvalidPublicInput);
        }
        Ok(Self {
            kind,
            minimum_age,
            maximum_age,
            reference_date,
            jurisdiction_set_root,
            registry_revision,
            chain,
            chain_genesis,
            asset,
            action,
            audience,
            verifier,
            purpose,
            policy_revision,
            nonce,
            expires_height,
            finalized_height,
            status_root,
            issuer,
            schema,
            holder_binding,
            linkability_scope,
            conjunction_count,
        })
    }
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        let bytes = activechain_canonical_codec::encode_envelope(self)?;
        let mut h = Shake256::default();
        h.update(b"ACTIVECHAIN-PRIVATE-IDENTITY-PUBLIC-V1");
        h.update(&bytes);
        let mut out = [0; 48];
        XofReader::read(&mut h.finalize_xof(), &mut out);
        Ok(Digest384::new(out))
    }
}
impl CanonicalEncode for PrivateIdentityPublicInputsV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.kind.encode(e)?;
        self.minimum_age.encode(e)?;
        self.maximum_age.encode(e)?;
        self.reference_date.encode(e)?;
        self.jurisdiction_set_root.encode(e)?;
        self.registry_revision.encode(e)?;
        self.chain.encode(e)?;
        self.chain_genesis.encode(e)?;
        self.asset.encode(e)?;
        self.action.encode(e)?;
        self.audience.encode(e)?;
        self.verifier.encode(e)?;
        self.purpose.encode(e)?;
        self.policy_revision.encode(e)?;
        self.nonce.encode(e)?;
        self.expires_height.encode(e)?;
        self.finalized_height.encode(e)?;
        self.status_root.encode(e)?;
        self.issuer.encode(e)?;
        self.schema.encode(e)?;
        self.holder_binding.encode(e)?;
        self.linkability_scope.encode(e)?;
        self.conjunction_count.encode(e)
    }
}
impl CanonicalDecode for PrivateIdentityPublicInputsV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrivateIdentityPredicateKindV1::decode(d)?,
            Option::<u8>::decode(d)?,
            Option::<u8>::decode(d)?,
            Option::<CanonicalDateV1>::decode(d)?,
            Option::<Digest384>::decode(d)?,
            Option::<u64>::decode(d)?,
            ChainId::decode(d)?,
            Digest384::decode(d)?,
            Option::<AssetId>::decode(d)?,
            TransactionId::decode(d)?,
            PrincipalId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            Digest384::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            Digest384::decode(d)?,
            u8::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid private identity public inputs"))
    }
}
impl CanonicalType for PrivateIdentityPublicInputsV1 {
    const TYPE_TAG: u16 = 0x01A0;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 900;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateIdentityWitnessV1 {
    pub date_of_birth: Option<CanonicalDateV1>,
    pub jurisdiction: Option<JurisdictionCodeV1>,
    pub registry_entries: Vec<JurisdictionCodeV1>,
}
impl CanonicalEncode for PrivateIdentityWitnessV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.date_of_birth.encode(e)?;
        self.jurisdiction.encode(e)?;
        if self.registry_entries.len() > MAX_JURISDICTION_SET {
            return Err(EncodeError::LengthLimitExceeded {
                length: self.registry_entries.len(),
                maximum: MAX_JURISDICTION_SET,
            });
        }
        (self.registry_entries.len() as u16).encode(e)?;
        for code in &self.registry_entries {
            code.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for PrivateIdentityWitnessV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let date_of_birth = Option::<CanonicalDateV1>::decode(d)?;
        let jurisdiction = Option::<JurisdictionCodeV1>::decode(d)?;
        let length = usize::from(u16::decode(d)?);
        if length > MAX_JURISDICTION_SET {
            return Err(DecodeError::LengthLimitExceeded { length, maximum: MAX_JURISDICTION_SET });
        }
        let mut registry_entries = Vec::with_capacity(length);
        for _ in 0..length {
            registry_entries.push(JurisdictionCodeV1::decode(d)?);
        }
        Ok(Self { date_of_birth, jurisdiction, registry_entries })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateIdentityRelationInputV1 {
    pub public: PrivateIdentityPublicInputsV1,
    pub witness: PrivateIdentityWitnessV1,
}
impl CanonicalEncode for PrivateIdentityRelationInputV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.public.encode(e)?;
        self.witness.encode(e)
    }
}
impl CanonicalDecode for PrivateIdentityRelationInputV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            public: PrivateIdentityPublicInputsV1::decode(d)?,
            witness: PrivateIdentityWitnessV1::decode(d)?,
        })
    }
}
impl CanonicalType for PrivateIdentityRelationInputV1 {
    const TYPE_TAG: u16 = 0x01A1;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 1100;
}

pub fn registry_root(entries: &[JurisdictionCodeV1]) -> Result<Digest384, PrivateIdentityError> {
    if entries.is_empty()
        || entries.len() > MAX_JURISDICTION_SET
        || !entries.windows(2).all(|p| p[0] < p[1])
    {
        return Err(PrivateIdentityError::RegistryNotCanonical);
    }
    let mut h = Shake256::default();
    h.update(b"ACTIVECHAIN-JURISDICTION-SET-V1");
    for code in entries {
        h.update(&code.0);
    }
    let mut out = [0; 48];
    XofReader::read(&mut h.finalize_xof(), &mut out);
    Ok(Digest384::new(out))
}
pub fn verify_private_identity_relation(
    input: &PrivateIdentityRelationInputV1,
) -> Result<(), PrivateIdentityError> {
    let p = input.public;
    match p.kind {
        PrivateIdentityPredicateKindV1::AgeAtLeast | PrivateIdentityPredicateKindV1::AgeInRange => {
            if input.witness.jurisdiction.is_some() || !input.witness.registry_entries.is_empty() {
                return Err(PrivateIdentityError::InvalidWitness);
            }
            let age = input
                .witness
                .date_of_birth
                .ok_or(PrivateIdentityError::InvalidWitness)?
                .age_at(p.reference_date.ok_or(PrivateIdentityError::InvalidPublicInput)?)?;
            if age < u16::from(p.minimum_age.unwrap())
                || p.maximum_age.is_some_and(|m| age > u16::from(m))
            {
                return Err(PrivateIdentityError::PredicateFalse);
            }
        }
        _ => {
            if input.witness.date_of_birth.is_some() {
                return Err(PrivateIdentityError::InvalidWitness);
            }
            let code = input.witness.jurisdiction.ok_or(PrivateIdentityError::InvalidWitness)?;
            if registry_root(&input.witness.registry_entries)? != p.jurisdiction_set_root.unwrap() {
                return Err(PrivateIdentityError::RegistryRootMismatch);
            }
            let member = input.witness.registry_entries.binary_search(&code).is_ok();
            let expect = matches!(
                p.kind,
                PrivateIdentityPredicateKindV1::ResidencyIn
                    | PrivateIdentityPredicateKindV1::NationalityIn
            );
            if member != expect {
                return Err(PrivateIdentityError::PredicateFalse);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn d(n: u8) -> Digest384 {
        Digest384::new([n; 48])
    }
    fn code(v: &[u8; 2]) -> JurisdictionCodeV1 {
        JurisdictionCodeV1::new(*v).unwrap()
    }
    fn public(kind: PrivateIdentityPredicateKindV1) -> PrivateIdentityPublicInputsV1 {
        let age = matches!(
            kind,
            PrivateIdentityPredicateKindV1::AgeAtLeast | PrivateIdentityPredicateKindV1::AgeInRange
        );
        let entries = [code(b"DE"), code(b"SE")];
        PrivateIdentityPublicInputsV1::new(
            kind,
            age.then_some(18),
            (kind == PrivateIdentityPredicateKindV1::AgeInRange).then_some(65),
            age.then(|| CanonicalDateV1::new(2026, 8, 2).unwrap()),
            (!age).then(|| registry_root(&entries).unwrap()),
            (!age).then_some(1),
            ChainId::new(d(1)),
            d(2),
            Some(AssetId::new(d(3))),
            TransactionId::new(d(4)),
            PrincipalId::new(d(5)),
            PrincipalId::new(d(6)),
            d(7),
            1,
            d(8),
            20,
            10,
            d(9),
            PrincipalId::new(d(10)),
            d(11),
            d(12),
            d(13),
            1,
        )
        .unwrap()
    }
    #[test]
    fn calendar_and_birthday_boundaries() {
        assert!(CanonicalDateV1::new(2000, 2, 29).is_ok());
        assert!(CanonicalDateV1::new(1900, 2, 29).is_err());
        let p = public(PrivateIdentityPredicateKindV1::AgeAtLeast);
        assert!(
            verify_private_identity_relation(&PrivateIdentityRelationInputV1 {
                public: p,
                witness: PrivateIdentityWitnessV1 {
                    date_of_birth: Some(CanonicalDateV1::new(2008, 8, 2).unwrap()),
                    jurisdiction: None,
                    registry_entries: vec![]
                }
            })
            .is_ok()
        );
        assert_eq!(
            CanonicalDateV1::new(2008, 8, 3)
                .unwrap()
                .age_at(CanonicalDateV1::new(2026, 8, 2).unwrap())
                .unwrap(),
            17
        );
    }
    #[test]
    fn membership_and_non_membership_are_not_invertible() {
        let entries = vec![code(b"DE"), code(b"SE")];
        for (kind, value, ok) in [
            (PrivateIdentityPredicateKindV1::ResidencyIn, code(b"SE"), true),
            (PrivateIdentityPredicateKindV1::ResidencyIn, code(b"US"), false),
            (PrivateIdentityPredicateKindV1::ResidencyNotIn, code(b"US"), true),
        ] {
            assert_eq!(
                verify_private_identity_relation(&PrivateIdentityRelationInputV1 {
                    public: public(kind),
                    witness: PrivateIdentityWitnessV1 {
                        date_of_birth: None,
                        jurisdiction: Some(value),
                        registry_entries: entries.clone()
                    }
                })
                .is_ok(),
                ok
            );
        }
    }
    #[test]
    fn jurisdiction_codes_and_registries_are_canonical() {
        assert!(JurisdictionCodeV1::new(*b"se").is_err());
        assert!(registry_root(&[code(b"SE"), code(b"DE")]).is_err());
        assert!(registry_root(&[code(b"SE"), code(b"SE")]).is_err());
    }
    #[test]
    fn published_private_identity_corpus_has_no_raw_attributes() {
        let vector = include_str!("../../../testing/vectors/private-identity-risc0-v1.tsv");
        let mut accept = 0;
        let mut reject = 0;
        for line in vector.lines().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 3);
            match fields[1] {
                "accept" => accept += 1,
                "reject" => reject += 1,
                other => panic!("unknown {other}"),
            }
        }
        assert_eq!((accept, reject), (5, 19));
        for forbidden in ["date_of_birth", "raw_residence", "subject_identifier"] {
            assert!(!vector.contains(forbidden));
        }
    }
}
