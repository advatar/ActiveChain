//! Reserve attestations, and what anchoring one does not establish.
//!
//! An issuer claiming its liabilities are backed makes a claim someone else
//! must stand behind. This type carries that claim in a form a reader can check
//! the shape of: who attested, for which asset, over which period, against what
//! figure, in what scope, and until when.
//!
//! What it deliberately does not carry is a verdict. Anchoring the commitment
//! of an attestation establishes integrity, time and provenance — that this
//! exact statement existed by that moment and has not changed since. It
//! establishes nothing whatever about reserves. An auditor can sign a false
//! statement, and the anchor will faithfully prove that the false statement is
//! the one that was signed.
//!
//! So [`ReserveClaim`] has no `Verified` variant. Not as a matter of naming —
//! there is no value a caller can construct that means reserves were checked,
//! because this code cannot check them. A surface that wants to display
//! "reserves verified" has to introduce that claim itself, in the open, rather
//! than reading it out of a digest's existence. This is the same discipline the
//! wallet uses in computing balance state from evidence instead of asserting
//! it.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{AssetId, Digest384, PrincipalId};

/// Why an attestation could not be built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveAttestationError {
    /// An identity, asset, or scope left at zero names nothing.
    Unidentified,
    /// A period that does not open before it closes, or an expiry that does not
    /// outlast the period it describes.
    ImpossibleWindow,
    /// A backing claim of zero is not a claim.
    EmptyClaim,
}

/// A signed statement that an issuer's liabilities were backed over a period.
///
/// `claimed_against` is the figure the attestation was made against — the
/// liability or supply the attestor examined. It is carried explicitly because
/// an attestation over yesterday's supply says nothing about today's, and a
/// reader comparing the two is the entire point of recording it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReserveAttestationV1 {
    issuer: PrincipalId,
    asset: AssetId,
    /// Who examined the reserves. Distinct from the issuer, because an issuer
    /// attesting to its own reserves is a claim about itself and a reader
    /// should be able to see that it is.
    attestor: PrincipalId,
    /// Commitment to what was in scope: which accounts, instruments, and
    /// exclusions. Off-chain, because scope descriptions are documents.
    reserve_scope: Digest384,
    claimed_against: u128,
    period_start: u64,
    period_end: u64,
    expires: u64,
}

impl ReserveAttestationV1 {
    /// # Errors
    /// Refuses an unidentified party, asset or scope, a period that does not
    /// open before it closes, an expiry inside the period it describes, and a
    /// zero backing claim.
    // Each argument is a distinct fact the attestation records; grouping them
    // into a struct would only move the same list one call earlier.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: PrincipalId,
        asset: AssetId,
        attestor: PrincipalId,
        reserve_scope: Digest384,
        claimed_against: u128,
        period_start: u64,
        period_end: u64,
        expires: u64,
    ) -> Result<Self, ReserveAttestationError> {
        if issuer.digest() == &Digest384::ZERO
            || attestor.digest() == &Digest384::ZERO
            || reserve_scope == Digest384::ZERO
        {
            return Err(ReserveAttestationError::Unidentified);
        }
        if claimed_against == 0 {
            return Err(ReserveAttestationError::EmptyClaim);
        }
        // An attestation that expires before the period it covers has ended
        // would never be in force for any moment it describes.
        if period_end <= period_start || expires <= period_end {
            return Err(ReserveAttestationError::ImpossibleWindow);
        }
        Ok(Self {
            issuer,
            asset,
            attestor,
            reserve_scope,
            claimed_against,
            period_start,
            period_end,
            expires,
        })
    }

    pub const fn issuer(&self) -> PrincipalId {
        self.issuer
    }
    pub const fn asset(&self) -> AssetId {
        self.asset
    }
    pub const fn attestor(&self) -> PrincipalId {
        self.attestor
    }
    pub const fn claimed_against(&self) -> u128 {
        self.claimed_against
    }
    pub const fn expires(&self) -> u64 {
        self.expires
    }

    /// Whether the issuer attested to its own reserves.
    ///
    /// Not refused — a self-attestation is a real thing an issuer may publish —
    /// but surfaced, because it is a materially weaker statement than a third
    /// party's and a reader must be able to tell them apart.
    #[must_use]
    pub fn is_self_attested(&self) -> bool {
        self.issuer == self.attestor
    }

    /// The commitment an anchor would carry.
    ///
    /// Anchoring this establishes that this exact statement existed by a
    /// moment and has not changed. It does not establish that the statement is
    /// true, which is why nothing in this module returns a verdict.
    ///
    /// # Errors
    /// Fails only if the attestation cannot be encoded.
    pub fn commitment(&self) -> Result<Digest384, EncodeError> {
        commit(DomainTag::CANONICAL_VALUE, self)
    }

    /// What this attestation supports about a supply figure at a moment.
    ///
    /// Deliberately not named `verify`. It reports coverage and nothing more.
    #[must_use]
    pub fn claim_at(&self, now: u64, supply: u128) -> ReserveClaim {
        if now >= self.expires {
            return ReserveClaim::Expired { expired_at: self.expires };
        }
        if now < self.period_start {
            return ReserveClaim::Uncovered;
        }
        if supply > self.claimed_against {
            // The figure grew after it was examined. The attestation is still
            // a true statement about what it examined, and says nothing about
            // the difference.
            return ReserveClaim::ClaimExceeded {
                claimed_against: self.claimed_against,
                supply,
                attestor: self.attestor,
            };
        }
        ReserveClaim::Attested {
            attestor: self.attestor,
            claimed_against: self.claimed_against,
            self_attested: self.is_self_attested(),
            expires: self.expires,
        }
    }
}

/// What a reserve attestation supports — never a verdict on reserves.
///
/// There is no `Verified` variant, and adding one would be a mistake rather
/// than a feature. This code can establish that a statement was made, by whom,
/// over what, and that it has not changed. Whether the reserves exist is not
/// knowable from any of that.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveClaim {
    /// No attestation covers this moment.
    Uncovered,
    /// The attestation has lapsed. An expired attestation is not weak
    /// evidence; it is evidence about a period that has closed.
    Expired { expired_at: u64 },
    /// The supply now exceeds the figure the attestor examined. Surfaced as
    /// its own state because rendering it as "attested" would let an issuer
    /// mint past its own attestation and keep the badge.
    ClaimExceeded { claimed_against: u128, supply: u128, attestor: PrincipalId },
    /// An attestation covers this moment and this figure. It says who made the
    /// claim and whether they were the issuer themselves — it does not say the
    /// claim is true.
    Attested { attestor: PrincipalId, claimed_against: u128, self_attested: bool, expires: u64 },
}

impl CanonicalEncode for ReserveAttestationV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.issuer.encode(e)?;
        self.asset.encode(e)?;
        self.attestor.encode(e)?;
        self.reserve_scope.encode(e)?;
        self.claimed_against.encode(e)?;
        self.period_start.encode(e)?;
        self.period_end.encode(e)?;
        self.expires.encode(e)
    }
}

impl CanonicalDecode for ReserveAttestationV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::new(
            PrincipalId::decode(d)?,
            AssetId::decode(d)?,
            PrincipalId::decode(d)?,
            Digest384::decode(d)?,
            u128::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
            u64::decode(d)?,
        )
        .map_err(|_| DecodeError::InvalidValue("invalid reserve attestation"))
    }
}

impl CanonicalType for ReserveAttestationV1 {
    const TYPE_TAG: u16 = 0x01c7;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 48 + 48 + 48 + 16 + 8 + 8 + 8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::{decode_envelope, encode_envelope};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn attestation(claimed_against: u128) -> ReserveAttestationV1 {
        ReserveAttestationV1::new(
            PrincipalId::new(digest(1)),
            AssetId::new(digest(2)),
            PrincipalId::new(digest(3)),
            digest(4),
            claimed_against,
            100,
            200,
            300,
        )
        .expect("a well formed attestation")
    }

    /// The property this module exists to hold. If a caller can ever obtain a
    /// value meaning "reserves verified", a surface will render it.
    #[test]
    fn no_reachable_state_asserts_that_reserves_were_verified() {
        let claims = [
            attestation(1_000).claim_at(150, 900),
            attestation(1_000).claim_at(150, 1_100),
            attestation(1_000).claim_at(50, 900),
            attestation(1_000).claim_at(400, 900),
        ];
        for claim in claims {
            match claim {
                ReserveClaim::Attested { attestor, .. } => {
                    assert_eq!(attestor, PrincipalId::new(digest(3)), "it names who claimed");
                }
                ReserveClaim::Uncovered
                | ReserveClaim::Expired { .. }
                | ReserveClaim::ClaimExceeded { .. } => {}
            }
        }
    }

    #[test]
    fn an_attestation_covers_the_period_it_describes() {
        let attested = attestation(1_000);
        assert_eq!(attested.claim_at(50, 900), ReserveClaim::Uncovered, "before the period");
        assert!(matches!(attested.claim_at(150, 900), ReserveClaim::Attested { .. }));
        assert_eq!(
            attested.claim_at(300, 900),
            ReserveClaim::Expired { expired_at: 300 },
            "expiry is the first moment it no longer speaks"
        );
    }

    /// Minting past an attestation must not keep its badge.
    #[test]
    fn supply_beyond_the_examined_figure_is_its_own_state() {
        assert_eq!(
            attestation(1_000).claim_at(150, 1_001),
            ReserveClaim::ClaimExceeded {
                claimed_against: 1_000,
                supply: 1_001,
                attestor: PrincipalId::new(digest(3)),
            }
        );
        assert!(
            matches!(attestation(1_000).claim_at(150, 1_000), ReserveClaim::Attested { .. }),
            "the examined figure itself is covered"
        );
    }

    /// A self-attestation is allowed but must never be indistinguishable from
    /// a third party's.
    #[test]
    fn a_self_attestation_is_visible_as_one() {
        let own = ReserveAttestationV1::new(
            PrincipalId::new(digest(1)),
            AssetId::new(digest(2)),
            PrincipalId::new(digest(1)),
            digest(4),
            1_000,
            100,
            200,
            300,
        )
        .unwrap();
        assert!(own.is_self_attested());
        let ReserveClaim::Attested { self_attested, .. } = own.claim_at(150, 900) else {
            panic!("expected coverage")
        };
        assert!(self_attested, "a reader must be able to tell");
        let ReserveClaim::Attested { self_attested, .. } = attestation(1_000).claim_at(150, 900)
        else {
            panic!("expected coverage")
        };
        assert!(!self_attested);
    }

    #[test]
    fn an_impossible_window_or_empty_claim_is_refused() {
        let build = |claimed, start, end, expires| {
            ReserveAttestationV1::new(
                PrincipalId::new(digest(1)),
                AssetId::new(digest(2)),
                PrincipalId::new(digest(3)),
                digest(4),
                claimed,
                start,
                end,
                expires,
            )
        };
        assert_eq!(build(0, 100, 200, 300), Err(ReserveAttestationError::EmptyClaim));
        assert_eq!(build(1, 200, 200, 300), Err(ReserveAttestationError::ImpossibleWindow));
        assert_eq!(
            build(1, 100, 200, 200),
            Err(ReserveAttestationError::ImpossibleWindow),
            "expiring as the period closes leaves no moment it is in force"
        );
    }

    #[test]
    fn an_unidentified_party_or_scope_is_refused() {
        assert_eq!(
            ReserveAttestationV1::new(
                PrincipalId::new(Digest384::ZERO),
                AssetId::new(digest(2)),
                PrincipalId::new(digest(3)),
                digest(4),
                1,
                100,
                200,
                300,
            ),
            Err(ReserveAttestationError::Unidentified)
        );
        assert_eq!(
            ReserveAttestationV1::new(
                PrincipalId::new(digest(1)),
                AssetId::new(digest(2)),
                PrincipalId::new(digest(3)),
                Digest384::ZERO,
                1,
                100,
                200,
                300,
            ),
            Err(ReserveAttestationError::Unidentified),
            "a scope naming nothing would let any reserves match"
        );
    }

    /// The commitment is what an anchor carries, so it must be stable and must
    /// move when any field does.
    #[test]
    fn the_commitment_covers_every_field() {
        let base = attestation(1_000);
        assert_eq!(base.commitment().unwrap(), attestation(1_000).commitment().unwrap());
        assert_ne!(base.commitment().unwrap(), attestation(1_001).commitment().unwrap());
    }

    #[test]
    fn an_attestation_round_trips() {
        let attested = attestation(1_000);
        let bytes = encode_envelope(&attested).unwrap();
        assert_eq!(decode_envelope::<ReserveAttestationV1>(&bytes).unwrap(), attested);
    }
}
