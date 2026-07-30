# Jurisdiction-specific regulated profiles

## Objective

Support multiple regulated profiles—such as EU, US, Tanzania, and Kenya—without changing the
base chain into a global KYC system or allowing one authority to control unrelated activity.

## Design rules

1. A profile is scoped to an operator, legal entity, jurisdiction set, regulated activity,
   asset/resource selectors, counterparty class, and validity window.
2. Profiles are versioned and signed. They never reinterpret historical actions.
3. The base protocol carries only profile identifiers, commitments, policy outcomes, and receipts;
   personal data, screening details, case notes, and Travel Rule payloads remain off-chain.
4. Profile applicability is determined from verified jurisdiction facts and service context—not
   from a global address blacklist.
5. If multiple profiles apply, their obligations compose by intersection. A conflict fails closed
   or selects the explicitly stricter obligation; it must never silently weaken a control.
6. Profile authority is separated from validator authority. A profile cannot grant unilateral
   chain-wide freeze or surveillance powers.

## Profile layers

- **Baseline:** protocol safety, privacy, authorization, conservation, and evidence rules.
- **Jurisdiction:** country/region legal obligations and supervisory references.
- **Activity:** hosted wallet, CASP transfer, issuer, payment, bridge, or custody rules.
- **Operator:** entity-specific providers, limits, escalation, and retention configuration.
- **Asset:** issuer, reserve, redemption, freeze, and disclosure controls.

Inheritance is explicit and immutable. Overrides name the parent rule, replacement, rationale,
authority, effective time, and review date.

## Initial profile catalogue

These are planning identifiers, not legal conclusions:

- `eu.casp.transfer.v1`
- `us.msb.transfer.v1`
- `tz.payment-operator.v1`
- `ke.virtual-asset-service.v2`
- `ke.stablecoin-issuer.v1`

Each profile requires qualified local counsel, a signed role/jurisdiction matrix, a regulatory
change owner, privacy/data-boundary review, provider configuration, deterministic vectors, and
an S3 operating-period evidence plan before production claims.

## Conflict and applicability algorithm

1. Resolve the operator legal entity and service activity.
2. Resolve customer/counterparty jurisdiction facts using minimal verified predicates.
3. Select all profiles whose jurisdiction, activity, asset, and validity ranges apply.
4. Require every selected profile’s mandatory obligations; choose the stricter limit when a
   limit conflict is explicitly comparable.
5. If obligations are incomparable or jurisdiction facts are stale/ambiguous, fail closed to
   runtime manual review by the operator's trained compliance team; never guess based on
   nationality or IP alone. Pre-deployment ambiguity blocks profile activation and is resolved
   by the accountable compliance owner and qualified local counsel.
6. Bind the selected profile set commitment to the exact action and evidence envelope.

## Privacy and due process

Profiles must support pairwise bindings, selective disclosure, purpose limitation, expiry,
appeal/release, temporary holds, threshold approvals, transparent aggregate reporting, and
non-enumerable public commitments. Legal access to confidential evidence is handled by the
responsible operator under applicable process; it is not a consensus-level spy/freeze primitive.

## Delivery stages

1. Freeze profile schema, inheritance/conflict semantics, and applicability vectors.
2. Add EU/US/Tanzania/Kenya profile manifests with explicit `TBD/counsel required` fields.
3. Implement canonical profile IDs, jurisdiction commitments, validity, selectors, and signed
   governance records.
4. Integrate profile-set selection into P-120/P-121 admission and replay barriers.
5. Add formal proofs for no weakening through inheritance, deterministic conflict resolution,
   expiry, non-retroactivity, and privacy-boundary preservation.
6. Run jurisdiction-specific operational pilots and obtain legal/security/compliance review.

## Kenya implementation

The Kenya profiles use the canonical `KenyaRegulatedProfileV1` activation record and the
[Kenya control register](KENYA_VASP_CONTROL_REGISTER_V1.md). They are implementation-complete but
activation-gated templates: deployment-specific commitments replace every `REQUIRED` marker only
after licence/approval verification, Kenyan counsel review, operator configuration, testing, and
independent evidence. Repository inclusion is not regulatory authorization.
